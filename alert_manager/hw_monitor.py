#!/usr/bin/env python3
"""Hardware metrics collector for Nemesis Firewall.

Run as a daemon (writes a sample every 5 minutes to the hw_metrics table)
or import as a module (dashboard.py uses get_live_metrics / init_db /
get_recent_samples).
"""
import json
import logging
import os
import signal
import sqlite3
import subprocess
import sys
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler

import psutil

DB_PATH      = "/home/paul/alert_manager/alerts.db"
LOG_FILE     = "/home/paul/alert_manager/hw_monitor.log"
HW_MAP_PATH  = "/home/paul/alert_manager/hw_map.json"
NET_IFACE    = "enp131s0"
SAMPLE_INTERVAL = 300

log = logging.getLogger("hw_monitor")
log.setLevel(logging.INFO)
if not log.handlers:
    _handler = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3)
    _handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(_handler)

# Prime psutil so the first cpu_percent() call returns a real value rather than 0.
psutil.cpu_percent(interval=None, percpu=True)

_state = {
    "disk": psutil.disk_io_counters(),
    "net": psutil.net_io_counters(pernic=True).get(NET_IFACE),
    "ts": time.monotonic(),
}

_running = True


def _stop(signum, _frame):
    global _running
    log.info("received signal %s, shutting down", signum)
    _running = False


def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS hw_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP NOT NULL,
                cpu_temp REAL,
                ambient_temp REAL,
                nvme_temp REAL,
                fan1_rpm INTEGER,
                fan2_rpm INTEGER,
                fan3_rpm INTEGER,
                cpu_percent REAL,
                ram_used_gb REAL,
                disk_read_mb REAL,
                disk_write_mb REAL,
                net_in_mb REAL,
                net_out_mb REAL,
                gpu_temp INTEGER,
                gpu_fan_percent INTEGER,
                gpu_power_watts REAL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_hw_metrics_ts ON hw_metrics(timestamp)")
        # Idempotent migrations for columns added after initial schema.
        existing = {row[1] for row in c.execute("PRAGMA table_info(hw_metrics)").fetchall()}
        for col, decl in (("gpu_temp", "INTEGER"),
                          ("gpu_fan_percent", "INTEGER"),
                          ("gpu_power_watts", "REAL"),
                          ("fan4_rpm", "INTEGER"),
                          ("fans_json", "TEXT")):
            if col not in existing:
                c.execute(f"ALTER TABLE hw_metrics ADD COLUMN {col} {decl}")
        conn.commit()

        # One-time data migration: backfill fans_json from old fan{n}_rpm columns.
        # Use hw_map.json fan labels if available, else fall back to generic "Fan N".
        fan_labels = {}
        try:
            with open(HW_MAP_PATH) as _mf:
                _hm = json.load(_mf)
                for _i, _f in enumerate(_hm.get("fans", []), start=1):
                    fan_labels[_i] = _f.get("label", f"Fan {_i}")
        except Exception:
            pass
        rows = c.execute(
            "SELECT id, fan1_rpm, fan2_rpm, fan3_rpm, fan4_rpm "
            "FROM hw_metrics WHERE fans_json IS NULL "
            "AND (fan1_rpm IS NOT NULL OR fan2_rpm IS NOT NULL "
            "     OR fan3_rpm IS NOT NULL OR fan4_rpm IS NOT NULL)"
        ).fetchall()
        migrated = 0
        for row_id, f1, f2, f3, f4 in rows:
            fans = [{"label": fan_labels.get(i, f"Fan {i}"), "rpm": rpm}
                    for i, rpm in enumerate([f1, f2, f3, f4], start=1)
                    if rpm is not None]
            if fans:
                c.execute("UPDATE hw_metrics SET fans_json = ? WHERE id = ?",
                          (json.dumps(fans), row_id))
                migrated += 1
        if migrated:
            conn.commit()
            log.info("init_db: migrated %d rows from fan_rpm columns to fans_json", migrated)
    finally:
        conn.close()


GPU_THERMAL_ZONE = "/sys/class/thermal/thermal_zone7/temp"


def _read_gpu_thermal_zone():
    """Fallback GPU temp from sysfs (TGPU zone)."""
    try:
        with open(GPU_THERMAL_ZONE) as f:
            millideg = int(f.read().strip())
        return int(round(millideg / 1000.0))
    except Exception as e:
        log.debug("TGPU thermal zone read failed: %s", e)
        return None


def _read_gpu_metrics():
    """Return (gpu_temp_c, gpu_fan_percent, gpu_power_watts).

    Uses `nvidia-smi --query-gpu=...,fan.speed,power.draw --format=csv,noheader,nounits`.
    Falls back to TGPU thermal zone for temperature only when nvidia-smi fails.
    Returns None for any field that cannot be parsed.
    """
    try:
        result = subprocess.run(
            ["nvidia-smi",
             "--query-gpu=temperature.gpu,fan.speed,power.draw",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            raise RuntimeError(f"nvidia-smi exit {result.returncode}: {result.stderr.strip()}")
        # Only the first GPU; line format: "49, 30, 114.40"
        line = result.stdout.strip().splitlines()[0]
        parts = [p.strip() for p in line.split(",")]

        def _to_int(s):
            try:
                return int(float(s))
            except (TypeError, ValueError):
                return None

        def _to_float(s):
            try:
                return float(s)
            except (TypeError, ValueError):
                return None

        return _to_int(parts[0]), _to_int(parts[1]), _to_float(parts[2])
    except Exception as e:
        log.warning("nvidia-smi read failed (%s); falling back to TGPU thermal zone", e)
        return _read_gpu_thermal_zone(), None, None


def _run_sensors_u():
    """Run 'sensors -u' and return raw text, or '' on failure."""
    try:
        result = subprocess.run(
            ["sensors", "-u"], capture_output=True, text=True, timeout=5
        )
        return result.stdout
    except Exception as e:
        log.warning("sensors -u failed: %s", e)
        return ""


def _parse_sensors_u(text):
    """
    Parse 'sensors -u' plain-text output into:
      {adapter_name: {unique_key: {"label": str, "value": float}}}

    unique_key is the lm-sensors internal key, e.g. "fan10_input" or
    "temp2_input".  Unlike 'sensors -j', duplicate human-readable labels
    (e.g. multiple "Chassis Motherboard Fan" entries) are all preserved here
    because each maps to a distinct unique_key.
    """
    result = {}
    current_adapter = None
    current_label   = None

    for line in text.splitlines():
        if not line.strip():
            continue
        n_spaces = len(line) - len(line.lstrip())
        stripped  = line.strip()

        if n_spaces == 0:
            if stripped.startswith("Adapter:"):
                continue
            if stripped.endswith(":"):
                current_label = stripped[:-1]
            else:
                current_adapter = stripped
                current_label   = None
                if current_adapter not in result:
                    result[current_adapter] = {}
        elif n_spaces >= 2 and current_adapter and current_label:
            if ":" in stripped:
                key, _, val_str = stripped.partition(":")
                key = key.strip()
                if key.endswith("_input"):
                    try:
                        result[current_adapter][key] = {
                            "label": current_label,
                            "value": float(val_str.strip()),
                        }
                    except ValueError:
                        pass

    return result


def _read_sensors():
    """Return parsed sensor data dict, or {} on failure."""
    return _parse_sensors_u(_run_sensors_u())


_hw_map        = None
_hw_map_loaded = False
_sensor_map_logged = False


def _load_hw_map():
    """Load hw_map.json once and cache the result. Returns the dict or None."""
    global _hw_map, _hw_map_loaded
    if _hw_map_loaded:
        return _hw_map
    _hw_map_loaded = True
    try:
        with open(HW_MAP_PATH) as f:
            data = json.load(f)
        # Require unique_key in every non-None entry (new format from hw_discover.py).
        # Old files only carry adapter+label; reject them so we fall back to
        # auto-discovery rather than silently looking up the wrong sensor.
        def _missing_key(entry):
            return entry is not None and "unique_key" not in entry
        if (    _missing_key(data.get("cpu_temp"))
             or _missing_key(data.get("ambient_temp"))
             or _missing_key(data.get("nvme_temp"))
             or any(_missing_key(f) for f in data.get("fans", []))):
            log.warning(
                "hw_map: %s uses old format (no unique_key) — run hw_discover.py to regenerate",
                HW_MAP_PATH,
            )
            return _hw_map   # stays None
        _hw_map = data
        log.info("hw_map: loaded from %s", HW_MAP_PATH)
    except FileNotFoundError:
        log.info("hw_map: %s not found — using auto-discovery", HW_MAP_PATH)
    except Exception as e:
        log.warning("hw_map: failed to load %s (%s) — using auto-discovery", HW_MAP_PATH, e)
    return _hw_map


def _lookup_by_key(parsed, adapter, unique_key):
    """Read a sensor value by adapter + unique_key from parsed sensors data."""
    try:
        return float(parsed[adapter][unique_key]["value"])
    except (KeyError, TypeError, ValueError):
        return None


def _extract_temps_and_fans(s):
    """Extract sensor readings from parsed sensors -u output.

    If hw_map.json exists, looks up each role by the adapter+unique_key the
    user chose during hw_discover.py.  Falls back to vendor-agnostic heuristic
    discovery when the file is absent or uses the old format.
    """
    global _sensor_map_logged

    out = {
        "cpu_temp":     None,
        "ambient_temp": None,
        "nvme_temp":    None,
        "fans":         [],
    }

    hw_map = _load_hw_map()

    if hw_map is not None:
        # ── Mapped path: explicit adapter/unique_key from hw_map.json ─────────
        if hw_map.get("cpu_temp"):
            m = hw_map["cpu_temp"]
            out["cpu_temp"] = _lookup_by_key(s, m["adapter"], m["unique_key"])
        if hw_map.get("ambient_temp"):
            m = hw_map["ambient_temp"]
            out["ambient_temp"] = _lookup_by_key(s, m["adapter"], m["unique_key"])
        if hw_map.get("nvme_temp"):
            m = hw_map["nvme_temp"]
            out["nvme_temp"] = _lookup_by_key(s, m["adapter"], m["unique_key"])
        for fan in hw_map.get("fans", []):
            rpm = _lookup_by_key(s, fan["adapter"], fan["unique_key"])
            out["fans"].append({
                "label": fan["label"],
                "rpm":   int(rpm) if rpm is not None else None,
            })

        if not _sensor_map_logged:
            _sensor_map_logged = True
            log.info("Sensor map (from hw_map.json):")
            if hw_map.get("cpu_temp"):
                m = hw_map["cpu_temp"]
                log.info("  %-16s -> %s / %s (%s)",
                         "cpu_temp", m["adapter"], m["label"], m["unique_key"])
            if hw_map.get("ambient_temp"):
                m = hw_map["ambient_temp"]
                log.info("  %-16s -> %s / %s (%s)",
                         "ambient_temp", m["adapter"], m["label"], m["unique_key"])
            for i, fan in enumerate(hw_map.get("fans", []), start=1):
                log.info("  fan%-13d -> %s / %s (%s)",
                         i, fan["adapter"], fan["label"], fan["unique_key"])
            if hw_map.get("nvme_temp"):
                m = hw_map["nvme_temp"]
                log.info("  %-16s -> %s / %s (%s)",
                         "nvme_temp", m["adapter"], m["label"], m["unique_key"])

        return out

    # ── Auto-discovery path (no hw_map.json) ─────────────────────────────────
    matched = {}
    fan_hits = []
    available_adapters = list(s.keys())

    for adapter_name, readings in s.items():
        adapter_lower = adapter_name.lower()

        for unique_key, info in readings.items():
            label       = info["label"]
            value       = info["value"]
            label_lower = label.lower()

            # CPU temp: Package (Intel), Tdie / Tctl (AMD)
            if out["cpu_temp"] is None and unique_key.startswith("temp") and (
                "package" in label_lower or "tdie" in label_lower or "tctl" in label_lower
            ):
                out["cpu_temp"]     = float(value)
                matched["cpu_temp"] = f"{adapter_name}/{label} ({unique_key})"

            # Ambient temp: any label containing "ambient"
            if out["ambient_temp"] is None and unique_key.startswith("temp") and "ambient" in label_lower:
                out["ambient_temp"]     = float(value)
                matched["ambient_temp"] = f"{adapter_name}/{label} ({unique_key})"

            # NVMe temp: adapter containing "nvme", label "Composite"
            if (out["nvme_temp"] is None and "nvme" in adapter_lower
                    and unique_key.startswith("temp") and label_lower == "composite"):
                out["nvme_temp"]     = float(value)
                matched["nvme_temp"] = f"{adapter_name}/{label} ({unique_key})"

            # Fan RPMs: unique_key starting with "fan"
            if unique_key.startswith("fan"):
                try:
                    fan_hits.append((adapter_name, unique_key, label, int(float(value))))
                except (TypeError, ValueError):
                    pass

    # CPU fallback: highest reading from any coretemp adapter
    if out["cpu_temp"] is None:
        best_temp, best_loc = None, None
        for adapter_name, readings in s.items():
            if "coretemp" not in adapter_name.lower():
                continue
            for unique_key, info in readings.items():
                if not unique_key.startswith("temp"):
                    continue
                try:
                    t = float(info["value"])
                    if best_temp is None or t > best_temp:
                        best_temp = t
                        best_loc  = f"{adapter_name}/{info['label']} ({unique_key})"
                except (TypeError, ValueError):
                    pass
        if best_temp is not None:
            out["cpu_temp"]     = best_temp
            matched["cpu_temp"] = f"{best_loc} (coretemp max)"

    # All fan hits become the fans list — no limit
    out["fans"] = [{"label": lbl, "rpm": rpm} for _, _, lbl, rpm in fan_hits]

    # Log auto-discovery results once on startup
    if not _sensor_map_logged:
        _sensor_map_logged = True
        log.info("Sensor map (auto-discovery) — adapters found: %s",
                 ", ".join(available_adapters) or "(none)")
        for field, loc in matched.items():
            log.info("  Mapped %-16s -> %s", field, loc)
        for i, (_, ukey, lbl, _rpm) in enumerate(fan_hits, start=1):
            log.info("  fan%-13d -> %s (%s)", i, lbl, ukey)
        if "ambient_temp" not in matched:
            log.warning(
                "No ambient temperature sensor found (no label containing 'Ambient'); "
                "available adapters: %s", ", ".join(available_adapters) or "(none)"
            )
        if not fan_hits:
            log.warning(
                "No fan speed sensors found; "
                "available adapters: %s", ", ".join(available_adapters) or "(none)"
            )

    return out


def get_live_metrics():
    """Snapshot of current metrics for the dashboard card. Cheap, no delta state."""
    sensors = _read_sensors()
    metrics = _extract_temps_and_fans(sensors)
    vm = psutil.virtual_memory()
    per_core = psutil.cpu_percent(interval=None, percpu=True)
    metrics["cpu_percent"] = round(sum(per_core) / len(per_core), 1) if per_core else None
    metrics["cpu_per_core"] = [round(p, 1) for p in per_core]
    metrics["ram_used_gb"] = round(vm.used / (1024 ** 3), 2)
    metrics["ram_total_gb"] = round(vm.total / (1024 ** 3), 2)
    metrics["ram_percent"] = vm.percent
    gpu_temp, gpu_fan, gpu_power = _read_gpu_metrics()
    metrics["gpu_temp"] = gpu_temp
    metrics["gpu_fan_percent"] = gpu_fan
    metrics["gpu_power_watts"] = gpu_power
    metrics["timestamp"] = datetime.now().isoformat(timespec="seconds")
    return metrics


def _collect_sample_with_deltas():
    """Build a full sample row including disk/net deltas vs the last reading."""
    now_mono = time.monotonic()
    elapsed = max(1e-3, now_mono - _state["ts"])

    sample = get_live_metrics()

    disk_now = psutil.disk_io_counters()
    disk_prev = _state["disk"]
    if disk_now and disk_prev:
        sample["disk_read_mb"] = round(
            (disk_now.read_bytes - disk_prev.read_bytes) / (1024 ** 2), 3
        )
        sample["disk_write_mb"] = round(
            (disk_now.write_bytes - disk_prev.write_bytes) / (1024 ** 2), 3
        )
    else:
        sample["disk_read_mb"] = None
        sample["disk_write_mb"] = None

    net_now = psutil.net_io_counters(pernic=True).get(NET_IFACE)
    net_prev = _state["net"]
    if net_now and net_prev:
        sample["net_in_mb"] = round(
            (net_now.bytes_recv - net_prev.bytes_recv) / (1024 ** 2), 3
        )
        sample["net_out_mb"] = round(
            (net_now.bytes_sent - net_prev.bytes_sent) / (1024 ** 2), 3
        )
    else:
        sample["net_in_mb"] = None
        sample["net_out_mb"] = None

    sample["elapsed_s"] = round(elapsed, 1)

    _state["disk"] = disk_now
    _state["net"] = net_now
    _state["ts"] = now_mono
    return sample


def insert_sample(s):
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute(
            """INSERT INTO hw_metrics
            (timestamp, cpu_temp, ambient_temp, nvme_temp,
             fans_json,
             cpu_percent, ram_used_gb,
             disk_read_mb, disk_write_mb, net_in_mb, net_out_mb,
             gpu_temp, gpu_fan_percent, gpu_power_watts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                s["timestamp"], s.get("cpu_temp"), s.get("ambient_temp"),
                s.get("nvme_temp"),
                json.dumps(s.get("fans", [])),
                s.get("cpu_percent"), s.get("ram_used_gb"),
                s.get("disk_read_mb"), s.get("disk_write_mb"),
                s.get("net_in_mb"), s.get("net_out_mb"),
                s.get("gpu_temp"), s.get("gpu_fan_percent"), s.get("gpu_power_watts"),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_recent_samples(limit=288):
    """Return up to `limit` samples, oldest first (suitable for charts)."""
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute(
            """SELECT timestamp, cpu_temp, ambient_temp, nvme_temp,
                      fans_json,
                      cpu_percent, ram_used_gb,
                      disk_read_mb, disk_write_mb, net_in_mb, net_out_mb,
                      gpu_temp, gpu_fan_percent, gpu_power_watts
               FROM hw_metrics
               ORDER BY id DESC
               LIMIT ?""",
            (limit,),
        )
        rows = c.fetchall()
    finally:
        conn.close()
    cols = ["timestamp", "cpu_temp", "ambient_temp", "nvme_temp",
            "fans_json",
            "cpu_percent", "ram_used_gb",
            "disk_read_mb", "disk_write_mb", "net_in_mb", "net_out_mb",
            "gpu_temp", "gpu_fan_percent", "gpu_power_watts"]
    rows.reverse()
    result = []
    for r in rows:
        d = dict(zip(cols, r))
        raw = d.pop("fans_json", None)
        d["fans"] = json.loads(raw) if raw else []
        result.append(d)
    return result


def _sleep_interruptible(seconds):
    for _ in range(int(seconds)):
        if not _running:
            return
        time.sleep(1)


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    log.info("hw_monitor starting (db=%s interval=%ds iface=%s)",
             DB_PATH, SAMPLE_INTERVAL, NET_IFACE)
    init_db()
    # Sleep one interval first so the first delta covers a full window.
    _sleep_interruptible(SAMPLE_INTERVAL)
    while _running:
        try:
            sample = _collect_sample_with_deltas()
            insert_sample(sample)
            fans_summary = " ".join(
                f"{f['label']}={f['rpm']}" for f in sample.get("fans", [])
            ) or "none"
            log.info(
                "sample cpu=%s ambient=%s nvme=%s fans=[%s] cpu%%=%s ram=%sGB "
                "gpu=%s°C/%s%%/%sW net=%s/%sMB disk=%s/%sMB",
                sample.get("cpu_temp"), sample.get("ambient_temp"),
                sample.get("nvme_temp"), fans_summary,
                sample.get("cpu_percent"), sample.get("ram_used_gb"),
                sample.get("gpu_temp"), sample.get("gpu_fan_percent"),
                sample.get("gpu_power_watts"),
                sample.get("net_in_mb"), sample.get("net_out_mb"),
                sample.get("disk_read_mb"), sample.get("disk_write_mb"),
            )
        except Exception as e:
            log.exception("sample failed: %s", e)
        _sleep_interruptible(SAMPLE_INTERVAL)
    log.info("hw_monitor stopped")


if __name__ == "__main__":
    main()
