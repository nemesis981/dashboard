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
                          ("fan4_rpm", "INTEGER")):
            if col not in existing:
                c.execute(f"ALTER TABLE hw_metrics ADD COLUMN {col} {decl}")
        conn.commit()
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


def _read_sensors():
    """Return parsed sensors -j output, or {} on failure."""
    try:
        result = subprocess.run(
            ["sensors", "-j"], capture_output=True, text=True, timeout=5
        )
        # sensors emits invalid JSON when adapters report duplicate keys;
        # tolerate by stripping trailing commas and using a permissive load.
        text = result.stdout
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # fall back: strip ",\n  }" patterns that some adapters produce
            cleaned = text.replace(",\n  }", "\n  }").replace(",\n}", "\n}")
            return json.loads(cleaned)
    except Exception as e:
        log.warning("sensors read failed: %s", e)
        return {}


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
            _hw_map = json.load(f)
        log.info("hw_map: loaded from %s", HW_MAP_PATH)
    except FileNotFoundError:
        log.info("hw_map: %s not found — using auto-discovery", HW_MAP_PATH)
    except Exception as e:
        log.warning("hw_map: failed to load %s (%s) — using auto-discovery", HW_MAP_PATH, e)
    return _hw_map


def _lookup_temp(s, adapter, label):
    """Read a temp*_input value from sensors dict by exact adapter+label."""
    try:
        sensor_data = s[adapter][label]
        for k, v in sensor_data.items():
            if "temp" in k and k.endswith("_input"):
                return float(v)
    except (KeyError, TypeError, AttributeError):
        pass
    return None


def _lookup_fan(s, adapter, label):
    """Read a fan*_input value from sensors dict by exact adapter+label."""
    try:
        sensor_data = s[adapter][label]
        for k, v in sensor_data.items():
            if "fan" in k and k.endswith("_input"):
                return int(float(v))
    except (KeyError, TypeError, AttributeError, ValueError):
        pass
    return None


def _extract_temps_and_fans(s):
    """Extract sensor readings from sensors -j output.

    If hw_map.json exists, looks up each role by the exact adapter/label the
    user chose during hw_discover.py.  Falls back to vendor-agnostic heuristic
    discovery when the file is absent.
    """
    global _sensor_map_logged

    out = {
        "cpu_temp":    None,
        "ambient_temp": None,
        "nvme_temp":   None,
        "fan1_rpm":    None,
        "fan2_rpm":    None,
        "fan3_rpm":    None,
        "fan4_rpm":    None,
    }

    hw_map = _load_hw_map()

    if hw_map is not None:
        # ── Mapped path: explicit adapter/label from hw_map.json ─────────────
        if hw_map.get("cpu_temp"):
            m = hw_map["cpu_temp"]
            out["cpu_temp"] = _lookup_temp(s, m["adapter"], m["label"])
        if hw_map.get("ambient_temp"):
            m = hw_map["ambient_temp"]
            out["ambient_temp"] = _lookup_temp(s, m["adapter"], m["label"])
        if hw_map.get("nvme_temp"):
            m = hw_map["nvme_temp"]
            out["nvme_temp"] = _lookup_temp(s, m["adapter"], m["label"])
        for i, fan in enumerate(hw_map.get("fans", [])[:4], start=1):
            out[f"fan{i}_rpm"] = _lookup_fan(s, fan["adapter"], fan["label"])

        if not _sensor_map_logged:
            _sensor_map_logged = True
            log.info("Sensor map (from hw_map.json):")
            if hw_map.get("cpu_temp"):
                m = hw_map["cpu_temp"]
                log.info("  %-16s -> %s / %s", "cpu_temp", m["adapter"], m["label"])
            if hw_map.get("ambient_temp"):
                m = hw_map["ambient_temp"]
                log.info("  %-16s -> %s / %s", "ambient_temp", m["adapter"], m["label"])
            for i, fan in enumerate(hw_map.get("fans", [])[:4], start=1):
                log.info("  %-16s -> %s / %s", f"fan{i}_rpm", fan["adapter"], fan["label"])
            if hw_map.get("nvme_temp"):
                m = hw_map["nvme_temp"]
                log.info("  %-16s -> %s / %s", "nvme_temp", m["adapter"], m["label"])

        return out

    # ── Auto-discovery path (no hw_map.json) ─────────────────────────────────
    matched = {}
    fan_hits = []
    available_adapters = list(s.keys())

    for adapter_name, adapter_data in s.items():
        if not isinstance(adapter_data, dict):
            continue
        adapter_lower = adapter_name.lower()

        for label, sensor_data in adapter_data.items():
            if not isinstance(sensor_data, dict):
                continue
            label_lower = label.lower()

            # CPU temp: Package (Intel), Tdie / Tctl (AMD)
            if out["cpu_temp"] is None and (
                "package" in label_lower or "tdie" in label_lower or "tctl" in label_lower
            ):
                for k, v in sensor_data.items():
                    if "temp" in k and k.endswith("_input"):
                        try:
                            out["cpu_temp"] = float(v)
                            matched["cpu_temp"] = f"{adapter_name}/{label}"
                            break
                        except (TypeError, ValueError):
                            pass

            # Ambient temp: any label containing "ambient" (case-insensitive)
            if out["ambient_temp"] is None and "ambient" in label_lower:
                for k, v in sensor_data.items():
                    if "temp" in k and k.endswith("_input"):
                        try:
                            out["ambient_temp"] = float(v)
                            matched["ambient_temp"] = f"{adapter_name}/{label}"
                            break
                        except (TypeError, ValueError):
                            pass

            # NVMe temp: adapter containing "nvme", label "Composite"
            if out["nvme_temp"] is None and "nvme" in adapter_lower and label_lower == "composite":
                for k, v in sensor_data.items():
                    if "temp" in k and k.endswith("_input"):
                        try:
                            out["nvme_temp"] = float(v)
                            matched["nvme_temp"] = f"{adapter_name}/{label}"
                            break
                        except (TypeError, ValueError):
                            pass

            # Fan RPMs: any label containing "fan" with a fan*_input value
            if "fan" in label_lower:
                for k, v in sensor_data.items():
                    if "fan" in k and k.endswith("_input"):
                        try:
                            fan_hits.append((adapter_name, label, int(float(v))))
                            break
                        except (TypeError, ValueError):
                            pass

    # CPU fallback: highest individual core reading from any coretemp adapter
    if out["cpu_temp"] is None:
        best_temp, best_loc = None, None
        for adapter_name, adapter_data in s.items():
            if not isinstance(adapter_data, dict) or "coretemp" not in adapter_name.lower():
                continue
            for label, sensor_data in adapter_data.items():
                if not isinstance(sensor_data, dict):
                    continue
                for k, v in sensor_data.items():
                    if "temp" in k and k.endswith("_input"):
                        try:
                            t = float(v)
                            if best_temp is None or t > best_temp:
                                best_temp = t
                                best_loc = f"{adapter_name}/{label}"
                        except (TypeError, ValueError):
                            pass
        if best_temp is not None:
            out["cpu_temp"] = best_temp
            matched["cpu_temp"] = f"{best_loc} (coretemp max)"

    # Assign first 4 fan hits
    for i, (a, lbl, rpm) in enumerate(fan_hits[:4], start=1):
        out[f"fan{i}_rpm"] = rpm
        matched[f"fan{i}_rpm"] = f"{a}/{lbl}"

    # Log auto-discovery results once on startup
    if not _sensor_map_logged:
        _sensor_map_logged = True
        log.info("Sensor map (auto-discovery) — adapters found: %s",
                 ", ".join(available_adapters) or "(none)")
        for field, loc in matched.items():
            log.info("  Mapped %-16s -> %s", field, loc)
        if "ambient_temp" not in matched:
            log.warning(
                "No ambient temperature sensor found (no label containing 'Ambient'); "
                "available adapters: %s", ", ".join(available_adapters) or "(none)"
            )
        if not any(f"fan{i}_rpm" in matched for i in range(1, 5)):
            log.warning(
                "No fan speed sensors found (no label containing 'fan'); "
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
             fan1_rpm, fan2_rpm, fan3_rpm, fan4_rpm,
             cpu_percent, ram_used_gb,
             disk_read_mb, disk_write_mb, net_in_mb, net_out_mb,
             gpu_temp, gpu_fan_percent, gpu_power_watts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                s["timestamp"], s.get("cpu_temp"), s.get("ambient_temp"),
                s.get("nvme_temp"), s.get("fan1_rpm"), s.get("fan2_rpm"),
                s.get("fan3_rpm"), s.get("fan4_rpm"), s.get("cpu_percent"),
                s.get("ram_used_gb"), s.get("disk_read_mb"), s.get("disk_write_mb"),
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
                      fan1_rpm, fan2_rpm, fan3_rpm, fan4_rpm,
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
            "fan1_rpm", "fan2_rpm", "fan3_rpm", "fan4_rpm",
            "cpu_percent", "ram_used_gb",
            "disk_read_mb", "disk_write_mb", "net_in_mb", "net_out_mb",
            "gpu_temp", "gpu_fan_percent", "gpu_power_watts"]
    rows.reverse()
    return [dict(zip(cols, r)) for r in rows]


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
            log.info(
                "sample cpu=%s ambient=%s nvme=%s fans=%s/%s/%s cpu%%=%s ram=%sGB "
                "gpu=%s°C/%s%%/%sW net=%s/%sMB disk=%s/%sMB",
                sample.get("cpu_temp"), sample.get("ambient_temp"),
                sample.get("nvme_temp"), sample.get("fan1_rpm"),
                sample.get("fan2_rpm"), sample.get("fan3_rpm"),
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
