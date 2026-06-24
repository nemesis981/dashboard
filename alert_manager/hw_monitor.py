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
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from logging.handlers import RotatingFileHandler

import psutil

_HERE        = os.path.dirname(os.path.abspath(__file__))
DB_PATH      = os.path.join(_HERE, "alerts.db")
LOG_FILE     = os.path.join(_HERE, "hw_monitor.log")
HW_MAP_PATH  = os.path.join(_HERE, "hw_map.json")
NET_IFACE    = "enp131s0"
SAMPLE_INTERVAL  = 300
WA_LISTEN_PORT   = 5001   # port for Windows-agent POST receiver

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
                          ("fans_json", "TEXT"),
                          ("is_anomalous", "INTEGER DEFAULT 0"),
                          ("device_id", "TEXT DEFAULT 'local'")):
            if col not in existing:
                c.execute(f"ALTER TABLE hw_metrics ADD COLUMN {col} {decl}")
        conn.commit()

        # fan_status: permanent per-fan activity record keyed by unique_key.
        # ever_active is promoted to 1 the first time a fan reports RPM > 0
        # and never reverts.  This lets the dashboard distinguish "never-seen"
        # empty headers from "previously-spinning, currently-stopped" fans.
        c.execute("""
            CREATE TABLE IF NOT EXISTS fan_status (
                unique_key       TEXT PRIMARY KEY,
                label            TEXT NOT NULL,
                ever_active      INTEGER NOT NULL DEFAULT 0,
                first_active_at  TIMESTAMP
            )
        """)
        # Pre-populate rows for fans listed in hw_map.json (INSERT OR IGNORE so
        # we never reset ever_active state that was already recorded).
        try:
            with open(HW_MAP_PATH) as _mf:
                _hm = json.load(_mf)
                for _f in _hm.get("fans", []):
                    if "unique_key" in _f:
                        c.execute(
                            "INSERT OR IGNORE INTO fan_status "
                            "(unique_key, label, ever_active) VALUES (?, ?, 0)",
                            (_f["unique_key"], _f.get("label", _f["unique_key"]))
                        )
        except Exception:
            pass
        conn.commit()

        # hw_alerts: tracks currently-active hardware alert conditions.
        # Written by watchdog; read by the dashboard to show a persistent
        # alert list independent of the fan section's collapsed/expanded state.
        c.execute("""
            CREATE TABLE IF NOT EXISTS hw_alerts (
                alert_key         TEXT PRIMARY KEY,
                severity          TEXT NOT NULL,
                breach            TEXT NOT NULL,
                recommendation    TEXT NOT NULL,
                first_triggered_ts REAL NOT NULL,
                last_triggered_ts  REAL NOT NULL,
                resolved_ts        REAL
            )
        """)
        conn.commit()

        # hw_anomaly_snapshots: system context captured when a sensor reading
        # deviates >2σ from its rolling same-hour-of-day 14-day baseline.
        c.execute("""
            CREATE TABLE IF NOT EXISTS hw_anomaly_snapshots (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                sensor_key        TEXT NOT NULL,
                reading_value     REAL NOT NULL,
                baseline_avg      REAL,
                deviation         REAL,
                captured_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                top_processes     TEXT,
                cpu_pct           REAL,
                ram_mb            REAL,
                net_mb_in         REAL,
                net_mb_out        REAL,
                disk_mb_read      REAL,
                disk_mb_write     REAL,
                gpu_load          REAL,
                throttle_detected INTEGER DEFAULT 0,
                throttle_freq_mhz REAL,
                sustained         INTEGER DEFAULT 0
            )
        """)
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_hw_anom_sensor "
            "ON hw_anomaly_snapshots(sensor_key, captured_at)"
        )
        # device_id migration for hw_anomaly_snapshots
        existing_anom = {row[1] for row in c.execute("PRAGMA table_info(hw_anomaly_snapshots)").fetchall()}
        if "device_id" not in existing_anom:
            c.execute("ALTER TABLE hw_anomaly_snapshots ADD COLUMN device_id TEXT DEFAULT 'local'")

        # correlation_events: fired when ≥2 sensors are simultaneously anomalous.
        c.execute("""
            CREATE TABLE IF NOT EXISTS correlation_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                sensor_keys TEXT NOT NULL,
                captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                severity    TEXT NOT NULL DEFAULT 'HIGH'
            )
        """)

        # hw_notifications: dashboard notifications for sustained baseline drift.
        # Never auto-dismissed; user must call /api/hw/reset-baseline to clear.
        c.execute("""
            CREATE TABLE IF NOT EXISTS hw_notifications (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                sensor_key   TEXT NOT NULL UNIQUE,
                message      TEXT NOT NULL,
                created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                dismissed    INTEGER DEFAULT 0
            )
        """)
        conn.commit()

        # agent_devices: tracks devices reporting via nemesis_agent.
        c.execute("""
            CREATE TABLE IF NOT EXISTS agent_devices (
                device_id       TEXT PRIMARY KEY,
                device_name     TEXT,
                device_type     TEXT,
                ip_address      TEXT,
                connection_type TEXT,
                agent_last_seen TIMESTAMP,
                suricata_running INTEGER DEFAULT 0,
                suricata_profile TEXT,
                last_scan_at    TIMESTAMP,
                last_scan_result TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_agent_devices_seen ON agent_devices(agent_last_seen)")

        # scan_jobs: tracks malware scan executions per device.
        c.execute("""
            CREATE TABLE IF NOT EXISTS scan_jobs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id       TEXT NOT NULL,
                scan_id         TEXT NOT NULL UNIQUE,
                path            TEXT NOT NULL DEFAULT '/',
                status          TEXT NOT NULL DEFAULT 'queued',
                progress_pct    INTEGER DEFAULT 0,
                files_scanned   INTEGER DEFAULT 0,
                threats_found   INTEGER DEFAULT 0,
                started_at      TIMESTAMP,
                completed_at    TIMESTAMP
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_device ON scan_jobs(device_id, started_at)")

        # scan_threats: individual threat findings from scan jobs.
        c.execute("""
            CREATE TABLE IF NOT EXISTS scan_threats (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_job_id     INTEGER NOT NULL,
                device_id       TEXT NOT NULL,
                file_path       TEXT NOT NULL,
                threat_name     TEXT NOT NULL,
                action_taken    TEXT,
                detected_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # scan_schedules: per-device scan schedules.
        c.execute("""
            CREATE TABLE IF NOT EXISTS scan_schedules (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id       TEXT NOT NULL,
                schedule_type   TEXT NOT NULL DEFAULT 'weekly',
                scheduled_time  TEXT,
                last_run_at     TIMESTAMP,
                enabled         INTEGER DEFAULT 1
            )
        """)
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
                "unique_key": fan["unique_key"],
                "label":      fan["label"],
                "rpm":        int(rpm) if rpm is not None else None,
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
    out["fans"] = [{"unique_key": ukey, "label": lbl, "rpm": rpm}
                   for _, ukey, lbl, rpm in fan_hits]

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
    hw_map = _load_hw_map()
    if hw_map and hw_map.get("source") == "windows_agent":
        # In windows_agent mode the DB is the source of truth.  Return the
        # most recent sample written by the HTTP listener.
        samples = get_recent_samples(limit=1)
        if samples:
            m = samples[0].copy()
            m["fan_status"] = get_fan_status()
            return m
        return {
            "cpu_temp": None, "ambient_temp": None, "nvme_temp": None,
            "fans": [], "cpu_percent": None, "ram_used_gb": None,
            "ram_total_gb": None, "ram_percent": None,
            "gpu_temp": None, "gpu_fan_percent": None, "gpu_power_watts": None,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "fan_status": get_fan_status(),
        }

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
    metrics["fan_status"] = get_fan_status()
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


def _update_fan_status(c, fans):
    """Upsert fan_status rows and promote ever_active=1 for fans with RPM > 0.

    Called inside an already-open connection/cursor so the caller commits.
    """
    now = datetime.now().isoformat(timespec="seconds")
    for f in fans:
        ukey = f.get("unique_key")
        if not ukey:
            continue
        lbl = f.get("label", ukey)
        c.execute(
            "INSERT OR IGNORE INTO fan_status (unique_key, label, ever_active) "
            "VALUES (?, ?, 0)",
            (ukey, lbl),
        )
        rpm = f.get("rpm")
        if rpm is not None and int(rpm) > 0:
            c.execute(
                "UPDATE fan_status SET ever_active=1, first_active_at=? "
                "WHERE unique_key=? AND ever_active=0",
                (now, ukey),
            )


def insert_sample(s):
    device_id = s.get("device_id", "local")
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute(
            """INSERT INTO hw_metrics
            (timestamp, cpu_temp, ambient_temp, nvme_temp,
             fans_json,
             cpu_percent, ram_used_gb,
             disk_read_mb, disk_write_mb, net_in_mb, net_out_mb,
             gpu_temp, gpu_fan_percent, gpu_power_watts, is_anomalous, device_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)""",
            (
                s["timestamp"], s.get("cpu_temp"), s.get("ambient_temp"),
                s.get("nvme_temp"),
                json.dumps(s.get("fans", [])),
                s.get("cpu_percent"), s.get("ram_used_gb"),
                s.get("disk_read_mb"), s.get("disk_write_mb"),
                s.get("net_in_mb"), s.get("net_out_mb"),
                s.get("gpu_temp"), s.get("gpu_fan_percent"), s.get("gpu_power_watts"),
                device_id,
            ),
        )
        row_id = c.lastrowid
        _update_fan_status(c, s.get("fans", []))
        conn.commit()
        # Run anomaly pipeline in the background after committing the sample.
        try:
            _run_anomaly_pipeline(s, row_id)
        except Exception as e:
            log.warning("anomaly pipeline error: %s", e)
    finally:
        conn.close()


# ── Anomaly detection engine ──────────────────────────────────────────────────
# Checks each new sample against a rolling same-hour-of-day baseline computed
# from the past 14 days of hw_metrics rows.  Anomalous readings capture a
# process/context snapshot; sustained (≥3 consecutive) anomalies are flagged;
# simultaneous multi-sensor anomalies create a correlation_event.

# Scalar columns we run anomaly detection on (fan RPMs handled separately).
_ANOMALY_SENSORS = [
    "cpu_temp", "ambient_temp", "nvme_temp",
    "gpu_temp", "cpu_percent", "ram_used_gb",
]


def _get_scalar(sample: dict, key: str):
    """Return numeric value from sample dict, or None."""
    v = sample.get(key)
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _compute_baseline(conn, sensor_col: str, ts_str: str):
    """Rolling avg+stddev at the same hour-of-day over the past 14 days.

    Returns (avg, stddev, n_samples) or (None, None, 0) if insufficient data.
    """
    try:
        hour = datetime.fromisoformat(ts_str).hour
    except Exception:
        hour = datetime.now().hour

    rows = conn.execute(
        f"""SELECT {sensor_col}
            FROM hw_metrics
            WHERE {sensor_col} IS NOT NULL
              AND is_anomalous = 0
              AND strftime('%H', timestamp) = ?
              AND timestamp >= datetime('now', '-14 days')
            ORDER BY timestamp DESC""",
        (f"{hour:02d}",),
    ).fetchall()

    vals = [r[0] for r in rows if r[0] is not None]
    n = len(vals)
    if n < 5:
        return None, None, n
    avg = sum(vals) / n
    variance = sum((v - avg) ** 2 for v in vals) / n
    stddev = variance ** 0.5
    return avg, stddev, n


def _read_throttle_info():
    """Check /proc/cpuinfo for CPU throttling (current MHz vs nominal max).

    Returns (throttle_detected: bool, current_freq_mhz: float | None).
    """
    try:
        with open("/proc/cpuinfo") as f:
            text = f.read()
        freqs = []
        for line in text.splitlines():
            if line.startswith("cpu MHz"):
                try:
                    freqs.append(float(line.split(":")[1].strip()))
                except (IndexError, ValueError):
                    pass
        if not freqs:
            return False, None
        current = sum(freqs) / len(freqs)
        # Try to read max from scaling_max_freq (first CPU core)
        try:
            with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq") as f:
                max_freq = float(f.read().strip()) / 1000.0
        except Exception:
            max_freq = max(freqs)
        throttled = max_freq > 0 and (current < max_freq * 0.8)
        return throttled, round(current, 1)
    except Exception:
        return False, None


def _capture_process_list():
    """Top processes by CPU — first 2000 chars of 'ps aux --sort=-%cpu'."""
    try:
        result = subprocess.run(
            ["ps", "aux", "--sort=-%cpu"],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout[:2000]
    except Exception:
        return ""


def _capture_snapshot(conn, sensor_key: str, value: float,
                      baseline_avg, deviation: float, sample: dict):
    """Write an hw_anomaly_snapshots row for one anomalous reading."""
    throttled, freq_mhz = _read_throttle_info()
    procs = _capture_process_list()
    conn.execute(
        """INSERT INTO hw_anomaly_snapshots
           (sensor_key, reading_value, baseline_avg, deviation, captured_at,
            top_processes, cpu_pct, ram_mb, net_mb_in, net_mb_out,
            disk_mb_read, disk_mb_write, gpu_load,
            throttle_detected, throttle_freq_mhz)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            sensor_key, value, baseline_avg, deviation,
            sample.get("timestamp", datetime.now().isoformat(timespec="seconds")),
            procs,
            sample.get("cpu_percent"),
            (sample.get("ram_used_gb") or 0) * 1024,
            sample.get("net_in_mb"), sample.get("net_out_mb"),
            sample.get("disk_read_mb"), sample.get("disk_write_mb"),
            None,  # gpu_load — not separately tracked yet
            1 if throttled else 0,
            freq_mhz,
        ),
    )


def _check_sustained_anomalies(conn, sensor_key: str, n_required: int = 3):
    """Mark the last N snapshots for this sensor as sustained if all are consecutive."""
    recent = conn.execute(
        """SELECT id FROM hw_anomaly_snapshots
           WHERE sensor_key = ? AND sustained = 0
           ORDER BY captured_at DESC LIMIT ?""",
        (sensor_key, n_required),
    ).fetchall()
    if len(recent) >= n_required:
        ids = [r[0] for r in recent]
        conn.execute(
            f"UPDATE hw_anomaly_snapshots SET sustained=1 WHERE id IN ({','.join('?' * len(ids))})",
            ids,
        )
        log.info("anomaly: sustained (%d consecutive) on %s", n_required, sensor_key)


def _check_correlation(conn, anomalous_keys: list, ts_str: str):
    """If ≥2 sensors anomalous in the same sample window, record a correlation_event."""
    if len(anomalous_keys) < 2:
        return
    severity = "CRITICAL" if len(anomalous_keys) >= 3 else "HIGH"
    conn.execute(
        "INSERT INTO correlation_events (sensor_keys, captured_at, severity) VALUES (?,?,?)",
        (json.dumps(sorted(anomalous_keys)), ts_str, severity),
    )
    log.info("anomaly: correlation event — %s (%s)", anomalous_keys, severity)


def _check_baseline_drift(conn, sensor_key: str, baseline_avg, current_val: float):
    """If sensor has been outside baseline for 48+ hours, create/update a notification."""
    # Count consecutive anomalous samples in the past 48h for this sensor
    cutoff = "datetime('now', '-48 hours')"
    count = conn.execute(
        f"""SELECT COUNT(*) FROM hw_anomaly_snapshots
            WHERE sensor_key=? AND captured_at >= {cutoff}""",
        (sensor_key,),
    ).fetchone()[0]

    # Require at least 12 anomalous samples in 48h (avg 1 per 4h) to flag drift
    if count >= 12:
        msg = (
            f"Sensor '{sensor_key}' has been outside its historical baseline for 48+ hours "
            f"(current: {current_val:.1f}, baseline avg: {baseline_avg:.1f}). "
            "Hardware change? Click to reset baseline."
        )
        conn.execute(
            """INSERT INTO hw_notifications (sensor_key, message, created_at)
               VALUES (?,?,datetime('now'))
               ON CONFLICT(sensor_key) DO UPDATE
               SET message=excluded.message, created_at=excluded.created_at, dismissed=0""",
            (sensor_key, msg),
        )


def _run_anomaly_pipeline(sample: dict, row_id: int):
    """Run all anomaly checks for a newly-inserted sample row."""
    ts = sample.get("timestamp", datetime.now().isoformat(timespec="seconds"))
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        anomalous_keys = []
        any_anomalous = False

        for key in _ANOMALY_SENSORS:
            value = _get_scalar(sample, key)
            if value is None:
                continue
            avg, stddev, n = _compute_baseline(conn, key, ts)
            if avg is None or stddev is None or stddev < 0.5:
                continue
            deviation = (value - avg) / stddev
            if abs(deviation) > 2.0:
                _capture_snapshot(conn, key, value, avg, deviation, sample)
                _check_sustained_anomalies(conn, key)
                _check_baseline_drift(conn, key, avg, value)
                anomalous_keys.append(key)
                any_anomalous = True
                log.info(
                    "anomaly: %s=%.1f baseline=%.1f σ=%.1f (deviation=%.1fσ)",
                    key, value, avg, stddev, deviation,
                )

        if any_anomalous:
            conn.execute(
                "UPDATE hw_metrics SET is_anomalous=1 WHERE id=?", (row_id,)
            )

        _check_correlation(conn, anomalous_keys, ts)
        conn.commit()
    finally:
        conn.close()


def get_anomaly_snapshots(sensor_key=None, since_ts=None, limit=200):
    """Return hw_anomaly_snapshots rows for the dashboard endpoint."""
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        clauses, params = [], []
        if sensor_key:
            clauses.append("sensor_key = ?")
            params.append(sensor_key)
        if since_ts:
            clauses.append("captured_at >= ?")
            params.append(since_ts)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        rows = conn.execute(
            f"""SELECT id, sensor_key, reading_value, baseline_avg, deviation,
                       captured_at, top_processes, cpu_pct, ram_mb,
                       net_mb_in, net_mb_out, disk_mb_read, disk_mb_write,
                       throttle_detected, throttle_freq_mhz, sustained
                FROM hw_anomaly_snapshots {where}
                ORDER BY captured_at DESC LIMIT ?""",
            params,
        ).fetchall()
        cols = ("id", "sensor_key", "reading_value", "baseline_avg", "deviation",
                "captured_at", "top_processes", "cpu_pct", "ram_mb",
                "net_mb_in", "net_mb_out", "disk_mb_read", "disk_mb_write",
                "throttle_detected", "throttle_freq_mhz", "sustained")
        return [dict(zip(cols, r)) for r in rows]
    finally:
        conn.close()


def get_hw_notifications(include_dismissed=False):
    """Return active hardware baseline-drift notifications."""
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        where = "" if include_dismissed else "WHERE dismissed=0"
        rows = conn.execute(
            f"SELECT id, sensor_key, message, created_at FROM hw_notifications {where}"
        ).fetchall()
        return [{"id": r[0], "sensor_key": r[1], "message": r[2], "created_at": r[3]}
                for r in rows]
    finally:
        conn.close()


def reset_baseline(sensor_key=None):
    """Clear anomaly data for one sensor or all sensors.

    Called from /api/hw/reset-baseline.  Deletes hw_anomaly_snapshots rows
    and dismisses the matching hw_notifications so the next cycle starts fresh.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        if sensor_key and sensor_key != "all":
            conn.execute(
                "DELETE FROM hw_anomaly_snapshots WHERE sensor_key=?", (sensor_key,)
            )
            conn.execute(
                "UPDATE hw_notifications SET dismissed=1 WHERE sensor_key=?", (sensor_key,)
            )
            conn.execute(
                "UPDATE hw_metrics SET is_anomalous=0 WHERE id IN ("
                "  SELECT m.id FROM hw_metrics m "
                "  WHERE NOT EXISTS (SELECT 1 FROM hw_anomaly_snapshots s "
                "                   WHERE s.captured_at = m.timestamp))"
            )
        else:
            conn.execute("DELETE FROM hw_anomaly_snapshots")
            conn.execute("UPDATE hw_notifications SET dismissed=1")
            conn.execute("UPDATE hw_metrics SET is_anomalous=0")
        conn.commit()
        log.info("baseline reset for sensor=%s", sensor_key or "all")
    finally:
        conn.close()


def get_fan_status():
    """Return fan activity history keyed by unique_key.

    Returns:
      {unique_key: {"label": str, "ever_active": bool, "first_active_at": str|None}}
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        rows = conn.execute(
            "SELECT unique_key, label, ever_active, first_active_at FROM fan_status"
        ).fetchall()
    finally:
        conn.close()
    return {
        row[0]: {
            "label":           row[1],
            "ever_active":     bool(row[2]),
            "first_active_at": row[3],
        }
        for row in rows
    }


def get_hw_alerts():
    """Return active (unresolved) hardware alerts, newest-first.

    Each dict: {alert_key, severity, breach, recommendation,
                first_triggered_ts, last_triggered_ts}
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        rows = conn.execute(
            """SELECT alert_key, severity, breach, recommendation,
                      first_triggered_ts, last_triggered_ts
               FROM hw_alerts
               WHERE resolved_ts IS NULL
               ORDER BY last_triggered_ts DESC"""
        ).fetchall()
    except Exception:
        rows = []
    finally:
        conn.close()
    cols = ("alert_key", "severity", "breach", "recommendation",
            "first_triggered_ts", "last_triggered_ts")
    return [dict(zip(cols, r)) for r in rows]


def _bootstrap_fan_status():
    """On startup, immediately promote fans that are spinning right now.

    init_db() inserts fan_status rows with ever_active=0.  Without this call
    the first page load would show all fans as hidden until the first 5-minute
    sample fires.  Reading sensors once here lets currently-spinning fans be
    correctly visible from the very first request.
    """
    try:
        sensors = _read_sensors()
        fans = _extract_temps_and_fans(sensors).get("fans", [])
        if not fans:
            return
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        try:
            c = conn.cursor()
            _update_fan_status(c, fans)
            conn.commit()
        finally:
            conn.close()
        log.info("fan_status bootstrapped: %d fan(s), %d active",
                 len(fans),
                 sum(1 for f in fans if f.get("rpm") and f["rpm"] > 0))
    except Exception as e:
        log.warning("fan_status bootstrap failed: %s", e)


# ── Windows agent source ──────────────────────────────────────────────────────
# When hw_map.json contains {"source": "windows_agent"}, hw_monitor skips all
# lm-sensors reads and instead receives pre-labeled JSON sensor data from a
# Python agent running on the Windows host via POST /hw_data on port 5001.
#
# UFW: allow inbound on port 5001 from the Windows host IP only, e.g.:
#   sudo ufw allow from <host_ip> to any port 5001 proto tcp
# Do NOT expose this port globally — the listener has no authentication.


def _wa_payload_to_metrics(payload: dict) -> dict:
    """Convert a Windows-agent POST body to the metrics dict used by insert_sample().

    Expected payload shape:
      {
        "source": "windows_agent",
        "timestamp": "2026-06-22T13:00:00",
        "sensors": {
          "cpu_temp":    {"value": 65.0, "unit": "°C"},
          "gpu_temp":    {"value": 72.0, "unit": "°C"},
          "nvme_temp":   {"value": 41.0, "unit": "°C"},
          "ram_percent": {"value": 45.2, "unit": "%"},
          "fan1":        {"value": 1200,  "unit": "RPM", "name": "CPU Fan"},
          ...
        }
      }
    """
    sensors = payload.get("sensors", {})
    ts = payload.get("timestamp") or datetime.now().isoformat(timespec="seconds")

    def _val(key, cast=float):
        entry = sensors.get(key)
        if entry is None:
            return None
        try:
            return cast(entry["value"])
        except (KeyError, TypeError, ValueError):
            return None

    # Collect all fan* keys (excluding gpu_fan_percent which is its own field)
    fans = []
    for key, entry in sorted(sensors.items()):
        if key.startswith("fan") and key != "gpu_fan_percent":
            try:
                rpm = int(float(entry["value"]))
                label = entry.get("name") or key.replace("_", " ").title()
                fans.append({"unique_key": key, "label": label, "rpm": rpm})
            except (KeyError, TypeError, ValueError):
                pass

    return {
        "cpu_temp":        _val("cpu_temp"),
        "ambient_temp":    _val("ambient_temp"),
        "nvme_temp":       _val("nvme_temp"),
        "fans":            fans,
        "cpu_percent":     _val("cpu_percent"),
        "ram_used_gb":     _val("ram_used_gb"),
        "ram_total_gb":    _val("ram_total_gb"),
        "ram_percent":     _val("ram_percent"),
        "gpu_temp":        _val("gpu_temp", int),
        "gpu_fan_percent": _val("gpu_fan_percent", int),
        "gpu_power_watts": _val("gpu_power_watts"),
        "disk_read_mb":    _val("disk_read_mb"),
        "disk_write_mb":   _val("disk_write_mb"),
        "net_in_mb":       _val("net_in_mb"),
        "net_out_mb":      _val("net_out_mb"),
        "timestamp":       ts,
    }


def _nemesis_payload_to_metrics(payload):
    """Convert nemesis_agent payload format to the internal sample dict."""
    hw = payload.get("hardware", {})
    ts = payload.get("timestamp") or datetime.now().isoformat(timespec="seconds")

    def _val(key, cast=float):
        entry = hw.get(key)
        if entry is None:
            return None
        try:
            return cast(entry["value"])
        except (KeyError, TypeError, ValueError):
            return None

    fans = []
    for key, entry in sorted(hw.items()):
        if key.startswith("fan") and key not in ("gpu_fan_percent",):
            try:
                rpm = int(float(entry["value"]))
                label = entry.get("label") or key.replace("_", " ").title()
                fans.append({"unique_key": key, "label": label, "rpm": rpm})
            except (KeyError, TypeError, ValueError):
                pass

    # ram_mb in payload → ram_used_gb
    ram_mb = _val("ram_mb")
    ram_used_gb = round(ram_mb / 1024.0, 2) if ram_mb is not None else None

    return {
        "device_id":       payload.get("device_id", "local"),
        "timestamp":       ts,
        "cpu_temp":        _val("cpu_temp"),
        "ambient_temp":    _val("ambient_temp"),
        "nvme_temp":       _val("nvme_temp"),
        "fans":            fans,
        "cpu_percent":     _val("cpu_pct"),
        "ram_used_gb":     ram_used_gb,
        "gpu_temp":        _val("gpu_temp", int),
        "gpu_fan_percent": _val("gpu_fan_percent", int),
        "gpu_power_watts": _val("gpu_power_watts"),
        "disk_read_mb":    None,
        "disk_write_mb":   None,
        "net_in_mb":       None,
        "net_out_mb":      None,
    }


def _update_agent_device(payload):
    """Upsert agent_devices row from a nemesis_agent POST."""
    device_id   = payload.get("device_id", "local")
    device_name = payload.get("device_name", device_id)
    device_type = payload.get("device_type", "")
    conn_type   = payload.get("connection_type", "")
    ts          = payload.get("timestamp") or datetime.now().isoformat(timespec="seconds")
    ah          = payload.get("agent_health", {})
    suri_run    = 1 if ah.get("suricata_running") else 0
    suri_prof   = ah.get("suricata_profile") or ""
    last_scan   = ah.get("last_scan_at") or ""
    last_result = ah.get("last_scan_result") or ""

    # best-effort IP from request — not available in this context, skip
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        conn.execute("""
            INSERT INTO agent_devices
                (device_id, device_name, device_type, connection_type,
                 agent_last_seen, suricata_running, suricata_profile,
                 last_scan_at, last_scan_result)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                device_name     = excluded.device_name,
                device_type     = excluded.device_type,
                connection_type = excluded.connection_type,
                agent_last_seen = excluded.agent_last_seen,
                suricata_running= excluded.suricata_running,
                suricata_profile= excluded.suricata_profile,
                last_scan_at    = excluded.last_scan_at,
                last_scan_result= excluded.last_scan_result
        """, (device_id, device_name, device_type, conn_type,
              ts, suri_run, suri_prof, last_scan, last_result))
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("_update_agent_device failed: %s", e)


def get_agent_devices():
    """Return all agent_devices rows as list of dicts."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        rows = conn.execute(
            "SELECT device_id, device_name, device_type, ip_address, connection_type, "
            "agent_last_seen, suricata_running, suricata_profile, last_scan_at, last_scan_result "
            "FROM agent_devices ORDER BY agent_last_seen DESC"
        ).fetchall()
        conn.close()
    except Exception:
        return []
    cols = ["device_id", "device_name", "device_type", "ip_address", "connection_type",
            "agent_last_seen", "suricata_running", "suricata_profile", "last_scan_at", "last_scan_result"]
    return [dict(zip(cols, r)) for r in rows]


def get_hw_devices():
    """Return distinct device_ids seen in hw_metrics last 24h with their latest readings."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        rows = conn.execute("""
            SELECT m.device_id,
                   m.timestamp,
                   m.cpu_temp, m.gpu_temp, m.cpu_percent, m.ram_used_gb
            FROM hw_metrics m
            INNER JOIN (
                SELECT device_id, MAX(timestamp) AS max_ts
                FROM hw_metrics
                WHERE timestamp >= datetime('now', '-24 hours')
                GROUP BY device_id
            ) latest ON m.device_id = latest.device_id AND m.timestamp = latest.max_ts
        """).fetchall()
        conn.close()
    except Exception:
        return []
    result = []
    for device_id, ts, cpu_t, gpu_t, cpu_pct, ram_gb in rows:
        result.append({
            "device_id":   device_id,
            "last_seen":   ts,
            "cpu_temp":    cpu_t,
            "gpu_temp":    gpu_t,
            "cpu_percent": cpu_pct,
            "ram_used_gb": ram_gb,
        })
    return result


def get_recent_samples_for_device(device_id, limit=288):
    """Return up to `limit` samples for a specific device_id, oldest first."""
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
               WHERE device_id = ?
               ORDER BY id DESC
               LIMIT ?""",
            (device_id, limit),
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


def _start_windows_agent_listener():
    """Start the background HTTP listener for both windows_agent and nemesis_agent POSTs.

    Runs in a daemon thread so it exits automatically when the main process ends.
    Calls insert_sample() on every valid POST so the dashboard reads from the DB.
    """

    class _WaHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # silence default per-request stdout logging

        def do_POST(self):
            if self.path != "/hw_data":
                self.send_response(404)
                self.end_headers()
                return
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                payload = json.loads(body)
            except Exception as e:
                log.warning("agent listener: bad POST body: %s", e)
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"bad request"}')
                return

            source = payload.get("source", "")
            if source not in ("windows_agent", "nemesis_agent"):
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"unknown source"}')
                return

            try:
                if source == "nemesis_agent":
                    metrics = _nemesis_payload_to_metrics(payload)
                    _update_agent_device(payload)
                    insert_sample(metrics)
                    log.info(
                        "nemesis_agent: sample device=%s cpu=%s°C gpu=%s°C conn=%s",
                        payload.get("device_id"), metrics.get("cpu_temp"),
                        metrics.get("gpu_temp"), payload.get("connection_type"),
                    )
                else:
                    metrics = _wa_payload_to_metrics(payload)
                    insert_sample(metrics)
                    log.info(
                        "windows_agent: sample cpu=%s°C gpu=%s°C fans=%d cpu%%=%s",
                        metrics.get("cpu_temp"), metrics.get("gpu_temp"),
                        len(metrics.get("fans", [])), metrics.get("cpu_percent"),
                    )
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
            except Exception as e:
                log.exception("agent listener: failed to store sample: %s", e)
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"internal error"}')

    def _serve():
        try:
            server = HTTPServer(("0.0.0.0", WA_LISTEN_PORT), _WaHandler)
            log.info("Agent listener started on port %d (windows_agent + nemesis_agent)", WA_LISTEN_PORT)
            server.serve_forever()
        except Exception as e:
            log.error("agent listener failed to start: %s", e)

    t = threading.Thread(target=_serve, daemon=True, name="wa-listener")
    t.start()


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

    # Always start the agent listener so remote nemesis_agent devices can POST.
    _start_windows_agent_listener()

    # Detect windows_agent mode — skip local sensor collection if Windows agent is the source.
    hw_map = _load_hw_map()
    if hw_map and hw_map.get("source") == "windows_agent":
        # Main thread must stay alive to keep the daemon listener thread running.
        while _running:
            _sleep_interruptible(60)
        log.info("hw_monitor stopped")
        return

    _bootstrap_fan_status()
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
