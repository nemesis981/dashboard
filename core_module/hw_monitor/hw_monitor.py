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
import data_manager
import database          # canonical DDL owner (init_scan_tables) — see init_db
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler

import psutil

_HERE        = os.path.dirname(os.path.abspath(__file__))
import nemesis_paths
DB_PATH      = nemesis_paths.db_path(os.path.join(_HERE, "alerts.db"))
# systemd sets $LOGS_DIRECTORY when the unit declares LogsDirectory=. Falling
# back to _HERE keeps the pre-migration unit working unchanged.
LOG_FILE     = os.path.join(os.environ.get("LOGS_DIRECTORY", _HERE), "hw_monitor.log")
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

# ── :5001 pacing ─────────────────────────────────────────────────────────────
# Token-bucket rate pacing for the agent channel, replacing the deferred
# `ufw limit 5001/tcp`. :5001 has NO reverse proxy in front of it (verified
# 2026-07-29: nginx fronts :80 -> :5000 only and has no 5001 stanza), so this
# cannot live in nginx without first putting nginx in front of the agent
# channel. It is therefore in-process. Disable with NEMESIS_5001_PACING=0;
# all thresholds are env-tunable — see agent_pacing.from_env().
import agent_pacing  # noqa: E402

_PACER = agent_pacing.from_env()
if _PACER is None:
    log.warning("agent listener: :5001 pacing DISABLED (NEMESIS_5001_PACING=0)")
else:
    log.info("agent listener: :5001 pacing active — %.1f req/s sustained, "
             "burst %.0f, max pace %.1fs", _PACER.rate, _PACER.burst,
             _PACER.max_delay)

# Prime psutil so the first cpu_percent() call returns a real value rather than 0.
psutil.cpu_percent(interval=None, percpu=True)

_state = {
    "disk": psutil.disk_io_counters(),
    "net": psutil.net_io_counters(pernic=True).get(NET_IFACE),
    "ts": time.monotonic(),
}

_running = True


# ── Data Manager wiring (ADR 0001/0006 retrofit, 2026-07-28) ─────────────────
_DM = None


def _db_connect():
    """Guarded connection scoped to this process's namespace.

    WARN MODE during the retrofit: every write outside the declared namespace is
    logged as ``WOULD DENY`` and then ALLOWED. The namespace table list came from
    static analysis of this file, which cannot see conditional SQL or statements
    built elsewhere — so it is treated as a hypothesis to be disproved by real
    traffic, not as a finished list. Flip to MODE_ENFORCE only once the journal
    is quiet across a representative period.
    """
    global _DM
    if _DM is None:
        _DM = data_manager.DataManager(DB_PATH)
        data_manager.set_namespace_mode("hw_monitor", data_manager.MODE_WARN)
    return _DM.connect("hw_monitor")


def _stop(signum, _frame):
    global _running
    log.info("received signal %s, shutting down", signum)
    _running = False


def init_db():
    conn = _db_connect()
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

        # hw_alerts is created and owned by watchdog (sole writer); this module
        # only reads it via the exception-guarded get_hw_alerts(). See ADR 0001 /
        # Pass 0 Stage 4: duplicate CREATE collapsed to the writer's process.

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
                last_scan_result TEXT,
                enrollment_status TEXT DEFAULT 'approved',
                public_key       TEXT,
                enrolled_by      TEXT,
                enrolled_at      TEXT,
                os               TEXT,
                os_version       TEXT,
                hardware_summary TEXT,
                interface_name   TEXT,
                connection_speed TEXT,
                lhm_available    INTEGER DEFAULT 0,
                last_heartbeat_data TEXT,
                pre_enrollment_scan TEXT,
                enrollment_has_findings INTEGER DEFAULT 0,
                link_type TEXT,
                hw_stable_id TEXT,
                hw_signals_used TEXT,
                hw_signal_hashes TEXT,
                hw_fp_confidence TEXT,
                hw_fp_schema_version INTEGER,
                hw_fp_locked_at REAL,
                hw_is_virtual INTEGER DEFAULT 0
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

        # scan_threats / scan_schedules: DDL moved to alert_manager/database.py
        # 2026-07-29 (init_scan_tables). hw_monitor never wrote a ROW to either —
        # dashboard owns both — and holding the CREATE here forced a full table
        # grant covering writes it does not perform. The call below still runs at
        # exactly this point in startup, so ordering is unchanged; it just issues
        # the CREATE on database.py's own raw connection instead of this process's
        # guarded one. Keep the call: there is no systemd ordering between the
        # services, so every process that needs the tables creates them itself.
        conn.commit()
        database.init_scan_tables()

        # agent_devices migrations: add columns introduced after initial schema.
        existing_ag = {row[1] for row in c.execute("PRAGMA table_info(agent_devices)").fetchall()}
        for col, decl in (("ip_address",        "TEXT"),
                          ("known_users_json",   "TEXT DEFAULT '[]'"),
                          ("known_usb_json",     "TEXT DEFAULT '[]'"),
                          # ── owner-gated enrollment layer (ONE migration, all columns) ──
                          ("enrollment_status",  "TEXT DEFAULT 'approved'"),  # grandfather existing devices
                          ("public_key",         "TEXT"),
                          ("enrolled_by",        "TEXT"),
                          ("enrolled_at",        "TEXT"),
                          ("os",                 "TEXT"),
                          ("os_version",         "TEXT"),
                          ("hardware_summary",   "TEXT"),
                          ("interface_name",     "TEXT"),
                          ("connection_speed",   "TEXT"),
                          ("lhm_available",      "INTEGER DEFAULT 0"),
                          ("last_heartbeat_data", "TEXT"),
                          # ── pre-enrollment scan (scan-before-trust) ──
                          ("pre_enrollment_scan", "TEXT"),
                          ("enrollment_has_findings", "INTEGER DEFAULT 0"),
                          ("link_type", "TEXT"),
                          # ── hardware-stable-ID fingerprint (ADR 0011 / TOFU) ──
                          ("hw_stable_id",        "TEXT"),
                          ("hw_signals_used",     "TEXT"),
                          ("hw_signal_hashes",    "TEXT"),
                          ("hw_fp_confidence",    "TEXT"),
                          ("hw_fp_schema_version", "INTEGER"),
                          ("hw_fp_locked_at",     "REAL"),
                          ("hw_is_virtual",       "INTEGER DEFAULT 0"),
                          # ── de-enroll on uninstall (clean-uninstall build spec) ──
                          ("uninstalled_at",      "TEXT"),
                          ("uninstalled_by",      "TEXT")):   # actor seam (device self / admin)
            if col not in existing_ag:
                c.execute(f"ALTER TABLE agent_devices ADD COLUMN {col} {decl}")
        conn.commit()

        # scan_queue: pending, executing and completed auto-triggered scans.
        c.execute("""
            CREATE TABLE IF NOT EXISTS scan_queue (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id       TEXT NOT NULL,
                trigger_type    TEXT NOT NULL,
                trigger_detail  TEXT,
                scan_path       TEXT DEFAULT '/',
                queued_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status          TEXT DEFAULT 'pending',
                executed_at     TIMESTAMP,
                scan_job_id     TEXT
            )
        """)
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_queue_device "
            "ON scan_queue(device_id, status)"
        )

        # scan_conditions: configurable rules that auto-queue scans.
        # NULL device_id means applies to all devices.
        c.execute("""
            CREATE TABLE IF NOT EXISTS scan_conditions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id       TEXT,
                condition_type  TEXT NOT NULL,
                condition_value TEXT,
                enabled         INTEGER DEFAULT 1,
                scan_path       TEXT DEFAULT '/'
            )
        """)
        conn.commit()

        # Seed default conditions if the table is empty.
        if c.execute("SELECT COUNT(*) FROM scan_conditions").fetchone()[0] == 0:
            defaults = [
                (None, "first_connect",      None,  1, "/"),
                (None, "return_from_remote", None,  1, "/"),
                (None, "extended_absence",   "24",  1, "/"),
                (None, "new_login",          None,  1, "/"),
                (None, "usb_inserted",       None,  1, "/"),
            ]
            c.executemany(
                "INSERT INTO scan_conditions "
                "(device_id, condition_type, condition_value, enabled, scan_path) "
                "VALUES (?, ?, ?, ?, ?)",
                defaults,
            )
            conn.commit()
            log.info("init_db: seeded 5 default scan conditions")

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
    conn = _db_connect()
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
    conn = _db_connect()
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
    conn = _db_connect()
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
    conn = _db_connect()
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
    conn = _db_connect()
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
    conn = _db_connect()
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
    conn = _db_connect()
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
        conn = _db_connect()
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


def _update_agent_device(payload, remote_ip=None):
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

    try:
        conn = _db_connect()
        try:
            if remote_ip:
                conn.execute("""
                    INSERT INTO agent_devices
                        (device_id, device_name, device_type, ip_address, connection_type,
                         agent_last_seen, suricata_running, suricata_profile,
                         last_scan_at, last_scan_result)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(device_id) DO UPDATE SET
                        device_name     = excluded.device_name,
                        device_type     = excluded.device_type,
                        ip_address      = excluded.ip_address,
                        connection_type = excluded.connection_type,
                        agent_last_seen = excluded.agent_last_seen,
                        suricata_running= excluded.suricata_running,
                        suricata_profile= excluded.suricata_profile,
                        last_scan_at    = excluded.last_scan_at,
                        last_scan_result= excluded.last_scan_result
                """, (device_id, device_name, device_type, remote_ip, conn_type,
                      ts, suri_run, suri_prof, last_scan, last_result))
            else:
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
            lt = payload.get("link_type")
            if lt:
                conn.execute("UPDATE agent_devices SET link_type=? WHERE device_id=?",
                             (lt, device_id))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        log.warning("_update_agent_device failed: %s", e)


# ── Scan queue trigger engine ─────────────────────────────────────────────────

import re as _re
import uuid as _uuid_mod
import urllib.request as _urllib_req


_LOGIN_USER_RE = _re.compile(
    r"for user (\w+)|session opened for (\w+)|Accepted \w+ for (\w+)"
)


def _extract_usernames(login_events):
    """Best-effort username extraction from login_events list."""
    users = set()
    for ev in login_events:
        raw = ev.get("raw", "") if isinstance(ev, dict) else str(ev)
        for m in _LOGIN_USER_RE.finditer(raw):
            u = next(g for g in m.groups() if g)
            if u not in ("root", "uid=0", "session"):
                users.add(u)
    return users


def _extract_usb_names(usb_events):
    """Return a set of short USB device identifiers from usb_events list."""
    names = set()
    for ev in usb_events:
        raw = ev.get("raw", "") if isinstance(ev, dict) else str(ev)
        raw = raw.strip()
        if raw:
            # Use first 80 chars as a stable key
            names.add(raw[:80])
    return names


def _queue_scan(device_id, trigger_type, trigger_detail, scan_path):
    """Insert into scan_queue if no pending entry already exists for this device."""
    try:
        conn = _db_connect()
        try:
            existing = conn.execute(
                "SELECT id FROM scan_queue WHERE device_id=? AND status='pending'",
                (device_id,),
            ).fetchone()
            if not existing:
                conn.execute(
                    "INSERT INTO scan_queue "
                    "(device_id, trigger_type, trigger_detail, scan_path) "
                    "VALUES (?, ?, ?, ?)",
                    (device_id, trigger_type, trigger_detail or "", scan_path or "/"),
                )
                conn.commit()
                log.info(
                    "scan queued: device=%s trigger=%s detail=%s",
                    device_id, trigger_type, trigger_detail,
                )
        finally:
            conn.close()
    except Exception as e:
        log.warning("_queue_scan failed: %s", e)


def _check_and_queue_scan_triggers(payload):
    """Evaluate all enabled scan_conditions against the incoming payload.

    Must be called BEFORE _update_agent_device so the previous device state
    is still in the database.
    """
    device_id = payload.get("device_id", "local")
    conn_type = payload.get("connection_type", "")
    security  = payload.get("security", {}) or {}

    try:
        conn = _db_connect()

        # Previous device state (before this payload)
        prev = conn.execute(
            "SELECT connection_type, agent_last_seen, known_users_json, known_usb_json "
            "FROM agent_devices WHERE device_id=?",
            (device_id,),
        ).fetchone()
        is_first_connect = prev is None
        prev_conn_type   = prev[0] if prev else None
        prev_last_seen   = prev[1] if prev else None
        known_users      = set(json.loads(prev[2] or "[]")) if prev else set()
        known_usb        = set(json.loads(prev[3] or "[]")) if prev else set()

        # Active conditions: device-specific overrides globals, NULL = all devices
        cond_rows = conn.execute(
            "SELECT condition_type, condition_value, scan_path FROM scan_conditions "
            "WHERE enabled=1 AND (device_id IS NULL OR device_id=?) "
            "ORDER BY device_id NULLS LAST",   # device-specific takes precedence
            (device_id,),
        ).fetchall()
        conn.close()

        # Build map: keep last (most-specific) entry per condition_type
        conditions = {}
        for ctype, cval, cpath in cond_rows:
            conditions[ctype] = (cval, cpath or "/")

        # ── 1. first_connect ─────────────────────────────────────────────────
        if is_first_connect and "first_connect" in conditions:
            _, cpath = conditions["first_connect"]
            _queue_scan(device_id, "first_connect", None, cpath)

        # ── 2. return_from_remote ────────────────────────────────────────────
        if (prev_conn_type == "vpn_remote" and conn_type == "local"
                and "return_from_remote" in conditions):
            _, cpath = conditions["return_from_remote"]
            _queue_scan(device_id, "return_from_remote", None, cpath)

        # ── 3. extended_absence ──────────────────────────────────────────────
        if prev_last_seen and "extended_absence" in conditions:
            threshold_h, cpath = conditions["extended_absence"]
            try:
                threshold_h = float(threshold_h or 24)
                last_dt     = datetime.fromisoformat(prev_last_seen)
                hours_absent = (datetime.now() - last_dt).total_seconds() / 3600
                if hours_absent >= threshold_h:
                    detail = f"absent {int(hours_absent)}h"
                    _queue_scan(device_id, "extended_absence", detail, cpath)
            except Exception:
                pass

        # ── 4. new_login ─────────────────────────────────────────────────────
        if "new_login" in conditions:
            _, cpath = conditions["new_login"]
            current_users = _extract_usernames(security.get("login_events", []))
            new_users = current_users - known_users
            if new_users:
                detail = "new user: " + ", ".join(sorted(new_users))
                _queue_scan(device_id, "new_login", detail, cpath)
                _persist_known_set(device_id, "known_users_json",
                                   known_users | current_users)

        # ── 5. usb_inserted ──────────────────────────────────────────────────
        if "usb_inserted" in conditions:
            _, cpath = conditions["usb_inserted"]
            current_usb = _extract_usb_names(security.get("usb_events", []))
            new_usb = current_usb - known_usb
            if new_usb:
                detail = "USB: " + list(new_usb)[0][:60]
                _queue_scan(device_id, "usb_inserted", detail, cpath)
                _persist_known_set(device_id, "known_usb_json",
                                   known_usb | current_usb)

    except Exception as e:
        log.warning("_check_and_queue_scan_triggers failed for %s: %s", device_id, e)


def _persist_known_set(device_id, column, values):
    """Write an updated known-users/usb set back to agent_devices."""
    try:
        conn = _db_connect()
        # Cap at 500 entries to avoid unbounded growth
        trimmed = list(values)[-500:]
        conn.execute(
            f"UPDATE agent_devices SET {column}=? WHERE device_id=?",
            (json.dumps(trimmed), device_id),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log.debug("_persist_known_set failed: %s", e)


def _dispatch_pending_scans(device_id, agent_ip):
    """Send the oldest pending queued scan to the agent right now.

    Called immediately after a payload is processed so reconnecting devices
    execute their queued scans without needing a manual trigger.
    For device_id='local' the scan runs in-process via subprocess.
    """
    try:
        conn = _db_connect()
        rows = conn.execute(
            "SELECT id, scan_path FROM scan_queue "
            "WHERE device_id=? AND status='pending' "
            "ORDER BY queued_at LIMIT 1",
            (device_id,),
        ).fetchall()
        conn.close()

        for queue_id, scan_path in rows:
            scan_id = str(_uuid_mod.uuid4())

            # Record in scan_jobs
            conn = _db_connect()
            conn.execute(
                "INSERT INTO scan_jobs (device_id, scan_id, path, status, started_at) "
                "VALUES (?, ?, ?, 'running', ?)",
                (device_id, scan_id, scan_path or "/", datetime.now().isoformat()),
            )
            conn.execute(
                "UPDATE scan_queue SET status='executing', executed_at=?, scan_job_id=? "
                "WHERE id=?",
                (datetime.now().isoformat(), scan_id, queue_id),
            )
            conn.commit()
            conn.close()

            if device_id == "local":
                # Import lazily to avoid circular dependency; dashboard.py owns this fn
                # but hw_monitor.py runs as a daemon too.  Use subprocess directly.
                import shutil as _shutil
                import threading as _threading
                if _shutil.which("clamscan"):
                    _t = _threading.Thread(
                        target=_local_clamscan_thread,
                        args=(scan_id, scan_path or "/"),
                        daemon=True,
                    )
                    _t.start()
                    log.info("dispatched local clamscan: queue_id=%d scan_id=%s", queue_id, scan_id)
            elif agent_ip:
                try:
                    import urllib.request as _ur
                    import urllib.error
                    body = json.dumps({
                        "action": "scan",
                        "path":    scan_path or "/",
                        "scan_id": scan_id,
                    }).encode()
                    req = _ur.Request(
                        f"http://{agent_ip}:5002",
                        data=body,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    _ur.urlopen(req, timeout=5)
                    log.info(
                        "dispatched queued scan to agent %s: queue_id=%d scan_id=%s",
                        agent_ip, queue_id, scan_id,
                    )
                except Exception as e:
                    log.warning("could not dispatch scan to agent %s: %s", agent_ip, e)

    except Exception as e:
        log.warning("_dispatch_pending_scans failed for %s: %s", device_id, e)


def _local_clamscan_thread(scan_id, path):
    """Minimal local clamscan runner for hw_monitor daemon context."""
    import shutil as _shutil
    import subprocess as _sp
    import os as _os
    log_file = f"/tmp/nemesis-scan-{scan_id}.log"
    try:
        proc = _sp.Popen(
            ["clamscan", "-r", path, "--no-summary", f"--log={log_file}"],
            stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
        )
        proc.wait()
        threats = []
        files_scanned = 0
        try:
            with open(log_file) as f:
                for line in f:
                    if ": " in line:
                        files_scanned += 1
                    if "FOUND" in line:
                        threats.append(line.strip())
        except Exception:
            pass
        status = "threats_found" if threats else "clean"
        conn = _db_connect()
        conn.execute(
            "UPDATE scan_jobs SET status=?, files_scanned=?, threats_found=?, "
            "progress_pct=100, completed_at=? WHERE scan_id=?",
            (status, files_scanned, len(threats), datetime.now().isoformat(), scan_id),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("_local_clamscan_thread failed: %s", e)
    finally:
        try:
            _os.unlink(log_file)
        except Exception:
            pass


# ── Public scan-queue / scan-conditions accessors ────────────────────────────

def get_scan_queue(status=None):
    """Return scan_queue rows as list of dicts, optionally filtered by status."""
    try:
        conn = _db_connect()
        if status:
            rows = conn.execute(
                "SELECT id, device_id, trigger_type, trigger_detail, scan_path, "
                "queued_at, status, executed_at, scan_job_id "
                "FROM scan_queue WHERE status=? ORDER BY queued_at",
                (status,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, device_id, trigger_type, trigger_detail, scan_path, "
                "queued_at, status, executed_at, scan_job_id "
                "FROM scan_queue ORDER BY queued_at DESC LIMIT 200"
            ).fetchall()
        conn.close()
    except Exception:
        return []
    cols = ["id", "device_id", "trigger_type", "trigger_detail", "scan_path",
            "queued_at", "status", "executed_at", "scan_job_id"]
    return [dict(zip(cols, r)) for r in rows]


def get_scan_conditions():
    """Return all scan_conditions rows as list of dicts."""
    try:
        conn = _db_connect()
        rows = conn.execute(
            "SELECT id, device_id, condition_type, condition_value, enabled, scan_path "
            "FROM scan_conditions ORDER BY id"
        ).fetchall()
        conn.close()
    except Exception:
        return []
    cols = ["id", "device_id", "condition_type", "condition_value", "enabled", "scan_path"]
    return [dict(zip(cols, r)) for r in rows]


def add_scan_condition(device_id, condition_type, condition_value, enabled, scan_path):
    try:
        conn = _db_connect()
        conn.execute(
            "INSERT INTO scan_conditions "
            "(device_id, condition_type, condition_value, enabled, scan_path) "
            "VALUES (?, ?, ?, ?, ?)",
            (device_id or None, condition_type, condition_value or None,
             1 if enabled else 0, scan_path or "/"),
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        log.warning("add_scan_condition failed: %s", e)
        return False


def delete_scan_condition(condition_id):
    try:
        conn = _db_connect()
        conn.execute("DELETE FROM scan_conditions WHERE id=?", (condition_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        log.warning("delete_scan_condition failed: %s", e)
        return False


def cancel_queue_item(queue_id):
    try:
        conn = _db_connect()
        conn.execute(
            "UPDATE scan_queue SET status='cancelled' WHERE id=? AND status='pending'",
            (queue_id,),
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        log.warning("cancel_queue_item failed: %s", e)
        return False


def get_pending_count_per_device():
    """Return {device_id: pending_count} for all devices with pending queue items."""
    try:
        conn = _db_connect()
        rows = conn.execute(
            "SELECT device_id, COUNT(*) FROM scan_queue "
            "WHERE status='pending' GROUP BY device_id"
        ).fetchall()
        conn.close()
        return {r[0]: r[1] for r in rows}
    except Exception:
        return {}


def get_agent_devices():
    """Return all agent_devices rows as list of dicts."""
    try:
        conn = _db_connect()
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
        conn = _db_connect()
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
    conn = _db_connect()
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


# ── Owner-gated agent enrollment (machine-to-machine; NOT Flask-Login guarded —
#    this is the raw 5001 http.server, the keypair signature is the agent's auth) ──
def _agent_enrollment_status(device_id):
    if not device_id:
        return None
    try:
        conn = _db_connect()
        row = conn.execute("SELECT enrollment_status FROM agent_devices WHERE device_id=?",
                           (device_id,)).fetchone()
        conn.close()
        return row[0] if row else None
    except Exception:
        log.exception("agent enrollment-status lookup failed")
        return None


def _reputation_dataset():
    """Feature 6 (observation-only): read the server's IP-reputation rows for an
    approved agent's local measurement cache. Read-only, best-effort → [] on any
    error (e.g. ip_enrichment table absent on a fresh box)."""
    try:
        conn = _db_connect()
        rows = conn.execute(
            "SELECT ip, abuse_score, threat_level, total_reports, last_checked "
            "FROM ip_enrichment").fetchall()
        conn.close()
        return [{"ip": r[0], "abuse_score": r[1], "threat_level": r[2],
                 "total_reports": r[3], "last_checked": r[4]} for r in rows]
    except Exception:
        log.exception("reputation dataset read failed")
        return []


def _agent_approved(device_id):
    return _agent_enrollment_status(device_id) == "approved"


def _verify_enroll_signature(public_key_pem, message, signature_b64):
    """Verify the enroll signature against the submitted public key (proof of
    possession). Returns True/False; never raises."""
    try:
        import base64
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes, serialization
        pub = serialization.load_pem_public_key(public_key_pem.encode())
        pub.verify(base64.b64decode(signature_b64), message.encode(),
                   padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


_HWID_MOD = None


def _match_fingerprint(incoming, stored):
    """TOFU "same device?" comparison, delegating to the canonical pure implementation in
    nemesis_agent/hwid.py (loaded by absolute path — single source of truth, no drift, no
    sys.path mutation). Returns (outcome, matched_device_id, matched_signal_count) with
    outcome 'exact' | 'partial' | 'none'. Informational — never gates enrollment."""
    global _HWID_MOD
    if _HWID_MOD is None:
        import importlib.util
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "nemesis_agent", "hwid.py")
        spec = importlib.util.spec_from_file_location("nemesis_hwid", path)
        _HWID_MOD = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_HWID_MOD)
    return _HWID_MOD.match_fingerprint(incoming, stored)


def _create_uninstall(payload, remote_ip):
    """De-enroll (soft) — a device signs off its own enrollment (clean-uninstall build spec §4).
    Proof-of-possession per ADR 0011: the request must be signed by the ENROLLED device's keypair
    (verified against the STORED public key, and the submitted key must match on file), so an
    attacker who only knows a device_id cannot de-enroll it. On success, marks the row
    enrollment_status='uninstalled' + uninstalled_at/uninstalled_by (actor seam). IDEMPOTENT:
    unknown or already-uninstalled device returns (True, <status>) — no error. Never deletes the
    row (preserves history / TOFU record; a hard 'forget device' is a separate admin action).
    Signed message contract: 'uninstall|<device_id>|<signed_at>' (PKCS1v15 / SHA-256)."""
    device_id  = (payload.get("device_id") or "").strip()
    public_key = payload.get("public_key", "") or ""
    signed_at  = payload.get("signed_at", "") or ""
    signature  = payload.get("signature", "") or ""
    if not device_id:
        return (False, "missing_device_id")
    try:
        conn = _db_connect()
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT enrollment_status, public_key FROM agent_devices "
                           "WHERE device_id=?", (device_id,)).fetchone()
        if row is None:
            conn.close()
            return (True, "not_found")          # idempotent: nothing to de-enroll
        stored_pub = row["public_key"] or ""
        msg = f"uninstall|{device_id}|{signed_at}"
        authed = (bool(stored_pub) and public_key == stored_pub
                  and _verify_enroll_signature(stored_pub, msg, signature))
        if not authed:
            conn.close()
            return (False, "bad_signature")
        if row["enrollment_status"] == "uninstalled":
            conn.close()
            return (True, "uninstalled")        # idempotent: already done
        now = datetime.now().isoformat(timespec="seconds")
        conn.execute("UPDATE agent_devices SET enrollment_status='uninstalled', "
                     "uninstalled_at=?, uninstalled_by=? WHERE device_id=?",
                     (now, "agent:self", device_id))   # actor: device-initiated (signed)
        conn.commit()
        conn.close()
        log.info("agent de-enroll: %s marked uninstalled", device_id)
        return (True, "uninstalled")
    except Exception:
        log.exception("de-enroll failed")
        return (False, "db_error")


def _create_enrollment(payload, remote_ip):
    """Verify the signed request, create a PENDING agent_devices row, open an
    approval ticket. Returns (device_id, status) or (None, error_str)."""
    public_key  = payload.get("public_key", "") or ""
    device_name = (payload.get("device_name") or "device").strip()
    os_name     = payload.get("os", "") or ""
    signed_at   = payload.get("signed_at", "") or ""
    signature   = payload.get("signature", "") or ""
    if not (public_key and signature and signed_at):
        return None, "missing_fields"
    if not _verify_enroll_signature(public_key, f"{device_name}|{os_name}|{signed_at}", signature):
        return None, "bad_signature"

    # ── pre-enrollment scan (scan-before-trust) — parse + summarize ──
    scan = {}
    scan_raw = payload.get("pre_enrollment_scan")
    if isinstance(scan_raw, str):
        try:
            scan = json.loads(scan_raw)
        except Exception:
            scan = {}
    elif isinstance(scan_raw, dict):
        scan = scan_raw
    scan_json = json.dumps(scan) if scan else None
    scan_status = scan.get("scan_status")
    clam_f = int(scan.get("clamav_findings") or 0)
    yara_f = int(scan.get("yara_findings") or 0)
    total_f = clam_f + yara_f
    has_findings = 1 if (scan_status == "findings" or total_f > 0) else 0
    enroll_status = "pending_with_findings" if has_findings else "pending"
    if not scan or scan_status in (None, "not_available"):
        scan_summary = "Pre-enrollment scan: ℹ️ Not available (scanner not installed on this device)"
    elif scan_status == "scan_failed":
        scan_summary = "Pre-enrollment scan: ⚠️ Scan failed (could not complete)"
    elif has_findings:
        scan_summary = (f"Pre-enrollment scan: ⚠️ {total_f} finding(s) — review before "
                        f"approving (ClamAV: {clam_f}, YARA: {yara_f})")
    else:
        scan_summary = f"Pre-enrollment scan: ✅ Clean (ClamAV: {clam_f} findings, YARA: {yara_f} findings)"

    # ── hardware-stable-ID fingerprint (ADR 0011) — parse; degrade-visibly, NEVER gate ──
    fp = payload.get("hardware_fingerprint")
    if isinstance(fp, str):
        try:
            fp = json.loads(fp)
        except Exception:
            fp = {}
    if not isinstance(fp, dict):
        fp = {}
    hw_stable_id      = fp.get("stable_id") or None
    hw_signals_used   = json.dumps(fp.get("signals_used") or [])
    hw_signal_hashes  = json.dumps(fp.get("signal_hashes") or {})
    hw_confidence     = fp.get("confidence") or None
    hw_schema_version = fp.get("schema_version")
    hw_is_virtual     = 1 if fp.get("is_virtual") else 0

    import uuid as _uuid
    import time as _time
    device_id = _uuid.uuid4().hex
    now = datetime.now().isoformat(timespec="seconds")

    # ── installer token: atomic single-use claim → auto-approve (skip pending) ──
    # The UPDATE both validates AND claims a use in one statement (concurrency-safe).
    # Any failure (no token, bad/expired/used token, missing table) leaves the
    # scan-derived enroll_status untouched → normal pending flow. Never errors out.
    token = (payload.get("enrollment_token") or "").strip()
    token_creator = None
    try:
        conn = _db_connect()
        if token:
            try:
                cur = conn.execute(
                    "UPDATE enrollment_tokens SET uses = uses + 1 "
                    "WHERE token=? AND revoked=0 AND auto_approve=1 "
                    "AND uses < max_uses AND expires_at > ?",
                    (token, _time.time()))
                if cur.rowcount == 1:
                    r = conn.execute(
                        "SELECT created_by, device_name_hint FROM enrollment_tokens "
                        "WHERE token=?", (token,)).fetchone()
                    token_creator = r[0] if r else None
                    enroll_status = "approved"
                    # Phase 6: if the agent didn't supply a specific name (blank or a
                    # generic default), fall back to the token's device_name_hint.
                    # Safe: signature was already verified against the supplied name.
                    hint = (r[1] if r else None) or ""
                    if hint.strip() and device_name.strip().lower() in (
                            "", "device", "my device", "windows device"):
                        device_name = hint.strip()
            except Exception:
                log.exception("enrollment token check failed; falling back to pending")
        # ── TOFU "same device?" — compare against PRIOR fingerprints (informational; the
        #    match NEVER blocks enrollment — degrade-visibly principle, ADR 0011). ──
        if hw_stable_id:
            try:
                prior = conn.execute(
                    "SELECT device_id, hw_stable_id, hw_signal_hashes FROM agent_devices "
                    "WHERE hw_stable_id IS NOT NULL").fetchall()
                outcome, matched_id, matched_n = _match_fingerprint(fp, prior)
                log.info("enroll fingerprint: outcome=%s confidence=%s is_virtual=%s "
                         "signals=%d matched_device=%s matched_signals=%s",
                         outcome, hw_confidence, bool(hw_is_virtual),
                         len(fp.get("signals_used") or []), matched_id, matched_n)
            except Exception:
                log.exception("fingerprint match failed (non-fatal)")

        conn.execute(
            "INSERT INTO agent_devices (device_id, device_name, os, os_version, "
            "hardware_summary, public_key, enrollment_status, ip_address, agent_last_seen, "
            "pre_enrollment_scan, enrollment_has_findings, enrolled_by, enrolled_at, "
            "hw_stable_id, hw_signals_used, hw_signal_hashes, hw_fp_confidence, "
            "hw_fp_schema_version, hw_fp_locked_at, hw_is_virtual) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (device_id, device_name, os_name, payload.get("os_version", ""),
             payload.get("hardware_summary", ""), public_key, enroll_status, remote_ip, now,
             scan_json, has_findings,
             (token_creator if enroll_status == "approved" else None),
             (now if enroll_status == "approved" else None),
             hw_stable_id, hw_signals_used, hw_signal_hashes, hw_confidence,
             hw_schema_version, _time.time(), hw_is_virtual))
        conn.commit()   # token claim + device insert commit together (or both roll back)
        conn.close()
    except Exception:
        log.exception("agent enrollment insert failed")
        return None, "db_error"
    try:   # best-effort approval ticket
        import modules
        modules.set_shared_db_path(DB_PATH)
        from modules.tickets.module import open_ticket
        if enroll_status == "approved":
            title = f"Device auto-enrolled via installer token: {device_name} ({os_name})"
            footer = (f"Auto-approved by installer token (created by {token_creator or 'unknown'}).\n"
                      f"Review in Settings -> Devices if unexpected.")
            prio = "HIGH" if has_findings else "LOW"
        else:
            title = f"New device pending approval: {device_name} ({os_name})"
            footer = "Approve or reject it in Settings -> Devices."
            prio = "HIGH" if has_findings else "MEDIUM"
        open_ticket(
            sensor_key=f"agent_enroll_{device_id}",
            title=title,
            body=(f"A device requested enrollment.\n\nName: {device_name}\n"
                  f"OS: {os_name} {payload.get('os_version', '')}\n"
                  f"Hardware: {payload.get('hardware_summary', '')}\nFrom: {remote_ip}\n\n"
                  f"{scan_summary}\n\n{footer}"),
            priority=prio, actor=(token_creator if enroll_status == "approved" else "system"))
    except Exception:
        log.exception("agent enrollment ticket failed (non-fatal)")
    return device_id, enroll_status


def _start_windows_agent_listener():
    """Start the background HTTP listener for nemesis_agent POSTs.

    Runs in a daemon thread so it exits automatically when the main process ends.
    Calls insert_sample() on every valid POST so the dashboard reads from the DB.
    Also serves the owner-gated enrollment endpoints (/enroll, /enrollment_status).
    """

    class _WaHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # silence default per-request stdout logging

        def _json(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _pace(self):
            """Token-bucket pacing. True = proceed, False = already answered 429.

            Replaces the deferred `ufw limit 5001/tcp`. Traffic inside the
            sustained rate is untouched (delay 0.0); traffic above it is SLOWED
            rather than blocked, so a fleet sharing one NAT address is never
            locked out the way a connection-count cap would lock it out.

            Sleeping here is only safe because this listener is a
            ThreadingHTTPServer -- under the previous single-threaded server a
            paced request would have stalled every other agent.
            """
            if _PACER is None:
                return True
            src = self.client_address[0] if self.client_address else "?"
            d = _PACER.check(src)
            if not d.allow:
                log.warning("agent listener: shedding request from %s "
                            "(flood pacing, retry_after=%ss)", src, d.retry_after)
                body = b'{"error":"rate limited"}'
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.send_header("Retry-After", str(d.retry_after))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return False
            if d.delay > 0:
                log.info("agent listener: pacing %s by %.2fs", src, d.delay)
                time.sleep(d.delay)
            return True

        def do_GET(self):
            if not self._pace():
                return
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(self.path)
            if parsed.path == "/enrollment_status":
                device_id = (parse_qs(parsed.query).get("device_id") or [""])[0]
                self._json(200, {"status": _agent_enrollment_status(device_id) or "unknown"})
                return
            if parsed.path == "/reputation_dataset":
                # Feature 6 (observation-only): serve the IP-reputation rows to an
                # APPROVED agent for its local measurement cache. Read-only; light
                # device_id gate (mirrors /hw_data trust; data is non-sensitive).
                device_id = (parse_qs(parsed.query).get("device_id") or [""])[0]
                if _agent_enrollment_status(device_id) != "approved":
                    self._json(403, {"error": "not approved"})
                    return
                self._json(200, {"rows": _reputation_dataset()})
                return
            self.send_response(404)
            self.end_headers()

        def _handle_enroll(self):
            try:
                length = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(length) or b"{}")
            except Exception:
                self._json(400, {"error": "bad request"})
                return
            device_id, status = _create_enrollment(payload, self.client_address[0])
            if not device_id:
                self._json(400, {"error": status})
                return
            log.info("agent enroll: %s pending approval (%s)", device_id, payload.get("device_name"))
            self._json(200, {"device_id": device_id, "status": status})

        def _handle_uninstall(self):
            try:
                length = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(length) or b"{}")
            except Exception:
                self._json(400, {"error": "bad request"})
                return
            ok, status = _create_uninstall(payload, self.client_address[0])
            if not ok:
                self._json(401 if status == "bad_signature" else 400, {"error": status})
                return
            self._json(200, {"status": status})

        def do_POST(self):
            if not self._pace():
                return
            if self.path == "/enroll":
                self._handle_enroll()
                return
            if self.path == "/api/agent/uninstall":
                self._handle_uninstall()
                return
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
            if source != "nemesis_agent":
                # Finding 1: only the signed-enrollment nemesis_agent is accepted.
                # The legacy ungated windows_agent ingress route is removed.
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"unknown source"}')
                return

            try:
                remote_ip = self.client_address[0]
                # Enrollment gate: drop heartbeats from non-approved devices.
                if not _agent_approved(payload.get("device_id")):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"ok":false,"status":"not_approved"}')
                    return
                metrics = _nemesis_payload_to_metrics(payload)
                _check_and_queue_scan_triggers(payload)   # before update (needs prev state)
                _update_agent_device(payload, remote_ip=remote_ip)
                insert_sample(metrics)
                device_id = payload.get("device_id", "local")
                _dispatch_pending_scans(device_id, remote_ip)
                log.info(
                    "nemesis_agent: sample device=%s cpu=%s°C gpu=%s°C conn=%s",
                    device_id, metrics.get("cpu_temp"),
                    metrics.get("gpu_temp"), payload.get("connection_type"),
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
            # ThreadingHTTPServer, not HTTPServer. The single-threaded server
            # handles exactly one connection at a time, so ANY slow or stuck
            # client -- a half-open socket, an agent on a bad link, a request
            # that never sends its body -- blocks every other agent's heartbeat
            # behind it for as long as it lasts. That is a live fragility
            # independent of any flood: it needs one bad connection, not an
            # attack. daemon_threads keeps shutdown immediate by not waiting on
            # in-flight handlers, matching the daemon=True thread this runs in.
            server = ThreadingHTTPServer(("0.0.0.0", WA_LISTEN_PORT), _WaHandler)
            server.daemon_threads = True
            log.info("Agent listener started on port %d (nemesis_agent, threaded)",
                     WA_LISTEN_PORT)
            server.serve_forever()
        except Exception as e:
            log.error("agent listener failed to start: %s", e)

    t = threading.Thread(target=_serve, daemon=True, name="wa-listener")
    t.start()


def get_recent_samples(limit=288):
    """Return up to `limit` samples, oldest first (suitable for charts)."""
    conn = _db_connect()
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
    # Assert the privilege boundary against the kernel before doing any work.
    # Inert until the migrated unit sets NEMESIS_EXPECT_USER (see nemesis_privsep).
    import nemesis_privsep
    nemesis_privsep.attest_from_env("hw-monitor")
    main()
