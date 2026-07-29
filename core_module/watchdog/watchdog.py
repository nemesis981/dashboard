#!/usr/bin/env python3
"""Watchdog service that monitors critical services and restarts/alerts on failure."""

import json
import logging
import os
import sqlite3
import data_manager
import subprocess
import time

from email_utils import send_email

SERVICES = [
    "pihole-FTL",
    "clamav-daemon",
    "suricata",
    "dashboard",
    "device-scanner",
    "hw-monitor",
]

CHECK_INTERVAL_SECONDS = 120
_HERE = os.path.dirname(os.path.abspath(__file__))
# systemd sets $LOGS_DIRECTORY when the unit declares LogsDirectory=. Falling
# back to _HERE keeps the pre-migration unit working unchanged.
LOG_PATH = os.path.join(os.environ.get("LOGS_DIRECTORY", _HERE), "watchdog.log")

import nemesis_paths
HW_DB_PATH = nemesis_paths.db_path(os.path.join(_HERE, "alerts.db"))
HW_CHECK_INTERVAL_SECONDS = 300
HW_ALERT_COOLDOWN_SECONDS = 1800

THRESH_CPU_TEMP = 85.0
# AMBF sensor on Alienware Area-51 reads internal chassis temp near the CPU
# (normal 74-81°C under typical load), not true room ambient — keep this high.
THRESH_AMBIENT_TEMP = 85.0
THRESH_NVME_TEMP = 70.0
THRESH_GPU_TEMP = 85.0
THRESH_CPU_FAN_MIN_RPM = 200
THRESH_CPU_TEMP_FOR_FAN_CHECK = 50.0
THRESH_LOAD_FOR_CHASSIS_FAN_CHECK = 30.0
THRESH_CPU_PERCENT_SUSTAINED = 90.0
SUSTAINED_LOAD_SAMPLES = 3  # 3 × 5 min = 15 min

_hw_state = {"last_check": 0.0, "cooldowns": {}}

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


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
        _DM = data_manager.DataManager(HW_DB_PATH)
        data_manager.set_namespace_mode("watchdog", data_manager.MODE_WARN)
    return _DM.connect("watchdog")


def is_service_active(service: str) -> bool:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", service],
    )
    return result.returncode == 0


def restart_service(service: str) -> bool:
    result = subprocess.run(
        ["systemctl", "restart", service],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        logging.error(
            "systemctl restart %s failed: %s",
            service,
            result.stderr.strip(),
        )
        return False
    time.sleep(3)
    return is_service_active(service)


def send_email_alert(service: str) -> None:
    subject = f"[Watchdog] Service '{service}' is down and could not be restarted"
    body = (
        f"The watchdog attempted to automatically restart the '{service}' service "
        f"but it remains inactive.\n\n"
        f"Host: {os.uname().nodename}\n"
        f"Please investigate as soon as possible."
    )
    if send_email(subject, body):
        logging.info("Sent alert email for %s", service)
    else:
        logging.error("Failed to send alert email for %s", service)


def _fetch_latest_hw_sample():
    conn = _db_connect()
    try:
        c = conn.cursor()
        c.execute(
            """SELECT timestamp, cpu_temp, ambient_temp, nvme_temp,
                      fans_json,
                      cpu_percent, ram_used_gb,
                      disk_read_mb, disk_write_mb, net_in_mb, net_out_mb,
                      gpu_temp, gpu_fan_percent, gpu_power_watts
               FROM hw_metrics ORDER BY id DESC LIMIT 1"""
        )
        row = c.fetchone()
    except Exception:
        # hw_metrics is created by hw_monitor (a separate process); there is no
        # systemd ordering, so on a fresh DB it may not exist yet. Return None
        # rather than crash — matches _fetch_fan_status's guard.
        row = None
    finally:
        conn.close()
    if not row:
        return None
    cols = ["timestamp", "cpu_temp", "ambient_temp", "nvme_temp",
            "fans_json",
            "cpu_percent", "ram_used_gb",
            "disk_read_mb", "disk_write_mb", "net_in_mb", "net_out_mb",
            "gpu_temp", "gpu_fan_percent", "gpu_power_watts"]
    d = dict(zip(cols, row))
    raw = d.pop("fans_json", None)
    d["fans"] = json.loads(raw) if raw else []
    return d


def _fetch_fan_status():
    """Return {unique_key: {"label": str, "ever_active": bool}} from fan_status table.

    Returns an empty dict if the table doesn't exist yet (pre-init_db).
    """
    conn = _db_connect()
    try:
        rows = conn.execute(
            "SELECT unique_key, label, ever_active FROM fan_status"
        ).fetchall()
    except Exception:
        rows = []
    finally:
        conn.close()
    return {row[0]: {"label": row[1], "ever_active": bool(row[2])} for row in rows}


def _fetch_recent_cpu_percents(n):
    conn = _db_connect()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT cpu_percent FROM hw_metrics ORDER BY id DESC LIMIT ?",
            (n,),
        )
        rows = c.fetchall()
    except Exception:
        # hw_metrics may not exist yet (created by hw_monitor, no startup
        # ordering). Return empty rather than crash — matches _fetch_fan_status.
        rows = []
    finally:
        conn.close()
    return [r[0] for r in rows if r[0] is not None]


def _init_cooldown_table():
    conn = _db_connect()
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS hw_alert_cooldowns (
                alert_key TEXT PRIMARY KEY,
                last_sent_ts REAL NOT NULL
            )
        """)
        # hw_alerts: persistent alert state read by the dashboard.
        # Written here (by watchdog) whenever a condition is detected or clears.
        c.execute("""
            CREATE TABLE IF NOT EXISTS hw_alerts (
                alert_key          TEXT PRIMARY KEY,
                severity           TEXT NOT NULL,
                breach             TEXT NOT NULL,
                recommendation     TEXT NOT NULL,
                first_triggered_ts REAL NOT NULL,
                last_triggered_ts  REAL NOT NULL,
                resolved_ts        REAL
            )
        """)
        conn.commit()
    finally:
        conn.close()


def _upsert_hw_alert(key, severity, breach, recommendation):
    """Record or refresh an active alert in hw_alerts.

    If the alert is new (or was previously resolved), opens a fresh entry.
    If it already exists and is unresolved, just bumps last_triggered_ts.
    Called unconditionally on every detected breach so the row stays fresh
    even while the email cooldown is suppressing repeated sends.
    """
    now = time.time()
    conn = _db_connect()
    try:
        c = conn.cursor()
        c.execute(
            """INSERT INTO hw_alerts
                   (alert_key, severity, breach, recommendation,
                    first_triggered_ts, last_triggered_ts, resolved_ts)
               VALUES (?, ?, ?, ?, ?, ?, NULL)
               ON CONFLICT(alert_key) DO UPDATE SET
                   severity          = excluded.severity,
                   breach            = excluded.breach,
                   recommendation    = excluded.recommendation,
                   last_triggered_ts = excluded.last_triggered_ts,
                   -- re-open if it was previously resolved
                   first_triggered_ts = CASE WHEN resolved_ts IS NOT NULL
                                             THEN excluded.first_triggered_ts
                                             ELSE first_triggered_ts END,
                   resolved_ts       = NULL""",
            (key, severity, breach, recommendation, now, now),
        )
        conn.commit()
    except Exception as e:
        logging.exception("_upsert_hw_alert %s: %s", key, e)
    finally:
        conn.close()


def _resolve_stale_alerts(active_keys):
    """Mark resolved any hw_alerts whose condition is no longer detected."""
    now = time.time()
    conn = _db_connect()
    try:
        c = conn.cursor()
        c.execute("SELECT alert_key FROM hw_alerts WHERE resolved_ts IS NULL")
        open_keys = {row[0] for row in c.fetchall()}
        for key in open_keys - active_keys:
            c.execute(
                "UPDATE hw_alerts SET resolved_ts = ? WHERE alert_key = ?",
                (now, key),
            )
            logging.info("HW alert resolved: %s", key)
        conn.commit()
    except Exception as e:
        logging.exception("_resolve_stale_alerts: %s", e)
    finally:
        conn.close()


def _load_cooldowns():
    """Restore cooldown timestamps from disk so a watchdog restart doesn't
    silently reset the 30-min window and trigger duplicate alerts."""
    try:
        conn = _db_connect()
        try:
            c = conn.cursor()
            c.execute("SELECT alert_key, last_sent_ts FROM hw_alert_cooldowns")
            for k, ts in c.fetchall():
                _hw_state["cooldowns"][k] = ts
        finally:
            conn.close()
        logging.info("loaded %d HW alert cooldowns from disk", len(_hw_state["cooldowns"]))
    except Exception as e:
        logging.exception("failed to load HW cooldowns: %s", e)


def _hw_cooldown_ok(key):
    last = _hw_state["cooldowns"].get(key, 0.0)
    return (time.time() - last) >= HW_ALERT_COOLDOWN_SECONDS


def _hw_record(key):
    """Record the cooldown timestamp in memory AND on disk so it survives restarts."""
    now_ts = time.time()
    _hw_state["cooldowns"][key] = now_ts
    try:
        conn = _db_connect()
        try:
            c = conn.cursor()
            c.execute(
                "INSERT OR REPLACE INTO hw_alert_cooldowns (alert_key, last_sent_ts) VALUES (?, ?)",
                (key, now_ts),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        logging.exception("failed to persist HW cooldown for %s: %s", key, e)


def _format_reading(sample):
    def f(v, suf=""):
        return "—" if v is None else f"{v}{suf}"
    fan_lines = ""
    for fan in sample.get("fans", []):
        lbl = fan.get("label") or fan.get("unique_key") or "Fan"
        fan_lines += f"  {lbl + ':':<22} {f(fan.get('rpm'), ' rpm')}\n"
    if not fan_lines:
        fan_lines = "  Fans:                 (no data)\n"
    return (
        f"  Timestamp:            {sample.get('timestamp')}\n"
        f"  CPU temp:             {f(sample.get('cpu_temp'), '°C')}\n"
        f"  GPU temp:             {f(sample.get('gpu_temp'), '°C')}\n"
        f"  Ambient temp:         {f(sample.get('ambient_temp'), '°C')}\n"
        f"  NVMe temp:            {f(sample.get('nvme_temp'), '°C')}\n"
        + fan_lines +
        f"  GPU fan:              {f(sample.get('gpu_fan_percent'), '%')}\n"
        f"  GPU power:            {f(sample.get('gpu_power_watts'), ' W')}\n"
        f"  CPU load:             {f(sample.get('cpu_percent'), '%')}\n"
        f"  RAM used:             {f(sample.get('ram_used_gb'), ' GB')}\n"
    )


def _send_hw_alert(key, severity, breach, recommendation, sample):
    # Always persist the alert state so the dashboard shows it immediately,
    # even if the email is still on cooldown.
    _upsert_hw_alert(key, severity, breach, recommendation)

    if not _hw_cooldown_ok(key):
        logging.info("HW alert %s suppressed by cooldown (last sent < 30 min ago)", key)
        return
    # Record the cooldown BEFORE attempting send. Otherwise a transient SMTP
    # failure or missing credentials would leave the timestamp un-set, and the
    # next check (~2 min later) would breach again and re-attempt — flooding
    # logs and (once creds are fixed) the inbox.
    _hw_record(key)
    subject = f"[Nemesis HW] {severity}: {breach}"
    body = (
        f"Hardware threshold exceeded on {os.uname().nodename}.\n\n"
        f"Breach:         {breach}\n"
        f"Severity:       {severity}\n\n"
        f"Current readings:\n{_format_reading(sample)}\n"
        f"Recommendation: {recommendation}\n"
    )
    if send_email(subject, body):
        logging.warning("HW alert sent: %s (%s)", key, breach)
    else:
        logging.error("HW alert email failed: %s (cooldown still recorded)", key)

    try:
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        # ADR 0001 Stage 3: tickets now reaches the shared DB via the module accessor.
        # watchdog is a SEPARATE process that never runs modules_loader.init(), so register
        # the shared path here (HW_DB_PATH is that same alert_manager/alerts.db). Idempotent.
        import modules
        modules.set_shared_db_path(HW_DB_PATH)
        from modules.tickets.module import open_ticket as _open_ticket, _get_settings as _tk_settings
        _tk = _tk_settings()
        # Shared ladder (alert_manager/nemesis_severity.py) — was a private dict
        # duplicated byte-for-byte in modules/malware_detection/module.py. The
        # threshold default is rank("HIGH"), matching the literal 2 this replaced
        # under the old 4-rung ordering; the ladder gained INFO at the bottom, so
        # the number moved but the meaning did not.
        import nemesis_severity as _sev
        _min_sev = _tk.get("min_severity_for_auto_ticket", "HIGH")
        if _tk.get("auto_ticket_on_alert", True) and \
                _sev.meets_threshold(severity, _min_sev):
            _open_ticket(
                sensor_key=key,
                title=f"Auto: {breach}",
                body=body,
                priority=severity,
                actor="system",   # actor seam: background service (watchdog)
            )
    except Exception:
        pass  # never crash watchdog


def check_hw_metrics():
    now = time.time()
    if now - _hw_state["last_check"] < HW_CHECK_INTERVAL_SECONDS:
        return
    _hw_state["last_check"] = now

    sample = _fetch_latest_hw_sample()
    if not sample:
        logging.info("HW check: no samples yet in hw_metrics table")
        return

    cpu_t = sample.get("cpu_temp")
    amb_t = sample.get("ambient_temp")
    nvme_t = sample.get("nvme_temp")
    gpu_t = sample.get("gpu_temp")
    load  = sample.get("cpu_percent")
    fans  = sample.get("fans", [])

    fan_summary = " ".join(
        f"{f.get('label', f.get('unique_key', '?'))}={f.get('rpm')}"
        for f in fans
    ) or "none"
    logging.info(
        "HW check: cpu=%s°C gpu=%s°C ambient=%s°C nvme=%s°C load=%s%% fans=[%s]",
        cpu_t, gpu_t, amb_t, nvme_t, load, fan_summary,
    )

    # Track every alert key that is currently breaching so we can resolve
    # stale ones (conditions that have since cleared) at the end of this check.
    breached_keys = set()

    if cpu_t is not None and cpu_t > THRESH_CPU_TEMP:
        breached_keys.add("cpu_temp")
        _send_hw_alert(
            "cpu_temp", "CRITICAL",
            f"CPU temperature {cpu_t}°C exceeds {THRESH_CPU_TEMP}°C",
            "Check CPU fan and case airflow. Consider reducing load until temps recover.",
            sample,
        )

    if amb_t is not None and amb_t > THRESH_AMBIENT_TEMP:
        breached_keys.add("ambient_temp")
        _send_hw_alert(
            "ambient_temp", "HIGH",
            f"Ambient temperature {amb_t}°C exceeds {THRESH_AMBIENT_TEMP}°C",
            "Check room ventilation, dust filters, and chassis fan operation.",
            sample,
        )

    if nvme_t is not None and nvme_t > THRESH_NVME_TEMP:
        breached_keys.add("nvme_temp")
        _send_hw_alert(
            "nvme_temp", "HIGH",
            f"NVMe temperature {nvme_t}°C exceeds {THRESH_NVME_TEMP}°C",
            "Verify NVMe heatsink contact and ambient airflow over the M.2 slot.",
            sample,
        )

    if gpu_t is not None and gpu_t > THRESH_GPU_TEMP:
        breached_keys.add("gpu_temp")
        _send_hw_alert(
            "gpu_temp", "CRITICAL",
            f"GPU temperature {gpu_t}°C exceeds {THRESH_GPU_TEMP}°C",
            "Check GPU fan and case airflow. Reduce GPU load (gaming, compute, ML) until temps recover.",
            sample,
        )

    # Fan checks: only fire for fans with ever_active=True (historically observed
    # spinning).  Fans that have never reported non-zero RPM are presumed-empty
    # motherboard headers and are ignored to avoid false alarms.
    fan_status = _fetch_fan_status()
    for fan in fans:
        ukey = fan.get("unique_key")
        if not ukey:
            continue
        if not fan_status.get(ukey, {}).get("ever_active"):
            continue   # never-active header — skip
        rpm   = fan.get("rpm")
        label = fan.get("label", ukey)
        if rpm is None or rpm > THRESH_CPU_FAN_MIN_RPM:
            continue   # spinning fine
        if "cpu" in label.lower():
            # CPU fan slow/stopped while CPU is hot — immediate risk
            if cpu_t is not None and cpu_t > THRESH_CPU_TEMP_FOR_FAN_CHECK:
                key = f"fan_stopped/{ukey}"
                breached_keys.add(key)
                _send_hw_alert(
                    key, "CRITICAL",
                    f"CPU fan '{label}' at {rpm} RPM while CPU is {cpu_t:.0f}°C",
                    "Inspect the CPU fan immediately. Risk of thermal damage if not addressed.",
                    sample,
                )
        else:
            # Chassis/other fan stopped while system is under load
            if load is not None and load > THRESH_LOAD_FOR_CHASSIS_FAN_CHECK:
                key = f"fan_stopped/{ukey}"
                breached_keys.add(key)
                _send_hw_alert(
                    key, "HIGH",
                    f"Fan '{label}' ({ukey}) at {rpm} RPM while system under {load:.0f}% load",
                    f"Inspect '{label}'. A stopped fan under sustained load will raise temperatures.",
                    sample,
                )

    recent = _fetch_recent_cpu_percents(SUSTAINED_LOAD_SAMPLES)
    if (len(recent) >= SUSTAINED_LOAD_SAMPLES
            and all(p > THRESH_CPU_PERCENT_SUSTAINED for p in recent)):
        breached_keys.add("cpu_sustained_load")
        _send_hw_alert(
            "cpu_sustained_load", "MEDIUM",
            f"CPU load above {THRESH_CPU_PERCENT_SUSTAINED}% for {SUSTAINED_LOAD_SAMPLES * 5} minutes",
            "Investigate runaway processes with `top` / `ps auxf`. May indicate stuck job or attack.",
            sample,
        )

    # Clear any alerts whose condition is no longer detected this cycle.
    _resolve_stale_alerts(breached_keys)


def check_service(service: str) -> None:
    if is_service_active(service):
        return

    logging.warning("Service '%s' is down. Attempting automatic restart.", service)
    if restart_service(service):
        logging.info("Service '%s' restarted successfully.", service)
    else:
        logging.error(
            "Service '%s' restart failed. Sending email alert.", service
        )
        send_email_alert(service)


def main() -> None:
    logging.info("Watchdog started. Monitoring: %s", ", ".join(SERVICES))
    _init_cooldown_table()
    _load_cooldowns()
    logging.info(
        "HW thresholds: cpu>%s°C gpu>%s°C ambient>%s°C nvme>%s°C "
        "fan<=%s rpm (cpu-fan when cpu>%s°C, chassis fan when load>%s%%) "
        "sustained load>%s%% for %d samples",
        THRESH_CPU_TEMP, THRESH_GPU_TEMP, THRESH_AMBIENT_TEMP, THRESH_NVME_TEMP,
        THRESH_CPU_FAN_MIN_RPM, THRESH_CPU_TEMP_FOR_FAN_CHECK,
        THRESH_LOAD_FOR_CHASSIS_FAN_CHECK, THRESH_CPU_PERCENT_SUSTAINED,
        SUSTAINED_LOAD_SAMPLES,
    )
    while True:
        for service in SERVICES:
            try:
                check_service(service)
            except Exception as exc:
                logging.exception("Unexpected error while checking %s: %s", service, exc)
        try:
            check_hw_metrics()
        except Exception as exc:
            logging.exception("Unexpected error in check_hw_metrics: %s", exc)
        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    # Assert the privilege boundary against the kernel before doing any work.
    # Inert until the migrated unit sets NEMESIS_EXPECT_USER (see nemesis_privsep).
    import nemesis_privsep
    nemesis_privsep.attest_from_env("watchdog")
    main()
