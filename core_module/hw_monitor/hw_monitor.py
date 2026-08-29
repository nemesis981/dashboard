#!/usr/bin/env python3
"""Hardware metrics collector for Nemesis Firewall.

Run as a daemon (writes a sample every 5 minutes to the hw_metrics table)
or import as a module (dashboard.py uses get_live_metrics / init_db /
get_recent_samples).
"""
import json
import logging
import hashlib
import os
import re as _re
import signal
import sqlite3
import data_manager
import database          # canonical DDL owner (init_scan_tables) — see init_db
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler

import psutil

_HERE        = os.path.dirname(os.path.abspath(__file__))
import nemesis_paths
DB_PATH      = nemesis_paths.db_path(os.path.join(_HERE, "alerts.db"))
# systemd sets $LOGS_DIRECTORY when the unit declares LogsDirectory=. Falling
# back to _HERE keeps the pre-migration unit working unchanged.
LOG_FILE     = os.path.join(os.environ.get("LOGS_DIRECTORY", _HERE), "hw_monitor.log")
# ⛔ DO NOT go back to os.path.join(_HERE, "hw_map.json") (fixed 2026-08-29).
# hw_discover.py writes the map from alert_manager/; this file reads from
# core_module/hw_monitor/. Both used that identical expression against their own
# directory, so the writer and reader named two different files and the user's
# chosen sensor mapping was silently discarded on every run. Resolver keeps the
# two in agreement — see nemesis_paths.hw_map_path().
HW_MAP_PATH  = nemesis_paths.hw_map_path()
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

# ── :5001 source admission (GAP 3, 2026-08-16) ───────────────────────────────
# Application-layer enforcement of "local traffic and VPN traffic, nothing
# else". Until now that rule lived only in ufw, so it held exactly as long as
# the firewall configuration did. See agent_source_guard for the full rationale,
# the allowlist, and the self-test that proves the guard can actually refuse
# something. Disable with NEMESIS_5001_SOURCE_GUARD=0.
import agent_source_guard  # noqa: E402

try:
    _SOURCE_GUARD, _sg_note = agent_source_guard.from_env()
except agent_source_guard.GuardError as _e:
    # Construction failing means the guard could not prove it works. Serving
    # without it would be the exact defect it exists to prevent — an absent
    # check that nothing distinguishes from a passing one — so refuse to come up
    # rather than silently reverting to ufw-only.
    log.critical("agent listener: source guard REFUSED TO BUILD — %s", _e)
    raise
if _SOURCE_GUARD is None:
    log.warning("agent listener: :5001 source guard DISABLED (%s) — admission "
                "rests on ufw alone", _sg_note)
else:
    if _SOURCE_GUARD.lan_enumeration_error:
        log.error("agent listener: :5001 source guard — %s", _sg_note)
    else:
        log.info("agent listener: :5001 source guard active (%s) — allowing %s",
                 _sg_note, _SOURCE_GUARD.describe())

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
#: Throttle handle for the sample loop, set in main() once hw-monitor registers
#: itself throttle-aware. None until then / if registration fails -> plain sleep.
_throttle = None


def _db_connect():
    """Guarded connection scoped to this process's namespace.

    WARN MODE during the retrofit: every write outside the declared namespace is
    logged as ``WOULD DENY`` and then ALLOWED. The namespace table list came from
    static analysis of this file, which cannot see conditional SQL or statements
    built elsewhere — so it is treated as a hypothesis to be disproved by real
    traffic, not as a finished list. Flip to MODE_ENFORCE only once the journal
    is quiet across a representative period.
    """
    return _dm().connect("hw_monitor")


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
                gpu_power_watts REAL,
                disk_total_gb REAL,
                disk_free_gb REAL,
                disk_pct_used REAL
            )
        """)

        # Agent SELF-REPORTED error digest (stage c, 2026-08-20). Kept SEPARATE
        # from the authoritative server error ledger (error_occurrences) on
        # purpose: these are what an agent CLAIMS about itself — a compromised
        # agent can fabricate or suppress them (the attest.py framing), so they
        # are diagnostic hints, never authoritative, and must not sit
        # indistinguishably beside the server's own evidence. Append-only.
        c.execute("""
            CREATE TABLE IF NOT EXISTS agent_error_reports (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id   TEXT NOT NULL,
                code        TEXT NOT NULL,
                severity    TEXT,
                count       INTEGER NOT NULL,
                first_ts    TEXT,
                last_ts     TEXT,
                context     TEXT,
                received_at TEXT NOT NULL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_aer_device ON agent_error_reports(device_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_aer_code   ON agent_error_reports(code)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_hw_metrics_ts ON hw_metrics(timestamp)")
        # Idempotent migrations for columns added after initial schema.
        existing = {row[1] for row in c.execute("PRAGMA table_info(hw_metrics)").fetchall()}
        for col, decl in (("gpu_temp", "INTEGER"),
                          ("gpu_fan_percent", "INTEGER"),
                          ("gpu_power_watts", "REAL"),
                          ("fan4_rpm", "INTEGER"),
                          ("fans_json", "TEXT"),
                          ("is_anomalous", "INTEGER DEFAULT 0"),
                          ("device_id", "TEXT DEFAULT 'local'"),
                          ("disk_total_gb", "REAL"),
                          ("disk_free_gb", "REAL"),
                          ("disk_pct_used", "REAL")):
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
        #
        # NARROWED (E-HWMON-003, 2026-08-19): this used to be one broad
        # `except Exception: pass` covering both an OPTIONAL file read
        # (HW_MAP_PATH is legitimately absent on non-hardware installs) and a
        # DB WRITE (INSERT OR IGNORE) — one clause could not tell "expected
        # absence" from "unexpected write failure" apart. Split: the file
        # half stays silent on its two genuinely expected failure shapes; the
        # write half is wired, because a failed INSERT here is not expected.
        try:
            with open(HW_MAP_PATH) as _mf:
                _hm = json.load(_mf)
        except (OSError, json.JSONDecodeError):
            _hm = None
        if _hm is not None:
            for _f in _hm.get("fans", []):
                if "unique_key" in _f:
                    try:
                        c.execute(
                            "INSERT OR IGNORE INTO fan_status "
                            "(unique_key, label, ever_active) VALUES (?, ?, 0)",
                            (_f["unique_key"], _f.get("label", _f["unique_key"]))
                        )
                    except Exception as exc:
                        _errors_record("E-HWMON-003", {
                            "fn": "init_db", "table": "fan_status",
                            "unique_key": _f.get("unique_key"),
                            "error": f"{type(exc).__name__}: {exc}"})
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
                sustained         INTEGER DEFAULT 0,
                top_processes_ref TEXT
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
        # top_processes_ref: archive filename once the blob has been MOVED out
        # (see archive_old_top_processes). The row itself never leaves the table,
        # so every numeric field stays searchable; only the process-list text is
        # one indirection away. NULL + NULL blob means "never captured"; NULL blob
        # + a ref means "archived, here is where".
        if "top_processes_ref" not in existing_anom:
            c.execute("ALTER TABLE hw_anomaly_snapshots ADD COLUMN top_processes_ref TEXT")

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
                hw_is_virtual INTEGER DEFAULT 0,
                -- ── Tier 1 agent self-attestation ──────────────────────────
                -- DEFAULT 'absent', NOT NULL, deliberately: a device that has
                -- never reported an attestation must not be distinguishable
                -- from one that reported failure by accident of NULL-handling.
                -- The A2 rule ("absent is never silently healthy") is enforced
                -- HERE, in the schema, so it cannot be lost by a caller that
                -- forgets to check. Existing rows migrate to 'absent', which is
                -- the truthful value for every one of them.
                attestation_state TEXT NOT NULL DEFAULT 'absent',
                attestation_detail TEXT,
                attestation_at TEXT,
                attestation_version TEXT,
                -- Tier 2 (challenge-response) OBSERVE-ONLY state — SEPARATE from
                -- attestation_state so it never gates Tier 1 health. 'absent' by
                -- default and dormant until Tier 2 issuance + the private module
                -- are deployed (ADR/attestation-tier2). See alert_manager/attestation.py.
                tier2_state TEXT NOT NULL DEFAULT 'absent',
                tier2_detail TEXT,
                tier2_at TEXT,
                -- ── remote-device entitlement (licensing cap) ──────────────
                -- Mirrors the migration entry below. NOT NULL DEFAULT 0 for the
                -- same reason attestation_state defaults to 'absent': a device
                -- that was never granted remote access must not be
                -- indistinguishable from one whose flag is merely NULL.
                -- Local devices are unlimited; only this flag is capped.
                remote_enabled INTEGER NOT NULL DEFAULT 0,
                remote_enabled_at TEXT,
                remote_enabled_by TEXT
            )
        """)
        # NOTE (2026-08-17): this CREATE is NOT a complete column list -- several
        # earlier additions (uninstalled_at/by, revoked_at/by, last_signed_at)
        # live only in the ALTER migration below, so a fresh install gets them
        # from the migration rather than from here. Pre-existing drift, not
        # introduced by this change; the new columns are added to BOTH per the
        # schema rule. Reconciling the rest is its own cleanup.
        c.execute("CREATE INDEX IF NOT EXISTS idx_agent_devices_seen ON agent_devices(agent_last_seen)")

        # agent_device_macs (ADR 0023): the device<->agent correlation key. An
        # agent reports the MAC(s) of its physical LAN interface(s) at enroll and
        # each heartbeat; those match `devices.mac` (the appliance's ARP view),
        # giving a reliable join the ip_address heuristic could not (2/13). One
        # agent -> many MACs (dock / WiFi+ethernet), so it is its own table keyed
        # (device_id, mac); `last_seen` lets a stale MAC age out without rewriting
        # the agent row. Owned/written here (hw_monitor ingest); read-any elsewhere.
        c.execute("""
            CREATE TABLE IF NOT EXISTS agent_device_macs (
                device_id  TEXT NOT NULL,
                mac        TEXT NOT NULL,
                last_seen  REAL NOT NULL,
                PRIMARY KEY (device_id, mac)
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_agent_device_macs_mac "
                  "ON agent_device_macs(mac)")

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
                started_at      TEXT,
                completed_at    TEXT
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
                          # ── Tier 1 agent self-attestation ──
                          # NOT NULL DEFAULT 'absent' matches the CREATE above.
                          # Every pre-existing row becomes 'absent', which is the
                          # honest value: none of them have ever attested.
                          ("attestation_state",   "TEXT NOT NULL DEFAULT 'absent'"),
                          ("attestation_detail",  "TEXT"),
                          ("attestation_at",      "TEXT"),
                          # Tier 2 observe-only (dormant until deployment) — same
                          # 'absent' default logic as attestation_state, separate column.
                          ("tier2_state",         "TEXT NOT NULL DEFAULT 'absent'"),
                          ("tier2_detail",        "TEXT"),
                          ("tier2_at",            "TEXT"),
                          ("attestation_version", "TEXT"),
                          # ── de-enroll on uninstall (clean-uninstall build spec) ──
                          ("uninstalled_at",      "TEXT"),
                          ("uninstalled_by",      "TEXT"),    # actor seam (device self / admin)
                          # ── owner revocation, mirroring the uninstall pair above ──
                          # Revocation previously recorded ONLY enrollment_status,
                          # with no timestamp and no actor on the row, while its
                          # sibling uninstall recorded both. That asymmetry makes
                          # "was this queued before the device was revoked?"
                          # unanswerable from agent_devices — the transition left
                          # no mark to compare against. The _audit entry exists but
                          # is a different table, and joining it to reconstruct a
                          # device's own history is not what a per-row check needs.
                          ("revoked_at",          "TEXT"),
                          ("revoked_by",          "TEXT"),    # actor seam (owner action)
                          # ── heartbeat auth (ADR 0004 step 3) ──
                          # Monotonic replay floor: the newest signed_at already
                          # accepted from this device. Advanced ONLY after a
                          # signature verifies, so a rejected or forged heartbeat
                          # cannot raise it and lock out the real agent. Local ISO
                          # TEXT, so lexical comparison is chronological
                          # (ADR 0004 step 2).
                          ("last_signed_at",      "TEXT"),
                          # ── remote-device entitlement (licensing cap) ──
                          # The free tier caps REMOTE-enabled devices at
                          # entitlements.FREE_TIER_REMOTE_CAP. Local devices are
                          # unlimited and are never counted.
                          #
                          # DEFAULT 0 is deliberate and its consequence is worth
                          # stating: every pre-existing row becomes NOT
                          # remote-enabled, including devices that ARE on the
                          # tailnet today. That is the honest value -- none of
                          # them were ever granted the flag, because it did not
                          # exist. Backfilling it from `connection_type` was
                          # considered and rejected: that field is a per-heartbeat
                          # OBSERVATION whose fallback conflates detection failure
                          # with a genuine remote answer, and it is NULL on 7 of
                          # 13 live rows. Seeding an entitlement from an untrusted
                          # observation would invent entitlements nobody granted.
                          #
                          # The resulting gap is not hidden: core/remote_census
                          # reconciles against the live tailnet and reports any
                          # node with no entitlement record, so the operator sees
                          # exactly which devices need a decision.
                          ("remote_enabled",      "INTEGER NOT NULL DEFAULT 0"),
                          ("remote_enabled_at",   "TEXT"),
                          ("remote_enabled_by",   "TEXT"),   # actor seam
                          # Per-endpoint detection-engine inventory (ADR 0004 hinge (b)):
                          # engines/versions/ruleset-versions/capability as reported on
                          # the heartbeat, so uneven fleet coverage is visible. JSON blob
                          # + when it was last reported (local ISO).
                          ("engine_inventory_json", "TEXT"),
                          ("engine_inventory_at",   "TEXT")):
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
                queued_at       TEXT,
                status          TEXT DEFAULT 'pending',
                executed_at     TEXT,
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
        # ── ADR 0004 step 2: actor seam + local-ISO timestamps ──────────────
        #
        # ACTOR is a nullable seam, NOT live attribution. The Data Manager stamps
        # current_actor() on every write, but nothing calls set_actor() in normal
        # operation yet, so this records NULL today. It exists so a future
        # authenticated caller needs no schema change.
        #
        # TIMESTAMPS: these columns were UTC (CURRENT_TIMESTAMP) or unset, while
        # every auth-adjacent neighbour is local ISO. THE SEPARATOR IS THE
        # DISCRIMINATOR — legacy rows read 'YYYY-MM-DD HH:MM:SS' (space, UTC),
        # converted rows 'YYYY-MM-DDTHH:MM:SS' (local) — so this selects exactly
        # the un-migrated rows and becomes a no-op once run. No flag, no version
        # table, and no way to double-convert a row into a second offset. Same
        # shape already proven on login_events.
        #
        # Defaults are dropped from the CREATEs above, but SQLite cannot alter a
        # default in place, so on an already-deployed database the WRITERS
        # supplying explicit values are what actually fix it.
        for _tbl in ("scan_jobs", "scan_queue", "scan_conditions"):
            _cols = {r[1] for r in c.execute("PRAGMA table_info(%s)" % _tbl).fetchall()}
            if _cols and "actor" not in _cols:
                c.execute("ALTER TABLE %s ADD COLUMN actor TEXT" % _tbl)
        for _tbl, _col in (("scan_jobs", "started_at"), ("scan_jobs", "completed_at"),
                           ("scan_queue", "queued_at"), ("scan_queue", "executed_at")):
            c.execute(
                "UPDATE {t} SET {c} = strftime('%Y-%m-%dT%H:%M:%S', {c}, 'localtime') "
                "WHERE {c} LIKE '____-__-__ %'".format(t=_tbl, c=_col))

        # scan_tasks: the Scheduler's outbound work queue (ADR 0004 Stage 1).
        #
        # A separate table rather than more columns on scan_queue: that table's
        # shape is scan-specific (scan_path, scan_job_id) while a task is broader —
        # notify, update_rules, and later memory-inspect. Overloading it would make
        # every non-scan task carry meaningless scan columns.
        #
        # actor + local-ISO timestamps from the start, per ADR 0004's cross-cutting
        # requirements. Adding those seams later means rewriting a table that by
        # then has live rows in it.
        c.execute("""
            CREATE TABLE IF NOT EXISTS scan_tasks (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id      TEXT NOT NULL UNIQUE,
                device_id    TEXT NOT NULL,
                action       TEXT NOT NULL,
                params_json  TEXT,
                status       TEXT NOT NULL DEFAULT 'pending',
                created_at   TEXT,
                dispatched_at TEXT,
                expires_at   TEXT,
                dispatch_count INTEGER NOT NULL DEFAULT 0,
                -- When this WORK was first queued, if it entered through an
                -- earlier queue (scan_queue) before becoming a task. NULL means
                -- created_at is already the true origin time.
                --
                -- Exists because scan_queue -> scan_tasks is a chain: a row that
                -- sat pending in scan_queue for months produces a scan_tasks row
                -- with created_at = now, which silently RESETS any staleness
                -- measured on created_at. Age must be measured from here when
                -- present, never from created_at alone.
                origin_queued_at TEXT,
                actor        TEXT,
                -- What the DEVICE REPORTED happened (ADR 0004 Stage 1, step 4).
                -- These are ATTESTED CLAIMS, not ground truth: status='completed'
                -- means the agent said it completed, not that the server
                -- verified it. Anything that later needs certainty (billing,
                -- compliance, an enforcement decision) must corroborate from
                -- server-side evidence, never from this column alone.
                result_ok    INTEGER,
                result_detail TEXT,
                reported_at  TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_scan_tasks_device "
                  "ON scan_tasks(device_id, status)")
        _st_cols = {r[1] for r in c.execute("PRAGMA table_info(scan_tasks)").fetchall()}
        for _c, _d in (("result_ok", "INTEGER"), ("result_detail", "TEXT"),
                       ("reported_at", "TEXT"), ("origin_queued_at", "TEXT")):
            if _st_cols and _c not in _st_cols:
                c.execute("ALTER TABLE scan_tasks ADD COLUMN %s %s" % (_c, _d))
        conn.commit()

        # Seed any MISSING default condition — NOT only when the table is empty.
        #
        # This guard was `if COUNT(*) == 0` until 2026-08-04, which meant a
        # condition type added to `defaults` after an install's first boot was
        # never inserted on that install. `new_login` and `usb_inserted` were
        # added later and had therefore NEVER existed on this box: their trigger
        # logic below (`"new_login" in conditions`, `"usb_inserted" in
        # conditions`) is fully implemented but could not fire, because the row
        # it tests for was not there.
        #
        # Nothing errored and the table was populated, so two dead triggers
        # looked exactly like two triggers that had simply not fired yet — which
        # is why this survived. Backfilling by type makes the seed converge on
        # the defaults instead of freezing at whatever the first boot happened
        # to contain.
        #
        # Scoped to GLOBAL rows (device_id IS NULL). A device-specific override
        # must not count as "present" — that would leave the global missing for
        # every other device, a subtler version of the same gap.
        #
        # Insert-only: an existing row keeps its value, so an operator who tuned
        # `extended_absence` is never reset back to the default.
        defaults = [
            (None, "first_connect",      None,  1, "/"),
            (None, "return_from_remote", None,  1, "/"),
            (None, "extended_absence",   "24",  1, "/"),
            (None, "new_login",          None,  1, "/"),
            (None, "usb_inserted",       None,  1, "/"),
        ]
        _have = {r[0] for r in c.execute(
            "SELECT condition_type FROM scan_conditions WHERE device_id IS NULL"
        ).fetchall()}
        _missing = [d for d in defaults if d[1] not in _have]
        if _missing:
            c.executemany(
                "INSERT INTO scan_conditions "
                "(device_id, condition_type, condition_value, enabled, scan_path) "
                "VALUES (?, ?, ?, ?, ?)",
                _missing,
            )
            conn.commit()
            log.info("init_db: seeded %d missing scan condition(s): %s",
                     len(_missing), ", ".join(d[1] for d in _missing))

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
            "disk_total_gb": None, "disk_free_gb": None, "disk_pct_used": None,
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
    # Same helper the 300s sampler uses, so the card and the stored history can
    # never disagree about what the disk looks like. Returns Nones on a failed
    # read; the card renders that as "unknown", never as a number.
    (metrics["disk_total_gb"],
     metrics["disk_free_gb"],
     metrics["disk_pct_used"]) = _collect_disk_capacity()
    metrics["timestamp"] = datetime.now().isoformat(timespec="seconds")
    metrics["fan_status"] = get_fan_status()
    return metrics


def _collect_disk_capacity(path=None):
    """Free/used capacity of the filesystem holding the DB.

    That filesystem — not `/` — is the one whose exhaustion actually stops
    Nemesis writing, so it is what gets sampled. Returns
    ``(total_gb, free_gb, pct_used)``, or three ``None``s if the read fails.

    A failed read must NOT come back as a number: `0.0` free is a legal-looking
    measurement that reads as a full disk, and would trip a low-disk warning
    that measured nothing. NULL is the only value the reader cannot mistake for
    a real reading.
    """
    target = path or os.path.dirname(DB_PATH)
    try:
        usage = psutil.disk_usage(target)
    except (OSError, ValueError) as e:
        log.warning("disk capacity read failed for %s: %s", target, e)
        return (None, None, None)
    return (
        round(usage.total / (1024 ** 3), 2),
        round(usage.free / (1024 ** 3), 2),
        round(usage.percent, 1),
    )


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

    (sample["disk_total_gb"],
     sample["disk_free_gb"],
     sample["disk_pct_used"]) = _collect_disk_capacity()

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
        # disk_total_gb/disk_free_gb/disk_pct_used are LOCAL-APPLIANCE capacity.
        # Remote agent samples arrive here too (the :5001 heartbeat handler calls
        # this same function) and legitimately carry none of them — agent-side
        # disk reporting is deliberately out of scope. `.get()` yields NULL for
        # those rows, which is the honest value: it must not be confused with a
        # real 0, and must never be back-filled from the server's own disk.
        c.execute(
            """INSERT INTO hw_metrics
            (timestamp, cpu_temp, ambient_temp, nvme_temp,
             fans_json,
             cpu_percent, ram_used_gb,
             disk_read_mb, disk_write_mb, net_in_mb, net_out_mb,
             gpu_temp, gpu_fan_percent, gpu_power_watts,
             disk_total_gb, disk_free_gb, disk_pct_used,
             is_anomalous, device_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)""",
            (
                s["timestamp"], s.get("cpu_temp"), s.get("ambient_temp"),
                s.get("nvme_temp"),
                json.dumps(s.get("fans", [])),
                s.get("cpu_percent"), s.get("ram_used_gb"),
                s.get("disk_read_mb"), s.get("disk_write_mb"),
                s.get("net_in_mb"), s.get("net_out_mb"),
                s.get("gpu_temp"), s.get("gpu_fan_percent"), s.get("gpu_power_watts"),
                s.get("disk_total_gb"), s.get("disk_free_gb"), s.get("disk_pct_used"),
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
                       throttle_detected, throttle_freq_mhz, sustained,
                       top_processes_ref
                FROM hw_anomaly_snapshots {where}
                ORDER BY captured_at DESC LIMIT ?""",
            params,
        ).fetchall()
        cols = ("id", "sensor_key", "reading_value", "baseline_avg", "deviation",
                "captured_at", "top_processes", "cpu_pct", "ram_mb",
                "net_mb_in", "net_mb_out", "disk_mb_read", "disk_mb_write",
                "throttle_detected", "throttle_freq_mhz", "sustained",
                "top_processes_ref")
        return [dict(zip(cols, r)) for r in rows]
    finally:
        conn.close()


TOP_PROC_ARCHIVE_DAYS = 14

# Archival primitives (archive_dir/ensure_archive_dir/write_archive/
# read_archive/verify_archive/selftest_verifier) live on the Data Manager —
# ONE implementation shared with its dm_operation_log coalescing. This file
# previously carried a near-identical private copy; a second copy of
# VERIFICATION logic is the dangerous kind, because a copy that drifts weaker
# keeps approving moves it should refuse and the failure looks like success.


def _dm():
    """The process-wide DataManager, created on first use.

    Same lazy construction `_db_connect` performs — factored out so the archival
    path can reach the shared helpers without opening a connection it does not
    need.
    """
    global _DM
    if _DM is None:
        _DM = data_manager.DataManager(DB_PATH)
        data_manager.set_namespace_mode("hw_monitor", data_manager.MODE_WARN)
    return _DM


def archive_old_top_processes(cutoff_days=TOP_PROC_ARCHIVE_DAYS, dry_run=False):
    """MOVE aged `top_processes` blobs into a verified archive file.

    This is a move, never a delete. Ordering is the correctness property: the
    archive is written, re-opened, and compared row-by-row against the live
    values BEFORE a single column is cleared. Any failure leaves the live data
    exactly as it was — a partial or unreadable archive must never be treated
    as a successful move.

    Archive files themselves are never removed by this or any other code path.
    Permanently destroying archived material is a user-initiated action only.
    """
    ok, why = _dm().selftest_verifier()
    if not ok:
        log.error("top_processes archival ABORTED — verifier self-test failed: %s", why)
        return {"status": "error", "error": f"verifier self-test failed: {why}"}

    conn = _db_connect()
    try:
        cutoff = f"-{int(cutoff_days)} days"
        rows = conn.execute(
            "SELECT id, captured_at, top_processes FROM hw_anomaly_snapshots "
            "WHERE captured_at < datetime('now','localtime',?) "
            "  AND top_processes IS NOT NULL AND top_processes != '' "
            "  AND top_processes_ref IS NULL",
            (cutoff,),
        ).fetchall()
        if not rows:
            return {"status": "ok", "archived": 0, "bytes": 0, "file": None}

        expected = {r[0]: r[2] for r in rows}
        total_bytes = sum(len(r[2]) for r in rows)
        if dry_run:
            return {"status": "ok", "archived": 0, "would_archive": len(rows),
                    "bytes": total_bytes, "file": None, "dry_run": True}

        adir = _dm().ensure_archive_dir()
        stamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
        fname = f"hw_anomaly_top_processes_{stamp}.jsonl.gz"
        final = os.path.join(adir, fname)
        if os.path.exists(final):
            return {"status": "error", "error": f"archive already exists: {fname}"}

        _dm().write_archive_manifested(final, ({"id": rid, "captured_at": cap,
                                     "top_processes": blob}
                                    for rid, cap, blob in rows))

        ok, why = _dm().verify_archive(final, expected, "top_processes")
        if not ok:
            log.error("top_processes archival ABORTED — %s (live data untouched, "
                      "archive kept for inspection: %s)", why, final)
            return {"status": "error", "error": why, "file": fname}

        # Verified. Only now is it safe to clear the live column.
        cur = conn.cursor()
        cur.executemany(
            "UPDATE hw_anomaly_snapshots SET top_processes=NULL, top_processes_ref=? "
            "WHERE id=?",
            [(fname, rid) for rid in expected],
        )
        conn.commit()
        log.info("top_processes archival: moved %d rows (%.1f MB) to %s",
                 len(expected), total_bytes / 1048576.0, fname)
        return {"status": "ok", "archived": len(expected),
                "bytes": total_bytes, "file": fname}
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


def _persist_lan_macs(conn, device_id, lan_macs, now=None):
    """Upsert reported LAN MAC(s) into agent_device_macs (ADR 0023 correlation key),
    within the caller's transaction. Normalises to lowercase colon-form and skips
    malformed/all-zero. Best-effort: never raises the enroll/heartbeat off course."""
    if not device_id or not lan_macs:
        return
    now = time.time() if now is None else now
    try:
        for raw in lan_macs:
            mac = (raw or "").strip().lower()
            if mac.count(":") != 5 or mac == "00:00:00:00:00:00":
                continue
            conn.execute(
                "INSERT INTO agent_device_macs (device_id, mac, last_seen) "
                "VALUES (?,?,?) ON CONFLICT(device_id, mac) DO UPDATE SET "
                "last_seen = excluded.last_seen",
                (device_id, mac, now))
    except Exception as e:                                   # noqa: BLE001
        log.warning("could not persist lan_macs for %s: %s", device_id, e)


def approved_agent_macs(conn):
    """Set of normalised LAN MACs belonging to APPROVED agents (ADR 0023). The
    caller matches devices.mac against this to compute has_agent. Read-any join."""
    try:
        rows = conn.execute(
            "SELECT m.mac FROM agent_device_macs m "
            "JOIN agent_devices a ON a.device_id = m.device_id "
            "WHERE a.enrollment_status = 'approved'").fetchall()
    except Exception as e:                                   # noqa: BLE001
        # A failed read must SURFACE, never default silently to a legal-looking
        # empty set — an empty result here reads as "no device is agent-connected",
        # indistinguishable from a real answer, and would silently disable the
        # whole ADR 0023 correlation (exactly how a use-after-close hid here once).
        log.error("approved_agent_macs read FAILED (%s) — correlation degraded to "
                  "empty; has_agent will be False for all devices this call", e)
        return set()
    return {(r[0] or "").strip().lower() for r in rows if r and r[0]}


#: Bounds on the agent-self-reported error digest (stage c). Everything below is
#: UNTRUSTED input from the endpoint (arriving on an authenticated heartbeat, so
#: bound to THIS device, but the CONTENTS are the agent's own claims). Cap the
#: entry count and string lengths so a buggy/hostile agent cannot flood the
#: server or smuggle oversized fields; validate the code shape; parameterize the
#: write; never make a security DECISION off these (they are hints).
_AGENT_ERR_CODE_RE = _re.compile(r"^E-AGENT-\d{3}$")
_AGENT_ERR_MAX_ENTRIES = 32        # > the ~20-code catalog, still hard-bounded
_AGENT_ERR_MAX_CONTEXT = 300
_AGENT_ERR_MAX_TS = 40


def _ingest_agent_errors(payload, device_id, conn):
    """Store the authenticated device's self-reported E-AGENT digest, bounded and
    append-only. Best-effort — NEVER raises out; a bad digest must not break the
    heartbeat it rode in on (same posture as ingest_connection_events). Returns
    how many entries were stored.

    Trust boundary: `device_id` is the AUTHENTICATED device (per-device
    isolation — an agent reports only its own), but the entries are the agent's
    own claims. Validate/bound every field; store as hints, decide nothing.
    """
    try:
        reports = payload.get("agent_errors")
        if not isinstance(reports, list) or not reports:
            return 0
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        stored = 0
        for e in reports[:_AGENT_ERR_MAX_ENTRIES]:      # cap ENTRIES
            if not isinstance(e, dict):
                continue
            code = e.get("code")
            if not isinstance(code, str) or not _AGENT_ERR_CODE_RE.match(code):
                continue                                # validate ^E-AGENT-\d{3}$
            try:
                count = int(e.get("count") or 0)
            except (TypeError, ValueError):
                continue
            if count <= 0:
                continue
            # Agent-sent severity — the agent's own catalog is the source of truth,
            # so the server stores it and gates on it rather than keeping its own
            # map. Only accept the canonical values; anything else -> NULL (a
            # pre-severity agent, or junk), and the ticket bridge treats NULL as
            # "cannot rank -> do not ticket" (conservative during rollout).
            sev = e.get("severity")
            if sev not in ("low", "medium", "high"):
                sev = None
            ctx = e.get("context")
            if ctx is not None:
                ctx = str(ctx)[:_AGENT_ERR_MAX_CONTEXT]  # cap CONTEXT
            first = (str(e.get("first"))[:_AGENT_ERR_MAX_TS] if e.get("first") else None)
            last = (str(e.get("last"))[:_AGENT_ERR_MAX_TS] if e.get("last") else None)
            conn.execute(                                # PARAMETERIZED
                "INSERT INTO agent_error_reports "
                "(device_id, code, severity, count, first_ts, last_ts, context, "
                " received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (device_id, code, sev, count, first, last, ctx, now))
            stored += 1
        if stored:
            conn.commit()
        return stored
    except Exception as e:                              # noqa: BLE001
        log.warning("agent_error ingest failed for %s: %s", device_id, e)
        return 0


def _update_agent_device(payload, remote_ip=None):
    """Upsert agent_devices row from a nemesis_agent POST."""
    device_id   = payload.get("device_id", "local")
    device_name = payload.get("device_name", device_id)
    device_type = payload.get("device_type", "")
    conn_type   = payload.get("connection_type", "")
    # ── agent_last_seen is the SERVER'S RECEIPT TIME, never the agent's clock ──
    #
    # This used to be `payload.get("timestamp")` -- the agent's own
    # `datetime.now().isoformat()`, i.e. NAIVE time in the AGENT's timezone.
    # Every reader compares it against the SERVER's naive `datetime.now()`:
    #   dashboard._agent_checkin_state      (the check-in label + revoke advice)
    #   dashboard._agent_status_from_seen   (online/offline badge + scan gating)
    #   this file's `extended_absence`      (auto-queues a catch-up scan)
    # Both operands were naive, so Python subtracted them happily -- no
    # TypeError, no warning, just an answer wrong by the offset difference.
    #
    # Measured live 2026-08-20: gateway on Etc/UTC, agents on America/Chicago.
    # A node that had beaten 0 seconds earlier computed an age of 18000s against
    # a 1800s staleness threshold -- 10x over -- so every healthy node rendered
    # as "no check-in since ...", whose note ends "If you think it may be lost or
    # stolen, revoke it." West-of-server agents were indistinguishable from dead
    # ones; east-of-server agents tripped the "in the future" branch instead.
    #
    # The timezone mix was the symptom; sourcing this column from the agent was
    # the design error. "When did the server last hear from this device" is a
    # fact the SERVER knows authoritatively, and stamping it here -- at the
    # moment the heartbeat is being processed -- puts it in the same frame as
    # every reader's `datetime.now()` by construction.
    #
    # It also takes the agent's clock out of the trust path: unlike `signed_at`,
    # this value is NOT skew-checked (dashboard.py:4691-4693 says so), so a
    # wrong, drifting, or falsified agent clock could previously claim any
    # freshness it liked. It cannot now.
    #
    # NOTE the deliberate asymmetry with `signed_at`, which is aware-UTC: this
    # stays NAIVE-LOCAL because that is the frame all three readers already use,
    # so they need no change and cannot be left half-converted. The residual
    # weakness is the server's own DST transition (a bounded ~1h misread twice a
    # year), against the permanent multi-hour error this replaces. Moving the
    # whole column to aware-UTC is a strictly better end state and needs all
    # three readers converted in the same commit -- do not convert one alone.
    #
    # Legacy agent-frame values already in the table are NOT reinterpreted --
    # they cannot be, the offset they were written in is unrecoverable. Each is
    # superseded by a correct value on that device's next heartbeat.
    #
    # ⚠ `_create_enrollment` stamps this SAME column and already uses the
    # server's clock (its own `now`, hw_monitor.py:3790). That agreement is what
    # makes the column single-framed -- if either writer moves, move both.
    ts          = datetime.now().isoformat(timespec="seconds")
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
            _persist_lan_macs(conn, device_id, payload.get("lan_macs"))
            lt = payload.get("link_type")
            if lt:
                conn.execute("UPDATE agent_devices SET link_type=? WHERE device_id=?",
                             (lt, device_id))
            # Tier 1 attestation state, recorded after the upsert so the row
            # exists. Deliberately NOT folded into the upsert above: an agent
            # that omits the field entirely must leave the stored state alone
            # rather than overwrite it via `excluded.*` with an empty value.
            # Failure to record is non-fatal — losing a heartbeat over an
            # attestation write would be a worse outcome than a stale state.
            try:
                from alert_manager import attestation
                attestation.record_attestation(conn, device_id, ah)
                # Self-sustaining: a device that is not attested gets a manifest
                # queued on this beat, deduplicated against one already in
                # flight. Without this, attestation only ever works when an
                # operator remembers to trigger it by hand.
                ensure_manifest_queued(conn, device_id)
                # Tier 2: queue a challenge on cadence, and ingest any response the
                # agent sent in the dedicated heartbeat field (parallel channel to
                # attestation_state; the task-result channel truncates at 400 chars).
                ensure_challenge_queued(conn, device_id)
                _cresp = payload.get("attest_challenge_response")
                if _cresp:
                    from alert_manager import attestation as _att_c   # noqa: PLC0415
                    # ATTESTATION'S OWN CONNECTION, not the heartbeat's (2026-08-29).
                    #
                    # ingest_challenge_response() now touches only attestation's
                    # tables — it reads the challenge, records the verdict to
                    # `attestation_tier2_state`, and deletes the challenge. All
                    # three land in ONE transaction on ONE connection owned by
                    # ONE namespace, which is why there is no torn write to
                    # reason about here any more.
                    #
                    # Passing `conn` (hw_monitor's) would put an
                    # out-of-namespace DELETE back inside the heartbeat
                    # transaction — the exact coupling this restructuring
                    # removed. The verdict no longer lives on agent_devices, so
                    # nothing here needs to share that transaction.
                    _ich = _dm().connect("attestation")
                    try:
                        _att_c.ingest_challenge_response(_ich, device_id, _cresp)
                        _ich.commit()
                    finally:
                        _ich.close()
            except Exception as _ae:                      # noqa: BLE001
                log.warning("attestation record failed for %s: %s", device_id, _ae)

            # Observation layer (process enumeration + UDP attribution).
            # Same shape and same reasoning as the attestation write above: a
            # separate UPDATE after the row exists, and ONLY when the agent
            # actually sent the field. An older agent that does not report
            # `observation` must leave the stored snapshot alone rather than
            # blank it — a wiped snapshot is indistinguishable from a host with
            # nothing running, which is never a true statement.
            #
            # Stored as the CURRENT snapshot, overwritten per beat, in the
            # long-declared-but-never-written last_heartbeat_data column. History
            # is deliberately NOT kept here: at ~70KB per beat per device it
            # needs a retention policy of its own, which is a separate decision
            # rather than something to inherit by accident.
            try:
                obs = payload.get("observation")
                if isinstance(obs, dict) and obs:
                    conn.execute(
                        "UPDATE agent_devices SET last_heartbeat_data=? WHERE device_id=?",
                        (json.dumps(obs), device_id),
                    )
            except Exception as _oe:                      # noqa: BLE001
                # Non-fatal for the same reason attestation is: losing a whole
                # heartbeat over an observation write would be the worse outcome.
                log.warning("observation record failed for %s: %s", device_id, _oe)

            # Detection-engine inventory (ADR 0004 hinge (b)). Stored as the current
            # snapshot per beat, with the time it was reported so the dashboard can
            # show stale/uneven coverage. Non-fatal: losing a whole heartbeat over
            # this write is the worse outcome.
            try:
                eng = payload.get("engine_inventory")
                if isinstance(eng, dict) and eng.get("engines"):
                    conn.execute(
                        "UPDATE agent_devices SET engine_inventory_json=?, "
                        "engine_inventory_at=? WHERE device_id=?",
                        (json.dumps(eng),
                         datetime.now().isoformat(timespec="seconds"), device_id),
                    )
            except Exception as _ee:                      # noqa: BLE001
                log.warning("engine inventory record failed for %s: %s", device_id, _ee)

            # Behavioral-detection findings (Malware Layer B, behavioral half). The
            # endpoint sends already-deduped/rate-capped events; validate each against
            # the shared schema and record valid ones as malware_findings (attested
            # endpoint claims). Non-fatal: a bad batch must not cost the heartbeat.
            try:
                bev = payload.get("behavioral_events")
                if isinstance(bev, list) and bev:
                    import behavioral_ingest
                    _bi = behavioral_ingest.ingest_behavioral(
                        conn, device_id, payload.get("device_name") or device_id,
                        bev, datetime.now().isoformat(timespec="seconds"))
                    if _bi["accepted"] or _bi["rejected"]:
                        log.info("behavioral ingest %s: accepted=%d rejected=%d",
                                 device_id, _bi["accepted"], _bi["rejected"])
            except Exception as _be:                      # noqa: BLE001
                log.warning("behavioral ingest failed for %s: %s", device_id, _be)

            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        log.warning("_update_agent_device failed: %s", e)


# ── Scan queue trigger engine ─────────────────────────────────────────────────

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
                    # queued_at supplied explicitly (ADR 0004 step 2). It used to
                    # come from DEFAULT CURRENT_TIMESTAMP, which is UTC; that
                    # default is gone, so omitting the column here would now
                    # write NULL rather than a wrong-but-present time.
                    "INSERT INTO scan_queue "
                    "(device_id, trigger_type, trigger_detail, scan_path, queued_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (device_id, trigger_type, trigger_detail or "", scan_path or "/",
                     datetime.now().isoformat(timespec="seconds")),
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


# Trust-boundary reinstatement. Its own trigger_type so the reason a scan ran is
# recoverable later, and so the targeted dedup below cannot be confused by an
# ordinary pending scan.
REINSTATEMENT_TRIGGER = "reinstated"

# Statuses that mean trust was WITHDRAWN or never granted. Returning to
# 'approved' from any of these is a trust-boundary crossing and forces a scan.
#
# 'rejected' belongs here for the same reason as 'revoked': the owner refused
# this device, and later admitting it is a decision about a machine whose state
# nobody has checked since. The agent SERVICE is still installed after a
# rejection — it exits rather than being removed — so on its next start it polls,
# sees 'approved', and proceeds. That makes the transition real, not theoretical.
#
# 'pending' is deliberately absent: a first-time approval is not a re-admission,
# and that path already has both the pre-enrollment scan and first_connect.
TRUST_WITHDRAWN_STATUSES = ("revoked", "uninstalled", "rejected")


def queue_reinstatement_scan(device_id, from_status, actor=None):
    """MANDATORY scan for a device crossing back over the trust boundary.

    Returns (queued: bool, reason: str) — never a bare bool, and never silence.

    Deliberately NOT routed through the `scan_conditions` table like
    first_connect and its siblings. Those are configurable preferences; this is
    not. A revocation exists precisely because trust was withdrawn, and the
    window is irrelevant — an hour is enough to introduce something. Making this
    switchable would mean the one scan that must not be optional could be turned
    off from a settings page.

    Also NOT routed through `_queue_scan`, for a subtler reason: that helper
    skips insertion when ANY pending scan already exists for the device, and
    reports nothing back. A mandatory scan suppressed by an unrelated pending row
    — with the caller unable to tell — is exactly the shape this codebase treats
    as a defect. The dedup here is narrowed to this trigger only, so repeated
    approve clicks cannot pile up while an ordinary pending scan cannot swallow
    the mandatory one.
    """
    try:
        conn = _db_connect()
        try:
            existing = conn.execute(
                "SELECT id FROM scan_queue WHERE device_id=? AND status='pending' "
                "AND trigger_type=?", (device_id, REINSTATEMENT_TRIGGER)).fetchone()
            if existing:
                log.info("reinstatement scan already pending for device=%s "
                         "(queue_id=%s) — not duplicating", device_id, existing[0])
                return (False, "already_pending")
            detail = "reinstated from %s" % (from_status or "unknown")
            if actor:
                detail += " by %s" % actor
            conn.execute(
                "INSERT INTO scan_queue "
                "(device_id, trigger_type, trigger_detail, scan_path, queued_at, actor) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (device_id, REINSTATEMENT_TRIGGER, detail, "/",
                 datetime.now().isoformat(timespec="seconds"), actor))
            conn.commit()
        finally:
            conn.close()
        log.warning("MANDATORY reinstatement scan queued: device=%s from=%s actor=%s",
                    device_id, from_status, actor)
        return (True, "queued")
    except Exception as e:
        # Reported as an explicit failure, never swallowed. A reinstatement whose
        # mandatory scan silently failed to queue is a device readmitted with no
        # check at all, which the caller must be able to see.
        log.error("FAILED to queue mandatory reinstatement scan for device=%s: %s",
                  device_id, e)
        return (False, "error: %s" % e)


def _conn_schema():
    """Import the ONE connection-event schema definition (Track C Piece 1).

    Same cross-package pattern `alert_manager/attestation.py` uses for
    `nemesis_agent.attest`. The repo root is derived from __file__ rather than
    assumed to be on sys.path — this process runs with PYTHONPATH pointed at
    alert_manager/, not at the repo root, so relying on the ambient path would
    work in a dev shell and fail as a service.
    """
    import sys as _sys                                   # noqa: PLC0415
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if root not in _sys.path:
        _sys.path.insert(0, root)
    from nemesis_agent import conn_events                # noqa: PLC0415
    return conn_events


def _conn_seen():
    """Import the seen-set module (Track C step 5).

    Lives in alert_manager/, which is on this process's PYTHONPATH — the same
    route `import database` already takes from main(). Imported lazily so a
    missing or broken seen-set module degrades to "no novelty tracking" rather
    than preventing the service from starting and stopping telemetry ingest
    altogether.
    """
    import conn_seen                                     # noqa: PLC0415
    return conn_seen


def _server_consent_version(conn, device_id):
    """The consent version this SERVER has recorded for a device, or None.

    Requirement 0 clause 5 rests on this: "a buggy, downgraded, or tampered agent
    must not be able to push data the user never agreed to". The agent's own local
    consent record is not evidence to the server — this is.

    Fails CLOSED. No row, a revoked row, an unreadable table, or any error at all
    returns None, and None means reject. There is no branch here that turns a
    failure into permission.
    """
    try:
        row = conn.execute(
            "SELECT consent_version, revoked_at FROM conn_consent WHERE device_id=?",
            (device_id,)).fetchone()
    except Exception:                                    # noqa: BLE001
        log.exception("conn ingest: consent lookup failed for %s — rejecting", device_id[:12])
        return None
    if not row:
        return None
    if row[1]:                       # revoked_at set => consent withdrawn
        return None
    v = row[0]
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def ingest_connection_events(payload):
    """Track C step 3 — accept connection events from a heartbeat payload.

    Returns a counts dict; callers log it. Never raises: a malformed telemetry
    block must not break heartbeat processing for everything else in the payload.

    Order is deliberate — CONSENT IS CHECKED BEFORE ANYTHING IS PARSED OR STORED.
    Validating first and checking consent later would mean unconsented data had
    already been through the parser, and any early-return bug in between would
    leak it into the store.
    """
    counts = {"received": 0, "stored": 0, "rejected_no_consent": 0,
              "rejected_consent_mismatch": 0, "rejected_invalid": 0}
    try:
        ce = _conn_schema()
        security = payload.get("security", {}) or {}
        events = security.get(ce.PAYLOAD_KEY)
        if not events:
            return counts
        if not isinstance(events, list):
            log.warning("conn ingest: %s is not a list — rejecting whole block", ce.PAYLOAD_KEY)
            counts["rejected_invalid"] = 1
            return counts
        counts["received"] = len(events)

        device_id = payload.get("device_id") or ""
        if not device_id:
            counts["rejected_no_consent"] = len(events)
            log.warning("conn ingest: payload has no device_id — rejecting %d event(s)",
                        len(events))
            return counts

        conn = _db_connect()
        try:
            server_version = _server_consent_version(conn, device_id)
            if server_version is None:
                # THE CLAUSE 5 GATE. Logged, not silent: the plan requires the
                # rejection be recorded, because a device pushing data it has no
                # consent for is a signal in its own right.
                counts["rejected_no_consent"] = len(events)
                log.warning("conn ingest: REJECTED %d event(s) from device %s — no "
                            "recorded consent on this server", len(events), device_id[:12])
                return counts

            now = datetime.now().isoformat(timespec="seconds")
            rows = []
            # Track C step 5. Built from the SAME loop that builds `rows`, and
            # only from records that survive every gate above — so the seen-set
            # can never learn a destination from an event that was rejected for
            # want of consent. Deriving it from `rows` afterwards would work
            # today and break the moment a column is inserted, since that is
            # positional; this is not.
            observations = []
            for rec in events:
                ok, errors = ce.validate(rec)
                if not ok:
                    counts["rejected_invalid"] += 1
                    # Rule 8: log the validation reason, never the record — a
                    # record contains a destination and a process path.
                    log.warning("conn ingest: invalid event from %s: %s",
                                device_id[:12], "; ".join(errors)[:200])
                    continue
                if rec["consent_version"] != server_version:
                    # The agent claims a disclosure version the server did not
                    # record. Stale agent, ahead-of-server agent, or tampering —
                    # all three are "do not store", not "store and sort out later".
                    counts["rejected_consent_mismatch"] += 1
                    log.warning("conn ingest: consent_version %r from %s != server's %r "
                                "— rejected", rec["consent_version"], device_id[:12],
                                server_version)
                    continue
                if rec["device_id"] != device_id:
                    # A record claiming to be from another device inside this
                    # device's authenticated payload.
                    counts["rejected_invalid"] += 1
                    log.warning("conn ingest: event device_id mismatch from %s — rejected",
                                device_id[:12])
                    continue
                rows.append((
                    rec["device_id"], rec["conn_id"], rec["event"], rec["consent_version"],
                    rec["proto"], rec["laddr"], rec["lport"], rec["raddr"], rec["rport"],
                    rec["ts_open_wall"], rec["ts_open_mono"],
                    rec.get("ts_close_wall"), rec.get("ts_close_mono"),
                    rec.get("pid"), rec.get("proc_name"), rec.get("proc_path"),
                    rec.get("proc_signed"), rec.get("bytes_sent"), rec.get("bytes_recv"),
                    rec.get("resolved_name"), rec.get("resolved_name_source"),
                    now))
                observations.append((rec["raddr"], rec.get("resolved_name"),
                                     rec["event"] == ce.EVENT_OPEN))
            if rows:
                conn.executemany(
                    "INSERT INTO conn_events (device_id, conn_id, event, consent_version, "
                    "proto, laddr, lport, raddr, rport, ts_open_wall, ts_open_mono, "
                    "ts_close_wall, ts_close_mono, pid, proc_name, proc_path, proc_signed, "
                    "bytes_sent, bytes_recv, resolved_name, resolved_name_source, received_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
                # Seen-set population, INSIDE the same transaction as the insert
                # above and committed with it. If it were committed separately,
                # a crash between the two would leave events stored whose
                # destinations the seen-set never learned — and those
                # destinations would then read as novel forever after, since
                # nothing ever revisits an old event to backfill.
                try:
                    seen_counts = _conn_seen().record_destinations(
                        conn, device_id, observations, now)
                    counts["seen_new"] = seen_counts.get("created", 0)
                    counts["seen_merged"] = seen_counts.get("merged", 0)
                    if seen_counts.get("errors"):
                        log.warning("conn ingest: seen-set recorded %d error(s) "
                                    "for device %s", seen_counts["errors"],
                                    device_id[:12])
                except Exception:                        # noqa: BLE001
                    # Novelty tracking is a consumer of ingest, not a
                    # precondition for it. Losing the seen-set update must not
                    # cost us the events themselves — but it is never silent.
                    log.exception("conn ingest: seen-set population FAILED for "
                                  "device %s — events still stored, novelty for "
                                  "this batch is not tracked", device_id[:12])
                conn.commit()
                counts["stored"] = len(rows)
        finally:
            conn.close()
    except Exception:                                    # noqa: BLE001
        log.exception("conn ingest: unexpected failure — no events stored this cycle")
    return counts


#: Wall-clock of the last retention sweep. Module-level so the loop can rate
#: limit it without a class or a closure.
_last_conn_reap = 0.0
_last_error_ticket_scan = 0.0


def reap_conn_events():
    """Enforce the retention window. Returns rows deleted, or -1 on failure.

    The plan requires retention "enforced by a real reaper, not by intention".
    Returns -1 rather than 0 on error so a caller cannot read a failure as a
    clean sweep — 0 is a real answer meaning "nothing was old enough".
    """
    try:
        conn = _db_connect()
        try:
            try:
                row = conn.execute(
                    "SELECT value FROM settings WHERE key='conn_event_retention_days'"
                ).fetchone()
                days = int(row[0]) if row and row[0] is not None else 30
            except Exception:                            # noqa: BLE001
                days = 30
            # Clamp: a corrupt or hostile setting must not disable retention
            # outright (0 = delete everything, or a huge value = keep forever).
            days = max(1, min(days, 365))
            cutoff = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")
            cur = conn.execute("DELETE FROM conn_events WHERE received_at < ?", (cutoff,))
            deleted = cur.rowcount or 0
            conn.commit()
            if deleted:
                log.info("conn reaper: deleted %d event(s) older than %d days",
                         deleted, days)
            return deleted
        finally:
            conn.close()
    except Exception:                                    # noqa: BLE001
        log.exception("conn reaper: failed — retention NOT enforced this cycle")
        return -1


def _setting_int(conn, key, default):
    """Read an integer setting. Returns `default` only when the key is genuinely
    absent or unusable — and says which in the log, so a misconfigured value is
    not mistaken for an unset one."""
    try:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    except Exception:                                    # noqa: BLE001
        log.exception("could not read setting %s — using default %d", key, default)
        return default
    if not row or row[0] is None:
        return default
    try:
        return int(row[0])
    except (TypeError, ValueError):
        log.warning("setting %s holds a non-integer value — using default %d",
                    key, default)
        return default


def reap_conn_seen():
    """Enforce the SEEN-SET's own retention. Returns rows deleted, or -1 on failure.

    Separate from `reap_conn_events` on purpose, and not merely for tidiness: the
    two windows are deliberately different lengths, and the seen-set's is floored
    at the event window so it can never expire a destination whose raw events are
    still on file. `conn_seen.effective_retention_days` owns that arithmetic.

    Returns -1 rather than 0 on error, matching the event reaper — 0 is a real
    answer meaning nothing was old enough.
    """
    try:
        cs = _conn_seen()
        conn = _db_connect()
        try:
            seen_days = _setting_int(conn, "conn_seen_retention_days", 365)
            event_days = _setting_int(conn, "conn_event_retention_days", 30)
            now = datetime.now().isoformat(timespec="seconds")
            res = cs.reap(conn, seen_days, event_days, now)
            conn.commit()
            total = res["destinations"] + res["addrs"] + res["orphans"]
            if total:
                log.info("conn seen-set reaper: deleted %d destination(s), %d "
                         "address row(s), %d orphan(s) older than %d days",
                         res["destinations"], res["addrs"], res["orphans"],
                         res["days"])
            return total
        finally:
            conn.close()
    except Exception:                                    # noqa: BLE001
        log.exception("conn seen-set reaper: failed — seen-set retention NOT "
                      "enforced this cycle")
        return -1


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
            except Exception as exc:
                # E-HWMON-002 — a device that SHOULD have been queued for a
                # returning-from-extended-absence scan silently isn't: a bad
                # stored threshold, a malformed prev_last_seen, or the queue
                # insert itself all land here, and nothing else records that
                # the scan never happened.
                _errors_record("E-HWMON-002", {"fn": "process condition triggers",
                                               "trigger": "extended_absence",
                                               "error": f"{type(exc).__name__}: {exc}"})

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


#: Cap on tasks carried by a single heartbeat response. A device that has
#: accumulated a backlog gets it drained across several beats rather than one
#: unbounded response — an agent that chokes on a huge body would then fail to
#: heartbeat at all, turning a queue problem into an outage.
MAX_TASKS_PER_BEAT = 5


def task_age_basis(origin_queued_at, created_at):
    """The timestamp any staleness question must be measured from. Pure.

    `origin_queued_at` wins when present, because it is when the WORK was first
    queued; `created_at` is only when this particular row was written. For a task
    that entered through scan_queue those differ by however long the device was
    offline, and using created_at would report months-old work as brand new.

    Returns None if NEITHER is usable — an explicit "cannot determine age", never
    a default that a caller could mistake for a real measurement. A caller that
    gets None must not treat the task as fresh.
    """
    for value in (origin_queued_at, created_at):
        if not value:
            continue
        try:
            return datetime.fromisoformat(value)
        except (TypeError, ValueError):
            continue
    return None


def enqueue_task(device_id, action, params=None, ttl_seconds=1800, actor=None,
                 origin_queued_at=None):
    """Queue one task for a device. Returns its task_id.

    Queuing is deliberately separate from signing: a row here is an intent, and
    the envelope is only built (and signed) at the moment it is actually handed
    to the device, so `expires_at` is measured from delivery rather than from
    whenever an operator happened to click.

    `origin_queued_at` carries the ORIGINAL queue time for work that arrived via
    an earlier queue. Pass it whenever this task is a re-expression of something
    already waiting, or the age of that wait is lost at the boundary.
    """
    import uuid
    task_id = str(uuid.uuid4())
    conn = _db_connect()
    try:
        conn.execute(
            "INSERT INTO scan_tasks (task_id, device_id, action, params_json, "
            "status, created_at, actor, origin_queued_at) "
            "VALUES (?,?,?,?,'pending',?,?,?)",
            (task_id, device_id, action, json.dumps(params or {}),
             datetime.now().isoformat(timespec="seconds"), actor,
             origin_queued_at))
        conn.commit()
    finally:
        conn.close()
    return task_id


def _device_anchor_fingerprint(device_id):
    """Which server key this device is on, or None if never rotated.

    Derived from its own completed rotation tasks — NO new column on a live
    table. The fingerprint stored in a rotation task's params IS the epoch
    marker: a completed rotation from an earlier epoch carries that epoch's
    fingerprint and so can never be mistaken for the current one.

    None is a real answer ("still on whatever it was installed with"), not a
    failure default — the caller distinguishes it from a known fingerprint.
    """
    conn = _db_connect()
    try:
        rows = conn.execute(
            "SELECT params_json FROM scan_tasks WHERE device_id=? AND action=? "
            "AND status='completed' ORDER BY id DESC LIMIT 1",
            (device_id, server_keys_rotate_action())).fetchall()
    finally:
        conn.close()
    for (params_json,) in rows:
        try:
            return json.loads(params_json or "{}").get("new_key_sha256")
        except Exception:
            return None
    return None


def server_keys_rotate_action():
    import server_keys
    return server_keys.ROTATE_ACTION


def enqueue_rotation(device_id, actor=None):
    """Queue a server-key rotation for one device. Returns task_id.

    The envelope itself is built and signed at DELIVERY (in _tasks_for_response),
    not here, because which key must sign it depends on which anchor the device
    is on at that moment — and that can change between queuing and delivery.
    """
    import server_keys
    if not server_keys.staged_fingerprint():
        raise RuntimeError("no staged keypair — stage a rotation first")
    return enqueue_task(device_id, server_keys.ROTATE_ACTION, {}, actor=actor)


def enqueue_manifest(device_id, actor=None):
    """Queue a Tier 1 attestation manifest for one device. Returns task_id.

    Params are EMPTY on purpose. Like `enqueue_rotation` above, the payload is
    built at DELIVERY (in `_tasks_for_response`) rather than here: a manifest
    describes the agent build the server currently ships, and one frozen at
    queue time would be delivered stale after any agent update — reporting every
    updated device as build-skewed for no reason.
    """
    return enqueue_task(device_id, "attest_manifest", {}, actor=actor)


def ensure_manifest_queued(conn, device_id):
    """Queue a manifest if the device has none and none is already in flight.

    This is what makes attestation self-sustaining rather than a manual trigger:
    a device reporting anything other than `attested` gets a manifest on its next
    beat, and one already pending or dispatched suppresses a duplicate.

    The in-flight check is load-bearing. Without it every heartbeat from an
    unattested device queues another task, which on a poll cadence is a
    slow-motion queue flood — and a device is unattested for the entire window
    between first contact and its first successful attestation, which is exactly
    when heartbeats are most frequent.

    Best-effort: never raises into the heartbeat path. Failing to queue leaves
    the device `absent`, which is the truthful state anyway.
    """
    try:
        row = conn.execute(
            "SELECT attestation_state FROM agent_devices WHERE device_id=?",
            (device_id,)).fetchone()
        if row and row[0] == "attested":
            return None
        pending = conn.execute(
            "SELECT 1 FROM scan_tasks WHERE device_id=? AND action='attest_manifest' "
            "AND status IN ('pending','dispatched') LIMIT 1", (device_id,)).fetchone()
        if pending:
            return None
        return enqueue_manifest(device_id, actor="system")
    except Exception as exc:                                  # noqa: BLE001
        log.warning("could not queue manifest for %s: %s", device_id, exc)
        return None


def ensure_challenge_queued(conn, device_id):
    """Queue a Tier 2 attest_challenge for a device on a cadence, deduped against one
    already in flight. Parallel to ensure_manifest_queued (heartbeat-triggered), but
    gated on: the private Tier 2 module being deployed, AND the last challenge being
    older than attestation_interval_hours. Best-effort; never raises into the beat."""
    try:
        from alert_manager import attestation as _att        # noqa: PLC0415
        if not _att.tier2_available():
            return None
        try:
            interval_h = float(database.get_setting("attestation_interval_hours", "24"))
        except Exception:                                    # noqa: BLE001
            interval_h = 24.0
        row = conn.execute("SELECT issued_at FROM agent_attestation_challenges "
                           "WHERE device_id=?", (device_id,)).fetchone()
        if row and (time.time() - float(row[0])) < interval_h * 3600:
            return None                                      # not due yet
        pending = conn.execute(
            "SELECT 1 FROM scan_tasks WHERE device_id=? AND action=? "
            "AND status IN ('pending','dispatched') LIMIT 1",
            (device_id, _att.TIER2_CHALLENGE_ACTION)).fetchone()
        if pending:
            return None
        return enqueue_task(device_id, _att.TIER2_CHALLENGE_ACTION, ttl_seconds=3600)
    except Exception as exc:                                  # noqa: BLE001
        log.warning("could not queue challenge for %s: %s", device_id, exc)
        return None


def rotation_readiness():
    """Per-device rotation state for the operator, plus whether cutover is safe.

    Reports devices that are NOT ready rather than only a count: "3 pending" is
    not actionable, and cutting over while a device is pending strands it.
    """
    import server_keys
    target = server_keys.staged_fingerprint() or server_keys.current_fingerprint()
    conn = _db_connect()
    try:
        devices = [r[0] for r in conn.execute(
            "SELECT device_id FROM agent_devices "
            "WHERE enrollment_status='approved'").fetchall()]
    finally:
        conn.close()
    ready, pending = [], []
    for d in devices:
        (ready if _device_anchor_fingerprint(d) == target else pending).append(d)
    return {"target_fingerprint": target, "ready": ready, "pending": pending,
            "safe_to_cutover": not pending}


def enqueue_rules_update(device_id, profile, rules_url, actor=None):
    """Queue a ruleset update with the content digest bound in. Returns task_id.

    The digest is computed HERE, at enqueue time, from the same bytes the
    serving route resolves — so the server attests to specific content, not
    merely to a URL. `params` is signed as part of the envelope, which makes the
    signature cover the digest and the digest cover the content.

    RAISES rather than enqueueing an unverifiable task. An update task whose
    digest could not be computed would be refused by every agent that received
    it; creating one anyway would turn a server-side misconfiguration into a
    fleet-wide silent failure discovered only in agent logs.

    TOCTOU is real and deliberately fails closed: if the ruleset changes between
    enqueue and fetch, the digest will not match and the agent refuses the
    update. The operator re-issues. The alternative — accepting whatever arrives
    — is the hole this exists to close.
    """
    import rules_dist
    d = rules_dist.rules_digest(profile)       # raises RulesUnavailable
    return enqueue_task(device_id, "update_rules",
                        {"rules_url": rules_url, "profile": d["profile"],
                         "sha256": d["sha256"], "size": d["size"]},
                        actor=actor)


# Redelivery (ADR 0004 Stage 1). A task handed to a device that never reports is
# stuck in 'dispatched' forever: step 4's result reporting makes that visible,
# and this is the remedy. Total deliveries per task, including the first.
REDELIVERY_MAX_ATTEMPTS = 3

# Explicit sentinel for "this row's expiry could not be read". Returned INSTEAD of
# a real decision so an unreadable row can never be mistaken for one that was
# examined and deliberately left alone -- a failed read must not wear the costume
# of a legitimate answer.
REDELIVER_UNREADABLE = "unreadable"


def _redelivery_decision(status, expires_at, dispatch_count, now):
    """What to do with one task. Pure — no DB, no clock of its own.

    Returns 'leave' | 'redeliver' | 'abandon' | REDELIVER_UNREADABLE.

    A task sitting in 'dispatched' past its envelope expiry is one whose delivery
    OR whose response was lost — the agent either never received it, or ran it and
    the report never arrived. Those two are indistinguishable from here, which is
    why redelivery has to be *safe* rather than merely *probably fine*: the
    agent's atomic claim (tasks.claim_task) refuses a task_id it has already
    executed, so a redelivery to a device that already ran it is a no-op rather
    than a second execution. That is what makes at-least-once delivery honest here
    instead of dangerous.

    Only 'dispatched' is ever touched. A 'completed' or 'failed' task has an
    answer, and re-sending it would overwrite a real outcome with a fresh attempt.
    """
    if status != "dispatched":
        return "leave"
    try:
        exp = datetime.fromisoformat(expires_at)
    except Exception:
        return REDELIVER_UNREADABLE
    # Not yet expired: the device may still be working on it. Redelivering here
    # would be the one case that genuinely races the agent.
    if now <= exp:
        return "leave"
    try:
        attempts = int(dispatch_count)
    except Exception:
        return REDELIVER_UNREADABLE
    if attempts >= REDELIVERY_MAX_ATTEMPTS:
        return "abandon"
    return "redeliver"


def _requeue_expired_tasks(device_id, now=None):
    """Return timed-out tasks to 'pending'; abandon ones past the attempt limit.

    Returns (requeued, abandoned). Runs on the device's own heartbeat, so no
    separate scheduler is needed — a device that never checks in has no stuck
    tasks worth reviving anyway.
    """
    now = now or datetime.now()
    requeued = abandoned = 0
    try:
        conn = _db_connect()
        try:
            rows = conn.execute(
                "SELECT task_id, status, expires_at, dispatch_count FROM scan_tasks "
                "WHERE device_id=? AND status='dispatched'", (device_id,)).fetchall()
            for task_id, status, expires_at, dispatch_count in rows:
                decision = _redelivery_decision(status, expires_at,
                                                dispatch_count, now)
                if decision == "redeliver":
                    # task_id is deliberately PRESERVED. The agent's claim store is
                    # keyed on it, and that identity is the whole reason a
                    # redelivery to a device that already ran this task is a no-op.
                    # A fresh task_id would defeat the claim and run it twice.
                    conn.execute(
                        "UPDATE scan_tasks SET status='pending' WHERE task_id=?",
                        (task_id,))
                    requeued += 1
                elif decision == "abandon":
                    # result_ok is left NULL on purpose: that column means "what the
                    # device attested", and nothing was attested here. The detail is
                    # prefixed so its server-side provenance is unmistakable.
                    conn.execute(
                        "UPDATE scan_tasks SET status='expired', result_detail=? "
                        "WHERE task_id=?",
                        ("server: no result after %d delivery attempts"
                         % REDELIVERY_MAX_ATTEMPTS, task_id))
                    abandoned += 1
                elif decision == REDELIVER_UNREADABLE:
                    log.warning("task %s has an unreadable expiry (%r) — left "
                                "dispatched, NOT redelivered", task_id, expires_at)
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        # Never let a redelivery pass break the heartbeat it rides on.
        log.warning("redelivery pass failed for %s: %s", device_id, e)
    if requeued or abandoned:
        log.info("redelivery for device=%s: %d requeued, %d abandoned",
                 device_id, requeued, abandoned)
    return requeued, abandoned


# How soon to ask an agent back when it has outstanding task work (ADR 0004
# Stage 1 step 6). Must stay at or above the agent's own POLL_INTERVAL_FLOOR
# (15s): a smaller value would simply be clamped on arrival, which would mean the
# two halves disagreed about the floor while appearing to work.
TASK_POLL_HINT_SECONDS = 30


def _steering_gate_armed():
    """Is the appliance's Tier 2 inspection gate ARMED and actively inspecting?

    The downward half of the roaming-steering lease (tunnel-back design §5.2): a
    roaming agent may only hold steering while the appliance is actually inspecting,
    so the agent needs this pushed down every beat. Sourced from
    tier2_gate_state.read_state()['inspecting'], which is ALREADY forced False when
    the gate posture is stale -- the exact false-reassurance guard this needs, so a
    gate that has stopped publishing does not keep authorising steering.

    FAIL-SAFE: any error (DB fault, module absent, gate never published) returns
    False. Authorising steering off a read that did not succeed is precisely the
    wrong direction, so an unreadable gate reads as 'not armed'.
    """
    try:
        import tier2_gate_state
        return bool(tier2_gate_state.read_state().get("inspecting"))
    except Exception:
        return False


def _next_poll_hint(device_id, dispatched):
    """Seconds to ask this device to come back in, or None for normal cadence.

    Emitted when the device has outstanding task work: either tasks just handed
    to it (whose results we want promptly) or more still queued behind them.
    None is a real answer -- "nothing outstanding, keep your normal cadence" --
    not a failure default.

    Step 5 is what makes this worth doing: scans and notifications are no longer
    pushed, so their latency is now exactly one heartbeat, up to 300s by default.

    The agent will only ever let this SHORTEN its interval, never lengthen it,
    so this value cannot be used to slow a device down even if the server is
    wrong or impersonated -- see agent.py `_effective_interval`.
    """
    if dispatched:
        return TASK_POLL_HINT_SECONDS
    try:
        conn = _db_connect()
        try:
            row = conn.execute(
                "SELECT 1 FROM scan_tasks WHERE device_id=? AND status='pending' "
                "LIMIT 1", (device_id,)).fetchone()
        finally:
            conn.close()
    except Exception as e:
        # An unreadable queue is reported, and yields normal cadence rather than
        # a guessed hint -- a fabricated "come back soon" would be indis-
        # tinguishable from a real one.
        log.warning("could not check pending tasks for %s: %s", device_id, e)
        return None
    return TASK_POLL_HINT_SECONDS if row else None


def _tasks_for_response(device_id):
    """Signed envelopes for this device's pending tasks, oldest first.

    Returns [] on ANY failure — a broken task path must never stop a heartbeat
    from being answered. Telemetry ingest is the primary job of this endpoint;
    tasking rides along and must not be able to take it down.
    """
    try:
        import server_keys
        if not server_keys.have_server_keypair():
            return []
        # BEFORE selecting pending work, not after: a task revived by this pass
        # must be eligible for the very same response, otherwise every redelivery
        # costs an extra heartbeat of latency for no reason.
        _requeue_expired_tasks(device_id)
        conn = _db_connect()
        try:
            rows = conn.execute(
                "SELECT task_id, action, params_json FROM scan_tasks "
                "WHERE device_id=? AND status='pending' ORDER BY id LIMIT ?",
                (device_id, MAX_TASKS_PER_BEAT)).fetchall()
        finally:
            conn.close()
        if not rows:
            return []

        envelopes, now = [], datetime.now()
        # EVERY task is signed with the key this device actually trusts, not just
        # rotation tasks. During a rotation the server may hold three keys and
        # devices may be on any of them: one that has already rotated trusts the
        # staged key before cutover, and one that never rotated still trusts the
        # previous key after it. Signing everything with the current key leaves
        # both untaskable for the whole rotation window. Resolved once per
        # response rather than per task.
        signer = server_keys.signing_key_for_fingerprint(
            _device_anchor_fingerprint(device_id))
        if signer:
            log.info("device=%s is on a non-current anchor — signing its tasks "
                     "with %s", device_id, os.path.basename(signer))
        for task_id, action, params_json in rows:
            try:
                params = json.loads(params_json or "{}")
            except Exception:
                params = {}
            if action == server_keys.ROTATE_ACTION:
                envelopes.append(server_keys.build_rotation_task(
                    device_id, task_id=task_id, sign_with=signer, now=now))
            elif action == "attest_manifest":
                # Built HERE, not at queue time, so the manifest always
                # describes the build the server ships right now. Goes through
                # the same build_task signer as every other task — the manifest
                # is just params, and params are covered by the signature.
                from alert_manager import attestation as _att
                params = {"manifest": _att.build_manifest(_att.agent_version())}
                envelopes.append(server_keys.build_task(
                    device_id, action, params, task_id=task_id,
                    sign_with=signer, now=now))
            elif action == "attest_challenge":
                # Tier 2 challenge, built at DELIVERY (like the manifest): the
                # server computes code_digests, stores nonce+digests to verify the
                # eventual response, and sends {nonce, covered}. Same build_task
                # signer as every other task. Dropped (no envelope) if the private
                # module is absent — a challenge with no verifiable state is worse
                # than none.
                from alert_manager import attestation as _attc
                # ⛔ A FRESH CONNECTION, DELIBERATELY — do not pass `conn` here.
                #
                # `conn` (opened above for the pending-task SELECT) is CLOSED in
                # that block's own `finally` before this loop begins. Passing it
                # to a write raised `sqlite3.ProgrammingError: Cannot operate on
                # a closed database` on every execution, which is why
                # `agent_attestation_challenges` has 0 rows: this path has never
                # completed once. It went unnoticed because it is gated on an
                # `attest_challenge` task existing and none had ever been queued
                # — and because the outer handler at the end of this function
                # catches everything and returns [].
                #
                # THE FAILURE MODE IS A POISON PILL, not a crash: the raise is
                # caught, `_tasks_for_response()` returns [], and NO tasks at all
                # go out on that beat — including unrelated scan tasks. The task
                # stays pending, so the next beat fails identically. One
                # undeliverable challenge would stall ALL task dispatch to that
                # device indefinitely, logging `could not build tasks for
                # device=…` each time.
                # Scoped to attestation's OWN namespace, not hw_monitor's:
                # `agent_attestation_challenges` belongs to attestation.py; this
                # process only drives delivery. Safe to scope correctly here
                # precisely because this connection is created for the write and
                # closed immediately — it shares a transaction with nothing.
                #
                # The sibling call at :1940 (`ingest_challenge_response`, which
                # DELETEs the consumed row) is scoped the same way — see that
                # call site. It only became possible once the Tier 2 verdict
                # moved off `agent_devices` into attestation's own table
                # (Shape 2, 2026-08-29): before that, the DELETE shared the
                # heartbeat's transaction with an hw_monitor-owned write, and
                # scoping it correctly would have torn that pair apart. See the
                # attestation entry in data_manager.NAMESPACES.
                _cch = _dm().connect("attestation")
                try:
                    _ch = _attc.build_and_store_challenge(_cch, device_id, now=None)
                    _cch.commit()
                finally:
                    _cch.close()
                if _ch is not None:
                    envelopes.append(server_keys.build_task(
                        device_id, action, {"nonce": _ch["nonce"],
                                            "covered": _ch["covered"]},
                        task_id=task_id, sign_with=signer, now=now))
            else:
                envelopes.append(server_keys.build_task(
                    device_id, action, params, task_id=task_id,
                    sign_with=signer, now=now))

        conn = _db_connect()
        try:
            for env in envelopes:
                conn.execute(
                    "UPDATE scan_tasks SET status='dispatched', dispatched_at=?, "
                    "expires_at=?, dispatch_count=dispatch_count+1 WHERE task_id=?",
                    (now.isoformat(timespec="seconds"), env["expires_at"],
                     env["task_id"]))
            conn.commit()
        finally:
            conn.close()
        log.info("dispatched %d task(s) to device=%s via heartbeat response",
                 len(envelopes), device_id)
        return envelopes
    except Exception as exc:
        log.error("could not build tasks for device=%s: %s", device_id, exc)
        return []


#: Reports accepted from one heartbeat. The agent caps what it sends; this caps
#: what is BELIEVED, independently — a bound enforced only by the sender is not a
#: bound at all, since the sender is the untrusted party here.
MAX_RESULTS_PER_BEAT_IN = 20

#: Server-side truncation of agent-supplied free text. Independent of the agent's
#: own limit for the same reason.
RESULT_DETAIL_MAX = 500


def _record_task_results(device_id, results):
    """Record what a device REPORTS happened to its tasks. Returns ids to ack.

    ATTESTED, NOT VERIFIED. Everything here is the device's own account of its
    work; the server confirms only that an authenticated device said it. The
    heartbeat gate upstream is what makes "which device said it" trustworthy,
    and that is the whole of the guarantee.

    Two scoping rules do the real work:

    - `device_id` is in the WHERE clause. Without it any enrolled device could
      close out ANOTHER device's task by guessing a task_id, which would let one
      compromised machine hide a second machine's failures.
    - `status='dispatched'` makes the update idempotent, so a redelivered report
      (the at-least-once contract's normal case) is a no-op rather than a
      second, conflicting write.

    Ids are acked whether or not a row matched. An unknown, foreign or
    already-recorded id that went un-acked would be retried by that agent
    forever; acking costs nothing, because acking is not the same as believing.
    """
    acked = []
    if not isinstance(results, list) or not results:
        return acked
    now = datetime.now().isoformat(timespec="seconds")
    conn = _db_connect()
    try:
        for item in results[:MAX_RESULTS_PER_BEAT_IN]:
            if not isinstance(item, dict):
                continue
            tid = item.get("task_id")
            if not tid or not isinstance(tid, str):
                continue
            ok = bool(item.get("ok"))
            detail = str(item.get("detail") or "")[:RESULT_DETAIL_MAX]
            conn.execute(
                "UPDATE scan_tasks SET status=?, result_ok=?, result_detail=?, "
                "reported_at=? WHERE task_id=? AND device_id=? AND status='dispatched'",
                ("completed" if ok else "failed", 1 if ok else 0, detail,
                 now, tid, device_id))
            acked.append(tid)
        conn.commit()
    finally:
        conn.close()
    return acked


def _dispatch_pending_scans(device_id, agent_ip):
    """Queue the oldest pending scan for the agent right now.

    Called immediately after a payload is processed so reconnecting devices
    execute their queued scans without needing a manual trigger.
    For device_id='local' the scan runs in-process via subprocess.

    `agent_ip` is retained but NO LONGER USED: delivery moved from a direct push
    to that address onto the task channel, which addresses devices by device_id.
    Kept so the one caller does not have to change in the same commit that
    retires the transport.
    """
    try:
        conn = _db_connect()
        rows = conn.execute(
            "SELECT id, scan_path, queued_at FROM scan_queue "
            "WHERE device_id=? AND status='pending' "
            "ORDER BY queued_at LIMIT 1",
            (device_id,),
        ).fetchall()
        conn.close()

        for queue_id, scan_path, queued_at in rows:
            scan_id = str(_uuid_mod.uuid4())

            # scan_jobs is written BEFORE dispatch, deliberately: both paths
            # report results against this scan_id, and the local path's worker
            # thread can finish before we would otherwise have written the row —
            # its result UPDATE would then match nothing and be lost silently.
            conn = _db_connect()
            conn.execute(
                "INSERT INTO scan_jobs (device_id, scan_id, path, status, started_at) "
                "VALUES (?, ?, ?, 'running', ?)",
                (device_id, scan_id, scan_path or "/", datetime.now().isoformat()),
            )
            conn.commit()
            conn.close()

            # Whether the work was actually handed off. The scan_queue row is
            # only advanced once this is true — see the write-back below.
            dispatched = False

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
                    dispatched = True
                    log.info("dispatched local clamscan: queue_id=%d scan_id=%s", queue_id, scan_id)
                else:
                    # Previously silent: the row was marked 'executing' regardless,
                    # so a box without clamscan accumulated queued scans that
                    # looked as though they had started and never would.
                    log.warning("clamscan not installed — cannot run local scan "
                                "queue_id=%d, leaving it queued", queue_id)
            else:
                # Queued as a task, not pushed. The direct POST this replaced went
                # to `http://{agent_ip}:5002`, but the agent's listener binds
                # 127.0.0.1 — so it could only connect for a device whose address
                # was loopback, and failed for every remote device. No longer
                # branches on agent_ip at all: delivery does not depend on the
                # device's address, only on it checking in.
                try:
                    # origin_queued_at carries the scan_queue row's ORIGINAL
                    # queue time across the boundary. Without it the new
                    # scan_tasks row gets created_at=now, so a scan that waited
                    # three months in scan_queue arrives looking brand new and
                    # any staleness check measured on created_at is silently
                    # defeated by the chain.
                    task_id = enqueue_task(
                        device_id, "scan",
                        {"path": scan_path or "/", "scan_id": scan_id},
                        origin_queued_at=queued_at)
                    dispatched = True
                    log.info(
                        "queued scan task for %s: queue_id=%d scan_id=%s task_id=%s "
                        "(originally queued %s)",
                        device_id, queue_id, scan_id, task_id, queued_at,
                    )
                except Exception as e:
                    log.warning("could not queue scan task for %s: %s", device_id, e)

            # Advance the queue row ONLY once the work was really handed off.
            #
            # This UPDATE used to run BEFORE dispatch, which meant any failure
            # left the row in 'executing' permanently — a scan that never runs,
            # never retries, and reads as in-progress forever. Leaving it
            # 'pending' instead means the next heartbeat simply tries again.
            #
            # The eager scan_jobs row is rolled back on failure so a failed
            # dispatch leaves nothing behind for anyone to interpret.
            #
            # Tradeoff, stated rather than hidden: a permanently-failing cause
            # (clamscan absent, say) now retries every heartbeat instead of
            # stranding once. That is deliberate — a retry is visible in the log
            # and ages out through the staleness sweep, whereas a stranded row is
            # invisible and permanent.
            conn = _db_connect()
            try:
                if dispatched:
                    conn.execute(
                        "UPDATE scan_queue SET status='executing', executed_at=?, "
                        "scan_job_id=? WHERE id=?",
                        (datetime.now().isoformat(), scan_id, queue_id),
                    )
                else:
                    conn.execute("DELETE FROM scan_jobs WHERE scan_id=?", (scan_id,))
                conn.commit()
            finally:
                conn.close()

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
        # FAIL CLOSED on an unreadable scan log. `threats` stays empty whether the
        # scan genuinely found nothing OR we could not read its log at all, so
        # deriving status from `threats` alone reported a scan we cannot vouch for
        # as "clean" — a verdict written to scan_jobs and shown to the operator as
        # a real result. An absent answer must not render as a reassuring one.
        log_read_ok = False
        try:
            with open(log_file) as f:
                for line in f:
                    if ": " in line:
                        files_scanned += 1
                    if "FOUND" in line:
                        threats.append(line.strip())
            log_read_ok = True
        except Exception as exc:
            log.exception("clamscan log unreadable (scan_id=%s, log=%s) — recording "
                          "this scan as ERROR, not clean", scan_id, log_file)
            # best_effort: already in a failure handler for the scan-log read;
            # the status="error" fallback below is the load-bearing fix, this
            # is the observability half (Rule 2 — two separate changes).
            _errors_record("E-HWMON-004", {"fn": "_local_clamscan_thread",
                                           "scan_id": scan_id,
                                           "error": f"{type(exc).__name__}: {exc}"})
        if not log_read_ok:
            status = "error"
        elif threats:
            status = "threats_found"
        else:
            status = "clean"
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


# ── structured error codes (alert_manager/nemesis_errors.py) ─────────────────
# Deferred registration via make_recorder: this process starts with no systemd
# ordering against whatever creates the error tables, so registering at import
# would be a race. See PUNCHLIST "Silent exception-swallow sites".
_ERR_CODES = {
    "E-HWMON-001": ("hw device list DB read failed; empty list returned as a real "
                    "result (reads as 'no devices reporting')",
                    "MEDIUM", "db-read-empty-default"),
    "E-HWMON-002": ("extended_absence condition trigger failed (bad threshold, "
                    "malformed prev_last_seen, or the scan-queue insert itself); "
                    "the device is never scanned and nothing else records it",
                    "MEDIUM", "silent-scan-skip"),
    "E-HWMON-003": ("fan_status pre-population INSERT failed during init_db "
                    "(the file-read half of this site is expected-absence and "
                    "stays silent; only the DB write is wired)",
                    "LOW", "db-write-failed"),
    "E-HWMON-004": ("clamscan log unreadable; scan recorded as status='error', "
                    "not 'clean' (fail closed) — this is the observability half, "
                    "the fail-closed fix is the status change itself",
                    "HIGH", "fail-open-scan-result"),
}
_recorder = None


def _errors_record(code, context):
    """Record one structured error occurrence. Never raises into the caller."""
    global _recorder
    try:
        if _recorder is None:
            import nemesis_errors
            _recorder = nemesis_errors.make_recorder(
                "hw_monitor", _db_connect, _ERR_CODES, logger=log)
        return _recorder(code, context=context)
    except Exception:
        return None


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
    except Exception as exc:
        # E-HWMON-001 — an empty list here renders as "no devices reporting",
        # which is a legitimate state on a quiet network. The caller cannot tell
        # the two apart, so the failure is recorded rather than discarded. The
        # [] return is KEPT deliberately: callers iterate it and a raise would
        # break the dashboard card.
        _errors_record("E-HWMON-001", {"fn": "get_hw_devices",
                                       "error": f"{type(exc).__name__}: {exc}"})
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


#: Heartbeat authentication mode. ENVIRONMENT ONLY, and deliberately not a
#: database setting: a switch that can disable authentication must not be
#: reachable from any API write path. This unit has no EnvironmentFile, so it is
#: set as an Environment= line in hw-monitor.service.
#:
#:   observe (default) — verify when a signature is present; ACCEPT an absent one
#:                       and log it, so fleet readiness is measurable before
#:                       enforcement. A PRESENT-but-INVALID signature still fails.
#:   enforce           — an unsigned heartbeat is rejected.
_AGENT_AUTH_MODE = os.environ.get("NEMESIS_AGENT_AUTH_MODE", "observe").strip().lower()

#: Clock-skew tolerance for signed_at, seconds either side.
_AGENT_AUTH_SKEW_S = 300


def _agent_public_key(device_id):
    """Stored enrollment public key for a device, or None."""
    try:
        conn = _db_connect()
        row = conn.execute("SELECT public_key FROM agent_devices WHERE device_id=?",
                           (device_id,)).fetchone()
        conn.close()
        return (row[0] or None) if row else None
    except Exception:
        log.exception("agent auth: public-key lookup failed for %s", device_id)
        return None


def _agent_last_signed_at(device_id):
    """Monotonic floor: the newest signed_at already accepted from this device."""
    try:
        conn = _db_connect()
        row = conn.execute("SELECT last_signed_at FROM agent_devices WHERE device_id=?",
                           (device_id,)).fetchone()
        conn.close()
        return (row[0] or None) if row else None
    except Exception:
        log.exception("agent auth: last_signed_at lookup failed for %s", device_id)
        return None


def _agent_record_signed_at(device_id, signed_at):
    """Advance the monotonic floor. Called ONLY after a signature verifies, so a
    rejected heartbeat can never raise the floor and lock out the real agent."""
    try:
        conn = _db_connect()
        conn.execute("UPDATE agent_devices SET last_signed_at=? WHERE device_id=?",
                     (signed_at, device_id))
        conn.commit()
        conn.close()
    except Exception:
        log.exception("agent auth: could not record signed_at for %s", device_id)


def _verify_agent_heartbeat(headers, body, device_id):
    """(ok, reason) — is this heartbeat authentic?

    WHAT IS SIGNED: "<device_id>|<signed_at>|<sha256(raw body)>". The digest is
    over the EXACT BYTES RECEIVED, not a re-serialised payload — so the signature
    binds the body itself and verification cannot be broken by two Python
    installs disagreeing about key order or float formatting. It also means an
    attacker who captures a valid signature cannot swap the metrics underneath
    it, which matters because that body drives scan-trigger evaluation.

    REPLAY is stopped by a per-device monotonic floor rather than a nonce cache:
    signed_at must be strictly newer than the last accepted value. A tolerance
    window alone would still permit replay INSIDE the window, and inside that
    window a replayed heartbeat can re-queue scans.

    NO CONFIDENTIALITY. The listener is plain HTTP. This authenticates the sender
    and binds the payload; it does NOT encrypt anything, and telemetry remains
    readable on the wire. Stated here so "authenticated" is never read as
    "secure channel".

    WHETHER THAT MATTERS DEPENDS ON THE TARGET ADDRESS, which is a deployment
    property rather than a property of this code. An agent configured with a
    tailnet address reaches the server inside WireGuard, so the cleartext above
    never crosses a shared network; one configured with a LAN address does not.
    Which of those an agent gets is decided by the host baked into its installer
    (dashboard.py `_nemesis_tailnet_host`), so NEMESIS_TAILNET_ADDR should be set
    on any deployment that has a tailnet -- otherwise the target is inherited from
    whatever URL fetched the installer, and the choice is made silently.
    Cleartext targets are now flagged to the operator when a link is generated.
    """
    sig = headers.get("X-Nemesis-Signature", "")
    signed_at = headers.get("X-Nemesis-Signed-At", "")
    hdr_device = headers.get("X-Nemesis-Device", "")

    if not sig or not signed_at:
        # ABSENT, not invalid. Tolerated in observe mode only — this is the
        # compatibility ramp for agents that predate signing, never a bypass.
        if _AGENT_AUTH_MODE == "enforce":
            return False, "unsigned heartbeat rejected (enforce mode)"
        log.warning("agent auth: UNSIGNED heartbeat accepted in observe mode "
                    "(device=%s) — this will be REJECTED once enforcement is on",
                    device_id)
        return True, "unsigned-observe"

    # From here the caller SUPPLIED a signature. Everything below fails closed in
    # both modes: observe tolerates the absence of a signature, never a bad one.
    if hdr_device and hdr_device != device_id:
        return False, "device_id header does not match payload"

    pub = _agent_public_key(device_id)
    if not pub:
        # Cannot evaluate. A failed read must not be reported as a pass.
        return False, "no stored public key for device"

    try:
        ts = datetime.fromisoformat(signed_at)
    except Exception:
        return False, "unparseable signed_at"
    # TIMEZONE-CORRECT skew (fixed 2026-08-20). Current agents send an
    # offset-AWARE UTC stamp; compare it against an aware UTC clock so the result
    # is independent of the server's own local zone. The previous code did
    # `datetime.now() - ts` with a naive LOCAL now, which only agreed with the
    # agent when both were in the same zone -- true same-machine, false for a
    # CDT agent vs this UTC server (measured skew 18000s, every beat rejected).
    # A naive `ts` means a LEGACY agent (pre-fix) that stamps naive local time;
    # keep comparing those against naive local `now` so they are unaffected
    # during rollout, and never mix aware/naive (which would raise TypeError).
    now = datetime.now(timezone.utc) if ts.tzinfo is not None else datetime.now()
    skew = abs((now - ts).total_seconds())
    if skew > _AGENT_AUTH_SKEW_S:
        return False, "signed_at outside +/-%ds tolerance (skew=%ds)" % (
            _AGENT_AUTH_SKEW_S, int(skew))

    # Replay floor: signed_at must be strictly newer than the last accepted one.
    # Compared CHRONOLOGICALLY, not lexically. The prior code did a raw string
    # `<=` on the ISO values, whose ADR-0004-step-2 premise ("local ISO strings
    # compare correctly lexicographically") held only while every heartbeat from
    # a device used the SAME format. The 2026-08-20 naive-local -> aware-UTC
    # switch breaks that during the per-device transition: a device EAST of UTC
    # whose stored floor is an old naive-local string (e.g. "..T21:18:51",
    # 9pm local) and whose next, genuinely newer heartbeat arrives as aware UTC
    # ("..T12:23:51+00:00") compares lexically LOWER at the hour digit, so the
    # real beat is falsely rejected as a replay for up to ~offset hours after
    # upgrade. West of UTC (e.g. CDT) happens to still order correctly, which is
    # why the CDT-only fleet did not surface it. Normalising both sides to aware
    # UTC before comparing makes the check frame-independent. `ts` is the already
    # -parsed signed_at; a naive value is interpreted as LOCAL, consistent with
    # the skew check above (naive.astimezone(UTC) treats it as local time).
    floor = _agent_last_signed_at(device_id)
    if floor:
        sat_utc = ts.astimezone(timezone.utc)
        try:
            floor_utc = datetime.fromisoformat(floor).astimezone(timezone.utc)
        except Exception:
            floor_utc = None
        replayed = (sat_utc <= floor_utc) if floor_utc is not None \
            else (signed_at <= floor)   # unparseable stored floor: conservative fallback
        if replayed:
            return False, "replay: signed_at %s not newer than %s" % (signed_at, floor)

    digest = hashlib.sha256(body).hexdigest()
    message = "%s|%s|%s" % (device_id, signed_at, digest)
    if not _verify_enroll_signature(pub, message, sig):
        return False, "signature verification failed (or body was modified)"

    _agent_record_signed_at(device_id, signed_at)
    return True, "verified"


_HWID_MOD = None


def _hwid_path():
    """Absolute path to nemesis_agent/hwid.py, found by WALKING UP rather than
    by counting directories.

    ⚠ THIS WAS BROKEN FOR WEEKS AND NOTHING SAID SO. The previous version used
    `dirname(dirname(abspath(__file__)))`, which was correct when this file lived
    at `alert_manager/hw_monitor.py` — one level under the repo root. Commit
    `9ffac56` relocated it to `core_module/hw_monitor/`, one level DEEPER, and the
    hard-coded count silently started resolving to
    `/opt/nemesis/core_module/nemesis_agent/hwid.py`, which does not exist.

    Counting `dirname()` calls encodes the file's depth in the tree as a magic
    number, so any future relocation breaks it again in exactly the same silent
    way. Searching upward for a known sibling directory does not.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    cur = here
    for _ in range(6):                       # bounded: never walk to /
        cand = os.path.join(cur, "nemesis_agent", "hwid.py")
        if os.path.exists(cand):
            return cand
        parent = os.path.dirname(cur)
        if parent == cur:                    # reached the filesystem root
            break
        cur = parent
    raise FileNotFoundError(
        "nemesis_agent/hwid.py not found walking up from %s" % here)


def _match_fingerprint(incoming, stored):
    """TOFU "same device?" comparison, delegating to the canonical pure implementation in
    nemesis_agent/hwid.py (loaded by absolute path — single source of truth, no drift).
    Returns (outcome, matched_device_id, matched_signal_count) with
    outcome 'exact' | 'partial' | 'none'. Informational — never gates enrollment.

    ⚠ THE sys.path INSERT IS REQUIRED, and is scoped to the load. `hwid` imports a
    SIBLING module (`win_run`) at module level, and loading a file by absolute path
    does NOT put that file's directory on sys.path — so the sibling import raises
    ModuleNotFoundError and the whole load fails. The directory is inserted for the
    duration of exec_module only and removed in `finally`, so this stays a scoped
    insert rather than the ambient path mutation that loading-by-path exists to
    avoid. Same fix, same reasoning as core/install_id.py's hwid_module().

    TWO separate defects were fixed here together (2026-08-17): the wrong path (see
    _hwid_path) and this sibling import. Either one alone was enough to make the
    comparison never run."""
    global _HWID_MOD
    if _HWID_MOD is None:
        import importlib.util
        path = _hwid_path()
        agent_dir = os.path.dirname(path)
        spec = importlib.util.spec_from_file_location("nemesis_hwid", path)
        mod = importlib.util.module_from_spec(spec)
        added = agent_dir not in sys.path
        if added:
            sys.path.insert(0, agent_dir)
        try:
            spec.loader.exec_module(mod)
        finally:
            if added:
                try:
                    sys.path.remove(agent_dir)
                except ValueError:
                    pass
        _HWID_MOD = mod
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

    # A scan that could not RUN is not a scan that came back CLEAN.
    #
    # Both used to collapse into "pending", so a device with no scanner installed
    # enrolled carrying exactly the same status as one that was scanned and found
    # clean. The scan JSON recorded the difference and the decision threw it away
    # — an absent measurement wearing a real result's costume. The dashboard badge
    # happened to render the distinction (it reads scan_status directly), but
    # nothing queryable or policy-driven could see it.
    #
    # "scan_failed" is treated as unverified for the same reason as
    # "not_available": neither produced evidence about this device.
    scan_verified = bool(scan) and scan_status not in (
        None, "", "not_available", "scan_failed")
    if has_findings:
        enroll_status = "pending_with_findings"
    elif not scan_verified:
        enroll_status = "pending_unverified"
    else:
        enroll_status = "pending"
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
    # Server clock, and it must STAY the server clock: this `now` is what seeds
    # `agent_last_seen` for a freshly-enrolled device, and `_update_agent_device`
    # stamps that same column from the server's clock on every heartbeat
    # thereafter (see the long note at its `ts =`). One column, one frame, two
    # writers that have to agree -- if either moves, move both. Sourcing this
    # from anything the AGENT sent would re-open the timezone split that made
    # healthy nodes read as silent for hours (fixed 2026-08-20).
    now = datetime.now().isoformat(timespec="seconds")

    # ── installer token: atomic single-use claim → auto-approve (skip pending) ──
    # The UPDATE both validates AND claims a use in one statement (concurrency-safe).
    # Any failure (no token, bad/expired/used token, missing table) leaves the
    # scan-derived enroll_status untouched → normal pending flow. Never errors out.
    token = (payload.get("enrollment_token") or "").strip()
    token_creator = None
    # Set when a VALID token was claimed but approval was withheld for lack of
    # scan evidence. Distinct from "no token at all": the owner needs to know the
    # install was authorised and still stopped, or the hold looks like a bug.
    auto_approve_withheld = False
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
                    # ── auto-approve requires COMPLETED, CLEAN scan evidence ──
                    #
                    # A valid installer token proves the INSTALL was authorised.
                    # It proves nothing whatever about the state of the machine it
                    # ran on. Approving on the token alone defeats the entire
                    # purpose of scanning before trust — the scan result was
                    # computed, recorded, and then overridden.
                    #
                    # The real case this closes: a client's employee enrolling
                    # their own unmanaged device with a legitimate token. The
                    # token is genuine; the machine is unknown. Previously that
                    # enrolled straight to 'approved' with no scan evidence, and
                    # a device carrying findings auto-approved just as readily as
                    # a clean one.
                    #
                    # Withheld enrollments hold at the SAME status the manual path
                    # would have produced (pending_unverified / _with_findings),
                    # so there is one set of pending states, not a parallel set
                    # meaning almost-the-same thing.
                    if scan_verified and not has_findings:
                        enroll_status = "approved"
                    else:
                        auto_approve_withheld = True
                        log.warning(
                            "installer token valid but auto-approve WITHHELD for "
                            "device=%s: scan_verified=%s has_findings=%s — holding "
                            "at %s for owner review",
                            device_name, scan_verified, bool(has_findings),
                            enroll_status)
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
        #
        # ⚠ A TAMPERING-DETECTION PATH DEPENDS ON THIS STAYING LOG-ONLY.
        #
        # `outcome`, `matched_id` and `matched_n` below go to log.info and are then
        # DISCARDED. `enroll_status` is decided entirely before this block, so nothing
        # here can influence the enrollment outcome. That is what makes a reinstall
        # produce a NEW device_id rather than resuming the old one.
        #
        # Why that matters, and it is not obvious from here: `first_connect` fires on
        # `prev is None`. A new device_id is therefore what makes it fire. Today
        # `first_connect` is the one path that reliably triggers a fresh scan after an
        # agent has been wiped and reinstalled — which is exactly the shape a tamperer
        # produces. There is no agent self-integrity check anywhere in the tree, so this
        # is doing more work than it looks like it is doing.
        #
        # So: this is currently **safe by accident, not by design**. If anyone later
        # "improves" enrollment to recognise returning devices via this match and resume
        # their existing device_id, the reinstall path stops minting a new one,
        # `first_connect` stops firing, and that detection closes SILENTLY — no error, no
        # failing test, just a scan that no longer happens. Recorded here so the
        # dependency is visible at the call site rather than rediscovered afterwards.
        #
        # Wiring this match into enrollment is not forbidden — but it requires replacing
        # the trigger it removes, not just noticing afterwards that it was load-bearing.
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
                # NOT labelled "non-fatal" any more, deliberately. That wording
                # invited ignoring this line, and it WAS ignored — the comparison
                # had never once succeeded in production (two loader defects,
                # fixed 2026-08-17) while enrollment carried on looking healthy.
                # Enrollment still proceeds; what is lost is the has-this-hardware
                # enrolled-before comparison, so say that rather than reassure.
                log.exception(
                    "enroll fingerprint: hardware comparison did NOT run for "
                    "device %s — enrollment continues, but this device was not "
                    "checked against previously-enrolled hardware",
                    str(device_id)[:12] if device_id else "?")

        # ── REMOTE ENTITLEMENT STAMPING (licensing cap, 2026-08-17) ──────────
        #
        # The cap counts ENTITLEMENT, not observation (operator decision closing
        # the 2026-08-16 audit §4.2). The entitlement is decided at installer
        # generation and recorded on the token; this carries it onto the device.
        #
        # Read SEPARATELY from the auto-approve claim above, deliberately: that
        # UPDATE requires `auto_approve=1`, so a manually-approved device would
        # never reach it — and a manually-approved device can be just as remote
        # as an auto-approved one. Tying the entitlement to the auto-approve
        # branch would silently under-count exactly the enrollments an admin
        # reviewed most carefully.
        #
        # Absent token, absent column, or an unreadable row all yield 0. That is
        # the correct direction: an entitlement that cannot be shown to have been
        # granted was not granted. Failing the other way would invent grants.
        token_remote = 0
        if token:
            try:
                _tr = conn.execute(
                    "SELECT remote_enabled FROM enrollment_tokens WHERE token=?",
                    (token,)).fetchone()
                token_remote = 1 if (_tr and _tr[0]) else 0
            except Exception:
                log.warning("enroll: could not read remote_enabled for token %s — "
                            "recording device as LOCAL-ONLY", token[:8])
                token_remote = 0

        conn.execute(
            "INSERT INTO agent_devices (device_id, device_name, os, os_version, "
            "hardware_summary, public_key, enrollment_status, ip_address, agent_last_seen, "
            "pre_enrollment_scan, enrollment_has_findings, enrolled_by, enrolled_at, "
            "hw_stable_id, hw_signals_used, hw_signal_hashes, hw_fp_confidence, "
            "hw_fp_schema_version, hw_fp_locked_at, hw_is_virtual, "
            "remote_enabled, remote_enabled_at, remote_enabled_by) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (device_id, device_name, os_name, payload.get("os_version", ""),
             payload.get("hardware_summary", ""), public_key, enroll_status, remote_ip, now,
             scan_json, has_findings,
             (token_creator if enroll_status == "approved" else None),
             (now if enroll_status == "approved" else None),
             hw_stable_id, hw_signals_used, hw_signal_hashes, hw_confidence,
             hw_schema_version, _time.time(), hw_is_virtual,
             token_remote,
             (now if token_remote else None),
             (token_creator if token_remote else None)))
        _persist_lan_macs(conn, device_id, payload.get("lan_macs"), now=_time.time())
        conn.commit()   # token claim + device insert commit together (or both roll back)
        conn.close()
    except Exception:
        log.exception("agent enrollment insert failed")
        return None, "db_error"
    try:   # best-effort approval ticket
        # The shared-path publish that used to sit here moved to main() — it is a
        # startup concern, not a per-request one. The lazy import stays: most
        # enrollments never open a ticket, and there is no reason to pay the
        # tickets-module import cost at startup for a path that rarely runs.
        from modules.tickets.module import open_ticket
        if enroll_status == "approved":
            title = f"Device auto-enrolled via installer token: {device_name} ({os_name})"
            footer = (f"Auto-approved by installer token (created by {token_creator or 'unknown'}).\n"
                      f"Review in Settings -> Devices if unexpected.")
            prio = "HIGH" if has_findings else "LOW"
        elif auto_approve_withheld:
            # Explained explicitly. A token-based install that silently lands in
            # the pending queue reads as a broken installer, and the owner's most
            # likely response to an unexplained hold is to approve it to make the
            # problem go away — which is precisely the decision this gate exists
            # to inform.
            title = f"Installer-token device HELD for approval: {device_name} ({os_name})"
            footer = ("A valid installer token was presented, but auto-approval was "
                      "WITHHELD because the pre-enrollment scan did not complete "
                      "cleanly.\n\n"
                      "The token proves the install was authorised. It says nothing "
                      "about the state of this machine — which is what the scan was "
                      "for.\n\n"
                      "Review the scan result above, then approve or reject in "
                      "Settings -> Devices.")
            prio = "HIGH" if has_findings else "MEDIUM"
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

        def _source_ok(self):
            """True = proceed, False = already answered 403.

            Runs BEFORE _pace(). A source that may not be served should not get
            to consume a pacing bucket on its way to being refused, and the
            cheaper check belongs first.
            """
            if _SOURCE_GUARD is None:
                return True
            src = self.client_address[0] if self.client_address else None
            if _SOURCE_GUARD.allows(src):
                return True
            log.warning("agent listener: REFUSED %s %s from %s — not a local or "
                        "VPN source (allowed: %s)", self.command, self.path,
                        src or "<no address>", _SOURCE_GUARD.describe())
            body = b'{"error":"source not permitted"}'
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return False

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
            if not self._source_ok():
                return
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
            if not self._source_ok():
                return
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
                # ── HEARTBEAT AUTHENTICATION (ADR 0004 step 3) ─────────────
                #
                # Placed HERE, above _check_and_queue_scan_triggers, because that
                # call is the reason this gate matters: it evaluates scan triggers
                # from the request body. Before this, the only checks were a
                # plaintext `source` string and a device_id lookup, both supplied
                # by the caller — so unauthenticated input could drive scan
                # dispatch. Verifying after dispatch would authenticate nothing
                # that mattered.
                _auth_ok, _auth_why = _verify_agent_heartbeat(
                    self.headers, body, payload.get("device_id"))
                if not _auth_ok:
                    log.warning("agent auth: REJECTED heartbeat device=%s from=%s: %s",
                                payload.get("device_id"), remote_ip, _auth_why)
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"ok":false,"error":"unauthenticated"}')
                    return

                metrics = _nemesis_payload_to_metrics(payload)
                _check_and_queue_scan_triggers(payload)   # before update (needs prev state)
                # Track C ingest. Deliberately AFTER the scan triggers and wrapped
                # in its own never-raising handler: connection telemetry is
                # opt-in and secondary, and must never be able to break heartbeat
                # processing for a device that has not opted in at all.
                _c = ingest_connection_events(payload)
                if _c["received"]:
                    log.info("conn ingest: %s", _c)
                _update_agent_device(payload, remote_ip=remote_ip)
                # Agent self-reported error digest (stage c). AFTER the auth gate
                # so it is bound to THIS authenticated device (per-device
                # isolation), and best-effort so a bad digest never breaks the
                # heartbeat. Its own connection, closed here.
                try:
                    _aer_conn = _db_connect()
                    try:
                        _aer_n = _ingest_agent_errors(
                            payload, payload.get("device_id", "local"), _aer_conn)
                        if _aer_n:
                            log.info("agent_error ingest: device=%s stored=%d",
                                     payload.get("device_id"), _aer_n)
                    finally:
                        _aer_conn.close()
                except Exception:
                    log.exception("agent_error ingest wrapper failed (non-fatal)")
                insert_sample(metrics)
                device_id = payload.get("device_id", "local")
                _dispatch_pending_scans(device_id, remote_ip)
                log.info(
                    "nemesis_agent: sample device=%s cpu=%s°C gpu=%s°C conn=%s",
                    device_id, metrics.get("cpu_temp"),
                    metrics.get("gpu_temp"), payload.get("connection_type"),
                )
                # Tasks ride the heartbeat RESPONSE (ADR 0004 Stage 1). Built only
                # after the auth + approval gates above, so an unauthenticated or
                # unapproved device receives none.
                #
                # Safe for every deployed agent: none of them read this body.
                # nemesis_agent checks `r.status_code == 200` and nothing else
                # (agent.py `_post_payload`), and the legacy windows_agent does not
                # read it at all — so extra fields are inert to anything already in
                # the field, and the server can emit tasks before any agent
                # understands them.
                # Results are recorded only for an AUTHENTICATED device, and
                # scoped to that device's own tasks. Wrapped so a malformed
                # report array cannot take down telemetry ingest, which is this
                # endpoint's primary job — same rule _tasks_for_response follows.
                try:
                    _acked = _record_task_results(device_id,
                                                  payload.get("task_results"))
                except Exception as _e:
                    log.error("could not record task results for device=%s: %s",
                              device_id, _e)
                    _acked = []
                _tasks = _tasks_for_response(device_id)
                # Always present, explicitly null when there is nothing
                # outstanding -- a key that appears only sometimes is easy to
                # mistake for one the server forgot to send.
                # Observation cadence for REMOTE agents, operator-adjustable in
                # Settings. Rides the heartbeat response for the same reason
                # next_poll_hint does: the channel exists, is already
                # authenticated, and a change takes effect on the next beat with
                # no agent reconfiguration or restart.
                #
                # Always present (same convention as next_poll_hint above), and
                # already clamped server-side -- but the agent clamps it AGAIN on
                # receipt. Neither side assumes the other validated: a bad value
                # here would turn a bandwidth saving into an every-beat storm on
                # exactly the metered connections it exists to protect.
                try:
                    _obs_n = database.get_remote_observe_every_n()
                except Exception:
                    _obs_n = None      # explicit "no usable value"; agent keeps its default
                # Roaming steering gate posture (tunnel-back §5.2). Always present,
                # same convention as the other hints. FAIL-SAFE False so a gate
                # read that fails never authorises a roaming device to steer. The
                # agent renews its steering lease only while this is True AND it is
                # reachable AND approved -- three independent facts, this being one.
                _resp = {"ok": True,
                         "server_time": datetime.now().isoformat(timespec="seconds"),
                         "tasks": _tasks,
                         "results_ack": _acked,
                         "next_poll_hint": _next_poll_hint(device_id, bool(_tasks)),
                         "observe_every_n": _obs_n,
                         "steering_gate_armed": _steering_gate_armed()}
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(_resp).encode())
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


def _sample_sleep(seconds):
    """The sample loop's wait, cooperatively throttled. If hw-monitor registered
    throttle-aware, the memory ladder can lengthen this sleep under RAM pressure;
    otherwise it is exactly the plain interruptible sleep. Reads intent each call,
    so a lifted/expired throttle takes effect on the next tick. Fails OPEN — a
    throttle read error runs at normal speed (throttle.py), never stalls sampling."""
    if _throttle is not None:
        _throttle.throttled_sleep(seconds, is_running=lambda: _running)
    else:
        _sleep_interruptible(seconds)


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    # Publish the shared DB path ONCE, at process startup, before anything can
    # need it. This used to live inside `_create_enrollment()` — a request
    # handler — which meant a freshly-restarted service had it unpublished until
    # the first agent enrollment happened to arrive. `get_shared_db_path()`
    # RAISES when unpublished (modules/__init__.py:33-38), so any future caller
    # reaching a module API before that first enrollment would have failed for a
    # reason that had nothing to do with what it was doing.
    #
    # Startup, NOT module import, and the distinction is load-bearing:
    # dashboard.py imports this file (line 108) and 9 test files do too. A
    # module-level publish would fire as an import side effect inside every one
    # of those processes and silently overwrite a path they had already chosen
    # for themselves. main() runs only in the service process, which is exactly
    # the one that owns this path. The dashboard publishes its own via
    # modules_loader.init(); the tests publish their temp DBs the same way.
    #
    # Safe to remove from the handler because `_create_enrollment()` is only
    # reachable through the listener thread, and the only thing that starts that
    # listener is `_start_windows_agent_listener()` at the bottom of this
    # function — so this line always precedes it.
    import modules
    modules.set_shared_db_path(DB_PATH)

    log.info("hw_monitor starting (db=%s interval=%ds iface=%s)",
             DB_PATH, SAMPLE_INTERVAL, NET_IFACE)
    init_db()
    # Track C tables. This process WRITES conn_events, so it must not depend on
    # the dashboard having started first — there is no systemd ordering between
    # them. Canonical DDL lives in alert_manager/database.py; both callers are
    # deliberate, same pattern as init_quarantines_table.
    try:
        import database as _database                     # noqa: PLC0415
        _database.init_conn_events_tables()
    except Exception:                                    # noqa: BLE001
        log.exception("could not ensure Track C tables exist — connection ingest "
                      "will reject everything until this is resolved")

    # Cooperative throttle seam (ADR 0006). Register hw-monitor so the memory
    # escalation ladder can publish a gentle slowdown of the sample loop under RAM
    # pressure (the loop reads that intent each tick via _sample_sleep). Best-effort:
    # a failure must not stop telemetry ingest, and throttle.py fails OPEN.
    global _throttle
    try:
        import throttle                                  # noqa: PLC0415
        import database as _db_throttle                  # noqa: PLC0415
        _db_throttle.init_throttle_tables()
        _db_throttle.init_memory_recovery_tables()
        _db_throttle.init_attestation_challenge_table()
        _throttle = throttle.register_throttle_aware("hw-monitor", _dm())
        log.info("throttle: hw-monitor registered as throttle-aware")
    except Exception as exc:                             # noqa: BLE001
        _throttle = None
        log.error("throttle: could not register hw-monitor (%s) -- sampling runs "
                  "at normal speed, un-throttleable, until this is resolved", exc)

    # Server signing keypair (ADR 0004 Stage 1). hw_monitor is the ONLY process
    # that signs task envelopes, so it is the only one that holds the private
    # half — the dashboard gets the public key alone. Created here rather than at
    # deploy time because the data dir is setgid nemesis-db and this process is in
    # that group, so it needs no root. Best-effort: a failure here must not stop
    # telemetry ingest, and nothing signs or verifies yet, so an absent keypair is
    # inert rather than dangerous.
    try:
        import server_keys
        server_keys.ensure_server_keypair()
        log.info("server signing keypair ready (%s)", server_keys.public_path())
    except Exception as exc:
        log.error("could not create the server signing keypair: %s -- task signing "
                  "will be unavailable until this is resolved", exc)

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
    _sample_sleep(SAMPLE_INTERVAL)
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
        # Track C retention. Hourly, not per-sample: the sample loop runs every
        # SAMPLE_INTERVAL seconds and a DELETE scan on every tick would be pure
        # waste. Time-based rather than a tick counter so the cadence does not
        # silently change if SAMPLE_INTERVAL is retuned.
        global _last_conn_reap
        if time.time() - _last_conn_reap >= 3600:
            _last_conn_reap = time.time()
            reap_conn_events()
            # Same cadence, separate sweep and separate window — see
            # reap_conn_seen. Called unconditionally rather than only when the
            # event reaper succeeded: the two retentions are independent, and
            # skipping this one on an unrelated failure would quietly stop
            # enforcing seen-set retention with nothing in the log saying so.
            reap_conn_seen()

        # Error-ledger -> ticket bridge (2026-08-20). Time-gated at 120s: errors
        # are not time-critical to ticket, and this is a JOIN + a few inserts at
        # most. OPT-IN (auto_ticket_on_error, default off) so this is a cheap
        # no-op until an operator turns it on; best-effort inside so a bridge
        # hiccup never disturbs the sample loop. Separate cadence var so retuning
        # SAMPLE_INTERVAL does not silently change how often it runs.
        global _last_error_ticket_scan
        if time.time() - _last_error_ticket_scan >= 120:
            _last_error_ticket_scan = time.time()
            try:
                from modules.tickets.module import (
                    scan_error_ledger_for_tickets,
                    scan_agent_error_reports_for_tickets)
                _n = scan_error_ledger_for_tickets()
                if _n:
                    log.info("error->ticket bridge: opened %d error_notice ticket(s)", _n)
                _na = scan_agent_error_reports_for_tickets()
                if _na:
                    log.info("agent-error->ticket bridge: opened %d self-reported "
                             "ticket(s)", _na)
            except Exception:
                log.exception("error->ticket bridge scan failed (non-fatal)")

        # Memory-injection ladder cycle — the production loop that makes the ladder
        # REAL: sample -> decide -> shadow-record -> resolve -> execute-live(throttle).
        # Without this nothing drives the ladder, so no shadow records accumulate and
        # RESTART/ABORT promotion stays at 0 forever. run_ladder_cycle swallows its
        # own errors; the wiring is wrapped too so a bad cycle never stops telemetry.
        # The SAMPLE_INTERVAL cadence IS the cadence the ladder thresholds assume.
        try:
            import mem_appliance as _mem_ladder             # noqa: PLC0415
            # Scoped to mem_appliance's OWN namespace, not hw_monitor's. The
            # ladder tables belong to mem_appliance; this process only drives the
            # cycle. Using _db_connect() here made every ladder write an
            # out-of-namespace write by hw_monitor — harmless today only because
            # this process runs in WARN mode, and a hard failure the moment
            # anyone flips it to MODE_ENFORCE.
            #
            # Safe because this connection is opened for the cycle and closed in
            # the `finally` below: run_ladder_cycle() commits its own work and
            # shares a transaction with nothing else here.
            _lc = _dm().connect("mem_appliance")
            try:
                _sum = _mem_ladder.run_ladder_cycle(_dm(), _lc)
                if _sum.get("shadow_new"):
                    log.info("mem ladder: %d new shadow decision(s), seq=%s",
                             _sum["shadow_new"], _sum.get("seq"))
            finally:
                _lc.close()
        except Exception as _e:                             # noqa: BLE001
            log.warning("mem ladder cycle wiring error: %s", _e)

        _sample_sleep(SAMPLE_INTERVAL)
    log.info("hw_monitor stopped")


if __name__ == "__main__":
    # Assert the privilege boundary against the kernel before doing any work.
    # Inert until the migrated unit sets NEMESIS_EXPECT_USER (see nemesis_privsep).
    import nemesis_privsep
    nemesis_privsep.attest_from_env("hw-monitor")
    main()
