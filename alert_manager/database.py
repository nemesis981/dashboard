import os
import sqlite3
from datetime import datetime

_HERE = os.path.dirname(os.path.abspath(__file__))
import nemesis_paths
DB_PATH = nemesis_paths.db_path(os.path.join(_HERE, "alerts.db"))

def init_db():
    conn = sqlite3.connect(DB_PATH)
    # ADR 0001 Stage-2 prerequisite: the shared DB runs in WAL mode so multiple
    # services + modules can write concurrently without "database is locked".
    # WAL is persistent on the file; asserting it here (idempotent) converts the
    # DB on first startup and keeps it WAL even if the file is ever recreated.
    # busy_timeout is per-connection — set 5s here too (matches Python's default).
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL,
            rule_name TEXT,
            classification TEXT,
            priority INTEGER,
            explanation TEXT,
            risk_level TEXT,
            action TEXT DEFAULT "pending",
            times_seen INTEGER DEFAULT 1,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT
        )
    ''')
    conn.commit()
    conn.close()
    print("Database initialized successfully")

def init_quarantines_table():
    """Canonical DDL for the core `quarantines` table (+ active index).

    Single source of truth, called by BOTH alert_watcher's startup init
    (init_quarantines_db) and the dashboard's lazy self-heal
    (_ensure_quarantines_table). CREATE ... IF NOT EXISTS, so whichever process
    runs first wins and later calls are no-ops. Both callers are kept (not
    collapsed to one): there is NO systemd ordering between the services, so
    alert_watcher's create-before-write and the dashboard's self-heal before its
    unguarded SELECT must each remain. This dedups the DDL text, not the safety
    nets. See ADR 0001 / Pass 0 Stage 4.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS quarantines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                actor TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_quarantines_active ON quarantines(status, expires_at)")
        # Idempotent migration: actor attribution seam (readiness Tier B). Adds the
        # column to pre-existing DBs; fresh installs get it from the CREATE above.
        existing = {row[1] for row in c.execute("PRAGMA table_info(quarantines)").fetchall()}
        if "actor" not in existing:
            c.execute("ALTER TABLE quarantines ADD COLUMN actor TEXT")
        conn.commit()
    finally:
        conn.close()

def init_devices_table():
    """Canonical DDL for the core `devices` table (LAN-scan inventory).

    Single source of truth, mirroring init_quarantines_table(). DDL matches the
    live table exactly (captured via `.schema devices`, 2026-06-27). Called by
    BOTH the device_scanner (create-before-write, since it is a separate process
    that may run on a fresh DB before the dashboard) and the dashboard's boot
    init (self-heal before its unguarded device reads). CREATE ... IF NOT EXISTS,
    so whichever process runs first wins and later calls are no-ops. There is NO
    systemd ordering between the services, so both call sites are kept. This
    table previously had NO CREATE anywhere — a fresh install crashed the
    device_scanner with `no such table: devices`. See ADR 0001 / readiness Tier A.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                ip TEXT,
                friendly_name TEXT,
                device_type TEXT,
                notes TEXT,
                trusted INTEGER DEFAULT 1
            )
        """)
        conn.commit()
    finally:
        conn.close()

def init_audit_log_table():
    """Canonical DDL for `audit_log` (per-action attribution, append-only).

    Moved here from dashboard 2026-07-29, same reasoning as init_scan_tables():
    schema ownership belongs in one module rather than in whichever process
    happened to need the table first. This one has TWO legitimate row writers —
    dashboard (`_audit`) and nemesis_fwd (`audit()`), both registered shared
    writers in the Data Manager — so leaving the CREATE in dashboard made it the
    de-facto schema owner purely by accident of history.

    NOTE, so this is not misread: unlike the scan-table move, no grant changes
    here. Both writers genuinely INSERT rows and keep their full table grants;
    column grants could not express it either, being UPDATE-only. What this
    changes is only that the CREATE stops being issued through a caller's guarded
    connection, which is what makes the DDL consistent with the other five core
    tables owned by this module.

    Runs on a RAW connection like its siblings, so no namespace grant is needed to
    call it. `IF NOT EXISTS`, so any process may call it and later calls are
    no-ops.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        # Byte-identical to what dashboard created, verified against the live
        # schema — an existing database is untouched.
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TIMESTAMP NOT NULL,
                rule_id TEXT,
                ip TEXT,
                action TEXT NOT NULL,
                user TEXT,
                request_id TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts)")
        # Idempotent migration: separate the two meanings that shared `rule_id`.
        #
        # The column is named rule_id, but only ONE of the two writers puts a rule
        # reference in it. dashboard `_audit()` writes a genuine alerts.rule_id;
        # nemesis_fwd `audit()` was writing its per-request correlation id into the
        # same column, so audit rows appeared to reference alerts that never existed
        # (found 2026-07-31 while investigating the empty `quarantines` table — the
        # mismatch is what made a non-bug look like data loss).
        #
        # Added as a SECOND column rather than renaming: rule_id keeps its meaning
        # for dashboard's rows, which are correct as they stand.
        #
        # NOT backfilled, deliberately. Rows written before this migration may carry
        # a request_id in `rule_id`. Deciding which historical rows came from which
        # writer means inferring from the `action` prefix (fw_* => helper), which is
        # a strong signal but not a guarantee — and this is an append-only audit
        # table. A documented quirk is preferable to a guessed rewrite of audit history.
        existing = {row[1] for row in c.execute("PRAGMA table_info(audit_log)").fetchall()}
        if "request_id" not in existing:
            c.execute("ALTER TABLE audit_log ADD COLUMN request_id TEXT")
        conn.commit()
    finally:
        conn.close()


def init_scan_tables():
    """Canonical DDL for `scan_threats` and `scan_schedules`.

    Moved here from hw_monitor 2026-07-29 as part of the table-ownership
    resolution. Both tables are written ONLY by dashboard (`scan_threats` rows at
    dashboard.py:6175, `scan_schedules` at :6362); hw_monitor never wrote a row to
    either — its only statements were these two CREATEs. Leaving the DDL there
    forced hw_monitor to hold a full table grant covering INSERT/UPDATE/DELETE it
    does not use, because the Data Manager grants per table for every write op and
    its only narrowing mechanism (column grants) is deliberately UPDATE-only.

    Relocating the DDL to this module — already the canonical DDL owner for
    `devices`, `quarantines` and `enrollment_tokens` — resolves that without
    adding a DDL-only grant type to the access-control module. This function runs
    on a RAW connection, exactly like its siblings, so the CREATE is never issued
    through a caller's guarded connection and no namespace grant is required to
    call it.

    `CREATE ... IF NOT EXISTS`, so whichever process calls first wins and the rest
    are no-ops. There is NO systemd ordering between these services, which is why
    every process that needs the tables calls this itself rather than assuming
    another one ran first.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        # DDL byte-identical to what hw_monitor created, so an existing database
        # is untouched and a fresh one gets the same schema.
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
    finally:
        conn.close()


def init_users_table():
    """Canonical DDL for the core `users` table (Flask-Login auth).

    Single source of truth, mirroring init_quarantines_table(). One place only
    (per the DB rules). Called from the shared boot init so every process sees
    the table. `password_hash` is bcrypt; `role` is a seam for the commercial
    multi-user tier. failed_attempts/lockout_until back the login rate-limit.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT NOT NULL UNIQUE,      -- login ID, stable, lowercase
                display_name    TEXT NOT NULL,             -- shown in UI, can change
                password_hash   TEXT NOT NULL,             -- bcrypt
                role            TEXT NOT NULL DEFAULT 'admin',  -- 'admin'|'user' (commercial seam)
                is_active       INTEGER NOT NULL DEFAULT 1,
                created_at      TEXT NOT NULL,
                last_login      TEXT,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                lockout_until   TEXT,
                lockout_tier    INTEGER NOT NULL DEFAULT 0
            )
        """)
        # Guarded migration: add lockout_tier to users tables created before it
        # existed (CLAUDE.md DB rule — ALTER alongside the updated CREATE).
        cols = [r[1] for r in c.execute("PRAGMA table_info(users)")]
        if "lockout_tier" not in cols:
            c.execute("ALTER TABLE users ADD COLUMN lockout_tier INTEGER NOT NULL DEFAULT 0")
        conn.commit()
    finally:
        conn.close()

def init_login_events_table():
    """Canonical DDL for the core `login_events` table (auth audit trail).

    One row per login attempt (success AND failure). The data source for
    concurrent-session detection, location anomaly, impossible travel, and
    brute-force detection. Collection starts now; detection logic comes later.
    geo_*/device_id/tailscale_ip/session_id are seams (NULL until populated).
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS login_events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL,
                timestamp     TEXT NOT NULL DEFAULT (datetime('now')),
                ip_address    TEXT NOT NULL,
                device_id     TEXT,
                tailscale_ip  TEXT,
                geo_country   TEXT,
                geo_city      TEXT,
                success       INTEGER NOT NULL,
                failure_reason TEXT,
                lockout_tier  INTEGER,
                session_id    TEXT,
                user_agent    TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_login_events_user_ts "
                  "ON login_events(username, timestamp)")
        conn.commit()
    finally:
        conn.close()

def init_enrollment_tokens_table():
    """Canonical DDL for the core `enrollment_tokens` table.

    Backs the dashboard's "Generate Windows Installer" flow: single-use,
    time-limited tokens that auto-approve a device at /enroll (hw_monitor),
    skipping the manual pending→approve step. Core-owned (unprefixed) per ADR 0001.
    Timestamps are epoch REAL. Created by the dashboard at boot; hw_monitor reads
    it (defensively — a missing/locked table just falls back to normal pending).
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS enrollment_tokens (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                token            TEXT NOT NULL UNIQUE,
                created_by       TEXT NOT NULL,
                created_at       REAL NOT NULL,
                expires_at       REAL NOT NULL,
                max_uses         INTEGER DEFAULT 1,
                uses             INTEGER DEFAULT 0,
                auto_approve     INTEGER DEFAULT 1,
                device_name_hint TEXT,
                revoked          INTEGER DEFAULT 0,
                preauth_key      TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_token "
                  "ON enrollment_tokens(token)")
        # Migration (ADR 0001 guarded ALTER): preauth_key = single-use Tailscale pre-auth
        # key baked into the generated installer conf. Secret-at-rest, mitigated by single-
        # use + short TTL (1-2h) + revocable; NEVER logged. (Delivery foundation, Phase 1.)
        _cols = {r[1] for r in c.execute("PRAGMA table_info(enrollment_tokens)").fetchall()}
        if "preauth_key" not in _cols:
            c.execute("ALTER TABLE enrollment_tokens ADD COLUMN preauth_key TEXT")
        # Migration (ADR 0001 guarded ALTER): poll_interval = optional custom heartbeat
        # cadence baked into the generated installer conf (floor-clamped at generation).
        # NULL => the agent uses its own 300s default.
        if "poll_interval" not in _cols:
            c.execute("ALTER TABLE enrollment_tokens ADD COLUMN poll_interval INTEGER")
        conn.commit()
    finally:
        conn.close()

def get_alert(rule_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM alerts WHERE rule_id = ?", (rule_id,))
    result = c.fetchone()
    conn.close()
    return result

def add_alert(rule_id, rule_name, classification, priority, explanation, risk_level, action, src_ip, dst_ip, protocol):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute('''
        INSERT INTO alerts 
        (rule_id, rule_name, classification, priority, explanation, risk_level, action, times_seen, first_seen, last_seen, src_ip, dst_ip, protocol)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
    ''', (rule_id, rule_name, classification, priority, explanation, risk_level, action, now, now, src_ip, dst_ip, protocol))
    conn.commit()
    conn.close()

def update_seen(rule_id, src_ip, dst_ip):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute('''
        UPDATE alerts 
        SET times_seen = times_seen + 1, last_seen = ?, src_ip = ?, dst_ip = ?
        WHERE rule_id = ?
    ''', (now, src_ip, dst_ip, rule_id))
    conn.commit()
    conn.close()

def update_action(rule_id, action):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE alerts SET action = ? WHERE rule_id = ?", (action, rule_id))
    conn.commit()
    conn.close()

def get_all_alerts():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY last_seen DESC")
    results = c.fetchall()
    conn.close()
    return results

if __name__ == "__main__":
    init_db()
