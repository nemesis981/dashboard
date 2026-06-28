import os
import sqlite3
from datetime import datetime

_HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(_HERE, "alerts.db")

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
                lockout_until   TEXT
            )
        """)
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
