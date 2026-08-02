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
                detected_at     TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS scan_schedules (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id       TEXT NOT NULL,
                schedule_type   TEXT NOT NULL DEFAULT 'weekly',
                scheduled_time  TEXT,
                last_run_at     TEXT,
                enabled         INTEGER DEFAULT 1
            )
        """)
        # ── ADR 0004 step 2: actor seam + local-ISO timestamps ──────────────
        #
        # Same treatment as the three scan_* tables created in hw_monitor — see
        # the fuller note there. ACTOR is a seam, not live attribution (nothing
        # calls set_actor() in normal operation yet). The separator IS the
        # migration guard: legacy rows are space-separated UTC, converted rows
        # ISO 'T' local, so this selects exactly the un-migrated rows and is a
        # no-op afterwards.
        #
        # scan_threats is converted even though ADR 0004 retires it into
        # malware_findings at step 4: leaving one UTC column beside converted
        # neighbours preserves the mixed-convention hazard for however long that
        # step takes, and the conversion is cheap. It may simply be dropped later.
        for _tbl in ("scan_threats", "scan_schedules"):
            _cols = {r[1] for r in c.execute("PRAGMA table_info(%s)" % _tbl).fetchall()}
            if _cols and "actor" not in _cols:
                c.execute("ALTER TABLE %s ADD COLUMN actor TEXT" % _tbl)
        for _tbl, _col in (("scan_threats", "detected_at"),
                           ("scan_schedules", "last_run_at")):
            c.execute(
                "UPDATE {t} SET {c} = strftime('%Y-%m-%dT%H:%M:%S', {c}, 'localtime') "
                "WHERE {c} LIKE '____-__-__ %'".format(t=_tbl, c=_col))
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
                lockout_tier    INTEGER NOT NULL DEFAULT 0,
                password_changed_at TEXT,
                recovery_grace_until TEXT
            )
        """)
        # Guarded migration: add lockout_tier to users tables created before it
        # existed (CLAUDE.md DB rule — ALTER alongside the updated CREATE).
        cols = [r[1] for r in c.execute("PRAGMA table_info(users)")]
        if "lockout_tier" not in cols:
            c.execute("ALTER TABLE users ADD COLUMN lockout_tier INTEGER NOT NULL DEFAULT 0")
        # Guarded migration: when the password was last SET, which `created_at`
        # and `last_login` between them cannot answer. Prerequisite for the
        # 30-day expiry policy — without it there is no way to tell a fresh
        # password from one set a year ago.
        #
        # TWO STEPS, not a DEFAULT. SQLite requires ADD COLUMN defaults to be
        # CONSTANT, so `DEFAULT created_at` is not expressible; the backfill has
        # to be a separate UPDATE. (Contrast login_events.source, whose default
        # 'login' is a literal and needed no second step.)
        #
        # Backfilling from created_at is a statement of fact, not a guess: there
        # is no password-change path in the codebase yet, so for every existing
        # row the password genuinely was set when the account was created.
        #
        # Deliberately NULLABLE. A NOT NULL column would need a constant default,
        # which would have to be a fixed timestamp — instantly wrong for every
        # account. NULL is handled by the expiry check as "unknown, treat as due
        # for change" rather than being silently skipped.
        # recovery_grace_until — the authoritative end of the post-recovery-code
        # window in which a password may be set WITHOUT supplying the old one.
        #
        # It lives in the DB rather than only in the session because Flask sessions
        # are client-side signed cookies: popping a key does not invalidate a cookie
        # already handed out, so a captured cookie could be replayed to change the
        # password after the window was supposedly closed — defeating the exact
        # protection that requiring the current password provides. A column can be
        # cleared authoritatively, and every replayed cookie then fails.
        #
        # NULL = no window open, which is the correct state for every existing row.
        if "recovery_grace_until" not in cols:
            c.execute("ALTER TABLE users ADD COLUMN recovery_grace_until TEXT")
        if "password_changed_at" not in cols:
            c.execute("ALTER TABLE users ADD COLUMN password_changed_at TEXT")
            c.execute("UPDATE users SET password_changed_at = created_at "
                      "WHERE password_changed_at IS NULL")
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
                timestamp     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S','now','localtime')),
                ip_address    TEXT NOT NULL,
                device_id     TEXT,
                tailscale_ip  TEXT,
                geo_country   TEXT,
                geo_city      TEXT,
                success       INTEGER NOT NULL,
                failure_reason TEXT,
                lockout_tier  INTEGER,
                session_id    TEXT,
                user_agent    TEXT,
                source        TEXT NOT NULL DEFAULT 'login',
                action        TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_login_events_user_ts "
                  "ON login_events(username, timestamp)")
        # Idempotent migration: this table gained a SECOND event source.
        #
        # Until 2026-07-31 every row was a dashboard login-form attempt, so the
        # table needed no way to say where an attempt came from. nemesis-fwd also
        # challenges for the admin password — on block, unblock, write_env and
        # restart_dashboard — and those failures incremented the shared lockout
        # counter while leaving no queryable row anywhere. Same credential, same
        # lockout budget, half the evidence.
        #
        #   source  which surface the attempt arrived at: 'login' | 'nemesis-fwd'
        #   action  the privileged op attempted (write_env, block_ip, ...).
        #           NULL for login-form rows, which are not op-specific.
        #
        # DEFAULT 'login' is what makes the backfill correct rather than merely
        # non-null: every pre-existing row genuinely IS a login-form attempt, so
        # the default states a fact about the history instead of guessing at one.
        existing = {row[1] for row in c.execute("PRAGMA table_info(login_events)").fetchall()}
        if "source" not in existing:
            c.execute("ALTER TABLE login_events ADD COLUMN source TEXT NOT NULL DEFAULT 'login'")
        if "action" not in existing:
            c.execute("ALTER TABLE login_events ADD COLUMN action TEXT")

        # Idempotent migration: UTC rows -> local time, matching every sibling table.
        #
        # THE DEFECT. Until 2026-08-02 `timestamp` came from the column DEFAULT
        # `datetime('now')`, which SQLite evaluates as UTC. Every other
        # auth-adjacent column — users.last_login, users.lockout_until,
        # users.password_changed_at, audit_log.ts — is written by Python
        # `datetime.now()`, which is LOCAL. The same login wrote
        # `2026-08-01 22:58:49` here and `2026-08-01T17:58:49` to users. Confirmed
        # in live data, not inferred.
        #
        # WHY IT WAS WORTH FIXING despite nothing being visibly broken: the two
        # readers happened to compare against SQLite's own UTC `datetime('now')`,
        # so the table was self-consistent. But this table exists to feed
        # brute-force, impossible-travel and concurrent-session detection, and the
        # first correlation anyone writes against users or audit_log inherits a
        # 5-hour error — in the direction that makes attacker activity look like it
        # happened in the future.
        #
        # THE FORMAT IS THE MIGRATION GUARD, which is what makes this safe to run
        # on every startup. Legacy rows are `YYYY-MM-DD HH:MM:SS` (space, UTC); new
        # rows are `YYYY-MM-DDTHH:MM:SS` (ISO 'T', local). The separator therefore
        # states which epoch a row belongs to, so the conversion selects exactly the
        # un-migrated rows and becomes a no-op the moment it has run. No flag, no
        # version table, and no way to double-convert a row into 10 hours of drift.
        #
        # The `-- login_events tz migration` marker is load-bearing for auditability
        # only; the WHERE clause is what makes it correct.
        c.execute("""
            UPDATE login_events                      -- login_events tz migration
               SET timestamp = strftime('%Y-%m-%dT%H:%M:%S', timestamp, 'localtime')
             WHERE timestamp LIKE '____-__-__ %'
        """)
        conn.commit()
    finally:
        conn.close()

def record_auth_failure(username, source, action=None, lockout_tier=None,
                        ip_address="local-socket",
                        failure_reason="credential_denied"):
    """Append ONE failed-authentication row to `login_events`. Returns True if it landed.

    Added 2026-07-31. `login_events` had a single writer — the dashboard login
    form — but the admin password is also challenged by nemesis-fwd on every
    privileged op (block, unblock, write_env, restart_dashboard). Those failures
    incremented the SHARED lockout counter and emitted a journal warning, leaving
    no queryable row: same credential, same lockout budget, half the evidence.

    WHY THIS LIVES HERE rather than the helper writing the table directly.
    The obvious route was to add `login_events` to nemesis_fwd's Data Manager
    grant. That was checked rather than assumed, and it cannot express what was
    wanted: column grants are UPDATE-only by design (see data_manager.py's
    check_write — "INSERT/DELETE/DROP affect whole rows or the table itself"), so
    the narrowest available grant is the WHOLE TABLE — INSERT, UPDATE and DELETE
    on an append-only authentication log. A component able to erase the record of
    its own misuse is a weaker guarantee than one that cannot.

    Moving the code instead follows the precedent set for `scan_threats`
    (data_manager.py ~:207), where the same wall was hit and resolved the same
    way. Runs on a RAW connection like init_audit_log_table(), so any process may
    call it with no namespace grant, and it performs INSERT only — the helper is
    structurally incapable of rewriting history through this path.

    BEST-EFFORT, and deliberately so: this NEVER raises. Its caller in the helper
    is the failed-credential path, where a refusal must stay a refusal — a
    logging problem must never become an authentication outcome. Callers should
    also invoke it AFTER applying the lockout, so that even a total failure here
    costs evidence rather than the throttle itself.

    `source` is required, with no default: a helper failure silently recorded as
    a login-form attempt would be worse than not recording it, because it would
    be believed.

    `ip_address` defaults to a sentinel because the column is NOT NULL and a Unix
    socket peer has no address. 'local-socket' is deliberately distinguishable
    from the login path's 'unknown', which means "we should have had an IP and
    did not".
    """
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        try:
            # `timestamp` is supplied EXPLICITLY rather than left to the column
            # DEFAULT. SQLite cannot alter a column default in place, so on an
            # already-created database the DEFAULT stays the old UTC expression
            # forever — passing the value here is what actually fixes the skew on
            # every existing install, and it puts this table on the same footing as
            # every sibling (Python-supplied local ISO), instead of being the one
            # table whose time came from a parallel SQL mechanism.
            conn.execute(
                "INSERT INTO login_events(username, timestamp, ip_address, success, "
                "failure_reason, lockout_tier, source, action) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (username, datetime.now().isoformat(timespec="seconds"),
                 ip_address or "local-socket", 0, failure_reason,
                 lockout_tier, source, action),
            )
            conn.commit()
            return True
        finally:
            conn.close()
    except Exception:
        # Swallowed on purpose — see BEST-EFFORT above. Logged via print because
        # this module has no logger and is imported by processes with different
        # logging setups; the caller's own logging is the primary channel.
        print("database: record_auth_failure failed for %r/%r" % (username, source))
        return False


def init_recovery_codes_table():
    """Canonical DDL for the core `recovery_codes` table (single-use backup codes).

    Core-owned and unprefixed, alongside `users` / `login_events` / `audit_log`
    (ADR 0001: modules own prefixed tables, core owns the unprefixed ones).

    A code is valid only while `used_at IS NULL AND superseded_at IS NULL`. Two
    separate columns rather than one status field because they are two genuinely
    different events and the difference matters when reading the trail later:

      used_at        this specific code was spent. Per-code, single use.
      superseded_at  the whole batch was replaced by regenerating. Not the
                     operator's doing, code by code — a batch-level event.

    Rows are superseded, never deleted. Deleting would invalidate the codes just
    as effectively but would erase the evidence that a batch ever existed, and
    "were recovery codes regenerated, and when?" is exactly the question asked
    after a suspected compromise. Retention costs one bcrypt hash per row.

    `created_actor` is the ADR 0006 actor seam — NULL today (nothing calls
    set_actor yet), present so that attributing "who issued this batch" in a
    multi-user tier is a write to an existing column rather than a migration.

    NOTE: nemesis-fwd is deliberately granted NO access to this table. It
    verifies the admin password for privileged ops; letting it also consume
    recovery codes would turn the break-glass credential into a routine one.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS recovery_codes (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id       INTEGER NOT NULL,
                code_hash     TEXT NOT NULL,
                batch_id      TEXT NOT NULL,
                created_at    TEXT NOT NULL,
                created_actor TEXT,
                used_at       TEXT,
                used_ip       TEXT,
                superseded_at TEXT
            )
        """)
        # Lookup is always "the live codes for this user", so the index carries
        # the validity predicate rather than just user_id.
        c.execute("CREATE INDEX IF NOT EXISTS idx_recovery_codes_live "
                  "ON recovery_codes(user_id, used_at, superseded_at)")
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
