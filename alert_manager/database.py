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
            protocol TEXT,
            explanation_beginner TEXT,
            explanation_intermediate TEXT,
            explanation_pro TEXT
        )
    ''')
    # ── Guarded migration: per-expertise-tier AI explanations ────────────────
    #
    # The dashboard has had a three-tier explanation system (static/tier.js:
    # beginner | intermediate | pro) since long before AI alert analysis existed,
    # but the AI path never participated in it: the prompt asked for one "Plain
    # English explanation for home user" unconditionally, so a `pro` user and a
    # `beginner` user received identical consumer-style prose.
    #
    # WHY THREE COLUMNS AND NOT A RE-USE OF `explanation`. `explanation` has a
    # live downstream consumer: dashboard's `_anchor_load_alert()` reads it BY
    # NAME and feeds it into the chat grounding prompt. Storing JSON (or any
    # multi-variant encoding) in that column would silently feed raw markup to a
    # model as though it were prose -- broken in a way that returns a plausible
    # answer rather than an error. So the variants get their own columns and
    # `explanation` keeps its existing meaning and format.
    #
    # `explanation` continues to be written, with the INTERMEDIATE variant: it is
    # the tier system's own documented default (tier.js `DEFAULT = 'intermediate'`)
    # and is the tier-neutral choice for a consumer that cannot express a tier.
    #
    # NOT BACKFILLED, deliberately. Pre-existing rows keep their single
    # `explanation` and leave these three NULL; the dashboard falls back to
    # `explanation` for every tier when they are absent, so old rows render
    # exactly as they do today. Backfilling would mean re-running a BILLED AI
    # call per historical row against a live `rate_per_hour` ceiling, to rewrite
    # analyses nobody has asked to see -- the same on-demand-not-bulk reasoning
    # already recorded inline at dashboard.py's analyze gate.
    _alert_cols = {row[1] for row in c.execute("PRAGMA table_info(alerts)").fetchall()}
    for _col in ("explanation_beginner", "explanation_intermediate", "explanation_pro"):
        if _col not in _alert_cols:
            c.execute("ALTER TABLE alerts ADD COLUMN %s TEXT" % _col)
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

def init_settings_table():
    """Canonical DDL for the core `settings` table — general-purpose key/value.

    DELIBERATELY NOT single-purpose. Core config has until now lived only in
    `/etc/nemesis.env`, which needs root and a service restart to change — fine
    for install-time values, unusable for anything a user should be able to
    adjust while the product runs. Every module already has its own
    `<module>_settings` table for exactly this; core had none, so the first
    live-adjustable core knob had nowhere to go. This is that table, and it is
    shaped for the next one too.

    Unprefixed because core owns unprefixed tables (ADR 0001). Modules must keep
    using their own `<module>_settings`; this is not a shared dumping ground.

    `updated_at`/`updated_by` are the attribution seam (multi-user-ready by
    default): who changed a setting is exactly the kind of thing that is painful
    to retrofit once a commercial tier needs attributed actions.

    Called from the dashboard's boot init. CREATE ... IF NOT EXISTS, so repeat
    calls are no-ops and whichever process runs first wins.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at TEXT,
                updated_by TEXT
            )
        """)
        conn.commit()
    finally:
        conn.close()


def init_conn_events_tables():
    """Canonical DDL for Track C's two tables (ADR 0001: one CREATE, in the repo).

    `conn_consent` — the SERVER-side record of consent, and the thing that makes
    Requirement 0 clause 5 enforceable. The agent has its own local record, but a
    buggy, downgraded, or tampered agent must not be able to push data the user
    never agreed to, so the server keeps its own and checks it on every ingest.
    Defence in depth, and the audit trail requirement 8 asks for (who, when, which
    disclosure version, which device).

    `conn_events` — one row per connection lifecycle event. Field names and types
    mirror `nemesis_agent/conn_events.py` deliberately: that module is the single
    schema definition and this table is its storage shape. If you change one,
    change both — the validator is what stops them silently diverging.

    Nullable columns are nullable ON PURPOSE. `bytes_sent`/`bytes_recv` NULL means
    "the platform did not provide it", which is NOT the same as 0, and
    `proc_signed` carries 'unknown' rather than a coerced boolean. Storing a
    default here would destroy the distinction the schema exists to preserve.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS conn_consent (
                device_id          TEXT PRIMARY KEY,
                consent_version    INTEGER NOT NULL,
                granted_at         TEXT,
                granted_by         TEXT,
                recorded_at        TEXT NOT NULL,
                revoked_at         TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS conn_events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id       TEXT NOT NULL,
                conn_id         TEXT NOT NULL,
                event           TEXT NOT NULL,
                consent_version INTEGER NOT NULL,
                proto           TEXT NOT NULL,
                laddr           TEXT NOT NULL,
                lport           INTEGER NOT NULL,
                raddr           TEXT NOT NULL,
                rport           INTEGER NOT NULL,
                ts_open_wall    TEXT NOT NULL,
                ts_open_mono    REAL NOT NULL,
                ts_close_wall   TEXT,
                ts_close_mono   REAL,
                pid             INTEGER,
                proc_name       TEXT,
                proc_path       TEXT,
                proc_signed     TEXT,
                bytes_sent      INTEGER,
                bytes_recv      INTEGER,
                resolved_name        TEXT,
                resolved_name_source TEXT,
                received_at     TEXT NOT NULL
            )
        """)
        # Retention reaping scans by received_at; novelty/seen-set work (Piece 5)
        # scans by destination. Both get an index rather than a table scan that
        # grows with a 30-day window of every connection every device makes.
        c.execute("CREATE INDEX IF NOT EXISTS idx_conn_events_received "
                  "ON conn_events(received_at)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_conn_events_dest "
                  "ON conn_events(raddr, rport)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_conn_events_device "
                  "ON conn_events(device_id, received_at)")
        conn.commit()
    finally:
        conn.close()


#: Core settings and their shipped defaults. A key absent from here is not a
#: known setting — get_setting() will still return it if stored, but the UI and
#: validation work from this map, so adding a knob means adding it here.
CORE_SETTING_DEFAULTS = {
    # Track C retention. The build plan requires 30 days "enforced by a real
    # reaper, not by intention", user-configurable and surfaced in settings.
    # Stored as a string like every other setting value.
    "conn_event_retention_days": "30",
    # How often a REMOTE (vpn_remote) agent sends a full observation snapshot,
    # expressed as "every Nth heartbeat". Local agents always observe every beat
    # and are deliberately not adjustable — it is free on a LAN.
    #
    # 6 is a STARTING POINT, not a measurement: ~161MB/month per roaming device
    # instead of ~659MB. See docs/OPERATION.md "Agent Devices: Local vs Remote
    # Reporting" for the user-facing statement of the tradeoff.
    "agent_remote_observe_every_n": "6",
}

#: Bounds for agent_remote_observe_every_n. 1 = full fidelity everywhere.
#: 48 = one snapshot per 4h at the 300s default beat; beyond that the snapshot is
#: stale enough to stop being an observation layer and start being a misleading
#: one, so the ceiling is a real limit rather than input hygiene.
REMOTE_OBSERVE_N_MIN = 1
REMOTE_OBSERVE_N_MAX = 48


def get_setting(key, default=None):
    """Read a core setting. Falls back to CORE_SETTING_DEFAULTS, then `default`.

    A missing table or unreadable row returns the DEFAULT, not None: these are
    configuration knobs with meaningful shipped values, and a fresh install that
    has never written one is a normal state rather than an error. That is only
    safe because every consumer clamps the value it gets — see
    get_remote_observe_every_n().
    """
    fallback = CORE_SETTING_DEFAULTS.get(key, default)
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        try:
            row = conn.execute(
                "SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        finally:
            conn.close()
    except Exception:
        return fallback
    return row[0] if row and row[0] is not None else fallback


def set_setting(key, value, actor=None):
    """Write a core setting. Returns True on success."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        try:
            conn.execute(
                "INSERT INTO settings (key, value, updated_at, updated_by) "
                "VALUES (?,?,?,?) ON CONFLICT(key) DO UPDATE SET "
                "value=excluded.value, updated_at=excluded.updated_at, "
                "updated_by=excluded.updated_by",
                (key, str(value), datetime.now().isoformat(timespec="seconds"), actor),
            )
            conn.commit()
        finally:
            conn.close()
        return True
    except Exception:
        return False


def get_remote_observe_every_n():
    """The remote-observation divisor, always a usable int inside the bounds.

    Clamps rather than trusting storage. A stored 0 would divide-by-zero on the
    agent; a stored negative or garbage value would make every beat 'due' and
    turn a bandwidth SAVING into a bandwidth storm on precisely the metered
    connections this exists to protect. So the value is bounded here, and the
    agent bounds it again independently on receipt — neither side assumes the
    other validated.
    """
    raw = get_setting("agent_remote_observe_every_n",
                      CORE_SETTING_DEFAULTS["agent_remote_observe_every_n"])
    default = int(CORE_SETTING_DEFAULTS["agent_remote_observe_every_n"])
    try:
        n = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    # Out of range falls back to the DEFAULT, not to the nearest bound. Clamping
    # a stored 0 up to REMOTE_OBSERVE_N_MIN would resolve an invalid value to
    # full-fidelity-every-beat -- the most expensive setting -- on the metered
    # links this exists to protect. Clamping is only safe from a value that was
    # meaningful to begin with; the agent applies the same rule on receipt.
    if n < REMOTE_OBSERVE_N_MIN or n > REMOTE_OBSERVE_N_MAX:
        return default
    return n


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
                trusted INTEGER DEFAULT 1,
                vendor TEXT,
                category_override TEXT,
                category_source TEXT,
                hostname TEXT
            )
        """)
        # ── Guarded migrations ───────────────────────────────────────────────
        #
        # ⚠ THE FIRST THREE FIX A REAL DRIFT, they are not new work. `vendor`,
        # `category_override` and `category_source` were added to the LIVE
        # database by `scripts/migrate_device_categories.py`, but this canonical
        # CREATE was never updated to match. The live table had 9 columns while
        # the repo's CREATE declared 6 (verified 2026-08-06).
        #
        # That is invisible on an existing install and breaks a FRESH one: a new
        # database would get a `devices` table without those columns, and device
        # categorisation would be silently inert — `get_network_devices()` probes
        # for them with PRAGMA and simply omits what is absent, so nothing would
        # error, the feature would just never work. Exactly the shape CLAUDE.md's
        # "guarded ALTER alongside the UPDATED create" rule exists to prevent.
        #
        # `hostname` is the new one: DHCP option 12, captured at lease time by
        # the dhcp module and reconciled in here (see `reconcile_dhcp_hostnames`).
        # It is DISTINCT from `friendly_name` on purpose — friendly_name is the
        # operator's own label and must never be overwritten by an observation.
        _cols = {row[1] for row in c.execute("PRAGMA table_info(devices)").fetchall()}
        for _col in ("vendor", "category_override", "category_source", "hostname"):
            if _col not in _cols:
                c.execute("ALTER TABLE devices ADD COLUMN %s TEXT" % _col)
        conn.commit()
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# DHCP lease -> device inventory reconciliation
#
# ⚠ WHY THIS FUNCTION IS IN CORE AND NOT IN THE DHCP MODULE.
#
# ADR 0001: modules own tables by prefix and are WRITE-OWN / READ-ANY. `devices`
# is core-owned and unprefixed, so the dhcp module may READ it but must never
# write it. The module therefore records what it observes into its own
# `dhcp_leases` table, and this core-side function is the only thing that
# promotes an observation into the shared inventory.
#
# THE TABLE IS THE INTERFACE. `dhcp_leases` is the contract between the two
# sides: the module produces rows, core consumes them. Neither reaches into the
# other's storage. That boundary is what lets the DHCP module be disabled,
# swapped for a different implementation, or run in a mode where it serves no
# leases at all, without any of that touching the device inventory's schema or
# its writers.
# ─────────────────────────────────────────────────────────────────────────────

def reconcile_dhcp_hostnames(conn=None):
    """Promote observed DHCP hostnames into `devices.hostname`. Returns a summary.

    Matches on MAC, which is the only identifier both sides share and the one
    `devices` is keyed on.

    NEVER TOUCHES `friendly_name`. That column is the operator's own naming, and
    an observation must not overwrite a human decision — the product already has
    one bug of exactly that shape on record (an OUI vendor string written into
    `friendly_name` and destroyed on rename). `hostname` is stored alongside it;
    display logic decides which to show, and the operator's name wins.

    Only writes when the value actually CHANGES, so a device that reconnects
    every few minutes does not generate a write per lease renewal.

    Absent `dhcp_leases` is a normal state, not an error: the DHCP module may be
    disabled, or running in `pihole`/`provider` mode where it never serves a
    lease. Returns zeroes with `available=False` rather than raising, and the
    caller can tell that apart from "ran and found nothing" — which a bare 0
    could not.
    """
    own_conn = conn is None
    if own_conn:
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        have = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='dhcp_leases'"
        ).fetchone()
        if not have:
            return {"available": False, "examined": 0, "updated": 0}

        rows = conn.execute(
            "SELECT mac, hostname FROM dhcp_leases "
            "WHERE hostname IS NOT NULL AND TRIM(hostname) != ''"
        ).fetchall()

        updated = 0
        for mac, hostname in rows:
            if not mac:
                continue
            cur = conn.execute(
                "UPDATE devices SET hostname=? "
                "WHERE mac=? AND IFNULL(hostname,'') != ?",
                (hostname, mac.lower(), hostname))
            updated += cur.rowcount
        conn.commit()
        return {"available": True, "examined": len(rows), "updated": updated}
    finally:
        if own_conn:
            conn.close()

def init_error_tables():
    """Create the structured error-code tables (ADR 0001 core-owned `error_*`).

    CANONICAL DDL LIVES IN `nemesis_errors._DDL`, not here — this is the core
    startup hook that calls it, mirroring how `init_devices_table()` works. Per
    the standing rule there is exactly ONE CREATE per table in the repo; a second
    copy here is what would drift.

    Called at dashboard startup AND create-before-write by each recording call
    site. That duplication is deliberate and matches the `devices`/`quarantines`
    precedent: there is no systemd ordering between the dashboard and the other
    services, so whichever process reaches the DB first must be able to create
    what it needs.
    """
    import nemesis_errors
    conn = sqlite3.connect(DB_PATH)
    try:
        nemesis_errors.init_error_tables(conn)
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


def init_connectivity_episodes_table():
    """Canonical DDL for `connectivity_episodes` (connectivity outage episodes).

    WHY THIS TABLE EXISTS (2026-08-07). Two independent subsystems already detect
    connectivity failure — the diagnostics watcher and `vpn_dns_guard` — and on
    2026-08-07 BOTH detected a real ~1-hour outage, dozens of times each, and
    neither told anyone: diagnostics wrote 27 consecutive LOCAL_FAIL samples to
    `diagnostics_connectivity_samples` and vpn_dns_guard logged ~56 warnings to a
    flat file, while the outage was chased as an ISP fault. Detection was never
    the gap; NOTIFICATION was.

    This table is the durable state that turns a stream of per-cycle samples into
    EPISODES, so one outage produces one notification instead of one per sample
    (27 alerts for a single event would train an operator to ignore the alert
    that matters).

    It is core-owned and unprefixed deliberately (ADR 0001). Both writers are
    core-side processes: the diagnostics *module* stays observe-only by design
    (ADR 0005 — it makes no system changes and raises nothing), so the episode
    logic lives in core where writing core tables, opening tickets and sending
    mail is already the established pattern (`watchdog.py` does exactly this for
    hardware alerts).

    THREE STATES, not two. A failure streak that never reaches the debounce
    threshold is recorded as `counting` and then closed without ever escalating.
    Those sub-threshold rows are KEPT, not deleted: they are the measured record
    of how often short blips occur, which is the evidence needed to tell whether
    the debounce threshold is set correctly. Deleting them would discard exactly
    the data that would justify changing it.

    Runs on a RAW connection like its siblings, so no namespace grant is needed to
    call it. `IF NOT EXISTS`, so any process may call it and later calls are
    no-ops.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS connectivity_episodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                state TEXT NOT NULL,
                verdict TEXT,
                severity TEXT,
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                first_failure_at TEXT,
                opened_at TEXT,
                closed_at TEXT,
                ticket_id INTEGER,
                alert_rule_id TEXT,
                email_sent INTEGER NOT NULL DEFAULT 0,
                detail TEXT,
                actor TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        # Lookup is always "the live row for this source" — the hot path on every
        # probe cycle for every writer.
        c.execute("CREATE INDEX IF NOT EXISTS idx_conn_ep_source_state "
                  "ON connectivity_episodes(source, state)")
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
                preauth_key      TEXT,
                preauth_key_id   TEXT,
                preauth_key_minted_at REAL
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
        # Migration (ADR 0001 guarded ALTER): preauth_key_id = the Tailscale key ID that
        # `mint_preauth_key()` already returns and the caller used to discard. It is NOT a
        # secret — it is the handle needed to REVOKE a key via the API. Storing it is what
        # makes revocation programmatic instead of a hand-search in the admin console, and
        # it is what survives after `preauth_key` itself is scrubbed. Audit 2026-08-07
        # found 22 keys retained in plaintext indefinitely with no id recorded for any of
        # them, so none could be revoked without matching them by hand.
        if "preauth_key_id" not in _cols:
            c.execute("ALTER TABLE enrollment_tokens ADD COLUMN preauth_key_id TEXT")
        # Migration (ADR 0001 guarded ALTER): when the current key was minted. NOT a
        # secret — a unix timestamp. It exists so a superseded key can be retired only
        # once it is old enough that revoking it cannot pull the rug out from under an
        # install that is already running (see
        # tailscale_api.should_retire_superseded_key). NULL on rows predating this
        # column, which that helper deliberately treats as "do not revoke".
        if "preauth_key_minted_at" not in _cols:
            c.execute("ALTER TABLE enrollment_tokens ADD COLUMN preauth_key_minted_at REAL")

        # backup_media_status: last-known free space per backup destination.
        #
        # Why a cache rather than a live poll: ADR 0018 specifies the backup
        # medium is mounted only for the brief window needed to write a
        # snapshot and unmounted the rest of the time — an unmounted drive is
        # unreachable to a compromised host. So free space is only observable
        # DURING a backup, and every reading is historical by the time anyone
        # looks at it. checked_at is therefore not decoration: a reading with
        # no age attached would be read as current and is worse than none.
        #
        # Local-ISO TEXT, supplied by the writer rather than a column DEFAULT —
        # ADR 0004's decided time convention. A DEFAULT cannot be altered in
        # place on an existing install, so writer-side values are what actually
        # fix already-deployed databases.
        c.execute("""
            CREATE TABLE IF NOT EXISTS backup_media_status (
                path        TEXT PRIMARY KEY,
                free_bytes  INTEGER,
                total_bytes INTEGER,
                checked_at  TEXT NOT NULL,
                actor       TEXT
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
