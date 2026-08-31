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

        # ── consent_basis migration (Track C step 5, 2026-08-08) ─────────────
        # `granted_by` already records WHO clicked. It does not record UNDER WHAT
        # AUTHORITY, and those are different questions: individual consent and
        # employer enrollment are different lawful bases, not different
        # usernames. A basis is what determines whether consent can be withdrawn
        # by the person using the device, so it cannot be inferred from the name.
        #
        # NO DEFAULT, DELIBERATELY. Rows written before this column existed get
        # NULL, and NULL means "recorded before the basis was tracked — unknown".
        # Defaulting them to 'individual' would manufacture a legal claim about
        # consent that nobody actually recorded, which is precisely the
        # failed-read-as-real-value shape this codebase treats as a defect.
        # Callers must branch on None explicitly rather than coalescing it.
        existing = {row[1] for row in
                    c.execute("PRAGMA table_info(conn_consent)").fetchall()}
        if "consent_basis" not in existing:
            c.execute("ALTER TABLE conn_consent ADD COLUMN consent_basis TEXT")

        _init_conn_seen_tables(c)
        conn.commit()
    finally:
        conn.close()


def init_tier2_gate_tables():
    """Canonical DDL for the Tier 2 gate's state-publication interface.

    ── WHAT THIS IS FOR ─────────────────────────────────────────────────────────
    The Tier 2 inspection gate's fail-safe (L3 Piece 5) lives outside this repo.
    The dashboard has to show whether traffic is currently being inspected, and
    every state transition has to leave an audit row. Those are the SAME fact
    published two ways, so they share one mechanism rather than two: the gate
    writes here, the dashboard reads here (ADR 0001 read-any), and no other
    coupling between the two sides exists.

    ── WHY THERE IS A HEARTBEAT, AND WHY THE READER MUST HONOUR IT ──────────────
    `tier2_gate_state` holds ONE row describing the current state. A stored state
    row is a CLAIM about a moment; it does not expire on its own. If the gate
    service dies while the row says `inspecting`, the row keeps saying
    `inspecting` forever and the dashboard keeps telling the operator their
    traffic is being inspected when nothing is running at all — a false
    reassurance that looks exactly like a working feature.

    So `heartbeat_at` is refreshed on every publish, and readers MUST treat a row
    older than the staleness bound as UNKNOWN rather than as the last known
    state. `tier2_gate_state.read_state()` does this; anything reading the table
    directly must do the same. Presence of a row is not evidence of a live gate.

    ── WHY `state` IS NOT A BOOLEAN ─────────────────────────────────────────────
    "Inspecting: yes/no" cannot express `soaking` (installed but still proving
    itself) or `locked_out` (bypassed and NOT retrying, needs a human). Those
    need different operator responses, and collapsing them would make the
    dashboard say the same thing for "recovering on its own" and "stuck until you
    act". The full state string is stored, and `inspecting`/`degraded` are stored
    alongside it as DERIVED convenience columns — derived by the gate, which owns
    the state machine, never re-derived by the dashboard from a string it would
    have to keep in sync.

    `tier2_gate_events` is append-only and is the audit trail: one row per
    transition, never updated, never deleted by the publisher. It carries
    `actor` for the same reason every other state-changing table here does
    (multi-user-ready by default) even though nothing sets it yet.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS tier2_gate_state (
                id                 INTEGER PRIMARY KEY CHECK (id = 1),
                state              TEXT    NOT NULL,
                inspecting         INTEGER NOT NULL,
                degraded           INTEGER NOT NULL,
                episodes_in_window INTEGER NOT NULL DEFAULT 0,
                reason             TEXT,
                since              TEXT    NOT NULL,
                heartbeat_at       TEXT    NOT NULL,
                actor              TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS tier2_gate_events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT    NOT NULL,
                event     TEXT    NOT NULL,
                severity  TEXT    NOT NULL,
                ticket    INTEGER NOT NULL DEFAULT 0,
                detail    TEXT,
                actor     TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_tier2_gate_events_ts "
                  "ON tier2_gate_events(ts DESC)")
        conn.commit()
    finally:
        conn.close()


#: The lawful basis a consent record rests on. NOT a free-text field — an
#: unrecognised value is a bug, and None means "predates the column" (see the
#: migration above), never "individual".
CONSENT_BASIS_INDIVIDUAL = "individual"   # the device's own user opted in
CONSENT_BASIS_EMPLOYER = "employer"       # enrolled under organisational authority
CONSENT_BASES = (CONSENT_BASIS_INDIVIDUAL, CONSENT_BASIS_EMPLOYER)


def _init_conn_seen_tables(c):
    """Canonical DDL for Track C's seen-set (step 5). Called from the Track C init.

    ── WHY THIS IS NOT DERIVED FROM conn_events ─────────────────────────────────
    The obvious implementation — answer "have I seen this destination before?" by
    querying conn_events — is WRONG, and wrong in a way that hides itself.
    conn_events is reaped at `conn_event_retention_days` (default 30). A seen-set
    derived from it would make EVERY destination novel again after 30 days:
    novelty would silently decay into a rolling 30-day window that nobody chose,
    that no setting describes, and that looks identical to a working feature.

    So the seen-set is its own store, populated INCREMENTALLY at ingest and never
    recomputed from the event table. It survives the event reaper by construction,
    not by ordering luck.

    ── ITS OWN RETENTION, AND WHY THE NUMBER IS DIFFERENT ───────────────────────
    Retaining it longer than conn_events is a deliberate decision, not an
    oversight, and it rests on the two stores holding genuinely different data:

      * conn_events is a DETAILED BEHAVIOURAL LOG — per-connection timing, ports,
        byte counts, the process path that opened it. Thirty days of that is a
        minute-by-minute account of how a person used their machine.
      * this table is a MEMBERSHIP SUMMARY — one row per destination, with a
        first/last date and a count. It cannot reconstruct a session, a sequence,
        or what someone was doing at 11pm on a Tuesday.

    Different sensitivity justifies a different window. It is still personal data,
    so it is BOUNDED and configurable (`conn_seen_retention_days`, default 365),
    not "forever" — and revocation purges it outright (Requirement 0 clause 7,
    see conn_seen.purge_device).

    ── AGED BY INACTIVITY, NEVER BY AGE ─────────────────────────────────────────
    Rows expire on `last_seen`, not `first_seen`. Expiring on first_seen would
    delete the OLDEST and best-established destinations first — the exact rows
    that make novelty meaningful — and would reintroduce the rolling-window bug
    from a different direction.

    365 days is chosen so annual-cadence destinations (tax software, travel
    booking, a seasonal service) do not read as novel every single year. Past
    that, "this device has not contacted this destination in over a year" IS
    genuinely novel again, so expiry here is a semantic statement rather than
    mere housekeeping.

    A FLOOR IS ENFORCED IN CODE (conn_seen.effective_retention_days): the seen-set
    window can never be shorter than conn_events'. If it were, raw events would
    outlive the summary of them and a destination with events still on file would
    read as never-seen — incoherent, and hard to spot from the outside.

    ── TWO TABLES, BECAUSE THE MERGE PATH NEEDS THE MAPPING ─────────────────────
    `conn_seen_destinations` holds one row per destination IDENTITY (name-keyed
    where a name was observed, address-keyed otherwise). `conn_seen_dest_addrs`
    maps every observed address to the destination it belongs to.

    The second table is what makes the merge correct rather than approximate. A
    destination first seen as a bare IP and later seen WITH a name must fold into
    the name entry carrying first_seen across; without a persistent addr->dest
    mapping, the next name-less connection to that IP would create a fresh
    address-keyed row with first_seen=now and the destination would read as novel
    again — history silently reset, which is the failure this whole design is
    built around avoiding. See conn_seen.record_destinations.
    """
    c.execute("""
        CREATE TABLE IF NOT EXISTS conn_seen_destinations (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id    TEXT NOT NULL,
            dest_key     TEXT NOT NULL,
            key_kind     TEXT NOT NULL,
            first_seen   TEXT NOT NULL,
            last_seen    TEXT NOT NULL,
            conn_count   INTEGER NOT NULL DEFAULT 0,
            merged_count INTEGER NOT NULL DEFAULT 0
        )
    """)
    # key_kind IS part of the unique key, not decoration. A hostile or broken
    # agent can report resolved_name="203.0.113.4" — a name that is textually an
    # address. Without key_kind in the index that record would collide with the
    # genuine address entry for 203.0.113.4 and silently merge two unrelated
    # destinations. With it, they coexist and stay distinguishable.
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_conn_seen_dest_key "
              "ON conn_seen_destinations(device_id, key_kind, dest_key)")
    # The reaper scans by last_seen (see the retention note above).
    c.execute("CREATE INDEX IF NOT EXISTS idx_conn_seen_dest_last "
              "ON conn_seen_destinations(last_seen)")
    c.execute("""
        CREATE TABLE IF NOT EXISTS conn_seen_dest_addrs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id  TEXT NOT NULL,
            addr       TEXT NOT NULL,
            dest_id    INTEGER NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen  TEXT NOT NULL
        )
    """)
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_conn_seen_addr "
              "ON conn_seen_dest_addrs(device_id, addr)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_conn_seen_addr_dest "
              "ON conn_seen_dest_addrs(dest_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_conn_seen_addr_last "
              "ON conn_seen_dest_addrs(last_seen)")


#: Core settings and their shipped defaults. A key absent from here is not a
#: known setting — get_setting() will still return it if stored, but the UI and
#: validation work from this map, so adding a knob means adding it here.
CORE_SETTING_DEFAULTS = {
    # Track C retention. The build plan requires 30 days "enforced by a real
    # reaper, not by intention", user-configurable and surfaced in settings.
    # Stored as a string like every other setting value.
    "conn_event_retention_days": "30",
    # Track C step 5. The seen-set's OWN retention, deliberately decoupled from
    # the event window above — a seen-set that aged with conn_events would make
    # every destination novel again every 30 days. Aged by INACTIVITY, and floored
    # at conn_event_retention_days in code so it can never outlive-by-less than
    # the events it summarises. Full reasoning: database._init_conn_seen_tables.
    "conn_seen_retention_days": "365",
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



def init_notify_tables():
    """Canonical DDL for the digest queue and its send-state.

    Two tables, and the split is load-bearing:

      * `notify_queue`  -- events routed to BUNDLE, held until a digest goes out.
        Without somewhere to hold them, `route()` returning BUNDLE means the event
        is simply dropped, which is exactly the silent-loss shape the digest
        exists to avoid. `sent_at`/`digest` stay NULL until a send genuinely
        succeeds.
      * `notify_state`  -- when each digest last went out. Kept OUT of the queue
        table on purpose: "when did the OPEN digest last send" must survive the
        queue being pruned, and a MAX(sent_at) over the queue would return NULL
        for a digest that correctly sent an empty report.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS notify_queue (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                queued_at   TEXT NOT NULL,
                severity    TEXT NOT NULL,
                surface     TEXT,
                family_key  TEXT,
                subject     TEXT NOT NULL,
                body        TEXT,
                digest      TEXT,
                sent_at     TEXT,
                actor       TEXT
            )
        """)
        # Pending lookup is the hot path: every tick asks "what is unsent".
        conn.execute("CREATE INDEX IF NOT EXISTS idx_notify_pending "
                     "ON notify_queue(sent_at, queued_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_notify_family "
                     "ON notify_queue(family_key)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS notify_state (
                key        TEXT PRIMARY KEY,
                value      TEXT,
                updated_at TEXT
            )
        """)
        conn.commit()
    finally:
        conn.close()

def init_capability_tables():
    """Canonical DDL for per-capability learning-gate unlocks (ADR 0026 §5).

    CORE-OWNED AND UNPREFIXED, deliberately: it belongs beside `users`, and the
    role model is core's, not any module's. Per ADR 0001 that makes it core's to
    create; per ADR 0006 every WRITE routes through the Data Manager with an
    actor, which `alert_manager/capabilities.py` does -- this function only
    creates the table.

    `UNIQUE(user_id, capability)` makes re-earning an UPSERT rather than a second
    row, so "is this unlocked" can never be ambiguous. Without it a re-take after
    a quiz revision would leave two rows disagreeing about the version, and the
    read path would have to pick one.

    `quiz_version` holds the CONTENT-DERIVED version from
    `quizzes.effective_version()`, not the author's declared label. That is what
    makes a quiz edit invalidate the unlock automatically instead of relying on
    someone remembering to bump a number.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_capability_unlocks (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id       INTEGER NOT NULL,
                capability    TEXT    NOT NULL,
                unlocked_at   TEXT    NOT NULL,
                quiz_version  TEXT    NOT NULL,
                quiz_score    INTEGER NOT NULL,
                -- READ THE NAME CAREFULLY: this counts PASSES, not tries.
                -- It increments only when `record_unlock` succeeds, so a learner
                -- who failed nine times and passed once has attempts=1, and a
                -- value of 3 means "earned, then re-earned twice after the quiz
                -- was revised". Failed submissions write nothing at all.
                -- Deliberate: a row here IS the unlock (presence plus a matching
                -- version), so recording failures would mean putting rows that
                -- must NOT count as unlocks into the table authorization reads.
                -- Counting real tries needs its own table; nothing consumes that
                -- today, so it is not built. The training page words this as
                -- "recorded N times", never as "N attempts".
                attempts      INTEGER NOT NULL DEFAULT 1,
                granted_by    TEXT,
                UNIQUE(user_id, capability)
            )
        """)
        # The hot path is "what has this user unlocked", asked on every request
        # that a sub-admin makes against a capability-covered route.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_capability_unlocks_user "
                     "ON user_capability_unlocks(user_id)")
        conn.commit()
    finally:
        conn.close()


def init_memory_recovery_tables():
    """Canonical DDL for the production memory-injection ladder loop (mem_appliance
    run_ladder_cycle). Two tables: the persisted ladder STATE (so streaks survive a
    restart instead of resetting the promotion clock to zero) and the SHADOW RECORDS
    that accumulate over real time — the evidence RESTART/ABORT promotion depends on.

    Without a running loop persisting these, the promotion gate sits at '0 resolved'
    forever, which is indistinguishable from 'not enough evidence yet' — the exact
    missing-machinery-vs-missing-evidence confusion this codebase keeps catching.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        # Single-row ladder state (the pure decide() state dict, JSON) + the sample
        # sequence counter it was last advanced to. id=1 CHECK keeps it single-row.
        c.execute("""
            CREATE TABLE IF NOT EXISTS mem_ladder_state (
                id          INTEGER PRIMARY KEY CHECK (id = 1),
                state_json  TEXT    NOT NULL,
                sample_seq  INTEGER NOT NULL,
                updated_ts  REAL    NOT NULL
            )
        """)
        # Shadow decisions awaiting evidence. follow_ups_json accumulates later
        # samples' verdicts; outcome is NULL until classify_outcome resolves it.
        # This is the promotion evidence, so it is APPEND-and-RESOLVE, never reset.
        c.execute("""
            CREATE TABLE IF NOT EXISTS mem_shadow_records (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                component        TEXT    NOT NULL,
                rung             TEXT    NOT NULL,
                decided_seq      INTEGER NOT NULL,
                observed_mb      REAL,
                budget_mb        REAL,
                follow_ups_json  TEXT    NOT NULL DEFAULT '[]',
                outcome          TEXT,
                created_ts       REAL    NOT NULL,
                resolved_ts      REAL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_mem_shadow_unresolved "
                  "ON mem_shadow_records(outcome) WHERE outcome IS NULL")
        c.execute("CREATE INDEX IF NOT EXISTS idx_mem_shadow_rung "
                  "ON mem_shadow_records(rung, outcome)")
        conn.commit()
    finally:
        conn.close()


def init_attestation_challenge_table():
    """Canonical DDL for the Tier 2 attestation issuer's per-device challenge state.

    When the issuer sends a challenge it must remember, PER DEVICE, what it issued —
    the nonce and the manifest's code_digests/python — so the eventual response can be
    verified (freshness/anti-replay depend on the server knowing its own nonce). One
    row per device (the latest outstanding challenge); superseded on re-issue.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS agent_attestation_challenges (
                device_id     TEXT    PRIMARY KEY,
                nonce         TEXT    NOT NULL,
                code_digests  TEXT    NOT NULL,   -- JSON {path: digest}
                code_python   TEXT    NOT NULL,
                issued_at     REAL    NOT NULL,
                expires_at    REAL    NOT NULL
            )
        """)
        # ── Tier 2 verdict state, moved OFF agent_devices (2026-08-29) ───────
        #
        # WHY IT MOVED. `ingest_challenge_response()` was one logical operation
        # spanning two owners: it read+deleted the challenge (attestation's) and
        # wrote the verdict to `agent_devices` (hw_monitor's), atomically on
        # hw_monitor's connection. That made the DELETE an out-of-namespace write
        # under ADR 0006, and every way of scoping it correctly forced a torn
        # write — record the verdict but fail to consume the challenge (leaving a
        # used nonce answerable), or consume it and lose the verdict.
        #
        # Putting the verdict in a table attestation OWNS collapses the whole
        # operation into one namespace, one connection and one transaction, so
        # there is no tear to choose between. That is the only option here with
        # no downside to trade.
        #
        # ⚠ THE OLD COLUMNS ON agent_devices ARE DELIBERATELY LEFT IN PLACE and
        # simply stop being written. Dropping them would make this migration
        # destructive for no gain: nothing in the product ever READ them
        # (verified across .py/.html/.js — the only references were the DDL, this
        # module, and tests), and every live value was the 'absent' default. They
        # are superseded, not in use; removing them is separate cleanup.
        c.execute("""
            CREATE TABLE IF NOT EXISTS attestation_tier2_state (
                device_id   TEXT PRIMARY KEY,
                state       TEXT NOT NULL DEFAULT 'absent',
                detail      TEXT,
                recorded_at TEXT
            )
        """)
        # One-time carry-over of any non-default verdict from the old columns, so
        # an install that HAD recorded state does not silently lose it. Guarded on
        # the source columns existing, since a fresh install has never had them.
        # INSERT OR IGNORE: never overwrite a value the new table already holds.
        try:
            _ad_cols = {r[1] for r in c.execute("PRAGMA table_info(agent_devices)")}
            if {"tier2_state", "tier2_detail", "tier2_at"} <= _ad_cols:
                c.execute("""
                    INSERT OR IGNORE INTO attestation_tier2_state
                        (device_id, state, detail, recorded_at)
                    SELECT device_id, tier2_state, tier2_detail, tier2_at
                      FROM agent_devices
                     WHERE tier2_state IS NOT NULL AND tier2_state != 'absent'
                """)
        except sqlite3.Error:
            # agent_devices may not exist yet on a first-run ordering; the
            # carry-over is best-effort and the table above is what matters.
            pass
        conn.commit()
    finally:
        conn.close()


def init_throttle_tables():
    """Canonical DDL for the cooperative-throttle seam (see alert_manager/throttle.py).

    Same publish-state shape as init_tier2_gate_tables: one namespace WRITES, every
    cooperating service READS (ADR 0001 read-any), no other coupling.

    `throttle_intents` holds ONE row per component describing the CURRENT intent.
    Like the tier2 gate's state row, a stored intent is a claim about a moment, not
    a fact that expires on its own -- so it carries `until_ts`, and every reader
    MUST treat now >= until_ts as NORMAL (throttle.py::_effective_factor does). If
    the executor dies mid-throttle, the intent lapses and services return to full
    speed on their own rather than staying stuck slow forever.

    `throttle_components` is the cooperating-service registry: one row per service
    that has declared itself throttle-aware, with a last-seen heartbeat and pid, so
    the executor/dashboard can tell which throttle-capable services are actually
    running and listening -- the difference between a THROTTLE that will be honoured
    and one published into the void.

    Both tables carry `actor` for the same multi-user-ready reason every other
    state-changing table here does; the Data Manager stamps it automatically.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS throttle_intents (
                component   TEXT    PRIMARY KEY,
                factor      REAL    NOT NULL,
                until_ts    REAL    NOT NULL,
                reason      TEXT,
                source      TEXT,
                updated_ts  REAL    NOT NULL,
                actor       TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS throttle_components (
                component           TEXT    PRIMARY KEY,
                last_registered_ts  REAL    NOT NULL,
                pid                 INTEGER,
                actor               TEXT
            )
        """)
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
                -- 'admin' | 'user' | 'viewonly'. Parsed by alert_manager/roles.py,
                -- which RAISES on anything else rather than defaulting -- the
                -- DEFAULT below is 'admin' only so a pre-RBAC single-user install
                -- keeps working, and a silent fallback would turn any corrupt
                -- value into a superuser. New accounts created through the user
                -- management UI get roles.DEFAULT_ROLE ('user'), not this default.
                role            TEXT NOT NULL DEFAULT 'admin',
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
                -- DEFAULT 0, NOT 1. Auto-approve is OPT-IN (ADR 0012): a token that does
                -- not say otherwise must require MANUAL approval. The column default is the
                -- last line of defence, not the live one -- the only writer (dashboard.py's
                -- `INSERT INTO enrollment_tokens`) always supplies the value explicitly. But
                -- a default of 1 means any future INSERT that merely OMITS the column grants
                -- auto-approval to every device using that token, and a default that fails
                -- OPEN on a security decision is the wrong way round regardless of who
                -- currently relies on it. Corrected 2026-08-25.
                --
                -- NEW INSTALLS ONLY. SQLite cannot ALTER a column default (verified, not
                -- assumed: ALTER TABLE ... ALTER COLUMN raises OperationalError) and this is
                -- CREATE TABLE IF NOT EXISTS, so an EXISTING database keeps DEFAULT 1 in its
                -- stored schema. Closing that means a table rebuild, not worth the risk while
                -- every writer passes the value -- which is why the suite pins BOTH this
                -- default AND the fact that the writer supplies the column.
                auto_approve     INTEGER DEFAULT 0,
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
        # Migration (ADR 0001 guarded ALTER): remote_enabled = does this installer
        # grant REMOTE (tailnet) access, and therefore consume a remote-device
        # slot? The licensing cap counts entitlement, not observation, so this is
        # where the entitlement is first recorded — the enrollment INSERT in
        # hw_monitor copies it onto agent_devices.remote_enabled.
        #
        # DEFAULT 0. Every pre-existing token becomes local-only, which is the
        # honest value: none of them were ever granted the entitlement, because
        # it did not exist. The alternative — defaulting to 1 — would silently
        # grant remote entitlement to every historic token, inventing exactly the
        # entitlements the cap exists to meter.
        if "remote_enabled" not in _cols:
            c.execute("ALTER TABLE enrollment_tokens "
                      "ADD COLUMN remote_enabled INTEGER NOT NULL DEFAULT 0")
        # Migration (ADR 0001 guarded ALTER): WHO revoked a token and WHEN.
        #
        # The `revoked` flag has been enforced since the column existed —
        # hw_monitor's claim is `WHERE token=? AND revoked=0 AND …`, so a revoked
        # token genuinely cannot be redeemed. What did not exist was any way for
        # the PRODUCT to set it: every enrollment_tokens statement in the tree was
        # an INSERT, a SELECT, or an update of `uses`/`preauth_key`. Revocation
        # therefore meant opening sqlite3 by hand, and an audit on 2026-08-29
        # found three tokens already revoked exactly that way — so the need was
        # demonstrated, not hypothetical.
        #
        # These two columns exist because the multi-user-ready rule says to leave
        # a place to record WHO for anything that records what happened. Revoking
        # an enrollment token is an admin action against a credential; "someone
        # revoked this at some point" is not an acceptable audit trail for it, and
        # retrofitting attribution later means touching every write.
        #
        # NULL on every pre-existing row, including the three revoked by hand.
        # That is the honest value — their actor genuinely was not recorded — and
        # it is deliberately distinguishable from a row this feature revoked.
        if "revoked_at" not in _cols:
            c.execute("ALTER TABLE enrollment_tokens ADD COLUMN revoked_at REAL")
        if "revoked_by" not in _cols:
            c.execute("ALTER TABLE enrollment_tokens ADD COLUMN revoked_by TEXT")

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


def init_fw_revert_tokens_table():
    """Canonical DDL for `fw_revert_tokens` — the ADR 0019 lockout-failsafe revert
    credential (Amendment 03 §4). Core-owned (unprefixed-module) per ADR 0001.

    SPLIT TOKEN, and the split is the security design, not a convenience. The
    emailed credential is `<selector>.<verifier>`. The selector is stored in the
    clear ONLY so a single row can be looked up by index; the verifier is stored
    as a SHA-256 hash and compared with `hmac.compare_digest`. Storing the whole
    token in the clear — the way `enrollment_tokens` still does, see PUNCHLIST —
    would mean anything that reads the DB (a backup, a support bundle, a copy on
    removable media) yields live, usable credentials. Hashing the verifier makes
    a stolen database useless for minting a revert.

    A plain "hash the whole token and SELECT on the hash" scheme would also work
    at rest, but it forces either a full-table scan to keep the comparison
    constant-time, or an indexed lookup on the hash that reintroduces the timing
    signal the hash was meant to remove. The selector/verifier split gives an
    indexed lookup AND a constant-time comparison at once.

    SCOPED TO ONE CHANGE. `change_id` is what makes a leaked token uninteresting:
    it can revert exactly the pending change it was minted for and nothing else,
    so it is not a general firewall-control capability that happens to be
    time-limited.

    SINGLE-USE is recorded as `used_at`/`used_from` rather than by deleting the
    row. A consumed token must stay auditable — "this token was used, at this
    time, from this address" is the record an operator needs after a lockout, and
    a deleted row cannot distinguish a spent token from one that never existed.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS fw_revert_tokens (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                selector      TEXT NOT NULL UNIQUE,
                verifier_hash TEXT NOT NULL,
                change_id     TEXT NOT NULL,
                created_at    REAL NOT NULL,
                expires_at    REAL NOT NULL,
                used_at       REAL,
                used_from     TEXT,
                created_by    TEXT NOT NULL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_fw_revert_tokens_selector "
                  "ON fw_revert_tokens(selector)")
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

def init_licensing_tables():
    """Canonical DDL for licensing: `license_state` and `license_backup_codes`.

    Core-owned and unprefixed, alongside `users` / `recovery_codes` (ADR 0001:
    modules own prefixed tables, core owns the unprefixed ones).

    ── WHY BACKUP CODES ARE A SEPARATE TABLE FROM `recovery_codes` ──────────────
    They look identical and are deliberately not shared. `recovery_codes`
    authenticates a HUMAN (`user_id`) to get back into an account.
    `license_backup_codes` authorises an INSTALL to rebind its licence to new
    hardware. Sharing one table would mean an account-recovery code could rebind
    a licence, and a licence code could unlock an account -- two different trust
    domains joined by an implementation detail. The PATTERN is copied; the rows
    are not.

    ── license_state: exactly one row, id=1 ────────────────────────────────────
    A singleton enforced by `CHECK (id = 1)` rather than by convention, so a
    second licence cannot be inserted by a bug and then silently win a
    `SELECT ... LIMIT 1`.

      install_id        the hwid stable_id computed at install (see core/install_id)
      install_signals   JSON signal_hashes, for QUORUM matching -- ordinary
                        hardware maintenance must not invalidate the licence, so
                        the individual signals are kept, not just the composite
      install_conf      'high' | 'medium' | 'low' -- a low-confidence fingerprint
                        (VM, junk SMBIOS) is recorded and NOT enforced against
      license_key       the signed key blob, verified OFFLINE (core/license_key)
      tier              cached tier from the last successful verification
      bound_at          when this install_id was bound
      rebind_count      how many times a backup code has moved this licence

    Rows are UPDATEd in place; history lives in `license_backup_codes` (which is
    append-only) and the audit log.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS license_state (
                id              INTEGER PRIMARY KEY CHECK (id = 1),
                install_id      TEXT,
                install_signals TEXT,
                install_conf    TEXT,
                license_key     TEXT,
                tier            TEXT,
                bound_at        TEXT,
                rebind_count    INTEGER NOT NULL DEFAULT 0,
                created_at      TEXT,
                updated_at      TEXT,
                updated_actor   TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS license_backup_codes (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                code_hash     TEXT NOT NULL,
                batch_id      TEXT NOT NULL,
                install_id    TEXT,
                created_at    TEXT NOT NULL,
                created_actor TEXT,
                used_at       TEXT,
                used_ip       TEXT,
                used_for_install TEXT,
                superseded_at TEXT
            )
        """)
        # Lookup is always "the live codes", so the index carries the validity
        # predicate rather than a bare column -- same shape as
        # idx_recovery_codes_live, for the same reason.
        c.execute("CREATE INDEX IF NOT EXISTS idx_license_codes_live "
                  "ON license_backup_codes(used_at, superseded_at)")
        conn.commit()
    finally:
        conn.close()


def init_email_security_tables():
    """Canonical DDL for the inbound email security gateway (ADR 0028, build-spec
    stage 2.6). Two tables, both `email_`-prefixed and MODULE-owned per ADR 0001 --
    `modules/email_security/` writes them; core only creates them here so the DDL
    lives in exactly one place like every other table in this file.

    THE PASSWORD IS DELIBERATELY NOT STORED HERE. `email_accounts.credential_ref`
    names a key in `/etc/nemesis.env` (mode 640 root:nemesis); the secret itself
    never enters `alerts.db`. Three reasons, none of them stylistic: the DB is
    backed up to removable media, where a stored app password becomes a credential
    on a drive that leaves the building; `imap_idle.py` is explicitly built to take
    credentials as constructor arguments and read no database, so storing one here
    would contradict the client that consumes it; and a Gmail app password grants
    FULL mailbox access, not scoped read -- it is not a low-value secret.

    UIDVALIDITY IS PART OF THE MESSAGE KEY, NOT DECORATION. An IMAP UID is unique
    only within one mailbox at one UIDVALIDITY. If a mailbox is deleted and
    recreated the server raises UIDVALIDITY and UIDs restart from 1, so a
    UNIQUE(account_id, uid) would silently collapse a NEW message onto an OLD
    message's verdict row -- a wrong verdict served with full confidence, which is
    strictly worse than no verdict. The uniqueness constraint therefore spans
    (account_id, uidvalidity, uid).

    SIGNALS KEEP fired AND substrate SEPARATE. `fast_check.signals()` returns each
    signal as {"fired": bool, "substrate": bool} precisely because "did not fire"
    and "could not be tested" are different facts that look identical once
    flattened to a boolean -- that distinction is what the D9 measurement campaign
    exists to preserve, and the measured false-positive rates are only meaningful
    with it intact. `signals_json` therefore stores the full per-signal structure
    verbatim. Do NOT "simplify" it to a set of boolean columns later: that would
    silently invalidate the FP rates the signal set was cleared on.

    QUARANTINE IS NOT ATOMIC ON GMAIL, AND THE SCHEMA SAYS SO. Gmail's IMAP does
    not support MOVE (verified live against the real mailbox during stage 2.2), so
    quarantine is COPY -> \\Deleted -> EXPUNGE: three round-trips that can fail
    between any two. `quarantine_state` enumerates the reachable intermediate
    states rather than pretending the operation is a boolean, because a process
    killed mid-sequence leaves the mailbox genuinely half-quarantined and a
    two-valued column could only describe that as a lie in one direction or the
    other. Reconciliation needs to know WHICH step completed.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS email_accounts (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                address        TEXT    NOT NULL,
                provider       TEXT    NOT NULL DEFAULT 'gmail',
                imap_host      TEXT    NOT NULL,
                imap_port      INTEGER NOT NULL DEFAULT 993,
                mailbox        TEXT    NOT NULL DEFAULT 'INBOX',
                -- NAME of an /etc/nemesis.env key, never the secret. See docstring.
                credential_ref TEXT    NOT NULL,
                -- Enrolment is opt-in and stays off until someone turns it on:
                -- a mailbox that begins watching itself the moment a row appears
                -- would read mail nobody consented to scan yet.
                enabled        INTEGER NOT NULL DEFAULT 0,
                created_at     TEXT    NOT NULL,
                -- ADR 0028 D11.6/D11.7 (ruled 2026-08-29). TWO DISTINCT fields,
                -- deliberately not one: under Option C the person who STARTS an
                -- enrollment and the person who AUTHORIZES it are different, and
                -- collapsing them would erase the distinction the design exists
                -- to preserve. SINGLE OWNER (D11.7): a column, NOT a join table.
                owner_user_id       INTEGER,
                enrolled_by_user_id INTEGER,
                -- Actor seam (multi-user-ready-by-default). Populated by the Data
                -- Manager's current_actor(); present now so adding attribution
                -- later is not a migration across every write path.
                created_actor  TEXT,
                last_connected_at TEXT,
                -- An explicit failure string, never a default that means something.
                -- NULL = never attempted; a value = the last real error observed.
                last_error     TEXT,
                -- WHO switched scanning on or off, and WHEN. The consent record
                -- (ADR 0028). `enabled` alone says the current state; these say
                -- who decided it. The op log cannot: it is metadata-only and
                -- records neither the mailbox nor the direction.
                enabled_actor  TEXT,
                enabled_at     TEXT,
                UNIQUE(address, mailbox)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS email_message_verdicts (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id    INTEGER NOT NULL,
                -- (uidvalidity, uid) together identify the message. See docstring.
                uidvalidity   INTEGER NOT NULL,
                uid           INTEGER NOT NULL,
                -- The RFC 5322 Message-ID header. Useful for correlation, NOT a
                -- key: it is attacker-controlled and may be absent or duplicated.
                message_id_hdr TEXT,
                received_at   TEXT,
                scanned_at    TEXT    NOT NULL,
                -- NULL until a verdict is actually reached. `fast_check` returns
                -- signals and auth facts and deliberately NO verdict, so "scanned"
                -- and "judged" are separate states and NULL is the honest value
                -- for the gap between them -- not a default 'clean'.
                verdict       TEXT,
                confidence    REAL,
                -- Human-readable WHY, and the structured evidence behind it.
                reason        TEXT,
                signals_json  TEXT,
                -- Auth facts kept as observed. NULL = not present/not evaluated,
                -- which is NOT the same as 'fail' -- a missing DMARC record and a
                -- DMARC failure are different findings.
                auth_spf      TEXT,
                auth_dkim     TEXT,
                auth_dmarc    TEXT,
                dmarc_policy  TEXT,
                auth_problems TEXT,
                -- D4 personal-baseline: a SALTED, TRUNCATED hash of the
                -- normalised sender. NOT the address -- see
                -- modules/email_security/sender_id.py for why a hash is
                -- sufficient (the baseline needs RECURRENCE, not identity)
                -- and why this is salted where sibling `name_hash` is not.
                -- NULL is normal: no salt configured, or no parseable From.
                -- NULL means "unknown", NEVER "new sender".
                sender_hash   TEXT,
                -- Reachable states of the non-atomic Gmail sequence:
                --   none        -- not quarantined, no action attempted
                --   copied      -- COPY to the quarantine label succeeded only
                --   flagged     -- COPY + \\Deleted set, EXPUNGE not yet done
                --   quarantined -- full sequence completed
                --   torn        -- a step failed mid-sequence; mailbox state is
                --                  known-inconsistent and needs reconciliation
                --   failed      -- the attempt failed with nothing applied
                quarantine_state TEXT NOT NULL DEFAULT 'none',
                quarantine_at TEXT,
                quarantine_actor TEXT,
                UNIQUE(account_id, uidvalidity, uid)
            )
        """)
        # Guarded ADD COLUMNs so existing installs gain the new fields without a
        # rebuild. Old rows keep NULL, which the baseline treats as "unknown" and
        # never as a signal -- backfill is impossible anyway, because the sender
        # was deliberately never stored.
        _emv_cols = {row[1] for row in
                     c.execute("PRAGMA table_info(email_message_verdicts)").fetchall()}
        if "sender_hash" not in _emv_cols:
            c.execute("ALTER TABLE email_message_verdicts ADD COLUMN sender_hash TEXT")
        _acct_cols = {row[1] for row in
                      c.execute("PRAGMA table_info(email_accounts)").fetchall()}
        for _col in ("owner_user_id", "enrolled_by_user_id"):
            if _col not in _acct_cols:
                c.execute("ALTER TABLE email_accounts ADD COLUMN %s INTEGER" % _col)

        # ── Enrollment requests (ADR 0028 D11.5 Option C, ruled 2026-08-29) ──
        #
        # THE TOKEN IS STORED AS A HASH, NEVER IN THE CLEAR. The plaintext exists
        # only in the code handed to the owner. A readable token column would let
        # anyone with DB access complete someone else's enrollment -- the exact
        # power Option C withholds from the admin.
        #
        # `used_at` is what makes it SINGLE-USE and `expires_at` bounds it in time;
        # both are ENFORCED in the UPDATE's WHERE clause (see
        # nemesis_fwd.op_write_email_secret -- the consume lives in the
        # PRIVILEGED HELPER, not in the web process, because the dashboard is
        # modelled as potentially compromised), not merely recorded here.
        c.execute("""
            CREATE TABLE IF NOT EXISTS email_enrollment_requests (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash     TEXT    NOT NULL UNIQUE,
                owner_user_id  INTEGER NOT NULL,
                created_by     INTEGER,
                address_hint   TEXT,
                created_at     TEXT    NOT NULL,
                expires_at     TEXT    NOT NULL,
                used_at        TEXT,
                account_id     INTEGER,
                actor          TEXT,
                disc_host      TEXT,
                disc_port      INTEGER,
                disc_tls       TEXT,
                disc_source    TEXT,
                disc_provider  TEXT,
                disc_problems  TEXT,
                disc_at        TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_email_enroll_owner "
                  "ON email_enrollment_requests(owner_user_id)")
        # ── Autodiscovery results, baked in at LINK-MINT time ────────────────
        #
        # WHY THEY ARE STORED ON THE REQUEST RATHER THAN LOOKED UP LATER, and
        # this is a security boundary rather than a caching decision:
        # autodiscovery performs outbound DNS (RFC 6186 SRV) and HTTPS (Mozilla
        # ISPDB) against a domain taken from its input. The owner-facing
        # /email/enroll pages are UNAUTHENTICATED. Running discovery there would
        # hand any anonymous caller the ability to make this appliance issue
        # lookups against a domain of their choosing, at whatever rate they like.
        # So it runs exactly once, ADMIN-SIDE, inside the authenticated
        # link-minting route, and the answer travels on the row.
        #
        # `disc_at` is not decoration: these are a point-in-time observation of
        # someone else's DNS, and a stale row must be recognisable as stale
        # rather than read as current fact.
        #
        # All NULL is a legitimate, expected state -- discovery genuinely fails
        # for most custom domains (measured: proton and the operator's own
        # domain both find nothing), which is why Tier 3 manual entry is a normal
        # path and not a rare fallback.
        _enr_cols = {row[1] for row in
                     c.execute("PRAGMA table_info(email_enrollment_requests)").fetchall()}
        for _col, _type in (("disc_host", "TEXT"), ("disc_port", "INTEGER"),
                            ("disc_tls", "TEXT"), ("disc_source", "TEXT"),
                            ("disc_provider", "TEXT"), ("disc_problems", "TEXT"),
                            ("disc_at", "TEXT")):
            if _col not in _enr_cols:
                c.execute("ALTER TABLE email_enrollment_requests "
                          "ADD COLUMN %s %s" % (_col, _type))

        # ── Credential slot sequence (ADR 0028 D11.5 Option C, 2026-08-31) ──
        #
        # Allocates the N in `EMAIL_SEC_APPPW_<N>`, the key naming this mailbox's
        # app password in /etc/nemesis-email-secrets.env.
        #
        # A SEQUENCE RATHER THAN max(existing)+1, and the difference is a real
        # bug rather than a style preference. Two household members completing
        # their enrollment links at the same moment would both read the same
        # max, both pick the same slot, and the second write would SILENTLY
        # OVERWRITE the first person's credential -- leaving a mailbox whose
        # stored password authenticates someone else's account. `next_sequence`
        # (ADR 0006) allocates with no read-modify-write window, which is the
        # same reasoning that produced the tickets_seq fix.
        #
        # NOT the account row's id: the slot must be known BEFORE the account row
        # exists, because the credential is written first and the row records
        # which slot holds it.
        #
        # Monotonic, never reused. A slot freed by a removed mailbox stays
        # retired rather than being handed to the next enrollment -- reuse would
        # mean a stale credential file entry could be inherited by a different
        # person's mailbox.
        c.execute("""
            CREATE TABLE IF NOT EXISTS email_credential_seq (
                id          INTEGER PRIMARY KEY CHECK (id = 1),
                next_number INTEGER NOT NULL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_email_verdicts_sender "
                  "ON email_message_verdicts(account_id, sender_hash)")


        # The hot read is "what has this mailbox already been judged on", asked
        # once per newly-arriving message before any scanning work is done.
        c.execute("CREATE INDEX IF NOT EXISTS idx_email_verdicts_account "
                  "ON email_message_verdicts(account_id, uidvalidity, uid)")
        # Reconciliation sweeps look for exactly the half-applied states above;
        # the index carries the predicate column rather than being a bare scan.
        c.execute("CREATE INDEX IF NOT EXISTS idx_email_verdicts_quarantine "
                  "ON email_message_verdicts(quarantine_state)")

        c.execute("""
            CREATE TABLE IF NOT EXISTS email_attachment_detonations (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                -- The message this attachment came from
                -- (email_message_verdicts.id).
                verdict_id    INTEGER NOT NULL,
                -- Content hash of the attachment bytes. NULL when the part
                -- carried no payload -- and SQLite treats NULLs as DISTINCT in a
                -- UNIQUE index, so several payload-less rows per message are
                -- allowed rather than collapsing onto one. That is correct: they
                -- are different parts, not one part recorded twice.
                attachment_sha256 TEXT,
                -- Filename HASHED, extension in the clear -- same split
                -- mime_parse makes, for the same reason: the extension is the
                -- signal, the name can carry personal information.
                name_hash     TEXT,
                extension     TEXT,
                detonated_at  TEXT    NOT NULL,
                -- ⚠ READ THE VALUES CAREFULLY. 'completed' means the sample RAN
                -- and a report was collected -- it does NOT mean clean; the
                -- verdict lives in the report. The two failure states are
                -- fundamentally different and must never be merged:
                --   completed            -- ran, observation collected
                --   isolation_unverified -- REFUSED, nothing ever executed
                --   teardown_failed      -- RAN, could not confirm the VM was
                --                           destroyed. DANGEROUS: a live VM may
                --                           still hold a running sample
                --   skipped_no_payload   -- metadata-only part, nothing to run
                --   skipped_too_large    -- above the size ceiling
                --   error                -- any other failure, detail in `error`
                -- Collapsing 'isolation_unverified' into a clean-looking outcome
                -- is precisely the "instrument that never ran, reporting an
                -- answer" shape this repo checks for.
                outcome       TEXT    NOT NULL,
                -- The sandbox's report dict, verbatim. Verdict INPUTS, not a
                -- verdict.
                report_json   TEXT,
                -- Explicit failure detail. NULL on success -- never an empty
                -- string standing in for "no error".
                error         TEXT,
                -- Actor seam (multi-user-ready-by-default), same as the sibling
                -- tables. Populated from the Data Manager's current_actor().
                actor         TEXT,
                UNIQUE(verdict_id, attachment_sha256)
            )
        """)
        # Reconciliation and review both ask "which detonations ended badly",
        # so the index carries the predicate column rather than being a scan.
        c.execute("CREATE INDEX IF NOT EXISTS idx_email_detonations_outcome "
                  "ON email_attachment_detonations(outcome)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_email_detonations_verdict "
                  "ON email_attachment_detonations(verdict_id)")

        c.execute("""
            CREATE TABLE IF NOT EXISTS email_link_detonations (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                -- The message this link came from (email_message_verdicts.id).
                verdict_id    INTEGER NOT NULL,
                -- The URL as it appeared. Stored in the CLEAR, unlike attachment
                -- filenames which are hashed -- and the asymmetry is deliberate.
                -- A filename can carry the owner's identity ("2026-tax-return-
                -- <name>.pdf") and its only signal is the extension. A URL's
                -- host, path and parameters ARE the signal, and hashing them
                -- would destroy the very thing detonation exists to examine.
                url           TEXT    NOT NULL,
                -- Split out for querying without re-parsing every row.
                host          TEXT,
                -- link_classify.side_effect_risk() at detonation time.
                -- ⚠ A RECORDED FACT, NEVER A GATE. 'low' means "nothing in the
                -- URL's shape suggests server-side state" -- NOT "safe to
                -- fetch": a 1x1 tracking pixel scores 'low' and still reports a
                -- read. Anything that filters on this column has misread it.
                side_effect_risk TEXT,
                detonated_at  TEXT    NOT NULL,
                -- ⚠ 'completed' means the URL WAS FETCHED and a report came
                -- back. It does NOT mean benign -- the verdict lives in the
                -- report, and a clean report has three indistinguishable causes
                -- (genuinely benign / the page detected the sandbox / the fetch
                -- never really happened). Only the third is eliminable, and the
                -- must-reach canary is what eliminates it. See
                -- known-limitations/link-detonation-sandbox-evasion-2026-08-26.
                --   completed          -- fetched, report collected
                --   egress_unverified  -- REFUSED, nothing was fetched
                --   skipped_scheme     -- non-http(s) target, never attempted
                --   skipped_unparseable-- no usable scheme/host
                --   error              -- fetch attempted and failed; detail in
                --                        `error`. Includes a fetcher CONTRACT
                --                        VIOLATION (returned instead of raising)
                outcome       TEXT    NOT NULL,
                -- The engine's report verbatim. Verdict INPUTS, not a verdict.
                report_json   TEXT,
                -- Explicit failure detail. NULL on success -- never an empty
                -- string standing in for "no error".
                error         TEXT,
                -- ⚠ TRUNCATION CARRIED PER ROW, deliberately. link_extract caps
                -- at 25 links/message and mime_parse at 500 URLs. A persistence
                -- layer that drops these turns a PARTIAL run into an apparently
                -- complete one -- the "silently truncated set" failure this repo
                -- checks for. A reader must be able to ask "was this message
                -- fully covered" from the rows alone.
                batch_truncated  INTEGER NOT NULL DEFAULT 0,
                batch_eligible   INTEGER,
                batch_detonated  INTEGER,
                -- Actor seam, same as the sibling tables.
                actor         TEXT,
                -- The same URL twice in one message is one detonation's worth of
                -- information; re-detonating UPDATES rather than duplicating.
                UNIQUE(verdict_id, url)
            )
        """)
        # Same predicate-carrying shape as the attachment indexes above.
        c.execute("CREATE INDEX IF NOT EXISTS idx_email_link_det_outcome "
                  "ON email_link_detonations(outcome)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_email_link_det_verdict "
                  "ON email_link_detonations(verdict_id)")

        # Guarded migrations. Both tables ship complete above, so these are no-ops
        # on a fresh install; they exist because CREATE TABLE IF NOT EXISTS will
        # NOT alter a table that already exists, and stage 2.6 may land on a DB
        # where an earlier shape was already created.
        _acct = {row[1] for row in
                 c.execute("PRAGMA table_info(email_accounts)").fetchall()}
        for _col, _decl in (("created_actor", "TEXT"),
                            ("last_connected_at", "TEXT"),
                            ("last_error", "TEXT"),
                            # ── The CONSENT record (ADR 0028, added 2026-08-31)
                            # Switching scanning on begins reading a person's
                            # mail; switching it off withdraws that. Until these
                            # existed the ONLY trace was the Data Manager op log,
                            # which is metadata-only by design -- module, table,
                            # operation, actor, rowcount, ts, and no parameters.
                            # So the durable record of "an admin began reading
                            # someone's private mail" could not say WHICH mailbox
                            # or in WHICH direction. For the one route this
                            # codebase calls a consent gate, that is the wrong
                            # thing to be unable to answer.
                            ("enabled_actor", "TEXT"),
                            ("enabled_at", "TEXT")):
            if _col not in _acct:
                c.execute("ALTER TABLE email_accounts ADD COLUMN %s %s"
                          % (_col, _decl))

        _verd = {row[1] for row in
                 c.execute("PRAGMA table_info(email_message_verdicts)").fetchall()}
        for _col, _decl in (("dmarc_policy", "TEXT"),
                            ("auth_problems", "TEXT"),
                            ("quarantine_actor", "TEXT")):
            if _col not in _verd:
                c.execute("ALTER TABLE email_message_verdicts ADD COLUMN %s %s"
                          % (_col, _decl))
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
