"""
ADR 0006 — Data Manager (v1).

The single authoritative layer between modules and the shared ``alerts.db``.
Modules stop calling ``get_db()`` / ``sqlite3`` directly and instead route DB
access through this layer, which provides, per ADR 0006:

  * an **atomic operations** layer  (``next_sequence`` / ``increment_counter`` /
    ``upsert``) — the formal home of the v0 race-fix seed;
  * **access control** — a module may only WRITE tables in its own namespace
    (write-own / read-any, ADR 0001), enforced, not by convention;
  * an **operation log** (audit trail) — every write records module, table,
    operation, actor, rowcount, and timestamp (metadata only — never row
    values, so the log carries no PII);
  * **failure handling** — bounded retry on transient lock / missing-table,
    then a structured :class:`DataManagerError`.

Design notes
------------
* This file lives in ``alert_manager/`` (not a package); ``modules/__init__.py``
  builds and exposes the singleton so module import ergonomics don't change.
* Reads pass straight through the guarded connection (read-any). Only writes are
  access-checked and logged, so the hot read path stays cheap.
* The guard classifies each statement by its leading keyword and, for writes,
  extracts the target table with a focused regex. Writes whose table cannot be
  identified are denied (fail-closed) — the test harness
  (``test_data_manager.py``) replays every real write shape to prove no
  legitimate statement is wrongly denied.

Scope: this is **v1**. The schema gatekeeper (v2) and contributor capability /
process isolation (v3) are deliberately out of scope (see the ADR build
sequence).
"""

import re
import os
import gzip
import json
import time
import sqlite3
import logging
import threading

log = logging.getLogger("nemesis.data_manager")

# The DM's own audit table (core-owned; written by the DM directly, never by a
# module through the guard).
OP_LOG_TABLE = "dm_operation_log"

# Module -> writable tables.  ADR 0001 ownership; the unprefixed legacy names
# (`tickets`, `community_queue`) are covered because their module prefix is
# itself a prefix of the table name ("tickets" ⊑ "tickets"/"tickets_seq";
# "community" ⊑ "community_queue").  Verified 2026-07-25 for the six MODULE
# namespaces: each writes only tables matching its own prefix.
#
# A namespace value is EITHER a tuple of table-name prefixes (the original ADR
# 0001 shorthand) OR a dict with explicit ``prefixes`` and/or ``tables`` keys.
#
# WHY EXPLICIT TABLE LISTS EXIST (added 2026-07-28 for the core_module retrofit).
# Prefixes were always a shorthand for per-table ownership, and the shorthand
# breaks where two processes legitimately share one prefix. `hw_monitor` writes
# hw_metrics / hw_notifications / hw_anomaly_snapshots; `watchdog` writes
# hw_alerts / hw_alert_cooldowns. The tables are disjoint and the ownership is
# unambiguous, but a `hw_` prefix grant cannot express it — granting either
# grants both. Rather than rename live tables to fit the shorthand, the model now
# says what it always meant: ownership is per table.
NAMESPACES = {
    "tickets":            ("tickets",),
    "ai_engine":          ("ai_",),
    "community_queue":    ("community",),
    "anomaly_detection":  ("anomaly_",),
    "malware_detection":  ("malware_",),
    "diagnostics":        ("diagnostics_",),

    # ── core_module processes (retrofit, 2026-07-28) ─────────────────────────
    # Table lists derived by parsing each process's SQL with this module's own
    # classify(), so the audit and the enforcement agree by construction.
    # Both start in WARN mode — see set_namespace_mode — because the lists are
    # static-analysis output and have not yet been proven against real traffic.
    "hw_monitor": {
        "tables": (
            "hw_metrics", "hw_notifications", "hw_anomaly_snapshots",
            "scan_jobs", "scan_queue", "scan_conditions",
            "agent_devices", "correlation_events",
            # `scan_threats` / `scan_schedules` — GRANT REMOVED 2026-07-29.
            # hw_monitor never wrote a row to either; its only statements were the
            # two CREATEs, which now live in alert_manager/database.py
            # (init_scan_tables) alongside the DDL for devices, quarantines and
            # enrollment_tokens. That function runs on a raw connection, so the
            # CREATE no longer passes through this process's guard and needs no
            # grant. dashboard owns the rows (see its entry below).
            # `fan_status` was in the audit but was dropped when the list was
            # first transcribed into this registry. WARN mode surfaced it on the
            # first real run — precisely the transcription error a static list
            # cannot catch about itself.
            "fan_status",
            # `enrollment_tokens` RESOLVED 2026-07-29 and moved to a column grant
            # below — hw_monitor is the token CONSUMER, not its owner.
        ),
        # COLUMN GRANT (resolved 2026-07-29). dashboard mints tokens; hw_monitor's
        # only write to this table, ever, is `SET uses = uses + 1` at enrollment.
        # This is the network-facing process on :5001 handling untrusted agent
        # payloads, so the narrow grant is doing real work: a compromised
        # hw_monitor physically cannot mint a token, extend expires_at, raise
        # max_uses, or clear `revoked`. It can only advance a counter that its own
        # SQL already bounds (`uses < max_uses AND revoked=0 AND expires_at > ?`).
        "columns": {
            "enrollment_tokens": ("uses",),
        },
    },
    "watchdog": {
        # Disjoint from hw_monitor despite the shared `hw_` prefix — the exact
        # case explicit table lists were added for.
        "tables": ("hw_alerts", "hw_alert_cooldowns"),
    },
    "nemesis_fwd": {
        # audit_log is append-only and written by several actors; the helper adds
        # its own attribution rows there.
        #
        # quarantines (2026-07-30): INSERT + a dedup SELECT only, one row per
        # fail2ban ban (record_fail2ban_quarantine). Shared with dashboard,
        # which remains the only writer that can UPDATE status here (confirm/
        # lift, both credentialed). The helper never updates or deletes a row
        # in this table — see PEER_POLICY["fail2ban"] for why that boundary
        # matters: this grant makes fail2ban's bans visible, it does not give
        # the helper any release authority it didn't already structurally lack.
        "tables": ("audit_log", "quarantines"),
        # COLUMN GRANT. The helper enforces account lockout itself (confirmed
        # 2026-07-28), which means maintaining the three fields that make up the
        # lockout state machine. `users` belongs to authentication, and the
        # helper must never be able to touch password_hash, role, or is_active —
        # a firewall helper that can grant itself admin is not a security
        # boundary. The grant says exactly that and nothing more.
        "columns": {
            "users": ("failed_attempts", "lockout_until", "lockout_tier"),
        },
    },

    # ── dashboard (HANDOFF §9 phase 1, 2026-07-29) ───────────────────────────
    #
    # Registered in WARN mode (set from dashboard.py's startup) while its 40
    # direct sqlite3 sites migrate to this guard one at a time. Nothing is denied
    # yet.
    #
    # DELIBERATELY PARTIAL — this is the whole point of the entry. dashboard
    # writes ELEVEN tables; only the four that no other namespace claims are
    # granted here. The other seven are already granted elsewhere:
    #
    #     scan_jobs, agent_devices, enrollment_tokens,
    #     scan_threats, scan_schedules  ........ hw_monitor
    #     audit_log ............................ nemesis_fwd
    #     users ................................ nemesis_fwd (column grant)
    #
    # Granting those here as well would put two namespaces on the same tables and
    # quietly reduce write-own from an access control to a logger. They are held
    # pending an ownership decision (two of them — scan_threats/scan_schedules —
    # are already flagged as open questions in hw_monitor's entry above, and
    # enrollment_tokens carries the same caveat). WARN mode is what produces the
    # evidence for that decision: every dashboard write to one of the seven logs
    # a WOULD DENY line naming the table, without blocking anything.
    #
    # Do NOT add the seven here to "make the warnings stop". The warnings are the
    # deliverable.
    # Ownership resolutions, 2026-07-29. The DM supports MULTIPLE registered
    # writers per table where the sharing is genuine — that is an operator
    # decision, not a workaround, and it is preferred over forcing a single owner
    # with call-through forwarding.
    "dashboard": {
        "tables": (
            # sole writer
            "alerts", "devices", "login_events",
            # SHARED WRITER with nemesis_fwd (2026-07-30). dashboard confirms/
            # lifts rows here (credentialed); nemesis_fwd now also INSERTs one
            # when fail2ban bans something, so that ban shows up next to
            # alert-watcher's own auto-quarantines instead of only existing as
            # an audit_log line. Same shape as the audit_log sharing below.
            "quarantines",
            # row owner; hw_monitor holds a `uses`-only column grant (see above)
            "enrollment_tokens",
            # SOLE row writer. hw_monitor's grant on both was removed 2026-07-29
            # once its CREATEs moved to database.init_scan_tables() — it never
            # wrote a row to either, verified before the move.
            "scan_threats", "scan_schedules",
            # SHARED WRITER with hw_monitor. Symmetric: both INSERT and UPDATE the
            # same columns over the same job lifecycle, from two legitimate
            # dispatch paths (operator-initiated and agent-initiated). A column
            # grant cannot express this — dashboard needs INSERT and DELETE, and
            # column grants are UPDATE-only by design.
            "scan_jobs",
            # SHARED WRITER with nemesis_fwd. Append-only attribution log with
            # several legitimate authors.
            "audit_log",
            # FULL grant, deliberately overlapping nemesis_fwd's narrow one.
            # dashboard INSERTs accounts and maintains the SAME three lockout
            # columns nemesis_fwd maintains — one shared lockout budget across
            # both surfaces, which is the documented intent of nemesis_fwd's
            # grant. The overlap is the design, not a conflict.
            "users",
            # SOLE writer. Last-known free space per backup destination, written
            # only from api_backup_create() — the one moment the medium is
            # provably mounted (ADR 0018 keeps it unmounted otherwise). No other
            # component observes the backup medium, so no sharing is expected.
            "backup_media_status",
        ),
        # COLUMN GRANT. hw_monitor owns agent_devices rows (it INSERTs them at
        # enrollment); dashboard never inserts, and only UPDATEs these four for
        # operator actions — approve/reject and rename. UPDATE-only fits exactly.
        "columns": {
            "agent_devices": ("enrollment_status", "enrolled_by",
                              "enrolled_at", "device_name"),
        },
    },
}

# RESOLVED (2026-07-29) — `scan_threats` / `scan_schedules`.
# The decision was "dashboard owns rows, hw_monitor owns schema/DDL only". The DDL
# half is not expressible here: check_write() grants per table for EVERY write op,
# and the only narrowing mechanism — column grants — is deliberately UPDATE-only,
# so there is no way to say "CREATE but not INSERT".
#
# Rather than add a DDL-only grant type to this module (new surface in the
# access-control path, for one case), the CREATEs moved to
# alert_manager/database.py:init_scan_tables(), which already owns the DDL for
# devices, quarantines and enrollment_tokens and runs on a raw connection.
# hw_monitor's grant on both tables is therefore gone entirely — the decision is
# now enforced rather than merely documented.
#
# NOTE for the OS-lock work: this pattern depends on database.py holding a RAW
# connection. When database.py is itself migrated behind the Data Manager, DDL
# ownership needs a real answer — see the non-dashboard connection audit.

# ── namespace enforcement mode (ADR 0001 rollout seam) ───────────────────────
#
# Turning the guard on for several long-running daemons at once risks an
# AccessDenied in a process at 3am over a table nobody remembered. WARN mode
# performs the full check and logs exactly what WOULD have been denied, while
# allowing the write — so a namespace can be proven complete against real
# traffic before it is allowed to break anything.
#
# OFF is retained for the existing `enforce=False` callers and means "do not
# check at all"; it is NOT the same as WARN, which is the distinction that
# matters during a retrofit.
MODE_ENFORCE = "enforce"
MODE_WARN = "warn"
MODE_OFF = "off"

_MODES = {}


def set_namespace_mode(module, mode):
    """Set enforcement mode for one module. Default for any module is ENFORCE."""
    if mode not in (MODE_ENFORCE, MODE_WARN, MODE_OFF):
        raise DataManagerError("unknown namespace mode: %r" % (mode,), module=module)
    _MODES[module] = mode


def namespace_mode(module):
    return _MODES.get(module, MODE_ENFORCE)


def _split_top_level(text, sep=","):
    """Split on ``sep`` only at paren-depth 0 and outside quotes.

    Naive ``text.split(",")`` is wrong for SQL: ``SET a = COALESCE(x, 0), b = 1``
    splits into three pieces, and a string literal containing a comma splits into
    two. This is an access-control parser, so getting that wrong means either
    denying a legitimate write or — far worse — failing to notice a column that
    was assigned.
    """
    parts, buf, depth, quote = [], [], 0, None
    for ch in text:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"', "`"):
            quote = ch; buf.append(ch); continue
        if ch == "(":
            depth += 1; buf.append(ch); continue
        if ch == ")":
            depth -= 1; buf.append(ch); continue
        if ch == sep and depth == 0:
            parts.append("".join(buf)); buf = []; continue
        buf.append(ch)
    if quote is not None or depth != 0:
        return None                      # unbalanced — refuse to guess
    parts.append("".join(buf))
    return parts


_SET_RE = re.compile(r"\bset\b(.*?)(?:\bwhere\b|\breturning\b|$)",
                     re.IGNORECASE | re.DOTALL)


def updated_columns(sql):
    """Columns assigned by an UPDATE, or ``None`` if that cannot be determined.

    ``None`` is NOT "no columns" — it means the statement could not be parsed
    with confidence, and every caller must treat it as a denial. Fail-closed is
    the only safe reading: an unparsed assignment is an unknown write.
    """
    m = _SET_RE.search(sql)
    if not m:
        return None
    assignments = _split_top_level(m.group(1))
    if assignments is None:
        return None
    cols = []
    for a in assignments:
        if not a.strip():
            return None
        lhs = _split_top_level(a, "=")
        if lhs is None or len(lhs) < 2:
            return None                  # no assignment, or an ambiguous one
        name = _ident(lhs[0])
        if not name or not _IDENT_RE.match(name):
            return None                  # not a bare column name — refuse
        cols.append(name.lower())
    return cols or None


def allowed_columns(module, table):
    """Column-level grant for ``module`` on ``table``, or ``None`` if it has none."""
    spec = NAMESPACES.get(module)
    if not isinstance(spec, dict):
        return None
    grants = spec.get("columns") or {}
    cols = grants.get(table)
    return {c.lower() for c in cols} if cols else None


def check_write(module, table, op, sql=None):
    """THE single decision point for every write. True = the write may proceed.

    Kept as one function so enforce/warn/off can never drift between the
    GuardedConnection path and the DataManager helper methods.
    """
    mode = namespace_mode(module)
    if mode == MODE_OFF:
        return True
    if allowed(module, table):
        return True

    # ── column-level grant ───────────────────────────────────────────────────
    # A narrow, deliberate widening of ADR 0001, added 2026-07-28. Two real
    # cases drove it, both found in one audit pass: nemesis_fwd maintaining the
    # lockout state on `users`, and hw_monitor updating `enrollment_tokens`
    # created by database.py. Both are legitimate writes to a table the process
    # does not own, and both are confined to specific columns.
    #
    # Deliberately restricted to UPDATE. INSERT/DELETE/DROP affect whole rows or
    # the table itself, so "you may touch these columns" is not a meaningful
    # limit on them — granting those needs full table ownership.
    grant = allowed_columns(module, table)
    if grant is not None and op == "update":
        cols = updated_columns(sql) if sql else None
        if cols is not None and set(cols) <= grant:
            return True
        # Unparseable, or touches something outside the grant: fall through to
        # the warn/deny path below. Never assume in the caller's favour.
        log.debug("data_manager: column grant not satisfied module=%r table=%r cols=%r grant=%r",
                  module, table, cols, sorted(grant))

    if mode == MODE_WARN:
        # Deliberately WARNING, not INFO: this is a real access violation that is
        # being allowed through on purpose, and it must be greppable.
        log.warning(
            "data_manager: WOULD DENY (warn-only) module=%r op=%s table=%r "
            "— not in its namespace; add it or fix the caller before enforcing",
            module, (op or "?").upper(), table)
        return True
    return False

_WRITE_OPS = frozenset(("insert", "replace", "update", "delete", "create", "alter", "drop"))
_READ_OPS = frozenset(("select", "with", "pragma", "explain", "begin", "commit",
                       "rollback", "savepoint", "release", "vacuum", "analyze",
                       "attach", "detach"))

_RETRY_ATTEMPTS = 3
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# sentinel so upsert() can distinguish "default: update all non-conflict cols"
# from an explicit ``update=None`` (DO NOTHING).
_UPDATE_DEFAULT = object()


# ── exceptions ────────────────────────────────────────────────────────────────

class DataManagerError(RuntimeError):
    """Structured Data Manager failure."""

    def __init__(self, message, *, module=None, table=None, op=None, kind=None):
        super().__init__(message)
        self.module = module
        self.table = table
        self.op = op
        self.kind = kind   # "access_denied" | "no_such_table" | "locked" | "unknown_module" | "bad_identifier"


class AccessDenied(DataManagerError):
    """A module attempted to write a table outside its namespace."""


# ── statement classification / table extraction ──────────────────────────────

_LEADING_JUNK_RE = re.compile(r"^\s*(?:--[^\n]*\n|/\*.*?\*/\s*)*", re.DOTALL)
_FIRST_WORD_RE = re.compile(r"\s*(\w+)")
_TABLE_TOKEN = r"([\"'`\[\]\w.]+)"


def _ident(token):
    """Strip quotes / brackets / schema-qualifier from a table token."""
    if token is None:
        return None
    t = token.strip().rstrip(";").strip()
    for q in ('"', "'", "`", "[", "]"):
        t = t.replace(q, "")
    if "." in t:
        t = t.split(".")[-1]
    return t or None


def classify(sql):
    """Return ``(op, table)`` for a single SQL statement.

    ``op`` is the lowercased leading keyword; ``table`` is the target table for a
    write, or ``None`` for reads / transaction control / unidentifiable targets.
    """
    body = sql[_LEADING_JUNK_RE.match(sql).end():] if _LEADING_JUNK_RE.match(sql) else sql
    m = _FIRST_WORD_RE.match(body)
    if not m:
        return (None, None)
    kw = m.group(1).lower()
    if kw in _READ_OPS:
        return (kw, None)
    if kw not in _WRITE_OPS:
        return (kw, None)

    table = None
    if kw in ("insert", "replace"):
        mt = re.search(r"\binto\s+" + _TABLE_TOKEN, body, re.IGNORECASE)
        table = _ident(mt.group(1)) if mt else None
    elif kw == "update":
        mt = re.match(r"\s*update\s+(?:or\s+\w+\s+)?" + _TABLE_TOKEN, body, re.IGNORECASE)
        table = _ident(mt.group(1)) if mt else None
    elif kw == "delete":
        mt = re.search(r"\bfrom\s+" + _TABLE_TOKEN, body, re.IGNORECASE)
        table = _ident(mt.group(1)) if mt else None
    elif kw == "create":
        if re.match(r"\s*create\s+(?:temp\w*\s+)?table", body, re.IGNORECASE):
            mt = re.search(r"\btable\s+(?:if\s+not\s+exists\s+)?" + _TABLE_TOKEN, body, re.IGNORECASE)
            table = _ident(mt.group(1)) if mt else None
        elif re.search(r"\bindex\b", body, re.IGNORECASE):
            # CREATE [UNIQUE] INDEX <name> ON <table>(...) — the guarded object is
            # the TABLE being indexed (index names use abbreviations, not prefixes).
            mt = re.search(r"\bon\s+" + _TABLE_TOKEN, body, re.IGNORECASE)
            table = _ident(mt.group(1)) if mt else None
        else:
            table = None   # trigger / view — none exist today; fail-closed on write
    elif kw == "alter":
        mt = re.match(r"\s*alter\s+table\s+" + _TABLE_TOKEN, body, re.IGNORECASE)
        table = _ident(mt.group(1)) if mt else None
    elif kw == "drop":
        mt = re.match(r"\s*drop\s+(?:table|index|trigger|view)\s+(?:if\s+exists\s+)?" + _TABLE_TOKEN,
                      body, re.IGNORECASE)
        table = _ident(mt.group(1)) if mt else None
    return (kw, table)


def is_write(op):
    return op in _WRITE_OPS


def _split_statements(script):
    """Naive ';' split for executescript batches. Adequate for the schema-init
    scripts in this codebase (no ';' embedded in string literals or triggers)."""
    return [s for s in (part.strip() for part in script.split(";")) if s]


def allowed(module, table):
    """True if ``module`` may WRITE ``table``. Fail-closed: unknown table => denied."""
    if module not in NAMESPACES:
        raise DataManagerError(f"unknown module namespace: {module!r}",
                               module=module, kind="unknown_module")
    if table is None:
        return False                    # unidentifiable write target — fail-closed
    if table == OP_LOG_TABLE:
        return False                    # the audit log is never module-writable
    spec = NAMESPACES[module]
    if isinstance(spec, dict):
        # Exact table names are checked BEFORE prefixes: an explicit grant is the
        # precise statement of ownership, and a namespace may legitimately carry
        # tables that share no prefix with each other.
        if table in {t.lower() for t in spec.get("tables", ())}:
            return True
        return any(table.startswith(p) for p in spec.get("prefixes", ()))
    return any(table.startswith(p) for p in spec)


# ── guarded connection ────────────────────────────────────────────────────────

class GuardedConnection:
    """Proxy over a raw ``sqlite3.Connection`` scoped to one module.

    Intercepts ``execute`` / ``executemany`` / ``executescript`` to enforce
    write-own access control and log writes to the audit trail. Reads pass
    through. All other connection attributes (``commit``, ``close``, ``cursor``,
    ``row_factory`` …) delegate to the underlying connection.
    """

    def __init__(self, dm, raw, module, enforce=True):
        object.__setattr__(self, "_dm", dm)
        object.__setattr__(self, "_raw", raw)
        object.__setattr__(self, "_module", module)
        object.__setattr__(self, "_enforce", enforce)

    def execute(self, sql, params=()):
        op, table = classify(sql)
        if is_write(op):
            self._guard(op, table, sql)
        cur = self._raw.execute(sql, params)
        if is_write(op):
            self._dm._log_op(self._raw, self._module, table, op, cur.rowcount)
        return cur

    def executemany(self, sql, seq_of_params):
        op, table = classify(sql)
        if is_write(op):
            self._guard(op, table, sql)
        cur = self._raw.executemany(sql, seq_of_params)
        if is_write(op):
            self._dm._log_op(self._raw, self._module, table, op, cur.rowcount)
        return cur

    def executescript(self, script):
        stmts = _split_statements(script)
        for stmt in stmts:
            op, table = classify(stmt)
            if is_write(op):
                self._guard(op, table, stmt)
        cur = self._raw.executescript(script)
        for stmt in stmts:
            op, table = classify(stmt)
            if is_write(op):
                self._dm._log_op(self._raw, self._module, table, op, None)
        return cur

    def _guard(self, op, table, sql=None):
        if not self._enforce:
            return
        if not check_write(self._module, table, op, sql=sql):
            raise AccessDenied(
                f"module {self._module!r} may not {op.upper()} table {table!r} "
                f"— write-own violation (ADR 0001/0006)",
                module=self._module, table=table, op=op, kind="access_denied")

    def cursor(self):
        """Return a GUARDED cursor.

        Without this override, ``conn.cursor().execute("INSERT ...")`` bypasses
        access control completely: the cursor comes from the RAW connection, so
        the guard never sees the statement and the operation log never records
        it. No module used cursors when the DM was written, which is why the gap
        stayed latent — but it was always a hole, and the core_module retrofit
        walks straight into it (hw_monitor and watchdog issue most of their
        writes through cursors).
        """
        return GuardedCursor(self, self._raw.cursor())

    # delegate everything else to the raw connection
    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_raw"), name)

    def __setattr__(self, name, value):
        setattr(self._raw, name, value)

    def __enter__(self):
        self._raw.__enter__()
        return self

    def __exit__(self, *exc):
        return self._raw.__exit__(*exc)


# ── the manager ───────────────────────────────────────────────────────────────

class GuardedCursor:
    """Cursor proxy applying the same write-own check as :class:`GuardedConnection`.

    Deliberately a thin wrapper: it defers the decision to the owning guarded
    connection so the two paths can never diverge in what they allow.
    """

    def __init__(self, guarded_conn, raw_cursor):
        object.__setattr__(self, "_gc", guarded_conn)
        object.__setattr__(self, "_raw", raw_cursor)

    def execute(self, sql, params=()):
        op, table = classify(sql)
        if is_write(op):
            self._gc._guard(op, table, sql)
        cur = self._raw.execute(sql, params)
        if is_write(op):
            self._gc._dm._log_op(self._gc._raw, self._gc._module, table, op, None)
        return cur

    def executemany(self, sql, seq):
        op, table = classify(sql)
        if is_write(op):
            self._gc._guard(op, table, sql)
        cur = self._raw.executemany(sql, seq)
        if is_write(op):
            self._gc._dm._log_op(self._gc._raw, self._gc._module, table, op, None)
        return cur

    def executescript(self, script):
        for stmt in _split_statements(script):
            op, table = classify(stmt)
            if is_write(op):
                self._gc._guard(op, table, stmt)
        return self._raw.executescript(script)

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_raw"), name)

    def __iter__(self):
        return iter(self._raw)


class DataManager:
    """Singleton DB access layer. One per process, built from the shared DB path."""

    def __init__(self, db_path):
        self._db_path = db_path
        self._actor = threading.local()
        self._ensure_schema()

    # -- connections --

    def _raw_connect(self):
        """A plain connection with the same WAL/busy_timeout settings as the
        shared accessor (replicated here to avoid importing the modules package
        and creating a cycle)."""
        conn = sqlite3.connect(self._db_path, timeout=5.0)
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def connect(self, module, enforce=True):
        """Return a :class:`GuardedConnection` for ``module``. Drop-in for the old
        ``get_db()`` — the module keeps writing raw SQL, now access-checked+logged."""
        if module not in NAMESPACES:
            raise DataManagerError(f"unknown module namespace: {module!r}",
                                   module=module, kind="unknown_module")
        conn = self._raw_connect()
        conn.row_factory = sqlite3.Row
        return GuardedConnection(self, conn, module, enforce=enforce)

    # -- actor context (applied automatically by the atomic helpers) --

    def set_actor(self, actor):
        self._actor.value = actor

    def clear_actor(self):
        self._actor.value = None

    def current_actor(self):
        return getattr(self._actor, "value", None)

    # -- schema (the one new table this build introduces) --

    def _ensure_schema(self):
        conn = self._raw_connect()
        try:
            conn.execute(
                f"""CREATE TABLE IF NOT EXISTS {OP_LOG_TABLE} (
                        id         INTEGER PRIMARY KEY AUTOINCREMENT,
                        module     TEXT,
                        table_name TEXT,
                        operation  TEXT,
                        actor      TEXT,
                        rowcount   INTEGER,
                        ts         REAL NOT NULL
                    )""")
            conn.execute(f"CREATE INDEX IF NOT EXISTS idx_dmlog_ts ON {OP_LOG_TABLE}(ts)")
            conn.execute(f"CREATE INDEX IF NOT EXISTS idx_dmlog_mod ON {OP_LOG_TABLE}(module, table_name)")
            # Coalescing columns (guarded ALTER, ADR 0001 migration pattern).
            # All NULL on an ordinary per-write row, so every existing reader is
            # unaffected: a row with op_count IS NULL is exactly what it always
            # was. A coalesced summary row sets all three.
            _cols = {r[1] for r in conn.execute(
                f"PRAGMA table_info({OP_LOG_TABLE})").fetchall()}
            for _c, _d in (("op_count", "INTEGER"),
                           ("ts_last", "REAL"),
                           ("archive_ref", "TEXT")):
                if _c not in _cols:
                    conn.execute(f"ALTER TABLE {OP_LOG_TABLE} ADD COLUMN {_c} {_d}")
            conn.commit()
        finally:
            conn.close()

    # -- operation-log archival + coalescing (storage/retention piece 5) --

    OP_LOG_ARCHIVE_DAYS = 7

    def _archive_dir(self):
        return os.path.join(os.path.dirname(self._db_path), "archives")

    @staticmethod
    def _read_oplog_archive(path):
        """Return {id: row_dict} from a gzipped-JSONL archive. Raises on any
        unreadable/malformed file — a failure must never be mistaken for an
        empty archive, which would look like a successful move of zero rows."""
        out = {}
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    rec = json.loads(line)
                    out[rec["id"]] = rec
        return out

    @classmethod
    def _verify_oplog_archive(cls, path, expected):
        """Prove the archive holds EXACTLY `expected` ({id: row_dict}) before a
        single live row is removed. Compares FIELD BY FIELD, not just ids — an
        archive with the right ids and wrong contents would otherwise pass.
        Returns (ok, reason)."""
        try:
            got = cls._read_oplog_archive(path)
        except Exception as e:
            return (False, f"archive unreadable: {e}")
        if set(got) != set(expected):
            return (False, f"id mismatch (missing="
                           f"{len(set(expected) - set(got))}, "
                           f"unexpected={len(set(got) - set(expected))})")
        for k, want in expected.items():
            if got[k] != want:
                return (False, f"content mismatch at id={k}")
        return (True, "ok")

    @classmethod
    def _selftest_oplog_verifier(cls):
        """Prove the verifier can FAIL before trusting it to approve a real
        move. A verifier broken so as to always return True would approve every
        run and the first symptom would be a silently gutted audit trail."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "canary.jsonl.gz")
            good = {1: {"id": 1, "module": "m", "ts": 1.0},
                    2: {"id": 2, "module": "n", "ts": 2.0}}
            with gzip.open(p, "wt", encoding="utf-8") as fh:
                for v in good.values():
                    fh.write(json.dumps(v) + "\n")
            if not cls._verify_oplog_archive(p, good)[0]:
                return (False, "known-good archive failed verification")
            bad = {1: {"id": 1, "module": "m", "ts": 1.0},
                   2: {"id": 2, "module": "WRONG", "ts": 2.0}}
            if cls._verify_oplog_archive(p, bad)[0]:
                return (False, "verifier accepted mismatched CONTENT")
            if cls._verify_oplog_archive(p, {**good, 3: {"id": 3}})[0]:
                return (False, "verifier accepted a MISSING row")
            if cls._verify_oplog_archive(os.path.join(td, "nope.gz"), good)[0]:
                return (False, "verifier accepted an unreadable file")
        return (True, "ok")

    def archive_and_coalesce_op_log(self, cutoff_days=None, dry_run=False):
        """Archive aged automated-writer rows, then replace them with one
        summary row per (module, table, operation, hour).

        Ordering is the correctness property, exactly as in the hw_monitor
        top_processes archival: write -> atomic rename -> re-open -> compare
        field by field -> only then modify the live table. Any failure leaves
        the log exactly as it was and keeps the archive for inspection.

        Rows with a non-NULL actor are NEVER touched, at any age. Human-
        attributed writes keep per-row fidelity permanently.

        Nothing is destroyed: every archived row is recoverable in full via the
        summary row's archive_ref. The count arithmetic that matters most
        ("N inserts, 1 delete") survives in the live table without opening the
        archive at all, because op_count and rowcount are summed rather than
        discarded.
        """
        days = self.OP_LOG_ARCHIVE_DAYS if cutoff_days is None else int(cutoff_days)
        ok, why = self._selftest_oplog_verifier()
        if not ok:
            log.error("op-log coalesce ABORTED — verifier self-test failed: %s", why)
            return {"status": "error", "error": f"verifier self-test failed: {why}"}

        conn = self._raw_connect()
        conn.row_factory = sqlite3.Row
        try:
            cutoff = time.time() - days * 86400
            rows = conn.execute(
                f"SELECT * FROM {OP_LOG_TABLE} "
                "WHERE ts < ? AND actor IS NULL AND op_count IS NULL "
                "ORDER BY id", (cutoff,)).fetchall()
            if not rows:
                return {"status": "ok", "archived": 0, "summary_rows": 0, "file": None}

            expected = {r["id"]: dict(r) for r in rows}
            if dry_run:
                buckets = {(r["module"], r["table_name"], r["operation"],
                            int(r["ts"] // 3600)) for r in rows}
                return {"status": "ok", "archived": 0, "would_archive": len(rows),
                        "would_write_summary_rows": len(buckets),
                        "file": None, "dry_run": True}

            os.makedirs(self._archive_dir(), mode=0o2770, exist_ok=True)
            try:
                os.chmod(self._archive_dir(), 0o2770)
            except OSError as e:
                log.warning("archives dir chmod failed: %s", e)
            stamp = time.strftime("%Y-%m-%d-%H%M%S", time.localtime())
            fname = f"dm_operation_log_{stamp}.jsonl.gz"
            final = os.path.join(self._archive_dir(), fname)
            if os.path.exists(final):
                return {"status": "error", "error": f"archive already exists: {fname}"}
            tmp = final + ".tmp"

            with gzip.open(tmp, "wt", encoding="utf-8") as fh:
                for r in rows:
                    fh.write(json.dumps(dict(r)) + "\n")
            os.replace(tmp, final)
            try:
                os.chmod(final, 0o640)
            except OSError as e:
                log.warning("archive chmod failed: %s", e)

            ok, why = self._verify_oplog_archive(final, expected)
            if not ok:
                log.error("op-log coalesce ABORTED — %s (live rows untouched, "
                          "archive kept for inspection: %s)", why, final)
                return {"status": "error", "error": why, "file": fname}

            # Verified. Only now is it safe to modify the live table.
            buckets = {}
            for r in rows:
                key = (r["module"], r["table_name"], r["operation"],
                       int(r["ts"] // 3600))
                b = buckets.setdefault(key, {"n": 0, "rc": 0,
                                             "first": r["ts"], "last": r["ts"]})
                b["n"] += 1
                b["rc"] += (r["rowcount"] or 0)
                b["first"] = min(b["first"], r["ts"])
                b["last"] = max(b["last"], r["ts"])

            cur = conn.cursor()
            cur.executemany(f"DELETE FROM {OP_LOG_TABLE} WHERE id=?",
                            [(i,) for i in expected])
            cur.executemany(
                f"INSERT INTO {OP_LOG_TABLE}"
                "(module, table_name, operation, actor, rowcount, ts,"
                " op_count, ts_last, archive_ref) "
                "VALUES(?,?,?,NULL,?,?,?,?,?)",
                [(k[0], k[1], k[2], v["rc"], v["first"], v["n"], v["last"], fname)
                 for k, v in buckets.items()])
            conn.commit()
            log.info("op-log coalesce: archived %d rows -> %d summary rows (%s)",
                     len(expected), len(buckets), fname)
            return {"status": "ok", "archived": len(expected),
                    "summary_rows": len(buckets), "file": fname}
        finally:
            conn.close()

    def _log_op(self, raw, module, table, op, rowcount):
        """Append one audit row using the given raw connection (bypasses the guard
        — the audit log is core-owned). Metadata only: never row values (no PII).
        Must never break a real write — failures are logged and swallowed.

        The current thread-local actor (``current_actor()``) is stamped on EVERY
        logged write — atomic-helper writes AND raw ``GuardedConnection`` passthrough
        writes (INSERT/UPDATE/DELETE) — because every write path funnels through this
        one method. There is no atomic-vs-raw asymmetry: a module never needs its raw
        writes retrofitted for attribution. (v1.1 guarantee; proved by
        ``test_data_manager.test_actor_on_raw_writes``.)"""
        try:
            raw.execute(
                f"INSERT INTO {OP_LOG_TABLE}(module, table_name, operation, actor, rowcount, ts) "
                "VALUES(?,?,?,?,?,?)",
                (module, table, op, self.current_actor(), rowcount, time.time()))
        except sqlite3.Error:
            log.exception("dm_operation_log insert failed for %s.%s (%s)", module, table, op)

    # -- retry wrapper --

    def _retry(self, fn, module, table, opname, attempts=_RETRY_ATTEMPTS):
        last = None
        for i in range(attempts):
            try:
                return fn()
            except sqlite3.OperationalError as e:
                last = e
                msg = str(e).lower()
                if "locked" in msg or "no such table" in msg:
                    time.sleep(0.05 * (i + 1))
                    continue
                raise
        kind = "no_such_table" if last and "no such table" in str(last).lower() else "locked"
        raise DataManagerError(
            f"{opname} on {table!r} failed after {attempts} attempts: {last}",
            module=module, table=table, op=opname, kind=kind)

    # -- identifier safety (helpers interpolate table/column names) --

    def _check_ident(self, *names):
        for n in names:
            if not (isinstance(n, str) and _IDENT_RE.match(n)):
                raise DataManagerError(f"unsafe SQL identifier: {n!r}", kind="bad_identifier")

    # ── atomic operations layer (formal home of the v0 race-fix seed) ─────────

    def next_sequence(self, module, seq_table, column="next_number"):
        """Atomically allocate the next value from a single-row sequence table
        (``id=1``, ``<column>``). Returns the value assigned to THIS caller (the
        pre-increment value) with no read-modify-write window. Generalises the
        tickets_seq v0 fix."""
        self._check_ident(seq_table, column)
        if not check_write(module, seq_table, "update"):
            raise AccessDenied(
                f"module {module!r} may not write sequence {seq_table!r}",
                module=module, table=seq_table, op="next_sequence", kind="access_denied")

        def op():
            conn = self._raw_connect()
            try:
                conn.execute(f"INSERT OR IGNORE INTO {seq_table}(id, {column}) VALUES(1, 1)")
                row = conn.execute(
                    f"UPDATE {seq_table} SET {column} = {column} + 1 WHERE id=1 "
                    f"RETURNING {column} - 1").fetchone()
                self._log_op(conn, module, seq_table, "update", 1)
                conn.commit()
                return int(row[0])
            finally:
                conn.close()
        return self._retry(op, module, seq_table, "next_sequence")

    def increment_counter(self, module, table, key, amount=1,
                          key_col="key", val_col="value", text_value=False):
        """Atomic INSERT…ON CONFLICT DO UPDATE counter. Returns the new value.
        ``text_value=True`` stores the value as TEXT with an INTEGER cast
        (the ``ai_rate_state`` v0 shape); otherwise an INTEGER column."""
        self._check_ident(table, key_col, val_col)
        if not check_write(module, table, "insert"):
            raise AccessDenied(
                f"module {module!r} may not write counter {table!r}",
                module=module, table=table, op="increment_counter", kind="access_denied")
        if text_value:
            set_expr = f"{val_col} = CAST(CAST({table}.{val_col} AS INTEGER) + {int(amount)} AS TEXT)"
            init_val = str(int(amount))
        else:
            set_expr = f"{val_col} = {table}.{val_col} + {int(amount)}"
            init_val = int(amount)
        sql = (f"INSERT INTO {table}({key_col}, {val_col}) VALUES(?, ?) "
               f"ON CONFLICT({key_col}) DO UPDATE SET {set_expr} "
               f"RETURNING {val_col}")

        def op():
            conn = self._raw_connect()
            try:
                row = conn.execute(sql, (key, init_val)).fetchone()
                self._log_op(conn, module, table, "insert", 1)
                conn.commit()
                return int(row[0])
            finally:
                conn.close()
        return self._retry(op, module, table, "increment_counter")

    def upsert(self, module, table, data, conflict_cols, update=_UPDATE_DEFAULT):
        """Atomic INSERT…ON CONFLICT.

        ``update=None``            → DO NOTHING.
        ``update`` omitted (default) → DO UPDATE SET every non-conflict column to
                                       its excluded value.
        ``update=[cols]``          → DO UPDATE SET only those columns to excluded.

        Returns ``cursor.rowcount``. Covers the community_queue / anomaly_incidents
        upsert shapes; bespoke conditional upserts route through ``connect()``
        instead (still access-checked + logged)."""
        cols = list(data.keys())
        self._check_ident(table, *cols, *conflict_cols)
        if not check_write(module, table, "insert"):
            raise AccessDenied(
                f"module {module!r} may not write {table!r}",
                module=module, table=table, op="upsert", kind="access_denied")

        col_list = ",".join(cols)
        placeholders = ",".join("?" for _ in cols)
        conflict = ",".join(conflict_cols)
        if update is None:
            set_cols = []
        elif update is _UPDATE_DEFAULT:
            set_cols = [c for c in cols if c not in conflict_cols]
        else:
            self._check_ident(*update)
            set_cols = list(update)
        if set_cols:
            clause = "DO UPDATE SET " + ",".join(f"{c}=excluded.{c}" for c in set_cols)
        else:
            clause = "DO NOTHING"
        sql = (f"INSERT INTO {table}({col_list}) VALUES({placeholders}) "
               f"ON CONFLICT({conflict}) {clause}")

        def op():
            conn = self._raw_connect()
            try:
                cur = conn.execute(sql, tuple(data.values()))
                self._log_op(conn, module, table, "insert", cur.rowcount)
                conn.commit()
                return cur.rowcount
            finally:
                conn.close()
        return self._retry(op, module, table, "upsert")
