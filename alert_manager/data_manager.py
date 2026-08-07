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
import fcntl
import hashlib
import sqlite3
import logging
import datetime
import threading
import contextlib

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

    # EXACT table grant. This module writes exactly one table -- observed
    # leases -- and a prefix grant would let it silently acquire more as it
    # grows, including tables that do not exist yet. It notably must NOT be able to write `devices`:
    # that is core-owned (ADR 0001), and promotion of a lease hostname into the
    # inventory happens in `database.reconcile_dhcp_hostnames()` on core's own
    # connection. This grant is what makes that boundary enforced rather than
    # merely intended -- a stray `UPDATE devices` from here is refused at runtime.
    # DICT form, not a bare tuple — the distinction is load-bearing and this
    # entry originally got it wrong. `allowed()` treats a plain tuple as a list of
    # PREFIXES (`table.startswith(p)`), so `("dhcp_leases",)` silently
    # pre-authorised `dhcp_leases_archive`, `dhcp_leases_anything` — every future
    # table sharing that stem — while the comment above it claimed to be an exact
    # grant. Exact-match semantics exist ONLY in the dict form. Matches the
    # `integrity_watch` precedent, which uses it for exactly this precision.
    # `dhcp_mode_change_log` added 2026-08-07 for the mode-switch fail-over trace
    # (see modules/dhcp/module.py::switch_mode). Kept in the EXACT-MATCH dict form
    # alongside dhcp_leases rather than relaxed to a `dhcp_` prefix: the prefix
    # form would silently pre-authorise every future dhcp_* table, and this grant
    # was made exact on 2026-08-06 precisely to stop that (a bare tuple falls
    # through to startswith(), which had already pre-authorised
    # `dhcp_leases_archive` unnoticed).
    "dhcp":               {"tables": ("dhcp_leases", "dhcp_mode_change_log")},

    # An EXPLICIT table list, not an `integrity_` prefix grant, and deliberately
    # so: this module exists to cross-check agent-reported scan activity, and a
    # prefix grant would let it silently acquire new writable tables as it grows.
    # Per the note above, per-table ownership is what the prefix shorthand always
    # meant; a security-relevant module should say it outright. Adding a table
    # here is then a deliberate act, not a side effect.
    # Reads `scan_tasks` and `malware_findings` (ADR 0001 read-any); writes only
    # this. Mode is the default ENFORCE — the list is authored, not
    # static-analysis output, so it needs no WARN grace period.
    "integrity_watch":    {"tables": ("integrity_observations",)},

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
            # Track C (2026-08-07): hw_monitor is the ingest point for agent
            # connection telemetry, so it writes the events and reaps them on
            # retention. `conn_consent` is the server-side consent record it
            # must CHECK before accepting any event (Requirement 0 clause 5) and
            # UPDATE when an agent reports a consent change.
            "conn_events", "conn_consent",
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
            # `scan_tasks` ADDED 2026-08-05. Not a transcription miss like
            # `fan_status` above — a DRIFT miss, which is a different failure and
            # worth recording as such. This list was derived 2026-07-28 (c10a9d3)
            # and was correct then; `scan_tasks` did not exist until 2026-08-03
            # (d4cd2a7, ADR 0004 Stage 1 step 3), and nothing re-ran the
            # derivation when it arrived. hw_monitor owns the DDL and is the only
            # writer (dashboard and database.py never touch it); integrity_watch
            # only reads it, under ADR 0001 read-any. A column grant would not be
            # narrower here — hw_monitor INSERTs whole rows, so it needs full
            # table write. Note what that means: the :5001 process handling
            # untrusted agent payloads can write the dispatch queue. That is
            # inherent to it BEING the dispatcher, so this grant does not widen
            # its real authority — but it is the opposite of the deliberately
            # narrow enrollment_tokens column grant below, so it should not sit
            # here unremarked.
            "scan_tasks",
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
    # Both sides normalised. This lookup previously matched NEITHER — the table
    # key came in at whatever casing the SQL used, and the grant keys were used
    # verbatim — so a mis-cased table silently had no column grant, on top of
    # failing the table grant in `allowed()`. Same 2026-08-06 fix.
    if table is None:
        return None
    table = table.lower()
    cols = grants.get(table) or next(
        (v for k, v in grants.items() if k.lower() == table), None)
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


class JobLockBusy(DataManagerError):
    """Another process already holds the named job lock.

    Raised rather than returned so a caller cannot accidentally proceed by
    ignoring a falsy result — a second concurrent run must stop, not continue
    unprotected.
    """


# ── statement classification / table extraction ──────────────────────────────

_LEADING_JUNK_RE = re.compile(r"^\s*(?:--[^\n]*\n|/\*.*?\*/\s*)*", re.DOTALL)
_FIRST_WORD_RE = re.compile(r"\s*(\w+)")
_TABLE_TOKEN = r"([\"'`\[\]\w.]+)"


def _ident(token):
    """Strip quotes / brackets / schema-qualifier from a table token, LOWERCASED.

    ⚠ THE `.lower()` IS AN ACCESS-CONTROL FIX, not cosmetics. Added 2026-08-06.

    SQLite treats identifiers case-insensitively, so `INSERT INTO DHCP_LEASES` and
    `INSERT INTO dhcp_leases` are the same write to the same table. The guard did
    not agree: `allowed()` lowercased only the GRANT side and compared it against
    whatever casing the SQL happened to use, so the mis-cased form matched neither
    the exact-table set nor the `startswith` prefixes and was DENIED. Measured
    across every namespace — `dhcp`/`DHCP_LEASES`, `tickets`/`TICKETS_SEQ`,
    `malware_detection`/`MALWARE_FINDINGS`, `integrity_watch`/`INTEGRITY_OBSERVATIONS`
    all returned False, on the exact and prefix paths alike.

    It failed CLOSED — it could only refuse a legitimate write, never permit an
    illegitimate one — which is why nothing broke: no SQL in the tree is mis-cased
    today. But `namespace_mode()` defaults to MODE_ENFORCE and every namespace
    resolves to `enforce`, so this was live, not latent. The symptom would have
    been "this module cannot write its own table", naming a table plainly present
    in its own grant list — reading as a broken guard rather than a casing issue.

    NORMALISED HERE, at the single funnel every table token in `classify()` passes
    through (all seven write branches call this), rather than at each comparison
    site. That is the point: a future comparison path cannot reintroduce the bug
    by forgetting to lowercase, because the value it receives is already
    normalised. Column names are unaffected — `updated_columns()` already lowers
    them at its own append.

    Deliberate consequence: `dm_operation_log.table_name` now records the
    lowercased table. That is a small behaviour change and it is the wanted one —
    the audit log becomes queryable by a single spelling instead of silently
    splitting one table's history across casings.
    """
    if token is None:
        return None
    t = token.strip().rstrip(";").strip()
    for q in ('"', "'", "`", "[", "]"):
        t = t.replace(q, "")
    if "." in t:
        t = t.split(".")[-1]
    return t.lower() or None


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
    # Defence in depth for DIRECT callers. `_ident()` already normalises anything
    # arriving via classify(), which is every production path — but this function
    # is also called straight from tests and tooling, where the caller supplies
    # the name itself. Normalising on entry means the guarantee holds for those
    # too, instead of depending on each caller remembering. Cheap; runs once.
    table = table.lower()
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

            # archive_manifest: what each archive file WAS at the moment it was
            # written. Core-owned, written only by this class.
            #
            # The sha256 is over the COMPRESSED bytes, deliberately. gzip's own
            # CRC32 already proves a file is not internally corrupt, so hashing
            # the decompressed content would mostly duplicate it. What neither
            # gzip nor a record count can detect is a whole file being REPLACED
            # with a well-formed fabrication — same name, valid framing, wrong
            # contents. Only a digest captured at write time and compared later
            # catches that, which is the case that matters once archives hold
            # the only surviving copy of data removed from live tables.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS archive_manifest (
                    filename         TEXT PRIMARY KEY,
                    sha256           TEXT NOT NULL,
                    size_bytes       INTEGER NOT NULL,
                    record_count     INTEGER NOT NULL,
                    created_at       TEXT NOT NULL,
                    last_verified_at TEXT,
                    last_verify_ok   INTEGER
                )
            """)
            conn.commit()
        finally:
            conn.close()

    # -- shared archival primitives -------------------------------------------
    #
    # ONE implementation, used by every archive-then-modify job in the product:
    # this class's dm_operation_log coalescing and hw_monitor's top_processes
    # archival. They previously carried near-identical private copies; a second
    # copy of VERIFICATION logic is the dangerous kind of duplication, because a
    # copy that drifts weaker keeps approving moves it should refuse and the
    # failure looks exactly like success.
    #
    # These live on the Data Manager because it is the shared dependency every
    # caller already imports, and because `archive_dir` derives from the database
    # location this class owns. Note the honest boundary: ADR 0006 is about
    # mediating DB ACCESS, and the file-level helpers below touch no connection —
    # the ADR neither mandates nor forbids their placement here. They are here so
    # there is exactly one authoritative home, which is the point.

    # -- concurrency primitives ------------------------------------------------
    #
    # Two DIFFERENT hazards, deliberately two different tools. Using the wrong
    # one gives no protection at all:
    #
    #   transaction()  — read-then-act WITHIN one logical DB operation. Takes the
    #                    write lock BEFORE the read, so a concurrent caller cannot
    #                    read the same stale state and act on it too. This is the
    #                    fix for "both SELECT, both INSERT".
    #
    #   job_lock()     — a whole job running twice, including its non-DB side
    #                    effects (files, subprocesses, external API calls). A
    #                    transaction cannot help there: it cannot roll back a
    #                    written file, a sent email, or a billed API call.
    #
    # Neither existed before 2026-08-03. There was no application-level
    # serialization anywhere in the product, and SQLite's own locking only
    # prevents corruption — it does not prevent two callers acting on the same
    # state they each read a moment earlier.

    def lock_dir(self):
        """Directory holding job lockfiles, derived from the database location."""
        return os.path.join(os.path.dirname(self._db_path), "locks")

    @contextlib.contextmanager
    def job_lock(self, name, timeout=0.0):
        """Exclusive, cross-process lock for a named job.

        ``with dm.job_lock("oplog_coalesce"): ...`` — raises :class:`JobLockBusy`
        if another process holds it (immediately, or after ``timeout`` seconds
        of retrying).

        Uses ``fcntl.flock`` rather than an O_EXCL lockfile or a DB lock row,
        deliberately: the kernel releases a flock when the holding process dies,
        so a crash cannot strand a lock that then needs manual clearing. The
        other two designs both require staleness heuristics, and a staleness
        heuristic that guesses wrong either blocks a legitimate run forever or
        silently permits the double-run it exists to prevent.

        The lockfile is never deleted. Unlinking it would let a second process
        create a fresh inode and lock *that* while the first still holds the
        old one — both would believe they hold the same lock. An empty file is
        the cheapest correct thing.
        """
        d = self.lock_dir()
        os.makedirs(d, mode=0o2770, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", str(name))
        path = os.path.join(d, f"{safe}.lock")
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o660)
        deadline = time.monotonic() + max(0.0, float(timeout))
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise JobLockBusy(
                            f"job {name!r} is already running in another process",
                            kind="job_lock_busy")
                    time.sleep(0.05)
            try:
                os.ftruncate(fd, 0)
                os.write(fd, f"{os.getpid()} {time.time():.0f}\n".encode())
            except OSError:
                pass          # informational only; the lock is the flock, not the content
            yield
        finally:
            os.close(fd)      # releases the flock

    @contextlib.contextmanager
    def transaction(self, module, enforce=True):
        """A guarded connection inside an IMMEDIATE transaction.

        ``with dm.transaction("hw_monitor") as conn: ...`` — commits on clean
        exit, rolls back on any exception.

        ``BEGIN IMMEDIATE`` is the load-bearing part. SQLite's default deferred
        transaction takes the write lock at the FIRST WRITE, which is already
        too late: two callers can both complete their reads, both decide from
        identical stale state, and only then serialize on the write. IMMEDIATE
        takes it up front, so the second caller waits (up to ``busy_timeout``)
        and reads the first one's committed result.

        Use this for any read-then-act sequence — check-then-insert,
        read-modify-write counters, "if not exists" guards. It does NOT help
        with non-DB side effects; use :meth:`job_lock` for those.
        """
        conn = self.connect(module, enforce=enforce)
        conn.isolation_level = None      # explicit transaction control (lands on _raw)
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        else:
            conn.execute("COMMIT")
        finally:
            conn.close()

    # Live columns that hold an archive filename. Hardcoded rather than a
    # pluggable registry: there are exactly two, and a generic "any module can
    # register an archived table" abstraction is design work for a third case
    # that does not exist. Add a tuple here when a third appears.
    ARCHIVE_REF_COLUMNS = (
        ("hw_anomaly_snapshots", "top_processes_ref"),
        (OP_LOG_TABLE,           "archive_ref"),
    )

    def check_archive_integrity(self):
        """Verify every archive the live tables still point at.

        Answers the question a manual spot-check cannot keep answering: are the
        files that now hold the ONLY copy of data removed from live tables still
        present, and still what they were when written?

        Four outcomes per referenced file:
          ok           — present, and its sha256 matches the manifest
          unmanifested — present, but predates the manifest (no baseline to
                         compare against; not proof of a problem)
          dangling     — a live row points at a file that is not on disk
          tampered     — present, but its bytes differ from what was recorded

        Deliberately does NOT report archive files on disk that no live row
        references. Under the no-automatic-deletion principle an unreferenced
        archive is not a fault, and flagging it invites exactly the wrong kind
        of cleanup.
        """
        adir = self.archive_dir()
        report = {"status": "ok", "checked": 0, "ok": 0,
                  "dangling": [], "tampered": [], "unmanifested": []}
        conn = self._raw_connect()
        try:
            manifest = {r[0]: r[1] for r in conn.execute(
                "SELECT filename, sha256 FROM archive_manifest")}
            refs = set()
            for table, column in self.ARCHIVE_REF_COLUMNS:
                try:
                    refs.update(r[0] for r in conn.execute(
                        f"SELECT DISTINCT {column} FROM {table} "
                        f"WHERE {column} IS NOT NULL") if r[0])
                except sqlite3.Error as e:
                    # A table that does not exist yet is not an integrity
                    # failure, but it must not silently reduce coverage either.
                    log.warning("archive integrity: cannot read %s.%s: %s",
                                table, column, e)
                    report["status"] = "partial"

            now = datetime.datetime.now().isoformat(timespec="seconds")
            for fname in sorted(refs):
                report["checked"] += 1
                path = os.path.join(adir, fname)
                if not os.path.isfile(path):
                    report["dangling"].append(fname)
                    continue
                if fname not in manifest:
                    report["unmanifested"].append(fname)
                    continue
                actual = self.hash_archive(path)
                verified = actual == manifest[fname]
                conn.execute(
                    "UPDATE archive_manifest SET last_verified_at=?, last_verify_ok=? "
                    "WHERE filename=?", (now, 1 if verified else 0, fname))
                if verified:
                    report["ok"] += 1
                else:
                    report["tampered"].append(fname)
            conn.commit()
        finally:
            conn.close()

        if report["dangling"] or report["tampered"]:
            report["status"] = "error"
            log.error("archive integrity FAILED — dangling=%s tampered=%s",
                      report["dangling"], report["tampered"])
        elif report["unmanifested"] and report["status"] == "ok":
            report["status"] = "warn"
        return report

    def backfill_archive_manifest(self):
        """Record a manifest baseline for archives written before this existed.

        Baselines from CURRENT on-disk content, so it can only ever attest to
        what the file is now — it cannot retroactively prove a file was never
        altered. Legitimate here only because those two archives were
        independently verified against their live rows on 2026-08-03 (record
        counts matched, and all 125 op-log summary rows were reconstructed from
        the archive with zero mismatches) before this ran. Do not use it to
        paper over a file of unknown provenance.
        """
        adir = self.archive_dir()
        conn = self._raw_connect()
        added = []
        try:
            known = {r[0] for r in conn.execute("SELECT filename FROM archive_manifest")}
            refs = set()
            for table, column in self.ARCHIVE_REF_COLUMNS:
                try:
                    refs.update(r[0] for r in conn.execute(
                        f"SELECT DISTINCT {column} FROM {table} "
                        f"WHERE {column} IS NOT NULL") if r[0])
                except sqlite3.Error:
                    pass
            for fname in sorted(refs - known):
                path = os.path.join(adir, fname)
                if not os.path.isfile(path):
                    continue
                with gzip.open(path, "rt", encoding="utf-8") as fh:
                    count = sum(1 for line in fh if line.strip())
                conn.execute(
                    "INSERT INTO archive_manifest"
                    "(filename, sha256, size_bytes, record_count, created_at) "
                    "VALUES(?,?,?,?,?)",
                    (fname, self.hash_archive(path), os.path.getsize(path), count,
                     datetime.datetime.fromtimestamp(
                         os.path.getmtime(path)).isoformat(timespec="seconds")))
                added.append({"filename": fname, "record_count": count})
            conn.commit()
        finally:
            conn.close()
        return {"status": "ok", "backfilled": added}

    @classmethod
    def selftest_integrity_checker(cls):
        """Prove the checker can detect BOTH failure modes before trusting it.

        A checker that only ever returns "ok" is indistinguishable from a
        healthy system right up until the moment it matters. Exercises a
        known-good file, a byte-flipped one, and a deleted one.
        """
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "canary.jsonl.gz")
            cls.write_archive(p, [{"id": 1, "v": "alpha"}, {"id": 2, "v": "beta"}])
            good = cls.hash_archive(p)
            if cls.hash_archive(p) != good:
                return (False, "hash is not stable across two reads of one file")

            raw = bytearray(open(p, "rb").read())
            raw[len(raw) // 2] ^= 0xFF          # flip one byte in the middle
            open(p, "wb").write(bytes(raw))
            if cls.hash_archive(p) == good:
                return (False, "hash did NOT change after a byte was flipped")

            os.unlink(p)
            if os.path.isfile(p):
                return (False, "test file could not be removed")
        return (True, "ok")

    OP_LOG_ARCHIVE_DAYS = 7

    def archive_dir(self):
        """Archive directory for this database. Derived from the DB path rather
        than configured separately, so it always travels with the database."""
        return os.path.join(os.path.dirname(self._db_path), "archives")

    def ensure_archive_dir(self):
        """Create the archive directory if absent and correct its mode if wrong.

        0770 + setgid, group inherited from the data dir, NOT world-readable:
        archived payloads can include process listings and audit metadata.
        `makedirs(exist_ok=True)` silently ignores `mode` for an existing
        directory, so an explicit chmod is what actually fixes one created
        wrongly. It is attempted only when the mode is actually wrong — the
        directory is root-owned by convention, so a service account cannot chmod
        it, and an unconditional attempt would warn on every single run about a
        directory that is already correct.
        """
        d = self.archive_dir()
        os.makedirs(d, mode=0o2770, exist_ok=True)
        if (os.stat(d).st_mode & 0o7777) != 0o2770:
            try:
                os.chmod(d, 0o2770)
            except OSError as e:
                log.warning("archives dir has wrong mode and chmod failed (%s): %s", d, e)
        return d

    @staticmethod
    def write_archive(path, records):
        """Write `records` (iterable of dicts, each carrying an ``id``) as
        gzipped JSONL, atomically. Returns the number of records written.

        Writes to ``<path>.tmp`` and renames, so a crash mid-write cannot leave
        a truncated file sitting at the name a live DB row will point at.

        Stays a STATICMETHOD and records no manifest. That is what lets
        :meth:`selftest_verifier` use it for throwaway canary files without
        polluting ``archive_manifest`` with temp paths that will not exist a
        millisecond later. Real archives go through
        :meth:`write_archive_manifested`.
        """
        tmp = path + ".tmp"
        count = 0
        with gzip.open(tmp, "wt", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec) + "\n")
                count += 1
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o640)   # owner rw, group r, world none
        except OSError as e:
            log.warning("archive chmod failed (%s): %s", path, e)
        return count

    @staticmethod
    def hash_archive(path):
        """sha256 over the compressed file's raw bytes, streamed."""
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def write_archive_manifested(self, path, records):
        """Write an archive AND record what it was, so later tampering or loss
        is detectable. Returns the record count.

        The manifest row is written after the file is on disk, not before: a
        manifest describing a file that failed to write would be worse than no
        manifest, because it would make a never-created archive look merely
        corrupted.
        """
        count = self.write_archive(path, records)
        try:
            conn = self._raw_connect()
            conn.execute(
                "INSERT INTO archive_manifest"
                "(filename, sha256, size_bytes, record_count, created_at) "
                "VALUES(?,?,?,?,?) "
                "ON CONFLICT(filename) DO UPDATE SET "
                "  sha256=excluded.sha256, size_bytes=excluded.size_bytes, "
                "  record_count=excluded.record_count, created_at=excluded.created_at",
                (os.path.basename(path), self.hash_archive(path),
                 os.path.getsize(path), count,
                 datetime.datetime.now().isoformat(timespec="seconds")))
            conn.commit()
            conn.close()
        except Exception as e:
            # Never fail a completed archive because its bookkeeping failed. The
            # file is written and verified by the caller either way; a missing
            # manifest row surfaces later as `unmanifested`, which is a warning,
            # not data loss.
            log.warning("archive manifest write failed for %s: %s", path, e)
        return count

    @staticmethod
    def read_archive(path, value_key=None):
        """Return ``{id: payload}`` from a gzipped-JSONL archive.

        ``value_key`` selects one field as the payload (hw_monitor archives a
        single column); omit it to get the whole record (the op-log archives
        entire rows). Raises on any unreadable or malformed file — a failure
        must NEVER be mistaken for an empty archive, which would look like a
        successful move of zero rows.
        """
        out = {}
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    rec = json.loads(line)
                    out[rec["id"]] = rec if value_key is None else rec[value_key]
        return out

    @classmethod
    def verify_archive(cls, path, expected, value_key=None):
        """Prove the archive holds EXACTLY `expected` before anything is cleared
        from the live table. Returns ``(ok, reason)``.

        Compares payloads, not just ids: an archive with the right ids and the
        wrong contents would sail through an id-only check. The comparison is
        plain ``!=``, which is why one implementation serves both callers — it
        works identically for a text column and a whole row dict.
        """
        try:
            got = cls.read_archive(path, value_key)
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
    def selftest_verifier(cls):
        """Prove the verifier can FAIL before trusting it to approve a real move.

        A verifier broken so as to always return True would approve every run and
        the first symptom would be silently lost data. Exercises BOTH payload
        shapes — single-field and whole-row — because one implementation now
        serves both callers, so a canary covering only one shape would leave the
        other unproven.
        """
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            # single-field payload (hw_monitor's shape)
            p1 = os.path.join(td, "field.jsonl.gz")
            cls.write_archive(p1, [{"id": 1, "v": "alpha"}, {"id": 2, "v": "beta"}])
            good1 = {1: "alpha", 2: "beta"}
            if not cls.verify_archive(p1, good1, "v")[0]:
                return (False, "known-good single-field archive failed verification")
            if cls.verify_archive(p1, {1: "alpha", 2: "WRONG"}, "v")[0]:
                return (False, "verifier accepted mismatched single-field CONTENT")
            if cls.verify_archive(p1, {**good1, 3: "gamma"}, "v")[0]:
                return (False, "verifier accepted a MISSING row (single-field)")

            # whole-row payload (the op-log's shape)
            p2 = os.path.join(td, "rows.jsonl.gz")
            rows = [{"id": 1, "module": "m", "ts": 1.0},
                    {"id": 2, "module": "n", "ts": 2.0}]
            cls.write_archive(p2, rows)
            good2 = {r["id"]: r for r in rows}
            if not cls.verify_archive(p2, good2)[0]:
                return (False, "known-good whole-row archive failed verification")
            if cls.verify_archive(p2, {1: rows[0],
                                       2: {**rows[1], "module": "WRONG"}})[0]:
                return (False, "verifier accepted mismatched whole-row CONTENT")
            if cls.verify_archive(p2, {**good2, 3: {"id": 3}})[0]:
                return (False, "verifier accepted a MISSING row (whole-row)")

            if cls.verify_archive(os.path.join(td, "nope.gz"), good2)[0]:
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
        ok, why = self.selftest_verifier()
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

            adir = self.ensure_archive_dir()
            stamp = time.strftime("%Y-%m-%d-%H%M%S", time.localtime())
            fname = f"dm_operation_log_{stamp}.jsonl.gz"
            final = os.path.join(adir, fname)
            if os.path.exists(final):
                return {"status": "error", "error": f"archive already exists: {fname}"}

            self.write_archive_manifested(final, (dict(r) for r in rows))

            ok, why = self.verify_archive(final, expected)
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
