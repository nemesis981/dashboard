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
import time
import sqlite3
import logging
import threading

log = logging.getLogger("nemesis.data_manager")

# The DM's own audit table (core-owned; written by the DM directly, never by a
# module through the guard).
OP_LOG_TABLE = "dm_operation_log"

# Module -> writable table prefix(es).  ADR 0001 ownership; the unprefixed legacy
# names (`tickets`, `community_queue`) are covered because their module prefix is
# itself a prefix of the table name ("tickets" ⊑ "tickets"/"tickets_seq";
# "community" ⊑ "community_queue").  Verified 2026-07-25: every module writes only
# tables matching its own prefix — no cross-prefix writes exist.
NAMESPACES = {
    "tickets":            ("tickets",),
    "ai_engine":          ("ai_",),
    "community_queue":    ("community",),
    "anomaly_detection":  ("anomaly_",),
    "malware_detection":  ("malware_",),
    "diagnostics":        ("diagnostics_",),
}

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
    return any(table.startswith(p) for p in NAMESPACES[module])


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
            self._guard(op, table)
        cur = self._raw.execute(sql, params)
        if is_write(op):
            self._dm._log_op(self._raw, self._module, table, op, cur.rowcount)
        return cur

    def executemany(self, sql, seq_of_params):
        op, table = classify(sql)
        if is_write(op):
            self._guard(op, table)
        cur = self._raw.executemany(sql, seq_of_params)
        if is_write(op):
            self._dm._log_op(self._raw, self._module, table, op, cur.rowcount)
        return cur

    def executescript(self, script):
        stmts = _split_statements(script)
        for stmt in stmts:
            op, table = classify(stmt)
            if is_write(op):
                self._guard(op, table)
        cur = self._raw.executescript(script)
        for stmt in stmts:
            op, table = classify(stmt)
            if is_write(op):
                self._dm._log_op(self._raw, self._module, table, op, None)
        return cur

    def _guard(self, op, table):
        if not self._enforce:
            return
        if not allowed(self._module, table):
            raise AccessDenied(
                f"module {self._module!r} may not {op.upper()} table {table!r} "
                f"— write-own violation (ADR 0001/0006)",
                module=self._module, table=table, op=op, kind="access_denied")

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
            conn.commit()
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
        if not allowed(module, seq_table):
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
        if not allowed(module, table):
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
        if not allowed(module, table):
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
