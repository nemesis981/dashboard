"""
Test harness for the Data Manager (ADR 0006 v1) — alert_manager/data_manager.py.

Standalone (no pytest needed): builds a DataManager against a throwaway temp DB
and exercises statement classification, access control, the atomic operations
layer (incl. a concurrent no-race proof), operation logging, and retry/error.

The classification corpus is drawn from the REAL write statements harvested from
all six module.py files (2026-07-25), so a pass proves no legitimate existing
write is wrongly denied by the guard.

Run:  python3 alert_manager/test_data_manager.py   (exit 0 = all pass)
"""

import os
import sys
import tempfile
import threading
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import data_manager as dm_mod
from data_manager import DataManager, AccessDenied, DataManagerError, classify

_failures = []


def check(cond, label):
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
    if not cond:
        _failures.append(label)


def expect_raises(exc, fn, label):
    try:
        fn()
        check(False, f"{label} (expected {exc.__name__}, none raised)")
    except exc:
        check(True, label)
    except Exception as e:  # noqa: BLE001
        check(False, f"{label} (expected {exc.__name__}, got {type(e).__name__}: {e})")


# ── 1. statement classification / table extraction ───────────────────────────
# (op, table) expected for each real / representative statement shape.
CORPUS = [
    ("INSERT OR IGNORE INTO tickets_seq (id, next_number) VALUES (1, 1)", "insert", "tickets_seq"),
    ("UPDATE tickets_seq SET next_number = next_number + 1 WHERE id=1 RETURNING next_number - 1", "update", "tickets_seq"),
    ("INSERT INTO tickets (type, body) VALUES (?, ?)", "insert", "tickets"),
    ("INSERT OR REPLACE INTO ai_settings(key, value) VALUES(?, ?)", "insert", "ai_settings"),
    ("INSERT INTO ai_rate_state(key, value) VALUES(?, '1') ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(ai_rate_state.value AS INTEGER) + 1 AS TEXT)", "insert", "ai_rate_state"),
    ("INSERT INTO ai_usage(date, hour, call_count) VALUES(?,?,1) ON CONFLICT(date, hour) DO UPDATE SET call_count = call_count + 1", "insert", "ai_usage"),
    ("INSERT OR REPLACE INTO ai_cache(cache_key, response_text, generated_at, expires_at) VALUES(?,?,?,?)", "insert", "ai_cache"),
    ("DELETE FROM community_queue WHERE id=?", "delete", "community_queue"),
    ("UPDATE community_queue SET submitted=1, actor=? WHERE id=?", "update", "community_queue"),
    ("UPDATE anomaly_incidents SET status='closed', updated_at=?, actor=? WHERE id=?", "update", "anomaly_incidents"),
    ("INSERT INTO anomaly_incidents (offending_target, score, status) VALUES (?,?,?) ON CONFLICT(offending_target) WHERE status='open' DO NOTHING", "insert", "anomaly_incidents"),
    ("INSERT OR REPLACE INTO anomaly_recurrence(metric_key, hour_of_week) VALUES(?,?)", "insert", "anomaly_recurrence"),
    ("DELETE FROM anomaly_recurrence WHERE metric_key=?", "delete", "anomaly_recurrence"),
    ("UPDATE malware_findings SET status=? WHERE id=?", "update", "malware_findings"),
    ("INSERT OR IGNORE INTO malware_scan_jobs(id, path, status) VALUES(?,?,?)", "insert", "malware_scan_jobs"),
    ("DELETE FROM malware_canary_files WHERE path=?", "delete", "malware_canary_files"),
    ("ALTER TABLE anomaly_incidents ADD COLUMN actor TEXT", "alter", "anomaly_incidents"),
    ("ALTER TABLE tickets ADD COLUMN created_by TEXT", "alter", "tickets"),
    ("CREATE TABLE IF NOT EXISTS diagnostics_settings (key TEXT PRIMARY KEY, value TEXT)", "create", "diagnostics_settings"),
    ("CREATE TABLE IF NOT EXISTS malware_findings (id INTEGER PRIMARY KEY)", "create", "malware_findings"),
    ("CREATE INDEX IF NOT EXISTS idx_cq_domain ON community_queue(domain_or_ip)", "create", "community_queue"),
    ("CREATE INDEX IF NOT EXISTS idx_mw_device ON malware_findings(device)", "create", "malware_findings"),
    ("CREATE UNIQUE INDEX IF NOT EXISTS ux_open ON anomaly_incidents(offending_target) WHERE status='open'", "create", "anomaly_incidents"),
    # reads / control — table must be None
    ("SELECT * FROM tickets WHERE id=?", "select", None),
    ("SELECT COUNT(*) FROM anomaly_incidents WHERE status='open'", "select", None),
    ("PRAGMA table_info(tickets)", "pragma", None),
    ("  \n  -- leading comment\n  UPDATE malware_findings SET status=? WHERE id=?", "update", "malware_findings"),
    ("/* block */ INSERT INTO tickets(body) VALUES(?)", "insert", "tickets"),
]


def test_classification():
    print("1. classification / table extraction")
    for sql, exp_op, exp_tbl in CORPUS:
        op, tbl = classify(sql)
        check(op == exp_op and tbl == exp_tbl,
              f"{exp_op}/{exp_tbl!s:22} <- {sql[:54]!r}"
              + ("" if (op == exp_op and tbl == exp_tbl) else f"  GOT {op}/{tbl}"))


# ── 2. access control (write-own / read-any) ─────────────────────────────────
def test_access_control(dm):
    print("2. access control")
    # own-prefix writes pass for every module against its real tables
    own = {
        "tickets": "tickets_settings", "ai_engine": "ai_usage",
        "community_queue": "community_queue", "anomaly_detection": "anomaly_state",
        "malware_detection": "malware_findings", "diagnostics": "diagnostics_status",
    }
    for module, table in own.items():
        conn = dm.connect(module)
        conn.execute(f"CREATE TABLE IF NOT EXISTS {table} (k TEXT PRIMARY KEY, v TEXT)")
        conn.commit()
        check(True, f"{module} may CREATE/own {table}")
        conn.close()

    # ADR 0023: agent_device_macs grant asserted DIRECTLY — behavioural tests build
    # tables on plain sqlite3 and never pass through this guard, so a missing grant
    # would surface only as a production WOULD-DENY with correlation silently empty.
    check(dm_mod.check_write("hw_monitor", "agent_device_macs", "insert"),
          "hw_monitor may WRITE agent_device_macs (ADR 0023 correlation)")
    check(not dm_mod.check_write("hw_monitor", "not_a_real_table", "insert"),
          "CONTROL: the grant is exact — a foreign table is refused")

    # reads across any table are allowed (read-any)
    conn = dm.connect("tickets")
    conn.execute("SELECT * FROM ai_usage")  # cross-module READ ok
    check(True, "tickets may READ ai_usage (read-any)")
    conn.close()

    # cross-prefix WRITE is denied
    conn = dm.connect("tickets")
    expect_raises(AccessDenied,
                  lambda: conn.execute("INSERT INTO ai_usage(k, v) VALUES('x','y')"),
                  "tickets may NOT write ai_usage (cross-prefix denied)")
    conn.close()

    # the audit log is never module-writable
    conn = dm.connect("ai_engine")
    expect_raises(AccessDenied,
                  lambda: conn.execute(f"INSERT INTO {dm_mod.OP_LOG_TABLE}(module) VALUES('x')"),
                  "no module may write dm_operation_log")
    conn.close()

    # unknown module namespace is rejected at connect()
    expect_raises(DataManagerError, lambda: dm.connect("not_a_module"),
                  "connect() rejects unknown module")

    # enforce=False disables the check (for controlled contexts)
    conn = dm.connect("tickets", enforce=False)
    conn.execute("CREATE TABLE IF NOT EXISTS ai_scratch (k TEXT)")
    conn.execute("INSERT INTO ai_scratch(k) VALUES('ok')")
    conn.commit()
    check(True, "enforce=False bypasses access control")
    conn.close()


# ── 3. atomic operations layer (+ concurrent no-race proof) ──────────────────
def test_atomics(dm):
    print("3. atomic operations")
    # next_sequence
    c = dm.connect("tickets")
    c.execute("CREATE TABLE IF NOT EXISTS tickets_seq (id INTEGER PRIMARY KEY CHECK (id=1), next_number INTEGER NOT NULL DEFAULT 1)")
    c.commit(); c.close()
    first = dm.next_sequence("tickets", "tickets_seq")
    second = dm.next_sequence("tickets", "tickets_seq")
    check(first == 1 and second == 2, f"next_sequence increments (got {first}, {second})")

    # increment_counter (text-value, ai_rate_state shape)
    c = dm.connect("ai_engine")
    c.execute("CREATE TABLE IF NOT EXISTS ai_rate_state (key TEXT PRIMARY KEY, value TEXT)")
    c.commit(); c.close()
    v1 = dm.increment_counter("ai_engine", "ai_rate_state", "calls", text_value=True)
    v2 = dm.increment_counter("ai_engine", "ai_rate_state", "calls", text_value=True)
    check(v1 == 1 and v2 == 2, f"increment_counter (text) counts (got {v1}, {v2})")

    # upsert: default (update non-conflict cols) then DO NOTHING
    # (distinct table name — community_queue is already created elsewhere in the suite)
    c = dm.connect("community_queue")
    c.execute("CREATE TABLE IF NOT EXISTS community_signals (id INTEGER PRIMARY KEY AUTOINCREMENT, domain_or_ip TEXT UNIQUE, hits INTEGER)")
    c.commit(); c.close()
    dm.upsert("community_queue", "community_signals", {"domain_or_ip": "a.com", "hits": 1}, ["domain_or_ip"])
    dm.upsert("community_queue", "community_signals", {"domain_or_ip": "a.com", "hits": 9}, ["domain_or_ip"])
    dm.upsert("community_queue", "community_signals", {"domain_or_ip": "a.com", "hits": 5}, ["domain_or_ip"], update=None)
    conn = dm.connect("community_queue")
    rows = conn.execute("SELECT COUNT(*), MAX(hits) FROM community_signals WHERE domain_or_ip='a.com'").fetchone()
    conn.close()
    check(rows[0] == 1 and rows[1] == 9, f"upsert dedups + conditional update (count={rows[0]}, hits={rows[1]})")

    # CONCURRENCY: N threads x M allocations => all unique + contiguous (no race)
    c = dm.connect("tickets"); c.execute("DELETE FROM tickets_seq"); c.commit(); c.close()
    N, M = 8, 25
    seen, lock = [], threading.Lock()

    def worker():
        local = [dm.next_sequence("tickets", "tickets_seq") for _ in range(M)]
        with lock:
            seen.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check(len(seen) == N * M and len(set(seen)) == N * M and sorted(seen) == list(range(1, N * M + 1)),
          f"next_sequence is race-free under {N} threads x {M} (got {len(set(seen))}/{N*M} unique)")


# ── 4. operation logging ─────────────────────────────────────────────────────
def test_logging(dm):
    print("4. operation logging")
    dm.set_actor("tester@nemesis")
    conn = dm.connect("diagnostics")
    conn.execute("CREATE TABLE IF NOT EXISTS diagnostics_status (k TEXT PRIMARY KEY, v TEXT)")
    conn.execute("INSERT OR REPLACE INTO diagnostics_status(k, v) VALUES('probe','ok')")
    conn.commit()
    # a read that must NOT be logged
    conn.execute("SELECT * FROM diagnostics_status").fetchall()
    conn.close()
    audit = dm.connect("diagnostics")
    rows = audit.execute(
        f"SELECT module, table_name, operation, actor FROM {dm_mod.OP_LOG_TABLE} "
        "WHERE table_name='diagnostics_status' AND operation IN ('insert','create') ORDER BY id"
    ).fetchall()
    reads = audit.execute(
        f"SELECT COUNT(*) FROM {dm_mod.OP_LOG_TABLE} WHERE operation='select'").fetchone()[0]
    audit.close()
    dm.clear_actor()
    check(len(rows) >= 2, f"writes logged (create+insert) — {len(rows)} rows")
    check(all(r["module"] == "diagnostics" for r in rows), "log records the module")
    check(any(r["actor"] == "tester@nemesis" for r in rows), "log applies the current actor")
    check(reads == 0, "reads are NOT logged")


# ── 6. actor on RAW passthrough writes (v1.1 gap closure) ────────────────────
def test_actor_on_raw_writes(dm):
    print("6. actor on RAW passthrough writes")
    dm.set_actor("raw-actor@nemesis")
    conn = dm.connect("malware_detection")
    conn.execute("CREATE TABLE IF NOT EXISTS malware_actortest (id INTEGER PRIMARY KEY, v TEXT)")
    conn.execute("INSERT INTO malware_actortest(id, v) VALUES(1, 'a')")   # raw INSERT
    conn.execute("UPDATE malware_actortest SET v='b' WHERE id=1")          # raw UPDATE
    conn.execute("DELETE FROM malware_actortest WHERE id=1")               # raw DELETE
    conn.commit()
    conn.close()
    audit = dm.connect("malware_detection")
    logged = {r["operation"]: r["actor"] for r in audit.execute(
        f"SELECT operation, actor FROM {dm_mod.OP_LOG_TABLE} "
        "WHERE table_name='malware_actortest' ORDER BY id").fetchall()}
    audit.close()
    for op in ("insert", "update", "delete"):
        check(logged.get(op) == "raw-actor@nemesis",
              f"raw {op.upper()} through connect() logs the actor (got {logged.get(op)!r})")

    # baseline: with no actor set, a raw write logs NULL actor
    dm.clear_actor()
    conn = dm.connect("malware_detection")
    conn.execute("INSERT INTO malware_actortest(id, v) VALUES(2, 'x')")
    conn.commit(); conn.close()
    audit = dm.connect("malware_detection")
    a = audit.execute(
        f"SELECT actor FROM {dm_mod.OP_LOG_TABLE} "
        "WHERE table_name='malware_actortest' AND operation='insert' ORDER BY id DESC LIMIT 1"
    ).fetchone()[0]
    audit.close()
    check(a is None, f"actor unset -> NULL in log (got {a!r})")


# ── 5. retry / structured error ──────────────────────────────────────────────
def test_failure(dm):
    print("5. failure handling")
    expect_raises(DataManagerError,
                  lambda: dm.next_sequence("tickets", "tickets_nonexistent_seq"),
                  "missing table -> bounded retry -> DataManagerError")
    try:
        dm.next_sequence("tickets", "tickets_nonexistent_seq")
    except DataManagerError as e:
        check(e.kind == "no_such_table" and e.module == "tickets",
              f"error carries structured context (kind={e.kind}, module={e.module})")
    # unsafe identifier rejected
    expect_raises(DataManagerError,
                  lambda: dm.next_sequence("tickets", "tickets_seq; DROP TABLE x"),
                  "unsafe identifier rejected")


# ── 6. explicit table lists + the shared-prefix collision (2026-07-28) ────────
def test_explicit_table_lists(dm):
    print("6. explicit table lists (shared prefix, disjoint ownership)")
    # Two modules sharing the `xh_` prefix but owning disjoint tables — the exact
    # hw_monitor / watchdog case a prefix grant cannot express.
    dm_mod.NAMESPACES["t_mon"] = {"tables": ("xh_metrics", "xh_notifications")}
    dm_mod.NAMESPACES["t_wat"] = {"tables": ("xh_alerts",)}
    check(dm_mod.allowed("t_mon", "xh_metrics"), "t_mon may write its own xh_metrics")
    check(dm_mod.allowed("t_wat", "xh_alerts"), "t_wat may write its own xh_alerts")
    check(not dm_mod.allowed("t_wat", "xh_metrics"),
          "t_wat may NOT write t_mon's xh_metrics (prefix grant could not express this)")
    check(not dm_mod.allowed("t_mon", "xh_alerts"),
          "t_mon may NOT write t_wat's xh_alerts")
    # prefix form still works unchanged
    check(dm_mod.allowed("tickets", "tickets_seq"), "prefix namespaces still work")


# ── 7. three-state enforcement mode ──────────────────────────────────────────
class _LogCap:
    """Capture WARNING records emitted by data_manager for assertions."""
    def __enter__(self):
        import logging
        self.recs = []
        self._h = logging.Handler()
        self._h.emit = lambda r: self.recs.append(r.getMessage())
        dm_mod.log.addHandler(self._h)
        self._lvl = dm_mod.log.level
        dm_mod.log.setLevel(logging.WARNING)
        return self
    def __exit__(self, *a):
        dm_mod.log.removeHandler(self._h)
        dm_mod.log.setLevel(self._lvl)


def test_three_state_modes(dm):
    print("7. three-state enforcement mode")
    dm_mod.NAMESPACES["t_mode"] = {"tables": ("tm_own",)}
    check(dm_mod.namespace_mode("t_mode") == dm_mod.MODE_ENFORCE, "default mode is ENFORCE")
    check(not dm_mod.check_write("t_mode", "tm_foreign", "insert"),
          "ENFORCE denies a foreign table")
    with _LogCap() as cap:
        dm_mod.set_namespace_mode("t_mode", dm_mod.MODE_WARN)
        allowed = dm_mod.check_write("t_mode", "tm_foreign", "insert")
    check(allowed, "WARN allows the foreign write through")
    check(any("WOULD DENY" in m and "tm_foreign" in m for m in cap.recs),
          "WARN logs a greppable WOULD DENY naming the table")
    with _LogCap() as cap:
        dm_mod.set_namespace_mode("t_mode", dm_mod.MODE_OFF)
        allowed = dm_mod.check_write("t_mode", "tm_foreign", "insert")
    check(allowed, "OFF allows the foreign write")
    check(not cap.recs, "OFF logs nothing (distinct from WARN)")
    dm_mod.set_namespace_mode("t_mode", dm_mod.MODE_ENFORCE)
    check(not dm_mod.check_write("t_mode", "tm_foreign", "insert"), "back to ENFORCE denies again")
    expect_raises(DataManagerError,
                  lambda: dm_mod.set_namespace_mode("t_mode", "banana"),
                  "unknown mode rejected")


# ── 8. column grants — the nemesis_fwd/users case (security-critical) ─────────
def test_column_grant(dm):
    print("8. column grants (UPDATE-only, fail-closed parsing)")
    dm_mod.NAMESPACES["t_fwd"] = {
        "tables": ("tf_audit",),
        "columns": {"tf_users": ("failed_attempts", "lockout_until", "lockout_tier")},
    }
    def allow(sql, op="update", table="tf_users"):
        return dm_mod.check_write("t_fwd", table, op, sql=sql)
    # legitimate lockout writes
    check(allow("UPDATE tf_users SET failed_attempts = failed_attempts + 1 WHERE id=?"),
          "increment of a granted column allowed")
    check(allow("UPDATE tf_users SET failed_attempts=?, lockout_until=?, lockout_tier=? WHERE id=?"),
          "all three granted columns allowed")
    check(allow("UPDATE tf_users SET failed_attempts=0, lockout_until=NULL, lockout_tier=0 WHERE id=?"),
          "reset (NULL/0) allowed")
    # privilege-escalation attempts — MUST be denied
    check(not allow("UPDATE tf_users SET password_hash='x' WHERE id=1"),
          "cannot write ungranted password_hash")
    check(not allow("UPDATE tf_users SET failed_attempts=0, password_hash='x' WHERE id=1"),
          "cannot smuggle password_hash beside a granted column")
    check(not allow("UPDATE tf_users SET role='admin' WHERE id=1"),
          "cannot write role")
    check(not dm_mod.check_write("t_fwd", "tf_users", "delete", sql="DELETE FROM tf_users WHERE id=1"),
          "grant is UPDATE-only: DELETE denied")
    check(not dm_mod.check_write("t_fwd", "tf_users", "insert",
                                 sql="INSERT INTO tf_users(id) VALUES(1)"),
          "grant is UPDATE-only: INSERT denied")
    # parser edge cases — deny when unsure
    check(allow("UPDATE tf_users SET failed_attempts = COALESCE(failed_attempts,0)+1 WHERE id=?"),
          "comma inside a function call is not a second column")
    check(not allow("UPDATE tf_users SET lockout_until='a,b', password_hash='y' WHERE id=1"),
          "comma inside a string literal does not hide a column")
    check(not allow("UPDATE tf_users SET password_hash='a=b' WHERE id=1"),
          "'=' inside a literal does not confuse the LHS")
    check(not allow("UPDATE tf_users SET failed_attempts = COALESCE(x, 0 WHERE id=1"),
          "unbalanced parens -> denied")
    check(not dm_mod.check_write("t_fwd", "tf_users", "update", sql=None),
          "no sql supplied -> denied (cannot verify => refuse)")
    # scoped to the granted table only
    check(not allow("UPDATE tf_other SET failed_attempts=1 WHERE id=1", table="tf_other"),
          "grant does not extend to another table")


# ── 9. GuardedCursor + executescript (regression: the .cursor()/script traps) ─
def test_identifier_case(dm):
    """SQLite identifiers are case-insensitive; the guard must agree.

    THE BUG (found 2026-08-06, fixed same day): `allowed()` lowercased only the
    GRANT side and compared it against whatever casing the SQL used. So
    `INSERT INTO DHCP_LEASES` — valid SQL, the module's own table — matched
    neither the exact-table set nor the prefix list, and was DENIED.

    It failed CLOSED, so nothing broke and no test caught it: every piece of SQL
    in the tree happens to be lowercase. But `namespace_mode()` defaults to
    MODE_ENFORCE, so it was live, not latent — one mis-cased statement away from
    a module being unable to write its own table, reported as a denial naming a
    table plainly present in its own grant.

    Both directions are asserted below, because a fix that lowercases everything
    unconditionally would satisfy the positives while quietly widening the
    guard — so every positive is paired with a mis-cased NEGATIVE that must still
    be refused.
    """
    print("11. identifier case-insensitivity (guard must match SQLite semantics)")
    dm_mod.NAMESPACES["t_case"] = {"tables": ("tcase_own",),
                                   "columns": {"tcase_shared": ("okcol",)}}

    # ── the extraction point normalises, so every downstream path agrees ──────
    for sql, want in (("INSERT INTO TCASE_OWN (x) VALUES (1)", "tcase_own"),
                      ("insert into tcase_own (x) values (1)", "tcase_own"),
                      ("UPDATE TCase_Own SET x=1", "tcase_own"),
                      ("DELETE FROM \"TCASE_OWN\"", "tcase_own")):
        check(classify(sql)[1] == want,
              f"classify normalises {sql[:34]!r} -> {want}")

    # ── positives: the module's own table, however it is spelled ─────────────
    for t in ("tcase_own", "TCASE_OWN", "TCase_Own"):
        check(dm_mod.allowed("t_case", t) is True, f"own table allowed as {t!r}")

    # ── NEGATIVES: the fix must not have widened anything ───────────────────
    for t in ("tcase_owned", "TCASE_OWNED", "tcase_own_archive", "TCASE_OWN_ARCHIVE",
              "alerts", "ALERTS"):
        check(dm_mod.allowed("t_case", t) is False, f"foreign/prefix-sibling refused: {t!r}")

    # The audit log is never module-writable, at any casing. Before the fix the
    # mis-cased form skipped this explicit guard entirely and fell through to
    # prefix matching — harmless only because no namespace grants that stem.
    for t in (dm_mod.OP_LOG_TABLE, dm_mod.OP_LOG_TABLE.upper()):
        check(dm_mod.allowed("t_case", t) is False, f"op-log refused as {t!r}")

    # ── column grants resolve their TABLE key case-insensitively too ─────────
    # This lookup normalised neither side before the fix.
    for t in ("tcase_shared", "TCASE_SHARED", "TCase_Shared"):
        g = dm_mod.allowed_columns("t_case", t)
        check(g == {"okcol"}, f"column grant found for table spelled {t!r} (got {g})")
    check(dm_mod.allowed_columns("t_case", "tcase_other") is None,
          "CONTROL an ungranted table still has no column grant")

    # ── end to end: check_write, the real decision point ────────────────────
    for sql in ("INSERT INTO TCASE_OWN (x) VALUES (1)",
                "insert into tcase_own (x) values (1)"):
        op, tbl = classify(sql)
        check(dm_mod.check_write("t_case", tbl, op, sql) is True,
              f"check_write allows {sql[:32]!r}")
    op, tbl = classify("INSERT INTO ALERTS (x) VALUES (1)")
    check(dm_mod.check_write("t_case", tbl, op) is False,
          "CONTROL check_write still refuses a foreign table, mis-cased")

    del dm_mod.NAMESPACES["t_case"]


def test_guarded_cursor_and_script(dm):
    print("9. GuardedCursor + executescript guarding")
    dm_mod.NAMESPACES["t_cur"] = {"tables": ("tc_own",)}
    # Create both tables OUT OF BAND (raw connection): a guarded t_cur connection
    # correctly refuses to CREATE tc_foreign, which it does not own, so the tables
    # must exist before the guarded-write assertions below.
    import sqlite3 as _sqlite3
    _raw = _sqlite3.connect(dm._db_path)
    _raw.execute("CREATE TABLE IF NOT EXISTS tc_own (x INTEGER)")
    _raw.execute("CREATE TABLE IF NOT EXISTS tc_foreign (x INTEGER)")
    _raw.commit(); _raw.close()
    conn = dm.connect("t_cur")

    cur = conn.cursor()
    check(type(cur).__name__ == "GuardedCursor", "cursor() returns a GuardedCursor, not a raw cursor")
    cur.execute("INSERT INTO tc_own VALUES (1)"); conn.commit()
    check(True, "owned write via cursor succeeds")
    expect_raises(AccessDenied,
                  lambda: conn.cursor().execute("INSERT INTO tc_foreign VALUES (1)"),
                  "foreign write via cursor DENIED (no guard bypass through .cursor())")

    # executescript on BOTH GuardedConnection and GuardedCursor must run the guard
    # (and not raise NameError — the 2026-07-28 copy/paste bug). A foreign write in
    # the script must surface as AccessDenied, proving the guard executed cleanly.
    expect_raises(AccessDenied,
                  lambda: conn.executescript("INSERT INTO tc_foreign VALUES (2);"),
                  "GuardedConnection.executescript guards a foreign write (not NameError)")
    expect_raises(AccessDenied,
                  lambda: conn.cursor().executescript("INSERT INTO tc_foreign VALUES (3);"),
                  "GuardedCursor.executescript guards a foreign write")
    # an owned-only script runs without raising
    try:
        conn.executescript("INSERT INTO tc_own VALUES (4); INSERT INTO tc_own VALUES (5);")
        check(True, "owned-only executescript runs cleanly")
    except Exception as e:  # noqa: BLE001
        check(False, f"owned-only executescript should not raise (got {type(e).__name__}: {e})")
    conn.close()


def main():
    tmp = tempfile.mkdtemp(prefix="dm_test_")
    db = os.path.join(tmp, "test.db")
    dm = DataManager(db)
    print(f"Data Manager test harness — temp db {db}\n")
    test_classification()
    test_access_control(dm)
    test_atomics(dm)
    test_logging(dm)
    test_actor_on_raw_writes(dm)
    test_failure(dm)
    test_explicit_table_lists(dm)
    test_three_state_modes(dm)
    test_column_grant(dm)
    test_guarded_cursor_and_script(dm)
    test_identifier_case(dm)
    print()
    if _failures:
        print(f"RESULT: {len(_failures)} FAILURE(S):")
        for f in _failures:
            print(f"   - {f}")
        return 1
    print("RESULT: ALL PASS")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        sys.exit(2)
