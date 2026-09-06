#!/usr/bin/env python3
"""enqueue_task must not self-deadlock against its own caller's transaction.

⛔ THE BUG THIS PINS, MEASURED IN PRODUCTION 2026-09-06.
    `_update_agent_device` opens a connection, writes, and does not commit until
    ~175 lines later. The queue block sits in the middle of that window, so the
    heartbeat holds SQLite's single writer slot. `enqueue_task` then opened a
    SECOND connection and tried to INSERT into scan_tasks -- which cannot
    proceed while the first transaction is open, even in WAL. It blocked for the
    full `busy_timeout` and raised `database is locked`.

    58 occurrences in the live log, first 2026-09-03 15:35:35. Every heartbeat
    burned ~10s (two 5.005s stalls, the timeout to three decimals) and queued
    NOTHING. Both `ensure_manifest_queued` and `ensure_challenge_queued` failed
    identically, which is why no attest_manifest or attest_challenge task had
    ever been created for any device.

⛔ WHY IT WAS INVISIBLE, AND WHY THAT MATTERS FOR THE TEST.
    The failure was caught and logged by the ensure_* helpers, so nothing raised
    into the beat and nothing appeared in the journal -- hw_monitor logs to a
    FILE (`LOGS_DIRECTORY`), while the attestation module propagates to stdout.
    A test is therefore the only cheap place this stays visible: assert the
    BEHAVIOUR (a row lands), never the absence of a log line.

The fix: `enqueue_task(..., conn=None)` borrows the caller's connection when one
is given. Borrowed means BORROWED -- it must not commit and must not close, or it
would end the heartbeat's transaction ~100 lines early, silently changing the
atomicity of everything after the queue block.

Run: python3 core_module/hw_monitor/test_enqueue_task_deadlock.py
"""
import os
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "alert_manager"))

_TMP = tempfile.mkdtemp(prefix="enqdl-")
os.environ["NEMESIS_DB_PATH"] = os.path.join(_TMP, "alerts.db")

import hw_monitor                                            # noqa: E402

EXPECTED_CHECKS = 17
_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


DB = os.environ["NEMESIS_DB_PATH"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT, device_id TEXT,
    action TEXT, params_json TEXT, status TEXT, created_at TEXT,
    dispatched_at TEXT, expires_at TEXT, dispatch_count INTEGER DEFAULT 0,
    actor TEXT, result_ok INTEGER, result_detail TEXT, reported_at TEXT,
    origin_queued_at TEXT, approved_envelope TEXT);
CREATE TABLE IF NOT EXISTS agent_devices (
    device_id TEXT PRIMARY KEY, device_name TEXT, attestation_state TEXT);
"""


def fresh_db():
    c = sqlite3.connect(DB)
    c.executescript(SCHEMA)
    c.execute("DELETE FROM scan_tasks")
    c.execute("INSERT OR REPLACE INTO agent_devices VALUES ('dev1','dev1','absent')")
    c.commit()
    c.close()


def holding_writer():
    """A connection with an OPEN write transaction -- the heartbeat's state at the
    moment the queue block runs. Short busy_timeout so the deadlock surfaces in
    milliseconds rather than the production 5 seconds."""
    c = sqlite3.connect(DB, timeout=0.3)
    c.execute("PRAGMA busy_timeout=300")
    c.execute("UPDATE agent_devices SET attestation_state='absent' WHERE device_id='dev1'")
    return c                                     # deliberately NOT committed


def rows():
    c = sqlite3.connect(DB)
    try:
        return c.execute("SELECT COUNT(*) FROM scan_tasks").fetchone()[0]
    finally:
        c.close()


def test_the_deadlock_reproduces_without_the_fix():
    """CONTROL FOR EVERYTHING BELOW. If a second connection can write while the
    first holds a transaction, this environment cannot express the bug and every
    other result here is meaningless."""
    print("\n[the bug: a second connection cannot write during an open transaction]")
    fresh_db()
    held = holding_writer()
    blocked = False
    try:
        c2 = sqlite3.connect(DB, timeout=0.3)
        c2.execute("PRAGMA busy_timeout=300")
        c2.execute("INSERT INTO scan_tasks (task_id, device_id, action, status, created_at) "
                   "VALUES ('x','dev1','attest_manifest','pending','now')")
        c2.commit()
        c2.close()
    except sqlite3.OperationalError as exc:
        blocked = "locked" in str(exc).lower()
    check("a SECOND connection is blocked by the held transaction", blocked,
          "no lock contention -- this environment cannot reproduce the bug")
    check("...and nothing was written", rows() == 0, "rows=%d" % rows())
    held.rollback(); held.close()


def test_enqueue_task_borrows_the_callers_connection():
    print("\n[the fix: passing conn lets the INSERT join the caller's transaction]")
    fresh_db()
    held = holding_writer()
    tid = err = None
    try:
        tid = hw_monitor.enqueue_task("dev1", "attest_manifest", {}, conn=held)
    except Exception as exc:                                  # noqa: BLE001
        err = "%s: %s" % (type(exc).__name__, exc)
    check("enqueue_task(conn=...) does not raise", err is None, "raised %s" % err)
    check("...and returns a task_id", bool(tid), "got %r" % tid)

    # Visible on the caller's own connection BEFORE commit: it is in that transaction.
    seen = held.execute("SELECT COUNT(*) FROM scan_tasks").fetchone()[0]
    check("the row is visible inside the caller's transaction", seen == 1, "seen=%d" % seen)

    # ⛔ BORROWED MEANS BORROWED. If enqueue_task committed, the row would already
    # be durable here -- and the heartbeat's transaction would have ended ~100
    # lines early, changing the atomicity of everything after the queue block.
    check("enqueue_task did NOT commit the borrowed connection", rows() == 0,
          "committed early -- rows visible externally=%d" % rows())

    held.commit()
    check("...and after the CALLER commits, the row is durable", rows() == 1,
          "rows=%d" % rows())
    # It must not have closed it either.
    still_open = True
    try:
        held.execute("SELECT 1")
    except Exception:                                         # noqa: BLE001
        still_open = False
    check("enqueue_task did NOT close the borrowed connection", still_open)
    held.close()


def test_without_conn_it_still_opens_its_own():
    """Backward compatibility. Six callers pass no conn and must keep working
    exactly as before -- own connection, own commit, durable immediately."""
    print("\n[unchanged behaviour for the 6 existing callers]")
    fresh_db()
    tid = hw_monitor.enqueue_task("dev1", "notify", {"a": 1})
    check("returns a task_id with no conn given", bool(tid))
    check("...and commits on its own (durable immediately)", rows() == 1,
          "rows=%d" % rows())
    c = sqlite3.connect(DB)
    action = c.execute("SELECT action FROM scan_tasks").fetchone()[0]
    c.close()
    check("...and wrote the right action", action == "notify", "got %r" % action)


def test_the_heartbeat_shaped_case_end_to_end():
    """The real shape: an open heartbeat transaction, then BOTH queue helpers,
    then one commit. Before the fix each helper burned busy_timeout and queued
    nothing; both must now land in the same transaction."""
    print("\n[the production shape: held transaction -> both helpers -> one commit]")
    fresh_db()
    held = holding_writer()
    hw_monitor.enqueue_task("dev1", "attest_manifest", {}, conn=held)
    hw_monitor.enqueue_task("dev1", "attest_challenge", {}, conn=held)
    check("nothing durable before the caller commits", rows() == 0, "rows=%d" % rows())
    held.commit()
    check("both tasks land after one commit", rows() == 2, "rows=%d" % rows())
    c = sqlite3.connect(DB)
    got = sorted(r[0] for r in c.execute("SELECT action FROM scan_tasks").fetchall())
    c.close()
    check("...and they are the two attest actions",
          got == ["attest_challenge", "attest_manifest"], "got %r" % got)
    held.close()


def test_the_ENSURE_helpers_thread_conn_through():
    """⛔ THE WIRING, NOT JUST THE FUNCTION. The production bug lived as much in the
    CALL SITES as in enqueue_task: a fixed enqueue_task that the helpers still call
    without `conn` deadlocks exactly as before. Testing enqueue_task alone would
    pass against that broken state, so the helpers are exercised against a HELD
    transaction here -- the real shape."""
    print("\n[ensure_manifest_queued must pass the heartbeat's conn through]")
    fresh_db()
    held = holding_writer()
    tid = err = None
    try:
        tid = hw_monitor.ensure_manifest_queued(held, "dev1")
    except Exception as exc:                                  # noqa: BLE001
        err = "%s: %s" % (type(exc).__name__, exc)
    # ensure_* swallow their own errors by contract, so a silent None IS the
    # failure signature -- assert the task, never the absence of an exception.
    check("ensure_manifest_queued returned a task id, not a swallowed None",
          bool(tid), "returned %r (err=%s) -- this is the original bug's signature"
          % (tid, err))
    seen = held.execute(
        "SELECT COUNT(*) FROM scan_tasks WHERE action='attest_manifest'").fetchone()[0]
    check("...and the row is in the caller's transaction", seen == 1, "seen=%d" % seen)
    held.commit()
    check("...durable after the caller commits", rows() == 1, "rows=%d" % rows())
    held.close()


if __name__ == "__main__":
    print("=" * 70)
    for fn in (test_the_deadlock_reproduces_without_the_fix,
               test_enqueue_task_borrows_the_callers_connection,
               test_without_conn_it_still_opens_its_own,
               test_the_heartbeat_shaped_case_end_to_end,
               test_the_ENSURE_helpers_thread_conn_through):
        fn()
    print("\n" + "=" * 70)
    ran = _pass + _fail
    print("checks: %d passed, %d failed (%d run)" % (_pass, _fail, ran))
    if ran != EXPECTED_CHECKS:
        print("EXPECTED_CHECKS MISMATCH: declared %d, ran %d" % (EXPECTED_CHECKS, ran))
        sys.exit(1)
    sys.exit(1 if _fail else 0)
