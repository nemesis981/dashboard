#!/usr/bin/env python3
"""
WAL concurrent-write smoke test — ADR 0001 Stage-2 prerequisite gate.

Fires writes from MANY independent processes (simulating the several services +
modules that write the shared DB at once) against the LIVE alerts.db, and counts
"database is locked" errors. With WAL + busy_timeout in effect the expected
result is ZERO lock errors.

Safety: all writes go to a throwaway table `_wal_smoketest`, created at start and
DROPped at the end. No real table is touched. Safe and idempotent to re-run.

Usage:  python3 scripts/wal_concurrent_smoketest.py [workers] [inserts_per_worker]
Default: 8 workers x 250 inserts = 2000 concurrent commits.
"""

import multiprocessing as mp
import os
import sqlite3
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(_HERE, "..", "alert_manager", "alerts.db")
TEST_TABLE = "_wal_smoketest"


def _connect():
    # Mirror the app: 5s timeout (busy_timeout=5000) + explicit pragma.
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def worker(worker_id, n_inserts, return_q):
    """Each process opens its OWN connection (like a separate service) and commits
    one row at a time to maximize write contention."""
    locked = 0
    other_err = 0
    conn = _connect()
    for i in range(n_inserts):
        try:
            conn.execute(
                f"INSERT INTO {TEST_TABLE} (worker, n, ts) VALUES (?, ?, ?)",
                (worker_id, i, time.time()),
            )
            conn.commit()
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e).lower():
                locked += 1
            else:
                other_err += 1
        except Exception:
            other_err += 1
    conn.close()
    return_q.put((worker_id, n_inserts, locked, other_err))


def main():
    workers = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    per = int(sys.argv[2]) if len(sys.argv) > 2 else 250

    # journal_mode is read from the file header — confirm we are actually in WAL.
    jm = _connect().execute("PRAGMA journal_mode").fetchone()[0]
    print(f"journal_mode in effect: {jm}")
    if jm.lower() != "wal":
        print("WARNING: DB is not in WAL mode — this test would not prove the gate.")

    # Throwaway table (idempotent).
    c = _connect()
    c.execute(f"DROP TABLE IF EXISTS {TEST_TABLE}")
    c.execute(
        f"CREATE TABLE {TEST_TABLE} "
        f"(id INTEGER PRIMARY KEY AUTOINCREMENT, worker INT, n INT, ts REAL)"
    )
    c.commit()
    c.close()

    print(f"Spawning {workers} concurrent writer processes x {per} commits each "
          f"= {workers * per} total writes, against the LIVE alerts.db")
    print("(the running services are ALSO writing concurrently — realistic load)\n")

    q = mp.Queue()
    procs = [mp.Process(target=worker, args=(w, per, q)) for w in range(workers)]
    t0 = time.time()
    for p in procs:
        p.start()
    results = [q.get() for _ in procs]
    for p in procs:
        p.join()
    dt = time.time() - t0

    total_locked = sum(r[2] for r in results)
    total_other = sum(r[3] for r in results)
    expected = workers * per

    conn = _connect()
    rows = conn.execute(f"SELECT COUNT(*) FROM {TEST_TABLE}").fetchone()[0]
    # Clean up the throwaway table.
    conn.execute(f"DROP TABLE IF EXISTS {TEST_TABLE}")
    conn.commit()
    conn.close()

    print("per-worker (worker, inserts, locked_errors, other_errors):")
    for r in sorted(results):
        print(f"  {r}")
    print()
    print(f"  rows actually written : {rows} / {expected} expected")
    print(f"  'database is locked'   : {total_locked}")
    print(f"  other errors           : {total_other}")
    print(f"  wall time              : {dt:.2f}s  "
          f"({expected/dt:.0f} commits/s across {workers} processes)")
    print()
    ok = (total_locked == 0 and total_other == 0 and rows == expected)
    print("RESULT:", "PASS — zero lock errors, all writes committed ✓"
          if ok else "FAIL — see counts above")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
