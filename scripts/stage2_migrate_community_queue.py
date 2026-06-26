#!/usr/bin/env python3
"""
ADR 0001 Stage 2 — consolidate the community_queue module's table into the shared
alerts.db. COPY ONLY: rows are copied into the shared community_queue table; the
source community_queue.db is opened READ-ONLY and left untouched, and NO
reads/writes are cut over (that is Stage 3). community_queue only — ai_engine and
tickets already migrated + cut over. This is the LAST module.

Renames: NONE. The single source table `community_queue` is already prefix-clean
(community_*); its two indexes (idx_cq_submitted, idx_cq_domain) target it and
need no rename. (Verified: source has no unprefixed/generic table names.)

Quiescing note: the community_queue manifest has NO `required` key, so set_enabled()
(modules_loader.py:69) would PERMIT a disable. But disable does not fully quiesce
writes by construction: stop() is a no-op (just logs), the Flask write routes
(_api_submit/_api_dismiss/_api_analyse) stay registered until a process restart,
and add_to_queue() is an importable module-level function. So we use the
READ-ONLY-SNAPSHOT quiesce: the source is opened mode=ro (can never be modified)
and read inside ONE deferred transaction (a consistent point-in-time snapshot that
blocks any writer commit mid-copy) — same guarantee as the ai_engine/tickets runs.

Run from the repo root. Safe to inspect; refuses to run if the shared
community_queue table already holds data (so it can't double-insert).
"""

import os
import re
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import modules  # shared DB accessor (Stage 1)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERTS = os.path.join(REPO, "alert_manager", "alerts.db")
SRC = os.path.join(REPO, "modules", "community_queue", "community_queue.db")
TABLE = "community_queue"  # no rename — already prefix-clean


def main():
    modules.set_shared_db_path(ALERTS)
    sh = modules.get_db()  # shared alerts.db via the Stage-1 accessor (WAL + busy_timeout)

    # --- guard: refuse if shared community_queue already exists WITH data -----
    r = sh.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)
    ).fetchone()
    if r:
        n = sh.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0]
        if n > 0:
            print(f"REFUSING: shared {TABLE} already holds {n} row(s).")
            sys.exit(2)
        print(f"Note: empty shared {TABLE} already exists — will reuse.")

    # --- read EXACT source schema (authoritative) ----------------------------
    src = sqlite3.connect(f"file:{SRC}?mode=ro", uri=True, timeout=10)  # READ-ONLY
    table_ddl = src.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)
    ).fetchone()
    if not table_ddl:
        print(f"REFUSING: source table {TABLE} not found")
        sys.exit(2)
    index_ddls = [
        row[0] for row in src.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL",
            (TABLE,)
        ).fetchall()
    ]

    # --- create community_queue (+indexes) in shared, via the accessor -------
    sh.execute(table_ddl[0])
    for isql in index_ddls:
        sh.execute(re.sub(r'CREATE\s+INDEX\s+', 'CREATE INDEX IF NOT EXISTS ', isql, count=1,
                          flags=re.IGNORECASE))
    sh.commit()
    print(f"Created {TABLE} (+{len(index_ddls)} indexes) in shared alerts.db "
          "(schema copied verbatim from source).")

    # --- consistent snapshot read of source (quiesce window) -----------------
    src.execute("BEGIN")  # deferred read txn: consistent snapshot, blocks writer commit
    cur = src.execute(f"SELECT * FROM {TABLE}")
    colnames = [d[0] for d in cur.description]
    rows = cur.fetchall()
    src.rollback()  # release lock; source DATA untouched (read-only anyway)
    print("Snapshotted source under a single read-only transaction (no mid-copy writes).")

    # --- copy rows into shared -----------------------------------------------
    if rows:
        ph = ",".join("?" * len(colnames))
        sh.executemany(
            f"INSERT INTO {TABLE} ({','.join(colnames)}) VALUES ({ph})", rows
        )
        sh.commit()
    print(f"Copied {len(rows)} row(s) into shared {TABLE}.\n")

    # --- VERIFY: source-vs-shared count + row-for-row content ----------------
    src2 = sqlite3.connect(f"file:{SRC}?mode=ro", uri=True, timeout=10)
    s = src2.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0]
    d = sh.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0]
    count_ok = (s == d)
    cols = ",".join(colnames)
    s_rows = src2.execute(f"SELECT {cols} FROM {TABLE} ORDER BY id").fetchall()
    d_rows = sh.execute(f"SELECT {cols} FROM {TABLE} ORDER BY id").fetchall()
    content_ok = (s_rows == d_rows)

    print(f"  {'table':<18}{'SOURCE':>8}{'SHARED':>8}   match")
    print(f"  {TABLE:<18}{s:>8}{d:>8}   {'OK' if count_ok else 'MISMATCH'}")
    print(f"\n  row-for-row identical: {content_ok}")
    print(f"  domains: {[r[colnames.index('domain_or_ip')] for r in s_rows]}")
    src2.close()
    sh.close()

    print("\nRESULT:", "PASS — count + content match ✓"
          if (count_ok and content_ok) else "FAIL — see above")
    sys.exit(0 if (count_ok and content_ok) else 1)


if __name__ == "__main__":
    main()
