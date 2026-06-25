#!/usr/bin/env python3
"""
ADR 0001 Stage 2 — consolidate the ai_engine module's tables into the shared
alerts.db. COPY ONLY: data is copied into shared ai_* tables; the source
ai_engine.db is opened READ-ONLY and left untouched, and NO reads/writes are cut
over (that is Stage 3). ai_engine only — tickets/community_queue not touched.

Quiescing note: ai_engine is manifest `required: true`, so the standard module
disable API (/api/modules/ai_engine/disable -> set_enabled(False)) refuses it by
design. Instead we quiesce by reading the source inside ONE read-only
transaction: the read-only open guarantees the source file is never modified, and
the single SHARED-lock transaction gives a consistent point-in-time snapshot while
blocking the module's writer from committing mid-copy. Same guarantee the
disable/stop() step is meant to provide (no row written mid-copy), achieved
without toggling a required module.

Run from the repo root. Safe to inspect; refuses to run if shared ai_* tables
already hold data (so it can't double-insert).
"""

import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import modules  # shared DB accessor (Stage 1)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERTS = os.path.join(REPO, "alert_manager", "alerts.db")
SRC = os.path.join(REPO, "modules", "ai_engine", "ai_engine.db")
TABLES = ["ai_settings", "ai_cache", "ai_usage", "ai_rate_state"]


def main():
    modules.set_shared_db_path(ALERTS)
    sh = modules.get_db()  # shared alerts.db via the Stage-1 accessor (WAL + busy_timeout)

    # --- guard: refuse if shared ai_* already exist with data -----------------
    present = []
    for t in TABLES:
        r = sh.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (t,)
        ).fetchone()
        if r:
            n = sh.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            present.append((t, n))
    if any(n > 0 for _, n in present):
        print(f"REFUSING: shared ai_* tables already hold data: {present}")
        sys.exit(2)
    if present:
        print(f"Note: empty shared ai_* tables already exist {present} — will reuse.")

    # --- read EXACT source schema (authoritative) -----------------------------
    src = sqlite3.connect(f"file:{SRC}?mode=ro", uri=True, timeout=10)  # READ-ONLY
    create_sql = {}
    for t in TABLES:
        row = src.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (t,)
        ).fetchone()
        if not row:
            print(f"REFUSING: source table {t} not found")
            sys.exit(2)
        create_sql[t] = row[0]

    # --- create ai_* in shared (one creator, via the accessor) ----------------
    for t in TABLES:
        sh.execute(create_sql[t])
    sh.commit()
    print("Created ai_* tables in shared alerts.db (schema copied verbatim from source).")

    # --- consistent snapshot read of source (quiesce window) ------------------
    src.execute("BEGIN")  # deferred read txn: consistent snapshot, blocks writer commit
    snapshot, colnames = {}, {}
    for t in TABLES:
        cur = src.execute(f"SELECT * FROM {t}")
        colnames[t] = [d[0] for d in cur.description]
        snapshot[t] = cur.fetchall()
    src.rollback()  # release lock; source DATA untouched (read-only anyway)
    src.close()
    print("Snapshotted source under a single read-only transaction (no mid-copy writes).")

    # --- copy rows into shared ------------------------------------------------
    for t in TABLES:
        rows = snapshot[t]
        if not rows:
            continue
        cols = colnames[t]
        ph = ",".join("?" * len(cols))
        sh.executemany(
            f"INSERT INTO {t} ({','.join(cols)}) VALUES ({ph})", rows
        )
    sh.commit()
    print("Copied rows into shared ai_* tables.\n")

    # --- VERIFY: source-vs-shared counts + ai_settings content ----------------
    src2 = sqlite3.connect(f"file:{SRC}?mode=ro", uri=True, timeout=10)
    print(f"  {'table':<16}{'SOURCE':>8}{'SHARED':>8}   match")
    all_ok = True
    for t in TABLES:
        s = src2.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        d = sh.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        ok = (s == d)
        all_ok = all_ok and ok
        print(f"  {t:<16}{s:>8}{d:>8}   {'OK' if ok else 'MISMATCH'}")

    # exact content check for the real config table
    s_set = dict(src2.execute("SELECT key,value FROM ai_settings").fetchall())
    d_set = dict(sh.execute("SELECT key,value FROM ai_settings").fetchall())
    content_ok = (s_set == d_set)
    print(f"\n  ai_settings content identical: {content_ok}")
    print(f"  ai_settings keys: {sorted(s_set.keys())}")
    src2.close()
    sh.close()

    print("\nRESULT:", "PASS — counts + config content match ✓"
          if (all_ok and content_ok) else "FAIL — see above")
    sys.exit(0 if (all_ok and content_ok) else 1)


if __name__ == "__main__":
    main()
