#!/usr/bin/env python3
"""
ADR 0001 Stage 2 — consolidate the tickets module's tables into the shared
alerts.db. COPY ONLY: rows are copied into shared tickets_* tables; the source
tickets.db is opened READ-ONLY and left untouched, and NO reads/writes are cut
over (that is Stage 3). tickets only — ai_engine already done; community_queue
not touched.

Renames (the new wrinkle vs ai_engine — tickets uses unprefixed generic names
that would collide in the shared DB):
    tickets      -> tickets          (already prefixed-by-name; keep)
    ticket_seq   -> tickets_seq
    settings     -> tickets_settings

Quiescing note: the tickets manifest has NO `required` key, so set_enabled()
(modules_loader.py:69) would PERMIT a disable. But disable does not actually
quiesce tickets' writes here: requires_background_service is false and stop()
is a no-op (just logs), its Flask routes stay registered until a process restart
(dashboard.py:2233), and add_note()/open_ticket() are importable module-level
functions other code paths call (auto_ticket_on_alert). So we use the same
READ-ONLY-SNAPSHOT quiesce as the ai_engine run: the source is opened mode=ro
(can never be modified) and read inside ONE deferred transaction (a consistent
point-in-time snapshot that blocks any writer commit mid-copy). This gives the
by-construction "no row written mid-copy" guarantee disable was meant to give,
without depending on a running dashboard.

Run from the repo root. Safe to inspect; refuses to run if shared tickets_*
tables already hold data (so it can't double-insert).
"""

import os
import re
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import modules  # shared DB accessor (Stage 1)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERTS = os.path.join(REPO, "alert_manager", "alerts.db")
SRC = os.path.join(REPO, "modules", "tickets", "tickets.db")

# source table -> shared (renamed) table
RENAME = {
    "tickets": "tickets",
    "ticket_seq": "tickets_seq",
    "settings": "tickets_settings",
}


def _rename_ddl(ddl: str, old: str, new: str) -> str:
    """Rewrite the table name in a CREATE TABLE statement, name only."""
    out = re.sub(
        r'(CREATE\s+TABLE\s+)(?:IF\s+NOT\s+EXISTS\s+)?(["`\[]?)' + re.escape(old) + r'(["`\]]?)',
        lambda m: f"{m.group(1)}IF NOT EXISTS {m.group(2)}{new}{m.group(3)}",
        ddl,
        count=1,
        flags=re.IGNORECASE,
    )
    if new not in out:
        raise RuntimeError(f"rename failed for {old}->{new}: {ddl!r}")
    return out


def main():
    modules.set_shared_db_path(ALERTS)
    sh = modules.get_db()  # shared alerts.db via the Stage-1 accessor (WAL + busy_timeout)

    # --- guard: refuse if shared tickets_* already exist WITH data ------------
    present = []
    for shared_t in RENAME.values():
        r = sh.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (shared_t,)
        ).fetchone()
        if r:
            n = sh.execute(f"SELECT COUNT(*) FROM {shared_t}").fetchone()[0]
            present.append((shared_t, n))
    if any(n > 0 for _, n in present):
        print(f"REFUSING: shared tickets_* tables already hold data: {present}")
        sys.exit(2)
    if present:
        print(f"Note: empty shared tickets_* tables already exist {present} — will reuse.")

    # --- read EXACT source schema (authoritative) -----------------------------
    src = sqlite3.connect(f"file:{SRC}?mode=ro", uri=True, timeout=10)  # READ-ONLY
    create_sql = {}
    for src_t, shared_t in RENAME.items():
        row = src.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (src_t,)
        ).fetchone()
        if not row:
            print(f"REFUSING: source table {src_t} not found")
            sys.exit(2)
        create_sql[src_t] = _rename_ddl(row[0], src_t, shared_t)

    # index DDLs that live on the `tickets` table (kept name; recreate verbatim)
    index_sql = [
        r[0] for r in src.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='tickets' "
            "AND sql IS NOT NULL"
        ).fetchall()
    ]

    # --- create tickets_* in shared (one creator, via the accessor) -----------
    for src_t in RENAME:
        sh.execute(create_sql[src_t])
    for isql in index_sql:
        # idempotent: skip if an index of that name already exists in shared
        isql_ine = re.sub(r'CREATE\s+INDEX\s+', 'CREATE INDEX IF NOT EXISTS ', isql, count=1,
                          flags=re.IGNORECASE)
        sh.execute(isql_ine)
    sh.commit()
    print("Created tickets / tickets_seq / tickets_settings (+tickets indexes) in shared "
          "alerts.db (schema copied from source, table names rewritten).")

    # --- consistent snapshot read of source (quiesce window) ------------------
    src.execute("BEGIN")  # deferred read txn: consistent snapshot, blocks writer commit
    snapshot, colnames = {}, {}
    for src_t in RENAME:
        cur = src.execute(f"SELECT * FROM {src_t}")
        colnames[src_t] = [d[0] for d in cur.description]
        snapshot[src_t] = cur.fetchall()
    src.rollback()  # release lock; source DATA untouched (read-only anyway)
    src.close()
    print("Snapshotted source under a single read-only transaction (no mid-copy writes).")

    # --- copy rows into shared (renamed) tables -------------------------------
    for src_t, shared_t in RENAME.items():
        rows = snapshot[src_t]
        if not rows:
            continue
        cols = colnames[src_t]
        ph = ",".join("?" * len(cols))
        sh.executemany(
            f"INSERT INTO {shared_t} ({','.join(cols)}) VALUES ({ph})", rows
        )
    sh.commit()
    print("Copied rows into shared tickets_* tables.\n")

    # --- VERIFY: source-vs-shared counts + ticket content ---------------------
    src2 = sqlite3.connect(f"file:{SRC}?mode=ro", uri=True, timeout=10)
    print(f"  {'source':<14}{'->':^4}{'shared':<18}{'SRC':>5}{'SHD':>5}   match")
    all_ok = True
    for src_t, shared_t in RENAME.items():
        s = src2.execute(f"SELECT COUNT(*) FROM {src_t}").fetchone()[0]
        d = sh.execute(f"SELECT COUNT(*) FROM {shared_t}").fetchone()[0]
        ok = (s == d)
        all_ok = all_ok and ok
        print(f"  {src_t:<14}{'->':^4}{shared_t:<18}{s:>5}{d:>5}   {'OK' if ok else 'MISMATCH'}")

    # the 3 test tickets (type='ticket') must survive intact, row-for-row
    cols = "id,type,rule_id,sensor_key,src_ip,dst_ip,priority,title,body,status,ticket_number,resolution_notes,ai_analysis_ref,hw_snapshot_ref,relevance_scores,created_at,updated_at"
    s_tk = src2.execute(f"SELECT {cols} FROM tickets ORDER BY id").fetchall()
    d_tk = sh.execute(f"SELECT {cols} FROM tickets ORDER BY id").fetchall()
    content_ok = (s_tk == d_tk)
    n_tickets = sum(1 for r in s_tk if r[1] == "ticket")
    n_notes = sum(1 for r in s_tk if r[1] == "note")
    print(f"\n  tickets table row-for-row identical: {content_ok}")
    print(f"  (of {len(s_tk)} rows: {n_tickets} ticket(s) + {n_notes} note(s))")
    print(f"  ticket numbers: {[r[10] for r in s_tk if r[1]=='ticket']}")
    src2.close()
    sh.close()

    print("\nRESULT:", "PASS — counts + ticket content match ✓"
          if (all_ok and content_ok) else "FAIL — see above")
    sys.exit(0 if (all_ok and content_ok) else 1)


if __name__ == "__main__":
    main()
