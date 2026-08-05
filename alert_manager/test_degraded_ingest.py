#!/usr/bin/env python3
"""`degraded_ingest` — the degraded journal reaches audit_log, exactly once.

Run: python3 alert_manager/test_degraded_ingest.py

WHY THIS EXISTS
---------------
`nemesis_fw_watch._audit_row()` is a no-op whose docstring says the audit
requirement MOVES to the dashboard. The move was never built, so a real
`NEM-FWW-0001 modified outside Nemesis` event sat in `degraded.jsonl` from
2026-08-01 with no reader. This suite covers the reader.

WHAT IT IS WEIGHTED TOWARD
--------------------------
The dangerous failures here are not "it crashed". They are:

  * reporting `ingested=0` because the file could not be read — identical output
    to a healthy quiet system, which is the exact instrument shape this repo's
    standing verification discipline exists to reject;
  * duplicating audit rows on a re-run, which turns an append-only attribution
    log into a misleading one;
  * silently skipping a security event because an offset was stale.

So every check that asserts something does NOT happen is paired with a control
proving the same path CAN produce the other outcome. A suite that only proved
"clean input works" would pass an implementation that swallowed every error.

Runs entirely against a throwaway database and a temp journal — it never touches
the live DB, and never imports the watcher.
"""
import json
import os
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import degraded_ingest as di

EXPECTED_CHECKS = 25

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 40:
        g, w = g[:37] + "...", w[:37] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


REC_TAMPER = {
    "ts": "2026-08-01T17:54:28", "code": "NEM-FWW-0001", "severity": "error",
    "message": "modified outside Nemesis",
    "context": {"expected": "9dbe58c483eb0491", "observed": "94db6df2c120d4ad",
                "reason": "netlink event"},
}
# RFC 5737 TEST-NET-3 throughout: expendable, non-routable, and the established
# convention for audit_log test rows (Rule 11's documented exception — audit_log
# has no free-text column to carry a "test data" label).
REC_LOST_AUDIT = {
    "ts": "2026-07-30T13:45:07", "code": "NEM-FWD-0001", "severity": "error",
    "message": "privileged firewall action succeeded but its audit record was lost",
    "context": {"actor": "fail2ban", "audit_action": "fw_block_ip",
                "target_ip": "203.0.113.60", "request_id": "test-1",
                "cause": "OperationalError"},
}


def make_db():
    path = os.path.join(tempfile.mkdtemp(prefix="di-test-"), "t.db")
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE audit_log (id INTEGER PRIMARY KEY, ts TIMESTAMP NOT NULL,
            rule_id TEXT, ip TEXT, action TEXT NOT NULL, user TEXT,
            request_id TEXT);
        CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL,
            updated_at TEXT, updated_by TEXT);
    """)
    conn.commit()
    conn.close()
    return path


def factory(db_path):
    return lambda: sqlite3.connect(db_path)


def write_journal(path, records):
    with open(path, "w") as fh:
        for r in records:
            fh.write(json.dumps(r, sort_keys=True) + "\n")


def rows(db_path):
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT ts, action, ip, user, request_id "
                            "FROM audit_log ORDER BY id").fetchall()
    finally:
        conn.close()


def main():
    tmp = tempfile.mkdtemp(prefix="di-journal-")
    jp = os.path.join(tmp, "degraded.jsonl")

    # ── the happy path, and that it is genuinely doing work ──────────────────
    print("\nrecords reach audit_log, mapped by writer")
    db = make_db()
    write_journal(jp, [REC_LOST_AUDIT, REC_TAMPER])
    r = di.ingest_once(factory(db), jp)
    check("both records ingested", r["ingested"], 2)
    got = rows(db)
    check("CONTROL audit_log actually has the rows", len(got), 2)

    # A lost-audit record RECONSTRUCTS the original row rather than recording
    # that an audit write failed.
    lost = [x for x in got if x[1] == "fw_block_ip"]
    check("lost audit record is reconstructed, not summarised", len(lost), 1)
    check("  its original actor is preserved", lost[0][3], "fail2ban")
    check("  its original target ip is preserved", lost[0][2], "203.0.113.60")
    check("  its original request_id is preserved", lost[0][4], "test-1")
    check("  its original timestamp is preserved, not now()",
          lost[0][0], "2026-07-30T13:45:07")

    tamper = [x for x in got if x[1] == "fw_table_tampered"]
    check("watcher tamper event maps to fw_table_tampered", len(tamper), 1)
    check("  attributed to the watcher, not the dashboard",
          tamper[0][3], "nemesis-fw-watch")
    check("  detail carries code and message",
          tamper[0][4], "NEM-FWW-0001 modified outside Nemesis")

    # ── idempotency: the property the offset design leans on ─────────────────
    print("\nre-running does not duplicate, with or without the offset")
    r2 = di.ingest_once(factory(db), jp)
    check("a second run ingests nothing new", r2["ingested"], 0)
    check("CONTROL and audit_log still holds exactly two rows", len(rows(db)), 2)

    # Wipe the offset entirely — the case a lost/corrupt offset would produce.
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM settings WHERE key=?", (di.OFFSET_KEY,))
    conn.commit()
    conn.close()
    r3 = di.ingest_once(factory(db), jp)
    check("a full re-scan with NO offset still duplicates nothing",
          r3["duplicate"], 2)
    check("CONTROL still exactly two rows after the re-scan", len(rows(db)), 2)

    # ── failure must not look like success ───────────────────────────────────
    print("\nan unreadable input raises rather than reporting zero")
    # An unreadable journal must NOT return ingested=0, which is what a healthy
    # quiet system also returns.
    db2 = make_db()
    bad = os.path.join(tmp, "unreadable.jsonl")
    write_journal(bad, [REC_TAMPER])
    os.chmod(bad, 0o000)
    raised = False
    try:
        di.ingest_once(factory(db2), bad)
    except di.IngestError:
        raised = True
    except PermissionError:
        raised = True
    finally:
        os.chmod(bad, 0o644)
    if os.geteuid() == 0:
        # root ignores the mode bits, so the check above cannot fail closed —
        # skipping is honest; asserting would be a vacuous pass.
        print("  [SKIP] running as root: chmod cannot make a file unreadable")
        _results.append(("unreadable journal raises (skipped as root)", True))
    else:
        check("an unreadable journal RAISES, not ingested=0", raised, True)

    # A corrupt stored offset must not silently mean "start from zero".
    db3 = make_db()
    conn = sqlite3.connect(db3)
    conn.execute("INSERT INTO settings (key,value) VALUES (?,?)",
                 (di.OFFSET_KEY, "not-a-number"))
    conn.commit()
    conn.close()
    raised2 = False
    try:
        di.ingest_once(factory(db3), jp)
    except di.IngestError:
        raised2 = True
    check("a corrupt stored offset RAISES", raised2, True)
    check("CONTROL nothing was written under the corrupt offset",
          len(rows(db3)), 0)

    # ── malformed and unmappable are counted, never silently dropped ─────────
    print("\nbad records are counted and logged, not silently dropped")
    db4 = make_db()
    jp4 = os.path.join(tmp, "mixed.jsonl")
    with open(jp4, "w") as fh:
        fh.write("{not json at all\n")
        fh.write(json.dumps({"ts": "2026-08-01T00:00:00", "code": "NEM-XXX-9999",
                             "message": "unknown code"}) + "\n")
        fh.write(json.dumps(REC_TAMPER, sort_keys=True) + "\n")
    r4 = di.ingest_once(factory(db4), jp4)
    check("the malformed line is counted", r4["malformed"], 1)
    check("the unmappable record is counted", r4["unmappable"], 1)
    check("and the good record still lands", r4["ingested"], 1)

    # ── a partial trailing line is not consumed ──────────────────────────────
    print("\na partial trailing write is left for the next run")
    db5 = make_db()
    jp5 = os.path.join(tmp, "partial.jsonl")
    with open(jp5, "w") as fh:
        fh.write(json.dumps(REC_TAMPER, sort_keys=True) + "\n")
        fh.write('{"ts": "2026-08-05T00:00:00", "code": "NEM-FWW-00')  # no newline
    r5 = di.ingest_once(factory(db5), jp5)
    check("only the complete record is ingested", r5["ingested"], 1)
    # Completing the line must then yield the second record — proving the partial
    # was DEFERRED, not discarded. Without this the check above would also pass an
    # implementation that threw the partial line away.
    with open(jp5, "a") as fh:
        fh.write('01", "message": "later"}\n')
    r6 = di.ingest_once(factory(db5), jp5)
    check("CONTROL completing the line ingests it on the next run",
          r6["ingested"], 1)

    # ── the production wiring: two DIFFERENT connections ─────────────────────
    # audit_log goes through the Data Manager guard; the offset goes raw, because
    # `settings` is granted to no namespace. Proven necessary, not assumed: routed
    # through the guard, the offset write is DENIED under enforce and every run
    # re-scans the whole journal. This check pins the split so a later "tidy-up"
    # cannot quietly merge them back.
    print("\nthe offset store is separable from the audit store")
    db6 = make_db()
    jp6 = os.path.join(tmp, "split.jsonl")
    write_journal(jp6, [REC_TAMPER])
    offset_calls = []

    def offset_factory():
        offset_calls.append(1)
        return sqlite3.connect(db6)

    r7 = di.ingest_once(factory(db6), jp6, offset_conn_factory=offset_factory)
    check("ingest works with a separate offset connection", r7["ingested"], 1)
    check("CONTROL the offset factory was actually used", len(offset_calls) > 0, True)
    stored = sqlite3.connect(db6).execute(
        "SELECT value FROM settings WHERE key=?", (di.OFFSET_KEY,)).fetchone()
    check("the offset landed in the separate store", stored is not None, True)

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [lbl for lbl, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d "
              "-- a check was skipped, not merely failed" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
