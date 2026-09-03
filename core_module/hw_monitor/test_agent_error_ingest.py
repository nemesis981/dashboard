"""Tests for _ingest_agent_errors — stage (c) server ingest of the agent's
self-reported E-AGENT digest into agent_error_reports.

Exercises the trust-boundary bounds: code validation (^E-AGENT-\\d{3}$), entry
and context caps, count validation, per-device isolation, parameterized/
injection-safe writes, and best-effort (never raises on hostile input).

Run: python3 core_module/hw_monitor/test_agent_error_ingest.py
"""
import os
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(_ROOT, "alert_manager"))

import hw_monitor as hm                                       # noqa: E402

_results = []


def check(label, got, want):
    ok = got == want
    _results.append((label, ok))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", label, got, want))


def _db():
    db = tempfile.mktemp(suffix=".db")
    conn = sqlite3.connect(db)
    conn.execute("""CREATE TABLE agent_error_reports(
        id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
        code TEXT NOT NULL, severity TEXT, count INTEGER NOT NULL, first_ts TEXT,
        last_ts TEXT, context TEXT, received_at TEXT NOT NULL)""")
    conn.commit()
    return conn, db


def main():
    conn, db = _db()

    print("valid digest -> stored with per-device isolation")
    n = hm._ingest_agent_errors({"agent_errors": [
        {"code": "E-AGENT-001", "severity": "high", "count": 2,
         "first": "2026-08-20T10:00:00+00:00", "last": "2026-08-20T10:05:00+00:00",
         "context": "L2 off"},
        {"code": "E-AGENT-030", "severity": "high", "count": 1, "context": "unsigned"},
    ]}, "dev-A", conn)
    check("stores every valid entry", n, 2)
    r = conn.execute("SELECT device_id, code, severity, count, context FROM "
                     "agent_error_reports WHERE code='E-AGENT-001'").fetchone()
    check("device_id is the authenticated device", r[0], "dev-A")
    check("agent-sent severity stored", r[2], "high")
    check("count/context stored intact", (r[3], r[4]), (2, "L2 off"))

    print("\nseverity validation: only canonical values stored, junk -> NULL")
    hm._ingest_agent_errors({"agent_errors": [
        {"code": "E-AGENT-010", "severity": "high", "count": 1},
        {"code": "E-AGENT-011", "severity": "CRITICAL", "count": 1},   # not canonical
        {"code": "E-AGENT-012", "severity": "'; DROP--", "count": 1},  # junk
        {"code": "E-AGENT-013", "count": 1},                            # missing
    ]}, "dev-S", conn)
    sevs = {row[0]: row[1] for row in conn.execute(
        "SELECT code, severity FROM agent_error_reports WHERE device_id='dev-S'")}
    check("canonical severity kept", sevs.get("E-AGENT-010"), "high")
    check("non-canonical severity -> NULL", sevs.get("E-AGENT-011"), None)
    check("junk/injection severity -> NULL", sevs.get("E-AGENT-012"), None)
    check("missing severity -> NULL", sevs.get("E-AGENT-013"), None)

    print("\ncode validation: only ^E-AGENT-NNN stored (injection codes rejected)")
    n = hm._ingest_agent_errors({"agent_errors": [
        {"code": "E-AGENT-999", "count": 1},            # ok
        {"code": "E-AGENT-NOPE", "count": 1},           # bad
        {"code": "not-a-code", "count": 1},             # bad
        {"code": "DROP TABLE tickets;--", "count": 1},  # injection -> rejected by regex
        {"code": "e-agent-001", "count": 1},            # wrong case -> bad
        {"count": 1},                                   # missing code
    ]}, "dev-B", conn)
    check("only the one well-formed code stored", n, 1)

    print("\ncount validation")
    n = hm._ingest_agent_errors({"agent_errors": [
        {"code": "E-AGENT-002", "count": 0},
        {"code": "E-AGENT-002", "count": -5},
        {"code": "E-AGENT-002", "count": "x"},
        {"code": "E-AGENT-002"},                        # missing count
    ]}, "dev-C", conn)
    check("zero / negative / non-int / missing counts rejected", n, 0)

    print("\nentry cap (a hostile agent cannot flood)")
    big = [{"code": "E-AGENT-001", "count": 1} for _ in range(100)]
    n = hm._ingest_agent_errors({"agent_errors": big}, "dev-D", conn)
    check("entries capped at _AGENT_ERR_MAX_ENTRIES", n, hm._AGENT_ERR_MAX_ENTRIES)

    print("\ncontext cap + injection-safe (parameterized)")
    hm._ingest_agent_errors({"agent_errors": [
        {"code": "E-AGENT-005", "count": 1, "context": "x" * 5000},
        {"code": "E-AGENT-006", "count": 1,
         "context": "'; DROP TABLE agent_error_reports; --"},
    ]}, "dev-E", conn)
    ctxs = [row[0] for row in conn.execute(
        "SELECT context FROM agent_error_reports WHERE device_id='dev-E'")]
    check("context truncated to the cap",
          all(c is None or len(c) <= hm._AGENT_ERR_MAX_CONTEXT for c in ctxs), True)
    check("SQL-injection context stored as a literal (table still exists)",
          conn.execute("SELECT COUNT(*) FROM agent_error_reports "
                       "WHERE device_id='dev-E'").fetchone()[0], 2)

    print("\nbest-effort: hostile / malformed input never raises, returns 0")
    for bad in (None, {"agent_errors": "notalist"}, {"agent_errors": 42},
                {"agent_errors": [None, 42, "x", []]}, {}, {"agent_errors": []}):
        try:
            r = hm._ingest_agent_errors(bad, "dev-F", conn)
            raised = False
        except Exception:
            raised = True
        check("no-raise on %.24r" % (bad,), raised, False)

    # ── Data Manager namespace grant — THE TRAP EVERY CHECK ABOVE IS BLIND TO ──
    #
    # Everything above builds `agent_error_reports` on a PLAIN sqlite3 connection,
    # so none of it passes through the Data Manager's write guard. A missing grant
    # is therefore invisible to this entire suite and surfaces only in production,
    # as a `WOULD DENY (warn-only)` log line with the write silently not happening
    # — and once hw_monitor is flipped to MODE_ENFORCE, as the ingest silently
    # dropping every agent-reported error. The registry's own notes ask for exactly
    # this treatment for each table added to it; the behavioural tests still cannot
    # see that file.
    #
    # Asserted DIRECTLY against allowed(), with controls proving the grant is an
    # exact-match rather than a prefix, and that a read-only consumer gets nothing.
    print("Data Manager namespace grant (invisible to the plain-sqlite3 checks above)")
    import data_manager as _dm                                # noqa: PLC0415
    check("hw_monitor may WRITE agent_error_reports",
          _dm.allowed("hw_monitor", "agent_error_reports"), True)
    check("CONTROL sibling grant still intact (agent_devices)",
          _dm.allowed("hw_monitor", "agent_devices"), True)
    check("CONTROL exact-match, not a truncated prefix",
          _dm.allowed("hw_monitor", "agent_error_report"), False)
    check("CONTROL exact-match, not a startswith extension",
          _dm.allowed("hw_monitor", "agent_error_reports_evil"), False)
    check("CONTROL tickets only READS it (ADR 0001 read-any), so no write grant",
          _dm.allowed("tickets", "agent_error_reports"), False)
    check("CONTROL dashboard only READS it too, so no write grant",
          _dm.allowed("dashboard", "agent_error_reports"), False)

    conn.close()
    os.unlink(db)
    passed = sum(1 for _, ok in _results if ok)
    print("\n%d/%d checks passed" % (passed, len(_results)))
    if passed != len(_results):
        print("FAILED:", [l for l, ok in _results if not ok])
        sys.exit(1)


if __name__ == "__main__":
    main()
