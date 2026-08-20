"""Tests for the error-ledger -> ticket bridge (scan_error_ledger_for_tickets).

Exercises the scan LOGIC — opt-in gate, severity floor, per-code dedup, the
high-water-mark, recurrence-while-open, and best-effort-on-missing-ledger —
against a temp DB, with open_ticket monkeypatched to a plain recorder (the real
one needs the full Data Manager sequence; the bridge logic under test does not).

Run: python3 modules/tickets/test_error_ticket_bridge.py
"""
import os
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)                                   # `import module`
sys.path.insert(0, _ROOT)                                  # `from modules import ...`
sys.path.insert(0, os.path.join(_ROOT, "alert_manager"))   # `import nemesis_severity`

import module as tk                                          # noqa: E402

_results = []


def check(label, got, want):
    ok = got == want
    _results.append((label, ok))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", label, got, want))


def _fresh():
    """A temp tickets DB with the real schema + a seeded error ledger, and
    open_ticket monkeypatched to a recorder. Returns (conn_factory, opened)."""
    db = tempfile.mktemp(suffix=".db")

    def mk():
        c = sqlite3.connect(db)
        c.row_factory = sqlite3.Row
        return c

    tk._conn = mk
    tk._init_done = False
    tk._init_db()                       # real tickets schema (incl. category)

    c = mk()
    c.executescript("""
    CREATE TABLE error_codes(code TEXT PRIMARY KEY, module TEXT, class TEXT,
        description TEXT, severity TEXT, first_defined_ts TEXT);
    CREATE TABLE error_occurrences(id INTEGER PRIMARY KEY, code TEXT, ts TEXT,
        context TEXT, snapshot_id INT, resolved_cause_id INT, actor TEXT);
    INSERT INTO error_codes VALUES
      ('E-X-001','m','','L2 off','high','t'),
      ('E-X-002','m','','metric fail','low','t'),
      ('E-X-003','m','','unsigned','high','t');
    INSERT INTO error_occurrences (id,code,ts,context) VALUES
      (1,'E-X-002','t','low'),(2,'E-X-001','t','high'),
      (3,'E-X-001','t','high-again'),(4,'E-X-003','t','high-other');
    """)
    c.commit()

    opened = []

    def fake_open(**kw):
        cc = mk()
        cc.execute(
            "INSERT INTO tickets (type,category,sensor_key,body,status,"
            "ticket_number,created_at,updated_at) VALUES('ticket',?,?,?,'Open',"
            "'NF-X',datetime('now'),datetime('now'))",
            (kw["category"], kw["sensor_key"], kw.get("body", "")))
        cc.commit()
        opened.append(dict(kw))
        return 1

    tk.open_ticket = fake_open
    return mk, opened, db


def _set(mk, k, v):
    c = mk()
    c.execute("INSERT INTO tickets_settings(key,value) VALUES(?,?) "
              "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, str(v)))
    c.commit()


def main():
    print("opt-in gate: default OFF -> nothing")
    mk, opened, db = _fresh()
    check("scan returns 0 when auto_ticket_on_error is off",
          tk.scan_error_ledger_for_tickets(), 0)
    check("  ...and opens no tickets", len(opened), 0)
    os.unlink(db)

    print("\nturned on: only HIGH severity, deduped one-per-code")
    mk, opened, db = _fresh()
    _set(mk, "auto_ticket_on_error", "true")
    n = tk.scan_error_ledger_for_tickets()
    check("opens exactly 2 (E-X-001 collapsed, E-X-003; low E-X-002 skipped)", n, 2)
    check("  ...the two HIGH codes", sorted(t["sensor_key"] for t in opened),
          ["E-X-001", "E-X-003"])
    check("  ...all category=error_notice",
          all(t["category"] == "error_notice" for t in opened), True)
    check("  ...priority carries the severity (HIGH)",
          sorted(set(t["priority"] for t in opened)), ["HIGH"])
    check("  ...low-severity code never ticketed",
          any(t["sensor_key"] == "E-X-002" for t in opened), False)

    print("\nhigh-water-mark: a rescan evaluates nothing already seen")
    check("rescan opens 0", tk.scan_error_ledger_for_tickets(), 0)

    print("\nrecurrence while the ticket is OPEN is deduped")
    c = mk()
    c.execute("INSERT INTO error_occurrences (id,code,ts,context) "
              "VALUES (9,'E-X-001','t','recurrence')")
    c.commit()
    check("a new HIGH occurrence of an open code opens 0",
          tk.scan_error_ledger_for_tickets(), 0)

    print("\nafter the ticket is CLOSED, a fresh occurrence opens a new one")
    c = mk()
    c.execute("UPDATE tickets SET status='Closed' WHERE sensor_key='E-X-001'")
    c.execute("INSERT INTO error_occurrences (id,code,ts,context) "
              "VALUES (10,'E-X-001','t','post-close')")
    c.commit()
    check("a fresh occurrence after close re-files", tk.scan_error_ledger_for_tickets(), 1)
    os.unlink(db)

    print("\nseverity floor is configurable (min set to LOW -> low tickets too)")
    mk, opened, db = _fresh()
    _set(mk, "auto_ticket_on_error", "true")
    _set(mk, "min_severity_for_error_ticket", "LOW")
    tk.scan_error_ledger_for_tickets()
    check("with LOW floor, the low-severity code IS ticketed",
          any(t["sensor_key"] == "E-X-002" for t in opened), True)
    os.unlink(db)

    print("\nbest-effort: no error ledger present -> 0, never raises")
    db = tempfile.mktemp(suffix=".db")

    def mk2():
        c = sqlite3.connect(db); c.row_factory = sqlite3.Row; return c
    tk._conn = mk2; tk._init_done = False; tk._init_db()
    _set(mk2, "auto_ticket_on_error", "true")   # on, but no error_occurrences table
    try:
        r = tk.scan_error_ledger_for_tickets(); raised = False
    except Exception:
        raised = True
    check("scan with no error ledger returns 0", r, 0)
    check("  ...and never raises", raised, False)
    os.unlink(db)

    # ── piece (3): agent-error self-reported source ──────────────────────
    print("\n=== AGENT-error bridge (piece 3) ===")
    db = tempfile.mktemp(suffix=".db")

    def mk3():
        c = sqlite3.connect(db); c.row_factory = sqlite3.Row; return c
    tk._conn = mk3; tk._init_done = False; tk._init_db()
    c = mk3()
    c.execute("""CREATE TABLE agent_error_reports(id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT NOT NULL, code TEXT NOT NULL, severity TEXT, count INTEGER NOT NULL,
        first_ts TEXT, last_ts TEXT, context TEXT, received_at TEXT NOT NULL)""")
    # AGENT-SENT severity drives the gate now (no server-side map). high tickets,
    # low is skipped, and a NULL severity (pre-fix agent) is NOT ticketed.
    c.executemany("INSERT INTO agent_error_reports (device_id,code,severity,count,received_at) "
                  "VALUES (?,?,?,?,'t')",
                  [("devX","E-AGENT-001","high",3),("devX","E-AGENT-001","high",1),  # dup code
                   ("devX","E-AGENT-040","low",2),                          # low -> skip
                   ("devX","E-AGENT-030","high",1),                          # high, other code
                   ("devY","E-AGENT-001","high",1),                          # same code, other dev
                   ("devZ","E-AGENT-001",None,1)])                          # NULL sev -> skip
    c.commit()

    opened3 = []
    def fake3(**kw):
        cc = mk3()
        cc.execute("INSERT INTO tickets (type,category,sensor_key,title,body,status,"
                   "ticket_number,created_at,updated_at) VALUES('ticket',?,?,?,?,'Open',"
                   "'NF-X',datetime('now'),datetime('now'))",
                   (kw["category"], kw["sensor_key"], kw["title"], kw["body"]))
        cc.commit(); opened3.append(kw); return 1
    tk.open_ticket = fake3

    check("agent scan is a separate opt-in (off by default -> 0)",
          tk.scan_agent_error_reports_for_tickets(), 0)
    _set(mk3, "auto_ticket_on_agent_error", "true")
    n = tk.scan_agent_error_reports_for_tickets()
    check("opens 3: devX 001, devX 030, devY 001 (low 040 skipped, devX 001 collapsed)", n, 3)
    keys = sorted(t["sensor_key"] for t in opened3)
    check("  sensor_keys are device-scoped (agent:<dev>:<code>)", keys,
          ["agent:devX:E-AGENT-001", "agent:devX:E-AGENT-030", "agent:devY:E-AGENT-001"])
    check("  low-severity agent code never ticketed",
          any("E-AGENT-040" in t["sensor_key"] for t in opened3), False)
    check("  marked SELF-REPORTED in title", all("[SELF-REPORTED]" in t["title"] for t in opened3), True)
    check("  body warns against automated action off it",
          all("do NOT drive any automated action" in t["body"] for t in opened3), True)
    check("  all category=error_notice", all(t["category"] == "error_notice" for t in opened3), True)
    check("  priority from agent-sent severity (HIGH)",
          sorted(set(t["priority"] for t in opened3)), ["HIGH"])
    check("  a NULL-severity entry (pre-fix agent) is NOT ticketed",
          any("devZ" in t["sensor_key"] for t in opened3), False)

    print("\nhwm: rescan opens nothing; a new same-(dev,code) is deduped while open")
    check("rescan opens 0", tk.scan_agent_error_reports_for_tickets(), 0)
    c = mk3(); c.execute("INSERT INTO agent_error_reports (device_id,code,count,received_at) "
                         "VALUES ('devX','E-AGENT-001',9,'t')"); c.commit()
    check("recurrence of an open (dev,code) opens 0", tk.scan_agent_error_reports_for_tickets(), 0)

    print("\nper-device rate-limit caps concurrent open agent tickets")
    _set(mk3, "agent_error_ticket_max_per_device", "2")  # devX already has 2 open (001,030)
    c = mk3(); c.execute("INSERT INTO agent_error_reports (device_id,code,severity,count,received_at) "
                         "VALUES ('devX','E-AGENT-002','high',1,'t')"); c.commit()  # a 3rd HIGH code
    before = len(opened3)
    tk.scan_agent_error_reports_for_tickets()
    check("devX at cap (2): the 3rd HIGH code does NOT open a ticket",
          len(opened3), before)
    os.unlink(db)

    passed = sum(1 for _, ok in _results if ok)
    print("\n%d/%d checks passed" % (passed, len(_results)))
    if passed != len(_results):
        print("FAILED:", [l for l, ok in _results if not ok])
        sys.exit(1)


if __name__ == "__main__":
    main()
