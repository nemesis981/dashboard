"""Tests for behavioral_ingest — server-side behavioral event -> malware_findings."""
import json, os, sqlite3, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
import behavioral_ingest as bi
from nemesis_agent import behavioral_events as be

_r = []
def check(l, g, w):
    ok = g == w; _r.append((l, ok))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", l, g, w))

def mkdb(with_table=True):
    c = sqlite3.connect(":memory:")
    if with_table:
        c.execute("""CREATE TABLE malware_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
            device_name TEXT, detected_at TEXT NOT NULL, layer TEXT NOT NULL,
            threat_name TEXT, file_path TEXT, file_hash TEXT, file_size INTEGER,
            severity TEXT NOT NULL DEFAULT 'INFO', score INTEGER NOT NULL DEFAULT 0,
            signals TEXT, status TEXT NOT NULL DEFAULT 'new', quarantine_path TEXT,
            scan_job_id TEXT, ai_verdict TEXT, ai_analyzed_at TEXT, ticket_id TEXT,
            notes TEXT, actor TEXT, created_at TEXT NOT NULL)""")
    return c

def ev(device="dev1", behavior="bulk_file_modify", **kw):
    return be.new_event(behavior, device, 3, kw.get("severity","high"), "falco",
                        kw.get("rule","Bulk file modification"), "2026-08-20T23:00:00",
                        kw.get("event_id","dev1-1"),
                        proc={"proc_name": kw.get("proc","cryptor"), "proc_pid": 9},
                        count=kw.get("count",1))

def main():
    print("valid behavioral events become malware_findings at layer=behavioral")
    c = mkdb()
    res = bi.ingest_behavioral(c, "dev1", "Laptop", [ev(), ev(rule="Run shell untrusted",
                               behavior="suspicious_process", event_id="dev1-2")],
                               "2026-08-20T23:05:00")
    check("both accepted", res["accepted"], 2)
    check("none rejected", res["rejected"], 0)
    rows = c.execute("SELECT layer, threat_name, severity, signals FROM malware_findings").fetchall()
    check("stored at layer=behavioral", all(r[0]=="behavioral" for r in rows), True)
    check("threat_name names the behavior+rule",
          rows[0][1].startswith("behavioral:bulk_file_modify"), True)
    sig = json.loads(rows[0][3])
    check("marked as an ATTESTED endpoint claim, not ground truth",
          sig["attested"], "endpoint")
    check("carries the count", sig["count"], 1)

    print("\nmalformed events are REJECTED, never coerced/stored")
    c2 = mkdb()
    bad = dict(ev()); del bad["behavior"]           # missing required field
    res2 = bi.ingest_behavioral(c2, "dev1", "Laptop",
                                [bad, dict(ev(), severity="nope"), ev()],
                                "2026-08-20T23:05:00")
    check("2 rejected, 1 accepted", (res2["rejected"], res2["accepted"]), (2, 1))
    check("only the valid one is stored",
          c2.execute("SELECT COUNT(*) FROM malware_findings").fetchone()[0], 1)

    print("\nan endpoint cannot report a finding for a DIFFERENT device")
    c3 = mkdb()
    res3 = bi.ingest_behavioral(c3, "dev1", "Laptop", [ev(device="dev2")],
                                "2026-08-20T23:05:00")
    check("device_id mismatch -> rejected", res3["rejected"], 1)
    check("...and nothing stored",
          c3.execute("SELECT COUNT(*) FROM malware_findings").fetchone()[0], 0)

    print("\ntolerates malware_findings absence at first boot (drops, no crash)")
    c4 = mkdb(with_table=False)
    res4 = bi.ingest_behavioral(c4, "dev1", "Laptop", [ev()], "t")
    check("no table -> all rejected, no raise", res4["rejected"], 1)

    print("\nempty / non-list input is a clean no-op")
    check("empty list", bi.ingest_behavioral(mkdb(), "d", "n", [], "t")["accepted"], 0)
    check("non-list", bi.ingest_behavioral(mkdb(), "d", "n", None, "t")["accepted"], 0)

    p = sum(1 for _, ok in _r if ok)
    print("\n%d/%d checks passed" % (p, len(_r)))
    if p != len(_r): sys.exit(1)

if __name__ == "__main__":
    main()
