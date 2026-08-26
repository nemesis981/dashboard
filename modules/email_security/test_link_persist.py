"""Stage 4 persistence -- link_extract.record_results, against a REAL DataManager.

DELIBERATELY NOT STUBBED. data_manager's own dhcp comment states the hazard: a
module writing an ungranted table is refused at RUNTIME, and because module
suites stub the Data Manager, a MISSING NAMESPACE GRANT PASSES EVERY TEST and
surfaces only in production as a `WOULD DENY` log line with the write silently
not happening.

Stage 2.7 hit exactly that -- `email_security` had no namespace entry at all --
and it was caught only by testing against a real DataManager. This suite exists
so the fourth table cannot repeat it.

NO NETWORK, NO MAILBOX, NO LIVE DB.
"""
import json
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, "/opt/nemesis")
sys.path.insert(0, "/opt/nemesis/alert_manager")

import modules                                                  # noqa: E402
import database                                                 # noqa: E402
import data_manager as dm_mod                                   # noqa: E402

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s %s" % (label, detail))


_TMPDB = os.path.join(tempfile.mkdtemp(prefix="emailsec-linkpersist-"), "t.db")
database.DB_PATH = _TMPDB
modules.set_shared_db_path(_TMPDB)
database.init_email_security_tables()

from modules.email_security import link_extract as le           # noqa: E402

DM = modules.get_data_manager()
DM.set_actor("user:tester")

print("-- 0. CONTROLS --")
check("throwaway DB, not the live one", "/var/lib/nemesis" not in _TMPDB)
check("REAL DataManager, not a stub", isinstance(DM, dm_mod.DataManager))
check("enforcement ON (so the grant is load-bearing)",
      dm_mod.namespace_mode("email_security") == dm_mod.MODE_ENFORCE)

print("\n-- 1. THE NAMESPACE GRANT (the Stage 2.7 gap) --")
check("email_link_detonations IS granted",
      dm_mod.allowed("email_security", "email_link_detonations"))
for t in ("email_link_detonations_archive", "email_links", "email_"):
    check("DENIES %s (exact-match, not a prefix)" % t,
          dm_mod.allowed("email_security", t) is False)
check("DENIES another module's table",
      dm_mod.allowed("email_security", "malware_findings") is False)

print("\n-- 2. The table exists with the expected shape --")
conn = DM.connect("email_security")
cols = {r[1] for r in conn.execute("PRAGMA table_info(email_link_detonations)")}
conn.close()
for c in ("verdict_id", "url", "host", "side_effect_risk", "outcome",
          "report_json", "error", "batch_truncated", "batch_eligible",
          "batch_detonated", "actor"):
    check("column %s present" % c, c in cols, sorted(cols))

BATCH = {
    "extraction": {"truncated": True, "upstream_truncated": False, "eligible": 40},
    "detonated": 25,
    "results": [
        {"url": "https://example.com/a", "host": "example.com",
         "side_effect_risk": "low", "outcome": "completed",
         "report": {"raw": "200"}, "error": None},
        {"url": "https://example.com/b", "host": "example.com",
         "side_effect_risk": "high", "outcome": "error",
         "report": None, "error": "RuntimeError: reset"},
    ],
}

print("\n-- 3. Writes actually land (the grant is exercised for real) --")
n = le.record_results(7, BATCH)
check("record_results reports 2 rows", n == 2, n)
conn = DM.connect("email_security")
rows = conn.execute("SELECT url, outcome, report_json, error, actor, "
                    "batch_truncated, batch_eligible, batch_detonated "
                    "FROM email_link_detonations ORDER BY id").fetchall()
conn.close()
check("2 rows PERSISTED (re-read, not rowcount)", len(rows) == 2, len(rows))
check("actor stamped from current_actor()", rows[0][4] == "user:tester", rows[0][4])
check("report stored for the completed one", json.loads(rows[0][2])["raw"] == "200")
check("report stays NULL for the failed one", rows[1][2] is None, rows[1][2])
check("error text preserved", "reset" in rows[1][3], rows[1][3])

print("\n-- 4. TRUNCATION IS CARRIED ONTO EVERY ROW --")
check("batch_truncated set on both rows", all(r[5] == 1 for r in rows), rows)
check("eligible recorded", rows[0][6] == 40, rows[0][6])
check("detonated recorded", rows[0][7] == 25, rows[0][7])
check("...so a partial run cannot READ as complete from the rows alone",
      rows[0][6] > rows[0][7], (rows[0][6], rows[0][7]))

print("\n-- 5. Re-detonation UPDATES, never duplicates --")
BATCH2 = {"extraction": {"truncated": False, "upstream_truncated": False,
                         "eligible": 2},
          "detonated": 2,
          "results": [dict(BATCH["results"][0], outcome="completed",
                           report={"raw": "301"})]}
le.record_results(7, BATCH2)
conn = DM.connect("email_security")
n_after = conn.execute("SELECT COUNT(*) FROM email_link_detonations").fetchone()[0]
updated = conn.execute("SELECT report_json, batch_truncated FROM "
                       "email_link_detonations WHERE url='https://example.com/a'"
                       ).fetchone()
conn.close()
check("still 2 rows (upsert, not a duplicate)", n_after == 2, n_after)
check("report updated in place", json.loads(updated[0])["raw"] == "301", updated[0])
check("batch_truncated updated too (now a complete run)", updated[1] == 0, updated[1])

print("\n-- 6. An unknown outcome is REFUSED, not stored --")
try:
    le.record_results(9, {"extraction": {}, "detonated": 1,
                          "results": [{"url": "https://x/", "outcome": "fine"}]})
    check("unknown outcome raises", False, "it was accepted")
except ValueError:
    check("unknown outcome raises ValueError rather than storing it", True)
conn = DM.connect("email_security")
n9 = conn.execute("SELECT COUNT(*) FROM email_link_detonations "
                  "WHERE verdict_id=9").fetchone()[0]
conn.close()
check("...and nothing was written for it", n9 == 0, n9)

print("\n-- 7. MUTATION: prove §1's grant check is not vacuous --")
_real = dm_mod.NAMESPACES["email_security"]["tables"]
dm_mod.NAMESPACES["email_security"] = {
    "tables": tuple(t for t in _real if t != "email_link_detonations")}
try:
    le.record_results(11, BATCH)
    _denied = False
except Exception:                                               # noqa: BLE001
    _denied = True
finally:
    dm_mod.NAMESPACES["email_security"] = {"tables": _real}
check("MUTANT (grant removed) REFUSES the write -> the grant is load-bearing",
      _denied is True)
check("CONTROL: grant restored, writes work again",
      le.record_results(12, BATCH) == 2)

print("\n-- 8. ADDRESS REDACTION at persistence time --")
RED = {"extraction": {"truncated": False, "upstream_truncated": False, "eligible": 3},
       "detonated": 3,
       "results": [
           {"url": "https://e.example/unsub?u=abc123&email=x%40example.com",
            "host": "e.example", "side_effect_risk": "high",
            "outcome": "completed", "report": {"raw": "200"}, "error": None},
           {"url": "https://e.example/u/alice.smith@example.org/confirm",
            "host": "e.example", "side_effect_risk": "high",
            "outcome": "completed", "report": {"raw": "200"}, "error": None},
           {"url": "https://e.example/click?e=aG9sZDEyMw&t=99",
            "host": "e.example", "side_effect_risk": "medium",
            "outcome": "completed", "report": {"raw": "200"}, "error": None},
       ]}
le.record_results(21, RED)
conn = DM.connect("email_security")
stored = [r[0] for r in conn.execute(
    "SELECT url FROM email_link_detonations WHERE verdict_id=21 ORDER BY id")]
conn.close()
joined = " ".join(stored)
check("no literal address survives in ANY stored url",
      "@example.com" not in joined and "@example.org" not in joined
      and "%40example.com" not in joined, stored)
check("query-param address redacted", any(le.REDACTED in s and "unsub" in s for s in stored), stored)
check("PATH address redacted too (the majority case in real mail)",
      any(le.REDACTED in s and "/confirm" in s for s in stored), stored)
check("opaque identity token LEFT INTACT (out of scope, deliberately)",
      any("e=aG9sZDEyMw" in s for s in stored), stored)
check("host and path structure preserved -- still the detection signal",
      all("e.example" in s for s in stored), stored)
check("a url with no address is stored byte-identical",
      "https://e.example/click?e=aG9sZDEyMw&t=99" in stored, stored)

print("\n-- 9. UNIQUE collapse on redacted duplicates is INTENDED --")
COLLAPSE = {"extraction": {"truncated": False, "upstream_truncated": False,
                           "eligible": 2}, "detonated": 2,
            "results": [
                {"url": "https://e.example/p?email=a%40example.com",
                 "host": "e.example", "outcome": "completed",
                 "report": {"raw": "200"}, "error": None},
                {"url": "https://e.example/p?email=b%40example.com",
                 "host": "e.example", "outcome": "completed",
                 "report": {"raw": "200"}, "error": None},
            ]}
le.record_results(22, COLLAPSE)
conn = DM.connect("email_security")
n22 = conn.execute("SELECT COUNT(*) FROM email_link_detonations "
                   "WHERE verdict_id=22").fetchone()[0]
conn.close()
check("two links differing ONLY by recipient collapse to ONE row (intended)",
      n22 == 1, n22)

print("\n-- 10. MUTATION: prove §8 is not vacuous --")
_real_re = le._ADDRESS_RE
le._ADDRESS_RE = __import__("re").compile(r"(?!x)x")   # matches nothing
try:
    le.record_results(23, RED)
    conn = DM.connect("email_security")
    leaked = " ".join(r[0] for r in conn.execute(
        "SELECT url FROM email_link_detonations WHERE verdict_id=23"))
    conn.close()
finally:
    le._ADDRESS_RE = _real_re
check("MUTANT (redactor disabled) LEAKS the address -> §8 is a real check",
      "example.org" in leaked or "%40example.com" in leaked, leaked[:90])
check("CONTROL: redactor restored, addresses removed again",
      le.redact_addresses("https://x/?email=q%40example.com")[1] == 1)

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
