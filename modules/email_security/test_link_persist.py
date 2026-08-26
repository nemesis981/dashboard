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

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
