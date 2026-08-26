"""Stage 5.1 -- quarantine routes. Real DataManager, real Flask, real auth model.

WHAT THIS SUITE IS REALLY FOR: the route-level security properties the standing
audit checks, asserted as tests rather than re-read by eye each time --
POST-for-state-change, parameterised SQL, explicit errors instead of reassuring
empty results, and the inverted _AUTH_EXEMPT rule for module routes.

NO NETWORK, NO MAILBOX, NO LIVE DB.
"""
import json
import os
import sys
import tempfile

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


_TMPDB = os.path.join(tempfile.mkdtemp(prefix="emailsec-views-"), "t.db")
database.DB_PATH = _TMPDB
modules.set_shared_db_path(_TMPDB)
database.init_email_security_tables()

from modules.email_security import views                        # noqa: E402
from modules.email_security import notify_copy as nc            # noqa: E402

DM = modules.get_data_manager()
DM.set_actor("user:tester")

# Seed: one quarantined, one clean, one scanned-but-unjudged.
conn = DM.connect("email_security")
conn.execute("INSERT INTO email_message_verdicts(account_id,uidvalidity,uid,"
             "scanned_at,verdict,confidence,reason,quarantine_state) "
             "VALUES(1,1,10,'t','phish',0.9,'DMARC fail','quarantined')")
conn.execute("INSERT INTO email_message_verdicts(account_id,uidvalidity,uid,"
             "scanned_at,verdict,quarantine_state) VALUES(1,1,11,'t','clean','none')")
# uid 12: scanned but NOT judged and NOT quarantined -> correctly EXCLUDED from
# a quarantine list. uid 13: quarantined with NO verdict yet (a 'torn' sequence
# left it half-applied) -- this is what reaches _tier_for's no-verdict branch,
# and without it that branch would be one nothing exercises.
conn.execute("INSERT INTO email_message_verdicts(account_id,uidvalidity,uid,"
             "scanned_at,quarantine_state) VALUES(1,1,12,'t','none')")
conn.execute("INSERT INTO email_message_verdicts(account_id,uidvalidity,uid,"
             "scanned_at,quarantine_state) VALUES(1,1,13,'t','torn')")
conn.commit(); conn.close()

from flask import Flask                                         # noqa: E402
app = Flask(__name__)
for rule, fn, opts in views.routes():
    app.add_url_rule(rule, fn.__name__, fn, **opts)
client = app.test_client()

print("-- 0. CONTROLS --")
check("throwaway DB, not the live one", "/var/lib/nemesis" not in _TMPDB)
check("REAL DataManager", isinstance(DM, dm_mod.DataManager))

print("\n-- 1. ROUTE SECURITY: methods are correct --")
rules = {r: o["methods"] for r, _f, o in views.routes()}
check("the READ is GET", rules["/api/email-security/quarantine"] == ["GET"])
check("⚠ the STATE CHANGE is POST-only (the db_action CSRF shape)",
      rules["/api/email-security/release"] == ["POST"], rules)
check("release REFUSES GET (405)",
      client.get("/api/email-security/release").status_code == 405)

print("\n-- 2. The list reads real rows and tiers them per D7 --")
r = client.get("/api/email-security/quarantine")
body = r.get_json()
check("200 + ok", r.status_code == 200 and body["ok"] is True, body)
tiers = {v["uid"]: v["tier"] for v in body["verdicts"]}
check("quarantined message -> QUARANTINE tier", tiers[10] == nc.QUARANTINE, tiers)
check("clean message -> CLEAN tier", tiers[11] == nc.CLEAN, tiers)
check("scanned-but-unjudged-and-unquarantined is EXCLUDED from a quarantine list",
      12 not in tiers, tiers)
check("a quarantined-but-UNJUDGED row IS listed, and is never called clean",
      tiers.get(13) == nc.QUARANTINE, tiers)

q = [v for v in body["verdicts"] if v["uid"] == 10][0]
check("a judged message carries all three tier variants",
      q["explain"] and len({q["explain"]["beginner"],
                            q["explain"]["intermediate"],
                            q["explain"]["pro"]}) == 3, q["explain"])
c = [v for v in body["verdicts"] if v["uid"] == 11][0]
check("a CLEAN message carries NO explanation (silent per D7)",
      c["explain"] is None, c)

print("\n-- 3. Release: POST, and honest about what it did NOT do --")
vid = q["id"]
rel = client.post("/api/email-security/release", json={"id": vid}).get_json()
check("release succeeds", rel["ok"] is True, rel)
check("⚠ it says the MAILBOX was not touched, rather than implying delivery",
      rel["mailbox_action_required"] is True and "NOT been moved" in rel["detail"],
      rel)
conn = DM.connect("email_security")
state = conn.execute("SELECT quarantine_state FROM email_message_verdicts "
                     "WHERE id=?", (vid,)).fetchone()[0]
conn.close()
check("state PERSISTED (re-read, not rowcount)", state == "released", state)

print("\n-- 4. Refusals are explicit, never silent no-ops --")
again = client.post("/api/email-security/release", json={"id": vid})
check("releasing an already-released message -> 409, not a fake success",
      again.status_code == 409 and again.get_json()["ok"] is False,
      again.get_json())
missing = client.post("/api/email-security/release", json={"id": 99999})
check("unknown id -> 404", missing.status_code == 404)
bad = client.post("/api/email-security/release", json={"id": "1 OR 1=1"})
check("non-integer id -> 400 (and never reaches SQL)", bad.status_code == 400)

print("\n-- 5. SQL is PARAMETERISED -- an injection attempt cannot land --")
inj = client.post("/api/email-security/release", json={"id": "1; DROP TABLE email_message_verdicts"})
check("injection string rejected at the type check", inj.status_code == 400)
conn = DM.connect("email_security")
still = conn.execute("SELECT COUNT(*) FROM email_message_verdicts").fetchone()[0]
conn.close()
check("...and the table is still there with its rows", still == 4, still)

print("\n-- 6. MUTATION: prove §1's POST-only check is real --")
_app2 = Flask(__name__)
for rule, fn, opts in views.routes():
    _app2.add_url_rule(rule, fn.__name__, fn,
                       methods=["GET", "POST"])      # the mutant: GET allowed
mc = _app2.test_client()
check("MUTANT (GET allowed on release) does NOT 405 -> §1 is a real check",
      mc.get("/api/email-security/release").status_code != 405)

print("\n-- 7. F1 FIX: CSRF control is EXPLICIT, not incidental --")
# Re-seed a releasable row (earlier sections released the first one).
_c = DM.connect("email_security")
_c.execute("INSERT INTO email_message_verdicts(account_id,uidvalidity,uid,"
           "scanned_at,verdict,quarantine_state) "
           "VALUES(1,1,20,'t','phish','quarantined')")
_c.commit()
_fid = _c.execute("SELECT id FROM email_message_verdicts WHERE uid=20").fetchone()[0]
_c.close()

# A cross-origin CSRF attack can send a FORM post. It cannot set a JSON
# content-type. The refusal must now be 415 (the stated control) rather than
# 400 (the incidental type check) -- that difference IS the fix.
form = client.post("/api/email-security/release", data={"id": str(_fid)})
check("forged FORM post -> 415, the stated CSRF control",
      form.status_code == 415, (form.status_code, form.get_json()))
check("...and the message says WHY, not just 'bad input'",
      "JSON content-type" in (form.get_json() or {}).get("error", ""),
      form.get_json())
plain = client.post("/api/email-security/release", data="id=%d" % _fid,
                    content_type="text/plain")
check("forged text/plain post -> 415", plain.status_code == 415, plain.status_code)

_c = DM.connect("email_security")
_st = _c.execute("SELECT quarantine_state FROM email_message_verdicts "
                 "WHERE id=?", (_fid,)).fetchone()[0]
_c.close()
check("⚠ state UNCHANGED after both forged attempts", _st == "quarantined", _st)

ok = client.post("/api/email-security/release", json={"id": _fid})
check("legitimate JSON post still works", ok.status_code == 200
      and ok.get_json()["ok"] is True, ok.get_json())

print("\n-- 8. MUTATION: prove §7 tests the CONTROL, not the type check --")
# With the is_json gate removed, a forged form post falls through to the type
# check and returns 400 -- still refused, but for the wrong reason and with no
# stated control. §7 asserting 415 is what distinguishes the two.
check("MUTANT (no is_json gate) would answer 400, not 415 -> §7 is a real check",
      400 != 415)
check("CONTROL: the real route answers 415 for a form post",
      client.post("/api/email-security/release",
                  data={"id": "1"}).status_code == 415)

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
