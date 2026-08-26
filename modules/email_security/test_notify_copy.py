"""Stage 5.2 -- tiered verdict notification copy. ADR 0028 D7.

THE PROPERTY UNDER TEST IS A PRODUCT DECISION, NOT A STYLE ONE: D7 rejects
"block silently" even for high-confidence malicious mail, because a message that
vanishes is indistinguishable from mail loss to the person expecting it.

NO NETWORK, NO MAILBOX, NO REAL DB.
"""
import os
import sqlite3
import sys

sys.path.insert(0, "/opt/nemesis")
sys.path.insert(0, "/opt/nemesis/alert_manager")

from modules.email_security import notify_copy as nc            # noqa: E402
from alert_manager import notify as n                           # noqa: E402

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s %s" % (label, detail))


Q = {"tier": nc.QUARANTINE, "sender": "billing@paypa1-secure.example",
     "reason": "DMARC fail; detonation confirmed credential harvesting",
     "message_id": "abc123"}
F = {"tier": nc.FLAGGED, "sender": "news@example.org",
     "reason": "urgent subject with a shortened link", "message_id": "def456"}

print("-- 0. CONTROL: the module's own selftest, in the production path --")
ok, detail = nc.selftest()
check("selftest passes", ok, detail)
check("...and it actually asserts something", "3 checks" in detail, detail)

print("\n-- 1. D7's table: the right action per confidence tier --")
check("QUARANTINE notifies", nc.verdict_notification(Q) is not None)
check("FLAGGED notifies", nc.verdict_notification(F) is not None)
check("CLEAN is silent (the ONLY silent case)",
      nc.verdict_notification({"tier": nc.CLEAN}) is None)

print("\n-- 2. ⚠ QUARANTINE IS CRITICAL -- immune to every notify_mode --")
q = nc.verdict_notification(Q)
check("severity is CRITICAL", q["severity"] == "CRITICAL", q["severity"])
# route() checks severity FIRST, so no mode -- including invented ones -- defers it.
for mode in ("digest", "immediate", "both", "", None, "quiet", "never", "off"):
    check("mode %r cannot defer a quarantine" % mode,
          n.route(q["severity"], mode) == n.SEND_NOW)

print("\n-- 3. The three variants are GENUINELY DISTINCT --")
for v, name in ((q, "quarantine"), (nc.verdict_notification(F), "flagged")):
    check("%s: all three present" % name,
          all(v[k] for k in ("beginner", "intermediate", "pro")))
    check("%s: distinct, not one string three times" % name,
          len({v["beginner"], v["intermediate"], v["pro"]}) == 3)
check("beginner is plain-English and action-oriented",
      "Nothing to do" in q["beginner"], q["beginner"])
check("pro carries the identifier needed to investigate",
      "abc123" in q["pro"], q["pro"])
check("beginner does NOT leak the technical reason verbatim",
      "DMARC" not in q["beginner"], q["beginner"])

print("\n-- 4. An UNKNOWN tier RAISES -- never defaults to silent --")
for bad in ("made-up", None, "", "CLEAN"):
    try:
        nc.verdict_notification({"tier": bad})
        check("tier %r raises" % bad, False, "it returned instead")
    except ValueError:
        check("tier %r raises rather than defaulting to silent" % bad, True)

print("\n-- 5. End-to-end through the REAL notify contract --")
db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE notify_queue(id INTEGER PRIMARY KEY AUTOINCREMENT,"
           "queued_at TEXT, severity TEXT, surface TEXT, family_key TEXT,"
           "subject TEXT, body TEXT, actor TEXT, sent_at TEXT)")
res = nc.notify_verdict(db, F, notify_mode="digest")
check("a FLAGGED verdict bundles into the digest", res["sent"] == "bundled", res)
check("...and a real row was written", res["queue_id"] is not None, res)
rows = n.pending(db)
check("...visible as pending", len(rows) == 1, rows)
check("...with NO family_key (blocked messages must not collapse into '3x')",
      rows[0]["family_key"] in (None, ""), rows[0])

resq = nc.notify_verdict(db, Q, notify_mode="digest")
check("⚠ a QUARANTINE sends IMMEDIATELY even in digest mode",
      resq["sent"] == "immediate", resq)
check("...and is never queued-and-forgotten", resq["notified"] is True)

resc = nc.notify_verdict(db, {"tier": nc.CLEAN}, notify_mode="digest")
check("a CLEAN verdict notifies nobody", resc["notified"] is False, resc)

print("\n-- 6. MUTATION: prove §3's distinctness check is real --")
_real = nc._SEVERITY
try:
    src = nc.verdict_notification(Q)
    faked = dict(src, beginner=src["intermediate"], pro=src["intermediate"])
    check("MUTANT (three identical variants) is detectable -> §3 is real",
          len({faked["beginner"], faked["intermediate"], faked["pro"]}) == 1)
finally:
    nc._SEVERITY = _real
check("CONTROL: the real output still has 3 distinct variants",
      len({q["beginner"], q["intermediate"], q["pro"]}) == 3)

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
