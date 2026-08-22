#!/usr/bin/env python3
"""The master-password authority override, and the limits it cannot cross.

Run: python3 modules/ai_engine/test_master_authority.py   (exit 0 = all pass)

WHAT THIS GUARDS. Full automation is user-settable at any time, but RAISING it
past the ladder's earned level needs a second credential distinct from the
dashboard login. The gate is authentication, not track record.

THE PROPERTY UNDER TEST is the set of things the password CANNOT do, because
that is where a credential-gated override goes wrong. A password establishes WHO
you are; it never changes what the code is capable of. Specifically it cannot:
  * make an irreversible action reversible  (execute_proposal's undo gate)
  * lift a CAPABILITY ceiling               (no password creates a restore path)
  * lift the spend cap                      (a liftable flood limit is not one)
  * override the user's OWN standing rule   (edit the rule instead)
and a demotion must clear a standing override, LOUDLY -- a password entered last
week must not outvote the safety system that just fired.

CONTROLS THROUGHOUT. Every refusal is paired with a case that SUCCEEDS: an
override that refused everything would pass every "is blocked" assertion and
prove nothing.

NO NETWORK. The SDK is stubbed; nothing here contacts Anthropic or spends money.
"""
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, "/opt/nemesis")

_db = os.path.join(tempfile.mkdtemp(prefix="ai-master-"), "throwaway.db")
os.environ["NEMESIS_DB_PATH"] = _db
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-not-real")

import modules                                          # noqa: E402
modules.set_shared_db_path(_db)
import modules_loader                                    # noqa: E402
modules_loader._db_path = _db
modules_loader._init_db()
_c = sqlite3.connect(_db)
_c.execute("INSERT OR REPLACE INTO modules_enabled (module_name, enabled) "
           "VALUES ('ai_engine', 1)")
_c.commit(); _c.close()

from modules.ai_engine import module as ai               # noqa: E402
ai._init_db()

passed = failed = 0
PW = "correct-horse-battery-staple"


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


print("\n== CEILING KIND: a judgment vs a fact about the code ==")
check("malware_file_quarantine is a CAPABILITY ceiling (no restore path exists)",
      ai.ceiling_kind("malware_file_quarantine") == "capability")
check("alert_disposition is a THRESHOLD ceiling (a judgment)",
      ai.ceiling_kind("alert_disposition") == "threshold")
check("an UNCLASSIFIED class defaults to capability, the restrictive answer",
      ai.ceiling_kind("something_nobody_classified") == "capability")
check("CONTROL: the two kinds are not all the same value",
      len({ai.ceiling_kind(c) for c in ai.ACTION_CLASS_CEILINGS}) == 2,
      {c: ai.ceiling_kind(c) for c in ai.ACTION_CLASS_CEILINGS})

print("\n== THE PASSWORD MUST EXIST BEFORE IT GATES ANYTHING ==")
check("no master password is set initially", ai.master_password_is_set() is False)
r = ai.raise_authority("alert_disposition", 2, "anything", "paul")
check("a raise is refused when no password has been set",
      not r["ok"] and "no master password" in r["error"], r)
r = ai.set_master_password("short")
check("a too-short password is refused", not r["ok"], r)
r = ai.set_master_password(PW)
check("a good password is accepted", r["ok"], r)
check("and it is now set", ai.master_password_is_set() is True)
_stored = ai._get_setting("master_password_hash", "")
check("only a HASH is stored, never the password",
      PW not in _stored and _stored.startswith("$2"), _stored[:12])

print("\n== ROTATION REQUIRES THE CURRENT PASSWORD ==")
r = ai.set_master_password("a-brand-new-password-here")
check("rotation without the current password is refused", not r["ok"], r)
check("CONTROL: rotation WITH it succeeds",
      ai.set_master_password("a-brand-new-password-here", current_pw=PW)["ok"])
check("CONTROL: and rotating back works too",
      ai.set_master_password(PW, current_pw="a-brand-new-password-here")["ok"])

print("\n== RAISING AUTHORITY: wrong password does nothing ==")
before = ai.effective_ceiling("alert_disposition")
r = ai.raise_authority("alert_disposition", 2, "wrong-password", "paul")
check("a wrong password is refused", not r["ok"] and r.get("auth_failed"), r)
after = ai.effective_ceiling("alert_disposition")
check("CONTROL: the authority level is UNCHANGED after a failed attempt",
      after["level"] == before["level"], (before["level"], after["level"]))
check("CONTROL: and no override was recorded",
      after["authority_source"] == "earned", after)

print("\n== RAISING AUTHORITY: correct password works ==")
check("precondition: earned level is L0", before["earned"] == 0, before)
check("precondition: it is not acting yet", before["level"] == 0, before)
r = ai.raise_authority("alert_disposition", 2, PW, "paul", reason="trial week")
check("the raise succeeds with the right password", r["ok"], r)
eff = ai.effective_ceiling("alert_disposition")
check("the effective level is now L2", eff["level"] == 2, eff)
check("PROVENANCE is recorded as an override, not as earned trust",
      eff["authority_source"] == "override", eff)
check("and it names who granted it", eff["override_by"] == "paul", eff)
check("the reason names the override", "manual_override" in eff["reasons"], eff)
check("CONTROL: earned trust itself was NOT falsified",
      ai._authority_override("alert_disposition")["level"] == 2
      and ai.effective_ceiling("alert_disposition")["earned"] >= 2, eff)

print("\n== IT CAN RAISE PAST THE HARD CEILING -- ONLY FOR THRESHOLD CLASSES ==")
r = ai.raise_authority("ip_action_internal", 3, PW, "paul")
check("a THRESHOLD class can be raised past its hard ceiling", r["ok"], r)
eff = ai.effective_ceiling("ip_action_internal")
check("and the effective level really is above the original ceiling",
      eff["level"] == 3 and ai.ACTION_CLASS_CEILINGS["ip_action_internal"] == 1, eff)

r = ai.raise_authority("malware_file_quarantine", 3, PW, "paul")
check("a CAPABILITY class REFUSES to be raised past its ceiling", not r["ok"], r)
check("and the refusal explains it is a missing capability, not caution",
      "MISSING CAPABILITY" in r.get("error", ""), r)
check("CONTROL: the capability class was not raised",
      ai.effective_ceiling("malware_file_quarantine")["level"] <= 1,
      ai.effective_ceiling("malware_file_quarantine"))
check("CONTROL: but it CAN be raised WITHIN its ceiling",
      ai.raise_authority("malware_file_quarantine", 1, PW, "paul")["ok"])

print("\n== THE UNDO GATE IS ABSOLUTE, REGARDLESS OF PASSWORD ==")
# alert_disposition is at L2 by override, and has NO undo handler registered in
# this process. Execution must still refuse.
pid = ai.create_proposal("alert_disposition", "alerts", "alert-X", "ignore",
                         "test", "claude-haiku-4-5")
ai.respond_to_proposal(pid, "approved", "paul")
check("precondition: authority is L2 via the override",
      ai.effective_ceiling("alert_disposition")["level"] == 2)
check("precondition: no undo handler is registered",
      ai.undo_handler_for("alert_disposition") is None)
r = ai.execute_proposal(pid, lambda p: (True, "did it"))
check("execution is REFUSED despite full authority",
      not r["ok"] and "no undo handler" in r["error"], r)
check("CONTROL: registering a reversal is what unlocks it",
      (ai.register_undo_handler("alert_disposition", lambda p: (True, "reversed")),
       ai.execute_proposal(pid, lambda p: (True, "did it"))["ok"])[1])

print("\n== THE WARNING TEXT SAYS THE RIGHT THING, PER CLASS ==")
w = ai.authority_raise_warnings("ip_block_permanent", 2)
check("an irreversible class warns it CANNOT BE UNDONE",
      any("CANNOT BE UNDONE" in x for x in w), w)
w2 = ai.authority_raise_warnings("malware_file_quarantine", 2)
check("a capability class warns the raise will not enable the action",
      any("missing capability" in x for x in w2), w2)
w3 = ai.authority_raise_warnings("alert_disposition", 2)
check("CONTROL: a reversible class does NOT get the cannot-be-undone warning",
      not any("CANNOT BE UNDONE" in x for x in w3), w3)
check("CONTROL: warnings are not empty for every class (not a vacuous check)",
      len(w) > 0 and len(w2) > 0, (w, w2))

print("\n== LOCKOUT: the override endpoint is not a brute-force oracle ==")
ai._set_setting("master_password_fails", "0")
ai._set_setting("master_password_locked_until", "")
for i in range(ai._MASTER_PW_MAX_FAILS):
    ai.raise_authority("alert_disposition", 2, "nope-%d" % i, "attacker")
r = ai.raise_authority("alert_disposition", 2, PW, "paul")
check("the CORRECT password is refused once locked out",
      not r["ok"] and "locked" in r["error"].lower(), r)
ai._set_setting("master_password_locked_until", "")
ai._set_setting("master_password_fails", "0")
check("CONTROL: after the lockout clears, the correct password works again",
      ai.raise_authority("alert_disposition", 2, PW, "paul")["ok"])

print("\n== DEMOTION WINS, AND IT IS LOUD ==")
sent = []
check("precondition: an override is standing at L2",
      ai.effective_ceiling("alert_disposition")["authority_source"] == "override")
res = ai.demote_action_class("alert_disposition", "two bad calls in an hour",
                             notifier=lambda subj, body: sent.append((subj, body)))
check("demotion succeeds", res["ok"], res)
check("it reports that it cleared a standing override", res["override_cleared"] is True)
eff = ai.effective_ceiling("alert_disposition")
check("THE OVERRIDE IS GONE -- authority is back to earned",
      eff["authority_source"] == "earned", eff)
check("and the level actually dropped to L0", eff["level"] == 0, eff)
check("a notification was actually SENT, not just logged",
      res["notified"] is True and len(sent) == 1, sent)
check("the notice tells the person their override was cleared",
      "OVERRIDE WAS CLEARED" in sent[0][1], sent[0][1][:200])
check("and says the password must be re-entered to restore it",
      "re-entered" in sent[0][1], sent[0][1][:300])

# A failing notifier must NOT roll back the safety action.
ai.raise_authority("alert_disposition", 2, PW, "paul")
def _boom(subj, body):
    raise RuntimeError("smtp down")
res2 = ai.demote_action_class("alert_disposition", "again", notifier=_boom)
check("a failed notification does not undo the demotion", res2["ok"], res2)
check("and it honestly reports that nobody was notified",
      res2["notified"] is False, res2)
check("CONTROL: the demotion still took effect",
      ai.effective_ceiling("alert_disposition")["level"] == 0)

print("\n== LOWERING NEEDS NO PASSWORD; ONLY RAISING DOES ==")
ai.raise_authority("alert_disposition", 2, PW, "paul")
check("precondition: raised again", ai.effective_ceiling("alert_disposition")["level"] == 2)
r = ai.clear_authority_override("alert_disposition", "anyone")
check("clearing an override requires no password", r["ok"] and r["cleared"], r)
check("CONTROL: authority really dropped",
      ai.effective_ceiling("alert_disposition")["authority_source"] == "earned")

print("\n== THE DECISION LOG RECORDS PROVENANCE ==")
t = ai.new_trace_id()
check("a trace id is minted", isinstance(t, str) and len(t) == 12, t)
ai.log_decision(t, "prefilter", "alerts", "alert-1", "dropped", "family_cooldown",
                reason_detail="seen 14x in 30m")
ai.log_decision(t, "gate", "alerts", "alert-1", "refused", "insufficient_authority",
                action_class="alert_disposition", level_needed=2, level_granted=0,
                authority_source="earned")
ai.log_decision(t, "execute", "alerts", "alert-1", "acted", "authorized",
                action_class="alert_disposition", level_needed=2, level_granted=2,
                authority_source="override", authority_by="paul")
trail = ai.decision_trail(t)
check("the whole trail is reconstructable from one trace id", len(trail) == 3, trail)
check("it is ordered", [r["stage"] for r in trail] == ["prefilter", "gate", "execute"])
check("a DROPPED item is logged, not merely absent",
      trail[0]["decision"] == "dropped" and trail[0]["reason_code"] == "family_cooldown")
check("the counterfactual is recorded (needed vs granted)",
      trail[1]["level_needed"] == 2 and trail[1]["level_granted"] == 0, trail[1])
check("an overridden action records WHO authorized it",
      trail[2]["authority_source"] == "override" and trail[2]["authority_by"] == "paul")
check("CONTROL: an earned action is distinguishable from an overridden one",
      trail[1]["authority_source"] != trail[2]["authority_source"])
check("CONTROL: an unrelated trace id returns nothing",
      ai.decision_trail("deadbeefcafe") == [])

print("\n== THE REFUSAL TICKET IS SELF-DOCUMENTING ==")
txt = ai.refusal_ticket_text("ip_block_permanent", "203.0.113.7", "block permanently")
check("it states the reversal limitation in plain words",
      "insufficient reversal support" in txt, txt[:200])
check("it says explicitly that a password cannot fix this",
      "cannot make an action reversible" in txt, txt[-400:])
check("it frames it as a product limitation, not a misconfiguration",
      "not a misconfiguration" in txt, txt[-300:])
txt2 = ai.refusal_ticket_text("alert_disposition", "rule-9", "ignore")
check("CONTROL: a class WITH a reversal gets the other explanation",
      "insufficient reversal support" not in txt2, txt2[:200])


print("\n== RAISE-TIME READINESS: nobody leaves the screen believing a lie ==")
# The failure this closes: a raise can succeed COMPLETELY and leave the class
# inert. The only prior signal was a refusal ticket generated later -- and if the
# triggering condition never occurs, no ticket ever fires and the user stays
# wrong for the whole trial.
ai.register_anchor("alert_t", lambda r: {"x": 1},
                   action_classes=("ip_quarantine_external", "ip_block_permanent"))
ai.register_anchor("malware_t", lambda r: {"x": 1},
                   action_classes=("malware_file_quarantine",))
ai.register_anchor("explain_t", lambda r: {"x": 1}, action_classes=())

check("a surface reports its registered action classes",
      set(ai.surface_action_classes("alert_t"))
      == {"ip_quarantine_external", "ip_block_permanent"})
check("a surface with none reports none", ai.surface_action_classes("explain_t") == ())
check("an UNREGISTERED surface reports none rather than raising",
      ai.surface_action_classes("no-such-surface") == ())

r = ai.automation_readiness(surface_key="alert_t", level=2)
check("both alert classes are reported", len(r) == 2, r)
check("NEITHER will act, despite a level-2 grant",
      all(not x["will_act"] for x in r), r)
check("and the reason is the SILENT one: no undo handler",
      all(x["reason"] == "no_undo_handler" for x in r), r)
check("the detail says it could not be taken back if wrong",
      all("taken back" in x["detail"] for x in r), r)

rm = ai.automation_readiness(surface_key="malware_t", level=2)
check("the capability class is inert for a DIFFERENT, named reason",
      rm[0]["reason"] == "capability_ceiling", rm)
check("and says no restore path is available",
      "no restore path" in rm[0]["detail"], rm)

# CONTROL: a class that genuinely CAN act must report so, or this is a
# function that only ever says "no" and proves nothing.
ai.register_undo_handler("alert_disposition", lambda p: (True, "reversed"))
rd = ai.automation_readiness(["alert_disposition"], level=2)
check("CONTROL: a class WITH a reversal reports it WILL act", rd[0]["will_act"], rd)
check("CONTROL: with reason 'ready'", rd[0]["reason"] == "ready", rd)

print("\n== `level` MEANS THE AUTHORITY BEING GRANTED, NOT THE CURRENT STATE ==")
# First cut clamped to the CURRENT level, so a pre-raise preview reported every
# class as "below_acting_level" purely because the raise had not happened yet --
# useless in the one dialog whose job is to predict the post-raise world.
ai.clear_authority_override("ip_block_permanent", "test")
cur = ai.effective_ceiling("ip_block_permanent")["level"]
check("precondition: the class is currently below acting level", cur < 2, cur)
prev = ai.automation_readiness(["ip_block_permanent"], level=2)[0]
check("a PREVIEW at L2 does not report 'below_acting_level'",
      prev["reason"] != "below_acting_level", prev)
check("it reports the real post-raise blocker instead",
      prev["reason"] == "no_undo_handler", prev)
check("CONTROL: previewing L0 DOES report below_acting_level",
      ai.automation_readiness(["ip_block_permanent"], level=0)[0]["reason"]
      == "below_acting_level")

print("\n== THE RAISE ITSELF CARRIES THE ANSWER, IN THE SAME RESPONSE ==")
res = ai.raise_authority("ip_block_permanent", 2, PW, "paul", reason="trial")
check("the raise succeeds", res["ok"], res)
check("and it returns readiness in the SAME response", "readiness" in res, list(res))
check("with an explicit 'inert' list the dialog can render",
      len(res["inert"]) == 1 and res["inert"][0]["action_class"] == "ip_block_permanent",
      res.get("inert"))
check("so a SUCCESSFUL raise still tells the user it will not act",
      res["inert"][0]["reason"] == "no_undo_handler", res["inert"])
# CONTROL: a raise that IS fully effective must have an EMPTY inert list,
# otherwise 'inert' is just always-populated noise.
res2 = ai.raise_authority("alert_disposition", 2, PW, "paul")
check("CONTROL: a genuinely effective raise reports nothing inert",
      res2["ok"] and res2["inert"] == [], res2.get("inert"))

print("\n== A FAILED AUTHORITY READ IS NOT 'IT WILL ACT' ==")
_real = ai.effective_ceiling
def _boom_ceiling(ac):
    raise ai.AuthorityUnavailable("db gone")
ai.effective_ceiling = _boom_ceiling
try:
    rb = ai.automation_readiness(["alert_disposition"], level=2)
    check("an unreadable authority state reports will_act=False",
          rb[0]["will_act"] is False, rb)
    check("and names it as unknown rather than inventing a reason",
          rb[0]["reason"] == "unknown", rb)
finally:
    ai.effective_ceiling = _real
check("CONTROL: readiness works again once the read recovers",
      ai.automation_readiness(["alert_disposition"], level=2)[0]["will_act"])

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
