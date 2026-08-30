#!/usr/bin/env python3
"""The proposal lifecycle and the UNDO path that authority to act rests on.

Run: python3 modules/ai_engine/test_undo_path.py   (exit 0 = all pass)

WHAT THIS GUARDS. `ai_proposals` shipped with `undone`/`undone_at`/`undone_by`
columns and NO code that ever read or wrote them -- schema describing a capability
that did not exist. The ladder cannot grant an engine permission to ACT until an
action can be taken back, so this is the blocker that had to clear before L2.

THE PROPERTY UNDER TEST is not "the flag flips". A flag flip is exactly the bug
this suite exists to catch: a row reading `undone=1` while the action is still in
force is worse than no undo at all, because it is the record an operator consults
during an incident. So every undo assertion here checks the REAL WORLD STATE (a
row in a real `alerts` table) and not just the bookkeeping.

CONTROLS THROUGHOUT. Every refusal is paired with a case that succeeds -- a
lifecycle that refused everything would pass every "is blocked" check. The
handler-required rule is proved by registering a handler and watching the SAME
proposal go from refused to executable. The failing-handler case proves the row
is NOT marked undone when the reversal genuinely fails.

NO NETWORK. The SDK is stubbed; nothing here contacts Anthropic or spends money.
"""
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, "/opt/nemesis")

_db = os.path.join(tempfile.mkdtemp(prefix="ai-undo-"), "throwaway.db")
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

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


def conn():
    return sqlite3.connect(_db)


# ── a real table to act on, so "undo" means something outside its own bookkeeping ──
_c = conn()
_c.execute("CREATE TABLE IF NOT EXISTS alerts (rule_id TEXT, action TEXT)")
_c.execute("DELETE FROM alerts")
_c.executemany("INSERT INTO alerts(rule_id, action) VALUES (?,?)",
               [("alert-A", "pending"), ("alert-B", "pending"),
                ("alert-C", "pending")])
_c.commit(); _c.close()


def alert_action(rule_id):
    c = conn()
    row = c.execute("SELECT action FROM alerts WHERE rule_id=?", (rule_id,)).fetchone()
    c.close()
    return row[0] if row else None


# The production handler shape: reverse the effect, report honestly.
def undo_alert_disposition(p):
    c = conn()
    cur = c.execute("UPDATE alerts SET action='pending' WHERE rule_id=? AND action=?",
                    (p["row_id"], p["proposed_action"]))
    c.commit()
    n = cur.rowcount
    c.close()
    if n == 0:
        return False, "no matching alert row"
    return True, "alert %s returned to pending" % p["row_id"]


def do_disposition(p):
    c = conn()
    c.execute("UPDATE alerts SET action=? WHERE rule_id=?",
              (p["proposed_action"], p["row_id"]))
    c.commit(); c.close()
    return True, "alert %s set to %s" % (p["row_id"], p["proposed_action"])


print("\n== THE TABLE HAD NO READER OR WRITER BEFORE THIS ==")
cols = {r[1] for r in conn().execute("PRAGMA table_info(ai_proposals)")}
check("ai_proposals carries the undo columns",
      {"undone", "undone_at", "undone_by"} <= cols, sorted(cols))
check("the engine now exposes a proposal lifecycle",
      all(hasattr(ai, n) for n in ("create_proposal", "respond_to_proposal",
                                   "execute_proposal", "undo_proposal")))

print("\n== CREATE: propose, do not act ==")
pid = ai.create_proposal("alert_disposition", "alerts", "alert-A", "ignore",
                         "no signal in 30d of history", "claude-haiku-4-5")
check("a proposal is created and returns its id", isinstance(pid, int) and pid > 0, pid)
p = ai.get_proposal(pid)
check("it is recorded unanswered", p and p["human_response"] is None)
check("it is recorded unexecuted and un-undone",
      p and p["executed"] == 0 and p["undone"] == 0)
check("CONTROL: proposing did NOT touch the alert",
      alert_action("alert-A") == "pending", alert_action("alert-A"))
try:
    ai.create_proposal("not_a_real_class", "alerts", "x", "y", "z")
    check("an unknown action class is refused", False, "no raise")
except ai.UnknownActionClass:
    check("an unknown action class is refused", True)

print("\n== EXECUTE REFUSES WHAT IT SHOULD ==")
r = ai.execute_proposal(pid, do_disposition)
check("refuses to execute a proposal nobody approved",
      not r["ok"] and "not approved" in r["error"], r)
check("CONTROL: the alert is still untouched", alert_action("alert-A") == "pending")

ai.respond_to_proposal(pid, "approved", "paul")
r = ai.execute_proposal(pid, do_disposition)
check("refuses even an APPROVED action with no undo handler registered",
      not r["ok"] and "no undo handler" in r["error"], r)
check("CONTROL: an irreversible action really did not run",
      alert_action("alert-A") == "pending", alert_action("alert-A"))

print("\n== REGISTERING THE REVERSAL IS WHAT UNLOCKS EXECUTION ==")
ai.register_undo_handler("alert_disposition", undo_alert_disposition)
check("the handler is registered",
      ai.undo_handler_for("alert_disposition") is not None)
r = ai.execute_proposal(pid, do_disposition, actor="ai_engine")
check("the SAME proposal now executes", r["ok"], r)
check("the effect really happened in the world",
      alert_action("alert-A") == "ignore", alert_action("alert-A"))
check("and it is recorded as executed", ai.get_proposal(pid)["executed"] == 1)
r = ai.execute_proposal(pid, do_disposition)
check("refuses to execute the same proposal twice",
      not r["ok"] and "already executed" in r["error"], r)

print("\n== APPROVE/REJECT IS AN AUDIT TRAIL, NOT A MUTABLE FIELD ==")
r = ai.respond_to_proposal(pid, "rejected", "someone-else")
check("a second, contradicting decision is refused",
      not r["ok"] and "already approved" in r["error"], r)
check("CONTROL: the original decision and decider stand",
      ai.get_proposal(pid)["responded_by"] == "paul")
r = ai.respond_to_proposal(pid, "maybe", "paul")
check("a nonsense response is refused", not r["ok"], r)

pid_rej = ai.create_proposal("alert_disposition", "alerts", "alert-B", "ignore",
                             "test", "claude-haiku-4-5")
ai.respond_to_proposal(pid_rej, "rejected", "paul")
r = ai.execute_proposal(pid_rej, do_disposition)
check("a REJECTED proposal cannot be executed", not r["ok"], r)
check("CONTROL: alert-B was never touched", alert_action("alert-B") == "pending")

print("\n== UNDO REVERSES THE WORLD, NOT JUST THE FLAG ==")
r = ai.undo_proposal(pid, "paul")
check("undo reports success", r["ok"], r)
check("THE ALERT IS ACTUALLY BACK TO pending",
      alert_action("alert-A") == "pending", alert_action("alert-A"))
p = ai.get_proposal(pid)
check("the row records who undid it and when",
      p["undone"] == 1 and p["undone_by"] == "paul" and p["undone_at"], p)
r = ai.undo_proposal(pid, "paul")
check("refuses to undo the same proposal twice",
      not r["ok"] and "already undone" in r["error"], r)

pid_new = ai.create_proposal("alert_disposition", "alerts", "alert-C", "ignore",
                             "test", "claude-haiku-4-5")
r = ai.undo_proposal(pid_new, "paul")
check("refuses to undo something that was never executed",
      not r["ok"] and "never executed" in r["error"], r)

print("\n== A FAILED REVERSAL MUST NOT REPORT SUCCESS ==")
# The load-bearing case: if the handler cannot reverse the effect, the row must
# NOT claim it did. A row reading `undone=1` over a still-live action is the
# single most dangerous state this table can be in.
ai.respond_to_proposal(pid_new, "approved", "paul")
ai.execute_proposal(pid_new, do_disposition)
check("precondition: alert-C is now ignored", alert_action("alert-C") == "ignore")


def failing_handler(p):
    return False, "simulated: the firewall rule could not be removed"


ai.register_undo_handler("alert_disposition", failing_handler)
r = ai.undo_proposal(pid_new, "paul")
check("a handler that fails makes undo fail", not r["ok"], r)
check("and it says the action is STILL IN FORCE", r.get("still_in_force") is True, r)
check("the row is NOT marked undone", ai.get_proposal(pid_new)["undone"] == 0)
check("CONTROL: the world is unchanged, matching the record",
      alert_action("alert-C") == "ignore", alert_action("alert-C"))


def raising_handler(p):
    raise RuntimeError("boom")


ai.register_undo_handler("alert_disposition", raising_handler)
r = ai.undo_proposal(pid_new, "paul")
check("a handler that RAISES is caught, not propagated", not r["ok"], r)
check("the row is still not marked undone", ai.get_proposal(pid_new)["undone"] == 0)

ai.register_undo_handler("alert_disposition", undo_alert_disposition)
r = ai.undo_proposal(pid_new, "paul")
check("CONTROL: once the handler works again, undo succeeds", r["ok"], r)
check("and alert-C is genuinely back to pending",
      alert_action("alert-C") == "pending", alert_action("alert-C"))

print("\n== A REVERSAL THAT MATCHES NOTHING IS NOT A SUCCESS ==")
# If a human already changed the disposition, the handler's UPDATE matches zero
# rows. Reporting that as a reversal would be the "default value read as a real
# answer" shape -- it must report the truth instead.
pid_h = ai.create_proposal("alert_disposition", "alerts", "alert-B", "ignore",
                           "test", "claude-haiku-4-5")
ai.respond_to_proposal(pid_h, "approved", "paul")
ai.execute_proposal(pid_h, do_disposition)
c = conn(); c.execute("UPDATE alerts SET action='escalated' WHERE rule_id='alert-B'")
c.commit(); c.close()
r = ai.undo_proposal(pid_h, "paul")
check("undo fails when a human already moved the row", not r["ok"], r)
check("the human's value is preserved, not stomped",
      alert_action("alert-B") == "escalated", alert_action("alert-B"))

print("\n== THE QUEUE IS READABLE ==")
rows = ai.list_proposals(limit=50)
check("proposals list newest-first", len(rows) >= 4 and rows[0]["id"] > rows[-1]["id"])
pend = ai.list_proposals(pending_only=True)
check("pending_only returns only unanswered proposals",
      all(r["human_response"] is None for r in pend), pend)
check("CONTROL: pending_only is a real filter, not everything",
      len(pend) < len(rows), (len(pend), len(rows)))

print("\n== THE LADDER STILL GATES THE CLASS ==")
check("alert_disposition is a known action class",
      "alert_disposition" in ai.ACTION_CLASS_CEILINGS)
check("its hard ceiling is L2 (reversible act), not higher",
      ai.ACTION_CLASS_CEILINGS["alert_disposition"] == ai.L2_ACT_REVERSIBLE)


print("\n== HANDLERS MAY REQUIRE A CREDENTIAL, PASSED THROUGH context ==")
# The asymmetry that makes L2 possible for IP blocks: the ENGINE acts unattended
# (nemesis_fwd's PEER_POLICY makes the unattended peer structurally incapable of
# lifting a block), but an UNDO is initiated by a HUMAN who has a session. So a
# reversal that needs a credential is still a reversal.
seen = {}


def ctx_handler(p, context=None):
    seen["ctx"] = context
    if not (context or {}).get("credential"):
        return False, "requires an administrator credential"
    return True, "unblocked with credential"


ai.register_undo_handler("ip_block_permanent", ctx_handler)
pid_ip = ai.create_proposal("ip_block_permanent", "alerts", "192.88.99.7",
                            "block permanently", "test data 2026-08-21 undo path",
                            "claude-haiku-4-5")
ai.respond_to_proposal(pid_ip, "approved", "paul")
# `ip_block_permanent` became A2-gated on 2026-08-30 (LOCAL_APPROVAL_REQUIRED), so
# execute_proposal now refuses it without a verified admin approval. A minimal
# pre-verified record is supplied here rather than switching this scenario to a
# non-gated class: what this section tests is the UNDO path's context threading,
# and ip_block_permanent is the class whose undo actually requires a credential —
# the whole point of the scenario. A2's own verification is covered end-to-end in
# core/test_admin_approval_local.py; duplicating it here would test it twice and
# this behaviour zero times.
ai.execute_proposal(pid_ip, lambda p: (True, "blocked"),
                    approval={"proposal_id": pid_ip})

r = ai.undo_proposal(pid_ip, "paul")
check("undo FAILS when no credential is supplied", not r["ok"], r)
check("and it says a credential is required, explicitly",
      "credential" in r["error"], r)
check("the row is NOT marked undone", ai.get_proposal(pid_ip)["undone"] == 0)
check("CONTROL: the handler really was called (context was threaded)",
      "ctx" in seen, seen)

r = ai.undo_proposal(pid_ip, "paul", context={"credential": "s3cret",
                                              "actor": "paul"})
check("CONTROL: undo SUCCEEDS once a credential is supplied", r["ok"], r)
check("the credential reached the handler",
      (seen["ctx"] or {}).get("credential") == "s3cret", seen)
check("and the row is now marked undone", ai.get_proposal(pid_ip)["undone"] == 1)

print("\n== A ONE-ARG HANDLER STILL WORKS (back-compat) ==")
# Signature-inspected, not try/except TypeError -- catching TypeError would also
# swallow a genuine TypeError raised INSIDE a handler and silently retry it with
# fewer arguments, turning a real bug into a confusing second failure.
calls = []


def one_arg(p):
    calls.append(p["id"])
    return True, "reversed"


ai.register_undo_handler("ip_quarantine_external", one_arg)
pid_q = ai.create_proposal("ip_quarantine_external", "alerts", "192.88.99.8",
                           "quarantine", "test data 2026-08-21 undo path",
                           "claude-haiku-4-5")
ai.respond_to_proposal(pid_q, "approved", "paul")
ai.execute_proposal(pid_q, lambda p: (True, "quarantined"))
r = ai.undo_proposal(pid_q, "paul", context={"credential": "x"})
check("a legacy one-arg handler is called without the context", r["ok"], r)
check("CONTROL: it really ran", calls == [pid_q], calls)


def raises_typeerror(p, context=None):
    raise TypeError("a genuine bug inside the handler")


ai.register_undo_handler("ip_quarantine_external", raises_typeerror)
pid_q2 = ai.create_proposal("ip_quarantine_external", "alerts", "192.88.99.9",
                            "quarantine", "test data 2026-08-21 undo path",
                            "claude-haiku-4-5")
ai.respond_to_proposal(pid_q2, "approved", "paul")
ai.execute_proposal(pid_q2, lambda p: (True, "quarantined"))
r = ai.undo_proposal(pid_q2, "paul", context={"credential": "x"})
check("a TypeError INSIDE a handler surfaces as a failure, not a silent retry",
      not r["ok"] and "raised" in r["error"], r)
check("and that proposal is not marked undone",
      ai.get_proposal(pid_q2)["undone"] == 0)

print("\n== BOTH IP CLASSES ARE NOW REVERSIBLE (the readiness change) ==")
ai.register_undo_handler("ip_quarantine_external", ctx_handler)
for ac in ("ip_quarantine_external", "ip_block_permanent"):
    check("%s has a registered reversal" % ac, ai.undo_handler_for(ac) is not None)
    check("%s reports undo_available" % ac,
          ai.effective_ceiling(ac)["undo_available"] is True)
check("CONTROL: malware_file_quarantine still has none (capability ceiling)",
      ai.undo_handler_for("malware_file_quarantine") is None)

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
