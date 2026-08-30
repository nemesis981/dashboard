#!/usr/bin/env python3
"""AI authority ladder — the L1 propose/approve/execute loop, end to end.

Covers the wiring added 2026-08-30 (ARCHITECTURE.md Phase 3, taken out of order
to unblock ADR 0026 §D3 A2). The loop's four functions were complete and tested
with ZERO production callers; this suite exercises them THROUGH the routes and
the real forward executor, which is the part that did not exist.

WHAT IS ACTUALLY NEW HERE, and therefore what this tests:
  * the L1 branch that calls `create_proposal` (was documented, never written)
  * `_do_alert_disposition`, the first FORWARD executor of any class
  * the three routes, and that the executor is chosen SERVER-side
  * that the loop cannot self-start without a deliberate authority raise

Routes are driven through Flask's test client with the auth gates removed; the
role gate is `test_roles.py`'s assertion against ROUTE_MINIMUMS, not this
suite's. The bypass is explicit and asserted, so a passing run is never mistaken
for evidence the routes are safe unauthenticated.

Run:  python3 modules/ai_engine/test_proposal_loop.py
Exit: 0 all passed · 1 failure(s) · 3 harness could not establish its premise
"""

import os
import sys
import json
import sqlite3
import tempfile
import traceback

_PASS, _FAIL = [], []
EXPECTED_CHECKS = 29


def check(label, cond, detail=""):
    (_PASS if cond else _FAIL).append(label)
    print(("  [PASS] " if cond else "  [FAIL] ") + label
          + (("  -- " + str(detail)) if detail and not cond else ""))
    return bool(cond)


def _die(msg):
    print("\nHARNESS PRECONDITION FAILED: %s" % msg)
    sys.exit(3)


_TMP = tempfile.mkdtemp(prefix="nemesis-proploop-")
os.environ["NEMESIS_DB_PATH"] = os.path.join(_TMP, "test-alerts.db")

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for p in (_REPO, os.path.join(_REPO, "alert_manager"),
          os.path.join(_REPO, "core_module", "hw_monitor"), os.path.join(_REPO, "core")):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import modules as _modules_pkg
    _modules_pkg.set_shared_db_path(os.environ["NEMESIS_DB_PATH"])
    import dashboard
    from modules import ai_engine as ai
    from modules.ai_engine import module as aim
except Exception:
    traceback.print_exc()
    _die("could not import dashboard / ai_engine")

if _modules_pkg.get_shared_db_path() != os.environ["NEMESIS_DB_PATH"]:
    _die("module resolved a DB other than the throwaway one — refusing to run")

app = dashboard.app
app.config["TESTING"] = True
_removed = []
for fn in list(app.before_request_funcs.get(None, [])):
    if fn.__name__ in ("_enforce_setup_and_auth", "_enforce_session_realm", "_enforce_role"):
        app.before_request_funcs[None].remove(fn)
        _removed.append(fn.__name__)
if not _removed:
    _die("no auth gate found to bypass — handler names changed; a suite that "
         "bypasses nothing would be testing the redirect")
client = app.test_client()
if client.get("/api/ai/proposals").status_code in (301, 302):
    _die("auth gate still active — every assertion would describe a redirect")


def _db():
    return sqlite3.connect(os.environ["NEMESIS_DB_PATH"])


print("\n== PACKAGE EXPORTS: the five names the wiring needs ==")
for _n in ("create_proposal", "get_proposal", "list_proposals",
           "respond_to_proposal", "execute_proposal"):
    check("ai_engine package exports %s" % _n, hasattr(ai, _n))


print("\n== THE LOOP CANNOT SELF-START (documented, and true) ==")
# Promotion is the only writer of ai_authority, runs only on an approved response,
# and proposals only exist at L1 -- so an untouched install proposes nothing.
check("effective ceiling for alert_disposition starts at L0",
      aim.effective_ceiling("alert_disposition")["level"] == 0,
      aim.effective_ceiling("alert_disposition"))
check("CONTROL: its HARD ceiling permits L1 (so L0 is the earned floor, not a cap)",
      aim.ACTION_CLASS_CEILINGS["alert_disposition"] >= 1)


print("\n== PROPOSE: create_proposal writes a real row ==")
pid = ai.create_proposal("alert_disposition", "alert", "9999001", "ignore",
                         "synthetic LOW verdict for the loop test", "test-model")
check("create_proposal returns an id", isinstance(pid, int) and pid > 0, pid)
p = ai.get_proposal(pid)
check("the proposal is readable", p is not None and p["action_class"] == "alert_disposition", p)
check("it starts with NO human response", not p["human_response"], p["human_response"])
check("it starts NOT executed", not p["executed"], p["executed"])
try:
    ai.create_proposal("no_such_class", "alert", "1", "x", "y")
    check("CONTROL: an unknown action class RAISES", False, "accepted silently")
except Exception as exc:
    check("CONTROL: an unknown action class RAISES", "UnknownActionClass" in type(exc).__name__,
          type(exc).__name__)


print("\n== ROUTES: queue, decide, execute are three separate steps ==")
r = client.get("/api/ai/proposals?pending=1")
j = r.get_json() or {}
check("the queue lists the pending proposal", r.status_code == 200
      and any(x["id"] == pid for x in j.get("proposals", [])), j)

# Executing BEFORE approval must be refused -- deciding and doing are separate.
rx = client.post("/api/ai/proposal/%d/execute" % pid, json={})
check("executing an UNAPPROVED proposal is refused", rx.status_code == 409, rx.get_json())
check("  ...and the refusal says it is not approved",
      "not approved" in ((rx.get_json() or {}).get("error") or ""), rx.get_json())

rr = client.post("/api/ai/proposal/%d/respond" % pid, json={"response": "approved"})
check("approving succeeds", rr.status_code == 200 and (rr.get_json() or {}).get("ok"),
      rr.get_json())
rr2 = client.post("/api/ai/proposal/%d/respond" % pid, json={"response": "rejected"})
check("a SECOND decision is refused (first stands, audit trail intact)",
      rr2.status_code == 409, rr2.get_json())
check("bad response values are rejected as input errors",
      client.post("/api/ai/proposal/%d/respond" % pid,
                  json={"response": "maybe"}).status_code == 400)


print("\n== EXECUTE: the forward executor actually changes the alert ==")
conn = _db()
try:
    conn.execute("CREATE TABLE IF NOT EXISTS alerts (rule_id TEXT, action TEXT)")
    conn.execute("INSERT INTO alerts (rule_id, action) VALUES ('9999001','pending')")
    conn.commit()
finally:
    conn.close()

rex = client.post("/api/ai/proposal/%d/execute" % pid, json={})
check("execute succeeds once approved", rex.status_code == 200
      and (rex.get_json() or {}).get("ok"), rex.get_json())
conn = _db()
try:
    _act = conn.execute("SELECT action FROM alerts WHERE rule_id='9999001'").fetchone()[0]
finally:
    conn.close()
check("the alert was actually dispositioned", _act == "ignore", _act)
check("the proposal is now marked executed", ai.get_proposal(pid)["executed"] == 1)
check("re-executing is refused",
      client.post("/api/ai/proposal/%d/execute" % pid, json={}).status_code == 409)


print("\n== EXECUTOR SELECTION IS SERVER-SIDE, and fails closed ==")
check("the executor registry is keyed by action class, not caller input",
      "alert_disposition" in dashboard._PROPOSAL_EXECUTORS)
pid2 = ai.create_proposal("ip_action_internal", "alert", "9999002", "x", "y", "m")
client.post("/api/ai/proposal/%d/respond" % pid2, json={"response": "approved"})
rno = client.post("/api/ai/proposal/%d/execute" % pid2, json={})
check("a class with NO forward executor is refused, not no-opped",
      rno.status_code == 409 and "no forward executor" in
      ((rno.get_json() or {}).get("error") or ""), rno.get_json())
check("CONTROL: and that proposal is NOT marked executed",
      ai.get_proposal(pid2)["executed"] == 0)


print("\n== EXECUTOR HONESTY: it reports failure rather than a hollow success ==")
pid3 = ai.create_proposal("alert_disposition", "alert", "no-such-rule", "ignore", "y", "m")
client.post("/api/ai/proposal/%d/respond" % pid3, json={"response": "approved"})
r3 = client.post("/api/ai/proposal/%d/execute" % pid3, json={})
check("executing against a missing alert REPORTS failure", r3.status_code == 409, r3.get_json())
check("  ...and says nothing matched rather than claiming success",
      "no pending alert matched" in ((r3.get_json() or {}).get("error") or ""), r3.get_json())
check("CONTROL: a failed execution leaves the proposal NOT executed",
      ai.get_proposal(pid3)["executed"] == 0)


print("\n== TOTALS ==")
_total = len(_PASS) + len(_FAIL)
check("assertion count matches EXPECTED_CHECKS (drift is a defect)",
      _total + 1 == EXPECTED_CHECKS, "ran %d, expected %d" % (_total + 1, EXPECTED_CHECKS))

import shutil
shutil.rmtree(_TMP, ignore_errors=True)
print("\n%d passed, %d failed" % (len(_PASS), len(_FAIL)))
sys.exit(1 if _FAIL else 0)
