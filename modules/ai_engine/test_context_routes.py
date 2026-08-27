"""§4.5 review-surface routes: registration, RBAC, and real request handling.

⚠ THE OBVIOUS RBAC TEST IS WORTHLESS HERE, AND THAT IS THE POINT.
`roles.required_role()` FAILS CLOSED — an endpoint with no registry entry
resolves to ADMIN anyway. So "assert admin is required" passes identically
whether the entries were added or forgotten: an instrument that can only
produce one answer, reporting that answer as a measurement. Section 2 below
therefore tests REGISTRY MEMBERSHIP and carries an explicit control proving the
naive assertion is empty.

NO NETWORK, NO LIVE DB.
"""
import os
import sys
import tempfile

sys.path.insert(0, "/opt/nemesis")
sys.path.insert(0, "/opt/nemesis/alert_manager")

_TMPDB = os.path.join(tempfile.mkdtemp(prefix="l4routes-"), "t.db")

from flask import Flask                                        # noqa: E402
import modules_loader                                          # noqa: E402

app = Flask(__name__)
modules_loader.init(app, _TMPDB, "/opt/nemesis/modules")
modules_loader._load_all_enabled()

import roles                                                   # noqa: E402
from modules.ai_engine import context_store as cs              # noqa: E402

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s %s" % (label, detail))


EPS = {
    "module_ai_engine__route_context_learned": "GET",
    "module_ai_engine__route_context_revoke": "POST",
    "module_ai_engine__route_context_resolve": "POST",
}

print("-- 0. CONTROLS --")
check("throwaway DB, not the live one", "/var/lib/nemesis" not in _TMPDB)
real = {r.endpoint for r in app.url_map.iter_rules()}
check("the loader actually registered ai_engine routes",
      any("ai_engine" in e for e in real))

print("\n-- 1. all three routes REGISTER (the loader gate did not skip them) --")
for ep in EPS:
    check("%s is registered" % ep, ep in real)

print("\n-- 2. ⭐ RBAC: registry MEMBERSHIP, not just the resolved answer --")
for ep, method in EPS.items():
    check("%s has a REAL registry entry" % ep, ep in roles.ROUTE_MINIMUMS)
    check("...admin may call it", roles.may(roles.ROLE_ADMIN, ep, method))
    check("...user may NOT", not roles.may(roles.ROLE_USER, ep, method))
    check("...viewonly may NOT", not roles.may(roles.ROLE_VIEWONLY, ep, method))

_ghost = "module_ai_engine__route_this_does_not_exist"
check("⚠ CONTROL: a NONEXISTENT endpoint ALSO resolves to admin "
      "(so 'admin is required' alone proves nothing)",
      roles.required_role(_ghost) == roles.ROLE_ADMIN
      and _ghost not in roles.ROUTE_MINIMUMS)
check("⭐ ...which is exactly why section 2 asserts MEMBERSHIP instead",
      all(e in roles.ROUTE_MINIMUMS for e in EPS))

print("\n-- 2b. ⭐ the SUB-ADMIN UNLOCK PATH cannot reach these either --")
# Rank is only half of dashboard.py's _enforce_role. A sub-admin denied by rank
# gets a second chance if a CAPABILITY covers the endpoint. Testing rank alone
# would miss that entirely and report admin-only for a route a sub-admin can
# actually earn. Exercise the same two calls the gate makes, plus the capability
# lookup that gates its escape hatch.
for ep, method in EPS.items():
    check("no capability covers %s" % ep,
          roles.capability_for_endpoint(ep) is None,
          roles.capability_for_endpoint(ep))
    need = roles.required_role(ep, method)
    check("...gate pair: required_role=%s, at_least(sub_admin) is False" % need,
          need == roles.ROLE_ADMIN and not roles.at_least(roles.ROLE_SUB_ADMIN, need))

print("\n-- 2c. these endpoints do NOT trip the E-RBAC-002 drift branch --")
# dashboard.py records E-RBAC-002 for any endpoint absent from ROUTE_MINIMUMS.
# Absence would still DENY (fail-closed), so the access level would look correct
# while never having been decided by anyone. Membership is what makes it a
# decision rather than an accident.
for ep in EPS:
    check("%s is classified, so no drift is recorded" % ep,
          ep in roles.ROUTE_MINIMUMS)

print("\n-- 3. the READ side is admin too, deliberately --")
check("learned-context READ is admin, not a lower role",
      roles.required_role("module_ai_engine__route_context_learned", "GET")
      == roles.ROLE_ADMIN)

print("\n-- 4. routes actually SERVE (exercised, not just registered) --")
c = app.test_client()
CLS = "ip_action_external"
keep = cs.add_learned(CLS, "ip", "203.0.113.10", cs.RESTRICTIVE, cs.SCOPE_TRIGGER,
                      "scanner range, stay strict")
doomed = cs.add_learned(CLS, "ip", "203.0.113.11", cs.PERMISSIVE, cs.SCOPE_TRIGGER,
                        "temporary, will be revoked in this test")

r = c.get("/api/ai/context/learned")
check("GET learned returns 200", r.status_code == 200, r.status_code)
body = r.get_json()
check("...ok:True", body.get("ok") is True, body)
ids = {e["id"] for e in body["entries"]}
check("...and contains both entries", {keep, doomed} <= ids, ids)
check("...counts are reported", body["counts"]["total"] >= 2, body["counts"])

r = c.get("/api/ai/context/learned?action_class=nope_not_a_class")
check("filtering by action_class narrows the result",
      r.get_json()["entries"] == [], r.get_json()["entries"])

print("\n-- 5. revoke --")
r = c.post("/api/ai/context/revoke", json={"id": doomed})
check("revoke returns 200", r.status_code == 200, r.status_code)
check("...ok:True", r.get_json().get("ok") is True, r.get_json())
check("⭐ the revoked entry no longer influences decisions",
      doomed not in {e["id"] for e in
                     cs.retrieve(CLS, "ip", "203.0.113.11")["learned"]})
check("...but is still listed in the review surface (§4.4)",
      doomed in {e["id"] for e in
                 c.get("/api/ai/context/learned").get_json()["entries"]})

r = c.post("/api/ai/context/revoke", json={"id": doomed})
check("⭐ re-revoking is 404, NOT a cheerful no-op", r.status_code == 404,
      r.status_code)
check("...and says so", r.get_json().get("ok") is False, r.get_json())
r = c.post("/api/ai/context/revoke", json={})
check("missing id is 400", r.status_code == 400, r.status_code)
r = c.post("/api/ai/context/revoke", json={"id": "not-a-number"})
check("non-integer id is 400, not a 500", r.status_code == 400, r.status_code)

print("\n-- 6. §4.7 suspension resolution over HTTP --")
perm = cs.add_learned("malware_file_quarantine", "path", "/opt/app/x.bin",
                      cs.PERMISSIVE, cs.SCOPE_TRIGGER, "vendor binary, allow")
res = cs.install_baseline("2026.09", [
    {"action_class": "malware_file_quarantine", "trigger_type": "path",
     "trigger_key": "/opt/app/x.bin", "guidance": "compromised upstream"}])
check("CONTROL: the entry really is suspended before we resolve it",
      perm in res["suspended"], res)

r = c.post("/api/ai/context/suspension", json={"id": perm, "resolution": "sideways"})
check("an invalid resolution is 400", r.status_code == 400, r.status_code)
check("...and the message names the valid values",
      "kept" in r.get_json().get("error", ""), r.get_json())
r = c.post("/api/ai/context/suspension", json={"id": perm})
check("a MISSING resolution is 400 — there is no default (§4.7)",
      r.status_code == 400, r.status_code)

r = c.post("/api/ai/context/suspension", json={"id": perm, "resolution": "kept"})
check("resolving 'kept' returns 200", r.status_code == 200, r.status_code)
check("⭐ and the entry resumes influencing decisions",
      perm in {e["id"] for e in cs.retrieve(
          "malware_file_quarantine", "path", "/opt/app/x.bin")["learned"]})
r = c.post("/api/ai/context/suspension", json={"id": perm, "resolution": "kept"})
check("resolving an unsuspended entry is 404", r.status_code == 404, r.status_code)

print("\n-- 7. CSRF: a form-encoded POST is REFUSED, not merely ineffective --")
for path in ("/api/ai/context/revoke", "/api/ai/context/suspension"):
    r = c.post(path, data={"id": str(keep), "resolution": "kept"})
    check("%s refuses form-encoded with 415" % path, r.status_code == 415,
          r.status_code)
# \u2b50 This single check carries BOTH facts, and it must not be split into a
# second cosmetic one: a 200 here proves `keep` was STILL REVOCABLE, i.e. the
# form-encoded attempts above changed nothing -- AND that 415 is a real
# content-type gate rather than a blanket refusal. A companion line asserting
# "nothing changed" would have to hardcode True, which is a check that cannot
# fail. (Written, caught, and deleted twice in this session.)
check("\u2b50 CONTROL: JSON still works AND the form POSTs left the row untouched",
      c.post("/api/ai/context/revoke", json={"id": keep}).status_code == 200)

print("\n-- 8. no route mutates state on GET --")
for rule in app.url_map.iter_rules():
    if rule.endpoint in ("module_ai_engine__route_context_revoke",
                         "module_ai_engine__route_context_resolve"):
        check("%s is POST-only (GET-as-write is CSRF-triggerable)"
              % rule.endpoint, "GET" not in rule.methods, sorted(rule.methods))

print("\n-- 9. \u00a74.5 THE PAGE --")
PAGE_EP = "module_ai_engine__route_context_page"
check("the page route is registered", PAGE_EP in real)
check("...and has a REAL registry entry", PAGE_EP in roles.ROUTE_MINIMUMS)
check("...admin only", roles.required_role(PAGE_EP, "GET") == roles.ROLE_ADMIN
      and not roles.may(roles.ROLE_USER, PAGE_EP, "GET"))
check("...no capability unlocks it for sub_admin",
      roles.capability_for_endpoint(PAGE_EP) is None)
for rule in app.url_map.iter_rules():
    if rule.endpoint == PAGE_EP:
        check("...GET-only", sorted(rule.methods - {"HEAD", "OPTIONS"}) == ["GET"],
              sorted(rule.methods))

pr = c.get("/ai/context")
check("the page renders 200 text/html", pr.status_code == 200
      and pr.mimetype == "text/html", (pr.status_code, pr.mimetype))
page = pr.get_data(as_text=True)
check("...and is a real document", "<!DOCTYPE html>" in page and len(page) > 4000)

print("\n-- 10. \u2b50 XSS: admin_reasoning is the one free-text field, and it "
      "is displayed --")
EVIL = "<script>window.__pwned=1</script><img src=x onerror=alert(1)>"
evil_id = cs.add_learned(CLS, "ip", "203.0.113.66", cs.RESTRICTIVE,
                         cs.SCOPE_TRIGGER, EVIL)
# 1. The PAGE must not carry any entry data at all -- it fetches. One read path
#    to secure, not two.
page2 = c.get("/ai/context").get_data(as_text=True)
check("\u2b50 the page ships NO entry data (it fetches instead)",
      EVIL not in page2 and "203.0.113.66" not in page2)
# 2. The payload comes back as JSON DATA, where quoting is structural.
api = c.get("/api/ai/context/learned")
check("the payload round-trips through the API as data",
      any(e["admin_reasoning"] == EVIL for e in api.get_json()["entries"]))
# ⚠ MY FIRST VERSION OF THIS CHECK ASSERTED THE JSON BODY ESCAPES `<`. IT DOES
# NOT, AND THAT IS CORRECT. Flask stopped escaping `<`/`>`/`&` in JSON bodies
# (3.1 here) because the response is served as application/json, which browsers
# do not parse as markup. The grep was right; the EXPECTATION attached to it was
# wrong -- so assert the property that actually confers the safety.
check("⭐ the payload is served as application/json, NOT text/html "
      "(this is what makes a raw '<' inert, not escaping)",
      api.mimetype == "application/json", api.mimetype)
check("...so the raw payload IS present in the body, by design",
      "<script>" in api.get_data(as_text=True))
# 3. Structural: the renderer must never assign innerHTML.
#    \u26a0 A plain `"innerHTML" in page` check FAILS here -- the page carries a
#    COMMENT saying "textContent, never innerHTML". Fourth time this shape has
#    bitten in this repo. Check for the ASSIGNMENT, and exclude comment lines.
import re                                                       # noqa: E402
noncomment = [l for l in page2.splitlines() if not l.strip().startswith("//")]
check("\u2b50 the renderer NEVER assigns innerHTML",
      not re.search(r"\.innerHTML\s*=", "\n".join(noncomment)),
      [l.strip() for l in noncomment if "innerHTML" in l])
check("CONTROL: the page DOES mention innerHTML in a comment "
      "(so the exclusion above was real, not vacuous)",
      any("innerHTML" in l for l in page2.splitlines()))
check("...and it does use textContent", "textContent" in page2)
cs.revoke_learned(evil_id, "test-cleanup")

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
