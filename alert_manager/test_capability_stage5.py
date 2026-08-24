#!/usr/bin/env python3
"""ADR 0026 §6 step 5 — the first REAL capability (`approve_enrollment`).

Until this landed, every capability declared an empty endpoint set, so the whole
learning gate changed no live behaviour: correct scaffolding, but a test written
against the shipped configuration would pass while proving nothing. This suite is
about the moment that stops being true.

What it proves, in order of how badly it would matter if wrong:

  * an unlock GRANTS the endpoints, and grants ONLY those, and only to sub_admin;
  * `assert_capabilities_sane()` catches a typo'd endpoint EVEN CALLED BARE --
    the gap this commit closes, pinned by a mutation rather than described;
  * every endpoint named resolves to a real route in `dashboard.py`;
  * `push_and_run` and `firewall_change` stay empty, for their own stated reasons.

Run: python3 alert_manager/test_capability_stage5.py
"""
import os
import re
import sys

ROOT = os.environ.get("NEMESIS_ROOT", "/opt/nemesis")
sys.path.insert(0, os.path.join(ROOT, "alert_manager"))
print("  [root] %s" % ROOT)

import roles as R                                                  # noqa: E402

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


CAP = "approve_enrollment"
EPS = ("api_agent_approve", "api_agent_revoke")


# ═══════════════════════════════════════════════════════════════════════════
print("\n== THE CAPABILITY IS REAL, AND THE OTHERS ARE STILL NOT ==")

check("%s is BUILT, not merely declared" % CAP,
      R.capability_state(CAP) == R.CAP_BUILT)
check("  ...covering exactly the approve/revoke pair",
      set(R.CAPABILITY_ROUTES[CAP]) == set(EPS), sorted(R.CAPABILITY_ROUTES[CAP]))
for other in ("push_and_run", "firewall_change"):
    check("%s remains DECLARED (deliberately empty)" % other,
          R.capability_state(other) == R.CAP_DECLARED)
check("no endpoint is claimed by two capabilities",
      len({e for eps in R.CAPABILITY_ROUTES.values() for e in eps})
      == sum(len(eps) for eps in R.CAPABILITY_ROUTES.values()))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== THE UNLOCK GRANTS THE ENDPOINTS (the point of step 5) ==")

for ep in EPS:
    check("sub_admin WITHOUT the unlock is refused %s" % ep,
          not R.may_with_unlocks(R.ROLE_SUB_ADMIN, [], ep, "POST"))
    check("sub_admin WITH the unlock is ALLOWED %s" % ep,
          R.may_with_unlocks(R.ROLE_SUB_ADMIN, [CAP], ep, "POST"))
    check("  admin is unaffected either way",
          R.may_with_unlocks(R.ROLE_ADMIN, [], ep, "POST"))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== AND GRANTS NOTHING ELSE ==")
#
# The failure that would not look like a failure: an unlock that quietly widens
# access beyond its own capability. Nothing about that shows up in the happy path.

check("does NOT open an unrelated admin route",
      not R.may_with_unlocks(R.ROLE_SUB_ADMIN, [CAP], "api_firewall_unblock", "POST"))
check("does NOT open settings",
      not R.may_with_unlocks(R.ROLE_SUB_ADMIN, [CAP], "settings_page", "POST"))
check("a DIFFERENT unlock does not open these endpoints",
      not R.may_with_unlocks(R.ROLE_SUB_ADMIN, ["firewall_change"], EPS[0], "POST"))
check("a plain USER is never elevated",
      not R.may_with_unlocks(R.ROLE_USER, [CAP], EPS[0], "POST"))
check("a VIEWONLY is never elevated",
      not R.may_with_unlocks(R.ROLE_VIEWONLY, [CAP], EPS[0], "POST"))
check("an unlock the user does not hold grants nothing",
      not R.may_with_unlocks(R.ROLE_SUB_ADMIN, [], EPS[0], "POST"))
check("safe-method behaviour is unchanged by the unlock",
      R.may_with_unlocks(R.ROLE_SUB_ADMIN, [CAP], EPS[0], "GET")
      == R.may_with_unlocks(R.ROLE_ADMIN, [], EPS[0], "GET"))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== D2 RULE 3: every covered endpoint is admin-only for unsafe methods ==")

for ep in EPS:
    entry = R.ROUTE_MINIMUMS.get(ep)
    check("%s is registered in ROUTE_MINIMUMS" % ep, entry is not None)
    if entry:
        check("  ...and its UNSAFE minimum is exactly admin", entry[1] == R.ROLE_ADMIN,
              repr(entry))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== THE BARE-INVOCATION GAP, PINNED BY MUTATION ==")
#
# `assert_capabilities_sane()` runs its url_map existence rule only when passed
# `endpoints=`. Called bare it used to compare a capability's endpoints against
# nothing at all, so a typo passed clean and read as a verified capability -- the
# `_AUTH_EXEMPT` shape: looks like coverage, protects nothing. Asserted here as a
# mutation, not described in a comment, so a regression fails a test.

_orig = dict(R.CAPABILITY_ROUTES)
try:
    R.CAPABILITY_ROUTES[CAP] = frozenset({"api_agent_approve_TYPO"})
    try:
        R.assert_capabilities_sane()
        check("MUTANT: a typo'd endpoint is caught even CALLED BARE", False,
              "it passed bare -- the gap is open again")
    except R.RoleError as exc:
        check("MUTANT: a typo'd endpoint is caught even CALLED BARE", True)
        check("  ...and the message names the offending endpoint",
              "api_agent_approve_TYPO" in str(exc), str(exc)[:90])
    # And with endpoints=, the url_map rule catches it too -- both paths, since
    # a fix that only worked one way would leave the other silently weak.
    try:
        R.assert_capabilities_sane(endpoints={"api_agent_approve", "api_agent_revoke"})
        check("MUTANT: also caught WITH endpoints=", False, "it passed")
    except R.RoleError:
        check("MUTANT: also caught WITH endpoints=", True)
finally:
    R.CAPABILITY_ROUTES.clear()
    R.CAPABILITY_ROUTES.update(_orig)

check("CONTROL: restored, and the shipped table passes bare",
      R.CAPABILITY_ROUTES == _orig and R.assert_capabilities_sane())

# A real endpoint that is NOT in the live url_map must still be caught when the
# map is supplied -- this is what the dashboard's startup call actually does.
try:
    R.assert_capabilities_sane(endpoints={"api_agent_approve"})
    check("a covered endpoint missing from the url_map is caught", False,
          "it passed")
except R.RoleError as exc:
    check("a covered endpoint missing from the url_map is caught",
          "api_agent_revoke" in str(exc), str(exc)[:90])


# ═══════════════════════════════════════════════════════════════════════════
print("\n== EVERY COVERED ENDPOINT RESOLVES TO A REAL ROUTE ==")
#
# Parsed from dashboard.py rather than trusting ROUTE_MINIMUMS, which is a
# hand-kept table and could agree with a typo. The dashboard's startup call uses
# the live url_map, which is stronger still; this is the offline equivalent.

_src = open(os.path.join(ROOT, "dashboard.py"), encoding="utf-8").read()
_decorated = set(re.findall(r'@app\.route\([^)]*\)\s*\n(?:@[^\n]+\n)*def (\w+)\(', _src))
check("parsed a PLAUSIBLE number of routes from dashboard.py (>=50)",
      len(_decorated) >= 50, "got %d" % len(_decorated))
for ep in EPS:
    check("%s is a real @app.route endpoint" % ep, ep in _decorated)
check("CONTROL: a deliberate typo does NOT resolve",
      "api_agent_approve_TYPO" not in _decorated)

# The startup wiring itself: passing `endpoints=` must not regress to a bare call.
check("dashboard.py calls assert_capabilities_sane with endpoints=, not bare",
      re.search(r"assert_capabilities_sane\(\s*\n?\s*endpoints=", _src) is not None)
check("  ...and builds that set from the live url_map",
      "app.url_map.iter_rules()" in _src)

# ═══════════════════════════════════════════════════════════════════════════
print("\n== THE QUIZ EXISTS, SO THE CAPABILITY IS EARNABLE AND NOT JUST BUILT ==")
#
# Endpoints alone would produce a capability reporting BUILT that nobody could
# ever earn: `record_unlock` refuses a capability whose quiz will not load, so the
# UI would offer training that errors. That is worse than DECLARED, and is exactly
# what ADR 0026 D2 rule 4 exists to prevent -- so the quiz is part of this commit,
# not a follow-up.

import quizzes as Q                                                # noqa: E402

try:
    _doc = Q.load(CAP)
    check("a quiz exists for %s and VALIDATES" % CAP, isinstance(_doc, dict))
except Exception as exc:                                           # noqa: BLE001
    _doc = None
    check("a quiz exists for %s and VALIDATES" % CAP, False, repr(exc))

if _doc:
    check("  it is listed by available()", CAP in Q.available(), repr(Q.available()))
    check("  it carries the pending-review marker (content is Window 1's, not final)",
          "PENDING WINDOW 3 REVIEW" in _doc.get("review_status", ""))
    check("  every question id is distinct (grading would be ambiguous otherwise)",
          len({q["id"] for q in _doc["questions"]}) == len(_doc["questions"]))

    _perfect = {q["id"]: q["correct"] for q in _doc["questions"]}
    _r = Q.grade(CAP, _perfect)
    check("a perfect paper scores %d and PASSES" % Q.PASS_MARK,
          _r.get("score") == Q.PASS_MARK and _r.get("passed") is True, repr(_r.get("score")))

    # One wrong must fail: the pass mark is 100, and a quiz that tolerates a wrong
    # answer on a capability like this is not a gate.
    _k = _doc["questions"][0]["id"]
    _one = dict(_perfect)
    _one[_k] = (_perfect[_k] + 1) % len(_doc["questions"][0]["options"])
    check("ONE wrong answer FAILS", not Q.grade(CAP, _one).get("passed"))
    check("answering NOTHING fails (a blank paper is not a pass)",
          not Q.grade(CAP, {}).get("passed"))
    check("effective_version resolves, so record_unlock will not refuse",
          isinstance(Q.effective_version(CAP), str) and "+" in Q.effective_version(CAP))

    # The property that makes Window 3's later review cheap: prose is not digested.
    _v_before = Q.effective_version(CAP, _doc)
    _edited = dict(_doc, title="Rewritten title", intro="Rewritten intro")
    _edited["questions"] = [dict(q, why="Rewritten explanation.") for q in _doc["questions"]]
    check("rewriting title/intro/why does NOT invalidate earned unlocks",
          Q.effective_version(CAP, _edited) == _v_before,
          "Window 3 can revise the wording without forcing a retake")
    _reworded = dict(_doc)
    _reworded["questions"] = [dict(_doc["questions"][0], prompt="Changed prompt?")] \
        + list(_doc["questions"][1:])
    check("  ...but changing a PROMPT does invalidate them (by design)",
          Q.effective_version(CAP, _reworded) != _v_before)


print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
