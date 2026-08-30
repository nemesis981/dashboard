"""A capability naming a DISABLED module's route must not crash the dashboard.

REGRESSION TEST FOR A LIVE OUTAGE, 2026-08-30. `assert_capabilities_sane` treated
any capability endpoint absent from the live `app.url_map` as a typo and raised
`RoleError` at startup. But module routes only register when their module is
ENABLED, and `email_security` ships `enabled_by_default: false` -- so
`enroll_email_account` naming `module_email_security_api_enroll_create` (a name
that is CORRECT and matches at all three registration sites) killed the dashboard
on every boot. Confirmed crash-loop, 8 restarts, 100% failure.

The fix must not weaken what the rule exists for, so this file pins BOTH
directions: the dormant case is tolerated, and every genuinely broken case still
raises. The controls are the point -- a fix that made the check permissive would
pass a test that only asserted "no longer crashes".
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import roles as R

_fail = []
_count = 0
EXPECTED_CHECKS = 13


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-66s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def raises(**kw):
    try:
        R.assert_capabilities_sane(**kw)
        return None
    except R.RoleError as e:
        return str(e)


# A url_map with every CORE endpoint registered and NO module routes -- exactly
# the shape of a box where the optional modules are switched off.
CORE_ONLY = {e for e in R.ROUTE_MINIMUMS if not e.startswith("module_")}


def test_dormant_is_tolerated():
    print("\n[a correctly-named route from a DISABLED module must not crash startup]")
    R._dormant_capabilities.clear()
    check("no exception with module routes absent", raises(endpoints=CORE_ONLY), None)
    check("the real live capability is recorded as dormant",
          "enroll_email_account" in R._dormant_capabilities, True)
    check("...naming the exact endpoint that took the dashboard down",
          R._dormant_capabilities.get("enroll_email_account"),
          ["module_email_security_api_enroll_create"])
    check("CONTROL: that endpoint really is absent from the map we passed",
          "module_email_security_api_enroll_create" in CORE_ONLY, False)
    check("CONTROL: and it really IS a registered route name",
          "module_email_security_api_enroll_create" in R.ROUTE_MINIMUMS, True)


def test_typos_are_still_fatal():
    print("\n[the protection the rule exists for is NOT weakened]")
    orig = dict(R.CAPABILITY_ROUTES)
    try:
        R.CAPABILITY_ROUTES["enroll_email_account"] = frozenset(
            {"module_email_security_api_TYPO"})
        err = raises(endpoints=CORE_ONLY)
        check("a misspelled MODULE endpoint still raises", err is not None, True)
        check("...and the message names it", "TYPO" in (err or ""), True)

        R.CAPABILITY_ROUTES["enroll_email_account"] = frozenset({"api_totally_made_up"})
        err = raises(endpoints=CORE_ONLY)
        check("a misspelled CORE endpoint still raises", err is not None, True)
    finally:
        R.CAPABILITY_ROUTES.clear()
        R.CAPABILITY_ROUTES.update(orig)


def test_missing_core_route_still_fatal():
    print("\n[a CORE route always registers, so its absence is a real defect]")
    # Pick a CORE endpoint that some capability actually covers. Not
    # `next(iter(...))` -- a capability may cover only module routes (or none),
    # and picking blind gave an IndexError that would have read as a code defect.
    victim = next((ep for eps in R.CAPABILITY_ROUTES.values() for ep in sorted(eps)
                   if not ep.startswith("module_")), None)
    check("CONTROL: found a core endpoint that a capability covers",
          victim is not None, True)
    err = raises(endpoints=CORE_ONLY - {victim})
    check("removing a covered core endpoint raises", err is not None, True)
    check("...and names it", victim in (err or ""), True)


def test_bare_call_unchanged():
    print("\n[the bare call keeps its own strictness -- unchanged by this fix]")
    check("bare call still passes on a sane table",
          R.assert_capabilities_sane(), True)
    orig = dict(R.CAPABILITY_ROUTES)
    try:
        R.CAPABILITY_ROUTES["enroll_email_account"] = frozenset({"module_nope_api_nope"})
        check("bare call still catches a name absent from ROUTE_MINIMUMS",
              raises() is not None, True)
    finally:
        R.CAPABILITY_ROUTES.clear()
        R.CAPABILITY_ROUTES.update(orig)


if __name__ == "__main__":
    print("roles -- dormant capability (disabled module) regression")
    test_dormant_is_tolerated()
    test_typos_are_still_fatal()
    test_missing_core_route_still_fatal()
    test_bare_call_unchanged()
    print()
    if _count != EXPECTED_CHECKS:
        print("SUITE DRIFT: ran %d checks, expected %d" % (_count, EXPECTED_CHECKS))
        sys.exit(1)
    if _fail:
        print("FAILED (%d of %d)" % (len(_fail), _count))
        for f in _fail:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS (%d checks)" % _count)
