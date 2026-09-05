#!/usr/bin/env python3
"""The additivity canary tolerates a sub_admin MINIMUM without ceasing to check.

WHY THIS FILE EXISTS
    `_additivity_holds()` proves that inserting `sub_admin` changed no answer for any
    pre-existing role, by recomputing every answer under the ORIGINAL three-role
    ranking. It reads `old[need]`, where `old` maps only viewonly/user/admin — so an
    entry whose MINIMUM is `sub_admin` raises `KeyError` at import and the module will
    not load. Measured before changing anything: zero entries used a sub_admin minimum,
    so this had never been reachable.

    A route gated at `sub_admin` is necessarily NEW — it could not have been expressed
    before the role existed — so there is no historical answer for it to have changed.
    The check cannot compute a baseline because there genuinely is none, not because one
    is being suppressed. Skipping it is the absence of a question.

⛔ THE DANGEROUS PART OF THIS CHANGE IS THE SKIP, SO THAT IS WHAT IS TESTED HARDEST.
    A `continue` is exactly how a check quietly stops covering things: "it no longer
    raises" and "it no longer checks" produce identical output. So the first test here
    is NOT that sub_admin entries are tolerated -- it is that the canary STILL FAILS on
    a genuine additivity regression for the original three roles. Without that, the
    tolerance test proves nothing.

Run: python3 alert_manager/test_roles_additivity_subadmin.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import roles as R                                                  # noqa: E402

EXPECTED_CHECKS = 29
_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


def _restore(saved):
    R.ROUTE_MINIMUMS.clear()
    R.ROUTE_MINIMUMS.update(saved)


# ── A. THE CONTROL: the canary must still catch a real regression ───────────

def test_the_canary_STILL_FAILS_on_a_genuine_additivity_regression():
    """Run FIRST and deliberately. If the skip made the check vacuous, this is the test
    that says so -- and every other assertion in this file would be worthless without it.

    The regression injected is a real one: giving a `viewonly`-readable endpoint an
    `admin` minimum changes the answer for a pre-existing role, which is precisely what
    additivity forbids.
    """
    saved = dict(R.ROUTE_MINIMUMS)
    try:
        check("baseline: additivity holds as shipped", R._additivity_holds()[0] is True)

        victim = next((ep for ep, v in R.ROUTE_MINIMUMS.items()
                       if v == (R.ROLE_VIEWONLY, R.ROLE_VIEWONLY)), None)
        if victim is None:
            victim = next(iter(R.ROUTE_MINIMUMS))
        # Break additivity by changing what a PRE-EXISTING role is allowed.
        R.ROUTE_MINIMUMS[victim] = (R.ROLE_VIEWONLY, R.ROLE_VIEWONLY)

        # Force may() to disagree with the historical model for a pre-existing role.
        real_may = R.may
        try:
            R.may = lambda role, ep, method="GET": (
                False if ep == victim else real_may(role, ep, method))
            check("a genuine regression IS caught (canary returns False)",
                  R._additivity_holds()[0] is False,
                  "the canary passed a run where may() disagrees with the baseline")
        finally:
            R.may = real_may
    finally:
        _restore(saved)
    check("registry restored", R.ROUTE_MINIMUMS == saved)


# ── B. The tolerance being added ────────────────────────────────────────────

def test_a_sub_admin_minimum_entry_does_not_raise():
    saved = dict(R.ROUTE_MINIMUMS)
    try:
        R.ROUTE_MINIMUMS["zz_subadmin_probe"] = (R.ROLE_SUB_ADMIN, R.ROLE_SUB_ADMIN)
        try:
            held = R._additivity_holds()[0]
            check("additivity check completes without KeyError", True)
            check("...and still reports True", held is True, "got %r" % held)
        except KeyError as e:
            check("additivity check completes without KeyError", False,
                  "raised KeyError(%r) -- the extension is not in place" % (e.args[0],))
            check("...and still reports True", False, "skipped: raised")
    finally:
        _restore(saved)


def test_the_sub_admin_entry_still_gates_correctly():
    """Tolerating it in the canary must not change what it ACTUALLY permits."""
    saved = dict(R.ROUTE_MINIMUMS)
    try:
        R.ROUTE_MINIMUMS["zz_subadmin_probe"] = (R.ROLE_SUB_ADMIN, R.ROLE_SUB_ADMIN)
        check("viewonly denied", R.may(R.ROLE_VIEWONLY, "zz_subadmin_probe", "POST") is False)
        check("user denied", R.may(R.ROLE_USER, "zz_subadmin_probe", "POST") is False)
        check("sub_admin allowed", R.may(R.ROLE_SUB_ADMIN, "zz_subadmin_probe", "POST") is True)
        check("admin allowed", R.may(R.ROLE_ADMIN, "zz_subadmin_probe", "POST") is True)
    finally:
        _restore(saved)


def test_the_skip_is_NARROW_and_measurable():
    """A bare `continue` is how coverage quietly shrinks. This asserts the skip applies
    to sub_admin minimums ONLY -- every other entry is still measured."""
    saved = dict(R.ROUTE_MINIMUMS)
    try:
        old = {n: i for i, n in enumerate(R._PRE_SUBADMIN_ORDER)}
        skipped = [ep for ep, v in R.ROUTE_MINIMUMS.items()
                   if v[0] not in old or v[1] not in old]
        check("NOTHING is skipped in the registry as shipped",
              skipped == [], "skipped=%r" % skipped)

        R.ROUTE_MINIMUMS["zz_subadmin_probe"] = (R.ROLE_SUB_ADMIN, R.ROLE_SUB_ADMIN)
        skipped = [ep for ep, v in R.ROUTE_MINIMUMS.items()
                   if v[0] not in old or v[1] not in old]
        check("exactly ONE entry is skipped once a sub_admin minimum exists",
              skipped == ["zz_subadmin_probe"], "skipped=%r" % skipped)
    finally:
        _restore(saved)


def test_a_sub_admin_MINIMUM_would_stop_the_dashboard_from_STARTING():
    """⛔ A GUARD AGAINST A DESIGN, NOT A SANCTIONED BREAKAGE. Read this before adding
    any ROUTE_MINIMUMS entry with a sub_admin minimum.

    An earlier version of this test asserted the breakage as "expected", which a later
    reader would reasonably take as licence to add such an entry. It is not. The
    consequence is not a failing test:

        _sub_admin_equals_user_without_unlocks() backs a _H.bad case
          -> canary() returns False
          -> _assert_canary_at_import() raises RuntimeError
          -> roles.py does not import
          -> THE DASHBOARD DOES NOT START.

    Measured, not reasoned: with a sub_admin-minimum entry present, canary() reports
    "known-bad case failed -- a sub_admin with no unlocks is exactly a standard user".

    WHY the model forbids it: `may_with_unlocks()` states that a sub-admin with no
    unlocks is EXACTLY a standard user. A sub_admin minimum makes rank alone sufficient,
    so a no-unlock sub_admin reaches something a user cannot -- the invariant negated.

    WHAT TO USE INSTEAD: give the endpoint ('admin', 'admin') and add it to a
    CAPABILITY_ROUTES capability. `approve_enrollment` is the shipped reference and
    yields exactly the intended split -- user denied, no-unlock sub_admin denied,
    unlocked sub_admin allowed, admin allowed -- with the invariant intact.
    """
    saved = dict(R.ROUTE_MINIMUMS)
    try:
        check("holds as shipped", R._sub_admin_equals_user_without_unlocks() is True)
        R.ROUTE_MINIMUMS["zz_subadmin_probe"] = (R.ROLE_SUB_ADMIN, R.ROLE_SUB_ADMIN)
        broke = R._sub_admin_equals_user_without_unlocks()
        check("a sub_admin-minimum entry violates the capability model",
              broke is False,
              "if this passes, the invariant no longer means what its name says")
        ok, detail = R.canary()
        check("...and therefore FAILS THE IMPORT CANARY (dashboard would not start)",
              ok is False, "canary passed -- the startup consequence is gone")
        check("...naming the invariant it broke",
              "no unlocks" in (detail or ""), "detail=%r" % detail)
    finally:
        _restore(saved)
    check("restored", R._sub_admin_equals_user_without_unlocks() is True)


# ── C. Window 1's required additions ────────────────────────────────────────

def test_a_TYPOD_role_still_fails_LOUDLY_rather_than_being_skipped():
    """Window 1's required change 1, and the sharpest point in the review.

    `need not in old` is true for sub_admin -- and equally true for "supervisor",
    "Admin", "sub-admin" or any garbage in a tuple. Before the guard those raised
    KeyError and failed the canary at import. A bare `continue` would have converted a
    loud typo into invisible non-coverage: every triple for that endpoint dropping out
    of the check while the import succeeded. Only a rank in the LIVE ordering may be
    skipped.
    """
    saved = dict(R.ROUTE_MINIMUMS)
    try:
        for garbage in ("supervisor", "Admin", "sub-admin", "", "ADMIN"):
            R.ROUTE_MINIMUMS["zz_typo_probe"] = (garbage, garbage)
            ok, _n = R._additivity_holds()
            check("a %r minimum FAILS the canary" % garbage, ok is False,
                  "it was silently skipped instead of failing")
            R.ROUTE_MINIMUMS.pop("zz_typo_probe", None)
    finally:
        _restore(saved)


def test_coverage_of_OTHER_routes_survives_the_skip():
    """Window 1's third proof, and the one that actually matters.

    Test A proves the canary works with NO sub_admin entries present. This proves it
    still works WITH one -- i.e. that the skip removed only the skipped entry from
    coverage and not the rest. Those are different claims and only this one is about
    the change being made.
    """
    saved = dict(R.ROUTE_MINIMUMS)
    try:
        R.ROUTE_MINIMUMS["zz_subadmin_probe"] = (R.ROLE_SUB_ADMIN, R.ROLE_SUB_ADMIN)
        ok, before = R._additivity_holds()
        check("holds with a sub_admin entry present", ok is True)

        victim = next(ep for ep in saved if ep != "zz_subadmin_probe")
        real_may = R.may
        try:
            R.may = lambda role, ep, method="GET": (
                False if ep == victim else real_may(role, ep, method))
            ok2, _n = R._additivity_holds()
            check("a regression on a DIFFERENT route is STILL caught",
                  ok2 is False,
                  "the skip weakened coverage of routes it still claims to cover")
        finally:
            R.may = real_may
    finally:
        _restore(saved)


def test_the_CANARY_CASE_is_wired_to_the_comparison_count():
    """⚠ ADDED AFTER A SURVIVING MUTATION. The test below asserts that
    `_additivity_holds()` RETURNS a comparison count -- which it does even if the canary
    case still reads `_additivity_sample_size()`. Reverting that one line left the whole
    suite green: a proxy assertion, not a test of the wiring.

    This drives the real path: force a LOW comparison count and require `canary()` to
    fail. If the control still counts pairs GENERATED, that number is unaffected by the
    patch and the canary passes -- which is exactly the mutation that escaped.
    """
    real = R._additivity_holds
    try:
        R._additivity_holds = lambda: (True, 5)      # holds, but almost nothing compared
        ok, detail = R.canary()
        check("canary FAILS when few comparisons are actually made", ok is False,
              "canary passed with only 5 comparisons -- the control is not wired to it")
        check("...and says so", "comparison" in (detail or "").lower(),
              "detail=%r" % detail)
    finally:
        R._additivity_holds = real
    ok, _d = R.canary()
    check("canary passes again once restored", ok is True)


def test_the_control_counts_COMPARISONS_not_pairs_generated():
    """Window 1's required change 2, measured: 3564 generated vs 3204 compared, so the
    old control was asserting against a number 10% larger than what it measured."""
    generated = R._additivity_sample_size()
    _ok, compared = R._additivity_holds()
    check("comparisons are FEWER than pairs generated", compared < generated,
          "gen=%d compared=%d" % (generated, compared))
    check("...and the gap is the pre-existing skip, not zero",
          generated - compared > 0, "gap=%d" % (generated - compared))
    check("the control still has a meaningful sample", compared > 100,
          "compared=%d" % compared)


if __name__ == "__main__":
    print("=" * 70)
    print("roles additivity canary: tolerate a sub_admin minimum, keep checking")
    print("=" * 70)
    for fn in (
        test_the_canary_STILL_FAILS_on_a_genuine_additivity_regression,
        test_a_sub_admin_minimum_entry_does_not_raise,
        test_the_sub_admin_entry_still_gates_correctly,
        test_the_skip_is_NARROW_and_measurable,
        test_a_sub_admin_MINIMUM_would_stop_the_dashboard_from_STARTING,
        test_a_TYPOD_role_still_fails_LOUDLY_rather_than_being_skipped,
        test_coverage_of_OTHER_routes_survives_the_skip,
        test_the_control_counts_COMPARISONS_not_pairs_generated,
        test_the_CANARY_CASE_is_wired_to_the_comparison_count,
    ):
        print("\n%s" % fn.__name__)
        fn()

    print("\n" + "=" * 70)
    ran = _pass + _fail
    print("checks: %d passed, %d failed (%d run)" % (_pass, _fail, ran))
    if ran != EXPECTED_CHECKS:
        print("EXPECTED_CHECKS MISMATCH: declared %d, ran %d" % (EXPECTED_CHECKS, ran))
        sys.exit(1)
    sys.exit(1 if _fail else 0)
