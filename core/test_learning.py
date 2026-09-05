#!/usr/bin/env python3
"""Learning Center — the ceiling, the entitlement, and one-shot seeding.

⛔ THE TEST THAT MATTERS MOST IS #1, AND IT IS THE ONE A HAPPY-PATH SUITE OMITS.
    A user who HOLDS a valid entitlement must stop seeing a topic the moment it flips
    to `not_included`. If the ceiling were resolved at grant time instead of on every
    read, that user would keep reading it forever -- and the feature would still look
    correct, because new users would correctly get nothing. The global control would
    be silently broken for precisely the population it was reached for.

⛔ FAIL-CLOSED IS ASSERTED, NOT ASSUMED.
    An unrecognised stored state and an unconfigured topic both resolve to invisible.
    A value nobody can interpret must not mean "show everyone", and content that ships
    with core unconditionally must not appear because nobody configured it yet.

⛔ SEEDING IS ONE-SHOT, AND THE TEST IS ABOUT REVOCATION SURVIVING.
    Re-seeding would re-grant a topic an admin deliberately revoked. Overriding a
    decision made on purpose is worse than never seeding, so the assertion is not
    "seeding is idempotent" but "a revoked topic stays revoked through a second
    assignment".

Run: python3 core/test_learning.py
"""
import os
import sqlite3
import sys
import tempfile

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (_REPO, os.path.join(_REPO, "alert_manager"), os.path.join(_REPO, "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import learning as L                                               # noqa: E402

EXPECTED_CHECKS = 49
_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


def eq(label, got, want):
    """Value comparison, deliberately a SEPARATE name from check().

    check() takes a boolean; eq() takes got/want. Both harness shapes exist in this
    repo and mixing them is silent: `check("x", value, expected)` passes `expected`
    as the unused `detail` argument and asserts only that `value` is TRUTHY -- so a
    wrong value passes whenever it is non-empty, and an empty-but-correct value fails.
    Both happened here before this split.
    """
    global _pass, _fail
    if got == want:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s: got %r, want %r" % (label, got, want))


def raises(exc, fn):
    try:
        fn()
        return False
    except exc:
        return True
    except Exception:
        return False


def fresh_db():
    """A DB with the real DDL, created the way production creates it."""
    path = os.path.join(tempfile.mkdtemp(prefix="learn-"), "alerts.db")
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE learning_topic_visibility (
            topic_slug TEXT PRIMARY KEY,
            state      TEXT NOT NULL DEFAULT 'not_included',
            in_default INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            actor      TEXT);
        CREATE TABLE learning_entitlements (
            user_id    INTEGER NOT NULL,
            topic_slug TEXT NOT NULL,
            granted_at TEXT NOT NULL,
            actor      TEXT,
            PRIMARY KEY (user_id, topic_slug));
        CREATE TABLE learning_seed_log (
            user_id   INTEGER PRIMARY KEY,
            seeded_at TEXT NOT NULL);
    """)
    conn.commit()
    conn.close()
    return path


# ── A. The ceiling ───────────────────────────────────────────────────────────

def test_not_included_beats_a_valid_entitlement():
    """THE test. A held entitlement must not survive the topic being withdrawn."""
    db = fresh_db()
    L.set_topic_state("t1", L.STATE_ALL_USERS, db_path=db)
    L.grant(7, "t1", db_path=db)
    check("baseline: an entitled user CAN see an all_users topic",
          L.visible_to(7, "user", "t1", db_path=db) is True)

    L.set_topic_state("t1", L.STATE_NOT_INCLUDED, db_path=db)
    check("the entitlement row still exists", L.has_entitlement(7, "t1", db_path=db))
    check("...but the topic is NO LONGER visible to them",
          L.visible_to(7, "user", "t1", db_path=db) is False)
    check("not_included hides it from an ADMIN too",
          L.visible_to(1, "admin", "t1", db_path=db) is False)
    check("and from sub_admin", L.visible_to(2, "sub_admin", "t1", db_path=db) is False)


def test_admin_only():
    db = fresh_db()
    L.set_topic_state("t2", L.STATE_ADMIN_ONLY, db_path=db)
    L.grant(7, "t2", db_path=db)
    check("admin sees an admin_only topic",
          L.visible_to(1, "admin", "t2", db_path=db) is True)
    check("admin needs NO entitlement for it",
          L.visible_to(99, "admin", "t2", db_path=db) is True)
    check("a user does NOT, even holding an entitlement",
          L.visible_to(7, "user", "t2", db_path=db) is False)
    check("sub_admin does not either",
          L.visible_to(2, "sub_admin", "t2", db_path=db) is False)


def test_all_users_requires_both_role_and_entitlement():
    db = fresh_db()
    L.set_topic_state("t3", L.STATE_ALL_USERS, db_path=db)
    L.grant(7, "t3", db_path=db)
    check("entitled user: visible", L.visible_to(7, "user", "t3", db_path=db) is True)
    check("un-entitled user: NOT visible",
          L.visible_to(8, "user", "t3", db_path=db) is False)
    check("entitled sub_admin: visible (user-and-above)",
          L.visible_to(7, "sub_admin", "t3", db_path=db) is True)


def test_viewonly_is_excluded_from_all_users():
    """Operator decision 2026-09-05: 'all users' means user-and-above, not viewonly."""
    db = fresh_db()
    L.set_topic_state("t4", L.STATE_ALL_USERS, db_path=db)
    L.grant(9, "t4", db_path=db)
    check("viewonly does NOT count as 'all users', even entitled",
          L.visible_to(9, "viewonly", "t4", db_path=db) is False)
    check("...while the same user at 'user' role does",
          L.visible_to(9, "user", "t4", db_path=db) is True)


# ── B. Fail-closed ───────────────────────────────────────────────────────────

def test_an_unconfigured_topic_is_invisible():
    """Content ships with core unconditionally; 'nobody configured it' must mean hidden."""
    db = fresh_db()
    L.grant(7, "ghost", db_path=db)
    eq("no visibility row at all -> not_included",
          L.topic_state("ghost", db_path=db), L.STATE_NOT_INCLUDED)
    check("...and therefore invisible even to an entitled user",
          L.visible_to(7, "ghost", "ghost", db_path=db) is False)
    check("and invisible to an admin",
          L.visible_to(1, "admin", "ghost", db_path=db) is False)


def test_a_corrupt_state_fails_closed():
    db = fresh_db()
    L.set_topic_state("t5", L.STATE_ALL_USERS, db_path=db)
    L.grant(7, "t5", db_path=db)
    conn = sqlite3.connect(db)
    conn.execute("UPDATE learning_topic_visibility SET state='nonsense' "
                 "WHERE topic_slug='t5'")
    conn.commit()
    conn.close()
    eq("an unrecognised state normalises to not_included",
          L.topic_state("t5", db_path=db), L.STATE_NOT_INCLUDED)
    check("...so it is invisible rather than open",
          L.visible_to(7, "user", "t5", db_path=db) is False)
    eq("normalise_state is total and safe", L.normalise_state(None),
          L.STATE_NOT_INCLUDED)
    eq("...including for a bogus string", L.normalise_state("whatever"),
          L.STATE_NOT_INCLUDED)


def test_a_bad_state_is_refused_on_the_WAY_IN():
    """Writers raise; readers normalise. A typo must not be storable and then silently
    reinterpreted -- it should fail where it enters."""
    db = fresh_db()
    check("validate_state raises on a typo",
          raises(L.LearningError, lambda: L.validate_state("all_user")))
    check("set_topic_state refuses it",
          raises(L.LearningError,
                 lambda: L.set_topic_state("t6", "all_user", db_path=db)))
    eq("and nothing was written", L.topic_state("t6", db_path=db),
          L.STATE_NOT_INCLUDED)


def test_an_unknown_role_proves_nothing():
    db = fresh_db()
    L.set_topic_state("t7", L.STATE_ALL_USERS, db_path=db)
    L.grant(7, "t7", db_path=db)
    check("an unrecognised role is refused, not ranked",
          L.visible_to(7, "wizard", "t7", db_path=db) is False)


# ── C. Index and detail cannot disagree ──────────────────────────────────────

def test_the_index_filter_uses_the_same_decision_as_the_detail_check():
    """A list that filters while the detail route does not enforce is reachable by
    typing the URL, and every test of the visible path passes against that bug."""
    db = fresh_db()
    L.set_topic_state("vis", L.STATE_ALL_USERS, db_path=db)
    L.set_topic_state("hid", L.STATE_NOT_INCLUDED, db_path=db)
    L.grant(7, "vis", db_path=db)
    L.grant(7, "hid", db_path=db)
    shown = L.visible_topics(7, "user", ["vis", "hid"], db_path=db)
    eq("index shows only the permitted topic", shown, ["vis"])
    for slug in ("vis", "hid"):
        check("index and detail agree on %r" % slug,
              (slug in shown) == L.visible_to(7, "user", slug, db_path=db))


# ── D. Seeding ───────────────────────────────────────────────────────────────

def test_seeding_grants_the_default_set_once():
    db = fresh_db()
    for s in ("d1", "d2"):
        L.set_topic_state(s, L.STATE_ALL_USERS, db_path=db)
        L.set_in_default(s, True, db_path=db)
    L.set_topic_state("nd", L.STATE_ALL_USERS, db_path=db)   # not in the default set

    granted = L.seed_user(7, db_path=db)
    eq("the default set is granted", granted, ["d1", "d2"])
    check("a non-default topic is NOT granted",
          L.has_entitlement(7, "nd", db_path=db) is False)
    check("the user is recorded as seeded", L.has_been_seeded(7, db_path=db) is True)


def test_a_revoked_topic_is_not_re_granted_by_a_second_seed():
    """The real point of the seed log: never override a deliberate revocation."""
    db = fresh_db()
    L.set_topic_state("d1", L.STATE_ALL_USERS, db_path=db)
    L.set_in_default("d1", True, db_path=db)
    L.seed_user(7, db_path=db)
    L.revoke(7, "d1", db_path=db)
    check("admin revoked it", L.has_entitlement(7, "d1", db_path=db) is False)

    again = L.seed_user(7, db_path=db)
    eq("a second seed grants nothing", again, [])
    check("and the revocation SURVIVES",
          L.has_entitlement(7, "d1", db_path=db) is False)


def test_seeding_is_recorded_even_when_the_default_set_is_empty():
    """Otherwise a user seeded while the set was empty is seeded again later -- the
    same override bug, arriving slowly."""
    db = fresh_db()
    eq("empty default set grants nothing", L.seed_user(7, db_path=db), [])
    check("but the user IS marked seeded", L.has_been_seeded(7, db_path=db) is True)
    L.set_topic_state("late", L.STATE_ALL_USERS, db_path=db)
    L.set_in_default("late", True, db_path=db)
    eq("a later seed still grants nothing", L.seed_user(7, db_path=db), [])
    check("...and the late topic was not back-granted",
          L.has_entitlement(7, "late", db_path=db) is False)


# ── E. Preview / apply ───────────────────────────────────────────────────────

def test_preview_writes_nothing():
    db = fresh_db()
    L.set_topic_state("d1", L.STATE_ALL_USERS, db_path=db)
    L.set_in_default("d1", True, db_path=db)
    before = L.user_entitlements(7, db_path=db)
    plan = L.preview_apply_defaults([7], db_path=db)
    eq("preview reports what would change", plan, {7: ["d1"]})
    eq("...and changed NOTHING", L.user_entitlements(7, db_path=db), before)
    check("specifically, no entitlement appeared",
          L.has_entitlement(7, "d1", db_path=db) is False)


def test_apply_is_additive_and_never_revokes():
    db = fresh_db()
    L.set_topic_state("d1", L.STATE_ALL_USERS, db_path=db)
    L.set_in_default("d1", True, db_path=db)
    L.set_topic_state("extra", L.STATE_ALL_USERS, db_path=db)
    L.grant(7, "extra", db_path=db)          # an individual, non-default assignment

    applied = L.apply_defaults([7], db_path=db)
    eq("the missing default was granted", applied, {7: ["d1"]})
    check("d1 is now held", L.has_entitlement(7, "d1", db_path=db) is True)
    check("THE INDIVIDUAL GRANT SURVIVED",
          L.has_entitlement(7, "extra", db_path=db) is True)

    again = L.apply_defaults([7], db_path=db)
    eq("re-applying is a no-op", again, {})


def test_apply_does_not_bypass_the_seed_log_or_the_ceiling():
    """apply_defaults is the admin's explicit action, so it MAY grant a user who was
    already seeded -- that is its purpose. The ceiling still applies at read time."""
    db = fresh_db()
    L.set_topic_state("d1", L.STATE_NOT_INCLUDED, db_path=db)
    L.set_in_default("d1", True, db_path=db)
    L.apply_defaults([7], db_path=db)
    check("apply granted the entitlement", L.has_entitlement(7, "d1", db_path=db) is True)
    check("but the topic is still not visible (ceiling holds)",
          L.visible_to(7, "user", "d1", db_path=db) is False)


# ── F. Selftest ──────────────────────────────────────────────────────────────

def test_selftest():
    db = fresh_db()
    ok, detail = L.selftest(db)
    check("selftest passes on a healthy build", ok is True, detail)
    check("and returns a detail string", isinstance(detail, str))


if __name__ == "__main__":
    print("=" * 70)
    print("Learning Center -- ceiling, entitlement, one-shot seeding")
    print("=" * 70)
    for fn in (
        test_not_included_beats_a_valid_entitlement,
        test_admin_only,
        test_all_users_requires_both_role_and_entitlement,
        test_viewonly_is_excluded_from_all_users,
        test_an_unconfigured_topic_is_invisible,
        test_a_corrupt_state_fails_closed,
        test_a_bad_state_is_refused_on_the_WAY_IN,
        test_an_unknown_role_proves_nothing,
        test_the_index_filter_uses_the_same_decision_as_the_detail_check,
        test_seeding_grants_the_default_set_once,
        test_a_revoked_topic_is_not_re_granted_by_a_second_seed,
        test_seeding_is_recorded_even_when_the_default_set_is_empty,
        test_preview_writes_nothing,
        test_apply_is_additive_and_never_revokes,
        test_apply_does_not_bypass_the_seed_log_or_the_ceiling,
        test_selftest,
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
