#!/usr/bin/env python3
"""Learning Center — route registration and DIRECT-URL enforcement.

⛔ THE POINT OF THIS FILE IS THE DIRECT URL, NOT THE INDEX.
    `core/test_learning.py` proves the decision function. This proves the ROUTES
    actually apply it -- a different claim. A detail route that renders whatever the
    index linked to passes every test of the visible path, because the index never
    links to a hidden topic. The only test that catches it types the URL.

⛔ AND IT CHECKS THE TWO REGISTRIES, WHICH FAIL DIFFERENTLY AND BOTH SILENTLY.
    A route missing from `roles.ROUTE_MINIMUMS` is refused registration and 404s
    ("no such endpoint"); an entry naming an endpoint that does not exist is a typo
    that protects nothing while looking like coverage. Neither is visible to a test
    that only exercises an authenticated happy path.

Run: python3 core/test_learning_routes.py
"""
import os
import sqlite3
import sys
import tempfile

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_TMP = tempfile.mkdtemp(prefix="learnroute-")
os.environ["NEMESIS_DB_PATH"] = os.path.join(_TMP, "alerts.db")

for _p in (_REPO, os.path.join(_REPO, "alert_manager"),
           os.path.join(_REPO, "core_module", "hw_monitor"),
           os.path.join(_REPO, "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

EXPECTED_CHECKS = 84
_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


def die(msg):
    print("FATAL: %s" % msg)
    sys.exit(1)


try:
    import dashboard
except BaseException:          # dashboard sys.exit()s on config failure
    import traceback
    traceback.print_exc()
    die("could not import dashboard")

import learning as L                                              # noqa: E402
import learning_topics as LT                                      # noqa: E402
import roles as R                                                 # noqa: E402

app = dashboard.app
app.config["TESTING"] = True

LEARN_ENDPOINTS = ("learn_page", "learn_topic", "api_learn_admin",
                   "api_learn_topic_state", "api_learn_user_grant",
                   "api_learn_defaults_preview", "api_learn_defaults_apply")


# ── A. Both registries, both directions ──────────────────────────────────────

def test_every_endpoint_exists_in_the_live_url_map():
    """A ROUTE_MINIMUMS entry naming a non-existent endpoint protects nothing while
    reading as coverage -- it fails closed and is indistinguishable from omission."""
    live = {r.endpoint for r in app.url_map.iter_rules()}
    for ep in LEARN_ENDPOINTS:
        check("%s is a real registered route" % ep, ep in live)


def test_every_endpoint_has_a_role_minimum():
    """Absent from ROUTE_MINIMUMS -> the gate refuses it and the route 404s."""
    for ep in LEARN_ENDPOINTS:
        check("%s has a ROUTE_MINIMUMS entry" % ep, ep in R.ROUTE_MINIMUMS)


def test_no_learn_endpoint_is_auth_exempt():
    """Training content is for authenticated users; none of this is public."""
    exempt = getattr(dashboard, "_AUTH_EXEMPT", set())
    for ep in LEARN_ENDPOINTS:
        check("%s is NOT in _AUTH_EXEMPT" % ep, ep not in exempt)


def test_admin_routes_are_admin_for_both_methods():
    """The GET exposes who has been granted what across every account, which is as
    sensitive as the POST that changes it."""
    for ep in ("api_learn_admin", "api_learn_topic_state", "api_learn_user_grant",
               "api_learn_defaults_preview", "api_learn_defaults_apply"):
        check("%s is admin/admin" % ep,
              R.ROUTE_MINIMUMS[ep] == (R.ROLE_ADMIN, R.ROLE_ADMIN),
              "got %r" % (R.ROUTE_MINIMUMS[ep],))


def test_no_topic_slug_leaks_into_the_shared_registry():
    """The naming resolution from the architecture doc, asserted rather than trusted:
    a topic slug is a DB value and a filename, never an entry in roles.py."""
    joined = " ".join(R.ROUTE_MINIMUMS)
    for slug in LT.all_slugs():
        check("slug %r does not appear in ROUTE_MINIMUMS" % slug,
              slug not in joined)


# ── B. Direct-URL enforcement, through the real route ────────────────────────

def _seed_users():
    """Real user rows, because the route reads current_user.role from the DB."""
    conn = sqlite3.connect(os.environ["NEMESIS_DB_PATH"])
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL, password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin', is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL, last_login TEXT, failed_attempts INTEGER DEFAULT 0,
        lockout_until TEXT, lockout_tier INTEGER DEFAULT 0,
        password_changed_at TEXT, recovery_grace_until TEXT)""")
    for uid, name, role in ((501, "t_user", "user"), (502, "t_admin", "admin")):
        conn.execute("INSERT OR REPLACE INTO users(id,username,display_name,"
                     "password_hash,role,is_active,created_at) "
                     "VALUES(?,?,?,'x',?,1,'2026-01-01')", (uid, name, name, role))
    conn.commit()
    conn.close()


def _bypass_gates():
    """Drop the auth/lock/expiry before_request gates, keep flask_login's loader.

    Copied from core/test_downgrade_guard.py rather than invented. What is under test
    here is whether the ROUTE applies `visible_to`; the gates are separately covered
    and each one merely redirects, which would mask the status codes this file is
    asserting. `current_user` is still the REAL user loaded from the session, so role
    is genuine rather than mocked.

    ⚠ Every 302 seen while building this file came from a gate, not from the route --
    setup, idle-lock, password-expiry and realm in turn. A suite that asserted only
    "not 200" would have passed against all four while testing nothing, which is why
    the enforcement tests below assert an exact 200 baseline first.
    """
    removed = []
    for fn in list(app.before_request_funcs.get(None, [])):
        if fn.__name__ in ("_enforce_setup_and_auth", "_enforce_session_realm",
                           "_enforce_role"):
            app.before_request_funcs[None].remove(fn)
            removed.append(fn.__name__)
    return removed


def _get(path, uid):
    """Request `path` as user `uid`, through the real route."""
    with app.test_client() as c:
        with c.session_transaction() as s:
            s["_user_id"] = str(uid)
            s["_fresh"] = True
        return c.get(path)


def test_not_included_is_404_on_a_DIRECT_URL_even_holding_an_entitlement():
    """THE test. The index would never link here; the URL still must not serve."""
    slug = LT.all_slugs()[0]
    L.set_topic_state(slug, L.STATE_ALL_USERS)
    L.grant(501, slug)
    r = _get("/learn/%s" % slug, 501)
    check("baseline: an entitled user CAN load the topic", r.status_code == 200,
          "got %s" % r.status_code)

    L.set_topic_state(slug, L.STATE_NOT_INCLUDED)
    check("the entitlement row still exists", L.has_entitlement(501, slug))
    r = _get("/learn/%s" % slug, 501)
    check("...but the DIRECT URL now 404s", r.status_code == 404,
          "got %s" % r.status_code)
    r = _get("/learn/%s" % slug, 502)
    check("and 404s for an ADMIN too", r.status_code == 404, "got %s" % r.status_code)


def test_a_nonexistent_topic_is_indistinguishable_from_a_hidden_one():
    """Different statuses would confirm that a topic exists to someone not permitted
    to know it -- which for this content is the whole point of the control."""
    slug = LT.all_slugs()[0]
    L.set_topic_state(slug, L.STATE_NOT_INCLUDED)
    hidden = _get("/learn/%s" % slug, 501)
    absent = _get("/learn/no_such_topic_at_all", 501)
    check("hidden and nonexistent return the SAME status",
          hidden.status_code == absent.status_code == 404,
          "hidden=%s absent=%s" % (hidden.status_code, absent.status_code))


def test_the_index_lists_only_permitted_topics():
    slugs = LT.all_slugs()
    vis, hid = slugs[0], slugs[1]
    L.set_topic_state(vis, L.STATE_ALL_USERS)
    L.set_topic_state(hid, L.STATE_ALL_USERS)
    L.grant(501, vis)
    L.revoke(501, hid)                     # entitled to one, not the other
    body = _get("/learn", 501).get_data(as_text=True)
    check("the permitted topic is listed", ("/learn/%s" % vis) in body)
    check("the un-entitled topic is NOT listed", ("/learn/%s" % hid) not in body)
    check("...and its direct URL 404s too",
          _get("/learn/%s" % hid, 501).status_code == 404)


# ── C. Admin surface ─────────────────────────────────────────────────────────

def test_admin_routes_refuse_a_non_admin_via_the_real_authorizer():
    """Checked through `roles.may()` rather than an HTTP status, deliberately.

    These route tests bypass `_enforce_role` (see _bypass_gates) so that gate
    redirects cannot mask the status codes section B asserts -- which means an HTTP
    request here would NOT prove role enforcement. `may()` IS the function that gate
    calls, so asking it directly tests the real decision instead of a stand-in.
    """
    for ep in ("learn_admin_page", "api_learn_admin", "api_learn_topic_state",
               "api_learn_user_grant", "api_learn_defaults_preview",
               "api_learn_defaults_apply"):
        check("%s refuses ROLE_USER" % ep, R.may(R.ROLE_USER, ep, "GET") is False)
        check("%s admits ROLE_ADMIN" % ep, R.may(R.ROLE_ADMIN, ep, "GET") is True)


def test_the_admin_page_is_registered_and_admin_gated():
    live = {r.endpoint for r in app.url_map.iter_rules()}
    check("learn_admin_page is a real route", "learn_admin_page" in live)
    check("...and is admin/admin",
          R.ROUTE_MINIMUMS.get("learn_admin_page") == (R.ROLE_ADMIN, R.ROLE_ADMIN))


def test_the_all_admin_case_is_stated_rather_than_silent():
    """On an all-admin install 'all users' and 'admin only' behave identically. A
    page that says nothing about that is indistinguishable from a broken feature."""
    from flask import render_template
    with app.test_request_context("/settings/learning"):
        warn = render_template("learn_admin.html", eligible_count=2,
                               non_admin_count=0)
        norm = render_template("learn_admin.html", eligible_count=2,
                               non_admin_count=3)
        err = render_template("learn_admin.html", eligible_count=0,
                              non_admin_count=-1)
    check("all-admin install shows the warning",
          "No non-admin accounts exist yet" in warn)
    check("a normal install does NOT show it",
          "No non-admin accounts exist yet" not in norm)
    check("an unreadable account list says so rather than implying zero",
          "could not be read" in err)
    check("...and does not also show the all-admin warning",
          "No non-admin accounts exist yet" not in err)


def test_preview_endpoint_writes_nothing_and_apply_is_additive():
    """Through the real endpoints, not the library -- the routes are what an admin
    actually triggers, and a route could call the wrong function."""
    slug = LT.all_slugs()[0]
    L.set_topic_state(slug, L.STATE_ALL_USERS)
    L.set_in_default(slug, True)
    L.revoke(501, slug)
    L.grant(501, "phishing_awareness")          # an individual, non-default grant

    before = L.user_entitlements(501)
    with app.test_client() as c:
        with c.session_transaction() as s:
            s["_user_id"] = "502"               # admin
            s["_fresh"] = True
        pv = c.post("/api/learn/defaults/preview").get_json()
        check("preview reports the missing default",
              slug in (pv.get("would_grant", {}).get("501") or []),
              "got %r" % pv)
        check("PREVIEW WROTE NOTHING", L.user_entitlements(501) == before,
              "before=%r after=%r" % (before, L.user_entitlements(501)))

        ap = c.post("/api/learn/defaults/apply").get_json()
        check("apply reports what it granted",
              slug in (ap.get("granted", {}).get("501") or []), "got %r" % ap)
    check("the default is now held", L.has_entitlement(501, slug))
    check("THE INDIVIDUAL GRANT SURVIVED APPLY",
          L.has_entitlement(501, "phishing_awareness"))


def test_a_bad_state_is_refused_by_the_route_with_400():
    slug = LT.all_slugs()[0]
    with app.test_client() as c:
        with c.session_transaction() as s:
            s["_user_id"] = "502"
            s["_fresh"] = True
        r = c.post("/api/learn/topic/%s/state" % slug, json={"state": "all_user"})
        check("a typo'd state is refused at the boundary", r.status_code == 400,
              "got %s" % r.status_code)
        r2 = c.post("/api/learn/topic/no_such_topic/state",
                    json={"state": "all_users"})
        check("an unknown topic is refused", r2.status_code == 404,
              "got %s" % r2.status_code)


def test_the_warning_honours_is_active_not_just_role():
    """The ONLY configuration where a correct is_active filter and a missing one differ.

    Window 1 found that the obvious live check cannot discriminate: on the appliance the
    single inactive account is an ADMIN, so the role filter excludes it before is_active
    is ever consulted, and `role!='admin' AND is_active=1` and `role!='admin'` both
    return 1. Observing "the warning is absent" there proves the count is non-zero and
    nothing about whether is_active is honoured -- it passes for the right and the wrong
    reason indistinguishably.

    An INACTIVE NON-ADMIN is what separates them: a correct implementation still shows
    the warning (0 ACTIVE non-admins) while a missing filter suppresses it (1 non-admin
    exists). Creating one on the live box is the operator's call; here it costs nothing.
    """
    conn = sqlite3.connect(os.environ["NEMESIS_DB_PATH"])
    saved = conn.execute("SELECT id, is_active FROM users").fetchall()
    try:
        # Every non-admin inactive, and one of them deliberately present-but-inactive.
        conn.execute("UPDATE users SET is_active=0 WHERE role!='admin'")
        conn.execute("INSERT OR REPLACE INTO users(id,username,display_name,"
                     "password_hash,role,is_active,created_at) "
                     "VALUES(503,'t_inactive','t_inactive','x','user',0,'2026-01-01')")
        conn.commit()

        both = sqlite3.connect(os.environ["NEMESIS_DB_PATH"])
        n_active = both.execute("SELECT COUNT(*) FROM users WHERE role!='admin' "
                                "AND is_active=1").fetchone()[0]
        n_all = both.execute("SELECT COUNT(*) FROM users "
                             "WHERE role!='admin'").fetchone()[0]
        both.close()
        # Guard the fixture: if these agree, the test below cannot fail and proves
        # nothing -- the same defect it exists to catch.
        check("fixture DISCRIMINATES (active=%d vs all=%d)" % (n_active, n_all),
              n_active != n_all)
        check("...specifically zero ACTIVE non-admins", n_active == 0)

        r = _get("/settings/learning", 502)          # admin
        body = r.get_data(as_text=True)
        check("page renders", r.status_code == 200, "got %s" % r.status_code)
        check("warning APPEARS despite an inactive non-admin existing",
              "No non-admin accounts exist yet" in body)
    finally:
        conn.execute("DELETE FROM users WHERE id=503")
        for uid, act in saved:
            conn.execute("UPDATE users SET is_active=? WHERE id=?", (act, uid))
        conn.commit()
        conn.close()


def test_the_warning_is_absent_when_an_active_non_admin_exists():
    """The other side of the pair, so neither direction is assumed."""
    r = _get("/settings/learning", 502)
    body = r.get_data(as_text=True)
    check("an active non-admin exists, so no warning",
          "No non-admin accounts exist yet" not in body)


# ── D. Unified landing page ──────────────────────────────────────────────────

def test_the_training_route_survives_removal_from_the_nav():
    """THE "no functionality lost" guarantee, asserted rather than assumed.

    /account/training left the header nav when the Learning Center consolidated to one
    entry. The ROUTE must remain registered and reachable -- bookmarks, deep links, and
    the quiz links on /learn all depend on it. Removing a link and removing a route look
    identical in a nav diff and are completely different for a user with a bookmark.
    """
    live = {r.endpoint for r in app.url_map.iter_rules()}
    check("training_page is still a registered route", "training_page" in live)
    check("training_quiz is still a registered route", "training_quiz" in live)
    check("...and still has its role minimum",
          R.ROUTE_MINIMUMS.get("training_page") == (R.ROLE_USER, R.ROLE_USER))
    check("it is NO LONGER in the header nav",
          _nav_has("/account/training") is False)
    check("/learn IS in the header nav", _nav_has("/learn") is True)


def _nav_has(href):
    src = open(os.path.join(_REPO, "dashboard.py"), encoding="utf-8").read()
    i = src.find('title="Log out">Logout</a>')
    j = src.find("</h1>", i) if i >= 0 else -1
    nav = src[i:j] if (i >= 0 and j > i) else ""
    return ('href="%s"' % href) in nav


def test_the_landing_page_lists_BOTH_kinds_and_labels_them_apart():
    """Quizzes are not articles: passing one grants a capability. Presenting them
    identically to reading material would hide the property that makes them different."""
    slug = LT.all_slugs()[0]
    L.set_topic_state(slug, L.STATE_ALL_USERS)
    L.grant(501, slug)
    body = _get("/learn", 501).get_data(as_text=True)
    check("education section present", "Security training" in body)
    check("quiz section present and labelled by EFFECT",
          "Operating Nemesis" in body and "grant permissions" in body)
    check("an education topic is listed", ("/learn/%s" % slug) in body)


def test_every_quiz_is_listed_passed_or_not():
    """Operator decision 2026-09-05: visibility is what prompts a user to ask an admin
    for access, which is also how the admin learns there is demand. Hiding unpassed
    quizzes would make the entire mechanism undiscoverable."""
    body = _get("/learn", 501).get_data(as_text=True)
    import roles as _r
    declared = sorted(_r.CAPABILITY_ROUTES)
    check("there are capabilities to list", len(declared) > 0)

    # ⚠ Matched on the RENDERED form, not the raw capability id. A capability with no
    # quiz authored yet has title=None and falls back to `label` -- the id with
    # underscores replaced by spaces. The first version of this check searched for the
    # underscore form and reported "2 of 4 missing" against a page that listed all four
    # correctly: a false failure caused by testing a string the page never emits.
    def rendered(cap):
        return cap in body or cap.replace("_", " ") in body

    listed = [c for c in declared if rendered(c)]
    check("EVERY declared capability appears, regardless of pass state",
          len(listed) == len(declared),
          "listed %d of %d: missing=%r" % (len(listed), len(declared),
                                           sorted(set(declared) - set(listed))))
    check("...including ones with no quiz authored yet",
          rendered("firewall_change"),
          "an unauthored capability must still be discoverable")


def test_a_quiz_subsystem_failure_does_not_break_the_education_listing():
    """They are separate systems and /learn is now the only route to both. A fault in
    one must not take the other down -- otherwise consolidating the nav would have made
    the page strictly more fragile than the two it replaced."""
    slug = LT.all_slugs()[0]
    L.set_topic_state(slug, L.STATE_ALL_USERS)
    L.grant(501, slug)
    real = dashboard._training_rows
    try:
        dashboard._training_rows = lambda uid: (_ for _ in ()).throw(
            RuntimeError("quiz backend exploded"))
        r = _get("/learn", 501)
        check("page still renders", r.status_code == 200, "got %s" % r.status_code)
        body = r.get_data(as_text=True)
        check("education topics still listed", ("/learn/%s" % slug) in body)
        check("quiz section is simply absent", "Operating Nemesis" not in body)
    finally:
        dashboard._training_rows = real


if __name__ == "__main__":
    print("=" * 70)
    print("Learning Center -- routes, registries, direct-URL enforcement")
    print("=" * 70)
    import database
    database.init_learning_tables()
    _seed_users()
    _removed = _bypass_gates()
    check("auth gates bypassed for these route tests", len(_removed) >= 1,
          "removed=%r" % _removed)

    for fn in (
        test_every_endpoint_exists_in_the_live_url_map,
        test_every_endpoint_has_a_role_minimum,
        test_no_learn_endpoint_is_auth_exempt,
        test_admin_routes_are_admin_for_both_methods,
        test_no_topic_slug_leaks_into_the_shared_registry,
        test_not_included_is_404_on_a_DIRECT_URL_even_holding_an_entitlement,
        test_a_nonexistent_topic_is_indistinguishable_from_a_hidden_one,
        test_the_index_lists_only_permitted_topics,
        test_admin_routes_refuse_a_non_admin_via_the_real_authorizer,
        test_the_admin_page_is_registered_and_admin_gated,
        test_the_all_admin_case_is_stated_rather_than_silent,
        test_preview_endpoint_writes_nothing_and_apply_is_additive,
        test_a_bad_state_is_refused_by_the_route_with_400,
        test_the_warning_honours_is_active_not_just_role,
        test_the_warning_is_absent_when_an_active_non_admin_exists,
        test_the_training_route_survives_removal_from_the_nav,
        test_the_landing_page_lists_BOTH_kinds_and_labels_them_apart,
        test_every_quiz_is_listed_passed_or_not,
        test_a_quiz_subsystem_failure_does_not_break_the_education_listing,
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
