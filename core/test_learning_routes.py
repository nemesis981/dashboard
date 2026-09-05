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

EXPECTED_CHECKS = 37
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
