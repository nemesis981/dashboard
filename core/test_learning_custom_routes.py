#!/usr/bin/env python3
"""Custom-content ROUTES: who may draft, who may publish, and what a draft leaks.

`test_learning_custom.py` proves the state machine. This proves the ROUTES enforce it --
a different claim. A domain rule that no route consults is not a control, and a route
that re-implements the rule is a second copy that will drift.

⛔ THE SPLIT IS THE POINT: ANYONE SUBMITS, ONLY AN ADMIN APPROVES.
    (This line used to say "sub_admin drafts" -- that design was rejected because a
    sub_admin ROUTE_MINIMUMS entry stops the dashboard starting. Submission is open to
    any authenticated account; approval never is.)
    Asserted through `roles.may()`, which is the function the gate itself calls. These
    tests bypass `_enforce_role` so gate redirects cannot mask the status codes the
    read-path assertions need, which means an HTTP request here would NOT prove role
    enforcement -- asking the authorizer directly does.

⛔ A DRAFT MUST 404 ON A DIRECT URL, IDENTICALLY TO A NONEXISTENT TOPIC.
    Distinguishing them would confirm that unpublished content EXISTS to someone not
    permitted to read it -- which, for material an admin has deliberately not approved,
    is exactly what must not leak.

Run: python3 core/test_learning_custom_routes.py
"""
import os
import sqlite3
import sys
import tempfile

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TMP = tempfile.mkdtemp(prefix="lcr-")
os.environ["NEMESIS_DB_PATH"] = os.path.join(_TMP, "alerts.db")

for _p in (_REPO, os.path.join(_REPO, "alert_manager"),
           os.path.join(_REPO, "core_module", "hw_monitor"),
           os.path.join(_REPO, "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

EXPECTED_CHECKS = 125
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
except BaseException:
    import traceback
    traceback.print_exc()
    die("could not import dashboard")

import learning as L                                              # noqa: E402
import learning_custom as C                                       # noqa: E402
import roles as R                                                 # noqa: E402

app = dashboard.app
app.config["TESTING"] = True

CUSTOM_ENDPOINTS = ("learn_custom_submit_page", "learn_custom_queue_page",
                    "api_learn_custom_save", "api_learn_custom_withdraw",
                    "api_learn_custom_delete", "api_learn_custom_publish",
                    "api_learn_custom_unpublish")

#: ⚠ SUPERSEDES a sub_admin-based table. That design was rejected: a sub_admin
#: ROUTE_MINIMUMS entry breaks `_sub_admin_equals_user_without_unlocks`, which backs a
#: known-bad canary case, so roles.py fails to import and the dashboard does not start.
#: Submission is now open to any authenticated account; approval is admin-only.
#:
#: Asserted as DATA so the split cannot drift silently: an edit that opened publish to
#: non-admins fails here rather than in a review someone skipped.
EXPECTED_MINIMUMS = {
    "learn_custom_submit_page":   R.ROLE_USER,
    "learn_custom_queue_page":    R.ROLE_ADMIN,
    "api_learn_custom_save":      R.ROLE_USER,    # row rule refines: own + unapproved
    "api_learn_custom_withdraw":  R.ROLE_USER,    # row rule refines
    "api_learn_custom_delete":    R.ROLE_USER,    # row rule refines
    "api_learn_custom_publish":   R.ROLE_ADMIN,
    "api_learn_custom_unpublish": R.ROLE_ADMIN,
}


def _seed_users():
    conn = sqlite3.connect(os.environ["NEMESIS_DB_PATH"])
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL, password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin', is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL, last_login TEXT, failed_attempts INTEGER DEFAULT 0,
        lockout_until TEXT, lockout_tier INTEGER DEFAULT 0,
        password_changed_at TEXT, recovery_grace_until TEXT)""")
    for uid, name, role in ((601, "c_user", "user"), (602, "c_sub", "sub_admin"),
                            (603, "c_admin", "admin"), (604, "c_cap", "user")):
        conn.execute("INSERT OR REPLACE INTO users(id,username,display_name,"
                     "password_hash,role,is_active,created_at) "
                     "VALUES(?,?,?,'x',?,1,'2026-01-01')", (uid, name, name, role))
    conn.commit()
    conn.close()


def _bypass_gates():
    removed = []
    for fn in list(app.before_request_funcs.get(None, [])):
        if fn.__name__ in ("_enforce_setup_and_auth", "_enforce_session_realm",
                           "_enforce_role"):
            app.before_request_funcs[None].remove(fn)
            removed.append(fn.__name__)
    return removed


def _get(path, uid):
    with app.test_client() as c:
        with c.session_transaction() as s:
            s["_user_id"] = str(uid)
            s["_fresh"] = True
        return c.get(path)


def _post(path, uid, payload=None):
    with app.test_client() as c:
        with c.session_transaction() as s:
            s["_user_id"] = str(uid)
            s["_fresh"] = True
        return c.post(path, json=payload or {})


# ── A. Registries, both directions ───────────────────────────────────────────

def test_every_endpoint_is_registered_and_gated():
    live = {r.endpoint for r in app.url_map.iter_rules()}
    for ep in CUSTOM_ENDPOINTS:
        check("%s is a real route" % ep, ep in live)
        check("%s has a ROUTE_MINIMUMS entry" % ep, ep in R.ROUTE_MINIMUMS)


def test_no_custom_endpoint_is_auth_exempt():
    exempt = getattr(dashboard, "_AUTH_EXEMPT", set())
    for ep in CUSTOM_ENDPOINTS:
        check("%s is NOT public" % ep, ep not in exempt)


# ── B. THE SPLIT: anyone submits, only an admin approves ────────────────────

def test_publish_and_unpublish_are_ADMIN_ONLY():
    """The core of 'not self-publish'. A sub_admin reaching these would make the whole
    approval gate decorative."""
    for ep in ("api_learn_custom_publish", "api_learn_custom_unpublish"):
        check("%s refuses sub_admin" % ep, R.may(R.ROLE_SUB_ADMIN, ep, "POST") is False)
        check("%s refuses user" % ep, R.may(R.ROLE_USER, ep, "POST") is False)
        check("%s admits admin" % ep, R.may(R.ROLE_ADMIN, ep, "POST") is True)
    check("the queue page is admin-only too",
          R.may(R.ROLE_USER, "learn_custom_queue_page", "GET") is False)


def test_submission_is_open_to_any_user_but_not_viewonly():
    ep = "api_learn_custom_save"
    check("a plain user MAY submit", R.may(R.ROLE_USER, ep, "POST") is True)
    check("sub_admin may submit", R.may(R.ROLE_SUB_ADMIN, ep, "POST") is True)
    check("admin may submit", R.may(R.ROLE_ADMIN, ep, "POST") is True)
    check("viewonly may NOT -- submitting writes", 
          R.may(R.ROLE_VIEWONLY, ep, "POST") is False)
    # The reachability that motivated the whole redesign.
    check("a no-unlock sub_admin gets EXACTLY what a user gets (invariant)",
          R.may_with_unlocks(R.ROLE_SUB_ADMIN, (), ep, "POST")
          == R.may(R.ROLE_USER, ep, "POST"))


def test_the_declared_minimums_match_the_registry():
    """Asserted as data so the split cannot drift silently: a future edit that opened
    publish to sub_admin would fail here rather than in a review someone skipped."""
    for ep, want in EXPECTED_MINIMUMS.items():
        got = R.ROUTE_MINIMUMS.get(ep)
        check("%s minimum is %s" % (ep, want),
              got is not None and got[1] == want, "got %r" % (got,))


# ── C. A draft leaks nothing on the read path ───────────────────────────────

def test_a_draft_404s_on_a_direct_url_exactly_like_a_missing_topic():
    C.save_draft(slug="custom-secret", title="Internal", summary="s",
                 body="confidential procedure", actor="c_sub", role="user")
    L.set_topic_state("custom-secret", L.STATE_ALL_USERS)
    L.grant(601, "custom-secret")

    draft = _get("/learn/custom-secret", 601)
    missing = _get("/learn/custom-nope-at-all", 601)
    check("a DRAFT 404s even at all_users with an entitlement",
          draft.status_code == 404, "got %s" % draft.status_code)
    check("identical to a nonexistent topic",
          draft.status_code == missing.status_code,
          "draft=%s missing=%s" % (draft.status_code, missing.status_code))
    check("its body is not leaked", "confidential procedure" not in
          draft.get_data(as_text=True))
    check("nor its title", "Internal" not in draft.get_data(as_text=True))


def test_publishing_makes_it_readable_and_renders_the_body():
    C.save_draft(slug="custom-pub", title="Published Thing", summary="s",
                 body="# Heading\n\n**bold**", actor="c_sub", role="user")
    C.publish("custom-pub", actor="c_admin", role="admin")
    L.set_topic_state("custom-pub", L.STATE_ALL_USERS)
    L.grant(601, "custom-pub")

    r = _get("/learn/custom-pub", 601)
    check("published + visible + entitled -> 200", r.status_code == 200,
          "got %s" % r.status_code)
    body = r.get_data(as_text=True)
    check("the body is RENDERED, not raw source", "<h2>" in body and "# Heading" not in body)
    check("bold rendered", "<strong>" in body)


def test_an_edit_immediately_removes_a_published_topic_from_the_read_path():
    """The revert-on-edit rule, observed through the ROUTE rather than the model.

    ⚠ Both halves matter and the first one is why this test was rewritten. Once
    something is PUBLISHED its author can no longer touch it -- so the only actor who
    can trigger the revert is an admin, and a version of this test that edits as the
    author now proves the OPPOSITE rule to the one that shipped.
    """
    C.save_draft(slug="custom-edit", title="T", summary="s", body="one", actor="c_sub", role="user")
    C.publish("custom-edit", actor="c_admin", role="admin")
    L.set_topic_state("custom-edit", L.STATE_ALL_USERS)
    L.grant(601, "custom-edit")
    check("readable while published", _get("/learn/custom-edit", 601).status_code == 200)

    refused = False
    try:
        C.save_draft(slug="custom-edit", title="T", summary="s", body="hijack",
                     actor="c_sub", role="user")
    except C.PermissionDenied:
        refused = True
    check("the AUTHOR may not edit it once approved", refused)
    check("...and it is still readable, unchanged",
          _get("/learn/custom-edit", 601).status_code == 200)

    C.save_draft(slug="custom-edit", title="T", summary="s", body="two",
                 actor="c_admin", role="admin")
    check("an admin EDIT makes it 404 again",
          _get("/learn/custom-edit", 601).status_code == 404)


def test_the_index_does_not_list_drafts():
    C.save_draft(slug="custom-hidden", title="Hidden Draft", summary="s",
                 body="x", actor="c_sub", role="user")
    L.set_topic_state("custom-hidden", L.STATE_ALL_USERS)
    L.grant(601, "custom-hidden")
    body = _get("/learn", 601).get_data(as_text=True)
    check("a draft is absent from the index", "Hidden Draft" not in body)
    check("...and its URL is not linked", "/learn/custom-hidden" not in body)


# ── D. Row-level delete, through the route ──────────────────────────────────

def test_the_delete_route_honours_the_ROW_rule_not_just_the_role():
    """ROUTE_MINIMUMS admits sub_admin; the row rule then refines it. If the route
    trusted the registry alone, a sub_admin could delete published content."""
    C.save_draft(slug="custom-own", title="Mine", summary="s", body="x", actor="c_sub", role="user")
    C.save_draft(slug="custom-other", title="Theirs", summary="s", body="x",
                 actor="someone_else", role="user")

    r = _post("/api/learn/custom/delete", 602, {"slug": "custom-other"})
    check("sub_admin CANNOT delete another author's draft", r.status_code == 403,
          "got %s" % r.status_code)
    check("...and the row survives", C.get("custom-other") is not None)

    C.publish("custom-own", actor="c_admin", role="admin")
    r = _post("/api/learn/custom/delete", 602, {"slug": "custom-own"})
    check("sub_admin CANNOT delete their own PUBLISHED topic", r.status_code == 403,
          "got %s" % r.status_code)
    check("...and that row survives too", C.get("custom-own") is not None)

    C.unpublish("custom-own", actor="c_admin", role="admin")
    r = _post("/api/learn/custom/delete", 602, {"slug": "custom-own"})
    check("sub_admin CAN delete their own unpublished draft", r.status_code == 200,
          "got %s" % r.status_code)
    check("...and it is gone", C.get("custom-own") is None)

    r = _post("/api/learn/custom/delete", 603, {"slug": "custom-other"})
    check("an admin may delete anything", r.status_code == 200, "got %s" % r.status_code)


# ── E. The two PAGES render, and the queue is a new untrusted-content surface ──

def test_the_submission_page_renders_and_shows_only_your_own_work():
    """`learn_submit.html` had no test that reached it. A template referenced by a
    handler but never rendered by a test raises at REQUEST time, in front of a user."""
    C.save_draft(slug="custom-mine-601", title="My Own Draft", summary="s", body="x",
                 actor="c_user", role="user")
    C.save_draft(slug="custom-theirs-602", title="Someone Elses Draft", summary="s",
                 body="x", actor="c_sub", role="user")

    r = _get("/learn/submit", 601)
    body = r.get_data(as_text=True)
    check("the submission page renders", r.status_code == 200, "got %s" % r.status_code)
    check("it lists your own submission", "My Own Draft" in body)
    check("it does NOT list another user's", "Someone Elses Draft" not in body)
    # ⚠ NOT `str(MAX_UNAPPROVED_PER_USER) in body`. That was the original check and a
    # mutation deleting the whole cap line SURVIVED it: the cap is 10, and the page
    # also carries `margin-top:10px` and `&#10;` newline entities, so the assertion was
    # true no matter what the template said. Match the sentence, which only that line
    # can produce.
    check("the remaining allowance is shown before the cap is hit",
          'id="cap-remaining"' in body and "%d" % C.MAX_UNAPPROVED_PER_USER in body,
          "cap line missing from the page")


def test_the_submission_page_warns_AT_the_cap_not_only_past_it():
    """The at-cap branch of `learn_submit.html` had nothing exercising it. A limit a
    user meets only by being refused reads as the product breaking."""
    for i in range(C.MAX_UNAPPROVED_PER_USER):
        C.save_draft(slug="custom-cap-%d" % i, title="Cap %d" % i, summary="s",
                     body="x", actor="c_cap", role="user")
    check("the fixture actually reached the cap",
          C.unapproved_count("c_cap") == C.MAX_UNAPPROVED_PER_USER,
          "count=%s" % C.unapproved_count("c_cap"))

    body = _get("/learn/submit", 604).get_data(as_text=True)
    # Matched on the element id, not the sentence. The first version of this check
    # looked for "which is the limit" and failed against a page that says exactly that
    # -- the phrase is broken by a line wrap in the template. Prose moves; an id is
    # the thing the template actually commits to.
    check("at the cap the page says so", 'id="cap-reached"' in body)
    check("...and the under-cap allowance line is gone",
          'id="cap-remaining"' not in body)
    check("...and it still offers a way out", "Withdraw" in body)


def test_the_review_queue_renders_and_separates_pending_from_published():
    C.save_draft(slug="custom-q-wait", title="Waiting For Review", summary="s",
                 body="pending source text", actor="c_user", role="user")
    C.save_draft(slug="custom-q-live", title="Already Approved", summary="s",
                 body="y", actor="c_user", role="user")
    C.publish("custom-q-live", actor="c_admin", role="admin")

    r = _get("/settings/learning/queue", 603)
    body = r.get_data(as_text=True)
    check("the queue page renders", r.status_code == 200, "got %s" % r.status_code)
    check("a pending submission is listed", "Waiting For Review" in body)
    check("an admin reviews the SOURCE, not the rendering",
          "pending source text" in body)
    check("published work is listed too, for withdrawal", "Already Approved" in body)
    check("the submitter is attributed", "c_user" in body)


def test_the_queue_ESCAPES_author_text_it_shows_as_source():
    """⛔ The queue is the one place raw author source is displayed. It does NOT go
    through the renderer -- an admin approves what was written -- so its safety rests
    entirely on Jinja autoescaping, and nothing else was asserting that."""
    C.save_draft(slug="custom-q-xss", title="<script>alert(1)</script>",
                 summary="<img src=x onerror=alert(2)>",
                 body="<script>alert(3)</script>", actor="c_user", role="user")
    body = _get("/settings/learning/queue", 603).get_data(as_text=True)
    check("a script tag in the BODY is escaped", "<script>alert(3)</script>" not in body)
    check("...and in the TITLE", "<script>alert(1)</script>" not in body)
    check("...and an onerror handler in the SUMMARY",
          "<img src=x onerror=alert(2)>" not in body)
    check("the text is still shown, just inert", "alert(3)" in body)


def test_the_mutating_APIS_refuse_GET():
    """The GET-as-write/CSRF shape this codebase has shipped before (`db_action`,
    `api_vpn_action`). A 405 here is the route's method list doing its job."""
    for path in ("/api/learn/custom/save", "/api/learn/custom/withdraw",
                 "/api/learn/custom/delete", "/api/learn/custom/publish",
                 "/api/learn/custom/unpublish"):
        r = _get(path, 603)
        check("GET %s is refused (405)" % path, r.status_code == 405,
              "got %s" % r.status_code)


# ── F. The pending-review badge ──────────────────────────────────────────────
#
# ⛔ THE COUNT ITSELF IS THE THING THAT MUST NOT LEAK. `/api/stats` is reachable by any
# authenticated account. A globally-computed badge would hand every user a running
# tally of unapproved submissions -- the same material the read path 404s to protect,
# just aggregated. So these tests check WHO GETS THE NUMBER, not only that it is right.

def _pending_now():
    return len(C.all_topics(status=C.STATUS_DRAFT))


def test_the_badge_is_admin_only_and_silent_at_zero():
    C.save_draft(slug="custom-badge-1", title="Badge One", summary="s", body="x",
                 actor="c_user", role="user")
    n = _pending_now()
    check("the fixture has something pending", n > 0, "n=%d" % n)

    admin = dashboard._learn_pending_badge_html("admin")
    check("an admin gets a badge", admin != "")
    check("...carrying the real count", "%d awaiting review" % n in admin,
          "badge=%r" % admin[-60:])
    check("...linking to the queue", "/settings/learning/queue" in admin)

    for role in ("user", "sub_admin", "viewonly"):
        check("%s gets NOTHING -- the count is not theirs to see" % role,
              dashboard._learn_pending_badge_html(role) == "")

    check("an unparseable role fails closed",
          dashboard._learn_pending_badge_html("not-a-role") == "")


def test_the_badge_disappears_when_the_queue_empties():
    """A permanent badge is furniture. One that APPEARS is a signal, which is the only
    reason this affordance exists."""
    for t in C.all_topics(status=C.STATUS_DRAFT):
        C.delete(t["slug"], actor="c_admin", role="admin")
    check("the queue is genuinely empty", _pending_now() == 0)
    check("an admin sees no badge at zero",
          dashboard._learn_pending_badge_html("admin") == "")

    C.save_draft(slug="custom-badge-2", title="Badge Two", summary="s", body="x",
                 actor="c_user", role="user")
    check("...and it reappears on the next submission",
          "1 awaiting review" in dashboard._learn_pending_badge_html("admin"))


def test_the_dashboard_HEADER_actually_renders_the_badge():
    """The header is built by a Python f-string. A misnamed local there is a KeyError at
    request time on the main page, and `py_compile` cannot see it -- the same class of
    defect as this codebase's #1 recurring bug."""
    C.save_draft(slug="custom-hdr", title="Header Badge", summary="s", body="x",
                 actor="c_user", role="user")
    r = _get("/", 603)
    body = r.get_data(as_text=True)
    check("the dashboard renders for an admin", r.status_code == 200,
          "got %s" % r.status_code)
    check("the badge span is in the header", 'id="learn-pending-badge"' in body)
    check("...and it is populated, not left empty",
          "awaiting review" in body)

    # The leak assertion on the real page, not just on the helper.
    plain = _get("/", 601).get_data(as_text=True)
    check("a plain user renders the same header with NO count",
          'id="learn-pending-badge"' in plain and "awaiting review" not in plain)


def test_api_stats_computes_the_badge_PER_REQUESTER():
    """The claim the helper's docstring makes, tested through the real payload rather
    than by reading the helper again."""
    admin = _get("/api/stats", 603)
    user = _get("/api/stats", 601)
    check("/api/stats answers for an admin", admin.status_code == 200,
          "got %s" % admin.status_code)
    check("/api/stats answers for a user", user.status_code == 200,
          "got %s" % user.status_code)

    a = admin.get_json() or {}
    u = user.get_json() or {}
    check("the key is present for the admin", "learning_pending_badge" in a)
    check("the admin payload carries the count",
          "awaiting review" in (a.get("learning_pending_badge") or ""))
    check("the USER payload carries no count at all",
          (u.get("learning_pending_badge") or "") == "",
          "leaked=%r" % (u.get("learning_pending_badge"),))


# ── G. One notification per SUBMISSION, not per SAVE ─────────────────────────
#
# ⛔ THE DEFECT THIS PINS. `save_draft` is BOTH the create and the edit path, and the
# save route notified unconditionally. The per-user cap bounds unapproved ROWS, and an
# edit creates no row, so the cap bounded nothing about notification volume. Measured
# before the fix: 40 saves -> 1 row -> 40 notifications. With DEFAULT_NOTIFY_MODE at
# `immediate` those are 40 real emails from the operator's own SMTP sender, driven by
# the lowest-privileged account that can write anything.
#
# The property asserted here is the operator's wording: exactly one notification per
# genuinely new submission, regardless of how many times it is subsequently edited.

class _NotifySpy:
    """Records calls to the route's notifier and always restores it.

    Restores in __exit__ rather than at the end of the test body so an assertion that
    raises cannot leave a stub installed for every later test in the file -- a leaked
    stub would make the badge suites measure a patched dashboard.
    """

    def __enter__(self):
        self.calls = []
        self._orig = dashboard._notify_custom_submission
        dashboard._notify_custom_submission = \
            lambda slug, actor: self.calls.append((slug, actor))
        return self

    def __exit__(self, *exc):
        dashboard._notify_custom_submission = self._orig
        return False


def _save(uid, slug, body, title="T", summary="s"):
    return _post("/api/learn/custom/save", uid,
                 {"slug": slug, "title": title, "summary": summary, "body": body})


def test_ONE_notification_per_submission_however_often_it_is_edited():
    EDITS = 12
    with _NotifySpy() as spy:
        codes = {_save(601, "custom-notify-a", "revision %d" % i).status_code
                 for i in range(EDITS)}
        check("every save succeeded", codes == {200}, "codes=%s" % sorted(codes))
        check("...and they wrote ONE row",
              len([t for t in C.all_topics() if t["slug"] == "custom-notify-a"]) == 1)
        check("exactly ONE notification for %d saves" % EDITS,
              len(spy.calls) == 1, "fired=%d" % len(spy.calls))

        # CONTROL. Without this, "1" could be a stub that never fires rather than a
        # measurement -- the instrument has to be shown capable of a different answer.
        _save(601, "custom-notify-b", "another submission")
        check("a genuinely NEW submission does notify (control)",
              len(spy.calls) == 2, "fired=%d" % len(spy.calls))
        check("...and it names the new slug, not the old one",
              spy.calls[-1][0] == "custom-notify-b", "got %r" % (spy.calls[-1],))

    # The response now reports the same fact. Asserted so the field is EXERCISED rather
    # than merely present -- an unread response key is an untested branch.
    fresh = _save(601, "custom-notify-c", "first")
    edit = _save(601, "custom-notify-c", "second")
    check("the response says a create was a create",
          fresh.get_json().get("created") is True, "got %r" % fresh.get_json())
    check("...and an edit was not", edit.get_json().get("created") is False,
          "got %r" % edit.get_json())


def test_a_REFUSED_save_notifies_nobody():
    """A notification means "there is something to review". A save that wrote nothing
    has produced nothing to review, so the branch must not be reached at all."""
    with _NotifySpy() as spy:
        bad = _save(601, "not-namespaced", "x")
        check("a malformed slug is refused", bad.status_code == 400,
              "got %s" % bad.status_code)
        check("...and notifies nobody", len(spy.calls) == 0)

        C.save_draft(slug="custom-notify-owned", title="Theirs", summary="s",
                     body="x", actor="c_sub", role="user")
        denied = _save(601, "custom-notify-owned", "hijack")
        check("overwriting someone else's submission is refused",
              denied.status_code == 403, "got %s" % denied.status_code)
        check("...and notifies nobody", len(spy.calls) == 0)


def test_reverting_a_PUBLISHED_topic_to_draft_does_not_renotify():
    """An admin edit of approved content reverts it to draft. That is a state change,
    but it is not a new submission and the admin making it already knows."""
    C.save_draft(slug="custom-notify-pub", title="Approved", summary="s", body="v1",
                 actor="c_user", role="user")
    C.publish("custom-notify-pub", actor="c_admin", role="admin")
    with _NotifySpy() as spy:
        r = _save(603, "custom-notify-pub", "v2 by an admin")
        check("the admin edit succeeded", r.status_code == 200, "got %s" % r.status_code)
        check("...it did revert the topic to draft",
              C.get("custom-notify-pub")["status"] == C.STATUS_DRAFT)
        check("...and nobody was notified about it", len(spy.calls) == 0)


def test_the_domain_layer_REPORTS_creation_rather_than_the_route_re_deriving_it():
    """⛔ The route must not decide this itself. `save_draft` already reads the existing
    row to enforce the cap and ownership; a second read in the handler would be a second
    source of truth for the same question, and the two would drift. The fact travels
    back from the read that actually made the decision."""
    C.delete("custom-notify-rep", actor="c_admin", role="admin") \
        if C.get("custom-notify-rep") else None

    first = C.save_draft(slug="custom-notify-rep", title="T", summary="s", body="1",
                         actor="c_user", role="user")
    again = C.save_draft(slug="custom-notify-rep", title="T", summary="s", body="2",
                         actor="c_user", role="user")
    check("a create reports created=True", first.created is True,
          "got %r" % (getattr(first, "created", "<absent>"),))
    check("an edit reports created=False", again.created is False,
          "got %r" % (getattr(again, "created", "<absent>"),))

    # The return must STILL be the slug string. 42 call sites use it that way, and a
    # shape change that broke them silently would be a worse defect than the one fixed.
    check("the return is still the slug", first == "custom-notify-rep")
    check("...and still a real str", isinstance(first, str))
    check("...so it still formats as the slug",
          "%s" % first == "custom-notify-rep")


def test_save_refuses_a_bad_slug_with_400_not_500():
    r = _post("/api/learn/custom/save", 602,
              {"slug": "not-prefixed", "title": "t", "summary": "s", "body": "b"})
    check("a non-namespaced slug is refused at the boundary", r.status_code == 400,
          "got %s" % r.status_code)
    # ⛔ The form now derives the slug itself, so a caller landing here is either a
    # direct API user or the one edge case the form leaves editable. Either way the
    # 400 body must read as an instruction, not a compiled regex.
    err = (r.get_json() or {}).get("error") or ""
    check("the error names the required prefix", "custom-" in err, "got %r" % err)
    check("...and carries no regex metacharacters",
          not any(c in err for c in "^$\\[]{}"), "got %r" % err)


if __name__ == "__main__":
    print("=" * 70)
    print("custom content ROUTES: the submit/approve split, enforced")
    print("=" * 70)
    import database
    database.init_learning_tables()
    _seed_users()
    removed = _bypass_gates()
    check("auth gates bypassed for these route tests", len(removed) >= 1,
          "removed=%r" % removed)

    for fn in (
        test_every_endpoint_is_registered_and_gated,
        test_no_custom_endpoint_is_auth_exempt,
        test_publish_and_unpublish_are_ADMIN_ONLY,
        test_submission_is_open_to_any_user_but_not_viewonly,
        test_the_declared_minimums_match_the_registry,
        test_a_draft_404s_on_a_direct_url_exactly_like_a_missing_topic,
        test_publishing_makes_it_readable_and_renders_the_body,
        test_an_edit_immediately_removes_a_published_topic_from_the_read_path,
        test_the_index_does_not_list_drafts,
        test_the_delete_route_honours_the_ROW_rule_not_just_the_role,
        test_the_submission_page_renders_and_shows_only_your_own_work,
        test_the_submission_page_warns_AT_the_cap_not_only_past_it,
        test_the_review_queue_renders_and_separates_pending_from_published,
        test_the_queue_ESCAPES_author_text_it_shows_as_source,
        test_the_mutating_APIS_refuse_GET,
        test_the_badge_is_admin_only_and_silent_at_zero,
        test_the_badge_disappears_when_the_queue_empties,
        test_the_dashboard_HEADER_actually_renders_the_badge,
        test_api_stats_computes_the_badge_PER_REQUESTER,
        test_ONE_notification_per_submission_however_often_it_is_edited,
        test_a_REFUSED_save_notifies_nobody,
        test_reverting_a_PUBLISHED_topic_to_draft_does_not_renotify,
        test_the_domain_layer_REPORTS_creation_rather_than_the_route_re_deriving_it,
        test_save_refuses_a_bad_slug_with_400_not_500,
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
