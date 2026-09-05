#!/usr/bin/env python3
"""Business-authored content: the draft/publish state machine and its two ceilings.

⛔ A DRAFT IS INVISIBLE REGARDLESS OF VISIBILITY STATE.
    This is a SECOND, INDEPENDENT ceiling above the existing three-state model, and both
    must pass. A draft set to `all_users` with an entitlement held is still invisible --
    otherwise "draft" would mean "published with extra steps" and the approval gate would
    be decorative rather than load-bearing.

⛔ EDITING A PUBLISHED TOPIC RETURNS IT TO DRAFT.
    The non-obvious half of "sub_admin drafts, admin publishes". Without it a sub_admin
    could alter text an admin already approved, and the approval would then attest to
    content that no longer exists. The friction (a typo fix needs re-approval) is
    accepted deliberately.

⛔ DELETE IS THE ONE RULE `ROUTE_MINIMUMS` CANNOT EXPRESS.
    It depends on the ROW's status and owner, not only the caller's role: an admin may
    delete anything; a sub_admin may delete only their OWN UNPUBLISHED draft. A registry
    entry gates by role alone, so this rule lives in the domain layer -- where a second
    caller cannot bypass it by reaching the function directly.

Run: python3 core/test_learning_custom.py
"""
import io
import os
import sqlite3
import sys
import tempfile

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (_REPO, os.path.join(_REPO, "alert_manager"), os.path.join(_REPO, "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import learning_custom as C                                        # noqa: E402
import learning as L                                               # noqa: E402

EXPECTED_CHECKS = 70
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
    path = os.path.join(tempfile.mkdtemp(prefix="lcustom-"), "alerts.db")
    conn = sqlite3.connect(path)
    conn.executescript(C.SCHEMA_SQL)
    conn.executescript("""
        CREATE TABLE learning_topic_visibility (
            topic_slug TEXT PRIMARY KEY, state TEXT NOT NULL DEFAULT 'not_included',
            in_default INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL, actor TEXT);
        CREATE TABLE learning_entitlements (
            user_id INTEGER NOT NULL, topic_slug TEXT NOT NULL,
            granted_at TEXT NOT NULL, actor TEXT,
            PRIMARY KEY (user_id, topic_slug));
    """)
    conn.commit()
    conn.close()
    return path


def mk(db, slug="custom-onboarding", actor="alice", **kw):
    return C.save_draft(slug=slug, title=kw.get("title", "Onboarding"),
                        summary=kw.get("summary", "How we do things"),
                        body=kw.get("body", "# Welcome\n\n**read this**"),
                        actor=actor, db_path=db)


# ── A. Slug namespacing ──────────────────────────────────────────────────────

def test_custom_slugs_are_namespaced_and_cannot_impersonate_a_builtin():
    db = fresh_db()
    check("a non-prefixed slug is refused",
          raises(C.CustomError, lambda: mk(db, slug="onboarding")))
    check("...and a built-in's slug specifically is refused",
          raises(C.CustomError, lambda: mk(db, slug="darkweb_safety_basics")))
    check("the prefix is accepted", mk(db, slug="custom-ok") is not None)
    import learning_topics as LT
    bad = [s for s in LT.all_slugs() if s.startswith(C.SLUG_PREFIX)]
    eq("NO built-in uses the custom prefix", bad, [])


def test_slug_charset_is_url_safe():
    db = fresh_db()
    for bad in ("custom-a/b", "custom-a b", "custom-<x>", "custom-" + "a" * 100, ""):
        check("refuses %r" % bad[:24], raises(C.CustomError, lambda b=bad: mk(db, slug=b)))


# ── B. The state machine ─────────────────────────────────────────────────────

def test_new_content_starts_as_a_draft():
    db = fresh_db()
    mk(db)
    t = C.get("custom-onboarding", db_path=db)
    eq("status is draft", t["status"], C.STATUS_DRAFT)
    eq("published_at is unset", t["published_at"], None)
    eq("published_by is unset", t["published_by"], None)
    eq("created_by recorded", t["created_by"], "alice")


def test_publish_records_who_approved_and_when():
    db = fresh_db()
    mk(db)
    C.publish("custom-onboarding", actor="admin1", db_path=db)
    t = C.get("custom-onboarding", db_path=db)
    eq("status is published", t["status"], C.STATUS_PUBLISHED)
    eq("publisher recorded SEPARATELY from the author", t["published_by"], "admin1")
    check("published_at set", bool(t["published_at"]))
    eq("author unchanged", t["created_by"], "alice")


def test_EDITING_A_PUBLISHED_TOPIC_REVERTS_IT_TO_DRAFT():
    """The approval must not survive the text it approved."""
    db = fresh_db()
    mk(db)
    C.publish("custom-onboarding", actor="admin1", db_path=db)
    eq("published first", C.get("custom-onboarding", db_path=db)["status"],
       C.STATUS_PUBLISHED)

    C.save_draft(slug="custom-onboarding", title="Onboarding v2",
                 summary="changed", body="new text", actor="bob", db_path=db)
    t = C.get("custom-onboarding", db_path=db)
    eq("editing REVERTED it to draft", t["status"], C.STATUS_DRAFT)
    eq("...and cleared the approval", t["published_by"], None)
    eq("...and its timestamp", t["published_at"], None)
    eq("the editor is recorded", t["updated_by"], "bob")
    eq("the original author is NOT overwritten", t["created_by"], "alice")


def test_unpublish_returns_to_draft():
    db = fresh_db()
    mk(db)
    C.publish("custom-onboarding", actor="admin1", db_path=db)
    C.unpublish("custom-onboarding", actor="admin1", db_path=db)
    t = C.get("custom-onboarding", db_path=db)
    eq("back to draft", t["status"], C.STATUS_DRAFT)
    eq("approval cleared", t["published_by"], None)


def test_an_unknown_status_can_never_be_stored():
    db = fresh_db()
    mk(db)
    check("a bogus status is refused at the boundary",
          raises(C.CustomError,
                 lambda: C.set_status("custom-onboarding", "live", actor="x", db_path=db)))
    eq("nothing changed", C.get("custom-onboarding", db_path=db)["status"],
       C.STATUS_DRAFT)


# ── C. Delete: status + ownership, which ROUTE_MINIMUMS cannot express ───────

def test_a_sub_admin_may_delete_only_their_OWN_UNPUBLISHED_draft():
    db = fresh_db()
    mk(db, slug="custom-mine", actor="alice")
    mk(db, slug="custom-theirs", actor="carol")

    check("own draft: allowed",
          C.can_delete(C.get("custom-mine", db_path=db), "alice", "sub_admin") is True)
    check("SOMEONE ELSE'S draft: refused",
          C.can_delete(C.get("custom-theirs", db_path=db), "alice", "sub_admin") is False)

    C.publish("custom-mine", actor="admin1", db_path=db)
    check("their OWN topic once PUBLISHED: refused",
          C.can_delete(C.get("custom-mine", db_path=db), "alice", "sub_admin") is False)


def test_an_admin_may_delete_anything():
    db = fresh_db()
    mk(db, slug="custom-x", actor="alice")
    check("admin deletes someone else's draft",
          C.can_delete(C.get("custom-x", db_path=db), "admin1", "admin") is True)
    C.publish("custom-x", actor="admin1", db_path=db)
    check("admin deletes published content",
          C.can_delete(C.get("custom-x", db_path=db), "admin1", "admin") is True)


def test_only_viewonly_may_delete_nothing():
    """⚠ SUPERSEDES an earlier version asserting that a plain `user` could delete
    nothing. That was correct under the sub_admin-drafting design and is WRONG under the
    redesign: submission is open to every account, so a submitter must be able to
    withdraw their own unapproved work. The floor moved; the rule did not.

    viewonly is unchanged and is the part that still matters here -- it writes nothing,
    ever, which is the same reasoning that excludes it from submitting at all.
    """
    db = fresh_db()
    mk(db, slug="custom-x", actor="dave")
    t = C.get("custom-x", db_path=db)
    check("viewonly cannot delete, even their own draft",
          C.can_delete(t, "dave", "viewonly") is False)
    check("a plain user CAN delete their own unapproved draft (redesign)",
          C.can_delete(t, "dave", "user") is True)
    check("...but still not someone else's",
          C.can_delete(t, "not-dave", "user") is False)


def test_delete_ENFORCES_rather_than_relying_on_the_caller_to_ask():
    """can_delete() is advice; delete() is the boundary. A second caller reaching the
    function directly must not bypass the rule."""
    db = fresh_db()
    mk(db, slug="custom-x", actor="alice")
    C.publish("custom-x", actor="admin1", db_path=db)
    check("delete refuses a sub_admin on published content",
          raises(C.PermissionDenied,
                 lambda: C.delete("custom-x", actor="alice", role="sub_admin",
                                  db_path=db)))
    check("the row survived", C.get("custom-x", db_path=db) is not None)

    C.delete("custom-x", actor="admin1", role="admin", db_path=db)
    check("admin delete succeeded", C.get("custom-x", db_path=db) is None)


# ── D. The second ceiling: drafts are invisible, full stop ──────────────────

def test_a_DRAFT_is_invisible_even_at_all_users_with_an_entitlement():
    db = fresh_db()
    mk(db, slug="custom-x", actor="alice")
    L.set_topic_state("custom-x", L.STATE_ALL_USERS, db_path=db)
    L.grant(7, "custom-x", db_path=db)
    check("visibility state says all_users",
          L.topic_state("custom-x", db_path=db) == L.STATE_ALL_USERS)
    check("entitlement is held", L.has_entitlement(7, "custom-x", db_path=db))
    check("...and it is STILL invisible, because it is a draft",
          C.visible_to(7, "user", "custom-x", db_path=db) is False)
    check("invisible to an admin too", C.visible_to(1, "admin", "custom-x", db_path=db) is False)


def test_publishing_alone_does_not_make_it_visible():
    """Both ceilings, independently. Published + not_included must stay hidden."""
    db = fresh_db()
    mk(db, slug="custom-x", actor="alice")
    C.publish("custom-x", actor="admin1", db_path=db)
    L.set_topic_state("custom-x", L.STATE_NOT_INCLUDED, db_path=db)
    L.grant(7, "custom-x", db_path=db)
    check("published but not_included -> invisible",
          C.visible_to(7, "user", "custom-x", db_path=db) is False)

    L.set_topic_state("custom-x", L.STATE_ALL_USERS, db_path=db)
    check("published AND all_users AND entitled -> visible",
          C.visible_to(7, "user", "custom-x", db_path=db) is True)
    L.revoke(7, "custom-x", db_path=db)
    check("...and revoking the entitlement hides it again",
          C.visible_to(7, "user", "custom-x", db_path=db) is False)


def test_reverting_to_draft_immediately_hides_published_content():
    db = fresh_db()
    mk(db, slug="custom-x", actor="alice")
    C.publish("custom-x", actor="admin1", db_path=db)
    L.set_topic_state("custom-x", L.STATE_ALL_USERS, db_path=db)
    L.grant(7, "custom-x", db_path=db)
    check("visible while published", C.visible_to(7, "user", "custom-x", db_path=db))
    C.save_draft(slug="custom-x", title="t", summary="s", body="b",
                 actor="alice", db_path=db)
    check("an EDIT hides it again immediately",
          C.visible_to(7, "user", "custom-x", db_path=db) is False)


# ── E. Storage stores SOURCE, not HTML ──────────────────────────────────────

def test_the_body_column_holds_SOURCE_never_rendered_html():
    """Storing output would freeze today's escaping into rows authored before a fix."""
    db = fresh_db()
    C.save_draft(slug="custom-x", title="t", summary="s",
                 body="# Head\n\n<script>alert(1)</script>", actor="alice", db_path=db)
    stored = C.get("custom-x", db_path=db)["body"]
    check("the raw source is preserved verbatim", "<script>" in stored, stored)
    check("no rendered markup was stored", "<h2>" not in stored, stored)

    html = C.render_body("custom-x", db_path=db)
    check("rendering happens on READ", "<h2>" in html, html)
    check("...and the script is neutralised there", "<script>" not in html, html)


def test_render_body_of_a_missing_topic_is_empty_not_an_error():
    db = fresh_db()
    eq("missing topic renders empty", C.render_body("custom-nope", db_path=db), "")


# ── F. Business content must never leave the box in a support export ────────

def test_no_diagnostic_reads_the_custom_content_table():
    """Converts "no diagnostic does this yet" into "none can without a red suite".

    Diagnostics dump table CONTENTS -- each names its own table explicitly, and the one
    dynamic read iterates a fixed device-table allow-list. So custom content is excluded
    today purely by absence, which is a weaker guarantee than an exclusion: a future
    diagnostic could add this table in one line and nothing would object.

    Business-internal procedures and onboarding notes are exactly what must not ride
    along in a support email. Exclusion is verifiable in a way that redaction of
    free-form prose is not, which is why this asserts absence rather than trusting a
    scrubber to catch it.
    """
    import glob
    diag_dir = os.path.join(_REPO, "diagnostics")
    files = [f for f in glob.glob(os.path.join(diag_dir, "*.py"))
             if not os.path.basename(f).startswith("test_")]
    # Guard the fixture: an empty file list would make the assertion vacuously true.
    check("there are diagnostics to scan", len(files) > 3, "found %d" % len(files))

    offenders = []
    for f in files:
        try:
            src = io.open(f, encoding="utf-8").read()
        except OSError:
            continue
        if "learning_custom_topics" in src:
            offenders.append(os.path.basename(f))
    check("NO diagnostic references learning_custom_topics",
          not offenders, "offenders=%r" % offenders)

    # And the positive control: the scan can actually find a table name when present,
    # so a clean result means "absent" rather than "the scan is broken".
    known = [os.path.basename(f) for f in files
             if "anomaly_state" in io.open(f, encoding="utf-8").read()]
    check("control: the scan DOES find a table name that is present",
          len(known) > 0, "the scan found nothing at all, so its clean result is suspect")


# ── G. Open submission: any user submits, admin approves ────────────────────

def test_a_plain_USER_may_delete_their_own_unapproved_submission():
    """The redesign generalises WHO submits. A submitter must be able to withdraw their
    own work while it is still unapproved -- the same rule that applied to a sub_admin,
    with the role floor lowered rather than the rule rewritten."""
    db = fresh_db()
    mk(db, slug="custom-mine", actor="dave")
    mk(db, slug="custom-theirs", actor="erin")

    check("own unapproved submission: allowed",
          C.can_delete(C.get("custom-mine", db_path=db), "dave", "user") is True)
    check("someone else's: refused",
          C.can_delete(C.get("custom-theirs", db_path=db), "dave", "user") is False)

    C.publish("custom-mine", actor="admin1", db_path=db)
    check("their own, once APPROVED: refused",
          C.can_delete(C.get("custom-mine", db_path=db), "dave", "user") is False,
          "a submitter must not be able to withdraw what an admin approved")


def test_viewonly_still_cannot_delete_anything():
    """The floor moved to `user`, not to everybody. viewonly writes nothing."""
    db = fresh_db()
    mk(db, slug="custom-x", actor="vic")
    check("viewonly refused even on their own draft",
          C.can_delete(C.get("custom-x", db_path=db), "vic", "viewonly") is False)


def test_sub_admin_and_admin_are_unaffected_by_the_lowered_floor():
    """Lowering a floor must not change what the roles above it could already do."""
    db = fresh_db()
    mk(db, slug="custom-s", actor="sam")
    check("sub_admin still deletes their own draft",
          C.can_delete(C.get("custom-s", db_path=db), "sam", "sub_admin") is True)
    check("admin still deletes anything",
          C.can_delete(C.get("custom-s", db_path=db), "other", "admin") is True)


# ── H. Per-user cap on UNAPPROVED submissions ───────────────────────────────

def test_the_cap_counts_only_UNAPPROVED_submissions():
    """An approved submission must not count against the author forever -- otherwise a
    productive contributor is punished for being published, which is backwards."""
    db = fresh_db()
    for i in range(C.MAX_UNAPPROVED_PER_USER):
        C.save_draft(slug="custom-d%d" % i, title="t", summary="s", body="b",
                     actor="dave", db_path=db)
    eq("at the cap", C.unapproved_count("dave", db_path=db),
       C.MAX_UNAPPROVED_PER_USER)
    check("one more is refused",
          raises(C.CustomError,
                 lambda: C.save_draft(slug="custom-over", title="t", summary="s",
                                      body="b", actor="dave", db_path=db)))

    C.publish("custom-d0", actor="admin1", db_path=db)
    eq("publishing frees a slot", C.unapproved_count("dave", db_path=db),
       C.MAX_UNAPPROVED_PER_USER - 1)
    check("...and a new submission is accepted again",
          C.save_draft(slug="custom-over", title="t", summary="s", body="b",
                       actor="dave", db_path=db) is not None)


def test_the_cap_is_PER_USER_not_global():
    """A global cap would let one noisy account block everyone else -- a denial of
    service dressed as a quota."""
    db = fresh_db()
    for i in range(C.MAX_UNAPPROVED_PER_USER):
        C.save_draft(slug="custom-a%d" % i, title="t", summary="s", body="b",
                     actor="dave", db_path=db)
    check("a DIFFERENT user is unaffected",
          C.save_draft(slug="custom-b0", title="t", summary="s", body="b",
                       actor="erin", db_path=db) is not None)
    eq("and their own count is 1", C.unapproved_count("erin", db_path=db), 1)


def test_EDITING_an_existing_submission_does_not_consume_a_new_slot():
    """Otherwise a user at the cap could not fix a typo in work they already submitted --
    the cap would block correction rather than volume."""
    db = fresh_db()
    for i in range(C.MAX_UNAPPROVED_PER_USER):
        C.save_draft(slug="custom-e%d" % i, title="t", summary="s", body="b",
                     actor="dave", db_path=db)
    check("editing one already at the cap is allowed",
          C.save_draft(slug="custom-e0", title="fixed", summary="s", body="b2",
                       actor="dave", db_path=db) is not None)
    eq("count unchanged", C.unapproved_count("dave", db_path=db),
       C.MAX_UNAPPROVED_PER_USER)


def test_an_admin_is_not_capped():
    """The cap is volume control against a wide submitting population; an admin
    publishing their own material is not that population."""
    db = fresh_db()
    for i in range(C.MAX_UNAPPROVED_PER_USER + 2):
        C.save_draft(slug="custom-adm%d" % i, title="t", summary="s", body="b",
                     actor="admin1", role="admin", db_path=db)
    check("admin exceeded the cap without refusal",
          C.unapproved_count("admin1", db_path=db) > C.MAX_UNAPPROVED_PER_USER)


if __name__ == "__main__":
    print("=" * 70)
    print("custom content: draft/publish, two ceilings, ownership-aware delete")
    print("=" * 70)
    for fn in (
        test_custom_slugs_are_namespaced_and_cannot_impersonate_a_builtin,
        test_slug_charset_is_url_safe,
        test_new_content_starts_as_a_draft,
        test_publish_records_who_approved_and_when,
        test_EDITING_A_PUBLISHED_TOPIC_REVERTS_IT_TO_DRAFT,
        test_unpublish_returns_to_draft,
        test_an_unknown_status_can_never_be_stored,
        test_a_sub_admin_may_delete_only_their_OWN_UNPUBLISHED_draft,
        test_an_admin_may_delete_anything,
        test_only_viewonly_may_delete_nothing,
        test_delete_ENFORCES_rather_than_relying_on_the_caller_to_ask,
        test_a_DRAFT_is_invisible_even_at_all_users_with_an_entitlement,
        test_publishing_alone_does_not_make_it_visible,
        test_reverting_to_draft_immediately_hides_published_content,
        test_the_body_column_holds_SOURCE_never_rendered_html,
        test_render_body_of_a_missing_topic_is_empty_not_an_error,
        test_no_diagnostic_reads_the_custom_content_table,
        test_a_plain_USER_may_delete_their_own_unapproved_submission,
        test_viewonly_still_cannot_delete_anything,
        test_sub_admin_and_admin_are_unaffected_by_the_lowered_floor,
        test_the_cap_counts_only_UNAPPROVED_submissions,
        test_the_cap_is_PER_USER_not_global,
        test_EDITING_an_existing_submission_does_not_consume_a_new_slot,
        test_an_admin_is_not_capped,
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
