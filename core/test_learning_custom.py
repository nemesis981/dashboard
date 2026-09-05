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

EXPECTED_CHECKS = 119
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
    # role is supplied because `can_edit` fails CLOSED on an unknown role -- a caller
    # that cannot say who it is does not get to edit an existing row.
    return C.save_draft(slug=slug, title=kw.get("title", "Onboarding"),
                        summary=kw.get("summary", "How we do things"),
                        body=kw.get("body", "# Welcome\n\n**read this**"),
                        actor=actor, role=kw.get("role", "user"), db_path=db)


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
    C.publish("custom-onboarding", actor="admin1", role="admin", db_path=db)
    t = C.get("custom-onboarding", db_path=db)
    eq("status is published", t["status"], C.STATUS_PUBLISHED)
    eq("publisher recorded SEPARATELY from the author", t["published_by"], "admin1")
    check("published_at set", bool(t["published_at"]))
    eq("author unchanged", t["created_by"], "alice")


def test_EDITING_A_PUBLISHED_TOPIC_REVERTS_IT_TO_DRAFT():
    """The approval must not survive the text it approved."""
    db = fresh_db()
    mk(db)
    C.publish("custom-onboarding", actor="admin1", role="admin", db_path=db)
    eq("published first", C.get("custom-onboarding", db_path=db)["status"],
       C.STATUS_PUBLISHED)

    # ⚠ Edited by an ADMIN, not by a passing user. An earlier version of this test had
    # "bob" (neither the creator nor an admin) edit alice's PUBLISHED row -- which is
    # exactly the privilege escalation `can_edit` now forbids. The test was demonstrating
    # revert-to-draft using an action that should never have been possible.
    C.save_draft(slug="custom-onboarding", title="Onboarding v2",
                 summary="changed", body="new text", actor="admin2", role="admin",
                 db_path=db)
    t = C.get("custom-onboarding", db_path=db)
    eq("editing REVERTED it to draft", t["status"], C.STATUS_DRAFT)
    eq("...and cleared the approval", t["published_by"], None)
    eq("...and its timestamp", t["published_at"], None)
    eq("the editor is recorded", t["updated_by"], "admin2")
    eq("the original author is NOT overwritten", t["created_by"], "alice")


def test_unpublish_returns_to_draft():
    db = fresh_db()
    mk(db)
    C.publish("custom-onboarding", actor="admin1", role="admin", db_path=db)
    C.unpublish("custom-onboarding", actor="admin1", role="admin", db_path=db)
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

    C.publish("custom-mine", actor="admin1", role="admin", db_path=db)
    check("their OWN topic once PUBLISHED: refused",
          C.can_delete(C.get("custom-mine", db_path=db), "alice", "sub_admin") is False)


def test_an_admin_may_delete_anything():
    db = fresh_db()
    mk(db, slug="custom-x", actor="alice")
    check("admin deletes someone else's draft",
          C.can_delete(C.get("custom-x", db_path=db), "admin1", "admin") is True)
    C.publish("custom-x", actor="admin1", role="admin", db_path=db)
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
    C.publish("custom-x", actor="admin1", role="admin", db_path=db)
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
    C.publish("custom-x", actor="admin1", role="admin", db_path=db)
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
    C.publish("custom-x", actor="admin1", role="admin", db_path=db)
    L.set_topic_state("custom-x", L.STATE_ALL_USERS, db_path=db)
    L.grant(7, "custom-x", db_path=db)
    check("visible while published", C.visible_to(7, "user", "custom-x", db_path=db))
    C.save_draft(slug="custom-x", title="t", summary="s", body="b",
                 actor="alice", role="admin", db_path=db)
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

    C.publish("custom-mine", actor="admin1", role="admin", db_path=db)
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

    C.publish("custom-d0", actor="admin1", role="admin", db_path=db)
    eq("publishing frees a slot", C.unapproved_count("dave", db_path=db),
       C.MAX_UNAPPROVED_PER_USER - 1)
    check("...and a new submission is accepted again",
          C.save_draft(slug="custom-over", title="t", summary="s", body="b",
                       actor="dave", role="user", db_path=db) is not None)


def test_the_cap_is_PER_USER_not_global():
    """A global cap would let one noisy account block everyone else -- a denial of
    service dressed as a quota."""
    db = fresh_db()
    for i in range(C.MAX_UNAPPROVED_PER_USER):
        C.save_draft(slug="custom-a%d" % i, title="t", summary="s", body="b",
                     actor="dave", db_path=db)
    check("a DIFFERENT user is unaffected",
          C.save_draft(slug="custom-b0", title="t", summary="s", body="b",
                       actor="erin", role="user", db_path=db) is not None)
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
                       actor="dave", role="user", db_path=db) is not None)
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


# ── I. ⛔ WRITE-PATH OWNERSHIP (privilege escalation, found by Window 1) ─────

def test_a_user_CANNOT_overwrite_someone_elses_submission():
    """⛔ REGRESSION TEST FOR A REPRODUCED PRIVILEGE ESCALATION.

    `save_draft` is an UPSERT keyed on slug alone. `can_delete` was given an ownership
    rule; the write path never had one, because the route minimum used to bound the
    population to trusted delegates. Opening submission to every account removes that
    bound, and nothing behind it took over.

    Reproduced at 986d077 before the fix: bob (role=user, not the creator) overwrote
    alice's ADMIN-APPROVED row. `created_by` stayed 'alice', so the queue still
    attributed it to her, and the "editing reverts to draft" rule silently revoked the
    admin's approval as a side effect. Slugs are user-chosen and enumerable from the
    published list, so it needed no guessing.

    The per-user cap does not help: it counts submissions BY actor, and overwriting
    someone else's row creates none.
    """
    db = fresh_db()
    C.save_draft(slug="custom-alice", title="Alice Title", summary="hers",
                 body="alice body", actor="alice", db_path=db)
    check("bob cannot overwrite alice's DRAFT",
          raises(C.PermissionDenied,
                 lambda: C.save_draft(slug="custom-alice", title="BOB", summary="x",
                                      body="y", actor="bob", role="user", db_path=db)))
    eq("...and the content is untouched",
       C.get("custom-alice", db_path=db)["title"], "Alice Title")


def test_a_user_CANNOT_overwrite_APPROVED_content_and_revoke_its_approval():
    """The sharper half: the edit-reverts-to-draft rule turns an unauthorised write into
    an unpublish. Approval must not be revocable by someone who cannot approve."""
    db = fresh_db()
    C.save_draft(slug="custom-alice", title="Alice Title", summary="hers",
                 body="b", actor="alice", db_path=db)
    C.publish("custom-alice", actor="admin1", role="admin", db_path=db)

    check("bob is refused",
          raises(C.PermissionDenied,
                 lambda: C.save_draft(slug="custom-alice", title="BOB", summary="x",
                                      body="y", actor="bob", role="user", db_path=db)))
    t = C.get("custom-alice", db_path=db)
    eq("status still published", t["status"], C.STATUS_PUBLISHED)
    eq("approval intact", t["published_by"], "admin1")
    eq("title untouched", t["title"], "Alice Title")


def test_even_the_CREATOR_cannot_edit_once_an_admin_approved_it():
    """Consistent with delete: approved content is the admin's to change. Otherwise the
    author could silently unpublish their own approved material at will."""
    db = fresh_db()
    C.save_draft(slug="custom-a", title="T", summary="s", body="b",
                 actor="alice", db_path=db)
    C.publish("custom-a", actor="admin1", role="admin", db_path=db)
    check("alice cannot edit her own APPROVED submission",
          raises(C.PermissionDenied,
                 lambda: C.save_draft(slug="custom-a", title="edit", summary="s",
                                      body="b2", actor="alice", role="user",
                                      db_path=db)))
    eq("still published", C.get("custom-a", db_path=db)["status"], C.STATUS_PUBLISHED)


def test_the_creator_CAN_edit_their_own_unapproved_submission():
    """The positive control. A rule that refused everyone would pass every check above
    while making the feature unusable."""
    db = fresh_db()
    C.save_draft(slug="custom-a", title="T", summary="s", body="b",
                 actor="alice", db_path=db)
    C.save_draft(slug="custom-a", title="Fixed", summary="s", body="b2",
                 actor="alice", role="user", db_path=db)
    eq("her own edit applied", C.get("custom-a", db_path=db)["title"], "Fixed")


def test_an_admin_may_edit_anything():
    db = fresh_db()
    C.save_draft(slug="custom-a", title="T", summary="s", body="b",
                 actor="alice", db_path=db)
    C.publish("custom-a", actor="admin1", role="admin", db_path=db)
    C.save_draft(slug="custom-a", title="Admin Edit", summary="s", body="b2",
                 actor="admin1", role="admin", db_path=db)
    t = C.get("custom-a", db_path=db)
    eq("admin edit applied", t["title"], "Admin Edit")
    eq("...and it reverted to draft as designed", t["status"], C.STATUS_DRAFT)


def test_creating_a_NEW_submission_is_open_to_any_submitter():
    """Ownership constrains EDITS of an existing row. It must not block creation, or
    open submission would not work at all."""
    db = fresh_db()
    check("a brand-new slug is accepted from anyone",
          C.save_draft(slug="custom-new", title="T", summary="s", body="b",
                       actor="zoe", role="user", db_path=db) is not None)


def test_can_edit_and_can_delete_agree_on_the_same_row():
    """Two rules, one intent. If they diverge, one of them is wrong -- and a caller
    consulting the wrong one gets a confident wrong answer."""
    db = fresh_db()
    C.save_draft(slug="custom-a", title="T", summary="s", body="b",
                 actor="alice", db_path=db)
    t = C.get("custom-a", db_path=db)
    for actor, role in (("alice", "user"), ("bob", "user"),
                        ("alice", "viewonly"), ("admin1", "admin")):
        check("edit/delete agree for %s/%s" % (actor, role),
              C.can_edit(t, actor, role) == C.can_delete(t, actor, role),
              "edit=%s delete=%s" % (C.can_edit(t, actor, role),
                                     C.can_delete(t, actor, role)))


def test_an_UNPARSEABLE_role_is_refused_by_both_rules():
    """⚠ ADDED AFTER A SURVIVING MUTATION. Flipping `can_edit`'s exception handler from
    `return False` to `return True` -- i.e. fail-OPEN on a role it cannot parse -- left
    the suite green. Nothing asserted the direction of that fallback, so the most
    security-relevant branch in the function was untested.

    A role that cannot be parsed proves nothing about the caller. Both rules must refuse,
    and they must refuse for the same reason.
    """
    db = fresh_db()
    mk(db, slug="custom-x", actor="alice")
    t = C.get("custom-x", db_path=db)
    # ⚠ "ADMIN " and "Admin" are NOT garbage: `normalise_role` deliberately accepts case
    # and separator variants ("sub-admin" -> "sub_admin"). An earlier version of this
    # test listed "ADMIN " as unparseable and FAILED against correct behaviour -- my
    # assumption about what counts as garbage, not a defect in the rule.
    for bad in ("wizard", "root", "", None, 42, ["admin"]):
        check("can_edit refuses role %r" % (bad,),
              C.can_edit(t, "alice", bad) is False)
        check("can_delete refuses role %r" % (bad,),
              C.can_delete(t, "alice", bad) is False)

    # The companion positive control: a legitimate VARIANT must still be honoured, or
    # "refuse what you cannot parse" would have quietly become "refuse anything odd".
    check("a case/space variant of admin IS honoured",
          C.can_edit(t, "someone-else", "ADMIN ") is True)


def test_save_draft_refuses_an_unparseable_role_on_an_existing_row():
    """The same fallback, exercised through the enforcing path rather than the advisor."""
    db = fresh_db()
    mk(db, slug="custom-x", actor="alice")
    check("save_draft refuses a garbage role",
          raises(C.PermissionDenied,
                 lambda: C.save_draft(slug="custom-x", title="t", summary="s",
                                      body="b", actor="alice", role="wizard",
                                      db_path=db)))
    eq("content untouched", C.get("custom-x", db_path=db)["title"], "Onboarding")


# ── J. ⛔ THE UNPUBLISH CHAIN (adjacent path defeating the status ceiling) ───

def test_the_author_cannot_UNPUBLISH_their_way_back_to_edit_rights():
    """⛔ REGRESSION TEST FOR AN ATTACK CHAIN, not a single call.

    can_edit and can_delete correctly check status BEFORE ownership, so an author cannot
    touch their own approved content directly. But `set_status` (and therefore publish /
    unpublish) had NO domain-layer guard at all -- it relied entirely on the route being
    admin-gated. Reproduced: alice, role=user, called unpublish() on her own published
    row and it became a draft. Ownership then applies again and she may edit or delete
    it.

    So the status ceiling was defeatable in two moves by the person it most needed to
    constrain. This is the same class Window 1 caught on the write path: a rule that
    exists only in the route is not a rule, because the function stays reachable.
    """
    db = fresh_db()
    mk(db, slug="custom-a", actor="alice")
    C.publish("custom-a", actor="admin1", role="admin", db_path=db)

    check("step 1: the author cannot unpublish her own approved content",
          raises(C.PermissionDenied,
                 lambda: C.unpublish("custom-a", actor="alice", role="user",
                                     db_path=db)))
    eq("...so it is still published", C.get("custom-a", db_path=db)["status"],
       C.STATUS_PUBLISHED)
    check("step 2: and therefore still cannot edit it",
          C.can_edit(C.get("custom-a", db_path=db), "alice", "user") is False)
    eq("approval intact throughout", C.get("custom-a", db_path=db)["published_by"],
       "admin1")


def test_a_non_admin_cannot_PUBLISH_their_own_submission():
    """The other half. Without a guard, a submitter could approve their own work --
    which is the entire thing the review queue exists to prevent."""
    db = fresh_db()
    mk(db, slug="custom-a", actor="alice")
    check("alice cannot publish her own draft",
          raises(C.PermissionDenied,
                 lambda: C.publish("custom-a", actor="alice", role="user",
                                   db_path=db)))
    eq("still a draft", C.get("custom-a", db_path=db)["status"], C.STATUS_DRAFT)
    check("nor can a sub_admin",
          raises(C.PermissionDenied,
                 lambda: C.publish("custom-a", actor="sam", role="sub_admin",
                                   db_path=db)))


def test_an_admin_CAN_publish_and_unpublish():
    """Positive control. A guard that refused everyone would satisfy both tests above
    while making approval impossible."""
    db = fresh_db()
    mk(db, slug="custom-a", actor="alice")
    C.publish("custom-a", actor="admin1", role="admin", db_path=db)
    eq("admin published it", C.get("custom-a", db_path=db)["status"],
       C.STATUS_PUBLISHED)
    C.unpublish("custom-a", actor="admin1", role="admin", db_path=db)
    eq("admin unpublished it", C.get("custom-a", db_path=db)["status"],
       C.STATUS_DRAFT)


def test_set_status_fails_closed_on_an_unparseable_role():
    db = fresh_db()
    mk(db, slug="custom-a", actor="alice")
    for bad in ("wizard", "", None, 42):
        check("publish refused for role %r" % (bad,),
              raises(C.PermissionDenied,
                     lambda b=bad: C.publish("custom-a", actor="x", role=b,
                                             db_path=db)))


# ── K. Two DDL copies must never drift (ADR 0001) ──────────────────────────

def test_the_two_DDL_copies_are_identical():
    """⚠ The table's CREATE lives in TWO places: `learning_custom.SCHEMA_SQL` (used by
    tests to build a temp DB) and `database.init_learning_tables()` (what a real install
    runs). ADR 0001 says a table's DDL lives in exactly ONE canonical init, and this is a
    real deviation from it.

    Identical today, verified. Kept as two copies rather than collapsed because the test
    fixture genuinely needs a standalone schema and importing `database` into every unit
    test would drag the whole alert_manager import graph in. So the duplication buys
    something -- but it must not be allowed to drift SILENTLY, which is the actual risk:
    whichever init runs first wins, and a column added to one copy would leave a fresh
    install with a different table shape than an upgraded one, discovered only when a
    query fails on one of them.

    This test is the cheap half of that trade. It fails the day someone edits one copy,
    which is the only moment the divergence is easy to fix.

    Compared on NORMALISED column text rather than raw source, so indentation and the
    surrounding Python (a bare string here, an `execute()` call there) do not produce a
    false mismatch that trains people to ignore it.
    """
    import re
    def columns(path):
        src = io.open(path, encoding="utf-8").read()
        m = re.search(
            r"CREATE TABLE IF NOT EXISTS learning_custom_topics\s*\((.*?)\)\s*;?",
            src, re.S | re.I)
        if not m:
            return None
        return re.sub(r"\s+", " ", m.group(1)).strip().rstrip(",")

    a = columns(os.path.join(_REPO, "core", "learning_custom.py"))
    b = columns(os.path.join(_REPO, "alert_manager", "database.py"))
    check("found the DDL in learning_custom.py", a is not None)
    check("found the DDL in database.py", b is not None)
    check("the two copies are IDENTICAL", a == b,
          "they have drifted:\n  learning_custom: %s\n  database:        %s" % (a, b))

    # Control: the comparison is not vacuously true because both are empty/None.
    check("control: the extracted DDL is substantial",
          a is not None and len(a) > 100, "len=%r" % (len(a) if a else None))
    check("control: it actually names the status column",
          a is not None and "status" in a)


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
        test_a_user_CANNOT_overwrite_someone_elses_submission,
        test_a_user_CANNOT_overwrite_APPROVED_content_and_revoke_its_approval,
        test_even_the_CREATOR_cannot_edit_once_an_admin_approved_it,
        test_the_creator_CAN_edit_their_own_unapproved_submission,
        test_an_admin_may_edit_anything,
        test_creating_a_NEW_submission_is_open_to_any_submitter,
        test_can_edit_and_can_delete_agree_on_the_same_row,
        test_an_UNPARSEABLE_role_is_refused_by_both_rules,
        test_save_draft_refuses_an_unparseable_role_on_an_existing_row,
        test_the_author_cannot_UNPUBLISH_their_way_back_to_edit_rights,
        test_a_non_admin_cannot_PUBLISH_their_own_submission,
        test_an_admin_CAN_publish_and_unpublish,
        test_set_status_fails_closed_on_an_unparseable_role,
        test_the_two_DDL_copies_are_identical,
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
