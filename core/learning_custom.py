"""Business-authored Learning Center content: storage and the draft/publish machine.

Custom content is the business's own material — onboarding notes, internal procedures,
job-specific training — stored in the database alongside the built-in curriculum that
ships as code. That split is structural: an upgrade replaces built-in topics and never
touches these rows, and these rows are the ONLY copy, since they cannot be restored from
git the way shipped content can.

⛔ TWO INDEPENDENT CEILINGS, AND BOTH MUST PASS.
    1. STATUS      — a draft is invisible to learners, full stop.
    2. VISIBILITY  — the existing three-state model plus per-user entitlement.
    A draft set to `all_users` with an entitlement held is STILL invisible. Without that
    independence, "draft" would mean "published with extra steps" and the approval gate
    would be decorative. `visible_to()` here checks status first and then delegates the
    rest to `learning.visible_to`, so there is one visibility rule, not two.

⛔ EDITING PUBLISHED CONTENT RETURNS IT TO DRAFT.
    The non-obvious half of "anyone submits, an admin approves". Without it a submitter
    could alter text an admin already approved, and the approval would then attest to
    content that no longer exists. The friction — a typo fix needs re-approval — is
    accepted deliberately, because the alternative is an approval that means nothing.
    (An earlier design gated drafting on `sub_admin`; that was rejected because a
    sub_admin ROUTE_MINIMUMS entry stops the dashboard starting. Submission is open to
    any authenticated account and approval is admin-only.)

⛔ DELETE IS THE ONE RULE `ROUTE_MINIMUMS` CANNOT EXPRESS, SO IT LIVES HERE.
    A registry entry gates on the caller's ROLE. This rule also depends on the ROW: an
    admin may delete anything; a submitter may delete only their OWN UNAPPROVED work.
    ⚠ No rule below the registry may branch on `sub_admin` -- the import canary can only
    see the registry layer, so that is maintained by discipline rather than by check.
    Putting it in the route would leave the function reachable by any second caller with
    the rule attached to only one path — the divergence the route-security practice
    exists to prevent. `delete()` therefore ENFORCES rather than trusting callers to ask.

⛔ THE BODY COLUMN HOLDS THE AUTHOR'S SOURCE, NEVER RENDERED HTML.
    Rendering happens on read. Storing output would freeze today's escaping into every
    row authored before a renderer fix — the fix would never reach existing content — and
    would fill the database with markup that LOOKS trusted.
"""
import re
import sqlite3
import time

SLUG_PREFIX = "custom-"
STATUS_DRAFT = "draft"
STATUS_PUBLISHED = "published"
STATUSES = (STATUS_DRAFT, STATUS_PUBLISHED)

#: URL-safe and DB-safe without escaping, and bounded so a slug cannot be used to
#: smuggle length into a path.
_SLUG_RE = re.compile(r"^%s[a-z0-9][a-z0-9-]{0,55}$" % re.escape(SLUG_PREFIX))

MAX_TITLE = 200
MAX_SUMMARY = 500

#: Per-user ceiling on UNAPPROVED submissions. Volume control, not authorization.
#:
#: Needed because the redesign widened submission from a handful of delegates to EVERY
#: authenticated account, and nothing else bounds row creation. Deliberately per-user: a
#: global cap would let one noisy account block everyone else, which is a denial of
#: service wearing a quota's clothes.
#:
#: Counts only UNAPPROVED work. An approved submission must not count against its author
#: forever -- that would punish a contributor for being published, which is backwards --
#: and editing an existing submission consumes no new slot, or the cap would block
#: CORRECTION rather than volume.
MAX_UNAPPROVED_PER_USER = 10

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS learning_custom_topics (
    slug         TEXT PRIMARY KEY,
    title        TEXT NOT NULL,
    summary      TEXT NOT NULL,
    body         TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'draft',
    created_by   TEXT,
    created_at   TEXT NOT NULL,
    updated_by   TEXT,
    updated_at   TEXT NOT NULL,
    published_by TEXT,
    published_at TEXT
);
"""


class CustomError(Exception):
    """Bad input. Raised rather than normalised — a typo should fail where it enters."""


class PermissionDenied(Exception):
    """The caller may not do this to THIS row. Distinct from CustomError so a route can
    answer 403 for one and 400 for the other rather than collapsing both."""


class SavedSlug(str):
    """The slug `save_draft` wrote, carrying whether that write CREATED the row.

    ⛔ A str SUBCLASS, not a tuple, deliberately. 43 call sites use this return as the
    slug and exactly one needs the provenance. A tuple would silently change what every
    other one formats, renders, or binds to SQL -- trading a notification bug for a
    quieter and more widespread one. This IS the slug: `==`, `%s`, `json.dumps` and
    sqlite binding all behave exactly as they did before, with one attribute added for
    the single caller that must tell a new submission from an edit.

    ⛔ WHY THE FACT TRAVELS BACK AT ALL, rather than the caller checking for itself.
    `save_draft` ALREADY reads the existing row -- it has to, to enforce ownership and
    the per-user cap. A route re-reading to ask "was this new?" would be a second source
    of truth for a question this function has already answered, and the two would drift
    the first time either changed. Same reasoning that keeps the row rules out of the
    handlers. See `dashboard.api_learn_custom_save`.

    (No `__slots__`: a non-empty one is not permitted on a subclass of a variable-length
    built-in like `str`.)
    """

    def __new__(cls, slug, created):
        obj = super().__new__(cls, slug)
        obj.created = bool(created)
        return obj

    def __repr__(self):
        return "SavedSlug(%s, created=%r)" % (str.__repr__(self), self.created)


def _db(db_path, readonly=False):
    if db_path is None:
        import nemesis_paths
        db_path = nemesis_paths.db_path()
    if readonly:
        return sqlite3.connect("file:%s?mode=ro" % db_path, uri=True, timeout=5.0)
    return sqlite3.connect(db_path, timeout=5.0)


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())


def _is_admin(role):
    """True only for a genuine admin. An unreadable role is NOT an admin."""
    if not role:
        return False
    try:
        import roles as _roles
        return _roles.normalise_role(role) == _roles.ROLE_ADMIN
    except Exception:
        return False


def validate_slug(slug):
    """A custom slug. Namespaced so it can never collide with or impersonate a built-in.

    Checked against the built-in registry as well as the pattern: the prefix makes
    collision impossible by construction, and the explicit check means a future built-in
    that broke that convention fails loudly here rather than silently shadowing.
    """
    if not isinstance(slug, str) or not _SLUG_RE.match(slug):
        # Human-readable, not the compiled pattern -- a raw regex in a 400 body is not
        # an acceptable answer to "why was this refused". The submission form now
        # derives and prepends the prefix itself, so a caller hitting this is either a
        # direct API user or the one edge case the form leaves editable; either way
        # they get an instruction, not a character class.
        raise CustomError(
            "slug must start with %r followed by 1-56 lowercase letters, numbers or "
            "hyphens (starting with a letter or number); got %r" % (SLUG_PREFIX, slug))
    try:
        import learning_topics as _lt
        if slug in _lt.all_slugs():
            raise CustomError("slug %r collides with a built-in topic" % slug)
    except ImportError:
        pass
    return slug


def validate_status(status):
    if status not in STATUSES:
        raise CustomError("unknown status %r; must be one of %s"
                          % (status, list(STATUSES)))
    return status


# ── reads ────────────────────────────────────────────────────────────────────

def unapproved_count(actor, db_path=None):
    """How many UNAPPROVED submissions this author currently holds."""
    if not actor:
        return 0
    conn = _db(db_path, readonly=True)
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM learning_custom_topics "
            "WHERE created_by=? AND status=?", (actor, STATUS_DRAFT)).fetchone()
        return row[0] if row else 0
    finally:
        conn.close()


def get(slug, db_path=None):
    """One topic as a dict, or None. Never raises for a missing row."""
    if not isinstance(slug, str) or not slug:
        return None
    try:
        conn = _db(db_path, readonly=True)
    except Exception:
        return None
    try:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM learning_custom_topics WHERE slug=?", (slug,)).fetchone()
    except Exception:
        return None
    finally:
        conn.close()
    return dict(row) if row else None


def all_topics(status=None, db_path=None):
    """Every custom topic, optionally filtered by status. Ordered for stable listings."""
    conn = _db(db_path, readonly=True)
    try:
        conn.row_factory = sqlite3.Row
        if status is None:
            rows = conn.execute("SELECT * FROM learning_custom_topics "
                                "ORDER BY title").fetchall()
        else:
            rows = conn.execute("SELECT * FROM learning_custom_topics "
                                "WHERE status=? ORDER BY title",
                                (validate_status(status),)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def render_body(slug, db_path=None):
    """The topic's body as SAFE HTML. "" when there is no such topic.

    Rendering on read is what lets a renderer fix reach content authored before it.
    """
    t = get(slug, db_path)
    if not t:
        return ""
    import learning_render
    return learning_render.render(t["body"])


# ── the state machine ────────────────────────────────────────────────────────

def save_draft(slug, title, summary, body, actor=None, role=None, db_path=None):
    """Create or edit. ALWAYS leaves the topic in DRAFT.

    Editing published content therefore revokes its approval — see the module docstring.
    That is the behaviour, not a side effect, and it is why there is no `save` that
    preserves status.

    Returns a `SavedSlug` — the slug, with `.created` saying whether this call inserted
    the row rather than updating one. Callers that only want the slug can keep treating
    it as the plain string it is.
    """
    validate_slug(slug)
    for name, val, cap in (("title", title, MAX_TITLE),
                           ("summary", summary, MAX_SUMMARY)):
        if not isinstance(val, str) or not val.strip():
            raise CustomError("%s is required" % name)
        if len(val) > cap:
            raise CustomError("%s exceeds %d characters" % (name, cap))
    if not isinstance(body, str):
        raise CustomError("body must be text")

    # ── Per-user cap, applied to NEW submissions only ────────────────────────
    # Checked against the EXISTING row rather than blindly: editing something already
    # submitted consumes no new slot, so a user at the cap can still fix a typo. A cap
    # that blocked correction would be punishing the wrong thing.
    #
    # Admins are exempt: this bounds a wide submitting population, and an admin
    # publishing their own material is not that population.
    existing = get(slug, db_path)
    # ENFORCED HERE, not in the route. The registry entry is a coarse outer bound that
    # cannot see the row; the row rule has to exist somewhere, and putting it behind the
    # function means a second caller cannot bypass it -- the same reasoning `delete()`
    # already follows by re-checking `can_delete`.
    if not can_edit(existing, actor, role):
        raise PermissionDenied(
            "%r (%s) may not edit %r: it belongs to %r and is %r"
            % (actor, role, slug,
               (existing or {}).get("created_by"), (existing or {}).get("status")))

    is_new = existing is None
    if is_new and actor and not _is_admin(role):
        if unapproved_count(actor, db_path) >= MAX_UNAPPROVED_PER_USER:
            raise CustomError(
                "%r already has %d unapproved submissions (the limit). Withdraw one, "
                "or wait for an administrator to review them."
                % (actor, MAX_UNAPPROVED_PER_USER))

    now = _now()
    conn = _db(db_path)
    try:
        conn.execute("""
            INSERT INTO learning_custom_topics
                   (slug, title, summary, body, status,
                    created_by, created_at, updated_by, updated_at,
                    published_by, published_at)
            VALUES (?, ?, ?, ?, 'draft', ?, ?, ?, ?, NULL, NULL)
            ON CONFLICT(slug) DO UPDATE SET
                   title=excluded.title,
                   summary=excluded.summary,
                   body=excluded.body,
                   -- Reverting to draft AND clearing the approval are one statement
                   -- deliberately: a version that reset status but kept published_by
                   -- would leave a draft carrying an approver's name.
                   status='draft',
                   published_by=NULL,
                   published_at=NULL,
                   updated_by=excluded.updated_by,
                   updated_at=excluded.updated_at
        """, (slug, title.strip(), summary.strip(), body, actor, now, actor, now))
        conn.commit()
    finally:
        conn.close()
    # `is_new` comes from the same read that enforced the cap and ownership above, not
    # from a second lookup. Two callers racing to create the SAME slug could both read
    # no row and both report created=True -- one duplicate notification, never a missed
    # one, since a row that does not exist yet cannot be read as existing. The race
    # therefore fails toward telling an admin twice rather than never.
    return SavedSlug(slug, created=is_new)


def set_status(slug, status, actor=None, role=None, db_path=None):
    """Move a topic between draft and published. ADMIN ONLY, enforced HERE.

    ⛔ THIS GUARD EXISTS BECAUSE ITS ABSENCE DEFEATED THE STATUS CEILING IN TWO MOVES.
    `can_edit` and `can_delete` correctly check status BEFORE ownership, so an author
    cannot touch their own approved content directly. But this function had no check at
    all and relied on the route being admin-gated -- so calling `unpublish()` reverted
    approved content to a draft, after which ownership applied again and the author could
    edit or delete it. Reproduced: alice (role=user) unpublished her own approved row.

    The same class Window 1 caught on the write path: a rule that lives only in the route
    is not a rule, because the function stays reachable. Approval is the one thing the
    review queue exists to control, so who may grant and revoke it belongs here.

    Fails CLOSED on an unparseable role -- a caller who cannot say who they are does not
    get to publish.
    """
    validate_status(status)
    if not _is_admin(role):
        raise PermissionDenied(
            "%r (%s) may not change publication status of %r: admin only"
            % (actor, role, slug))
    if get(slug, db_path) is None:
        raise CustomError("no such custom topic: %r" % slug)

    now = _now()
    conn = _db(db_path)
    try:
        if status == STATUS_PUBLISHED:
            conn.execute("UPDATE learning_custom_topics SET status=?, published_by=?, "
                         "published_at=? WHERE slug=?", (status, actor, now, slug))
        else:
            # Returning to draft clears the approval. Keeping it would leave a draft
            # that still names an approver for text they may never have seen.
            conn.execute("UPDATE learning_custom_topics SET status=?, published_by=NULL,"
                         " published_at=NULL WHERE slug=?", (status, slug))
        conn.commit()
    finally:
        conn.close()
    return status


def publish(slug, actor=None, role=None, db_path=None):
    """Approve a submission. Admin only -- see set_status."""
    return set_status(slug, STATUS_PUBLISHED, actor=actor, role=role, db_path=db_path)


def unpublish(slug, actor=None, role=None, db_path=None):
    """Withdraw approval. Admin only, and NOT a back door to edit rights -- see
    set_status for the chain this closes."""
    return set_status(slug, STATUS_DRAFT, actor=actor, role=role, db_path=db_path)


# ── delete: status- and ownership-aware ─────────────────────────────────────

def can_edit(topic, actor, role):
    """May `actor` (holding `role`) EDIT this existing row?

    ⛔ THIS EXISTS BECAUSE THE WRITE PATH HAD NO OWNERSHIP RULE AND NEEDED ONE.
    `save_draft` is an UPSERT keyed on slug alone. While submission was limited to a few
    trusted delegates, the route minimum bounded who could reach it at all. Opening
    submission to every account removed that bound and nothing behind it took over --
    reproduced at 986d077: a plain user overwrote another user's ADMIN-APPROVED row,
    which stayed attributed to the original author while the edit-reverts-to-draft rule
    silently revoked the approval.

    Deliberately IDENTICAL in shape to `can_delete`: admin may act on anything; a
    submitter only on their OWN work and only while UNAPPROVED. Two rules with one
    intent, and a test asserts they agree on the same row -- if they diverge, a caller
    consulting either gets a confident wrong answer.

    Returns True for a MISSING topic: creating a new submission is not an edit, and
    ownership must not block creation or open submission would not work at all.
    """
    if not topic:
        return True                       # a new row -- see docstring
    try:
        import roles as _roles
        r = _roles.normalise_role(role)
    except Exception:
        return False                      # an unknown role proves nothing
    if r == _roles.ROLE_ADMIN:
        return True
    if _roles.rank(r) < _roles.rank(_roles.ROLE_USER):
        return False                      # viewonly writes nothing, ever
    return (topic.get("status") == STATUS_DRAFT
            and bool(actor) and topic.get("created_by") == actor)


def can_delete(topic, actor, role):
    """May `actor` (holding `role`) delete THIS row?

    Advice, for a UI deciding whether to show a button. `delete()` re-checks it, because
    a control that only hides an action does not prevent it.
    """
    if not topic:
        return False
    try:
        import roles as _roles
        r = _roles.normalise_role(role)
    except Exception:
        return False           # an unknown role proves nothing

    if r == _roles.ROLE_ADMIN:
        return True
    if _roles.rank(r) < _roles.rank(_roles.ROLE_USER):
        return False           # viewonly writes nothing, ever
    # Any SUBMITTER (user and above): their OWN work, and only while UNAPPROVED.
    # The floor moved from sub_admin to user when submission opened to every account;
    # the ownership and status conditions are deliberately unchanged, because they are
    # what stop a submitter withdrawing something an admin already approved.
    return (topic.get("status") == STATUS_DRAFT
            and bool(actor) and topic.get("created_by") == actor)


def delete(slug, actor, role, db_path=None):
    """Delete a custom topic. ENFORCES `can_delete` rather than trusting the caller.

    The route also gates by role, but this is the boundary: the rule depends on the row,
    which a registry entry cannot see, and a second caller reaching this function must
    not bypass it.
    """
    topic = get(slug, db_path)
    if topic is None:
        raise CustomError("no such custom topic: %r" % slug)
    if not can_delete(topic, actor, role):
        raise PermissionDenied(
            "%r (%s) may not delete %r in status %r"
            % (actor, role, slug, topic.get("status")))
    conn = _db(db_path)
    try:
        conn.execute("DELETE FROM learning_custom_topics WHERE slug=?", (slug,))
        conn.commit()
    finally:
        conn.close()
    return True


# ── visibility: status ceiling, then the shared rule ────────────────────────

def visible_to(user_id, role, slug, db_path=None):
    """May this account READ this custom topic right now?

    Status is checked FIRST and independently; everything after it delegates to
    `learning.visible_to` so custom and built-in content share one visibility rule
    rather than growing a second, divergent one.
    """
    topic = get(slug, db_path)
    if topic is None:
        return False
    if topic.get("status") != STATUS_PUBLISHED:
        return False           # ceiling 1: a draft is invisible to everyone
    import learning
    return learning.visible_to(user_id, role, slug, db_path)   # ceiling 2
