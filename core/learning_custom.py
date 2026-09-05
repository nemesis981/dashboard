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
    The non-obvious half of "sub_admin drafts, admin publishes". Without it a sub_admin
    could alter text an admin already approved, and the approval would then attest to
    content that no longer exists. The friction — a typo fix needs re-approval — is
    accepted deliberately, because the alternative is an approval that means nothing.

⛔ DELETE IS THE ONE RULE `ROUTE_MINIMUMS` CANNOT EXPRESS, SO IT LIVES HERE.
    A registry entry gates on the caller's ROLE. This rule also depends on the ROW: an
    admin may delete anything; a sub_admin may delete only their OWN UNPUBLISHED draft.
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


def _db(db_path, readonly=False):
    if db_path is None:
        import nemesis_paths
        db_path = nemesis_paths.db_path()
    if readonly:
        return sqlite3.connect("file:%s?mode=ro" % db_path, uri=True, timeout=5.0)
    return sqlite3.connect(db_path, timeout=5.0)


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())


def validate_slug(slug):
    """A custom slug. Namespaced so it can never collide with or impersonate a built-in.

    Checked against the built-in registry as well as the pattern: the prefix makes
    collision impossible by construction, and the explicit check means a future built-in
    that broke that convention fails loudly here rather than silently shadowing.
    """
    if not isinstance(slug, str) or not _SLUG_RE.match(slug):
        raise CustomError(
            "slug must match %s and be url-safe; got %r" % (_SLUG_RE.pattern, slug))
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

def save_draft(slug, title, summary, body, actor=None, db_path=None):
    """Create or edit. ALWAYS leaves the topic in DRAFT.

    Editing published content therefore revokes its approval — see the module docstring.
    That is the behaviour, not a side effect, and it is why there is no `save` that
    preserves status.
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
    return slug


def set_status(slug, status, actor=None, db_path=None):
    """Move a topic between draft and published. Raises on an unknown status."""
    validate_status(status)
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


def publish(slug, actor=None, db_path=None):
    return set_status(slug, STATUS_PUBLISHED, actor=actor, db_path=db_path)


def unpublish(slug, actor=None, db_path=None):
    return set_status(slug, STATUS_DRAFT, actor=actor, db_path=db_path)


# ── delete: status- and ownership-aware ─────────────────────────────────────

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
    if _roles.rank(r) < _roles.rank(_roles.ROLE_SUB_ADMIN):
        return False           # user and viewonly may delete nothing
    # sub_admin: their OWN work, and only while it is still unapproved.
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
