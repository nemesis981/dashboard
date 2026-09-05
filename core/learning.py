"""Learning Center — three-state topic visibility and per-user entitlements.

Two controls govern one page, and the whole correctness of this module is in how they
compose:

    TOPIC STATE   — a global ceiling, set by an admin, one of:
                      not_included  (default; nobody, ever)
                      admin_only    (admins only)
                      all_users     (user-and-above WHO HOLD AN ENTITLEMENT)
    ENTITLEMENT   — a per-user assignment, seeded from a default set and adjustable
                      individually afterwards.

⛔ THE CEILING IS RE-READ ON EVERY REQUEST AND IS NEVER BAKED INTO A GRANT.
    The tempting shortcut is to resolve "can this person read this" once, at grant
    time, and store the answer. It is wrong in a way that fails silently and in the
    worst direction: flipping a topic to `not_included` would then leave every
    previously-granted user still reading it. The global control would appear to work
    -- new users correctly get nothing -- while doing nothing at all for the
    population it was reached for. So `visible_to()` reads state fresh, every time.

⛔ AN UNRECOGNISED STATE FAILS CLOSED, AND ABSENCE IS NOT AN ERROR.
    A topic with no row is `not_included`, because content ships with core
    unconditionally and "nobody configured this yet" must mean invisible. A row whose
    state is corrupt or unrecognised is ALSO `not_included` -- a value nobody can
    interpret must not resolve to "show it to everyone".

⛔ TIER IS NOT A CONTROL HERE AND MUST NEVER BECOME ONE.
    The curriculum's Beginner/Intermediate/Pro tiers are a client-side localStorage
    preference, and `tier.js` emits ALL THREE variants into the DOM because the server
    cannot read localStorage. Pro text is therefore already delivered to a Beginner
    reader. That is fine for prose and fatal for anything else: no capability may ever
    be gated on tier. Visibility and role are the server-side controls; tier is
    presentation.
"""
import sqlite3
import time

#: The three states, and the only three. Anything else is refused rather than mapped.
STATE_NOT_INCLUDED = "not_included"
STATE_ADMIN_ONLY = "admin_only"
STATE_ALL_USERS = "all_users"
STATES = (STATE_NOT_INCLUDED, STATE_ADMIN_ONLY, STATE_ALL_USERS)

#: The safe state. Used for an absent row, an unreadable row, and an unrecognised value.
DEFAULT_STATE = STATE_NOT_INCLUDED


class LearningError(Exception):
    """Bad input. Raised rather than resolved to a default -- see module docstring."""


def _db(db_path=None, readonly=False):
    """Connection. Mirrors core/entitlements.py rather than inventing a second idiom."""
    if db_path is None:
        import nemesis_paths
        db_path = nemesis_paths.db_path()
    if readonly:
        return sqlite3.connect("file:%s?mode=ro" % db_path, uri=True, timeout=5.0)
    return sqlite3.connect(db_path, timeout=5.0)


def normalise_state(raw):
    """A stored value -> a known state. Unrecognised input becomes not_included.

    Deliberately TOTAL rather than raising: this is the read path, and a corrupt row
    must not take the page down. It fails toward the narrowest entitlement, so the
    failure mode of a bad value is "nobody sees it" rather than "everybody does".
    Writers use `validate_state()` instead, which DOES raise -- a bad value should be
    refused where it enters, not silently narrowed there.
    """
    if isinstance(raw, str) and raw in STATES:
        return raw
    return DEFAULT_STATE


def validate_state(raw):
    """A state on its way IN. Raises, so a typo cannot be stored and later normalised."""
    if not isinstance(raw, str) or raw not in STATES:
        raise LearningError(
            "unknown visibility state %r; must be one of %s" % (raw, list(STATES)))
    return raw


def topic_state(topic_slug, db_path=None):
    """The stored ceiling for one topic. `not_included` when absent or unreadable."""
    if not topic_slug or not isinstance(topic_slug, str):
        return DEFAULT_STATE
    try:
        conn = _db(db_path, readonly=True)
    except Exception:
        # Cannot read the ceiling -> cannot prove anyone may see it.
        return DEFAULT_STATE
    try:
        row = conn.execute(
            "SELECT state FROM learning_topic_visibility WHERE topic_slug=?",
            (topic_slug,)).fetchone()
    except Exception:
        return DEFAULT_STATE
    finally:
        conn.close()
    if not row:
        return DEFAULT_STATE
    return normalise_state(row[0])


def has_entitlement(user_id, topic_slug, db_path=None):
    """Has this user been ASSIGNED this topic. Not the same as may-read -- see visible_to."""
    if user_id is None or not topic_slug:
        return False
    try:
        conn = _db(db_path, readonly=True)
    except Exception:
        return False
    try:
        row = conn.execute(
            "SELECT 1 FROM learning_entitlements WHERE user_id=? AND topic_slug=?",
            (user_id, topic_slug)).fetchone()
    except Exception:
        return False
    finally:
        conn.close()
    return row is not None


def visible_to(user_id, role, topic_slug, db_path=None):
    """THE decision. May this account read this topic, right now?

    Called by BOTH the index (to filter) and the detail route (to enforce). One
    function for both deliberately: a list that filters while the detail route does
    not enforce is reachable by typing the URL, and every test of the visible path
    passes against that bug. It is the `install_windows_start` shape.
    """
    import roles as _roles

    state = topic_state(topic_slug, db_path)          # ceiling, re-read every call
    if state == STATE_NOT_INCLUDED:
        return False                                   # applies to everyone, admins too

    try:
        r = _roles.normalise_role(role)
    except Exception:
        return False                                   # unknown role proves nothing

    if state == STATE_ADMIN_ONLY:
        return r == _roles.ROLE_ADMIN

    # all_users: `user` and above (viewonly deliberately excluded, operator decision
    # 2026-09-05), AND an individual assignment must exist.
    if _roles.rank(r) < _roles.rank(_roles.ROLE_USER):
        return False
    return has_entitlement(user_id, topic_slug, db_path)


def visible_topics(user_id, role, slugs, db_path=None):
    """Filter a slug list through `visible_to`. The index's only entry point.

    Takes the candidate list from the caller rather than reading every configured
    topic, so the index cannot show a topic the content layer does not actually have.
    """
    return [s for s in slugs if visible_to(user_id, role, s, db_path)]


# ── writes ───────────────────────────────────────────────────────────────────

def set_topic_state(topic_slug, state, actor=None, db_path=None):
    """Set a topic's ceiling. Raises on an unknown state rather than storing it."""
    if not topic_slug or not isinstance(topic_slug, str):
        raise LearningError("topic_slug is required")
    validate_state(state)
    conn = _db(db_path)
    try:
        conn.execute("""
            INSERT INTO learning_topic_visibility
                   (topic_slug, state, in_default, updated_at, actor)
            VALUES (?, ?, COALESCE((SELECT in_default FROM learning_topic_visibility
                                    WHERE topic_slug=?), 0), ?, ?)
            ON CONFLICT(topic_slug) DO UPDATE SET
                   state=excluded.state, updated_at=excluded.updated_at,
                   actor=excluded.actor
        """, (topic_slug, state, topic_slug, _now(), actor))
        conn.commit()
    finally:
        conn.close()


def set_in_default(topic_slug, in_default, actor=None, db_path=None):
    """Mark a topic as part of the set new trainees are seeded with."""
    if not topic_slug or not isinstance(topic_slug, str):
        raise LearningError("topic_slug is required")
    conn = _db(db_path)
    try:
        conn.execute("""
            INSERT INTO learning_topic_visibility
                   (topic_slug, state, in_default, updated_at, actor)
            VALUES (?, COALESCE((SELECT state FROM learning_topic_visibility
                                 WHERE topic_slug=?), ?), ?, ?, ?)
            ON CONFLICT(topic_slug) DO UPDATE SET
                   in_default=excluded.in_default, updated_at=excluded.updated_at,
                   actor=excluded.actor
        """, (topic_slug, topic_slug, DEFAULT_STATE, 1 if in_default else 0,
              _now(), actor))
        conn.commit()
    finally:
        conn.close()


def default_topics(db_path=None):
    """Slugs new trainees are seeded with. Order is stable for predictable previews."""
    conn = _db(db_path, readonly=True)
    try:
        return [r[0] for r in conn.execute(
            "SELECT topic_slug FROM learning_topic_visibility "
            "WHERE in_default=1 ORDER BY topic_slug")]
    finally:
        conn.close()


def grant(user_id, topic_slug, actor=None, db_path=None):
    """Assign a topic to a user. Idempotent."""
    if user_id is None or not topic_slug:
        raise LearningError("user_id and topic_slug are required")
    conn = _db(db_path)
    try:
        conn.execute("""
            INSERT INTO learning_entitlements (user_id, topic_slug, granted_at, actor)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id, topic_slug) DO NOTHING
        """, (user_id, topic_slug, _now(), actor))
        conn.commit()
    finally:
        conn.close()


def revoke(user_id, topic_slug, db_path=None):
    """Remove an assignment. The seed log means this is not undone by a later reseed."""
    conn = _db(db_path)
    try:
        conn.execute("DELETE FROM learning_entitlements "
                     "WHERE user_id=? AND topic_slug=?", (user_id, topic_slug))
        conn.commit()
    finally:
        conn.close()


def user_entitlements(user_id, db_path=None):
    conn = _db(db_path, readonly=True)
    try:
        return [r[0] for r in conn.execute(
            "SELECT topic_slug FROM learning_entitlements WHERE user_id=? "
            "ORDER BY topic_slug", (user_id,))]
    finally:
        conn.close()


# ── seeding ──────────────────────────────────────────────────────────────────

def has_been_seeded(user_id, db_path=None):
    conn = _db(db_path, readonly=True)
    try:
        return conn.execute("SELECT 1 FROM learning_seed_log WHERE user_id=?",
                            (user_id,)).fetchone() is not None
    finally:
        conn.close()


def seed_user(user_id, actor=None, db_path=None):
    """Seed a user with the default topic set. ONE-SHOT, ever. Returns slugs granted.

    Returns [] when already seeded, and that is the important case rather than an
    optimisation: re-seeding would re-grant topics an admin deliberately revoked for
    this person. Overriding a decision someone made on purpose is worse than never
    seeding, so the seed log is checked first and written even when the default set is
    empty -- otherwise a user seeded while the set was empty would be seeded again
    later, which is the same bug arriving slowly.
    """
    if user_id is None:
        raise LearningError("user_id is required")
    if has_been_seeded(user_id, db_path):
        return []

    slugs = default_topics(db_path)
    for slug in slugs:
        grant(user_id, slug, actor=actor, db_path=db_path)

    conn = _db(db_path)
    try:
        conn.execute("INSERT OR IGNORE INTO learning_seed_log (user_id, seeded_at) "
                     "VALUES (?, ?)", (user_id, _now()))
        conn.commit()
    finally:
        conn.close()
    return slugs


def preview_apply_defaults(user_ids, db_path=None):
    """What `apply_defaults` WOULD grant. Writes nothing.

    A separate function from the one that applies, not a flag on it: a dry-run flag
    that defaults wrong, or that a caller forgets to pass, silently turns a preview
    into a mutation. Two names cannot be confused by omission.
    """
    defaults = set(default_topics(db_path))
    out = {}
    for uid in user_ids:
        missing = sorted(defaults - set(user_entitlements(uid, db_path)))
        if missing:
            out[uid] = missing
    return out


def apply_defaults(user_ids, actor=None, db_path=None):
    """Grant any default topic a user is missing. ADDITIVE ONLY -- never revokes.

    Never revoking is the point: the per-user checklist exists so an admin can tailor
    an individual, and a sync that removed anything not in the defaults would undo
    exactly that work. Adding is recoverable by revoking; silently removing a
    deliberate grant is not noticed at all.
    """
    granted = preview_apply_defaults(user_ids, db_path)
    for uid, slugs in granted.items():
        for slug in slugs:
            grant(uid, slug, actor=actor, db_path=db_path)
    return granted


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())


def selftest(db_path):
    """Prove the ceiling on a known-good AND the known-bads that fail silently.

    The silent failures here are the two that look like a working feature: a
    not_included topic still readable by someone who holds an entitlement, and an
    unrecognised state resolving to visible. Both would pass any test that only walks
    the happy path.

    Returns (ok, detail). Never raises.
    """
    try:
        import roles as _roles  # noqa: F401
    except Exception as e:
        return False, "roles unavailable: %s" % e

    try:
        set_topic_state("st_a", STATE_ALL_USERS, db_path=db_path)
        grant(1, "st_a", db_path=db_path)
        if not visible_to(1, "user", "st_a", db_path=db_path):
            return False, "known-good: an entitled user could not see an all_users topic"

        set_topic_state("st_a", STATE_NOT_INCLUDED, db_path=db_path)
        if visible_to(1, "user", "st_a", db_path=db_path):
            return False, ("CEILING FAILED: a not_included topic is still visible to a "
                           "user holding an entitlement -- the state is being ignored")
        if visible_to(1, "admin", "st_a", db_path=db_path):
            return False, "CEILING FAILED: not_included is not absolute (admin saw it)"

        conn = _db(db_path)
        try:
            conn.execute("UPDATE learning_topic_visibility SET state='nonsense' "
                         "WHERE topic_slug='st_a'")
            conn.commit()
        finally:
            conn.close()
        if visible_to(1, "admin", "st_a", db_path=db_path):
            return False, "FAIL-OPEN: an unrecognised state resolved to visible"

        if visible_to(1, "user", "st_never_configured", db_path=db_path):
            return False, "FAIL-OPEN: an unconfigured topic was visible"

        return True, "ceiling, fail-closed and unconfigured-absent all behaved"
    except Exception as e:
        return False, "selftest raised: %s: %s" % (type(e).__name__, e)
