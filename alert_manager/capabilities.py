"""Learning-gate unlocks: what a delegated operator has earned, and recording it.

THE SPLIT THAT MATTERS (ADR 0026 D1)
------------------------------------
`roles.py` decides. THIS module reads and writes. That separation is why
`roles.py` still has no I/O and can run its 60-case canary at import in the
production path -- a property that disappears the moment anything there touches a
database. The request gate fetches unlocks here and hands them to
`roles.may_with_unlocks()` as a plain frozenset.

Do not "simplify" this later by having roles.py call into this module.

INVALIDATION HAPPENS ON READ, NOT ONLY ON WRITE
-----------------------------------------------
`unlocks_for()` drops any row whose stored `quiz_version` no longer matches the
live quiz's content-derived version. Putting that in the READ path means a stale
unlock cannot be used even if some future write path forgets to clear it, or if a
quiz is edited while rows already exist. A write-side-only check would leave the
authoritative answer depending on every writer remembering.

WHAT AN UNLOCK IS NOT
---------------------
It is not authorization. A dangerous action needs role tier AND this unlock AND
the admin-approval signature AND (agent side) device consent. This module answers
exactly one of those four questions and must never be described as answering more.
"""

from __future__ import annotations

import datetime
import logging

log = logging.getLogger(__name__)

#: The Data Manager namespace this writes under.
#:
#: `dashboard`, not a new `core` namespace, and the distinction is worth stating:
#: ADR 0001 makes `user_capability_unlocks` CORE-owned (it is unprefixed and lives
#: beside `users`), but a Data Manager namespace is keyed by the WRITING COMPONENT,
#: not by table ownership. The dashboard process is what writes here, and its grant
#: already covers `users` -- the row this table extends. Minting a `core` namespace
#: for one table would add a second answer to "who writes this" with no new
#: enforcement.
MODULE = "dashboard"


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _conn():
    """A connection through the Data Manager, per ADR 0006."""
    import data_manager                                        # noqa: PLC0415
    return data_manager.get_data_manager().connect(MODULE)


def unlocks_for(user_id, conn=None):
    """Capabilities this user has CURRENTLY earned, as a frozenset.

    Returns an empty frozenset for a user with none -- that is a real answer, and
    it is also what every non-sub-admin gets, since only a sub-admin's unlocks are
    ever consulted.

    A row is DROPPED (and logged) when:
      * its capability is no longer declared -- the feature was removed;
      * its quiz no longer loads -- it was withdrawn or is malformed;
      * its stored version differs from the live quiz's -- the content changed, so
        the training the row attests to is not the training that now exists.

    Dropping is the safe direction here, unlike role parsing: a dropped unlock
    removes access, so failing closed costs a retake rather than granting
    something unearned.
    """
    import roles                                               # noqa: PLC0415
    import quizzes                                             # noqa: PLC0415

    owned = conn is None
    if owned:
        conn = _conn()
    try:
        rows = conn.execute(
            "SELECT capability, quiz_version FROM user_capability_unlocks "
            "WHERE user_id=?", (int(user_id),)).fetchall()
    except Exception:
        # An unreadable unlock table must not grant anything. Loud, and empty.
        log.exception("capabilities: could not read unlocks for user %s; "
                      "treating as NO unlocks", user_id)
        return frozenset()
    finally:
        if owned:
            try:
                conn.close()
            except Exception:                                  # noqa: BLE001
                pass

    live = set()
    for row in rows:
        cap = row[0] if not isinstance(row, dict) else row["capability"]
        stored = row[1] if not isinstance(row, dict) else row["quiz_version"]
        if cap not in roles.CAPABILITY_ROUTES:
            log.warning("capabilities: user %s holds an unlock for %r, which is "
                        "no longer a declared capability; ignoring", user_id, cap)
            continue
        try:
            current = quizzes.effective_version(cap)
        except quizzes.QuizError:
            log.warning("capabilities: user %s holds an unlock for %r but its "
                        "quiz is unavailable; ignoring", user_id, cap)
            continue
        if stored != current:
            log.info("capabilities: user %s must re-earn %r -- the quiz changed "
                     "(held %r, current %r)", user_id, cap, stored, current)
            continue
        live.add(cap)
    return frozenset(live)


def record_unlock(user_id, capability, score, actor=None, conn=None):
    """Record a PASS. Returns the stored row as a dict.

    Refuses anything that is not a genuine pass of a currently-loadable quiz:

      * an undeclared capability raises (a typo must not create a phantom unlock);
      * a quiz that will not load raises;
      * a score below the pass mark raises -- this function records passes, and
        accepting a fail here would make the grader the only thing standing
        between a wrong answer and a dangerous capability.

    The version stored is the live content-derived one, so a later edit to the
    quiz invalidates this row automatically.
    """
    import roles                                               # noqa: PLC0415
    import quizzes                                             # noqa: PLC0415

    if capability not in roles.CAPABILITY_ROUTES:
        raise roles.UnknownCapability(
            "%r is not a declared capability" % (capability,))
    version = quizzes.effective_version(capability)            # raises if unusable
    if int(score) < quizzes.PASS_MARK:
        raise ValueError(
            "refusing to record an unlock for %r at %s%% -- the pass mark is %s%%"
            % (capability, score, quizzes.PASS_MARK))

    owned = conn is None
    if owned:
        conn = _conn()
    try:
        # UPSERT, so re-earning after a quiz revision replaces the stale row
        # rather than leaving two that disagree about the version. `attempts`
        # accumulates across re-earns rather than resetting -- how many goes it
        # took is exactly the signal worth keeping.
        conn.execute(
            "INSERT INTO user_capability_unlocks "
            "(user_id, capability, unlocked_at, quiz_version, quiz_score, "
            " attempts, granted_by) VALUES (?,?,?,?,?,1,?) "
            "ON CONFLICT(user_id, capability) DO UPDATE SET "
            "  unlocked_at=excluded.unlocked_at, "
            "  quiz_version=excluded.quiz_version, "
            "  quiz_score=excluded.quiz_score, "
            "  attempts=user_capability_unlocks.attempts+1, "
            "  granted_by=excluded.granted_by",
            (int(user_id), capability, _now(), version, int(score), actor))
        conn.commit()
    finally:
        if owned:
            try:
                conn.close()
            except Exception:                                  # noqa: BLE001
                pass
    log.info("capabilities: user %s unlocked %r at version %r (actor=%s)",
             user_id, capability, version, actor)
    return {"user_id": int(user_id), "capability": capability,
            "quiz_version": version, "quiz_score": int(score)}


def revoke(user_id, capability, actor=None, conn=None):
    """Remove an unlock. Returns True if a row was actually removed.

    Separate from expiry-by-version: this is a deliberate administrative act, and
    the return value distinguishes "revoked" from "there was nothing to revoke" so
    a caller cannot report success for a no-op.
    """
    owned = conn is None
    if owned:
        conn = _conn()
    try:
        cur = conn.execute(
            "DELETE FROM user_capability_unlocks WHERE user_id=? AND capability=?",
            (int(user_id), capability))
        conn.commit()
        removed = bool(getattr(cur, "rowcount", 0))
    finally:
        if owned:
            try:
                conn.close()
            except Exception:                                  # noqa: BLE001
                pass
    log.info("capabilities: %s %r for user %s (actor=%s)",
             "revoked" if removed else "no-op revoke of", capability, user_id, actor)
    return removed
