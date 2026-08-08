"""Track C — server-side consent grant / revoke, and Requirement 0 clause 7's purge.

THE GAP THIS CLOSES
    Until now NOTHING in the codebase wrote `conn_consent`. `hw_monitor` only
    ever read it, and its ingest gate fails closed on an absent row — correctly.
    The consequence was that the whole Track C pipeline was inert by
    construction: 13 enrolled agent devices, 0 consent rows, so 0 events could
    ever be accepted, so the seen-set could never populate and novelty could
    never run. The gate was not broken; there was simply no way to open it.

    Requirement 0 clause 7 was unimplemented for the same reason.
    `conn_seen.purge_device()` was built and tested with no caller, because
    revocation had nowhere to live. This module is that caller.

SCOPE — INDIVIDUAL BASIS ONLY, DELIBERATELY
    `CONSENT_BASIS_EMPLOYER` is defined in `database.py` and is REFUSED here.
    Employer-basis consent needs legal review before it ships (standing open
    item), and the reviewable question is not "does the code work" but "may an
    organisation consent on a person's behalf, and under what disclosure". So
    the seam stays, the value stays defined, and the path raises
    `EmployerBasisNotAvailable` rather than silently accepting or silently
    coercing to `individual`. A stub that quietly recorded `individual` for an
    employer-enrolled device would be a false compliance record — worse than a
    missing feature.

REVOCATION IS ATOMIC, AND THE ORDER IS LOAD-BEARING
    Revoke marks `revoked_at` FIRST, then purges, inside ONE transaction:

      * Marking first closes the ingest gate before any data is deleted. Purging
        first would leave a window in which the gate is still open and a
        concurrent heartbeat could write fresh rows behind the purge — data
        collected after the user revoked, which is precisely what clause 7 is
        about.
      * One transaction means a failed purge ROLLS BACK the revocation and
        raises. That is deliberate and is the lesser of two bad states: a
        half-applied revocation that records "revoked" while the data is still
        on disk is a compliance claim that is not true, and nothing downstream
        could tell. An all-or-nothing failure is loud and retryable.

    Both stores are purged — `conn_events` (the behavioural log) and the
    seen-set (the membership summary). The summary is NOT exempt for being a
    summary: it still records which destinations a person's device contacted.
"""
import sqlite3
import time

import conn_seen
from database import CONSENT_BASES, CONSENT_BASIS_EMPLOYER, CONSENT_BASIS_INDIVIDUAL

#: The disclosure version this server currently records consent against.
#: ⚠ MUST MATCH `nemesis_agent/consent.py::DISCLOSURE_VERSION`. The ingest gate
#: rejects any event whose version differs from the server's stored value, so a
#: mismatch here does not leak data — it silently rejects everything, which
#: looks like an agent that has stopped reporting. Checked by the test suite
#: against the agent constant so the two cannot drift unnoticed.
CURRENT_CONSENT_VERSION = 1

#: The namespace these writes run under. NOT `dashboard`: revocation must DELETE
#: from `conn_events` and the seen-set, and granting the web-facing process
#: standing delete authority over the whole telemetry store — for every request
#: it serves, not just this one — is a wider grant than this operation needs.
#: A dedicated namespace with an explicit four-table list follows the
#: `integrity_watch` / `tier2_gate` precedent: a security-relevant capability
#: names its tables outright, so adding one is a deliberate act.
NAMESPACE = "conn_consent"

_ISO = "%Y-%m-%dT%H:%M:%S"


class ConsentError(RuntimeError):
    """A consent operation failed. Raised, never defaulted — a consent write
    that silently does nothing is indistinguishable from one that worked, and
    the thing it gates is data collection about a person."""


class EmployerBasisNotAvailable(ConsentError):
    """Employer-basis consent is not shippable until legal review completes.

    Its own type so it can be caught and surfaced specifically ("not yet
    available") rather than being reported as a generic validation failure,
    which would read to an operator as a bug in their input.
    """


def _now():
    return time.strftime(_ISO, time.gmtime())


def grant(device_id, basis=CONSENT_BASIS_INDIVIDUAL, granted_by=None,
          version=None, actor=None, conn=None):
    """Record consent for one device. Opens the ingest gate for it.

    Re-granting after a revocation is allowed and clears `revoked_at` — a person
    may change their mind. It does NOT resurrect purged data: that is gone, and
    the device starts collecting fresh from this moment. Tested explicitly,
    because "re-grant restores history" is an easy and very wrong assumption.
    """
    device_id = _require_device_id(device_id)
    if basis == CONSENT_BASIS_EMPLOYER:
        raise EmployerBasisNotAvailable(
            "employer-basis consent is gated on legal review and cannot be "
            "recorded yet — the seam exists, the path does not")
    if basis not in CONSENT_BASES:
        raise ConsentError("unknown consent basis %r (known: %s)"
                           % (basis, ", ".join(CONSENT_BASES)))
    v = CURRENT_CONSENT_VERSION if version is None else version
    if not isinstance(v, int) or isinstance(v, bool) or v < 1:
        raise ConsentError("consent_version must be a positive int, got %r" % (v,))

    now = _now()
    own, conn = _conn(conn)
    try:
        conn.execute("""
            INSERT INTO conn_consent
                (device_id, consent_version, granted_at, granted_by,
                 recorded_at, revoked_at, consent_basis)
            VALUES (?, ?, ?, ?, ?, NULL, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                consent_version=excluded.consent_version,
                granted_at=excluded.granted_at,
                granted_by=excluded.granted_by,
                recorded_at=excluded.recorded_at,
                revoked_at=NULL,
                consent_basis=excluded.consent_basis
        """, (device_id, v, now, granted_by or actor, now, basis))
        if own:
            conn.commit()
    except sqlite3.Error as e:
        if own:
            conn.rollback()
        raise ConsentError("could not record consent for %s: %r"
                           % (device_id[:12], e))
    finally:
        if own:
            conn.close()
    return {"device_id": device_id, "consent_version": v, "basis": basis,
            "granted_at": now}


def revoke(device_id, actor=None, conn=None):
    """Withdraw consent AND purge what was collected. Requirement 0 clause 7.

    Atomic: mark revoked, purge `conn_events`, purge the seen-set. Any failure
    rolls the whole thing back and raises — see the module docstring for why a
    half-applied revocation is the worse outcome.
    """
    device_id = _require_device_id(device_id)
    now = _now()
    own, conn = _conn(conn)
    try:
        row = conn.execute(
            "SELECT revoked_at FROM conn_consent WHERE device_id=?",
            (device_id,)).fetchone()
        if row is None:
            # Explicit, not a silent success. "No consent on file" and "consent
            # revoked and data purged" are different facts, and an operator
            # acting on a revocation request needs to know which one happened —
            # a quiet no-op here would read as a completed erasure.
            raise ConsentError(
                "no consent record for %s — nothing to revoke. If this device "
                "reported data, that is a separate problem worth investigating, "
                "not a revocation." % device_id[:12])

        # 1. Close the gate FIRST, inside the same transaction as the purge.
        conn.execute("UPDATE conn_consent SET revoked_at=? WHERE device_id=?",
                     (now, device_id))
        # 2. Purge the behavioural log.
        events = conn.execute("DELETE FROM conn_events WHERE device_id=?",
                              (device_id,)).rowcount or 0
        # 3. Purge the membership summary. Not exempt for being a summary.
        seen = conn_seen.purge_device(conn, device_id)
        if own:
            conn.commit()
    except ConsentError:
        if own:
            conn.rollback()
        raise
    except Exception as e:                                   # noqa: BLE001
        if own:
            conn.rollback()
        raise ConsentError(
            "revocation FAILED for %s and was rolled back — consent is still "
            "recorded as granted and data was NOT purged. Retry; do not report "
            "this as an erasure: %r" % (device_id[:12], e))
    finally:
        if own:
            conn.close()
    return {"device_id": device_id, "revoked_at": now,
            "purged_events": events,
            "purged_destinations": seen.get("destinations", 0),
            "purged_addrs": seen.get("addrs", 0)}


def status(device_id, conn=None):
    """Current consent state for one device. Read-only."""
    device_id = _require_device_id(device_id)
    own, conn = _conn(conn, write=False)
    try:
        row = conn.execute(
            "SELECT consent_version, granted_at, granted_by, recorded_at, "
            "revoked_at, consent_basis FROM conn_consent WHERE device_id=?",
            (device_id,)).fetchone()
    finally:
        if own:
            conn.close()
    if row is None:
        return {"device_id": device_id, "consented": False, "reason": "no record"}
    v, granted_at, granted_by, recorded_at, revoked_at, basis = row
    return {
        "device_id": device_id,
        "consented": revoked_at is None,
        "consent_version": v,
        "version_current": v == CURRENT_CONSENT_VERSION,
        "granted_at": granted_at, "granted_by": granted_by,
        "recorded_at": recorded_at, "revoked_at": revoked_at,
        # NULL basis means "recorded before the column existed", never a
        # manufactured 'individual' — see database.py's migration note.
        "consent_basis": basis,
    }


def ensure_codes(conn):
    """Register the E-CONSENT-* catalog. Idempotent; safe to call per request.

    Called by the route before any operation that can fail, because
    `record_error()` REFUSES an unregistered code — so without this, every
    occurrence this module tries to record would be rejected downstream and the
    instrumentation would look present while recording nothing.
    """
    import conn_consent_errors                              # noqa: PLC0415
    return conn_consent_errors.ensure_registered(conn)


def _require_device_id(device_id):
    if not isinstance(device_id, str) or not device_id.strip():
        raise ConsentError("device_id must be a non-empty string, got %r"
                           % (device_id,))
    return device_id.strip()


def _conn(conn, write=True):
    """(owns_connection, connection). A caller-supplied conn is never closed or
    committed here — the caller owns its transaction, which is what lets revoke
    participate in a larger atomic operation if one is ever needed."""
    if conn is not None:
        return False, conn
    from data_manager import get_data_manager                # noqa: PLC0415
    dm = get_data_manager()
    return True, dm.connect(NAMESPACE) if write else dm.connect(NAMESPACE)
