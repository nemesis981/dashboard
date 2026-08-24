#!/usr/bin/env python3
"""Admin-key rotation — adding and retiring authenticators, authorized by the
OUTGOING key (ADR 0026 §D3).

THE PROBLEM THIS SOLVES
-----------------------
`admin_approval_authenticators.register()` will store any well-formed record. That
is correct for the module that owns the table and wrong as the only door: an
attacker who reaches a registration endpoint would simply add their own phone and
thereafter approve anything. Rotation must therefore be authorized BY AN EXISTING
ADMIN KEY, which is the one credential a compromised appliance does not hold.

THE BOOTSTRAP PROBLEM, AND WHY THE RULE IS A FLOOR AND NOT A FLAG
-----------------------------------------------------------------
Requiring an approval for every registration deadlocks the first pairing forever --
`admin_approval_pairing.build_registration` already carries that warning, which is
why IT takes no approval argument. A boolean "bootstrap mode" is the obvious fix
and is a bad one: a flag that can be set is a flag an attacker sets.

So the rule is derived from state that cannot be asserted, only counted:

    registrations are UNAPPROVED while fewer than MIN_AUTHENTICATORS_FOR_UNLOCK
    are active, and REQUIRE an approval from the moment the floor is reached.

Bootstrap ends by itself, at exactly the point the system first has a key capable
of authorizing. There is no window to widen and no switch to flip back -- revoking
down to one device does NOT reopen it, because `_bootstrap_open()` counts every
registration ever made, not just the active ones. Otherwise an attacker who could
revoke could re-enter bootstrap and add their own key unapproved, which would turn
the recovery path into the attack.

WHAT AN APPROVAL IS BOUND TO
----------------------------
`action_params` carries the exact operation, canonically serialized:

    {"key_fp": "<sha256 of the COSE key>", "op": "add"|"revoke", "target_id": "..."}

Every field of that is inside `P` and therefore signed. An approval to ADD phone-B
cannot be replayed to add phone-C, nor to revoke phone-A -- the two most damaging
substitutions available to whoever relays the request. `key_fp` uses the ONE shared
`admin_approval.key_fingerprint`, so the value the operator is shown on their phone,
the value bound into the signature, and the value the agent later computes over its
pinned set are all the same digest by construction.

RECOVERY SEMANTICS
------------------
Losing one device is survivable without this module: the floor is two, so the
remaining phone still signs. Losing ALL of them is not recoverable here, and
deliberately so -- any appliance-side override would be exactly the forgeable
bypass this design exists to remove. That case is a re-enrollment, not a rotation.
"""

import json

from core.admin_approval_authenticators import (
    AuthenticatorError, active, all_records, get, register, revoke)
from core.admin_approval_pairing import MIN_AUTHENTICATORS_FOR_UNLOCK

__all__ = ["CAPABILITY", "OP_ADD", "OP_REVOKE", "RotationError",
           "rotation_params", "bootstrap_open", "register_authenticator",
           "revoke_authenticator"]

#: The capability an approval must carry to authorize a rotation. Distinct from
#: every operational capability: an approval earned to push a command must not
#: also be able to re-key the admin set.
CAPABILITY = "admin_key_rotation"

OP_ADD = "add"
OP_REVOKE = "revoke"


class RotationError(ValueError):
    """A rotation was refused. Never a bare False -- the caller must be able to
    tell 'not authorized' from 'already revoked'."""


def _aap():
    try:
        from core import admin_approval as m                       # noqa: PLC0415
        return m
    except Exception:                                              # noqa: BLE001
        import admin_approval as m                                 # noqa: PLC0415
        return m


def rotation_params(op, target_id, key_fp) -> bytes:
    """The canonical `action_params` bytes for a rotation. §4.2-safe.

    Deterministic and BYTES, produced by one function used at both ends: the
    request that the operator signs and the authorization that consumes it must
    agree byte-for-byte, and re-serializing a dict on one side is exactly the
    round-trip §4.2 forbids. Callers pass these bytes straight to
    `create_request(action_params=...)` and never rebuild them.
    """
    if op not in (OP_ADD, OP_REVOKE):
        raise RotationError("op must be %r or %r, got %r" % (OP_ADD, OP_REVOKE, op))
    if not target_id or not isinstance(target_id, str):
        raise RotationError("target_id must be a non-empty string")
    if not key_fp or not isinstance(key_fp, str):
        # A revoke still binds the key fingerprint, not just the id: an id can be
        # reused after a revoke, and binding only the id would let an approval to
        # revoke the old holder of an id apply to whatever holds it later.
        raise RotationError("key_fp must be a non-empty string")
    return json.dumps({"key_fp": key_fp, "op": op, "target_id": target_id},
                      separators=(",", ":"), sort_keys=True).encode()


def bootstrap_open(conn) -> bool:
    """True while registrations may be made WITHOUT an approval.

    Counts EVERY registration ever made, revoked included -- see the module
    docstring. Counting only active ones would let an attacker who can revoke
    re-enter bootstrap and add an unapproved key, making the recovery path the
    attack.
    """
    return len(all_records(conn)) < MIN_AUTHENTICATORS_FOR_UNLOCK


def _authorize(conn, *, op, target_id, key_fp, stored_request, authenticator,
               assertion, now, consume):
    """Verify an approval and confirm it authorizes THIS rotation. Raises or returns."""
    aap = _aap()
    if stored_request is None:
        raise RotationError("no approval supplied for a rotation that requires one")
    if stored_request.get("capability") != CAPABILITY:
        raise RotationError(
            "approval carries capability %r, not %r -- an approval earned for "
            "another capability must not re-key the admin set"
            % (stored_request.get("capability"), CAPABILITY))

    expected = rotation_params(op, target_id, key_fp)
    got = stored_request.get("action_params")
    if not isinstance(got, bytes) or got != expected:
        # Compared as BYTES against the canonical form, never by decoding both
        # and comparing dicts -- a dict comparison would accept a re-serialized
        # payload whose bytes no longer match what was signed.
        raise RotationError(
            "approval does not authorize this operation (bound to %r, attempted %r)"
            % (got, expected))

    verdict = aap.verify_approval(stored_request=stored_request,
                                  authenticator=authenticator, assertion=assertion,
                                  now=now, consume=consume)
    if not verdict.ok:
        raise RotationError("approval did not verify (%s at step %s): %s"
                            % (verdict.reason, verdict.step, verdict.detail))
    return verdict


def register_authenticator(conn, record, *, stored_request=None, authenticator=None,
                           assertion=None, now=None, consume=None, actor=None):
    """Add an authenticator. Requires an approval unless bootstrap is still open.

    The approval must be signed by an ALREADY-REGISTERED authenticator and must be
    bound to this exact key's fingerprint, so it cannot be replayed to enrol a
    different device.
    """
    aap = _aap()
    if not isinstance(record, dict) or not record.get("public_key"):
        raise RotationError("record must be a registration with a public_key")
    key_fp = aap.key_fingerprint(record["public_key"])

    if bootstrap_open(conn):
        # First pairing(s). No key exists that could authorize this, so requiring
        # one would deadlock forever. Recorded with the actor so the unapproved
        # window is auditable rather than invisible.
        return register(conn, record, actor=actor or "bootstrap")

    if authenticator is not None:
        # The signer must itself be a registered, non-revoked authenticator on THIS
        # appliance -- resolved from the table, never taken from the caller. A
        # caller-supplied signer record would let whoever calls this nominate the
        # key that authorizes the change.
        signer = get(conn, authenticator.get("authenticator_id"))
        if signer is None or signer.get("revoked"):
            raise RotationError(
                "the approving authenticator %r is not an active registration on "
                "this appliance" % (authenticator.get("authenticator_id"),))
        authenticator = signer

    _authorize(conn, op=OP_ADD, target_id=record["authenticator_id"], key_fp=key_fp,
               stored_request=stored_request, authenticator=authenticator,
               assertion=assertion, now=now, consume=consume)
    return register(conn, record, actor=actor)


def revoke_authenticator(conn, authenticator_id, *, stored_request=None,
                         authenticator=None, assertion=None, now=None,
                         consume=None, actor=None):
    """Retire an authenticator. ALWAYS requires an approval.

    No bootstrap exemption, deliberately: bootstrap exists so a system with no key
    can acquire one, and revocation of a key that exists is never that case.
    Unapproved revocation would also be a denial-of-capability primitive -- revoke
    both phones and the admin set is empty with no key left to authorize a repair.

    Refuses to revoke the LAST active registration, for the same reason: an empty
    set is unrecoverable by design (no appliance-side override exists, because an
    override would be the forgeable bypass this whole design removes). Retiring the
    final device is a re-enrollment, not a rotation.
    """
    aap = _aap()
    existing = get(conn, authenticator_id)
    if existing is None:
        raise RotationError("no such authenticator %r" % (authenticator_id,))
    if existing.get("revoked"):
        raise RotationError("authenticator %r is already revoked" % (authenticator_id,))
    if len(active(conn)) <= 1:
        raise RotationError(
            "refusing to revoke the last active authenticator -- the admin set "
            "would be empty and nothing could authorize a repair; re-enroll instead")

    key_fp = aap.key_fingerprint(existing["public_key"])

    if authenticator is not None:
        signer = get(conn, authenticator.get("authenticator_id"))
        if signer is None or signer.get("revoked"):
            raise RotationError(
                "the approving authenticator %r is not an active registration on "
                "this appliance" % (authenticator.get("authenticator_id"),))
        authenticator = signer

    _authorize(conn, op=OP_REVOKE, target_id=authenticator_id, key_fp=key_fp,
               stored_request=stored_request, authenticator=authenticator,
               assertion=assertion, now=now, consume=consume)
    if not revoke(conn, authenticator_id, actor=actor):
        # Lost a race with a concurrent revoke. The approval is already spent, so
        # this is reported rather than retried -- a silent success here would tell
        # an audit trail that this call performed a revocation it did not.
        raise RotationError("authenticator %r was revoked concurrently"
                            % (authenticator_id,))
    return get(conn, authenticator_id)
