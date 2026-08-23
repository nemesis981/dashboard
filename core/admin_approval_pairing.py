"""Admin Approval Protocol v1 §5 — registration (pairing) of authenticators.

IMPLEMENTS `docs/protocol/admin-approval-v1.md` §5 (ADR 0026 §D3). The spec is the
contract; this file is subordinate to it.

⚠ THE DEADLOCK THIS MODULE EXISTS TO AVOID — §5, and the reason it is stated in the
spec rather than left to implementers:

    Registration MUST NOT itself require an approval from a companion.

On a fresh appliance no companion is registered. If registering the FIRST one
required a companion approval, there would be no authenticator able to grant it,
and the appliance could never be paired -- permanently, with no recovery short of
a reinstall. The failure is not subtle in hindsight and is very easy to introduce
by applying an "all admin actions need approval" rule uniformly.

**Enforced structurally, not by convention:** this module does not import the
verifier, holds no reference to an approval gate, and takes no approval argument.
There is nothing here to call. A conformance test asserts the absence, because a
comment saying "do not add an approval check" is exactly the kind of instruction
that loses to a later uniform refactor.

⚠ THE SECOND RULE, which points the other way — §5:

    At least two authenticators MUST be registered before any capability can be
    unlocked.

Registration is unguarded so pairing can bootstrap; UNLOCKING is guarded so a single
lost or compromised phone can neither strand the operator nor act alone. Those are
different gates on different actions and must not be collapsed into one.
"""

import time

__all__ = ["MIN_AUTHENTICATORS_FOR_UNLOCK", "PairingError", "build_registration",
           "active_authenticators", "can_unlock", "UnlockRefusal"]

#: §5 — the floor for unlocking a capability. Two, so that losing one device
#: does not strand the operator and no single device can act alone.
MIN_AUTHENTICATORS_FOR_UNLOCK = 2


class PairingError(ValueError):
    """A registration record could not be built. An appliance-side input problem."""


class UnlockRefusal:
    """Why an unlock was refused. Never a bare boolean -- same discipline as §8."""

    __slots__ = ("allowed", "reason", "have", "need")

    def __init__(self, allowed, reason=None, have=0, need=MIN_AUTHENTICATORS_FOR_UNLOCK):
        self.allowed, self.reason, self.have, self.need = allowed, reason, have, need

    def __repr__(self):
        return ("UnlockRefusal(allowed=%r, reason=%r, have=%d, need=%d)"
                % (self.allowed, self.reason, self.have, self.need))


def build_registration(*, authenticator_id, user_id, mode, cose_alg, public_key,
                       rp_id_hash=None, now=None, sign_count=0):
    """Build a §5 registration record. Keyword-only, every field validated.

    TAKES NO APPROVAL ARGUMENT, deliberately and permanently. See the module
    docstring: an approval requirement here deadlocks first pairing forever.

    The CALLER is responsible for establishing that this is an authenticated admin
    session with console access (§5). That is a session-layer property this module
    cannot check and must not pretend to -- returning a record does not mean the
    caller was authorised, only that the record is well-formed.
    """
    from core.admin_approval import (MODE_WEBAUTHN, MODE_NATIVE, SUPPORTED_ALGS)

    if not authenticator_id or not isinstance(authenticator_id, str):
        raise PairingError("authenticator_id must be a non-empty string")
    if not user_id or not isinstance(user_id, str):
        raise PairingError("user_id must be a non-empty string")
    if mode not in (MODE_WEBAUTHN, MODE_NATIVE):
        raise PairingError("mode must be WEBAUTHN(1) or NATIVE(2), got %r" % (mode,))
    if cose_alg not in SUPPORTED_ALGS:
        # §2: reject an unsupported algorithm rather than defaulting to one.
        raise PairingError("unsupported cose_alg %r (see spec §2)" % (cose_alg,))
    if not isinstance(public_key, dict):
        raise PairingError("public_key must be a decoded COSE_Key mapping (RFC 9052)")
    if mode == MODE_WEBAUTHN:
        if not isinstance(rp_id_hash, bytes) or len(rp_id_hash) != 32:
            # Without this the §7 step-7 binding check has nothing to compare
            # against, and would either crash or -- far worse -- be skipped.
            raise PairingError("WEBAUTHN registration requires a 32-byte rp_id_hash")
    elif rp_id_hash is not None:
        raise PairingError("rp_id_hash is meaningless for a NATIVE authenticator")

    # Validate the key is actually constructible NOW, at registration, rather than
    # discovering it at first use. A key that cannot be parsed is a pairing that
    # silently never works, and the failure would surface much later as an
    # unexplained AAP-010.
    from core.admin_approval import cose_key_to_public, ProtocolError
    try:
        cose_key_to_public(public_key)
    except ProtocolError as exc:
        raise PairingError("public_key is not usable: %s" % exc)

    return {
        "authenticator_id": authenticator_id,
        "user_id": user_id,
        "mode": mode,
        "cose_alg": cose_alg,
        "public_key": public_key,
        "sign_count": int(sign_count),
        "rp_id_hash": rp_id_hash,
        "registered_at": int(now if now is not None else time.time()),
        "revoked": False,
    }


def active_authenticators(records, user_id=None):
    """Registered, non-revoked authenticators -- optionally for one user."""
    out = [r for r in (records or ()) if not r.get("revoked")]
    if user_id is not None:
        out = [r for r in out if r.get("user_id") == user_id]
    return out


def can_unlock(records, user_id=None):
    """§5 — may a capability be unlocked given these registrations?

    REFUSES below the floor. The spec says a verifier MUST refuse to RECORD an
    unlock while fewer than two are registered and active, so this is a hard gate
    rather than a warning: a warning that can be clicked through is not a floor.
    """
    active = active_authenticators(records, user_id)
    n = len(active)
    if n < MIN_AUTHENTICATORS_FOR_UNLOCK:
        return UnlockRefusal(
            False,
            reason=("only %d active authenticator(s) registered; %d are required "
                    "before any capability can be unlocked (spec §5)"
                    % (n, MIN_AUTHENTICATORS_FOR_UNLOCK)),
            have=n)
    return UnlockRefusal(True, have=n)
