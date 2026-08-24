#!/usr/bin/env python3
"""Admin Approval Protocol v1 — the GATE: a verified approval becomes a signed task.

IMPLEMENTS the inner-envelope half of ADR 0026 §D3 (build order step 2). The wire
protocol itself is specified normatively in `admin-approval-v1.md`, held private
per the Rule 10 decision of 2026-08-23; this module implements its §4.2 byte-fidelity
requirement at the point where an approval turns into work.

WHAT THIS IS
------------
ADR 0026 §D3 composes two signatures answering two different questions:

  * OUTER envelope, existing `alert_manager/server_keys.sign_task` server key --
    "did this task come from the real server?"  Verified BY THE AGENT, as today.
  * INNER authorization, the companion-app admin key -- "did a specific,
    capability-unlocked human approve this exact action, just now, on their own
    device?"  Verified HERE, server-side, and recorded for attribution.

This module is the join. It refuses to mint a task envelope at all unless a stored,
still-PENDING approval verifies against the §7 procedure AND its bound fields match
the dispatch the caller is asking for.

⚠ VERIFIED TWICE, AND THE SECOND TIME IS THE ONE THAT MATTERS
------------------------------------------------------------
This gate is NOT the only thing standing between a forged task and execution, and
it must never be built as though it were.

ADR 0026 §D3 contradicts itself. It claims to **close** appliance compromise ("an
attacker with root on the appliance can no longer sign as the admin, because there
is nothing there to sign with") and then specifies that the inner authorization is
"verified server-side at the gate". Both cannot hold: the appliance owns the server
task key, so a compromised one patches out THIS FUNCTION, mints its own envelope,
signs it, and an agent checking only the outer signature runs it. The admin key
never enters the picture and the headline guarantee evaporates exactly when it is
needed. (Operator decision, 2026-08-24: resolve toward the stronger reading. Do not
re-litigate this back toward server-side-only.)

So the inner envelope is emitted in full and **`nemesis_agent/tasks.py`
independently verifies it against a key the agent pinned at enrollment.** This
gate's own verification is therefore the *first* of two, not the only one:

  * appliance-side (here)  -- rejects early, records attribution, spends the
    approval in the appliance's own store;
  * agent-side (tasks.py)  -- the load-bearing one. It re-runs §7 against pinned
    key material and spends the approval AGAIN in its own single-use claim store.

Two independent single-use guarantees, one per side, deliberately. The appliance's
consumption record is worthless to an agent defending against that appliance.

WHAT THIS MEANS FOR CHANGES HERE: every field the agent needs to rebuild `P` must
be emitted, and **key material must NOT be.** The agent resolves
`authenticator_id` against its own pinned store; shipping a public key alongside
the signature would hand the whole property back, since an attacker minting the
envelope trivially holds the private half of any key it chooses to include.

Still genuinely out of reach, and stated so nobody over-claims: an attacker holding
the server key can still run any action classified EXEMPT agent-side (those never
carried this layer), and an appliance compromised AT ENROLLMENT can pin its own
admin key -- the trust root, mitigated out of band by comparing
`enrollment.admin_authenticators_fingerprint()` against the companion app, not by
anything in this file.

⚠ §4.2 IS WHY THIS MODULE EXISTS AT ALL
---------------------------------------
The spec requires that the SAME BYTES be stored, displayed and executed, and forbids
deserialising and re-serialising `action_params` anywhere between signing and
execution -- because a round-trip through a language's native map type can reorder
keys or renormalise numbers, and the resulting failure surfaces as a mysterious
signature mismatch rather than as the data-handling bug it is.

The existing task envelope carries `params` as a NESTED DICT, canonicalised with
`json.dumps(sort_keys=True)`. Routing human-approved parameters through that shape
would round-trip them exactly as §4.2 forbids. So approved parameters ride in their
own field, `action_params_b64`, as the verbatim approved bytes:

  * base64 is a byte-exact, reversible TRANSPORT -- not a re-serialisation. The bytes
    that come out of `approved_params()` are `==` to the bytes that went into `P`.
    JSON cannot hold arbitrary bytes, which is the only reason an encoding is needed.
  * the legacy dict `params` is UNTOUCHED (operator decision, 2026-08-24, option (a)).
    `rotate_server_key` and `attest_manifest` have server-generated parameters that
    were never human-approved, so unifying them would buy a cleaner concept at the
    cost of real risk to the key-rotation rescue path. Rule 2: isolate this change.
  * a task minted here carries NO `params` key at all. An approved action takes its
    parameters from `action_params_b64` and from nowhere else. An empty dict left
    here would be an invitation to populate it, and then two fields would disagree
    about what the operator approved.

⚠ CONSUME-THEN-SIGN, AND WHY THAT ORDER
---------------------------------------
`verify_approval()` consumes the request atomically at §7 step 11. Only then is the
envelope signed. If signing fails after consumption, the approval is SPENT and no
task was issued -- the operator must approve again.

That is the deliberate direction to fail in. The alternative, sign-then-consume,
leaves a window in which two concurrent callers both sign before either consumes,
and one approval authorises two dispatches. An operator re-tapping their phone is an
annoyance; a duplicated `push_and_run` is the thing the protocol exists to prevent.
"""
from __future__ import annotations

import base64
import binascii
import uuid
from datetime import datetime, timedelta

__all__ = ["GateRejected", "GateReason", "PARAMS_FIELD", "REQUEST_FIELD",
           "mint_approved_task", "approved_params", "approval_request_id"]

#: The envelope field carrying the verbatim approved bytes (base64, §4.2).
PARAMS_FIELD = "action_params_b64"

#: The envelope field carrying the consumed request id, hex, for attribution.
REQUEST_FIELD = "approval_request_id"

#: Default task TTL. Separate from the APPROVAL's ttl: the approval bounds how long
#: the operator's decision stays valid; this bounds how long the resulting task stays
#: dispatchable. They are different clocks and must not be conflated.
DEFAULT_TASK_TTL_S = 300


class GateReason:
    """Gate-level rejection codes. DELIBERATELY NOT `AAP-0xx`.

    §8's reason codes are a stable, cross-language protocol contract -- new ones may
    be added but never reassigned, and adding one here would be a change to a spec
    this module only implements. More importantly these are not protocol failures at
    all: the approval may verify perfectly and still not authorise the dispatch the
    CALLER asked for. That is a caller error, and collapsing it into an `AAP-` code
    would tell an operator "your approval was rejected" when their approval was fine.

    `GATE-004` is the exception that proves the split: it reports that the underlying
    §7 verification failed, and carries that verdict's real `AAP-` code alongside.
    """
    TARGET_MISMATCH = "GATE-001"       # approval binds a different device
    CAPABILITY_MISMATCH = "GATE-002"   # approval is for a different capability
    ACTION_UNSPECIFIED = "GATE-003"    # caller named no action to dispatch
    APPROVAL_REJECTED = "GATE-004"     # §7 verification failed; see .verdict

    ALL = ("GATE-001", "GATE-002", "GATE-003", "GATE-004")


class GateRejected(Exception):
    """Raised instead of returning a falsy value or a half-built envelope.

    Carries `reason` (a `GateReason`) and, for `GATE-004`, the underlying protocol
    `verdict` so the `AAP-` code is never lost behind a generic gate failure. Same
    discipline as `tasks.py` and spec §8: why something was refused must never have
    to be inferred.
    """

    def __init__(self, reason, detail="", verdict=None):
        self.reason = reason
        self.detail = detail
        self.verdict = verdict
        super().__init__("%s: %s" % (reason, detail) if detail else reason)


#: Emitted as the block's `v`. The protocol version lives in `P` and is covered by
#: the signature; this copy is for a reader/parser, and MUST match.
PROTOCOL_VERSION_EMITTED = 1


#: Envelope field carrying the inner authorization. Must match
#: `nemesis_agent/tasks.APPROVAL_FIELD` -- the two are one wire contract written in
#: two files, and `test_admin_approval_gate.py` asserts they agree rather than
#: leaving it to a reader to notice.
APPROVAL_FIELD = "admin_approval"

#: Fields of the inner envelope. Every one is an input to `P`, or is needed to
#: verify the assertion over it. NOTHING here is key material -- see the module
#: docstring for why that is load-bearing rather than merely tidy.
_INNER_SCALARS = ("capability", "target", "appliance_id", "authenticator_id",
                  "issued_at", "expires_at", "match_code")
_INNER_BYTES = ("nonce",)
_ASSERTION_BYTES = ("authenticator_data", "client_data_json", "signature")

#: Belt and braces. If a future edit ever tries to put one of these in the block,
#: `_inner_envelope` raises rather than shipping it.
_FORBIDDEN_IN_BLOCK = ("public_key", "cose_key", "private_key", "secret")


def _inner_envelope(stored, authenticator, assertion) -> dict:
    """Build the block the agent verifies. Raises rather than emitting a partial one.

    Sourced from the appliance's OWN stored record (never from client input), and
    from the authenticator registration for the two fields that describe how to
    check the signature rather than what was signed (`mode`, `cose_alg`).
    """
    block = {"v": PROTOCOL_VERSION_EMITTED,
             "mode": authenticator.get("mode"),
             "cose_alg": authenticator.get("cose_alg"),
             "request_id": stored["request_id"].hex()
             if isinstance(stored.get("request_id"), bytes)
             else str(stored.get("request_id"))}

    for name in _INNER_SCALARS:
        v = stored.get(name)
        if v is None:
            raise GateRejected(GateReason.APPROVAL_REJECTED,
                               "stored request has no %s; refusing to emit a "
                               "partial inner envelope" % name)
        block[name] = v
    for name in _INNER_BYTES:
        v = stored.get(name)
        if not isinstance(v, bytes):
            raise GateRejected(GateReason.APPROVAL_REJECTED,
                               "stored %s is %s, not bytes" % (name, type(v).__name__))
        block[name] = base64.b64encode(v).decode("ascii")
    for name in _ASSERTION_BYTES:
        v = (assertion or {}).get(name)
        if not isinstance(v, bytes):
            raise GateRejected(GateReason.APPROVAL_REJECTED,
                               "assertion.%s is %s, not bytes"
                               % (name, type(v).__name__))
        block[name] = base64.b64encode(v).decode("ascii")

    leaked = sorted(k for k in block if k in _FORBIDDEN_IN_BLOCK)
    if leaked:
        # Unreachable by construction today. It exists so that if someone later
        # adds a field by looping over the registration record, this fails loudly
        # instead of quietly re-opening the hole the pin was built to close.
        raise GateRejected(GateReason.APPROVAL_REJECTED,
                           "refusing to emit key material in the inner envelope: %s"
                           % leaked)
    return block


def _default_sign(envelope):
    """Sign with the server task key.

    Imported LAZILY and inside the function, deliberately. `core/` is importable from
    services whose PYTHONPATH does NOT include `alert_manager` -- `nemesis-fw-watch`
    carries `/opt/nemesis/alert_manager` ONLY, and a top-level cross-package import
    here would break whichever service is missing the other half. The failure mode is
    an ImportError at service start, i.e. exactly the kind that looks like an
    unrelated deployment problem.
    """
    from alert_manager import server_keys                      # noqa: PLC0415
    return server_keys.sign_task(envelope)


def mint_approved_task(*, conn, request_id, authenticator, assertion, now,
                       device_id, action, capability, sign=None,
                       ttl_seconds=DEFAULT_TASK_TTL_S, task_id=None,
                       load_request=None, consume=None):
    """Verify an approval and return the signed task envelope it authorises.

    Every field of `P` is recomputed from the APPLIANCE'S stored record by
    `verify_approval()` (§7 step 6); nothing the companion app sent contributes a
    field of `P`. This function adds the checks the protocol cannot make on its own,
    because they are about the DISPATCH rather than the approval:

      * the approval's `target` must be the device we are about to task (§4.1 --
        `target` is covered by the signature precisely so an approval cannot be
        replayed against a different device, but something has to actually COMPARE
        it, and the protocol verifier has no idea which device the caller intends);
      * the approval's `capability` must be the capability the caller is exercising.

    `capability` is a PARAMETER rather than a lookup from `roles.CAPABILITY_ROUTES`
    on purpose: the action->capability mapping is the role layer's to own, and this
    module deliberately holds no opinion on it. The caller states which capability it
    is exercising and the gate proves the approval matches; it does not decide.

    Raises `GateRejected` on every failure path -- never returns None, never returns
    a partially-built envelope.
    """
    from core import admin_approval as aap                     # noqa: PLC0415
    from core import admin_approval_store as store             # noqa: PLC0415

    if not action:
        raise GateRejected(GateReason.ACTION_UNSPECIFIED,
                           "no action given to dispatch")

    load = load_request or store.load_request
    stored = load(conn, request_id)

    # Order note: the §7 verification runs FIRST and owns every approval-level
    # rejection, including "no such request". Pre-checking target/capability against
    # `stored` here would mean reading fields off an unverified -- possibly
    # nonexistent -- record and reporting a gate error where the honest answer is
    # AAP-001. The dispatch checks belong strictly AFTER the approval is known good.
    consume_fn = consume
    if consume_fn is None:
        def consume_fn(rid):                                   # noqa: E306
            return store.consume(conn, rid)

    verdict = aap.verify_approval(stored_request=stored, authenticator=authenticator,
                                  assertion=assertion, now=now, consume=consume_fn)
    if not verdict.ok:
        raise GateRejected(GateReason.APPROVAL_REJECTED,
                           "approval did not verify (%s at step %s)"
                           % (verdict.reason, verdict.step), verdict=verdict)

    # `stored` is trustworthy from here: verification recomputed P from it and the
    # signature covered every one of these fields.
    if (stored.get("target") or "") != (device_id or ""):
        raise GateRejected(
            GateReason.TARGET_MISMATCH,
            "approval binds target %r but dispatch is for %r"
            % (stored.get("target") or "", device_id or ""))

    if stored.get("capability") != capability:
        raise GateRejected(
            GateReason.CAPABILITY_MISMATCH,
            "approval is for capability %r but caller is exercising %r"
            % (stored.get("capability"), capability))

    params = stored.get("action_params")
    if not isinstance(params, bytes):
        # The store refuses non-bytes at creation (§4.2), so this can only mean the
        # record was written by something that bypassed it. Fail closed and loud
        # rather than coercing -- a coercion here would re-serialise, which is the
        # exact defect §4.2 exists to prevent.
        raise GateRejected(GateReason.APPROVAL_REJECTED,
                           "stored action_params is %s, not bytes (§4.2 violated "
                           "upstream of this gate)" % type(params).__name__)

    block = _inner_envelope(stored, authenticator, assertion)

    issued = datetime.fromtimestamp(int(now))
    envelope = {
        "task_id": task_id or str(uuid.uuid4()),
        "device_id": device_id,
        "action": action,
        # The inner authorization, in full, for the AGENT to verify independently.
        # See the module docstring: this gate's verification is the first of two.
        APPROVAL_FIELD: block,
        # Verbatim approved bytes. NOT re-serialised, NOT round-tripped (§4.2).
        PARAMS_FIELD: base64.b64encode(params).decode("ascii"),
        # Attribution: which human decision authorised this (ADR 0026 §D3, and the
        # multi-user "attribute state-changing actions" rule). Hex because the
        # envelope is JSON and request_id is 16 raw bytes.
        REQUEST_FIELD: stored["request_id"].hex()
        if isinstance(stored.get("request_id"), bytes) else str(stored.get("request_id")),
        # Same timestamp shape the existing envelopes use -- naive local isoformat to
        # seconds, which is what `tasks.verify_task` parses with `fromisoformat`. A
        # different shape here would fail on the agent, not here.
        "issued_at": issued.isoformat(timespec="seconds"),
        "expires_at": (issued + timedelta(seconds=int(ttl_seconds))
                       ).isoformat(timespec="seconds"),
    }
    # NOTE: no "params" key. See the §4.2 block in the module docstring.
    envelope["signature"] = (sign or _default_sign)(envelope)
    return envelope


def approved_params(envelope) -> bytes:
    """Recover the EXACT approved bytes from a minted envelope.

    This closes §4.2's loop: the bytes returned here are the bytes that entered `P`
    and were signed by the operator's device. An executor MUST take its parameters
    from this function and MUST NOT re-derive them from any other field.

    Raises rather than returning b"" for a missing or malformed field. An empty
    bytestring is a legal parameter value, so returning it on failure would make
    "no parameters were approved" indistinguishable from "the field was corrupt" --
    the exact failed-read-as-default shape the standing practice forbids.
    """
    if not isinstance(envelope, dict):
        raise GateRejected(GateReason.APPROVAL_REJECTED, "envelope is not an object")
    raw = envelope.get(PARAMS_FIELD)
    if raw is None:
        raise GateRejected(GateReason.APPROVAL_REJECTED,
                           "envelope carries no %s -- it was not minted by this gate"
                           % PARAMS_FIELD)
    if not isinstance(raw, str):
        raise GateRejected(GateReason.APPROVAL_REJECTED,
                           "%s is %s, not a string" % (PARAMS_FIELD, type(raw).__name__))
    try:
        # validate=True so non-alphabet bytes RAISE rather than being silently
        # discarded, which is base64's default and would let a tampered field decode
        # to something plausible.
        return base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise GateRejected(GateReason.APPROVAL_REJECTED,
                           "%s is not valid base64: %s" % (PARAMS_FIELD, exc)) from exc


def approval_request_id(envelope) -> str:
    """The consumed request id (hex) a minted envelope was authorised by.

    Same fail-closed contract as `approved_params`: raises if absent, so an
    unattributed task can never read as an attributed one.
    """
    if not isinstance(envelope, dict):
        raise GateRejected(GateReason.APPROVAL_REJECTED, "envelope is not an object")
    rid = envelope.get(REQUEST_FIELD)
    if not rid:
        raise GateRejected(GateReason.APPROVAL_REJECTED,
                           "envelope carries no %s -- it was not minted by this gate"
                           % REQUEST_FIELD)
    return rid
