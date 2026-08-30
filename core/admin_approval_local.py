"""Admin Approval Protocol v1 — the LOCAL gate: an approval authorises an
appliance-local action (ADR 0026 §D3 "A2").

SIBLING OF `admin_approval_gate.py`, NOT AN EXTENSION OF IT. That module mints a
signed TASK ENVELOPE for dispatch to an agent, and its central check compares the
approval's `target` against the device being tasked. An appliance-local action —
setting an alert's disposition, applying a permanent block — is never dispatched
anywhere, has no target device, and produces no envelope. There is nothing for
that comparison to compare, so this is a separate gate with its own binding rules
rather than a mode flag on that one.

⚠ WHAT THIS DOES AND DOES NOT BUY. Stated here because the resemblance to §D3 is
close enough to be misleading, and because A2 must never inherit D3's headline
claim by association.

D3's guarantee is that a SECOND MACHINE verifies. `nemesis_agent/tasks.py` re-runs
§7 against a key the agent pinned at enrollment and spends the approval in its own
claim store, so an appliance with root can forge the outer envelope and still not
forge the admin signature. **A2 cannot have that property and does not claim it.**
An appliance-local action executes on the appliance; this verifier runs on the
appliance; root patches it out and calls the executor directly. There is no second
machine, so there is no second opinion.

What A2 genuinely defends against, each real and none of them appliance root:
  * a compromised SESSION — a stolen cookie, a CSRF, an XSS-driven request cannot
    produce the signature. The strongest of the four.
  * the ENGINE itself — ai_engine runs on this box but holds no admin key, so a
    malfunctioning or prompt-injected engine can propose and cannot approve. The
    authority ladder exists because the engine may be wrong; this is on target.
  * an admin without a paired authenticator acting unilaterally.
  * attribution — a durable record of who approved what. **NOT non-repudiation:**
    the record is on-box and root can rewrite it. See `RECORD_IS_ON_BOX_ONLY`.

One-line framing for docs: *D3 defends the agent against a compromised appliance.
A2 defends the appliance's own actions against everything except a compromised
appliance.*
"""

import base64
import json

__all__ = ["LocalApprovalError", "RECORD_IS_ON_BOX_ONLY", "local_action_params",
           "verify_local_approval"]


#: Stated as a constant so it is greppable and cannot quietly stop being true.
#: The approval record lives in `ai_local_approval_log` on this appliance. No
#: off-box replication exists in this project (measured 2026-08-30: no scheduled
#: export anywhere, the only systemd timer is cert renewal, and the
#: dead-man's-switch heartbeat is unstarted), so the record survives exactly as
#: long as the box's integrity does. Attribution: yes. Non-repudiation: NO.
RECORD_IS_ON_BOX_ONLY = True


class LocalApprovalError(ValueError):
    """An approval did not authorise this local action. Every path is a refusal."""


def local_action_params(*, action_class, row_id, proposed_action, proposal_id):
    """The canonical `action_params` bytes for an appliance-local action.

    ⚠ THIS IS THE BINDING, and it replaces the device-target check the task gate
    performs. `target` alone is not enough here: two proposals can share a
    `row_id` and an `action_class` (the same alert re-proposed after a rejection),
    so `proposal_id` is folded in to tie an approval to one specific proposal
    rather than to a shape that recurs.

    ONE definition, used by BOTH the request builder and the verifier. If the two
    sides ever derived these bytes separately they could disagree while both
    looking correct, and the symptom would be a signature that never verifies —
    the hardest kind of failure to attribute.

    `separators` and `sort_keys` are pinned: the bytes are what gets signed, so a
    formatting change is a signature-breaking change, not cosmetics.
    """
    if not action_class or not isinstance(action_class, str):
        raise LocalApprovalError("action_class must be a non-empty string")
    if proposal_id is None:
        raise LocalApprovalError("proposal_id is required — it is what stops an "
                                 "approval being replayed onto a different "
                                 "proposal with the same row_id")
    payload = {
        "v": 1,
        "action_class": action_class,
        "row_id": "" if row_id is None else str(row_id),
        "proposed_action": "" if proposed_action is None else str(proposed_action),
        "proposal_id": int(proposal_id),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def verify_local_approval(*, stored_request, authenticator, assertion, now,
                          action_class, row_id, proposed_action, proposal_id,
                          consume):
    """Verify an approval AND confirm it authorises exactly this local action.

    Returns the verified request record. Raises `LocalApprovalError` on every
    failure path — never returns None, never returns a partial result.

    ORDER MATTERS AND IS DELIBERATE: the BINDING is checked before the signature.
    A caller presenting a valid approval for a different action should be told
    that, not told its signature failed — and checking the cheap, local,
    non-cryptographic condition first means a mismatched request never reaches
    the verifier at all.

    `consume` is REQUIRED, not optional. `verify_approval()` accepts None to mean
    "do not spend", which it documents as test/dry-run only; a production caller
    that omitted it would verify an approval without spending it and the same
    approval could be replayed. Making it mandatory here removes that foot-gun
    from this path entirely.
    """
    from core import admin_approval as aap

    if stored_request is None:
        raise LocalApprovalError("no such approval request")
    if consume is None:
        raise LocalApprovalError(
            "consume is required: verifying without spending would leave this "
            "approval replayable")

    # ── binding, before anything cryptographic ──────────────────────────────
    if stored_request.get("capability") != action_class:
        raise LocalApprovalError(
            "approval carries capability %r, not %r — an approval earned for one "
            "action class must not authorise another"
            % (stored_request.get("capability"), action_class))

    want_target = "" if row_id is None else str(row_id)
    if (stored_request.get("target") or "") != want_target:
        raise LocalApprovalError(
            "approval is bound to target %r, not %r — it cannot be replayed onto "
            "a different subject"
            % (stored_request.get("target"), want_target))

    expected = local_action_params(action_class=action_class, row_id=row_id,
                                   proposed_action=proposed_action,
                                   proposal_id=proposal_id)
    got = stored_request.get("action_params")
    # Compared as BYTES against the canonical form, never by decoding both and
    # comparing dicts: a dict comparison would accept a re-serialized payload
    # whose bytes no longer match what was signed. Same precedent and same
    # reasoning as `admin_approval_rotation._authorize`.
    if not isinstance(got, bytes) or got != expected:
        raise LocalApprovalError(
            "approval does not authorise this exact action (bound to %r, "
            "attempted %r)" % (got, expected))

    verdict = aap.verify_approval(stored_request=stored_request,
                                  authenticator=authenticator,
                                  assertion=assertion, now=now, consume=consume)
    if not verdict.ok:
        raise LocalApprovalError(
            "approval did not verify (%s at step %s): %s"
            % (verdict.reason, verdict.step, verdict.detail))
    return stored_request


def record_row(*, stored_request, action_class, proposal_id, actor, now):
    """The append-only log row for a spent local approval.

    Structured deliberately, and shaped to be SHIPPABLE. No off-box destination
    exists today (see `RECORD_IS_ON_BOX_ONLY`), but the dead-man's-switch
    heartbeat is the natural one when it is built, and a row that already carries
    its own identifiers can be shipped without a migration. Costs nothing now.

    Carries NO key material and no assertion bytes: the row is evidence that an
    approval was spent, not a re-verifiable copy of it. Storing the signature
    would invite someone to re-verify from the log, which is precisely the
    appliance-trusting-itself move A2 cannot support.
    """
    return {
        "request_id": base64.b16encode(
            stored_request.get("request_id") or b"").decode().lower(),
        "action_class": action_class,
        "proposal_id": int(proposal_id),
        "target": stored_request.get("target") or "",
        "authenticator_id": stored_request.get("authenticator_id") or "",
        "approved_by": stored_request.get("user_id") or "",
        "executed_by": actor or "",
        "spent_at": int(now),
    }
