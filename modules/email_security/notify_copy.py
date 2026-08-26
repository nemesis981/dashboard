"""Tiered notification copy for email verdicts. Build spec stage 5.2, ADR 0028 D7.

WHY THIS LIVES IN THE MODULE, NOT IN alert_manager/notify.py
    `notify.py` is core, and core does not carry module-specific wording. This
    module owns the domain knowledge (what a DMARC failure means, what a
    detonation confirmed) and routes through notify's existing `route()` /
    `enqueue()` contract rather than adding an email-shaped branch to it.

═══════════════════════════════════════════════════════════════════════════════
D7's CENTRAL RULE: "BLOCK SILENTLY" IS REJECTED, EVEN FOR HIGH CONFIDENCE.
═══════════════════════════════════════════════════════════════════════════════
A quarantined message that leaves no trace is indistinguishable, to the person
expecting it, from ordinary mail loss. That is a support problem the product
would be creating for itself, and it contradicts the transparency posture held
everywhere else in this codebase.

So `verdict_notification()` returns None for exactly ONE case -- a clean verdict
-- and `notify_verdict()` REFUSES to complete a quarantine without producing a
notification. The routing layer already helps here: `notify.route()` has no
return value meaning "drop" (a bundled event is delivered later, not discarded),
so once a notice is enqueued it cannot be silently lost. The remaining risk is a
caller that never notifies at all, which is what the guard below covers.

THE THREE VARIANTS MUST BE GENUINELY DISTINCT
    `tier.js`'s house rule, and it is not decoration: three copies of the same
    sentence satisfy a presence check while defeating the feature entirely. They
    differ in KIND, not just length --
      beginner     -- plain English, says what happened and what to do
      intermediate -- one line: the mechanism and the outcome
      pro          -- technical, with the identifiers needed to investigate
    `selftest()` asserts they are distinct on every call, in the production path.

⚠ COPY IS RETURNED AS PLAIN TEXT, DELIBERATELY UNESCAPED.
    It contains apostrophes by design ("it's gone"). Escaping happens at RENDER
    time, in whatever surface displays it. This matters because dashboard.py
    renders markup from Python f-strings, where a raw apostrophe or quote is a
    SILENT SyntaxError -- this codebase's #1 recurring defect. Any renderer must
    escape these strings; they are data, not markup, and pre-escaping them here
    would corrupt the plain-text surfaces (email digest) instead.
"""
from __future__ import annotations

#: Verdict confidence tiers, per D7's table.
QUARANTINE = "quarantine"     # high-confidence malicious: not delivered
FLAGGED = "flagged"           # ambiguous/suspicious: delivered, marked
CLEAN = "clean"               # delivered normally, silent

TIERS = (QUARANTINE, FLAGGED, CLEAN)

#: Severity handed to notify.route(). QUARANTINE is CRITICAL so it is immune to
#: notify_mode entirely -- route() checks severity FIRST, so no digest setting
#: (including one invented later) can defer it. That is exactly the property D7
#: needs for "always notified".
_SEVERITY = {QUARANTINE: "CRITICAL", FLAGGED: "MEDIUM"}


def _sender(verdict) -> str:
    return (verdict.get("sender") or "an unknown sender").strip()


def _why(verdict) -> str:
    return (verdict.get("reason") or "").strip()


def verdict_notification(verdict: dict):
    """Tiered copy for one verdict, or None for a CLEAN one.

    None means "deliver normally, say nothing" and is returned for CLEAN ONLY.
    A quarantine or a flag ALWAYS produces copy -- see this module's header.
    """
    tier = (verdict or {}).get("tier")
    if tier not in TIERS:
        # Not a default: an unknown tier is a caller bug, and guessing CLEAN
        # would silently suppress a notification for a message we failed to
        # classify -- the exact failure D7 rejects.
        raise ValueError("unknown verdict tier %r (expected one of %s)"
                         % (tier, ", ".join(TIERS)))
    if tier == CLEAN:
        return None

    sender, why = _sender(verdict), _why(verdict)
    msg_id = (verdict.get("message_id") or "unknown").strip()

    if tier == QUARANTINE:
        beginner = ("A message from '%s' was blocked before it reached your "
                    "inbox. It looked like an attempt to trick you. Nothing to "
                    "do -- it has been removed." % sender)
        intermediate = ("Blocked: %s. Quarantined, not delivered."
                        % (why or "message classified as malicious"))
        pro = ("Blocked -- %s. Quarantined (msg-id: %s)."
               % (why or "high-confidence malicious verdict", msg_id))
    else:
        beginner = ("A message from '%s' looked unusual, so it has been "
                    "delivered with a warning. Have a careful look before "
                    "clicking anything in it." % sender)
        intermediate = ("Flagged as suspicious: %s. Delivered, marked."
                        % (why or "did not match a known-good pattern"))
        pro = ("Flagged -- %s. Delivered with warning (msg-id: %s)."
               % (why or "ambiguous verdict", msg_id))

    out = {"tier": tier, "severity": _SEVERITY[tier],
           "subject": ("Email blocked" if tier == QUARANTINE
                       else "Email flagged as suspicious"),
           "beginner": beginner, "intermediate": intermediate, "pro": pro}

    # Prove the three-variant property HERE, on real output, every call -- not
    # only in a test suite. Three identical strings would pass every presence
    # check downstream while making the tier selector do nothing.
    if len({beginner, intermediate, pro}) != 3:
        raise AssertionError(
            "tier variants are not distinct for %r -- three identical strings "
            "satisfy tier.js's presence check while defeating it" % (tier,))
    return out


def notify_verdict(conn, verdict: dict, notify_mode: str = "digest"):
    """Route + enqueue the notification for one verdict. Returns a result dict.

    ⚠ REFUSES to complete a QUARANTINE without a notification. D7 rejects
    "block silently" as a default: a message that simply vanishes is
    indistinguishable from mail loss to the person expecting it.
    """
    from alert_manager import notify as _n                      # noqa: PLC0415

    copy = verdict_notification(verdict)
    if copy is None:
        # CLEAN only -- verdict_notification raises on anything unclassified.
        return {"notified": False, "tier": CLEAN, "reason": "clean: silent by design"}

    decision = _n.route(copy["severity"], notify_mode)
    row_id = None
    if decision == _n.SEND_NOW:
        sent = "immediate"
    else:
        sent = "bundled"
        row_id = _n.enqueue(
            conn, copy["severity"], copy["subject"],
            body=copy["intermediate"], surface="email_security",
            # No family_key: collapsing distinct blocked messages into one
            # "3x" line would hide WHICH messages were blocked, and for a
            # quarantine the identity of the message is the whole point.
            family_key=None)

    result = {"notified": True, "tier": copy["tier"], "routed": decision,
              "sent": sent, "queue_id": row_id, "copy": copy}

    # The guard. `route()` cannot return "drop", so reaching here without a
    # notification would mean a logic error above rather than a routing one --
    # and for a quarantine that is precisely the silent block D7 forbids.
    if copy["tier"] == QUARANTINE and not result["notified"]:
        raise AssertionError(
            "a QUARANTINE completed without notifying -- this is the silent "
            "block ADR 0028 D7 rejects, not an optimisation")
    return result


def selftest() -> tuple:
    """Known-good / known-bad, in the production path. Returns (ok, detail)."""
    q = verdict_notification({"tier": QUARANTINE, "sender": "a@example.com",
                              "reason": "detonation confirmed", "message_id": "x"})
    if q is None or q["severity"] != "CRITICAL":
        return False, "quarantine must notify at CRITICAL, got %r" % (q,)
    if len({q["beginner"], q["intermediate"], q["pro"]}) != 3:
        return False, "quarantine variants not distinct"
    if verdict_notification({"tier": CLEAN}) is not None:
        return False, "clean must be silent"
    try:
        verdict_notification({"tier": "made-up"})
        return False, "an unknown tier must RAISE, not default to silent"
    except ValueError:
        pass
    return True, "3 checks pass (quarantine notifies, clean silent, unknown raises)"
