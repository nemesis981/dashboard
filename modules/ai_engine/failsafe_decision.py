"""Engine-side handler for `nemesis.failsafe.decision_request/1`.

Window 1 owns the SHAPE (`firewall-enforcement-engine/DECISION-REQUEST-SHAPE-v1.md`,
ADR 0019 Amendment 03 §10.3). This module owns the ENGINE side of it: turning one
request into one response.

═══════════════════════════════════════════════════════════════════════════════
⛔ THE ONE INVARIANT: A RESPONSE CAN ONLY EVER *REMOVE* AN OVERRIDE, NEVER ADD ONE
═══════════════════════════════════════════════════════════════════════════════
Any parse failure, timeout, unknown schema version, missing field, unexpected
value, unregistered action class, unavailable authority, expired deadline, or
unhandled exception resolves to `allow_revert`. **This function never raises and
never returns anything but a well-formed response.**

The safe default must be what happens when the mechanism FAILS, not something
the mechanism has to successfully choose. That is why there is no `defer` and no
`ask_again`: silence and malformed input are already `allow_revert`, so a
mechanism that cannot run produces the safe outcome for free.

⭐ WHY CONTEXT IS RETRIEVED *HERE* AND NOT CARRIED IN THE REQUEST
    (operator decision, 2026-08-27; Window 1's shape doc, "no prior decisions")
The failsafe sends FACTS AND A DEADLINE, and no persuasion. Learned context IS
prior decisions — precedent — and precedent in the request body is exactly the
persuasion that shape is narrow to exclude. So the engine, which OWNS the store,
enriches its own reasoning after the fact. The failsafe never reaches into the
AI's context store, and the request cannot be used to argue for its own outcome.

⚠ CONTEXT SHAPES JUDGMENT, NEVER AUTHORITY (DESIGN-L4 §4.6)
`effective_ceiling()` remains the sole authority. No learned entry can make this
class executable; the strongest possible context cannot raise a ceiling. Context
only informs WHICH choice is made once the ladder has already permitted the
class. `test_failsafe_decision.py` mutation-tests that separation.

⚠ `level_asserted` IS AN ASSERTION, NOT A GRANT. We assert L4 only when
`effective_ceiling()` actually reports L4. The failsafe independently refuses
anything that is not exactly L4 — deliberately NOT re-implementing the ladder,
because a second implementation could only ever disagree by WIDENING authority.
"""
from __future__ import annotations

import logging
import time

log = logging.getLogger("ai_engine.failsafe")

REQUEST_SCHEMA = "nemesis.failsafe.decision_request/1"
RESPONSE_SCHEMA = "nemesis.failsafe.decision_response/1"

#: Window 1 owns this registry entry (ADR 0019 Amendment 03 §10.3). We CONSUME
#: it. It is deliberately not defined here, and until it is registered every
#: request resolves to allow_revert via the invariant above — which is the
#: correct behaviour, not a gap to paper over.
ACTION_CLASS = "firewall_failsafe_override"

ALLOW_REVERT = "allow_revert"
OVERRIDE = "override"


def _response(change_id, decision, reasoning=None, level=None):
    out = {"schema": RESPONSE_SCHEMA,
           "change_id": change_id,
           "decision": decision}
    if decision == OVERRIDE:
        out["level_asserted"] = level or "L4"
        out["reasoning"] = reasoning
    return out


def _safe(change_id, why):
    """The only way this module declines to override. Always logged."""
    log.info("failsafe decision: allow_revert (change_id=%r) — %s", change_id, why)
    return _response(change_id, ALLOW_REVERT)


def decide(request, *, now=None, _analyze=None):
    """One decision request in, one decision response out. NEVER raises.

    `_analyze` is an injection seam for tests only; production passes nothing and
    the real `analyze()` is used.
    """
    change_id = None
    try:
        if not isinstance(request, dict):
            return _safe(None, "request is not an object")
        change_id = request.get("change_id")

        # An unknown schema version is not a reason to guess. A v2 field an old
        # consumer ignores may cost an override; it must never cause one.
        if request.get("schema") != REQUEST_SCHEMA:
            return _safe(change_id,
                         "unknown schema %r" % (request.get("schema"),))
        if not change_id:
            return _safe(None, "no change_id")

        checks = request.get("checks")
        if not isinstance(checks, list) or not checks:
            return _safe(change_id, "no checks supplied — the engine cannot "
                                    "reason about a system it cannot see")

        deadline = request.get("revert_deadline_epoch")
        if not isinstance(deadline, (int, float)) or isinstance(deadline, bool):
            return _safe(change_id, "revert_deadline_epoch missing or not a number")
        # Deciding after the deadline is meaningless: the revert has already
        # fired. Overriding here would look like a decision and change nothing,
        # which is worse than declining.
        if (now or time.time()) >= deadline:
            return _safe(change_id, "deadline already passed")

        # ── AUTHORITY, before anything else is even assembled ────────────────
        # Raises UnknownActionClass while Window 1's registry entry is unlanded,
        # and AuthorityUnavailable if the ladder cannot be read. Both are caught
        # below and both mean allow_revert.
        from modules.ai_engine import module as ai            # noqa: PLC0415
        try:
            ceiling = ai.effective_ceiling(ACTION_CLASS)
        except ai.UnknownActionClass:
            # EXPECTED while Window 1's registry entry is unlanded. Handled
            # explicitly rather than left to the catch-all below, which would
            # log a traceback for a known state -- and a traceback that appears
            # routinely is one nobody reads when it finally means something.
            return _safe(change_id,
                         "action class %r is not registered (Window 1 owns that "
                         "entry); refusing by default" % (ACTION_CLASS,))
        except ai.AuthorityUnavailable as exc:
            return _safe(change_id, "authority unreadable: %s" % (exc,))
        if ceiling.get("level") != ai.L4_GOVERN:
            return _safe(change_id,
                         "ceiling is %r, not L4 — the ladder has not granted "
                         "this class" % (ceiling.get("level"),))

        prompt = _build_prompt(request, checks)
        if prompt is None:
            return _safe(change_id, "prompt could not be assembled under NPFA/1")

        analyze = _analyze or ai.analyze
        result = analyze(prompt, surface="failsafe_override")
        if not isinstance(result, dict) or not result.get("ok"):
            return _safe(change_id, "analyze() declined or failed")

        # ⚠ THE REAL `analyze()` RETURNS {"ok", "text", ...} — THERE IS NO
        # "decision" KEY. An earlier version read result["decision"], which an
        # injected test double supplied and the real function never does, so
        # EVERY live call fell through to allow_revert. 64 unit checks were
        # green against a contract only the mock satisfied. Found 2026-08-27 on
        # the first real §5 run, which it turned into an all-allow_revert table
        # that read exactly like "accumulated context does nothing".
        # `decision`/`reasoning` are still honoured so an injected double keeps
        # working, but TEXT is the path production actually takes.
        verdict = (result.get("decision") or "").strip().lower()
        reasoning = (result.get("reasoning") or "").strip()
        if not verdict:
            verdict, reasoning = _parse_text(result.get("text") or "")
        if verdict != OVERRIDE:
            # Includes the empty string, an unparseable answer, an unexpected
            # value, and an explicit allow_revert. All the same answer,
            # deliberately — an answer we cannot read is not permission.
            return _safe(change_id, "verdict %r is not an override" % (verdict,))

        if not reasoning:
            # §10.4: an override whose reasoning exists only in the engine is
            # not disclosed, and an undisclosed override must not happen.
            return _safe(change_id, "override had no reasoning — refusing")

        log.warning("failsafe decision: OVERRIDE (change_id=%r) — %s",
                    change_id, reasoning)
        return _response(change_id, OVERRIDE, reasoning=reasoning, level="L4")

    except Exception:                                          # noqa: BLE001
        # The catch-all IS the invariant, not sloppiness. Every failure above is
        # already handled explicitly; this exists so that a failure nobody
        # anticipated still produces the safe outcome rather than a traceback
        # that leaves the caller with no response at all.
        log.exception("failsafe decision: unhandled error — allow_revert")
        return _response(change_id, ALLOW_REVERT)


def _parse_text(text):
    """(verdict, reasoning) from the model's free text. Fail-closed.

    ⭐ REQUIRES AN EXACT, UNAMBIGUOUS TOKEN. Anything this cannot read with
    certainty returns ("", "") and therefore allow_revert. Free-text parsing on
    a safety-critical path is where a permissive reading does the most damage:
    a response arguing AGAINST overriding contains the word "override", so
    substring matching would invert the answer. The model is instructed to emit
    one line in exactly this shape, and only that shape is honoured.
    """
    verdict, reasoning = "", ""
    for line in (text or "").splitlines():
        line = line.strip()
        low = line.lower()
        if low.startswith("decision:"):
            val = low.split(":", 1)[1].strip()
            # Exact match only. Never `in`, never startswith.
            if val in (OVERRIDE, ALLOW_REVERT):
                verdict = val
        elif low.startswith("reasoning:"):
            reasoning = line.split(":", 1)[1].strip()
    return verdict, reasoning


def _build_prompt(request, checks):
    """Assemble the NPFA/1 prompt: request facts + engine-side context.

    Returns a `BuiltPrompt`, or None if any field is inexpressible — which the
    caller turns into allow_revert. Refusing to send a prompt is always safe;
    silently dropping a field that would not validate is not.
    """
    try:
        import prompt_fields as pf                             # noqa: PLC0415
        from modules.ai_engine import context_store as cs      # noqa: PLC0415

        parts = [
            "A pending firewall change failed its post-apply health check. "
            "A revert is ALREADY SCHEDULED and will fire at the deadline below. "
            "You are not being asked to approve the revert; you are being "
            "offered a bounded window to prevent it. Override only if "
            "preventing the revert is clearly safer than allowing it.\n"
            "Answer in EXACTLY this form, two lines, nothing else:\n"
            "DECISION: override      (or)      DECISION: allow_revert\n"
            "REASONING: <one sentence, required if you override>\n"
            "Any other form is read as allow_revert.",
            ("Change id", pf.IDENTIFIER, request["change_id"]),
            ("Trigger", pf.ENUM, request.get("trigger"),
             {"allowed": {"healthcheck_failed", "guard_refusal"}}),
            ("Mode", pf.ENUM, request.get("mode"),
             {"allowed": {"manual", "unattended"}}),
            ("Revert deadline (epoch)", pf.TIMESTAMP,
             request["revert_deadline_epoch"]),
        ]

        # EVERY check, not just the failures (§10.4). Sending only failures
        # would let the engine reason about a system whose healthy half it
        # cannot see, and make UNKNOWN indistinguishable from an absent check.
        for chk in checks:
            if not isinstance(chk, dict):
                return None
            parts.append(("Check", pf.LABEL, str(chk.get("id", ""))))
            parts.append(("  verdict", pf.ENUM, chk.get("verdict"),
                          {"allowed": {"PASS", "FAIL", "UNKNOWN"}}))

        # ⭐ ENGINE-SIDE CONTEXT ENRICHMENT — the call site this whole module
        # exists to host. Never part of the request; retrieved here, from the
        # store this engine owns. Structure only, never admin_reasoning.
        ctx = cs.retrieve(ACTION_CLASS, "change", str(request["change_id"]))
        parts.extend(cs.context_parts(ctx, key_kind=pf.IDENTIFIER))

        return pf.build(parts)
    except Exception:                                          # noqa: BLE001
        log.exception("failsafe decision: prompt assembly failed")
        return None
