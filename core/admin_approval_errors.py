"""E-APPROVAL-* codes: the bridge from the AAP-/GATE- wire vocabulary.

WHAT THIS IS NOT. It is NOT a replacement for `AAP-*`/`GATE-*`. Those are a
stable cross-language contract, mirrored BYTE-FOR-BYTE into
`nemesis_agent/admin_approval.py` (verified by diff, 2026-08-31), and
`admin_approval.Reason` says they are "never reassigned". Nothing here changes
or supersedes them.

WHAT WAS ACTUALLY MISSING, stated precisely, because the audit that found this
overstated it. The headline was "~108 KB of authentication code with no logger
at all", and the 0-of-8 figure is real -- but six of those eight files are
PURE, and a pure protocol verifier that returns typed verdicts SHOULD NOT log.
That is the same division `conn_consent` uses and the one applied to
email-security. The actual defect is narrower and sharper:

    `GateRejected` already carries `.reason` (a GATE- code) AND, for GATE-004,
    `.verdict` (carrying the underlying AAP- code) -- deliberately, so that
    "the AAP- code is never lost behind a generic gate failure".
    `dashboard.py` then collapsed all of it into `log.warning(... str(exc))`.

So the structured verdict survived the whole way up and was thrown away by its
caller. This module is the ~40 lines that stop that happening.

GRANULARITY: OUTCOME CLASS, NOT ONE-PER-DOMAIN-CODE (operator's decision,
2026-08-31). Seventeen 1:1 codes would mint a large catalog on speculation --
several domain codes (ALG_MISMATCH, COUNTER_REGRESSION) may never fire, which
is the phantom risk the registry guard warns about. One code would be too
coarse: a forged signature and an expired request would be indistinguishable at
the ledger, which is the entire reason to record. So rejections group by what
an operator DOES, and the exact domain code always travels in `context` -- no
information is lost, only aggregated.

⚠ THE MOST IMPORTANT CODE HERE IS NOT A REJECTION AT ALL. `E_AUDIT_GAP` is a
different KIND of event from the four above it: those are refusals of requests
that never happened, and it is the missing audit trail for a privileged action
that ALREADY DID. It has its own error_class for that reason -- grouping it
with the rejections would bury the one event nobody can reconstruct afterwards.
"""
import logging

log = logging.getLogger("nemesis.admin_approval.errors")

MODULE = "admin_approval"

# ── failure families ────────────────────────────────────────────────────────
#: A request was REFUSED. Nothing happened; the question is why, and how often.
_CLASS_REJECTED = "approval-rejected"

#: ⚠ NOT a refusal. A privileged action was ALREADY TAKEN and the record of it
#: is missing or incomplete. Deliberately its own class so it can never be read
#: as "another rejection".
_CLASS_AUDIT_GAP = "approval-audit-gap"


#: Cryptographic verification failed. A BURST OF THESE IS AN ATTACK SIGNAL and
#: is the reason this whole bridge is worth building: previously a forged
#: signature and an expired request produced the same single log line.
E_REJECTED_CRYPTO = "E-APPROVAL-001"

#: The approval is real and valid but binds something else -- a different
#: device, or a different capability. Operator error, not an attack.
E_REJECTED_SCOPE = "E-APPROVAL-002"

#: Ordinary lifecycle: unknown, expired, already consumed, or a lost race.
#: Routine; recorded so "routine" is measurable rather than assumed.
E_REJECTED_LIFECYCLE = "E-APPROVAL-003"

#: Rate limiter refused. Separate from lifecycle because a sustained rate-limit
#: is a different conversation from a user starting over.
E_REJECTED_RATE_LIMITED = "E-APPROVAL-004"

#: ⛔ THE ACTION HAPPENED AND THE RECORD DID NOT. Two sites: an approval spent
#: and executed whose `ai_local_approval_log` row failed to write, and a
#: successful mint whose follow-up queue write failed. Neither is recoverable
#: after the fact -- the approval is spent and unreplayable -- so the ledger
#: entry is the only remaining evidence that a privileged action occurred.
E_AUDIT_GAP = "E-APPROVAL-005"


# ── the mapping, and its completeness guarantee ─────────────────────────────
#
# Sets rather than a dict so an unmapped code is DETECTABLE (see classify()).
# `test_admin_approval_errors.py` asserts every code in Reason.ALL and
# GateReason.ALL appears in exactly one set, so adding a domain code upstream
# without classifying it FAILS A TEST rather than silently landing in a bucket.

_CRYPTO = frozenset({
    "AAP-006",   # ALG_MISMATCH
    "AAP-008",   # CHALLENGE_MISMATCH
    "AAP-009",   # UV_NOT_ASSERTED
    "AAP-010",   # BAD_SIGNATURE
    "AAP-011",   # COUNTER_REGRESSION
})

_SCOPE = frozenset({
    "AAP-004",   # UNKNOWN_AUTHENTICATOR
    "AAP-005",   # NOT_OWNED
    "AAP-007",   # BINDING_MISMATCH
    "GATE-001",  # TARGET_MISMATCH
    "GATE-002",  # CAPABILITY_MISMATCH
    "GATE-003",  # ACTION_UNSPECIFIED
})

_LIFECYCLE = frozenset({
    "AAP-001",   # UNKNOWN_REQUEST
    "AAP-002",   # ALREADY_CONSUMED
    "AAP-003",   # EXPIRED
    "AAP-012",   # CONSUMPTION_RACE
    "GATE-004",  # APPROVAL_REJECTED -- only when no inner verdict is carried
})

_RATE = frozenset({"AAP-013"})   # RATE_LIMITED


def classify(reason=None, aap_code=None) -> tuple:
    """(code, unmapped) for a rejection. NEVER guesses benign.

    `aap_code` wins over `reason`: GATE-004 exists precisely to say "the inner
    §7 verification failed, see .verdict", so classifying on the outer GATE
    code would file a forged signature as ordinary lifecycle -- exactly the
    conflation this bridge is meant to end.

    ⚠ AN UNRECOGNISED CODE MAPS TO THE **CRYPTO** BUCKET, NOT LIFECYCLE, and
    that direction is deliberate. If a domain code is added upstream and nobody
    updates the sets above, the wrong answer must be the LOUD one: a new
    security-relevant refusal quietly filed as routine is how a real signal
    goes unnoticed for months. Over-escalating is recoverable by reading
    `context["unmapped"]`; under-escalating is not. The completeness test
    exists so this fallback should never actually be reached.
    """
    for candidate in (aap_code, reason):
        if not candidate:
            continue
        if candidate in _CRYPTO:
            return E_REJECTED_CRYPTO, False
        if candidate in _SCOPE:
            return E_REJECTED_SCOPE, False
        if candidate in _RATE:
            return E_REJECTED_RATE_LIMITED, False
        if candidate in _LIFECYCLE:
            return E_REJECTED_LIFECYCLE, False
    return E_REJECTED_CRYPTO, True


_CATALOG = (
    (E_REJECTED_CRYPTO,       "Admin approval refused: cryptographic "
                              "verification failed (signature, challenge, "
                              "user-verification or counter). A burst is an "
                              "attack signal",                "high",   _CLASS_REJECTED),
    (E_REJECTED_SCOPE,        "Admin approval refused: the approval binds a "
                              "different device, capability or authenticator",
                                                              "medium", _CLASS_REJECTED),
    (E_REJECTED_LIFECYCLE,    "Admin approval refused: unknown, expired, "
                              "already consumed, or a lost consumption race",
                                                              "low",    _CLASS_REJECTED),
    (E_REJECTED_RATE_LIMITED, "Admin approval refused: rate limited",
                                                              "low",    _CLASS_REJECTED),
    (E_AUDIT_GAP,             "A privileged action was taken under an approval "
                              "and its record FAILED to write; the approval is "
                              "spent and unreplayable, so no audit trail of it "
                              "exists",                       "high",   _CLASS_AUDIT_GAP),
)


def ensure_registered(conn):
    """Register the catalog. Idempotent; safe to call per request."""
    import nemesis_errors                                     # noqa: PLC0415
    for code, desc, sev, cls in _CATALOG:
        try:
            nemesis_errors.register_error_code(conn, code, MODULE, desc, sev,
                                               error_class=cls)
        except Exception:                                     # noqa: BLE001
            log.debug("admin_approval: could not register %s", code)


def record(conn, code, context, actor=None):
    """Record one occurrence. NEVER raises.

    Mirrors `conn_consent_errors.record`: "recorded" and "logged because
    recording was impossible" must never look the same to whoever reads the
    journal later, or the ledger appears to have gaps it cannot account for.
    """
    if conn is None:
        log.error("[%s] %s | NOT PERSISTED (no DB connection at this call site)",
                  code, context)
        return None
    try:
        import nemesis_errors                                 # noqa: PLC0415
        ensure_registered(conn)
        rid = nemesis_errors.record_error_best_effort(
            conn, code, context=context, actor=actor, logger=log)
    except Exception:                                         # noqa: BLE001
        log.exception("[%s] %s | NOT PERSISTED (recorder raised)", code, context)
        return None
    if rid is None:
        log.error("[%s] %s | NOT PERSISTED (error system could not record it)",
                  code, context)
    return rid
