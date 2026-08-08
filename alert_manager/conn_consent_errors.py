"""Structured error codes for the Track C consent route (E-CONSENT-*).

Declared and registered here rather than inline in `dashboard.py` so the catalog
is greppable in one place and the route stays about routing — the same shape
`modules/dhcp/module.py` uses for E-DHCP-*.

WHY THESE ARE WIRED FROM THE START, not retrofitted
    This route grants and revokes permission to collect data about a person, and
    revocation ERASES data irreversibly. When one of those fails, "there is a
    line in the journal somewhere" is not good enough — the question an operator
    or an auditor will ask later is "did this person's erasure actually happen",
    and that has to be answerable from a structured record, not from grepping
    logs for a stack trace.

    `E_REVOKE_FAILED` is the most important code here. A revocation that was
    requested, rolled back, and left no structured trace is the worst outcome
    this route can produce: the requester believes their data is gone and it is
    not.

⚠ THE GRANT THIS DEPENDS ON, AND HOW IT WAS VERIFIED
    `record_error_best_effort()` NEVER raises — that is its whole purpose inside
    an exception handler. The consequence is that a namespace lacking write
    access to `error_codes`/`error_occurrences` records NOTHING while every call
    site looks correctly instrumented.

    That was the live state on 2026-08-08: no namespace at all could write those
    tables. Verified empirically rather than inferred — a guarded connection
    returned `None` from `record_error_best_effort()` and left 0 rows — before
    adding the two tables to the `conn_consent` namespace.

    ⚠ SCOPE: that fix covers THIS namespace. Other namespaces still lack the
    grant, and that broader sweep belongs to Window 3's error-code audit; it is
    deliberately not pre-empted here.
"""
import logging

import nemesis_errors

log = logging.getLogger("nemesis.conn_consent")

MODULE = "conn_consent"

#: Input the route refused. Not a system fault — recorded because a burst of
#: these is a signal (a broken caller, or someone probing the endpoint).
E_BAD_REQUEST = "E-CONSENT-001"

#: A grant could not be recorded. Consequence: the device stays unconsented and
#: its telemetry continues to be rejected — fails safe, but silently from the
#: user's point of view, which is why it is recorded.
E_GRANT_FAILED = "E-CONSENT-002"

#: ⚠ THE ONE THAT MATTERS MOST. A revocation failed and was rolled back. The
#: requester may believe their data was erased. It was not.
E_REVOKE_FAILED = "E-CONSENT-003"

#: Revocation requested for a device with no consent record. Not necessarily an
#: error in the system, but it MUST be recorded: if that device ever reported
#: data, the absence of a consent row is itself the finding.
E_REVOKE_NO_RECORD = "E-CONSENT-004"

#: Employer-basis consent was attempted while it is gated on legal review.
#: Recorded so demand for it is measurable rather than anecdotal.
E_EMPLOYER_BASIS_GATED = "E-CONSENT-005"

#: The consent state could not be read.
E_STATUS_FAILED = "E-CONSENT-006"

#: Failure family: an operation that changes what data may exist about a person
#: did not complete. Grouped so one confirmed cause can explain an occurrence at
#: any of them.
_CLASS_CONSENT_WRITE = "consent-write-failed"

_CATALOG = (
    (E_BAD_REQUEST,          "Consent request refused: invalid input",          "low",      None),
    (E_GRANT_FAILED,         "Consent grant could not be recorded",             "high",     _CLASS_CONSENT_WRITE),
    (E_REVOKE_FAILED,        "Consent revocation FAILED and was rolled back — "
                             "data was NOT purged",                             "critical", _CLASS_CONSENT_WRITE),
    (E_REVOKE_NO_RECORD,     "Revocation requested for a device with no "
                             "consent record",                                  "medium",   None),
    (E_EMPLOYER_BASIS_GATED, "Employer-basis consent attempted; gated on "
                             "legal review",                                    "low",      None),
    (E_STATUS_FAILED,        "Consent status could not be read",                "medium",   None),
)


def ensure_registered(conn):
    """Register every code. Idempotent. Returns the number registered.

    Best-effort by design: a catalog-registration failure must not stop a
    revocation from proceeding. But it is LOGGED loudly, because an unregistered
    code is refused by `record_error()` later — so a silent failure here would
    disable the error recording this module exists to provide, one layer down
    and out of sight.
    """
    n = 0
    for code, desc, sev, cls in _CATALOG:
        try:
            nemesis_errors.register_error_code(conn, code, MODULE, desc, sev,
                                               error_class=cls)
            n += 1
        except Exception as e:                                # noqa: BLE001
            log.error("consent error catalog: could not register %s: %r — "
                      "occurrences at this code will be REFUSED downstream",
                      code, e)
    return n


def record(conn, code, context, actor=None):
    """Record one occurrence. Never raises.

    Mirrors `modules/dhcp/module.py::_record`: "recorded" and "logged because
    recording was impossible" must never look the same to whoever reads the
    journal later, or the ledger appears to have gaps it cannot account for.
    """
    if conn is None:
        log.error("[%s] %s | NOT PERSISTED (no DB connection at this call site)",
                  code, context)
        return None
    rid = nemesis_errors.record_error_best_effort(conn, code, context=context,
                                                  actor=actor, logger=log)
    if rid is None:
        log.error("[%s] %s | NOT PERSISTED (error system could not record it)",
                  code, context)
    return rid
