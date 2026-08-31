"""E-EMAIL-* error codes for the email-security pipeline.

WHY THIS FILE EXISTS. Before 2026-08-31 this subsystem recorded ZERO structured
errors across 20 files. Its failure DESIGN was already good -- three terminal
watcher states, three credential exception classes, fail-closed refusals -- but
all of it lived only in log lines and in a thread-local `_Watcher.state` string.
A dashboard restart erased every record that a mailbox had ever failed, and a
mailbox stuck in AUTH_FAILED for three weeks was indistinguishable, in
`states()`, from one that entered it thirty seconds ago.

GRANULARITY: ONE CODE PER OPERATOR-ACTIONABLE DISTINCTION (operator's decision,
2026-08-31). The filter applied to every candidate was "would an operator do
something DIFFERENT for these two?" So:

  * credential store unreadable (EVERY mailbox, a deployment fault) and
    credential missing (ONE incomplete enrollment) are separate codes -- the
    fixes are unrelated and the blast radius differs by orders of magnitude.
  * cert-verification, TLS handshake and STARTTLS-refused are ONE transport
    code with the specific cause in `context` -- the operator's action is the
    same ("fix this mailbox's transport"), and the distinction that mattered
    historically is preserved in the context payload rather than lost.

DELIBERATELY NOT CODED: the ordinary enrollment refusals (invalid / expired /
already-used code, SettingsError). They are input refusals on the highest-volume
unauthenticated path, not system faults, and coding them would bury real faults
under probe traffic. E-EMAIL-010 (the privileged helper's consume rejection) is
the ONE exception, and it earns it -- see its note at the bottom of this file.

WHERE RECORDING HAPPENS, AND WHY IT IS NOT WHERE THE ERROR IS RAISED.
`imap_idle`, `credential_store`, `enrollment` and `fast_check` have NO database
access at all -- verified, not assumed. They raise typed exceptions and the
layers that CATCH them (supervisor, views, the dashboard routes) record. That is
the same division `conn_consent` uses, and it keeps four pure modules pure.

THE DATA MANAGER GRANT, AND HOW IT WAS VERIFIED. `email_security` is NOT granted
`error_codes`/`error_occurrences` -- `dm.allowed("email_security",
"error_occurrences")` returns **False**. Recording still works, because the
error-ledger exemption in data_manager.py operates BELOW `allowed()` and is
namespace-independent. This was proven end to end on a throwaway DB (a recorded
occurrence read back as 1 row), not inferred from that comment, because a
missing grant in this codebase fails SILENTLY -- a `WOULD DENY` log line and a
write that simply does not happen. If someone later makes `allowed()` the single
gate for every path, this breaks, and the symptom will be silence.
"""
import logging

# ⚠ `nemesis_errors` is imported LAZILY inside _get_recorder(), not here.
# A top-level import would make this module -- and therefore supervisor.py,
# which imports it -- unimportable unless `alert_manager` is already on
# sys.path. That is true in the dashboard process and NOT true for standalone
# runs and test harnesses; it broke test_build_client.py the moment it was
# added. Same deferral, same reason, as diagnostics/redact.py.

log = logging.getLogger("nemesis.email_security.errors")

MODULE = "email_security"

# ── failure families, for grouping a catalog this size ──────────────────────
#: The mailbox is enrolled and enabled and is NOT being scanned. One confirmed
#: cause ("the app password was rotated") can explain an occurrence at any of
#: them, rather than each site relearning it.
_CLASS_UNSCANNED = "email-mailbox-unscanned"

#: The credential file itself -- shared by every mailbox on the appliance.
_CLASS_CREDENTIAL = "email-credential-store"

#: A defect in this code, not a configuration the operator can fix.
_CLASS_DEFECT = "email-defect"


# ── terminal watcher states (supervisor.TERMINAL_STATES) ────────────────────

#: The provider rejected the credential. PERMANENT: it will not recover on its
#: own. The most important code here -- it is the state the whole supervisor
#: was written for, and the one an operator most needs aggregated over time.
E_AUTH_FAILED = "E-EMAIL-001"

#: Transport is unusable: certificate verification failed, the TLS handshake
#: failed, STARTTLS was refused, or the stored settings are not connectable.
#: The specific cause goes in `context` -- see this module's header for why
#: these three share one code.
E_TRANSPORT_CONFIG = "E-EMAIL-002"

#: The watcher raised something neither auth nor transport. This is a BUG, and
#: the code exists to say so: without it a defect is filed as CONFIG_ERROR and
#: the operator is sent to check a configuration that is fine. Exactly what
#: happened on 2026-08-31 with an unbound name in `_build_client`.
E_WATCHER_CRASHED = "E-EMAIL-003"


# ── credential store ────────────────────────────────────────────────────────

#: The store could not be READ -- absent, permission-denied, unreadable, or not
#: valid UTF-8. Affects EVERY mailbox, so it is the deployment-wide fault.
#: Direct analogue of E-REDACT-001, which codes the identical situation (a 0640
#: root:nemesis file unreadable by the calling process) in the reference
#: implementation.
E_CREDENTIAL_STORE_UNREADABLE = "E-EMAIL-004"

#: No entry for THIS mailbox's credential_ref. One incomplete enrollment, not a
#: deployment fault. Separated from 004 precisely because the fixes differ:
#: this one is "send the owner a new enrollment link".
E_CREDENTIAL_MISSING = "E-EMAIL-005"

#: The `EMAIL_SEC_APPPW_<N>` keyspace is exhausted (slot > 999). Permanent and
#: install-wide, with a documented widening procedure -- worth its own code
#: because no amount of retrying or re-enrolling clears it.
E_CREDENTIAL_KEYSPACE = "E-EMAIL-006"


# ── subsystem-level ─────────────────────────────────────────────────────────

#: The enrolled-account list could not be read, so the supervisor cannot start
#: ANY watcher. The whole feature is down, not one mailbox.
E_ACCOUNT_LOAD_FAILED = "E-EMAIL-007"

#: A delivered message could not be scanned (parse or check failure). Per
#: message, so a burst is the signal -- it means mail is arriving and NOT being
#: examined, which is a coverage gap rather than an outage.
E_SCAN_FAILED = "E-EMAIL-008"

#: The credential was stored but the account row write failed. A HALF-STATE:
#: the app password is on disk in a slot nothing references, and the mailbox is
#: not registered. Recorded because the owner believes they finished enrolling.
E_ENROLL_HALF_WRITTEN = "E-EMAIL-009"


# ── the one enrollment refusal that IS coded ────────────────────────────────

#: The privileged helper refused to consume an enrollment code.
#:
#: ⚠ WHY THIS ONE AND NOT THE OTHER REFUSALS. `op_write_email_secret` is the
#: SOLE AUTHORITY for writing an email credential from an unauthenticated
#: request, and until this code existed its rejection branch had **no log call
#: at all** -- invalid, expired and already-used were collapsed into one
#: caller-facing answer (correct: that collapse is the anti-oracle the
#: enrollment design requires) and then recorded NOWHERE. The `_AUTH_EXEMPT`
#: hardening checklist requires "log the distinction internally, never expose
#: it"; it was exposed to nobody and logged to nobody, so the distinction was
#: destroyed rather than protected.
#:
#: The internal reason goes in `context`. It must NEVER reach the caller.
#:
#: ⛔ DECLARED IN alert_manager/nemesis_fwd.py, NOT HERE, AND THAT IS DELIBERATE.
#: The recording happens inside the privileged root helper, which imports
#: NOTHING from modules/ by design -- verified, not assumed. Declaring the code
#: in both places would be a genuine cross-file duplicate and the registry
#: collision guard would (correctly) reject it, so it has exactly one
#: declaration site: nemesis_fwd's own `_ERR_CODES`. Named here in prose only,
#: so this catalog still documents the full E-EMAIL range.


_CATALOG = (
    (E_AUTH_FAILED,       "Mailbox authentication rejected by the provider; "
                          "scanning has stopped and will not resume without a "
                          "new credential",                     "high",     _CLASS_UNSCANNED),
    (E_TRANSPORT_CONFIG,  "Mailbox transport unusable (certificate, TLS "
                          "handshake, STARTTLS or unconnectable settings); "
                          "scanning has stopped",               "high",     _CLASS_UNSCANNED),
    (E_WATCHER_CRASHED,   "Mailbox watcher crashed unexpectedly — a defect, "
                          "not a configuration fault",          "high",     _CLASS_DEFECT),
    (E_CREDENTIAL_STORE_UNREADABLE,
                          "Email credential store unreadable; EVERY mailbox "
                          "is affected (deployment or permissions fault)",
                                                                "critical", _CLASS_CREDENTIAL),
    (E_CREDENTIAL_MISSING,
                          "No stored credential for this mailbox; its "
                          "enrollment never completed",         "medium",   _CLASS_CREDENTIAL),
    (E_CREDENTIAL_KEYSPACE,
                          "Credential slot keyspace exhausted; no further "
                          "mailbox can be enrolled until it is widened",
                                                                "high",     _CLASS_CREDENTIAL),
    (E_ACCOUNT_LOAD_FAILED,
                          "Enrolled-account list unreadable; the email "
                          "supervisor cannot start any watcher",
                                                                "critical", None),
    (E_SCAN_FAILED,       "A delivered message could not be scanned; it "
                          "arrived and was not examined",       "medium",   None),
    (E_ENROLL_HALF_WRITTEN,
                          "Credential stored but the mailbox row was not "
                          "written; an orphaned slot and an unregistered "
                          "mailbox the owner believes is connected",
                                                                "high",     None),
)

_recorder = None


def _get_recorder():
    """Deferred, because importing a module must never touch the database.

    Same reasoning as diagnostics/redact.py and modules/dhcp/module.py: this
    module is imported by pure code paths and by standalone runs where the
    shared DB path is not registered yet.
    """
    global _recorder
    if _recorder is None:
        import nemesis_errors                                   # noqa: PLC0415
        from modules import get_data_manager                    # noqa: PLC0415
        _recorder = nemesis_errors.make_recorder(
            MODULE,
            lambda: get_data_manager().connect(MODULE),
            {code: (desc, sev, cls) for code, desc, sev, cls in _CATALOG},
            logger=log)
    return _recorder


def record(code, context=None):
    """Record one occurrence. NEVER raises, and that is load-bearing.

    Every call site is inside an exception handler on a path that is already
    failing. A recorder that raised would replace a specific, actionable
    failure (a rejected app password) with the error system's own failure, and
    in the supervisor's case would take the watcher thread down with it.

    Returns the occurrence id, or None if recording itself failed.
    """
    try:
        return _get_recorder()(code, context=context)
    except Exception:                                           # noqa: BLE001
        # Deliberately silent to the CALLER, but not to the journal: a
        # recording system that fails invisibly is the thing this whole
        # subsystem was just fixed for.
        log.warning("email_security: could not record %s", code, exc_info=True)
        return None
