"""Runtime privilege attestation for Nemesis services.

Why this exists: systemd's hardening directives FAIL OPEN. A unit that asks for
a restriction the kernel cannot supply logs a warning and starts anyway,
unrestricted — the finding recorded in the L3 Tier-2 sandbox work. So a service
must never infer its own confinement from the fact that its unit file requested
it. It asserts the boundary against the kernel at startup and refuses to run if
the assertion fails.

Every de-privileged Nemesis service calls attest_from_env() as its first action.

Sources of truth (all kernel-provided, none self-reported by the unit):
  * os.geteuid()                    — actual effective uid
  * /proc/self/status CapEff        — actual effective capability set
  * /proc/self/status NoNewPrivs    — actual no-new-privs bit
  * os.access(..., os.W_OK)         — actual write reachability

STAGING: attest_from_env() is INERT unless the unit sets NEMESIS_EXPECT_USER.
That is deliberate. It means dropping this module into the tree changes nothing
for a service still running under its old unit — the boundary check activates
only when the migrated unit declares what identity to expect. Without that, a
restart between the code change and the unit change would kill the service.
"""

import os
import sys
import pwd
import logging

log = logging.getLogger("nemesis.privsep")

#: Unit-provided expectation. Absent => pre-migration unit => attestation skipped.
EXPECT_USER_ENV = "NEMESIS_EXPECT_USER"


class PrivilegeAttestationError(RuntimeError):
    """The running process does not match its declared privilege boundary."""


def _proc_status_field(name):
    """Read one field from /proc/self/status. Returns None if unavailable."""
    try:
        with open("/proc/self/status", "r") as fh:
            for line in fh:
                if line.startswith(name + ":"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        return None
    return None


def effective_capabilities():
    """Effective capability bitmask from the kernel, or None if unreadable."""
    raw = _proc_status_field("CapEff")
    if raw is None:
        return None
    try:
        return int(raw, 16)
    except ValueError:
        return None


def no_new_privs():
    """True/False from the kernel, or None if unreadable."""
    raw = _proc_status_field("NoNewPrivs")
    if raw is None:
        return None
    return raw == "1"


def attest(service,
           expect_user=None,
           must_not_write=(),
           require_no_new_privs=True,
           require_empty_caps=True,
           allow_root=False):
    """Assert this process's privilege boundary. Raise if it does not hold.

    service        — name, for log lines.
    expect_user    — if given, the euid must resolve to this username.
    must_not_write — paths this service must NOT be able to write. Checked with
                     a real access() call, not assumed from ownership.
    allow_root     — escape hatch for a service that legitimately needs root.
                     Must be set deliberately; never the default.
    """
    findings = []

    euid = os.geteuid()
    if euid == 0 and not allow_root:
        findings.append("running as root (euid=0) but allow_root is not set")

    if expect_user is not None:
        try:
            actual = pwd.getpwuid(euid).pw_name
        except KeyError:
            actual = "uid:%d" % euid
        if actual != expect_user:
            findings.append("running as %r, expected %r" % (actual, expect_user))

    caps = effective_capabilities()
    if require_empty_caps and not allow_root:
        if caps is None:
            findings.append("could not read CapEff from /proc/self/status")
        elif caps != 0:
            findings.append("effective capabilities are not empty "
                            "(CapEff=0x%016x)" % caps)

    if require_no_new_privs:
        nnp = no_new_privs()
        if nnp is None:
            findings.append("could not read NoNewPrivs from /proc/self/status")
        elif not nnp:
            findings.append("NoNewPrivs is not set — privilege escalation via "
                            "setuid binaries is still possible")

    for path in must_not_write:
        if os.access(path, os.W_OK):
            findings.append("can write %r, which is outside this service's "
                            "boundary" % path)

    if findings:
        detail = "; ".join(findings)
        log.critical("privilege attestation FAILED for %s: %s", service, detail)
        raise PrivilegeAttestationError(
            "%s: privilege boundary not satisfied: %s" % (service, detail))

    log.info("privilege attestation OK for %s (euid=%d, CapEff=0x%016x, "
             "NoNewPrivs=%s)", service, euid, caps or 0, no_new_privs())
    return True


def attest_or_exit(service, **kw):
    """attest(), but exit non-zero instead of raising — for use at service start.

    Exiting non-zero is deliberate: systemd's Restart= will retry, and a
    persistently mis-privileged service stays down and visible rather than
    running silently without its boundary.
    """
    try:
        attest(service, **kw)
    except PrivilegeAttestationError as exc:
        print("FATAL: %s" % exc, file=sys.stderr)
        sys.exit(78)          # EX_CONFIG


def attest_from_env(service, must_not_write=()):
    """Attest against the identity the UNIT declares, or skip if it declares none.

    Reads NEMESIS_EXPECT_USER. If unset, this service is still on its
    pre-migration unit: log once and return without asserting anything, so the
    module is inert until the migrated unit is in place.
    """
    expect = os.environ.get(EXPECT_USER_ENV, "").strip()
    if not expect:
        log.warning("privilege attestation SKIPPED for %s — %s not set "
                    "(pre-migration unit)", service, EXPECT_USER_ENV)
        return False
    attest_or_exit(service, expect_user=expect, must_not_write=must_not_write)
    return True
