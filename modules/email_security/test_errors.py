"""E-EMAIL-* codes: recorded, durable, and from the RIGHT failure path.

Run: python3 modules/email_security/test_errors.py

WHAT THIS PROTECTS, AND WHY EACH CHECK DRIVES A REAL FAILURE
    The whole point of this work is that a mailbox failure survives a restart
    and is queryable. So asserting the catalog "looks right" would prove
    nothing -- a catalog is just a dict. Every check below makes the supervisor
    ACTUALLY FAIL in a specific way and then reads the row back out of the
    database, because the failure this replaces was precisely one where the
    in-memory state looked fine.

    That is also the lesson from 2026-08-31's `_build_client` regression: all 25
    suites passed while no test ever executed the function, because they inject
    a client_factory and route around it. These tests inject a factory that
    RAISES the exception under test, so the real handler runs.

REAL DATA MANAGER, ENFORCE MODE, THROWAWAY DB. Not a stub: `email_security` is
NOT granted error_codes/error_occurrences (allowed() returns False), and
recording works only because the error-ledger exemption sits below allowed().
A stubbed DM cannot observe that, and a missing grant in this codebase fails
SILENTLY -- the write simply does not happen. So the grant is proven here, live,
rather than assumed from a comment.
"""
import os
import sys
import tempfile

sys.path.insert(0, "/opt/nemesis")
sys.path.insert(0, "/opt/nemesis/alert_manager")

import modules                                               # noqa: E402
import database                                              # noqa: E402
import data_manager as dm_mod                                # noqa: E402

_TMPDB = os.path.join(tempfile.mkdtemp(prefix="emailsec-errors-"), "t.db")
database.DB_PATH = _TMPDB
modules.set_shared_db_path(_TMPDB)
database.init_email_security_tables()

from modules.email_security import errors as E                # noqa: E402
from modules.email_security import supervisor as sup          # noqa: E402
from modules.email_security import imap_idle                  # noqa: E402
from modules.email_security import credential_store as cs     # noqa: E402

EXPECTED_CHECKS = 30
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 46:
        g, w = g[:43] + "...", w[:43] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def occurrences(code=None):
    """Rows read BACK OUT of the database -- never from memory."""
    conn = modules.get_data_manager().connect("email_security")
    try:
        if code:
            return conn.execute(
                "SELECT COUNT(*) FROM error_occurrences WHERE code=?",
                (code,)).fetchone()[0]
        return conn.execute(
            "SELECT code FROM error_occurrences ORDER BY id").fetchall()
    finally:
        conn.close()


ACCOUNT = {"id": 7, "address": "someone@example.com", "provider": "gmail",
           "imap_host": "imap.gmail.com", "imap_port": 993, "mailbox": "INBOX",
           "credential_ref": "EMAIL_SEC_APPPW_1", "tls_mode": "implicit",
           "authserv_id": None}


class _FakeClient:
    """A client that connects fine and then fails inside run().

    ⚠ THE DISTINCTION THIS CLASS EXISTS FOR. Raising from the client_factory
    exercises the BUILD-failure handler, which correctly files CONFIG_ERROR for
    everything. AUTH_FAILED and CRASHED live in the handlers around
    `client.run()`, so reaching them requires a client that is successfully
    built and then raises. The first version of this suite raised from the
    factory and "found" that auth failures were filed as config errors -- a
    defect in the test, not in the supervisor.
    """

    def __init__(self, exc):
        self._exc = exc

    def run(self, stop_event):
        raise self._exc

    def close(self):
        pass


def _run_watcher_with(exc, at="run"):
    """Drive the REAL supervisor until its handler files a terminal state.

    `at="build"` raises from the factory (credential/config faults, which is
    genuinely where those surface); `at="run"` raises from inside run().
    """
    def factory(account, cb):
        if at == "build":
            raise exc
        return _FakeClient(exc)
    s = sup.MailboxSupervisor(account_loader=lambda: [ACCOUNT],
                              client_factory=factory)
    s.start()
    for _ in range(200):
        st = s.states()
        if st and st[0]["state"] in sup.TERMINAL_STATES:
            break
        import time
        time.sleep(0.01)
    out = s.states()
    s.stop()
    return out


def main():
    print("\n0. CONTROLS: the harness is what it claims to be")
    check("throwaway DB, not the live one",
          "/var/lib/nemesis" not in _TMPDB and os.path.exists(_TMPDB), True)
    check("CONTROL a REAL DataManager, not a stub",
          isinstance(modules.get_data_manager(), dm_mod.DataManager), True)
    check("CONTROL enforcement is ON",
          dm_mod.namespace_mode("email_security"), dm_mod.MODE_ENFORCE)
    # The grant fact this whole file depends on, asserted rather than assumed.
    check("CONTROL email_security is NOT granted error_occurrences...",
          dm_mod.allowed("email_security", "error_occurrences"), False)
    check("CONTROL ...and recording works anyway (ledger exemption is real)",
          E.record(E.E_SCAN_FAILED, context={"probe": "grant"}) is not None, True)
    check("CONTROL ...and the row is READABLE BACK from the DB",
          occurrences(E.E_SCAN_FAILED), 1)

    print("\n1. the catalog is internally sound")
    codes = [c for c, _d, _s, _cl in E._CATALOG]
    check("every catalog code is unique", len(set(codes)), len(codes))
    check("every code is E-EMAIL-NNN shaped",
          all(c.startswith("E-EMAIL-") and c.split("-")[2].isdigit()
              for c in codes), True)
    check("every code has a non-empty description",
          all(d.strip() for _c, d, _s, _cl in E._CATALOG), True)
    check("severities are from the known set",
          {s for _c, _d, s, _cl in E._CATALOG} <= {"low", "medium", "high",
                                                   "critical"}, True)
    # NO PHANTOMS: a declared code nobody records is a lie in the catalog.
    src = ""
    for f in ("supervisor.py", "views.py", "errors.py"):
        src += open(os.path.join(os.path.dirname(os.path.abspath(__file__)), f),
                    encoding="utf-8").read()
    fwd = open("/opt/nemesis/alert_manager/nemesis_fwd.py", encoding="utf-8").read()
    # Matched by CONSTANT name, which is how call sites actually reference
    # them, plus the raw code for the one declared in nemesis_fwd.
    const_for = {v: k for k, v in vars(E).items()
                 if isinstance(v, str) and v.startswith("E-EMAIL-")}
    phantom = [c for c in codes
               if ("%s.record" % "_errors") not in src or
               (const_for.get(c, "@@") not in src and c not in fwd)]
    check("no PHANTOM codes -- every declared code has a call site",
          phantom, [])

    print("\n2. terminal watcher states record the RIGHT code")
    before = occurrences(E.E_AUTH_FAILED)
    st = _run_watcher_with(imap_idle.ImapAuthError("bad app password"))
    check("auth failure reaches AUTH_FAILED", st[0]["state"], sup.AUTH_FAILED)
    check("...and records E-EMAIL-001",
          occurrences(E.E_AUTH_FAILED), before + 1)

    before = occurrences(E.E_TRANSPORT_CONFIG)
    st = _run_watcher_with(imap_idle.ImapConfigError("certificate verify failed"))
    check("transport failure reaches CONFIG_ERROR", st[0]["state"],
          sup.CONFIG_ERROR)
    check("...and records E-EMAIL-002",
          occurrences(E.E_TRANSPORT_CONFIG), before + 1)

    transport_after_step2 = occurrences(E.E_TRANSPORT_CONFIG)
    before = occurrences(E.E_WATCHER_CRASHED)
    st = _run_watcher_with(ValueError("an unbound name, say"))
    check("an unexpected exception reaches CRASHED", st[0]["state"], sup.CRASHED)
    check("...and records E-EMAIL-003, NOT the transport code",
          occurrences(E.E_WATCHER_CRASHED), before + 1)
    # THE DISTINCTION THAT MATTERS: a defect must not be filed as a config
    # fault. This is exactly what happened with the _build_client regression --
    # the operator was told the transport was misconfigured.
    check("...and a crash did NOT add a transport occurrence",
          occurrences(E.E_TRANSPORT_CONFIG), transport_after_step2)

    print("\n3. credential faults are told apart (different fixes)")
    before_u = occurrences(E.E_CREDENTIAL_STORE_UNREADABLE)
    before_m = occurrences(E.E_CREDENTIAL_MISSING)
    _run_watcher_with(cs.CredentialUnavailable("store is 0640 and unreadable"),
                      at="build")
    check("store-unreadable records E-EMAIL-004 (affects EVERY mailbox)",
          occurrences(E.E_CREDENTIAL_STORE_UNREADABLE), before_u + 1)
    check("...and NOT the per-mailbox missing code",
          occurrences(E.E_CREDENTIAL_MISSING), before_m)
    _run_watcher_with(cs.CredentialMissing("no entry for this ref"), at="build")
    check("credential-missing records E-EMAIL-005 (ONE enrollment)",
          occurrences(E.E_CREDENTIAL_MISSING), before_m + 1)
    check("...and did not add another store-unreadable",
          occurrences(E.E_CREDENTIAL_STORE_UNREADABLE), before_u + 1)

    print("\n4. it SURVIVES a restart -- the entire point")
    # Drop every in-memory supervisor and re-read from the database, which is
    # what a dashboard restart does. Before this work, _Watcher.state was a
    # thread-local string and all of this vanished.
    total = occurrences()
    check("occurrences persist in the DB, not in memory", len(total) > 5, True)
    codes_seen = {r[0] for r in total}
    for expected in (E.E_AUTH_FAILED, E.E_TRANSPORT_CONFIG, E.E_WATCHER_CRASHED,
                     E.E_CREDENTIAL_STORE_UNREADABLE, E.E_CREDENTIAL_MISSING):
        check("%s readable after the fact" % expected, expected in codes_seen,
              True)

    print("\n5. recording NEVER raises -- every call site is already failing")
    check("an UNKNOWN code does not raise into the caller",
          E.record("E-EMAIL-999", context={"x": 1}) is None or True, True)
    # CONTROL: the no-raise guarantee is not vacuous -- a real code still works.
    check("CONTROL a known code still records after that",
          E.record(E.E_SCAN_FAILED, context={"after": "unknown-code"})
          is not None, True)

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [l for l, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
