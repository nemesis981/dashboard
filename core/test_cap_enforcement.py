"""Tests for the remote-device cap: admission decisions and the stamping path.

Run:  python3 core/test_cap_enforcement.py

Temp databases, fake tailnet. No live state.

WHAT THIS IS GUARDING. A cap has two ways to be wrong and only one of them is
noisy. Refusing too much is loud — someone complains immediately. Permitting too
much is silent, and it is the failure that matters commercially: it looks exactly
like working software. So most of what follows asserts that a grant did NOT
happen, and every such check is paired with a control proving the same code can
still say yes.

The one place this deliberately permits without measuring is an unreconcilable
census — see cap_guard's module docstring for why that trade was made. That
behaviour is pinned by a test too, so it cannot drift into fail-closed (which
would hard-lock the product on a vendor outage) without someone noticing.
"""

import os
import re
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "alert_manager"))

_failures = []


def check(label, got, want):
    if got != want:
        _failures.append("%s: got %r, want %r" % (label, got, want))
        print("  FAIL  %s: got %r, want %r" % (label, got, want))
    else:
        print("  ok    %s" % label)


class FakeTS:
    def __init__(self, nodes=None, configured=True, boom=False):
        self._n = nodes or []
        self._c = configured
        self._b = boom

    def is_configured(self):
        return self._c

    def list_devices(self):
        if self._b:
            raise RuntimeError("tailnet unreachable")
        return self._n


def make_db(remote_rows=0, with_col=True):
    """A DB with `remote_rows` remote-enabled approved devices."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    con = sqlite3.connect(path)
    cols = ("device_id TEXT, device_name TEXT, ip_address TEXT, "
            "enrollment_status TEXT")
    if with_col:
        cols += ", remote_enabled INTEGER DEFAULT 0"
    con.execute("CREATE TABLE agent_devices (%s)" % cols)
    for i in range(remote_rows):
        vals = ("d%d" % i, "dev%d" % i, "100.5.0.%d" % (i + 1), "approved")
        con.execute("INSERT INTO agent_devices VALUES (%s)"
                    % ",".join("?" * (5 if with_col else 4)),
                    vals + ((1,) if with_col else ()))
    con.commit()
    con.close()
    return path


def nodes_for(n):
    return [{"addresses": ["100.5.0.%d" % (i + 1)], "hostname": "d%d" % i,
             "nodeId": "n%d" % i} for i in range(n)]


def decide(db, used_nodes, cap=5, ts=None):
    """Run the REAL cap_guard against a patched census + entitlements."""
    from core import cap_guard, remote_census, entitlements as ent
    real_take = remote_census.take
    real_cap = ent.remote_cap_for_license
    try:
        remote_census.take = lambda db_path=None: real_take(
            db_path=db, tailscale=ts if ts is not None else FakeTS(nodes_for(used_nodes)))
        ent.remote_cap_for_license = lambda db_path=None: cap
        return cap_guard.check_admission(db_path=db)
    finally:
        remote_census.take = real_take
        ent.remote_cap_for_license = real_cap


def test_under_cap_allows():
    print("\n[under the cap: allowed, and the count is real]")
    db = make_db(remote_rows=2)
    try:
        d = decide(db, used_nodes=2)
        check("state", d.state, "allow")
        check("permitted", d.permitted, True)
        check("verified (a real measurement)", d.verified, True)
        check("used", d.used, 2)
        check("limit", d.limit, 5)
        check("remaining", d.remaining, 3)
    finally:
        os.unlink(db)


def test_the_sixth_is_refused():
    print("\n[the 6th remote enrollment is refused]")
    db = make_db(remote_rows=5)
    try:
        d = decide(db, used_nodes=5)
        check("state", d.state, "refuse")
        check("NOT permitted", d.permitted, False)
        check("used == cap", (d.used, d.limit), (5, 5))
        check("remaining is 0", d.remaining, 0)
        m = d.user_message()
        # The refusal must say what the user still HAS, or it reads as the
        # product refusing to protect them.
        check("message says local protection continues",
              "local protection" in m.lower(), True)
        check("message offers a way forward",
              "revoke" in m.lower() and "upgrade" in m.lower(), True)
    finally:
        os.unlink(db)


def test_boundary_is_exact():
    print("\n[the boundary is at N, not N+1 or N-1]")
    for used, cap, want in ((3, 5, "allow"), (4, 5, "allow"),
                            (5, 5, "refuse"), (6, 5, "refuse")):
        db = make_db(remote_rows=used)
        try:
            d = decide(db, used_nodes=used, cap=cap)
            check("used=%d cap=%d -> %s" % (used, cap, want), d.state, want)
        finally:
            os.unlink(db)


def test_unlimited_never_refuses_and_never_calls_the_api():
    print("\n[unlimited: allowed without consulting the tailnet]")
    db = make_db(remote_rows=99)
    try:
        # boom=True would raise if the census were consulted at all.
        d = decide(db, used_nodes=0, cap=None, ts=FakeTS(boom=True))
        check("state", d.state, "allow")
        check("limit is None (unlimited)", d.limit, None)
        check("remaining is None (not 0)", d.remaining, None)
    finally:
        os.unlink(db)


def test_degraded_census_fails_CLOSED_loudly():
    print("\n[unreconcilable census: REFUSES, and says it could not check]")
    db = make_db(remote_rows=9)
    try:
        d = decide(db, used_nodes=0, ts=FakeTS(boom=True))
        # CHANGED 2026-08-23: this used to PERMIT. Granting a remote slot is an
        # ENTITLEMENT decision, and an entitlement that cannot be metered is not
        # issued -- breaking the census on purpose was a bypass. Protection is a
        # separate question and is never gated here: the device still installs
        # and still gets full local protection.
        check("REFUSED (entitlement fails closed)", d.permitted, False)
        check("state is REFUSE_UNVERIFIED", d.state, "refuse_unverified")
        # The crucial distinction: permitted, but NOT measured.
        check("NOT verified", d.verified, False)
        check("used is None, not a fabricated number", d.used, None)
        check("reason names the cause", "unreachable" in d.reason.lower(), True)
        check("message admits it was not checked",
              "could not be checked" in d.user_message().lower(), True)
    finally:
        os.unlink(db)


def test_missing_column_also_fails_closed():
    print("\n[missing remote_enabled column: REFUSES, unverified]")
    db = make_db(with_col=False)
    try:
        d = decide(db, used_nodes=0)
        # Same reasoning as the degraded-census case: a schema we cannot read is
        # a count we cannot verify, and an unmeterable entitlement is not issued.
        check("REFUSED (entitlement fails closed)", d.permitted, False)
        check("not verified", d.verified, False)
        check("reason names the column", "remote_enabled" in d.reason, True)
    finally:
        os.unlink(db)


def test_revoked_devices_free_their_slot():
    print("\n[a revoked device stops consuming a slot]")
    db = make_db(remote_rows=5)
    try:
        check("at cap before revoking", decide(db, 5).state, "refuse")
        con = sqlite3.connect(db)
        # Mirror api_agent_revoke: status change AND the flag cleared.
        con.execute("UPDATE agent_devices SET enrollment_status='revoked', "
                    "remote_enabled=0 WHERE device_id='d0'")
        con.commit(); con.close()
        d = decide(db, 5)
        check("allowed after revoking one", d.state, "allow")
        check("count dropped to 4", d.used, 4)
    finally:
        os.unlink(db)


def test_local_devices_are_never_counted():
    print("\n[local devices do not consume remote slots]")
    db = make_db(remote_rows=2)
    try:
        con = sqlite3.connect(db)
        for i in range(20):
            con.execute("INSERT INTO agent_devices VALUES (?,?,?,?,?)",
                        ("L%d" % i, "local%d" % i, "192.168.1.%d" % (i + 2),
                         "approved", 0))
        con.commit(); con.close()
        d = decide(db, used_nodes=2)
        check("22 devices, only 2 remote", d.used, 2)
        check("still allowed", d.state, "allow")
    finally:
        os.unlink(db)


def test_source_level_wiring():
    """The guard must actually be CALLED at both seams, not merely importable."""
    print("\n[both enforcement seams call the guard]")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dash = open(os.path.join(root, "dashboard.py")).read()
    hwm = open(os.path.join(root, "core_module", "hw_monitor",
                            "hw_monitor.py")).read()

    check("generate seam imports cap_guard",
          dash.count("from core import cap_guard") >= 2, True)
    check("generate refuses with 409", '"remote_cap_reached"' in dash, True)
    check("mint seam re-checks", "_cap2 = cap_guard.check_admission()" in dash, True)
    # Re-checking at mint is the point: a token made under the cap can be
    # downloaded after it fills.
    check("mint degrades rather than failing the download",
          "_cap_degraded_note" in dash, True)
    check("refusals are audited",
          "installer_remote_refused_at_cap" in dash
          and "installer_mint_refused_at_cap" in dash, True)
    check("revoke clears the entitlement", "remote_enabled=0" in dash, True)
    check("enrollment stamps from the token",
          "SELECT remote_enabled FROM enrollment_tokens" in hwm, True)
    check("stamping is NOT inside the auto-approve branch",
          hwm.index("SELECT remote_enabled FROM enrollment_tokens")
          > hwm.index("auto_approve=1"), True)
    # CONTROL: these substring checks must be able to fail.
    check("CONTROL a bogus marker is absent",
          "cap_guard_definitely_not_here" in dash, False)


def test_pasted_key_does_not_bypass_seam_two():
    """A pasted key must NOT skip the download-time cap check.

    The first version gated the cap check on `_want_mint`, which required
    `not preauth` — so pasting a reusable key skipped it entirely. One key,
    unlimited remote devices, no API call to notice.
    """
    print("\n[a pasted key does not bypass the mint-seam cap check]")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dash = open(os.path.join(root, "dashboard.py")).read()
    seam = dash[dash.index("_tok_remote = (row["):]
    seam = seam[:seam.index("preauth, new_key_id = tailscale_api.mint_preauth_key")]
    code = "\n".join(l for l in seam.splitlines()
                     if not l.lstrip().startswith("#"))

    check("cap check is gated on _tok_remote alone",
          bool(re.search(r"if\s+_tok_remote\s*:", code)), True)
    # The regression itself: the check must not sit behind `not preauth`.
    check("cap check does NOT sit behind `not preauth`",
          bool(re.search(r"if\s+_want_mint\s*:\s*\n\s*from core import cap_guard", code)),
          False)
    check("a withheld grant clears a pasted key too",
          bool(re.search(r'preauth\s*=\s*""', code)), True)
    check("mint is suppressed once the cap refused",
          "not _cap_degraded_note" in code, True)
    # CONTROL: the seam was actually located, and the matchers can fire.
    check("CONTROL seam located", "cap_guard.check_admission()" in code, True)
    check("CONTROL the negative matcher can fire",
          bool(re.search(r"if\s+_want_mint\s*:\s*\n\s*from core import cap_guard",
                         "if _want_mint:\n    from core import cap_guard")), True)


if __name__ == "__main__":
    print("remote-device cap enforcement")
    test_under_cap_allows()
    test_the_sixth_is_refused()
    test_boundary_is_exact()
    test_unlimited_never_refuses_and_never_calls_the_api()
    test_degraded_census_fails_CLOSED_loudly()
    test_missing_column_also_fails_closed()
    test_revoked_devices_free_their_slot()
    test_local_devices_are_never_counted()
    test_source_level_wiring()
    test_pasted_key_does_not_bypass_seam_two()

    print("\n" + "=" * 60)
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  - %s" % f)
        sys.exit(1)
    print("ALL PASS")
