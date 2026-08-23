"""Tests for the connectivity-aware admission logic in cap_guard.

FAIL-CLOSED ON ENTITLEMENT since 2026-08-23 (was fail-open): granting a remote
slot requires a verified count. Protection is a separate question and is never
decided here -- a refused grant still leaves the device fully protected locally.

Run:  python3 core/test_cap_connectivity.py

No network: the reachability probe is replaced with a fake. Temp DBs.

WHAT THIS IS GUARDING. The cap previously failed open unconditionally, so
disconnecting the box was a one-step bypass. The fix must satisfy two opposing
requirements at once, and it is easy to satisfy only one:

  * a VENDOR outage must still fail open  (or a Tailscale blip locks out every
    install worldwide -- DRM behaviour)
  * NO INTERNET must refuse              (or the bypass is still there)

Every test below therefore pins one side of that line, and the pair
`test_case1_*` / `test_case2_*` are the two halves. A change that breaks either
one breaks the feature, in opposite directions.
"""

import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "alert_manager"))

from core import cap_guard, net_reachability as nr, remote_census, entitlements as ent  # noqa: E402

_failures = []


def check(label, got, want):
    if got != want:
        _failures.append("%s: got %r, want %r" % (label, got, want))
        print("  FAIL  %s: got %r, want %r" % (label, got, want))
    else:
        print("  ok    %s" % label)


class FakeTS:
    def __init__(self, nodes=None, boom=False):
        self._n = nodes or []
        self._b = boom

    def is_configured(self):
        return True

    def list_devices(self):
        if self._b:
            raise RuntimeError("tailnet unreachable")
        return self._n


def make_db(remote_rows=0):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE agent_devices (device_id TEXT, device_name TEXT, "
                "ip_address TEXT, enrollment_status TEXT, "
                "remote_enabled INTEGER DEFAULT 0)")
    for i in range(remote_rows):
        con.execute("INSERT INTO agent_devices VALUES (?,?,?,?,1)",
                    ("d%d" % i, "dev%d" % i, "100.6.0.%d" % (i + 1), "approved"))
    con.commit(); con.close()
    return path


def decide(db, ts, reach_state, corro=None, cap=5, reach_raises=False):
    """Run the REAL cap_guard with a faked census, probe and corroborator."""
    real_take = remote_census.take
    real_cap = ent.remote_cap_for_license
    real_verdict = nr.verdict
    real_corro = nr.diagnostics_corroboration
    try:
        remote_census.take = lambda db_path=None: real_take(db_path=db, tailscale=ts)
        ent.remote_cap_for_license = lambda db_path=None: cap

        def fake_verdict(force=False):
            if reach_raises:
                raise RuntimeError("probe exploded")
            return nr.Reach(reach_state, "fake:%s" % reach_state, 0, 3)

        nr.verdict = fake_verdict
        nr.diagnostics_corroboration = lambda db_path=None, max_age_s=300.0: corro
        return cap_guard.check_admission(db_path=db)
    finally:
        remote_census.take = real_take
        ent.remote_cap_for_license = real_cap
        nr.verdict = real_verdict
        nr.diagnostics_corroboration = real_corro


# ── the two halves of the line ───────────────────────────────────────────────

def test_case1_vendor_outage_fails_closed():
    """Tailscale down, internet fine -> REFUSES the grant (changed 2026-08-23).

    This asserted fail-OPEN until the entitlement/protection split. Granting a
    remote slot is an ENTITLEMENT decision and an entitlement that cannot be
    metered is not issued -- breaking the census on purpose was otherwise a
    one-step bypass. Protection is a separate question and is not decided here:
    the device still installs and still gets full local protection.
    """
    print("\n[CASE 1: Tailscale API down, internet ONLINE -> refuses, unverified]")
    db = make_db(remote_rows=99)          # far over cap: only the state matters
    try:
        d = decide(db, FakeTS(boom=True), nr.ONLINE)
        check("REFUSED", d.permitted, False)
        check("state", d.state, cap_guard.REFUSE_UNVERIFIED)
        check("not verified", d.verified, False)
        check("used is None, not fabricated", d.used, None)
        # Distinct from "you are at your limit" -- different cause, different remedy.
        check("not conflated with the cap being full",
              d.state != cap_guard.REFUSE, True)
    finally:
        os.unlink(db)


def test_case2_no_internet_refuses():
    """No internet at all -> refuse, with its own state."""
    print("\n[CASE 2: no internet -> REFUSE_NO_CONNECTIVITY]")
    db = make_db(remote_rows=0)           # under cap: only the state matters
    try:
        d = decide(db, FakeTS(boom=True), nr.OFFLINE)
        check("NOT permitted", d.permitted, False)
        check("state", d.state, cap_guard.REFUSE_NO_CONNECTIVITY)
        # Distinct from being at the cap: different cause, different remedy.
        check("distinct from REFUSE", d.state == cap_guard.REFUSE, False)
        m = d.user_message().lower()
        check("message says reconnect", "reconnect" in m, True)
        check("message promises local protection", "local protection" in m, True)
        check("message does NOT claim a grant", "granted" in m, False)
    finally:
        os.unlink(db)


# ── the ways this could be got wrong ─────────────────────────────────────────

def test_connectivity_never_overrides_a_real_count():
    """Offline but the census RECONCILED -> normal cap logic, not a refusal."""
    print("\n[offline is irrelevant when the count is real]")
    db = make_db(remote_rows=2)
    try:
        d = decide(db, FakeTS(nodes=[{"addresses": ["100.6.0.1"]},
                                     {"addresses": ["100.6.0.2"]}]), nr.OFFLINE)
        # The probe is not even consulted on this path.
        check("allowed on a real count", d.state, cap_guard.ALLOW)
        check("verified", d.verified, True)
        check("used", d.used, 2)
    finally:
        os.unlink(db)


def test_frozen_cache_bypass_is_closed():
    """Stale-green diagnostics + live OFFLINE -> the LIVE probe wins."""
    print("\n[frozen-cache bypass: live probe beats a stale ALL_OK]")
    db = make_db()
    try:
        d = decide(db, FakeTS(boom=True), nr.OFFLINE,
                   corro=(nr.ONLINE, "diagnostics verdict ALL_OK (12s old)"))
        check("still refuses", d.state, cap_guard.REFUSE_NO_CONNECTIVITY)
        check("reason records the disagreement",
              "trusting the live probe" in d.reason, True)
    finally:
        os.unlink(db)


def test_disagreement_the_other_way_is_inconclusive():
    """Live ONLINE but diagnostics says LOCAL_FAIL -> do not silently pick one."""
    print("\n[probe/diagnostics disagreement -> inconclusive, permitted]")
    db = make_db()
    try:
        d = decide(db, FakeTS(boom=True), nr.ONLINE,
                   corro=(nr.OFFLINE, "diagnostics verdict LOCAL_FAIL (30s old)"))
        check("REFUSED", d.permitted, False)
        check("state", d.state, cap_guard.REFUSE_UNVERIFIED)
        # The point of this test is unchanged by the fail-closed switch: the two
        # signals disagree and neither is silently preferred. Only the decision
        # that follows changed.
        check("reason records the disagreement", "disagree" in d.reason, True)
    finally:
        os.unlink(db)


def test_broken_probe_refuses_and_says_why():
    """A probe that raises must not silently grant.

    This asserted "must not deny service" until 2026-08-23. It still does not
    deny the PRODUCT -- local installation and protection are untouched. It
    declines to mint a new remote slot while the checker is broken, because a
    broken checker cannot distinguish a vendor outage from someone breaking the
    checker to defeat the cap, and the second is the case this exists to handle.
    """
    print("\n[broken probe -> INCONCLUSIVE, refused, recorded]")
    db = make_db()
    try:
        d = decide(db, FakeTS(boom=True), nr.ONLINE, reach_raises=True)
        check("REFUSED", d.permitted, False)
        check("state", d.state, cap_guard.REFUSE_UNVERIFIED)
        check("reason names the probe failure",
              "inconclusive" in d.reason.lower(), True)
        check("message tells the user to retry, not to buy slots",
              "try again" in d.user_message().lower(), True)
    finally:
        os.unlink(db)


def test_partial_reachability_is_not_offline():
    print("\n[1 of 3 targets reachable is INCONCLUSIVE, never OFFLINE]")
    db = make_db()
    try:
        d = decide(db, FakeTS(boom=True), nr.INCONCLUSIVE)
        check("REFUSED", d.permitted, False)
        # THE POINT OF THIS TEST IS UNCHANGED: partial reachability is
        # INCONCLUSIVE, never OFFLINE. Both refuse now, so the distinction lives
        # in WHICH refusal -- and it still matters, because "reconnect this
        # server" and "try again shortly" are different instructions.
        check("state", d.state, cap_guard.REFUSE_UNVERIFIED)
        check("NOT classified as offline", d.state != cap_guard.REFUSE_NO_CONNECTIVITY, True)
    finally:
        os.unlink(db)


# ── the real probe's own classification ──────────────────────────────────────

def test_quorum_classification():
    print("\n[the probe's quorum arithmetic]")
    real = nr._probe_one
    try:
        def make(n_ok):
            def _p(url, results, idx):
                results[idx] = (idx < n_ok, "fake")
            return _p
        for n_ok, want in ((3, nr.ONLINE), (2, nr.ONLINE),
                           (1, nr.INCONCLUSIVE), (0, nr.OFFLINE)):
            nr._probe_one = make(n_ok)
            r = nr.verdict(force=True)
            check("%d/3 reachable -> %s" % (n_ok, want), r.state, want)
    finally:
        nr._probe_one = real
        nr._cache.update(at=0.0, result=None)


def test_stale_diagnostics_gives_no_opinion():
    print("\n[a stale diagnostics row yields None, not agreement]")
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE diagnostics_status (id INTEGER PRIMARY KEY, "
                "updated_at REAL, verdict TEXT)")
    con.execute("INSERT INTO diagnostics_status VALUES (1,?, 'ALL_OK')",
                (time.time() - 3600,))
    con.commit(); con.close()
    try:
        check("1h-old row -> None", nr.diagnostics_corroboration(path), None)
        con = sqlite3.connect(path)
        con.execute("UPDATE diagnostics_status SET updated_at=?", (time.time(),))
        con.commit(); con.close()
        got = nr.diagnostics_corroboration(path)
        check("fresh row -> an opinion", got[0] if got else None, nr.ONLINE)
        con = sqlite3.connect(path)
        con.execute("UPDATE diagnostics_status SET verdict='UPSTREAM_FAIL'")
        con.commit(); con.close()
        got = nr.diagnostics_corroboration(path)
        # Operator decision 2026-08-17: UPSTREAM_FAIL counts as OFFLINE.
        check("UPSTREAM_FAIL counts as OFFLINE", got[0] if got else None, nr.OFFLINE)
        con = sqlite3.connect(path)
        con.execute("UPDATE diagnostics_status SET verdict='LOCAL_FAIL'")
        con.commit(); con.close()
        got = nr.diagnostics_corroboration(path)
        check("LOCAL_FAIL counts as OFFLINE", got[0] if got else None, nr.OFFLINE)
    finally:
        os.unlink(path)


# ── backstops ────────────────────────────────────────────────────────────────

def test_only_one_state_permits():
    """Backstop: adding a state must not accidentally default to permitting.

    Was "exactly two states permit" until 2026-08-23. ALLOW is now the only one:
    a grant requires a verified count, not merely the absence of a refusal.
    """
    print("\n[backstop: exactly ONE state permits a grant]")
    permitting = [s for s in cap_guard.ALL_STATES
                  if cap_guard.Decision(s, limit=5).permitted]
    check("all states enumerated", len(cap_guard.ALL_STATES), 4)
    check("exactly ALLOW permits", sorted(permitting), [cap_guard.ALLOW])


def test_no_message_contradicts_its_decision():
    """A refusal must never render as a grant.

    REFUSE_NO_CONNECTIVITY originally fell through user_message()'s branches to
    the trailing "Remote access granted..." text. That is worse than no message.
    """
    print("\n[backstop: no refusing state produces a 'granted' message]")
    # MATCH THE CLAIM, NOT THE WORD (corrected 2026-08-23). The bare substring
    # "granted" flagged REFUSE_UNVERIFIED's correct message -- "a new remote slot
    # cannot be granted yet" -- as though it claimed a grant. The matcher was
    # wrong, not the wording. A refusal that contains the word while denying it
    # is exactly what this backstop should tolerate; what it must catch is a
    # refusal that reads as "Remote access granted".
    CLAIM = "access granted"
    for s in cap_guard.ALL_STATES:
        d = cap_guard.Decision(s, used=2, limit=5)
        msg = d.user_message().lower()
        if not d.permitted:
            check("%s does not CLAIM a grant" % s, CLAIM in msg, False)
            # Paired positive: absence of the claim is not enough -- the message
            # must actually read as a refusal, or an empty string would pass.
            check("%s reads as a refusal" % s,
                  any(w in msg for w in ("cannot", "no internet", "used all",
                                         "not be granted", "try again")), True)
        else:
            # CONTROL: permitting states SHOULD claim a grant, or the check above
            # would pass against a function that never says it at all.
            check("CONTROL %s does claim a grant" % s, CLAIM in msg, True)



def test_route_reports_the_right_cause():
    """The 409's machine-readable code must match the actual cause.

    Both refusals are 409, but the remedies are opposite: revoke a device vs.
    plug the network back in. A client branching on `error` would give exactly
    the wrong instruction if both said "cap reached".
    """
    print("\n[the generate seam distinguishes the two refusal causes]")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dash = open(os.path.join(root, "dashboard.py")).read()
    i = dash.index("installer_remote_refused")
    blk = dash[i - 1400:i + 1400]
    check("a distinct error code exists",
          "no_internet_connectivity" in blk, True)
    check("it is chosen from the decision state",
          "REFUSE_NO_CONNECTIVITY" in blk, True)
    check("the offline refusal is audited separately",
          "installer_remote_refused_offline" in blk, True)
    check("the offline hint says reconnect",
          "Reconnect this server" in blk, True)
    check("CONTROL the cap-reached code is still present",
          "remote_cap_reached" in blk, True)



if __name__ == "__main__":
    print("cap guard — connectivity-aware admission (fail-closed on entitlement)")
    test_case1_vendor_outage_fails_closed()
    test_case2_no_internet_refuses()
    test_connectivity_never_overrides_a_real_count()
    test_frozen_cache_bypass_is_closed()
    test_disagreement_the_other_way_is_inconclusive()
    test_broken_probe_refuses_and_says_why()
    test_partial_reachability_is_not_offline()
    test_quorum_classification()
    test_stale_diagnostics_gives_no_opinion()
    test_only_one_state_permits()
    test_no_message_contradicts_its_decision()
    test_route_reports_the_right_cause()

    print("\n" + "=" * 60)
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  - %s" % f)
        sys.exit(1)
    print("ALL PASS")
