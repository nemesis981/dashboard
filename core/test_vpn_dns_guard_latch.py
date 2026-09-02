"""apply_fix() state-machine: a null tunnel-DNS verdict must be RE-CHECKED, not latched.

WHY THIS FILE EXISTS. `state["applied"]` carried two different meanings:

  1. "a fix is in place"        -> correctly skips rediscovery and only re-verifies
  2. "no tunnel DNS was found"  -> must NOT skip rediscovery

Because both wrote the same flag, and the early return at the top of apply_fix()
sits ABOVE discover_tunnel_dns(), a cycle that found no tunnel-reachable resolver
marked itself applied and every later cycle short-circuited before discovery could
run again. The verdict was then frozen for the whole VPN session.

MEASURED LIVE, 2026-09-01 (Proton OpenVPN, /var/log/nemesis/vpn-dns-guard/):

    18:44:37  tunnel-dns candidates=[...] via_tunnel=[]   <- discovery ran ONCE
    18:44:42 .. 18:49:45   59 cycles, verify lines only   <- discovery never re-ran
    18:49:45  restored pre-VPN upstreams                  <- only tunnel-down cleared it

Ten minutes later the identical VPN and protocol, sampled at the same offset after
tun0 came up (+12.6s vs +12.3s), DID see the tunnel resolver 10.96.0.1 and applied
correctly. So the empty verdict is transient and re-checking is what recovers it.

Severity was latent, not live: the public upstream still resolved through the tunnel
that night. It becomes an outage the moment a killswitch blocks the public upstream
while tunnel DNS was in fact available -- the guard would sit latched on the wrong
answer holding a remedy it had already decided against.

WHY THE TRIGGER IS NOT ENCODED HERE. What makes discovery come back empty at +12s is
a SEPARATE, still-open question (a systemd-resolved restart racing the sample is the
leading candidate, not proven). This file deliberately asserts only the state machine:
whatever empties discovery, the correct response is to look again next cycle. Stubbing
discovery is therefore the right instrument, not a shortcut around the unknown.

Pure tests. No root, no network, no live Pi-hole, no live tailscaled. Writes ONLY to a
private temp dir -- never the production state file or the production log, which is a
forensic record this suite must not pollute.
"""
import contextlib
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

# ⛔ BEFORE THE IMPORT. STATE_PATH and LOG_PATH are resolved at module-import time,
# so setting these afterwards would silently leave the suite pointed at production.
_TMP = tempfile.mkdtemp(prefix="vpn-dns-guard-latch-")
os.environ["VPN_DNS_GUARD_STATE"] = os.path.join(_TMP, "state.json")
os.environ["VPN_DNS_GUARD_LOG"] = os.path.join(_TMP, "guard.log")

sys.path.insert(0, HERE)
sys.path.insert(0, REPO)
import vpn_dns_guard as G  # noqa: E402

# ⛔ NEUTRALISE THE LEGACY-STATE FALLBACK, or this suite measures the wrong box.
#
# _load_state() reads _LEGACY_STATE_PATH whenever the primary file is absent -- which
# is exactly the condition fresh_state() creates. On the build machine that legacy file
# is real, root-owned, dated 2026-08-02, and reads {"applied": true, ... "tun0"}. So a
# "fresh" state arrived ALREADY APPLIED, apply_fix() took its early return, and
# discovery was never reached: the suite reported zero discovery calls and every symptom
# looked exactly like the latch it was written to detect. The instrument was broken in
# the same shape as the bug, which is the hardest kind to notice.
#
# Pointing it at a path inside the temp dir keeps the REAL loader under test while
# removing the contamination. test_fresh_state_precondition below proves it took.
G._LEGACY_STATE_PATH = os.path.join(_TMP, "legacy-must-not-exist.json")

_fail = []
_count = 0
EXPECTED_CHECKS = 32

TUNNEL = {"up": True, "iface": "tun0", "kind": "tun"}
PRE_VPN = ["1.1.1.1"]
TUN_DNS = ["10.96.0.1"]


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-72s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


# --------------------------------------------------------------------------
# Doubles
# --------------------------------------------------------------------------

class FakePihole:
    """Records every write, so 'left untouched' is provable rather than assumed."""

    def __init__(self, upstreams):
        self.upstreams = list(upstreams)
        self.set_calls = []

    def get_upstreams(self):
        return list(self.upstreams)

    def set_upstreams(self, upstreams):
        self.upstreams = list(upstreams)
        self.set_calls.append(list(upstreams))


class Scripted:
    """A scripted stub that COUNTS its calls.

    The call count is the load-bearing assertion in this file: the latch is not
    visible in the return value of any single cycle, only in discovery never being
    asked a second time. A stub that merely returned canned answers could not tell
    the fixed code from the broken code.
    """

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []
        self._last = None

    def __call__(self, *args):
        self.calls.append(args)
        if self.answers:
            self._last = self.answers.pop(0)
        return self._last


@contextlib.contextmanager
def patched(discovery, verify):
    od, ov = G.discover_tunnel_dns, G.verify_upstream_resolves
    G.discover_tunnel_dns, G.verify_upstream_resolves = discovery, verify
    try:
        yield
    finally:
        G.discover_tunnel_dns, G.verify_upstream_resolves = od, ov


def fresh_state():
    """A genuinely empty state, through the REAL loader -- not a hand-built dict.

    Going through _load_state() means the default shape this suite asserts against is
    the one production actually starts from; a literal here would keep passing after
    the real default drifted away from it.
    """
    try:
        os.unlink(G.STATE_PATH)
    except FileNotFoundError:
        pass
    return G._load_state()


def _log_tail_since(offset):
    with open(G.LOG_PATH, "r", errors="replace") as fh:
        fh.seek(offset)
        return fh.read()


def _log_size():
    try:
        return os.path.getsize(G.LOG_PATH)
    except FileNotFoundError:
        return 0


# --------------------------------------------------------------------------
# 0. THE HARNESS'S OWN PRECONDITION. A control has to prove its own premise before
#    anything it reports can be trusted -- and this exact premise silently failed
#    once already (see the legacy-state note at the top of this file).
# --------------------------------------------------------------------------

def test_fresh_state_precondition():
    print("\n[precondition: a fresh state must genuinely start NOT-applied]")
    st = fresh_state()
    check("fresh state is not applied", st.get("applied"), False)
    check("fresh state has no baseline", st.get("saved_upstreams"), None)
    check("legacy fallback cannot contaminate it",
          os.path.exists(G._LEGACY_STATE_PATH), False)


# --------------------------------------------------------------------------
# 1. THE MUTATION PROOF -- this is the test that fails against the broken code.
# --------------------------------------------------------------------------

def test_null_verdict_is_rechecked_next_cycle():
    print("\n[THE LATCH: an empty verdict must not freeze discovery for the session]")
    d = Scripted([], list(TUN_DNS))
    v = Scripted(True, True, True, True)
    ph = FakePihole(PRE_VPN)
    state = fresh_state()

    with patched(d, v):
        ok1 = G.apply_fix(ph, TUNNEL, state)
        # SNAPSHOT BEFORE CYCLE 2. `state` is mutated in place and set_calls
        # accumulates, so a cycle-1 assertion read after cycle 2 describes the end of
        # the sequence, not the step it names. Read that way the fixed code reports
        # cycle 1 as having applied ['10.96.0.1'] -- which is cycle 2's work, and looks
        # exactly like a real defect.
        after_1 = dict(state)
        writes_1 = list(ph.set_calls)
        calls_1 = len(d.calls)
        ok2 = G.apply_fix(ph, TUNNEL, state)

    check("cycle 1 returns True (public upstream still resolves)", ok1, True)
    check("cycle 1 ran discovery once", calls_1, 1)
    check("cycle 1 leaves Pi-hole untouched", writes_1, [])
    check("cycle 1 does NOT claim a fix is applied", after_1.get("applied"), False)
    check("cycle 1 records the absent-DNS marker",
          after_1.get("tunnel_dns_absent"), True)
    check("cycle 2 RE-RUNS discovery  <-- THE LATCH", len(d.calls), 2)
    check("cycle 2 applies the now-visible resolver", ph.upstreams, TUN_DNS)
    check("cycle 2 marks applied", state.get("applied"), True)
    check("cycle 2 clears the absent-DNS marker",
          state.get("tunnel_dns_absent"), False)
    check("cycle 2 returns True", ok2, True)


# --------------------------------------------------------------------------
# 2. The legitimate early return must SURVIVE. Fixing the latch by deleting the
#    re-verify short-circuit would trade one defect for a rediscovery every cycle.
# --------------------------------------------------------------------------

def test_genuine_applied_fix_still_short_circuits():
    print("\n[the real applied-fix early return must stay]")
    d = Scripted(list(TUN_DNS))
    v = Scripted(True, True, True)
    ph = FakePihole(PRE_VPN)
    state = fresh_state()

    with patched(d, v):
        G.apply_fix(ph, TUNNEL, state)
        G.apply_fix(ph, TUNNEL, state)

    check("discovery ran exactly once across two cycles", len(d.calls), 1)
    check("Pi-hole written exactly once", len(ph.set_calls), 1)
    check("still applied", state.get("applied"), True)


# --------------------------------------------------------------------------
# 3. A genuine applied fix that STOPS resolving must still fall through.
# --------------------------------------------------------------------------

def test_failed_reverify_still_reapplies():
    print("\n[applied + no longer resolving -> rediscover and re-apply]")
    d = Scripted(list(TUN_DNS), list(TUN_DNS))
    v = Scripted(True, False, True)   # apply-verify, re-verify FAILS, re-apply-verify
    ph = FakePihole(PRE_VPN)
    state = fresh_state()

    with patched(d, v):
        G.apply_fix(ph, TUNNEL, state)
        G.apply_fix(ph, TUNNEL, state)

    check("failed re-verify falls through to discovery", len(d.calls), 2)
    check("still applied after the re-apply", state.get("applied"), True)


# --------------------------------------------------------------------------
# 4. Tunnel-down after a null-verdict session must not leave state behind.
# --------------------------------------------------------------------------

def test_restore_clears_the_null_verdict_state():
    print("\n[tunnel down after a null verdict: clear the marker AND the baseline]")
    d = Scripted([])
    v = Scripted(True, True, True)
    ph = FakePihole(PRE_VPN)
    state = fresh_state()

    with patched(d, v):
        G.apply_fix(ph, TUNNEL, state)
        writes_before_restore = len(ph.set_calls)
        ok = G.restore(ph, state)

    check("restore returns True", ok, True)
    check("restore does NOT write to Pi-hole (nothing was applied)",
          len(ph.set_calls), writes_before_restore)
    check("absent-DNS marker cleared", state.get("tunnel_dns_absent"), False)
    check("stale baseline cleared", state.get("saved_upstreams"), None)
    check("tunnel_iface cleared", state.get("tunnel_iface"), None)
    on_disk = G._load_state()
    check("cleared state PERSISTED", on_disk.get("tunnel_dns_absent"), False)


# --------------------------------------------------------------------------
# 5. The null path still captures and persists the genuine pre-VPN baseline.
# --------------------------------------------------------------------------

def test_null_verdict_persists_the_baseline():
    print("\n[a null verdict still records a real pre-VPN baseline, durably]")
    d = Scripted([])
    v = Scripted(True, True)
    ph = FakePihole(PRE_VPN)
    state = fresh_state()

    with patched(d, v):
        G.apply_fix(ph, TUNNEL, state)

    on_disk = G._load_state()
    check("baseline captured", state.get("saved_upstreams"), PRE_VPN)
    check("baseline persisted to disk", on_disk.get("saved_upstreams"), PRE_VPN)
    check("disk does NOT claim applied", on_disk.get("applied"), False)


# --------------------------------------------------------------------------
# 6. The ordinary apply -> restore round trip is unchanged.
# --------------------------------------------------------------------------

def test_normal_apply_restore_round_trip():
    print("\n[regression: a real apply still restores the pre-VPN upstreams]")
    d = Scripted(list(TUN_DNS))
    v = Scripted(True, True, True, True)
    ph = FakePihole(PRE_VPN)
    state = fresh_state()

    with patched(d, v):
        G.apply_fix(ph, TUNNEL, state)
        G.restore(ph, state)

    check("Pi-hole back on the pre-VPN upstreams", ph.upstreams, PRE_VPN)
    check("applied cleared", state.get("applied"), False)
    check("absent marker cleared", state.get("tunnel_dns_absent"), False)


# --------------------------------------------------------------------------
# 7. The empty->found transition is LOGGED. This is the observability that makes
#    the still-open "why was discovery empty at +12s" question answerable at all:
#    with re-checking in place, the log now shows exactly when the resolver appears.
# --------------------------------------------------------------------------

def test_empty_to_found_transition_is_logged():
    print("\n[the empty->found transition must be visible in the log]")
    d = Scripted([], list(TUN_DNS))
    v = Scripted(True, True, True, True)
    ph = FakePihole(PRE_VPN)
    state = fresh_state()

    offset = _log_size()
    with patched(d, v):
        G.apply_fix(ph, TUNNEL, state)
        G.apply_fix(ph, TUNNEL, state)
    tail = _log_tail_since(offset)

    # POSITIVE CONTROL FIRST. "the line is present" asserted against an empty capture
    # is vacuously true of a broken log handler, so prove the capture received
    # anything at all before trusting what it says about one specific line.
    check("control: the log capture received output", len(tail.strip()) > 0, True)
    check("transition logged exactly once",
          tail.count("tunnel DNS now discoverable"), 1)


if __name__ == "__main__":
    print("=" * 78)
    print("apply_fix latch — a null tunnel-DNS verdict must be re-checked")
    print("=" * 78)
    test_fresh_state_precondition()
    test_null_verdict_is_rechecked_next_cycle()
    test_genuine_applied_fix_still_short_circuits()
    test_failed_reverify_still_reapplies()
    test_restore_clears_the_null_verdict_state()
    test_null_verdict_persists_the_baseline()
    test_normal_apply_restore_round_trip()
    test_empty_to_found_transition_is_logged()
    print()
    # The assertion COUNT is fixed on purpose. A suite that silently runs fewer checks
    # under failure reports as a smaller suite rather than a failing one -- the
    # run-to-run comparison hazard this repo has already been bitten by.
    if _count != EXPECTED_CHECKS:
        print("SUITE DRIFT: ran %d checks, expected %d" % (_count, EXPECTED_CHECKS))
        sys.exit(1)
    if _fail:
        print("FAILED (%d of %d)" % (len(_fail), _count))
        for f in _fail:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS (%d checks)" % _count)
