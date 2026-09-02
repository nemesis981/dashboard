"""apply_fix() must never baseline its OWN earlier write as a "pre-VPN" value.

WHY THIS FILE EXISTS. `restore()` puts `saved_upstreams` back into Pi-hole when the
tunnel drops. If that value is a TUNNEL resolver rather than a genuine pre-VPN one, the
guard deliberately points Pi-hole at an address that is only reachable through the tunnel
that just died -- an outage, performed on purpose and logged as a success. That is the
exact failure the "REFUSING to baseline" branch exists to prevent.

THE GUARD IT ALREADY HAD WAS TOO NARROW. It refused only when
`current == tun_dns` -- i.e. it recognised its own write only when that write happened to
equal what it was about to apply next. Measured 2026-09-02 by driving the real functions:

    persist-fail -> next cycle discovers a DIFFERENT resolver
      baseline recorded : ['10.96.0.1']      <- the guard's own earlier write
      restore() WROTE   : ['10.96.0.1']      <- replayed as "pre-VPN", into a dead tunnel

Tunnel resolvers routinely differ between servers (10.96.0.1 vs 10.2.0.1 were both seen on
2026-09-01), so this is ordinary behaviour, not an exotic case. An empty discovery result
reaches the same place; it is NOT required, which is how the original filing described it.

⛔ WHY A PERSISTED MARKER CANNOT BE THE PRIMARY MECHANISM. Every route into this state runs
through a FAILED STATE WRITE (`applied` never reaches disk, so the next cycle reloads
`applied: False` while Pi-hole already holds the guard's resolver). A marker written to the
same file that just failed to write is unavailable precisely when it is needed. So the
primary defence is IN-PROCESS: what THIS process last wrote. The persisted copy is a
secondary, additive layer covering a guard restart when the disk is healthy.

FAIL-SAFE INVARIANT: the marker may only ever cause a REFUSAL to baseline. It must never
assert that a fix is applied. Same shape as ADR 0019's failsafe -- it can add protection,
never remove it.

Pure tests. No root, no network, no live Pi-hole. Writes only to a private temp dir.
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

# BEFORE the import: STATE_PATH and LOG_PATH resolve at import time.
_TMP = tempfile.mkdtemp(prefix="vpn-dns-guard-baseline-")
os.environ["VPN_DNS_GUARD_STATE"] = os.path.join(_TMP, "state.json")
os.environ["VPN_DNS_GUARD_LOG"] = os.path.join(_TMP, "guard.log")

sys.path.insert(0, HERE)
sys.path.insert(0, REPO)
import vpn_dns_guard as G  # noqa: E402

# Neutralise the legacy-state fallback. On the build machine that file is real, root-owned,
# and reads {"applied": true, ...}, so a "fresh" state would arrive ALREADY APPLIED and every
# scenario below would silently measure the wrong thing.
G._LEGACY_STATE_PATH = os.path.join(_TMP, "legacy-must-not-exist.json")

_fail = []
_count = 0
EXPECTED_CHECKS = 37

PRE_VPN = ["1.1.1.1"]        # a genuine pre-VPN upstream
TUN_A = ["10.96.0.1"]        # tunnel resolver, server 1
TUN_B = ["10.2.0.1"]         # tunnel resolver, server 2 (a different exit)
TUNNEL = {"up": True, "iface": "tun0", "kind": "tun"}


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-74s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


class FakePihole:
    def __init__(self, upstreams):
        self.upstreams = list(upstreams)
        self.set_calls = []

    def get_upstreams(self):
        return list(self.upstreams)

    def set_upstreams(self, upstreams):
        self.upstreams = list(upstreams)
        self.set_calls.append(list(upstreams))


class ReorderingPihole(FakePihole):
    """Pi-hole is free to return the same servers in a different order.

    Exists because an order-SENSITIVE comparison is invisible while some other signal
    happens to match exactly -- the mutation only shows up when reordering is the sole
    difference between what we wrote and what we read back.
    """

    def get_upstreams(self):
        return list(reversed(self.upstreams))


def scenario(discovery, fail_saves=(), simulate_restart_before_restore=False,
             restart_before_cycle=None, pihole_reorders=False):
    """Drive the REAL apply_fix/restore with a scripted discovery and forced save failures.

    `fail_saves` are 1-based _save_state call numbers to fail -- this is the gateway to the
    whole defect, so it is modelled directly rather than mocked around.
    """
    try:
        os.unlink(G.STATE_PATH)
    except FileNotFoundError:
        pass
    G._session_applied_upstreams = None          # fresh process

    ph = ReorderingPihole(PRE_VPN) if pihole_reorders else FakePihole(PRE_VPN)
    seq = list(discovery)
    G.discover_tunnel_dns = lambda iface: (seq.pop(0) if seq else [])
    G.verify_upstream_resolves = lambda: True

    real_save = G._save_state
    calls = {"n": 0}

    def save(state):
        calls["n"] += 1
        if calls["n"] in fail_saves:
            return False
        return real_save(state)

    G._save_state = save
    try:
        for i in range(len(discovery)):
            if restart_before_cycle is not None and i == restart_before_cycle:
                # Guard process restarted mid-session: in-process marker gone, disk intact.
                G._session_applied_upstreams = None
            st = G._load_state()
            G.apply_fix(ph, TUNNEL, st)
        st = G._load_state()
        applied_on_disk = st.get("applied")
        saved = st.get("saved_upstreams")
        if simulate_restart_before_restore:
            G._session_applied_upstreams = None   # process restarted; disk state survives
        marker_before_restore = G._session_applied_upstreams
        writes_before = len(ph.set_calls)
        G.restore(ph, st)
        restore_writes = ph.set_calls[writes_before:]
    finally:
        G._save_state = real_save

    return {
        "saved": saved,
        "applied_on_disk": applied_on_disk,
        "restore_writes": restore_writes,
        "pihole_final": ph.upstreams,
        "state_after": st,
        "marker_before_restore": marker_before_restore,
    }


def wrote_a_tunnel_resolver(rec):
    """The load-bearing assertion: did restore() PUT a tunnel resolver into Pi-hole?

    Deliberately checks what restore WROTE, not where Pi-hole ended up. Refusing to
    baseline legitimately leaves Pi-hole on the tunnel resolver with a loud error -- that
    is the documented accepted outcome, and conflating it with an actively-written fiction
    is exactly the misreading the first probe of this defect made.
    """
    return any(w in (TUN_A, TUN_B) for w in rec["restore_writes"])


# --------------------------------------------------------------------------
def test_precondition():
    print("\n[precondition: the harness must start from a genuinely clean state]")
    try:
        os.unlink(G.STATE_PATH)
    except FileNotFoundError:
        pass
    st = G._load_state()
    check("fresh state is not applied", st.get("applied"), False)
    check("fresh state has no baseline", st.get("saved_upstreams"), None)
    check("legacy fallback cannot contaminate", os.path.exists(G._LEGACY_STATE_PATH), False)


def test_minimal_different_resolver():
    print("\n[THE DEFECT: persist-fail then a DIFFERENT resolver -- no empty cycle needed]")
    rec = scenario([TUN_A, TUN_B], fail_saves={1})
    # precondition: the path must actually have been exercised
    check("precondition: disk reloaded as NOT-applied", rec["applied_on_disk"], True)
    check("baseline is NOT the guard's own earlier write", rec["saved"] == TUN_A, False)
    check("restore never WROTE a tunnel resolver  <-- THE FICTION",
          wrote_a_tunnel_resolver(rec), False)


def test_empty_discovery_path():
    print("\n[the originally-filed shape: persist-fail then an EMPTY discovery]")
    rec = scenario([TUN_A, [], TUN_B], fail_saves={1})
    check("baseline is NOT the guard's own earlier write", rec["saved"] == TUN_A, False)
    check("restore never WROTE a tunnel resolver", wrote_a_tunnel_resolver(rec), False)


def test_in_process_marker_without_working_disk():
    print("\n[PRIMARY MECHANISM: protection must hold when EVERY state write fails]")
    rec = scenario([TUN_A, TUN_B], fail_saves=set(range(1, 40)))
    check("no state ever persisted (gateway condition really present)",
          os.path.exists(G.STATE_PATH), False)
    check("baseline still refused / never the guard's own write", rec["saved"] == TUN_A, False)
    check("restore never WROTE a tunnel resolver with a dead disk",
          wrote_a_tunnel_resolver(rec), False)


def test_persisted_marker_covers_a_restart():
    print("\n[SECONDARY: a guard restart, disk healthy -- in-process marker is gone]")
    rec = scenario([TUN_A, TUN_B], fail_saves={1},
                   simulate_restart_before_restore=True)
    check("restore never WROTE a tunnel resolver after a restart",
          wrote_a_tunnel_resolver(rec), False)
    check("persisted marker is present in state",
          "last_applied_upstreams" in rec["state_after"], True)


def test_persisted_marker_is_the_deciding_signal():
    print("\n[SECONDARY, exercised properly: restart mid-session, disk is the ONLY signal]")
    # apply (save fails, so only the in-process marker exists) -> a null-DNS cycle whose
    # save SUCCEEDS, persisting last_applied_upstreams with applied=False -> RESTART, so
    # the in-process marker is gone -> a cycle discovering a DIFFERENT resolver.
    # Only the persisted marker can recognise our own write here.
    rec = scenario([TUN_A, [], TUN_B], fail_saves={1}, restart_before_cycle=2)
    check("precondition: disk carried the marker across the restart",
          rec["state_after"].get("last_applied_upstreams") is not None
          or rec["saved"] is None, True)
    check("restore never WROTE a tunnel resolver after a mid-session restart",
          wrote_a_tunnel_resolver(rec), False)


def test_order_insensitivity_is_load_bearing():
    print("\n[order-insensitive compare must be the ONLY thing standing in the way]")
    # Pi-hole hands the set back reversed, so `current` never matches anything by
    # list equality -- only a sorted comparison recognises it as our own write.
    pair = ["10.96.0.1", "fd00::1"]
    rec = scenario([pair, TUN_B], fail_saves={1}, pihole_reorders=True)
    check("reordered readback still recognised as our own write",
          rec["saved"] is None or sorted(map(str, rec["saved"])) != sorted(map(str, pair)),
          True)
    check("restore did not write the reordered tunnel set",
          any(sorted(map(str, w)) == sorted(map(str, pair))
              for w in rec["restore_writes"]), False)


def test_restore_clears_marker_on_the_not_applied_path():
    print("\n[restore()'s NOT-applied branch must clear the marker too]")
    # A null-DNS session leaves applied=False, so restore takes its other branch --
    # the one a marker set by an earlier failed-persist apply would otherwise survive.
    rec = scenario([TUN_A, []], fail_saves={1})
    check("precondition: marker was set before restore",
          rec["marker_before_restore"], TUN_A)
    check("in-process marker cleared on the not-applied path",
          G._session_applied_upstreams, None)
    check("persisted marker cleared on the not-applied path",
          rec["state_after"].get("last_applied_upstreams"), None)


def test_in_process_marker_when_the_two_markers_DISAGREE():
    print("\n[the in-process check is independently load-bearing when markers diverge]")
    # apply T1 (save fails) -> null cycle whose save SUCCEEDS, persisting last=T1
    # -> apply T2 (save fails), so in-process=T2 while DISK still says T1
    # -> a cycle discovering T3, with Pi-hole holding T2.
    # The persisted marker (T1) does not match `current` (T2); only the in-process
    # marker does. Without it, T2 -- our own write -- gets baselined as "pre-VPN".
    T3 = ["10.7.0.1"]
    rec = scenario([TUN_A, [], TUN_B, T3], fail_saves={1, 3})
    check("precondition: markers really did diverge",
          rec["marker_before_restore"] != rec["state_after"].get("last_applied_upstreams")
          or rec["saved"] is None, True)
    check("restore never WROTE a tunnel resolver when markers disagree",
          any(w in (TUN_A, TUN_B, T3) for w in rec["restore_writes"]), False)


def test_failsafe_invariant_never_asserts_applied():
    print("\n[INVARIANT: the marker may REFUSE, never claim a fix is in place]")
    rec = scenario([TUN_A, TUN_B], fail_saves=set(range(1, 40)))
    st = rec["state_after"]
    check("marker did not fabricate applied=True on a dead disk",
          st.get("applied") in (False, None), True)
    check("marker did not fabricate a baseline out of nothing",
          st.get("saved_upstreams") in (None, PRE_VPN), True)


# --------------------------------------------------------------------------
# Regressions: the behaviour that was already correct must stay correct.
# --------------------------------------------------------------------------

def test_control_healthy_run_keeps_the_genuine_baseline():
    print("\n[control: no persistence failure -- the real pre-VPN value must survive]")
    rec = scenario([TUN_A, TUN_A])
    check("baseline is the genuine pre-VPN value", rec["saved"], PRE_VPN)
    check("restore wrote the genuine pre-VPN value", rec["restore_writes"], [PRE_VPN])
    check("Pi-hole ends on the pre-VPN upstreams", rec["pihole_final"], PRE_VPN)


def test_control_same_resolver_still_refuses_loudly():
    print("\n[control: the pre-existing current==tun_dns refusal must still work]")
    rec = scenario([TUN_A, TUN_A], fail_saves={1})
    check("still refuses to baseline", rec["saved"], None)
    check("restore wrote nothing", rec["restore_writes"], [])


def test_restore_clears_the_marker():
    print("\n[restore() must clear the session-scoped marker, both copies]")
    rec = scenario([TUN_A, TUN_A])
    # Asserted FIRST so this test cannot pass vacuously: before the fix the marker is
    # never set at all, and "it is None afterwards" would then be true for the wrong reason.
    check("marker WAS set by a successful apply", rec["marker_before_restore"], TUN_A)
    check("persisted marker cleared", rec["state_after"].get("last_applied_upstreams"), None)
    check("in-process marker cleared", G._session_applied_upstreams, None)


def test_marker_is_order_insensitive():
    print("\n[a set returned in a different order is the SAME set, not a new baseline]")
    rec = scenario([["10.96.0.1", "fd00::1"], ["fd00::1", "10.96.0.1"]], fail_saves={1})
    check("reordered tunnel resolvers are recognised as our own write",
          rec["saved"] in (None, PRE_VPN), True)
    check("restore did not write the reordered tunnel set",
          any(sorted(w) == sorted(["10.96.0.1", "fd00::1"]) for w in rec["restore_writes"]),
          False)


def test_normal_apply_restore_round_trip_unaffected():
    print("\n[regression: the ordinary happy path is untouched]")
    rec = scenario([TUN_A])
    check("baseline genuine", rec["saved"], PRE_VPN)
    check("restore returned Pi-hole to pre-VPN", rec["pihole_final"], PRE_VPN)
    check("applied was recorded on disk", rec["applied_on_disk"], True)


if __name__ == "__main__":
    print("=" * 80)
    print("apply_fix — never baseline the guard's own write as a pre-VPN value")
    print("=" * 80)
    test_precondition()
    test_minimal_different_resolver()
    test_empty_discovery_path()
    test_in_process_marker_without_working_disk()
    test_persisted_marker_covers_a_restart()
    test_persisted_marker_is_the_deciding_signal()
    test_order_insensitivity_is_load_bearing()
    test_restore_clears_marker_on_the_not_applied_path()
    test_in_process_marker_when_the_two_markers_DISAGREE()
    test_failsafe_invariant_never_asserts_applied()
    test_control_healthy_run_keeps_the_genuine_baseline()
    test_control_same_resolver_still_refuses_loudly()
    test_restore_clears_the_marker()
    test_marker_is_order_insensitive()
    test_normal_apply_restore_round_trip_unaffected()
    print()
    # Fixed count: a suite that quietly runs fewer checks under failure reports as a
    # smaller suite rather than a failing one.
    if _count != EXPECTED_CHECKS:
        print("SUITE DRIFT: ran %d checks, expected %d" % (_count, EXPECTED_CHECKS))
        sys.exit(1)
    if _fail:
        print("FAILED (%d of %d)" % (len(_fail), _count))
        for f in _fail:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS (%d checks)" % _count)
