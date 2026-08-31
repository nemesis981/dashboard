"""Topology by measured routing OUTCOME. Pure tests, no root, no network.

WHY THIS FILE EXISTS. `classify_topology()` decided topology from which interface held a
route literally named `default`. A VPN using a `0.0.0.0/1` + `128.0.0.0/1` straddle
leaves the physical `default` in place, so FULL_TUNNEL was unreachable and the operator's
"full-tunnel -> decline" ruling could never fire. Measured live 2026-08-31 against a
connected full-tunnel VPN: the decision came out INSTALL while every internet destination
resolved to the tunnel.

Operator ruling (decisions/2026-08-31-forkb-topology-by-routing-outcome-RESOLVED.md):
classify by routing outcome, determine it empirically via `ip route get`, and DECLINE
when coverage cannot be computed confidently.

The first test is the regression: the exact straddle shape must now read FULL_TUNNEL.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forkb_policy_route as F

K = F._K
_fail = []
_count = 0
EXPECTED_CHECKS = 31

TUN = {"tun0": "tun", "eth0": ""}


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-68s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def _all_to(iface, dests=None):
    return {d: iface for d in (dests or F.PROBE_DESTINATIONS)}


def test_the_straddle_regression():
    print("\n[REGRESSION: a /1-straddle full tunnel must now read full_tunnel]")
    res = _all_to("tun0")
    topo, reason = F.classify_by_resolution(res, TUN, K)
    check("classified full_tunnel", topo, F.FULL_TUNNEL)
    check("the reason names the tunnel interface", "tun0" in reason, True)
    decision, egress, msg = F.decide(topo, F.resolved_egress(res, TUN, K), reason)
    check("and the DECISION is decline", decision, F.DECLINE)
    check("no egress is pinned", egress, None)
    check("the message explains the posture reason",
          "security-posture" in msg, True)
    # The old classifier on the same box: physical default still present -> not full.
    old, _ = F.classify_topology(["eth0", "tun0"], TUN, K)
    check("...and the superseded classifier still disagrees (documents the bug)",
          old == F.FULL_TUNNEL, False)


def test_no_vpn_and_split():
    print("\n[the other two topologies]")
    res = _all_to("eth0")
    check("all-direct -> no_vpn", F.classify_by_resolution(res, TUN, K)[0], F.NO_VPN)
    check("...and it installs", F.decide(F.NO_VPN, F.resolved_egress(res, TUN, K))[0],
          F.INSTALL)
    mixed = _all_to("eth0")
    mixed["1.0.0.1"] = "tun0"
    check("genuinely mixed -> split_tunnel",
          F.classify_by_resolution(mixed, TUN, K)[0], F.SPLIT_TUNNEL)
    check("...and it installs to the non-tunnel egress",
          F.decide(F.SPLIT_TUNNEL, F.resolved_egress(mixed, TUN, K))[1], "eth0")


def test_low_confidence_declines():
    print("\n[Q3: low confidence DECLINES rather than guessing]")
    for label, res in (
        ("no probes at all", {}),
        ("a probe that did not resolve", {"1.0.0.1": None, "129.0.0.1": "eth0"}),
        ("too few probes", {"1.0.0.1": "eth0", "129.0.0.1": "eth0"}),
    ):
        topo = F.classify_by_resolution(res, TUN, K, min_probes=4)[0]
        check(label + " -> undetermined", topo, F.UNDETERMINED)
        check("...which decides DECLINE", F.decide(topo, "eth0")[0], F.DECLINE)


def test_premise_checks():
    print("\n[the classifier proves its own premise before answering]")
    # A LAN destination resolves to the physical NIC even under a full tunnel, so
    # probing one would manufacture a split verdict out of nothing.
    bad = _all_to("eth0")
    bad["192.168.1.1"] = "eth0"
    check("a private probe destination is refused",
          F.classify_by_resolution(bad, TUN, K)[0], F.UNDETERMINED)
    tailnet = _all_to("eth0")
    tailnet["100.64.0.1"] = "tailscale0"
    check("our OWN tailnet range is refused too",
          F.classify_by_resolution(tailnet, TUN, K)[0], F.UNDETERMINED)
    one_side = {d: "eth0" for d in ("1.0.0.1", "32.0.0.1", "64.0.0.1", "96.0.0.1")}
    check("a one-sided probe set cannot see a straddle -> refused",
          F.classify_by_resolution(one_side, TUN, K)[0], F.UNDETERMINED)
    check("the shipped probe set DOES cover both halves",
          len({F._probe_half(d) for d in F.PROBE_DESTINATIONS}), 2)
    check("...and every shipped probe is globally routable",
          all(F._is_public_probe(d) for d in F.PROBE_DESTINATIONS), True)


def test_resolved_egress_refuses_to_guess():
    print("\n[a disagreeing egress is None, never a pick]")
    check("unanimous -> that interface",
          F.resolved_egress(_all_to("eth0"), TUN, K), "eth0")
    check("disagreeing -> None",
          F.resolved_egress({"1.0.0.1": "eth0", "129.0.0.1": "eth1"},
                            {"eth0": "", "eth1": ""}, K), None)
    check("...and None makes decide() decline",
          F.decide(F.NO_VPN, None)[0], F.DECLINE)


def test_provider_agnostic():
    print("\n[operator ruling: never provider-specific]")
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "forkb_policy_route.py"), encoding="utf-8").read()
    # Split the module docstring off: prose may discuss history, code may not name a
    # vendor. The check that matters is on executable code.
    code = src.split('"""', 2)[2]
    for vendor in ("piavpn", "pia_", "nordvpn", "expressvpn", "mullvad"):
        check("no %r in executable code" % vendor, vendor in code.lower(), False)


def test_canary_count_cannot_drift():
    print("\n[the selftest's advertised canary count is checked against the source]")
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "forkb_policy_route.py"), encoding="utf-8").read()
    actual = len(re.findall(r'return False, "canary', src))
    check("_CANARY_COUNT matches the real number of canaries", F._CANARY_COUNT, actual)
    check("and selftest reports it", "%d canaries" % actual in F.selftest()[1], True)


if __name__ == "__main__":
    print("Fork B topology by measured routing outcome")
    test_the_straddle_regression()
    test_no_vpn_and_split()
    test_low_confidence_declines()
    test_premise_checks()
    test_resolved_egress_refuses_to_guess()
    test_provider_agnostic()
    test_canary_count_cannot_drift()
    print()
    if _count != EXPECTED_CHECKS:
        print("SUITE DRIFT: ran %d checks, expected %d" % (_count, EXPECTED_CHECKS))
        sys.exit(1)
    if _fail:
        print("FAILED (%d of %d)" % (len(_fail), _count))
        for f in _fail:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS (%d checks)" % _count)
