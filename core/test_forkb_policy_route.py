"""Fork B policy-route bypass — pure tests. No root, no network, no VPN, no imports of
vpn_dns_guard (tunnel kinds are injected, so nothing writes a log file).

The load-bearing cases are the REFUSALS and the LOSING case. A bypass that installs is
easy; one that correctly declines where no bypass can exist, and one that notices it has
been out-prioritised, are the two behaviours that would silently route inspected traffic
through a user's VPN if they regressed.

Every suppression also proves its DERIVATION -- the same input with the deciding property
changed must flip the outcome -- so a case cannot pass because some earlier branch caught
it.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import forkb_policy_route as F

_fail = []
_count = 0
EXPECTED_CHECKS = 46

K = {"tun", "tap", "wireguard", "vti", "vti6", "ppp", "gre", "ip6tnl"}


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-68s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def topo(ifaces, kinds):
    return F.classify_topology(ifaces, kinds, K)[0]


# ── the bug this file exists to keep fixed ───────────────────────────────────
def test_empty_kind_is_physical_not_unknown():
    print("\n[REGRESSION: an empty link kind means PHYSICAL, not unreadable]")
    # A plain ethernet NIC has no linkinfo.info_kind, so _iface_kind() returns ''.
    # An earlier version treated that as suspicious and disabled Fork B for every
    # user with no VPN at all.
    check("a wired box with no VPN is no_vpn, NOT undetermined",
          topo(["eth0"], {"eth0": ""}), F.NO_VPN)
    check("...and a differently-named NIC too (no name heuristics)",
          topo(["enp0s31f6"], {"enp0s31f6": ""}), F.NO_VPN)
    check("CONTROL: the same iface WITH a tunnel kind is full_tunnel",
          topo(["eth0"], {"eth0": "wireguard"}), F.FULL_TUNNEL)


def test_topologies():
    print("\n[the four topologies, keyed on KIND not name]")
    check("physical only -> no_vpn", topo(["eth0"], {"eth0": ""}), F.NO_VPN)
    check("physical + wireguard -> split_tunnel",
          topo(["eth0", "wg0"], {"eth0": "", "wg0": "wireguard"}), F.SPLIT_TUNNEL)
    check("physical + tun -> split_tunnel",
          topo(["eth0", "tun0"], {"eth0": "", "tun0": "tun"}), F.SPLIT_TUNNEL)
    check("wireguard only -> full_tunnel (AllowedIPs=0.0.0.0/0)",
          topo(["wg0"], {"wg0": "wireguard"}), F.FULL_TUNNEL)
    check("tun only -> full_tunnel (OpenVPN redirect-gateway)",
          topo(["tun0"], {"tun0": "tun"}), F.FULL_TUNNEL)
    check("ppp only -> full_tunnel", topo(["ppp0"], {"ppp0": "ppp"}), F.FULL_TUNNEL)
    check("two tunnels, no physical -> full_tunnel",
          topo(["wg0", "tun0"], {"wg0": "wireguard", "tun0": "tun"}), F.FULL_TUNNEL)


def test_vendor_name_independence():
    print("\n[vendor builds use arbitrary device NAMES -- kind must decide]")
    check("a tunnel named like a NIC is still full_tunnel",
          topo(["eth42"], {"eth42": "wireguard"}), F.FULL_TUNNEL)
    check("a NIC named like a tunnel is still a valid egress",
          topo(["tun9"], {"tun9": ""}), F.NO_VPN)
    check("CONTROL: flipping ONLY the kind flips the verdict",
          topo(["tun9"], {"tun9": "tun"}), F.FULL_TUNNEL)


def test_fail_closed():
    print("\n[an unreadable premise must never read as 'fine']")
    check("no default route -> undetermined", topo([], {}), F.UNDETERMINED)
    check("None -> undetermined", topo(None, {}), F.UNDETERMINED)
    check("empty strings are not interfaces", topo(["", ""], {}), F.UNDETERMINED)
    check("undetermined DECLINES", F.decide(F.UNDETERMINED, "eth0")[0], F.DECLINE)
    check("...even when an egress was supplied (topology decides, not the egress)",
          F.decide(F.UNDETERMINED, "eth0")[0], F.DECLINE)


def test_hybrid_ruling():
    print("\n[the operator's hybrid ruling: (b) split-tunnel, (c) full-tunnel]")
    d, egress, msg = F.decide(F.SPLIT_TUNNEL, "eth0", "r")
    check("split_tunnel -> INSTALL", d, F.INSTALL)
    check("...pinned to the resolved egress", egress, "eth0")
    check("...and says which", "eth0" in msg, True)

    d, egress, msg = F.decide(F.FULL_TUNNEL, None, "every candidate is a tunnel")
    check("full_tunnel -> DECLINE", d, F.DECLINE)
    check("...with no egress", egress, None)
    check("...and explains WHY, in user-facing terms", "full-tunnel VPN" in msg, True)
    check("...naming the posture reason, not just a failure",
          "security-posture" in msg, True)

    check("CONTROL: an egress argument does NOT override the refusal",
          F.decide(F.FULL_TUNNEL, "eth0", "r")[0], F.DECLINE)
    check("no_vpn -> INSTALL (bypass is inert but valid)",
          F.decide(F.NO_VPN, "eth0", "r")[0], F.INSTALL)
    check("a missing egress declines even on a good topology",
          F.decide(F.SPLIT_TUNNEL, None, "r")[0], F.DECLINE)
    check("...and empty-string egress too", F.decide(F.SPLIT_TUNNEL, "", "r")[0], F.DECLINE)


def test_parse_route_get():
    print("\n[reading which egress the FULL rule chain actually selected]")
    check("simple form", F.parse_route_get("1.2.3.4 dev eth0 src 5.6.7.8"), "eth0")
    check("via form",
          F.parse_route_get("1.2.3.4 via 10.0.0.1 dev enp1s0 src 10.0.0.2 uid 0"), "enp1s0")
    check("multi-line takes the first device line",
          F.parse_route_get("1.2.3.4 dev wg0 src 10.0.0.2\n    cache"), "wg0")
    check("no device -> None (unparseable, NOT a default)",
          F.parse_route_get("1.2.3.4 unreachable"), None)
    check("empty -> None", F.parse_route_get(""), None)
    check("None -> None", F.parse_route_get(None), None)
    check("trailing 'dev' with no value -> None", F.parse_route_get("1.2.3.4 dev"), None)


def test_verify_winning():
    print("\n[THE load-bearing check: an installed rule is not a winning rule]")
    ok, d = F.verify_winning("1.2.3.4 dev eth0 src 5.6.7.8", "eth0")
    check("selected == expected -> winning", ok, True)

    ok, d = F.verify_winning("1.2.3.4 dev wg0 src 5.6.7.8", "eth0")
    check("pre-empted by another rule -> NOT winning", ok, False)
    check("...and says what took precedence", "wg0" in d, True)
    check("...and names it as a precedence problem", "precedence" in d, True)

    ok, d = F.verify_winning("garbage", "eth0")
    check("unparseable -> NOT winning (never assume agreement)", ok, False)
    check("...and says so", "refusing to assume" in d, True)

    ok, d = F.verify_winning("1.2.3.4 dev eth0", "")
    check("no expected egress -> NOT winning", ok, False)
    check("empty output -> NOT winning", F.verify_winning("", "eth0")[0], False)


def test_selftest():
    print("\n[the instrument proves it produces every answer it claims]")
    ok, detail = F.selftest()
    check("selftest passes", ok, True)
    check("selftest counts its canaries", "canaries passed" in detail, True)


if __name__ == "__main__":
    print("Fork B policy-route bypass -- pure core")
    test_empty_kind_is_physical_not_unknown()
    test_topologies()
    test_vendor_name_independence()
    test_fail_closed()
    test_hybrid_ruling()
    test_parse_route_get()
    test_verify_winning()
    test_selftest()
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
