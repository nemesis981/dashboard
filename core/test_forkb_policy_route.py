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
EXPECTED_CHECKS = 80

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


def test_parse_default_route():
    print("\n[reading the egress + gateway to point the bypass table at]")
    check("via form", F.parse_default_route("default via 10.0.0.1 dev eth0 proto static"),
          ("10.0.0.1", "eth0"))
    check("directly-connected default keeps the device, gateway None",
          F.parse_default_route("default dev ppp0 scope link"), (None, "ppp0"))
    check("picks the default line out of a full table",
          F.parse_default_route("10.0.0.0/24 dev eth0\ndefault via 10.0.0.1 dev eth0"),
          ("10.0.0.1", "eth0"))
    check("no default -> (None, None)", F.parse_default_route("10.0.0.0/24 dev eth0"),
          (None, None))
    check("empty -> (None, None)", F.parse_default_route(""), (None, None))
    check("None -> (None, None)", F.parse_default_route(None), (None, None))
    check("a device-less default is not usable", F.parse_default_route("default via 10.0.0.1"),
          (None, None))


def test_table_claim():
    print("\n[claiming a routing table ID is a convention, not a guarantee]")
    check("empty table is free", F.table_is_free(""), True)
    check("whitespace-only is free", F.table_is_free("   \n "), True)
    check("None is free", F.table_is_free(None), True)
    check("an OCCUPIED table is refused (do not append to a stranger's table)",
          F.table_is_free("default via 1.2.3.4 dev eth9"), False)


def test_plan_install():
    print("\n[install plan: idempotent by construction]")
    cmds = F.plan_install("eth0", "10.0.0.1", "tailscale0")
    check("three steps", len(cmds), 3)
    check("DELETE precedes add (ip rule add appends, it does not replace)",
          cmds[0][:3], ["ip", "rule", "del"])
    check("route uses `replace`, which is idempotent", cmds[1][2], "replace")
    check("route targets our table", cmds[1][-2:], ["table", "291"])
    check("rule selects on SOURCE, never a mark",
          "from" in cmds[2] and "fwmark" not in cmds[2], True)
    check("...our tunnel is the inbound selector", cmds[2][cmds[2].index("iif") + 1],
          "tailscale0")
    check("...and the source prefix is our tailnet", cmds[2][cmds[2].index("from") + 1],
          F.FORKB_SOURCE_PREFIX)
    check("pref is below PIA's observed 50", F.BYPASS_RULE_PREF < 50, True)
    check("...and above `local` at 0, which must never be displaced",
          F.BYPASS_RULE_PREF > 0, True)

    gwless = F.plan_install("ppp0", None, "tailscale0")
    check("a directly-connected egress plans without `via`", "via" in gwless[1], False)
    check("...and still names the device", gwless[1][-3], "ppp0")

    check("no egress -> no plan", F.plan_install("", "10.0.0.1", "tailscale0"), None)
    check("no inbound iface -> no plan", F.plan_install("eth0", "10.0.0.1", ""), None)
    check("neither -> no plan", F.plan_install(None, None, None), None)


def test_plan_teardown():
    print("\n[teardown order is load-bearing]")
    td = F.plan_teardown()
    check("rule removed FIRST", td[0][:3], ["ip", "rule", "del"])
    check("...then the table flushed", td[1][:3], ["ip", "route", "flush"])
    # A live rule pointing at an emptied table falls through to the next rule, which
    # silently reverts traffic to the VPN path -- the exact outcome this prevents.
    check("CONTROL: the order is not incidental -- table flush is second",
          td[1][-1], "291")


def test_verify_installed():
    print("\n[PRESENT is not WINNING -- this checks only presence]")
    rules = "30:\tfrom 100.64.0.0/10 iif tailscale0 lookup 291"
    ok, d = F.verify_installed(rules, "default via 10.0.0.1 dev eth0")
    check("fully installed -> ok", ok, True)
    check("no rule -> not installed", F.verify_installed("", "default via x dev y")[0], False)
    ok, d = F.verify_installed(rules, "")
    check("rule pointing at an EMPTY table -> not installed", ok, False)
    check("...and says why it matters", "falls through" in d, True)
    ok, d = F.verify_installed(rules, "10.0.0.0/24 dev eth0")
    check("table without a default route -> not installed", ok, False)
    check("rule at the wrong table -> not installed",
          F.verify_installed("30:\tfrom 100.64.0.0/10 lookup 999", "default via x dev y")[0],
          False)


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
    test_parse_default_route()
    test_table_claim()
    test_plan_install()
    test_plan_teardown()
    test_verify_installed()
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
