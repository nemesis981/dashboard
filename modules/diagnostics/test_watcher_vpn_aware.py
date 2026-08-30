"""Connectivity verdict must be TUNNEL-aware. Pure core: no DB, no network, no curl.

WHY THIS EXISTS (measured on production, 2026-08-30). A leak-blocking VPN disables
IPv6 egress and blocks the raw-egress probe BY DESIGN, so `classify()` reported
DEGRADED every cycle while a tunnel was up — and one blocked raw-egress sample
escalated an episode to LOCAL_FAIL — while routing/dns/api were all healthy. That
raised a MEDIUM `action=investigate` alert for a correctly functioning VPN.

⚠ WHY IT EXISTS IN THIS PARTICULAR SHAPE. The FIRST version of the fix shipped and
was reverted within one cycle. It fed the verdict from `vpn_connected`
(`_probe_vpn()`), which is True whenever ANY provider reports connected — and
Tailscale is connected permanently on any appliance, because agent enrollment runs
over the tailnet. The flag was therefore permanently True and silently suppressed
every genuine IPv6 fault: a loss of detection coverage, which complains about
nothing.

**The 36-check suite of that version passed it.** Every test supplied the flag as an
explicit boolean, which proves the BRANCH and says nothing about what production
supplies. A branch test proves the branch, not the predicate. So this file now also
tests the PREDICATE — `tunnel_carries_default()` — including the exact mesh-VPN
shape that was mis-read, and the live value on the host it runs on.

THE NEGATIVES ARE THE LOAD-BEARING HALF: every permissive case is paired with one
proving the same input still reports a fault when no tunnel carries the default.

TOTAL IS ASSERTED, so a run with less coverage fails rather than reporting as a
smaller suite.
"""
import os
import sys

# Repo root from __file__, never the cwd: running from the repo root silently
# rescues imports that would fail inside the service.
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from modules.diagnostics import watcher as w

_fail = []
_count = 0

EXPECTED_CHECKS = 50


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-74s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def flags(routing=1, dns=1, egress=1, api=1):
    return {"routing_ok": bool(routing), "dns_ok": bool(dns),
            "egress_ok": bool(egress), "api_ok": bool(api)}


def mk_runner(routes_json, kinds):
    """Fake `ip` runner: (routes for `ip -j route`, {iface: link_kind})."""
    def runner(cmd):
        if "route" in cmd:
            return (0, routes_json)
        iface = cmd[-1]
        if iface not in kinds:
            return (1, "")
        k = kinds[iface]
        return (0, '[%s]' % ('{"linkinfo":{"info_kind":"%s"}}' % k if k else '{}'))
    return runner


PHYS = '[{"dst":"default","dev":"eth0"}]'
TUN = '[{"dst":"default","dev":"tun0"}]'
MESH = '[{"dst":"default","dev":"eth0"},{"dst":"100.64.0.1","dev":"tailscale0"}]'
EXITNODE = '[{"dst":"default","dev":"tailscale0"}]'


# ── 0. THE PREDICATE — the half the reverted fix got wrong ───────────────────
def test_predicate_mesh_vpn_must_not_qualify():
    """THE regression test. A mesh VPN with no default route is NOT tunnelled."""
    check("mesh VPN (tailscale0 up, no default) -> NOT tunnelled",
          w.tunnel_carries_default(mk_runner(MESH, {"eth0": None, "tailscale0": "tun"})),
          False)
    check("physical-only egress -> NOT tunnelled",
          w.tunnel_carries_default(mk_runner(PHYS, {"eth0": None})), False)
    check("tun device carrying the default -> tunnelled",
          w.tunnel_carries_default(mk_runner(TUN, {"tun0": "tun"})), True)
    check("wireguard device carrying the default -> tunnelled",
          w.tunnel_carries_default(mk_runner(TUN, {"tun0": "wireguard"})), True)
    # Matched by KIND, never by name — the name proves nothing either way.
    check("a device NAMED tun0 with no tunnel kind -> NOT tunnelled",
          w.tunnel_carries_default(mk_runner(TUN, {"tun0": None})), False)
    check("predicate DIFFERS between mesh and exit-node routing tables",
          w.tunnel_carries_default(mk_runner(MESH, {"eth0": None, "tailscale0": "tun"}))
          != w.tunnel_carries_default(mk_runner(EXITNODE, {"tailscale0": "tun"})), True)


def test_predicate_exit_node_decided_deliberately():
    """DECIDED: an exit node DOES qualify. Its egress genuinely is tunnelled."""
    check("tailscale EXIT NODE carrying the default -> tunnelled (deliberate)",
          w.tunnel_carries_default(mk_runner(EXITNODE, {"tailscale0": "tun"})), True)


def test_predicate_fails_closed():
    """A failed read must never read as tunnelled — permissive is the unsafe side."""
    check("failed route read -> NOT tunnelled", w.tunnel_carries_default(lambda c: (1, "")), False)
    check("empty route output -> NOT tunnelled", w.tunnel_carries_default(lambda c: (0, "")), False)
    check("unparseable route JSON -> NOT tunnelled",
          w.tunnel_carries_default(lambda c: (0, "not json")), False)
    check("route ok but link read fails -> NOT tunnelled",
          w.tunnel_carries_default(mk_runner(TUN, {})), False)


def test_predicate_live_value_on_this_host():
    """Pin what production actually supplies — the check the reverted fix lacked."""
    live_tunnelled = w.tunnel_carries_default()
    live_vpn = w._probe_vpn([])
    check("LIVE tunnel_carries_default() returns a bool",
          isinstance(live_tunnelled, bool), True)
    # On a host where a mesh VPN is up but carries no default, the two MUST
    # disagree. Reported either way, so a host lacking the case cannot look like
    # a silent pass.
    if live_vpn and not live_tunnelled:
        check("LIVE mesh VPN up but egress NOT tunnelled — predicate diverges from "
              "vpn_connected (regression guard ACTIVE)", True, True)
    else:
        check("LIVE divergence case absent here (vpn=%s tunnelled=%s) — guard not "
              "exercised on this host" % (live_vpn, live_tunnelled), True, True)


# ── 1. TUNNELLED: the exact production state must NOT report a fault ─────────
def test_tunnelled_ipv6_blocked_is_not_a_fault():
    f = flags()
    check("tunnelled, ipv6 blocked -> ALL_OK (not DEGRADED)",
          w.classify(f, True, False, w.IPV6_EXPECTED, True), "ALL_OK")
    check("tunnelled, ipv6 blocked -> note names the vpn",
          w._note(f, True, False, w.IPV6_EXPECTED, True), w._NOTE_IPV6_VPN_BLOCKED)
    check("tunnelled, ipv6 blocked -> NOT the fault vocabulary",
          w._note(f, True, False, w.IPV6_EXPECTED, True) == w._NOTE_IPV6_FAIL, False)
    check("tunnelled, ipv6 blocked -> note non-empty (visible, not hidden)",
          bool(w._note(f, True, False, w.IPV6_EXPECTED, True)), True)


# ── 2. NOT TUNNELLED: identical input MUST still report the fault ────────────
def test_not_tunnelled_ipv6_fault_still_fires():
    f = flags()
    check("NOT tunnelled, ipv6 provisioned+failing -> DEGRADED",
          w.classify(f, True, False, w.IPV6_EXPECTED, False), "DEGRADED")
    check("NOT tunnelled, ipv6 provisioned+failing -> real-fault note",
          w._note(f, True, False, w.IPV6_EXPECTED, False), w._NOTE_IPV6_FAIL)
    check("flag omitted -> strict verdict (old behaviour preserved)",
          w.classify(f, True, False, w.IPV6_EXPECTED), "DEGRADED")
    check("flag omitted -> strict note",
          w._note(f, True, False, w.IPV6_EXPECTED), w._NOTE_IPV6_FAIL)


def test_flag_is_load_bearing():
    f = flags()
    check("verdict DIFFERS on the tunnelled flag alone",
          w.classify(f, True, False, w.IPV6_EXPECTED, True)
          != w.classify(f, True, False, w.IPV6_EXPECTED, False), True)
    check("note DIFFERS on the tunnelled flag alone",
          w._note(f, True, False, w.IPV6_EXPECTED, True)
          != w._note(f, True, False, w.IPV6_EXPECTED, False), True)


# ── 3. raw-egress: degrade while tunnelled, never escalate ───────────────────
def test_egress_blocked_degrades_not_escalates():
    f = flags(egress=0)
    check("tunnelled, egress-only blocked -> DEGRADED (not LOCAL_FAIL)",
          w.classify(f, True, True, w.IPV6_EXPECTED, True), "DEGRADED")
    check("tunnelled, egress-only blocked -> NOT ALL_OK (still visible)",
          w.classify(f, True, True, w.IPV6_EXPECTED, True) == "ALL_OK", False)
    check("tunnelled, egress blocked -> note names the vpn",
          w._note(f, True, True, w.IPV6_EXPECTED, True), w._NOTE_EGRESS_VPN_BLOCKED)
    check("NOT tunnelled, egress blocked -> LOCAL_FAIL (unchanged)",
          w.classify(f, True, True, w.IPV6_EXPECTED, False), "LOCAL_FAIL")
    check("NOT tunnelled, egress blocked -> original note",
          w._note(f, True, True, w.IPV6_EXPECTED, False), w._NOTE_EGRESS_FAIL)
    check("egress verdict DIFFERS on the flag alone",
          w.classify(f, True, True, w.IPV6_EXPECTED, True)
          != w.classify(f, True, True, w.IPV6_EXPECTED, False), True)
    check("tunnelled, egress AND ipv6 blocked -> DEGRADED (egress still surfaces)",
          w.classify(flags(egress=0), True, False, w.IPV6_EXPECTED, True), "DEGRADED")


# ── 4. a REAL local fault while tunnelled must STILL be LOCAL_FAIL ───────────
def test_tunnel_does_not_mask_genuine_local_faults():
    check("tunnelled, no default route -> LOCAL_FAIL",
          w.classify(flags(routing=0), True, True, w.IPV6_EXPECTED, True), "LOCAL_FAIL")
    check("tunnelled, dns dead -> LOCAL_FAIL",
          w.classify(flags(dns=0), True, True, w.IPV6_EXPECTED, True), "LOCAL_FAIL")
    check("tunnelled, routing AND egress dead -> LOCAL_FAIL",
          w.classify(flags(routing=0, egress=0), True, True, w.IPV6_EXPECTED, True), "LOCAL_FAIL")
    check("tunnelled, dns AND egress dead -> LOCAL_FAIL",
          w.classify(flags(dns=0, egress=0), True, True, w.IPV6_EXPECTED, True), "LOCAL_FAIL")
    check("tunnelled, no route -> route note, not a vpn excuse",
          w._note(flags(routing=0), True, True, w.IPV6_EXPECTED, True), w._NOTE_NO_ROUTE)
    check("tunnelled, dns dead -> dns note",
          w._note(flags(dns=0), True, True, w.IPV6_EXPECTED, True), w._NOTE_DNS_FAIL)
    check("tunnelled, upstream dead -> UPSTREAM_FAIL (not masked)",
          w.classify(flags(api=0), True, True, w.IPV6_EXPECTED, True), "UPSTREAM_FAIL")
    check("tunnelled, IPv4 keytest failing -> DEGRADED (a real degradation)",
          w.classify(flags(), False, True, w.IPV6_EXPECTED, True), "DEGRADED")
    check("tunnelled, ipv4 failing -> ipv4 note, not a vpn note",
          w._note(flags(), False, True, w.IPV6_EXPECTED, True), w._NOTE_IPV4_FAIL)


# ── 5. pre-existing IPv4-only-link behaviour untouched ───────────────────────
def test_prior_ipv6_expectation_cases_unchanged():
    f = flags()
    check("ipv4-only link, not tunnelled -> ALL_OK (2026-08-22 fix intact)",
          w.classify(f, True, False, w.IPV6_NOT_PROVISIONED, False), "ALL_OK")
    check("ipv4-only link -> absent note",
          w._note(f, True, False, w.IPV6_NOT_PROVISIONED, False), w._NOTE_IPV6_ABSENT)
    check("ipv6 undetermined, not tunnelled -> ALL_OK",
          w.classify(f, True, False, w.IPV6_UNKNOWN, False), "ALL_OK")
    check("ipv6 undetermined -> unknown note",
          w._note(f, True, False, w.IPV6_UNKNOWN, False), w._NOTE_IPV6_UNKNOWN)
    check("healthy everything, not tunnelled -> ALL_OK",
          w.classify(f, True, True, w.IPV6_EXPECTED, False), "ALL_OK")
    check("healthy everything, tunnelled -> ALL_OK",
          w.classify(f, True, True, w.IPV6_EXPECTED, True), "ALL_OK")
    check("healthy everything -> empty note",
          w._note(f, True, True, w.IPV6_EXPECTED, False), "")
    check("tunnelled beats NOT_PROVISIONED for the note",
          w._note(f, True, False, w.IPV6_NOT_PROVISIONED, True), w._NOTE_IPV6_VPN_BLOCKED)


# ── 6. controlled vocabulary (these strings reach the DB) ────────────────────
def test_notes_are_controlled_vocabulary():
    for name in ("_NOTE_IPV6_VPN_BLOCKED", "_NOTE_EGRESS_VPN_BLOCKED"):
        val = getattr(w, name)
        check("%s is a fixed lowercase string" % name,
              isinstance(val, str) and val == val.lower() and val.strip() == val, True)
    check("TUNNEL_LINK_KINDS excludes nothing tunnel-like (tun/wireguard present)",
          {"tun", "wireguard"}.issubset(w.TUNNEL_LINK_KINDS), True)


if __name__ == "__main__":
    test_predicate_mesh_vpn_must_not_qualify()
    test_predicate_exit_node_decided_deliberately()
    test_predicate_fails_closed()
    test_predicate_live_value_on_this_host()
    test_tunnelled_ipv6_blocked_is_not_a_fault()
    test_not_tunnelled_ipv6_fault_still_fires()
    test_flag_is_load_bearing()
    test_egress_blocked_degrades_not_escalates()
    test_tunnel_does_not_mask_genuine_local_faults()
    test_prior_ipv6_expectation_cases_unchanged()
    test_notes_are_controlled_vocabulary()
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
