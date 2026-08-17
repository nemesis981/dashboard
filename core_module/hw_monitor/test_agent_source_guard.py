"""Tests for agent_source_guard (:5001 source admission).

Run:  python3 core_module/hw_monitor/test_agent_source_guard.py

Standalone, no pytest, matching the other hw_monitor tests. Exits non-zero on
the first failure so a harness cannot mistake a broken run for a passing one.

The test that matters most is `test_self_test_catches_a_permissive_allowlist`:
it builds a guard whose allowlist covers everything and asserts that
construction RAISES. Without that, every other assertion here would still pass
against a guard that permits the entire internet — which is precisely the
failure mode the self-test exists to catch, and precisely the kind of green
test-run that would hide it.
"""

import ipaddress
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import agent_source_guard as G  # noqa: E402

_failures = []


def check(label, got, want):
    if got != want:
        _failures.append("%s: got %r, want %r" % (label, got, want))
        print("  FAIL  %s: got %r, want %r" % (label, got, want))
    else:
        print("  ok    %s" % label)


def check_raises(label, exc, fn, *a, **kw):
    try:
        fn(*a, **kw)
    except exc as e:
        print("  ok    %s (raised: %s)" % (label, str(e)[:70]))
        return
    except Exception as e:
        _failures.append("%s: raised %s, wanted %s" % (label, type(e).__name__, exc.__name__))
        print("  FAIL  %s: raised %s, wanted %s" % (label, type(e).__name__, exc.__name__))
        return
    _failures.append("%s: did NOT raise %s" % (label, exc.__name__))
    print("  FAIL  %s: did NOT raise %s" % (label, exc.__name__))


def base_plus(*extra):
    return [ipaddress.ip_network(n) for n in G.BASE_ALLOW] + \
           [ipaddress.ip_network(n, strict=False) for n in extra]


def test_base_allowlist():
    print("\n[base allowlist — loopback and VPN, no LAN]")
    g = G.SourceGuard(base_plus())
    check("loopback allowed", g.allows("127.0.0.1"), True)
    check("IPv6 loopback allowed", g.allows("::1"), True)
    check("tailnet v4 low allowed", g.allows("100.64.0.1"), True)
    check("tailnet v4 high allowed", g.allows("100.127.255.254"), True)
    check("tailnet v6 allowed", g.allows("fd7a:115c:a1e0:ab12::1"), True)
    check("public refused", g.allows("8.8.8.8"), False)
    check("LAN refused when not configured", g.allows("172.20.0.69"), False)
    # 100.128.0.0 is the first address ABOVE the CGNAT /10 — the off-by-one a
    # hand-written range check gets wrong.
    check("just past CGNAT refused", g.allows("100.128.0.1"), False)
    check("last CGNAT address allowed", g.allows("100.127.255.255"), True)


def test_lan_allowlist():
    print("\n[with a LAN network]")
    g = G.SourceGuard(base_plus("172.20.0.0/22"))
    check("in-LAN allowed", g.allows("172.20.0.69"), True)
    check("upper half of /22 allowed", g.allows("172.20.3.250"), True)
    check("adjacent subnet refused", g.allows("172.20.4.1"), False)
    check("other RFC1918 refused", g.allows("10.0.0.5"), False)


def test_malformed_input_refused():
    print("\n[malformed input is refused, never ignored]")
    g = G.SourceGuard(base_plus("172.20.0.0/22"))
    check("None refused", g.allows(None), False)
    check("empty refused", g.allows(""), False)
    check("garbage refused", g.allows("not-an-ip"), False)
    check("hostname refused", g.allows("example.com"), False)
    check("port-suffixed refused", g.allows("172.20.0.69:5001"), False)
    check("unparseable counted", g.stats["unparseable"] >= 4, True)


def test_v4_mapped_v6():
    print("\n[IPv4-mapped IPv6 resolves to its v4 meaning]")
    g = G.SourceGuard(base_plus("172.20.0.0/22"))
    check("mapped LAN allowed", g.allows("::ffff:172.20.0.69"), True)
    check("mapped public refused", g.allows("::ffff:8.8.8.8"), False)
    check("zone index stripped", g.allows("::1%lo"), True)


def test_self_test_catches_a_permissive_allowlist():
    print("\n[the self-test proves the premise]")
    # 0.0.0.0/0 permits everything. A guard built on it would answer True to
    # every question and look healthy. Construction must refuse.
    check_raises("allow-everything v4 rejected", G.GuardError,
                 G.SourceGuard, base_plus("0.0.0.0/0"))
    # A LAN entry wide enough to swallow every deny canary is the same defect
    # arriving by accident rather than by typo.
    check_raises("allowlist swallowing all canaries rejected", G.GuardError,
                 G.SourceGuard, base_plus("192.88.99.0/24", "8.8.8.0/24",
                                          "203.0.113.0/24"))
    check_raises("empty allowlist rejected", G.GuardError, G.SourceGuard, [])
    # And the inverse: a guard that cannot permit what it must permit.
    check_raises("allowlist missing loopback rejected", G.GuardError,
                 G.SourceGuard, [ipaddress.ip_network("172.20.0.0/22")])


def test_from_env():
    print("\n[from_env]")
    saved = {k: os.environ.get(k) for k in
             ("NEMESIS_5001_SOURCE_GUARD", "NEMESIS_5001_ALLOW")}
    try:
        os.environ.pop("NEMESIS_5001_ALLOW", None)

        os.environ["NEMESIS_5001_SOURCE_GUARD"] = "0"
        g, note = G.from_env()
        check("disabled returns None", g is None, True)
        check("disabled explains why", "SOURCE_GUARD" in note, True)

        os.environ["NEMESIS_5001_SOURCE_GUARD"] = "1"
        os.environ["NEMESIS_5001_ALLOW"] = "10.9.8.0/24"
        g, note = G.from_env()
        check("configured network allowed", g.allows("10.9.8.20"), True)
        check("base entries still present", g.allows("100.64.0.1"), True)
        check("outside configured refused", g.allows("10.9.9.20"), False)
        check("note names the source", "NEMESIS_5001_ALLOW" in note, True)

        os.environ["NEMESIS_5001_ALLOW"] = "10.9.8.0/24, nonsense/24"
        check_raises("bad CIDR raises rather than silently dropping",
                     G.GuardError, G.from_env)

        # Auto-detection path: must produce a guard that still refuses.
        os.environ.pop("NEMESIS_5001_ALLOW", None)
        g, note = G.from_env()
        check("auto-detect builds a guard", g is not None, True)
        check("auto-detect still refuses public", g.allows("8.8.8.8"), False)
        check("auto-detect permits loopback", g.allows("127.0.0.1"), True)
        print("        note: %s" % note)
        print("        allowlist: %s" % g.describe())
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_lan_enumeration_failure_is_loud_and_closed():
    print("\n[LAN enumeration failure fails closed and is reported]")
    saved = G.local_ipv4_networks
    os.environ.pop("NEMESIS_5001_ALLOW", None)
    os.environ["NEMESIS_5001_SOURCE_GUARD"] = "1"

    def boom():
        raise G.GuardError("simulated interface read failure")

    G.local_ipv4_networks = boom
    try:
        g, note = G.from_env()
        check("still builds a guard", g is not None, True)
        check("VPN path survives", g.allows("100.64.0.1"), True)
        check("loopback survives", g.allows("127.0.0.1"), True)
        check("LAN now refused (fails CLOSED)", g.allows("172.20.0.69"), False)
        check("failure recorded on the guard",
              "simulated" in (g.lan_enumeration_error or ""), True)
        check("failure surfaced in the note", "FAILED" in note, True)
    finally:
        G.local_ipv4_networks = saved
        os.environ.pop("NEMESIS_5001_SOURCE_GUARD", None)


def test_local_ipv4_networks_matches_reality():
    print("\n[local_ipv4_networks agrees with the kernel]")
    try:
        nets = G.local_ipv4_networks()
    except G.GuardError as e:
        print("  SKIP  could not enumerate: %s" % e)
        return
    print("        detected: %s" % ([str(n) for n in nets] or "none"))
    check("no /32 host routes", all(n.prefixlen != 32 for n in nets), True)
    check("all IPv4", all(n.version == 4 for n in nets), True)
    # Regression guard: an unconfigured NIC self-assigns a link-local address,
    # and admitting 169.254.0.0/16 would admit a range any host on that segment
    # can claim unasked. Caught live on the dev box, which has exactly this.
    check("no link-local", all(not n.is_link_local for n in nets), True)
    # Cross-check against psutil directly: every detected network must contain
    # at least one address this host actually holds. An entry that matches no
    # local address would mean the derivation invented a network.
    try:
        import psutil
        mine = [a.address for addrs in psutil.net_if_addrs().values()
                for a in addrs if a.family == socket.AF_INET]
        for n in nets:
            hit = any(ipaddress.ip_address(m) in n for m in mine)
            check("%s contains a real local address" % n, hit, True)
    except ImportError:
        print("  SKIP  psutil cross-check unavailable")


if __name__ == "__main__":
    print("agent_source_guard tests")
    test_base_allowlist()
    test_lan_allowlist()
    test_malformed_input_refused()
    test_v4_mapped_v6()
    test_self_test_catches_a_permissive_allowlist()
    test_from_env()
    test_lan_enumeration_failure_is_loud_and_closed()
    test_local_ipv4_networks_matches_reality()

    print("\n" + "=" * 60)
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  - %s" % f)
        sys.exit(1)
    print("ALL PASS")
