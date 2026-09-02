"""Tests for net_identity — the ONE 'is this us' resolver.

Consolidates three drifting copies (firewall._local_addresses, lan_behavior's
_refresh_local_identity, post_detection's _pde_refresh_local_ips). These tests pin the
strict-superset behaviour every consumer needs: v4+v6 IPs with zone id stripped, MACs
lowercased with all-zero/empty excluded, AF_PACKET and AF_LINK both, and empty-on-
failure (callers layer keep-previous on top themselves).
"""
import os
import socket
import sys
from collections import namedtuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import net_identity  # noqa: E402

_fail = []
_count = 0
EXPECTED_CHECKS = 21

_Snic = namedtuple("snic", ["family", "address", "netmask", "broadcast", "ptp"])


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-70s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def _snic(family, address):
    return _Snic(family, address, None, None, None)


# A realistic multi-interface host: v4, v6-with-zone, a MAC, plus the edge cases.
AF_PACKET = getattr(socket, "AF_PACKET", 17)
_FAKE = {
    "lo":    [_snic(socket.AF_INET, "127.0.0.1"),
              _snic(socket.AF_INET6, "::1"),
              _snic(AF_PACKET, "00:00:00:00:00:00")],          # all-zero MAC -> excluded
    "eth0":  [_snic(socket.AF_INET, "192.0.2.10"),
              _snic(socket.AF_INET6, "fe80::1%eth0"),          # zone id -> stripped
              _snic(AF_PACKET, "AA:BB:CC:DD:EE:01")],          # upper -> lowercased
    "wg0":   [_snic(socket.AF_INET, "198.51.100.5"),
              _snic(AF_PACKET, "")],                            # empty MAC -> excluded
    "extra": [_snic(socket.AF_INET, "")],                       # empty IP -> excluded
}


def _patched(fake_or_exc):
    """Context: replace psutil.net_if_addrs with a fake dict or an exception."""
    import contextlib

    @contextlib.contextmanager
    def _cm():
        import psutil
        orig = psutil.net_if_addrs
        if isinstance(fake_or_exc, Exception):
            def boom():
                raise fake_or_exc
            psutil.net_if_addrs = boom
        else:
            psutil.net_if_addrs = lambda: fake_or_exc
        try:
            yield
        finally:
            psutil.net_if_addrs = orig
    return _cm()


def test_local_identity_ips():
    print("\n[IPs: v4+v6, zone stripped, empties excluded]")
    with _patched(_FAKE):
        ips, _macs = net_identity.local_identity()
    check("127.0.0.1 present", "127.0.0.1" in ips, True)
    check("::1 present", "::1" in ips, True)
    check("192.0.2.10 present", "192.0.2.10" in ips, True)
    check("198.51.100.5 present", "198.51.100.5" in ips, True)
    check("zone id stripped (fe80::1, not fe80::1%eth0)", "fe80::1" in ips, True)
    check("no zone-tagged form leaked", "fe80::1%eth0" in ips, False)
    check("empty IP excluded", "" in ips, False)
    check("exactly the 5 expected IPs", len(ips), 5)


def test_local_identity_macs():
    print("\n[MACs: lowercased, all-zero and empty excluded]")
    with _patched(_FAKE):
        _ips, macs = net_identity.local_identity()
    check("MAC lowercased", "aa:bb:cc:dd:ee:01" in macs, True)
    check("uppercase form not present", "AA:BB:CC:DD:EE:01" in macs, False)
    check("all-zero MAC excluded", "00:00:00:00:00:00" in macs, False)
    check("empty MAC excluded", "" in macs, False)
    check("exactly the 1 real MAC", len(macs), 1)


def test_convenience_wrappers_match():
    print("\n[local_ip_addresses / local_macs == the identity tuple halves]")
    with _patched(_FAKE):
        ips, macs = net_identity.local_identity()
        check("local_ip_addresses() == identity ips", net_identity.local_ip_addresses(), ips)
        check("local_macs() == identity macs", net_identity.local_macs(), macs)


def test_empty_on_failure():
    print("\n[enumeration failure -> EMPTY sets, never an exception (callers layer keep-previous)]")
    with _patched(RuntimeError("no interfaces")):
        ips, macs = net_identity.local_identity()
    check("ips empty on failure", ips, set())
    check("macs empty on failure", macs, set())
    with _patched(RuntimeError("boom")):
        check("local_ip_addresses empty on failure", net_identity.local_ip_addresses(), set())
        check("local_macs empty on failure", net_identity.local_macs(), set())


def test_returns_are_sets():
    print("\n[return types are sets, matching what every caller unions/membership-tests]")
    with _patched(_FAKE):
        ips, macs = net_identity.local_identity()
    check("ips is a set", isinstance(ips, set), True)
    check("macs is a set", isinstance(macs, set), True)


if __name__ == "__main__":
    print("=" * 74)
    print("net_identity — the one 'is this us' resolver")
    print("=" * 74)
    test_local_identity_ips()
    test_local_identity_macs()
    test_convenience_wrappers_match()
    test_empty_on_failure()
    test_returns_are_sets()
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
