"""masquerade_egress_iface() decides by MEASURED routing outcome. No root, no network.

WHY THIS FILE EXISTS. This function had NO test coverage, which is how it kept a wrong
answer for a year's worth of the commonest full-tunnel shape there is. It walked
`ip route show default` and returned the first non-tunnel interface, documented with the
claim that redirect-gateway VPNs "FAIL VISIBLY" by returning None because the tunnel
replaces the main default.

An OpenVPN `/1` straddle does not replace it: it adds 0.0.0.0/1 + 128.0.0.0/1 and leaves
the physical `default` alone. Measured live 2026-08-31 against a connected full tunnel,
the function returned `enp131s0` with exit 0 while traffic resolved to `tun0` -- and
install.sh would have persisted a MASQUERADE rule pinning forwarded tailnet traffic
outside the user's VPN.

The load-bearing tests are `test_straddle_full_tunnel_refuses` (the regression) and
`test_old_default_route_signal_is_not_consulted` (proves the fix is a real change of
input, not a wrapper around the same wrong reading).
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Set BEFORE import: this module calls logging.basicConfig(filename=...) at import time,
# so importing it writes a log file wherever LOG_PATH resolves. Point it at a temp file
# rather than letting it land in the tree.
os.environ.setdefault("VPN_DNS_GUARD_LOG",
                      os.path.join(tempfile.gettempdir(), "vdg-test.log"))
import vpn_dns_guard as vg           # noqa: E402
import forkb_policy_route as F       # noqa: E402

_fail = []
_count = 0
EXPECTED_CHECKS = 13


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-68s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


class _Patch(object):
    """Swap module attributes for the duration of a with-block."""

    def __init__(self, **kw):
        self.kw = kw
        self.old = {}

    def __enter__(self):
        for k, v in self.kw.items():
            self.old[k] = getattr(vg, k)
            setattr(vg, k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.old.items():
            setattr(vg, k, v)


def _fake_run(mapping, fail_for=()):
    """Fake `ip route get` -- returns realistic output per destination."""
    def run(cmd, timeout=6):
        dest = cmd[-1]
        if dest in fail_for:
            return 1, "", "network is unreachable"
        iface = mapping.get(dest)
        if not iface:
            return 1, "", "no route"
        return 0, "%s via 10.0.0.1 dev %s src 10.0.0.2 uid 0 \ncache\n" % (dest, iface), ""
    return run


def _kinds(mapping):
    return lambda iface: mapping.get(iface, "")


def test_straddle_full_tunnel_refuses():
    print("\n[REGRESSION: a /1-straddle full tunnel must REFUSE, not return the NIC]")
    allt = {d: "tun0" for d in F.PROBE_DESTINATIONS}
    with _Patch(_run=_fake_run(allt), _iface_kind=_kinds({"tun0": "tun", "eth0": ""})):
        check("returns None under a full tunnel", vg.masquerade_egress_iface(), None)


def test_no_vpn_returns_the_nic():
    print("\n[no VPN: the physical egress is still returned]")
    alle = {d: "eth0" for d in F.PROBE_DESTINATIONS}
    with _Patch(_run=_fake_run(alle), _iface_kind=_kinds({"eth0": ""})):
        check("returns the physical interface", vg.masquerade_egress_iface(), "eth0")


def test_split_tunnel_returns_the_nic():
    print("\n[split tunnel: still a real non-tunnel egress to masquerade out of]")
    mixed = {d: "eth0" for d in F.PROBE_DESTINATIONS}
    mixed[F.PROBE_DESTINATIONS[0]] = "tun0"
    with _Patch(_run=_fake_run(mixed), _iface_kind=_kinds({"eth0": "", "tun0": "tun"})):
        check("returns the physical interface", vg.masquerade_egress_iface(), "eth0")


def test_low_confidence_refuses():
    print("\n[a failed lookup is a non-measurement -> refuse (operator ruling Q3)]")
    alle = {d: "eth0" for d in F.PROBE_DESTINATIONS}
    with _Patch(_run=_fake_run(alle, fail_for=(F.PROBE_DESTINATIONS[0],)),
                _iface_kind=_kinds({"eth0": ""})):
        check("one unresolved probe -> None", vg.masquerade_egress_iface(), None)
    with _Patch(_run=_fake_run({}), _iface_kind=_kinds({})):
        check("every probe failing -> None", vg.masquerade_egress_iface(), None)


def test_disagreeing_egress_refuses():
    print("\n[two different physical egresses -> refuse rather than pick one]")
    split = {}
    for i, d in enumerate(F.PROBE_DESTINATIONS):
        split[d] = "eth0" if i % 2 == 0 else "eth1"
    with _Patch(_run=_fake_run(split), _iface_kind=_kinds({"eth0": "", "eth1": ""})):
        check("ambiguous egress -> None", vg.masquerade_egress_iface(), None)


def test_old_default_route_signal_is_not_consulted():
    print("\n[the fix changes the INPUT, not just the output]")
    called = {"n": 0}

    def boom():
        called["n"] += 1
        raise AssertionError("_default_route_ifaces must no longer be consulted")

    allt = {d: "tun0" for d in F.PROBE_DESTINATIONS}
    with _Patch(_run=_fake_run(allt), _iface_kind=_kinds({"tun0": "tun"}),
                _default_route_ifaces=boom):
        check("full tunnel still refuses", vg.masquerade_egress_iface(), None)
    check("...without reading `ip route show default` at all", called["n"], 0)

    alle = {d: "eth0" for d in F.PROBE_DESTINATIONS}
    with _Patch(_run=_fake_run(alle), _iface_kind=_kinds({"eth0": ""}),
                _default_route_ifaces=boom):
        check("and the no-VPN answer is reached the new way too",
              vg.masquerade_egress_iface(), "eth0")
    check("...still without the old signal", called["n"], 0)


def test_provider_agnostic():
    print("\n[operator ruling: no vendor fingerprint in the decision path]")
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "vpn_dns_guard.py"), encoding="utf-8").read()
    body = src.split("def masquerade_egress_iface", 1)[1].split("\ndef ", 1)[0]
    code = body.split('"""', 2)[2]      # docstring may discuss history; code may not
    for vendor in ("piavpn", "nordvpn", "mullvad"):
        check("no %r in the decision code" % vendor, vendor in code.lower(), False)


if __name__ == "__main__":
    print("masquerade_egress_iface by measured routing outcome")
    test_straddle_full_tunnel_refuses()
    test_no_vpn_returns_the_nic()
    test_split_tunnel_returns_the_nic()
    test_low_confidence_refuses()
    test_disagreeing_egress_refuses()
    test_old_default_route_signal_is_not_consulted()
    test_provider_agnostic()
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
