#!/usr/bin/env python3
"""Fork B: an UNDETERMINED link kind must refuse, not read as 'physical'.

Run: python3 core/test_forkb_iface_kind_failclosed.py

THE BUG THIS PINS. `_iface_kind()` returned '' for BOTH "the kernel says this
is a plain physical NIC" and "the lookup failed", and
`classify_by_resolution`'s contract states that '' or missing means PHYSICAL,
not unknown -- correctly, since a normal ethernet NIC genuinely has no
`linkinfo.info_kind`.

So ANY failure of `ip -d -j link show` (missing binary, timeout, permission,
an iproute2 build change) classified the interface as physical-not-tunnel.
That is the PERMISSIVE direction: `masquerade_egress_iface()` could hand back a
tunnel it should have refused, and `install.sh` would persist a MASQUERADE rule
pinning forwarded tailnet traffic OUTSIDE the user's VPN. Same consequence as
the /1-straddle bug fixed in 707bf2f, arriving by a different route and
producing no output at all.

⚠ THE CONTROL MATTERS AS MUCH AS THE FIX. A change that makes the function
refuse ALWAYS would pass every security check here and silently break Fork B's
NAT. So the healthy split-tunnel path is asserted to still RETURN an interface.
"""
import io
import logging
import sys

sys.path.insert(0, "/opt/nemesis/core")
sys.path.insert(0, "/opt/nemesis")

import vpn_dns_guard as V                                     # noqa: E402

EXPECTED_CHECKS = 15
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 40:
        g, w = g[:37] + "...", w[:37] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


class _Env:
    """Swap `_run` and sysfs probing for a scripted network. Restores on exit."""

    def __init__(self, egress, link_rc=0, link_kind=None, tun_flags=False):
        self.egress, self.link_rc = egress, link_rc
        self.link_kind, self.tun_flags = link_kind, tun_flags

    def __enter__(self):
        self._run, self._exists = V._run, V.os.path.exists
        self.cap = io.StringIO()
        self._h = logging.StreamHandler(self.cap)
        V.log.addHandler(self._h)
        V.log.setLevel(logging.DEBUG)

        def fake_run(cmd, timeout=6):
            if cmd[:3] == ["ip", "route", "get"]:
                return 0, "1.1.1.1 dev %s src 10.0.0.2 uid 0\n" % self.egress, ""
            if cmd[:2] == ["ip", "-d"]:
                if self.link_rc != 0:
                    return self.link_rc, "", "simulated failure"
                info = ('{"linkinfo":{"info_kind":"%s"}}' % self.link_kind
                        if self.link_kind else "{}")
                return 0, "[%s]" % info, ""
            return self._run(cmd, timeout)

        V._run = fake_run
        V.os.path.exists = (lambda p: self.tun_flags if "tun_flags" in p
                            else self._exists(p))
        return self

    def __exit__(self, *a):
        V._run, V.os.path.exists = self._run, self._exists
        V.log.removeHandler(self._h)

    @property
    def logged(self):
        return self.cap.getvalue()


def main():
    print("\n1. _iface_kind_ex tells the three cases apart")
    with _Env("eth0", link_rc=0, link_kind=None):
        check("a plain NIC: ('', determined)", V._iface_kind_ex("eth0"), ("", True))
    with _Env("wg0", link_rc=0, link_kind="wireguard"):
        check("a tunnel: kind + determined",
              V._iface_kind_ex("wg0"), ("wireguard", True))
    with _Env("wg0", link_rc=1):
        check("lookup FAILED: ('', NOT determined)",
              V._iface_kind_ex("wg0"), ("", False))
    # The sysfs fallback is definitive for tun/tap even when `ip` is unusable.
    with _Env("tun0", link_rc=1, tun_flags=True):
        check("sysfs tun_flags still resolves tun/tap when ip fails",
              V._iface_kind_ex("tun0"), ("tun", True))

    print("\n2. _iface_kind keeps its old contract for existing callers")
    with _Env("eth0", link_rc=0, link_kind=None):
        check("plain NIC -> ''", V._iface_kind("eth0"), "")
    with _Env("wg0", link_rc=0, link_kind="wireguard"):
        check("tunnel -> its kind", V._iface_kind("wg0"), "wireguard")
    with _Env("wg0", link_rc=1):
        # THE AMBIGUITY THE OLD API CANNOT ESCAPE -- pinned so nobody "fixes"
        # this by making the legacy function return a sentinel that its callers
        # would then compare against TUNNEL_KINDS.
        check("failure ALSO -> '' (why security callers must not use it)",
              V._iface_kind("wg0"), "")

    print("\n3. THE FIX: masquerade refuses on an undetermined kind")
    with _Env("wg0", link_rc=1) as env:
        out = V.masquerade_egress_iface()
        check("returns None instead of guessing", out, None)
        check("...and says so loudly", "REFUSING" in env.logged, True)
        check("...naming the interface it could not classify",
              "wg0" in env.logged, True)

    print("\n4. CONTROL: the healthy path STILL WORKS")
    # Without this, a change that always returns None would pass section 3 and
    # silently break Fork B's NAT.
    with _Env("eth0", link_rc=0, link_kind=None) as env:
        out = V.masquerade_egress_iface()
        check("a split-tunnel/no-VPN egress is still returned", out, "eth0")
        check("...and nothing was refused", "REFUSING" not in env.logged, True)

    print("\n5. pre-existing behaviour preserved: a real tunnel still refuses")
    with _Env("wg0", link_rc=0, link_kind="wireguard") as env:
        out = V.masquerade_egress_iface()
        check("a full tunnel returns None", out, None)
        # It must refuse for the TOPOLOGY reason, not the undetermined one --
        # otherwise the new guard would be masking the original logic.
        check("...via the topology path, not the undetermined-kind path",
              "could not determine the link kind" not in env.logged, True)
        check("...and the refusal is logged", "refusing" in env.logged.lower(), True)

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [l for l, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
