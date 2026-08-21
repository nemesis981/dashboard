#!/usr/bin/env python3
"""`_detect_connection_type()` — local vs vpn_remote, across BOTH address families.

Run: python3 nemesis_agent/test_connection_type.py

WHY THIS EXISTS NOW
-------------------
The function decided local-vs-remote by sweeping local interface addresses and
filtering on `addr.family == socket.AF_INET`. IPv6 was therefore never
considered, so a device whose only local-link address is v6 classified as
remote. It failed toward the MORE restrictive answer, so this was a
misclassification rather than an open door -- but it is the same IPv4-only
assumption class already found and fixed once in the Tier 2 gate, which is why
it is worth pinning with controls rather than just patching.

Widening to v6 is not a one-word change, and that is the real point of this
suite. The original parsed every address inside a single try/except wrapping the
whole sweep, so ONE unparseable address silently ended the loop and returned
vpn_remote. IPv6 link-local addresses arrive scope-suffixed ("fe80::1%eth0") --
exactly the shape most likely to fail parsing. Adding v6 without moving the
parse guard inside the loop would have INTRODUCED that silent abort while
looking like it fixed something.

WHAT THIS SUITE IS WEIGHTED TOWARD
----------------------------------
In production this function has returned "local" ZERO times across 13 enrolled
devices -- every classified device sits on a tailnet address and is genuinely
remote. So the "local" branch has no production exercise at all, and a suite
that only asserted "remote stays remote" would pass an implementation whose
local branch was dead. Every negative check here is therefore paired with a
control proving the same code path can produce the OTHER answer.

The last check is a mutation control: it reimplements the pre-fix v4-only sweep
and proves it returns the WRONG answer for the v6 case. Without it, a green run
would not distinguish "the fix works" from "the test never exercised the fix".

EXPECTED BEFORE THE IMPLEMENTATION: red on the v6 and parse-guard checks, green
on the v4 controls.
"""
import ast
import collections
import logging
import os
import socket
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, HERE)

# 14 -> 19 with the 2026-08-20 sentinel split: two rewritten (no-subnet and
# detection-failure now assert UNKNOWN rather than vpn_remote) plus four new ones
# covering the affirmative-remote case and the preserved conservative outcomes.
EXPECTED_CHECKS = 19

_results = []

# Mirrors psutil's snicaddr shape closely enough for the code under test.
Addr = collections.namedtuple("Addr", "family address netmask broadcast ptp")


def addr(family, address):
    return Addr(family, address, None, None, None)


def v4(a):
    return addr(socket.AF_INET, a)


def v6(a):
    return addr(socket.AF_INET6, a)


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


class _Capture(logging.Handler):
    """Collects agent log records, with their levels, so a deliberate
    fail-safe fallback can be told apart from a silent one."""

    def __init__(self):
        logging.Handler.__init__(self)
        self.records = []

    def emit(self, record):
        self.records.append((record.levelno, record.getMessage()))


def old_v4_only_detect(conf, ifaces):
    """The PRE-FIX implementation, reproduced verbatim in shape.

    Exists solely as a mutation control: if the v6 checks below pass against
    this too, then those checks are not measuring the fix.
    """
    import ipaddress
    try:
        subnet_str = conf.get("nemesis_subnet") or ""
        if not subnet_str:
            return "vpn_remote"
        subnet = ipaddress.ip_network(subnet_str, strict=False)
        local_ips = [a.address for iface_addrs in ifaces.values()
                     for a in iface_addrs if a.family == socket.AF_INET]
        for ip in local_ips:
            if ipaddress.ip_address(ip) in subnet:
                return "local"
    except Exception:
        pass
    return "vpn_remote"


def main():
    import agent

    def detect(subnet, ifaces, raises=False):
        """Run the real function against a synthetic interface table."""
        def fake_net_if_addrs():
            if raises:
                raise OSError("synthetic interface enumeration failure")
            return ifaces
        real = agent.psutil.net_if_addrs
        agent.psutil.net_if_addrs = fake_net_if_addrs
        try:
            conf = {} if subnet is None else {"nemesis_subnet": subnet}
            return agent._detect_connection_type(conf)
        finally:
            agent.psutil.net_if_addrs = real

    LAN4 = "198.51.100.0/24"
    LAN6 = "2001:db8:4::/64"

    # ── the v4 path still works, in both directions ──────────────────────────
    print("\nthe IPv4 path is unchanged, and can still return BOTH answers")
    check("CONTROL a v4 address on the subnet is local",
          detect(LAN4, {"eth0": [v4("198.51.100.22")]}), "local")
    check("CONTROL a v4 address off the subnet is remote",
          detect(LAN4, {"eth0": [v4("203.0.113.9")]}), "vpn_remote")

    # ── the v6 half: the actual defect ───────────────────────────────────────
    print("\nan IPv6-only local link is classified, not assumed remote")
    check("POSITIVE a v6 address on a v6 subnet is local",
          detect(LAN6, {"eth0": [v6("2001:db8:4::10")]}), "local")
    check("CONTROL a v6 address off the v6 subnet is remote",
          detect(LAN6, {"eth0": [v6("2001:db8:9::10")]}), "vpn_remote")

    # A v6 address alongside a v4 subnet must not raise. ipaddress returns False
    # across families rather than raising, which is what makes collecting both
    # families safe -- if that ever changed, this check catches it.
    check("a v6 address present under a v4 subnet does not break the v4 match",
          detect(LAN4, {"eth0": [v6("2001:db8:4::10"), v4("198.51.100.22")]}),
          "local")

    # ── the parse guard: one bad address must not abort the sweep ────────────
    print("\none unparseable address does not abort the whole sweep")
    # Order matters. The bad address must come FIRST -- if the good one were
    # first the function would return before ever reaching the bad one and the
    # check would pass without exercising the guard at all.
    check("a bad address BEFORE a good one still finds local",
          detect(LAN4, {"eth0": [v4("not-an-ip"), v4("198.51.100.22")]}), "local")
    check("CONTROL a bad address alone yields remote, not a crash",
          detect(LAN4, {"eth0": [v4("not-an-ip")]}), "vpn_remote")
    # Scope-suffixed link-locals are the realistic instance of the above.
    check("a scope-suffixed link-local is parsed, not skipped",
          detect("fe80::/10", {"eth0": [v6("fe80::1%eth0")]}), "local")

    # ── the sentinel split (2026-08-20) ─────────────────────────────────────
    # These two checks previously asserted the OPPOSITE: that "no subnet" and "a
    # detection failure" both yielded "vpn_remote". That collapse was correct while
    # this field was purely descriptive -- every consumer only ever asked "is this
    # local?", and failing to the restrictive answer was genuinely safe. The
    # tunnel-back design makes this classification decide whether to STEER a
    # device's traffic, and a failure that reads as a confident "remote" would then
    # send a machine sitting on the home LAN out through the tunnel and back, with
    # nothing to indicate anything had gone wrong. The old docstring recorded the
    # split as owed; this is it.
    print("\ncannot-tell is its own answer, distinct from an affirmative remote")
    check("no subnet configured -> UNKNOWN (we were never given the fact)",
          detect(None, {"eth0": [v4("198.51.100.22")]}), agent.CONN_UNKNOWN)
    check("a detection failure -> UNKNOWN, not a location",
          detect(LAN4, {}, raises=True), agent.CONN_UNKNOWN)
    check("subnet configured + sweep completed + no match -> affirmative remote",
          detect(LAN4, {"eth0": [v4("203.0.113.9")]}), agent.CONN_REMOTE)

    # The safety property the two replaced checks were really protecting: nothing
    # that could not be measured is ever treated as an affirmative remote, and the
    # OUTWARD behaviour is unchanged, so the server sees exactly what it saw before.
    print("\n...but the conservative outcome is preserved, now visibly")
    check("UNKNOWN is not a confirmed remote",
          agent.is_confirmed_remote(agent.CONN_UNKNOWN), False)
    check("UNKNOWN still leaves the wire two-valued (server compat)",
          agent._connection_type_for_wire(detect(LAN4, {}, raises=True)), "vpn_remote")
    check("no-subnet still leaves the wire two-valued",
          agent._connection_type_for_wire(
              detect(None, {"eth0": [v4("203.0.113.9")]})), "vpn_remote")
    check("UNKNOWN still takes the broader roaming ruleset",
          agent._expected_suricata_profile(agent.CONN_UNKNOWN, {}), "roaming")

    cap = _Capture()
    agent.log.addHandler(cap)
    prior = agent.log.level
    agent.log.setLevel(logging.DEBUG)
    try:
        detect(LAN4, {}, raises=True)
        failure_records = list(cap.records)
        cap.records = []
        detect(LAN4, {"eth0": [v4("198.51.100.22")]})
        success_records = list(cap.records)
    finally:
        agent.log.setLevel(prior)
        agent.log.removeHandler(cap)

    check("a detection FAILURE is logged at WARNING, not debug",
          any(lvl >= logging.WARNING for lvl, _ in failure_records), True)
    # Without this control the check above would also pass an implementation
    # that warned on every call, which would make the warning meaningless.
    check("CONTROL a successful detection logs no warning",
          any(lvl >= logging.WARNING for lvl, _ in success_records), False)

    # ── the source itself ────────────────────────────────────────────────────
    print("\nthe implementation carries the fix, not an equivalent elsewhere")
    src = agent.__file__.replace(".pyc", ".py")
    with open(src) as fh:
        tree = ast.parse(fh.read(), src)
    fn = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_detect_connection_type":
            fn = node
    names = {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)} if fn else set()
    check("the function itself references AF_INET6", "AF_INET6" in names, True)
    # The unused `hostname = socket.gethostname()` assignment was dead code.
    check("the unused gethostname assignment is gone",
          "gethostname" in names, False)

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)

    # ── mutation control ─────────────────────────────────────────────────────
    # Not a _results check: this asserts about the OLD code, proving the v6
    # checks above are measuring the fix rather than passing regardless.
    print("\nmutation control (pre-fix code, expected to get the v6 case WRONG)")
    old = old_v4_only_detect({"nemesis_subnet": LAN6},
                             {"eth0": [v6("2001:db8:4::10")]})
    old_guard = old_v4_only_detect({"nemesis_subnet": LAN4},
                                   {"eth0": [v4("not-an-ip"), v4("198.51.100.22")]})
    print("  pre-fix v6-only link      -> %s (fixed code says 'local')" % old)
    print("  pre-fix bad-address-first -> %s (fixed code says 'local')" % old_guard)
    if old == "local" or old_guard == "local":
        print("\n!! MUTATION CONTROL FAILED: the pre-fix code gets these RIGHT, "
              "so the checks above do not prove the fix")
        return 3

    print("\n%d/%d checks passed" % (passed, ran))
    failed = [lbl for lbl, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d "
              "-- a check was skipped, not merely failed" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
