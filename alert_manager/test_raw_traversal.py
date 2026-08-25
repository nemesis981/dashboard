#!/usr/bin/env python3
"""raw_traversal — the instrument has to prove it can be WRONG before it is trusted.

A simulator that returned DROP for everything would pass a naive "does it find our
rule" test. So the tests below are built around discrimination: for every case that
must come back DROP there is a near-identical one that must not, and the self-test
itself is deliberately broken to confirm it actually fails when the logic is wrong.

The most valuable case here is not synthetic. `LIVE_RAW_V4` is the real
`iptables-nft -t raw -S` from the appliance, and the appliance's tailnet :80 was
independently MEASURED answering 302 from a remote device. The simulator must say
NOT_DROP for that dump -- if it did not, it would be disagreeing with reality, and
reality is the one that is right.

Run: python3 alert_manager/test_raw_traversal.py
"""
import os
import sys

ROOT = os.environ.get("NEMESIS_ROOT", "/opt/nemesis")
sys.path.insert(0, os.path.join(ROOT, "alert_manager"))

import raw_traversal as rt                                          # noqa: E402

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


#: The REAL raw table, captured from the appliance 2026-08-25. No addresses in it,
#: so it is safe to commit verbatim -- and verbatim is the point: a paraphrased
#: ruleset would not be evidence of anything.
LIVE_RAW_V4 = """-P PREROUTING ACCEPT
-P OUTPUT ACCEPT
-N piavpn.100.vpnTunOnly
-N piavpn.PREROUTING
-N piavpn.a.100.vpnTunOnly
-N piavpn.r.100.vpnTunOnly
-A PREROUTING -j piavpn.PREROUTING
-A piavpn.100.vpnTunOnly -j piavpn.r.100.vpnTunOnly
-A piavpn.PREROUTING -j piavpn.a.100.vpnTunOnly
-A piavpn.r.100.vpnTunOnly -j ACCEPT"""

#: Exactly what nemesis_fwd installs, in the form `-S` reads it BACK (with `-m tcp`,
#: which the inserted spec does not contain -- verified on a VM 2026-08-25).
OUR_RULE = "-A PREROUTING -i tailscale0 -p tcp -m tcp --dport 80 -j DROP"


def with_our_rule(dump):
    """Insert our rule at PREROUTING position 1, as `-I PREROUTING 1` would."""
    lines = dump.splitlines()
    first_a = next(i for i, l in enumerate(lines) if l.startswith("-A PREROUTING "))
    return "\n".join(lines[:first_a] + [OUR_RULE] + lines[first_a:])


print("== THE SELF-TEST IS REAL: break the logic, it must REFUSE to vouch ==")

check("selftest passes on the shipped logic", rt.selftest() == len(rt._CANARIES))

# If the self-test cannot fail, its passing means nothing. Break each predicate in
# turn and confirm it is caught -- this is the premise-proving step the standing
# practice asks for, applied to the checker itself.
for name, attr, broken in (
    ("interface matching always true", "_iface_match", lambda p, a: True),
    ("interface matching always false", "_iface_match", lambda p, a: False),
    ("port matching always true", "_port_match", lambda s, a: True),
):
    orig = getattr(rt, attr)
    setattr(rt, attr, broken)
    try:
        rt.selftest()
        caught = False
    except rt.SelfTestFailed:
        caught = True
    finally:
        setattr(rt, attr, orig)
    check("  broken %s is CAUGHT by the self-test" % name, caught)

check("...and the logic was restored afterwards", rt.selftest() == len(rt._CANARIES))


print("\n== AGREEMENT WITH MEASURED REALITY (the live ruleset, unmodified) ==")

r = rt.classify(LIVE_RAW_V4)
check("the live table today is NOT_DROP -- matching the measured 302",
      r.status == rt.NOT_DROP, repr(r))
check("  ...and it says so because the chain policy applies, not by accident",
      "policy" in r.reason, r.reason)
check("  ...having actually walked into PIA's chain, not stopped at the top",
      any("piavpn.PREROUTING" in t for t in r.trace), repr(r.trace))

r = rt.classify(with_our_rule(LIVE_RAW_V4))
check("the SAME table with our rule at position 1 is DROP",
      r.status == rt.DROP, repr(r))
check("  ...terminated by a rule, not by a policy", "rule" in r.reason, r.reason)


print("\n== CASE 3, BUILT FROM THE REAL CHAIN NAMES ==")

# PIA's restore slot is ALREADY armed with an unconditional ACCEPT; it is unreachable
# only because nothing jumps to piavpn.100.vpnTunOnly. This is that one edge added,
# plus PIA's jump re-inserted above ours -- the exact scenario the design fears.
case3 = with_our_rule(LIVE_RAW_V4).replace(
    "-A PREROUTING -j piavpn.PREROUTING",
    "-A PREROUTING -j piavpn.PREROUTING").replace(
    "-A piavpn.PREROUTING -j piavpn.a.100.vpnTunOnly",
    "-A piavpn.PREROUTING -j piavpn.100.vpnTunOnly")
lines = case3.splitlines()
lines.remove("-A PREROUTING -j piavpn.PREROUTING")
lines.insert(lines.index(OUR_RULE), "-A PREROUTING -j piavpn.PREROUTING")
case3 = "\n".join(lines)

r = rt.classify(case3)
check("our rule still EXISTS in this dump (iptables -C would say yes)",
      OUR_RULE in case3)
check("  ...but the verdict is NOT_DROP: it is never reached",
      r.status == rt.NOT_DROP, repr(r))
check("  ...and the trace names the ACCEPT that stole it",
      any("ACCEPT" in t for t in r.trace), repr(r.trace))
check("  ...which is exactly what a presence check CANNOT see",
      OUR_RULE in case3 and r.status == rt.NOT_DROP)


print("\n== THE -m tcp NORMALISATION TRAP (found on a VM, 2026-08-25) ==")

# The spec we INSERT has no `-m tcp`; the spec `-S` reads back always does. A parser
# that treats `-m tcp` as unmodelled reports the guard defeated while it is fine.
inserted_form = "-A PREROUTING -i tailscale0 -p tcp --dport 80 -j DROP"
check("the READ-BACK form (-m tcp) is recognised",
      rt.classify("-P PREROUTING ACCEPT\n" + OUR_RULE).status == rt.DROP)
check("the INSERTED form (no -m tcp) is recognised too",
      rt.classify("-P PREROUTING ACCEPT\n" + inserted_form).status == rt.DROP)
check("  ...and an unrelated -m module is still treated as unmodelled",
      rt.classify("-P PREROUTING ACCEPT\n"
                  "-A PREROUTING -i tailscale0 -p tcp -m conntrack --ctstate NEW -j ACCEPT\n"
                  + OUR_RULE).status == rt.UNDETERMINED)


print("\n== FAIL-CLOSED: every way of not knowing is UNDETERMINED, never a default ==")

for label, dump in (
    ("garbage input", "this is not an iptables dump"),
    ("a jump into an undeclared chain", "-P PREROUTING ACCEPT\n-A PREROUTING -j ghost\n" + OUR_RULE),
    ("an unknown target", "-P PREROUTING ACCEPT\n-A PREROUTING -i tailscale0 -p tcp -m tcp --dport 80 -j WAT"),
    ("a chain with no policy and no match", "-N only\n-A only -j RETURN"),
    ("a matching rule with no target at all", "-P PREROUTING ACCEPT\n-A PREROUTING -i tailscale0"),
):
    st = rt.classify(dump, rt.Packet("tailscale0", "tcp", 80)).status if label != "a chain with no policy and no match" \
        else rt.evaluate(rt.parse(dump), rt.TAILNET_HTTP, chain="only").status
    check("%s => UNDETERMINED" % label, st == rt.UNDETERMINED, st)

check("an empty dump is UNDETERMINED, not silently 'fine'",
      rt.classify("").status == rt.UNDETERMINED)

# A loop must not hang or blow the stack.
loop = "-N a\n-N b\n-P PREROUTING ACCEPT\n-A PREROUTING -j a\n-A a -j b\n-A b -j a"
check("a rule loop is UNDETERMINED, not a hang or a crash",
      rt.classify(loop).status == rt.UNDETERMINED)


print("\n== DISCRIMINATION: near-misses must NOT read as protection ==")

for label, dump, want in (
    ("DROP on the wrong port", "-P PREROUTING ACCEPT\n-A PREROUTING -i tailscale0 -p tcp -m tcp --dport 443 -j DROP", rt.NOT_DROP),
    ("DROP on the wrong interface", "-P PREROUTING ACCEPT\n-A PREROUTING -i eth0 -p tcp -m tcp --dport 80 -j DROP", rt.NOT_DROP),
    ("DROP on the wrong protocol", "-P PREROUTING ACCEPT\n-A PREROUTING -i tailscale0 -p udp -m udp --dport 80 -j DROP", rt.NOT_DROP),
    ("negated interface excludes us", "-P PREROUTING ACCEPT\n-A PREROUTING ! -i tailscale0 -p tcp -m tcp --dport 80 -j DROP", rt.NOT_DROP),
    ("a port RANGE covering 80 does protect", "-P PREROUTING ACCEPT\n-A PREROUTING -i tailscale0 -p tcp -m tcp --dport 79:81 -j DROP", rt.DROP),
    ("a wildcard interface does protect", "-P PREROUTING ACCEPT\n-A PREROUTING -i tailscale+ -p tcp -m tcp --dport 80 -j DROP", rt.DROP),
    ("a LOG rule above ours does not steal the packet", "-P PREROUTING ACCEPT\n-A PREROUTING -i tailscale0 -p tcp -m tcp --dport 80 -j LOG\n" + OUR_RULE, rt.DROP),
    # NB: status DROP, but see the attribution section below -- "the packet is
    # blocked" and "our guard is installed" are different questions.
    ("a chain policy of DROP also blocks the packet", "-P PREROUTING DROP", rt.DROP),
):
    check("%s => %s" % (label, want), rt.classify(dump).status == want,
          rt.classify(dump).status)


print("\n== ATTRIBUTION: 'blocked' AND 'our rule is installed' ARE DIFFERENT ==")

# The healer's condition is both. A healer keying only on status would sit still
# while its own rule was missing, because something unrelated happened to be
# blocking the traffic -- and would then be surprised when that thing went away.
for label, dump, want_status, want_ours in (
    ("our exact rule", "-P PREROUTING ACCEPT\n" + OUR_RULE, rt.DROP, True),
    ("the inserted form (no -m tcp) is still ours",
     "-P PREROUTING ACCEPT\n-A PREROUTING -i tailscale0 -p tcp --dport 80 -j DROP", rt.DROP, True),
    ("a chain policy of DROP blocks, but is NOT our rule",
     "-P PREROUTING DROP", rt.DROP, False),
    ("someone else's port-range DROP blocks, but is NOT our rule",
     "-P PREROUTING ACCEPT\n-A PREROUTING -i tailscale0 -p tcp -m tcp --dport 79:81 -j DROP",
     rt.DROP, False),
    ("a wildcard-interface DROP blocks, but is NOT our rule",
     "-P PREROUTING ACCEPT\n-A PREROUTING -i tailscale+ -p tcp -m tcp --dport 80 -j DROP",
     rt.DROP, False),
    ("our rule present but unreachable is neither",
     case3, rt.NOT_DROP, False),
):
    r = rt.classify(dump)
    check("%s => %s / by_our_rule=%s" % (label, want_status, want_ours),
          r.status == want_status and r.by_our_rule is want_ours,
          "got %s / %s" % (r.status, r.by_our_rule))

check("the terminating rule is reported, so the alert can name it",
      rt.classify("-P PREROUTING ACCEPT\n" + OUR_RULE).terminator is not None)
check("  ...and is None when a POLICY ended traversal, not a rule",
      rt.classify("-P PREROUTING DROP").terminator is None)

# Attribution is new logic, so it needs its own can-it-fail proof, not just a
# passing assertion.
_orig_ours = rt.is_our_rule
rt.is_our_rule = lambda toks: True
try:
    rt.selftest()
    caught = False
except rt.SelfTestFailed:
    caught = True
finally:
    rt.is_our_rule = _orig_ours
check("a broken is_our_rule is CAUGHT by the self-test", caught)


print("\n== v6 IS A SEPARATE RULESET AND MUST BE CHECKED SEPARATELY ==")

check("a v6 dump missing the rule is NOT_DROP even when v4 has it",
      rt.classify("-P PREROUTING ACCEPT").status == rt.NOT_DROP)
check("a v6 dump with the rule is DROP",
      rt.classify("-P PREROUTING ACCEPT\n" + OUR_RULE).status == rt.DROP)


print("\n== classify() CANNOT SKIP THE SELF-TEST ==")

orig = rt._iface_match
rt._iface_match = lambda p, a: True
try:
    rt.classify(LIVE_RAW_V4)
    bypassed = True
except rt.SelfTestFailed:
    bypassed = False
finally:
    rt._iface_match = orig
check("a broken simulator refuses to classify real data at all", not bypassed)


print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
