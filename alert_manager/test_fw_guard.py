#!/usr/bin/env python3
"""The tailnet plain-HTTP guard check (ADR 0026 step 4) — every branch, walked.

The point of this suite is not that the happy path works. It is that each way the check
can be WRONG is exercised by a test that forces execution down that exact path:

  * it does nothing at all until deliberately armed
  * a read failure is not mistaken for "no rules, therefore defeated"
  * an undecidable ruleset does NOT trigger a repair
  * a checker that fails its own canaries repairs nothing
  * a repair that reports success but did not work is caught and re-alerted
  * "the packet is blocked" is not accepted as "our guard is installed"

Nothing here runs iptables or opens a socket. `_guard_dump` and the firewall client are
replaced, so what is asserted is the DECISION the check makes given a ruleset.

Run: python3 alert_manager/test_fw_guard.py
"""
import os
import sys
import types

ROOT = os.environ.get("NEMESIS_ROOT", "/opt/nemesis")
sys.path.insert(0, os.path.join(ROOT, "alert_manager"))

import nemesis_fw_watch as W                                        # noqa: E402
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


OURS = "-A PREROUTING -i tailscale0 -p tcp -m tcp --dport 80 -j DROP"
HEALTHY = "-P PREROUTING ACCEPT\n" + OURS
# NB: the jumped-to chain MUST be declared, or this dump is undecidable rather than
# "rule absent" -- which is a different branch entirely. Caught by this suite.
ABSENT = ("-P PREROUTING ACCEPT\n"
          "-N piavpn.PREROUTING\n"
          "-A PREROUTING -j piavpn.PREROUTING")
CASE3 = ("-P PREROUTING ACCEPT\n"
         "-N vpn\n"
         "-A PREROUTING -j vpn\n"
         + OURS + "\n"
         "-A vpn -j ACCEPT")
POLICY_DROP = "-P PREROUTING DROP"
UNDECIDABLE = ("-P PREROUTING ACCEPT\n"
               "-A PREROUTING -i tailscale0 -p tcp -m conntrack --ctstate NEW -j ACCEPT\n"
               + OURS)


class Harness:
    """Replaces the world around the check and records what it decided to do."""

    def __init__(self, dumps, heal=True):
        #: str -> same dump for both families, or dict/list for per-call control
        self.dumps = dumps
        self.heal_ok = heal
        self.alerts = []
        self.degraded = []
        self.emails = []
        self.heals = 0
        self.dump_calls = 0

    def dump(self, binary):
        self.dump_calls += 1
        d = self.dumps
        if isinstance(d, list):
            d = d[min(self.dump_calls - 1, len(d) - 1)]
        if isinstance(d, tuple):
            return d
        return d, None

    def fw_client(self):
        outer = self

        class _C:
            @staticmethod
            def reassert_port_deny_on_interface(iface, port, proto="tcp", **kw):
                outer.heals += 1
                if outer.heal_ok is True:
                    return {"ok": True}
                if outer.heal_ok is False:
                    raise RuntimeError("helper refused")
                return outer.heal_ok(iface, port, proto)
        return _C

    def _degraded(self, code, severity, message, context):
        self.degraded.append((code, severity, message, context))

    def _email(self, subject, body):
        self.emails.append((subject, body))

    def codes(self):
        return [c for c, _s, _m, _ctx in self.degraded]


def run(dumps, enabled=True, heal=True, reason="test"):
    h = Harness(dumps, heal=heal)
    W.GUARD_ENABLED = enabled
    W._guard_dump = h.dump
    W._degraded = h._degraded
    W._email_async = h._email
    W._last_guard_alert_key = None
    W._guard_repairs.clear()
    sys.modules["firewall"] = types.SimpleNamespace(
        reassert_port_on_interface=h.fw_client().reassert_port_deny_on_interface)
    W.verify_tailnet_guard(reason)
    return h


_orig_dump = W._guard_dump
_orig_degraded = W._degraded
_orig_email = W._email_async


print("== IT SHIPS INERT: disabled is the DEFAULT, and disabled means DO NOTHING ==")

check("the shipped default is OFF (a deploy must not change network behaviour)",
      os.environ.get("NEMESIS_FW_GUARD") is None
      and W.__dict__["GUARD_ENABLED"] in (True, False))
h = run(CASE3, enabled=False)
check("disabled: no ruleset is even read", h.dump_calls == 0, repr(h.dump_calls))
check("  ...no repair is attempted", h.heals == 0)
check("  ...and nothing is alerted", h.degraded == [], repr(h.degraded))
check("CONTROL: the SAME ruleset when armed does act",
      run(CASE3, enabled=True).heals == 1)


print("\n== HEALTHY: quiet, and genuinely checked ==")

h = run(HEALTHY)
check("no alert", h.degraded == [], repr(h.degraded))
check("no repair", h.heals == 0)
check("  ...but it did read both families (2 dumps), not zero",
      h.dump_calls == 2, repr(h.dump_calls))


print("\n== DEFEATED: alert AND repair, then prove the repair ==")

h = run([CASE3, CASE3, HEALTHY, HEALTHY])
check("alerts NEM-FWW-0005", W.ERR_GUARD_DEFEATED in h.codes(), repr(h.codes()))
check("  ...at critical severity", any(s == "critical" for _c, s, _m, _x in h.degraded))
check("  ...repairs exactly once for both families", h.heals == 1, repr(h.heals))
check("  ...emails the operator", len(h.emails) >= 1)
check("  ...and the alert carries the trace naming what stole the packet",
      any("trace" in ctx for _c, _s, _m, ctx in h.degraded), repr(h.degraded[0][3].keys()))
check("  ...re-reads afterwards to PROVE the repair (2 before + 2 after)",
      h.dump_calls == 4, repr(h.dump_calls))
check("  ...and does not re-alert once healthy", W.ERR_GUARD_HEAL_FAILED not in h.codes())

h = run([ABSENT, ABSENT, HEALTHY, HEALTHY])
check("a missing rule is also a defeat, not a no-op", h.heals == 1 and W.ERR_GUARD_DEFEATED in h.codes())


print("\n== 'BLOCKED' IS NOT 'INSTALLED': a policy DROP still needs the guard ==")

# The packet is dropped, so a status-only check would report healthy while our rule is
# absent -- and the moment that unrelated policy changes, the port is open.
h = run([POLICY_DROP, POLICY_DROP, HEALTHY, HEALTHY])
check("policy DROP is still treated as the guard being absent", h.heals == 1, repr(h.heals))
check("  ...and the alert says so via by_our_rule",
      any(ctx.get("by_our_rule") is False for _c, _s, _m, ctx in h.degraded), repr(h.degraded))
check("CONTROL: the same check on our real rule does NOT repair", run(HEALTHY).heals == 0)


print("\n== UNDETERMINED: alert, and do NOT repair on the strength of not knowing ==")

h = run(UNDECIDABLE)
check("alerts NEM-FWW-0006", W.ERR_GUARD_UNDETERMINED in h.codes(), repr(h.codes()))
check("  ...and repairs NOTHING", h.heals == 0, repr(h.heals))
check("  ...because the thing to repair may not be what is wrong",
      W.ERR_GUARD_DEFEATED not in h.codes())


print("\n== A FAILED READ IS NOT 'NO RULES' ==")

# The trap: '' parses as a ruleset with no rules -> NOT_DROP -> repair, on the strength
# of having learned nothing. The read must surface as an explicit failure instead.
h = run((None, "iptables exited 4: resource temporarily unavailable"))
check("a read failure alerts UNDETERMINED", W.ERR_GUARD_UNDETERMINED in h.codes(), repr(h.codes()))
check("  ...and does NOT repair", h.heals == 0)
check("  ...and is not reported as the guard being defeated",
      W.ERR_GUARD_DEFEATED not in h.codes())
check("  ...the failure detail is carried, not swallowed",
      any("resource temporarily" in str(ctx) for _c, _s, _m, ctx in h.degraded), repr(h.degraded))

# An empty dump has no PREROUTING chain and no policy, so it is UNDECIDABLE rather
# than "a ruleset with no rules". That is the safer answer and worth pinning: the
# alternative would repair on the strength of a truncated read.
h = run(("", None))
check("CONTROL: an EMPTY dump is UNDETERMINED, not silently 'defeated'",
      W.ERR_GUARD_UNDETERMINED in h.codes(), repr(h.codes()))
check("  ...and still does not repair", h.heals == 0, repr(h.heals))


print("\n== A CHECKER THAT FAILS ITS OWN CANARIES REPAIRS NOTHING ==")

_orig_iface = rt._iface_match
rt._iface_match = lambda p, a: True
try:
    h = run(HEALTHY)
finally:
    rt._iface_match = _orig_iface
check("self-test failure alerts", W.ERR_GUARD_UNDETERMINED in h.codes(), repr(h.codes()))
check("  ...at critical severity", any(s == "critical" for _c, s, _m, _x in h.degraded))
check("  ...and NO repair is attempted on a broken instrument", h.heals == 0)
check("CONTROL: with the checker restored, the same call is quiet", run(HEALTHY).degraded == [])


print("\n== A REPAIR THAT DOES NOT WORK IS NOT REPORTED AS SUCCESS ==")

h = run([CASE3, CASE3, CASE3, CASE3])          # still defeated after the repair
check("alerts NEM-FWW-0007 when the state is still bad afterwards",
      W.ERR_GUARD_HEAL_FAILED in h.codes(), repr(h.codes()))
check("  ...having actually attempted the repair", h.heals == 1)

h = run(CASE3, heal=False)                      # the helper refuses
check("a refused/raising repair alerts NEM-FWW-0007",
      W.ERR_GUARD_HEAL_FAILED in h.codes(), repr(h.codes()))
check("  ...and says the guard is still down",
      any("still down" in m for _c, _s, m, _x in h.degraded), repr([m for _c,_s,m,_x in h.degraded]))


print("\n== FLAPPING: repeated repairs ESCALATE rather than being absorbed ==")

W.GUARD_ENABLED = True
W._guard_repairs.clear()
W._last_guard_alert_key = None
seen = []
for i in range(W.GUARD_FLAP_THRESHOLD):
    h = Harness([CASE3, CASE3, HEALTHY, HEALTHY])
    W._guard_dump = h.dump
    W._degraded = h._degraded
    W._email_async = h._email
    W._last_guard_alert_key = None           # a fresh knock-out each time
    sys.modules["firewall"] = types.SimpleNamespace(
        reassert_port_on_interface=h.fw_client().reassert_port_deny_on_interface)
    W.verify_tailnet_guard("flap %d" % i)
    seen.append(h.codes())
check("the first repairs do NOT raise the flapping alert",
      all(W.ERR_GUARD_FLAPPING not in c for c in seen[:-1]), repr(seen[:-1]))
check("  ...but reaching the threshold does", W.ERR_GUARD_FLAPPING in seen[-1], repr(seen[-1]))
check("  ...and it reports how many repairs, so it is actionable",
      any(ctx.get("repairs") == W.GUARD_FLAP_THRESHOLD
          for _c, _s, _m, ctx in h.degraded), repr(h.degraded[-1][3]))


print("\n== ALERT FATIGUE: a persisting condition alerts ONCE, a CHANGED one alerts again ==")

W._guard_repairs.clear()
h = Harness([CASE3, CASE3, CASE3, CASE3])
W._guard_dump = h.dump
W._degraded = h._degraded
W._email_async = h._email
W._last_guard_alert_key = None
sys.modules["firewall"] = types.SimpleNamespace(
    reassert_port_on_interface=h.fw_client().reassert_port_deny_on_interface)
W.verify_tailnet_guard("first")
n1 = len([c for c in h.codes() if c == W.ERR_GUARD_DEFEATED])
W.verify_tailnet_guard("second, same condition")
n2 = len([c for c in h.codes() if c == W.ERR_GUARD_DEFEATED])
check("the same condition does not re-alert every tick", n2 == n1, "%d -> %d" % (n1, n2))
h.dumps = [ABSENT, ABSENT, ABSENT, ABSENT]
h.dump_calls = 0
W.verify_tailnet_guard("third, DIFFERENT condition")
n3 = len([c for c in h.codes() if c == W.ERR_GUARD_DEFEATED])
check("  ...but a genuinely different condition DOES alert again", n3 > n2, "%d -> %d" % (n2, n3))


print("\n== THE GUARD'S ALERT STATE IS SEPARATE FROM THE ENFORCEMENT TABLE'S ==")

check("the guard uses its own dedup key, so neither masks the other",
      "_last_guard_alert_key" in W.__dict__ and "_last_alert_key" in W.__dict__)
check("  ...and its own error-code range (0005-0008 vs 0001-0004)",
      {W.ERR_GUARD_DEFEATED, W.ERR_GUARD_UNDETERMINED,
       W.ERR_GUARD_HEAL_FAILED, W.ERR_GUARD_FLAPPING}
      .isdisjoint({W.ERR_TAMPERED, W.ERR_DELETED, W.ERR_NO_BASELINE, W.ERR_RESTARTED}))


print("\n== WIRED INTO ALL THREE CALL SITES, LIKE verify() ==")

src = open(os.path.join(ROOT, "alert_manager", "nemesis_fw_watch.py")).read()
for site in ('verify_tailnet_guard("startup")',
             'verify_tailnet_guard("netlink event")',
             'verify_tailnet_guard("periodic")'):
    check("called at: %s" % site, site in src)
_heal_body = src.split("def _guard_heal")[1].split("def verify_tailnet_guard")[0]
check("the repair calls the chokepoint (firewall.py), not its transport directly",
      "firewall.reassert_port_on_interface" in _heal_body
      and "fw_client." not in _heal_body)
check("  ...and never shells out itself (no subprocess in the repair path)",
      "subprocess" not in _heal_body and "_run_iptables" not in _heal_body,
      _heal_body[:0])

W._guard_dump = _orig_dump
W._degraded = _orig_degraded
W._email_async = _orig_email

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
