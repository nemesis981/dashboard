"""Port-request policy evaluator — every check, both directions.

Run: python3 alert_manager/test_port_policy.py

⚠ EVERY REFUSAL IS PAIRED WITH A GRANT. An evaluator that refused everything would
satisfy every negative test here while being useless, and one that granted
everything is worse. The control cases are not padding — they are what make the
refusals mean something.

⚠ THE CHECK COUNT MUST NOT VARY WITH INPUT. The decision trail IS the audit
record; a trail that shrinks under malformed input cannot be compared against a
good one, and the missing checks would vanish silently rather than fail. Asserted
directly.

⚠ THE TIER GATE IS TESTED SEPARATELY FROM POLICY. A third-party request that
passes every policy check must still not be granted -- that is the doctrine, not a
side effect, and conflating the two would let a future refactor collapse them.

ASSERTION COUNT IS FIXED and self-asserted.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import port_policy as pp            # noqa: E402

EXPECTED_CHECKS = 41
passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    ok = bool(cond)
    print(("  [PASS] " if ok else "  [FAIL] ") + name
          + ("" if ok or not detail else "  (%s)" % detail))
    if ok:
        passed += 1
    else:
        failed += 1


ST = {"allowed_ifaces": ["eth1"], "lan_cidr": "192.168.10.0/24"}


def req(**kw):
    base = dict(module="core.gate", tier=pp.TIER_FIRST_PARTY, port=8443,
                iface="eth1", source_cidr="192.168.10.0/24", peer="dashboard")
    base.update(kw)
    return pp.Request(**base)


def ev(state=None, **kw):
    return pp.evaluate(req(**kw), state if state is not None else ST)


def refused_by(name, state=None, **kw):
    d = ev(state, **kw)
    return (not d.allowed) and name in d.refusals


print("⭐ CONTROL: the evaluator can say YES")
d = ev()
check("⭐ a well-formed first-party request is GRANTED", d.allowed, d.refusals)
check("  and no check refused", d.policy_passed)
check("  the decision carries the full trail", len(d.checks) == 16, len(d.checks))
check("  summary reads as a grant", d.summary().startswith("GRANT:"))

print("\nidentity and authority")
check("unattended peer refused", refused_by("peer_allowed", peer="alert-watcher"))
check("unknown peer refused", refused_by("peer_allowed", peer="nobody"))
check("no peer refused", refused_by("peer_allowed", peer=None))
check("unknown tier refused", refused_by("tier_known", tier="trusted"))
check("unnamed module refused", refused_by("module_named", module="  "))

print("\nthe port itself")
check("⭐ SSH (22) refused even to first-party",
      refused_by("port_not_denylisted", port=22))
check("⭐ DNS (53) refused", refused_by("port_not_denylisted", port=53))
check("⭐ the dashboard's own port refused",
      refused_by("port_not_denylisted", port=5000))
check("SMB (445) refused", refused_by("port_not_denylisted", port=445))
check("privileged port refused", refused_by("port_not_privileged", port=443))
check("⭐ ephemeral-range port refused", refused_by("port_not_ephemeral", port=40000))
check("out-of-range port refused", refused_by("port_in_range", port=70000))
check("⭐ a RANGE is refused outright", refused_by("port_is_single_int", port="8000-9000"))
check("a bool is not a port (bool subclasses int)",
      refused_by("port_is_single_int", port=True))
check("unknown proto refused", refused_by("proto_known", proto="sctp"))

print("\nscope")
check("un-allowlisted iface refused", refused_by("iface_allowed", iface="eth0"))
check("⭐ unconfigured broker grants nothing",
      refused_by("iface_allowed", state={"lan_cidr": "192.168.10.0/24"}))
check("missing source CIDR refused", refused_by("source_cidr_present", source_cidr=None))
check("unparseable source CIDR refused",
      refused_by("source_cidr_parses", source_cidr="not-a-network"))
check("⭐ source outside the gateway LAN refused",
      refused_by("source_within_lan", source_cidr="10.0.0.0/8"))
check("⭐ absent LAN config is a REFUSAL, not permission",
      refused_by("source_within_lan", state={"allowed_ifaces": ["eth1"]}))
check("an in-LAN subrange is accepted", ev(source_cidr="192.168.10.0/28").allowed)

print("\nconflict detection")
check("⭐ conflicts with an existing chokepoint DENY",
      refused_by("no_conflicting_deny",
                 state=dict(ST, existing_denies=[("eth1", 8443, "tcp")])))
check("a deny on a DIFFERENT port does not block",
      ev(state=dict(ST, existing_denies=[("eth1", 9999, "tcp")])).allowed)
check("⭐ refuses a port already owned by another module",
      refused_by("no_other_owner",
                 state=dict(ST, existing_grants=[
                     {"module": "other", "iface": "eth1", "port": 8443, "proto": "tcp"}])))
d2 = ev(state=dict(ST, existing_grants=[
    {"module": "core.gate", "iface": "eth1", "port": 8443, "proto": "tcp"}]))
check("re-issuing one's OWN grant is idempotent, not refused", d2.allowed)
check("  and the trail says it was already held",
      any(n == "idempotent_reissue" and "already held" in det
          for n, _o, det in d2.checks))

print("\n⭐ THE TIER GATE — doctrine, tested independently of policy")
t = ev(tier=pp.TIER_THIRD_PARTY)
check("⭐ third-party PASSES policy", t.policy_passed, t.refusals)
check("⭐ but is NOT granted", not t.allowed)
check("  and says a hand-placed grant is required", t.requires_hand_placed_grant)
check("  summary states it plainly", "HAND-PLACED" in t.summary())
hp = ev(tier=pp.TIER_THIRD_PARTY,
        state=dict(ST, hand_placed=[{"module": "core.gate", "iface": "eth1",
                                     "port": 8443, "proto": "tcp"}]))
check("⭐ WITH a core-reviewed hand-placed grant it IS granted", hp.allowed)
check("a third-party request that FAILS policy is refused regardless of any grant",
      not ev(tier=pp.TIER_THIRD_PARTY, port=22,
             state=dict(ST, hand_placed=[{"module": "core.gate", "iface": "eth1",
                                          "port": 22, "proto": "tcp"}])).allowed)

print("\nthe trail is stable and the evaluator never raises")
check("⭐ check count is identical for a grant and a refusal",
      len(ev().checks) == len(ev(port=22).checks) == len(ev(port="range").checks))
for bad in (dict(port=None), dict(iface=None), dict(source_cidr=[]),
            dict(module=None), dict(proto=None)):
    try:
        ev(**bad)
    except Exception as exc:                                 # noqa: BLE001
        check("malformed input %r did not raise" % bad, False, repr(exc))
        break
else:
    check("malformed inputs never raise (a DENY must not become a 500)", True)
check("selftest passes (known-good AND known-bad)", pp.selftest()[0])

_total = passed + failed
check("assertion count matches EXPECTED_CHECKS (%d)" % EXPECTED_CHECKS,
      _total + 1 == EXPECTED_CHECKS, "ran %d" % (_total + 1))

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
