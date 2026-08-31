"""gateway_switch -- the op that re-roles the box's network stack.

WHAT THIS SUITE IS FOR
    `gateway_switch` turns on IP forwarding and installs a source-NAT rule. It is
    the most consequential op in this helper after the credential-exempt ones, and
    the renderer INTERPOLATES its interface name into the emitted nft ruleset --
    so the validator is a ruleset-injection boundary, not cosmetic input checking.
    Every control that makes it safe is asserted here rather than assumed.

⚠ EVERY BRANCH IS EXERCISED, NOT MERELY REACHABLE
    Per CLAUDE.md (2026-08-24): a new branch needs a test that forces execution
    down that exact path. Each rejection below names the specific input that
    triggers it, and the accept case proves the validator can still say yes -- a
    validator that rejected everything would pass a suite of rejections alone.

ASSERTION COUNT IS FIXED. Every check runs unconditionally; none sits inside a
success-path `if`. A suite whose total shrinks under failure cannot be compared
between runs (CLAUDE.md, 2026-08-29). The expected total is asserted at the end
against a named constant so drift reports itself rather than passing quietly.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "core"))

import nemesis_fwd as F

EXPECTED_CHECKS = 30

passed = failed = 0


def check(label, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s %s" % (label, extra))


def rejects(label, params, expect_kind="bad_request"):
    """Assert the validator REFUSES, and refuses with the right kind."""
    try:
        F._validate_gateway_params(params)
    except F.Denied as exc:
        check(label, getattr(exc, "kind", None) == expect_kind,
              "kind=%r" % getattr(exc, "kind", None))
        return
    check(label, False, "was ACCEPTED but should have been refused")


print("-- registration: the op exists and is wired everywhere it must be --")
check("op is in OPS", "gateway_switch" in F.OPS)
check("op is in WRITE_OPS (so it is AUDITED)", "gateway_switch" in F.WRITE_OPS)
check("op is NOT in READ_OPS (a view cache can never satisfy it)",
      "gateway_switch" not in F.READ_OPS)
check("op is NOT credential-exempt", "gateway_switch" not in F.NO_CREDENTIAL_OPS)
check("audit action is net_gateway_switch",
      F.audit_action_for("gateway_switch") == "net_gateway_switch")
check("dashboard peer MAY invoke it",
      "gateway_switch" in F.PEER_POLICY["dashboard"]["ops"])
check("dashboard peer requires a credential",
      F.PEER_POLICY["dashboard"]["require_credential"] is True)
_granted = [p for p, v in F.PEER_POLICY.items() if "gateway_switch" in v["ops"]]
check("NO unattended peer has it -- dashboard alone", _granted == ["dashboard"],
      "granted to %r" % (_granted,))

print("\n-- validator REFUSES every malformed shape --")
rejects("enable missing is refused", {})
rejects("enable as a string is refused", {"enable": "true"})
rejects("enable as an int is refused", {"enable": 1})
rejects("enabling with no iface is refused", {"enable": True, "cidr": "10.88.1.0/24"})
rejects("enabling with no cidr is refused", {"enable": True, "iface": "lo"})

print("\n-- ⭐ ruleset-injection shapes are refused BEFORE reaching the renderer --")
for bad in ('lo; rm -rf /', 'lo"', "lo'", "lo\nx", "lo $(id)", "lo`id`", "-lo",
            "l" * 16):
    rejects("iface %r refused" % bad, {"enable": True, "iface": bad,
                                       "cidr": "10.88.1.0/24"})

print("\n-- CIDR rules --")
rejects("non-private CIDR refused (we do not own it)",
        {"enable": True, "iface": "lo", "cidr": "8.8.8.0/24"})
rejects("IPv6 CIDR refused", {"enable": True, "iface": "lo", "cidr": "fd00::/64"})
rejects("unparseable CIDR refused",
        {"enable": True, "iface": "lo", "cidr": "not-a-network"})
rejects("non-canonical CIDR refused (host bits set)",
        {"enable": True, "iface": "lo", "cidr": "10.88.1.5/24"})
rejects("interface that does not exist on THIS box is refused",
        {"enable": True, "iface": "nosuchif0", "cidr": "10.88.1.0/24"})

print("\n-- ⭐ CONTROL: the validator can still say YES --")
# Without this the whole suite could pass against a validator that refuses
# everything, which would be a validator that cannot fail rather than one that works.
_ok = F._validate_gateway_params({"enable": True, "iface": "lo",
                                  "cidr": "10.88.1.0/24"})
check("a well-formed enable is ACCEPTED", _ok == (True, "lo", "10.88.1.0/24"),
      "got %r" % (_ok,))
_off = F._validate_gateway_params({"enable": False})
check("disable needs no iface/cidr", _off == (False, None, None), "got %r" % (_off,))

print("\n-- executor rejects an unknown verb rather than silently succeeding --")
check("_gw_run refuses an unknown verb", F._gw_run(("bogus_verb", None, None)) is False)

print("\n-- the suite asserts its OWN size, so silent drift is impossible --")
_total = passed + failed
check("assertion count matches EXPECTED_CHECKS (%d)" % EXPECTED_CHECKS,
      _total + 1 == EXPECTED_CHECKS, "ran %d" % (_total + 1))

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
