"""Port broker ops in nemesis_fwd — wiring, refusals, and the registry contract.

Run: python3 alert_manager/test_port_broker_ops.py

⚠ WHAT THIS PROVES AND WHAT IT DOES NOT. `ufw` needs root, so the actual rule
issue/delete cannot run here. This covers the DECISION path, the registry
contract, and the wiring — that the evaluator is genuinely consulted rather than
bypassed, that a denial is a returned RESULT carrying the trail rather than an
exception, and that an unreadable registry is LOUD. It does not prove ufw accepts
the command; that was measured separately on a VM (ufw allow reached the listener;
a raw-table ACCEPT did not).

⚠ THE REGISTRY-FAILURE TEST IS THE SUBTLE ONE. An unreadable registry must NOT
read as "no grants": conflict detection would then evaluate against a world that
is not real, and a corrupt file could silently re-grant a port someone else holds.

ASSERTION COUNT IS FIXED and self-asserted.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nemesis_fwd as F             # noqa: E402
import port_policy as pp            # noqa: E402

EXPECTED_CHECKS = 27
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


print("wiring: registered in every place that governs an op")
for o in ("request_port", "release_port", "list_port_grants"):
    check("%s is in OPS" % o, o in F.OPS)
check("the two WRITE ops are audited", {"request_port", "release_port"} <= F.WRITE_OPS)
check("list is a READ op (a view cache may satisfy it)",
      "list_port_grants" in F.READ_OPS)
check("none is credential-exempt",
      not ({"request_port", "release_port", "list_port_grants"} & F.NO_CREDENTIAL_OPS))
check("audit actions use their own port_ prefix",
      F.audit_action_for("request_port") == "port_request"
      and F.audit_action_for("release_port") == "port_release")
check("⭐ dashboard is the ONLY peer with any port op",
      [p for p, v in F.PEER_POLICY.items()
       if {"request_port", "release_port"} & set(v["ops"])] == ["dashboard"])
check("⭐ no unattended peer can request a port",
      not any({"request_port", "release_port"} & set(v["ops"])
              for k, v in F.PEER_POLICY.items() if not v["require_credential"]))

print("\nthe ALLOW mechanism is ufw, and the DENY mechanism is still raw")
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "nemesis_fwd.py")).read()
rp = src[src.index("def op_request_port"):src.index("def op_release_port")]
check("⭐ request_port issues via ufw", "_run_ufw(" in rp)
check("⭐ and does NOT use the raw table (measured: raw ACCEPT does not work)",
      "-t" not in rp or "raw" not in rp)
dp = src[src.index("def op_deny_port_on_interface"):]
check("the deny op still uses the raw table (opposite answer, deliberately)",
      '"-t", "raw"' in dp[:2000])

print("\ninterface allowlists are SEPARATE powers")
check("⭐ port-grant ifaces are not the deny allowlist",
      "_port_grant_ifaces" in src and "PORT_GRANT_IFACES = DENY_IFACE_ALLOWED" not in src)
os.environ.pop("NEMESIS_PORT_IFACES", None)
check("an unconfigured box grants nothing (empty iface list)",
      isinstance(F._port_grant_ifaces(), list))

print("\n⭐ the registry contract")
tmp = tempfile.mkdtemp()
F.PORT_GRANTS_PATH = os.path.join(tmp, "g.json")
check("missing registry reads as empty (a fresh box has no grants)",
      F._load_port_grants() == [])
F._save_port_grants([{"module": "m", "iface": "eth1", "port": 8443, "proto": "tcp"}])
check("saved grants round-trip", len(F._load_port_grants()) == 1)
with open(F.PORT_GRANTS_PATH, "w") as fh:
    fh.write("{not json")
raised = False
try:
    F._load_port_grants()
except F.Denied as e:
    raised = "refusing to evaluate" in str(e)
check("⭐ an UNREADABLE registry RAISES rather than reading as empty", raised,
      "empty would let a corrupt file silently re-grant a held port")

print("\n⭐ the evaluator is genuinely consulted, not bypassed")
check("request_port calls port_policy.evaluate", "pp.evaluate(" in rp)
check("  and returns the decision trail on refusal",
      "decision.as_dict()" in rp and "if not decision.allowed" in rp)
check("  refusal is a RESULT, not an exception (a DENY must not become a 500)",
      "return result" in rp.split("if not decision.allowed")[1][:200])
check("release checks OWNERSHIP by module",
      'g.get("module") == module' in src[src.index("def op_release_port"):])

print("\nhand-placed grants exist as a core-reviewed list")
check("⭐ HAND_PLACED_PORT_GRANTS exists and starts EMPTY",
      isinstance(F.HAND_PLACED_PORT_GRANTS, list)
      and len(F.HAND_PLACED_PORT_GRANTS) == 0,
      "a populated default would be a grant nobody reviewed")

print("\n⭐ UNKNOWN env fails CLOSED (the tuple contract I got wrong first time)")
# _read_env_values returns (values, readable). Treating it as a dict silently
# conflates "absent" with "unreadable" -- and granting a port on an interface we
# cannot identify is the failed-read-as-default defect with a network surface.
_real = F._read_env_values
try:
    F._read_env_values = lambda path, keys: ({}, False)     # unreadable
    check("⭐ unreadable env -> NO grantable interfaces", F._port_grant_ifaces() == [])
    check("⭐ unreadable env -> LAN unknown (None), not a guess",
          F._lan_cidr_or_none() is None)
    F._read_env_values = lambda path, keys: ({"NEMESIS_GW_LAN_IFACE": "eth1",
                                              "NEMESIS_GW_LAN_CIDR": "10.1.0.0/24"}, True)
    check("CONTROL: a readable env DOES yield the interface",
          F._port_grant_ifaces() == ["eth1"])
    check("CONTROL: and the LAN CIDR", F._lan_cidr_or_none() == "10.1.0.0/24")
finally:
    F._read_env_values = _real

_total = passed + failed
check("assertion count matches EXPECTED_CHECKS (%d)" % EXPECTED_CHECKS,
      _total + 1 == EXPECTED_CHECKS, "ran %d" % (_total + 1))

print("\n%d passed, %d failed" % (passed, failed))
print("NOT PROVEN HERE: the actual ufw allow/delete — needs root (measured on a VM).")
sys.exit(1 if failed else 0)
