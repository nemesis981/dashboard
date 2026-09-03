#!/usr/bin/env python3
"""port_risk.assess -- the judgment layer over the v1 exposure collector.

The property that matters most is NOT "does it flag Telnet". It is that the two
verdict kinds stay separable: a BASIS_PROTOCOL finding is a statement of fact about
the protocol, a BASIS_EXPOSURE finding is a question that needs device purpose to
answer. A classifier that merged them would either cry wolf about every database
server or excuse Telnet, and both look like "it works" on a host that runs neither.

Every catalogue entry is therefore driven through all five exposure classes, rather
than spot-checking a few -- the whole point of the exercise is that a clean host and
a too-narrow list are indistinguishable from a single sample.

Run: python3 alert_manager/test_port_risk.py
"""
import os
import sys

ROOT = os.environ.get("NEMESIS_ROOT", "/opt/nemesis")
sys.path.insert(0, os.path.join(ROOT, "alert_manager"))

import port_risk as R                                              # noqa: E402

_pass = _fail = 0

#: The appliance's own device record: it IS us, and it legitimately runs the resolver.
APPLIANCE = {"is_appliance": True, "roles": ("dns_resolver",)}


_RAISED = object()


def safe(fn):
    """Call fn, converting an exception into a sentinel.

    Without this, a mutation that makes assess() raise ABORTS the run: exit is
    non-zero but zero checks report FAIL and the EXPECTED_CHECKS guard never runs,
    so a crash is indistinguishable from a suite that simply ended early. Observed
    live while mutation-testing this file (M10, dropping the non-dict guard).
    """
    try:
        return fn()
    except Exception:
        return _RAISED


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


N = len(R.CATALOGUE)
# 1 (size) + 7 (drift) + N*5 (exposure matrix) + N*2 (finding shape) + 12 (edges)
EXPECTED_CHECKS = 1 + 7 + N * 5 + N * 2 + 12 + 4 + 15

print("\n0. catalogue size is asserted, so silent shrinkage fails")
check("catalogue has 28 entries (update this number deliberately, never to match)",
      N == 28, str(N))

# ── 1. wire-constant drift against the AGENT module ──────────────────────────
# The server duplicates these strings rather than importing the agent package.
# That is a deliberate boundary, so this is the check that keeps it honest.
print("\n1. wire constants agree with the agent collector")
sys.path.insert(0, os.path.join(ROOT, "nemesis_agent", "modules"))
import listening_ports as L                                        # noqa: E402

for name in ("EXPOSURE_LOOPBACK", "EXPOSURE_ALL", "EXPOSURE_SPECIFIC",
             "EXPOSURE_MULTICAST", "EXPOSURE_UNKNOWN", "ATTR_OK", "ATTR_DENIED"):
    check("%s matches the agent's value" % name,
          getattr(R, name) == getattr(L, name),
          "server=%r agent=%r" % (getattr(R, name, None), getattr(L, name, None)))

# ── 2. the exposure matrix: every entry x every exposure class ───────────────
print("\n2. every catalogue entry, across all five exposure classes")

REACHABLE = (R.EXPOSURE_ALL, R.EXPOSURE_SPECIFIC)
for (port, proto), (service, risk, basis, _why) in sorted(R.CATALOGUE.items()):
    ev = lambda exp: {"port": port, "proto": proto, "exposure": exp,
                      "process": "svc", "attribution": R.ATTR_OK}

    fires_all = R.assess(ev(R.EXPOSURE_ALL))
    fires_spec = R.assess(ev(R.EXPOSURE_SPECIFIC))
    quiet_lo = R.assess(ev(R.EXPOSURE_LOOPBACK))
    quiet_mc = R.assess(ev(R.EXPOSURE_MULTICAST))
    unknown = R.assess(ev(R.EXPOSURE_UNKNOWN))

    check("%d/%s %s: fires when bound to all interfaces" % (port, proto, service),
          fires_all is not None and fires_all["risk"] == risk, repr(fires_all))
    check("%d/%s: fires when bound to a specific reachable address" % (port, proto),
          fires_spec is not None, repr(fires_spec))
    check("%d/%s: SILENT on loopback (not reachable off-host)" % (port, proto),
          quiet_lo is None, repr(quiet_lo))
    check("%d/%s: SILENT on a multicast group join" % (port, proto),
          quiet_mc is None, repr(quiet_mc))
    check("%d/%s: UNKNOWN exposure is a finding, not silence" % (port, proto),
          unknown is not None and unknown["basis"] == R.BASIS_UNDETERMINED,
          repr(unknown))

# ── 3. finding shape and the protocol/exposure split ─────────────────────────
print("\n3. the two verdict kinds stay separable")

for (port, proto), (service, risk, basis, _why) in sorted(R.CATALOGUE.items()):
    f = R.assess({"port": port, "proto": proto, "exposure": R.EXPOSURE_ALL,
                  "process": "svc", "attribution": R.ATTR_OK})
    check("%d/%s carries its declared basis (%s)" % (port, proto, basis),
          f is not None and f["basis"] == basis, repr(f))
    # A BASIS_EXPOSURE finding is a QUESTION; a BASIS_PROTOCOL finding is a VERDICT.
    check("%d/%s needs_operator_intent is %s" % (port, proto,
                                                 basis == R.BASIS_EXPOSURE),
          f is not None and f["needs_operator_intent"] == (basis == R.BASIS_EXPOSURE),
          repr(f))

# ── 4. edges ─────────────────────────────────────────────────────────────────
print("\n4. edges and malformed input")

check("an uncatalogued high port is silent even bound to all interfaces",
      R.assess({"port": 51234, "proto": "tcp", "exposure": R.EXPOSURE_ALL}) is None)
check("a catalogued port on the WRONG proto is silent (69 is udp, not tcp)",
      R.assess({"port": 69, "proto": "tcp", "exposure": R.EXPOSURE_ALL}) is None)
check("  ...and fires on its real proto",
      R.assess({"port": 69, "proto": "udp", "exposure": R.EXPOSURE_ALL}) is not None)
check("proto is matched case-insensitively",
      R.assess({"port": 23, "proto": "TCP", "exposure": R.EXPOSURE_ALL}) is not None)
check("non-dict input returns None, does not raise", R.assess(None) is None)
check("missing port returns None", R.assess({"proto": "tcp"}) is None)
check("a string port is rejected, not coerced",
      R.assess({"port": "23", "proto": "tcp", "exposure": R.EXPOSURE_ALL}) is None)
check("empty exposure is NOT treated as loopback/safe",
      R.assess({"port": 23, "proto": "tcp", "exposure": ""}) is not None)

f = R.assess({"port": 3306, "proto": "tcp", "exposure": R.EXPOSURE_ALL,
              "process": "", "attribution": R.ATTR_DENIED})
check("an unattributed owner is carried explicitly, never blanked",
      f is not None and f["attribution"] == R.ATTR_DENIED and f["process"] == "",
      repr(f))
check("  ...and a missing attribution field defaults to unattributed, not ok",
      R.assess({"port": 3306, "proto": "tcp",
                "exposure": R.EXPOSURE_ALL})["attribution"] == R.ATTR_DENIED)

check("selftest passes on the real catalogue", R.selftest() is True)

# The selftest must be able to FAIL -- an always-true canary proves nothing.
_saved = R.CATALOGUE.pop((23, "tcp"))
try:
    R.selftest()
    _detected = False
except AssertionError:
    _detected = True
finally:
    R.CATALOGUE[(23, "tcp")] = _saved
check("selftest DETECTS a gutted catalogue (it can fail, so passing means something)",
      _detected)

# ── 5. SSH: info level, and DELIBERATELY not suppressed ──────────────────────
print("\n5. SSH (22/tcp) is info-level and carries no suppression logic")

ssh = R.assess({"port": 22, "proto": "tcp", "exposure": R.EXPOSURE_ALL,
                "process": "sshd", "attribution": R.ATTR_OK})
check("22/tcp fires when exposed", ssh is not None, repr(ssh))
check("  ...at info level, not high/medium",
      ssh is not None and ssh["risk"] == R.RISK_INFO, repr(ssh))
check("  ...as a question, not an accusation",
      ssh is not None and ssh["needs_operator_intent"] is True, repr(ssh))
# The whole point of SSH needing no suppression: it is correct at ANY privilege,
# including on the appliance itself, where attribution is 0% for privileged ports.
check("  ...and is NOT suppressed on the appliance (no role explains 22)",
      R.assess({"port": 22, "proto": "tcp", "exposure": R.EXPOSURE_ALL},
               context=APPLIANCE) is not None)

# ── 6. device-scoped suppression for DNS ─────────────────────────────────────
print("\n6. DNS suppression is DEVICE-scoped, narrow, and fails closed")

dns_ev = lambda proto: {"port": 53, "proto": proto, "exposure": R.EXPOSURE_ALL,
                        "process": "", "attribution": R.ATTR_DENIED}

check("53/tcp fires with NO context (an unknown device is not the appliance)",
      R.assess(dns_ev("tcp")) is not None)
check("53/udp fires with NO context", R.assess(dns_ev("udp")) is not None)
check("  ...at high risk -- an open resolver is an amplification vector",
      R.assess(dns_ev("udp"))["risk"] == R.RISK_HIGH)
check("53/tcp SUPPRESSED on the appliance running the resolver role",
      R.assess(dns_ev("tcp"), context=APPLIANCE) is None)
check("53/udp SUPPRESSED on the appliance running the resolver role",
      R.assess(dns_ev("udp"), context=APPLIANCE) is None)

# Narrowness: the appliance is not blanket-exempt.
check("3306 on the SAME appliance still fires (not a blanket exemption)",
      R.assess({"port": 3306, "proto": "tcp", "exposure": R.EXPOSURE_ALL},
               context=APPLIANCE) is not None)
check("23/tcp Telnet on the appliance still fires",
      R.assess({"port": 23, "proto": "tcp", "exposure": R.EXPOSURE_ALL},
               context=APPLIANCE) is not None)

# Fail-closed: every way of not-being-the-known-appliance must still fire.
check("a NON-appliance device with the resolver role still fires",
      R.assess(dns_ev("udp"),
               context={"is_appliance": False,
                        "roles": (R.ROLE_DNS_RESOLVER,)}) is not None)
check("the appliance WITHOUT the resolver role still fires",
      R.assess(dns_ev("udp"),
               context={"is_appliance": True, "roles": ()}) is not None)
check("an empty context dict still fires", R.assess(dns_ev("udp"), context={}) is not None)
_mal = safe(lambda: R.assess(dns_ev("udp"), context="appliance"))
check("a malformed (non-dict) context still fires, does not raise",
      _mal is not _RAISED and _mal is not None,
      "raised" if _mal is _RAISED else repr(_mal))
check("an unknown role name does not suppress",
      R.assess(dns_ev("udp"),
               context={"is_appliance": True, "roles": ("nonsense",)}) is not None)

# The predicate is public so the suppression surface can be enumerated/audited --
# a suppression nobody can list cannot be reviewed.
# The deliberate ordering: device expectation is checked BEFORE the exposure class,
# so an unparseable bind address on the appliance's own resolver port does not
# manufacture a self-alert. This is the branch that documents that choice.
check("UNKNOWN exposure on the appliance's own resolver port is still suppressed",
      R.assess({"port": 53, "proto": "udp", "exposure": R.EXPOSURE_UNKNOWN},
               context=APPLIANCE) is None)
check("device_expects() is public and agrees with assess()",
      R.device_expects(53, "udp", APPLIANCE) is True
      and R.device_expects(3306, "tcp", APPLIANCE) is False)
check("  ...and the role->ports map is narrow (resolver explains ONLY 53)",
      R.APPLIANCE_ROLE_PORTS[R.ROLE_DNS_RESOLVER]
      == frozenset({(53, "tcp"), (53, "udp")}),
      repr(R.APPLIANCE_ROLE_PORTS))


print("\n%d passed, %d failed" % (_pass, _fail))
if _pass + _fail != EXPECTED_CHECKS:
    print("EXPECTED_CHECKS MISMATCH: declared %d, ran %d"
          % (EXPECTED_CHECKS, _pass + _fail))
    sys.exit(1)
sys.exit(1 if _fail else 0)
