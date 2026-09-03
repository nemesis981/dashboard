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
EXPECTED_CHECKS = 1 + 7 + N * 5 + N * 2 + 12

print("\n0. catalogue size is asserted, so silent shrinkage fails")
check("catalogue has 25 entries (update this number deliberately, never to match)",
      N == 25, str(N))

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

print("\n%d passed, %d failed" % (_pass, _fail))
if _pass + _fail != EXPECTED_CHECKS:
    print("EXPECTED_CHECKS MISMATCH: declared %d, ran %d"
          % (EXPECTED_CHECKS, _pass + _fail))
    sys.exit(1)
sys.exit(1 if _fail else 0)
