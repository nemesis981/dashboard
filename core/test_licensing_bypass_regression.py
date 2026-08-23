#!/usr/bin/env python3
"""Regression: the three licensing bypasses found on 2026-08-23 stay closed.

Each test performs the ACTUAL EXPLOIT as it was originally demonstrated, and
asserts it now fails. Asserting "the env var is gone" would be weaker and would
not notice if the value came back through some other runtime input.

  1. FORGED LICENCE. `PUBLIC_KEY_B64` read NEMESIS_LICENSE_PUBKEY, so the
     VERIFICATION key was caller-controlled. Exploit: generate a keypair, export
     the variable, self-sign {"tier":"commercial"} -> verdict=valid,
     tier=commercial. No source access, no patching.
  2. INFLATED CAP. `FREE_TIER_REMOTE_CAP` read NEMESIS_FREE_REMOTE_CAP.
     Exploit: NEMESIS_FREE_REMOTE_CAP=999999.
  3. UNMETERED GRANT. An unreconcilable census while online returned
     ALLOW_UNVERIFIED, which PERMITTED. Exploit: break the census, grant freely.

Every test is paired with a CONTROL proving the mechanism still works for the
legitimate case -- otherwise "the attack failed" would be indistinguishable from
"nothing works at all".

No network. No live DB.
"""
import base64
import importlib
import os
import sys
import time

sys.path.insert(0, "/opt/nemesis")

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _attacker_keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)
    return priv, _b64u(pub)


def _mint(lk, priv, tier="commercial"):
    payload = {"tier": tier, "iss": "attacker", "sub": "forged",
               "install_id": "ANY", "exp": int(time.time()) + 10 ** 7}
    raw = lk.encode_payload(payload)
    return "NEMLIC1.%s.%s" % (_b64u(raw), _b64u(priv.sign(raw)))


# ═══════════════════════════════════════════════════════════════════════
print("\n== 1. FORGED LICENCE via NEMESIS_LICENSE_PUBKEY ==")

priv, pub_b64 = _attacker_keypair()
os.environ["NEMESIS_LICENSE_PUBKEY"] = pub_b64
try:
    import core.license_key as lk
    importlib.reload(lk)                      # a fresh import must not pick it up
    check("the env var does NOT become the verification key",
          lk.PUBLIC_KEY_B64 != pub_b64, "pubkey is attacker-controlled!")

    forged = _mint(lk, priv)
    res = lk.verify(forged)
    check("a self-signed 'commercial' licence is REFUSED", not res.valid,
          "verdict=%s tier=%s" % (res.verdict,
                                  (res.payload or {}).get("tier")))
    check("  ...and the verdict names it a bad signature",
          res.verdict == lk.Verdict.BAD_SIGNATURE, res.verdict)
finally:
    os.environ.pop("NEMESIS_LICENSE_PUBKEY", None)
    importlib.reload(lk)

# CONTROL: verification is not simply broken -- a key signed by the key the
# verifier actually trusts still validates. Monkeypatching the attribute is the
# supported test seam; it exists in-process only.
_real = lk.PUBLIC_KEY_B64
try:
    lk.PUBLIC_KEY_B64 = pub_b64               # trust the attacker key ON PURPOSE
    res = lk.verify(_mint(lk, priv))
    check("CONTROL: a key signed by the TRUSTED issuer still validates", res.valid,
          "verdict=%s" % res.verdict)
finally:
    lk.PUBLIC_KEY_B64 = _real

check("the shipped key is a real key, not the build placeholder",
      lk.PUBLIC_KEY_B64 and lk.PUBLIC_KEY_B64 != lk._PLACEHOLDER)


# ═══════════════════════════════════════════════════════════════════════
print("\n== 2. INFLATED CAP via NEMESIS_FREE_REMOTE_CAP ==")

os.environ["NEMESIS_FREE_REMOTE_CAP"] = "999999"
try:
    import core.entitlements as ent
    importlib.reload(ent)
    check("the env var does NOT raise the free cap",
          ent.FREE_TIER_REMOTE_CAP == 5,
          "cap=%r" % ent.FREE_TIER_REMOTE_CAP)
finally:
    os.environ.pop("NEMESIS_FREE_REMOTE_CAP", None)
    importlib.reload(ent)

check("CONTROL: the cap is still readable and is the documented value",
      ent.FREE_TIER_REMOTE_CAP == 5, repr(ent.FREE_TIER_REMOTE_CAP))
# Source-level backstop: the exact reads are gone from LIVE code. Comment lines
# still mention the variable names deliberately -- the history is why the values
# are compiled in -- so only non-comment lines are inspected.
def _live_lines(path):
    return [l for l in open(path, encoding="utf-8").read().split("\n")
            if not l.lstrip().startswith("#")]


check("license_key.py has no live os.environ read",
      not any("os.environ" in l for l in _live_lines("/opt/nemesis/core/license_key.py")))
check("entitlements.py never reads NEMESIS_FREE_REMOTE_CAP",
      not any("NEMESIS_FREE_REMOTE_CAP" in l
              for l in _live_lines("/opt/nemesis/core/entitlements.py")))


# ═══════════════════════════════════════════════════════════════════════
print("\n== 3. UNMETERED GRANT when the census cannot be reconciled ==")

import core.cap_guard as cg
importlib.reload(cg)

check("ALLOW is the ONLY permitting state",
      cg.PERMITTING_STATES == (cg.ALLOW,), repr(cg.PERMITTING_STATES))
check("the old permit-on-doubt state no longer exists",
      not hasattr(cg, "ALLOW_UNVERIFIED"))
check("an unverified census is a REFUSAL",
      cg.REFUSE_UNVERIFIED not in cg.PERMITTING_STATES)

# Every state must be classified, so a new one cannot default to permitting.
for st in cg.ALL_STATES:
    d = cg.Decision(st, used=1, limit=5, reason="test")
    permits = d.permitted
    check("state %-22s -> %s" % (st, "PERMIT" if permits else "refuse"),
          permits == (st == cg.ALLOW))

# A refusal must never render as a grant -- the defect the docstring warns about.
for st in cg.ALL_STATES:
    if st == cg.ALLOW:
        continue
    msg = cg.Decision(st, used=1, limit=5, reason="test").user_message().lower()
    # "cannot be granted" is a refusal that legitimately contains the word, so
    # match the CLAIM ("remote access granted"), not the bare word. A naive
    # substring check flagged a correct message -- the test was wrong, not the
    # wording, and this is the kind of near-miss matcher this repo keeps finding.
    check("%-22s message does not CLAIM a grant" % st,
          "access granted" not in msg, msg[:70])
    check("  %-20s ...and reads as a refusal" % st,
          any(w in msg for w in ("cannot", "no internet", "used all",
                                 "not be granted", "try again")), msg[:70])

# CONTROL: an ALLOW still reads as a grant, so the check above is measuring
# wording rather than just finding the word absent everywhere.
check("CONTROL: ALLOW's message DOES claim a grant",
      "access granted" in cg.Decision(cg.ALLOW, used=1, limit=5).user_message().lower())

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
