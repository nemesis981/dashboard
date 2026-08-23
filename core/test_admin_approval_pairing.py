#!/usr/bin/env python3
"""Conformance for Admin Approval Protocol v1 §5 (registration / pairing).

The load-bearing test here is the DEADLOCK one: registering the first
authenticator on a fresh appliance must not require a companion approval, because
no companion exists yet. That is asserted structurally -- by the absence of any
approval dependency -- not just behaviourally, because a behavioural test passes
right up until someone adds a uniform "all admin actions need approval" rule.
"""
import ast
import hashlib
import inspect
import sys

sys.path.insert(0, "/opt/nemesis")

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import serialization

from core.admin_approval import (COSE_ES256, COSE_EDDSA, MODE_WEBAUTHN, MODE_NATIVE)
from core import admin_approval_pairing as pairing
from core.admin_approval_pairing import (
    build_registration, can_unlock, active_authenticators, PairingError,
    MIN_AUTHENTICATORS_FOR_UNLOCK)

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


RP_HASH = hashlib.sha256(b"nemesis.local").digest()


def es_key():
    p = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    return {1: 2, 3: COSE_ES256, -1: 1,
            -2: p.x.to_bytes(32, "big"), -3: p.y.to_bytes(32, "big")}


def ed_key():
    raw = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {1: 1, 3: COSE_EDDSA, -1: 6, -2: raw}


# ═══════════════════════════════════════════════════════════════════════════
print("\n== §5 DEADLOCK: first pairing must NOT require a companion approval ==")

# Behavioural: on a fresh appliance, with NO authenticators registered, the first
# registration succeeds.
first = build_registration(authenticator_id="auth-1", user_id="admin-1",
                           mode=MODE_WEBAUTHN, cose_alg=COSE_ES256,
                           public_key=es_key(), rp_id_hash=RP_HASH, now=1000)
check("first registration on a fresh appliance SUCCEEDS", first["authenticator_id"] == "auth-1")
check("  ...with zero authenticators previously registered",
      len(active_authenticators([])) == 0)

# STRUCTURAL: there is nothing to call. A behavioural test alone would keep passing
# until someone applied an "all admin actions need approval" rule uniformly, which
# is exactly how this deadlock gets introduced.
sig = inspect.signature(build_registration)
check("build_registration takes NO approval parameter",
      not any("approval" in p or "approve" in p for p in sig.parameters))

src = open(pairing.__file__, encoding="utf-8").read()
tree = ast.parse(src)
imported = set()
for n in ast.walk(tree):
    if isinstance(n, ast.ImportFrom) and n.module:
        for a in n.names:
            imported.add("%s.%s" % (n.module, a.name))
    elif isinstance(n, ast.Import):
        for a in n.names:
            imported.add(a.name)
check("module never imports verify_approval",
      not any("verify_approval" in i for i in imported), str(sorted(imported)))
check("module body contains no call to an approval gate",
      "verify_approval(" not in src and "require_approval" not in src)
# CONTROL: the scanner can see the imports it does have, so the absence above is
# a real finding rather than a scanner that found nothing.
check("CONTROL: the import scan does see real imports",
      any("admin_approval" in i for i in imported), str(sorted(imported)))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== §5: the two-authenticator floor for UNLOCKING ==")

one = [first]
d = can_unlock(one)
check("ONE authenticator: unlock REFUSED", not d.allowed)
check("  ...and says how many are needed", d.need == MIN_AUTHENTICATORS_FOR_UNLOCK and d.have == 1)
check("  ...with a reason, not a bare boolean", isinstance(d.reason, str) and d.reason)

second = build_registration(authenticator_id="auth-2", user_id="admin-1",
                            mode=MODE_NATIVE, cose_alg=COSE_EDDSA,
                            public_key=ed_key(), now=1001)
two = [first, second]
check("TWO authenticators: unlock ALLOWED", can_unlock(two).allowed)

# Revocation must drop it back below the floor -- otherwise "active" is decorative.
revoked = dict(second, revoked=True)
check("revoking one drops back below the floor",
      not can_unlock([first, revoked]).allowed)
check("  ...and the count reflects only ACTIVE ones",
      can_unlock([first, revoked]).have == 1)

# Per-user scoping: two authenticators belonging to different admins must not
# satisfy one admin's floor.
other_user = build_registration(authenticator_id="auth-3", user_id="admin-2",
                                mode=MODE_NATIVE, cose_alg=COSE_EDDSA,
                                public_key=ed_key(), now=1002)
check("two authenticators owned by DIFFERENT users do not satisfy one user's floor",
      not can_unlock([first, other_user], user_id="admin-1").allowed)
check("CONTROL: unscoped, the same two do pass the raw count",
      can_unlock([first, other_user]).allowed)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== §5: record validation ==")

req = dict(authenticator_id="a", user_id="u", mode=MODE_WEBAUTHN,
           cose_alg=COSE_ES256, public_key=es_key(), rp_id_hash=RP_HASH)
for bad, why in (
        (dict(authenticator_id=""), "empty authenticator_id"),
        (dict(user_id=""), "empty user_id"),
        (dict(mode=99), "unknown mode"),
        (dict(cose_alg=-999), "unsupported algorithm"),
        (dict(public_key={1: 99}), "unusable COSE_Key"),
        (dict(rp_id_hash=None), "WEBAUTHN without rp_id_hash"),
        (dict(rp_id_hash=b"short"), "malformed rp_id_hash"),
):
    try:
        build_registration(**dict(req, **bad))
        check("rejects %s" % why, False, "accepted")
    except PairingError:
        check("rejects %s" % why, True)

try:
    build_registration(authenticator_id="a", user_id="u", mode=MODE_NATIVE,
                       cose_alg=COSE_EDDSA, public_key=ed_key(), rp_id_hash=RP_HASH)
    check("rejects rp_id_hash on a NATIVE authenticator", False, "accepted")
except PairingError:
    check("rejects rp_id_hash on a NATIVE authenticator (meaningless there)", True)

r = build_registration(**req, now=1234)
for f in ("authenticator_id", "user_id", "mode", "cose_alg", "public_key",
          "sign_count", "rp_id_hash", "registered_at"):
    check("record stores %s (spec §5 table)" % f, f in r)
check("sign_count starts at 0", r["sign_count"] == 0)
check("registered_at is an int Unix timestamp, never a string",
      isinstance(r["registered_at"], int))

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
