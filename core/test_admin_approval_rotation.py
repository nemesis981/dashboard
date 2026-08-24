#!/usr/bin/env python3
"""Admin-key rotation — authorized by the OUTGOING key (ADR 0026 §D3).

THE NEGATIVES ARE THE POINT. Rotation is the operation an attacker most wants:
add my phone, or retire yours. Each check below exists because skipping it hands
that over.

  * bootstrap CLOSES BY ITSELF at the two-device floor, and revoking back down
    does NOT reopen it -- otherwise revoke-then-add is an unapproved way in;
  * an approval is bound to the exact key fingerprint AND operation, so an
    approval to add phone-B cannot add phone-C or revoke phone-A;
  * the approving signer is resolved from the TABLE, never taken from the caller;
  * an approval carrying a different capability cannot re-key the admin set;
  * the last active authenticator cannot be revoked -- an empty set is
    unrecoverable by design.

Run: python3 core/test_admin_approval_rotation.py
"""
import hashlib
import json
import os
import sqlite3
import struct
import sys
import tempfile

sys.path.insert(0, "/opt/nemesis")

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from core import admin_approval as aap
from core import admin_approval_authenticators as store
from core import admin_approval_rotation as rot
from core.admin_approval_pairing import MIN_AUTHENTICATORS_FOR_UNLOCK, build_registration
from core.admin_approval_store import create_request, init_admin_approval_tables

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


def raises(fn, exc=rot.RotationError):
    try:
        fn()
    except exc:
        return True
    except Exception:                                              # noqa: BLE001
        return False
    return False


RP_ID = "nemesis.local"
RP_ID_HASH = hashlib.sha256(RP_ID.encode()).digest()
NOW = 1_700_000_000


def fresh():
    path = os.path.join(tempfile.mkdtemp(prefix="arot-"), "t.db")
    conn = sqlite3.connect(path)
    store.init_authenticator_tables(conn)
    init_admin_approval_tables(conn)
    return conn


def cose_of(priv):
    n = priv.public_key().public_numbers()
    return {1: 2, 3: aap.COSE_ES256, -1: 1,
            -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}


def reg(auth_id, priv=None):
    priv = priv or ec.generate_private_key(ec.SECP256R1())
    return priv, build_registration(
        authenticator_id=auth_id, user_id="admin-1", mode=aap.MODE_WEBAUTHN,
        cose_alg=aap.COSE_ES256, public_key=cose_of(priv), rp_id_hash=RP_ID_HASH,
        now=NOW)


def approval(conn, priv, signer_id, *, op, target_id, key_fp,
             capability=rot.CAPABILITY):
    """Create a real request for this rotation and sign it as `signer_id` would."""
    params = rot.rotation_params(op, target_id, key_fp)
    rec = create_request(conn, user_id="admin-1", capability=capability,
                         target="", action_params=params,
                         appliance_id="appliance-A", authenticator_id=signer_id,
                         ttl_seconds=300, now=NOW)
    P = aap.encode_payload(
        request_id=rec["request_id"], capability=rec["capability"],
        target=rec["target"], action_params=rec["action_params"],
        appliance_id=rec["appliance_id"], authenticator_id=rec["authenticator_id"],
        issued_at=rec["issued_at"], expires_at=rec["expires_at"],
        match_code=rec["match_code"], nonce=rec["nonce"])
    ad = RP_ID_HASH + bytes([0x05]) + struct.pack(">I", 1)
    import base64
    cd = json.dumps({"type": "webauthn.get",
                     "challenge": base64.urlsafe_b64encode(
                         aap.challenge_for(P)).rstrip(b"=").decode(),
                     "origin": "https://" + RP_ID}).encode()
    assertion = {"authenticator_data": ad, "client_data_json": cd,
                 "signature": priv.sign(ad + hashlib.sha256(cd).digest(),
                                        ec.ECDSA(hashes.SHA256()))}
    return rec, assertion


def fp_of(record):
    return aap.key_fingerprint(record["public_key"])


# ═══════════════════════════════════════════════════════════════════════════
print("\n== BOOTSTRAP: opens at zero, closes at the floor, never reopens ==")

conn = fresh()
check("bootstrap is OPEN with no registrations", rot.bootstrap_open(conn) is True)

p1, r1 = reg("phone-1")
rot.register_authenticator(conn, r1, actor="user:operator")
check("first registration needs no approval (nothing could sign one)",
      store.get(conn, "phone-1") is not None)
check("  recorded as a bootstrap registration, not silently unattributed",
      store.get(conn, "phone-1")["created_by"] == "user:operator")
check("bootstrap still open below the floor (%d)" % MIN_AUTHENTICATORS_FOR_UNLOCK,
      rot.bootstrap_open(conn) is True)

p2, r2 = reg("phone-2")
rot.register_authenticator(conn, r2)
check("bootstrap CLOSES once the floor is reached",
      rot.bootstrap_open(conn) is False)

# The attack this guards: revoke back below the floor, then add unapproved.
rec, asrt = approval(conn, p1, "phone-1", op=rot.OP_REVOKE, target_id="phone-2",
                     key_fp=fp_of(r2))
rot.revoke_authenticator(conn, "phone-2", stored_request=rec,
                         authenticator=store.get(conn, "phone-1"),
                         assertion=asrt, now=NOW + 1,
                         consume=lambda _r: True, actor="user:operator")
check("after revoking back to ONE active, bootstrap stays CLOSED",
      rot.bootstrap_open(conn) is False,
      "revoke-then-add would be an unapproved way in")
p3, r3 = reg("phone-3")
check("  ...so an unapproved add is now REFUSED",
      raises(lambda: rot.register_authenticator(conn, r3)))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== APPROVED ADD: bound to this exact key and operation ==")

conn = fresh()
p1, r1 = reg("phone-1")
p2, r2 = reg("phone-2")
rot.register_authenticator(conn, r1)
rot.register_authenticator(conn, r2)

p3, r3 = reg("phone-3")
rec, asrt = approval(conn, p1, "phone-1", op=rot.OP_ADD, target_id="phone-3",
                     key_fp=fp_of(r3))
out = rot.register_authenticator(conn, r3, stored_request=rec,
                                 authenticator=store.get(conn, "phone-1"),
                                 assertion=asrt, now=NOW + 1,
                                 consume=lambda _r: True, actor="user:operator")
check("an approved add SUCCEEDS", out["authenticator_id"] == "phone-3")
check("  ...and the new key is live", len(store.active(conn)) == 3)

# Substitution: the approval was for phone-3's key. It must not enrol phone-4.
p4, r4 = reg("phone-4")
rec2, asrt2 = approval(conn, p1, "phone-1", op=rot.OP_ADD, target_id="phone-3",
                       key_fp=fp_of(r3))
check("an approval for phone-3 cannot enrol phone-4 (id bound)",
      raises(lambda: rot.register_authenticator(
          conn, r4, stored_request=rec2, authenticator=store.get(conn, "phone-1"),
          assertion=asrt2, now=NOW + 1, consume=lambda _r: True)))

# Same id, DIFFERENT key material -- the substitution that binding only the id
# would miss entirely.
p5, r5 = reg("phone-5")
rec3, asrt3 = approval(conn, p1, "phone-1", op=rot.OP_ADD, target_id="phone-5",
                       key_fp=fp_of(r5))
_, r5_evil = reg("phone-5")
check("an approval for phone-5's KEY cannot enrol a different key under that id",
      raises(lambda: rot.register_authenticator(
          conn, r5_evil, stored_request=rec3,
          authenticator=store.get(conn, "phone-1"), assertion=asrt3, now=NOW + 1,
          consume=lambda _r: True)),
      "key_fp binding is what catches this; target_id alone would not")
check("  CONTROL: the two phone-5 records really are different keys",
      fp_of(r5) != fp_of(r5_evil))

# An ADD approval must not perform a REVOKE.
rec4, asrt4 = approval(conn, p1, "phone-1", op=rot.OP_ADD, target_id="phone-2",
                       key_fp=fp_of(r2))
check("an ADD approval cannot be used to REVOKE (op bound)",
      raises(lambda: rot.revoke_authenticator(
          conn, "phone-2", stored_request=rec4,
          authenticator=store.get(conn, "phone-1"), assertion=asrt4, now=NOW + 1,
          consume=lambda _r: True)))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== THE SIGNER COMES FROM THE TABLE, NEVER FROM THE CALLER ==")

conn = fresh()
p1, r1 = reg("phone-1")
p2, r2 = reg("phone-2")
rot.register_authenticator(conn, r1)
rot.register_authenticator(conn, r2)

evil_priv, evil_reg = reg("phone-EVIL")
p6, r6 = reg("phone-6")
rec, asrt = approval(conn, evil_priv, "phone-EVIL", op=rot.OP_ADD,
                     target_id="phone-6", key_fp=fp_of(r6))
check("an UNREGISTERED signer cannot authorize a rotation",
      raises(lambda: rot.register_authenticator(
          conn, r6, stored_request=rec, authenticator=evil_reg, assertion=asrt,
          now=NOW + 1, consume=lambda _r: True)))

# A REVOKED authenticator must not keep signing rotations.
rec_r, asrt_r = approval(conn, p1, "phone-1", op=rot.OP_REVOKE,
                         target_id="phone-2", key_fp=fp_of(r2))
rot.revoke_authenticator(conn, "phone-2", stored_request=rec_r,
                         authenticator=store.get(conn, "phone-1"),
                         assertion=asrt_r, now=NOW + 1, consume=lambda _r: True)
p7, r7 = reg("phone-7")
rec7, asrt7 = approval(conn, p2, "phone-2", op=rot.OP_ADD, target_id="phone-7",
                       key_fp=fp_of(r7))
check("a REVOKED authenticator cannot authorize a rotation",
      raises(lambda: rot.register_authenticator(
          conn, r7, stored_request=rec7, authenticator=store.get(conn, "phone-2"),
          assertion=asrt7, now=NOW + 1, consume=lambda _r: True)))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== CAPABILITY SEPARATION and LAST-DEVICE PROTECTION ==")

conn = fresh()
p1, r1 = reg("phone-1")
p2, r2 = reg("phone-2")
rot.register_authenticator(conn, r1)
rot.register_authenticator(conn, r2)

p8, r8 = reg("phone-8")
rec, asrt = approval(conn, p1, "phone-1", op=rot.OP_ADD, target_id="phone-8",
                     key_fp=fp_of(r8), capability="push_and_run")
check("an approval for ANOTHER capability cannot re-key the admin set",
      raises(lambda: rot.register_authenticator(
          conn, r8, stored_request=rec, authenticator=store.get(conn, "phone-1"),
          assertion=asrt, now=NOW + 1, consume=lambda _r: True)))

rec, asrt = approval(conn, p1, "phone-1", op=rot.OP_REVOKE, target_id="phone-2",
                     key_fp=fp_of(r2))
rot.revoke_authenticator(conn, "phone-2", stored_request=rec,
                         authenticator=store.get(conn, "phone-1"),
                         assertion=asrt, now=NOW + 1, consume=lambda _r: True)
check("one active authenticator remains", len(store.active(conn)) == 1)
rec, asrt = approval(conn, p1, "phone-1", op=rot.OP_REVOKE, target_id="phone-1",
                     key_fp=fp_of(r1))
check("revoking the LAST active authenticator is REFUSED",
      raises(lambda: rot.revoke_authenticator(
          conn, "phone-1", stored_request=rec,
          authenticator=store.get(conn, "phone-1"), assertion=asrt, now=NOW + 1,
          consume=lambda _r: True)),
      "an empty admin set is unrecoverable by design")
check("  ...and it is still active", len(store.active(conn)) == 1)

check("revoking an unknown id raises (not a silent False)",
      raises(lambda: rot.revoke_authenticator(conn, "nope")))
check("revocation ALWAYS needs an approval -- no bootstrap exemption",
      raises(lambda: rot.revoke_authenticator(conn, "phone-1")))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== rotation_params: canonical, deterministic, §4.2-safe ==")

a = rot.rotation_params(rot.OP_ADD, "phone-1", "ff" * 32)
b = rot.rotation_params(rot.OP_ADD, "phone-1", "ff" * 32)
check("rotation_params is deterministic", a == b)
check("  ...and returns BYTES (never a dict for someone else to serialise)",
      isinstance(a, bytes))
check("  ...with sorted keys and no whitespace",
      a == b'{"key_fp":"' + b"ff" * 32 + b'","op":"add","target_id":"phone-1"}', a)
check("op and target are distinguishable in the bytes",
      rot.rotation_params(rot.OP_REVOKE, "phone-1", "ff" * 32) != a)
for bad, why in ((("nope", "phone-1", "ff"), "an unknown op"),
                 ((rot.OP_ADD, "", "ff"), "an empty target_id"),
                 ((rot.OP_ADD, "phone-1", ""), "an empty key_fp")):
    check("rejects %s" % why, raises(lambda b=bad: rot.rotation_params(*b)))

# The shared fingerprint: one definition across appliance, agent and companion.
check("key_fingerprint is stable across a tag/untag round trip",
      aap.key_fingerprint(r1["public_key"])
      == aap.key_fingerprint(aap.untag_bytes(aap.tag_bytes(r1["public_key"]))))
check("  ...and is a full sha256 hex digest",
      len(aap.key_fingerprint(r1["public_key"])) == 64)
check("  ...and differs between two keys",
      aap.key_fingerprint(r1["public_key"]) != aap.key_fingerprint(r2["public_key"]))

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
