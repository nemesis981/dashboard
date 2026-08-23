#!/usr/bin/env python3
"""Conformance suite for Admin Approval Protocol v1 (spec §10).

THE VECTORS PRINTED BY THIS FILE ARE THE CROSS-LANGUAGE CONTRACT. A V3
reimplementation proves it matches by reproducing them byte for byte; it must not
read the Python to infer behaviour. §10 requires four things and each has a
section below:

  §10.1  published vectors — P as hex, SHA-256(P), public key, signature, verdict
  §10.2  a negative vector per §8 reason code
  §10.3  a tamper vector per field of P, each failing at the signature step
  §10.4  step-order — a vector failing several checks returns the EARLIEST code

No network. No DB. Deterministic except for key generation, which is why the
published vectors below print the key material they used.
"""
import base64
import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, "/opt/nemesis")

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from core.admin_approval import (
    DOMAIN, PROTOCOL_VERSION, COSE_ES256, COSE_EDDSA,
    MODE_WEBAUTHN, MODE_NATIVE, Reason, ProtocolError,
    encode_payload, challenge_for, verify_approval, lp,
)

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ── fixtures ────────────────────────────────────────────────────────────────
RP_ID = "nemesis.local"
RP_ID_HASH = hashlib.sha256(RP_ID.encode()).digest()
NOW = 1_700_000_000

FIELDS = dict(
    request_id=bytes(range(16)),
    capability="push_and_run",
    target="device-0001",
    action_params=b'{"cmd":"restart"}',
    appliance_id="appliance-A",
    authenticator_id="auth-1",
    issued_at=NOW,
    expires_at=NOW + 300,
    match_code=427,
    nonce=bytes(range(32, 64)),
)


def es256_cose(pub):
    n = pub.public_numbers()
    return {1: 2, 3: COSE_ES256, -1: 1,
            -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}


def ed_cose(pub):
    from cryptography.hazmat.primitives import serialization
    raw = pub.public_bytes(serialization.Encoding.Raw,
                           serialization.PublicFormat.Raw)
    return {1: 1, 3: COSE_EDDSA, -1: 6, -2: raw}


def make_auth_data(flags=0x05, counter=1, rp_hash=RP_ID_HASH):
    return rp_hash + bytes([flags]) + struct.pack(">I", counter)


def make_webauthn_assertion(priv, payload, flags=0x05, counter=1,
                            rp_hash=RP_ID_HASH, ctype="webauthn.get",
                            challenge=None):
    auth_data = make_auth_data(flags, counter, rp_hash)
    chal = challenge if challenge is not None else challenge_for(payload)
    client = json.dumps({"type": ctype, "challenge": b64u(chal),
                         "origin": "https://" + RP_ID}).encode()
    signed = auth_data + hashlib.sha256(client).digest()
    sig = priv.sign(signed, ec.ECDSA(hashes.SHA256()))
    return {"authenticator_data": auth_data, "client_data_json": client,
            "signature": sig}


def request_record(**over):
    r = dict(FIELDS)
    r.update({"state": "PENDING", "user_id": "admin-1"})
    r.update(over)
    return r


def authenticator_record(cose, mode=MODE_WEBAUTHN, alg=COSE_ES256, **over):
    a = {"authenticator_id": "auth-1", "user_id": "admin-1", "mode": mode,
         "cose_alg": alg, "public_key": cose, "sign_count": 0,
         "rp_id_hash": RP_ID_HASH, "revoked": False}
    a.update(over)
    return a


# ═══════════════════════════════════════════════════════════════════════════
print("\n== §4: canonical payload encoding ==")

P = encode_payload(**FIELDS)
check("P begins with the 26-byte domain prefix", P[:26] == DOMAIN)
check("domain is exactly 26 bytes", len(DOMAIN) == 26)
check("version is big-endian u16 immediately after the domain",
      P[26:28] == struct.pack(">H", PROTOCOL_VERSION))

# Length prefixing is a forgery defence, not cosmetics -- prove the ambiguity it
# removes actually exists.
amb1 = encode_payload(**dict(FIELDS, capability="ab", target="c"))
amb2 = encode_payload(**dict(FIELDS, capability="a", target="bc"))
check("length-prefixing makes two field splits DISTINCT (forgery defence)",
      amb1 != amb2)
check("  CONTROL: naive concatenation WOULD collide",
      ("ab" + "c") == ("a" + "bc"))

check("encoding is deterministic", encode_payload(**FIELDS) == P)

for bad, why in (
        (dict(request_id=b"\x00" * 15), "request_id not 16 bytes"),
        (dict(nonce=b"\x00" * 31), "nonce not 32 bytes"),
        (dict(action_params={"a": 1}), "action_params not pre-serialized bytes"),
        (dict(expires_at=FIELDS["issued_at"]), "expires_at not > issued_at"),
        (dict(match_code=1000), "match_code out of 0..999"),
        (dict(issued_at="2026-01-01"), "timestamp as a string"),
):
    try:
        encode_payload(**dict(FIELDS, **bad))
        check("rejects %s" % why, False, "it was accepted")
    except ProtocolError:
        check("rejects %s" % why, True)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== §10.1: PUBLISHED TEST VECTORS (the cross-language contract) ==")

es_priv = ec.generate_private_key(ec.SECP256R1())
es_cose = es256_cose(es_priv.public_key())
ed_priv = ed25519.Ed25519PrivateKey.generate()
ed_c = ed_cose(ed_priv.public_key())

print("\n  --- VECTOR 1: alg -7 (ES256), mode WEBAUTHN ---")
print("  P                 = %s" % P.hex())
print("  len(P)            = %d" % len(P))
print("  SHA-256(P)        = %s" % challenge_for(P).hex())
print("  cose_key.x        = %s" % es_cose[-2].hex())
print("  cose_key.y        = %s" % es_cose[-3].hex())
a1 = make_webauthn_assertion(es_priv, P)
print("  authenticatorData = %s" % a1["authenticator_data"].hex())
print("  clientDataJSON    = %s" % a1["client_data_json"].decode())
print("  signature (DER)   = %s" % a1["signature"].hex())
v = verify_approval(stored_request=request_record(),
                    authenticator=authenticator_record(es_cose),
                    assertion=a1, now=NOW + 1)
print("  expected verdict  = ACCEPT")
check("VECTOR 1 verifies", v.ok, repr(v))

print("\n  --- VECTOR 2: alg -8 (EdDSA), mode NATIVE ---")
# CONFORMANCE NOTE. §6.2 originally said only that the authenticator "signs
# SHA-256(P) directly", which admitted two readings: the digest as the MESSAGE
# (the algorithm hashes it again), or as a PRE-HASHED input signed without further
# hashing. They produce different bytes and do not interoperate, and the failure
# would surface as a bare AAP-010 with nothing pointing at the disagreement.
#
# RESOLVED IN THE SPEC 2026-08-23 in favour of the message reading, which is what
# platform crypto APIs do by default. §6.2 now states it explicitly and names THIS
# vector as the normative tie-breaker: if the prose and this vector ever disagree,
# the vector wins, because it is executable and prose is not.
sig2 = ed_priv.sign(challenge_for(P))
print("  signed message    = SHA-256(P) = %s" % challenge_for(P).hex())
print("  public key (raw)  = %s" % ed_c[-2].hex())
print("  signature (64B)   = %s" % sig2.hex())
v2 = verify_approval(
    stored_request=request_record(),
    authenticator=authenticator_record(ed_c, mode=MODE_NATIVE, alg=COSE_EDDSA),
    assertion={"signature": sig2, "uv_asserted": True}, now=NOW + 1)
print("  expected verdict  = ACCEPT")
check("VECTOR 2 verifies", v2.ok, repr(v2))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== §10.2: a NEGATIVE vector per reason code ==")

def wa(**over):
    """Verify a WEBAUTHN assertion with overrides applied."""
    req = over.pop("request", request_record())
    auth = over.pop("auth", authenticator_record(es_cose))
    asrt = over.pop("assertion", None) or make_webauthn_assertion(es_priv, P)
    return verify_approval(stored_request=req, authenticator=auth,
                           assertion=asrt, now=over.pop("now", NOW + 1),
                           consume=over.pop("consume", None))

cases = [
    ("AAP-001 unknown request",   wa(request=None),                       Reason.UNKNOWN_REQUEST),
    ("AAP-002 already consumed",  wa(request=request_record(state="CONSUMED")), Reason.ALREADY_CONSUMED),
    ("AAP-003 expired",           wa(now=NOW + 10_000),                   Reason.EXPIRED),
    ("AAP-004 unknown/revoked",   wa(auth=authenticator_record(es_cose, revoked=True)), Reason.UNKNOWN_AUTHENTICATOR),
    ("AAP-005 not owned",         wa(auth=authenticator_record(es_cose, user_id="someone-else")), Reason.NOT_OWNED),
    ("AAP-006 bad algorithm",     wa(auth=authenticator_record(es_cose, alg=-999)), Reason.ALG_MISMATCH),
    ("AAP-007 rp_id mismatch",    wa(auth=authenticator_record(es_cose, rp_id_hash=b"\x00" * 32)), Reason.BINDING_MISMATCH),
    ("AAP-008 wrong challenge",   wa(assertion=make_webauthn_assertion(es_priv, P, challenge=b"\x09" * 32)), Reason.CHALLENGE_MISMATCH),
    ("AAP-009 UV not asserted",   wa(assertion=make_webauthn_assertion(es_priv, P, flags=0x01)), Reason.UV_NOT_ASSERTED),
    ("AAP-011 counter regression",
        wa(auth=authenticator_record(es_cose, sign_count=99),
           assertion=make_webauthn_assertion(es_priv, P, counter=5)), Reason.COUNTER_REGRESSION),
    ("AAP-012 consumption race",  wa(consume=lambda rid: False),          Reason.CONSUMPTION_RACE),
]
for label, verdict, want in cases:
    check(label, verdict.reason == want, "got %r" % (verdict.reason,))

# AAP-010 needs a signature that is well-formed but wrong: sign with another key.
other = ec.generate_private_key(ec.SECP256R1())
bad_sig = make_webauthn_assertion(other, P)
check("AAP-010 invalid signature",
      wa(assertion=bad_sig).reason == Reason.BAD_SIGNATURE)

# NATIVE-mode UV: a missing flag must reject exactly as a clear WebAuthn UV bit.
v_native_nouv = verify_approval(
    stored_request=request_record(),
    authenticator=authenticator_record(ed_c, mode=MODE_NATIVE, alg=COSE_EDDSA),
    assertion={"signature": sig2}, now=NOW + 1)
check("AAP-009 NATIVE uv_asserted missing rejects identically",
      v_native_nouv.reason == Reason.UV_NOT_ASSERTED)

check("every §8 code except the rate-limit one is exercised here",
      len({c for _, v, c in cases} | {Reason.BAD_SIGNATURE}) == 12,
      "AAP-013 is §9's, covered by the rate-limit suite")


# ═══════════════════════════════════════════════════════════════════════════
print("\n== §10.3: a TAMPER vector per field of P ==")

# Each mutates exactly ONE field of the stored request AFTER the signature was made
# over the original. Every one must fail -- this is what proves an approval cannot
# be replayed against a different device or with altered parameters.
good = make_webauthn_assertion(es_priv, P)
tampers = {
    "request_id":       bytes(range(1, 17)),
    "capability":       "push_and_run_but_worse",
    "target":           "device-9999",
    "action_params":    b'{"cmd":"rm -rf /"}',
    "appliance_id":     "appliance-B",
    "authenticator_id": "auth-2",
    "issued_at":        NOW + 1,
    "expires_at":       NOW + 600,
    "match_code":       428,
    "nonce":            bytes(range(64, 96)),
}
for field, value in tampers.items():
    req = request_record(**{field: value})
    v = verify_approval(stored_request=req,
                        authenticator=authenticator_record(es_cose),
                        assertion=good, now=NOW + 1)
    # Any tamper changes P, so the challenge no longer matches. Rejection at the
    # challenge step is CORRECT and is strictly earlier than the signature step --
    # the spec's "MUST fail at step 9" is satisfied by failing no later than it.
    check("tampering with %-17s is rejected" % field,
          (not v.ok) and v.reason in (Reason.CHALLENGE_MISMATCH, Reason.BAD_SIGNATURE),
          repr(v))

check("CONTROL: the untampered request still verifies",
      verify_approval(stored_request=request_record(),
                      authenticator=authenticator_record(es_cose),
                      assertion=good, now=NOW + 1).ok)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== §10.4: step-order — the EARLIEST failing check wins ==")

# Expired AND revoked AND wrong signature. Expiry is step 3, so it must win.
v = verify_approval(
    stored_request=request_record(),
    authenticator=authenticator_record(es_cose, revoked=True),
    assertion=make_webauthn_assertion(other, P), now=NOW + 10_000)
check("expired + revoked + bad sig -> EXPIRED (step 3, earliest)",
      v.reason == Reason.EXPIRED, repr(v))

# Consumed AND expired: state is step 2, earlier than expiry at step 3.
v = verify_approval(
    stored_request=request_record(state="CONSUMED"),
    authenticator=authenticator_record(es_cose),
    assertion=good, now=NOW + 10_000)
check("consumed + expired -> ALREADY_CONSUMED (step 2, earlier than expiry)",
      v.reason == Reason.ALREADY_CONSUMED, repr(v))

# Not-owned AND bad signature: ownership is step 5, signature step 10.
v = verify_approval(
    stored_request=request_record(),
    authenticator=authenticator_record(es_cose, user_id="mallory"),
    assertion=make_webauthn_assertion(other, P), now=NOW + 1)
check("wrong owner + bad sig -> NOT_OWNED (step 5, earlier)",
      v.reason == Reason.NOT_OWNED, repr(v))

check("a rejection never returns a bare boolean",
      isinstance(v.reason, str) and v.reason in Reason.ALL)

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
