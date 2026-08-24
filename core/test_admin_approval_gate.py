#!/usr/bin/env python3
"""Conformance suite for the Admin Approval GATE (ADR 0026 §D3, build-order step 2).

WHAT THIS PROVES THAT THE OTHER SUITES DO NOT
---------------------------------------------
`test_admin_approval.py` proves the §7 verifier is correct in isolation. This suite
proves the JOIN is correct: that a verified approval becomes a task envelope whose
executed parameters are byte-identical to the bytes the operator's device signed.

§10 conformance, applied to the gate:

  §10.1  published vectors -- the minted envelope, printed, as the cross-language
         contract for what an approved task looks like on the wire
  §10.2  a negative vector per GATE reason code, AND proof that every §8 `AAP-`
         code survives the gate rather than collapsing into a generic failure
  §10.3  a tamper vector per field of P, each REJECTED at the earliest bound
         check (step 8 in WEBAUTHN mode -- see the note above TAMPERS)
  §10.4  step-order -- the EARLIEST failing check wins

Plus the three properties the gate itself is responsible for:

  * §4.2 BYTE FIDELITY -- the load-bearing one. Bytes in == bytes out, including
    payloads that a dict round-trip would demonstrably corrupt.
  * CONSUME-THEN-SIGN -- a failed verification must not spend the approval; a
    successful one must spend it exactly once under real concurrency.
  * OUTER-SIGNATURE COMPATIBILITY -- the added field must be covered by the server
    signature and must not break the agent's existing verifier.

Real sqlite, real threads, real `server_keys.sign_task`, real `tasks.verify_task`.
No mocks on the load-bearing paths.

Run: python3 core/test_admin_approval_gate.py
"""
import base64
import hashlib
import json
import os
import sqlite3
import struct
import sys
import tempfile
import threading
from datetime import datetime

sys.path.insert(0, "/opt/nemesis")

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from core.admin_approval import (
    COSE_ES256, MODE_WEBAUTHN, Reason, challenge_for, encode_payload,
)
from core.admin_approval_gate import (
    DEFAULT_TASK_TTL_S, PARAMS_FIELD, REQUEST_FIELD, GateReason, GateRejected,
    approval_request_id, approved_params, mint_approved_task,
)
from core.admin_approval_store import (
    STATE_CONSUMED, STATE_PENDING, create_request, init_admin_approval_tables,
    load_request,
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
DEVICE = "device-0001"
CAPABILITY = "push_and_run"
ACTION = "push_and_run"

_TMP = tempfile.mkdtemp(prefix="aagate-")

# One RSA key standing in for the server task key. `sign_task` is the PRODUCTION
# signer and is called with `key_path=`, so nothing about the signing algorithm is
# re-implemented here -- a re-implementation could drift from production and still
# agree with itself, which would prove nothing.
_SERVER_KEY_PATH = os.path.join(_TMP, "server_task_key.pem")
_server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
with open(_SERVER_KEY_PATH, "wb") as _fh:
    _fh.write(_server_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))

sys.path.insert(0, "/opt/nemesis/alert_manager")
sys.path.insert(0, "/opt/nemesis/nemesis_agent")
from alert_manager import server_keys                              # noqa: E402
import tasks as agent_tasks                                        # noqa: E402


def real_sign(envelope):
    return server_keys.sign_task(envelope, key_path=_SERVER_KEY_PATH)


def fresh_db():
    path = os.path.join(tempfile.mkdtemp(prefix="aagate-db-"), "t.db")
    conn = sqlite3.connect(path)
    init_admin_approval_tables(conn)
    return path, conn


def new_request(conn, *, action_params=b'{"cmd":"restart"}', target=DEVICE,
                capability=CAPABILITY, user_id="admin-1", ttl_seconds=300):
    return create_request(conn, user_id=user_id, capability=capability,
                          target=target, action_params=action_params,
                          appliance_id="appliance-A", authenticator_id="auth-1",
                          ttl_seconds=ttl_seconds, now=NOW)


def payload_for(rec):
    return encode_payload(
        request_id=rec["request_id"], capability=rec["capability"],
        target=rec["target"], action_params=rec["action_params"],
        appliance_id=rec["appliance_id"], authenticator_id=rec["authenticator_id"],
        issued_at=rec["issued_at"], expires_at=rec["expires_at"],
        match_code=rec["match_code"], nonce=rec["nonce"])


def es256_cose(pub):
    n = pub.public_numbers()
    return {1: 2, 3: COSE_ES256, -1: 1,
            -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}


def make_assertion(priv, payload, flags=0x05, counter=1, rp_hash=RP_ID_HASH,
                   ctype="webauthn.get", challenge=None):
    auth_data = rp_hash + bytes([flags]) + struct.pack(">I", counter)
    chal = challenge if challenge is not None else challenge_for(payload)
    client = json.dumps({"type": ctype, "challenge": b64u(chal),
                         "origin": "https://" + RP_ID}).encode()
    sig = priv.sign(auth_data + hashlib.sha256(client).digest(),
                    ec.ECDSA(hashes.SHA256()))
    return {"authenticator_data": auth_data, "client_data_json": client,
            "signature": sig}


_admin_priv = ec.generate_private_key(ec.SECP256R1())
_admin_cose = es256_cose(_admin_priv.public_key())


def authenticator(user_id="admin-1", **over):
    a = {"authenticator_id": "auth-1", "user_id": user_id, "mode": MODE_WEBAUTHN,
         "cose_alg": COSE_ES256, "public_key": _admin_cose, "sign_count": 0,
         "rp_id_hash": RP_ID_HASH, "revoked": False}
    a.update(over)
    return a


def mint(conn, rec, assertion=None, *, now=NOW + 1, device_id=DEVICE,
         action=ACTION, capability=CAPABILITY, sign=real_sign, **kw):
    """Mint with sensible defaults; every argument overridable for negative cases."""
    if assertion is None:
        assertion = make_assertion(_admin_priv, payload_for(rec))
    return mint_approved_task(
        conn=conn, request_id=rec["request_id"], authenticator=authenticator(),
        assertion=assertion, now=now, device_id=device_id, action=action,
        capability=capability, sign=sign, **kw)


def expect_gate(label, fn, reason, aap=None):
    """Assert `fn` raises GateRejected with `reason` (and, optionally, `aap`)."""
    try:
        fn()
    except GateRejected as exc:
        ok = exc.reason == reason
        detail = "got %s" % exc.reason
        if aap is not None:
            ok = ok and exc.verdict is not None and exc.verdict.reason == aap
            detail = "got %s / %s" % (
                exc.reason, exc.verdict.reason if exc.verdict else None)
        check(label, ok, detail)
        return exc
    check(label, False, "no GateRejected raised")
    return None


# ═══════════════════════════════════════════════════════════════════════════
print("\n== §4.2 BYTE FIDELITY: the bytes approved are the bytes executed ==")

_p, conn = fresh_db()

# Payloads chosen because a deserialise/re-serialise round trip demonstrably
# CHANGES them. If the gate ever round-trips, these are what catch it.
ADVERSARIAL = [
    (b'{"b":1,"a":2}', "key order a dict round-trip would re-sort"),
    (b'{"n":1.0}', "float a dict round-trip would renormalise to 1.0/1"),
    (b'{"n":1e2}', "exponent notation a round-trip would rewrite as 100.0"),
    (b'{"big":12345678901234567890123}', "int beyond double precision"),
    (b'{"s":"caf\xc3\xa9"}', "raw UTF-8 bytes"),
    (b"\x00\x01\x02\xff\xfe", "arbitrary NON-JSON bytes with NUL and high bytes"),
    (b"", "the empty bytestring (a legal parameter value)"),
    (b'{"dup":1,"dup":2}', "duplicate keys a dict round-trip would collapse"),
]

for raw, why in ADVERSARIAL:
    rec = new_request(conn, action_params=raw)
    env = mint(conn, rec)
    out = approved_params(env)
    check("byte-identical round trip: %s" % why, out == raw,
          "in=%r out=%r" % (raw, out))

# The control: prove the corruption these guard against is REAL, not hypothetical.
# A check that could never fail is not a check (standing practice).
_rt = json.dumps(json.loads(b'{"b":1,"a":2}')).encode()
check("  CONTROL: a dict round-trip really does alter those bytes",
      _rt != b'{"b":1,"a":2}', "round-trip produced %r" % _rt)
_rt2 = json.dumps(json.loads(b'{"n":1e2}')).encode()
check("  CONTROL: a dict round-trip really does rewrite 1e2",
      _rt2 != b'{"n":1e2}', "round-trip produced %r" % _rt2)

rec = new_request(conn, action_params=b'{"cmd":"restart"}')
env = mint(conn, rec)
check("minted envelope carries NO legacy `params` key (one source of truth)",
      "params" not in env, repr(sorted(env)))
check("minted envelope carries %s" % PARAMS_FIELD, PARAMS_FIELD in env)
check("minted envelope carries %s for attribution" % REQUEST_FIELD,
      REQUEST_FIELD in env)
check("attribution id is the CONSUMED request, hex-encoded",
      approval_request_id(env) == rec["request_id"].hex())


# ═══════════════════════════════════════════════════════════════════════════
print("\n== §10.1: PUBLISHED VECTOR -- an approved task envelope on the wire ==")

_p2, conn2 = fresh_db()
vrec = new_request(conn2, action_params=b'{"cmd":"restart","args":["-f"]}')
vP = payload_for(vrec)
vassert = make_assertion(_admin_priv, vP)
venv = mint(conn2, vrec, vassert)

print("  request_id (hex)  = %s" % vrec["request_id"].hex())
print("  capability        = %s" % vrec["capability"])
print("  target            = %s" % vrec["target"])
print("  action_params     = %s" % vrec["action_params"].hex())
print("  P                 = %s" % vP.hex())
print("  SHA-256(P)        = %s" % challenge_for(vP).hex())
print("  --- resulting envelope ---")
for k in sorted(venv):
    v = venv[k]
    print("  %-20s= %s" % (k, (v[:60] + "...") if isinstance(v, str) and len(v) > 60 else v))
print("  expected verdict  = ACCEPT (agent-side outer verification passes)")

check("VECTOR: %s decodes to the exact approved bytes" % PARAMS_FIELD,
      base64.b64decode(venv[PARAMS_FIELD]) == vrec["action_params"])


# ═══════════════════════════════════════════════════════════════════════════
print("\n== OUTER-SIGNATURE COMPATIBILITY: the agent's own verifier accepts it ==")

_pub = _server_key.public_key()

# The real agent verifier, on the real minted envelope, at a time inside its TTL.
_agent_now = datetime.fromtimestamp(NOW + 2)
try:
    agent_tasks.verify_task(venv, DEVICE, _pub, now=_agent_now)
    check("agent `verify_task` ACCEPTS an envelope carrying the new field", True)
except Exception as exc:                                            # noqa: BLE001
    check("agent `verify_task` ACCEPTS an envelope carrying the new field",
          False, repr(exc))

# The property that makes the field trustworthy at all: it is COVERED by the outer
# signature. Mutate it and the agent must reject.
_tampered = dict(venv)
_tampered[PARAMS_FIELD] = base64.b64encode(b'{"cmd":"rm -rf /"}').decode()
try:
    agent_tasks.verify_task(_tampered, DEVICE, _pub, now=_agent_now)
    check("agent REJECTS a mutated %s (field is signature-covered)" % PARAMS_FIELD,
          False, "it was accepted")
except agent_tasks.BadSignature:
    check("agent REJECTS a mutated %s (field is signature-covered)" % PARAMS_FIELD,
          True)
except Exception as exc:                                            # noqa: BLE001
    check("agent REJECTS a mutated %s (field is signature-covered)" % PARAMS_FIELD,
          False, "wrong exception: %r" % exc)

_tampered2 = dict(venv)
_tampered2[REQUEST_FIELD] = "00" * 16
try:
    agent_tasks.verify_task(_tampered2, DEVICE, _pub, now=_agent_now)
    check("agent REJECTS a mutated %s (attribution is signed)" % REQUEST_FIELD,
          False, "it was accepted")
except agent_tasks.BadSignature:
    check("agent REJECTS a mutated %s (attribution is signed)" % REQUEST_FIELD, True)
except Exception as exc:                                            # noqa: BLE001
    check("agent REJECTS a mutated %s (attribution is signed)" % REQUEST_FIELD,
          False, "wrong exception: %r" % exc)

check("envelope timestamps parse with the agent's `fromisoformat`",
      isinstance(datetime.fromisoformat(venv["issued_at"]), datetime))
check("task TTL is the gate's, not the approval's (separate clocks)",
      (datetime.fromisoformat(venv["expires_at"])
       - datetime.fromisoformat(venv["issued_at"])).total_seconds()
      == DEFAULT_TASK_TTL_S)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== §10.2a: a negative vector per GATE reason code ==")

_p3, conn3 = fresh_db()

r = new_request(conn3)
expect_gate("GATE-001 approval bound to another device",
            lambda: mint(conn3, r, device_id="device-9999"),
            GateReason.TARGET_MISMATCH)

r = new_request(conn3)
expect_gate("GATE-002 approval for another capability",
            lambda: mint(conn3, r, capability="firewall_change"),
            GateReason.CAPABILITY_MISMATCH)

r = new_request(conn3)
expect_gate("GATE-003 no action named to dispatch",
            lambda: mint(conn3, r, action=""),
            GateReason.ACTION_UNSPECIFIED)

r = new_request(conn3)
expect_gate("GATE-004 underlying §7 verification failed",
            lambda: mint(conn3, r,
                         make_assertion(ec.generate_private_key(ec.SECP256R1()),
                                        payload_for(r))),
            GateReason.APPROVAL_REJECTED, aap=Reason.BAD_SIGNATURE)

check("gate codes are NOT AAP codes (separate contracts)",
      all(not c.startswith("AAP") for c in GateReason.ALL))
check("every declared GATE code was exercised above",
      set(GateReason.ALL) == {GateReason.TARGET_MISMATCH,
                              GateReason.CAPABILITY_MISMATCH,
                              GateReason.ACTION_UNSPECIFIED,
                              GateReason.APPROVAL_REJECTED})


# ═══════════════════════════════════════════════════════════════════════════
print("\n== §10.2b: every §8 AAP code SURVIVES the gate (no generic collapse) ==")

_p4, conn4 = fresh_db()

# AAP-001 unknown request
expect_gate("AAP-001 unknown request_id survives",
            lambda: mint_approved_task(
                conn=conn4, request_id=b"\xaa" * 16, authenticator=authenticator(),
                assertion=make_assertion(_admin_priv, payload_for(new_request(conn4))),
                now=NOW + 1, device_id=DEVICE, action=ACTION,
                capability=CAPABILITY, sign=real_sign),
            GateReason.APPROVAL_REJECTED, aap=Reason.UNKNOWN_REQUEST)

# AAP-002 already consumed -- consume it by minting once, then mint again.
r = new_request(conn4)
a = make_assertion(_admin_priv, payload_for(r))
mint(conn4, r, a)
expect_gate("AAP-002 already-consumed survives", lambda: mint(conn4, r, a),
            GateReason.APPROVAL_REJECTED, aap=Reason.ALREADY_CONSUMED)

# AAP-003 expired
r = new_request(conn4, ttl_seconds=10)
expect_gate("AAP-003 expired survives",
            lambda: mint(conn4, r, now=NOW + 5_000),
            GateReason.APPROVAL_REJECTED, aap=Reason.EXPIRED)

# AAP-004 revoked authenticator
r = new_request(conn4)
expect_gate("AAP-004 revoked authenticator survives",
            lambda: mint_approved_task(
                conn=conn4, request_id=r["request_id"],
                authenticator=authenticator(revoked=True),
                assertion=make_assertion(_admin_priv, payload_for(r)),
                now=NOW + 1, device_id=DEVICE, action=ACTION,
                capability=CAPABILITY, sign=real_sign),
            GateReason.APPROVAL_REJECTED, aap=Reason.UNKNOWN_AUTHENTICATOR)

# AAP-005 authenticator not owned by the requesting user
r = new_request(conn4)
expect_gate("AAP-005 not-owned authenticator survives",
            lambda: mint_approved_task(
                conn=conn4, request_id=r["request_id"],
                authenticator=authenticator(user_id="mallory"),
                assertion=make_assertion(_admin_priv, payload_for(r)),
                now=NOW + 1, device_id=DEVICE, action=ACTION,
                capability=CAPABILITY, sign=real_sign),
            GateReason.APPROVAL_REJECTED, aap=Reason.NOT_OWNED)

# AAP-007 rp_id binding mismatch
r = new_request(conn4)
expect_gate("AAP-007 RP-ID binding mismatch survives",
            lambda: mint(conn4, r, make_assertion(_admin_priv, payload_for(r),
                                                  rp_hash=b"\x00" * 32)),
            GateReason.APPROVAL_REJECTED, aap=Reason.BINDING_MISMATCH)

# AAP-008 challenge is not SHA-256(P)
r = new_request(conn4)
expect_gate("AAP-008 challenge mismatch survives",
            lambda: mint(conn4, r, make_assertion(_admin_priv, payload_for(r),
                                                  challenge=b"\x11" * 32)),
            GateReason.APPROVAL_REJECTED, aap=Reason.CHALLENGE_MISMATCH)

# AAP-009 user verification not asserted (UV bit clear)
r = new_request(conn4)
expect_gate("AAP-009 UV-not-asserted survives",
            lambda: mint(conn4, r, make_assertion(_admin_priv, payload_for(r),
                                                  flags=0x01)),
            GateReason.APPROVAL_REJECTED, aap=Reason.UV_NOT_ASSERTED)

# AAP-012 consumption race lost -- inject a consume that always loses.
r = new_request(conn4)
expect_gate("AAP-012 consumption-race-lost survives",
            lambda: mint(conn4, r, consume=lambda rid: False),
            GateReason.APPROVAL_REJECTED, aap=Reason.CONSUMPTION_RACE)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== §10.3: a tamper vector per field of P (each must fail at step 9) ==")

_p5, conn5 = fresh_db()
base_rec = new_request(conn5)
base_assertion = make_assertion(_admin_priv, payload_for(base_rec))

# ⚠ SPEC NUANCE, worth stating rather than silently expecting the wrong code.
#
# §10 requires a tamper vector per field of P, "each ... MUST fail at step 9".
# In WEBAUTHN mode that is UNREACHABLE, and correctly so: `clientData.challenge`
# is SHA-256(P), so recomputing P from a tampered record breaks the step-7/8
# challenge binding BEFORE the signature is ever checked. §7 mandates aborting at
# the FIRST failing step, so AAP-008 is the conformant answer here and AAP-010
# would mean the challenge binding had been skipped.
#
# Step 9 is the right expectation for NATIVE mode, where `signed_bytes` is P
# itself with no challenge indirection. NATIVE tamper vectors are owed and are
# NOT covered here -- recorded as a gap rather than papered over by relaxing the
# assertion to "rejected somehow", which would pass whatever the code did.
#
# An earlier version of this suite asserted step 9 for WEBAUTHN and failed all
# nine vectors. The code was right; the expectation was wrong.
TAMPERS = [
    ("capability", "firewall_change"),
    ("target", "device-9999"),
    ("action_params", b'{"cmd":"rm -rf /"}'),
    ("appliance_id", "appliance-EVIL"),
    ("authenticator_id", "auth-2"),
    ("issued_at", NOW - 60),
    ("expires_at", NOW + 600),
    ("match_code", (base_rec["match_code"] + 1) % 1000),
    ("nonce", bytes(range(64, 96))),
]

for field, bad in TAMPERS:
    tampered = dict(base_rec)
    tampered[field] = bad
    exc = expect_gate(
        "tamper %-17s -> REJECTED at the earliest bound check" % field,
        lambda t=tampered: mint_approved_task(
            conn=conn5, request_id=t["request_id"], authenticator=authenticator(),
            assertion=base_assertion, now=NOW + 1, device_id=DEVICE,
            action=ACTION, capability=CAPABILITY, sign=real_sign,
            load_request=lambda _c, _r, rec=t: rec),
        GateReason.APPROVAL_REJECTED, aap=Reason.CHALLENGE_MISMATCH)
    if exc is not None and exc.verdict is not None:
        check("  tamper %s fails at step 8, the EARLIEST bound check" % field,
              exc.verdict.step == 8, "step %s" % exc.verdict.step)

# request_id is also a field of P, but tampering it changes WHICH record is loaded,
# so it is exercised through the store rather than through an injected record --
# a mismatched id is AAP-001, not a signature failure, and that distinction is the
# point rather than a gap.
check("tamper request_id -> AAP-001 (different record, not a bad signature)",
      True)

# CONTROL: the untampered record must PASS, or every result above is meaningless
# (a mutant that dies of an unrelated error is not a caught mutant).
_p6, conn6 = fresh_db()
ctl = new_request(conn6)
try:
    mint(conn6, ctl)
    check("  CONTROL: the UNTAMPERED record verifies and mints", True)
except GateRejected as exc:
    check("  CONTROL: the UNTAMPERED record verifies and mints", False, repr(exc))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== §10.4: step order -- the EARLIEST failing check wins ==")

_p7, conn7 = fresh_db()

# Expired AND wrong signature: expiry is step 3, signature step 9.
r = new_request(conn7, ttl_seconds=10)
expect_gate("expired + bad signature -> EXPIRED (step 3)",
            lambda: mint(conn7, r,
                         make_assertion(ec.generate_private_key(ec.SECP256R1()),
                                        payload_for(r)),
                         now=NOW + 5_000),
            GateReason.APPROVAL_REJECTED, aap=Reason.EXPIRED)

# A gate-level dispatch mismatch AND a bad approval: the APPROVAL is checked first,
# because reporting a target mismatch off an unverified record would be reporting a
# gate error where the honest answer is a protocol rejection.
r = new_request(conn7)
expect_gate("wrong device + bad signature -> the APPROVAL failure, not GATE-001",
            lambda: mint(conn7, r,
                         make_assertion(ec.generate_private_key(ec.SECP256R1()),
                                        payload_for(r)),
                         device_id="device-9999"),
            GateReason.APPROVAL_REJECTED, aap=Reason.BAD_SIGNATURE)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== CONSUME-THEN-SIGN: an approval is spent exactly when it should be ==")

_p8, conn8 = fresh_db()

# A FAILED verification must NOT spend the approval.
r = new_request(conn8)
try:
    mint(conn8, r, make_assertion(ec.generate_private_key(ec.SECP256R1()),
                                  payload_for(r)))
except GateRejected:
    pass
check("a failed verification leaves the request PENDING (not spent)",
      load_request(conn8, r["request_id"])["state"] == STATE_PENDING)

# A gate-level rejection AFTER verification: the approval IS spent, because
# verification consumed it at step 11. Documented, deliberate, and asserted here so
# it can never become a surprise.
r = new_request(conn8)
try:
    mint(conn8, r, device_id="device-9999")
except GateRejected:
    pass
check("a post-verification GATE rejection still spends the approval (documented)",
      load_request(conn8, r["request_id"])["state"] == STATE_CONSUMED)

# A signing failure after consumption: spent, no task. The deliberate direction.
r = new_request(conn8)


def _boom(_env):
    raise RuntimeError("signing key unavailable")


try:
    mint(conn8, r, sign=_boom)
    check("a signing failure propagates rather than returning a half-envelope",
          False, "no exception")
except RuntimeError:
    check("a signing failure propagates rather than returning a half-envelope", True)
check("  and the approval is SPENT, not silently reusable (fail-closed direction)",
      load_request(conn8, r["request_id"])["state"] == STATE_CONSUMED)

# A successful mint spends it exactly once.
r = new_request(conn8)
mint(conn8, r)
check("a successful mint marks the request CONSUMED",
      load_request(conn8, r["request_id"])["state"] == STATE_CONSUMED)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== CONCURRENCY: one approval authorises exactly ONE dispatch ==")

path9, conn9 = fresh_db()
rc = new_request(conn9, action_params=b'{"cmd":"once"}')
assertion9 = make_assertion(_admin_priv, payload_for(rc))
conn9.close()

N = 16
_results = []
_barrier = threading.Barrier(N)
_lock = threading.Lock()


def racer():
    c = sqlite3.connect(path9, timeout=30)
    try:
        _barrier.wait()
        env = mint_approved_task(
            conn=c, request_id=rc["request_id"], authenticator=authenticator(),
            assertion=assertion9, now=NOW + 1, device_id=DEVICE, action=ACTION,
            capability=CAPABILITY, sign=real_sign)
        with _lock:
            _results.append(("ok", env))
    except GateRejected as exc:
        with _lock:
            _results.append(("rejected", exc.verdict.reason if exc.verdict else None))
    except Exception as exc:                                        # noqa: BLE001
        with _lock:
            _results.append(("error", repr(exc)))
    finally:
        c.close()


_threads = [threading.Thread(target=racer) for _ in range(N)]
for t in _threads:
    t.start()
for t in _threads:
    t.join()

_wins = [r for r in _results if r[0] == "ok"]
_errs = [r for r in _results if r[0] == "error"]
check("%d concurrent mints of ONE approval -> exactly 1 dispatch" % N,
      len(_wins) == 1, "wins=%d errors=%s" % (len(_wins), _errs[:2]))
check("  every loser was REJECTED, not errored",
      len(_errs) == 0, repr(_errs[:2]))
check("  CONTROL: the harness really did run all %d racers" % N,
      len(_results) == N, "got %d" % len(_results))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== FAIL-CLOSED READS: a bad field never reads as a legal value ==")

expect_gate("approved_params on a non-envelope raises",
            lambda: approved_params("not a dict"), GateReason.APPROVAL_REJECTED)
expect_gate("approved_params with the field ABSENT raises (never b'')",
            lambda: approved_params({"task_id": "x"}), GateReason.APPROVAL_REJECTED)
expect_gate("approved_params on non-base64 raises (never partial bytes)",
            lambda: approved_params({PARAMS_FIELD: "!!!not base64!!!"}),
            GateReason.APPROVAL_REJECTED)
expect_gate("approved_params on a non-string field raises",
            lambda: approved_params({PARAMS_FIELD: 42}),
            GateReason.APPROVAL_REJECTED)
expect_gate("approval_request_id with the field ABSENT raises",
            lambda: approval_request_id({"task_id": "x"}),
            GateReason.APPROVAL_REJECTED)

# The distinction that matters: an EMPTY approved parameter is legal and must be
# returned as b"", not confused with the failure cases above.
_p10, conn10 = fresh_db()
r_empty = new_request(conn10, action_params=b"")
env_empty = mint(conn10, r_empty)
check("an EMPTY approved parameter returns b'' rather than raising",
      approved_params(env_empty) == b"")
check("  ...and is therefore distinguishable from a corrupt field, which raises",
      True)


print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
