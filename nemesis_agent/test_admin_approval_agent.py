#!/usr/bin/env python3
"""Agent-side inner-envelope verification (ADR 0026 §D3) — conformance suite.

THE THREAT MODEL THIS ACTUALLY TESTS
------------------------------------
Not "does a valid approval verify". The question is: **what can an appliance that
has been fully taken over still make this agent do?** It holds the server task
key, so it can mint and sign any outer envelope it likes. Every negative below is
written from that position.

  * forge an approval          -> NO. It has no admin private key (§10.3 tampers)
  * supply its own admin key   -> NO. Lookup is against PINNED state only
  * replay a genuine approval  -> NO. Single-use claim on request_id
  * replay onto another agent  -> NO. target is bound and checked
  * wait out and reuse         -> NO. expires_at is checked agent-side
  * swap the parameters        -> NO. action_params is inside P
  * strip the approval block   -> NO. Default-deny plus ApprovalMissing
  * downgrade to an easier action -> outside this file; that is commit 1's
    default-deny, tested in test_task_classification.py

§10 conformance is inherited: the SAME `admin_approval.py` runs §7 on both sides,
so the appliance suite's vectors, per-reason-code negatives and per-field tampers
apply verbatim. This suite proves the AGENT reaches that code correctly and adds
the checks the protocol cannot make for itself (which device, which appliance,
already-spent-here).

Run: python3 nemesis_agent/test_admin_approval_agent.py
"""
import base64
import hashlib
import importlib.util
import json
import os
import struct
import sys
import tempfile
import threading

ROOT = os.environ.get("NEMESIS_ROOT", "/opt/nemesis")
sys.path.insert(0, os.path.join(ROOT, "nemesis_agent"))
print("  [root] %s" % ROOT)

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


import config                                                      # noqa: E402
_TMP = tempfile.mkdtemp(prefix="aagent-")
config.CONF_PATH = os.path.join(_TMP, "nemesis.conf")

import tasks                                                       # noqa: E402
import admin_approval as aap                                       # noqa: E402
from cryptography.hazmat.primitives import hashes                  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec           # noqa: E402


# ═══════════════════════════════════════════════════════════════════════════
print("\n== PACKAGING: the agent copy is a MIRROR, not a second implementation ==")

_canon = os.path.join(ROOT, "core", "admin_approval.py")
_agent = os.path.join(ROOT, "nemesis_agent", "admin_approval.py")
check("the canonical appliance copy exists", os.path.isfile(_canon))
check("the agent copy exists (it must ship in the payload)", os.path.isfile(_agent))
if os.path.isfile(_canon) and os.path.isfile(_agent):
    _h1 = hashlib.sha256(open(_canon, "rb").read()).hexdigest()
    _h2 = hashlib.sha256(open(_agent, "rb").read()).hexdigest()
    check("the two files are sha256-IDENTICAL (edit core/, then re-sync)",
          _h1 == _h2, "%s vs %s" % (_h1[:16], _h2[:16]))
    # A port would drift; a mirror cannot. This is what makes "one §7, both sides"
    # a fact rather than an intention.
    check("  the agent copy is import-FLAT (no `core.` refs would break it)",
          "from core." not in open(_agent, encoding="utf-8").read())
check("`install_linux.sh` ships the whole agent dir, so no manifest edit is owed",
      "tar -C \"$SCRIPT_DIR\"" in open(
          os.path.join(ROOT, "nemesis_agent", "install_linux.sh"),
          encoding="utf-8").read())


# ── fixtures: a real pinned authenticator and a real signed approval ────────
RP_ID = "nemesis.local"
RP_ID_HASH = hashlib.sha256(RP_ID.encode()).digest()
NOW = 1_700_000_000
DEVICE = "device-0001"
APPLIANCE = "appliance-A"

_admin_priv = ec.generate_private_key(ec.SECP256R1())
_attacker_priv = ec.generate_private_key(ec.SECP256R1())


def cose(pub):
    n = pub.public_numbers()
    return {1: 2, 3: aap.COSE_ES256, -1: 1,
            -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}


PINNED = {"authenticator_id": "phone-1", "user_id": "admin-1",
          "mode": aap.MODE_WEBAUTHN, "cose_alg": aap.COSE_ES256,
          "public_key": cose(_admin_priv.public_key()), "sign_count": 0,
          "rp_id_hash": RP_ID_HASH, "revoked": False}


def only_pinned(auth_id):
    return PINNED if auth_id == "phone-1" else None


_counter = [0]


def make_approval(*, priv=None, params=b'{"cmd":"restart"}', target=DEVICE,
                  appliance=APPLIANCE, auth_id="phone-1", expires=NOW + 300,
                  capability="push_and_run", flags=0x05, request_id=None):
    """Build a genuine signed approval block, the way the gate will emit one."""
    _counter[0] += 1
    rid = request_id or (b"\x00" * 12 + struct.pack(">I", _counter[0]))
    nonce = hashlib.sha256(rid).digest()
    P = aap.encode_payload(
        request_id=rid, capability=capability, target=target, action_params=params,
        appliance_id=appliance, authenticator_id=auth_id, issued_at=NOW,
        expires_at=expires, match_code=427, nonce=nonce)
    auth_data = RP_ID_HASH + bytes([flags]) + struct.pack(">I", 1)
    client = json.dumps({"type": "webauthn.get",
                         "challenge": base64.urlsafe_b64encode(
                             aap.challenge_for(P)).rstrip(b"=").decode(),
                         "origin": "https://" + RP_ID}).encode()
    sig = (priv or _admin_priv).sign(
        auth_data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
    b64 = lambda b: base64.b64encode(b).decode()                   # noqa: E731
    return {
        "v": 1, "mode": aap.MODE_WEBAUTHN, "cose_alg": aap.COSE_ES256,
        "request_id": rid.hex(), "capability": capability, "target": target,
        "appliance_id": appliance, "authenticator_id": auth_id,
        "issued_at": NOW, "expires_at": expires, "match_code": 427,
        "nonce": b64(nonce), "authenticator_data": b64(auth_data),
        "client_data_json": b64(client), "signature": b64(sig),
    }, params


def envelope(block, params, action="push_and_run"):
    return {"task_id": "t-1", "device_id": DEVICE, "action": action,
            tasks.APPROVAL_FIELD: block,
            tasks.APPROVED_PARAMS_FIELD: base64.b64encode(params).decode()}


def verify(env, **kw):
    kw.setdefault("lookup", only_pinned)
    kw.setdefault("appliance_id", APPLIANCE)
    kw.setdefault("now", NOW + 1)
    return tasks.verify_admin_approval(env, DEVICE, **kw)


def refuses(label, env, exc_type, **kw):
    try:
        verify(env, **kw)
        check(label, False, "IT WAS ACCEPTED")
    except exc_type:
        check(label, True)
    except tasks.TaskRejected as exc:
        check(label, False, "refused, but as %s" % type(exc).__name__)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== CONTROL FIRST: a genuine approval verifies ==")
#
# Without this, every refusal below could be an unrelated error and would prove
# nothing at all.

b, p = make_approval()
try:
    got = verify(envelope(b, p))
    check("CONTROL: a genuine, correctly-signed approval is ACCEPTED",
          got["request_id"] == b["request_id"])
except Exception as exc:                                           # noqa: BLE001
    check("CONTROL: a genuine, correctly-signed approval is ACCEPTED", False,
          repr(exc))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== A COMPROMISED APPLIANCE CANNOT FORGE ==")

b, p = make_approval(priv=_attacker_priv)
refuses("signed with an ATTACKER key -> refused", envelope(b, p),
        tasks.ApprovalBadSignature)

# THE SHARPEST CASE, and the one this whole design exists for. The attacker signs
# with its own key AND ships that key inside the envelope, exactly as a compromised
# appliance would if it thought the agent might use it.
#
# Note what is being asserted: not "the block has no key field" (trivially true
# today and therefore untestable), but "a block that DOES carry key material is
# refused anyway". That distinction matters -- the first is a property of today's
# emitter, the second is a property of the VERIFIER, and only the second survives
# someone later adding a field to the block.
b, p = make_approval(priv=_attacker_priv, auth_id="phone-1")
rogue = dict(b,
             public_key=aap and {str(k): (base64.b64encode(v).decode()
                                          if isinstance(v, bytes) else v)
                                 for k, v in cose(_attacker_priv.public_key()).items()},
             cose_alg=aap.COSE_ES256,
             rp_id_hash=base64.b64encode(RP_ID_HASH).decode())
refuses("attacker-signed block CARRYING its own public key -> refused",
        envelope(rogue, p), tasks.ApprovalBadSignature)
check("  ...refused because the PINNED key was used, not the supplied one",
      True)

# The same block, verified against a lookup that DOES trust the wire, is accepted --
# which is what makes the refusal above a real measurement rather than a tautology.
# If this demonstration ever stops reproducing, the negative above proves less than
# it claims and both need re-deriving.
_wire_trusting = lambda _a: {                                      # noqa: E731
    "authenticator_id": "phone-1", "user_id": "admin-1",
    "mode": aap.MODE_WEBAUTHN, "cose_alg": aap.COSE_ES256,
    "public_key": cose(_attacker_priv.public_key()), "sign_count": 0,
    "rp_id_hash": RP_ID_HASH, "revoked": False}
try:
    verify(envelope(rogue, p), lookup=_wire_trusting)
    check("  CONTROL: a wire-TRUSTING lookup accepts the very same forgery", True)
except tasks.TaskRejected as exc:
    check("  CONTROL: a wire-TRUSTING lookup accepts the very same forgery", False,
          "did not reproduce (%s) -- the negative above proves less" % type(exc).__name__)

b, p = make_approval(priv=_attacker_priv)
refuses("attacker key with NO pinned authenticator -> refused",
        envelope(b, p), tasks.ApprovalUnknownAuthenticator, lookup=lambda a: None)

# THE ACTUAL ATTACK, and the one the two cases above do NOT cover between them:
# an attacker does not reuse a pinned authenticator_id (whose key it cannot match).
# It invents an id nobody pinned and ships a key for it. That is the only path on
# which a "fall back to the supplied key when lookup misses" regression would ever
# fire -- and with a pinned id in play the fallback is dead code, so neither case
# above exercises it. Found by mutation testing: two earlier framings of this
# section both left that regression alive.
b, p = make_approval(priv=_attacker_priv, auth_id="phone-INVENTED")
rogue_unpinned = dict(
    b,
    public_key={str(k): (base64.b64encode(v).decode() if isinstance(v, bytes) else v)
                for k, v in cose(_attacker_priv.public_key()).items()},
    cose_alg=aap.COSE_ES256,
    rp_id_hash=base64.b64encode(RP_ID_HASH).decode())
refuses("INVENTED authenticator_id + its own key -> refused (the real attack)",
        envelope(rogue_unpinned, p), tasks.ApprovalUnknownAuthenticator)

b, p = make_approval(auth_id="phone-99")
refuses("an UNPINNED authenticator_id -> refused", envelope(b, p),
        tasks.ApprovalUnknownAuthenticator)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== PARAMETER BINDING: swapping the work invalidates the approval ==")

b, p = make_approval(params=b'{"cmd":"restart"}')
env = envelope(b, p)
env[tasks.APPROVED_PARAMS_FIELD] = base64.b64encode(b'{"cmd":"rm -rf /"}').decode()
refuses("params swapped after signing -> refused (action_params is inside P)",
        env, tasks.ApprovalBadSignature)

b, p = make_approval(params=b"")
try:
    verify(envelope(b, p))
    check("an EMPTY approved parameter is legal and verifies", True)
except Exception as exc:                                           # noqa: BLE001
    check("an EMPTY approved parameter is legal and verifies", False, repr(exc))

env = envelope(*make_approval())
env[tasks.APPROVED_PARAMS_FIELD] = "!!!not base64!!!"
refuses("non-base64 params -> refused, not silently truncated", env,
        tasks.ApprovalMalformed)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== BINDING: this device, this appliance, this time window ==")

b, p = make_approval(target="some-other-device")
refuses("approval bound to ANOTHER device -> refused", envelope(b, p),
        tasks.ApprovalWrongTarget)

b, p = make_approval(appliance="appliance-EVIL")
refuses("approval issued by another appliance -> refused", envelope(b, p),
        tasks.ApprovalWrongTarget)

b, p = make_approval(expires=NOW + 10)
refuses("EXPIRED approval -> refused (agent checks the clock itself)",
        envelope(b, p), tasks.ApprovalExpired, now=NOW + 5_000)

b, p = make_approval(flags=0x01)          # UV bit clear
refuses("user verification NOT asserted -> refused (§7 step 8)",
        envelope(b, p), tasks.ApprovalBadSignature)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== REPLAY: an approval is single-use ON THIS AGENT ==")

b, p = make_approval()
env = envelope(b, p)
verify(env)
refuses("the SAME approval a second time -> refused as replayed", env,
        tasks.ApprovalReplayed)

# The load-bearing detail: a fresh task_id around an old approval must not help,
# because a compromised appliance can mint task_ids freely.
env2 = envelope(b, p)
env2["task_id"] = "a-brand-new-task-id"
refuses("  ...even wrapped in a FRESH task_id", env2, tasks.ApprovalReplayed)

# CONTROL: a different approval still works, so the claim store is not simply
# refusing everything after the first.
b2, p2 = make_approval()
try:
    verify(envelope(b2, p2))
    check("  CONTROL: a DIFFERENT approval still verifies", True)
except Exception as exc:                                           # noqa: BLE001
    check("  CONTROL: a DIFFERENT approval still verifies", False, repr(exc))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== CONCURRENCY: one approval authorises exactly ONE execution ==")

bC, pC = make_approval()
N = 16
_res, _lock, _bar = [], threading.Lock(), threading.Barrier(N)


def racer():
    _bar.wait()
    try:
        verify(envelope(bC, pC))
        with _lock:
            _res.append("ok")
    except tasks.TaskRejected:
        with _lock:
            _res.append("refused")
    except Exception as exc:                                       # noqa: BLE001
        with _lock:
            _res.append("error:%r" % exc)


_ts = [threading.Thread(target=racer) for _ in range(N)]
for t in _ts:
    t.start()
for t in _ts:
    t.join()
check("%d concurrent verifications -> exactly 1 accepted" % N,
      _res.count("ok") == 1, "ok=%d %s" % (_res.count("ok"), _res[:3]))
check("  every loser was REFUSED, not errored",
      not [r for r in _res if r.startswith("error")],
      repr([r for r in _res if r.startswith("error")][:2]))
check("  CONTROL: the harness ran all %d racers" % N, len(_res) == N,
      "got %d" % len(_res))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== MALFORMED / MISSING: refuse with a DISTINCT reason, never a crash ==")

refuses("no admin_approval block at all -> ApprovalMissing",
        {"action": "push_and_run"}, tasks.ApprovalMissing)
refuses("admin_approval is not an object", {"action": "x", tasks.APPROVAL_FIELD: 7},
        tasks.ApprovalMalformed)
b, p = make_approval()
env = envelope(b, p)
del env[tasks.APPROVED_PARAMS_FIELD]
refuses("approved params field missing", env, tasks.ApprovalMalformed)
for field in ("authenticator_id", "request_id", "capability"):
    b, p = make_approval()
    bad = dict(b)
    bad.pop(field)
    refuses("missing %-18s -> ApprovalMalformed" % field, envelope(bad, p),
            tasks.ApprovalMalformed)
for field in ("issued_at", "expires_at", "match_code"):
    b, p = make_approval()
    refuses("non-numeric %-15s -> ApprovalMalformed" % field,
            envelope(dict(b, **{field: "not-a-number"}), p), tasks.ApprovalMalformed)

check("every refusal type is a TaskRejected (existing handlers catch them)",
      all(issubclass(c, tasks.TaskRejected) for c in (
          tasks.ApprovalMissing, tasks.ApprovalMalformed,
          tasks.ApprovalUnknownAuthenticator, tasks.ApprovalWrongTarget,
          tasks.ApprovalExpired, tasks.ApprovalBadSignature,
          tasks.ApprovalReplayed)))
_reasons = [c.reason for c in (
    tasks.ApprovalMissing, tasks.ApprovalMalformed,
    tasks.ApprovalUnknownAuthenticator, tasks.ApprovalWrongTarget,
    tasks.ApprovalExpired, tasks.ApprovalBadSignature, tasks.ApprovalReplayed)]
check("every refusal reason is DISTINCT (why must not be inferred)",
      len(set(_reasons)) == len(_reasons), repr(_reasons))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== CLASSIFICATION: the approval tier, and which way ambiguity resolves ==")

check("the approval-required set is EMPTY (push_and_run is not built -- ADR §6)",
      tasks.BASE_APPROVAL_REQUIRED_ACTIONS == frozenset())
tasks.register_approval_required_action("push_and_run", "test")
check("a registered action reports APPROVAL_REQUIRED",
      tasks.disposition("push_and_run") == tasks.DISP_APPROVAL_REQUIRED)
check("  ...and assert_dispatchable RETURNS that, rather than raising",
      tasks.assert_dispatchable("push_and_run") == tasks.DISP_APPROVAL_REQUIRED)

# An action in BOTH sets must resolve to the STRICTER reading. Resolved the other
# way it would silently drop the admin check while looking classified.
tasks.register_exempt_action("push_and_run", "deliberate conflict for the test")
check("an action in BOTH sets resolves to APPROVAL_REQUIRED (stricter wins)",
      tasks.disposition("push_and_run") == tasks.DISP_APPROVAL_REQUIRED)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== MUTATION: the approval self-test must DIE against a broken verifier ==")

try:
    tasks.approval_self_test()
    check("CONTROL: unmutated approval_self_test PASSES", True)
except Exception as exc:                                           # noqa: BLE001
    check("CONTROL: unmutated approval_self_test PASSES", False, repr(exc))

_real = tasks.verify_admin_approval
MUTANTS = [
    ("always ACCEPTS (a compromised appliance walks straight in)",
     lambda *a, **k: {"forged": True}),
    ("accepts anything with a block, however unpinned",
     lambda env, dev, **k: env.get(tasks.APPROVAL_FIELD) or {}),
]
for label, mut in MUTANTS:
    tasks.verify_admin_approval = mut
    try:
        tasks.approval_self_test()
        check("mutant CAUGHT: %s" % label, False, "the self-test passed anyway")
    except tasks.VerifierBroken:
        check("mutant CAUGHT: %s" % label, True)
    except Exception as exc:                                       # noqa: BLE001
        check("mutant CAUGHT: %s" % label, False,
              "died of an UNRELATED error, proving nothing: %r" % exc)
    finally:
        tasks.verify_admin_approval = _real
check("CONTROL: the real verifier was restored",
      tasks.verify_admin_approval is _real)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== END TO END: the GATE mints it, the AGENT verifies it ==")
#
# The single most important test in this file. Everything above verifies blocks
# this suite built itself -- which proves the verifier is correct about a format
# the SUITE agrees with, not necessarily the one the appliance emits. The wire
# contract is written in two files (`core/admin_approval_gate.py` emits,
# `nemesis_agent/tasks.py` consumes) and nothing but this section makes them
# agree. A field renamed on one side would pass every other check here.

sys.path.insert(0, ROOT)
import sqlite3                                                     # noqa: E402
from core import admin_approval_gate as gate                       # noqa: E402
from core.admin_approval_store import (                            # noqa: E402
    init_admin_approval_tables, create_request)

check("the two sides agree on the envelope field NAME",
      gate.APPROVAL_FIELD == tasks.APPROVAL_FIELD,
      "%r vs %r" % (gate.APPROVAL_FIELD, tasks.APPROVAL_FIELD))
check("the two sides agree on the approved-params field NAME",
      gate.PARAMS_FIELD == tasks.APPROVED_PARAMS_FIELD,
      "%r vs %r" % (gate.PARAMS_FIELD, tasks.APPROVED_PARAMS_FIELD))

_dbp = os.path.join(_TMP, "gate.db")
_conn = sqlite3.connect(_dbp)
init_admin_approval_tables(_conn)

E2E_PARAMS = b'{"cmd":"restart","args":["-f"]}'
rec = create_request(_conn, user_id="admin-1", capability="push_and_run",
                     target=DEVICE, action_params=E2E_PARAMS,
                     appliance_id=APPLIANCE, authenticator_id="phone-1",
                     ttl_seconds=300, now=NOW)

# A real assertion over the real stored request, exactly as the phone would make.
_P = aap.encode_payload(
    request_id=rec["request_id"], capability=rec["capability"], target=rec["target"],
    action_params=rec["action_params"], appliance_id=rec["appliance_id"],
    authenticator_id=rec["authenticator_id"], issued_at=rec["issued_at"],
    expires_at=rec["expires_at"], match_code=rec["match_code"], nonce=rec["nonce"])
_ad = RP_ID_HASH + bytes([0x05]) + struct.pack(">I", 1)
_cd = json.dumps({"type": "webauthn.get",
                  "challenge": base64.urlsafe_b64encode(
                      aap.challenge_for(_P)).rstrip(b"=").decode(),
                  "origin": "https://" + RP_ID}).encode()
_assertion = {"authenticator_data": _ad, "client_data_json": _cd,
              "signature": _admin_priv.sign(_ad + hashlib.sha256(_cd).digest(),
                                            ec.ECDSA(hashes.SHA256()))}

minted = gate.mint_approved_task(
    conn=_conn, request_id=rec["request_id"], authenticator=PINNED,
    assertion=_assertion, now=NOW + 1, device_id=DEVICE, action="push_and_run",
    capability="push_and_run", sign=lambda _e: "outer-signature-not-under-test")
check("the gate minted an envelope", isinstance(minted, dict))

# THE ASSERTION THAT MATTERS: the agent's verifier, unmodified, accepts it.
try:
    blk = tasks.verify_admin_approval(minted, DEVICE, appliance_id=APPLIANCE,
                                      now=NOW + 2, lookup=only_pinned)
    check("the AGENT verifies a GATE-minted envelope end to end", True)
    check("  ...and the approved bytes arrive intact",
          base64.b64decode(minted[tasks.APPROVED_PARAMS_FIELD]) == E2E_PARAMS)
    check("  ...bound to the same request the appliance consumed",
          blk["request_id"] == rec["request_id"].hex())
except Exception as exc:                                           # noqa: BLE001
    check("the AGENT verifies a GATE-minted envelope end to end", False, repr(exc))

# The gate must NOT ship key material -- the agent resolves the key from its pin.
_blk = minted[gate.APPROVAL_FIELD]
check("the minted block carries NO key material",
      not [k for k in _blk if k in ("public_key", "cose_key", "private_key")],
      repr(sorted(_blk)))
check("  CONTROL: it DOES carry every field P is rebuilt from",
      all(k in _blk for k in ("capability", "target", "appliance_id",
                              "authenticator_id", "issued_at", "expires_at",
                              "match_code", "nonce", "request_id")),
      repr(sorted(_blk)))
check("the minted envelope carries no legacy `params` key", "params" not in minted)

# Tamper the gate's own output: the agent must reject it. This is the compromised
# appliance modifying a genuine envelope in flight.
_t = json.loads(json.dumps(minted))
_t[tasks.APPROVED_PARAMS_FIELD] = base64.b64encode(b'{"cmd":"rm -rf /"}').decode()
try:
    tasks.verify_admin_approval(_t, DEVICE, appliance_id=APPLIANCE, now=NOW + 2,
                                lookup=only_pinned)
    check("a GATE-minted envelope with swapped params is REJECTED", False,
          "IT WAS ACCEPTED")
except tasks.ApprovalBadSignature:
    check("a GATE-minted envelope with swapped params is REJECTED", True)
except tasks.TaskRejected as exc:
    check("a GATE-minted envelope with swapped params is REJECTED", False,
          "refused as %s" % type(exc).__name__)


print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
