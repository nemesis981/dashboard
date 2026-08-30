#!/usr/bin/env python3
"""Admin Approval Protocol v1 — the HTTP wiring (ADR 0026 §D3, A1 build).

Covers the pairing / listing / request routes added 2026-08-30. The protocol
library itself is tested by its own suites; this file tests only the ROUTES —
that they enforce the spec's two opposing gates, that they never leak key
material, and that the challenge they hand out is one a real authenticator can
actually sign and have verified.

⚠ WHAT THIS PROVES, AND WHAT IT CANNOT
--------------------------------------
It proves the SERVER-SIDE round trip with a SYNTHETIC authenticator: a real
P-256 key, a real WebAuthn-shaped assertion over the challenge the route
returned, verified by the real `verify_approval()`, consumed once and refused
the second time.

It does NOT prove a physical touch on a real device. That needs a real
authenticator and a browser over HTTPS, and only the operator can perform it.
Nothing in this file should be read as evidence that half works. The two are
reported separately on purpose.

⚠ ROUTES ARE EXERCISED THROUGH FLASK'S TEST CLIENT, WITH AUTH BYPASSED.
The role gate is `test_roles.py`'s job and is asserted there against
ROUTE_MINIMUMS. Re-asserting it here would prove nothing this suite controls;
what this suite controls is what the handlers DO once reached. The bypass is
explicit below rather than implicit, so no reader mistakes a passing test for
evidence the routes are unauthenticated-safe.

Run:  python3 core/test_admin_approval_routes.py
Exit: 0 all passed · 1 failure(s) · 3 harness could not establish its premise
"""

import os
import sys
import json
import time
import base64
import struct
import hashlib
import sqlite3
import tempfile
import traceback

_PASS, _FAIL = [], []
EXPECTED_CHECKS = 54


def check(label, cond, detail=""):
    (_PASS if cond else _FAIL).append(label)
    print(("  [PASS] " if cond else "  [FAIL] ") + label
          + (("  -- " + str(detail)) if detail and not cond else ""))
    return bool(cond)


def _die(msg):
    print("\nHARNESS PRECONDITION FAILED: %s" % msg)
    sys.exit(3)


_TMP = tempfile.mkdtemp(prefix="nemesis-aaproutes-")
os.environ["NEMESIS_DB_PATH"] = os.path.join(_TMP, "test-alerts.db")

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# MIRRORS the production PYTHONPATH exactly, read from dashboard.service:
#   /opt/nemesis/alert_manager:/opt/nemesis/core_module/hw_monitor
# Copied rather than invented: importing dashboard under a DIFFERENT path than
# the service uses would test a module graph that never runs in production, and
# the failure would look like a test-only quirk in either direction.
for p in (_REPO,
          os.path.join(_REPO, "alert_manager"),
          os.path.join(_REPO, "core_module", "hw_monitor"),
          os.path.join(_REPO, "core")):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    from core import admin_approval as aap
    from core import admin_approval_store as store
    from core import admin_approval_authenticators as auth
    from core import admin_approval_pairing as pairing
    from core import admin_approval_rotation as rotation
except Exception:
    traceback.print_exc()
    _die("could not import the protocol modules")


# ── synthetic authenticator (same shape as core/test_admin_approval.py) ──────
def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def es256_cose(pub):
    n = pub.public_numbers()
    return {1: 2, 3: aap.COSE_ES256, -1: 1,
            -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}


def make_assertion(priv, challenge, rp_hash, rp_id, counter=1, flags=0x05):
    auth_data = rp_hash + bytes([flags]) + struct.pack(">I", counter)
    client = json.dumps({"type": "webauthn.get", "challenge": b64u(challenge),
                         "origin": "https://" + rp_id}).encode()
    sig = priv.sign(auth_data + hashlib.sha256(client).digest(),
                    ec.ECDSA(hashes.SHA256()))
    return {"authenticator_data": auth_data, "client_data_json": client,
            "signature": sig}


KEYS = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
COSE = [es256_cose(k.public_key()) for k in KEYS]
RP_ID = "test-appliance.example.ts.net"
RP_HASH = hashlib.sha256(RP_ID.encode()).digest()


# ── the app ─────────────────────────────────────────────────────────────────
try:
    import dashboard
except Exception:
    traceback.print_exc()
    _die("could not import dashboard")

app = dashboard.app
app.config["TESTING"] = True


def _bypass_auth():
    """Reach the handlers without a session. See the module docstring: the role
    gate is test_roles.py's assertion, not this suite's."""
    # Names read from dashboard.py's @app.before_request handlers, not guessed:
    # _enforce_setup_and_auth (session), _enforce_session_realm, _enforce_role
    # (RBAC). _set_dm_actor is LEFT IN PLACE deliberately — it is the Data
    # Manager's actor stamping, not a gate, and removing it would change what the
    # handlers record rather than what they permit.
    removed = []
    for fn in list(app.before_request_funcs.get(None, [])):
        if fn.__name__ in ("_enforce_setup_and_auth", "_enforce_session_realm",
                           "_enforce_role"):
            app.before_request_funcs[None].remove(fn)
            removed.append(fn.__name__)
    return removed


_removed = _bypass_auth()
if not _removed:
    _die("no auth gate was found to bypass — the handler names have changed, and "
         "a suite that silently bypasses nothing would be testing the redirect")
print("  (bypassed for testing: %s)" % ", ".join(_removed))
client = app.test_client()

# Prove the bypass actually took. If a gate still redirects, every assertion
# below would be about a 302 body rather than the handler's, and "element
# missing" and "page never rendered" produce identical failures.
_probe = client.get("/api/admin-approval/authenticators")
if _probe.status_code in (301, 302):
    _die("auth gate still active (%s) — every result would describe a redirect"
         % _probe.status_code)


def _db():
    return sqlite3.connect(os.environ["NEMESIS_DB_PATH"])


def _reset():
    conn = _db()
    try:
        store.init_admin_approval_tables(conn)
        auth.init_authenticator_tables(conn)
        conn.execute("DELETE FROM admin_approval_authenticators")
        conn.execute("DELETE FROM admin_approval_requests")
        conn.commit()
    finally:
        conn.close()


try:
    _reset()
except Exception:
    traceback.print_exc()
    _die("could not initialise the throwaway schema")


def pair(idx, auth_id, **over):
    body = {"authenticator_id": auth_id, "user_id": "operator",
            "mode": aap.MODE_WEBAUTHN, "cose_alg": aap.COSE_ES256,
            # TAGGED-JSON, via the protocol's own encoder -- the same shape the
            # authenticator table stores and the agent's pinned store holds. Built
            # with tag_bytes() rather than hand-rolled here, so this test cannot
            # pass against an encoding the rest of the system does not use.
            "public_key": aap.tag_bytes(COSE[idx]),
            "rp_id_hash_b64": base64.b64encode(RP_HASH).decode()}
    body.update(over)
    # An explicit None means "omit it", which is how a real browser calls this --
    # it never sends rp_id_hash_b64, leaving the server to derive and pin.
    if body.get("rp_id_hash_b64") is None:
        body.pop("rp_id_hash_b64", None)
    return client.post("/api/admin-approval/pair", json=body)


print("\n== LISTING: empty appliance reports bootstrap open, refuses unlock ==")
r = client.get("/api/admin-approval/authenticators")
j = r.get_json() or {}
check("listing returns 200", r.status_code == 200, r.status_code)
check("no authenticators yet", j.get("authenticators") == [], j)
check("bootstrap is OPEN on a fresh appliance", j.get("bootstrap_open") is True, j)
check("unlock is REFUSED below the floor", j.get("can_unlock") is False, j)
check("refusal states the count, not a bare no",
      "required" in (j.get("unlock_refusal") or ""), j.get("unlock_refusal"))


print("\n== PAIRING: first two need no approval (§5 deadlock avoidance) ==")
r1 = pair(0, "auth-1")
check("first pairing succeeds with NO approval", r1.status_code == 200, r1.get_json())
check("still cannot unlock with only one", (r1.get_json() or {}).get("can_unlock") is False,
      r1.get_json())
r2 = pair(1, "auth-2")
check("second pairing succeeds with NO approval", r2.status_code == 200, r2.get_json())
check("TWO active authenticators now unlock", (r2.get_json() or {}).get("can_unlock") is True,
      r2.get_json())
check("bootstrap has CLOSED after two", (r2.get_json() or {}).get("bootstrap_open") is False,
      r2.get_json())


print("\n== PAIRING: bootstrap does not reopen; third needs an approval ==")
r3 = pair(2, "auth-3")
check("third pairing is REFUSED without an approval", r3.status_code == 409, r3.status_code)
check("refusal names the missing approval",
      "approval" in ((r3.get_json() or {}).get("error") or "").lower(),
      (r3.get_json() or {}).get("error"))
# NEGATIVE CONTROL: the refusal must be about approval, not a malformed body --
# an input-validation 400 would pass a naive "it was refused" assertion.
check("CONTROL: refusal is 409 (policy), not 400 (bad input)", r3.status_code == 409,
      r3.status_code)


print("\n== PAIRING: duplicate id is refused (replace is revoke-then-add) ==")
rdup = pair(2, "auth-1")
check("re-registering an existing id is refused", rdup.status_code in (409, 400),
      rdup.status_code)
conn = _db()
try:
    _stored = auth.get(conn, "auth-1")
finally:
    conn.close()
check("CONTROL: the original key material was NOT replaced",
      aap.key_fingerprint(_stored["public_key"]) == aap.key_fingerprint(COSE[0]),
      "auth-1 key changed")


print("\n== LISTING: no key material, no fingerprints leak ==")
body = client.get("/api/admin-approval/authenticators").get_data(as_text=True)
j = json.loads(body)
check("listing shows both authenticators", len(j.get("authenticators") or []) == 2, j)
check("no public_key field is exposed",
      all("public_key" not in a for a in j["authenticators"]), j)
check("no rp_id_hash is exposed",
      all("rp_id_hash" not in a for a in j["authenticators"]), j)
check("no fingerprint is exposed", "fingerprint" not in body.lower(), "leaked")
# NEGATIVE CONTROL: prove the response is non-trivial -- an empty body would
# satisfy every "does not contain" assertion above.
check("CONTROL: the response does carry the ids (not vacuously clean)",
      "auth-1" in body and "auth-2" in body, body[:200])


print("\n== REQUEST: creates a PENDING request and returns a signable challenge ==")
rq = client.post("/api/admin-approval/request", json={
    "capability": "restart", "target": "device-0001",
    "action_params_b64": base64.b64encode(b'{"cmd":"restart"}').decode(),
    "authenticator_id": "auth-1"})
q = rq.get_json() or {}
check("request created", rq.status_code == 200 and q.get("ok"), q)
check("request_id is returned as hex", len(q.get("request_id") or "") == 32, q)
check("match_code is a 3-digit string", (q.get("match_code") or "").isdigit()
      and len(q["match_code"]) == 3, q.get("match_code"))
check("a challenge is returned", bool(q.get("challenge_b64")), q)
# The nonce is server-only state; leaking it would let a caller precompute.
check("the nonce is NOT returned", "nonce" not in json.dumps(q), q)

conn = _db()
try:
    _rec = store.load_request(conn, bytes.fromhex(q["request_id"]))
finally:
    conn.close()
check("the stored request is PENDING", _rec["state"] == "PENDING", _rec["state"])
# The challenge must be derived from STORED state, not echoed from the request.
_expected = aap.challenge_for(aap.encode_payload(
    request_id=_rec["request_id"], capability=_rec["capability"],
    target=_rec["target"], action_params=_rec["action_params"],
    appliance_id=_rec["appliance_id"], authenticator_id=_rec["authenticator_id"],
    issued_at=_rec["issued_at"], expires_at=_rec["expires_at"],
    match_code=_rec["match_code"], nonce=_rec["nonce"]))
check("the challenge is derived from the STORED record",
      base64.b64decode(q["challenge_b64"]) == _expected, "challenge mismatch")


print("\n== REQUEST: refuses an unknown authenticator and an unmet floor ==")
rbad = client.post("/api/admin-approval/request", json={
    "capability": "restart", "target": "d", "action_params_b64": "",
    "authenticator_id": "auth-nope"})
check("unknown authenticator is refused", rbad.status_code == 409, rbad.status_code)
rbadb = client.post("/api/admin-approval/request", json={
    "capability": "restart", "target": "d",
    "action_params_b64": "!!not base64!!", "authenticator_id": "auth-1"})
check("malformed action_params is refused as bad input", rbadb.status_code == 400,
      rbadb.status_code)


print("\n== ROUND TRIP (synthetic authenticator, NOT a physical touch) ==")
conn = _db()
try:
    _signer = auth.get(conn, "auth-1")
    _signer_record = dict(_signer)
    _assertion = make_assertion(KEYS[0], base64.b64decode(q["challenge_b64"]),
                                RP_HASH, RP_ID)
    _consumed = []

    def _consume(rid):
        ok = store.consume(conn, rid)
        _consumed.append(ok)
        return ok

    verdict = aap.verify_approval(stored_request=_rec, authenticator=_signer,
                                  assertion=_assertion, now=_rec["issued_at"] + 1,
                                  consume=_consume)
    check("the route's challenge VERIFIES against a real signature", verdict.ok,
          getattr(verdict, "detail", verdict))
    check("the approval was consumed exactly once", _consumed == [True], _consumed)
    check("the stored request is now CONSUMED",
          store.load_request(conn, _rec["request_id"])["state"] == "CONSUMED")

    # Replay: the SAME assertion again must fail on consumption, not on signature.
    _consumed2 = []
    v2 = aap.verify_approval(stored_request=_rec, authenticator=_signer,
                             assertion=_assertion, now=_rec["issued_at"] + 2,
                             consume=lambda rid: (_consumed2.append(
                                 store.consume(conn, rid)) or _consumed2[-1]))
    check("REPLAY of the same approval is refused", not v2.ok, v2)
    check("and it is refused at CONSUMPTION (single-use), not signature",
          v2.reason == aap.Reason.CONSUMPTION_RACE, v2.reason)

    # NEGATIVE CONTROL: a tampered challenge must fail at the SIGNATURE, proving
    # the verifier is not simply refusing everything by this point.
    conn.execute("UPDATE admin_approval_requests SET state='PENDING' "
                 "WHERE request_id=?", (_rec["request_id"],))
    conn.commit()
    _bad = make_assertion(KEYS[1], base64.b64decode(q["challenge_b64"]),
                          RP_HASH, RP_ID)          # wrong key
    v3 = aap.verify_approval(stored_request=_rec, authenticator=_signer,
                             assertion=_bad, now=_rec["issued_at"] + 3,
                             consume=lambda rid: store.consume(conn, rid))
    check("CONTROL: a wrong-key signature is refused", not v3.ok, v3)
    check("CONTROL: and refused for a SIGNATURE reason, not consumption",
          v3.reason != aap.Reason.CONSUMPTION_RACE, v3.reason)
finally:
    conn.close()


print("\n== MINT: /approve spends the approval and queues a SIGNED task ==")
# The OUTER envelope needs the server signing key. Generated into the throwaway
# tree rather than mocked: mint_approved_task() calls the real sign_task(), and a
# mocked signer would leave the one thing this section exists to prove -- that a
# real, fully-signed envelope survives to the agent -- untested.
import server_keys as _sk
try:
    _sk.ensure_server_keypair()
except Exception as _e:
    _die("could not create a throwaway server keypair: %s" % _e)
if not _sk.have_server_keypair():
    _die("server keypair still absent after ensure_server_keypair()")
# A fresh request, since the one above was deliberately consumed and replayed.
rq2 = client.post("/api/admin-approval/request", json={
    "capability": "restart", "target": "device-0001",
    "action_params_b64": base64.b64encode(b"{}").decode(),
    "authenticator_id": "auth-1"})
q2 = rq2.get_json() or {}
_asrt = make_assertion(KEYS[0], base64.b64decode(q2["challenge_b64"]), RP_HASH, RP_ID,
                       counter=9)
ap = client.post("/api/admin-approval/approve", json={
    "request_id": q2["request_id"],
    "authenticator_data_b64": base64.b64encode(_asrt["authenticator_data"]).decode(),
    "client_data_json_b64": base64.b64encode(_asrt["client_data_json"]).decode(),
    "signature_b64": base64.b64encode(_asrt["signature"]).decode(),
    "device_id": "device-0001", "action": "restart", "capability": "restart"})
aj = ap.get_json() or {}
check("approve succeeds and returns a task_id", ap.status_code == 200 and aj.get("task_id"), aj)
check("the deliverable window is the 900s decided for this build",
      aj.get("deliverable_for_seconds") == 900, aj)

conn = _db()
try:
    _row = conn.execute("SELECT action, status, approved_envelope FROM scan_tasks "
                        "WHERE task_id=?", (aj.get("task_id"),)).fetchone()
finally:
    conn.close()
check("the task row exists and is pending", _row is not None and _row[1] == "pending", _row)
check("the task carries a stored envelope", bool(_row and _row[2]), "no envelope stored")
_env = json.loads(_row[2])
check("the stored envelope carries the INNER approval block",
      any("approval" in k for k in _env), sorted(_env))
check("REPLAY of the spent approval is refused by /approve",
      client.post("/api/admin-approval/approve", json={
          "request_id": q2["request_id"],
          "authenticator_data_b64": base64.b64encode(_asrt["authenticator_data"]).decode(),
          "client_data_json_b64": base64.b64encode(_asrt["client_data_json"]).decode(),
          "signature_b64": base64.b64encode(_asrt["signature"]).decode(),
          "device_id": "device-0001", "action": "restart",
          "capability": "restart"}).status_code == 409)


print("\n== DELIVERY: the envelope is handed over VERBATIM, not rebuilt ==")
import hw_monitor
_delivered = hw_monitor._tasks_for_response("device-0001")
_mine = [e for e in _delivered if e.get("task_id") == aj.get("task_id")]
check("the approved task is delivered", len(_mine) == 1, len(_delivered))
check("delivered bytes are IDENTICAL to what was minted", _mine and _mine[0] == _env,
      "envelope was rebuilt at delivery")


print("\n== CROSS-SIDE: the AGENT independently verifies the appliance's envelope ==")
# The load-bearing check. The agent re-runs §7 against a key IT pinned, and spends
# the approval AGAIN in its own claim store -- the appliance's consumption record is
# worthless to an agent defending against that appliance.
sys.path.insert(0, os.path.join(_REPO, "nemesis_agent"))
import tasks as agent_tasks
check("`restart` is APPROVAL-REQUIRED on the agent",
      agent_tasks.disposition("restart") == agent_tasks.DISP_APPROVAL_REQUIRED,
      agent_tasks.disposition("restart"))
_pinned = dict(_signer_record)
_claims = []
try:
    _blk = agent_tasks.verify_admin_approval(
        _env, "device-0001", appliance_id=None, now=int(time.time()) + 1,
        lookup=lambda aid: _pinned if aid == _pinned["authenticator_id"] else None,
        claim=lambda rid, exp, now=None: (_claims.append(rid) or True))
    check("the AGENT verifies the appliance-minted approval", bool(_blk))
    check("and it spent the approval in its OWN claim store", len(_claims) == 1, _claims)
except Exception as exc:
    check("the AGENT verifies the appliance-minted approval", False, "%s: %s"
          % (type(exc).__name__, exc))
    check("and it spent the approval in its OWN claim store", False, "not reached")
# CONTROL: the same envelope aimed at a DIFFERENT device must be refused, or the
# target binding proves nothing.
try:
    agent_tasks.verify_admin_approval(
        _env, "device-OTHER", appliance_id=None, now=int(time.time()) + 1,
        lookup=lambda aid: _pinned, claim=lambda rid, exp, now=None: True)
    check("CONTROL: a wrong-target envelope is REFUSED", False, "accepted")
except Exception as exc:
    check("CONTROL: a wrong-target envelope is REFUSED",
          isinstance(exc, agent_tasks.TaskRejected), type(exc).__name__)


print("\n== RP ID: the derive-and-pin branch (the one that shipped broken) ==")
# ⚠ THIS BRANCH HAD NEVER EXECUTED IN A TEST. Every pairing above supplies
# rp_id_hash_b64, which skips it entirely -- so a route that called
# `pin_rp_id()` with no argument passed the whole suite and failed on the second
# live attempt with "missing 1 required positional argument: 'value'". A branch
# with no test that ENTERS it is untested however green the file looks.
#
# The pin file is redirected to the throwaway tree first: pinning is effectively
# one-way, and a test must never pin the real appliance as a side effect.
from core import rp_identity as _rp
_rp.RP_ID_FILE = os.path.join(_TMP, "rp_id_pin")
check("precondition: nothing is pinned in the throwaway tree",
      _rp.pinned_rp_id() is None, _rp.pinned_rp_id())
# Reopen the bootstrap window: by this point the suite has registered two
# authenticators, so pairing would be refused for a DIFFERENT reason (no
# approval) and this section would test that instead of what it is here for.
# bootstrap_open() counts every record ever made, so the rows must go.
_c = _db()
try:
    _c.execute("DELETE FROM admin_approval_authenticators")
    _c.commit()
finally:
    _c.close()

_r = pair(2, "auth-rp", rp_id_hash_b64=None)
_j = _r.get_json() or {}
check("pairing succeeds WITHOUT a client-supplied rp_id_hash",
      _r.status_code == 200 and _j.get("ok"), _j)
check("  ...and it reports the RP ID it pinned on this request",
      bool(_j.get("rp_id_pinned_now")), _j)
check("the pin is now persisted", _rp.pinned_rp_id() is not None)
# CONTROL: a second pairing must NOT re-report a pin -- it is already pinned, and
# claiming otherwise would tell an operator their identity changed.
_r2 = pair(0, "auth-rp2", rp_id_hash_b64=None)
check("CONTROL: a later pairing does not claim to pin again",
      not (_r2.get_json() or {}).get("rp_id_pinned_now"), _r2.get_json())


print("\n== TOTALS ==")
_total = len(_PASS) + len(_FAIL)
check("assertion count matches EXPECTED_CHECKS (drift is a defect)",
      _total + 1 == EXPECTED_CHECKS, "ran %d, expected %d" % (_total + 1, EXPECTED_CHECKS))

import shutil
shutil.rmtree(_TMP, ignore_errors=True)

print("\n%d passed, %d failed" % (len(_PASS), len(_FAIL)))
sys.exit(1 if _FAIL else 0)
