#!/usr/bin/env python3
"""ADR 0026 §D3 "A2" — appliance-local approval gating, end to end.

Covers the gate added 2026-08-30: an `ip_block_permanent` proposal cannot be
executed without a verified admin approval bound to that exact proposal.

⚠ WHAT THIS PROVES, AND WHAT A2 CANNOT PROVE
--------------------------------------------
The SERVER-SIDE round trip with a SYNTHETIC authenticator: a real P-256 key, a
real WebAuthn-shaped assertion over the challenge the request route returned,
verified by the real `verify_approval()`, consumed once, refused on replay.

It does NOT prove a physical touch on a real device — that needs a real
authenticator and a browser over HTTPS, and only the operator can do it.

And A2 itself does not survive appliance root, by construction: the verifier runs
on the same box as the action. No test here should be read as evidence otherwise.
What A2 defends is session compromise, the engine self-authorizing, and an
unequipped admin acting alone.

Run:  python3 core/test_admin_approval_local.py
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
EXPECTED_CHECKS = 30


def check(label, cond, detail=""):
    (_PASS if cond else _FAIL).append(label)
    print(("  [PASS] " if cond else "  [FAIL] ") + label
          + (("  -- " + str(detail)) if detail and not cond else ""))
    return bool(cond)


def _die(msg):
    print("\nHARNESS PRECONDITION FAILED: %s" % msg)
    sys.exit(3)


_TMP = tempfile.mkdtemp(prefix="nemesis-a2-")
os.environ["NEMESIS_DB_PATH"] = os.path.join(_TMP, "test-alerts.db")

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (_REPO, os.path.join(_REPO, "alert_manager"),
          os.path.join(_REPO, "core_module", "hw_monitor"), os.path.join(_REPO, "core")):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    import modules as _pkg
    _pkg.set_shared_db_path(os.environ["NEMESIS_DB_PATH"])
    import dashboard
    from modules import ai_engine as ai
    from core import admin_approval as aap
    from core import admin_approval_local as local
    from core import admin_approval_store as store
    from core import admin_approval_authenticators as auth
except Exception:
    traceback.print_exc()
    _die("could not import the A2 stack")

if _pkg.get_shared_db_path() != os.environ["NEMESIS_DB_PATH"]:
    _die("resolved a DB other than the throwaway one — refusing to run")

app = dashboard.app
app.config["TESTING"] = True
_removed = []
for fn in list(app.before_request_funcs.get(None, [])):
    if fn.__name__ in ("_enforce_setup_and_auth", "_enforce_session_realm", "_enforce_role"):
        app.before_request_funcs[None].remove(fn)
        _removed.append(fn.__name__)
if not _removed:
    _die("no auth gate found to bypass — a suite that bypasses nothing tests the redirect")
client = app.test_client()
if client.get("/api/ai/proposals").status_code in (301, 302):
    _die("auth gate still active — every assertion would describe a redirect")


def _db():
    return sqlite3.connect(os.environ["NEMESIS_DB_PATH"])


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


RP_ID = "test-appliance.example.ts.net"
RP_HASH = hashlib.sha256(RP_ID.encode()).digest()
KEYS = [ec.generate_private_key(ec.SECP256R1()) for _ in range(2)]


def cose(k):
    n = k.public_key().public_numbers()
    return {1: 2, 3: aap.COSE_ES256, -1: 1,
            -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}


def assertion_for(priv, challenge, counter=1):
    ad = RP_HASH + bytes([0x05]) + struct.pack(">I", counter)
    cd = json.dumps({"type": "webauthn.get", "challenge": b64u(challenge),
                     "origin": "https://" + RP_ID}).encode()
    sig = priv.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
    return {"authenticator_data_b64": base64.b64encode(ad).decode(),
            "client_data_json_b64": base64.b64encode(cd).decode(),
            "signature_b64": base64.b64encode(sig).decode()}


conn = _db()
try:
    store.init_admin_approval_tables(conn)
    auth.init_authenticator_tables(conn)
    for i, k in enumerate(KEYS):
        client.post("/api/admin-approval/pair", json={
            "authenticator_id": "a%d" % i, "user_id": "operator",
            "mode": aap.MODE_WEBAUTHN, "cose_alg": aap.COSE_ES256,
            "public_key": aap.tag_bytes(cose(k)),
            "rp_id_hash_b64": base64.b64encode(RP_HASH).decode()})
finally:
    conn.close()


print("\n== THE GATE IS DECLARED, AND SCOPED ==")
check("ip_block_permanent requires a local approval",
      ai.local_approval_required("ip_block_permanent"))
# CONTROL: the gate must not have become universal — a class NOT listed must be
# unaffected, or "required" proves nothing about scoping.
check("CONTROL: alert_disposition does NOT require one",
      not ai.local_approval_required("alert_disposition"))
check("CONTROL: an unknown class does not require one",
      not ai.local_approval_required("no_such_class"))


print("\n== REFUSAL: an A2 class cannot execute without an approval ==")
pid = ai.create_proposal("ip_block_permanent", "alert", "198.51.100.9", "block",
                         "synthetic", "m")
client.post("/api/ai/proposal/%d/respond" % pid, json={"response": "approved"})
r = client.post("/api/ai/proposal/%d/execute" % pid, json={})
check("execute is refused with no approval supplied", r.status_code in (400, 409),
      r.get_json())
check("  ...and says an approval is required", "approval" in
      ((r.get_json() or {}).get("error") or "").lower(), r.get_json())
check("CONTROL: the proposal was NOT executed", ai.get_proposal(pid)["executed"] == 0)


print("\n== BINDING: local_action_params ties an approval to ONE proposal ==")
p_a = local.local_action_params(action_class="ip_block_permanent",
                                row_id="198.51.100.9", proposed_action="block",
                                proposal_id=pid)
p_b = local.local_action_params(action_class="ip_block_permanent",
                                row_id="198.51.100.9", proposed_action="block",
                                proposal_id=pid + 1)
p_c = local.local_action_params(action_class="ip_block_permanent",
                                row_id="203.0.113.5", proposed_action="block",
                                proposal_id=pid)
check("same inputs produce identical bytes (deterministic)",
      p_a == local.local_action_params(action_class="ip_block_permanent",
                                       row_id="198.51.100.9",
                                       proposed_action="block", proposal_id=pid))
check("a DIFFERENT proposal_id produces different bytes", p_a != p_b)
check("a DIFFERENT target produces different bytes", p_a != p_c)
try:
    local.local_action_params(action_class="ip_block_permanent", row_id="x",
                              proposed_action="block", proposal_id=None)
    check("CONTROL: a missing proposal_id RAISES rather than defaulting", False,
          "accepted None")
except local.LocalApprovalError:
    check("CONTROL: a missing proposal_id RAISES rather than defaulting", True)


def request_approval(proposal_id, row_id, proposed_action, auth_id="a0",
                     action_class="ip_block_permanent"):
    params = local.local_action_params(action_class=action_class, row_id=row_id,
                                       proposed_action=proposed_action,
                                       proposal_id=proposal_id)
    rq = client.post("/api/admin-approval/request", json={
        "capability": action_class, "target": str(row_id),
        "action_params_b64": base64.b64encode(params).decode(),
        "authenticator_id": auth_id})
    return rq.get_json() or {}


print("\n== ROUND TRIP: approval + execute (synthetic authenticator) ==")
q = request_approval(pid, "198.51.100.9", "block")
check("an approval request was created", bool(q.get("challenge_b64")), q)
body = dict(assertion_for(KEYS[0], base64.b64decode(q["challenge_b64"])))
body["approval_request_id"] = q["request_id"]
r = client.post("/api/ai/proposal/%d/execute" % pid, json=body)
j = r.get_json() or {}
# The executor will fail (no real firewall in a test), and that is FINE and is
# asserted deliberately: what matters here is that it got PAST the A2 gate.
check("the A2 gate was satisfied (refusal is no longer about approval)",
      "approval" not in ((j.get("error") or "").lower()), j)

conn = _db()
try:
    _spent = conn.execute("SELECT state FROM admin_approval_requests "
                          "WHERE request_id=?",
                          (bytes.fromhex(q["request_id"]),)).fetchone()
finally:
    conn.close()
check("the approval was CONSUMED by verifying", _spent and _spent[0] == "CONSUMED",
      _spent)


print("\n== THE LOG RECORDS A SPENT APPROVAL, success or not ==")
conn = _db()
try:
    rows = conn.execute("SELECT request_id, action_class, proposal_id, "
                        "authenticator_id, executed_by FROM ai_local_approval_log "
                        "WHERE proposal_id=?", (pid,)).fetchall()
finally:
    conn.close()
check("one log row was appended", len(rows) == 1, rows)
check("it records the action class", rows and rows[0][1] == "ip_block_permanent", rows)
check("it records which authenticator approved", rows and rows[0][3] == "a0", rows)
# The row must exist even though the executor FAILED -- a spent approval that
# authorised a failed action is exactly what an incident reconstruction needs.
check("the row exists even though the executor did not succeed",
      len(rows) == 1 and ai.get_proposal(pid)["executed"] == 0, rows)
check("CONTROL: the log carries NO signature or key material",
      all("signature" not in str(c).lower() for row in rows for c in row), rows)


print("\n== REPLAY: a spent approval cannot authorise a second execution ==")
r2 = client.post("/api/ai/proposal/%d/execute" % pid, json=body)
check("replaying the same approval is refused", r2.status_code == 409, r2.get_json())


print("\n== CROSS-BINDING: an approval for one proposal cannot run another ==")
pid2 = ai.create_proposal("ip_block_permanent", "alert", "198.51.100.9", "block",
                          "second", "m")
client.post("/api/ai/proposal/%d/respond" % pid2, json={"response": "approved"})
# An approval built for pid, presented against pid2. Same class, same target,
# same action -- ONLY the proposal differs, which is exactly the case
# `proposal_id` was folded into the binding to catch.
q2 = request_approval(pid, "198.51.100.9", "block")
body2 = dict(assertion_for(KEYS[0], base64.b64decode(q2["challenge_b64"]), counter=3))
body2["approval_request_id"] = q2["request_id"]
r3 = client.post("/api/ai/proposal/%d/execute" % pid2, json=body2)
check("an approval bound to a different proposal is REFUSED", r3.status_code == 409,
      r3.get_json())
check("  ...and the refusal names the binding, not the signature",
      "authorise" in ((r3.get_json() or {}).get("error") or "").lower()
      or "bound" in ((r3.get_json() or {}).get("error") or "").lower(),
      r3.get_json())


print("\n== WRONG KEY: a signature from an unpaired-for-this-request key fails ==")
pid3 = ai.create_proposal("ip_block_permanent", "alert", "203.0.113.9", "block",
                          "third", "m")
client.post("/api/ai/proposal/%d/respond" % pid3, json={"response": "approved"})
q3 = request_approval(pid3, "203.0.113.9", "block", auth_id="a0")
bad = dict(assertion_for(KEYS[1], base64.b64decode(q3["challenge_b64"]), counter=4))
bad["approval_request_id"] = q3["request_id"]
r4 = client.post("/api/ai/proposal/%d/execute" % pid3, json=bad)
check("a wrong-key signature is refused", r4.status_code == 409, r4.get_json())
check("CONTROL: and it is refused for a SIGNATURE reason, not a binding one",
      "did not verify" in ((r4.get_json() or {}).get("error") or ""), r4.get_json())


print("\n== CEILING RAISE: an A2-gated class needs an approval, not just the password ==")
_pw = "test-master-password-1234"
ai.set_master_password(_pw)
res = ai.raise_authority("ip_block_permanent", 2, _pw, "operator", "test")
check("raising an A2-gated class above L1 is refused on the password alone",
      not res.get("ok"), res)
check("  ...and says an admin approval is needed", res.get("needs_admin_approval"), res)
check("CONTROL: raising WITHIN L1 is still allowed on the password",
      ai.raise_authority("ip_block_permanent", 1, _pw, "operator", "t").get("ok"))
check("CONTROL: a non-A2 class is unaffected by this requirement",
      ai.raise_authority("alert_disposition", 2, _pw, "operator", "t").get("ok"))


print("\n== HONESTY: the on-box-only property is stated in code ==")
check("RECORD_IS_ON_BOX_ONLY is declared true", local.RECORD_IS_ON_BOX_ONLY is True)
check("the module says it does NOT provide non-repudiation",
      "NOT non-repudiation" in (local.__doc__ or "")
      or "not non-repudiation" in (local.__doc__ or "").lower())


print("\n== TOTALS ==")
_total = len(_PASS) + len(_FAIL)
check("assertion count matches EXPECTED_CHECKS (drift is a defect)",
      _total + 1 == EXPECTED_CHECKS, "ran %d, expected %d" % (_total + 1, EXPECTED_CHECKS))

import shutil
shutil.rmtree(_TMP, ignore_errors=True)
print("\n%d passed, %d failed" % (len(_PASS), len(_FAIL)))
sys.exit(1 if _FAIL else 0)
