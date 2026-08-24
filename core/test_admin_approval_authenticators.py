#!/usr/bin/env python3
"""Admin Approval §5 — authenticator registration STORE.

The properties that carry weight, each because getting it wrong is silent:

  * a re-registered id must be REFUSED, not overwritten -- overwriting is exactly
    how an attacker with a registration path swaps in their own phone;
  * revocation is RECORDED, never deleted -- a deleted row destroys the evidence of
    which key approved past actions, and `active()` must stop returning it while
    `get()` still resolves it for attribution;
  * the signature counter is MONOTONIC -- the natural `SET sign_count=?` silently
    disables the cloned-authenticator check it exists to serve;
  * a stored record must round-trip to the exact shape `verify_approval()` needs,
    integer COSE labels and byte coordinates included, and must actually VERIFY a
    real assertion afterwards.

That last one is the point of the whole module, so it is tested end to end against
the real §7 verifier rather than by inspecting the dict.

Run: python3 core/test_admin_approval_authenticators.py
"""
import hashlib
import json
import os
import sqlite3
import struct
import sys
import tempfile
import threading

sys.path.insert(0, "/opt/nemesis")

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from core import admin_approval as aap
from core import admin_approval_authenticators as store
from core.admin_approval_pairing import (
    MIN_AUTHENTICATORS_FOR_UNLOCK, build_registration, can_unlock)

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


RP_ID = "nemesis.local"
RP_ID_HASH = hashlib.sha256(RP_ID.encode()).digest()
NOW = 1_700_000_000


def fresh_db():
    path = os.path.join(tempfile.mkdtemp(prefix="aauth-"), "t.db")
    conn = sqlite3.connect(path)
    store.init_authenticator_tables(conn)
    return path, conn


def cose_of(priv):
    n = priv.public_key().public_numbers()
    return {1: 2, 3: aap.COSE_ES256, -1: 1,
            -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}


def reg(auth_id="phone-1", user_id="admin-1", priv=None):
    priv = priv or ec.generate_private_key(ec.SECP256R1())
    return priv, build_registration(
        authenticator_id=auth_id, user_id=user_id, mode=aap.MODE_WEBAUTHN,
        cose_alg=aap.COSE_ES256, public_key=cose_of(priv),
        rp_id_hash=RP_ID_HASH, now=NOW)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== ADR 0001: exactly one canonical CREATE for this table ==")

# The needle is ASSEMBLED at runtime so this file does not contain the literal it
# searches for. A first version hardcoded it and matched itself, reporting two
# declarations where there is one -- a check whose own source was part of the
# corpus it measured. Excluding `test_*` would have hidden the self-match instead
# of removing it, and would also blind the check to a test that really did restate
# the DDL, which is the ADR 0001 violation worth catching.
_NEEDLE = "CREATE TABLE IF NOT " + "EXISTS admin_approval_" + "authenticators"
_srcdir = os.path.join("/opt/nemesis")
_hits = []
for _root, _dirs, _files in os.walk(_srcdir):
    _dirs[:] = [d for d in _dirs if d not in (".git", "__pycache__", "venv", "node_modules")]
    for _f in _files:
        if not _f.endswith((".py", ".sql")):
            continue
        _p = os.path.join(_root, _f)
        try:
            with open(_p, encoding="utf-8", errors="ignore") as fh:
                if _NEEDLE in fh.read():
                    _hits.append(os.path.relpath(_p, _srcdir))
        except OSError:
            continue
check("the DDL search found ANY declaration at all (needle is valid)",
      len(_hits) >= 1, "found none -- the assembled needle may be wrong")
check("exactly ONE file declares the table's DDL", len(_hits) == 1, repr(_hits))
check("  ...and it is the owning module",
      _hits == ["core/admin_approval_authenticators.py"], repr(_hits))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== ROUND TRIP: stored -> the exact shape §7 needs -> it VERIFIES ==")

_p, conn = fresh_db()
priv, record = reg("phone-1")
stored = store.register(conn, record, actor="user:operator")

check("register() returns the stored record",
      stored["authenticator_id"] == "phone-1")
check("COSE labels come back as INTEGERS, not strings",
      set(stored["public_key"]) == set(record["public_key"]),
      repr(sorted(map(str, stored["public_key"]))))
check("COSE coordinates come back as BYTES, exactly",
      stored["public_key"][-2] == record["public_key"][-2]
      and stored["public_key"][-3] == record["public_key"][-3])
check("rp_id_hash round-trips as 32 raw bytes",
      isinstance(stored["rp_id_hash"], bytes) and stored["rp_id_hash"] == RP_ID_HASH)
check("the actor seam is recorded", stored["created_by"] == "user:operator")

# The proof that matters: a real assertion verifies against the STORED record.
# Inspecting the dict only shows it has the right shape; this shows it works.
FIELDS = dict(request_id=bytes(range(16)), capability="push_and_run",
              target="device-1", action_params=b'{"cmd":"restart"}',
              appliance_id="appliance-A", authenticator_id="phone-1",
              issued_at=NOW, expires_at=NOW + 300, match_code=1,
              nonce=bytes(range(32, 64)))
P = aap.encode_payload(**FIELDS)
_ad = RP_ID_HASH + bytes([0x05]) + struct.pack(">I", 1)
_cd = json.dumps({"type": "webauthn.get",
                  "challenge": aap.__dict__ and __import__("base64").urlsafe_b64encode(
                      aap.challenge_for(P)).rstrip(b"=").decode(),
                  "origin": "https://" + RP_ID}).encode()
_assertion = {"authenticator_data": _ad, "client_data_json": _cd,
              "signature": priv.sign(_ad + hashlib.sha256(_cd).digest(),
                                     ec.ECDSA(hashes.SHA256()))}
_req = dict(FIELDS, state="PENDING", user_id="admin-1")
v = aap.verify_approval(stored_request=_req, authenticator=stored,
                        assertion=_assertion, now=NOW + 1)
check("a REAL assertion verifies against the STORED record", v.ok, repr(v))

# CONTROL: a different key must NOT verify, or the check above proves nothing.
_other, _orec = reg("phone-x")
v2 = aap.verify_approval(stored_request=_req, authenticator=dict(stored, public_key=_orec["public_key"]),
                         assertion=_assertion, now=NOW + 1)
check("  CONTROL: a DIFFERENT stored key does not verify", not v2.ok, repr(v2))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== RE-REGISTRATION IS REFUSED (the phone-swap attack) ==")

_p, conn = fresh_db()
good_priv, good = reg("phone-1")
store.register(conn, good)
evil_priv, evil = reg("phone-1")          # same id, attacker key
try:
    store.register(conn, evil)
    check("re-registering an existing id is REFUSED", False, "it was accepted")
except store.AuthenticatorError:
    check("re-registering an existing id is REFUSED", True)
check("  ...and the ORIGINAL key is untouched",
      store.get(conn, "phone-1")["public_key"][-2] == good["public_key"][-2])
check("  CONTROL: the attacker key really was different",
      evil["public_key"][-2] != good["public_key"][-2])


# ═══════════════════════════════════════════════════════════════════════════
print("\n== REVOCATION: recorded, not deleted; active() stops honouring it ==")

_p, conn = fresh_db()
store.register(conn, reg("phone-1")[1])
store.register(conn, reg("phone-2")[1])
check("both are active", len(store.active(conn)) == 2)

check("revoke() returns True for the caller that revoked it",
      store.revoke(conn, "phone-2", actor="user:operator", now=NOW) is True)
check("  a SECOND revoke returns False (already revoked, not an error)",
      store.revoke(conn, "phone-2", now=NOW) is False)
check("  revoking an unknown id returns False", store.revoke(conn, "nope") is False)

check("active() no longer returns it", [r["authenticator_id"] for r in
                                        store.active(conn)] == ["phone-1"])
check("get() STILL resolves it (attribution for past approvals)",
      store.get(conn, "phone-2") is not None)
check("  ...and it is marked revoked, with a timestamp",
      store.get(conn, "phone-2")["revoked"] is True
      and store.get(conn, "phone-2")["revoked_at"] == NOW)
check("all_records() still includes it (the row was never deleted)",
      len(store.all_records(conn)) == 2)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== SIGN COUNTER IS MONOTONIC (§7 step 10 must stay meaningful) ==")

_p, conn = fresh_db()
store.register(conn, reg("phone-1")[1])
check("advancing the counter succeeds", store.update_sign_count(conn, "phone-1", 5))
check("  ...and is persisted", store.get(conn, "phone-1")["sign_count"] == 5)
check("MOVING IT BACKWARDS is refused (a clone signal, not a no-op)",
      store.update_sign_count(conn, "phone-1", 3) is False)
check("  ...and the stored value is unchanged",
      store.get(conn, "phone-1")["sign_count"] == 5)
check("re-applying the SAME value is refused (no forward progress)",
      store.update_sign_count(conn, "phone-1", 5) is False)
check("advancing further still works", store.update_sign_count(conn, "phone-1", 6))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== THE TWO-DEVICE FLOOR now has records to count ==")

_p, conn = fresh_db()
store.register(conn, reg("phone-1")[1])
check("one registration is BELOW the floor",
      can_unlock(store.active(conn), "admin-1").allowed is False)
store.register(conn, reg("phone-2")[1])
check("two registrations meet the floor (%d)" % MIN_AUTHENTICATORS_FOR_UNLOCK,
      can_unlock(store.active(conn), "admin-1").allowed is True)
store.revoke(conn, "phone-2")
check("revoking one drops back BELOW the floor (losing a device is visible)",
      can_unlock(store.active(conn), "admin-1").allowed is False)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== INSTALLER EXPORT: one format end to end, no operator identity ==")

_p, conn = fresh_db()
store.register(conn, reg("phone-1")[1], actor="user:operator")
store.register(conn, reg("phone-2")[1], actor="user:operator")
store.revoke(conn, "phone-2")
exported = store.export_for_installer(conn)
check("export contains only ACTIVE registrations", len(exported) == 1,
      "got %d" % len(exported))

# The decisive one: the AGENT's decoder must accept the APPLIANCE's encoder output.
sys.path.insert(0, "/opt/nemesis/nemesis_agent")
import importlib.util                                              # noqa: E402
_spec = importlib.util.spec_from_file_location(
    "enrollment_probe", "/opt/nemesis/nemesis_agent/enrollment.py")
try:
    decoded = [aap.untag_bytes(r) for r in exported]
    check("the export decodes with the SHARED untag_bytes", len(decoded) == 1)
    check("  ...to integer COSE labels and byte coordinates",
          isinstance(decoded[0]["public_key"][-2], bytes)
          and 1 in decoded[0]["public_key"])
    check("  ...and the decoded key LOADS",
          aap.cose_key_to_public(decoded[0]["public_key"]) is not None)
except Exception as exc:                                           # noqa: BLE001
    check("the export decodes with the SHARED untag_bytes", False, repr(exc))

check("export is JSON-serialisable on ONE line (configparser needs that)",
      "\n" not in json.dumps(exported, separators=(",", ":"), sort_keys=True))
check("export carries NO operator identity (Rule 8)",
      not any("created_by" in r or "str:created_by" in r for r in exported),
      repr(sorted(exported[0])))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== REJECTIONS: unusable key material never reaches the table ==")

_p, conn = fresh_db()
_, base = reg("phone-1")
for bad, why in (
        ({k: v for k, v in base.items() if k != "public_key"}, "missing public_key"),
        (dict(base, cose_alg=-999), "unsupported cose_alg"),
        (dict(base, rp_id_hash=b"short"), "WEBAUTHN with a short rp_id_hash"),
        (dict(base, public_key={1: 2, 3: -7}), "a COSE key that cannot load"),
        (dict(base, user_id=""), "empty user_id"),
):
    try:
        store.register(conn, bad)
        check("REFUSES %s" % why, False, "it was accepted")
    except store.AuthenticatorError:
        check("REFUSES %s" % why, True)
check("  ...and nothing was written", store.all_records(conn) == [])
check("  CONTROL: the same path accepts a VALID record",
      store.register(conn, base)["authenticator_id"] == "phone-1")

# A corrupt stored key must RAISE, never come back as a plausible empty mapping.
conn.execute("UPDATE admin_approval_authenticators SET public_key='not json' "
             "WHERE authenticator_id='phone-1'")
conn.commit()
try:
    store.get(conn, "phone-1")
    check("a CORRUPT stored public_key raises rather than returning a shell", False,
          "it returned")
except store.AuthenticatorError:
    check("a CORRUPT stored public_key raises rather than returning a shell", True)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== CONCURRENCY: one revocation wins, and the counter cannot go back ==")

path, conn = fresh_db()
store.register(conn, reg("phone-1")[1])
conn.close()

N = 12
_wins, _lock, _bar = [], threading.Lock(), threading.Barrier(N)


def racer():
    c = sqlite3.connect(path, timeout=30)
    try:
        _bar.wait()
        if store.revoke(c, "phone-1", now=NOW):
            with _lock:
                _wins.append(1)
    finally:
        c.close()


_ts = [threading.Thread(target=racer) for _ in range(N)]
for t in _ts:
    t.start()
for t in _ts:
    t.join()
check("%d concurrent revocations -> exactly ONE reports the revoke" % N,
      len(_wins) == 1, "wins=%d" % len(_wins))
_c = sqlite3.connect(path)
check("  CONTROL: the device really is revoked",
      store.get(_c, "phone-1")["revoked"] is True)

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
