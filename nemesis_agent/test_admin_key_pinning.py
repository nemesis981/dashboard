#!/usr/bin/env python3
"""Agent-side admin-authenticator pinning (ADR 0026 §D3) — conformance suite.

THE PROPERTY UNDER TEST
-----------------------
ADR 0026 §D3 closes appliance compromise by keeping the admin private key on the
operator's phone. That guarantee reaches the AGENT only if the agent verifies
approvals against a key it PINNED, never one handed to it at task time by the
appliance. This suite is about that pin.

The load-bearing negatives, each of which would silently void the property:

  * a key supplied at use time is not consulted -- lookup is by
    `authenticator_id` against local state only;
  * a re-run of the installer cannot re-anchor which humans the device trusts;
  * a revoked registration is treated as absent, not merely flagged;
  * a corrupt store is DISTINGUISHABLE from an empty one, so a damaged file
    cannot read as "this device was never set up";
  * pinning refuses outright if the protocol module is not deployed, rather than
    storing key material it could never verify against.

Run: python3 nemesis_agent/test_admin_key_pinning.py
"""
import base64
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile

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


def _raises(fn, exc_type):
    try:
        fn()
    except exc_type:
        return True
    except Exception:                                              # noqa: BLE001
        return False
    return False


# ── deploy the protocol module the way the agent build will ─────────────────
#
# Production does a FLAT `import admin_approval`, because agent modules are flat
# and the frozen build bundles sources from one directory. The canonical copy
# lives at `core/admin_approval.py` -- one implementation, not two, since two
# hand-maintained verifiers would drift and the published vectors would only
# catch it after it shipped. Loading it under its flat name here simulates the
# deployed layout rather than papering over the packaging question.
_CANON = os.path.join(ROOT, "core", "admin_approval.py")


def _deploy_protocol_module():
    while _blocker in sys.meta_path:
        sys.meta_path.remove(_blocker)
    spec = importlib.util.spec_from_file_location("admin_approval", _CANON)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["admin_approval"] = mod
    spec.loader.exec_module(mod)
    return mod


class _BlockAdminApproval:
    """Make `import admin_approval` genuinely fail.

    Popping `sys.modules` USED to be enough, back when no `admin_approval.py` sat
    beside the agent. It no longer is: the module is now a real, shipped part of
    the payload, so a pop just causes a fresh successful import from disk and the
    "not deployed" test silently stopped testing anything. Caught by this suite
    regressing 52/0 -> 50/2 the moment the mirror was added, which is the outcome
    worth having -- a simulation whose premise has quietly expired should break
    loudly rather than keep passing.
    """

    def find_module(self, fullname, path=None):                    # legacy hook
        return self if fullname == "admin_approval" else None

    def find_spec(self, fullname, path=None, target=None):
        if fullname == "admin_approval":
            raise ImportError("No module named 'admin_approval' (blocked by test)")
        return None


_blocker = _BlockAdminApproval()


def _undeploy_protocol_module():
    sys.modules.pop("admin_approval", None)
    if _blocker not in sys.meta_path:
        sys.meta_path.insert(0, _blocker)


import config                                                      # noqa: E402
import enrollment                                                  # noqa: E402

_TMP = tempfile.mkdtemp(prefix="adminpin-")
config.CONF_PATH = os.path.join(_TMP, "nemesis.conf")


def fresh_keys_dir():
    kd = config.keys_dir()
    if os.path.isdir(kd):
        shutil.rmtree(kd)
    os.makedirs(kd, exist_ok=True)
    return kd


# ── fixtures ────────────────────────────────────────────────────────────────
aap = _deploy_protocol_module()
from cryptography.hazmat.primitives.asymmetric import ec           # noqa: E402

RP_ID_HASH = hashlib.sha256(b"nemesis.local").digest()


def es256_cose(pub):
    n = pub.public_numbers()
    return {1: 2, 3: aap.COSE_ES256, -1: 1,
            -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}


def registration(auth_id="phone-1", user_id="admin-1", revoked=False, priv=None):
    priv = priv or ec.generate_private_key(ec.SECP256R1())
    return {
        "authenticator_id": auth_id, "user_id": user_id,
        "mode": aap.MODE_WEBAUTHN, "cose_alg": aap.COSE_ES256,
        "public_key": es256_cose(priv.public_key()),
        "sign_count": 0, "rp_id_hash": RP_ID_HASH,
        "registered_at": 1_700_000_000, "revoked": revoked,
    }


def payload(records):
    """Serialise as the install conf will carry it (tagged JSON)."""
    return json.dumps([enrollment._tag_bytes(r) for r in records])


# ═══════════════════════════════════════════════════════════════════════════
print("\n== ROUND TRIP: byte fields survive the store exactly ==")

fresh_keys_dir()
r1, r2 = registration("phone-1"), registration("phone-2")
check("pinning a two-authenticator set succeeds",
      enrollment.pin_admin_authenticators(payload([r1, r2])) is True)

back = enrollment.pinned_admin_authenticators()
check("both registrations read back", len(back) == 2, "got %d" % len(back))

by_id = {r["authenticator_id"]: r for r in back}
check("rp_id_hash survives as 32 raw BYTES, not a base64 string",
      isinstance(by_id["phone-1"]["rp_id_hash"], bytes)
      and by_id["phone-1"]["rp_id_hash"] == RP_ID_HASH)
check("COSE integer labels survive as INTS, not strings",
      set(by_id["phone-1"]["public_key"]) == set(r1["public_key"]),
      repr(sorted(map(str, by_id["phone-1"]["public_key"]))))
check("COSE coordinate bytes survive exactly",
      by_id["phone-1"]["public_key"][-2] == r1["public_key"][-2]
      and by_id["phone-1"]["public_key"][-3] == r1["public_key"][-3])
check("the restored key actually LOADS (not merely shaped right)",
      aap.cose_key_to_public(by_id["phone-1"]["public_key"]) is not None)

# CONTROL: prove the round trip is doing real work -- a naive json.dumps of the
# same record cannot even be serialised, which is why the tagging exists.
check("  CONTROL: plain json.dumps of a registration FAILS (bytes/int keys)",
      _raises(lambda: json.dumps(r1), TypeError))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== LOOKUP: by pinned id only, never from the request ==")

check("a pinned id resolves",
      enrollment.pinned_admin_authenticator("phone-1")["authenticator_id"] == "phone-1")
check("an UNKNOWN id resolves to None (caller must refuse)",
      enrollment.pinned_admin_authenticator("attacker-key") is None)
check("an empty id resolves to None",
      enrollment.pinned_admin_authenticator("") is None)
check("None resolves to None (no crash on hostile input)",
      enrollment.pinned_admin_authenticator(None) is None)

fresh_keys_dir()
enrollment.pin_admin_authenticators(payload([registration("phone-1"),
                                             registration("phone-2", revoked=True)]))
check("a REVOKED registration resolves to None (revocation is not advisory)",
      enrollment.pinned_admin_authenticator("phone-2") is None)
check("  ...while it is still PRESENT in the raw store (not silently dropped)",
      any(r["authenticator_id"] == "phone-2"
          for r in enrollment.pinned_admin_authenticators()))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== NON-DESTRUCTIVE: an installer re-run cannot re-anchor trust ==")

fresh_keys_dir()
good = registration("phone-1")
enrollment.pin_admin_authenticators(payload([good, registration("phone-2")]))
first = enrollment.admin_authenticators_fingerprint()

rogue = registration("phone-1")            # same id, ATTACKER's key
check("a second pin returns True (idempotent, not an error)",
      enrollment.pin_admin_authenticators(payload([rogue])) is True)
check("...but the pinned key is UNCHANGED (no silent re-anchor)",
      enrollment.admin_authenticators_fingerprint() == first)
check("...and the original key is still the one that resolves",
      enrollment.pinned_admin_authenticator("phone-1")["public_key"][-2]
      == good["public_key"][-2])
check("  CONTROL: the rogue key really WAS different",
      rogue["public_key"][-2] != good["public_key"][-2])


# ═══════════════════════════════════════════════════════════════════════════
print("\n== FAIL-CLOSED: empty, corrupt and unvalidatable are all distinct ==")

fresh_keys_dir()
check("nothing pinned -> EMPTY LIST (a real, expected state)",
      enrollment.pinned_admin_authenticators() == [])
check("nothing pinned -> fingerprint is None, not a hash of nothing",
      enrollment.admin_authenticators_fingerprint() is None)
check("an empty payload is a quiet False (feature not enabled yet)",
      enrollment.pin_admin_authenticators("") is False)
check("None payload is a quiet False",
      enrollment.pin_admin_authenticators(None) is False)

# A corrupt store must RAISE -- distinguishable from the empty case above, which
# returns []. Collapsing them would make a damaged file look like a device that
# was simply never set up.
for corrupt, why in (("not json at all", "unparseable json"),
                     ('{"a":1}', "a JSON object rather than a list"),
                     ('[{"untyped_key":1}]', "an untagged key"),
                     ('[{"str:public_key":{"__bytes_b64__":"!!!"}}]', "bad base64")):
    fresh_keys_dir()
    with open(enrollment._admin_auth_path(), "w", encoding="utf-8") as fh:
        fh.write(corrupt)
    # Asserted by CALLING it and failing on any return value -- including `[]`.
    # An earlier version of this asserted `not _raises(lambda: None, Exception)`,
    # which is True unconditionally: a check that cannot fail, reporting a pass it
    # never measured. Exactly the shape this suite exists to catch, written into
    # the suite itself.
    try:
        got = enrollment.pinned_admin_authenticators()
        check("corrupt store RAISES (%s)" % why, False,
              "returned %r instead of raising" % (got,))
        check("  ...and is NOT reported as an empty store", got != [],
              "a damaged file read as an unprovisioned device")
    except enrollment.AdminKeyStoreError:
        check("corrupt store RAISES (%s)" % why, True)
        check("  ...and is NOT reported as an empty store", True)

# Rejections at pin time -- key material that could never work must not reach disk.
for bad, why in (
        ([{k: v for k, v in registration().items() if k != "public_key"}],
         "missing public_key"),
        ([dict(registration(), cose_alg=-999)], "unsupported cose_alg"),
        ([dict(registration(), rp_id_hash=b"short")], "WEBAUTHN with a short rp_id_hash"),
        ([dict(registration(), public_key={1: 2, 3: -7})], "a COSE key that cannot load"),
        ([registration("dup"), registration("dup")], "duplicate authenticator_id"),
        ([], "an empty list"),
):
    fresh_keys_dir()
    check("pin REFUSES %s" % why,
          enrollment.pin_admin_authenticators(payload(bad)) is False)
    check("  ...and writes NOTHING to disk",
          not os.path.exists(enrollment._admin_auth_path()))

fresh_keys_dir()
check("  CONTROL: a VALID payload is accepted by the same path",
      enrollment.pin_admin_authenticators(payload([registration()])) is True)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== NO PROTOCOL MODULE -> refuse to pin at all ==")

fresh_keys_dir()
_undeploy_protocol_module()
try:
    ok = enrollment.pin_admin_authenticators(payload([registration()]))
    check("pinning FAILS when the protocol module is not deployed", ok is False)
    check("  ...and stores no unvalidated key material",
          not os.path.exists(enrollment._admin_auth_path()))
finally:
    _deploy_protocol_module()
check("  CONTROL: with the module redeployed the same payload pins",
      enrollment.pin_admin_authenticators(payload([registration()])) is True)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== FINGERPRINTS: comparable out of band, order-independent ==")

fresh_keys_dir()
a, b = registration("phone-1"), registration("phone-2")
enrollment.pin_admin_authenticators(payload([a, b]))
fp_ab = enrollment.admin_authenticators_fingerprint()
fresh_keys_dir()
enrollment.pin_admin_authenticators(payload([b, a]))          # reversed order
check("the set fingerprint is ORDER-INDEPENDENT",
      enrollment.admin_authenticators_fingerprint() == fp_ab)

fresh_keys_dir()
enrollment.pin_admin_authenticators(payload([a, registration("phone-2")]))
check("  CONTROL: a DIFFERENT key set yields a different fingerprint",
      enrollment.admin_authenticators_fingerprint() != fp_ab)

check("a per-authenticator fingerprint is stable across serialisation",
      enrollment.admin_authenticator_fingerprint(a)
      == enrollment.admin_authenticator_fingerprint(
          enrollment._untag_bytes(json.loads(json.dumps(enrollment._tag_bytes(a))))))
check("a per-authenticator fingerprint is a full sha256 hex digest",
      len(enrollment.admin_authenticator_fingerprint(a)) == 64)
check("two different authenticators fingerprint differently",
      enrollment.admin_authenticator_fingerprint(a)
      != enrollment.admin_authenticator_fingerprint(b))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== ISOLATION: the server anchor is untouched by any of this ==")

check("pinning admin keys did not create a server anchor",
      enrollment.pinned_server_key() is None)
check("the two stores are different files",
      enrollment._admin_auth_path() != enrollment._server_key_path())

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
