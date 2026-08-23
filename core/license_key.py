"""Licence keys: signed, node-locked, verified OFFLINE.

A licence key is a signed assertion binding a tier and a remote-device cap to one
install id:

    NEMLIC1.<base64url(payload_json)>.<base64url(ed25519_signature)>

── OFFLINE VERIFICATION IS THE POINT ───────────────────────────────────────
The product ships the PUBLIC key and verifies locally. No network, no licence
server, no phone-home. Nemesis is a security appliance whose whole job is to keep
working when other things are down; a licence check that needs the internet would
fail exactly when the product matters most.

Issuing is the asymmetric half and lives elsewhere (`scripts/nemesis-license-issue`)
with the PRIVATE key, which never ships and is never in this repo.

── Ed25519, not RSA ────────────────────────────────────────────────────────
64-byte signatures keep the key short enough to paste. `cryptography` is already
a dependency (hw_monitor uses it to verify agent signatures), so this adds none.

── WHAT THE SIGNATURE COVERS ───────────────────────────────────────────────
The exact payload BYTES that were signed, not a re-serialisation of the parsed
payload. Canonical JSON (sorted keys, no spaces) is used when ISSUING, but
verification never re-serialises -- it verifies the bytes as received and only
then parses them. Two Python versions disagreeing about float formatting or key
order cannot break a valid licence, and a modified payload cannot ride a captured
signature.

── FAILURE IS ALWAYS A NAMED STATE ─────────────────────────────────────────
Never a bare False. "malformed", "bad signature", "wrong install" and "expired"
call for completely different user-facing responses -- one is support, one is a
backup code, one is a renewal. Collapsing them into a boolean throws that away.
"""

import base64
import json
import os
import time

__all__ = ["verify", "Verdict", "LicenseError", "PUBLIC_KEY_B64",
           "encode_payload", "KEY_PREFIX"]

KEY_PREFIX = "NEMLIC1"

#: The issuing PUBLIC key (base64url, 32 bytes). Safe to ship -- it can only
#: verify, never sign.
#:
#: The real issuing key, generated 2026-08-17 on the operator's machine. Its
#: PRIVATE half lives outside every repository (`~/nemesis-issuer/`, mode 0600)
#: and is never committed — see scripts/nemesis-license-issue, whose `keygen`
#: actively refuses to write a private key inside this tree.
#:
#: Publishing the public half is the point: every install must trust the same
#: issuer, and a public key can only verify, never sign.
#:
#: ⚠ NOT ENVIRONMENT-OVERRIDABLE, AND THAT IS THE WHOLE POINT (fixed 2026-08-23).
#: This used to read `os.environ.get("NEMESIS_LICENSE_PUBKEY", ...)`, which made
#: the VERIFICATION key caller-controlled. Proven exploitable end-to-end: generate
#: an Ed25519 keypair, export NEMESIS_LICENSE_PUBKEY=<your public key>, sign
#: {"tier": "commercial"} with your private half, and `verify()` returned
#: verdict=valid, tier=commercial. No source access, no patching, no tooling --
#: one environment variable defeated the entire licensing system.
#:
#: The name is legitimate on the ISSUER side (`licensing-backend/` configures a
#: verification key that way, correctly). Carrying the same affordance into the
#: CLIENT turned it into a bypass. A verifier must trust exactly one issuer, and
#: "exactly one" cannot be a runtime input.
#:
#: TESTS: monkeypatch the module attribute (`lk.PUBLIC_KEY_B64 = ...`) or use
#: `_load_public_key`'s cache reset — see core/test_licensing.py. A test-only
#: seam that exists in the shipped binary is not a test seam, it is a back door.
_PLACEHOLDER = "REPLACE_WITH_ISSUER_PUBLIC_KEY"
PUBLIC_KEY_B64 = "kuTKVWzH-vzIR5Sl7Chf8Z5gf2_yGjE19p_slMqYaOs"


class Verdict:
    """Outcomes of verifying a licence key. Not booleans -- see module docstring."""
    VALID = "valid"
    ABSENT = "absent"                # no key installed: free tier, not an error
    MALFORMED = "malformed"          # not a licence key at all
    BAD_SIGNATURE = "bad_signature"  # forged, corrupted, or wrong issuer
    WRONG_INSTALL = "wrong_install"  # genuine key, different machine
    EXPIRED = "expired"
    NO_PUBKEY = "no_pubkey"          # product misconfigured; NOT the user's fault

    #: Only this grants entitlements.
    GRANTS = (VALID,)


class LicenseError(Exception):
    pass


class Result:
    __slots__ = ("verdict", "detail", "payload")

    def __init__(self, verdict, detail="", payload=None):
        self.verdict = verdict
        self.detail = detail
        self.payload = payload or {}

    @property
    def valid(self):
        return self.verdict in Verdict.GRANTS

    def as_dict(self):
        return {"verdict": self.verdict, "detail": self.detail,
                "valid": self.valid,
                "tier": self.payload.get("tier"),
                "remote_cap": self.payload.get("remote_cap")}

    def __repr__(self):
        return "Result(%s, %r)" % (self.verdict, self.detail[:60])


def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def encode_payload(payload: dict) -> bytes:
    """Canonical payload bytes. Used by the ISSUER; verification never calls it.

    Sorted keys and no whitespace so the same dict always produces the same
    bytes -- otherwise two issuer runs could sign different bytes for an
    identical licence.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _load_public_key():
    if not PUBLIC_KEY_B64 or PUBLIC_KEY_B64 == _PLACEHOLDER:
        raise LicenseError(
            "no issuer public key configured (still the build placeholder). "
            "Bake the real issuer key into "
            "core/license_key.PUBLIC_KEY_B64.")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        raw = _b64u_decode(PUBLIC_KEY_B64)
    except Exception as e:
        raise LicenseError("issuer public key is not valid base64url: %s" % e)
    if len(raw) != 32:
        raise LicenseError("issuer public key must be 32 bytes, got %d" % len(raw))
    return Ed25519PublicKey.from_public_bytes(raw)


def verify(key_str, install_id=None, now=None):
    """Verify a licence key offline. Returns a Result; never raises on bad input.

    `install_id` binds the key to this machine. It is compared EXACTLY here --
    quorum tolerance for hardware drift belongs in core/install_id, which decides
    whether the current machine still counts as the bound install. Doing fuzzy
    matching inside a signature check would mean the signed value and the checked
    value were different things.
    """
    if not (key_str or "").strip():
        return Result(Verdict.ABSENT, "no licence key installed")

    try:
        pub = _load_public_key()
    except LicenseError as e:
        # The product is misconfigured. This is NOT "your licence is invalid",
        # and must never be shown to a user as though it were their problem.
        return Result(Verdict.NO_PUBKEY, str(e))

    parts = key_str.strip().replace("\n", "").split(".")
    if len(parts) != 3 or parts[0] != KEY_PREFIX:
        return Result(Verdict.MALFORMED,
                      "not a Nemesis licence key (expected %s.<payload>.<sig>)"
                      % KEY_PREFIX)
    _, payload_b64, sig_b64 = parts

    try:
        payload_bytes = _b64u_decode(payload_b64)
        sig = _b64u_decode(sig_b64)
    except Exception as e:
        return Result(Verdict.MALFORMED, "key is not valid base64url: %s" % e)

    # Verify the BYTES AS RECEIVED, before parsing them. Parsing first and
    # re-encoding would verify a re-serialisation, not the licence.
    from cryptography.exceptions import InvalidSignature
    try:
        pub.verify(sig, payload_bytes)
    except InvalidSignature:
        return Result(Verdict.BAD_SIGNATURE,
                      "signature does not verify against the issuer key -- the "
                      "key is corrupted, altered, or not issued by this vendor")
    except Exception as e:
        return Result(Verdict.BAD_SIGNATURE, "signature check failed: %s" % e)

    try:
        payload = json.loads(payload_bytes)
    except Exception as e:
        # Signature verified but the content is unreadable: an issuer bug, not
        # tampering. Distinguished so it is not misreported as forgery.
        return Result(Verdict.MALFORMED,
                      "signature verified but payload is not JSON: %s" % e)

    exp = payload.get("expires_at")
    if exp:
        try:
            if float(exp) < (time.time() if now is None else now):
                return Result(Verdict.EXPIRED,
                              "licence expired", payload)
        except (TypeError, ValueError):
            return Result(Verdict.MALFORMED, "unparseable expires_at", payload)

    bound = (payload.get("install_id") or "").strip()
    if install_id is not None:
        if not bound:
            return Result(Verdict.MALFORMED,
                          "licence carries no install_id", payload)
        if bound != str(install_id).strip():
            return Result(Verdict.WRONG_INSTALL,
                          "this licence is bound to a different install",
                          payload)

    return Result(Verdict.VALID, "licence valid", payload)
