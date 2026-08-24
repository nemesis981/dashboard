"""Admin Approval Protocol v1 — canonical payload + verification.

⚠ THIS FILE IS MIRRORED, BYTE FOR BYTE, TO `nemesis_agent/admin_approval.py`.
THIS COPY IS CANONICAL; edit here and re-sync, never the other way round.

The agent verifies admin approvals ITSELF (ADR 0026 §D3) rather than trusting the
appliance's word, so both sides run §7 — and they must run the SAME §7. Two
hand-maintained verifiers would drift, and the published vectors would only catch
the drift after it had shipped. So the agent copy is a mechanical duplicate, not a
port, and `nemesis_agent/test_admin_approval_agent.py` asserts the two files are
sha256-identical. That check failing means someone edited one and not the other;
the fix is to re-sync, not to reconcile by hand.

The file is deliberately import-flat (no `core.` references anywhere) so the same
bytes work as `core.admin_approval` on the appliance and as a top-level
`admin_approval` inside the agent's payload. Keep it that way — a single `from
core...` here would break every agent.

IMPLEMENTS: `docs/protocol/admin-approval-v1.md` (held private until this lands).
**That document is the CONTRACT and this file is subordinate to it.** Where the two
disagree, this file is wrong. Nothing here may be inferred from by a reimplementation —
the spec plus the published test vectors are the cross-language contract, which matters
because a compiled server is expected in V3.

WHAT THIS FILE IS NOT: it is not a convenience wrapper over a crypto library. Every
encoding decision below is load-bearing for signature validity across languages, and the
comments say WHY rather than WHAT so a reimplementer knows which choices are free and
which are not.

THE THREE THINGS MOST LIKELY TO BE GOT WRONG, per the spec's own warnings:

  * §7 step 6 — `P` MUST be rebuilt from the appliance's STORED request, never from
    client input. A verifier that accepts a client-supplied field verifies only that the
    client signed something the client chose, which is not authorization at all.
  * §7 step 8 — user verification is checked BY THE SERVER. A UV requirement the server
    does not check does not exist.
  * §4.2 — `action_params` is opaque bytes and MUST NOT be deserialized/reserialized
    between signing and execution; a dict round-trip can reorder keys and the failure
    surfaces as a mysterious signature mismatch rather than as the data bug it is.
"""

import hashlib
import hmac
import struct

__all__ = [
    "DOMAIN", "PROTOCOL_VERSION", "COSE_ES256", "COSE_EDDSA",
    "MODE_WEBAUTHN", "MODE_NATIVE", "SUPPORTED_ALGS",
    "encode_payload", "challenge_for", "lp", "Reason", "ProtocolError",
]

# ── §4: domain separation ────────────────────────────────────────────────────
#: 25 ASCII characters + one NUL = 26 bytes. Stated as an explicit length check
#: rather than a comment, because an off-by-one here produces a payload that
#: verifies against nothing and the error message would be "invalid signature".
DOMAIN = b"nemesis-admin-approval-v1\x00"
assert len(DOMAIN) == 26, "DOMAIN must be exactly 26 bytes (spec §4)"

PROTOCOL_VERSION = 1

# ── §2: algorithms, identified by COSE ID and never by library name ──────────
COSE_ES256 = -7        # REQUIRED: ECDSA P-256 + SHA-256 (what WebAuthn implements)
COSE_EDDSA = -8        # OPTIONAL: Ed25519
SUPPORTED_ALGS = (COSE_ES256, COSE_EDDSA)

# ── §3: authenticator modes ──────────────────────────────────────────────────
MODE_WEBAUTHN = 1
MODE_NATIVE = 2


class Reason:
    """§8 reason codes. Stable across versions; never reassigned.

    A verifier returns exactly one of these and never a bare boolean. "Why was this
    rejected" must not have to be inferred.
    """
    UNKNOWN_REQUEST = "AAP-001"
    ALREADY_CONSUMED = "AAP-002"
    EXPIRED = "AAP-003"
    UNKNOWN_AUTHENTICATOR = "AAP-004"
    NOT_OWNED = "AAP-005"
    ALG_MISMATCH = "AAP-006"
    BINDING_MISMATCH = "AAP-007"
    CHALLENGE_MISMATCH = "AAP-008"
    UV_NOT_ASSERTED = "AAP-009"
    BAD_SIGNATURE = "AAP-010"
    COUNTER_REGRESSION = "AAP-011"
    CONSUMPTION_RACE = "AAP-012"
    RATE_LIMITED = "AAP-013"

    ALL = ("AAP-001", "AAP-002", "AAP-003", "AAP-004", "AAP-005", "AAP-006",
           "AAP-007", "AAP-008", "AAP-009", "AAP-010", "AAP-011", "AAP-012",
           "AAP-013")


class ProtocolError(ValueError):
    """A payload could not be ENCODED. Distinct from a verification rejection:
    this means the appliance's own request record is malformed, which is a bug on
    this side, not an attack from the other."""


def _utf8(name, value):
    """UTF-8 bytes, with NO Unicode normalization (spec §1).

    Normalization is deliberately absent. Runtimes disagree about which form to
    apply, and applying one silently on the signing side produces signatures the
    verifying side cannot reproduce. Both parties operate on exact bytes.
    """
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        raise ProtocolError("%s must be str or bytes, got %s"
                            % (name, type(value).__name__))
    return value.encode("utf-8")


def lp(value: bytes) -> bytes:
    """Length-prefixed byte string: u32(len) || value  (spec §4).

    WHY THIS EXISTS AND IS NOT DECORATIVE: plain concatenation lets two different
    field sets produce identical bytes -- e.g. capability="ab", target="c" and
    capability="a", target="bc". That is a signature-forgery primitive, not a
    cosmetic concern. Length prefixing makes the encoding unambiguous.
    """
    if len(value) > 0xFFFFFFFF:
        raise ProtocolError("field exceeds u32 length prefix")
    return struct.pack(">I", len(value)) + value


def encode_payload(*, request_id: bytes, capability, target, action_params: bytes,
                   appliance_id, authenticator_id, issued_at: int,
                   expires_at: int, match_code: int, nonce: bytes,
                   protocol_version: int = PROTOCOL_VERSION) -> bytes:
    """Build `P`, the canonical approval payload (spec §4).

    KEYWORD-ONLY, deliberately. `P` is an ordered concatenation of ten fields, six
    of which are strings; positional arguments would make a transposition of two
    of them a silent change to what gets authorized rather than a type error.

    Every argument is validated. An appliance that encodes a malformed `P` produces
    a signature request nothing can satisfy, and the resulting failure looks like a
    crypto problem rather than the input-validation problem it is.
    """
    if protocol_version != PROTOCOL_VERSION:
        # §11: a signature made under one version can never be accepted under
        # another, and versions are never mixed.
        raise ProtocolError("unsupported protocol version %r" % (protocol_version,))
    if not isinstance(request_id, bytes) or len(request_id) != 16:
        raise ProtocolError("request_id must be exactly 16 bytes")
    if not isinstance(nonce, bytes) or len(nonce) != 32:
        raise ProtocolError("nonce must be exactly 32 bytes")
    if not isinstance(action_params, bytes):
        # §4.2 -- it is opaque and ALREADY serialized. Accepting a dict here would
        # invite this layer to serialize it, which is exactly the round-trip the
        # spec forbids.
        raise ProtocolError("action_params must be bytes, already serialized "
                            "(spec §4.2); this layer must never serialize it")
    if not isinstance(issued_at, int) or not isinstance(expires_at, int):
        raise ProtocolError("timestamps must be int Unix seconds, never strings")
    if expires_at <= issued_at:
        raise ProtocolError("expires_at must be > issued_at")
    if not isinstance(match_code, int) or not (0 <= match_code <= 999):
        raise ProtocolError("match_code must be 0..999")

    try:
        return b"".join((
            DOMAIN,
            struct.pack(">H", protocol_version),
            lp(request_id),
            lp(_utf8("capability", capability)),
            lp(_utf8("target", target)),
            lp(action_params),
            lp(_utf8("appliance_id", appliance_id)),
            lp(_utf8("authenticator_id", authenticator_id)),
            struct.pack(">q", issued_at),
            struct.pack(">q", expires_at),
            struct.pack(">H", match_code),
            lp(nonce),
        ))
    except struct.error as exc:
        raise ProtocolError("field out of range for its declared width: %s" % exc)


def challenge_for(payload: bytes) -> bytes:
    """SHA-256(P) — the WebAuthn challenge (§6.1) and the NATIVE signed digest (§6.2)."""
    return hashlib.sha256(payload).digest()


def constant_time_eq(a: bytes, b: bytes) -> bool:
    """Timing-safe comparison, used for challenge and rp_id_hash equality.

    Neither is a secret, so this is defence in depth rather than a strict
    requirement -- but a verifier is exactly the place where an equality check
    should not become a side channel if one of these later carries a secret.
    """
    return hmac.compare_digest(a, b)


# ═══════════════════════════════════════════════════════════════════════════
# §6 / §7 — verification
# ═══════════════════════════════════════════════════════════════════════════

import base64
import json


class Verdict:
    """The outcome of a verification. NEVER a bare boolean (spec §7/§8).

    `reason` is one of `Reason.*` on rejection and None on success. `step` records
    which ordered check produced the outcome, so a conformance test can assert the
    EARLIEST failing step fired rather than merely that something failed.
    """
    __slots__ = ("ok", "reason", "step", "detail")

    def __init__(self, ok, reason=None, step=None, detail=""):
        self.ok, self.reason, self.step, self.detail = ok, reason, step, detail

    def __repr__(self):
        return ("Verdict(ok=True)" if self.ok
                else "Verdict(%s at step %s: %s)" % (self.reason, self.step, self.detail))


def _b64u_decode(s):
    """base64url WITHOUT padding, per WebAuthn/JSON conventions (§6.1 step 2)."""
    if isinstance(s, bytes):
        s = s.decode("ascii")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def cose_key_to_public(cose_key: dict):
    """RFC 9052 COSE_Key -> a public key object.

    Takes an ALREADY-DECODED mapping. CBOR decoding belongs to the registration
    layer, not here: this file must stay free of a CBOR dependency so the
    verification core can be reimplemented (and audited) without one.

    Only the two algorithms on §2's table are constructible. An unknown kty/crv
    raises rather than falling back -- §2 requires rejecting an unsupported
    algorithm, not defaulting to one.
    """
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    kty = cose_key.get(1)
    if kty == 2:                                    # EC2
        crv, x, y = cose_key.get(-1), cose_key.get(-2), cose_key.get(-3)
        if crv != 1 or not isinstance(x, bytes) or not isinstance(y, bytes):
            raise ProtocolError("unsupported EC2 COSE_Key (only P-256 / crv=1)")
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"),
            ec.SECP256R1()).public_key()
    if kty == 1:                                    # OKP
        crv, x = cose_key.get(-1), cose_key.get(-2)
        if crv != 6 or not isinstance(x, bytes):
            raise ProtocolError("unsupported OKP COSE_Key (only Ed25519 / crv=6)")
        return ed25519.Ed25519PublicKey.from_public_bytes(x)
    raise ProtocolError("unsupported COSE_Key kty %r" % (kty,))


def _verify_signature(public_key, cose_alg, signed_bytes, signature) -> bool:
    """Raw cryptographic check for one algorithm. Returns bool; raises nothing."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.exceptions import InvalidSignature
    try:
        if cose_alg == COSE_ES256:
            # DER-encoded SEQUENCE{r,s}, as WebAuthn authenticators produce (§2).
            public_key.verify(signature, signed_bytes, ec.ECDSA(hashes.SHA256()))
        elif cose_alg == COSE_EDDSA:
            public_key.verify(signature, signed_bytes)      # fixed 64-byte form
        else:
            return False
        return True
    except InvalidSignature:
        return False
    except Exception:                                        # noqa: BLE001
        # A malformed DER body, a wrong-curve point, or a truncated signature all
        # land here. They are INVALID SIGNATURE, not internal errors -- but they
        # must not be silently swallowed into a pass.
        return False


#: WebAuthn authenticatorData flag bits (WebAuthn §6.1).
FLAG_UP = 0x01      # user present
FLAG_UV = 0x04      # user VERIFIED -- the one §7 step 8 requires


def verify_approval(*, stored_request, authenticator, assertion, now,
                    consume=None) -> Verdict:
    """The §7 verification procedure: ordered, fail-closed, first failure wins.

    ⚠ `stored_request` is the APPLIANCE'S OWN RECORD. Every field of `P` is taken
    from it (step 6). `assertion` is attacker-controlled and contributes ONLY the
    signature, the authenticator data, the client data, and the asserted counter --
    never a field of `P`. That separation is the whole security property; if a
    future change lets an assertion field reach `P`, this stops being authorization
    and becomes a proof that the client signed something it chose itself.

    `consume` is a callable implementing step 11 atomically. It MUST return True
    only for the caller that won the race. Passing None means "do not consume",
    which is for TEST and DRY-RUN use only -- a production caller that omits it has
    verified an approval without spending it, and the same approval could be
    replayed.
    """
    # ── 1: known request ────────────────────────────────────────────────────
    if stored_request is None:
        return Verdict(False, Reason.UNKNOWN_REQUEST, 1, "no such request_id")

    state = stored_request.get("state")
    # ── 2: state is PENDING ─────────────────────────────────────────────────
    if state != "PENDING":
        # CONSUMED is its own code: "already used" and "never existed" have
        # different operational meanings and different responses.
        if state in ("CONSUMED", "USED"):
            return Verdict(False, Reason.ALREADY_CONSUMED, 2, "state=%s" % state)
        return Verdict(False, Reason.ALREADY_CONSUMED, 2,
                       "state=%r is not PENDING" % (state,))

    # ── 3: not expired ──────────────────────────────────────────────────────
    if now > int(stored_request["expires_at"]):
        return Verdict(False, Reason.EXPIRED, 3,
                       "expired at %s, now %s" % (stored_request["expires_at"], now))

    # ── 4: known, active authenticator ──────────────────────────────────────
    if authenticator is None or authenticator.get("revoked"):
        return Verdict(False, Reason.UNKNOWN_AUTHENTICATOR, 4,
                       "unknown or revoked authenticator")

    # ── 5 (ownership half of step 4 in the table) ───────────────────────────
    if authenticator.get("user_id") != stored_request.get("user_id"):
        return Verdict(False, Reason.NOT_OWNED, 5,
                       "authenticator belongs to a different user")

    # ── 6 (alg): on the table AND matching the registration ─────────────────
    alg = authenticator.get("cose_alg")
    if alg not in SUPPORTED_ALGS:
        return Verdict(False, Reason.ALG_MISMATCH, 6, "unsupported alg %r" % (alg,))
    if assertion.get("cose_alg") is not None and assertion["cose_alg"] != alg:
        return Verdict(False, Reason.ALG_MISMATCH, 6,
                       "assertion alg %r != registered %r" % (assertion["cose_alg"], alg))

    # ── 6b: rebuild P FROM STORED FIELDS ONLY ───────────────────────────────
    try:
        payload = encode_payload(
            request_id=stored_request["request_id"],
            capability=stored_request["capability"],
            target=stored_request["target"],
            action_params=stored_request["action_params"],
            appliance_id=stored_request["appliance_id"],
            authenticator_id=stored_request["authenticator_id"],
            issued_at=int(stored_request["issued_at"]),
            expires_at=int(stored_request["expires_at"]),
            match_code=int(stored_request["match_code"]),
            nonce=stored_request["nonce"])
    except ProtocolError as exc:
        # The appliance's own record is malformed. This is OUR bug, and it must
        # not be reported as a client-side rejection reason.
        return Verdict(False, Reason.UNKNOWN_REQUEST, 6,
                       "stored request is malformed: %s" % exc)

    expected_challenge = challenge_for(payload)
    mode = authenticator.get("mode")

    # ── 7 + 8 + 9: mode-specific binding, UV, signature ─────────────────────
    if mode == MODE_WEBAUTHN:
        auth_data = assertion.get("authenticator_data") or b""
        client_json = assertion.get("client_data_json") or b""
        if len(auth_data) < 37:
            return Verdict(False, Reason.BINDING_MISMATCH, 7,
                           "authenticatorData shorter than 37 bytes")
        if not constant_time_eq(auth_data[:32], authenticator.get("rp_id_hash") or b""):
            return Verdict(False, Reason.BINDING_MISMATCH, 7, "rp_id_hash mismatch")
        try:
            client = json.loads(client_json.decode("utf-8"))
        except Exception:                                    # noqa: BLE001
            return Verdict(False, Reason.BINDING_MISMATCH, 7, "clientDataJSON unparseable")
        if client.get("type") != "webauthn.get":
            return Verdict(False, Reason.BINDING_MISMATCH, 7,
                           "clientData.type=%r" % (client.get("type"),))
        try:
            got_challenge = _b64u_decode(client.get("challenge", ""))
        except Exception:                                    # noqa: BLE001
            return Verdict(False, Reason.CHALLENGE_MISMATCH, 8, "challenge not base64url")
        if not constant_time_eq(got_challenge, expected_challenge):
            return Verdict(False, Reason.CHALLENGE_MISMATCH, 8,
                           "challenge != SHA-256(P)")

        flags = auth_data[32]
        if not (flags & FLAG_UV):
            # §7 step 8: NOT configurable. A UV requirement the server does not
            # check does not exist.
            return Verdict(False, Reason.UV_NOT_ASSERTED, 9, "UV flag clear")

        signed_bytes = auth_data + hashlib.sha256(client_json).digest()

    elif mode == MODE_NATIVE:
        if not assertion.get("uv_asserted"):
            return Verdict(False, Reason.UV_NOT_ASSERTED, 9,
                           "uv_asserted missing or false")
        # §6.2: the authenticator signs SHA-256(P) directly. See CONFORMANCE NOTE
        # in the module test -- this reading is the one the published vectors pin.
        signed_bytes = expected_challenge

    else:
        return Verdict(False, Reason.ALG_MISMATCH, 6, "unknown mode %r" % (mode,))

    # ── 9: the signature itself ─────────────────────────────────────────────
    try:
        public_key = cose_key_to_public(authenticator["public_key"])
    except ProtocolError as exc:
        return Verdict(False, Reason.ALG_MISMATCH, 6, str(exc))
    if not _verify_signature(public_key, alg, signed_bytes, assertion.get("signature") or b""):
        return Verdict(False, Reason.BAD_SIGNATURE, 10, "signature did not verify")

    # ── 10: WebAuthn signature counter ──────────────────────────────────────
    if mode == MODE_WEBAUTHN:
        stored_count = int(authenticator.get("sign_count") or 0)
        got_count = int.from_bytes(auth_data[33:37], "big")
        # A zero on BOTH sides means the authenticator does not implement counters
        # and MUST NOT be treated as a failure (§6.1).
        if not (stored_count == 0 and got_count == 0) and got_count <= stored_count:
            return Verdict(False, Reason.COUNTER_REGRESSION, 11,
                           "counter %d <= stored %d" % (got_count, stored_count))

    # ── 11: atomic consumption ──────────────────────────────────────────────
    if consume is not None and not consume(stored_request["request_id"]):
        return Verdict(False, Reason.CONSUMPTION_RACE, 12, "lost the consumption race")

    return Verdict(True)


# ── portable byte-tagging for stored/transported registrations ─────────────
#
# JSON has no byte string, and a COSE key is full of them (`-2`/`-3` are the EC
# coordinates, `rp_id_hash` is 32 raw bytes). Both the APPLIANCE's authenticator
# store and the AGENT's pinned store must encode the same records the same way, and
# the installer conf carries them between the two.
#
# Defined HERE, in the file that is mirrored byte-for-byte to the agent, so there
# is exactly ONE encoder rather than one per side. Two implementations of a format
# whose only consumer is the other side is the drift that produces an agent which
# silently pins nothing -- indistinguishable, from the outside, from an operator
# who never paired a phone.
#
# The tag is explicit rather than inferred from the label: a bare base64 string is
# indistinguishable from a genuine text value, and guessing by label would break
# the first time a COSE key type with different labels is supported.
BYTES_TAG = "__bytes_b64__"


class TagError(ValueError):
    """A tagged structure could not be decoded. Never a silent partial result."""


def tag_bytes(obj):
    """Make a registration record JSON-encodable. Inverse of `untag_bytes`."""
    import base64 as _b64
    if isinstance(obj, bytes):
        return {BYTES_TAG: _b64.b64encode(obj).decode("ascii")}
    if isinstance(obj, dict):
        # COSE uses INTEGER labels; JSON object keys are always strings, so the
        # label's TYPE is recorded in the key text and restored on the way back.
        return {("int:%d" % k) if isinstance(k, int) else ("str:%s" % k): tag_bytes(v)
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [tag_bytes(v) for v in obj]
    return obj


def untag_bytes(obj):
    """Inverse of `tag_bytes`. Raises `TagError` on anything malformed.

    Raises rather than skipping: a dropped field would produce a record that looks
    structurally fine and then fails much later as an unexplained signature
    rejection, far from the decode that caused it.
    """
    import base64 as _b64
    if isinstance(obj, dict):
        if set(obj) == {BYTES_TAG}:
            try:
                return _b64.b64decode(obj[BYTES_TAG], validate=True)
            except Exception as exc:                               # noqa: BLE001
                raise TagError("tagged value is not valid base64: %s" % exc) from exc
        out = {}
        for k, v in obj.items():
            if not isinstance(k, str):
                raise TagError("non-string key %r" % (k,))
            if k.startswith("int:"):
                try:
                    out[int(k[4:])] = untag_bytes(v)
                except ValueError as exc:
                    raise TagError("bad integer label %r" % k) from exc
            elif k.startswith("str:"):
                out[k[4:]] = untag_bytes(v)
            else:
                raise TagError("untyped key %r" % k)
        return out
    if isinstance(obj, list):
        return [untag_bytes(v) for v in obj]
    return obj


def key_fingerprint(public_key) -> str:
    """Stable sha256 hex over a COSE public key. Comparable across all three sides.

    ONE definition, because three separate things compare against it: the
    appliance's rotation authorization (which key is being added/revoked), the
    agent's `enrollment.admin_authenticator_fingerprint()`, and the companion app's
    out-of-band display. Three implementations of "the fingerprint" would silently
    disagree, and the symptom would be an operator told the digests do not match
    when the keys are in fact identical -- training them to ignore the one check
    that defends the enrollment trust root.

    Defined over the TAGGED canonical form rather than raw COSE bytes so it does
    not depend on a CBOR encoder being present or byte-identical on every side.
    """
    import hashlib as _h
    import json as _j
    return _h.sha256(_j.dumps(tag_bytes(public_key), separators=(",", ":"),
                              sort_keys=True).encode()).hexdigest()
