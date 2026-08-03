"""The SERVER's signing keypair — the trust anchor agents verify tasks against.

Stage 1 of ADR 0004's tasking channel. Until now trust ran one way only: agents
authenticate to the server (heartbeat signatures, ADR 0004 step 3), and nothing
authenticates the server to an agent. That is harmless while the heartbeat
response is a constant `{"ok":true}` — a forged copy of that is worthless — and
stops being harmless the moment the response carries instructions.

The listener is plain HTTP with no confidentiality (see hw_monitor's
`_verify_agent_heartbeat`), and local agents talk cleartext over the LAN by
design, so anyone able to answer on that socket could otherwise task an agent.
Signing the task envelope closes that independently of transport.

PRIVILEGE SPLIT — deliberate, not incidental:

    server_private.pem   0600  nemesis-hwmon   hw_monitor signs; nobody else reads
    server_public.pem    0644                  dashboard bakes it into installers

hw_monitor is the only process that signs, so it is the only one that needs the
private half. The dashboard — the web-facing, internet-adjacent process — holds
the public half only, which means compromising it cannot forge a task. Keeping
that split real is why `public_key_pem()` never touches the private file.

Generation happens on hw_monitor startup rather than at deploy time: the data
dir is setgid `nemesis-db` and hw_monitor is in that group, so it needs no root
and no install step.
"""
from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import nemesis_paths

KEY_DIR_NAME = "serverkeys"
PRIVATE_NAME = "server_private.pem"
PUBLIC_NAME = "server_public.pem"

#: A rotation is TWO-PHASE and the phases are separated by these filenames.
#:
#: Phase 1 stages a new pair alongside the live one. The old key keeps signing
#: everything, so a rotation that is abandoned halfway costs nothing — the fleet
#: never noticed it started.
#:
#: Phase 2 (cutover, operator-driven) promotes new -> current and current ->
#: prev. `prev` is the whole reason a straggler is recoverable rather than
#: bricked: a device that missed the rotation window still trusts the old key, so
#: its rescue task must be signed by that key, which only exists if cutover kept
#: it. Deleting it would turn "one device was offline" into "reinstall that
#: device's agent by hand".
NEW_PRIVATE_NAME = "server_private.new.pem"
NEW_PUBLIC_NAME = "server_public.new.pem"
PREV_PRIVATE_NAME = "server_private.prev.pem"
PREV_PUBLIC_NAME = "server_public.prev.pem"

#: Action name for a rotation task. Shared with nemesis_agent/tasks.py, which
#: must agree exactly — a mismatch means rotations silently route to the normal
#: dispatcher, which is the one place they must never reach.
ROTATE_ACTION = "rotate_server_key"

#: RSA to match the one signing convention already in the codebase
#: (`_verify_enroll_signature`, the agent's enrollment key). Ed25519 is the
#: better primitive; one convention beats one better algorithm when the
#: alternative is two. Revisit only if a hardware-backed server key is ever
#: wanted.
KEY_SIZE_BITS = 2048


def keys_dir() -> str:
    return os.path.join(nemesis_paths.data_dir(), KEY_DIR_NAME)


def private_path() -> str:
    return os.path.join(keys_dir(), PRIVATE_NAME)


def public_path() -> str:
    return os.path.join(keys_dir(), PUBLIC_NAME)


def ensure_server_keypair() -> str:
    """Create the keypair if absent. Returns the public PEM. Idempotent.

    Called once at hw_monitor startup. An existing key is NEVER regenerated:
    doing so would silently invalidate the anchor pinned in every already-
    deployed agent, and every one of them would start refusing tasks with no
    obvious cause.
    """
    os.makedirs(keys_dir(), exist_ok=True)
    if os.path.isfile(private_path()) and os.path.isfile(public_path()):
        return public_key_pem()

    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE_BITS)

    # Write the private half via an exclusive temp + replace, with the mode set
    # BEFORE any bytes land: creating it 0644 and chmod-ing afterwards leaves a
    # window where the key is world-readable.
    tmp = private_path() + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, private_path())

    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    with open(public_path(), "w", encoding="utf-8") as fh:
        fh.write(pub_pem)
    try:
        os.chmod(public_path(), 0o644)
    except OSError:
        pass
    return pub_pem


def public_key_pem() -> str:
    """The public half. Deliberately never reads the private file.

    The dashboard calls this. If it were implemented by loading the private key
    and deriving the public half, the privilege split above would be fiction —
    the dashboard would need read access to the signing key to serve installers.
    """
    with open(public_path(), "r", encoding="utf-8") as fh:
        return fh.read()


def public_key_b64() -> str:
    """Public key as base64 DER (SubjectPublicKeyInfo) — one line, no newlines.

    `nemesis_install.conf` is INI parsed by configparser, where a multi-line PEM
    needs continuation-line indentation that breaks the moment anyone hand-edits
    the sidecar. A single base64 line sidesteps the format entirely; the agent
    rebuilds it with `load_der_public_key`.
    """
    pub = serialization.load_pem_public_key(public_key_pem().encode())
    return base64.b64encode(pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).decode()


def _canonical_bytes(envelope: dict) -> bytes:
    """The exact bytes a task signature covers: the envelope minus `signature`,
    serialised deterministically.

    Identical to the convention the agent's heartbeat already uses
    (`agent.py::_post_payload` -> `json.dumps(separators=(",", ":"), sort_keys=True)`).
    Deliberately the SAME rule rather than a second, near-identical one: two
    canonicalisations that differ only in whitespace or key order produce
    signatures that verify in testing and fail in the field, and the difference is
    invisible in a diff.
    """
    import json
    return json.dumps({k: v for k, v in envelope.items() if k != "signature"},
                      separators=(",", ":"), sort_keys=True).encode()


def sign_task(envelope: dict, key_path: str = None) -> str:
    """Base64 PKCS1v15/SHA256 signature over the canonical envelope.

    Only hw_monitor can call this — it is the sole holder of the private key.
    Raises rather than returning a falsy value if the key is unavailable: an
    unsigned task must never leave the server, and a caller that mistook "" for a
    signature would ship exactly that.

    `key_path` exists solely for post-cutover straggler rescue: a device still
    holding the OLD anchor can only be reached by a task signed with the old key.
    Defaults to the current key, so every ordinary caller is unaffected.
    """
    import hashlib

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    with open(key_path or private_path(), "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    digest = hashlib.sha256(_canonical_bytes(envelope)).hexdigest().encode()
    return base64.b64encode(
        key.sign(digest, padding.PKCS1v15(), hashes.SHA256())).decode()


# ── rotation (ADR 0004 Stage 1, step 4 Part B) ────────────────────────────
def _path(name: str) -> str:
    return os.path.join(keys_dir(), name)


def key_fingerprint(pub_pem) -> str:
    """sha256 of the public key's DER encoding — the rotation EPOCH identifier.

    Used to answer "which key is this device on?" without adding a column to a
    live table: the fingerprint recorded in a completed rotation task's params
    IS the answer, and it cannot be confused with a previous rotation's because
    the fingerprints differ.
    """
    import hashlib
    if isinstance(pub_pem, str):
        pub_pem = pub_pem.encode()
    pub = serialization.load_pem_public_key(pub_pem)
    return hashlib.sha256(pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def current_fingerprint() -> str:
    return key_fingerprint(public_key_pem())


def staged_fingerprint():
    """Fingerprint of the staged pair, or None if no rotation is in progress."""
    if not (os.path.isfile(_path(NEW_PRIVATE_NAME))
            and os.path.isfile(_path(NEW_PUBLIC_NAME))):
        return None
    with open(_path(NEW_PUBLIC_NAME), "r", encoding="utf-8") as fh:
        return key_fingerprint(fh.read())


def prev_fingerprint():
    """Fingerprint of the retained previous key, or None if there is none."""
    if not have_prev_keypair():
        return None
    with open(_path(PREV_PUBLIC_NAME), "r", encoding="utf-8") as fh:
        return key_fingerprint(fh.read())


def signing_key_for_fingerprint(device_fp):
    """Path to the private key a device holding `device_fp` will accept, or None
    for "use the current key".

    A rotation is not instantaneous across a fleet, so at any moment during one
    the server may hold THREE keys and different devices trust different ones:

      * before cutover, a device that has already rotated trusts the STAGED key
        while the server still signs everything else with the current one;
      * after cutover, a device that never rotated still trusts the PREVIOUS key.

    Signing every task with the current key would make both of those devices
    untaskable for the whole rotation window — the first is the gap that
    prompted this function, found when a rotated device stopped accepting
    ordinary tasks. The server knows which key each device is on, so it signs
    with that one.

    Returns None (meaning current) for an unrecognised fingerprint: current is
    the best available guess, and the alternative — refusing to sign — would
    turn an unknown state into an outage.
    """
    if device_fp is None or device_fp == current_fingerprint():
        return None
    if device_fp == staged_fingerprint():
        return _path(NEW_PRIVATE_NAME)
    if device_fp == prev_fingerprint():
        return _path(PREV_PRIVATE_NAME)
    return None


def have_prev_keypair() -> bool:
    return (os.path.isfile(_path(PREV_PRIVATE_NAME))
            and os.path.isfile(_path(PREV_PUBLIC_NAME)))


def stage_new_keypair() -> dict:
    """Generate the replacement pair alongside the live one. Phase 1 of two.

    REFUSES if a pair is already staged. Silently regenerating would invalidate
    every rotation task already in flight — devices would receive a task whose
    PoP proves possession of a key the server had already discarded, and the
    resulting refusals would look like an attack rather than an own goal.
    """
    if staged_fingerprint():
        raise RuntimeError(
            "a rotation is already staged (fingerprint %s) — cutover or abort it first"
            % staged_fingerprint()[:16])
    os.makedirs(keys_dir(), exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE_BITS)

    # Mode set BEFORE any bytes land, same as ensure_server_keypair().
    tmp = _path(NEW_PRIVATE_NAME) + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, _path(NEW_PRIVATE_NAME))

    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    with open(_path(NEW_PUBLIC_NAME), "w", encoding="utf-8") as fh:
        fh.write(pub_pem)
    try:
        os.chmod(_path(NEW_PUBLIC_NAME), 0o644)
    except OSError:
        pass
    return {"fingerprint": key_fingerprint(pub_pem),
            "public_b64": _pem_to_b64(pub_pem)}


def _pem_to_b64(pub_pem: str) -> str:
    pub = serialization.load_pem_public_key(pub_pem.encode())
    return base64.b64encode(pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).decode()


def build_rotation_task(device_id: str, ttl_seconds: int = 1800,
                        task_id: str = None, sign_with: str = None,
                        now=None) -> dict:
    """A rotation task: authorised by the OLD key, PROVING possession of the new.

    TWO signatures, and the second is the one that matters. The envelope
    signature (old key) proves the change was AUTHORISED. It says nothing about
    whether the server actually holds the private half of the key it is handing
    out — a typo, a truncated file, or the wrong public key pasted in would
    produce a perfectly valid envelope that permanently brick every device that
    honoured it. The PoP closes exactly that: the new PRIVATE key signs
    "rotate|<device_id>|<task_id>|<new_pub_b64>", so an agent can confirm the
    server can actually sign with what it is being asked to trust.

    The PoP is bound to this device AND this task_id, so one lifted from another
    device's rotation — or from a different task to the same device — does not
    verify. task_id is therefore generated up front rather than by build_task().
    """
    import uuid
    from datetime import datetime, timedelta
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    fp = staged_fingerprint()
    if not fp:
        raise RuntimeError("no staged keypair — run stage_new_keypair() first")

    with open(_path(NEW_PUBLIC_NAME), "r", encoding="utf-8") as fh:
        new_pub_pem = fh.read()
    new_pub_b64 = _pem_to_b64(new_pub_pem)

    task_id = task_id or str(uuid.uuid4())
    message = "rotate|%s|%s|%s" % (device_id, task_id, new_pub_b64)
    with open(_path(NEW_PRIVATE_NAME), "rb") as fh:
        new_priv = serialization.load_pem_private_key(fh.read(), password=None)
    # Raw message bytes, matching hw_monitor's _verify_enroll_signature — which
    # is already the codebase's proof-of-possession convention. Reusing it beats
    # introducing a third signing shape.
    pop = base64.b64encode(new_priv.sign(
        message.encode(), padding.PKCS1v15(), hashes.SHA256())).decode()

    now = now or datetime.now()
    env = {
        "task_id": task_id,
        "device_id": device_id,
        "action": ROTATE_ACTION,
        "params": {"new_public_key": new_pub_b64,
                   "new_key_sha256": fp,
                   "pop": pop},
        "issued_at": now.isoformat(timespec="seconds"),
        "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(timespec="seconds"),
    }
    env["signature"] = sign_task(env, key_path=sign_with)
    return env


def cutover() -> dict:
    """Promote the staged pair to current, demoting current to prev. Phase 2.

    Ordering is the design. `prev` is written BEFORE `current` is overwritten, so
    there is no instant at which the old private key has been discarded but the
    new one is not yet live — that gap would strand every un-rotated device
    permanently, with no key left to sign their rescue.
    """
    fp = staged_fingerprint()
    if not fp:
        raise RuntimeError("nothing staged to cut over to")
    if not have_server_keypair():
        raise RuntimeError("no current keypair to rotate away from")

    old_fp = current_fingerprint()
    for src, dst in ((private_path(), _path(PREV_PRIVATE_NAME)),
                     (public_path(), _path(PREV_PUBLIC_NAME))):
        with open(src, "rb") as a, open(dst + ".tmp", "wb") as b:
            b.write(a.read())
        if dst.endswith(PREV_PRIVATE_NAME):
            os.chmod(dst + ".tmp", 0o600)
        os.replace(dst + ".tmp", dst)

    os.replace(_path(NEW_PRIVATE_NAME), private_path())
    os.replace(_path(NEW_PUBLIC_NAME), public_path())
    return {"previous_fingerprint": old_fp, "current_fingerprint": fp}


def abort_rotation() -> bool:
    """Discard a staged pair. Only meaningful BEFORE cutover.

    After cutover the staged files no longer exist, so this cannot undo one —
    reversing a completed rotation means staging the old key again and rotating
    forward to it, which is a deliberate operation, not an "undo".
    """
    removed = False
    for name in (NEW_PRIVATE_NAME, NEW_PUBLIC_NAME):
        try:
            os.remove(_path(name))
            removed = True
        except FileNotFoundError:
            continue
    return removed


def build_task(device_id: str, action: str, params: dict = None,
               ttl_seconds: int = 1800, task_id: str = None,
               now=None, sign_with: str = None) -> dict:
    """A complete, signed task envelope addressed to one device.

    `device_id` is inside the signed material on purpose — without it an envelope
    captured from one machine could be replayed at another, and every agent shares
    the same server anchor. `expires_at` bounds how long a captured envelope stays
    useful at all.
    """
    import uuid
    from datetime import datetime, timedelta

    now = now or datetime.now()
    env = {
        "task_id": task_id or str(uuid.uuid4()),
        "device_id": device_id,
        "action": action,
        "params": params or {},
        "issued_at": now.isoformat(timespec="seconds"),
        "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(timespec="seconds"),
    }
    env["signature"] = sign_task(env, key_path=sign_with)
    return env


def have_server_keypair() -> bool:
    """True only if BOTH halves exist. A half-written pair is not usable, and
    reporting it as present would send a caller down a path that fails later
    and less clearly."""
    return os.path.isfile(private_path()) and os.path.isfile(public_path())
