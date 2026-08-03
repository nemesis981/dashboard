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


def have_server_keypair() -> bool:
    """True only if BOTH halves exist. A half-written pair is not usable, and
    reporting it as present would send a caller down a path that fails later
    and less clearly."""
    return os.path.isfile(private_path()) and os.path.isfile(public_path())
