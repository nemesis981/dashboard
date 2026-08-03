"""Tier 4 -> tier 3 migration: adopt an unencrypted key into a protected one.

This is the only DESTRUCTIVE step in the tier-3 build -- it ends by deleting the
plaintext private key -- so the ordering below is the whole design:

    1. load the existing key            (fails -> nothing touched)
    2. write the protected envelope     (atomic via os.replace)
    3. verify it FROM A FRESH DISK READ (fails -> plaintext still there)
    4. only now delete the plaintext

Reversed -- delete first, write second -- a crash between the two destroys the
device's identity permanently and forces a re-enrolment. Verifying against the
in-memory backend instead of re-reading the file would prove nothing about what
actually landed on disk, which is the thing the deletion is betting on.

Because the deletion is last and unconditional on success, "the plaintext key
survives every failure" is a structural property here, not a runtime check that
could itself be wrong.

The key is ADOPTED, not replaced, so the public key -- and therefore the device's
server-side identity -- is unchanged. That is why this migration needs no server
round-trip and no key-rotation endpoint. A future tier-1 migration cannot adopt
(a TPM-resident key must be generated in the chip), so it will genuinely rotate
and publish; the return shape here is rotation-shaped so that slots in without
reworking the caller.
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .base import KeyProtectError
from .legacy import LegacyBackend
from .password import PasswordBackend

#: Signed during verification to prove the migrated key can actually produce a
#: signature that validates -- not merely that a file was written.
PROBE_MESSAGE = "keyprotect-migration-probe"


class MigrationAborted(KeyProtectError):
    """Migration stopped before deleting anything. The old key is intact."""


def needs_migration(keys_dir: str) -> bool:
    """True while an unencrypted private key is still present.

    Also true in the half-migrated state (envelope AND plaintext both present),
    which is what makes migration resumable: a crash between writing the
    envelope and deleting the plaintext leaves a device that WORKS -- detection
    prefers the password backend -- but whose key is still readable on disk.
    Nothing else would ever notice that, so it is caught here.
    """
    return LegacyBackend(keys_dir).is_provisioned()


def _self_verify(public_pem: str, message: str, signature_b64: str) -> bool:
    """Does this signature actually validate under this public key?

    The same PKCS1v15/SHA256 check the server performs. Verifying locally before
    deleting the only other copy of the key is the difference between "a file was
    written" and "the thing we are about to rely on works".
    """
    import base64
    try:
        pub = serialization.load_pem_public_key(public_pem.encode())
        pub.verify(base64.b64decode(signature_b64), message.encode(),
                   padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def migrate_legacy(secret: str, keys_dir: str, target=None):
    """Protect an unencrypted key. Returns (backend, public_key_pem).

    Idempotent: a directory with no plaintext key is a no-op that reports
    whatever backend is already there. Raises MigrationAborted on any failure,
    always with the plaintext key still in place.
    """
    legacy = LegacyBackend(keys_dir)
    protected = target if target is not None else PasswordBackend(keys_dir)

    if not legacy.is_provisioned():
        # Nothing to migrate. Report the existing state rather than raising, so
        # this is safe to call unconditionally at every startup.
        if protected.is_provisioned():
            return protected, protected.public_key_pem()
        return None, None

    if not secret:
        raise MigrationAborted("refusing to migrate without a device secret")

    # ── 1/2: ensure a protected envelope exists holding THIS device's key ──
    if not protected.is_provisioned():
        try:
            existing = legacy.export_private_key()
        except KeyProtectError as exc:
            raise MigrationAborted(
                "cannot read the existing key, so there is nothing safe to "
                "adopt: %s" % exc) from exc
        try:
            protected.provision(secret, existing_private_key=existing)
        except KeyProtectError as exc:
            raise MigrationAborted(
                "could not write the protected key: %s" % exc) from exc

    # ── 3: verify what LANDED ON DISK, via a handle that re-reads it ──
    fresh = type(protected)(keys_dir)
    try:
        fresh.unlock(secret)
    except KeyProtectError as exc:
        raise MigrationAborted(
            "the protected key did not unlock (%s) — the existing key has been "
            "left in place" % exc) from exc

    # The adopted key must be the SAME key, or the device's server-side identity
    # silently changes and it stops being able to authenticate.
    # Derived from the legacy PRIVATE key material, deliberately -- NOT from
    # public_key_pem(). Both backends read the same public.pem, so comparing
    # their public_key_pem() outputs compares that file against itself and can
    # only ever report "equal": a check that cannot fail is not a check.
    # (Caught by a mutation test, 2026-08-03, after this was written the naive
    # way and described as load-bearing when it was doing nothing.)
    try:
        expected_pub = legacy.export_private_key().public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    except KeyProtectError:
        # An unreadable legacy key cannot be compared against. Say so rather
        # than skipping the comparison silently and calling it a pass.
        expected_pub = None
    try:
        signature = fresh.sign(PROBE_MESSAGE)
    except KeyProtectError as exc:
        raise MigrationAborted(
            "the protected key could not sign (%s) — the existing key has been "
            "left in place" % exc) from exc

    # ONE check, and it cannot be vacuous: the signature comes from the
    # envelope's key, the public key is derived from the legacy PRIVATE key
    # material, and the two only agree if it is genuinely the same key.
    #
    # The obvious alternative -- comparing legacy.public_key_pem() against
    # fresh.public_key_pem() -- looks like a stronger check and is actually no
    # check at all: both backends read the same public.pem, so it compares that
    # file against itself and can only ever say "equal". Written that way first,
    # and caught by a mutation test (2026-08-03).
    #
    # Falls back to the envelope's own public key only when the legacy key is
    # unreadable, which is weaker and is why it is not the default path.
    reference_pub = expected_pub if expected_pub is not None else fresh.public_key_pem()
    if not _self_verify(reference_pub, PROBE_MESSAGE, signature):
        raise MigrationAborted(
            ("the protected key is a DIFFERENT key from the one being replaced"
             if expected_pub is not None else
             "the protected key produced a signature that does not verify")
            + " — the existing key has been left in place")

    # ── 4: everything above passed, so the plaintext copy is now redundant ──
    try:
        os.remove(legacy.private_path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        # The protected key is good; we simply could not remove the old one.
        # Report it loudly rather than claiming a completed migration.
        raise MigrationAborted(
            "the protected key is in place but the unencrypted copy could not "
            "be removed (%s) — it is still readable on disk" % exc) from exc

    return fresh, fresh.public_key_pem()
