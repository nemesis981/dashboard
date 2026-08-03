"""Tier 3 — password-protected key at rest (scrypt + AES-256-GCM).

Replaces the pre-2026-08-03 behaviour, in which enrollment.py wrote the private
key as an UNENCRYPTED PKCS8 PEM with a best-effort os.chmod(0o600) that is a
no-op for access-control purposes on Windows, the primary target platform.

Why an explicit envelope instead of serialization.BestAvailableEncryption:
  * KDF parameters are chosen and recorded here, rather than being whatever the
    backend happens to default to.
  * AES-GCM is authenticated, so damaged key material fails loudly on the tag
    instead of yielding garbage key bytes that fail somewhere less obvious.

This is the permanent fallback for machines without a usable TPM (VMs, older
hardware, Linux, macOS) — not scaffolding. Tier 1 (TPM+PIN) is the destination
for machines that can run it.
"""
from __future__ import annotations

import base64
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .base import (SECRET_PASSWORD, Corrupt, KeyProtectionBackend, Locked,
                   NotProvisioned, WrongSecret)

ENVELOPE_NAME = "private.enc.json"
PUBLIC_NAME = "public.pem"

ENVELOPE_VERSION = 1
KEY_SIZE_BITS = 2048
SCRYPT_N = 1 << 15          # ~100ms on desktop hardware; approved 2026-08-03
SCRYPT_R = 8
SCRYPT_P = 1
DERIVED_LEN = 32            # AES-256
SALT_BYTES = 16
NONCE_BYTES = 12


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _b64d(txt: str) -> bytes:
    return base64.b64decode(txt)


class PasswordBackend(KeyProtectionBackend):
    tier_id = "password"

    def __init__(self, keys_dir: str):
        super().__init__(keys_dir)
        self._key = None  # unlocked private key, in memory for this process

    # ── paths ─────────────────────────────────────────────────────────────
    @property
    def envelope_path(self) -> str:
        return os.path.join(self.keys_dir, ENVELOPE_NAME)

    @property
    def public_path(self) -> str:
        return os.path.join(self.keys_dir, PUBLIC_NAME)

    # ── capability ────────────────────────────────────────────────────────
    def available(self) -> bool:
        return True     # software-only; runs anywhere the agent runs

    def is_provisioned(self) -> bool:
        return os.path.isfile(self.envelope_path)

    def secret_kind(self) -> str:
        return SECRET_PASSWORD

    # ── internals ─────────────────────────────────────────────────────────
    @staticmethod
    def _derive(secret: str, salt: bytes, n: int, r: int, p: int) -> bytes:
        return Scrypt(salt=salt, length=DERIVED_LEN, n=n, r=r, p=p).derive(
            secret.encode("utf-8"))

    def _read_envelope(self) -> dict:
        """Parse the envelope, or raise a TYPED error. Never returns a default.

        Structural damage is diagnosed here, BEFORE any decryption is attempted,
        so it can be reported as Corrupt rather than being mistaken for a wrong
        password further down.
        """
        if not os.path.isfile(self.envelope_path):
            raise NotProvisioned("no key envelope at %s" % self.envelope_path)
        try:
            with open(self.envelope_path, "r", encoding="utf-8") as fh:
                env = json.load(fh)
        except (OSError, ValueError) as exc:
            raise Corrupt("key envelope unreadable: %s" % exc) from exc

        if not isinstance(env, dict) or env.get("v") != ENVELOPE_VERSION:
            raise Corrupt("unsupported key envelope version: %r"
                          % (env.get("v") if isinstance(env, dict) else env))
        try:
            kdf = env["kdf"]
            salt = _b64d(kdf["salt"])
            nonce = _b64d(env["aead"]["nonce"])
            ct = _b64d(env["ct"])
            ct_sha256 = env["ct_sha256"]
            int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
        except (KeyError, TypeError, ValueError, base64.binascii.Error) as exc:
            raise Corrupt("key envelope malformed: %s" % exc) from exc

        if len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES or not ct:
            raise Corrupt("key envelope field sizes are wrong")

        # Secret-INDEPENDENT damage check. An AEAD tag failure cannot by itself
        # distinguish "wrong password" from "a byte got flipped" — both are just
        # InvalidTag. This digest separates the two so the caller can say which
        # actually happened. It is a DIAGNOSTIC, not an integrity control: the
        # authenticity guarantee is AES-GCM's tag, and anyone who can rewrite the
        # ciphertext can rewrite this digest too. Do not read it as tamper-proofing.
        digest = hashes.Hash(hashes.SHA256())
        digest.update(ct)
        if _b64e(digest.finalize()) != ct_sha256:
            raise Corrupt("ciphertext does not match its recorded digest "
                          "(damaged file, not a wrong password)")
        return env

    # ── lifecycle ─────────────────────────────────────────────────────────
    def provision(self, secret: str, existing_private_key=None) -> str:
        if not secret:
            raise WrongSecret("refusing to protect a key with an empty secret")
        os.makedirs(self.keys_dir, exist_ok=True)

        key = existing_private_key or rsa.generate_private_key(
            public_exponent=65537, key_size=KEY_SIZE_BITS)

        # PKCS8 DER exists ONLY in memory here. It is never written to disk in
        # this form -- that is the whole defect this backend closes.
        der = key.private_bytes(serialization.Encoding.DER,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        salt = os.urandom(SALT_BYTES)
        nonce = os.urandom(NONCE_BYTES)
        ct = AESGCM(self._derive(secret, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
                    ).encrypt(nonce, der, None)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(ct)

        env = {
            "v": ENVELOPE_VERSION,
            "tier": self.tier_id,
            "kdf": {"alg": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R,
                    "p": SCRYPT_P, "salt": _b64e(salt)},
            "aead": {"alg": "AES-256-GCM", "nonce": _b64e(nonce)},
            "ct": _b64e(ct),
            "ct_sha256": _b64e(digest.finalize()),
        }
        tmp = self.envelope_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(env, fh)
        os.replace(tmp, self.envelope_path)     # atomic; never a half-written key
        try:
            os.chmod(self.envelope_path, 0o600)
        except OSError:
            pass    # POSIX-only; the envelope's protection is the passphrase

        pub_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        with open(self.public_path, "w", encoding="utf-8") as fh:
            fh.write(pub_pem)

        self._key = key
        return pub_pem

    def unlock(self, secret: str) -> None:
        env = self._read_envelope()     # raises NotProvisioned / Corrupt
        kdf = env["kdf"]
        derived = self._derive(secret, _b64d(kdf["salt"]),
                               int(kdf["n"]), int(kdf["r"]), int(kdf["p"]))
        try:
            der = AESGCM(derived).decrypt(
                _b64d(env["aead"]["nonce"]), _b64d(env["ct"]), None)
        except InvalidTag as exc:
            # Structural damage was already ruled out by _read_envelope, so an
            # authentication failure here means the secret was wrong.
            raise WrongSecret("password did not unlock the key") from exc
        try:
            self._key = serialization.load_der_private_key(der, password=None)
        except Exception as exc:
            raise Corrupt("decrypted material is not a private key: %s" % exc) from exc

    def sign(self, message: str) -> str:
        if self._key is None:
            if not self.is_provisioned():
                raise NotProvisioned("no key material to sign with")
            raise Locked("key is provisioned but not unlocked in this process")
        return base64.b64encode(
            self._key.sign(message.encode(), padding.PKCS1v15(),
                           hashes.SHA256())).decode()

    def public_key_pem(self) -> str:
        if not os.path.isfile(self.public_path):
            if self._key is not None:
                return self._key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            raise NotProvisioned("no public key at %s" % self.public_path)
        with open(self.public_path, "r", encoding="utf-8") as fh:
            return fh.read()

    def change_secret(self, old_secret: str, new_secret: str) -> None:
        self.unlock(old_secret)         # raises if old_secret is wrong
        self.provision(new_secret, existing_private_key=self._key)

    def erase(self) -> None:
        for path in (self.envelope_path, self.public_path):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
        self._key = None
