"""Tier 4 — the unencrypted key on disk. READ-ONLY, migrate-from only.

This is what every agent enrolled before 2026-08-03 has: a PKCS8 PEM written
with NoEncryption() by enrollment.ensure_keypair(). It exists here for exactly
two reasons — so an already-deployed agent keeps working until it migrates, and
so migration can adopt its key and preserve the device's server-side identity.

It deliberately CANNOT be provisioned into. A "no protection" tier that can be
chosen is a footgun: the selector must never be able to land here for a new
install, only find it already present on an old one.
"""
from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .base import (SECRET_PASSWORD, Corrupt, KeyProtectionBackend,
                   NotProvisioned, NotSupported)

PRIVATE_NAME = "private.pem"
PUBLIC_NAME = "public.pem"


class LegacyBackend(KeyProtectionBackend):
    tier_id = "none"

    def __init__(self, keys_dir: str):
        super().__init__(keys_dir)
        self._key = None

    @property
    def private_path(self) -> str:
        return os.path.join(self.keys_dir, PRIVATE_NAME)

    @property
    def public_path(self) -> str:
        return os.path.join(self.keys_dir, PUBLIC_NAME)

    # ── capability ────────────────────────────────────────────────────────
    def available(self) -> bool:
        """True only if an unencrypted private key is actually loadable here.

        Deliberately loads rather than stat-ing: a present-but-unparseable file
        is not an available backend, and reporting it as one would hand the
        selector a key it cannot use.
        """
        try:
            self._load()
            return True
        except Exception:
            return False

    def is_provisioned(self) -> bool:
        return os.path.isfile(self.private_path)

    def is_unlocked(self) -> bool:
        """Always True — and that is the honest answer, not a shortcut.

        An unencrypted key really is usable by anyone holding the file, which
        is the defect tier 3 closes. Reporting True here is what stops the
        startup gate prompting the deployed fleet for a secret that does not
        exist for them.
        """
        return True

    def secret_kind(self) -> str:
        return SECRET_PASSWORD      # unused; nothing here consumes a secret

    # ── internals ─────────────────────────────────────────────────────────
    def _load(self):
        if self._key is not None:
            return self._key
        if not os.path.isfile(self.private_path):
            raise NotProvisioned("no legacy key at %s" % self.private_path)
        try:
            with open(self.private_path, "rb") as fh:
                self._key = serialization.load_pem_private_key(
                    fh.read(), password=None)
        except Exception as exc:
            raise Corrupt("legacy key unreadable: %s" % exc) from exc
        return self._key

    # ── lifecycle ─────────────────────────────────────────────────────────
    def provision(self, secret: str, existing_private_key=None) -> str:
        raise NotSupported(
            "the legacy backend is migrate-from only and cannot be provisioned")

    def unlock(self, secret: str) -> None:
        """No-op: an unencrypted key has nothing to unlock.

        This is the honest description of tier 4, not a bypass — the key really
        is usable by anyone holding the file, which is the defect tier 3 closes.
        """
        self._load()

    def sign(self, message: str) -> str:
        return base64.b64encode(
            self._load().sign(message.encode(), padding.PKCS1v15(),
                              hashes.SHA256())).decode()

    def public_key_pem(self) -> str:
        if os.path.isfile(self.public_path):
            with open(self.public_path, "r", encoding="utf-8") as fh:
                return fh.read()
        return self._load().public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def change_secret(self, old_secret: str, new_secret: str) -> None:
        raise NotSupported("the legacy backend holds no secret to change")

    def erase(self) -> None:
        for path in (self.private_path, self.public_path):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
        self._key = None

    # ── migration support (NOT on the base interface, deliberately) ───────
    def export_private_key(self):
        """The live key object, for a migration to adopt.

        Intentionally absent from KeyProtectionBackend: no TPM-resident backend
        can ever implement it, and putting it on the interface would invite
        callers to depend on something the destination design cannot provide.
        """
        return self._load()
