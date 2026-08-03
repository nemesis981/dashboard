"""Tier 1 — TPM-resident key with a PIN. NOT IMPLEMENTED YET.

Present now, unimplemented on purpose. Selection logic with only one selectable
backend is single-branch code that cannot be tested in both directions; this
stub gives the selector a real second option so "prefers TPM when available,
password when not" is verifiable from day one, in both directions.

Feasibility is not speculative — it was measured on 2026-08-03 against a
Windows 11 VM with TPM 2.0, and every mechanism this backend needs was proven:

  * key created in the Microsoft Platform Crypto Provider, non-exportable
    (private-key export attempt failed; ExportPolicy=None survived reopen);
  * NCRYPT_PIN_PROPERTY set at creation, finalized, and reopened;
  * signing REFUSED without the PIN (0x80090022, "context was acquired as
    silent") and with a WRONG PIN (0x80090010, "access denied"), and permitted
    with the right one;
  * the resulting PKCS1v15/SHA256 signature verified against the server's
    unmodified _verify_enroll_signature.

Two things that are NOT yet proven and must not be assumed by the build:
  * TPM anti-hammering lockout behaviour (only one wrong PIN was ever tried);
  * Python ctypes marshalling specifically — the spike used PowerShell P/Invoke
    against the same ncrypt.dll entry points, which validates the call shape
    and flags but not ctypes' own struct handling.

MANDATORY when this is implemented: NCRYPT_SILENT_FLAG (0x40) on every NCrypt
call. Without it, NCryptFinalizeKey blocks indefinitely on interactive platform
UI that a service session can never satisfy — reproduced live, no error, no
timeout, just a hang until the process was killed.
"""
from __future__ import annotations

from .base import SECRET_PIN, BackendUnavailable, KeyProtectionBackend

#: Test seam. The selector must be provable in BOTH directions, so tests force
#: availability here rather than requiring real TPM hardware to exercise the
#: "prefers TPM" branch. Production never sets this.
_FORCE_AVAILABLE = False


class TpmBackend(KeyProtectionBackend):
    tier_id = "tpm_pin"

    def available(self) -> bool:
        # Real detection (NCryptOpenStorageProvider against the Platform Crypto
        # Provider) lands with the implementation. Until then this is False, so
        # the selector always falls through to the password backend.
        return bool(_FORCE_AVAILABLE)

    def is_provisioned(self) -> bool:
        return False

    def is_unlocked(self) -> bool:
        # A TPM key is never usable without its PIN -- proven 2026-08-03:
        # signing without one returns 0x80090022 under NCRYPT_SILENT_FLAG.
        return False

    def secret_kind(self) -> str:
        return SECRET_PIN

    def _unavailable(self):
        raise BackendUnavailable(
            "the TPM backend is not implemented yet (tier 1 is a fast-follow)")

    def provision(self, secret: str, existing_private_key=None) -> str:
        self._unavailable()

    def unlock(self, secret: str) -> None:
        self._unavailable()

    def sign(self, message: str) -> str:
        self._unavailable()

    def public_key_pem(self) -> str:
        self._unavailable()

    def change_secret(self, old_secret: str, new_secret: str) -> None:
        self._unavailable()

    def erase(self) -> None:
        # Deliberately a no-op rather than an error: an uninstaller sweeping all
        # backends must not be derailed by a backend that was never provisioned.
        return None
