"""Tier 1 — TPM-resident key with a PIN.

LINUX ARM: IMPLEMENTED + VM-PROVEN 2026-08-22 (see linux_tpm.LinuxTpmBackend) against a
VirtualBox emulated TPM 2.0. TpmBackend delegates to it on Linux.
WINDOWS ARM (CNG): IMPLEMENTED + VM-PROVEN 2026-08-22 (see windows_cng_tpm.WindowsCngTpmBackend)
against an emulated TPM 2.0 on the build-env VM, exercised through Python ctypes (not just the
2026-08-03 PowerShell spike). TpmBackend delegates to it on Windows. A full 15-check lifecycle
passed clean: provision, non-exportable-key enforcement, server-compatible PKCS1v15/SHA256
signature verification, Locked-until-unlock across a fresh process, wrong-PIN -> WrongSecret
(0x80090010), DA lockout -> LockedOut (0x80090031), and erase. change_secret is an honest
NotSupported: the PCP cannot change a finalized key's PIN in place (NCryptSetProperty(SmartCardPin)
returns NTE_BAD_FLAGS), so PIN rotation is rotate-key-and-re-enroll.

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

Both open items from the 2026-08-03 spike are now CLOSED (2026-08-22, ctypes on the
build-env VM):
  * anti-hammering lockout confirmed — repeated wrong PINs drove the TPM into DA lockout,
    surfaced distinctly as LockedOut (0x80090031), not conflated with a single wrong PIN;
  * Python ctypes marshalling proven end-to-end (this backend is pure ctypes against
    ncrypt.dll — no PowerShell), including the TOKEN/BLOB struct handling.

MANDATORY when this is implemented: NCRYPT_SILENT_FLAG (0x40) on every NCrypt
call. Without it, NCryptFinalizeKey blocks indefinitely on interactive platform
UI that a service session can never satisfy — reproduced live, no error, no
timeout, just a hang until the process was killed.
"""
from __future__ import annotations

import sys

from .base import SECRET_PIN, BackendUnavailable, KeyProtectionBackend

try:
    from .linux_tpm import LinuxTpmBackend as _LinuxTpm
except Exception:                                            # noqa: BLE001
    _LinuxTpm = None

try:
    from .windows_cng_tpm import WindowsCngTpmBackend as _WinCng
except Exception:                                            # noqa: BLE001
    _WinCng = None

#: Test seam. The selector must be provable in BOTH directions, so tests force
#: availability here rather than requiring real TPM hardware to exercise the
#: "prefers TPM" branch. Production never sets this.
_FORCE_AVAILABLE = False


class TpmBackend(KeyProtectionBackend):
    """TPM+PIN backend. Delegates to the Linux tpm2 implementation on Linux; on Windows it
    is the CNG follow-up (available() False until built). tier_id stays 'tpm_pin' either way
    so the selector and server capability reporting are platform-uniform."""
    tier_id = "tpm_pin"

    def __init__(self, keys_dir: str):
        super().__init__(keys_dir)
        # One TpmBackend, two real implementations behind it: tpm2-tools on Linux,
        # CNG/Platform-Crypto-Provider on Windows. Everything below delegates to
        # self._impl, so the selector/capability surface is platform-uniform and the
        # only platform branch lives here.
        if _LinuxTpm is not None and sys.platform.startswith("linux"):
            self._impl = _LinuxTpm(keys_dir)
        elif _WinCng is not None and sys.platform == "win32":
            self._impl = _WinCng(keys_dir)
        else:
            self._impl = None

    def available(self) -> bool:
        # _FORCE_AVAILABLE keeps the selector provable in both directions without real
        # hardware (see the seam note above). Otherwise: real Linux tpm2 or Windows CNG
        # (whichever this platform's impl reports), or False if no TPM is present.
        if _FORCE_AVAILABLE:
            return True
        return self._impl.available() if self._impl else False

    def is_provisioned(self) -> bool:
        return self._impl.is_provisioned() if self._impl else False

    def is_unlocked(self) -> bool:
        return self._impl.is_unlocked() if self._impl else False

    def secret_kind(self) -> str:
        return SECRET_PIN

    def _no_backend(self):
        raise BackendUnavailable(
            "no TPM backend for this platform (need Linux tpm2-tools or a Windows "
            "TPM via the Platform Crypto Provider); the selector should have chosen "
            "the password backend instead")

    def provision(self, secret: str, existing_private_key=None) -> str:
        if not self._impl:
            self._no_backend()
        return self._impl.provision(secret, existing_private_key)

    def unlock(self, secret: str) -> None:
        if not self._impl:
            self._no_backend()
        self._impl.unlock(secret)

    def sign(self, message: str) -> str:
        if not self._impl:
            self._no_backend()
        return self._impl.sign(message)

    def public_key_pem(self) -> str:
        if not self._impl:
            self._no_backend()
        return self._impl.public_key_pem()

    def change_secret(self, old_secret: str, new_secret: str) -> None:
        if not self._impl:
            self._no_backend()
        self._impl.change_secret(old_secret, new_secret)

    def erase(self) -> None:
        if self._impl:
            self._impl.erase()
