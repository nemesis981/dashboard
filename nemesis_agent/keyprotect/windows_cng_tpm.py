"""Tier 1 (Windows arm) — TPM-resident signing key with a PIN, via CNG (ncrypt.dll).

The Windows counterpart to linux_tpm.py, completing TPM key-protection cross-platform. The
key lives in the Microsoft Platform Crypto Provider (TPM-backed) and is non-exportable; it
signs inside the TPM and never exists in process memory. VM-PROVEN 2026-08-22 against a
Windows 11 VM with an emulated TPM 2.0: NCryptCreatePersistedKey + NCRYPT_PIN_PROPERTY +
NCRYPT_SILENT_FLAG finalize, NCryptSignHash(PKCS1) -> a 256-byte signature that VERIFIES with
the server's PKCS1v15/SHA256 scheme.

MANDATORY: NCRYPT_SILENT_FLAG on every NCrypt call. Without it NCryptFinalizeKey blocks on
interactive TPM UI a service session can never satisfy (spike 2026-08-03). All calls here set
it. Error mapping (VM-observed): 0x80090010 access-denied -> WrongSecret; 0x80090022 silent-
context/PIN-required -> Locked; TPM lockout code -> LockedOut.
"""
from __future__ import annotations

import base64
import struct
import sys

from .base import (SECRET_PIN, BackendUnavailable, Corrupt, KeyProtectionBackend,
                   Locked, LockedOut, NotProvisioned, NotSupported, WrongSecret)

_PCP = "Microsoft Platform Crypto Provider"
_KEYNAME = "nemesis-agent-signing-key"
NCRYPT_SILENT_FLAG = 0x40
NCRYPT_OVERWRITE_KEY_FLAG = 0x80
NCRYPT_PAD_PKCS1_FLAG = 0x2
NCRYPT_PERSIST_FLAG = 0x1000
_PIN_PROP = "SmartCardPin"
_LEN_PROP = "Length"
_PUB_BLOB = "RSAPUBLICBLOB"

# VM-observed / documented HRESULTs (low 32 bits)
_E_ACCESS_DENIED = 0x80090010     # NTE_PERM -> wrong PIN
_E_SILENT_CONTEXT = 0x80090022    # PIN required but none supplied (silent) -> Locked
_E_LOCKOUT = (0x80090031, 0x80280400, 0x80280402)  # auth ignored / TPM DA lockout


def _win():
    if sys.platform != "win32":
        raise BackendUnavailable("CNG TPM backend is Windows-only")
    import ctypes
    nc = ctypes.WinDLL("ncrypt.dll")
    for name in ("NCryptOpenStorageProvider", "NCryptCreatePersistedKey",
                 "NCryptSetProperty", "NCryptFinalizeKey", "NCryptExportKey",
                 "NCryptSignHash", "NCryptOpenKey", "NCryptFreeObject",
                 "NCryptDeleteKey"):
        getattr(nc, name).restype = ctypes.c_long
    return ctypes, nc


class WindowsCngTpmBackend(KeyProtectionBackend):
    tier_id = "tpm_pin"

    def __init__(self, keys_dir: str):
        super().__init__(keys_dir)
        self._pin = None

    # ── error mapping: HRESULT -> typed error, never a silent default ──
    def _map(self, rc, where):
        rc &= 0xffffffff
        if rc == 0:
            return
        if rc == _E_ACCESS_DENIED:
            raise WrongSecret("the PIN was rejected by the TPM (0x%08x)" % rc)
        if rc == _E_SILENT_CONTEXT:
            raise Locked("the TPM key needs its PIN (0x%08x)" % rc)
        if rc in _E_LOCKOUT:
            raise LockedOut("the TPM is in dictionary-attack lockout (0x%08x)" % rc)
        raise Corrupt("%s failed: 0x%08x" % (where, rc))

    def _open_provider(self, ctypes, nc):
        import ctypes.wintypes as wt
        h = wt.HANDLE()
        self._map(nc.NCryptOpenStorageProvider(ctypes.byref(h),
                  ctypes.c_wchar_p(_PCP), 0), "NCryptOpenStorageProvider")
        return h

    def _open_key(self, ctypes, nc, hProv):
        import ctypes.wintypes as wt
        h = wt.HANDLE()
        rc = nc.NCryptOpenKey(hProv, ctypes.byref(h), ctypes.c_wchar_p(_KEYNAME),
                              0, NCRYPT_SILENT_FLAG) & 0xffffffff
        if rc != 0:
            return None
        return h

    # ── capability ──
    def available(self) -> bool:
        if sys.platform != "win32":
            return False
        try:
            ctypes, nc = _win()
            hProv = self._open_provider(ctypes, nc)
            nc.NCryptFreeObject(hProv)
            return True
        except Exception:                                    # noqa: BLE001
            return False

    def is_provisioned(self) -> bool:
        try:
            ctypes, nc = _win()
        except BackendUnavailable:
            return False
        hProv = self._open_provider(ctypes, nc)
        try:
            hKey = self._open_key(ctypes, nc, hProv)
            if hKey:
                nc.NCryptFreeObject(hKey)
                return True
            return False
        finally:
            nc.NCryptFreeObject(hProv)

    def is_unlocked(self) -> bool:
        return self._pin is not None

    def secret_kind(self) -> str:
        return SECRET_PIN

    def _export_public_pem(self, ctypes, nc, hKey) -> str:
        cb = ctypes.c_ulong(0)
        self._map(nc.NCryptExportKey(hKey, None, ctypes.c_wchar_p(_PUB_BLOB), None,
                  None, 0, ctypes.byref(cb), 0), "NCryptExportKey(size)")
        blob = (ctypes.c_ubyte * cb.value)()
        self._map(nc.NCryptExportKey(hKey, None, ctypes.c_wchar_p(_PUB_BLOB), None,
                  blob, cb.value, ctypes.byref(cb), 0), "NCryptExportKey")
        raw = bytes(blob)
        _magic, _bits, cbExp, cbMod = struct.unpack("<4I", raw[:16])
        # BCRYPT_RSAKEY_BLOB header is 6 DWORDs; exp||modulus follow.
        off = 24
        exp = int.from_bytes(raw[off:off + cbExp], "big")
        mod = int.from_bytes(raw[off + cbExp:off + cbExp + cbMod], "big")
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        pub = rsa.RSAPublicNumbers(exp, mod).public_key()
        return pub.public_bytes(serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def _set_pin(self, ctypes, nc, hKey, pin):
        buf = ctypes.create_unicode_buffer(pin)
        self._map(nc.NCryptSetProperty(hKey, ctypes.c_wchar_p(_PIN_PROP),
                  ctypes.cast(buf, ctypes.c_void_p), (len(pin) + 1) * 2, 0),
                  "NCryptSetProperty(PIN)")

    def _sign_with(self, ctypes, nc, hKey, message: str) -> str:
        import ctypes.wintypes as wt  # noqa: F401
        from cryptography.hazmat.primitives import hashes
        h = hashes.Hash(hashes.SHA256()); h.update(message.encode()); digest = h.finalize()

        class _PKCS1(ctypes.Structure):
            _fields_ = [("pszAlgId", ctypes.c_wchar_p)]
        pad = _PKCS1("SHA256")
        dbuf = (ctypes.c_ubyte * len(digest)).from_buffer_copy(digest)
        cb = ctypes.c_ulong(0)
        self._map(nc.NCryptSignHash(hKey, ctypes.byref(pad), dbuf, len(digest), None,
                  0, ctypes.byref(cb), NCRYPT_PAD_PKCS1_FLAG), "NCryptSignHash(size)")
        sig = (ctypes.c_ubyte * cb.value)()
        self._map(nc.NCryptSignHash(hKey, ctypes.byref(pad), dbuf, len(digest), sig,
                  cb.value, ctypes.byref(cb), NCRYPT_PAD_PKCS1_FLAG), "NCryptSignHash")
        return base64.b64encode(bytes(sig)).decode()

    # ── lifecycle ──
    def provision(self, secret: str, existing_private_key=None) -> str:
        if existing_private_key is not None:
            raise NotSupported("a TPM-resident key cannot adopt an external private key")
        if not secret:
            raise WrongSecret("refusing to protect a TPM key with an empty PIN")
        ctypes, nc = _win()
        import ctypes.wintypes as wt
        hProv = self._open_provider(ctypes, nc)
        try:
            old = self._open_key(ctypes, nc, hProv)
            if old:
                # flag 0, NOT NCRYPT_SILENT_FLAG: NCryptDeleteKey rejects the silent
                # flag with NTE_BAD_FLAGS (0x80090009) and the key survives; delete
                # is non-interactive regardless (VM-confirmed 2026-08-22).
                nc.NCryptDeleteKey(old, 0)
            hKey = wt.HANDLE()
            self._map(nc.NCryptCreatePersistedKey(hProv, ctypes.byref(hKey),
                      ctypes.c_wchar_p("RSA"), ctypes.c_wchar_p(_KEYNAME), 0,
                      NCRYPT_OVERWRITE_KEY_FLAG), "NCryptCreatePersistedKey")
            length = ctypes.c_ulong(2048)
            self._map(nc.NCryptSetProperty(hKey, ctypes.c_wchar_p(_LEN_PROP),
                      ctypes.byref(length), ctypes.sizeof(length), 0),
                      "NCryptSetProperty(Length)")
            self._set_pin(ctypes, nc, hKey, secret)
            self._map(nc.NCryptFinalizeKey(hKey, NCRYPT_SILENT_FLAG), "NCryptFinalizeKey")
            pem = self._export_public_pem(ctypes, nc, hKey)
            nc.NCryptFreeObject(hKey)
        finally:
            nc.NCryptFreeObject(hProv)
        self._pin = secret
        return pem

    def unlock(self, secret: str) -> None:
        ctypes, nc = _win()
        hProv = self._open_provider(ctypes, nc)
        try:
            hKey = self._open_key(ctypes, nc, hProv)
            if not hKey:
                raise NotProvisioned("no TPM key to unlock")
            try:
                self._set_pin(ctypes, nc, hKey, secret)
                self._sign_with(ctypes, nc, hKey, "unlock-probe")  # auth check inside TPM
            finally:
                nc.NCryptFreeObject(hKey)
        finally:
            nc.NCryptFreeObject(hProv)
        self._pin = secret

    def sign(self, message: str) -> str:
        if self._pin is None:
            if not self.is_provisioned():
                raise NotProvisioned("no TPM key to sign with")
            raise Locked("TPM key is provisioned but not unlocked in this process")
        ctypes, nc = _win()
        hProv = self._open_provider(ctypes, nc)
        try:
            hKey = self._open_key(ctypes, nc, hProv)
            if not hKey:
                raise NotProvisioned("TPM key vanished")
            try:
                self._set_pin(ctypes, nc, hKey, self._pin)
                return self._sign_with(ctypes, nc, hKey, message)
            finally:
                nc.NCryptFreeObject(hKey)
        finally:
            nc.NCryptFreeObject(hProv)

    def public_key_pem(self) -> str:
        ctypes, nc = _win()
        hProv = self._open_provider(ctypes, nc)
        try:
            hKey = self._open_key(ctypes, nc, hProv)
            if not hKey:
                raise NotProvisioned("no TPM key")
            try:
                return self._export_public_pem(ctypes, nc, hKey)
            finally:
                nc.NCryptFreeObject(hKey)
        finally:
            nc.NCryptFreeObject(hProv)

    def change_secret(self, old_secret: str, new_secret: str) -> None:
        """NOT SUPPORTED on Windows PCP. Unlike Linux tpm2 (tpm2_changeauth), the Microsoft
        Platform Crypto Provider does not expose an in-place PIN change for a finalized
        persisted key (NCryptSetProperty(SmartCardPin) after finalize returns NTE_BAD_FLAGS /
        is ignored -- VM-confirmed 2026-08-22). Changing the PIN therefore requires ROTATING
        the key (provision() a new one), which yields a NEW public key and so a NEW device
        identity -- a re-enroll, not a re-protect. That is a different operation from what
        change_secret promises (preserve identity), so this raises rather than silently
        rotating and breaking the device's server-side identity. The caller (or operator)
        rotates + re-enrolls deliberately.
        """
        raise NotSupported(
            "Windows PCP cannot change a TPM key PIN in place; rotate via provision() and "
            "re-enroll (Linux tpm2 supports in-place change, Windows CNG does not)")

    def erase(self) -> None:
        try:
            ctypes, nc = _win()
        except BackendUnavailable:
            self._pin = None
            return
        hProv = self._open_provider(ctypes, nc)
        try:
            hKey = self._open_key(ctypes, nc, hProv)
            if hKey:
                # flag 0, NOT NCRYPT_SILENT_FLAG (see provision): the silent flag makes
                # NCryptDeleteKey fail NTE_BAD_FLAGS and leaves the key behind, which is
                # exactly the leak erase() exists to prevent.
                nc.NCryptDeleteKey(hKey, 0)
        finally:
            nc.NCryptFreeObject(hProv)
        self._pin = None
