"""Tier 1 (Linux arm) — TPM-resident signing key with a PIN, via tpm2-tools.

The Linux counterpart to the CNG design in tpm.py. The signing key is created INSIDE the
TPM and is non-exportable: its private half is a TPM-wrapped blob that never exists in
process memory in the clear, so this backend implements the sign() seam (base.py) rather
than any "give me the key" shape. VM-PROVEN 2026-08-22 against a VirtualBox emulated
TPM 2.0 (software TPM, not host hardware):
  * a non-exportable rsa2048:rsassa child key under the owner primary;
  * tpm2_sign -f plain -> a raw 256-byte PKCS1v15/SHA256 signature that VERIFIES against
    the stored public key with the server's exact scheme;
  * wrong PIN -> TPM_RC_AUTH_FAIL (0x...98e) -> WrongSecret;
  * repeated wrong PINs -> TPM_RC_LOCKOUT (0x921) -> LockedOut (DA anti-hammering — the
    behaviour the 2026-08-03 spike had NOT yet proven).

Requires tpm2-tools and the agent user in the `tss` group (no sudo). available() answers
False cleanly where neither holds, so the selector falls through to the password backend.
The Windows CNG arm (tpm.py) is a SEPARATE follow-up against the tpm-cng-spike VM.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile

from .base import (SECRET_PIN, BackendUnavailable, Corrupt, KeyProtectionBackend,
                   Locked, LockedOut, NotProvisioned, NotSupported, WrongSecret)

MARKER_NAME = "tpm_key.json"
PUBLIC_NAME = "public.pem"
BLOB_PUB = "tpm_k.pub"          # TPM-wrapped public blob (safe at rest)
BLOB_PRIV = "tpm_k.priv"        # TPM-wrapped private blob — encrypted BY the TPM primary,
                                # non-exportable in the clear; safe at rest, useless off-chip
PERSIST_HANDLE = "0x81018090"   # owner persistent range; one signing key per agent
MARKER_VERSION = 1

#: TPM response codes we must map. Substring-matched from tpm2-tools stderr.
_RC_AUTH_FAIL = ("0x98e", "0x9a2", "0x22")   # bad authValue (wrong PIN)
_RC_LOCKOUT = ("0x921",)                      # dictionary-attack lockout


def _tpm_available() -> bool:
    if not sys.platform.startswith("linux"):
        return False
    if not (os.path.exists("/dev/tpmrm0") or os.path.exists("/dev/tpm0")):
        return False
    try:
        r = subprocess.run(["tpm2_getcap", "properties-fixed"],
                           capture_output=True, timeout=10)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class LinuxTpmBackend(KeyProtectionBackend):
    tier_id = "tpm_pin"

    def __init__(self, keys_dir: str):
        super().__init__(keys_dir)
        self._pin = None                # cached ONLY for this process after unlock()

    # ── paths ──
    @property
    def marker_path(self): return os.path.join(self.keys_dir, MARKER_NAME)
    @property
    def public_path(self): return os.path.join(self.keys_dir, PUBLIC_NAME)
    @property
    def _blob_pub(self): return os.path.join(self.keys_dir, BLOB_PUB)
    @property
    def _blob_priv(self): return os.path.join(self.keys_dir, BLOB_PRIV)

    # ── tpm2 runner: maps exit/stderr to TYPED errors, never a silent default ──
    def _tpm(self, *args, check=True):
        try:
            r = subprocess.run(list(args), capture_output=True, text=True, timeout=30)
        except FileNotFoundError as exc:
            raise BackendUnavailable("tpm2-tools not installed: %s" % exc) from exc
        except subprocess.SubprocessError as exc:
            raise Corrupt("tpm2 call failed to run: %s" % exc) from exc
        if r.returncode != 0 and check:
            err = (r.stderr or "").lower()
            if any(c in err for c in _RC_LOCKOUT) or "lockout" in err:
                raise LockedOut("TPM is in dictionary-attack lockout; wait for the "
                                "lockout to clear before retrying the PIN")
            if any(c in err for c in _RC_AUTH_FAIL) or "authorization" in err:
                raise WrongSecret("the PIN did not authorize the TPM key")
            raise Corrupt("tpm2 %s failed (rc=%d): %s"
                          % (args[0], r.returncode, (r.stderr or "").strip()[:200]))
        return r

    def _handle(self):
        """The persistent handle from the marker, or raise. Fail-closed."""
        if not os.path.isfile(self.marker_path):
            raise NotProvisioned("no TPM key marker at %s" % self.marker_path)
        try:
            m = json.load(open(self.marker_path, encoding="utf-8"))
            if m.get("v") != MARKER_VERSION or not m.get("handle"):
                raise Corrupt("TPM key marker malformed: %r" % m)
            return m["handle"]
        except (OSError, ValueError) as exc:
            raise Corrupt("TPM key marker unreadable: %s" % exc) from exc

    # ── capability ──
    def available(self) -> bool:
        return _tpm_available()

    def is_provisioned(self) -> bool:
        if not os.path.isfile(self.marker_path):
            return False
        # A marker without a live handle is CORRUPT, not "not provisioned" -- surface it.
        try:
            handle = self._handle()
            r = self._tpm("tpm2_readpublic", "-c", handle, check=False)
            if r.returncode != 0:
                raise Corrupt("TPM marker present but persistent handle %s is gone "
                              "(evicted or different TPM)" % handle)
            return True
        except BackendUnavailable:
            return False

    def is_unlocked(self) -> bool:
        return self._pin is not None

    def secret_kind(self) -> str:
        return SECRET_PIN

    # ── lifecycle ──
    def provision(self, secret: str, existing_private_key=None) -> str:
        if existing_private_key is not None:
            raise NotSupported("a TPM-resident key cannot adopt an external private key "
                               "without breaking non-exportability; provision generates "
                               "the key inside the TPM")
        if not secret:
            raise WrongSecret("refusing to protect a TPM key with an empty PIN")
        if not self.available():
            raise BackendUnavailable("no usable TPM on this machine")
        os.makedirs(self.keys_dir, exist_ok=True)
        with tempfile.TemporaryDirectory() as wd:
            prim = os.path.join(wd, "prim.ctx")
            kctx = os.path.join(wd, "k.ctx")
            self._tpm("tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "rsa",
                      "-c", prim)
            self._tpm("tpm2_create", "-C", prim, "-G", "rsa2048:rsassa:null",
                      "-g", "sha256", "-u", self._blob_pub, "-r", self._blob_priv,
                      "-p", secret)
            self._tpm("tpm2_load", "-C", prim, "-u", self._blob_pub,
                      "-r", self._blob_priv, "-c", kctx)
            # Clear any stale key at our handle, then persist this one.
            self._tpm("tpm2_evictcontrol", "-C", "o", "-c", PERSIST_HANDLE, check=False)
            self._tpm("tpm2_evictcontrol", "-C", "o", "-c", kctx, PERSIST_HANDLE)
            self._tpm("tpm2_readpublic", "-c", PERSIST_HANDLE, "-f", "pem",
                      "-o", self.public_path)
        tmp = self.marker_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"v": MARKER_VERSION, "tier": self.tier_id,
                       "handle": PERSIST_HANDLE}, fh)
        os.replace(tmp, self.marker_path)
        self._pin = secret
        return self.public_key_pem()

    def unlock(self, secret: str) -> None:
        handle = self._handle()             # NotProvisioned / Corrupt
        # Verify by signing a probe INSIDE the TPM. Auth failure -> WrongSecret; lockout ->
        # LockedOut; both come typed from _tpm. Only a real success caches the PIN.
        with tempfile.TemporaryDirectory() as wd:
            msg = os.path.join(wd, "probe"); open(msg, "wb").write(b"unlock-probe")
            self._tpm("tpm2_sign", "-c", handle, "-g", "sha256", "-s", "rsassa",
                      "-f", "plain", "-p", secret, "-o", os.path.join(wd, "s"), msg)
        self._pin = secret

    def sign(self, message: str) -> str:
        if self._pin is None:
            if not self.is_provisioned():
                raise NotProvisioned("no TPM key to sign with")
            raise Locked("TPM key is provisioned but not unlocked in this process")
        handle = self._handle()
        with tempfile.TemporaryDirectory() as wd:
            msg = os.path.join(wd, "m"); sig = os.path.join(wd, "s")
            open(msg, "wb").write(message.encode())
            self._tpm("tpm2_sign", "-c", handle, "-g", "sha256", "-s", "rsassa",
                      "-f", "plain", "-p", self._pin, "-o", sig, msg)
            return base64.b64encode(open(sig, "rb").read()).decode()

    def public_key_pem(self) -> str:
        if os.path.isfile(self.public_path):
            return open(self.public_path, encoding="utf-8").read()
        raise NotProvisioned("no public key at %s" % self.public_path)

    def change_secret(self, old_secret: str, new_secret: str) -> None:
        if not new_secret:
            raise WrongSecret("refusing to set an empty PIN")
        self.unlock(old_secret)             # raises WrongSecret/LockedOut if old is wrong
        if not (os.path.isfile(self._blob_pub) and os.path.isfile(self._blob_priv)):
            raise Corrupt("wrapped key blobs missing; cannot change the TPM PIN")
        with tempfile.TemporaryDirectory() as wd:
            prim = os.path.join(wd, "prim.ctx"); kctx = os.path.join(wd, "k.ctx")
            newpriv = os.path.join(wd, "k.priv.new")
            self._tpm("tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "rsa",
                      "-c", prim)
            self._tpm("tpm2_load", "-C", prim, "-u", self._blob_pub,
                      "-r", self._blob_priv, "-c", kctx)
            self._tpm("tpm2_changeauth", "-c", kctx, "-C", prim, "-p", old_secret,
                      "-r", newpriv, new_secret)
            os.replace(newpriv, self._blob_priv)
            # re-persist the re-authed key at the same handle (public key unchanged)
            self._tpm("tpm2_load", "-C", prim, "-u", self._blob_pub,
                      "-r", self._blob_priv, "-c", kctx)
            self._tpm("tpm2_evictcontrol", "-C", "o", "-c", PERSIST_HANDLE, check=False)
            self._tpm("tpm2_evictcontrol", "-C", "o", "-c", kctx, PERSIST_HANDLE)
        self._pin = new_secret

    def erase(self) -> None:
        # Evict the persistent handle from the TPM, then remove on-disk material. The
        # handle eviction is why erase() exists on the interface: deleting keys_dir alone
        # would leave the key resident in the TPM.
        try:
            if os.path.isfile(self.marker_path):
                self._tpm("tpm2_evictcontrol", "-C", "o", "-c", self._handle(),
                          check=False)
        except (Corrupt, NotProvisioned, BackendUnavailable):
            pass
        for p in (self.marker_path, self.public_path, self._blob_pub, self._blob_priv):
            try:
                os.remove(p)
            except FileNotFoundError:
                pass
        self._pin = None
