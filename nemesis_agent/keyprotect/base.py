"""Key-protection backends — the sign() seam.

The agent's RSA private key is used for exactly three things: the enrollment
signature, the heartbeat signature, and the de-enrollment signature. Every one
of those needs a SIGNATURE — none of them needs the key itself.

That distinction is the entire point of this interface. The destination design
is a TPM-resident key (tier 1), which is non-exportable: it signs inside the
chip and never exists in process memory. Any interface shaped as "give me the
private key and I'll sign with it" therefore cannot be implemented by the
backend this design is headed for. Callers ask a backend to sign; they never
see key material.

Backends are selected, not hardcoded — see ``keyprotect/__init__.py``.
"""
from __future__ import annotations

import abc

# Secret kinds. Drives the GUI prompt's wording, masking and validation; the
# dialog never learns which backend it is talking to.
SECRET_PASSWORD = "password"
SECRET_PIN = "pin"


# ── Typed errors ──────────────────────────────────────────────────────────
# Typed, not strings. Callers (and the GUI) branch on the type; nothing parses
# a backend-specific message. The tier 1 spike (2026-08-03) confirmed the
# Windows CNG codes map cleanly onto these: 0x80090022 (silent context, PIN
# required) -> Locked, 0x80090010 (access denied) -> WrongSecret.

class KeyProtectError(Exception):
    """Base for every key-protection failure."""


class NotProvisioned(KeyProtectError):
    """No key material exists for this backend yet."""


class Locked(KeyProtectError):
    """Provisioned, but not unlocked in this session. Needs the secret."""


class WrongSecret(KeyProtectError):
    """The supplied password/PIN did not unlock the key."""


class LockedOut(KeyProtectError):
    """The backend refuses further attempts (e.g. TPM anti-hammering)."""


class Corrupt(KeyProtectError):
    """Key material is present but structurally damaged. NOT a wrong secret."""


class BackendUnavailable(KeyProtectError):
    """This backend cannot run on this machine (e.g. no TPM present)."""


class NotSupported(KeyProtectError):
    """The operation is not valid for this backend (e.g. provisioning legacy)."""


class KeyProtectionBackend(abc.ABC):
    """One way of holding the agent's signing key.

    Lifecycle: ``provision()`` once, then ``unlock()`` once per process, then
    ``sign()`` freely for the life of the process. Every method fails with a
    typed error rather than returning a default — a failed read must never be
    reported as a legitimate value.
    """

    #: Stable identifier reported to the server for capability visibility.
    tier_id: str = "unset"

    def __init__(self, keys_dir: str):
        #: Injected rather than resolved internally, so the whole backend is
        #: testable against a throwaway directory without touching %APPDATA%.
        self.keys_dir = keys_dir

    # ── capability ────────────────────────────────────────────────────────
    @abc.abstractmethod
    def available(self) -> bool:
        """Can this backend run on THIS machine at all?"""

    @abc.abstractmethod
    def is_provisioned(self) -> bool:
        """Does key material for this backend already exist?"""

    @abc.abstractmethod
    def is_unlocked(self) -> bool:
        """Can this backend sign RIGHT NOW, without being given a secret?

        The startup gate branches on this rather than on ``tier_id``. Asking
        "can you sign?" is the operational question; comparing a tier label
        infers behaviour from a name, and names drift. It is also what keeps
        already-deployed tier-4 devices from being prompted for a password
        nobody ever set — LegacyBackend answers True because it genuinely
        needs no secret.
        """

    @abc.abstractmethod
    def secret_kind(self) -> str:
        """SECRET_PASSWORD or SECRET_PIN — drives the prompt, not the crypto."""

    # ── lifecycle ─────────────────────────────────────────────────────────
    @abc.abstractmethod
    def provision(self, secret: str, existing_private_key=None) -> str:
        """Create key material protected by ``secret``; return public key PEM.

        ``existing_private_key`` lets a migration ADOPT the key it is migrating
        from, so the public key — and therefore the device's server-side
        identity — survives the move. Backends that cannot import a key (any
        TPM-resident backend) raise NotSupported when it is passed.
        """

    @abc.abstractmethod
    def unlock(self, secret: str) -> None:
        """Make signing possible for the rest of this process."""

    @abc.abstractmethod
    def sign(self, message: str) -> str:
        """Base64 RSA PKCS1v15/SHA256 signature over ``message.encode()``.

        Byte-for-byte compatible with the server's _verify_enroll_signature.
        """

    @abc.abstractmethod
    def public_key_pem(self) -> str:
        """SubjectPublicKeyInfo PEM, as the server stores it."""

    @abc.abstractmethod
    def change_secret(self, old_secret: str, new_secret: str) -> None:
        """Re-protect existing key material under a new secret."""

    @abc.abstractmethod
    def erase(self) -> None:
        """Remove this backend's key material. Idempotent.

        Exists on the interface because tier 1 persists keys in CNG storage,
        independently of the filesystem — an uninstaller that only deletes
        %APPDATA%\\Nemesis would leave them behind.
        """
