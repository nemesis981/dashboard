"""Key-protection backend selection.

Two distinct questions, deliberately two functions — conflating them is how a
selector ends up quietly provisioning into a weaker tier than it should:

  detect_backend()    which backend currently HOLDS this device's key?
  preferred_backend() which backend should a NEW provision use?

detect never invents key material, and preferred never returns the legacy tier.
"""
from __future__ import annotations

from .base import (SECRET_PASSWORD, SECRET_PIN, BackendUnavailable, Corrupt,
                   KeyProtectError, KeyProtectionBackend, Locked, LockedOut,
                   NotProvisioned, NotSupported, WrongSecret)
from .legacy import LegacyBackend
from .password import PasswordBackend
from .tpm import TpmBackend

__all__ = [
    "SECRET_PASSWORD", "SECRET_PIN",
    "KeyProtectError", "NotProvisioned", "Locked", "WrongSecret", "LockedOut",
    "Corrupt", "BackendUnavailable", "NotSupported", "KeyProtectionBackend",
    "PasswordBackend", "LegacyBackend", "TpmBackend",
    "detect_backend", "preferred_backend", "all_backends", "tier_of",
]

#: Strongest first. Selection walks this order.
_ORDER = (TpmBackend, PasswordBackend)


def all_backends(keys_dir: str):
    """Every backend instance, including legacy — for uninstall sweeps."""
    return [cls(keys_dir) for cls in (TpmBackend, PasswordBackend, LegacyBackend)]


def detect_backend(keys_dir: str):
    """The backend holding this device's existing key, or None.

    Returns None rather than a default-constructed backend: "no key material
    here" is a real answer the caller must handle, and handing back an empty
    password backend would make an unprovisioned device indistinguishable from
    a provisioned one.
    """
    for cls in _ORDER:
        be = cls(keys_dir)
        try:
            if be.available() and be.is_provisioned():
                return be
        except KeyProtectError:
            continue
    legacy = LegacyBackend(keys_dir)
    if legacy.available():
        return legacy
    return None


def preferred_backend(keys_dir: str):
    """The backend a NEW provision should use: strongest available.

    Never returns LegacyBackend — tier 4 is migrate-from only, so a fresh
    install can never land on "no protection".
    """
    for cls in _ORDER:
        be = cls(keys_dir)
        if be.available():
            return be
    # PasswordBackend.available() is unconditionally True, so this is
    # unreachable in practice. Raising beats returning something weaker.
    raise BackendUnavailable("no key-protection backend is available")


def tier_of(keys_dir: str) -> str:
    """Tier id for capability reporting, or 'unprovisioned'.

    Reported to the server in the heartbeat so uneven key protection across the
    fleet is visible rather than silent — the same argument ADR 0004 (b) makes
    for engine and ruleset versions.
    """
    be = detect_backend(keys_dir)
    return be.tier_id if be is not None else "unprovisioned"
