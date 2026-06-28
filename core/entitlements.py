"""
Entitlements — the commercial-tier gate.

A single stub today. Every commercial feature checks `is_commercial()`. When the
license-key system is built, ONLY this module changes — call sites stay put.
Graceful downgrade only: never hard-lock a security product behind a paywall.
See docs/roadmap/ for the licensing / key-unlock architecture.
"""


def is_commercial() -> bool:
    """
    Returns True if a valid commercial license is active.
    Free tier and expired trials return False.
    Graceful downgrade only — never hard-lock a security product.
    See docs/roadmap/ for the licensing/key-unlock architecture.
    """
    return False


def get_tier() -> str:
    """Returns 'commercial' or 'free'."""
    return 'commercial' if is_commercial() else 'free'
