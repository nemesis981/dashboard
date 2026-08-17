"""Entitlements — the commercial-tier gate and the remote-device cap.

Replaces the 23-line stub whose docstring promised: *"When the license-key system
is built, ONLY this module changes — call sites stay put."* That promise is kept:
`is_commercial()` and `get_tier()` have the same signatures and the same meaning,
and the single existing call site (`dashboard.py`, Users section) is untouched.

── THE PRINCIPLE, AND HOW THE CAP STAYS INSIDE IT ──────────────────────────
The stub carried an instruction worth restating rather than deleting:

    "Graceful downgrade only: never hard-lock a security product behind a paywall."

A remote-device cap is technical enforcement, so the reconciliation matters and
was made explicitly (operator, 2026-08-17):

  * **The cap withholds REMOTE REACH, never LOCAL PROTECTION.** Local devices are
    unlimited under all conditions. A device past the cap still installs the full
    agent and gets full local security; only the tailnet path is withheld.
    Security is not reduced — reach is. That is what makes refusal legitimate
    here rather than a paywall on safety.
  * **A node-lock mismatch DEGRADES to free tier; it never stops the product.**
    Losing a licence must never mean losing protection.

Nothing detection-related is ever gated. If a future change would gate a
detection feature behind `is_commercial()`, the instruction above is being
violated and the change is wrong.

── WHAT THE CAP COUNTS (resolved 2026-08-17) ───────────────────────────────
**Tailscale-remote-enabled devices** — entitlement-flagged. NOT "ever observed
remote", NOT "concurrently remote". This was the central open question of the
2026-08-16 audit (§4.2) and it is now closed.

The reason it matters: entitlement is a deliberate act (issuing a key), whereas
observation is an inference from `connection_type`, whose fallback conflates
detection failure with a genuine remote answer and which is NULL on 7 of 13 live
rows. Metering against an untrustworthy observation would have produced confident
wrong answers in both directions.

Counting is reconciled against the live tailnet (`core/remote_census`), because
the database alone was measured to undercount — see that module.
"""

import os

__all__ = ["is_commercial", "get_tier", "remote_device_budget",
           "license_status", "FREE_TIER_REMOTE_CAP", "TIER_FREE", "TIER_COMMERCIAL"]

TIER_FREE = "free"
TIER_COMMERCIAL = "commercial"

#: Free-tier remote-device cap. FINAL — operator decision, 2026-08-17, closing the
#: "5 or 10" question open since 2026-08-16.
#:
#: Five REMOTE-enabled devices. Local devices are unlimited and are never counted
#: against this (see the principle above) -- a household can run as many locally
#: protected machines as it likes; the cap is only on how many may reach the
#: server over the VPN.
#:
#: Overridable via NEMESIS_FREE_REMOTE_CAP for testing only. It is deliberately
#: NOT a database setting: a value that decides entitlements must not be reachable
#: from an API write path, the same reasoning that keeps the agent auth mode in
#: the environment rather than in `settings`.
FREE_TIER_REMOTE_CAP = int(os.environ.get("NEMESIS_FREE_REMOTE_CAP", "5"))

#: Commercial is uncapped, contingent on the gateway being attached. "Gateway
#: attached" is not yet machine-evaluable (no gateway_mode flag exists anywhere —
#: 2026-08-16 audit §3.3), so commercial currently reports an unlimited budget
#: without evaluating that contingency. Flagged rather than faked.
COMMERCIAL_REMOTE_CAP = None   # None == unlimited


def _license_state(db_path=None):
    """(license_key, install_id, install_signals, install_conf, tier) or None."""
    import sqlite3
    if db_path is None:
        import nemesis_paths
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db_path = nemesis_paths.db_path(
            os.path.join(here, "alert_manager", "alerts.db"))
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    except Exception:
        return None
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(license_state)")]
        if not cols:
            return None
        row = conn.execute(
            "SELECT license_key, install_id, install_signals, install_conf, tier "
            "FROM license_state WHERE id = 1").fetchone()
        return tuple(row) if row else None
    except Exception:
        return None
    finally:
        conn.close()


def license_status(db_path=None):
    """Full licence picture: (tier, verdict, detail).

    The single place licence validity is decided. `is_commercial()` is a thin
    wrapper so existing call sites keep working unchanged.

    Order matters: the signature is checked FIRST, then the node-lock. A forged
    key must not be able to reach the hardware check at all, and a genuine key on
    changed hardware must be distinguishable from a fake one — the first calls
    for a backup code, the second for support.
    """
    from core import license_key as lk

    state = _license_state(db_path)
    if not state:
        return TIER_FREE, lk.Verdict.ABSENT, "no licence installed"

    key, install_id, signals, conf, _cached_tier = state
    res = lk.verify(key, install_id=None)      # signature/expiry first
    if not res.valid:
        return TIER_FREE, res.verdict, res.detail

    # Signature is good. Now: is this still the machine it was bound to?
    from core import install_id as iid
    bound = (res.payload.get("install_id") or "").strip()
    verdict, detail = iid.verify_install(bound or install_id, signals, conf)

    if verdict == iid.MATCH_OK:
        tier = res.payload.get("tier") or TIER_COMMERCIAL
        return tier, lk.Verdict.VALID, detail
    if verdict == iid.MATCH_LOW_CONFIDENCE:
        # Deliberately NOT enforced. Honouring the licence is the correct call
        # when the instrument is known to be unreliable — the alternative is
        # revoking a paying user's tier on evidence we have already labelled
        # untrustworthy.
        tier = res.payload.get("tier") or TIER_COMMERCIAL
        return tier, lk.Verdict.VALID, "node-lock not enforced: " + detail
    if verdict == iid.MATCH_UNAVAILABLE:
        # Cannot fingerprint right now. Same reasoning: absence of evidence is
        # not evidence of a mismatch. Honour the licence and say why.
        tier = res.payload.get("tier") or TIER_COMMERCIAL
        return tier, lk.Verdict.VALID, "node-lock unverified: " + detail

    # Genuine hardware mismatch -> degrade to free. NOT a stop.
    return TIER_FREE, lk.Verdict.WRONG_INSTALL, detail


def is_commercial() -> bool:
    """True if a valid commercial licence is active.

    Free tier, absent, expired and node-lock-mismatched licences all return
    False. Graceful downgrade only — never hard-lock a security product.
    """
    try:
        tier, _verdict, _detail = license_status()
    except Exception:
        # A broken licence subsystem must not take the product with it. Free
        # tier is the safe direction: full local protection, no commercial
        # features.
        return False
    return tier == TIER_COMMERCIAL


def get_tier() -> str:
    """Returns 'commercial' or 'free'."""
    return TIER_COMMERCIAL if is_commercial() else TIER_FREE


def remote_device_budget(db_path=None):
    """(used, limit, census) for the REMOTE-device cap.

    `limit` is None for unlimited (commercial). `used` is None when the census
    could not be reconciled — callers MUST treat that as "unknown", never as
    zero. The whole reason this returns a census object is so a caller cannot
    accidentally consume a number that was never established.

    LOCAL devices are not counted and are never capped.
    """
    from core import remote_census
    census = remote_census.take(db_path=db_path)
    limit = None if is_commercial() else FREE_TIER_REMOTE_CAP
    return census.count, limit, census
