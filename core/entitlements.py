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
           "license_status", "FREE_TIER_REMOTE_CAP", "MAX_REMOTE_CAP_BONUS",
           "TIER_FREE", "TIER_COMMERCIAL"]

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
#: It is deliberately NOT a database setting: a value that decides entitlements
#: must not be reachable from an API write path.
#:
#: ⚠ NOT ENVIRONMENT-OVERRIDABLE EITHER (fixed 2026-08-23). This used to read
#: `os.environ.get("NEMESIS_FREE_REMOTE_CAP", "5")` with a comment saying "for
#: testing only" -- but a comment is a convention, not a control. Proven:
#: NEMESIS_FREE_REMOTE_CAP=999999 raised the cap to 999999.
#:
#: The original reasoning was exactly right and simply did not go far enough: a
#: value that decides entitlements must not be reachable from an API write path
#: OR from the process environment. Both are inputs the person being metered
#: controls. TESTS monkeypatch this module attribute.
FREE_TIER_REMOTE_CAP = 5

#: Ceiling on PURCHASED free-tier capacity (`remote_cap_bonus`, see
#: `_purchased_bonus`). The signature is trusted, so this does not defend against a
#: forged key -- it defends against an ISSUER BUG. Without a ceiling, one malformed
#: value in a variant map or a stray zero in an accumulation could hand a free
#: install effectively-unlimited capacity, and nothing downstream would question it.
#: Deliberately generous: 100 five-device packs on one install is far past any real
#: purchase, so a value above it is evidence of a mistake rather than a big customer.
MAX_REMOTE_CAP_BONUS = 500

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


def _purchased_bonus(db_path=None):
    """Extra remote-device capacity BOUGHT for a free-tier install. 0 if none.

    Read only from a signature-verified payload. `remote_cap_bonus` is a DELTA, not
    an absolute: the issuer cannot know this build's FREE_TIER_REMOTE_CAP, so signing
    an absolute would mean guessing that constant across a version boundary it cannot
    observe — and a later change to the free base would then silently shrink what
    existing pack holders had already bought. The issuer signs what was PURCHASED;
    the client adds its own current base.

    Validation is deliberately STRICTER than the commercial `remote_cap` path below,
    which accepts anything `int()` swallows. Here a float, a numeric string, or a
    bool is refused outright rather than coerced: those are signs of a malformed
    issuance, and silently rounding one into an entitlement is how a wrong number
    becomes a granted one. Every rejection returns 0 — the NARROWER answer — so a
    corrupted value can only ever cost capacity, never create it.
    """
    state = _license_state(db_path)
    if not state:
        return 0

    from core import license_key as lk
    res = lk.verify(state[0], install_id=None)
    if not res.valid:
        # An unverified payload contributes nothing. This is the whole entitlement:
        # if a bonus could be read from an unsigned or edited key, anyone could mint
        # themselves capacity by editing the licence row.
        return 0

    raw = res.payload.get("remote_cap_bonus")
    if raw is None:
        return 0
    if isinstance(raw, bool) or not isinstance(raw, int):
        return 0
    if raw <= 0 or raw > MAX_REMOTE_CAP_BONUS:
        return 0
    return raw


def remote_cap_for_license(db_path=None):
    """The cap this install is entitled to. None means unlimited.

    Precedence, and the first rule is the one that matters:

      1. A `remote_cap` in the SIGNED licence payload wins for a COMMERCIAL licence.
         The issuing tool can set it (`nemesis-license-issue --remote-cap N`), and
         because it is inside the signature it cannot be edited by the holder.
         Ignoring it would mean a value the vendor deliberately signed had no effect
         — issuing a 25-device licence and silently granting unlimited instead.
      2. Otherwise a valid commercial licence is unlimited.
      3. Otherwise the free-tier cap, PLUS any purchased `remote_cap_bonus`.

    Anything unparseable or nonsensical falls through to the narrower entitlement
    rather than to unlimited: a corrupted number must not widen an entitlement.

    ⚠ Rule 1 is commercial-only, and used to be written as though it applied to any
    signed payload. It did not: this function returned the hardcoded free cap before
    ever reading the payload, so a signed cap on a FREE licence was silently ignored
    (fixed 2026-09-04, having made the key pack impossible — a bought pack was
    indistinguishable from not buying one, with no error anywhere). `remote_cap` is
    still commercial-only by design; free-tier capacity is bought via
    `remote_cap_bonus`, which is additive and cannot be used to grant unlimited.
    """
    tier, verdict, _detail = license_status(db_path)
    if tier != TIER_COMMERCIAL:
        return FREE_TIER_REMOTE_CAP + _purchased_bonus(db_path)

    state = _license_state(db_path)
    if state:
        from core import license_key as lk
        res = lk.verify(state[0], install_id=None)
        if res.valid:
            raw = res.payload.get("remote_cap")
            if raw is not None:
                try:
                    n = int(raw)
                    if n > 0:
                        return n
                except (TypeError, ValueError):
                    pass
                # Present but unusable. Fail toward the NARROWER entitlement.
                return FREE_TIER_REMOTE_CAP
    return COMMERCIAL_REMOTE_CAP


def remote_device_budget(db_path=None):
    """(used, limit, census) for the REMOTE-device cap.

    `limit` is None for unlimited. `used` is None when the census could not be
    reconciled — callers MUST treat that as "unknown", never as zero. The whole
    reason this returns a census object is so a caller cannot accidentally
    consume a number that was never established.

    LOCAL devices are not counted and are never capped.
    """
    from core import remote_census
    census = remote_census.take(db_path=db_path)
    return census.count, remote_cap_for_license(db_path), census
