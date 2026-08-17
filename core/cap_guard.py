"""Remote-device cap admission: may this install grant ONE more remote device?

The enforcement half of the licensing work. `core/remote_census` establishes how
many remote slots are in use; this decides what to do about it.

── WHAT IS BEING REFUSED, AND WHAT NEVER IS ────────────────────────────────
Refusal withholds **remote reach**: a tailnet pre-auth key, and the
`remote_enabled` entitlement that goes with it. It never withholds protection.
A device refused here still installs the full agent and gets full local security
— it simply cannot reach the server over the VPN. Local devices are unlimited
under all conditions and are never counted.

That distinction is what keeps this inside `entitlements.py`'s standing
instruction — *"graceful downgrade only: never hard-lock a security product
behind a paywall"* — rather than in violation of it. If a future change would
refuse something detection-related here, the instruction is being broken and the
change is wrong.

── ⚠ THE FAIL-OPEN DECISION, AND WHY IT IS NOW CONDITIONAL ─────────────────
When the census cannot be reconciled, the response depends on WHY — a
distinction added 2026-08-17 after the unconditional version was found to be a
one-step bypass (disconnect the box; the census can never reconcile; every grant
sails through unverified).

  | census     | internet reachable | decision                 |
  |------------|--------------------|--------------------------|
  | reconciled | —                  | ALLOW / REFUSE by count  |
  | degraded   | ONLINE             | ALLOW_UNVERIFIED         |
  | degraded   | OFFLINE            | REFUSE_NO_CONNECTIVITY   |
  | degraded   | INCONCLUSIVE       | ALLOW_UNVERIFIED, escalated |

**Fail-open on ONLINE** — the original reasoning, unchanged. Refusing on
infrastructure failure punishes the user for the vendor's outage: a Tailscale API
blip would block every enrollment on every install at once, which is DRM
behaviour and worse than a briefly over-run cap. An over-count is recoverable; a
fleet that cannot enroll is an incident.

**Refuse on OFFLINE** — and this costs the user almost nothing, which is what
makes it defensible rather than punitive: with no internet the tailnet has no
coordination server, so a remote device could not reach this box even if the
grant were issued. Withholding it withholds something unusable. Local installer
generation is unaffected under all conditions.

**Fail-open on INCONCLUSIVE** — refusing when the CHECKER is broken would let a
broken checker deny service and make reachability probing a licensing dependency.

This check has known limitations and is not intended to be airtight against a
determined local adversary. Full detail is tracked separately (Rule 10 — see
the private mirror) for eventual inclusion in commercial documentation, rather
than spelled out here.
"""

import logging

__all__ = ["Decision", "check_admission", "ALLOW", "REFUSE", "ALLOW_UNVERIFIED",
           "REFUSE_NO_CONNECTIVITY", "PERMITTING_STATES", "ALL_STATES"]

log = logging.getLogger("nemesis.cap_guard")

ALLOW = "allow"
REFUSE = "refuse"
ALLOW_UNVERIFIED = "allow_unverified"
#: The census could not be reconciled AND this box has no internet at all --
#: which is indistinguishable from someone disconnecting it to defeat the cap.
#: Distinct from REFUSE because the cause and the remedy are completely
#: different: one means "you are at your limit", this means "reconnect".
REFUSE_NO_CONNECTIVITY = "refuse_no_connectivity"

#: The ONLY states that permit a grant. Everything else refuses.
#: Enumerated explicitly, and asserted by a backstop test, so that adding a new
#: state cannot accidentally default to permitting.
PERMITTING_STATES = (ALLOW, ALLOW_UNVERIFIED)
ALL_STATES = (ALLOW, REFUSE, ALLOW_UNVERIFIED, REFUSE_NO_CONNECTIVITY)


class Decision:
    """A cap decision. `permitted` is the only thing callers should branch on.

    Deliberately not a boolean: ALLOW and ALLOW_UNVERIFIED both permit, but only
    one of them was actually measured, and the caller must be able to record
    which — otherwise an unverified grant is indistinguishable from a verified
    one the moment it is written to the database.
    """

    __slots__ = ("state", "used", "limit", "reason", "census")

    def __init__(self, state, used=None, limit=None, reason="", census=None):
        self.state = state
        self.used = used
        self.limit = limit
        self.reason = reason
        self.census = census

    @property
    def permitted(self):
        return self.state in PERMITTING_STATES

    @property
    def verified(self):
        return self.state == ALLOW

    @property
    def remaining(self):
        if self.limit is None:
            return None                      # unlimited
        if self.used is None:
            return None                      # unknown
        return max(0, self.limit - self.used)

    def user_message(self):
        """What the operator should read. Never a bare number.

        ⚠ EVERY refusing state needs its own branch BEFORE the trailing
        "granted" text. Without this one, REFUSE_NO_CONNECTIVITY fell through to
        "Remote access granted. N of M slots in use." — a refusal rendering as a
        grant, which is worse than no message at all. The backstop test asserts
        no state produces a message contradicting its own decision.
        """
        if self.state == REFUSE_NO_CONNECTIVITY:
            return ("This server currently has no internet connection, so the "
                    "number of remote devices in use cannot be checked — and a "
                    "remote device would not be able to reach it anyway. The "
                    "device can still be installed now and will get full local "
                    "protection. Reconnect this server, then re-issue the "
                    "installer to add it as a remote device.")
        if self.state == REFUSE:
            return ("This installation has used all %d of its remote-device "
                    "slots. The device can still be installed and will get full "
                    "local protection — it just will not be able to reach "
                    "Nemesis over the VPN. To add it remotely, revoke a device "
                    "you no longer use, or upgrade your licence."
                    % (self.limit if self.limit is not None else 0))
        if self.state == ALLOW_UNVERIFIED:
            return ("Remote access granted, but the remote-device count could "
                    "not be checked: %s. Review your remote devices when "
                    "convenient." % self.reason)
        if self.limit is None:
            return "Remote access granted (unlimited remote devices)."
        return ("Remote access granted. %d of %d remote slots in use."
                % ((self.used or 0) + 1, self.limit))

    def as_dict(self):
        return {"state": self.state, "permitted": self.permitted,
                "verified": self.verified, "used": self.used,
                "limit": self.limit, "remaining": self.remaining,
                "reason": self.reason, "message": self.user_message()}

    def __repr__(self):
        return "Decision(%s, used=%r, limit=%r)" % (self.state, self.used, self.limit)


def check_admission(db_path=None, additional=1):
    """May this install grant `additional` more remote device(s)?

    Called at BOTH enforcement seams — generating a remote-capable installer and
    minting the key at download — because a token created while under the cap can
    be downloaded after it fills. Checking only at generation would leave a hole
    exactly the width of the gap between the two.
    """
    from core import entitlements as ent
    from core import remote_census

    try:
        limit = ent.remote_cap_for_license(db_path)
    except Exception as e:
        log.exception("cap guard: could not read the licence")
        return Decision(ALLOW_UNVERIFIED, reason="licence unreadable: %s" % str(e)[:120])

    if limit is None:
        # Unlimited. No census needed -- do not make an API call to answer a
        # question whose answer cannot change.
        return Decision(ALLOW, used=None, limit=None,
                        reason="unlimited remote devices")

    try:
        census = remote_census.take(db_path=db_path)
    except Exception as e:
        log.exception("cap guard: census raised")
        return Decision(ALLOW_UNVERIFIED, limit=limit,
                        reason="census failed: %s" % str(e)[:120])

    if not census.reconciled or census.count is None:
        # ── The census failed. WHY it failed decides what happens next. ───────
        #
        # Before 2026-08-17 this fell straight through to ALLOW_UNVERIFIED, which
        # treated "Tailscale's API is down" and "this box has no internet"
        # identically -- so disconnecting the box was a one-step way to enroll
        # unlimited remote devices with the census permanently unable to check.
        return _degraded_decision(limit, census, db_path)

    if census.count + additional > limit:
        log.info("cap guard: REFUSED remote grant — %d/%d slots in use",
                 census.count, limit)
        return Decision(REFUSE, used=census.count, limit=limit,
                        reason="remote-device cap reached", census=census)

    return Decision(ALLOW, used=census.count, limit=limit,
                    reason=census.reason, census=census)


def _degraded_decision(limit, census, db_path=None):
    """The census could not reconcile. Is the internet reachable at all?

    ONLINE       -> vendor outage. ALLOW_UNVERIFIED, as before.
    OFFLINE      -> REFUSE_NO_CONNECTIVITY.
    INCONCLUSIVE -> ALLOW_UNVERIFIED, escalated.

    ── WHY REFUSING WHILE OFFLINE COSTS THE USER (ALMOST) NOTHING ────────────
    If the box has no internet, a remote device cannot reach it anyway -- the
    tailnet needs its coordination server. So withholding a REMOTE grant while
    offline withholds something that could not be used even if granted. That is
    materially different from refusing during a vendor outage, where existing
    peers may still carry traffic and the grant has real value.

    LOCAL installer generation is never affected. Local protection stays
    available under all conditions (operator decision, 2026-08-17) -- that is
    what keeps this inside entitlements.py's "graceful downgrade only".
    """
    from core import net_reachability as nr

    try:
        reach = nr.verdict()
    except Exception as e:
        log.exception("cap guard: reachability probe raised")
        reach = nr.Reach(nr.INCONCLUSIVE, "probe raised: %s" % str(e)[:100])

    corro = None
    try:
        corro = nr.diagnostics_corroboration(db_path=db_path)
    except Exception:
        log.debug("cap guard: diagnostics corroboration unavailable", exc_info=True)

    state, detail = reach.state, reach.detail
    if corro:
        c_state, c_detail = corro
        if c_state == state:
            detail = "%s; diagnostics agrees (%s)" % (detail, c_detail)
        elif state == nr.ONLINE and c_state == nr.OFFLINE:
            # Live probe says reachable, the 60s cache says not. Do NOT resolve
            # this silently either way -- disagreement is itself the signal.
            state = nr.INCONCLUSIVE
            detail = ("live probe and diagnostics disagree (%s vs %s)"
                      % (detail, c_detail))
        elif state == nr.OFFLINE and c_state == nr.ONLINE:
            # A LIVE measurement beats a cached one. This is the frozen-cache
            # bypass: stop the watcher on a green verdict, then disconnect.
            detail = ("%s; diagnostics still reports reachable (%s) — trusting "
                      "the live probe" % (detail, c_detail))

    if state == nr.OFFLINE:
        log.error("cap guard: REFUSING remote grant — this box has no internet "
                  "connectivity, so the count cannot be verified AND a remote "
                  "device could not reach it anyway (%s)", detail)
        return Decision(REFUSE_NO_CONNECTIVITY, used=None, limit=limit,
                        reason=detail, census=census)

    if state == nr.INCONCLUSIVE:
        # Permits, deliberately: refusing when the CHECKER is broken would let a
        # broken checker deny service, and would make reachability probing a
        # licensing dependency. Recorded far more loudly than a routine grant.
        log.error("cap guard: granting remote access UNVERIFIED and could not "
                  "establish internet reachability either (limit=%s) — census: %s "
                  "— reachability: %s", limit, census.reason, detail)
        return Decision(ALLOW_UNVERIFIED, used=None, limit=limit,
                        reason="%s; reachability inconclusive: %s"
                               % (census.reason, detail), census=census)

    # ONLINE: the original, approved case-1 behaviour, unchanged.
    log.warning("cap guard: granting remote access WITHOUT a verified count "
                "(limit=%s) — %s (internet reachable: %s)",
                limit, census.reason, detail)
    return Decision(ALLOW_UNVERIFIED, used=None, limit=limit,
                    reason=census.reason, census=census)
