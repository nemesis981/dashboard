"""Admin Approval Protocol v1 §9 — rate limiting, lockout, burst alerting.

IMPLEMENTS `docs/protocol/admin-approval-v1.md` §9 (ADR 0026 §H2). The spec is the
contract; this file is subordinate to it.

THE FOUR NORMATIVE REQUIREMENTS, and how each is met here:

  §9.1  Limiting applies to request CREATION, keyed by (user, capability). It MUST
        NOT apply to verifying an already-pending request.
        → `check_create()` is the only gate. There is deliberately NO function here
          that a verifier could call, so the mistake is not merely discouraged, it
          is unavailable. Throttling approval would hand an attacker a denial of
          admin capability -- the flood would lock out the very person trying to
          stop it.

  §9.2  Exceeding the burst threshold raises CRITICAL on a channel OTHER than the
        one being flooded.
        → `check_create()` returns the alert channel to use, chosen as "not the
          one carrying approvals". Alerting down the flooded channel is how a
          push-bombing defence becomes part of the push-bombing.

  §9.3  Lockout is time-bounded and console-clearable. A permanent lockout MUST NOT
        be implementable.
        → `MAX_LOCKOUT_SECONDS` is a hard ceiling applied to any configured value,
          asserted at import. `clear_lockout()` exists unconditionally. An
          unrecoverable admin lockout is a self-inflicted outage with no path back
          on an appliance whose console is the recovery mechanism.

  §9.4  Thresholds are configuration, not protocol -- explicit, never implicit.
        → All four live in `Thresholds`, passed in. No caller inherits a value by
          accident, and the defaults are stated in one place rather than scattered
          as literals.

STORAGE is injected rather than assumed. This module holds the POLICY; where counters
live is the caller's concern, which keeps the policy unit-testable without a database
and reimplementable against different storage in V3.
"""

import threading
import time

__all__ = ["Thresholds", "RateLimiter", "Decision", "MAX_LOCKOUT_SECONDS",
           "ALERT_CHANNEL_FOR"]

#: §9.3 — the hard ceiling on any lockout, in seconds. One hour.
#: A configured value above this is CLAMPED, not honoured: the spec says a permanent
#: lockout must not be implementable, and "implementable" includes "reachable by
#: misconfiguration", not merely "written as infinity in the source".
MAX_LOCKOUT_SECONDS = 3600

#: §9.2 — where a burst alert goes, given the channel being flooded. The rule is
#: simply "not that one"; the mapping is explicit so the choice is reviewable
#: rather than buried in a conditional.
ALERT_CHANNEL_FOR = {
    "push": "email",
    "email": "push",
    "sms": "email",
    None: "email",
}


class Thresholds:
    """§9.4 — explicit configuration. Every value must be passed or defaulted HERE."""

    __slots__ = ("burst_count", "burst_window_s", "lockout_s", "sustained_per_hour")

    def __init__(self, burst_count=5, burst_window_s=60, lockout_s=900,
                 sustained_per_hour=20):
        if burst_count < 1:
            raise ValueError("burst_count must be >= 1")
        if burst_window_s < 1:
            raise ValueError("burst_window_s must be >= 1")
        if lockout_s < 1:
            raise ValueError("lockout_s must be >= 1 (a zero lockout is not a lockout)")
        self.burst_count = burst_count
        self.burst_window_s = burst_window_s
        # §9.3 clamp. Applied at CONSTRUCTION so an over-large configured value can
        # never reach the enforcement path at all.
        self.lockout_s = min(lockout_s, MAX_LOCKOUT_SECONDS)
        self.sustained_per_hour = sustained_per_hour


class Decision:
    """Outcome of a creation check. Never a bare boolean -- same discipline as §8."""

    __slots__ = ("allowed", "reason", "retry_after_s", "alert", "alert_channel",
                 "detail")

    def __init__(self, allowed, reason=None, retry_after_s=0, alert=False,
                 alert_channel=None, detail=""):
        self.allowed = allowed
        self.reason = reason
        self.retry_after_s = retry_after_s
        self.alert = alert
        self.alert_channel = alert_channel
        self.detail = detail

    def __repr__(self):
        return ("Decision(allowed=%r, reason=%r, retry_after=%ss, alert=%r via %r)"
                % (self.allowed, self.reason, self.retry_after_s, self.alert,
                   self.alert_channel))


class RateLimiter:
    """§9 policy. In-memory by default; inject `store` for cross-process state.

    NOTE ON SCOPE, stated rather than assumed: the default store is per-process.
    On an appliance where approval requests are created from one dashboard process
    that is correct and sufficient. If creation ever becomes reachable from a
    second process, this must be given a shared store or the limit silently
    becomes per-process -- which is a weaker guarantee wearing the same name.
    """

    def __init__(self, thresholds=None, clock=time.time):
        self.t = thresholds or Thresholds()
        self._clock = clock
        self._events = {}        # (user, capability) -> [timestamps]
        self._locked_until = {}  # (user, capability) -> timestamp
        self._alerted_for = {}   # (user, capability) -> lockout stamp already alerted
        self._lock = threading.Lock()

    # ── §9.1: the ONLY gate, and it is on creation ──────────────────────────
    def check_create(self, user_id, capability, *, flooded_channel="push"):
        """May this user create another approval request for this capability?"""
        now = self._clock()
        key = (user_id, capability)
        with self._lock:
            until = self._locked_until.get(key, 0)
            if now < until:
                return Decision(
                    False, reason="AAP-013", retry_after_s=int(until - now),
                    detail="locked out until %d" % int(until))

            window_start = now - self.t.burst_window_s
            events = [t for t in self._events.get(key, ()) if t >= window_start]
            events.append(now)
            self._events[key] = events

            if len(events) > self.t.burst_count:
                lock_until = now + self.t.lockout_s
                self._locked_until[key] = lock_until
                # §9.2 — alert ONCE per lockout, not once per blocked attempt. An
                # alert channel that is itself flooded by the flood defence is not
                # a defence, and a CRITICAL that arrives 200 times is noise that
                # gets muted, which is worse than one that arrives once.
                first_time = self._alerted_for.get(key) != lock_until
                self._alerted_for[key] = lock_until
                return Decision(
                    False, reason="AAP-013",
                    retry_after_s=int(self.t.lockout_s),
                    alert=first_time,
                    alert_channel=ALERT_CHANNEL_FOR.get(flooded_channel, "email"),
                    detail="burst threshold exceeded: %d requests in %ds"
                           % (len(events), self.t.burst_window_s))
            return Decision(True)

    # ── §9.3: always available, by construction ─────────────────────────────
    def clear_lockout(self, user_id, capability):
        """Clear a lockout from the appliance console. Always available.

        There is no flag that disables this and no state from which it cannot be
        called -- that is what makes a permanent lockout unimplementable rather
        than merely undesirable.
        """
        key = (user_id, capability)
        with self._lock:
            had = key in self._locked_until
            self._locked_until.pop(key, None)
            self._events.pop(key, None)
            self._alerted_for.pop(key, None)
        return had

    def is_locked(self, user_id, capability):
        with self._lock:
            return self._clock() < self._locked_until.get((user_id, capability), 0)


# §9.3, asserted at import rather than trusted: no configuration can produce a
# lockout longer than the ceiling.
assert Thresholds(lockout_s=10 ** 9).lockout_s == MAX_LOCKOUT_SECONDS, \
    "lockout clamp is not being applied (spec §9.3)"
