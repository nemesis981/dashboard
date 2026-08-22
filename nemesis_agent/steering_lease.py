#!/usr/bin/env python3
"""Roaming traffic-steering LEASE + FAILSAFE — the safety machinery, with NO
steering actually attached yet.

WHAT THIS IS. The part of tunnel-back-when-roaming (design 2026-08-20 §5) that has
to be bulletproof before a single packet is ever steered: the mechanism that
decides whether steering may be active, tears it down the instant it may not, and
PROVES the teardown happened by reading live state back. Steering itself -- the
WFP/nftables packet path -- is deliberately NOT here. A `SteeringBackend` is an
abstract seam; the only backend in this file records intent in memory so the lease
logic, the boot reconciliation, and the read-back verification can be proven
alone. The real backends plug into the same seam later and inherit this safety
machinery unchanged.

WHY IT EXISTS, AND WHY IT IS BUILT FIRST. The 2026-08-07 incident: a self-reverting
exit-node test whose `trap ... EXIT` never fired, leaving the operator routed
through a test VM for ~3 days. Rule 13 is the response. Every property below is a
direct answer to that failure:

  * **The lease EXPIRES BY DEFAULT.** Steering is held only while something keeps
    renewing the lease with fresh evidence. Stop renewing -- crash, lost comms,
    a killed agent, a hung loop -- and the lease lapses and steering is torn down.
    Nothing has to FIRE for the safe state to be reached; the safe state is what
    happens when nothing happens. That is the exact inverse of a trap that must run.

  * **Boot RECONCILES to safe before anything else.** On every start the controller
    tears down and verifies safe BEFORE it will grant a lease, so a steering state
    left over from a previous run (or a crash, or a reboot) is never inherited --
    which is precisely how the exit-node pref survived a reboot and broke the box.

  * **Reversion is PROVEN by reading live state back, never assumed.** Every
    teardown is followed by `read_state()`, and if that does not confirm the safe
    state the controller raises an ALARM and refuses to report safe. A teardown
    that "returned without error" is not evidence; the read-back is.

  * **FAIL-OPEN only.** Any error, exception, or ambiguity drives toward the safe
    (direct-traffic) state, never toward keeping steering up.

No OS calls, no sockets, no clock reads except through an injectable `clock` -- so
every one of the properties above is tested deterministically, including the
adversarial cases (a teardown that fails, a boot that inherits stale state, a
backend whose read-back disagrees with what it was told).
"""
import logging
import time

log = logging.getLogger("nemesis_agent.steering_lease")


# ── what "is steering on?" looks like, and what renews the lease ─────────────

class SteeringState:
    """The answer read_state() gives: is steering ACTIVE on this box right now.

    `active` is the load-bearing field and it is what the controller trusts --
    never what it asked the backend to do. `detail` is human context for logs.
    `unknown` marks a read that could not determine the truth: it is treated as
    NOT-safe (fail-open), because "I could not tell" must never pass for "safe".
    """

    __slots__ = ("active", "detail", "unknown")

    def __init__(self, active, detail="", unknown=False):
        self.active = bool(active)
        self.detail = detail
        self.unknown = bool(unknown)

    @property
    def is_safe(self):
        # Safe == provably not active. An unknown read is NOT safe.
        return (not self.unknown) and (not self.active)

    def __repr__(self):
        if self.unknown:
            return "SteeringState(UNKNOWN, %r)" % self.detail
        return "SteeringState(active=%s, %r)" % (self.active, self.detail)


class RenewalEvidence:
    """The facts that justify HOLDING steering for another lease period (§5.2).

    All three must hold, every renewal. Missing any one -- appliance unreachable,
    device not approved, the inspection gate not armed -- means we are not entitled
    to steer, so the lease is simply not renewed and lapses on its own.
    """

    __slots__ = ("appliance_reachable", "device_approved", "gate_armed", "detail")

    def __init__(self, appliance_reachable, device_approved, gate_armed, detail=""):
        self.appliance_reachable = bool(appliance_reachable)
        self.device_approved = bool(device_approved)
        self.gate_armed = bool(gate_armed)
        self.detail = detail

    @property
    def ok(self):
        return (self.appliance_reachable and self.device_approved and self.gate_armed)

    def missing(self):
        out = []
        if not self.appliance_reachable:
            out.append("appliance_unreachable")
        if not self.device_approved:
            out.append("device_not_approved")
        if not self.gate_armed:
            out.append("gate_not_armed")
        return out


# ── the steering seam (real WFP/nft backends plug in here later) ─────────────

class SteeringBackend:
    """Abstract. A real backend applies/removes the packet path and, crucially,
    reads the LIVE system state back (WFP filter enumeration / `nft list ruleset`
    / handle state). Every method may raise; the controller treats a raise as a
    reason to fail toward safe."""

    def apply(self, plan):
        raise NotImplementedError

    def teardown(self):
        raise NotImplementedError

    def read_state(self):
        raise NotImplementedError


class NullRecordingBackend(SteeringBackend):
    """The skeleton's only backend: it steers NOTHING, it just records intent in
    memory and reports it back, so the lease + failsafe logic can be proven with
    no OS involvement.

    It also carries deliberate FAULT INJECTION -- fail the next teardown, fail the
    next apply, or make read_state lie -- because the safety properties are only
    real if the tests can make them fail. A read-back verifier that has never seen
    a failed teardown is not evidence it would catch one.
    """

    def __init__(self):
        self._active = False           # the "live system state" this box models
        self.applies = 0
        self.teardowns = 0
        # fault injection knobs (all off by default)
        self.fail_apply = False
        self.fail_teardown_times = 0   # fail teardown this many times, then work
        self.read_returns_unknown = False
        self.read_lies = False         # read_state reports the OPPOSITE of reality

    def apply(self, plan):
        self.applies += 1
        if self.fail_apply:
            raise RuntimeError("injected apply failure")
        self._active = True

    def teardown(self):
        self.teardowns += 1
        if self.fail_teardown_times > 0:
            self.fail_teardown_times -= 1
            raise RuntimeError("injected teardown failure")
        self._active = False

    def read_state(self):
        if self.read_returns_unknown:
            return SteeringState(False, "injected unknown", unknown=True)
        active = (not self._active) if self.read_lies else self._active
        return SteeringState(active, "recording backend")


# ── the controller: holds the lease, enforces the failsafe ───────────────────

class SteeringController:
    """Owns the lease and the failsafe. Feed it heartbeat evidence and periodic
    ticks; it keeps steering active ONLY while the lease is valid, and drives to
    the proven-safe state the moment it is not.

    Threading: not internally locked. The agent drives it from ONE place (the poll
    loop), the same single-writer discipline the rest of the agent uses. If a second
    caller is ever added, it needs a lock -- called out here so that is a decision,
    not an accident.
    """

    def __init__(self, backend, ttl_seconds, clock=time.monotonic, on_alarm=None):
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._backend = backend
        self._ttl = float(ttl_seconds)
        self._clock = clock
        self._on_alarm = on_alarm or (lambda reason, detail: None)
        self._lease_expires_at = None   # monotonic deadline; None == no lease
        self._booted = False            # reconcile_boot() has run and confirmed safe
        self._last_verified = None      # last read_state() result
        self._alarm = None              # set when a teardown could not be proven safe

    # ── the failsafe primitives, each ending in a READ-BACK ──────────────────

    def _verify_safe(self):
        """Read live state and return True only if it PROVES steering is off.

        The read itself may raise; a raise is treated as not-safe (fail-open),
        because a read we could not complete tells us nothing and must not be
        allowed to look like a clean result."""
        try:
            state = self._backend.read_state()
        except Exception as exc:                             # noqa: BLE001
            log.error("read_state raised during safe-verify: %s", exc)
            self._last_verified = SteeringState(True, "read failed: %s" % exc,
                                                unknown=True)
            return False
        self._last_verified = state
        return state.is_safe

    def _drive_safe(self, reason):
        """Tear down and PROVE safe by read-back. Idempotent, and loud on failure.

        Returns True only when the read-back confirms the safe state. If teardown
        or its verification fails, raises the alarm and returns False -- and the
        controller will NOT report itself safe until a later attempt succeeds. This
        is the anti-2026-08-07 core: a teardown is not done because it was called,
        it is done because the box was read and found clean.
        """
        try:
            self._backend.teardown()
        except Exception as exc:                             # noqa: BLE001
            log.error("teardown raised (%s): %s -- will re-verify and retry",
                      reason, exc)
        if self._verify_safe():
            if self._alarm is not None:
                log.warning("steering safe-state recovered (%s)", reason)
            self._alarm = None
            self._lease_expires_at = None
            return True
        # Teardown did not prove safe. This is the dangerous case; make it loud.
        self._alarm = "teardown_unverified:%s" % reason
        log.critical("STEERING TEARDOWN NOT PROVEN SAFE (%s): live state=%r",
                     reason, self._last_verified)
        self._on_alarm(self._alarm, self._last_verified)
        return False

    def _drive_applied(self, plan):
        """Apply steering, then confirm active by read-back. Fail-open: if apply
        or its verification fails, drive straight back to safe."""
        try:
            self._backend.apply(plan)
        except Exception as exc:                             # noqa: BLE001
            log.error("apply raised: %s -- failing back to safe", exc)
            self._drive_safe("apply_failed")
            return False
        try:
            state = self._backend.read_state()
        except Exception as exc:                             # noqa: BLE001
            log.error("read_state raised after apply: %s -- failing back to safe", exc)
            self._drive_safe("apply_verify_failed")
            return False
        self._last_verified = state
        if not state.active:
            log.error("apply did not take (read-back not active) -- failing to safe")
            self._drive_safe("apply_did_not_take")
            return False
        return True

    # ── boot reconciliation (§5.3) ───────────────────────────────────────────

    def reconcile_boot(self):
        """Run once at agent start, BEFORE any lease may be granted.

        Unconditionally drives to safe and verifies it, so nothing steering-wise
        is ever inherited from a previous run. Until this succeeds, grant requests
        are refused. Returns True iff the box is proven safe.
        """
        ok = self._drive_safe("boot_reconcile")
        self._booted = ok
        if ok:
            log.info("boot reconcile: steering confirmed OFF")
        else:
            log.critical("boot reconcile could NOT confirm steering off -- "
                         "refusing to arm; live state=%r", self._last_verified)
        return ok

    # ── the two hooks the agent drives ───────────────────────────────────────

    def on_heartbeat(self, evidence, plan=None, now=None):
        """Renew (and, if entitled, apply) or let the lease stand to lapse.

        Called on every heartbeat with the current RenewalEvidence. Good evidence
        renews the lease and ensures steering is applied; bad or partial evidence
        does NOT renew -- the lease keeps counting down and `tick()` will expire it.
        This is deliberately not a teardown-on-bad-evidence: expiry-by-timeout is
        the mechanism, so a single flaky beat does not thrash steering, but a
        sustained loss reliably lapses it.
        """
        now = self._clock() if now is None else now
        if not self._booted:
            # Never arm before boot reconciliation has proven a clean slate.
            log.warning("heartbeat before successful boot reconcile -- not arming")
            return False
        if not evidence.ok:
            log.info("heartbeat: not renewing steering lease (%s)",
                     ",".join(evidence.missing()))
            return False
        self._lease_expires_at = now + self._ttl
        state = self._safe_read()
        if state is not None and not state.active:
            return self._drive_applied(plan)
        return True

    def tick(self, now=None):
        """Periodic check. Expires the lease and tears steering down the instant
        the lease is no longer valid. Safe to call as often as the loop likes."""
        now = self._clock() if now is None else now
        if not self.lease_valid(now):
            if self._lease_expires_at is not None or self._maybe_active():
                self._drive_safe("lease_expired")
        return self.status(now)

    # ── helpers ──────────────────────────────────────────────────────────────

    def lease_valid(self, now=None):
        now = self._clock() if now is None else now
        return self._lease_expires_at is not None and now < self._lease_expires_at

    def _safe_read(self):
        try:
            state = self._backend.read_state()
            self._last_verified = state
            return state
        except Exception as exc:                             # noqa: BLE001
            log.error("read_state raised: %s", exc)
            return None

    def _maybe_active(self):
        """Best-effort 'might steering be active?' for deciding whether tick must
        act. Errs toward True (act) so a lapsed lease always triggers a teardown+
        verify even if the last read is stale or unknown."""
        st = self._last_verified
        if st is None:
            return True
        return st.active or st.unknown

    def status(self, now=None):
        now = self._clock() if now is None else now
        remaining = None
        if self._lease_expires_at is not None:
            remaining = max(0.0, self._lease_expires_at - now)
        return {
            "booted": self._booted,
            "lease_valid": self.lease_valid(now),
            "lease_remaining_s": remaining,
            "alarm": self._alarm,
            "last_verified_active": None if self._last_verified is None
            else self._last_verified.active,
            "last_verified_unknown": None if self._last_verified is None
            else self._last_verified.unknown,
        }
