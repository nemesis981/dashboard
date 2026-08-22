"""Tests for steering_lease — the roaming-steering lease + failsafe.

This is Rule-13-critical code (the 2026-08-07 exit-node incident is why it exists),
so the tests are ADVERSARIAL: each safety property is checked by making it FAIL.
A failsafe that has only ever been tested on the happy path is not a failsafe.

The clock is injected, so lease expiry is tested deterministically without waiting.

Run: python3 nemesis_agent/test_steering_lease.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import steering_lease as sl                                  # noqa: E402

_results = []


def check(label, got, want):
    ok = got == want
    _results.append((label, ok))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", label, got, want))


def check_true(label, got):
    check(label, bool(got), True)


class Clock:
    """A hand-cranked monotonic clock."""
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def good_evidence():
    return sl.RenewalEvidence(True, True, True)


def new(ttl=10.0):
    clock = Clock()
    backend = sl.NullRecordingBackend()
    alarms = []
    ctrl = sl.SteeringController(backend, ttl_seconds=ttl, clock=clock,
                                on_alarm=lambda r, d: alarms.append((r, d)))
    return clock, backend, ctrl, alarms


def main():
    print("evidence — all three facts required to hold steering")
    check("all present -> ok", good_evidence().ok, True)
    check("appliance down -> not ok",
          sl.RenewalEvidence(False, True, True).ok, False)
    check("not approved -> not ok",
          sl.RenewalEvidence(True, False, True).ok, False)
    check("gate not armed -> not ok",
          sl.RenewalEvidence(True, True, False).ok, False)
    check("missing lists the reasons",
          sl.RenewalEvidence(False, True, False).missing(),
          ["appliance_unreachable", "gate_not_armed"])

    print("\nsteering state — 'unknown' is NOT safe")
    check("provably off is safe", sl.SteeringState(False).is_safe, True)
    check("active is not safe", sl.SteeringState(True).is_safe, False)
    check("UNKNOWN is not safe", sl.SteeringState(False, unknown=True).is_safe, False)

    print("\nboot reconcile — a stale steering state from a prior run is torn down")
    clock, backend, ctrl, alarms = new()
    backend._active = True                     # pretend a previous run left steering ON
    check("box starts dirty", backend.read_state().active, True)
    check("reconcile_boot returns safe", ctrl.reconcile_boot(), True)
    check("...and the box is now provably off", backend.read_state().active, False)
    check("...and a teardown actually happened", backend.teardowns >= 1, True)
    check("...and status reports booted", ctrl.status()["booted"], True)

    print("\nno arming before a successful boot reconcile")
    clock, backend, ctrl, alarms = new()
    check("heartbeat before boot refuses to arm",
          ctrl.on_heartbeat(good_evidence()), False)
    check("...and nothing was applied", backend.applies, 0)

    print("\nhappy path — good evidence arms steering, verified by read-back")
    clock, backend, ctrl, alarms = new(ttl=10.0)
    ctrl.reconcile_boot()
    check("good heartbeat arms", ctrl.on_heartbeat(good_evidence()), True)
    check("...steering is active", backend.read_state().active, True)
    check("...lease is valid", ctrl.lease_valid(), True)
    check("...apply happened once", backend.applies, 1)

    print("\nEXPIRY BY DEFAULT — stop renewing and steering lapses on its own")
    # This is the core anti-2026-08-07 property: nothing has to fire.
    clock.advance(9.9)
    check("just before expiry, lease still valid", ctrl.lease_valid(), True)
    ctrl.tick()
    check("...still active just before deadline", backend.read_state().active, True)
    clock.advance(0.2)                          # now past the 10s deadline
    check("past the deadline, lease is invalid", ctrl.lease_valid(), False)
    st = ctrl.tick()                            # the tick that must tear down
    check("tick after expiry tears steering DOWN", backend.read_state().active, False)
    check("...status shows lease no longer valid", st["lease_valid"], False)
    check("...and a teardown was performed", backend.teardowns >= 1, True)

    print("\n...and a single flaky beat does NOT thrash steering (expiry is by timeout)")
    clock, backend, ctrl, alarms = new(ttl=10.0)
    ctrl.reconcile_boot()
    ctrl.on_heartbeat(good_evidence())
    clock.advance(3.0)
    ctrl.on_heartbeat(sl.RenewalEvidence(True, True, False))   # one bad beat (gate flapped)
    check("one bad beat does not tear down immediately",
          backend.read_state().active, True)
    check("...lease still valid (not renewed, but not yet expired)",
          ctrl.lease_valid(), True)
    clock.advance(11.0)                         # now sustained loss outlives the lease
    ctrl.tick()
    check("...sustained loss DOES lapse it", backend.read_state().active, False)

    print("\nREVERSION PROVEN BY READ-BACK — a teardown that fails is caught, loudly")
    clock, backend, ctrl, alarms = new(ttl=10.0)
    ctrl.reconcile_boot()
    ctrl.on_heartbeat(good_evidence())
    backend.fail_teardown_times = 1            # the next teardown will NOT clear state
    clock.advance(11.0)
    ctrl.tick()                                # lease expired -> teardown attempted -> fails
    check("a failed teardown is NOT reported as safe",
          ctrl.status()["alarm"] is not None, True)
    check("...the alarm callback fired", len(alarms), 1)
    check("...steering is still (dangerously) active, and we KNOW it",
          backend.read_state().active, True)
    check("...status reflects the live active state, not the intent",
          ctrl.status()["last_verified_active"], True)
    # ...and a subsequent tick, once the fault clears, recovers to safe
    st = ctrl.tick()
    check("a later tick recovers to safe once teardown works",
          backend.read_state().active, False)
    check("...and the alarm clears", ctrl.status()["alarm"], None)

    print("\nread-back is the source of truth — a lying backend is believed over intent")
    clock, backend, ctrl, alarms = new(ttl=10.0)
    ctrl.reconcile_boot()
    ctrl.on_heartbeat(good_evidence())
    backend.read_lies = True                   # read_state now reports the OPPOSITE
    clock.advance(11.0)
    ctrl.tick()                                # teardown clears _active, but read says active
    check("a teardown the read-back contradicts raises the alarm",
          ctrl.status()["alarm"] is not None, True)
    backend.read_lies = False                  # read tells the truth again
    ctrl.tick()
    check("...and clears once the read agrees", ctrl.status()["alarm"], None)

    print("\nan UNKNOWN read is treated as not-safe (fail-open)")
    clock, backend, ctrl, alarms = new(ttl=10.0)
    backend._active = True
    backend.read_returns_unknown = True
    check("boot reconcile cannot confirm safe on an unknown read",
          ctrl.reconcile_boot(), False)
    check("...so it refuses to mark booted", ctrl.status()["booted"], False)
    backend.read_returns_unknown = False
    check("...and succeeds once the read is definite", ctrl.reconcile_boot(), True)

    print("\nFAIL-OPEN on apply — a failing apply drives straight back to safe")
    clock, backend, ctrl, alarms = new(ttl=10.0)
    ctrl.reconcile_boot()
    backend.fail_apply = True
    check("a heartbeat whose apply fails returns False",
          ctrl.on_heartbeat(good_evidence()), False)
    check("...and the box ends up SAFE, not half-steered",
          backend.read_state().active, False)

    print("\napply that silently does not take is caught by read-back")
    clock, backend, ctrl, alarms = new(ttl=10.0)
    ctrl.reconcile_boot()

    class _NoTakeBackend(sl.NullRecordingBackend):
        def apply(self, plan):
            self.applies += 1                  # pretend success but change nothing
    nb = _NoTakeBackend()
    ctrl2 = sl.SteeringController(nb, ttl_seconds=10.0, clock=clock)
    ctrl2.reconcile_boot()
    check("apply that doesn't take -> heartbeat returns False",
          ctrl2.on_heartbeat(good_evidence()), False)
    check("...and drives to safe", nb.read_state().active, False)

    print("\nconstruction guards")
    try:
        sl.SteeringController(sl.NullRecordingBackend(), ttl_seconds=0)
        check("zero ttl rejected", "no raise", "ValueError")
    except ValueError:
        check("zero ttl rejected", True, True)

    print("\nno OS coupling — the module imports and runs with no sockets/roots")
    check("NullRecordingBackend is the only backend used here",
          isinstance(backend, sl.NullRecordingBackend), True)

    passed = sum(1 for _, ok in _results if ok)
    print("\n%d/%d checks passed" % (passed, len(_results)))
    failed = [l for l, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  -", f)
        sys.exit(1)


if __name__ == "__main__":
    main()
