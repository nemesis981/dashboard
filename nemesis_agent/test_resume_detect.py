#!/usr/bin/env python3
"""Resume awareness: after a suspend, beat promptly instead of waiting out the interval.

⛔ THE GAP THIS CLOSES. The agent has no suspend/resume awareness at all. Its
scheduled task is `/SC ONLOGON`, which a resume does not re-trigger, and the
process survives suspend anyway — so on waking it silently resumes its timer. The
device is then RUNNING AND UNVERIFIED for up to a full poll interval (300s
default): network back, user active, no check-in, no attestation.

That window is the only genuinely exposed part of a suspend. During suspend
itself nothing executes, so "unmonitored" is not "unprotected"; on resume it is.

⛔ WHY WALL-CLOCK AND NOT monotonic. `_interruptible_sleep`'s deadline is
`time.monotonic()`, and monotonic's behaviour across suspend is PLATFORM-SPECIFIC:
Linux CLOCK_MONOTONIC excludes suspended time (so the agent waits out the
remainder AFTER waking — the bad case), while Windows GetTickCount64 includes it.
Wall-clock advances across suspend on both, so comparing elapsed wall-clock
against the slice we intended to wait detects a resume WITHOUT any OS hook,
without touching the installer, and identically on both platforms.

⛔ A FALSE POSITIVE IS CHEAP AND BOUNDED, WHICH IS WHY THIS HEURISTIC IS SAFE.
An NTP step or a severely loaded machine can also produce a wall-clock jump. The
consequence is ONE extra heartbeat, and even that is bounded: detection calls
`request_early_beat`, so the existing POLL_INTERVAL_FLOOR rate limiter applies
unchanged. Detection deliberately does NOT bypass the floor — it records a reason
and lets the tested path decide, rather than adding a second way to beat.

Run: python3 nemesis_agent/test_resume_detect.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import agent                                                  # noqa: E402

EXPECTED_CHECKS = 24
_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


def test_a_normal_wait_is_not_a_resume():
    """The common case, and the one a bad threshold breaks: every ordinary slice
    must NOT look like a resume, or the agent beats continuously."""
    print("\n[an ordinary wait is not a resume]")
    check("exact wait is not a resume",
          agent._resume_detected(60.0, 1000.0, 1060.0) is False)
    check("slightly long wait (scheduler jitter) is not a resume",
          agent._resume_detected(60.0, 1000.0, 1060.9) is False)
    check("slightly SHORT wait is not a resume",
          agent._resume_detected(60.0, 1000.0, 1059.5) is False)
    check("a zero-length wait is not a resume",
          agent._resume_detected(0.0, 1000.0, 1000.0) is False)


def test_a_real_suspend_is_detected():
    print("\n[a wall-clock jump past the tolerance IS a resume]")
    # 60s intended, three hours of wall clock passed.
    check("a 3-hour jump is detected",
          agent._resume_detected(60.0, 1000.0, 1000.0 + 60 + 10800) is True)
    check("a jump just past the tolerance is detected",
          agent._resume_detected(60.0, 1000.0,
                                 1060.0 + agent.RESUME_JUMP_TOLERANCE_S + 1) is True)
    # CONTROL: just INSIDE the tolerance must not trip, or the threshold is
    # doing nothing and the two assertions above prove nothing about it.
    check("CONTROL: just inside the tolerance does NOT trip",
          agent._resume_detected(60.0, 1000.0,
                                 1060.0 + agent.RESUME_JUMP_TOLERANCE_S - 1) is False)


def test_a_backwards_clock_is_not_a_resume():
    """An NTP step BACKWARDS makes elapsed negative. That is a clock correction,
    not a resume, and treating it as one would beat for the wrong reason."""
    print("\n[a backwards clock step is not a resume]")
    check("clock moved backwards is not a resume",
          agent._resume_detected(60.0, 1000.0, 900.0) is False)


def test_detection_goes_through_the_RATE_LIMITER_not_around_it():
    """⛔ The property that keeps a false positive cheap. Detection must record a
    reason via request_early_beat, so POLL_INTERVAL_FLOOR still applies. A version
    that returned early directly would bypass the floor and could beat in a loop
    on a machine with a misbehaving clock."""
    print("\n[detection records a reason; the existing floor still decides]")
    agent._early_beat_reasons.clear()
    agent._wake.clear()
    # Pretend we just beat, so the floor is NOT yet satisfied.
    agent._last_beat_at = agent.time.monotonic()
    due_now = agent.request_early_beat("resume")
    check("a request inside the floor reports NOT due now", due_now is False,
          "got %r -- the floor is being bypassed" % due_now)
    check("...but the reason is RECORDED, not dropped",
          "resume" in agent._early_beat_reasons,
          "reasons=%r" % agent._early_beat_reasons)
    check("...and the loop is woken to re-evaluate", agent._wake.is_set())

    # And once the floor has passed, the same call reports due.
    agent._early_beat_reasons.clear()
    agent._last_beat_at = agent.time.monotonic() - (agent.POLL_INTERVAL_FLOOR + 1)
    check("outside the floor, a request IS due now",
          agent.request_early_beat("resume") is True)
    agent._early_beat_reasons.clear()
    agent._wake.clear()


def test_the_slice_cap_is_what_makes_detection_possible():
    """Detection can only happen when a wait RETURNS. One long wait spanning the
    suspend would report nothing until the whole interval elapsed, so the wait is
    capped into slices. Assert the cap is real and meaningfully shorter than the
    interval it protects."""
    print("\n[the slice cap bounds how late a resume can be noticed]")
    check("a resume-check slice is defined", agent.RESUME_CHECK_SLICE_S > 0)
    check("...and is well under the default poll interval",
          agent.RESUME_CHECK_SLICE_S < agent.POLL_INTERVAL_DEFAULT,
          "slice=%s interval=%s" % (agent.RESUME_CHECK_SLICE_S,
                                    agent.POLL_INTERVAL_DEFAULT))
    check("...and is not so small it wakes constantly (battery)",
          agent.RESUME_CHECK_SLICE_S >= 15,
          "slice=%s -- too aggressive for a laptop on battery"
          % agent.RESUME_CHECK_SLICE_S)


class _FakeClock:
    """Two clocks that can DIVERGE — which is the whole point. Modelled on Linux,
    the harder platform: CLOCK_MONOTONIC does not advance across a suspend, so the
    deadline is still in the future on waking and the agent would otherwise sit
    out the remainder. Wall-clock advances by the full suspended duration."""

    def __init__(self):
        self.mono = 1000.0
        self.wall = 5000.0

    def monotonic(self):
        return self.mono

    def time(self):
        return self.wall


class _FakeWake:
    """Stands in for the `_wake` Event, and drives the fake clock forward so the
    loop actually progresses. Records every requested wait so the slice cap can
    be asserted against BEHAVIOUR rather than against its own constant."""

    def __init__(self, clock, suspend_after_call=None, suspend_seconds=0.0):
        self.clock = clock
        self.suspend_after_call = suspend_after_call
        self.suspend_seconds = suspend_seconds
        self.waited = []

    def clear(self):
        pass

    def set(self):
        pass

    def wait(self, timeout=None):
        self.waited.append(timeout)
        if len(self.waited) > 50:
            raise AssertionError("runaway loop: _interruptible_sleep did not return")
        self.clock.mono += timeout
        self.clock.wall += timeout
        if len(self.waited) == self.suspend_after_call:
            self.clock.wall += self.suspend_seconds     # wall only: the suspend
        return False


def _run_sleep(suspend_after_call=None, suspend_seconds=0.0, seconds=300.0,
               realistic_last_beat=False):
    """Drive the REAL `_interruptible_sleep` against injected clocks.

    `realistic_last_beat` models production: the poll loop beats, sets
    `_last_beat_at`, then immediately enters the sleep — so the floor is NOT
    pre-satisfied and has to be earned by the slices actually elapsing.
    """
    clock = _FakeClock()
    wake = _FakeWake(clock, suspend_after_call, suspend_seconds)
    saved = (agent.time, agent._wake, agent._running, agent._last_beat_at)
    agent._early_beat_reasons.clear()
    try:
        agent.time = clock
        agent._wake = wake
        agent._running = True
        agent._last_beat_at = (clock.mono if realistic_last_beat else -1e6)
        agent._interruptible_sleep(seconds)
    finally:
        agent.time, agent._wake, agent._running, agent._last_beat_at = saved
    reasons = list(agent._early_beat_reasons)
    agent._early_beat_reasons.clear()
    return wake, clock, reasons


def test_the_FLOOR_does_not_delay_the_resume_beat():
    """⛔ PINS A LATENCY CLAIM THAT WILL BE WRITTEN INTO DOCS. "A resuming device
    checks in within ~60s" is only true if POLL_INTERVAL_FLOOR is already satisfied
    when detection fires — otherwise the beat waits out the floor as well.

    ⚠ The reason this needs a test rather than arithmetic: on Linux, monotonic does
    NOT advance during suspend, so `_last_beat_at` can still look recent after hours
    of wall-clock. What rescues it is that the SLICE itself advances monotonic by
    RESUME_CHECK_SLICE_S, and that is larger than the floor. If someone ever tunes
    the slice below the floor, this claim silently becomes false."""
    print("\n[the floor must already be satisfied when a resume is detected]")
    check("the slice exceeds the floor, so a completed slice earns the floor",
          agent.RESUME_CHECK_SLICE_S > agent.POLL_INTERVAL_FLOOR,
          "slice=%s floor=%s -- a resume beat would be delayed by the floor"
          % (agent.RESUME_CHECK_SLICE_S, agent.POLL_INTERVAL_FLOOR))
    # The production shape: beat, then sleep, then suspend during the first slice.
    wake, clock, reasons = _run_sleep(suspend_after_call=1, suspend_seconds=10800.0,
                                      realistic_last_beat=True)
    check("...and with a REALISTIC last-beat it still returns after 1 slice",
          len(wake.waited) == 1, "waited %r" % (wake.waited,))
    check("...having recorded the resume", reasons == ["resume"], "reasons=%r" % reasons)


def test_INTEGRATION_the_loop_actually_uses_the_detection():
    """⛔ THE LOAD-BEARING TEST. Every check above passes against an agent.py that
    defines `_resume_detected` and never calls it. This one drives the real
    `_interruptible_sleep` across a simulated suspend and asserts it returns EARLY
    — the behaviour, not the ingredients."""
    print("\n[INTEGRATION: a suspend during the wait cuts the wait short]")
    # 300s interval, 60s slices; the suspend lands during the 2nd slice.
    wake, clock, reasons = _run_sleep(suspend_after_call=2, suspend_seconds=10800.0)
    check("returned after 2 slices, not the full 5", len(wake.waited) == 2,
          "waited %d times: %r -- the detection is not wired in"
          % (len(wake.waited), wake.waited))
    check("...and recorded 'resume' as the reason", reasons == ["resume"],
          "reasons=%r" % reasons)
    check("...and returned with monotonic time still short of the deadline",
          clock.mono < 1000.0 + 300.0, "mono=%s" % clock.mono)


def test_INTEGRATION_CONTROL_no_jump_waits_the_whole_interval():
    """⛔ THE CONTROL THAT PROVES THE HARNESS CAN PRODUCE THE OTHER ANSWER. Without
    it, a `_interruptible_sleep` that returned early for ANY reason would satisfy
    the test above and look like working detection."""
    print("\n[INTEGRATION CONTROL: no jump -> the full interval is waited]")
    wake, clock, reasons = _run_sleep()
    check("CONTROL: no early return -- all 5 slices waited", len(wake.waited) == 5,
          "waited %d times: %r" % (len(wake.waited), wake.waited))
    check("CONTROL: ...and no resume reason was recorded", reasons == [],
          "reasons=%r" % reasons)
    # Asserts the cap is APPLIED by the loop, not merely declared as a constant.
    check("CONTROL: ...and every slice was capped at RESUME_CHECK_SLICE_S",
          wake.waited and max(wake.waited) <= agent.RESUME_CHECK_SLICE_S,
          "longest slice was %r" % (max(wake.waited) if wake.waited else None))


if __name__ == "__main__":
    print("=" * 70)
    for fn in (test_a_normal_wait_is_not_a_resume,
               test_a_real_suspend_is_detected,
               test_a_backwards_clock_is_not_a_resume,
               test_detection_goes_through_the_RATE_LIMITER_not_around_it,
               test_the_slice_cap_is_what_makes_detection_possible,
               test_INTEGRATION_the_loop_actually_uses_the_detection,
               test_INTEGRATION_CONTROL_no_jump_waits_the_whole_interval,
               test_the_FLOOR_does_not_delay_the_resume_beat):
        fn()
    print("\n" + "=" * 70)
    ran = _pass + _fail
    print("checks: %d passed, %d failed (%d run)" % (_pass, _fail, ran))
    if ran != EXPECTED_CHECKS:
        print("EXPECTED_CHECKS MISMATCH: declared %d, ran %d" % (EXPECTED_CHECKS, ran))
        sys.exit(1)
    sys.exit(1 if _fail else 0)
