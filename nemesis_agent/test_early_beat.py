#!/usr/bin/env python3
"""Event-triggered check-in — the reporting accelerator.

Run: python3 /opt/nemesis/nemesis_agent/test_early_beat.py

Timing logic, so every check measures ELAPSED TIME against a shortened floor
rather than asserting on internal flags. A test that only inspected state could
pass while the loop still slept the full interval, which is the one failure that
matters here.

The floor is monkeypatched down to keep the suite fast; the logic under test
reads it dynamically, so this exercises the real code path.
"""

import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agent                                                 # noqa: E402

EXPECTED_CHECKS = 12
_state = {"ran": 0, "failed": 0}

FLOOR = 0.40          # stands in for POLL_INTERVAL_FLOOR
TOL = 0.18            # timing slack; generous enough not to be flaky


def check(label, got, want):
    _state["ran"] += 1
    ok = got == want
    if not ok:
        _state["failed"] += 1
    print("  %-58s %s  (got=%r want=%r)" % (label, "PASS" if ok else "FAIL", got, want))


def near(label, got, want, tol=TOL):
    _state["ran"] += 1
    ok = abs(got - want) <= tol
    if not ok:
        _state["failed"] += 1
    print("  %-58s %s  (got=%.2fs want~%.2fs)"
          % (label, "PASS" if ok else "FAIL", got, want))


def reset(last_beat_offset=-10.0):
    agent._running = True
    agent._wake.clear()
    agent._take_early_reasons()
    agent._last_beat_at = time.monotonic() + last_beat_offset


def timed(fn, *a):
    t0 = time.monotonic()
    fn(*a)
    return time.monotonic() - t0


def main():
    agent.POLL_INTERVAL_FLOOR = FLOOR
    print("-- rate-limit decision (request_early_beat return value) --")
    reset()
    check("beat due immediately when floor already passed",
          agent.request_early_beat("evidence"), True)
    reset(last_beat_offset=-0.05)          # only 0.05s since last beat
    check("beat NOT due when inside the floor",
          agent.request_early_beat("evidence"), False)

    print("\n-- a request inside the floor is NOT lost --")
    reset(last_beat_offset=-0.05)
    agent.request_early_beat("game_launch")
    # Full interval is 5s; the floor expires 0.35s from now. If the pending
    # request were dropped, this would sleep the whole 5s.
    el = timed(agent._interruptible_sleep, 5.0)
    near("waits out the floor then beats (not the full interval)", el, 0.35)
    check("still under the full interval", el < 2.0, True)

    print("\n-- no request: the full interval is respected --")
    reset()
    el = timed(agent._interruptible_sleep, 0.5)
    near("sleeps the requested duration", el, 0.5)

    print("\n-- request after the floor: beats promptly --")
    reset()                                 # last beat 10s ago, floor passed
    agent.request_early_beat("evidence")
    el = timed(agent._interruptible_sleep, 5.0)
    near("returns almost immediately", el, 0.0)

    print("\n-- storm: many requests, floor still honoured --")
    reset(last_beat_offset=-0.05)
    for i in range(50):
        agent.request_early_beat("launch_%d" % i)
    el = timed(agent._interruptible_sleep, 5.0)
    near("50 requests do NOT shorten below the floor", el, 0.35)
    check("floor was not violated", el >= (FLOOR - 0.05 - TOL), True)
    reasons = agent._take_early_reasons()
    check("all 50 reasons retained for diagnostics", len(reasons), 50)
    check("reason list drains empty", agent._take_early_reasons(), [])

    print("\n-- shutdown wakes the loop at once --")
    reset()
    def stop():
        time.sleep(0.15)
        agent._shutdown()
    threading.Thread(target=stop, daemon=True).start()
    el = timed(agent._interruptible_sleep, 5.0)
    near("shutdown interrupts a long wait", el, 0.15)
    check("shutdown actually cleared _running", agent._running, False)
    agent._running = True

    print("\n%d/%d checks (ran=%d failed=%d)"
          % (_state["ran"] - _state["failed"], EXPECTED_CHECKS,
             _state["ran"], _state["failed"]))
    if _state["ran"] != EXPECTED_CHECKS:
        print("!! declared %d but ran %d — count guard failed"
              % (EXPECTED_CHECKS, _state["ran"]))
        return 1
    return 1 if _state["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
