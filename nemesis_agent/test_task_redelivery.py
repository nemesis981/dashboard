#!/usr/bin/env python3
"""Task redelivery: a dispatched task whose result never arrives gets re-sent.

Run: python3 nemesis_agent/test_task_redelivery.py

THE PROBLEM
-----------
A task handed to a device moves to 'dispatched'. If the device never reports —
it crashed, the network dropped, the response was lost — nothing ever moves it
again. Step 4's result reporting made those stuck tasks VISIBLE; this makes them
recoverable. Without it, result reporting is a window onto a problem with no
remedy behind it.

WHY REDELIVERY IS SAFE HERE, WHICH IS THE WHOLE ARGUMENT
--------------------------------------------------------
From the server, "the agent never got it" and "the agent ran it and the report
was lost" are indistinguishable. So redelivery cannot rely on guessing which
happened — it has to be safe in both cases.

It is, because of Step 3's atomic claim: the agent stores a claim marker keyed on
task_id, and `claim_task` refuses a task_id it has already claimed. A redelivery
to a device that already ran the task is therefore a no-op, not a second
execution. That is what makes at-least-once delivery honest rather than
dangerous, and it is why the task_id must be PRESERVED across a redelivery — a
fresh id would defeat the claim and run the work twice.

The claim is pruned by expiry, so once the envelope's window has genuinely
passed, a redelivery does run again. Both halves are exercised below against the
real claim store, not a stand-in.

WHAT THIS SUITE WEIGHTS TOWARD
------------------------------
The dangerous direction is redelivering too eagerly — re-sending a task that is
still live, or one that already has an answer. So most of these are controls on
what must NOT be redelivered, not confirmations that redelivery happens.

hw_monitor IS imported here. A sibling suite's docstring claims it "opens sockets
and a DB on import"; that was checked and is not true of the current file — it
imports in ~0.04s with no socket and no DB connection. The decision logic under
test is a pure function, so no database is touched by this suite at all.
"""
import os
import sys
import tempfile
import shutil
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "core_module", "hw_monitor"))
sys.path.insert(0, "/opt/nemesis/alert_manager")

EXPECTED_CHECKS = 17

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def main():
    import hw_monitor as hw

    NOW = datetime(2026, 8, 4, 12, 0, 0)
    LIVE = (NOW + timedelta(minutes=10)).isoformat(timespec="seconds")   # not expired
    GONE = (NOW - timedelta(minutes=10)).isoformat(timespec="seconds")   # expired
    MAX = hw.REDELIVERY_MAX_ATTEMPTS

    d = hw._redelivery_decision

    # ── what must NOT be redelivered ─────────────────────────────────────────
    print("\nonly a genuinely stuck task is ever re-sent")
    check("CONTROL a dispatched task still inside its envelope is left alone",
          d("dispatched", LIVE, 1, NOW), "leave")
    check("CONTROL a completed task is never redelivered",
          d("completed", GONE, 1, NOW), "leave")
    check("CONTROL a failed task is never redelivered — it answered",
          d("failed", GONE, 1, NOW), "leave")
    check("CONTROL a still-pending task is left alone",
          d("pending", GONE, 0, NOW), "leave")
    check("CONTROL an already-abandoned task is not retried",
          d("expired", GONE, MAX, NOW), "leave")

    # Boundary: expiry is the moment it STOPS being valid, so equality is still
    # live. Off by one here means re-sending tasks the agent may be mid-way
    # through, which is the one case that genuinely races the device.
    exact = NOW.isoformat(timespec="seconds")
    check("CONTROL a task expiring exactly now is not yet expired",
          d("dispatched", exact, 1, NOW), "leave")

    # ── what must be redelivered ─────────────────────────────────────────────
    print("\na dispatched task past its envelope, with attempts left, is re-sent")
    check("POSITIVE an expired dispatched task is redelivered",
          d("dispatched", GONE, 1, NOW), "redeliver")
    check("POSITIVE one attempt below the limit still redelivers",
          d("dispatched", GONE, MAX - 1, NOW), "redeliver")

    # ── bounded, so a permanently dead device cannot loop forever ────────────
    print("\nredelivery is bounded and gives up visibly")
    check("CONTROL at the attempt limit it abandons instead of retrying",
          d("dispatched", GONE, MAX, NOW), "abandon")
    check("CONTROL past the attempt limit it still abandons",
          d("dispatched", GONE, MAX + 5, NOW), "abandon")
    check("abandoning is a distinct outcome, not a quiet 'leave'",
          d("dispatched", GONE, MAX, NOW) != "leave", True)

    # ── an unreadable row is an explicit sentinel, never a default ───────────
    print("\nan unreadable expiry surfaces as itself, not as a decision")
    check("a malformed expiry yields the explicit sentinel",
          d("dispatched", "not-a-timestamp", 0, NOW), hw.REDELIVER_UNREADABLE)
    check("a missing expiry yields the explicit sentinel",
          d("dispatched", None, 0, NOW), hw.REDELIVER_UNREADABLE)
    # If the sentinel equalled 'leave' the caller could not tell a row it examined
    # from one it failed to read -- the failure would wear a legitimate answer's
    # costume, which is exactly what this project treats as a defect.
    check("the sentinel is distinguishable from every real decision",
          hw.REDELIVER_UNREADABLE not in ("leave", "redeliver", "abandon"), True)

    # ── the claim is what makes it safe: exercised for real ─────────────────
    print("\nthe agent's claim makes an unnecessary redelivery a no-op")
    tmp = tempfile.mkdtemp(prefix="nemesis-redeliver-")
    try:
        import config
        import tasks as task_mod
        config.CONF_PATH = os.path.join(tmp, "agent.conf")

        claim_live = (NOW + timedelta(minutes=30)).isoformat(timespec="seconds")
        check("the first delivery wins the claim",
              task_mod.claim_task("task-alpha", claim_live, NOW), True)
        check("CONTROL redelivering a task the agent already ran is refused",
              task_mod.claim_task("task-alpha", claim_live, NOW), False)

        # Claims are pruned by expiry, so past the window a redelivery legitimately
        # runs again -- proving redelivery is not permanently suppressed by a
        # stale marker, which would make the whole mechanism useless.
        task_mod.claim_task("task-beta", GONE, NOW)
        check("POSITIVE past the claim window a redelivery executes again",
              task_mod.claim_task("task-beta", claim_live, NOW), True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [lbl for lbl, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d "
              "-- a check was skipped, not merely failed" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
