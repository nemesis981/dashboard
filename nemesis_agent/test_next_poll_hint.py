#!/usr/bin/env python3
"""Stage 1 step 6: `next_poll_hint` — the server asks for an earlier next beat.

Run: python3 nemesis_agent/test_next_poll_hint.py

WHY THIS EXISTS NOW
-------------------
Step 5 retired the direct `:5002` pushes, so every scan and notification is
delivered on the next heartbeat instead of immediately. With a 300s default
poll_interval that is up to five minutes of latency on work that used to be
instant. `next_poll_hint` lets the server say "come back sooner, I have work for
you" without making every agent poll hard all the time.

THE SECURITY PROPERTY THIS SUITE EXISTS TO PIN DOWN
---------------------------------------------------
The heartbeat RESPONSE is unsigned. Only the task envelopes carried inside it are
signed; the surrounding body is not, and the transport is plain HTTP. So anything
able to answer on that socket can supply a hint — the same threat model already
accepted for `results_ack`.

Therefore the hint may only ever SHORTEN the next interval, never lengthen it.

That single rule is what makes an unsigned, attacker-influenceable field safe to
honour at all:
  * shortening is bounded below by POLL_INTERVAL_FLOOR, so the worst a hostile
    hint achieves is a chatty agent — noisy, self-limiting, and visible.
  * lengthening would be the real attack: a hint of "come back in 30 days"
    silences a device's telemetry while leaving it apparently healthy. Refusing
    to lengthen means that attack does not exist rather than being merely
    bounded.

A suite that only checked "a short hint is honoured" would pass an implementation
that also honoured long ones, which is precisely the dangerous case. So the
controls here are weighted toward what must NOT happen.

EXPECTED BEFORE THE IMPLEMENTATION: red on everything except the two structural
server checks. A green run on unimplemented code means the control is broken.
"""
import ast
import logging
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
HW_MONITOR = os.path.join(REPO, "core_module", "hw_monitor", "hw_monitor.py")

sys.path.insert(0, HERE)
sys.path.insert(0, "/opt/nemesis/alert_manager")

EXPECTED_CHECKS = 16

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


class _Capture(logging.Handler):
    """Collects agent log records so 'rejected' can be told from 'ignored'."""

    def __init__(self):
        logging.Handler.__init__(self)
        self.records = []

    def emit(self, record):
        self.records.append(record.getMessage())


def parse(path):
    with open(path) as fh:
        return ast.parse(fh.read(), path)


def function_named(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def main():
    import agent

    STEADY = 300           # the shipped default poll_interval
    FLOOR = agent.POLL_INTERVAL_FLOOR

    # ── the hint may only shorten ────────────────────────────────────────────
    print("\na hint may only shorten the next interval, never lengthen it")

    # Beat far past the ramp so `steady` is the thing being compared against.
    settled = agent.RAMP_BEATS + 5

    longer = agent._effective_interval(settled, STEADY,
                                       agent._clamp_poll_hint(STEADY * 2))
    check("CONTROL a hint longer than poll_interval does not delay the beat",
          longer, STEADY)
    week = agent._effective_interval(settled, STEADY,
                                     agent._clamp_poll_hint(7 * 24 * 3600))
    check("CONTROL a one-week hint cannot silence the agent", week, STEADY)

    check("POSITIVE a hint shorter than poll_interval is honoured",
          agent._effective_interval(settled, STEADY, agent._clamp_poll_hint(30)), 30)
    check("CONTROL a hint below the floor is clamped up to it",
          agent._effective_interval(settled, STEADY, agent._clamp_poll_hint(1)), FLOOR)
    check("CONTROL a zero hint cannot produce a busy loop",
          agent._effective_interval(settled, STEADY, agent._clamp_poll_hint(0)), STEADY)

    # ── malformed is not the same as absent ──────────────────────────────────
    print("\na malformed hint is rejected out loud, not silently defaulted")
    check("an absent hint leaves the interval untouched",
          agent._effective_interval(settled, STEADY, agent._clamp_poll_hint(None)),
          STEADY)
    check("a non-numeric hint is rejected, not coerced",
          agent._clamp_poll_hint("30"), None)
    # bool is a subclass of int in Python -- int(True) == 1, which would sail
    # through a naive numeric check and clamp to the floor.
    check("a boolean hint is rejected (bool is an int subclass)",
          agent._clamp_poll_hint(True), None)
    check("a negative hint is rejected", agent._clamp_poll_hint(-60), None)

    cap = _Capture()
    agent.log.addHandler(cap)
    try:
        agent._clamp_poll_hint("not-a-number")
    finally:
        agent.log.removeHandler(cap)
    check("rejecting a malformed hint is reported, not silent",
          any("hint" in m.lower() for m in cap.records), True)

    # ── composes with the startup ramp ───────────────────────────────────────
    print("\nthe hint composes with the startup ramp")
    ramp0 = agent._ramp_interval(0, STEADY)
    check("during the ramp a shorter hint still wins",
          agent._effective_interval(0, STEADY, agent._clamp_poll_hint(FLOOR)), FLOOR)
    check("during the ramp a longer hint does not slow the ramp",
          agent._effective_interval(0, STEADY, agent._clamp_poll_hint(STEADY)), ramp0)

    # ── one-shot, never sticky ───────────────────────────────────────────────
    print("\nthe hint applies to the next beat only")
    agent._poll_hint = None
    agent._handle_response_tasks(_FakeResponse({"next_poll_hint": 45}), "dev-under-test")
    check("receiving a hint records it for the next beat", agent._poll_hint, 45)

    loop = function_named(parse(agent.__file__.replace(".pyc", ".py")), "_poll_loop")
    clears = False
    for node in ast.walk(loop) if loop else []:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "_poll_hint" and \
                        isinstance(node.value, ast.Constant) and node.value.value is None:
                    clears = True
    check("_poll_loop clears it after use, so it cannot stick", clears, True)

    # ── the server actually emits one ────────────────────────────────────────
    print("\nthe server emits a hint when it wants the agent back sooner")
    hw = parse(HW_MONITOR)
    keys = set()
    for node in ast.walk(hw):
        if isinstance(node, ast.Dict):
            for k in node.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    keys.add(k.value)
    check("the heartbeat response carries a next_poll_hint key",
          "next_poll_hint" in keys, True)

    # The server must never emit a hint the agent would have to clamp -- a value
    # below the floor would mean the two halves disagree about the floor.
    hint_const = None
    for node in ast.walk(hw):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "TASK_POLL_HINT_SECONDS" and \
                        isinstance(node.value, ast.Constant):
                    hint_const = node.value.value
    check("the server's hint is not below the agent's floor",
          hint_const is not None and hint_const >= FLOOR, True)

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


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200

    def json(self):
        return self._payload


if __name__ == "__main__":
    raise SystemExit(main())
