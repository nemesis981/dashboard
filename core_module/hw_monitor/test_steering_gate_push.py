"""Server-side test: the steering gate posture pushed on the heartbeat response.

Covers hw_monitor._steering_gate_armed() -- the downward half of the roaming
steering lease (tunnel-back §5.2). The property that matters: it is FAIL-SAFE.
An armed+inspecting gate pushes True; a stale gate, a bypassed gate, or a read
that RAISES all push False, because authorising a roaming device to steer off a
gate read that could not be trusted is the wrong direction.

Run: python3 core_module/hw_monitor/test_steering_gate_push.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "alert_manager"))

import hw_monitor                                            # noqa: E402
import tier2_gate_state                                     # noqa: E402

_results = []


def check(label, got, want):
    ok = got == want
    _results.append((label, ok))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", label, got, want))


def with_gate(state):
    """Run _steering_gate_armed() with read_state monkeypatched to `state`."""
    orig = tier2_gate_state.read_state
    try:
        if isinstance(state, Exception):
            def _raise(*a, **k):
                raise state
            tier2_gate_state.read_state = _raise
        else:
            tier2_gate_state.read_state = lambda *a, **k: state
        return hw_monitor._steering_gate_armed()
    finally:
        tier2_gate_state.read_state = orig


def main():
    print("gate posture -> steering_gate_armed, fail-safe in every uncertain case")
    check("armed + inspecting -> True",
          with_gate({"state": "armed", "inspecting": True, "stale": False}), True)
    check("armed but NOT inspecting -> False",
          with_gate({"state": "armed", "inspecting": False, "stale": False}), False)
    check("STALE gate -> False (read_state already forces inspecting False)",
          with_gate({"state": "stale", "inspecting": False, "stale": True}), False)
    check("bypassed gate -> False",
          with_gate({"state": "bypassed", "inspecting": False, "stale": False}), False)
    check("unpublished gate -> False",
          with_gate({"state": "unpublished", "inspecting": False, "stale": True}),
          False)
    check("a gate read that RAISES -> False (fail-safe, never propagates)",
          with_gate(RuntimeError("db broken")), False)
    check("a missing 'inspecting' key -> False",
          with_gate({"state": "armed"}), False)

    print("\nthe pushed value is a real bool (json-serialisable, not a truthy dict)")
    val = with_gate({"state": "armed", "inspecting": True, "stale": False})
    check("it is exactly True/False", isinstance(val, bool), True)

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
