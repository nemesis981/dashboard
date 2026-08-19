#!/usr/bin/env python3
"""Tests for the cooperative-throttle seam (alert_manager/throttle.py).

Pure-core tests (factor clamping, expiry, fail-open, sleep scaling) plus a real
temp-DB integration test through the Data Manager -- publish -> read-back ->
expiry-lift -> registry -> clear. Never touches the live alerts.db."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import database                                              # noqa: E402
import data_manager                                          # noqa: E402
import throttle as th                                        # noqa: E402

_failures = []


def check(label, got, want):
    if got != want:
        _failures.append("%s: got %r, want %r" % (label, got, want))
        print("  FAIL  %s: got %r, want %r" % (label, got, want))
    else:
        print("  ok    %s" % label)


def _run(label, fn):
    """Run a test body; a raising body is a FAILURE that does not abort the rest."""
    try:
        fn()
    except Exception as e:                                   # noqa: BLE001
        import traceback
        _failures.append("%s raised: %s" % (label, e))
        print("  FAIL  %s raised: %s" % (label, e))
        traceback.print_exc()


# ── pure core ────────────────────────────────────────────────────────────────
def test_effective_factor():
    print("\n[_effective_factor: expiry, clamp, fail-open]")
    NOW = 1000.0
    check("no row -> normal", th._effective_factor(None, NOW), th.NORMAL)
    check("expired -> normal (auto-lift)",
          th._effective_factor({"factor": 4.0, "until_ts": 999.0}, NOW), th.NORMAL)
    check("live factor honoured",
          th._effective_factor({"factor": 4.0, "until_ts": 1100.0}, NOW), 4.0)
    check("factor below normal -> normal",
          th._effective_factor({"factor": 0.5, "until_ts": 1100.0}, NOW), th.NORMAL)
    check("above MAX -> clamped",
          th._effective_factor({"factor": 999.0, "until_ts": 1100.0}, NOW),
          th.MAX_FACTOR)
    check("malformed -> normal (fail-open, not a guess)",
          th._effective_factor({"factor": "x", "until_ts": 1100.0}, NOW), th.NORMAL)
    check("boundary now==until -> expired",
          th._effective_factor({"factor": 4.0, "until_ts": 1000.0}, NOW), th.NORMAL)


def test_scaled_seconds():
    print("\n[_scaled_seconds: multiply, floor, cap]")
    check("normal -> base", th._scaled_seconds(300, 1.0), 300)
    check("4x", th._scaled_seconds(300, 4.0), 1200)
    check("floor at 1s", th._scaled_seconds(0, 1.0), 1)
    check("capped at base*MAX", th._scaled_seconds(300, th.MAX_FACTOR), 2400)


def test_handle_fail_open():
    print("\n[current_factor: fail-open on read error]")
    class BoomDM:
        def connect(self, ns):
            raise RuntimeError("db down")
    h = th.ThrottleHandle("hw-monitor", BoomDM(), now_fn=lambda: 0.0)
    check("read error -> NORMAL, never stalls", h.current_factor(), th.NORMAL)


def test_throttled_sleep_scales_and_stops():
    print("\n[throttled_sleep: step count + early stop]")
    # Fake dm returning a live 3x intent; count sleep calls instead of waiting.
    class Row(dict):
        pass
    class FakeDM:
        def connect(self, ns):
            outer = self
            class C:
                def execute(self, sql, params):
                    class Cur:
                        def fetchone(self):
                            return {"factor": 3.0, "until_ts": 9e9}
                    return Cur()
                def close(self): pass
            return C()
    calls = {"n": 0}
    def fake_sleep(_): calls["n"] += 1
    h = th.ThrottleHandle("hw-monitor", FakeDM(), now_fn=lambda: 0.0)
    h.throttled_sleep(10, is_running=lambda: True, sleep_fn=fake_sleep)
    check("10s base * 3x = 30 steps", calls["n"], 30)
    # early stop: is_running flips false after 5 steps
    calls["n"] = 0
    def stop_after_5(): return calls["n"] < 5
    h.throttled_sleep(10, is_running=stop_after_5, sleep_fn=fake_sleep)
    check("honours is_running early stop", calls["n"], 5)


# ── real DB integration through the Data Manager ─────────────────────────────
def test_integration_publish_read_expire_register_clear():
    print("\n[integration: publish -> read -> expire -> register -> clear (temp DB)]")
    tmp = tempfile.mkdtemp(prefix="nem-throttle-test-")
    dbp = os.path.join(tmp, "alerts.db")
    database.DB_PATH = dbp
    database.init_throttle_tables()
    dm = data_manager.DataManager(dbp)
    h = th.register_throttle_aware("hw-monitor", dm, pid=4242, now=1000.0)

    # registry row written
    conn = dm.connect(th.NAMESPACE)
    reg = conn.execute("SELECT component, pid FROM throttle_components "
                       "WHERE component=?", ("hw-monitor",)).fetchone()
    conn.close()
    check("registry records component", reg["component"] if reg else None, "hw-monitor")
    check("registry records pid", reg["pid"] if reg else None, 4242)

    # no intent yet -> normal
    check("no intent -> NORMAL",
          th.ThrottleHandle("hw-monitor", dm, now_fn=lambda: 1000.0).current_factor(),
          th.NORMAL)

    # publish a live 4x throttle for 600s at t=1000
    th.publish_throttle("hw-monitor", 4.0, 600, "mem pressure 82%", dm, now=1000.0)
    check("live intent read back = 4x",
          th.ThrottleHandle("hw-monitor", dm, now_fn=lambda: 1100.0).current_factor(),
          4.0)

    # same intent, read AFTER expiry -> auto-lift to normal (executor died case)
    check("expired intent -> NORMAL (fail-safe)",
          th.ThrottleHandle("hw-monitor", dm, now_fn=lambda: 1700.0).current_factor(),
          th.NORMAL)

    # explicit clear -> positive normal record
    th.publish_throttle("hw-monitor", 4.0, 600, "still hot", dm, now=1000.0)
    th.clear_throttle("hw-monitor", dm, now=1200.0)
    check("clear -> NORMAL even before natural expiry",
          th.ThrottleHandle("hw-monitor", dm, now_fn=lambda: 1250.0).current_factor(),
          th.NORMAL)

    # CONTROL: the read is a real measurement, not always-normal. A fresh live
    # intent right after the clear must read as throttled again.
    th.publish_throttle("hw-monitor", 2.0, 600, "reheat", dm, now=1300.0)
    check("CONTROL: fresh intent throttles again (read isn't stuck-normal)",
          th.ThrottleHandle("hw-monitor", dm, now_fn=lambda: 1350.0).current_factor(),
          2.0)


if __name__ == "__main__":
    print("throttle — cooperative throttle seam")
    _run("effective_factor", test_effective_factor)
    _run("scaled_seconds", test_scaled_seconds)
    _run("handle_fail_open", test_handle_fail_open)
    _run("throttled_sleep", test_throttled_sleep_scales_and_stops)
    _run("integration", test_integration_publish_read_expire_register_clear)

    print("\n" + "=" * 64)
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  - %s" % f)
        sys.exit(1)
    print("ALL PASS")
