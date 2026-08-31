"""Track C Piece 6 + the six-item gate, at the collection point.

Run: python3 nemesis_agent/test_security_gating.py

⚠ THE PLATFORM SPLIT IS THE POINT AND IT IS DELIBERATE.
The poll-based `_network_connections()` is retired on WINDOWS ONLY, because that is
the only platform whose event-driven replacement exists and has been proven against
real hardware. On Linux/macOS there is no event-driven collector at all, so retiring
it there would silently remove connection telemetry from those agents. A test that
only checked "the poll path is gone" would happily pass the version that breaks
every non-Windows agent, so both directions are asserted.

⚠ AN ITEM THAT IS OFF MUST BE ABSENT, NOT EMPTY. `"usb_events": []` is
indistinguishable server-side from "this device saw no USB activity" -- a different
fact the server acts on. So the assertions check key PRESENCE, not falsiness.

ASSERTION COUNT IS FIXED and self-asserted.
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "modules"))
import config                                   # noqa: E402
config.CONF_PATH = os.path.join(tempfile.mkdtemp(prefix="secgate-"), "agent.conf")
import consent                                  # noqa: E402
import security                                 # noqa: E402

EXPECTED_CHECKS = 16
passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    ok = bool(cond)
    print(("  [PASS] " if ok else "  [FAIL] ") + name
          + ("" if ok or not detail else "  (%s)" % detail))
    if ok:
        passed += 1
    else:
        failed += 1


def all_on():
    for k in consent.ITEM_KEYS:
        consent.set_enabled(k, True, device_id="gate-test")


print("Piece 6 -- the poll path is retired on WINDOWS ONLY")
check("Windows -> superseded", security._etw_supersedes("Windows") is True)
check("⭐ Linux -> NOT superseded (no replacement exists there)",
      security._etw_supersedes("Linux") is False)
check("⭐ macOS -> NOT superseded", security._etw_supersedes("Darwin") is False)
check("unknown/None -> NOT superseded (fail toward keeping collection)",
      security._etw_supersedes(None) is False)

print("\ncollect() honours that split")
all_on()
lin = security.collect("Linux")
check("⭐ Linux still ships network_connections", "network_connections" in lin)
win = security.collect("Windows")
check("⭐ Windows no longer ships network_connections",
      "network_connections" not in win, sorted(win))

print("\nevery item is individually gated, and OFF means ABSENT")
all_on()
full = security.collect("Linux")
for key in ("top_processes", "login_events", "usb_events",
            "new_files_in_suspicious_locations"):
    check("%s present when on" % key, key in full)

consent.set_enabled(consent.ITEM_USB_EVENTS, False, device_id="gate-test")
part = security.collect("Linux")
check("⭐ usb_events ABSENT when off (not an empty list)",
      "usb_events" not in part, sorted(part))
check("turning one off does not disturb the others",
      "top_processes" in part and "login_events" in part)

print("\nall off -> nothing collected at all")
for k in consent.ITEM_KEYS:
    consent.set_enabled(k, False, device_id="gate-test")
none = security.collect("Linux")
check("empty block when every item is off", none == {}, sorted(none))

print("\n⭐ a MISSING gate collects nothing (never falls through to collecting)")
_real = security._consent
try:
    def _boom():
        raise ImportError("consent module unavailable")
    security._consent = _boom
    check("⭐ consent import failure -> {} , not full collection",
          security.collect("Linux") == {})
finally:
    security._consent = _real
all_on()
check("CONTROL: collection works again once the gate is back",
      "top_processes" in security.collect("Linux"))

_total = passed + failed
check("assertion count matches EXPECTED_CHECKS (%d)" % EXPECTED_CHECKS,
      _total + 1 == EXPECTED_CHECKS, "ran %d" % (_total + 1))

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
