"""Server-side USB device-control (v1: detect + durable record + operator alert).

The agent now sends STRUCTURED usb events (vid/pid/serial/model). This suite pins the
server ingest: the stable dedup key (structured AND legacy-raw), the durable usb_events
table with first-sighting dedup, and the operator alert on a genuinely new device.

Backward compatibility is a first-class requirement: a device still running the OLD
agent sends {"raw": "..."} events, and the server must keep handling those (the Windows/
macOS agent backends are not upgraded yet), never crash or lose them.
"""
import os
import sqlite3
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "alert_manager"))
sys.path.insert(0, _HERE)
import hw_monitor as hw   # noqa: E402
import database           # noqa: E402

_fail = []
_count = 0
EXPECTED_CHECKS = 25

_FLASH = {"action": "present", "vendor_id": "0781", "product_id": "5591",
          "serial": "4C530001234567890", "model": "Ultra Fit", "vendor": "SanDisk",
          "devname": "/dev/sdb"}
_HDD = {"action": "present", "vendor_id": "0bc2", "product_id": "ab62",
        "serial": "FAKESERIAL0HDD01", "model": "One Touch HDD", "vendor": "Seagate",
        "devname": "/dev/sda"}
_LEGACY = {"raw": "usb 1-1: new high-speed USB device number 5 using xhci_hcd"}


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-70s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def _conn():
    c = sqlite3.connect(":memory:")
    c.executescript(database.USB_EVENTS_DDL)
    return c


class _AlertSpy:
    def __init__(self):
        self.calls = []

    def __call__(self, device_id, ev):
        self.calls.append((device_id, ev))


def test_seen_key_structured_and_legacy():
    print("\n[stable key: structured -> vid:pid:serial; legacy raw -> raw prefix]")
    check("structured key", hw._usb_seen_key(_FLASH), "usb:0781:5591:4C530001234567890")
    check("structured key stable across devname churn",
          hw._usb_seen_key(dict(_FLASH, devname="/dev/sdX")),
          "usb:0781:5591:4C530001234567890")
    check("legacy raw key is a raw-prefixed slice",
          hw._usb_seen_key(_LEGACY).startswith("raw:"), True)
    check("legacy raw key non-empty", bool(hw._usb_seen_key(_LEGACY)), True)
    check("two different devices -> different keys",
          hw._usb_seen_key(_FLASH) != hw._usb_seen_key(_HDD), True)


def test_new_device_recorded_and_alerted():
    print("\n[a new device -> one durable row + one operator alert with identifying detail]")
    c = _conn()
    spy = _AlertSpy()
    new = hw._record_usb_devices(c, "devA", [_FLASH], now=1000.0, alert_fn=spy)
    check("one new device reported", len(new), 1)
    check("one alert raised", len(spy.calls), 1)
    rows = c.execute("SELECT device_id, vendor, model, serial, vendor_id, product_id "
                     "FROM usb_events").fetchall()
    check("one durable row written", len(rows), 1)
    check("row carries device_id", rows[0][0], "devA")
    check("row carries vendor", rows[0][1], "SanDisk")
    check("row carries model", rows[0][2], "Ultra Fit")
    check("row carries serial", rows[0][3], "4C530001234567890")
    # alert detail must identify the device (vendor/model/serial), not just "a USB device"
    _dev, ev = spy.calls[0]
    check("alert event carries serial", ev["serial"], "4C530001234567890")
    check("alert event carries vendor", ev["vendor"], "SanDisk")


def test_same_device_deduped():
    print("\n[the same device on a later beat -> no new row, no repeat alert]")
    c = _conn()
    spy = _AlertSpy()
    hw._record_usb_devices(c, "devA", [_FLASH], now=1000.0, alert_fn=spy)
    hw._record_usb_devices(c, "devA", [_FLASH], now=1060.0, alert_fn=spy)   # same device again
    check("still one row after re-sighting", c.execute("SELECT COUNT(*) FROM usb_events").fetchone()[0], 1)
    check("no repeat alert", len(spy.calls), 1)


def test_same_key_different_device_is_separate():
    print("\n[the same USB stick on TWO machines -> a row + alert per machine]")
    c = _conn()
    spy = _AlertSpy()
    hw._record_usb_devices(c, "devA", [_FLASH], now=1000.0, alert_fn=spy)
    hw._record_usb_devices(c, "devB", [_FLASH], now=1000.0, alert_fn=spy)
    check("two rows (dedup is per device+key, not global)",
          c.execute("SELECT COUNT(*) FROM usb_events").fetchone()[0], 2)
    check("two alerts", len(spy.calls), 2)


def test_legacy_raw_still_handled():
    print("\n[a device on the OLD agent (raw events) is still recorded + alerted]")
    c = _conn()
    spy = _AlertSpy()
    new = hw._record_usb_devices(c, "devC", [_LEGACY], now=1000.0, alert_fn=spy)
    check("legacy raw device recorded", len(new), 1)
    check("legacy raw device alerted", len(spy.calls), 1)
    row = c.execute("SELECT raw, serial FROM usb_events WHERE device_id='devC'").fetchone()
    check("raw text preserved", bool(row[0]), True)
    check("no serial for a legacy raw event", row[1] in ("", None), True)


def test_extract_usb_names_structured_aware():
    print("\n[the scan-trigger key extractor understands structured events too]")
    keys = hw._extract_usb_names([_FLASH, _HDD])
    check("structured events yield identity keys", "usb:0781:5591:4C530001234567890" in keys, True)
    check("two devices -> two keys", len(keys), 2)
    # legacy raw still works (backward compat for the scan trigger)
    legkeys = hw._extract_usb_names([_LEGACY])
    check("legacy raw still yields a key", len(legkeys), 1)


if __name__ == "__main__":
    print("=" * 74)
    print("hw_monitor — USB device-control server ingest (v1)")
    print("=" * 74)
    test_seen_key_structured_and_legacy()
    test_new_device_recorded_and_alerted()
    test_same_device_deduped()
    test_same_key_different_device_is_separate()
    test_legacy_raw_still_handled()
    test_extract_usb_names_structured_aware()
    print()
    if _count != EXPECTED_CHECKS:
        print("SUITE DRIFT: ran %d checks, expected %d" % (_count, EXPECTED_CHECKS))
        sys.exit(1)
    if _fail:
        print("FAILED (%d of %d)" % (len(_fail), _count))
        for f in _fail:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS (%d checks)" % _count)
