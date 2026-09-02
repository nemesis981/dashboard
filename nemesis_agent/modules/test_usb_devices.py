"""Tests for usb_devices — the structured USB-storage collector's PURE core.

Upgrades the old raw-dmesg-string _usb_events into structured device identity
(VID/PID/serial/model) shared by BOTH the existing usb_inserted scan trigger and the
new device-level operator alert. These tests pin the pure logic: the storage filter,
the normaliser, and the stable dedup key. The pyudev enumeration itself is a thin
impure wrapper exercised on a real Linux host, not here.

⛔ THE FILTER IS THE LOAD-BEARING PART, and it is NOT the kernel 'removable' flag.
Measured on a real box 2026-09-02: a USB HDD reports removable=0 -- the kernel's
'removable' attribute is about removable MEDIA (card readers, floppies), not removable
DEVICES, so filtering on it MISSES most USB storage (flash drives, HDDs, SSDs). The
real discriminator is ID_BUS=usb + DEVTYPE=disk.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import usb_devices as U  # noqa: E402

_fail = []
_count = 0
EXPECTED_CHECKS = 23

# A real USB flash drive's udev properties (shape from live pyudev output).
_FLASH = {"ID_BUS": "usb", "DEVTYPE": "disk", "ID_VENDOR_ID": "0781",
          "ID_MODEL_ID": "5591", "ID_SERIAL_SHORT": "4C530001234567890",
          "ID_MODEL": "Ultra_Fit", "ID_VENDOR": "SanDisk", "DEVNAME": "/dev/sdb"}
# A USB HDD -- removable=0 but STILL usb storage (the case the naive filter misses).
_USB_HDD = {"ID_BUS": "usb", "DEVTYPE": "disk", "ID_VENDOR_ID": "0bc2",
            "ID_MODEL_ID": "ab62", "ID_SERIAL_SHORT": "FAKESERIAL0HDD01",
            "ID_MODEL": "One_Touch_HDD", "ID_VENDOR": "Seagate", "DEVNAME": "/dev/sda"}
# An internal NVMe -- NOT usb.
_NVME = {"ID_BUS": None, "DEVTYPE": "disk", "ID_SERIAL_SHORT": "   BIE1N008",
         "ID_MODEL": "SK hynix", "DEVNAME": "/dev/nvme0n1"}
# A partition on the flash drive -- not a whole device.
_PART = {"ID_BUS": "usb", "DEVTYPE": "partition", "ID_VENDOR_ID": "0781",
         "ID_MODEL_ID": "5591", "ID_SERIAL_SHORT": "4C530001234567890",
         "DEVNAME": "/dev/sdb1"}
# An internal SATA disk.
_SATA = {"ID_BUS": "ata", "DEVTYPE": "disk", "ID_MODEL": "Samsung_SSD",
         "DEVNAME": "/dev/sdc"}


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-70s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def test_filter_matches_usb_storage():
    print("\n[filter: ID_BUS=usb + DEVTYPE=disk, NOT the removable flag]")
    check("USB flash drive matches", U.is_usb_storage(_FLASH), True)
    check("USB HDD matches (removable=0 does NOT exclude it)", U.is_usb_storage(_USB_HDD), True)
    check("internal NVMe excluded (ID_BUS None)", U.is_usb_storage(_NVME), False)
    check("USB partition excluded (DEVTYPE=partition, not a whole device)",
          U.is_usb_storage(_PART), False)
    check("internal SATA excluded (ID_BUS=ata)", U.is_usb_storage(_SATA), False)
    check("empty props excluded", U.is_usb_storage({}), False)


def test_structured_device():
    print("\n[normaliser: structured identity, serial trimmed, model de-underscored]")
    d = U.structured_device(_FLASH, "present")
    check("action carried", d["action"], "present")
    check("vendor_id", d["vendor_id"], "0781")
    check("product_id", d["product_id"], "5591")
    check("serial", d["serial"], "4C530001234567890")
    check("model de-underscored", d["model"], "Ultra Fit")
    check("vendor", d["vendor"], "SanDisk")
    check("devname", d["devname"], "/dev/sdb")
    # leading-space serials (seen live on nvme) must be trimmed
    d2 = U.structured_device(_NVME, "present")
    check("leading-space serial trimmed", d2["serial"], "BIE1N008")
    # missing fields -> empty strings, never None (server builds keys/text from these)
    d3 = U.structured_device({"ID_BUS": "usb", "DEVTYPE": "disk"}, "present")
    check("missing vendor_id -> empty string not None", d3["vendor_id"], "")
    check("missing serial -> empty string", d3["serial"], "")


def test_stable_key():
    print("\n[stable_key: vid:pid:serial when present, deterministic fallback otherwise]")
    k = U.stable_key(U.structured_device(_FLASH, "present"))
    check("full key is usb:vid:pid:serial", k, "usb:0781:5591:4C530001234567890")
    # same device -> same key regardless of action or devname churn
    d_ins = U.structured_device(dict(_FLASH, DEVNAME="/dev/sdX"), "insert")
    check("key stable across action + devname change",
          U.stable_key(d_ins), "usb:0781:5591:4C530001234567890")
    # no serial/ids -> falls back to a NON-EMPTY deterministic key, never empty
    noid = U.structured_device({"ID_BUS": "usb", "DEVTYPE": "disk",
                                "ID_MODEL": "Weird_Stick", "DEVNAME": "/dev/sdz"}, "present")
    kf = U.stable_key(noid)
    check("fallback key is non-empty", bool(kf), True)
    check("fallback key is deterministic", kf, U.stable_key(noid))
    check("fallback differs from a full-id key", kf != k, True)


def test_list_usb_storage_is_safe_without_hardware():
    print("\n[enumeration is best-effort: returns a list, never raises, even if pyudev absent]")
    out = U.list_usb_storage()
    check("returns a list", isinstance(out, list), True)
    # every entry (if any on this host) is a structured dict with the required keys
    ok = all(isinstance(e, dict) and "vendor_id" in e and "action" in e for e in out)
    check("every entry is a structured event", ok, True)


if __name__ == "__main__":
    print("=" * 74)
    print("usb_devices — structured USB-storage collector (pure core)")
    print("=" * 74)
    test_filter_matches_usb_storage()
    test_structured_device()
    test_stable_key()
    test_list_usb_storage_is_safe_without_hardware()
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
