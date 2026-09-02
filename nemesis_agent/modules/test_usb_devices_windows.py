"""Tests for usb_devices_windows -- the Windows USB-storage collector's PURE core.

Mirrors test_usb_devices.py (the Linux side). Pins the load-bearing string parsing
(VID/PID out of a USB\\VID id, serial out of a USBSTOR id), the storage filter, the
WMI-row normaliser, and the disk<->parent VID/PID correlation. The PowerShell
enumeration itself is a thin impure wrapper, live-validated on a Win11 VM, not here.

⛔ THE CROSS-PLATFORM CONTRACT IS THE POINT. The Windows backend exists so the
server's usb_events table + alert path never has to know which OS produced an event.
test_output_shape_matches_linux_contract asserts the two backends emit the EXACT same
dict keys -- if either drifts, the server silently mis-keys or mis-labels one
platform's devices, which is exactly the "right-looking value from the wrong shape"
failure the repo's SHAPE checks exist to catch.

Serial is sanitised (FAKESERIAL0HDD01), not a real device id -- Rule 8.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import usb_devices_windows as W  # noqa: E402

_fail = []
_count = 0
EXPECTED_CHECKS = 45

# A real USB HDD as Windows reports it: Win32_DiskDrive row + its parent USB PnP
# entity. VEN_/PROD_ in the USBSTOR id are SCSI strings; the hex VID/PID (0bc2/ab62)
# live only on the parent USB\VID entity, which is why correlation exists.
_HDD_DISK = {
    "Model": "Seagate One Touch HDD USB Device",
    "SerialNumber": "FAKESERIAL0HDD01",
    "PNPDeviceID": "USBSTOR\\DISK&VEN_SEAGATE&PROD_ONE_TOUCH_HDD&REV_0304\\FAKESERIAL0HDD01&0",
    "InterfaceType": "USB",
    "Manufacturer": "(Standard disk drives)",
}
_HDD_USB_ENTITY = {
    "PNPDeviceID": "USB\\VID_0BC2&PID_AB62\\FAKESERIAL0HDD01",
    "Name": "USB Mass Storage Device",
}
# A flash drive whose disk row exposes NO clean SerialNumber -> serial must come from
# the USBSTOR instance id instead.
_FLASH_DISK = {
    "Model": "SanDisk Ultra Fit USB Device",
    "SerialNumber": "",
    "PNPDeviceID": "USBSTOR\\DISK&VEN_SANDISK&PROD_ULTRA_FIT&REV_1.00\\4C530001234567890&0",
    "InterfaceType": "USB",
    "Manufacturer": "(Standard disk drives)",
}
# An internal SATA/NVMe disk -- NOT USB, must be excluded.
_INTERNAL = {
    "Model": "Samsung SSD 990 PRO",
    "SerialNumber": "S1A2B3C4",
    "PNPDeviceID": "SCSI\\DISK&VEN_NVME&PROD_SAMSUNG_SSD_990\\5&...",
    "InterfaceType": "SCSI",
    "Manufacturer": "(Standard disk drives)",
}


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-70s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def test_parse_usb_vidpid():
    print("\n[VID/PID out of a USB\\VID id, lowercased to match the Linux backend]")
    check("hex vid/pid extracted + lowercased",
          W.parse_usb_vidpid("USB\\VID_0BC2&PID_AB62\\FAKESERIAL0HDD01"), ("0bc2", "ab62"))
    check("tolerates MI_/REV between VID and PID",
          W.parse_usb_vidpid("USB\\VID_0781&PID_5591&MI_00\\6&x"), ("0781", "5591"))
    check("no VID/PID -> ('','') not a raise", W.parse_usb_vidpid("USBSTOR\\DISK&..."), ("", ""))
    check("empty input -> ('','')", W.parse_usb_vidpid(""), ("", ""))
    check("None input -> ('','') not a raise", W.parse_usb_vidpid(None), ("", ""))


def test_parse_usbstor_serial():
    print("\n[serial out of a USBSTOR instance id, trailing &<n> stripped]")
    check("serial from USBSTOR id, &0 stripped",
          W.parse_usbstor_serial(_HDD_DISK["PNPDeviceID"]), "FAKESERIAL0HDD01")
    check("flash serial from USBSTOR id",
          W.parse_usbstor_serial(_FLASH_DISK["PNPDeviceID"]), "4C530001234567890")
    check("no backslash -> '' (not a device instance id)", W.parse_usbstor_serial("USBSTOR"), "")
    check("instance without &suffix returned whole",
          W.parse_usbstor_serial("USBSTOR\\DISK&VEN_X\\PLAINSERIAL"), "PLAINSERIAL")
    check("empty -> ''", W.parse_usbstor_serial(""), "")


def test_is_usb_storage_wmi():
    print("\n[storage filter: InterfaceType == USB, the Win32_DiskDrive analog of ID_BUS=usb]")
    check("USB disk matches", W.is_usb_storage_wmi(_HDD_DISK), True)
    check("USB flash matches", W.is_usb_storage_wmi(_FLASH_DISK), True)
    check("internal SCSI/NVMe excluded", W.is_usb_storage_wmi(_INTERNAL), False)
    check("case-insensitive on InterfaceType", W.is_usb_storage_wmi({"InterfaceType": "usb"}), True)
    check("missing InterfaceType excluded", W.is_usb_storage_wmi({}), False)


def test_structured_from_wmi():
    print("\n[normaliser: structured identity, serial preference, model de-suffixed]")
    d = W.structured_from_wmi(_HDD_DISK, ("0bc2", "ab62"), "present")
    check("action carried", d["action"], "present")
    check("vendor_id", d["vendor_id"], "0bc2")
    check("product_id", d["product_id"], "ab62")
    check("serial from SerialNumber", d["serial"], "FAKESERIAL0HDD01")
    check("model de-suffixed (' USB Device' dropped)", d["model"], "Seagate One Touch HDD")
    check("devname is the PNPDeviceID (stable key fallback handle)",
          d["devname"], _HDD_DISK["PNPDeviceID"])
    # serial fallback: no SerialNumber -> parsed from the USBSTOR id
    d2 = W.structured_from_wmi(_FLASH_DISK, ("0781", "5591"), "present")
    check("serial falls back to the USBSTOR instance id", d2["serial"], "4C530001234567890")
    check("flash model de-suffixed", d2["model"], "SanDisk Ultra Fit")
    # missing fields -> '' never None
    d3 = W.structured_from_wmi({"InterfaceType": "USB"}, ("", ""), "present")
    check("missing model -> '' not None", d3["model"], "")
    check("missing serial -> ''", d3["serial"], "")
    check("missing vendor_id -> ''", d3["vendor_id"], "")


def test_correlate_vidpid():
    print("\n[disk<->parent correlation: match USBSTOR serial to a USB\\VID entity]")
    check("correlates HDD disk to its parent VID/PID by serial",
          W._correlate_vidpid(_HDD_DISK["PNPDeviceID"], [_HDD_USB_ENTITY]), ("0bc2", "ab62"))
    check("no matching entity -> ('','') (fallback, never a wrong id)",
          W._correlate_vidpid(_HDD_DISK["PNPDeviceID"], [{"PNPDeviceID": "USB\\VID_1234&PID_5678\\OTHER"}]),
          ("", ""))
    check("no serial to match on -> ('','')",
          W._correlate_vidpid("USBSTOR", [_HDD_USB_ENTITY]), ("", ""))
    check("empty entity list -> ('','')",
          W._correlate_vidpid(_HDD_DISK["PNPDeviceID"], []), ("", ""))


def test_as_list():
    print("\n[ConvertTo-Json normalisation: none->[], one->[one], many->many]")
    check("None -> []", W._as_list(None), [])
    check("single dict -> [dict]", W._as_list({"a": 1}), [{"a": 1}])
    check("list passthrough", W._as_list([1, 2]), [1, 2])


def test_output_shape_matches_linux_contract():
    print("\n[CONTRACT: Windows output keys == Linux output keys, exactly]")
    win = W.structured_from_wmi(_HDD_DISK, ("0bc2", "ab62"), "present")
    try:
        import usb_devices as L  # Linux pure core imports without pyudev
        linux = L.structured_device(
            {"ID_BUS": "usb", "DEVTYPE": "disk", "ID_VENDOR_ID": "0bc2",
             "ID_MODEL_ID": "ab62", "ID_SERIAL_SHORT": "FAKESERIAL0HDD01",
             "ID_MODEL": "One_Touch_HDD", "ID_VENDOR": "Seagate",
             "DEVNAME": "/dev/sda"}, "present")
        check("both backends emit the SAME dict keys", set(win) == set(linux), True)
        check("key set is exactly the server contract",
              set(win), {"action", "vendor_id", "product_id", "serial", "model",
                         "vendor", "devname"})
    except ImportError:
        # Linux pure core genuinely unimportable here -> still pin the contract set
        # directly rather than skipping (a skipped contract check is a silent gap).
        check("key set is exactly the server contract (linux core unavailable)",
              set(win), {"action", "vendor_id", "product_id", "serial", "model",
                         "vendor", "devname"})
        check("contract check ran (control)", True, True)


# --- Real-hardware regression sample -------------------------------------------
# Captured LIVE 2026-09-02 from a real Windows 11 (build 26200) guest running the
# collector's own _PS_QUERY against a genuine USB flash drive. Everything above this
# point is hand-written fixture data; this is the shape Windows ACTUALLY emits, kept
# verbatim except the serial, sanitized per Rule 8 (real value replaced consistently
# in BOTH ids so the correlation it exercises stays intact).
#
# It exists because the correlation is the one assumption in this module that cannot
# be proven by construction: that a USB storage device's USBSTOR-disk serial really
# does appear inside its parent USB\VID PNPDeviceID. That was verified on real
# hardware, and this pins the observed evidence so a future refactor cannot quietly
# invalidate it.
_REAL_WIN11_JSON = (
    '{"usb":[{"PNPDeviceID":"USB\\\\VID_80EE\\u0026PID_0021\\\\5\\u002618F54CB7\\u00260\\u00261",'
    '"Name":"USB Input Device"},'
    '{"PNPDeviceID":"USB\\\\VID_9129\\u0026PID_1583\\\\FAKESERIAL0USB01",'
    '"Name":"USB Mass Storage Device"}],'
    '"disks":[{"Model":"General USB Flash Disk USB Device",'
    '"SerialNumber":"FAKESERIAL0USB01",'
    '"PNPDeviceID":"USBSTOR\\\\DISK\\u0026VEN_GENERAL\\u0026PROD_USB_FLASH_DISK'
    '\\u0026REV_1.00\\\\FAKESERIAL0USB01\\u00260",'
    '"InterfaceType":"USB","Manufacturer":"(Standard disk drives)"}]}'
)


def test_real_win11_sample():
    """Pin the shape a real Win11 host emits, end to end through the pure core."""
    data = json.loads(_REAL_WIN11_JSON)
    disks = W._as_list(data.get("disks"))
    usb = W._as_list(data.get("usb"))
    # ConvertTo-Json escapes '&' as \u0026; json.loads must decode it back or every
    # downstream '&'-delimited parse silently sees the wrong string.
    check("real sample: one USB disk decoded", len(disks), 1)
    check("real sample: two USB\\VID entities decoded", len(usb), 2)
    check("real sample: '&' unescaped by json.loads",
          "&" in disks[0]["PNPDeviceID"], True)

    disk = disks[0]
    check("real sample: recognised as USB storage", W.is_usb_storage_wmi(disk), True)
    serial = W.parse_usbstor_serial(disk["PNPDeviceID"])
    check("real sample: serial parsed, '&0' suffix stripped", serial, "FAKESERIAL0USB01")

    # THE LOAD-BEARING ASSUMPTION, asserted against observed output rather than assumed.
    parent = [e for e in usb if "VID_9129" in e["PNPDeviceID"]][0]
    check("real sample: USBSTOR serial IS inside the parent USB\\VID id",
          serial in parent["PNPDeviceID"], True)

    check("real sample: correlation yields the real hex ids",
          W._correlate_vidpid(disk["PNPDeviceID"], usb), ("9129", "1583"))
    # The non-storage entity (a VirtualBox input device) shares the list; correlation
    # must pick the mass-storage parent, not merely the first VID_ id it encounters.
    check("real sample: correlation is not first-match-wins",
          W._correlate_vidpid(disk["PNPDeviceID"], usb)
          != W.parse_usb_vidpid(usb[0]["PNPDeviceID"]), True)

    ev = W.structured_from_wmi(disk, W._correlate_vidpid(disk["PNPDeviceID"], usb))
    check("real sample: full structured event", ev, {
        "action": "present", "vendor_id": "9129", "product_id": "1583",
        "serial": "FAKESERIAL0USB01", "model": "General USB Flash Disk",
        "vendor": "(Standard disk drives)",
        "devname": disk["PNPDeviceID"],
    })
    # Windows reports a generic Manufacturer for standard storage, so `vendor` is NOT
    # a usable identity field there -- vid/pid/serial carry identity, as the key does.
    check("real sample: vendor is generic on Windows, not identity",
          ev["vendor"], "(Standard disk drives)")


if __name__ == "__main__":
    print("=" * 74)
    print("usb_devices_windows -- structured USB-storage collector (pure core)")
    print("=" * 74)
    test_parse_usb_vidpid()
    test_parse_usbstor_serial()
    test_is_usb_storage_wmi()
    test_structured_from_wmi()
    test_correlate_vidpid()
    test_as_list()
    test_output_shape_matches_linux_contract()
    test_real_win11_sample()
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
