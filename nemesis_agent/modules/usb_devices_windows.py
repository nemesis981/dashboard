r"""Structured USB-storage device collector (agent-side, WINDOWS backend).

Windows analog of usb_devices.py (the Linux/pyudev backend). It produces the
IDENTICAL structured event shape --
    {action, vendor_id, product_id, serial, model, vendor, devname}
-- so the server-side usb_events table + operator-alert path (hw_monitor) stays
platform-agnostic: ONE contract, two backends, mirroring the keyprotect
linux_tpm.py / windows_cng_tpm.py split. security._usb_events() dispatches by
platform; the server never has to know which OS produced an event.

⛔ SOURCE IS Win32_DiskDrive FILTERED TO InterfaceType='USB', not Win32_USBHub.
That is the Windows equivalent of Linux's ID_BUS=usb + DEVTYPE=disk: a whole USB
mass-storage DEVICE (flash drive, HDD, SSD), not media-removability, and not
partitions. The old code queried Win32_USBHub, which enumerates HUBS -- no storage,
no device identity -- and did it via `wmic`, which is deprecated and removed on
modern Windows 11. This backend uses PowerShell Get-CimInstance instead, run through
win_run so no console window flashes on the user's machine.

⛔ HEX VID/PID NEED A CORRELATION, they are not in the disk's own id. A USB disk's
Win32_DiskDrive.PNPDeviceID is a USBSTOR id carrying SCSI-level VEN_/PROD_ strings
(e.g. USBSTOR\DISK&VEN_SEAGATE&PROD_ONE_TOUCH&REV_0304\<serial>&0), NOT the USB
vendor/product hex. The hex VID/PID live on the PARENT USB device
(USB\VID_0bc2&PID_ab62\<usb-serial>), enumerated separately from Win32_PnPEntity and
correlated by the shared serial. When correlation fails, vid/pid come back empty and
the server's stable_key falls back to model+devname -- still stable per device, same
graceful-degradation contract as the Linux fallback. So a device is never lost for
lack of a hex id; it just keys less precisely.

PURE CORE (parse_usb_vidpid, parse_usbstor_serial, structured_from_wmi,
is_usb_storage_wmi) is where the load-bearing string parsing lives and is testable
without Windows -- see test_usb_devices_windows.py. The impure enumeration
(list_usb_storage) is a thin PowerShell/JSON wrapper, best-effort [] on any failure,
live-validated on a Win11 VM.

macOS is intentionally NOT here: no structured backend and no agent candidate for
that platform yet -- accurate scope, not a gap. It keeps the legacy raw scrape.
"""
import json
import logging
import re

log = logging.getLogger("nemesis.usb_devices_windows")

# VID/PID are 4 hex digits in a USB\VID_xxxx&PID_xxxx instance id. Case-insensitive
# match; we normalise to lowercase to match the Linux backend (udev ID_VENDOR_ID is
# lowercase hex), so the SAME physical device keys identically whichever OS saw it.
_VIDPID_RE = re.compile(r"VID_([0-9A-Fa-f]{4}).*?PID_([0-9A-Fa-f]{4})")


def _clean(v):
    return (str(v) if v is not None else "").strip()


def parse_usb_vidpid(pnp_id: str):
    """(vid, pid) lowercased hex from a USB\\VID_xxxx&PID_xxxx id, else ('','').

    Deliberately lenient about what sits between VID_ and PID_ (revision, MI_, etc.)
    and returns empties rather than raising on a non-matching string, so an
    unexpected id shape degrades to the model+devname fallback instead of crashing
    the collector."""
    m = _VIDPID_RE.search(_clean(pnp_id))
    if not m:
        return "", ""
    return m.group(1).lower(), m.group(2).lower()


def parse_usbstor_serial(pnp_id: str) -> str:
    """Instance serial from a USBSTOR id, else ''.

    A USBSTOR PNPDeviceID is BUS\\DEVICE\\INSTANCE, e.g.
    USBSTOR\\DISK&VEN_SEAGATE&PROD_ONE_TOUCH&REV_0304\\FAKESERIAL0HDD01&0 -- the instance
    (last backslash-separated field) is the serial, with a trailing '&<n>'
    interface suffix Windows appends. Strip that suffix; a device whose USB
    descriptor carries no serial gets a Windows-synthesised '&0'-style id, which we
    return as-is (non-empty, still stable per port) rather than inventing one."""
    pid = _clean(pnp_id)
    if "\\" not in pid:
        return ""
    inst = pid.rsplit("\\", 1)[1]
    # Drop the trailing interface index Windows appends ('&0', '&1', ...).
    return inst.rsplit("&", 1)[0] if "&" in inst else inst


def is_usb_storage_wmi(disk: dict) -> bool:
    """A Win32_DiskDrive row that is USB mass storage. InterfaceType=='USB' is the
    Windows analog of ID_BUS=usb + DEVTYPE=disk (Win32_DiskDrive is already
    per-DEVICE, so partitions are excluded by the class itself)."""
    return _clean(disk.get("InterfaceType")).upper() == "USB"


def _strip_usb_device_suffix(model: str) -> str:
    """Windows appends ' USB Device' to a USB disk's Model. Drop it so the stored
    model matches what a human recognises (and roughly what Linux's ID_MODEL gives)."""
    m = _clean(model)
    low = m.lower()
    return m[: -len(" usb device")].strip() if low.endswith(" usb device") else m


def structured_from_wmi(disk: dict, vidpid=("", ""), action: str = "present") -> dict:
    """Normalise a Win32_DiskDrive row (+ correlated (vid,pid)) into the shared
    structured event shape. Missing fields become '' never None -- the server builds
    dedup keys and alert text from these and a None would poison both, identical to
    the Linux backend's contract.

    Serial preference: the disk's own SerialNumber, else the serial parsed out of the
    USBSTOR PNPDeviceID -- the former is the clean USB iSerial when Windows exposes
    it, the latter is the reliable fallback."""
    pnp = _clean(disk.get("PNPDeviceID"))
    vid, pid = vidpid
    serial = _clean(disk.get("SerialNumber")) or parse_usbstor_serial(pnp)
    return {
        "action": action,
        "vendor_id": _clean(vid),
        "product_id": _clean(pid),
        "serial": serial,
        "model": _strip_usb_device_suffix(disk.get("Model")),
        "vendor": _clean(disk.get("Manufacturer")),
        # devname: the OS-stable device path, used as the key fallback when there is
        # no vid/pid/serial -- the PNPDeviceID is the most stable such handle here.
        "devname": pnp,
    }


def _correlate_vidpid(pnp_id: str, usb_entities) -> tuple:
    """Find (vid,pid) for a USBSTOR disk by matching its serial against the parent
    USB\\VID entities. Best-effort: ('','') when no confident match, which the caller
    turns into the model+devname fallback rather than a wrong id."""
    serial = parse_usbstor_serial(pnp_id)
    if not serial:
        return "", ""
    for ent in usb_entities:
        eid = _clean(ent.get("PNPDeviceID"))
        # The USB device instance id ends in the same serial the USBSTOR id carries.
        if serial and serial in eid and "VID_" in eid.upper():
            return parse_usb_vidpid(eid)
    return "", ""


# PowerShell: emit USB disks and USB\VID PnP entities as JSON on one invocation.
# -NoProfile keeps it fast/clean; ConvertTo-Json with a forced array shape so a
# single device is still a list, not a bare object.
_PS_QUERY = (
    "$d=@(Get-CimInstance Win32_DiskDrive | "
    "Where-Object {$_.InterfaceType -eq 'USB'} | "
    "Select-Object Model,SerialNumber,PNPDeviceID,InterfaceType,Manufacturer); "
    "$p=@(Get-CimInstance Win32_PnPEntity | "
    "Where-Object {$_.PNPDeviceID -like 'USB\\VID_*'} | "
    "Select-Object PNPDeviceID,Name); "
    "ConvertTo-Json -Compress -Depth 3 @{disks=$d; usb=$p}"
)


def _as_list(v):
    """PowerShell ConvertTo-Json emits a bare object for one item, a list for many,
    and $null for none. Normalise all three to a list."""
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def list_usb_storage():
    """Currently-connected USB mass-storage devices as structured events (Windows).

    Best-effort: returns [] on a non-Windows host, without PowerShell, or on any
    error -- never raises. A collector that crashes the beat is worse than one that
    reports nothing, and 'nothing' is disambiguated upstream by the consent-omit
    contract, identical to the Linux backend."""
    import os
    if os.name != "nt":
        return []
    try:
        from . import win_run  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        try:
            import win_run  # type: ignore  # noqa: PLC0415
        except Exception:  # noqa: BLE001
            return []
    try:
        proc = win_run.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_QUERY],
            capture_output=True, text=True, timeout=20,
        )
        out = (proc.stdout or "").strip()
        if not out:
            return []
        data = json.loads(out)
        disks = _as_list(data.get("disks"))
        usb_entities = _as_list(data.get("usb"))
        events = []
        for disk in disks:
            if not is_usb_storage_wmi(disk):
                continue
            vidpid = _correlate_vidpid(_clean(disk.get("PNPDeviceID")), usb_entities)
            events.append(structured_from_wmi(disk, vidpid, "present"))
        return events
    except Exception as exc:  # noqa: BLE001
        log.debug("usb_devices_windows: enumeration failed: %s", exc)
        return []
