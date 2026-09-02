"""Structured USB-storage device collector (agent-side, Linux backend).

Upgrades the old raw-dmesg-string _usb_events into structured device identity
(VID / PID / serial / model), shared by BOTH consumers:
  * the existing usb_inserted scan trigger (hw_monitor) -- better dedup keys, and
  * the new device-level operator alert (removable-media-device-control v1).

One collector, two consumers -- not two USB paths that drift (the same principle the
net_identity consolidation applied 2026-09-02).

⛔ THE FILTER IS ID_BUS=usb + DEVTYPE=disk, NOT the kernel 'removable' flag. Measured
on a real host: a USB HDD reports removable=0, because 'removable' means removable
MEDIA (card readers/floppies), not a removable DEVICE. Filtering on it would miss most
USB storage -- flash drives, HDDs, SSDs -- which is the actual attack/exfil surface.
This is why the backend is pyudev (ID_BUS) rather than /sys/block/*/removable.

LINUX ONLY for v1. Windows/macOS backends are deferred to their own VM session (same
constraint as the clean-uninstall Windows work). On a non-Linux host or without pyudev,
list_usb_storage() returns [] -- best-effort, never raises.

CADENCE: enumerate-current-and-diff, matching the existing usb_events architecture --
the server diffs the current set against the known set to detect a NEW device. That
reuses the proven poll+diff model rather than adding a background udev monitor thread;
edge-event monitoring is a later refinement, not needed to detect a connection.
"""
import logging

log = logging.getLogger("nemesis.usb_devices")

# The udev properties we read. Kept explicit so the pure normaliser takes a plain dict
# and is testable without pyudev.
_UDEV_KEYS = ("ID_BUS", "DEVTYPE", "ID_VENDOR_ID", "ID_MODEL_ID",
              "ID_SERIAL_SHORT", "ID_MODEL", "ID_VENDOR", "DEVNAME")


def is_usb_storage(props: dict) -> bool:
    """A whole USB mass-storage device. ID_BUS=usb + DEVTYPE=disk -- deliberately NOT
    the 'removable' attribute (see module docstring: most USB storage reports
    removable=0). DEVTYPE=disk excludes partitions (one event per device, not per part)."""
    return props.get("ID_BUS") == "usb" and props.get("DEVTYPE") == "disk"


def _clean(v):
    return (v or "").strip()


def structured_device(props: dict, action: str = "present") -> dict:
    """Normalise udev properties into a structured event. Missing fields become empty
    strings, never None -- the server builds dedup keys and alert text from these and a
    None would poison both."""
    return {
        "action": action,
        "vendor_id": _clean(props.get("ID_VENDOR_ID")),
        "product_id": _clean(props.get("ID_MODEL_ID")),
        "serial": _clean(props.get("ID_SERIAL_SHORT")),
        "model": _clean(props.get("ID_MODEL")).replace("_", " "),
        "vendor": _clean(props.get("ID_VENDOR")).replace("_", " "),
        "devname": _clean(props.get("DEVNAME")),
    }


def stable_key(dev: dict) -> str:
    """A dedup key stable across re-enumeration of the SAME device. Prefers the true
    identity (vid:pid:serial); falls back to model+devname when a device exposes no
    serial/ids, so the key is always non-empty (an empty key would collapse distinct
    devices together server-side). Deliberately does NOT include `action` or churny
    fields, so the same physical device keys identically every beat."""
    vid, pid, ser = dev.get("vendor_id", ""), dev.get("product_id", ""), dev.get("serial", "")
    if vid and pid and ser:
        return "usb:%s:%s:%s" % (vid, pid, ser)
    return "usb:%s:%s" % (dev.get("model") or "?", dev.get("devname") or "?")


def list_usb_storage():
    """Currently-connected USB mass-storage devices as structured events. Best-effort:
    returns [] on a non-Linux host, without pyudev, or on any enumeration error --
    never raises (a collector that crashes the beat is worse than one that reports
    nothing, and 'nothing' is disambiguated upstream by the consent-omit contract)."""
    try:
        import pyudev
    except Exception:  # noqa: BLE001  -- not Linux, or pyudev unavailable
        return []
    try:
        ctx = pyudev.Context()
        out = []
        for d in ctx.list_devices(subsystem="block"):
            props = {k: d.properties.get(k) for k in _UDEV_KEYS}
            if is_usb_storage(props):
                out.append(structured_device(props, "present"))
        return out
    except Exception as exc:  # noqa: BLE001
        log.debug("usb_devices: enumeration failed: %s", exc)
        return []
