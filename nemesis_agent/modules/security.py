"""Security telemetry collection (all platforms, psutil where possible)."""
import logging
import os
import platform
import subprocess

import psutil
import win_run

log = logging.getLogger("nemesis_agent.modules.security")

_SUSPICIOUS_DIRS_LINUX = ["/tmp", os.path.expanduser("~/Downloads"), os.path.expanduser("~/Desktop")]
_SUSPICIOUS_DIRS_MAC   = ["/tmp", os.path.expanduser("~/Downloads"), os.path.expanduser("~/Desktop")]
_SUSPICIOUS_DIRS_WIN   = [os.environ.get("TEMP", "C:\\Windows\\Temp"),
                           os.path.expanduser("~\\Downloads"),
                           os.path.expanduser("~\\Desktop")]
_EXEC_EXTS_WIN  = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js"}
_EXEC_EXTS_UNIX = {".sh", ".py", ".pl", ".rb", ".elf", ""}

# Track files seen to report only NEW ones per poll
_seen_files = set()


def _etw_supersedes(platform_name):
    """True where the event-driven collector has REPLACED this poll path.

    Takes the platform from `collect()`'s own argument rather than reading
    platform.system() again: one source of truth per call, and it makes this
    testable without monkeypatching a stdlib module.

    ⚠ WINDOWS ONLY, AND THE PLATFORM CHECK IS THE WHOLE POINT (Track C Piece 6,
    2026-08-31). The build plan retires this path LAST, after Linux collection, and
    for a concrete reason: on Linux and macOS there is no event-driven collector at
    all (no netlink/sock_diag, no eBPF), so retiring it there would silently remove
    connection telemetry from those agents entirely. Windows is the only platform
    whose replacement exists and has been PROVEN against real hardware -- a real
    ETW session on Windows 11 10.0.26200.8655 delivering real events end to end.

    Two mechanisms for one kind of data is exactly the "second source of truth that
    disagrees with the first" the plan says to avoid, which is why this is a
    replacement rather than both running.

    ⚠ THE REPLACEMENT IS NOT FEATURE-EQUIVALENT, AND THAT IS A KNOWN, ACCEPTED
    TRADE -- not an oversight. This poll path resolves `process` from the pid via
    psutil; `EtwSource` does NOT populate proc_name/proc_path/proc_signed at all
    (they are parameters it never passes). The build plan calls those fields "the
    asymmetric win -- no network sensor can produce this", so retiring this path on
    Windows gives up process NAMES in exchange for event-driven completeness. The
    pid is still captured, so the field can be filled later. Tracked in PUNCHLIST;
    do not treat the absence as a bug in this function.
    """
    return (platform_name or "") == "Windows"


def _consent():
    """The gate module, imported lazily so this module still imports without it.

    Frozen and unfrozen import shapes differ (same dance as conn_collector).
    """
    try:
        import consent                                   # noqa: PLC0415
    except ImportError:                                  # pragma: no cover
        from .. import consent                           # type: ignore  # noqa: PLC0415
    return consent


def collect(platform_name: str) -> dict:
    """Collect the security-telemetry block, item by item, each behind its toggle.

    ⚠ AN ITEM THAT IS OFF IS OMITTED ENTIRELY — not sent as an empty list.
    Sending `"usb_events": []` would be indistinguishable, server-side, from "this
    device saw no USB activity", which is a different fact and one the server
    already acts on (it diffs USB and login sets against previous state). Omitting
    the key is the only shape that says "not collected" rather than "nothing
    happened". Verified safe before relying on it: every server-side read goes
    through `security.get(...)` with a default (`hw_monitor.py:2256,2535,2546`), so
    a missing key is tolerated rather than a KeyError.

    ⚠ AND FAILING TO IMPORT THE GATE MEANS COLLECT NOTHING.
    If `consent` cannot be imported we do not fall back to collecting — a gate that
    is missing must not read as a gate that said yes.
    """
    try:
        c = _consent()
    except Exception as exc:                             # noqa: BLE001
        log.warning("security: consent gate unavailable, collecting nothing: %s", exc)
        return {}

    out = {}
    if c.collection_allowed(c.ITEM_TOP_PROCESSES):
        out["top_processes"] = _top_processes()
    if c.collection_allowed(c.ITEM_CONNECTIONS) and not _etw_supersedes(platform_name):
        # The legacy poll-based collector. Rides the SAME item as the event-driven
        # one deliberately: they are two mechanisms for one kind of data, and a
        # user who switched connection recording off must not keep the poll path.
        out["network_connections"] = _network_connections()
    if c.collection_allowed(c.ITEM_LOGIN_EVENTS):
        out["login_events"] = _login_events(platform_name)
    if c.collection_allowed(c.ITEM_NEW_FILES):
        out["new_files_in_suspicious_locations"] = _new_suspicious_files(platform_name)
    if c.collection_allowed(c.ITEM_USB_EVENTS):
        out["usb_events"] = _usb_events(platform_name)
    return out


def _top_processes():
    procs = []
    try:
        for p in sorted(psutil.process_iter(["pid", "name", "cpu_percent", "username"]),
                        key=lambda x: x.info.get("cpu_percent") or 0, reverse=True)[:10]:
            procs.append({
                "pid":     p.info.get("pid"),
                "name":    p.info.get("name", ""),
                "cpu_pct": round(p.info.get("cpu_percent") or 0, 1),
                "user":    p.info.get("username", ""),
            })
    except Exception as e:
        log.debug("top_processes error: %s", e)
    return procs


def _network_connections():
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status != "ESTABLISHED":
                continue
            try:
                proc = psutil.Process(c.pid).name() if c.pid else ""
            except Exception:
                proc = ""
            conns.append({
                "local":  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                "pid":    c.pid,
                "proc":   proc,
            })
    except Exception as e:
        log.debug("network_connections error: %s", e)
    return conns[:50]


def _login_events(platform_name: str):
    events = []
    try:
        if platform_name == "Windows":
            import win32evtlog
            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            records = win32evtlog.ReadEventLog(hand, flags, 0)
            for r in records[:20]:
                if r.EventID in (4624, 4634):
                    events.append({"event_id": r.EventID, "time": str(r.TimeGenerated)})
            win32evtlog.CloseEventLog(hand)
        elif platform_name == "Darwin":
            out = win_run.run(["last", "-10"], capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines()[:10]:
                if line.strip():
                    events.append({"raw": line.strip()})
        else:
            out = win_run.run(
                ["tail", "-n", "20", "/var/log/auth.log"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            for line in out.splitlines():
                if "session opened" in line or "session closed" in line or "sudo" in line:
                    events.append({"raw": line.strip()})
    except Exception as e:
        log.debug("login_events error: %s", e)
    return events[:10]


def _new_suspicious_files(platform_name: str):
    global _seen_files
    if platform_name == "Windows":
        dirs = _SUSPICIOUS_DIRS_WIN
        exts = _EXEC_EXTS_WIN
    elif platform_name == "Darwin":
        dirs = _SUSPICIOUS_DIRS_MAC
        exts = _EXEC_EXTS_UNIX
    else:
        dirs = _SUSPICIOUS_DIRS_LINUX
        exts = _EXEC_EXTS_UNIX

    found = []
    current = set()
    for d in dirs:
        if not os.path.isdir(d):
            continue
        try:
            for fname in os.listdir(d):
                full = os.path.join(d, fname)
                current.add(full)
                _, ext = os.path.splitext(fname)
                if full not in _seen_files and (ext.lower() in exts or os.access(full, os.X_OK)):
                    found.append({"path": full, "name": fname})
        except Exception:
            pass
    _seen_files = current
    return found[:20]


def _usb_events(platform_name: str):
    # Linux + Windows: structured device identity (VID/PID/serial/model), shared with
    # the usb_inserted scan trigger AND the device-level operator alert, both emitting
    # the SAME event shape so the server is platform-agnostic. Replaces the old scrapes,
    # which carried no stable identity (Linux dmesg rolling window; Windows `wmic`
    # Win32_USBHub -- deprecated, and hubs are not storage). Darwin keeps the legacy raw
    # scrape until a structured backend exists (no agent candidate for that platform
    # yet); the server tolerates both shapes.
    if platform_name == "Linux":
        try:
            import usb_devices                          # noqa: PLC0415
        except ImportError:                             # pragma: no cover
            from . import usb_devices                   # type: ignore  # noqa: PLC0415
        return usb_devices.list_usb_storage()
    if platform_name == "Windows":
        try:
            import usb_devices_windows                  # noqa: PLC0415
        except ImportError:                             # pragma: no cover
            from . import usb_devices_windows           # type: ignore  # noqa: PLC0415
        return usb_devices_windows.list_usb_storage()

    events = []
    try:
        if platform_name == "Darwin":
            out = win_run.run(
                ["system_profiler", "SPUSBDataType"],
                capture_output=True, text=True, timeout=8,
            ).stdout
            for line in out.splitlines():
                if "Product ID:" in line or "Vendor ID:" in line:
                    events.append({"raw": line.strip()})
    except Exception as e:
        log.debug("usb_events error: %s", e)
    return events[:10]
