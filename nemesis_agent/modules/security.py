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


def collect(platform_name: str) -> dict:
    return {
        "top_processes":                  _top_processes(),
        "network_connections":            _network_connections(),
        "login_events":                   _login_events(platform_name),
        "new_files_in_suspicious_locations": _new_suspicious_files(platform_name),
        "usb_events":                     _usb_events(platform_name),
    }


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
    events = []
    try:
        if platform_name == "Linux":
            out = win_run.run(
                ["dmesg", "--time-format", "iso"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            for line in out.splitlines()[-200:]:
                if "usb" in line.lower() and ("new" in line.lower() or "disconnect" in line.lower()):
                    events.append({"raw": line.strip()})
        elif platform_name == "Darwin":
            out = win_run.run(
                ["system_profiler", "SPUSBDataType"],
                capture_output=True, text=True, timeout=8,
            ).stdout
            for line in out.splitlines():
                if "Product ID:" in line or "Vendor ID:" in line:
                    events.append({"raw": line.strip()})
        elif platform_name == "Windows":
            out = win_run.run(
                ["wmic", "path", "Win32_USBHub", "get", "DeviceID,Description"],
                capture_output=True, text=True, timeout=8,
            ).stdout
            for line in out.splitlines()[1:]:
                if line.strip():
                    events.append({"raw": line.strip()})
    except Exception as e:
        log.debug("usb_events error: %s", e)
    return events[:10]
