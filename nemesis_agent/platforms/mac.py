"""macOS hardware collection via powermetrics and psutil."""
import logging
import re
import subprocess
import psutil

log = logging.getLogger("nemesis_agent.platforms.mac")


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception as e:
        log.debug("cmd %s failed: %s", cmd[0], e)
        return ""


def get_hardware_metrics():
    hw = {}

    # powermetrics for CPU die temp and package power (requires sudo on some macOS)
    pm = _run(["sudo", "-n", "powermetrics", "--samplers", "cpu_power,thermal",
               "-n", "1", "-i", "1000"], timeout=8)
    for line in pm.splitlines():
        ll = line.lower()
        if "cpu die temperature" in ll or "package power" in ll:
            try:
                val = float(line.split(":")[1].strip().split()[0])
                if "temperature" in ll:
                    hw["cpu_temp"] = val
                elif "power" in ll:
                    hw["gpu_power_watts"] = val  # proxy
            except (IndexError, ValueError):
                pass

    # psutil for CPU% and RAM
    hw["cpu_pct"] = round(psutil.cpu_percent(interval=0.5), 1)
    vm = psutil.virtual_memory()
    hw["ram_mb"] = round(vm.used / (1024 ** 2), 0)
    hw["ram_pct"] = vm.percent

    # GPU temp via system_profiler (best effort, Metal/IOKit path varies)
    sp = _run(["system_profiler", "SPDisplaysDataType"], timeout=8)
    for line in sp.splitlines():
        if "temperature" in line.lower():
            try:
                hw["gpu_temp"] = float(line.split(":")[1].strip().split()[0])
            except (IndexError, ValueError):
                pass
            break

    return hw


_MAC_TUNNEL = ("utun", "tailscale", "tun", "tap", "ppp", "ipsec")


def _route_iface_mac(server):
    """Physical interface used to reach `server`, skipping tunnel devices."""
    def iface_for(target):
        out = _run(["route", "-n", "get", str(target)], timeout=5) or ""
        m = re.search(r"interface:\s*(\S+)", out)
        return m.group(1) if m else None
    iface = iface_for(server) if server else None
    if not iface or iface.startswith(_MAC_TUNNEL):
        iface = iface_for("8.8.8.8")
    if not iface or iface.startswith(_MAC_TUNNEL):
        return None
    return iface


def get_lan_macs(server=None):
    """ADR 0023 LAN-MAC correlation key. NOT YET IMPLEMENTED for mac — returns []
    so the enrollment/heartbeat contract degrades cleanly (device simply is not
    MAC-correlated until this lands). Follow-up: collect the physical (non-tunnel)
    adapter MAC(s) and VERIFY ON A REAL MAC VM before trusting (same discipline as
    tools/win_priv_probe.py), never ship unverified. Must never raise."""
    return []


def get_link_type(server=None):
    """'wifi' | 'ethernet' | 'unknown' for the physical link to the Nemesis server."""
    try:
        iface = _route_iface_mac(server)
        if not iface:
            return "unknown"
        ports = _run(["networksetup", "-listallhardwareports"]) or ""
        cur = None
        for line in ports.splitlines():
            line = line.strip()
            if line.startswith("Hardware Port:"):
                cur = line.split(":", 1)[1].strip()
            elif line.startswith("Device:") and line.split(":", 1)[1].strip() == iface:
                return "wifi" if ("Wi-Fi" in (cur or "") or "AirPort" in (cur or "")) else "ethernet"
        return "ethernet"
    except Exception:
        return "unknown"
