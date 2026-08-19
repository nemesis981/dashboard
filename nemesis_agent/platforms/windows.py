"""Windows hardware collection.

cpu%/RAM come from psutil (always available, no driver). Temperatures, fan RPM
and GPU power/fan come from the in-process LibreHardwareMonitor library
(platforms.lhm_inproc, pythonnet) -- no LHM.exe, no HTTP web server, no port 8085."""
import logging
import subprocess
import psutil

import win_run
from platforms import lhm_inproc

log = logging.getLogger("nemesis_agent.platforms.windows")


def get_hardware_metrics():
    """Windows hardware metrics.

    cpu%/RAM from psutil (proven, driverless); temps/fans/GPU merged from the
    in-process LHM library. Returns whatever it can -- an empty/partial dict never
    raises, so a missing driver or pythonnet only costs the extra sensors."""
    hw = {}
    try:
        hw["cpu_pct"] = round(psutil.cpu_percent(interval=0.3), 1)
    except Exception as e:
        log.warning("psutil cpu_percent failed: %s", e)
    try:
        hw["ram_mb"] = round(psutil.virtual_memory().used / (1024 ** 2), 0)
    except Exception as e:
        log.warning("psutil virtual_memory failed: %s", e)
    try:
        hw.update(lhm_inproc.read_sensors())
    except Exception as e:
        log.warning("in-process sensor read failed: %s", e)
    return hw


_WIN_TUNNEL = ("tailscale", "tun", "tap", "wireguard", "wg", "nordlynx", "proton", "mullvad")


def _ps(cmd, timeout=8):
    try:
        r = win_run.run(["powershell", "-NoProfile", "-Command", cmd],
                        capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "").strip()
    except Exception:
        return ""


def _route_alias(server):
    """InterfaceAlias used to reach `server`, skipping tunnel adapters (we want the
    real WiFi/ethernet link, not the Tailscale tunnel)."""
    def alias_for(target):
        return _ps("(Find-NetRoute -RemoteIPAddress '%s' -ErrorAction SilentlyContinue | "
                   "Select-Object -First 1).InterfaceAlias" % target)
    alias = alias_for(server) if server else ""
    if not alias or any(t in alias.lower() for t in _WIN_TUNNEL):
        alias = alias_for("8.8.8.8")
    if not alias or any(t in alias.lower() for t in _WIN_TUNNEL):
        return ""
    return alias


def get_lan_macs(server=None):
    """ADR 0023 LAN-MAC correlation key. NOT YET IMPLEMENTED for windows — returns []
    so the enrollment/heartbeat contract degrades cleanly (device simply is not
    MAC-correlated until this lands). Follow-up: collect the physical (non-tunnel)
    adapter MAC(s) and VERIFY ON A REAL WINDOWS VM before trusting (same discipline as
    tools/win_priv_probe.py), never ship unverified. Must never raise."""
    return []


def get_link_type(server=None):
    """'wifi' | 'ethernet' | 'unknown' for the physical link to the Nemesis server."""
    try:
        alias = _route_alias(server)
        if not alias:
            return "unknown"
        media = _ps("(Get-NetAdapter -Name '%s' -ErrorAction SilentlyContinue).PhysicalMediaType" % alias)
        if media and "802.11" in media:
            return "wifi"
        if media:
            return "ethernet"
        # Fallback: netsh wlan show interfaces lists connected wireless adapters.
        try:
            wlan = win_run.run(["netsh", "wlan", "show", "interfaces"],
                               capture_output=True, text=True, timeout=8).stdout or ""
        except Exception:
            wlan = ""
        if "State" in wlan and "connected" in wlan.lower() and alias.lower() in wlan.lower():
            return "wifi"
        return "ethernet"
    except Exception:
        return "unknown"
