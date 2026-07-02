"""Windows hardware collection.

cpu%/RAM come from psutil (always available, no driver). Temperatures, fan RPM
and GPU power/fan come from the in-process LibreHardwareMonitor library
(platforms.lhm_inproc, pythonnet) -- no LHM.exe, no HTTP web server, no port 8085.
The legacy HTTP scraper is retained dormant as _read_lhm_http() until Phase 3
retires the LHM.exe launch / NemesisLHM task / manifest entry."""
import logging
import re
import subprocess
import requests
import psutil

from platforms import lhm_inproc

LHM_URL = "http://localhost:8085/data.json"
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


def _find(nodes, path_parts):
    """Recursively find a node by path fragment list."""
    for node in nodes:
        if node.get("Text", "").strip() in path_parts or any(
            p in node.get("Text", "") for p in path_parts
        ):
            return node
        children = node.get("Children", [])
        if children:
            result = _find(children, path_parts)
            if result:
                return result
    return None


def _collect_all_sensors(nodes, sensors=None):
    if sensors is None:
        sensors = []
    for node in nodes:
        stype = node.get("SensorType", "")
        if stype:
            sensors.append(node)
        children = node.get("Children", [])
        if children:
            _collect_all_sensors(children, sensors)
    return sensors


def _parse_value(text):
    try:
        return float(str(text).replace(",", ".").split()[0])
    except (ValueError, AttributeError):
        return None


def _read_lhm_http():
    """DORMANT (retired in Phase 3): legacy hardware read via LibreHardwareMonitor's
    HTTP web server on :8085. Superseded by the in-process lhm_inproc reader. Kept
    only so Phase 3 removes the LHM.exe launch / NemesisLHM task / port in one clean
    commit. Returns {} on failure."""
    try:
        resp = requests.get(LHM_URL, timeout=5)
        data = resp.json()
    except Exception as e:
        log.warning("LHM fetch failed: %s", e)
        return {}

    all_sensors = _collect_all_sensors(data.get("Children", []))

    hw = {}
    cpu_temps = []
    fan_rpms = []
    gpu_temps = []
    gpu_fans = []
    gpu_powers = []

    for s in all_sensors:
        name = s.get("Text", "").lower()
        stype = s.get("SensorType", "")
        val = _parse_value(s.get("Value", ""))
        if val is None:
            continue

        if stype == "Temperature":
            if "cpu" in name and "package" in name:
                hw["cpu_temp"] = val
            elif "cpu" in name or "core" in name:
                cpu_temps.append(val)
            elif "gpu" in name:
                gpu_temps.append(val)
            elif "nvme" in name or "ssd" in name or "drive" in name:
                hw["nvme_temp"] = val
            elif "ambient" in name or "case" in name or "chassis" in name:
                hw["ambient_temp"] = val

        elif stype == "Fan":
            fan_rpms.append({"label": s.get("Text", f"Fan {len(fan_rpms)+1}"),
                              "unique_key": f"fan{len(fan_rpms)+1}", "rpm": int(val)})

        elif stype == "Load":
            if "cpu total" in name or "cpu load" in name:
                hw["cpu_pct"] = round(val, 1)
            elif "gpu core" in name and "gpu_pct" not in hw:
                hw["gpu_pct"] = round(val, 1)
            elif "memory" in name and "cpu" not in name:
                hw["ram_pct"] = round(val, 1)

        elif stype == "Data" or stype == "SmallData":
            if "memory used" in name and "ram_mb" not in hw:
                hw["ram_mb"] = round(val * 1024, 0) if val < 1000 else val

        elif stype == "Power":
            if "gpu" in name:
                gpu_powers.append(val)

        elif stype == "Control":
            if "gpu" in name and "fan" in name:
                gpu_fans.append(val)

    if "cpu_temp" not in hw and cpu_temps:
        hw["cpu_temp"] = max(cpu_temps)
    if gpu_temps:
        hw["gpu_temp"] = max(gpu_temps)
    if gpu_fans:
        hw["gpu_fan_percent"] = round(gpu_fans[0], 1)
    if gpu_powers:
        hw["gpu_power_watts"] = round(gpu_powers[0], 1)
    if fan_rpms:
        hw["fans"] = fan_rpms

    return hw


_WIN_TUNNEL = ("tailscale", "tun", "tap", "wireguard", "wg", "nordlynx", "proton", "mullvad")


def _ps(cmd, timeout=8):
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
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
            wlan = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                                  capture_output=True, text=True, timeout=8).stdout or ""
        except Exception:
            wlan = ""
        if "State" in wlan and "connected" in wlan.lower() and alias.lower() in wlan.lower():
            return "wifi"
        return "ethernet"
    except Exception:
        return "unknown"
