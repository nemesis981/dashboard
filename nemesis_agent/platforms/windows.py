"""Windows hardware collection via LibreHardwareMonitor HTTP API."""
import logging
import requests

LHM_URL = "http://localhost:8085/data.json"
log = logging.getLogger("nemesis_agent.platforms.windows")


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


def get_hardware_metrics():
    """Return hardware dict from LibreHardwareMonitor. Returns {} on failure."""
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
