"""Linux hardware collection via lm-sensors and psutil."""
import json
import logging
import subprocess
import psutil

log = logging.getLogger("nemesis_agent.platform.linux")


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception as e:
        log.debug("cmd %s failed: %s", cmd[0], e)
        return ""


def _parse_sensors_json(text):
    try:
        return json.loads(text)
    except Exception:
        return {}


def get_hardware_metrics():
    hw = {}

    # lm-sensors via JSON output
    raw = _parse_sensors_json(_run(["sensors", "-j"], timeout=8))
    cpu_temps = []
    fans = []
    for adapter_name, adapter_data in raw.items():
        if not isinstance(adapter_data, dict):
            continue
        for feature_name, feature_data in adapter_data.items():
            if not isinstance(feature_data, dict):
                continue
            for subkey, val in feature_data.items():
                if not isinstance(val, (int, float)):
                    continue
                fname = feature_name.lower()
                sk = subkey.lower()
                if "_input" not in sk and "_average" not in sk:
                    continue
                if "temp" in sk or "temp" in fname:
                    if "cpu" in adapter_name.lower() or "coretemp" in adapter_name.lower():
                        if "package" in fname or "physical" in fname:
                            hw["cpu_temp"] = round(val, 1)
                        else:
                            cpu_temps.append(val)
                    elif "nvme" in adapter_name.lower() or "nvme" in fname:
                        if "nvme_temp" not in hw:
                            hw["nvme_temp"] = round(val, 1)
                    elif "ambient" in fname or "case" in fname:
                        hw["ambient_temp"] = round(val, 1)
                elif "fan" in sk or "fan" in fname:
                    if "rpm" in sk or "_input" in sk:
                        fans.append({
                            "label": feature_name,
                            "unique_key": f"{adapter_name}_{feature_name}".replace(" ", "_"),
                            "rpm": int(val),
                        })

    if "cpu_temp" not in hw and cpu_temps:
        hw["cpu_temp"] = round(max(cpu_temps), 1)
    if fans:
        hw["fans"] = fans

    # nvidia-smi GPU metrics
    smi = _run(["nvidia-smi", "--query-gpu=temperature.gpu,fan.speed,power.draw",
                "--format=csv,noheader,nounits"], timeout=5)
    if smi.strip():
        parts = [p.strip() for p in smi.strip().split(",")]
        try:
            hw["gpu_temp"] = int(float(parts[0]))
        except (ValueError, IndexError):
            pass
        try:
            hw["gpu_fan_percent"] = int(float(parts[1]))
        except (ValueError, IndexError):
            pass
        try:
            hw["gpu_power_watts"] = float(parts[2])
        except (ValueError, IndexError):
            pass

    # psutil CPU% and RAM
    hw["cpu_pct"] = round(psutil.cpu_percent(interval=0.5), 1)
    vm = psutil.virtual_memory()
    hw["ram_mb"] = round(vm.used / (1024 ** 2), 0)
    hw["ram_pct"] = vm.percent

    return hw
