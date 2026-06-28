"""macOS hardware collection via powermetrics and psutil."""
import logging
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
