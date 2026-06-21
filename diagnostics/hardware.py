"""Check: current hardware metrics — CPU, RAM, disk, temperatures."""

import subprocess
import os

META = {
    "id": "hardware",
    "name": "Hardware Metrics",
    "icon": "🌡️",
    "descriptions": {
        "beginner": "Shows how hard your firewall hardware is working — CPU usage, memory, and temperatures. High temperatures or 100% CPU usage can cause slowdowns.",
        "intermediate": "Current CPU load, RAM usage, disk I/O, and hardware sensor readings from lm-sensors.",
        "pro": "/proc/loadavg, /proc/meminfo, df, lm-sensors — point-in-time snapshot.",
    },
}


def _read_proc(path: str) -> str:
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return ""


def run() -> dict:
    sections = []

    # CPU load average
    loadavg = _read_proc("/proc/loadavg").split()
    if loadavg:
        sections.append(
            f"Load average (1m/5m/15m): {loadavg[0]} / {loadavg[1]} / {loadavg[2]}\n"
            f"Running processes: {loadavg[3]}"
        )

    # CPU count for context
    try:
        with open("/proc/cpuinfo") as f:
            ncpu = sum(1 for l in f if l.startswith("processor"))
        sections.append(f"CPU cores: {ncpu}")
    except Exception:
        pass

    # Memory
    mem = {}
    for line in _read_proc("/proc/meminfo").splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            mem[k.strip()] = v.strip()
    if mem:
        total_kb  = int(mem.get("MemTotal",  "0 kB").split()[0])
        avail_kb  = int(mem.get("MemAvailable", "0 kB").split()[0])
        used_kb   = total_kb - avail_kb
        sections.append(
            f"Memory: {used_kb // 1024} MB used / {total_kb // 1024} MB total "
            f"({100 * used_kb // total_kb if total_kb else 0}% used)"
        )

    # Disk space on key paths
    try:
        r = subprocess.run(
            ["df", "-h", "/", "/home", "/var/log"],
            capture_output=True, text=True, timeout=10,
        )
        if r.stdout:
            sections.append("Disk usage:\n" + r.stdout.rstrip())
    except Exception as e:
        sections.append(f"Disk: (error: {e})")

    # Hardware sensors
    try:
        r = subprocess.run(
            ["sensors"], capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and r.stdout:
            sections.append("Hardware sensors:\n" + r.stdout.rstrip())
        else:
            sections.append("Hardware sensors: lm-sensors not installed or no data")
    except FileNotFoundError:
        sections.append("Hardware sensors: lm-sensors not installed")
    except Exception as e:
        sections.append(f"Hardware sensors: error ({e})")

    return {
        "id": META["id"],
        "name": META["name"],
        "icon": META["icon"],
        "status": "info",
        "summary": "Hardware metrics collected",
        "output": "\n\n".join(sections),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))
