#!/usr/bin/env python3
"""
Nemesis Windows Agent — one-time sensor discovery.

Connects to LibreHardwareMonitor's HTTP API, lists available sensors,
and asks you to confirm which ones to monitor.  Saves the selection to
windows_hw_map.json in the same directory.

Prerequisites:
  - LibreHardwareMonitor running as Administrator with Web Server enabled
    (Options → Web Server, default port 8085)
  - pip install requests

Usage:
  python discover.py [--lhwm-url http://localhost:8085] [--nemesis-ip 192.168.x.x]
"""

import argparse
import json
import os
import sys

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

LHWM_DEFAULT_URL = "http://localhost:8085"
MAP_FILE = os.path.join(os.path.dirname(__file__), "windows_hw_map.json")

# Sensor types we care about
WANTED_TYPES = {"Temperature", "Fan", "Load", "Power", "Data"}

# Role labels shown to the user and the key written to windows_hw_map.json
ROLES = [
    ("cpu_temp",        "CPU temperature (°C)"),
    ("gpu_temp",        "GPU temperature (°C)"),
    ("nvme_temp",       "NVMe / SSD temperature (°C)"),
    ("ambient_temp",    "Ambient / case temperature (°C)"),
    ("fan1",            "Fan 1 (RPM)"),
    ("fan2",            "Fan 2 (RPM)"),
    ("fan3",            "Fan 3 (RPM)"),
    ("fan4",            "Fan 4 (RPM)"),
    ("gpu_fan_percent", "GPU fan speed (%)"),
    ("cpu_percent",     "CPU utilisation (%)"),
    ("ram_percent",     "RAM utilisation (%)"),
    ("gpu_power_watts", "GPU power draw (W)"),
]


def _flatten_sensors(node, hw_path=""):
    """Recursively walk the LHM JSON tree and yield sensor leaf dicts."""
    text = node.get("Text", "")
    sensor_id = node.get("SensorId", "")
    sensor_type = node.get("Type", "")
    value = node.get("Value", "")
    children = node.get("Children", [])

    current_path = f"{hw_path} / {text}" if hw_path else text

    if sensor_id and sensor_type in WANTED_TYPES:
        yield {
            "id":   sensor_id,
            "name": text,
            "type": sensor_type,
            "value": value,
            "path": current_path,
        }

    for child in children:
        yield from _flatten_sensors(child, current_path)


def fetch_sensors(lhwm_url: str) -> list:
    url = lhwm_url.rstrip("/") + "/data.json"
    try:
        r = requests.get(url, timeout=5)
        r.raise_for_status()
        data = r.json()
    except requests.exceptions.ConnectionError:
        sys.exit(
            f"\nCannot connect to LibreHardwareMonitor at {url}\n"
            "Make sure it is running as Administrator and the Web Server is enabled\n"
            "(Options → Web Server → check 'Run web server', default port 8085)."
        )
    except Exception as e:
        sys.exit(f"\nFailed to fetch sensor list: {e}")
    return list(_flatten_sensors(data))


def pick_sensor(sensors: list, prompt: str) -> dict | None:
    """Show a numbered sensor list and return the one the user picks, or None."""
    print(f"\n  {prompt}")
    print("  " + "-" * 60)
    for i, s in enumerate(sensors, 1):
        print(f"  {i:>3}.  [{s['type']:12}]  {s['name']:<30}  {s['value']:<12}  ({s['path']})")
    print(f"  {len(sensors)+1:>3}.  Skip / not applicable")
    while True:
        raw = input(f"  Choose (1-{len(sensors)+1}): ").strip()
        if raw.isdigit():
            n = int(raw)
            if 1 <= n <= len(sensors):
                return sensors[n - 1]
            if n == len(sensors) + 1:
                return None
        print("  Invalid choice — enter a number from the list.")


def main():
    parser = argparse.ArgumentParser(description="Nemesis sensor discovery for Windows")
    parser.add_argument("--lhwm-url",   default=LHWM_DEFAULT_URL,
                        help=f"LibreHardwareMonitor URL (default: {LHWM_DEFAULT_URL})")
    parser.add_argument("--nemesis-ip", default="",
                        help="IP of the Nemesis VM (e.g. 192.168.1.50)")
    parser.add_argument("--nemesis-port", type=int, default=5001,
                        help="Port that hw_monitor.py listens on (default: 5001)")
    parser.add_argument("--poll-interval", type=int, default=300,
                        help="Seconds between sensor pushes (default: 300)")
    args = parser.parse_args()

    print(f"\nConnecting to LibreHardwareMonitor at {args.lhwm_url} …")
    sensors = fetch_sensors(args.lhwm_url)
    if not sensors:
        sys.exit("No sensors found — is LibreHardwareMonitor running with Web Server enabled?")
    print(f"Found {len(sensors)} sensors.")

    nemesis_ip = args.nemesis_ip
    if not nemesis_ip:
        nemesis_ip = input("\nEnter the Nemesis VM IP address (e.g. 192.168.1.50): ").strip()
    if not nemesis_ip:
        sys.exit("Nemesis VM IP is required.")

    print("\n" + "=" * 66)
    print("  Map each role to a sensor.  Choose the most relevant reading.")
    print("=" * 66)

    selected = {}
    for role_key, role_label in ROLES:
        sensor = pick_sensor(sensors, f"Select sensor for: {role_label}")
        if sensor:
            # Determine unit from type
            unit_map = {
                "Temperature": "°C",
                "Fan":         "RPM",
                "Load":        "%",
                "Power":       "W",
                "Data":        "GB",
            }
            unit = unit_map.get(sensor["type"], "")
            selected[role_key] = {
                "lhwm_id": sensor["id"],
                "name":    sensor["name"],
                "unit":    unit,
            }
            print(f"  → {role_key}: {sensor['name']} ({sensor['id']})")
        else:
            print(f"  → {role_key}: skipped")

    if not selected:
        sys.exit("\nNo sensors selected — nothing to save.")

    mapping = {
        "nemesis_vm_ip":          nemesis_ip,
        "nemesis_vm_port":        args.nemesis_port,
        "poll_interval_seconds":  args.poll_interval,
        "lhwm_url":               args.lhwm_url,
        "sensors":                selected,
    }

    with open(MAP_FILE, "w") as f:
        json.dump(mapping, f, indent=2)
    print(f"\nSaved sensor map to {MAP_FILE}")
    print("Run agent.py to start pushing data to Nemesis.")


if __name__ == "__main__":
    main()
