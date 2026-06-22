#!/usr/bin/env python3
"""
Nemesis Windows Agent — ongoing hardware monitor.

Reads windows_hw_map.json (created by discover.py), polls LibreHardwareMonitor
for the selected sensor IDs every poll_interval_seconds, and POSTs a pre-labelled
JSON payload to the Nemesis VM.

Prerequisites:
  - pip install requests
  - LibreHardwareMonitor running as Administrator with Web Server enabled
  - windows_hw_map.json present in the same directory (run discover.py first)

Usage:
  python agent.py [--map path/to/windows_hw_map.json]
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

MAP_FILE = os.path.join(os.path.dirname(__file__), "windows_hw_map.json")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("nemesis_agent")


def _load_map(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        sys.exit(
            f"\nSensor map not found: {path}\n"
            "Run discover.py first to create it."
        )
    except Exception as e:
        sys.exit(f"\nFailed to read sensor map: {e}")


def _flatten_sensors(node, result=None):
    """Walk the LHM JSON tree and index all sensor leaves by SensorId."""
    if result is None:
        result = {}
    sensor_id = node.get("SensorId", "")
    if sensor_id:
        result[sensor_id] = node
    for child in node.get("Children", []):
        _flatten_sensors(child, result)
    return result


def fetch_lhwm(lhwm_url: str) -> dict:
    """Fetch all sensors from LHM and return a dict keyed by SensorId."""
    url = lhwm_url.rstrip("/") + "/data.json"
    r = requests.get(url, timeout=5)
    r.raise_for_status()
    return _flatten_sensors(r.json())


def _parse_value(raw_value: str, unit: str):
    """Extract numeric value from LHM's string like '65.0 °C' or '1200 RPM'."""
    try:
        # LHM value strings: "65.0 °C", "1 200 RPM" (sometimes space as thousands sep)
        numeric = raw_value.replace(" ", "").replace(" ", "")
        for suffix in ("°C", "RPM", "%", "W", "GB", "MB", "V", "A", "MHz", "GHz"):
            numeric = numeric.replace(suffix, "")
        return float(numeric)
    except (ValueError, AttributeError):
        return None


def collect_sample(mapping: dict) -> dict:
    """Poll LHM, extract mapped sensors, return payload dict."""
    lhwm_url = mapping.get("lhwm_url", "http://localhost:8085")
    all_sensors = fetch_lhwm(lhwm_url)

    sensors_out = {}
    for role_key, info in mapping["sensors"].items():
        lhwm_id = info["lhwm_id"]
        unit    = info.get("unit", "")
        name    = info.get("name", role_key)
        node = all_sensors.get(lhwm_id)
        if node is None:
            log.warning("sensor %s (%s) not found in LHM response", role_key, lhwm_id)
            continue
        raw_val = node.get("Value", "")
        value = _parse_value(raw_val, unit)
        if value is None:
            log.warning("could not parse value %r for %s", raw_val, role_key)
            continue
        sensors_out[role_key] = {"value": value, "unit": unit, "name": name}

    return {
        "source":    "windows_agent",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
        "sensors":   sensors_out,
    }


def push_sample(payload: dict, nemesis_ip: str, nemesis_port: int) -> bool:
    """POST payload to hw_monitor listener.  Returns True on success."""
    url = f"http://{nemesis_ip}:{nemesis_port}/hw_data"
    r = requests.post(url, json=payload, timeout=10)
    r.raise_for_status()
    return True


def main():
    parser = argparse.ArgumentParser(description="Nemesis hardware agent for Windows")
    parser.add_argument("--map", default=MAP_FILE,
                        help="Path to windows_hw_map.json")
    args = parser.parse_args()

    mapping = _load_map(args.map)
    nemesis_ip   = mapping["nemesis_vm_ip"]
    nemesis_port = mapping.get("nemesis_vm_port", 5001)
    interval     = mapping.get("poll_interval_seconds", 300)

    log.info("Nemesis Windows Agent starting")
    log.info("  Nemesis target : http://%s:%d/hw_data", nemesis_ip, nemesis_port)
    log.info("  LHM source     : %s", mapping.get("lhwm_url", "http://localhost:8085"))
    log.info("  Poll interval  : %ds", interval)
    log.info("  Mapped sensors : %s", ", ".join(mapping["sensors"].keys()))

    while True:
        try:
            payload = collect_sample(mapping)
            push_sample(payload, nemesis_ip, nemesis_port)
            sensor_summary = "  ".join(
                f"{k}={v['value']}{v['unit']}"
                for k, v in payload["sensors"].items()
            )
            log.info("pushed %d sensor(s): %s", len(payload["sensors"]), sensor_summary)
        except requests.exceptions.ConnectionError as e:
            log.warning("connection error (will retry in %ds): %s", interval, e)
        except requests.exceptions.HTTPError as e:
            log.warning("HTTP error from Nemesis (will retry in %ds): %s", interval, e)
        except requests.exceptions.Timeout:
            log.warning("request timed out (will retry in %ds)", interval)
        except Exception as e:
            log.exception("unexpected error (will retry in %ds): %s", interval, e)

        time.sleep(interval)


if __name__ == "__main__":
    main()
