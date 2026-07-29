#!/usr/bin/env python3
import sqlite3
import subprocess
import requests
import time
import os
from datetime import datetime

from database import init_devices_table

_HERE = os.path.dirname(os.path.abspath(__file__))
import nemesis_paths
DB_PATH = nemesis_paths.db_path(os.path.join(_HERE, "alerts.db"))

def lookup_mac_vendor(mac):
    """Vendor name for a MAC's OUI, or "Unknown" — never the server's error body.

    The status check is load-bearing. api.macvendors.com answers an unregistered
    OUI with 404 and a JSON error body, and the old code returned r.text
    unconditionally — so update_devices() stored that body as the device's
    friendly_name and the dashboard displayed it as the device's name. Confirmed
    in production 2026-07-29: a device was inserted named
    `{"errors":{"detail":"Not Found"}}`.

    This is not a rare edge. A locally-administered / randomised MAC (the
    privacy-MAC behaviour every modern phone ships with) has no OUI to look up by
    construction, so it 404s every time.
    """
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
        if r.status_code != 200:
            return "Unknown"
        # An empty 200 body would otherwise be stored as an empty name.
        return r.text.strip() or "Unknown"
    except:
        return "Unknown"

def scan_network():
    try:
        result = subprocess.run(
            ["sudo", "nmap", "-sn", os.environ.get("LAN_SUBNET", "192.168.1.0/24")],
            capture_output=True, text=True, timeout=60
        )
        devices = []
        lines = result.stdout.split("\n")
        current_ip = ""
        for line in lines:
            if "Nmap scan report for" in line:
                current_ip = line.split()[-1].strip("()")
            elif "MAC Address:" in line:
                parts = line.split("MAC Address:")[1].strip()
                mac = parts.split()[0].lower()
                vendor = parts.split("(")[1].rstrip(")") if "(" in parts else ""
                devices.append((current_ip, mac, vendor))
        return devices
    except Exception as e:
        print(f"Scan error: {e}")
        return []

def update_devices(devices):
    # Ensure-table-exists before any access. The `devices` table has no other
    # guaranteed creator and there is no systemd ordering, so on a fresh DB this
    # process would otherwise crash with `no such table: devices`. Canonical DDL
    # lives in database.init_devices_table() (readiness Tier A).
    init_devices_table()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    for ip, mac, vendor in devices:
        c.execute("SELECT mac, friendly_name FROM devices WHERE mac = ?", (mac,))
        existing = c.fetchone()
        if existing:
            c.execute("UPDATE devices SET ip = ? WHERE mac = ?", (ip, mac))
            print(f"Updated IP for {existing[1]}: {ip}")
        else:
            if not vendor or vendor == "Unknown":
                vendor = lookup_mac_vendor(mac)
                time.sleep(1)
            now = datetime.now().isoformat()
            c.execute("""INSERT INTO devices 
                (mac, ip, friendly_name, device_type, notes, trusted)
                VALUES (?, ?, ?, ?, ?, 0)""",
                (mac, ip, vendor, "Unknown", f"Auto-discovered {now}"))
            print(f"New device found: {ip} - {mac} - {vendor}")
    conn.commit()
    conn.close()

def run():
    print("Nemesis Device Scanner starting...")
    while True:
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Scanning network...")
        devices = scan_network()
        print(f"Found {len(devices)} devices with MAC addresses")
        update_devices(devices)
        print("Sleeping 5 minutes...")
        time.sleep(300)

if __name__ == "__main__":
    run()
