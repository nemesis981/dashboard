#!/usr/bin/env python3
import ipaddress
import sqlite3
import subprocess
import requests
import sys
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

def _loud(msg):
    """Diagnostics that must actually reach the journal.

    stdout is block-buffered when it is a pipe (which it is under systemd), and
    this process then sleeps for five minutes — so an unflushed error can sit in
    the buffer indefinitely. A warning nobody sees is the whole reason the
    breakage below went unnoticed; these go to stderr, flushed.
    """
    print(msg, file=sys.stderr, flush=True)


def _arp_devices(net, path="/proc/net/arp"):
    """(ip, mac, vendor) for every address the KERNEL resolved inside `net`.

    Read from /proc/net/arp rather than shelling out to `ip neigh`: a file read
    needs no subprocess, no iproute2 binary inside the sandbox, and no socket at
    all — so nothing here depends on the unit's RestrictAddressFamilies list.

    Vendor is left empty on purpose. nmap's "(eero)" annotation came from its own
    OUI table and only appears on the privileged ARP scan we no longer run;
    update_devices() already falls back to lookup_mac_vendor() for any device
    whose vendor is empty, and only for genuinely new MACs.
    """
    try:
        with open(path) as fh:
            rows = fh.readlines()[1:]          # drop the column header
    except OSError as e:
        _loud(f"Scan error: cannot read {path}: {e}")
        return []

    devices = []
    for row in rows:
        parts = row.split()
        if len(parts) < 4:
            continue
        ip, flags, mac = parts[0], parts[2], parts[3].lower()
        # Flags 0x0 is an INCOMPLETE entry — the kernel asked and nothing
        # answered, so the MAC reads 00:00:00:00:00:00. Recording that would
        # invent a device that does not exist. The broadcast MAC can also appear
        # in /proc/net/arp and is likewise not a device — arp_watch excludes both
        # via _NULL_MACS; keep this parser in agreement with it (Window 3 sweep,
        # 2026-09-02: this was the one real gap between the two ARP parsers).
        if flags == "0x0" or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            continue
        try:
            if ipaddress.ip_address(ip) not in net:
                continue                        # docker / VPN / other-interface neighbours
        except ValueError:
            continue
        devices.append((ip, mac, ""))
    return devices


def scan_network():
    """Discover LAN devices WITHOUT any privilege: sweep, then read the kernel's
    ARP table.

    Why not `sudo nmap`, which this used to do: the unit sets
    NoNewPrivileges=yes, which makes the kernel ignore setuid — so sudo could not
    elevate and every scan returned nothing, silently, because the old code never
    checked the return code. Why not the AmbientCapabilities=CAP_NET_RAW the unit
    used to carry instead: measured 2026-07-29, nmap gates raw-socket scanning on
    uid, not on the capability, so an ambient CAP_NET_RAW produced no MAC
    addresses either.

    So the MAC addresses are taken from where they already are. An unprivileged
    `nmap -sn` still has to reach every host, and the kernel must ARP-resolve each
    on-link address to do that — populating /proc/net/arp as a side effect. That
    needs no privilege at all, which is why CAP_NET_RAW comes off the unit.

    PRECONDITION, verified against this install before relying on it (2026-07-29):
    LAN_SUBNET must be a single L2 broadcast domain, or ARP cannot see the far end
    of it. Confirm with `ip route` — the whole of LAN_SUBNET must appear as one
    `scope link` route on one interface. If it is ever changed to something routed
    or segmented, this silently stops seeing the off-segment half, because a ping
    sweep still reaches those hosts but the local ARP table never learns them.

    Bonus, not a compromise: this finds MORE than the old parse did. A device that
    ignores nmap's probes still answers ARP — measured on the install LAN, roughly
    double the hosts nmap's own "N hosts up" line reported.
    """
    subnet = os.environ.get("LAN_SUBNET", "192.168.1.0/24")
    # Validated BEFORE the sweep, not after: an unparseable LAN_SUBNET is a
    # configuration error, and reporting it as "scan found nothing" (which is
    # what checking it later looks like) is the exact failure mode this rewrite
    # exists to remove.
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        _loud(f"Scan error: LAN_SUBNET is not a valid network: {subnet!r} — no scan attempted")
        return []

    try:
        result = subprocess.run(
            ["nmap", "-sn", subnet],
            capture_output=True, text=True, timeout=60
        )
    except subprocess.TimeoutExpired:
        _loud(f"Scan error: nmap -sn {subnet} exceeded its 60s timeout — no scan this cycle")
        return []
    except OSError as e:
        _loud(f"Scan error: could not execute nmap: {e}")
        return []

    # Checked explicitly. The old code ignored this, so a scan that could not run
    # at all was indistinguishable from a LAN with nothing on it.
    if result.returncode != 0:
        _loud(f"Scan error: nmap -sn {subnet} exited {result.returncode}: "
              f"{(result.stderr or '').strip()[:200]}")
        return []

    devices = _arp_devices(net)
    if not devices:
        # Not fatal — but a sweep that completes and resolves nothing on a LAN
        # that is supposed to have devices on it is a symptom, not a quiet zero.
        _loud(f"Scan warning: nmap -sn {subnet} completed but the ARP table holds "
              f"no resolved addresses in that range — discovery found nothing")
    return devices

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
    # Line-buffer stdout before anything is printed.
    #
    # systemd gives this process a PIPE for stdout, not a tty, so Python
    # block-buffers it at 8192 bytes — and this loop then sleeps 300s between
    # cycles. At ~89 bytes of output per cycle that is ~92 cycles, roughly SEVEN
    # AND A HALF HOURS, before the first line reaches the journal. Measured
    # 2026-07-29: a scan ran, found devices and wrote them to the database while
    # `journalctl -u device-scanner` stayed completely empty.
    #
    # _loud() already writes diagnostics to stderr with flush=True, but a healthy
    # cycle never calls it — so without this line the SUCCESS path is invisible,
    # which is indistinguishable from the service being dead. That is the same
    # failure mode that hid the broken `sudo nmap` scan for weeks.
    #
    # (device_scanner is the only Nemesis daemon that logs via print(); the other
    # five use `logging`, whose handlers flush per record. Converting this one to
    # match is tracked separately.)
    sys.stdout.reconfigure(line_buffering=True)

    print("Nemesis Device Scanner starting...")
    while True:
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Scanning network...")
        devices = scan_network()
        print(f"Found {len(devices)} devices with MAC addresses")
        update_devices(devices)
        print("Sleeping 5 minutes...")
        time.sleep(300)

if __name__ == "__main__":
    # Assert the privilege boundary against the kernel before doing any work.
    # Inert until the migrated unit sets NEMESIS_EXPECT_USER (see nemesis_privsep).
    #
    # Added 2026-07-31, with the nemesis-scan cutover. Until then this service was
    # the only de-privileged daemon whose unit CLAIMED attestation ("Activates
    # runtime privilege attestation") while the code never imported nemesis_privsep
    # and never read NEMESIS_EXPECT_USER — so the variable was inert and the claim
    # was false. systemd's hardening fails open, which is precisely why the unit
    # file is not evidence of confinement; only this call is.
    import nemesis_privsep
    nemesis_privsep.attest_from_env("device-scanner")
    run()
