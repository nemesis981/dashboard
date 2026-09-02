#!/usr/bin/env python3
"""Coverage for device_scanner._arp_devices — the /proc/net/arp parser.

Committed rather than run from a scratch script, because the interesting cases
are ones the live ARP table does not reliably contain: an INCOMPLETE entry only
exists while the kernel is waiting on an ARP reply that never comes, so a test
that waits for one to appear naturally is a test that usually does not run.

  python3 core_module/device_scanner/test_arp_parse.py
"""
import ipaddress
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "..", "alert_manager"))
import device_scanner  # noqa: E402

HEADER = "IP address       HW type     Flags       HW address            Mask     Device\n"

# Addresses are RFC 5737 documentation ranges and MACs are locally-administered
# (02:...) synthetics — Rule 8: no real LAN addressing in the public repo.
ROWS = [
    # complete, in subnet — the only ones that should survive
    "192.0.2.1        0x1         0x2         02:00:00:00:00:01     *        eth0\n",
    "192.0.2.92       0x1         0x2         02:00:00:00:00:5C     *        eth0\n",
    # INCOMPLETE: kernel asked, nothing answered. Recording this invents a device.
    "192.0.2.200      0x1         0x0         00:00:00:00:00:00     *        eth0\n",
    # complete flags but a zero MAC — belt and braces, same reasoning
    "192.0.2.201      0x1         0x2         00:00:00:00:00:00     *        eth0\n",
    # broadcast MAC — a real /proc/net/arp entry can carry ff:ff:ff:ff:ff:ff; it is
    # not a device. arp_watch already excludes it (_NULL_MACS); this parser must too.
    "192.0.2.202      0x1         0x2         FF:FF:FF:FF:FF:FF     *        eth0\n",
    # out of subnet: docker bridge / VPN / another interface
    "198.51.100.2     0x1         0x2         02:00:00:00:00:F1     *        docker0\n",
    "203.0.113.1      0x1         0x2         02:00:00:00:00:F2     *        tun0\n",
    # malformed / truncated lines must not raise
    "192.0.2.5\n",
    "\n",
    "garbage garbage\n",
]

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if not cond and detail else ""))
    if cond:
        passed += 1
    else:
        failed += 1


def main():
    net = ipaddress.ip_network("192.0.2.0/24")
    with tempfile.NamedTemporaryFile("w", suffix=".arp", delete=False) as fh:
        fh.write(HEADER)
        fh.writelines(ROWS)
        path = fh.name
    try:
        got = device_scanner._arp_devices(net, path=path)
    finally:
        os.unlink(path)

    ips = [ip for ip, _, _ in got]
    macs = [mac for _, mac, _ in got]

    check("returns exactly the two real devices", len(got) == 2, repr(got))
    check("keeps 192.0.2.1", "192.0.2.1" in ips, repr(ips))
    check("keeps 192.0.2.92", "192.0.2.92" in ips, repr(ips))
    check("drops INCOMPLETE (flags 0x0)", "192.0.2.200" not in ips, repr(ips))
    check("drops zero MAC even when flagged complete", "192.0.2.201" not in ips, repr(ips))
    check("drops broadcast MAC ff:ff:ff:ff:ff:ff", "192.0.2.202" not in ips, repr(ips))
    check("drops out-of-subnet docker neighbour", "198.51.100.2" not in ips, repr(ips))
    check("drops out-of-subnet VPN neighbour", "203.0.113.1" not in ips, repr(ips))
    check("lowercases the MAC", "02:00:00:00:00:5c" in macs, repr(macs))
    check("vendor left empty for update_devices to fill", all(v == "" for _, _, v in got), repr(got))

    # A missing file must be loud and empty, never an exception.
    check("unreadable path returns []", device_scanner._arp_devices(net, path="/nonexistent/arp") == [])

    print(f"\n  {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
