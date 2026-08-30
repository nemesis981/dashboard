#!/usr/bin/env python3
"""VPN-topology matrix for `tunnel_carries_egress()`, against REAL kernel devices.

Companion to `test_forkb_topology_matrix.py`, which does the same job for Fork B's
`classify_topology()`. This one tests the DIAGNOSTICS predicate, which asks a
deliberately different question -- see the divergence note in both source files.

WHY THIS EXISTS. The predicate was twice PIA-specific without looking it:
  1. keyed on `vpn_connected`, true whenever ANY provider is up (Tailscale always is);
  2. keyed on `dst == "default"`, which PIA satisfies only via its own policy tables --
     a vanilla OpenVPN `redirect-gateway def1` client has NO default on its tunnel.
Both passed a green synthetic suite. This file feeds the predicate the same
`info_kind` and route shapes a real client produces, from a real kernel.

RUNS IN A PRIVATE NETWORK NAMESPACE, NOT ON THE HOST. Everything happens inside an
`ip netns`, so host routing, DNS and connectivity are untouched no matter what this
does or how it fails. That is a stronger isolation guarantee than a VM for this
particular question, and it needs no boot.

    sudo python3 core/vmtests/test_tunnel_predicate_matrix.py

Root is required to create netns and link devices; there is no unprivileged path on
Ubuntu 24.04+ (kernel.apparmor_restrict_unprivileged_userns=1).
"""
import json, os, subprocess, sys

NS = "nemtunmatrix"
sys.path.insert(0, "/opt/nemesis")
os.environ.setdefault("VPN_DNS_GUARD_LOG", "/tmp/vdg-tunmatrix.log")


def sh(*a):
    return subprocess.run(a, capture_output=True, text=True)


def nsx(*a):
    return sh("ip", "netns", "exec", NS, *a)


def ns_runner(cmd):
    """The runner handed to the predicate: every `ip` call inside the namespace."""
    p = nsx(*cmd)
    return (p.returncode, p.stdout)


def build(devs, routes):
    """Reset the namespace to exactly `devs` + `routes`."""
    for d in ("tun0", "wg0", "tailscale0", "eth0"):
        nsx("ip", "link", "del", d)
    nsx("ip", "route", "flush", "table", "all")
    for name, kind in devs.items():
        if kind == "wireguard":
            nsx("ip", "link", "add", name, "type", "wireguard")
        elif kind == "tun":
            nsx("ip", "tuntap", "add", "mode", "tun", name)
        else:
            nsx("ip", "link", "add", name, "type", "dummy")
        nsx("ip", "link", "set", name, "up")
    for r in routes:
        nsx(*(["ip"] + (["-6"] if ":" in r[0] else []) + ["route", "add"] + r))


def observed_kinds(devs):
    out = {}
    for name in devs:
        p = nsx("ip", "-j", "-d", "link", "show", name)
        try:
            out[name] = (json.loads(p.stdout)[0].get("linkinfo") or {}).get("info_kind")
        except Exception:
            out[name] = None
    return out


def main():
    if os.geteuid() != 0:
        print("ERROR: needs root (netns + link creation). Re-run with sudo.")
        return 2
    from modules.diagnostics import watcher as w

    sh("ip", "netns", "del", NS)
    if sh("ip", "netns", "add", NS).returncode != 0:
        print("ERROR: could not create netns")
        return 2
    nsx("ip", "link", "set", "lo", "up")

    PHYS = {"eth0": "dummy"}
    OVPN = {"eth0": "dummy", "tun0": "tun"}
    WG = {"eth0": "dummy", "wg0": "wireguard"}
    MESH = {"eth0": "dummy", "tailscale0": "tun"}

    # (label, devs, routes, expected, category)
    CASES = [
        ("no VPN (physical default only)", PHYS,
         [["default", "dev", "eth0"]], False, "confirmed"),
        ("mesh VPN, per-peer route only (Tailscale shape)", MESH,
         [["default", "dev", "eth0"], ["100.64.0.1/32", "dev", "tailscale0"]],
         False, "confirmed"),
        ("mesh VPN as EXIT NODE (default on tun-kind)", MESH,
         [["default", "dev", "tailscale0"]], True, "confirmed"),
        ("OpenVPN redirect-gateway def1 (/1 straddle, no default)", OVPN,
         [["default", "dev", "eth0"], ["0.0.0.0/1", "dev", "tun0"],
          ["128.0.0.0/1", "dev", "tun0"]], True, "confirmed"),
        ("OpenVPN half straddle only (split tunnel)", OVPN,
         [["default", "dev", "eth0"], ["0.0.0.0/1", "dev", "tun0"]],
         False, "confirmed"),
        ("OpenVPN full replace (default on tun0)", OVPN,
         [["default", "dev", "tun0"]], True, "confirmed"),
        ("OpenVPN split tunnel (specific prefix only)", OVPN,
         [["default", "dev", "eth0"], ["10.8.0.0/24", "dev", "tun0"]],
         False, "confirmed"),
        ("WireGuard full tunnel (AllowedIPs 0.0.0.0/0)", WG,
         [["default", "dev", "wg0"]], True, "confirmed"),
        ("WireGuard full tunnel via policy table (wg-quick)", WG,
         [["default", "dev", "eth0"],
          ["default", "dev", "wg0", "table", "51820"]], True, "confirmed"),
        ("WireGuard split tunnel (specific AllowedIPs)", WG,
         [["default", "dev", "eth0"], ["10.2.0.0/16", "dev", "wg0"]],
         False, "confirmed"),
        ("IPv6 straddle ::/1 + 8000::/1 on tunnel", OVPN,
         [["default", "dev", "eth0"], ["::/1", "dev", "tun0"],
          ["8000::/1", "dev", "tun0"]], True, "confirmed"),
        ("IPv6 global-unicast 2000::/3 on tunnel (PIA shape)", OVPN,
         [["default", "dev", "eth0"], ["2000::/3", "dev", "tun0"]],
         True, "confirmed"),
    ]

    print("=== tunnel_carries_egress() vs REAL kernel devices (netns %s) ===\n" % NS)
    fails, kindfails = [], []
    try:
        for label, devs, routes, expect, _cat in CASES:
            build(devs, routes)
            kinds = observed_kinds(devs)
            # PROVE THE PREMISE: the kernel must actually report the kind we think
            # we created. A dummy silently standing in for a tun would make every
            # result meaningless while looking clean.
            for name, want in devs.items():
                got = kinds.get(name)
                if want == "dummy":
                    bad = got not in (None, "dummy")
                else:
                    bad = got != want
                if bad:
                    kindfails.append("%s: %s reported kind=%r wanted %r"
                                     % (label, name, got, want))
            got = w.tunnel_carries_egress(runner=ns_runner)
            ok = got == expect
            if not ok:
                fails.append(label)
            print("  %-56s kinds=%-34s -> %-5s  %s"
                  % (label[:56], str(kinds)[:34], got,
                     "PASS" if ok else "FAIL (wanted %s)" % expect))
    finally:
        sh("ip", "netns", "del", NS)

    print()
    if kindfails:
        print("PREMISE FAILURE — the kernel did not report the kinds this test assumes:")
        for k in kindfails:
            print("   -", k)
        print("   Results above are NOT trustworthy.")
        return 1
    print("premise ok: every device reported the kernel kind the case intended")
    if fails:
        print("FAILED (%d of %d)" % (len(fails), len(CASES)))
        for f in fails:
            print("   -", f)
        return 1
    print("ALL PASS (%d real-kernel cases)" % len(CASES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
