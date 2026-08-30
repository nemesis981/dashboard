#!/usr/bin/env python3
"""Fork B VPN-topology matrix, against REAL kernel interface kinds.

Creates genuine `wireguard` and `tun` devices rather than fixtures, so the classifier
is fed the same `info_kind` a real VPN client would produce. This tests the DECISION
layer (refuse vs install) against real kernel data -- not the behaviour of any
particular VPN product, which is a different and larger question.

SSH is on a directly-connected subnet, so removing the default route cannot cut the
control channel.
"""
import json, os, subprocess, sys
os.environ.setdefault("VPN_DNS_GUARD_LOG", "/tmp/vdg-matrix.log")
sys.path.insert(0, "/tmp/forkb")
sys.path.insert(0, "/opt/nemesis/core")
import forkb_policy_route as F

def sh(*a):
    return subprocess.run(a, capture_output=True, text=True)

def observe():
    ifaces = []
    for line in sh("ip", "-4", "route", "show", "default").stdout.splitlines():
        t = line.split()
        if "dev" in t:
            ifaces.append(t[t.index("dev") + 1])
    kinds = {}
    for i in set(ifaces):
        k = ""
        try:
            k = (json.loads(sh("ip", "-d", "-j", "link", "show", i).stdout)[0]
                 .get("linkinfo") or {}).get("info_kind", "") or ""
        except Exception:
            pass
        if not k and os.path.exists("/sys/class/net/%s/tun_flags" % i):
            k = "tun"          # the sysfs fallback vpn_dns_guard documents
        kinds[i] = k
    return ifaces, kinds

def run_case(name, setup, expect_topo, expect_decision):
    for cmd in setup:
        sh(*cmd)
    ifaces, kinds = observe()
    topo, reason = F.classify_topology(ifaces, kinds)
    egress = next((i for i in ifaces if kinds.get(i, "") not in F._resolve_tunnel_kinds(None)), None)
    decision, eg, msg = F.decide(topo, egress, reason)
    ok = (topo == expect_topo and decision == expect_decision)
    print("  %-34s kinds=%-34s -> %-13s %-8s  %s" % (
        name, str({k: (v or "physical") for k, v in kinds.items()})[:34], topo, decision,
        "PASS" if ok else "FAIL (wanted %s/%s)" % (expect_topo, expect_decision)))
    return ok, msg

def main():
    saved = sh("ip", "-4", "route", "show", "default").stdout.strip()
    results = []
    try:
        sh("ip", "link", "del", "wgtest"); sh("ip", "link", "del", "tuntest")
        sh("ip", "route", "flush", "default")
        sh("ip", "addr", "add", "10.77.0.1/24", "dev", "enp0s8")
        sh("ip", "link", "set", "enp0s8", "up")

        print("\n[baseline: no tunnel at all]")
        results.append(run_case("physical default only",
            [["ip", "route", "replace", "default", "via", "10.77.0.254", "dev", "enp0s8"]],
            F.NO_VPN, F.INSTALL))

        print("\n[PRIORITY CASE: full-tunnel VPNs must REFUSE]")
        sh("ip", "link", "add", "wgtest", "type", "wireguard")
        sh("ip", "addr", "add", "10.66.0.1/24", "dev", "wgtest")
        sh("ip", "link", "set", "wgtest", "up")
        results.append(run_case("WireGuard AllowedIPs=0.0.0.0/0",
            [["ip", "route", "flush", "default"],
             ["ip", "route", "replace", "default", "dev", "wgtest"]],
            F.FULL_TUNNEL, F.DECLINE))

        sh("ip", "tuntap", "add", "mode", "tun", "tuntest")
        sh("ip", "addr", "add", "10.55.0.1/24", "dev", "tuntest")
        sh("ip", "link", "set", "tuntest", "up")
        results.append(run_case("OpenVPN redirect-gateway (tun)",
            [["ip", "route", "flush", "default"],
             ["ip", "route", "replace", "default", "dev", "tuntest"]],
            F.FULL_TUNNEL, F.DECLINE))

        results.append(run_case("both tunnels, no physical default",
            [["ip", "route", "flush", "default"],
             ["ip", "route", "replace", "default", "dev", "wgtest"],
             ["ip", "route", "append", "default", "dev", "tuntest", "metric", "50"]],
            F.FULL_TUNNEL, F.DECLINE))

        print("\n[split-tunnel: physical keeps the default -> INSTALL]")
        results.append(run_case("WireGuard up, narrow AllowedIPs",
            [["ip", "route", "flush", "default"],
             ["ip", "route", "replace", "default", "via", "10.77.0.254", "dev", "enp0s8"],
             ["ip", "route", "replace", "10.8.0.0/24", "dev", "wgtest"]],
            F.NO_VPN, F.INSTALL))

        results.append(run_case("physical default + tunnel default (metric)",
            [["ip", "route", "flush", "default"],
             ["ip", "route", "replace", "default", "via", "10.77.0.254", "dev", "enp0s8"],
             ["ip", "route", "append", "default", "dev", "wgtest", "metric", "500"]],
            F.SPLIT_TUNNEL, F.INSTALL))

        print("\n[fail closed]")
        results.append(run_case("no default route at all",
            [["ip", "route", "flush", "default"]],
            F.UNDETERMINED, F.DECLINE))
    finally:
        sh("ip", "route", "flush", "default")
        sh("ip", "link", "del", "wgtest"); sh("ip", "link", "del", "tuntest")
        for line in saved.splitlines():
            sh(*(["ip", "route", "add"] + line.split()))
        print("\n  restored default route: %r" % sh("ip", "-4", "route", "show", "default").stdout.strip())

    n_ok = sum(1 for ok, _ in results if ok)
    print("\n  %d/%d cases passed" % (n_ok, len(results)))
    return 0 if n_ok == len(results) else 1

sys.exit(main())
