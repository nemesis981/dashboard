#!/usr/bin/env python3
"""reconcile() end-to-end against a LIVE routing table: install, verify, roll back.

The matrix proved the decision layer. This proves the part that actually edits the
kernel -- and specifically that a bypass which does NOT win is removed again, which is
the one behaviour that would silently send inspected traffic through a user's VPN if it
regressed.
"""
import json, os, subprocess, sys
os.environ.setdefault("VPN_DNS_GUARD_LOG", "/tmp/vdg-e2e.log")
sys.path.insert(0, "/tmp/forkb"); sys.path.insert(0, "/opt/nemesis/core")
import forkb_policy_route as F

def sh(*a): return subprocess.run(a, capture_output=True, text=True)

def collect(what):
    if what == "topology":
        ifaces = []
        for line in sh("ip", "-4", "route", "show", "default").stdout.splitlines():
            t = line.split()
            if "dev" in t: ifaces.append(t[t.index("dev")+1])
        kinds = {}
        for i in set(ifaces):
            k = ""
            try:
                k = (json.loads(sh("ip","-d","-j","link","show",i).stdout)[0].get("linkinfo") or {}).get("info_kind","") or ""
            except Exception: pass
            if not k and os.path.exists("/sys/class/net/%s/tun_flags" % i): k = "tun"
            kinds[i] = k
        return ifaces, kinds
    if what == "rules":  return sh("ip", "rule", "show").stdout
    if what == "table":  return sh("ip", "route", "show", "table", str(F.BYPASS_TABLE_ID)).stdout
    if what == "default_route": return sh("ip", "-4", "route", "show", "default").stdout
    if what == "in_iface": return "tailscale0"
    if what == "route_get":
        return sh("ip", "route", "get", "1.1.1.1", "from", "100.64.0.5", "iif", "tailscale0").stdout
    raise AssertionError(what)

ran = []
def run(cmd):
    ran.append(" ".join(cmd)); r = sh(*cmd); return r.returncode, r.stdout

def setup():
    sh("sysctl", "-w", "net.ipv4.ip_forward=1")
    sh("ip", "link", "del", "tailscale0")
    sh("ip", "link", "add", "tailscale0", "type", "dummy")
    sh("ip", "addr", "add", "100.64.0.1/10", "dev", "tailscale0")
    sh("ip", "link", "set", "tailscale0", "up")
    sh("ip", "addr", "add", "10.77.0.1/24", "dev", "enp0s8"); sh("ip","link","set","enp0s8","up")
    sh("ip", "route", "replace", "default", "via", "10.77.0.254", "dev", "enp0s8")

def cleanup():
    for c in F.plan_teardown(): sh(*c)
    sh("ip", "rule", "del", "pref", "20")
    sh("ip", "link", "del", "tailscale0")
    sh("ip", "route", "flush", "default")
    sh("sysctl", "-w", "net.ipv4.ip_forward=0")

fails = []
def check(label, got, want):
    ok = got == want
    print("  %-58s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok: fails.append(label)

try:
    setup()
    print("\n[A. install against a live kernel, then verify it is winning]")
    del ran[:]
    r = F.reconcile(collect, run, now=1000.0, stable_since=0.0, debounce=8)
    check("action", r["action"], F.INSTALL)
    check("winning", r.get("winning"), True)
    check("ok", r["ok"], True)
    check("rule really exists in the kernel", "291" in collect("rules"), True)
    check("table really has a default", "default" in collect("table"), True)

    print("\n[B. THE ROLLBACK CASE: a competing rule out-prioritises us]")
    for c in F.plan_teardown(): sh(*c)
    # Another client installs at pref 20 -- lower than our 30, so it wins.
    sh("ip", "route", "replace", "default", "dev", "tailscale0", "table", "292")
    sh("ip", "rule", "add", "pref", "20", "from", "100.64.0.0/10", "iif", "tailscale0",
       "lookup", "292")
    del ran[:]
    r = F.reconcile(collect, run, now=1000.0, stable_since=0.0, debounce=8)
    check("detected as NOT winning", r.get("winning"), False)
    check("action records the rollback", r["action"], "install_rolled_back")
    check("reported not-ok", r["ok"], False)
    check("bypass was actually REMOVED from the kernel again",
          "lookup 291" in collect("rules"), False)
    check("...and the table was flushed", collect("table").strip(), "")

    print("\n[C. CONTROL: remove the competitor, same flow now succeeds]")
    sh("ip", "rule", "del", "pref", "20")
    sh("ip", "route", "flush", "table", "292")
    del ran[:]
    r = F.reconcile(collect, run, now=1000.0, stable_since=0.0, debounce=8)
    check("installs and wins once unopposed", r.get("winning"), True)

    print("\n[D. full-tunnel appears while the bypass is live -> immediate teardown]")
    sh("ip", "link", "add", "wgt", "type", "wireguard"); sh("ip","link","set","wgt","up")
    sh("ip", "route", "flush", "default")
    sh("ip", "route", "replace", "default", "dev", "wgt")
    del ran[:]
    r = F.reconcile(collect, run, now=1000.0, stable_since=1000.0, debounce=8)
    check("topology", r["topology"], F.FULL_TUNNEL)
    check("action is teardown, with NO debounce wait", r["action"], F.TEARDOWN)
    check("bypass gone from the kernel", "lookup 291" in collect("rules"), False)
    sh("ip", "link", "del", "wgt")
finally:
    cleanup()
    print("\n  cleaned: rules=%s table=%r" % (
        "291" in sh("ip","rule","show").stdout,
        sh("ip","route","show","table",str(F.BYPASS_TABLE_ID)).stdout.strip()))

print("\n  %s" % ("ALL PASS" if not fails else "FAILED: %s" % fails))
sys.exit(1 if fails else 0)
