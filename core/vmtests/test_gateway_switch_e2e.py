#!/usr/bin/env python3
"""Gateway Mode reversible switch, driven against a LIVE kernel.

Fixtures proved the transaction logic. This proves it against the real thing:
/etc/nemesis.env, a real sysctl drop-in, the real renderer, and a real nft table --
with the watcher left RUNNING, because that is the realistic condition and it is what
caught the step-2 defect.
"""
import os, subprocess, sys
sys.path.insert(0, os.environ.get("NEMESIS_CORE", "/opt/nemesis/core"))
import gateway_mode as G

ENV = "/etc/nemesis.env"
RENDER = "/opt/nemesis/scripts/nemesis-fw-render"
DROPIN = G.SYSCTL_DROPIN

def sh(*a, **kw): return subprocess.run(a, capture_output=True, text=True, **kw)

def _envget(key):
    try:
        for line in open(ENV):
            line = line.split("#", 1)[0].strip()
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip() or None
    except OSError:
        pass
    return None

def collect():
    try: dropin = open(DROPIN).read()
    except OSError: dropin = ""
    live = sh("sysctl", "-n", "net.ipv4.ip_forward").stdout.strip()
    snat = "masquerade" in sh("nft", "list", "chain", "inet", "nemesis_enforce",
                              "gateway_snat").stdout
    return {"iface": _envget("NEMESIS_GW_LAN_IFACE"), "cidr": _envget("NEMESIS_GW_LAN_CIDR"),
            "dropin": dropin, "live": live, "snat": snat}

def run(action):
    verb, a, b = action
    if verb == "config_set":
        sh("sed", "-i", "/^NEMESIS_GW_LAN_/d", ENV)
        with open(ENV, "a") as f:
            f.write("NEMESIS_GW_LAN_IFACE=%s\nNEMESIS_GW_LAN_CIDR=%s\n" % (a, b))
        return True
    if verb == "config_clear":
        return sh("sed", "-i", "/^NEMESIS_GW_LAN_/d", ENV).returncode == 0
    if verb == "render_apply":
        r = sh("sh", "-c", "NEMESIS_FW_ENFORCE=0 %s render -o /run/gw.nft" % RENDER)
        if r.returncode != 0: return False
        sh("nft", "delete", "table", "inet", "nemesis_enforce")
        return sh("nft", "-f", "/run/gw.nft").returncode == 0
    if verb == "fwd":
        if a == 1:
            try:
                with open(DROPIN, "w") as f: f.write(G.DROPIN_CONTENT)
            except OSError:
                return False          # GENUINE failure, not a mock
            return sh("sysctl", "--system").returncode == 0
        try:
            if os.path.exists(DROPIN): os.remove(DROPIN)
        except OSError:
            return False
        sh("sysctl", "--system")
        return sh("sysctl", "-w", "net.ipv4.ip_forward=0").returncode == 0
    return False

fails = []
def check(label, got, want):
    ok = got == want
    print("  %-56s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok: fails.append(label)

# ⚠ ASSERT THE BASELINE IS CLEAN BEFORE MEASURING ANYTHING AGAINST IT.
# The first run of this test compared the post-disable state against a baseline that
# already had a SNAT chain in it, and reported a failure that was entirely an artifact
# of the dirty starting point. A comparison against an unverified baseline is not a
# measurement.
print("\n[0. baseline must be CLEAN before anything is compared to it]")
before = collect()
check("baseline: no gateway config", before["iface"], None)
check("baseline: no sysctl drop-in", G.dropin_says_enabled(before["dropin"]), False)
check("baseline: forwarding off", before["live"], "0")
check("baseline: no SNAT chain", before["snat"], False)
if fails:
    print("\n  REFUSING to continue against a dirty baseline: %s" % fails)
    sys.exit(1)

print("\n[A. ENABLE via the real switch]")
r = G.switch(True, "enp0s8", "10.88.1.0/24", run, collect)
print("   ", r["reason"])
st = collect()
check("switch reported ok", r["ok"], True)
check("axis 1/4 config iface persisted", st["iface"], "enp0s8")
check("axis 2/4 sysctl drop-in says enabled", G.dropin_says_enabled(st["dropin"]), True)
check("axis 3/4 live kernel forwarding", st["live"], "1")
check("axis 4/4 SNAT chain present in nft", st["snat"], True)

print("\n[B. DISABLE via the real switch]")
r = G.switch(False, None, None, run, collect)
print("   ", r["reason"])
st = collect()
check("switch reported ok", r["ok"], True)
check("axis 1/4 config cleared", st["iface"], None)
check("axis 2/4 drop-in gone", G.dropin_says_enabled(st["dropin"]), False)
check("axis 3/4 live forwarding off", st["live"], "0")
check("axis 4/4 SNAT chain gone", st["snat"], False)
check("box is back to the pre-enable state", collect(), before)

print("\n[C. FORCED FAILURE at step 3 -- genuine, not mocked]")
# Point the drop-in at a path that cannot be written: the write really fails.
G.SYSCTL_DROPIN = "/proc/definitely-not-writable/nemesis.conf"
globals()['DROPIN'] = G.SYSCTL_DROPIN
before_c = collect()
r = G.switch(True, "enp0s8", "10.88.1.0/24", run, collect)
print("   ", r["reason"])
check("switch reported NOT ok", r["ok"], False)
check("phase is rollback", r["phase"], "rollback")
check("failed at the forwarding step", r["failed_step"], "enable_forwarding")
check("rollback reported RESTORED", r["restored"], True)
G.SYSCTL_DROPIN = DROPIN = "/etc/sysctl.d/99-nemesis-gateway.conf"
st = collect()
check("REAL KERNEL: config cleared again", st["iface"], None)
check("REAL KERNEL: SNAT chain gone again", st["snat"], False)
check("REAL KERNEL: forwarding still off", st["live"], "0")
check("REAL KERNEL: matches pre-attempt state", st, before_c)

print("\n  %s" % ("ALL PASS" if not fails else "FAILED: %s" % fails))
sys.exit(1 if fails else 0)
