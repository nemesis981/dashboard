#!/usr/bin/env python3
"""nemesis-fwd interface-scoped port denial — the ALLOWLIST is the security boundary.

This op runs inside the privileged helper, so the thing worth testing is not that
it works. It is that it **cannot be turned into something bigger than its job.**

A general "drop any port on any interface" primitive would hand a compromised
dashboard a denial-of-service on the box it is supposed to protect: drop 22 on the
LAN interface and the operator loses the recovery path too. So both parameters are
allowlisted helper-side, and every test below is an attempt to get past that.

Nothing here executes iptables. `_run_iptables` is replaced by a recorder, so what
is asserted is the exact argv the helper WOULD run — which is the part that carries
the privilege.

Run: python3 alert_manager/test_fwd_iface_deny.py
"""
import os
import sys

ROOT = os.environ.get("NEMESIS_ROOT", "/opt/nemesis")
sys.path.insert(0, os.path.join(ROOT, "alert_manager"))

import nemesis_fwd as F                                            # noqa: E402

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


def denied(fn):
    try:
        fn()
    except F.Denied:
        return True
    except Exception:                                              # noqa: BLE001
        return False
    return False


# ── recorder: capture argv instead of running it ────────────────────────────
_calls = []


def fake_run(binary, *args):
    _calls.append((binary,) + args)
    # `-C` returns 1 (rule absent) so the insert path is exercised; everything
    # else returns 0. A recorder that returned 0 for `-C` would make every test
    # take the "already present" branch and assert nothing about insertion.
    return (1 if "-C" in args else 0), "", ""


F._run_iptables = fake_run


def reset():
    _calls.clear()


# ═══════════════════════════════════════════════════════════════════════════
print("\n== THE ALLOWLIST REFUSES EVERYTHING OUTSIDE THE JOB ==")

for iface, why in (("eth0", "the LAN interface — would lock the operator out"),
                   ("lo", "loopback"),
                   ("enp0s3", "a real NIC name"),
                   ("tailscale1", "a plausible near-miss"),
                   ("", "empty"),
                   ("tailscale0; rm -rf /", "a shell-injection attempt"),
                   ("../tailscale0", "path traversal shape"),
                   (None, "None"),
                   (0, "a non-string")):
    check("refuses iface %-24r (%s)" % (iface, why),
          denied(lambda i=iface: F.op_deny_port_on_interface(
              {"iface": i, "port": 80})))

for port, why in ((22, "SSH — the recovery path"),
                  (443, "HTTPS — the sanctioned remote door"),
                  (5000, "the dashboard's own loopback port"),
                  (0, "zero"), (65536, "out of range"), (-1, "negative"),
                  ("80; drop", "injection shape"), (None, "None")):
    check("refuses port %-14r (%s)" % (port, why),
          denied(lambda p=port: F.op_deny_port_on_interface(
              {"iface": "tailscale0", "port": p})))

check("refuses a non-tcp protocol",
      denied(lambda: F.op_deny_port_on_interface(
          {"iface": "tailscale0", "port": 80, "proto": "udp"})))
check("refuses empty params", denied(lambda: F.op_deny_port_on_interface({})))
check("refuses None params", denied(lambda: F.op_deny_port_on_interface(None)))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== THE ONE ALLOWED COMBINATION WORKS, AND BUILDS THE RIGHT RULE ==")

reset()
r = F.op_deny_port_on_interface({"iface": "tailscale0", "port": 80})
check("CONTROL: the allowed combination is ACCEPTED", r["port"] == 80)
check("  ...applied to BOTH v4 and v6", len(r["applied"]) == 2, repr(r["applied"]))

inserts = [c for c in _calls if "-I" in c]
check("exactly two inserts (v4 + v6)", len(inserts) == 2, repr(len(inserts)))
v4 = [c for c in inserts if c[0] == F.IPTABLES_BIN]
check("  v4 insert present", len(v4) == 1)
if v4:
    argv = v4[0]
    check("  uses the RAW table (filter would be preempted by ts-input)",
          "raw" in argv, repr(argv))
    check("  inserts at POSITION 1 (a rule after a jump can be bypassed)",
          "1" in argv and argv[argv.index("PREROUTING") + 1] == "1", repr(argv))
    check("  matches on INGRESS INTERFACE, not destination address",
          "-i" in argv and "tailscale0" in argv, repr(argv))
    check("  targets DROP", "DROP" in argv)
    check("  and never reaches a shell (argv list, no shell string)",
          all(isinstance(a, str) for a in argv))
check("v6 insert present too (a v4-only rule leaves the same path open)",
      any(c[0] == F.IP6TABLES_BIN for c in inserts))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== IDEMPOTENT: re-applying does not stack duplicate rules ==")

def already_present(binary, *args):
    _calls.append((binary,) + args)
    return 0, "", ""          # -C succeeds => rule already there


F._run_iptables = already_present
reset()
r = F.op_deny_port_on_interface({"iface": "tailscale0", "port": 80})
check("a second apply inserts NOTHING", not [c for c in _calls if "-I" in c])
check("  ...and reports it as already present", len(r["already_present"]) == 2, repr(r))
F._run_iptables = fake_run


# ═══════════════════════════════════════════════════════════════════════════
print("\n== THE REVERT IS A FIRST-CLASS OPERATION ==")

def present_then_delete(binary, *args):
    _calls.append((binary,) + args)
    return 0, "", ""


F._run_iptables = present_then_delete
reset()
r = F.op_allow_port_on_interface({"iface": "tailscale0", "port": 80})
dels = [c for c in _calls if "-D" in c]
check("removal issues a delete on both families", len(dels) == 2, repr(len(dels)))
check("  ...and reports what it actually removed", len(r["removed"]) == 2, repr(r))
check("the revert obeys the SAME allowlist (not a bypass)",
      denied(lambda: F.op_allow_port_on_interface({"iface": "eth0", "port": 80})))

def absent(binary, *args):
    return 1, "", ""


F._run_iptables = absent
r = F.op_allow_port_on_interface({"iface": "tailscale0", "port": 80})
check("removing an absent rule is reported, not an error",
      r["already_absent"] and not r["removed"], repr(r))
F._run_iptables = fake_run


# ═══════════════════════════════════════════════════════════════════════════
print("\n== WIRING: registered, and reachable only by an authorised peer ==")

check("both ops are in the OPS table",
      "deny_port_on_interface" in F.OPS and "allow_port_on_interface" in F.OPS)
check("the dashboard peer may call them",
      {"deny_port_on_interface", "allow_port_on_interface"}
      <= F.PEER_POLICY["dashboard"]["ops"])
check("the UNATTENDED alert-watcher peer may NOT",
      not ({"deny_port_on_interface", "allow_port_on_interface"}
           & F.PEER_POLICY["alert-watcher"]["ops"]),
      "an unattended peer must stay structurally incapable of firewalling ports")
check("they carry distinct audit action names",
      F.audit_action_for("deny_port_on_interface") != "deny_port_on_interface")

# The allowlists themselves must be narrow. A test that only checked membership
# would pass just as happily against an allowlist containing every interface.
check("the interface allowlist is EXACTLY one entry",
      len(F.DENY_IFACE_ALLOWED) == 1 and "tailscale0" in F.DENY_IFACE_ALLOWED,
      repr(F.DENY_IFACE_ALLOWED))
check("the port allowlist is EXACTLY one entry",
      len(F.DENY_PORT_ALLOWED) == 1 and 80 in F.DENY_PORT_ALLOWED,
      repr(F.DENY_PORT_ALLOWED))

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
