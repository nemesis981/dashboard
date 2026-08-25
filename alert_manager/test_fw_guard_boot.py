#!/usr/bin/env python3
"""The boot reassert (ADR 0026 step 4, C4) — driven as the real script, not imported.

This is a systemd ExecStart, so its contract is its EXIT CODE: a guard that could not be
installed must leave a failed unit behind. Importing main() and inspecting a return value
would test a different thing from what systemd actually observes, so every case here runs
the real executable in a subprocess and asserts on the exit status and the journal text.

The environment is faked at the seams the script already exposes rather than by patching
its internals: NEMESIS_IPTABLES/NEMESIS_IP6TABLES point at stub binaries that emit a
chosen ruleset (or fail), and NEMESIS_ROOT points at a tree holding a stub `firewall`
module. The REAL raw_traversal does the classifying in every case -- the decision under
test is the script's, and it is made from real parsing of real ruleset text.

Run: python3 alert_manager/test_fw_guard_boot.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.environ.get("NEMESIS_ROOT", "/opt/nemesis")
SCRIPT = os.path.join(ROOT, "scripts", "nemesis-fw-guard-boot")

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


OURS = "-A PREROUTING -i tailscale0 -p tcp -m tcp --dport 80 -j DROP"
HEALTHY = "-P PREROUTING ACCEPT\n" + OURS
CASE3 = ("-P PREROUTING ACCEPT\n-N vpn\n-A PREROUTING -j vpn\n"
         + OURS + "\n-A vpn -j ACCEPT")
UNDECIDABLE = ("-P PREROUTING ACCEPT\n"
               "-A PREROUTING -i tailscale0 -p tcp -m conntrack --ctstate NEW -j ACCEPT\n"
               + OURS)


class Rig:
    """A throwaway tree: stub iptables binaries, and a stub firewall chokepoint."""

    def __init__(self, before, after=None, heal="ok"):
        self.dir = tempfile.mkdtemp(prefix="nemfwguard-")
        self.after = after if after is not None else before
        am = os.path.join(self.dir, "alert_manager")
        os.makedirs(am)
        # the REAL parser -- the classification under test must not be faked
        shutil.copy(os.path.join(ROOT, "alert_manager", "raw_traversal.py"), am)
        self.flag = os.path.join(self.dir, "healed")
        body = {
            "ok": "open(%r, 'w').close()" % self.flag,
            "raise": "open(%r, 'w').close()\n    raise RuntimeError('helper refused')" % self.flag,
            "missing": None,
        }[heal]
        if body is not None:
            with open(os.path.join(am, "firewall.py"), "w") as f:
                f.write("def reassert_port_on_interface(iface, port, proto='tcp', **kw):\n"
                        "    %s\n    return True\n" % body)
        self.bins = []
        for name in ("iptables", "ip6tables"):
            p = os.path.join(self.dir, name)
            with open(p, "w") as f:
                f.write("#!/usr/bin/env python3\n"
                        "import os, sys\n"
                        "flag = %r\n"
                        "before = %r\nafter = %r\n"
                        "if before is None:\n"
                        "    sys.stderr.write('simulated read failure\\n'); sys.exit(4)\n"
                        "sys.stdout.write(after if os.path.exists(flag) else before)\n"
                        % (self.flag, before, self.after))
            os.chmod(p, 0o755)
            self.bins.append(p)

    def run(self, armed=True):
        env = dict(os.environ)
        env["NEMESIS_ROOT"] = self.dir
        env["NEMESIS_IPTABLES"], env["NEMESIS_IP6TABLES"] = self.bins
        env["PYTHONPATH"] = ""
        if armed:
            env["NEMESIS_FW_GUARD"] = "1"
        else:
            env.pop("NEMESIS_FW_GUARD", None)
        r = subprocess.run([sys.executable, SCRIPT], capture_output=True, text=True,
                           env=env, timeout=60, cwd="/tmp")
        return r.returncode, (r.stdout + r.stderr), os.path.exists(self.flag)

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def scenario(label, before, after=None, heal="ok", armed=True):
    rig = Rig(before, after, heal)
    try:
        return rig.run(armed=armed)
    finally:
        rig.cleanup()


print("== INERT UNLESS ARMED (installing the unit must not change the network) ==")

rc, out, healed = scenario("unarmed", CASE3, armed=False)
check("unarmed exits 0 -- an unarmed box is not a failure", rc == 0, out.strip()[-160:])
check("  ...and repairs NOTHING even though the ruleset is defeated", not healed)
check("  ...and says why, rather than exiting silently", "not armed" in out, out.strip()[-120:])
rc2, _o, healed2 = scenario("armed control", CASE3, after=HEALTHY)
check("CONTROL: the SAME ruleset when armed DOES repair", healed2 and rc2 == 0)


print("\n== ALREADY EFFECTIVE: no change, no churn ==")

rc, out, healed = scenario("healthy", HEALTHY)
check("exits 0", rc == 0, out.strip()[-160:])
check("  ...makes no call to the chokepoint", not healed)
check("  ...and says so explicitly", "already effective" in out, out.strip()[-120:])


print("\n== DEFEATED: repair, then PROVE it ==")

rc, out, healed = scenario("case3 -> fixed", CASE3, after=HEALTHY)
check("exits 0 once the guard is effective", rc == 0, out.strip()[-200:])
check("  ...having actually called the chokepoint", healed)
check("  ...and reports the verification, not just the attempt",
      "verified effective" in out, out.strip()[-120:])

rc, out, healed = scenario("absent -> fixed", "-P PREROUTING ACCEPT", after=HEALTHY)
check("a missing rule is repaired too", rc == 0 and healed, out.strip()[-160:])


print("\n== A REPAIR THAT DID NOT WORK EXITS NON-ZERO ==")

# The helper returns success; the table is unchanged. systemd must see a failed unit.
rc, out, healed = scenario("repair ineffective", CASE3, after=CASE3)
check("exits NON-ZERO", rc != 0, "rc=%s" % rc)
check("  ...having tried", healed)
check("  ...and names the real problem", "NOT effective" in out, out.strip()[-200:])

rc, out, healed = scenario("helper raises", CASE3, after=HEALTHY, heal="raise")
check("a refusing helper exits NON-ZERO", rc != 0, "rc=%s" % rc)
check("  ...and says the reassert was refused", "refused" in out, out.strip()[-160:])

rc, out, healed = scenario("no chokepoint at all", CASE3, after=HEALTHY, heal="missing")
check("an unavailable chokepoint exits NON-ZERO", rc != 0, "rc=%s" % rc)
check("  ...and points at nemesis-fwd", "nemesis-fwd" in out, out.strip()[-160:])


print("\n== A FAILED READ IS NOT 'NO RULES' ==")

rc, out, healed = scenario("iptables read fails", None)
check("exits NON-ZERO rather than treating an unreadable table as empty", rc != 0, "rc=%s" % rc)
check("  ...and repairs nothing on the strength of a failed read", not healed)
check("  ...and reports the read failure", "could not read" in out, out.strip()[-200:])


print("\n== UNDECIDABLE: do not repair what may not be the problem ==")

rc, out, healed = scenario("undecidable", UNDECIDABLE, after=HEALTHY)
check("does NOT call the chokepoint", not healed, out.strip()[-200:])
check("  ...exits NON-ZERO so the unit stays visibly failed", rc != 0, "rc=%s" % rc)
check("  ...and the state it reports is UNDETERMINED",
      "UNDETERMINED" in out, out.strip()[-200:])
check("  ...matching the runtime healer, which also refuses to repair here",
      "could NOT be determined" in out, out.strip()[-200:])


print("\n== THE UNIT FILE ITSELF ==")

unit = os.path.join(ROOT, "scripts", "systemd", "nemesis-fw-guard-boot.service")
check("the unit exists", os.path.exists(unit))
u = open(unit).read() if os.path.exists(unit) else ""
#: Directive lines only. Matching raw text finds the word inside the comment that
#: EXPLAINS why a directive was left out -- so "Restart= is absent" and "a comment
#: mentions Restart=" become indistinguishable, and the check silently inverts.
directives = [ln.strip() for ln in u.splitlines()
              if ln.strip() and not ln.strip().startswith("#")]
D = "\n".join(directives)
check("it is a oneshot", "Type=oneshot" in u)
check("it is ordered after the helper it depends on", "After=nemesis-fwd.service" in u)
check("  ...with Wants=, not Requires= (a helper fault should not cascade)",
      "Wants=nemesis-fwd.service" in D and "Requires=" not in D, repr(D[:80]))
check("it does NOT wait on tailscaled (verified unnecessary, 2026-08-25)",
      "tailscaled" not in D, repr([l for l in directives if "After" in l]))
check("no Restart= -- a failed guard must stay visibly failed", "Restart=" not in D)
check("  CONTROL: the directive scan can SEE directives (or the two checks above are vacuous)",
      any(ln.startswith("Type=oneshot") for ln in directives), repr(directives[:3]))
check("it reads the env file that carries the arming flag",
      "EnvironmentFile=-/etc/nemesis.env" in u)
check("it holds only CAP_NET_ADMIN", "CapabilityBoundingSet=CAP_NET_ADMIN" in u)
check("  ...and the rest of the hardening block is present",
      all(k in u for k in ("NoNewPrivileges=yes", "ProtectSystem=strict",
                           "RestrictNamespaces=yes", "SystemCallFilter=@system-service")))
check("the ExecStart path matches the script this suite drove",
      "ExecStart=/opt/nemesis/scripts/nemesis-fw-guard-boot" in u)
check("the script is executable", os.access(SCRIPT, os.X_OK))

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
