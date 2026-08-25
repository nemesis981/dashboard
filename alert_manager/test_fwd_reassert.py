#!/usr/bin/env python3
"""reassert_port_deny_on_interface — the repair must never open the port it protects.

This op runs unattended, as root, on the rule that is the only thing keeping plain
HTTP off the tailnet. Two properties matter more than "it works":

  1. There is no instant during a repair at which no matching rule exists. A
     delete-then-reinsert implementation would open the port -- briefly, on the exact
     interface and port the rule exists to protect, during a repair prompted by the
     guard having already failed once.
  2. It cannot be made to REMOVE protection. It is granted to an unattended peer, so
     the argument for that grant is that no input produces an unprotected end state.

Argv assertions alone cannot show either. So the runner here is a STATEFUL FAKE TABLE
that applies the inserts and deletes it is given and snapshots the ruleset after every
mutation -- letting the tests assert what was true at each intermediate step, not just
what commands were issued.

Run: python3 alert_manager/test_fwd_reassert.py
"""
import os
import sys

ROOT = os.environ.get("NEMESIS_ROOT", "/opt/nemesis")
sys.path.insert(0, os.path.join(ROOT, "alert_manager"))

import nemesis_fwd as F                                             # noqa: E402
import raw_traversal as rt                                          # noqa: E402

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
    except Exception:                                               # noqa: BLE001
        return False
    return False


#: The rule as `-S` reads it BACK (with -m tcp), which is what the op parses.
OURS = ["-i", "tailscale0", "-p", "tcp", "-m", "tcp", "--dport", "80", "-j", "DROP"]
OTHER = ["-j", "piavpn.PREROUTING"]
ACCEPT_ABOVE = ["-i", "tailscale0", "-p", "tcp", "-m", "tcp", "--dport", "80", "-j", "ACCEPT"]


class FakeTable:
    """Applies the commands it is given, per binary, and records history."""

    def __init__(self, initial):
        self.rules = {F.IPTABLES_BIN: [list(r) for r in initial],
                      F.IP6TABLES_BIN: [list(r) for r in initial]}
        self.calls = []
        #: presence of a matching rule after every mutation, per binary
        self.presence = {F.IPTABLES_BIN: [], F.IP6TABLES_BIN: []}

    def _snapshot(self, binary):
        self.presence[binary].append(
            any(rt.rule_matches_spec(r, "tailscale0", "tcp", 80) for r in self.rules[binary]))

    def run(self, binary, *args):
        self.calls.append((binary,) + args)
        a = list(args)
        if "-S" in a:
            body = "\n".join("-A PREROUTING " + " ".join(r) for r in self.rules[binary])
            return 0, "-P PREROUTING ACCEPT\n" + body + ("\n" if body else ""), ""
        if "-I" in a:
            i = a.index("-I")
            pos = int(a[i + 2])
            spec = a[i + 3:]
            self.rules[binary].insert(pos - 1, spec)
            self._snapshot(binary)
            return 0, "", ""
        if "-D" in a:
            i = a.index("-D")
            rest = a[i + 2:]
            if len(rest) == 1 and rest[0].isdigit():
                idx = int(rest[0])
                if 1 <= idx <= len(self.rules[binary]):
                    self.rules[binary].pop(idx - 1)
                    self._snapshot(binary)
                    return 0, "", ""
                return 1, "", "index out of range"
            return 1, "", "this fake only accepts deletion BY INDEX"
        return 0, "", ""


def install(initial):
    t = FakeTable(initial)
    F._run_iptables = t.run
    return t


_real_run = F._run_iptables

print("== THE ALLOWLIST APPLIES HERE TOO (a repair op is still a firewall op) ==")

install([OURS])
for bad in ("eth0", "lo", "tailscale1", "", None):
    check("refuses interface %r" % (bad,),
          denied(lambda i=bad: F.op_reassert_port_deny_on_interface({"iface": i, "port": 80})))
for bad in (22, 443, 5000, 0):
    check("refuses port %r" % (bad,),
          denied(lambda p=bad: F.op_reassert_port_deny_on_interface({"iface": "tailscale0", "port": p})))
check("refuses a non-tcp protocol",
      denied(lambda: F.op_reassert_port_deny_on_interface(
          {"iface": "tailscale0", "port": 80, "proto": "udp"})))
check("refuses empty params", denied(lambda: F.op_reassert_port_deny_on_interface({})))


print("\n== ALREADY CORRECT: no writes at all ==")

t = install([OURS, OTHER])
r = F.op_reassert_port_deny_on_interface({"iface": "tailscale0", "port": 80})
check("reports both families already correct", len(r["already_correct"]) == 2, repr(r))
check("  ...and issued NO -I", not [c for c in t.calls if "-I" in c])
check("  ...and NO -D", not [c for c in t.calls if "-D" in c])
check("  ...so a healthy table is not churned on every check",
      all("-S" in c for c in t.calls), repr(t.calls[:2]))


print("\n== ABSENT: installed at position 1 ==")

t = install([OTHER])
r = F.op_reassert_port_deny_on_interface({"iface": "tailscale0", "port": 80})
check("reports it installed on both families", len(r["installed"]) == 2, repr(r))
check("  ...rule is now FIRST", rt.rule_matches_spec(t.rules[F.IPTABLES_BIN][0], "tailscale0", "tcp", 80))
check("  ...v6 too (a v4-only repair leaves the same path open)",
      rt.rule_matches_spec(t.rules[F.IP6TABLES_BIN][0], "tailscale0", "tcp", 80))
check("  ...and nothing was deleted", not [c for c in t.calls if "-D" in c])


print("\n== CASE 3: rule exists but is BELOW something that steals the packet ==")

# This is the state the whole design exists for: our rule present (so -C says yes),
# an ACCEPT above it, and traversal never reaching us.
t = install([ACCEPT_ABOVE, OTHER, OURS])
before = rt.classify("-P PREROUTING ACCEPT\n" +
                     "\n".join("-A PREROUTING " + " ".join(x) for x in [ACCEPT_ABOVE, OTHER, OURS]))
check("PRECONDITION: this table really is defeated", before.status == rt.NOT_DROP, repr(before))

r = F.op_reassert_port_deny_on_interface({"iface": "tailscale0", "port": 80})
check("reports it repositioned, not freshly installed",
      len(r["repositioned"]) == 2 and not r["installed"], repr(r))
after = rt.classify("-P PREROUTING ACCEPT\n" +
                    "\n".join("-A PREROUTING " + " ".join(x) for x in t.rules[F.IPTABLES_BIN]))
check("  ...and the table is now genuinely protected",
      after.status == rt.DROP and after.by_our_rule, repr(after))
check("  ...with EXACTLY ONE copy of the rule",
      sum(1 for x in t.rules[F.IPTABLES_BIN]
          if rt.rule_matches_spec(x, "tailscale0", "tcp", 80)) == 1,
      repr(t.rules[F.IPTABLES_BIN]))
check("  ...the stale copy was removed, one per family",
      r["duplicates_removed"] == {F.IPTABLES_BIN: 1, F.IP6TABLES_BIN: 1}, repr(r["duplicates_removed"]))


print("\n== ⭐ THE PORT IS NEVER OPEN DURING THE REPAIR ==")

# The property argv assertions cannot show. Snapshots are taken after EVERY mutation.
for label, initial in (("rule below an ACCEPT", [ACCEPT_ABOVE, OTHER, OURS]),
                       ("rule at the bottom", [OTHER, OTHER, OURS]),
                       ("two stale duplicates", [OTHER, OURS, OTHER, OURS])):
    t = install(initial)
    F.op_reassert_port_deny_on_interface({"iface": "tailscale0", "port": 80})
    hist = t.presence[F.IPTABLES_BIN]
    check("%s: a matching rule existed after EVERY mutation" % label,
          all(hist), repr(hist))
    check("  ...and there were mutations to check (an empty history proves nothing)",
          len(hist) > 0, repr(hist))

# The control: prove the snapshot instrument can actually observe absence, or "all
# present" above would be vacuous.
t = install([OURS])
t.run(F.IPTABLES_BIN, "-t", "raw", "-D", "PREROUTING", "1")
check("CONTROL: the snapshot records absence when the rule IS removed",
      t.presence[F.IPTABLES_BIN] == [False], repr(t.presence[F.IPTABLES_BIN]))


print("\n== INSERT PRECEDES DELETE, AND DELETION IS BY INDEX ==")

t = install([ACCEPT_ABOVE, OURS])
F.op_reassert_port_deny_on_interface({"iface": "tailscale0", "port": 80})
v4 = [c for c in t.calls if c[0] == F.IPTABLES_BIN and ("-I" in c or "-D" in c)]
check("the first mutation is an INSERT, not a delete",
      "-I" in v4[0], repr(v4[0]))
check("  ...and a delete follows it", any("-D" in c for c in v4[1:]), repr(v4))
dels = [c for c in v4 if "-D" in c]
check("deletion targets an INDEX, not a rule spec",
      all(c[c.index("-D") + 2].isdigit() and len(c) == c.index("-D") + 3 for c in dels),
      repr(dels))
check("  ...and the index accounts for the shift caused by the insert",
      dels[0][dels[0].index("-D") + 2] == "3", repr(dels[0]))


print("\n== DUPLICATES ARE DELETED HIGHEST-FIRST (or the indices shift underneath) ==")

t = install([OURS, OTHER, OURS, OTHER, OURS])
F.op_reassert_port_deny_on_interface({"iface": "tailscale0", "port": 80})
dels = [int(c[c.index("-D") + 2]) for c in t.calls
        if c[0] == F.IPTABLES_BIN and "-D" in c]
check("all three stale copies removed", len(dels) == 3, repr(dels))
check("  ...in descending index order", dels == sorted(dels, reverse=True), repr(dels))
check("  ...leaving exactly one, at position 1",
      sum(1 for x in t.rules[F.IPTABLES_BIN]
          if rt.rule_matches_spec(x, "tailscale0", "tcp", 80)) == 1
      and rt.rule_matches_spec(t.rules[F.IPTABLES_BIN][0], "tailscale0", "tcp", 80),
      repr(t.rules[F.IPTABLES_BIN]))


print("\n== THE RESULT IS PROVEN, NOT ASSUMED ==")


class LyingTable(FakeTable):
    """Accepts every command and reports success, but never changes anything --
    the shape of a repair that 'worked' according to every exit code."""

    def run(self, binary, *args):
        self.calls.append((binary,) + args)
        if "-S" in list(args):
            body = "\n".join("-A PREROUTING " + " ".join(r) for r in self.rules[binary])
            return 0, "-P PREROUTING ACCEPT\n" + body + "\n", ""
        return 0, "", ""


t = LyingTable([ACCEPT_ABOVE, OTHER, OURS])
F._run_iptables = t.run
check("a repair that changes nothing but exits 0 is REFUSED, not reported as success",
      denied(lambda: F.op_reassert_port_deny_on_interface({"iface": "tailscale0", "port": 80})))


print("\n== THE GRANT: structurally incapable of opening the port ==")

F._run_iptables = _real_run
pol = F.PEER_POLICY["fw-healer"]
check("fw-healer exists as a peer", isinstance(pol, dict))
check("  ...with EXACTLY ONE op", pol["ops"] == {"reassert_port_deny_on_interface"}, repr(pol["ops"]))
check("  ...it CANNOT lift the rule", "allow_port_on_interface" not in pol["ops"])
check("  ...it CANNOT block arbitrary IPs", not ({"block_ip", "deny_ip"} & pol["ops"]))
check("  ...it CANNOT enumerate the ruleset", not ({"list_rules", "list_blocked"} & pol["ops"]))
check("  ...it CANNOT write the environment file", "write_env" not in pol["ops"])
check("  ...and needs no credential (no human in the loop)", pol["require_credential"] is False)
check("  ...but is attributed in the audit trail", pol["audit_actor"] == "fw-healer")
check("the op is registered and dispatchable", "reassert_port_deny_on_interface" in F.OPS)
check("  ...with its own audit action, distinct from a manual deny",
      F.audit_action_for("reassert_port_deny_on_interface") == "fw_reassert_port_iface"
      and F.audit_action_for("reassert_port_deny_on_interface")
      != F.audit_action_for("deny_port_on_interface"))
check("the dashboard peer did NOT silently gain it",
      "reassert_port_deny_on_interface" not in F.PEER_POLICY["dashboard"]["ops"])
check("nor did the other unattended peers",
      not any("reassert_port_deny_on_interface" in F.PEER_POLICY[p]["ops"]
              for p in ("alert-watcher", "fail2ban")))
check("the healer peer resolves to root (uid 0), per the design note", F.HEALER_USER == "root")

# Every granted op must exist in OPS, or the grant is a typo that fails closed and
# looks identical to a missing entry.
for peer, p in F.PEER_POLICY.items():
    missing = p["ops"] - set(F.OPS)
    check("peer %r grants only ops that exist" % peer, not missing, repr(missing))

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
