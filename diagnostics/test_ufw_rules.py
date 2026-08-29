#!/usr/bin/env python3
"""ufw_rules must tell a DENIAL apart from a real firewall fault.

Run: python3 diagnostics/test_ufw_rules.py   (exit 0 = all pass)

WHAT THIS GUARDS. Under the shipped service accounts this probe CANNOT succeed:
the dashboard runs as `nemesis-dash` and diagnostics-watcher as `nemesis-diag`,
neither has a sudoers grant (the installer grants ufw to the installing human,
not to service users), and both units set `NoNewPrivileges=yes`, which makes the
kernel ignore setuid so sudo cannot elevate even WITH a rule. Verified live
2026-08-28: the identical command exits 0 with a valid NOPASSWD grant and exits
1 under `setpriv --no-new-privs`.

So the probe's failure is the NORMAL case in production, and the only thing that
matters is that it reports the failure HONESTLY. Before this fix it collapsed
every non-zero exit into `warn` + "UFW query returned rc=1" and dumped sudo's
error where the ruleset should be -- a permissions problem rendered as a
firewall problem, which invites someone to go debugging a firewall that is fine.

WHY STUBBED. Each branch is forced by replacing `subprocess.run`, because the
real ones cannot all be produced on demand: a genuine non-permission ufw failure
would mean breaking ufw, and "not installed" would mean uninstalling it. A
branch nothing exercises is indistinguishable from a branch that does not work
(standing practice, 2026-08-24), so each is driven directly.

THE DENIAL AND FAULT CASES ARE ASSERTED AS A PAIR. Both are non-zero exits and
both render `warn`; a test that only checked the denial case would still pass if
the two were merged back together -- which is exactly the bug being fixed.
"""
import subprocess
import sys

sys.path.insert(0, "/opt/nemesis")

import diagnostics.ufw_rules as ur                       # noqa: E402

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s" % label)
        if detail:
            print("         %s" % (detail,))


class _R:
    """Stand-in for CompletedProcess."""

    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _with(fake):
    """Run ur.run() with subprocess.run replaced, always restoring it."""
    real = subprocess.run
    ur.subprocess.run = fake
    try:
        return ur.run()
    finally:
        ur.subprocess.run = real


# The real sudo text for a NoNewPrivileges denial, captured verbatim from a live
# `setpriv --no-new-privs sudo -n ufw status verbose` on 2026-08-28. Hard-coding
# a paraphrase here would let the matcher drift away from what sudo really says.
_NNP_STDERR = ('sudo: The "no new privileges" flag is set, which prevents sudo '
               'from running as root.\nsudo: If sudo is running in a container, '
               'you may need to adjust the container configuration to disable '
               'the flag.')
_PW_STDERR = "sudo: a password is required"


print("\n-- 1. success path --")
_ok = _with(lambda *a, **k: _R(0, "Status: active\nTo   Action   From\n"))
check("⭐ exit 0 -> ok", _ok["status"] == "ok", _ok)
check("...summary says retrieved", "retrieved" in _ok["summary"], _ok)
check("...the real ruleset is passed through untouched",
      "Status: active" in _ok["output"], _ok)


print("\n-- 2. DENIED (the production case): warn, and named as a privilege problem --")
for label, err in (("NoNewPrivileges", _NNP_STDERR), ("password required", _PW_STDERR)):
    d = _with(lambda *a, **k: _R(1, "", err))
    check("⭐ %s -> warn (not error: nothing is broken)" % label,
          d["status"] == "warn", d)
    check("⭐ %s -> summary says the FIREWALL IS FINE, so nobody debugs a "
          "healthy firewall" % label,
          "firewall itself is fine" in d["summary"], d)
    check("%s -> output names it a privilege problem" % label,
          "no privilege" in d["output"], d)
    check("%s -> sudo's actual stderr is preserved, not swallowed" % label,
          err.split("\n")[0] in d["output"], d)
    check("%s -> output explicitly says it is NOT a firewall fault" % label,
          "NOT a firewall fault" in d["output"], d)


print("\n-- 3. CONTROL: a real ufw fault must NOT read as a denial --")
# Same shape as section 2 (non-zero exit, warn) -- differing ONLY in stderr. If
# the two branches were ever merged, this section fails and section 2 does not.
_fault = _with(lambda *a, **k: _R(2, "", "ERROR: Could not load logging rules"))
check("⭐ CONTROL: a non-permission failure is still warn", _fault["status"] == "warn", _fault)
check("⭐ CONTROL: ...but is NOT labelled a privilege problem",
      "no privilege" not in _fault["output"], _fault)
check("⭐ CONTROL: ...and is NOT excused as 'firewall itself is fine'",
      "firewall itself is fine" not in _fault["summary"], _fault)
check("⭐ CONTROL: ...it says plainly this is not a permissions issue",
      "not a permissions issue" in _fault["summary"], _fault)
check("CONTROL: ...and surfaces ufw's own error text",
      "Could not load logging rules" in _fault["output"], _fault)
check("CONTROL: ...and reports the real exit code", "2" in _fault["summary"], _fault)


print("\n-- 4. environmental failures are their own states, not 'warn' --")
def _raise(exc):
    def _f(*a, **k):
        raise exc
    return _f


_ni = _with(_raise(FileNotFoundError()))
check("⭐ ufw absent -> error (a missing firewall is not a warning)",
      _ni["status"] == "error", _ni)
check("...and says so", "not installed" in _ni["summary"], _ni)

_to = _with(_raise(subprocess.TimeoutExpired(cmd="ufw", timeout=10)))
check("⭐ timeout -> error, distinct from both denial and fault",
      _to["status"] == "error" and "timed out" in _to["summary"], _to)

_ex = _with(_raise(RuntimeError("boom")))
check("unexpected exception -> error, with the type named",
      _ex["status"] == "error" and "RuntimeError" in _ex["output"], _ex)


print("\n-- 5. every branch returns the shape run_check() expects --")
for name, res in (("ok", _ok), ("denied", d), ("fault", _fault),
                  ("not-installed", _ni), ("timeout", _to)):
    check("%s: has all required keys with the right id" % name,
          all(k in res for k in ("id", "name", "icon", "status", "summary", "output"))
          and res["id"] == "ufw_rules", res)
    check("%s: status is one of the three the UI renders" % name,
          res["status"] in ("ok", "warn", "error"), res)


print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
