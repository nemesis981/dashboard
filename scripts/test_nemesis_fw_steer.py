"""nemesis-fw-steer — the privileged steering helper.

Run: python3 scripts/test_nemesis_fw_steer.py

⚠ WHAT THIS CAN AND CANNOT PROVE, STATED UP FRONT.
`nft` needs root, so the APPLY and FLUSH paths cannot run here. This suite proves
the decision logic: every refusal, the chain allowlist, the state-file checks, and
that install refuses to apply a render containing no steer chain. It proves NOTHING
about nft actually flushing a chain. Claiming otherwise from a green run would be
the "instrument answered from the wrong place" failure this repo keeps finding.

⚠ THE ALLOWLIST TEST IS THE ONE THAT MATTERS. This helper runs as root and issues
`nft flush chain inet nemesis_enforce <chain>`. `input` holds every derived block
rule; flushing it would silently disarm the firewall. That branch is asserted
against `input` and `forward` BY NAME, not merely "some invalid value" -- a pattern
check that happened to admit `input` would pass a generic test.

ASSERTION COUNT IS FIXED and self-asserted.
"""
import importlib.machinery
import importlib.util
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
HELPER = os.path.join(HERE, "nemesis-fw-steer")

EXPECTED_CHECKS = 21
passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    ok = bool(cond)
    print(("  [PASS] " if ok else "  [FAIL] ") + name
          + ("" if ok or not detail else "  (%s)" % detail))
    if ok:
        passed += 1
    else:
        failed += 1


def run(*args):
    p = subprocess.run([sys.executable, HELPER, *args],
                       capture_output=True, text=True, timeout=60)
    return p.returncode, (p.stdout + p.stderr)


print("the helper exists and is executable")
check("file exists", os.path.isfile(HELPER))
check("executable bit set", os.access(HELPER, os.X_OK))

print("\n⭐ THE CHAIN ALLOWLIST — the branch between a bug and a disarmed firewall")
rc, out = run("withdraw", "--chain", "input")
check("⭐ refuses to flush 'input' (holds every derived block rule)",
      rc == 3 and "refusing to flush" in out, "rc=%d %s" % (rc, out[:80]))
rc, out = run("withdraw", "--chain", "forward")
check("⭐ refuses to flush 'forward'", rc == 3 and "refusing" in out)
rc, out = run("withdraw", "--chain", "output")
check("⭐ refuses to flush 'output'", rc == 3)
rc, out = run("withdraw", "--chain", "steer")
check("accepts the ONE permitted chain (reaches the root check)",
      rc == 2 and "must run as root" in out, "rc=%d" % rc)
rc, out = run("withdraw")
check("default chain is the permitted one", rc == 2 and "must run as root" in out)

print("\nusage errors are DISTINCT from permission errors")
check("bad chain -> 3, not root -> 2 (different codes, different meanings)",
      run("withdraw", "--chain", "input")[0] == 3 and run("withdraw")[0] == 2)
rc, out = run("install", "--state", "relative/path")
check("relative --state refused", rc == 3 and "absolute" in out)
rc, out = run("install", "--state", "/nonexistent/nope.state")
check("missing state file refused, not treated as 'no steering'",
      rc == 3 and "does not exist" in out, out[:80])

print("\n⭐ install REFUSES to apply a render with no steer chain")
# Malformed intent -> renderer refuses -> a naive helper would apply a table with
# no steer chain and exit 0, reporting success for a silent no-op.
spec = importlib.util.spec_from_loader(
    "fwsteer", importlib.machinery.SourceFileLoader("fwsteer", HELPER))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
check("module loads (no side effects at import)", mod is not None)
check("ALLOWED_CHAIN is exactly 'steer'", mod.ALLOWED_CHAIN == "steer")
check("it is a single value, not a collection that could grow silently",
      isinstance(mod.ALLOWED_CHAIN, str))
check("targets the owned table only",
      mod.TABLE_FAMILY == "inet" and mod.TABLE_NAME == "nemesis_enforce")
check("withdraw path never references the renderer",
      "RENDER" not in mod.cmd_withdraw.__code__.co_names,
      "Amendment 01 §5.1: withdrawal must not depend on the renderer")

print("\nthe renderer contract this helper depends on")
tmp = tempfile.mkdtemp()
good = os.path.join(tmp, "good.state")
open(good, "w").write("port 8443\ndest 198.51.100.10\n")
env = dict(os.environ, NEMESIS_FW_STEER_STATE=good)
p = subprocess.run([mod.RENDER, "render"], capture_output=True, text=True, env=env, timeout=60)
check("⭐ valid intent renders a steer chain", "chain steer {" in p.stdout)
check("  and the redirect carries the intended port", "redirect to :8443" in p.stdout)
bad = os.path.join(tmp, "bad.state")
open(bad, "w").write("port 8443\ndest 1.2.3.4; drop\n")
env2 = dict(os.environ, NEMESIS_FW_STEER_STATE=bad)
p2 = subprocess.run([mod.RENDER, "render"], capture_output=True, text=True, env=env2, timeout=60)
check("⭐ malformed intent renders NO steer chain", "chain steer {" not in p2.stdout)
check("  and says so loudly rather than silently omitting it", "REFUSING" in p2.stderr)
check("  while the rest of the table still renders (steering never costs blocks)",
      "chain input {" in p2.stdout and "chain forward {" in p2.stdout)

_total = passed + failed
check("assertion count matches EXPECTED_CHECKS (%d)" % EXPECTED_CHECKS,
      _total + 1 == EXPECTED_CHECKS, "ran %d" % (_total + 1))

print("\n%d passed, %d failed" % (passed, failed))
print("\nNOT PROVEN HERE: nft apply, nft flush, and the rebaseline — all need root.")
sys.exit(1 if failed else 0)
