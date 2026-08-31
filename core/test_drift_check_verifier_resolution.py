"""Where nemesis-drift-check loads its verifier from. Executes the script, both ways.

WHY THIS FILE EXISTS. The checker runs as ROOT from a timer. /opt/nemesis/core is
0664 <user>:<user>, so if the root unit imports netfilter_drift.py from the repo it is
executing code an unprivileged account can rewrite -- a privilege-escalation path
created by a security checker. deploy_drift_check.sh installs a root-owned copy
BESIDE the script, and the script must prefer it.

⚠ A STRING CHECK WOULD NOT DO. Asserting that the source contains `_HERE` proves the
line was typed, not that the import resolves to it. Both branches are therefore
exercised by RUNNING the script and reading back the `verifier` path it recorded --
the same reason the fact file records provenance at all. A misdeployment and a correct
deployment both print verdict "ok"; only the path distinguishes them.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
_SCRIPT = os.path.join(_REPO, "scripts", "nemesis-drift-check")
_VERIFIER = os.path.join(_HERE, "netfilter_drift.py")

_fail = []
_count = 0
EXPECTED_CHECKS = 7

# A healthy ruleset, so the run reaches the status write instead of failing early.
_GOOD_RULES = """\
-A ufw-before-input -i lo -j ACCEPT
# NEMESIS-TAILNET-ANTISPOOF
-A ufw-before-input -s 100.64.0.0/10 ! -i tailscale0 -j DROP
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
"""


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-66s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def _run(script_path, tmp):
    """Run the checker, return its parsed fact file. Exit code is deliberately not
    asserted: it depends on the live tailscaled, which this test does not control."""
    status = os.path.join(tmp, "status.json")
    rules = os.path.join(tmp, "before.rules")
    with open(rules, "w", encoding="utf-8") as fh:
        fh.write(_GOOD_RULES)
    env = dict(os.environ, NEMESIS_DRIFT_STATUS=status, NEMESIS_UFW_RULES=rules)
    # Neutral cwd: run from tmp, never the repo root, so nothing is rescued by cwd
    # landing on sys.path -- that would silently defeat the whole point of the test.
    subprocess.run([sys.executable, script_path], env=env, cwd=tmp,
                   capture_output=True, text=True, timeout=60)
    if not os.path.exists(status):
        return None
    with open(status, encoding="utf-8") as fh:
        return json.load(fh)


def test_prefers_the_copy_beside_it():
    print("\n[installed shape: a verifier beside the script WINS over the repo]")
    tmp = tempfile.mkdtemp(prefix="drift-installed-")
    try:
        dest = os.path.join(tmp, "nemesis-drift-check")
        shutil.copy2(_SCRIPT, dest)
        shutil.copy2(_VERIFIER, os.path.join(tmp, "netfilter_drift.py"))
        payload = _run(dest, tmp)
        check("wrote a fact file", payload is not None, True)
        if payload:
            check("loaded the verifier beside it, NOT the repo",
                  os.path.dirname(payload.get("verifier", "")), tmp)
            check("...and that is not the repo core dir",
                  os.path.dirname(payload.get("verifier", "")) == _HERE, False)
            check("recorded a verdict alongside it", "verdict" in payload, True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_falls_back_to_repo_when_run_in_tree():
    print("\n[dev shape: no verifier beside it -> repo fallback, still runnable]")
    tmp = tempfile.mkdtemp(prefix="drift-intree-")
    try:
        # The real in-tree script: scripts/ has no netfilter_drift.py beside it.
        check("scripts/ really has no verifier beside it",
              os.path.exists(os.path.join(_REPO, "scripts", "netfilter_drift.py")), False)
        payload = _run(_SCRIPT, tmp)
        check("wrote a fact file", payload is not None, True)
        if payload:
            check("fell back to the repo core copy",
                  os.path.dirname(payload.get("verifier", "")), "/opt/nemesis/core")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    print("nemesis-drift-check verifier resolution (both branches, executed)")
    test_prefers_the_copy_beside_it()
    test_falls_back_to_repo_when_run_in_tree()
    print()
    if _count != EXPECTED_CHECKS:
        print("SUITE DRIFT: ran %d checks, expected %d" % (_count, EXPECTED_CHECKS))
        sys.exit(1)
    if _fail:
        print("FAILED (%d of %d)" % (len(_fail), _count))
        for f in _fail:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS (%d checks)" % _count)
