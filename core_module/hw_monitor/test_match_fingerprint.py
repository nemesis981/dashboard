"""Does hw_monitor._match_fingerprint() actually work?

Run:  python3 core_module/hw_monitor/test_match_fingerprint.py

WHY THIS TEST EXISTS. `_match_fingerprint` loads `nemesis_agent/hwid.py` by
absolute path, but `hwid` imports a SIBLING module (`win_run`) at module level --
and loading a file by absolute path does not put that file's directory on
sys.path. Under the production PYTHONPATH the load raised ModuleNotFoundError
every time, and the only call site swallows it:

    except Exception:
        log.exception("fingerprint match failed (non-fatal)")

So enrollment kept working while the TOFU "have I seen this hardware before?"
comparison had never once run. Nothing failed loudly; the feature was simply
absent.

⚠ THIS TEST MUST BE RUN IN A SUBPROCESS WITH THE PRODUCTION PYTHONPATH. Running
it from a shell that already has `nemesis_agent` on sys.path would make the
broken loader succeed by accident -- the test would pass against the bug, which
is the whole failure mode it exists to catch. `_run()` below sets the path
explicitly rather than inheriting whatever the caller happened to have.
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))

#: Exactly what the hw-monitor unit sets. NOT the caller's environment.
PROD_PYTHONPATH = "%s/alert_manager:%s" % (REPO, REPO)

_failures = []


def check(label, got, want):
    if got != want:
        _failures.append("%s: got %r, want %r" % (label, got, want))
        print("  FAIL  %s: got %r, want %r" % (label, got, want))
    else:
        print("  ok    %s" % label)


def _run(snippet):
    """Execute `snippet` in a fresh process under the production PYTHONPATH."""
    env = dict(os.environ)
    env["PYTHONPATH"] = PROD_PYTHONPATH
    env["NEMESIS_DB_PATH"] = "/tmp/nemesis-test-match-fp.db"
    env["LOGS_DIRECTORY"] = "/tmp"
    env.pop("NEMESIS_EXPECT_USER", None)      # do not trip privsep attestation
    env["NEMESIS_5001_PACING"] = "0"
    # Deliberately NOT adding nemesis_agent to PYTHONPATH: that is the accident
    # that would hide the bug.
    r = subprocess.run([sys.executable, "-c", snippet],
                       capture_output=True, text=True, timeout=120, env=env,
                       cwd=REPO)
    return r


_SNIPPET = r'''
import json, sys
sys.path.insert(0, "%s/core_module/hw_monitor")
import hw_monitor

fp = {"stable_id": "abc123", "signal_hashes": {"cpu_id": "h1", "machine_id": "h2"}}
stored = [("dev-1", "abc123", {"cpu_id": "h1", "machine_id": "h2"})]
try:
    out = hw_monitor._match_fingerprint(fp, stored)
    print("RESULT " + json.dumps({"ok": True, "outcome": out[0],
                                  "device": out[1], "n": out[2]}))
except Exception as e:
    print("RESULT " + json.dumps({"ok": False,
                                  "error": "%%s: %%s" %% (type(e).__name__, e)}))
''' % REPO


def _result():
    r = _run(_SNIPPET)
    for line in (r.stdout or "").splitlines():
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return {"ok": False, "error": "no RESULT line; stderr=%s"
                                  % (r.stderr or "")[-300:]}


def test_match_fingerprint_runs_at_all():
    """THE regression check. Before the fix this returns ok=False with
    ModuleNotFoundError: No module named 'win_run'."""
    print("\n[_match_fingerprint loads hwid under the PRODUCTION PYTHONPATH]")
    res = _result()
    if not res.get("ok"):
        print("        error: %s" % res.get("error"))
    check("it does not raise", res.get("ok"), True)
    # POSITIVE control: a known-identical fingerprint must match EXACTLY. A
    # function that returned 'none' for everything would satisfy "does not raise"
    # while still being useless.
    check("an identical fingerprint matches exactly", res.get("outcome"), "exact")
    check("it names the matched device", res.get("device"), "dev-1")


def test_it_can_also_say_no():
    """NEGATIVE control: the matcher must be able to return 'none'.

    Without this, a stub that always answered 'exact' would pass the test above.
    """
    print("\n[the matcher can also refuse a match]")
    snippet = _SNIPPET.replace(
        'stored = [("dev-1", "abc123", {"cpu_id": "h1", "machine_id": "h2"})]',
        'stored = [("dev-1", "zzz999", {"cpu_id": "different", "machine_id": "other"})]')
    env = dict(os.environ)
    env["PYTHONPATH"] = PROD_PYTHONPATH
    env["NEMESIS_DB_PATH"] = "/tmp/nemesis-test-match-fp.db"
    env["LOGS_DIRECTORY"] = "/tmp"
    env.pop("NEMESIS_EXPECT_USER", None)
    env["NEMESIS_5001_PACING"] = "0"
    r = subprocess.run([sys.executable, "-c", snippet], capture_output=True,
                       text=True, timeout=120, env=env, cwd=REPO)
    res = {"ok": False}
    for line in (r.stdout or "").splitlines():
        if line.startswith("RESULT "):
            res = json.loads(line[7:])
    check("it does not raise", res.get("ok"), True)
    check("a different fingerprint does NOT match", res.get("outcome"), "none")


def test_loader_does_not_leak_syspath():
    """The sys.path insert must be scoped to the load and reverted.

    A permanent mutation would defeat the reason hwid is loaded by absolute path
    in the first place (one source of truth, no ambient import shadowing).
    """
    print("\n[the sys.path insert is reverted after loading]")
    snippet = r'''
import json, sys
sys.path.insert(0, "%s/core_module/hw_monitor")
import hw_monitor
agent_dir = "%s/nemesis_agent"
before = agent_dir in sys.path
hw_monitor._match_fingerprint({"stable_id": "x", "signal_hashes": {}}, [])
after = agent_dir in sys.path
print("RESULT " + json.dumps({"before": before, "after": after}))
''' % (REPO, REPO)
    env = dict(os.environ)
    env["PYTHONPATH"] = PROD_PYTHONPATH
    env["NEMESIS_DB_PATH"] = "/tmp/nemesis-test-match-fp.db"
    env["LOGS_DIRECTORY"] = "/tmp"
    env.pop("NEMESIS_EXPECT_USER", None)
    env["NEMESIS_5001_PACING"] = "0"
    r = subprocess.run([sys.executable, "-c", snippet], capture_output=True,
                       text=True, timeout=120, env=env, cwd=REPO)
    res = None
    for line in (r.stdout or "").splitlines():
        if line.startswith("RESULT "):
            res = json.loads(line[7:])
    check("CONTROL the probe ran", res is not None, True)
    if res:
        check("nemesis_agent was not on sys.path before", res["before"], False)
        check("...and is not left there afterwards", res["after"], False)


def test_call_site_no_longer_calls_it_non_fatal():
    """A failure here means the TOFU check silently did not happen.

    'non-fatal' invited ignoring it, and it was ignored for weeks. The wording
    should state the CONSEQUENCE, not the severity.
    """
    print("\n[the call site describes the consequence, not just the severity]")
    src = open(os.path.join(HERE, "hw_monitor.py")).read()
    i = src.index("_match_fingerprint(fp, prior)")
    blk = src[i:i + 1400]
    # Strip comment lines before matching. The fix's own comment QUOTES the old
    # "non-fatal" wording as the thing being removed, and matching prose would
    # flag the explanation as the defect -- the same false positive already hit
    # once tonight on the _dm_conn check.
    code = "\n".join(l for l in blk.splitlines()
                     if not l.lstrip().startswith("#"))
    check("no longer labelled merely 'non-fatal' in CODE",
          "non-fatal" in code, False)
    check("still logs at exception level", "log.exception" in code, True)
    check("names what was lost", "comparison" in code.lower(), True)
    # CONTROL: the stripper must not have eaten the code with the comments.
    check("CONTROL the log call survived stripping",
          "enroll fingerprint" in code, True)
    # CONTROL: the matcher can still fire on the old wording.
    check("CONTROL the matcher detects the old wording",
          "non-fatal" in 'log.exception("fingerprint match failed (non-fatal)")', True)


if __name__ == "__main__":
    print("hw_monitor._match_fingerprint")
    test_match_fingerprint_runs_at_all()
    test_it_can_also_say_no()
    test_loader_does_not_leak_syspath()
    test_call_site_no_longer_calls_it_non_fatal()

    print("\n" + "=" * 60)
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  - %s" % f)
        sys.exit(1)
    print("ALL PASS")
