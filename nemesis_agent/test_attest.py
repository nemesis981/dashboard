#!/usr/bin/env python3
"""Tier 1 attestation self-check tests.

Run: python3 /opt/nemesis/nemesis_agent/test_attest.py

Built against a SYNTHETIC agent tree, never the real one, so the tests cannot be
made to pass by the state of the installed agent.

Mutation-checked: `main()` runs a mutation pass that breaks `compare()` three
ways and asserts the suite NOTICES each. A control written after the code is
green-from-birth and proves nothing until it has been shown it can fail.
"""

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import attest                                                    # noqa: E402

EXPECTED_CHECKS = 16
_state = {"ran": 0, "failed": 0}


def check(label, got, want):
    _state["ran"] += 1
    ok = got == want
    if not ok:
        _state["failed"] += 1
    print("  %-56s %s  (got=%r want=%r)"
          % (label, "PASS" if ok else "FAIL", got, want))


def build_tree(root):
    """A miniature agent tree, including every excluded shape."""
    os.makedirs(os.path.join(root, "modules"), exist_ok=True)
    os.makedirs(os.path.join(root, "__pycache__"), exist_ok=True)
    os.makedirs(os.path.join(root, "keys"), exist_ok=True)
    os.makedirs(os.path.join(root, "yara_rules"), exist_ok=True)
    _w(root, "agent.py", "print('agent')\n")
    _w(root, "config.py", "X = 1\n")
    _w(os.path.join(root, "modules"), "security.py", "def scan(): pass\n")
    # excluded shapes
    _w(root, "nemesis_agent.conf", "device_id = abc\n")
    _w(root, "nemesis_agent.log", "log line\n")
    _w(os.path.join(root, "__pycache__"), "agent.cpython.pyc", "junk")
    _w(os.path.join(root, "keys"), "device.pem", "SECRET")
    _w(os.path.join(root, "yara_rules"), "rules.yar", "rule x {}")


def _w(d, name, content):
    with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
        fh.write(content)


def write_manifest(root, manifest):
    import json
    with open(attest.manifest_path(root), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)


def run_suite():
    root = tempfile.mkdtemp(prefix="attest_test_")
    try:
        build_tree(root)

        # ── coverage / exclusions ───────────────────────────────────────────
        digests = attest.compute_digests(root)
        covered = sorted(digests)
        check("covers only .py files", covered,
              ["agent.py", "config.py", "modules/security.py"])
        check("per-install conf excluded", "nemesis_agent.conf" in digests, False)
        check("runtime log excluded", "nemesis_agent.log" in digests, False)
        check("key material excluded", any("keys/" in p for p in digests), False)
        check("independently-updated rules excluded",
              any("yara_rules" in p for p in digests), False)
        check("build artefacts excluded",
              any("__pycache__" in p for p in digests), False)

        # deterministic ordering — a manifest that is not reproducible makes
        # every comparison against it suspect
        check("digest computation is reproducible",
              attest.compute_digests(root) == digests, True)

        # ── absent ──────────────────────────────────────────────────────────
        r = attest.evaluate(root, agent_version="1.0.0")
        check("no manifest -> ABSENT", r["state"], attest.ABSENT)
        check("ABSENT is not ATTESTED", r["state"] == attest.ATTESTED, False)

        # ── attested ────────────────────────────────────────────────────────
        m = attest.build_manifest("1.0.0", root)
        write_manifest(root, m)
        r = attest.evaluate(root, agent_version="1.0.0")
        check("matching manifest -> ATTESTED", r["state"], attest.ATTESTED)

        # ── failed: modified file (the tampering shape) ─────────────────────
        _w(os.path.join(root, "modules"), "security.py", "def scan(): return True\n")
        r = attest.evaluate(root, agent_version="1.0.0")
        check("modified file -> FAILED", r["state"], attest.FAILED)
        check("modification is reported as modified, not missing",
              r["diff"]["modified"], ["modules/security.py"])

        # ── failed: unexpected file a digest-only check would miss ──────────
        _w(os.path.join(root, "modules"), "security.py", "def scan(): pass\n")
        _w(root, "backdoor.py", "evil()\n")
        r = attest.evaluate(root, agent_version="1.0.0")
        check("ADDED file -> FAILED", r["state"], attest.FAILED)
        check("added file reported as unexpected", r["diff"]["unexpected"],
              ["backdoor.py"])
        os.remove(os.path.join(root, "backdoor.py"))

        # ── version skew is ABSENT, not FAILED ──────────────────────────────
        # A legitimate upgrade must not be reported as tampering; that false
        # positive is what would get the whole signal ignored.
        r = attest.evaluate(root, agent_version="2.0.0")
        check("build skew -> ABSENT not FAILED", r["state"], attest.ABSENT)

        # ── malformed manifest ──────────────────────────────────────────────
        with open(attest.manifest_path(root), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        r = attest.evaluate(root, agent_version="1.0.0")
        check("malformed manifest -> ABSENT", r["state"], attest.ABSENT)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def mutation_pass():
    """Break compare() three ways; the suite must NOTICE each."""
    print("\n-- mutation check (each mutant MUST be caught) --")
    real = attest.compare
    mutants = {
        "ignores modified files":
            lambda m, l: {**real(m, l), "modified": [],
                          "ok": not (real(m, l)["missing"] or real(m, l)["unexpected"])},
        "ignores unexpected files":
            lambda m, l: {**real(m, l), "unexpected": [],
                          "ok": not (real(m, l)["modified"] or real(m, l)["missing"])},
        "always reports ok":
            lambda m, l: {"modified": [], "missing": [], "unexpected": [], "ok": True},
    }
    caught = 0
    for name, mutant in mutants.items():
        attest.compare = mutant
        before = dict(_state)
        # Silence the re-run: a mutation pass that reprints the whole suite three
        # times buries the real tally in output that looks like failures.
        import contextlib
        import io
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                run_suite()
        except Exception:                                        # noqa: BLE001
            pass
        died = _state["failed"] > before["failed"]
        # roll the counters back — the mutation pass must not pollute the real tally
        _state.update(before)
        print("  mutant %-28s %s" % (name, "CAUGHT" if died else "!! SURVIVED"))
        caught += 1 if died else 0
    attest.compare = real
    return caught, len(mutants)


def main():
    print("-- attestation self-check --")
    run_suite()
    passed = _state["ran"] - _state["failed"]
    print("\n%d/%d checks (ran=%d failed=%d)"
          % (passed, EXPECTED_CHECKS, _state["ran"], _state["failed"]))
    if _state["ran"] != EXPECTED_CHECKS:
        print("!! declared %d checks but ran %d — count guard failed"
              % (EXPECTED_CHECKS, _state["ran"]))
        return 1

    caught, total = mutation_pass()
    print("mutants caught: %d/%d" % (caught, total))
    return 0 if (_state["failed"] == 0 and caught == total) else 1


if __name__ == "__main__":
    sys.exit(main())
