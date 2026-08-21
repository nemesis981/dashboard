"""Tests for engine_inventory — per-endpoint detection-engine reporting.

The property that matters most (ADR 0004 hinge (b)): EXPLICIT DEGRADATION. A missing
engine reports ABSENT; a present-but-crippled engine reports DEGRADED with a reason;
neither is ever silently dropped or dressed up as available. So the tests hammer the
not-available cases specifically, with injected probe results, since those are what a
real fleet mostly reports and what a silent-coverage-gap would hide.

Run: python3 nemesis_agent/test_engine_inventory.py
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import engine_inventory as ei                                # noqa: E402

_results = []


def check(label, got, want):
    ok = got == want
    _results.append((label, ok))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", label, got, want))


def main():
    print("clamav parsing — version + db(ruleset) version + freshness")
    # inject the runner + which via monkeypatch
    orig_run, orig_which = ei._run, ei.shutil.which
    try:
        ei.shutil.which = lambda x: "/usr/bin/clamscan"
        ei._run = lambda cmd, timeout=6: (0, "ClamAV 1.0.5/27000/Mon Aug 18 2026\n")
        st = ei.probe_clamav()
        check("present + db -> available", st.capability, ei.CAP_AVAILABLE)
        check("...engine version parsed", st.version, "1.0.5")
        check("...ruleset (db) version parsed", st.ruleset_version, "27000")

        # present but NO db reported -> degraded, NOT available (no signatures = no coverage)
        ei._run = lambda cmd, timeout=6: (0, "ClamAV 1.0.5\n")
        st = ei.probe_clamav()
        check("present but no db -> DEGRADED", st.capability, ei.CAP_DEGRADED)
        check("...still reports the engine version", st.version, "1.0.5")

        # version probe fails -> degraded (present but unusable), not absent
        ei._run = lambda cmd, timeout=6: (1, "some error")
        check("present but --version fails -> DEGRADED",
              ei.probe_clamav().capability, ei.CAP_DEGRADED)

        # not on PATH -> absent
        ei.shutil.which = lambda x: None
        check("clamscan absent -> ABSENT", ei.probe_clamav().capability, ei.CAP_ABSENT)
    finally:
        ei._run, ei.shutil.which = orig_run, orig_which

    print("\nyara — version + rule-file digest, degraded when present-without-rules")
    orig_which = ei.shutil.which
    try:
        # absent binary
        ei.shutil.which = lambda x: None
        check("yara binary absent -> ABSENT", ei.probe_yara().capability, ei.CAP_ABSENT)

        ei.shutil.which = lambda x: "/usr/bin/yara"
        ei._run = lambda cmd, timeout=6: (0, "4.5.0\n")
        # present, no rules dir -> degraded
        check("yara present, no rules -> DEGRADED",
              ei.probe_yara(rules_dir=None).capability, ei.CAP_DEGRADED)
        # present + a real rules dir -> available with a digest
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "a.yar"), "w") as fh:
                fh.write("rule x { condition: true }")
            st = ei.probe_yara(rules_dir=d)
            check("yara present + rules -> AVAILABLE", st.capability, ei.CAP_AVAILABLE)
            check("...ruleset version is a stable digest",
                  bool(st.ruleset_version) and len(st.ruleset_version) == 16, True)
            v1 = st.ruleset_version
            # same content -> same version (drift is a plain string compare)
            check("...identical rules -> identical version",
                  ei.probe_yara(rules_dir=d).ruleset_version, v1)
            # changed content -> changed version
            with open(os.path.join(d, "b.yar"), "w") as fh:
                fh.write("rule y { condition: false }")
            check("...changed rules -> changed version",
                  ei.probe_yara(rules_dir=d).ruleset_version != v1, True)
    finally:
        ei.shutil.which = orig_which
        ei._run = orig_run

    print("\nbehavioral seam — absent until a status reader is injected (M2)")
    check("no reader -> ABSENT (visible coverage gap, not assumed)",
          ei.probe_behavioral(None).capability, ei.CAP_ABSENT)
    check("reader says not present -> ABSENT",
          ei.probe_behavioral(lambda: (False, None, None, False)).capability,
          ei.CAP_ABSENT)
    check("present but not running -> DEGRADED",
          ei.probe_behavioral(lambda: (True, "0.39", "r7", False)).capability,
          ei.CAP_DEGRADED)
    check("present + running -> AVAILABLE",
          ei.probe_behavioral(lambda: (True, "0.39", "r7", True)).capability,
          ei.CAP_AVAILABLE)
    check("a reader that raises -> DEGRADED, not a crash",
          ei.probe_behavioral(lambda: (_ for _ in ()).throw(RuntimeError("x")))
          .capability, ei.CAP_DEGRADED)

    print("\ninventory() — buckets engines, never drops one, never raises")
    inv = ei.inventory()
    check("every registered engine appears", sorted(inv["engines"]),
          ["behavioral", "clamav", "yara"])
    check("summary buckets sum to the engine count",
          sum(len(v) for v in inv["summary"].values()), 3)
    # a probe that raises must land as degraded in the report, not vanish
    orig = ei._PROBES["clamav"]
    try:
        ei._PROBES["clamav"] = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        inv2 = ei.inventory()
        check("a raising probe is reported DEGRADED, not dropped",
              inv2["engines"]["clamav"]["capability"], ei.CAP_DEGRADED)
        check("...and still present in the inventory", "clamav" in inv2["engines"], True)
    finally:
        ei._PROBES["clamav"] = orig

    print("\nlive self-check on THIS box (clamav present here)")
    live = ei.inventory()
    check("clamav is available on this build box",
          live["engines"]["clamav"]["capability"], ei.CAP_AVAILABLE)
    check("...with a real ruleset version",
          bool(live["engines"]["clamav"]["ruleset_version"]), True)

    passed = sum(1 for _, ok in _results if ok)
    print("\n%d/%d checks passed" % (passed, len(_results)))
    failed = [l for l, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  -", f)
        sys.exit(1)


if __name__ == "__main__":
    main()
