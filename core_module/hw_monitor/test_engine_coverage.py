"""Tests for engine_coverage — fleet detection-coverage compute (ADR 0004 hinge (b))."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine_coverage as ec

_r = []
def check(l, g, w):
    ok = g == w; _r.append((l, ok))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", l, g, w))

def dev(did, at, engines):
    return {"device_id": did, "reported_at": at, "engines": engines}
def eng(cap, rv=None):
    return {"capability": cap, "ruleset_version": rv, "version": "x"}

def main():
    print("newest ruleset = the freshest-reporting healthy endpoint's version")
    A = ec.CAP_AVAILABLE
    devs = [
        dev("d1", "2026-08-20T10:00:00", {"clamav": eng(A, "27000"), "yara": eng(A, "abc")}),
        dev("d2", "2026-08-20T12:00:00", {"clamav": eng(A, "27100"), "yara": eng(A, "abc")}),
    ]
    rep = ec.compute_coverage(devs)
    check("current clamav = the later report's db", rep["current_ruleset_versions"]["clamav"], "27100")
    check("d1 is STALE on clamav (27000 < fleet 27100)",
          rep["devices"][0]["stale"], [{"engine": "clamav", "have": "27000", "current": "27100"}])
    check("d2 is fully covered", rep["devices"][1]["fully_covered"], True)
    check("summary counts the gap", rep["summary"]["with_gaps"], 1)

    print("\nabsent + degraded are gaps, and expected-everywhere flags fleet gaps")
    devs2 = [
        dev("d1", "t1", {"clamav": eng(A, "1"), "yara": eng(ec.CAP_ABSENT),
                          "behavioral": eng(ec.CAP_ABSENT)}),
        dev("d2", "t1", {"clamav": eng(ec.CAP_DEGRADED), "yara": eng(A, "9"),
                          "behavioral": eng(ec.CAP_ABSENT)}),
    ]
    rep2 = ec.compute_coverage(devs2)
    check("d1 lists yara+behavioral absent", rep2["devices"][0]["absent"], ["behavioral", "yara"])
    check("d2 lists clamav degraded", rep2["devices"][1]["degraded"], ["clamav"])
    check("behavioral available NOWHERE -> fleet gap", "behavioral" in rep2["fleet_gaps"], True)
    check("clamav is not a fleet gap (available on d1)", "clamav" in rep2["fleet_gaps"], False)

    print("\nbadge never reassures on no/partial data")
    check("no devices -> unknown", ec.coverage_badge(ec.compute_coverage([]))[0], "unknown")
    check("fleet gap -> bad", ec.coverage_badge(rep2)[0], "bad")
    check("stale/degraded but no fleet gap -> warn", ec.coverage_badge(rep)[0], "warn")
    allok = ec.compute_coverage([dev("d1","t",{"clamav":eng(A,"1")})])
    check("all covered -> ok", ec.coverage_badge(allok)[0], "ok")

    p = sum(1 for _, ok in _r if ok)
    print("\n%d/%d checks passed" % (p, len(_r)))
    if p != len(_r): sys.exit(1)

if __name__ == "__main__":
    main()
