#!/usr/bin/env python3
"""R6 — required-detector suppression alarm (modules_loader.required_detector_coverage).

Run: python3 test_required_detector_coverage.py

A required detector that is enabled-but-not-healthy is suppressed coverage — an alertable
event on its own. Every 'is flagged' is paired with a 'is not flagged' control, and the
fail-closed case (unreadable status = suppressed) is asserted."""
import sys
sys.path.insert(0, "/opt/nemesis")
import modules_loader as ml

_fail = 0
def check(label, cond, detail=""):
    global _fail
    print(("  [PASS] " if cond else "  [FAIL] ") + label + ("" if cond else "  " + str(detail)))
    if not cond: _fail += 1

# Drive it with injected state rather than the live DB.
ml._manifests = {
    "req_healthy":   {"required": True},
    "req_erroring":  {"required": True},
    "req_unknown":   {"required": True},
    "optional_bad":  {"required": False},
}
_status = {}
_enabled = {"req_healthy": True, "req_erroring": True, "req_unknown": True, "optional_bad": True}
ml.is_enabled = lambda n: _enabled.get(n, False)
ml.module_status = lambda n: _status.get(n, {"state": "stopped"})

print("== healthy required detector is NOT flagged ==")
_status = {"req_healthy": {"state": "running"}, "req_erroring": {"state":"running"},
           "req_unknown": {"state":"running"}}
f = ml.required_detector_coverage()
check("all-healthy required detectors -> no findings", f == [], f)

print("== an enabled-but-erroring required detector IS flagged ==")
_status["req_erroring"] = {"state": "error", "detail": "DB down"}
f = ml.required_detector_coverage()
names = [x["module"] for x in f]
check("req_erroring flagged", "req_erroring" in names, f)
check("CONTROL: healthy ones not flagged", "req_healthy" not in names and "req_unknown" not in names, f)
check("detail carried for triage", any(x["module"]=="req_erroring" and "DB down" in x["detail"] for x in f), f)

print("== fail-closed: an unreadable / unknown status counts as suppressed ==")
_status = {"req_healthy":{"state":"running"}, "req_erroring":{"state":"running"},
           "req_unknown": {}}   # empty status -> unknown
f = ml.required_detector_coverage()
check("required detector with unknown status is flagged (fail-closed)",
      "req_unknown" in [x["module"] for x in f], f)

print("== an OPTIONAL module that is unhealthy is NOT a coverage finding ==")
_status = {"req_healthy":{"state":"running"},"req_erroring":{"state":"running"},
           "req_unknown":{"state":"running"}, "optional_bad": {"state":"error"}}
f = ml.required_detector_coverage()
check("optional module error is not a required-coverage finding",
      "optional_bad" not in [x["module"] for x in f], f)

print("== a required detector somehow disabled is flagged ==")
_enabled["req_healthy"] = False
f = ml.required_detector_coverage()
check("disabled required detector flagged", any(x["module"]=="req_healthy" and x["state"]=="disabled" for x in f), f)
_enabled["req_healthy"] = True

print("\n%s" % ("ALL PASS" if not _fail else "FAILED (%d)"%_fail))
sys.exit(1 if _fail else 0)
