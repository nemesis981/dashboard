#!/usr/bin/env python3
"""A pre-enrollment scan that could not run must not read as clean.

Run: python3 nemesis_agent/test_enroll_scan_status.py

THE DEFECT
----------
`_create_enrollment` computed `enroll_status = "pending_with_findings" if
has_findings else "pending"`. That collapsed three different situations into two
values: a device scanned and found clean, a device whose scanner was not
installed ("not_available"), and a device whose scan errored ("scan_failed") all
became plain "pending".

So a machine that was never scanned enrolled carrying exactly the status of a
machine that was scanned and verified clean. The scan JSON recorded the
difference; the decision threw it away. That is an absent measurement wearing a
real result's costume — the same class this repo keeps finding, here on the
enrollment trust boundary.

The dashboard badge happened to render the distinction because it reads
`scan_status` out of the JSON directly, which is why this stayed invisible: the
screen looked right while the stored, queryable value was wrong.

THE SECOND TRAP THIS SUITE GUARDS
---------------------------------
The device list groups rows by `enrollment_status` with a hardcoded ALLOWLIST.
A status missing from it matches neither pending, enrolled, nor revoked — and
the device disappears from the UI completely, leaving no way to approve it.
The codebase already learned this once (see the 'revoked' comment beside that
list). Adding a status without adding it to the allowlist would fix the audit
trail by making the device unapprovable, which is a worse bug than the one being
fixed. That grouping is asserted here by AST, against the real dashboard source.

Pure logic + structural checks; no database is touched.
"""
import ast
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
HW = os.path.join(REPO, "core_module", "hw_monitor", "hw_monitor.py")
DASH = os.path.join(REPO, "dashboard.py")

EXPECTED_CHECKS = 22

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def enroll_status_for(scan):
    """Mirror of the shipped decision, kept in lockstep by the AST checks below.

    Reimplemented rather than imported because the real logic sits inline inside
    _create_enrollment, which needs a signed payload and a database to reach. The
    structural checks at the end are what stop this mirror from drifting: they
    assert the shipped source really contains each branch this models.
    """
    scan_status = scan.get("scan_status")
    total_f = int(scan.get("clamav_findings") or 0) + int(scan.get("yara_findings") or 0)
    has_findings = 1 if (scan_status == "findings" or total_f > 0) else 0
    scan_verified = bool(scan) and scan_status not in (
        None, "", "not_available", "scan_failed")
    if has_findings:
        return "pending_with_findings"
    if not scan_verified:
        return "pending_unverified"
    return "pending"


def auto_approve_status(scan, token_ok):
    """Mirror of the shipped decision INCLUDING the installer-token branch.

    A valid token claims a use and can auto-approve, but only on completed, clean
    scan evidence. Otherwise the enrollment holds at whatever status the manual
    path would have produced — deliberately the same value, so there is one set
    of pending states rather than a parallel set meaning almost the same thing.
    """
    base = enroll_status_for(scan)
    if not token_ok:
        return base
    scan_status = scan.get("scan_status")
    total_f = int(scan.get("clamav_findings") or 0) + int(scan.get("yara_findings") or 0)
    has_findings = 1 if (scan_status == "findings" or total_f > 0) else 0
    scan_verified = bool(scan) and scan_status not in (
        None, "", "not_available", "scan_failed")
    if scan_verified and not has_findings:
        return "approved"
    return base


def parse(path):
    with open(path) as fh:
        return ast.parse(fh.read(), path)


def string_constants(tree):
    return {n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)}


def function_named(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def main():
    CLEAN = {"scan_status": "clean", "clamav_findings": 0, "yara_findings": 0}
    ABSENT = {"scan_status": "not_available", "clamav_findings": 0, "yara_findings": 0}
    FAILED = {"scan_status": "scan_failed", "clamav_findings": 0, "yara_findings": 0}
    FOUND = {"scan_status": "findings", "clamav_findings": 2, "yara_findings": 0}

    print("\nan unrun scan is distinguishable from a clean one")
    check("a verified-clean scan enrols as plain pending",
          enroll_status_for(CLEAN), "pending")
    check("CONTROL an absent scanner does NOT enrol as clean-equivalent",
          enroll_status_for(ABSENT) == enroll_status_for(CLEAN), False)
    check("an absent scanner enrols as pending_unverified",
          enroll_status_for(ABSENT), "pending_unverified")
    check("CONTROL a failed scan also does not read as clean",
          enroll_status_for(FAILED) == enroll_status_for(CLEAN), False)
    check("a failed scan enrols as pending_unverified",
          enroll_status_for(FAILED), "pending_unverified")
    check("an empty scan payload is unverified, not clean",
          enroll_status_for({}), "pending_unverified")
    check("a missing scan_status is unverified, not clean",
          enroll_status_for({"clamav_findings": 0}), "pending_unverified")

    print("\nfindings still win over everything else")
    check("a scan with findings enrols as pending_with_findings",
          enroll_status_for(FOUND), "pending_with_findings")
    # Contradictory input: counts present but the scan claims it never ran.
    # Findings must win — the safer reading of an inconsistent report.
    check("CONTROL findings win even if scan_status says not_available",
          enroll_status_for({"scan_status": "not_available", "clamav_findings": 3}),
          "pending_with_findings")

    print("\nthe shipped code really contains these branches")
    hw = parse(HW)
    enroll_fn = function_named(hw, "_create_enrollment") or hw
    consts = string_constants(enroll_fn)
    check("the shipped enrollment emits pending_unverified",
          "pending_unverified" in consts, True)
    check("it still emits pending_with_findings", "pending_with_findings" in consts, True)
    check("it treats scan_failed as unverified too", "scan_failed" in consts, True)

    print("\nthe new status cannot make a device vanish from the UI")
    dash = parse(DASH)
    dash_consts = string_constants(dash)
    # THE trap: the device list is an allowlist. A status absent from it matches
    # no group and the device disappears, leaving no way to approve it.
    check("CONTROL dashboard grouping lists pending_unverified explicitly",
          "pending_unverified" in dash_consts, True)
    check("the other pending-family statuses are still listed",
          {"pending", "pending_with_findings"} <= dash_consts, True)

    # ── a valid installer token does not substitute for scan evidence ───────
    print("\nauto-approve requires completed, clean scan evidence")
    check("POSITIVE a clean scan + valid token still auto-approves",
          auto_approve_status(CLEAN, token_ok=True), "approved")
    # The case the operator named: an employee enrolling their own unmanaged
    # device with a legitimate token. The token is genuine, the machine unknown.
    check("CONTROL an absent scanner + valid token does NOT auto-approve",
          auto_approve_status(ABSENT, token_ok=True), "pending_unverified")
    check("CONTROL a failed scan + valid token does NOT auto-approve",
          auto_approve_status(FAILED, token_ok=True), "pending_unverified")
    # Previously the worst case: a device with known findings auto-approved just
    # as readily as a clean one, because the token overrode the scan outcome.
    check("CONTROL findings + valid token does NOT auto-approve",
          auto_approve_status(FOUND, token_ok=True), "pending_with_findings")
    # A withheld token enrollment must land on the SAME status the manual path
    # produces — one set of pending states, not a parallel near-synonym.
    check("a withheld token enrollment matches the manual path's status",
          auto_approve_status(ABSENT, token_ok=True), enroll_status_for(ABSENT))
    check("CONTROL no token at all is unchanged by this gate",
          auto_approve_status(CLEAN, token_ok=False), enroll_status_for(CLEAN))

    print("\nthe shipped gate exists and the hold is explained")
    src = open(HW).read()
    check("the shipped code gates approval on scan_verified and findings",
          "if scan_verified and not has_findings:" in src, True)
    check("a withheld hold is surfaced to the owner, not silent",
          "auto_approve_withheld" in string_constants(hw)
          or "auto_approve_withheld" in src, True)

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [lbl for lbl, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d "
              "-- a check was skipped, not merely failed" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
