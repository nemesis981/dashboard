#!/usr/bin/env python3
"""Revocation records WHEN and BY WHOM, not just that it happened.

Run: python3 nemesis_agent/test_revoke_provenance.py

THE DEFECT
----------
`api_agent_revoke` set `enrollment_status='revoked'` and nothing else. Its
sibling, the agent-initiated uninstall, recorded `uninstalled_at` AND
`uninstalled_by` on the same table. That asymmetry is the defect: a revoked
device carried no timestamp and no actor on its own row, so the question a
trust-boundary check has to answer -- "was this work queued BEFORE this device
was revoked?" -- was unanswerable from agent_devices at all.

The `_audit` entry does record the event, but it lives in a different table.
Reconstructing a device's own history by joining an audit log is not what a
per-row check needs, and the absence was invisible precisely because the
revocation still "worked": the status flipped, the device stopped being
dispatched to, and nothing looked wrong.

WHY THIS IS STRUCTURAL RATHER THAN BEHAVIOURAL
----------------------------------------------
Exercising the real route means POSTing to the live dashboard and writing to the
production alerts.db -- a state-changing action requiring a snapshot, for a
change whose entire content is "two more columns in one UPDATE". So this asserts
against the parsed source of both call sites instead, and states that limit
plainly rather than implying coverage it does not have.

The migration mechanism itself is NOT re-proven here: the sibling pair
uninstalled_at/uninstalled_by is already present in the live database, having
arrived by the identical guarded-ALTER list, which is the evidence that adding
to that list reaches real deployments.
"""
import ast
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
HW = os.path.join(REPO, "core_module", "hw_monitor", "hw_monitor.py")
DASH = os.path.join(REPO, "dashboard.py")

EXPECTED_CHECKS = 10

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def parse(path):
    with open(path) as fh:
        return ast.parse(fh.read(), path)


def function_named(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def strings_in(node):
    return {n.value for n in ast.walk(node)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)}


def mentions(node, needle):
    """True if any string constant under `node` contains `needle`.

    String constants only -- comments are not in the AST, which matters here
    because both call sites discuss these column names at length in prose.
    """
    return any(needle in s for s in strings_in(node))


def calls(node, name):
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            fn = sub.func
            got = fn.id if isinstance(fn, ast.Name) else (
                fn.attr if isinstance(fn, ast.Attribute) else None)
            if got == name:
                return True
    return False


def main():
    hw = parse(HW)
    dash = parse(DASH)

    # ── the columns reach real databases ─────────────────────────────────────
    print("\nthe columns are declared where they actually reach databases")
    init = function_named(hw, "init_db")
    init_strings = strings_in(init) if init else set()
    check("revoked_at is in the agent_devices migration list",
          "revoked_at" in init_strings, True)
    check("revoked_by is in the agent_devices migration list",
          "revoked_by" in init_strings, True)
    # Declared alongside the pair already proven to have landed in production --
    # a column added to some OTHER list, or only to a CREATE TABLE, would not
    # reach an existing database at all.
    check("CONTROL they sit in the same list as the uninstall pair",
          {"uninstalled_at", "uninstalled_by"} <= init_strings, True)

    # ── the revoke route records them ────────────────────────────────────────
    print("\nthe revoke route writes both, with a real actor")
    revoke = function_named(dash, "api_agent_revoke")
    check("the revoke UPDATE names revoked_at", mentions(revoke, "revoked_at"), True)
    check("the revoke UPDATE names revoked_by", mentions(revoke, "revoked_by"), True)
    # A literal would make every revocation look like the same actor -- the actor
    # seam exists to answer "who", so a hardcoded value is worse than NULL.
    check("the actor comes from _actor(), not a hardcoded string",
          calls(revoke, "_actor"), True)
    check("CONTROL it still sets enrollment_status='revoked'",
          mentions(revoke, "enrollment_status='revoked'"), True)

    # ── parity with the sibling path, which is what was missing ─────────────
    print("\nrevoke and uninstall now record the same shape of evidence")
    uninstall = function_named(hw, "_create_uninstall")
    check("uninstall still records its timestamp",
          mentions(uninstall, "uninstalled_at"), True)
    check("uninstall still records its actor",
          mentions(uninstall, "uninstalled_by"), True)
    revoke_pair = mentions(revoke, "revoked_at") and mentions(revoke, "revoked_by")
    uninstall_pair = (mentions(uninstall, "uninstalled_at")
                      and mentions(uninstall, "uninstalled_by"))
    check("CONTROL both trust-withdrawal paths now record timestamp AND actor",
          revoke_pair and uninstall_pair, True)

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
