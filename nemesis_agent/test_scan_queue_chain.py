#!/usr/bin/env python3
"""scan_queue -> scan_tasks chain: age survives it, and the queue row can't strand.

Run: python3 nemesis_agent/test_scan_queue_chain.py

TWO DEFECTS, ONE FUNCTION
-------------------------
1. STALENESS RESET. `_dispatch_pending_scans` turns a scan_queue row into a
   scan_tasks row. The new row got `created_at = now`, so work that waited three
   months in scan_queue arrived looking brand new. Any staleness check measured
   on created_at was silently defeated by the chain -- the more stale the work,
   the more convincingly fresh it looked. Fixed by carrying the original
   `queued_at` across as `origin_queued_at`.

2. STRANDING. The queue row was set to 'executing' BEFORE the work was handed
   off. Any dispatch failure left it there permanently: a scan that never runs,
   never retries, and reads as in-progress forever. Fixed by advancing the row
   only after dispatch actually succeeded, and rolling back the eager scan_jobs
   row otherwise.

WHAT THIS SUITE WEIGHTS TOWARD
------------------------------
Both defects are ORDERING and PROVENANCE properties, not value computations, so
most checks here assert sequence and survival rather than return values. The
ordering assertions are AST-based: they compare the line at which dispatch
happens against the line at which the queue row is advanced. That is a real
structural property, and it is checked against the parsed tree rather than by
matching source text -- the phrase "executing" appears in prose comments in this
same function (including comments explaining this very fix), so a grep would
match the explanation instead of the code.

`task_age_basis` is pure, so it is exercised directly with real values. No
database is touched by this suite.
"""
import ast
import os
import sys
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
HW = os.path.join(REPO, "core_module", "hw_monitor", "hw_monitor.py")
sys.path.insert(0, os.path.join(REPO, "core_module", "hw_monitor"))
sys.path.insert(0, "/opt/nemesis/alert_manager")

EXPECTED_CHECKS = 16

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def parse():
    with open(HW) as fh:
        return ast.parse(fh.read(), HW)


def function_named(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def call_lines(node, name, kwarg=None):
    """Lines where `name` is called, optionally requiring a given keyword."""
    hits = []
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        fn = sub.func
        got = fn.id if isinstance(fn, ast.Name) else (
            fn.attr if isinstance(fn, ast.Attribute) else None)
        if got != name:
            continue
        if kwarg and not any(k.arg == kwarg for k in sub.keywords):
            continue
        hits.append(sub.lineno)
    return sorted(hits)


def sql_lines(node, fragment):
    """Lines of string constants containing `fragment`.

    Only string CONSTANTS in the parsed tree -- comments are absent from the AST
    entirely, which is the point: this function's comments discuss 'executing'
    at length while explaining the fix.
    """
    hits = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str) \
                and fragment in sub.value:
            hits.append(sub.lineno)
    return sorted(hits)


def main():
    import hw_monitor as hw

    NOW = datetime(2026, 8, 4, 12, 0, 0)
    OLD = (NOW - timedelta(days=90)).isoformat(timespec="seconds")
    RECENT = (NOW - timedelta(minutes=5)).isoformat(timespec="seconds")

    # ── age survives the chain ───────────────────────────────────────────────
    print("\nage is measured from when the WORK was queued, not the row written")
    check("origin_queued_at wins when present",
          hw.task_age_basis(OLD, RECENT), datetime.fromisoformat(OLD))
    check("created_at is used when there is no earlier origin",
          hw.task_age_basis(None, RECENT), datetime.fromisoformat(RECENT))

    # The defect itself: a 90-day-old queue entry must not read as 5 minutes old.
    basis = hw.task_age_basis(OLD, RECENT)
    age_days = (NOW - basis).days if basis else None
    check("CONTROL 90-day-old queued work is not reported as fresh",
          age_days, 90)
    check("CONTROL without propagation it WOULD have looked fresh",
          (NOW - hw.task_age_basis(None, RECENT)).days, 0)

    # ── failed reads are explicit, never defaults ────────────────────────────
    print("\nan unusable timestamp is explicit, not silently 'now'")
    check("a malformed origin falls back to created_at",
          hw.task_age_basis("not-a-timestamp", RECENT),
          datetime.fromisoformat(RECENT))
    check("both unusable yields an explicit None, not a default time",
          hw.task_age_basis(None, None), None)
    check("a malformed pair also yields None", hw.task_age_basis("x", "y"), None)
    check("None is distinguishable from any real timestamp",
          isinstance(hw.task_age_basis(None, None), datetime), False)

    tree = parse()

    # ── the column exists, on fresh installs AND existing DBs ───────────────
    print("\nthe column is declared and migrated onto existing databases")
    init = function_named(tree, "init_db")
    ddl = sql_lines(init, "origin_queued_at TEXT") if init else []
    check("origin_queued_at is in the CREATE TABLE", bool(ddl), True)
    # A column added only to the CREATE reaches fresh installs and silently
    # misses every existing database -- the failure appears later, as a column
    # that is simply always NULL in production.
    mig = [ln for ln in sql_lines(init, "origin_queued_at")] if init else []
    check("it is also in the guarded ALTER migration list", len(mig) >= 2, True)

    enq = function_named(tree, "enqueue_task")
    args = [a.arg for a in enq.args.args] if enq else []
    check("enqueue_task accepts origin_queued_at",
          "origin_queued_at" in args, True)
    check("the INSERT names the origin_queued_at column",
          bool(sql_lines(enq, "origin_queued_at")), True)

    # ── propagation and ordering in the chain ───────────────────────────────
    print("\nthe chain propagates the original queue time, and cannot strand")
    disp = function_named(tree, "_dispatch_pending_scans")
    check("the scan_queue SELECT reads queued_at",
          bool(sql_lines(disp, "queued_at FROM scan_queue")), True)
    check("enqueue_task is called WITH origin_queued_at",
          bool(call_lines(disp, "enqueue_task", kwarg="origin_queued_at")), True)

    # THE ordering assertion. 'executing' must be written after dispatch.
    enq_line = min(call_lines(disp, "enqueue_task") or [10 ** 9])
    exec_line = min(sql_lines(disp, "status='executing'") or [0])
    check("CONTROL the queue row is advanced AFTER dispatch, not before",
          exec_line > enq_line, True)
    check("a failed dispatch rolls back the eager scan_jobs row",
          bool(sql_lines(disp, "DELETE FROM scan_jobs")), True)

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
