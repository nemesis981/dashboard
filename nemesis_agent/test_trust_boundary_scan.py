#!/usr/bin/env python3
"""Readmitting a device forces a scan, however short the withdrawal was.

Run: python3 nemesis_agent/test_trust_boundary_scan.py

THE GAP THIS CLOSES
-------------------
`api_agent_revoke` only flipped `enrollment_status`; the `agent_devices` row
survived. So on re-approval `first_connect` could never fire — it tests
`prev is None` — and `extended_absence` needs 24h. A device revoked and
reinstated inside a day was therefore readmitted with NO scan of any kind, even
though revocation exists precisely because trust was withdrawn. An hour is
enough to introduce something.

Now any transition into 'approved' from a trust-withdrawn status queues a
mandatory scan.

THE PROPERTY MOST LIKELY TO REGRESS SILENTLY
--------------------------------------------
The prior status must be read BEFORE the UPDATE. Read afterwards it is always
'approved', so the crossing becomes undetectable — and the code would still run,
still report success, and still look correct. That ordering is asserted here by
comparing AST line numbers, not by reading the source as text: this function's
comments discuss 'approved' and the ordering at length, and a grep would match
the explanation rather than the code.

WHY IT IS NOT ROUTED THROUGH scan_conditions
--------------------------------------------
first_connect and its siblings are configurable rows in `scan_conditions`. This
one is not, deliberately: it is the one scan that must not be switchable from a
settings page. That independence is asserted too, because "make it consistent
with the other triggers" is exactly the tidy-up that would silently make it
optional again.
"""
import ast
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
HW = os.path.join(REPO, "core_module", "hw_monitor", "hw_monitor.py")
DASH = os.path.join(REPO, "dashboard.py")
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


def code_strings_in(fn):
    """String constants in a function's CODE, excluding its docstring.

    Comments never reach the AST, but a docstring does — it is a real string
    constant. So a check asking "does this function touch X?" will happily match
    the docstring explaining why it does NOT touch X. That is the same
    substring-versus-behaviour confusion this file exists to avoid, and it caught
    this suite on its first run: the `scan_conditions` check matched its own
    rationale.
    """
    body = list(fn.body)
    if body and isinstance(body[0], ast.Expr) and \
            isinstance(body[0].value, ast.Constant) and \
            isinstance(body[0].value.value, str):
        body = body[1:]          # drop the docstring, keep the code
    out = set()
    for stmt in body:
        out |= strings_in(stmt)
    return out


def sql_lines(node, fragment):
    return sorted(n.lineno for n in ast.walk(node)
                  if isinstance(n, ast.Constant) and isinstance(n.value, str)
                  and fragment in n.value)


def call_lines(node, name):
    hits = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            fn = sub.func
            got = fn.id if isinstance(fn, ast.Name) else (
                fn.attr if isinstance(fn, ast.Attribute) else None)
            if got == name:
                hits.append(sub.lineno)
    return sorted(hits)


def main():
    import hw_monitor as hw

    hw_tree = parse(HW)
    dash = parse(DASH)
    approve = function_named(dash, "api_agent_approve")

    # ── which statuses count as a crossing ───────────────────────────────────
    print("\nthe trust-withdrawn statuses are exactly the ones that matter")
    check("revoked counts as trust withdrawn",
          "revoked" in hw.TRUST_WITHDRAWN_STATUSES, True)
    check("uninstalled counts as trust withdrawn",
          "uninstalled" in hw.TRUST_WITHDRAWN_STATUSES, True)
    # Added once the UI fix made rejected devices visible and re-approvable. The
    # agent SERVICE survives a rejection (it exits rather than being removed), so
    # re-approval genuinely readmits a machine nobody has checked since.
    check("rejected counts as trust withdrawn",
          "rejected" in hw.TRUST_WITHDRAWN_STATUSES, True)
    # A first-time approval is not a re-admission: that path already runs the
    # pre-enrollment scan and first_connect.
    check("CONTROL pending is not treated as a crossing",
          "pending" in hw.TRUST_WITHDRAWN_STATUSES, False)
    check("CONTROL approved is not treated as a crossing",
          "approved" in hw.TRUST_WITHDRAWN_STATUSES, False)

    # ── the mandatory scan helper reports honestly ──────────────────────────
    print("\nthe helper reports what actually happened")
    fn = function_named(hw_tree, "queue_reinstatement_scan")
    check("queue_reinstatement_scan exists", fn is not None, True)
    # A bare bool (or None) would leave the caller unable to distinguish "queued"
    # from "silently deduped" from "failed" -- the whole reason this exists
    # rather than calling _queue_scan directly.
    returns = [n for n in ast.walk(fn) if isinstance(n, ast.Return)] if fn else []
    tuple_returns = [n for n in returns if isinstance(n.value, ast.Tuple)]
    check("it returns a (queued, reason) pair, not a bare bool",
          len(returns) > 0 and len(tuple_returns) == len(returns), True)
    check("it distinguishes an existing pending reinstatement",
          "already_pending" in strings_in(fn), True)
    check("it has its own trigger_type", hw.REINSTATEMENT_TRIGGER, "reinstated")

    # ── mandatory means not configurable ────────────────────────────────────
    print("\nthe mandatory scan cannot be switched off")
    # If it consulted scan_conditions it would inherit an enable/disable flag,
    # making the one non-optional scan optional.
    check("CONTROL it does not consult the scan_conditions table",
          any("scan_conditions" in s for s in code_strings_in(fn)), False)
    # _queue_scan skips insertion when ANY pending scan exists and reports
    # nothing back, which would let an unrelated row swallow this one.
    check("CONTROL it does not delegate to the deduping _queue_scan helper",
          bool(call_lines(fn, "_queue_scan")), False)
    check("its dedup is narrowed to its own trigger_type",
          bool(sql_lines(fn, "trigger_type=?")), True)

    # ── the route wires it up, in the right order ───────────────────────────
    print("\nthe approve route detects the crossing before it destroys the evidence")
    check("the approve route calls the mandatory scan helper",
          bool(call_lines(approve, "queue_reinstatement_scan")), True)
    read_line = min(sql_lines(approve, "SELECT enrollment_status") or [10 ** 9])
    write_line = min(sql_lines(approve, "SET enrollment_status='approved'") or [0])
    # THE ordering assertion: read the prior status BEFORE overwriting it.
    check("CONTROL prior status is read BEFORE the UPDATE overwrites it",
          read_line < write_line, True)
    check("the crossing is gated on TRUST_WITHDRAWN_STATUSES, not a local literal",
          "TRUST_WITHDRAWN_STATUSES" in {
              n.attr for n in ast.walk(approve) if isinstance(n, ast.Attribute)},
          True)
    check("a failed queue is logged as an error, not swallowed",
          bool(call_lines(approve, "error")), True)

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
