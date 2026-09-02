#!/usr/bin/env python3
"""ADR 0012 FLEET-auto — the typed gate on auto-approving installer tokens.

Run: python3 nemesis_agent/test_fleet_auto_typed_gate.py

The gate sits at token SETUP, not at device enrollment, and that placement is
the design: no human is present when a device later redeems the token — that is
what auto-approve MEANS — so the acknowledgement can only be captured when the
grant is created.

dashboard.py is not imported (it builds a live Flask app), so the route is
checked by parsing its source, same approach as test_revoke_route.py and
test_bulk_approve.py. The JS half is cross-checked against the rendered HTML,
because a selector mismatch there is silent: the control renders, the click
does nothing, and every single-file check still passes.
"""
import ast
import re
import sys

DASHBOARD = "/opt/nemesis/dashboard.py"
JS = "/opt/nemesis/static/agent-enroll.js"

EXPECTED_CHECKS = 18
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def function_named(tree, name):
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return n
    return None


def main():
    src = open(DASHBOARD).read()
    js = open(JS).read()
    tree = ast.parse(src)
    fn = function_named(tree, "api_agent_installer_generate")
    check("CONTROL the generate route was found and parsed", fn is not None, True)
    body = ast.get_source_segment(src, fn) or ""
    check("CONTROL the body was extracted (non-trivial)", len(body) > 500, True)

    print("\nthe gate is enforced SERVER-SIDE and only on the auto-approve path")
    check("the route requires a confirmation when auto_approve is set",
          'if auto_approve and str(data.get("confirm")' in body, True)
    check("it refuses with 400, not a silent pass", '"confirmation required"' in body, True)
    check("it states what it expected", '"expected": "yes"' in body, True)
    # The safe default must not acquire new friction.
    check("THE PROPERTY: the gate is conditional on auto_approve, not global",
          bool(re.search(r"if auto_approve and ", body)), True)
    check("CONTROL a non-auto installer sends no confirmation and is not gated",
          "confirm" in js and "if (auto) {" in js, True)

    print("\nthe warning names the actual consequence, not a vague caution")
    for phrase in ("TRUSTED NETWORK ACCESS", "without review", "physically own"):
        check("warning mentions %r" % phrase, phrase in body, True)

    print("\nthe browser sends what the human typed")
    check("THE PROPERTY: the JS sends the TYPED value", "confirm: confirmWord" in js, True)
    check("CONTROL it does not hardcode the confirmation string",
          bool(re.search(r"confirm:\s*['\"]yes['\"]", js)), False)
    check("the prompt only appears for auto-approve", "if (auto) {" in js, True)
    check("cancelling is distinguished from typing a wrong value",
          "confirmWord === null" in js, True)

    print("\nsubnet field: JS and rendered HTML agree (a mismatch here is silent)")
    check("the JS reads #installerSubnet", "getElementById('installerSubnet')" in js, True)
    check("the page emits #installerSubnet", 'id="installerSubnet"' in src, True)
    check("the JS sends it as source_subnet", "source_subnet: subnet" in js, True)
    check("the route validates it and rejects a malformed value",
          "is not a valid network" in body, True)

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [l for l, ok in _results if not ok]
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
