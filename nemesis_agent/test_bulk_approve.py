#!/usr/bin/env python3
"""ADR 0012 build-spec step 1 — BULK-MANUAL batch approve.

Run: python3 nemesis_agent/test_bulk_approve.py

Three halves:
  * the standing route-level security audit, applied to the new route as
    assertions rather than a read-through;
  * registry completeness — a route missing from ROUTE_MINIMUMS 404s, which
    reads as "no such route" rather than "misconfigured";
  * THE SAFETY PROPERTY: this route deliberately omits api_agent_approve's
    trust-boundary rescan, and that is only safe because its eligible set and
    hw_monitor.TRUST_WITHDRAWN_STATUSES are DISJOINT. That disjointness is
    asserted here, with a liveness control, so widening the eligible set later
    turns this red instead of silently creating a rescan bypass.

dashboard.py is NOT imported (it builds a live Flask app and touches services),
so the route is checked by parsing its source — same approach as
test_revoke_route.py. The set-disjointness half uses the real values.
"""
import ast
import os
import re
import sys

DASHBOARD = "/opt/nemesis/dashboard.py"
HW_MONITOR = "/opt/nemesis/core_module/hw_monitor/hw_monitor.py"

# Declared up front and asserted at the end: a suite whose shape changes between
# runs is not comparable to a previous run, and a check that silently stops
# running looks exactly like a check that passed.
EXPECTED_CHECKS = 37

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 50:
        g, w = g[:47] + "...", w[:47] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def route_decorators(src, func_name):
    """Every @app.route(...) decorating func_name, as (rule, methods)."""
    tree = ast.parse(src)
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call):
                    continue
                rule = dec.args[0].value if dec.args else None
                methods = None
                for kw in dec.keywords:
                    if kw.arg == "methods":
                        methods = [e.value for e in kw.value.elts]
                out.append((rule, methods))
    return out


def function_named(tree, name):
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return n
    return None


def call_names(node):
    out = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            fn = sub.func
            got = fn.id if isinstance(fn, ast.Name) else (
                fn.attr if isinstance(fn, ast.Attribute) else None)
            if got:
                out.add(got)
    return out


def sql_lines(node, fragment):
    return sorted(n.lineno for n in ast.walk(node)
                  if isinstance(n, ast.Constant) and isinstance(n.value, str)
                  and fragment in n.value)


def literal_tuple(src, name):
    """Read a module-level tuple-of-strings constant out of source."""
    tree = ast.parse(src)
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return tuple(e.value for e in n.value.elts)
    return None


def main():
    src = open(DASHBOARD).read()
    tree = ast.parse(src)
    fn = function_named(tree, "api_agent_bulk_approve")

    # ── route-level security audit ───────────────────────────────────────────
    print("route-level security audit — the new batch route")
    decs = route_decorators(src, "api_agent_bulk_approve")
    check("the endpoint resolves to a real @app.route function", len(decs), 1)
    check("rule is the expected path", decs[0][0] if decs else None,
          "/api/agent/bulk-approve")
    check("POST-only (GET-as-write is the known CSRF shape)",
          decs[0][1] if decs else None, ["POST"])
    # If the parse failed, every AST assertion below would report a confident
    # nothing. Prove the instrument found the function before trusting it.
    check("CONTROL the function body was actually parsed", fn is not None, True)

    exempt_src = re.search(r"_AUTH_EXEMPT\s*=\s*\{(.*?)\}", src, re.S).group(1)
    exempt = set(re.findall(r'"([a-z_0-9]+)"', exempt_src))
    check("bulk approve is NOT auth-exempt",
          "api_agent_bulk_approve" in exempt, False)
    check("CONTROL the exemption set was actually parsed (non-empty)",
          len(exempt) > 3, True)

    body = src[src.index("def api_agent_bulk_approve"):]
    body = body[:body.index("\n@app.route")] if "\n@app.route" in body else body
    check("SQL is parameterized, not interpolated", "device_id=?" in body, True)
    check("CONTROL no f-string interpolation into the SQL",
          bool(re.search(r'f"[^"]*(SELECT|UPDATE)[^"]*\{', body)), False)

    # ── the two gates this route has that its siblings do not ───────────────
    print("\nthe typed confirmation is enforced SERVER-SIDE, not just in the browser")
    check("the route compares against the confirmation constant",
          "_BULK_APPROVE_CONFIRM" in {n.id for n in ast.walk(fn)
                                      if isinstance(n, ast.Name)}, True)
    check("a non-string / missing confirmation is refused (isinstance guard)",
          "isinstance(confirm, str)" in body, True)
    check("the refusal is a 400, not a silent pass", "400" in body, True)

    print("\neligibility is re-read from the DB, never taken from the client")
    read_lines = sql_lines(fn, "SELECT enrollment_status")
    write_lines = sql_lines(fn, "SET enrollment_status='approved'")
    check("it SELECTs the current status", bool(read_lines), True)
    check("it UPDATEs to approved", bool(write_lines), True)
    # Same ordering property the single-device route is held to: decide on the
    # prior status BEFORE overwriting it, or the check reports on its own write.
    check("CONTROL status is read BEFORE the UPDATE overwrites it",
          min(read_lines or [10 ** 9]) < min(write_lines or [0]), True)
    check("eligibility is gated on the constant, not a local literal",
          "_BULK_APPROVE_ELIGIBLE" in {n.id for n in ast.walk(fn)
                                       if isinstance(n, ast.Name)}, True)
    check("the batch size is bounded",
          "_BULK_APPROVE_MAX" in {n.id for n in ast.walk(fn)
                                  if isinstance(n, ast.Name)}, True)

    print("\nthe audit trail records every device, not a summary")
    check("it audits through the shared _audit path", "_audit" in call_names(fn), True)
    check("it uses the SAME action string as the single-device route",
          'action="agent_approve"' in body, True)
    check("a refusal is reported, not dropped", '"refused"' in body, True)

    # ── THE SAFETY PROPERTY ─────────────────────────────────────────────────
    # This route omits the trust-boundary rescan that api_agent_approve carries.
    # That is safe ONLY while no trust-withdrawn status can reach this route.
    print("\nthe absent trust-boundary rescan is safe ONLY if the sets are disjoint")
    eligible = literal_tuple(src, "_BULK_APPROVE_ELIGIBLE")
    hw_src = open(HW_MONITOR).read()
    withdrawn = literal_tuple(hw_src, "TRUST_WITHDRAWN_STATUSES")
    # Vacuity guards FIRST. An empty set is disjoint from everything, so the
    # disjointness assertion below would pass loudest exactly when both reads
    # had failed -- the failure mode this codebase treats as a broken instrument.
    # Liveness proof by CONTENT, not by a magic count: a threshold calibrated to
    # today's size goes stale the moment the set is deliberately narrowed (it
    # did exactly that when pending_with_findings was excluded), and a stale
    # control fails for a reason unrelated to what it guards.
    check("CONTROL the eligible set was actually read (contains 'pending')",
          "pending" in (eligible or ()), True)
    check("CONTROL the trust-withdrawn set was actually read (non-empty)",
          bool(withdrawn) and len(withdrawn) >= 3, True)
    check("CONTROL the two reads produced DIFFERENT sets (not the same constant twice)",
          set(eligible or ()) != set(withdrawn or ()), True)
    check("THE PROPERTY: eligible ∩ trust-withdrawn is empty",
          sorted(set(eligible or ()) & set(withdrawn or ())), [])
    # Named individually so a future widening says WHICH status broke it.
    for st in ("revoked", "uninstalled", "rejected"):
        check("a %s device can never enter the batch" % st,
              st in (eligible or ()), False)
    check("CONTROL those statuses ARE the ones treated as a crossing",
          sorted(withdrawn or ()), ["rejected", "revoked", "uninstalled"])
    check("the route does NOT call the rescan helper (unreachable by construction)",
          "queue_reinstatement_scan" in call_names(fn), False)

    # The eligible set must be a SUBSET of what the review page shows as
    # pending -- the page is where the human picks the batch -- but it is
    # deliberately a PROPER subset, see below.
    page_pending = literal_tuple(src, "PENDING_STATUSES")
    check("CONTROL the review page's pending bucket was actually read",
          bool(page_pending) and len(page_pending) >= 3, True)
    check("every eligible status is one the review page shows as pending",
          sorted(set(eligible or ()) - set(page_pending or ())), [])

    # ── the SECOND deliberate narrowing ─────────────────────────────────────
    # A findings device is approvable only via agentApproveAnyway(), which
    # carries its own stronger warning. A generic batch confirmation is weaker,
    # so admitting findings devices here would make bulk approve the cheap way
    # around the one warning built for them.
    print("\na findings device stays a single-device, individually-warned decision")
    check("THE PROPERTY: pending_with_findings is NOT bulk-eligible",
          "pending_with_findings" in (eligible or ()), False)
    check("CONTROL it IS a status the review page treats as pending "
          "(so the exclusion is a real narrowing, not a typo)",
          "pending_with_findings" in (page_pending or ()), True)
    check("CONTROL the per-device findings gate still exists",
          "agentApproveAnyway" in src, True)

    # ── registry completeness (a missing entry 404s, and that reads as
    #    "no such route" rather than "misconfigured") ─────────────────────────
    print("\nregistry completeness")
    sys.path.insert(0, "/opt/nemesis")
    sys.path.insert(0, "/opt/nemesis/alert_manager")
    import roles as R
    check("registered in ROUTE_MINIMUMS",
          "api_agent_bulk_approve" in R.ROUTE_MINIMUMS, True)
    check("its floor is not LOOSER than the single-device route",
          R.ROUTE_MINIMUMS.get("api_agent_bulk_approve"),
          R.ROUTE_MINIMUMS.get("api_agent_approve"))
    check("carried by the approve_enrollment capability",
          "api_agent_bulk_approve" in R.CAPABILITY_ROUTES["approve_enrollment"], True)
    check("CONTROL the registry was actually imported (non-trivial size)",
          len(R.ROUTE_MINIMUMS) > 50, True)

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
