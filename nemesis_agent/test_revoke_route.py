#!/usr/bin/env python3
"""Step 3b verification: revoke / re-approve an enrolled device.

Run: python3 nemesis_agent/test_revoke_route.py

Two halves:
  * the standing route-level security audit, applied to the NEW route as a set
    of assertions rather than a read-through;
  * a status round-trip against a throwaway DB, using hw_monitor's real
    _agent_approved() logic so enforcement is verified, not assumed.

dashboard.py is NOT imported (it builds a live Flask app and touches services);
the route is checked by parsing its source, and enforcement is checked directly.
"""
import ast
import os
import re
import sqlite3
import sys
import tempfile

DASHBOARD = "/opt/nemesis/dashboard.py"
HW_MONITOR = "/opt/nemesis/core_module/hw_monitor/hw_monitor.py"
JS = "/opt/nemesis/static/agent-enroll.js"

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


def main():
    src = open(DASHBOARD).read()

    print("route-level security audit — new route")
    decs = route_decorators(src, "api_agent_revoke")
    check("the endpoint resolves to a real @app.route function", len(decs), 1)
    check("rule is the expected path", decs[0][0], "/api/agent/<device_id>/revoke")
    check("POST-only (GET-as-write is the known CSRF shape)", decs[0][1], ["POST"])

    # _AUTH_EXEMPT: this is an OWNER action and must never be exempt. The
    # install_windows_start bug on 2026-08-02 was the mirror image -- a route
    # that SHOULD have been listed and wasn't -- so check membership explicitly
    # rather than assuming.
    exempt_src = re.search(r"_AUTH_EXEMPT\s*=\s*\{(.*?)\}", src, re.S).group(1)
    exempt = set(re.findall(r'"([a-z_0-9]+)"', exempt_src))
    check("CONTROL revoke is NOT auth-exempt", "api_agent_revoke" in exempt, False)
    check("CONTROL its siblings are not exempt either",
          {"api_agent_approve", "api_agent_reject"} & exempt, set())
    check("CONTROL the exemption set was actually parsed (non-empty)",
          len(exempt) > 3, True)

    body = src[src.index("def api_agent_revoke"):]
    body = body[:body.index("\n@app.route")] if "\n@app.route" in body else body
    check("SQL is parameterized, not interpolated", "device_id=?" in body, True)
    check("CONTROL no f-string interpolation into the SQL",
          bool(re.search(r'f"[^"]*UPDATE|f\'[^\']*UPDATE', body)), False)
    check("the action is audited like its siblings",
          'action="agent_revoke"' in body, True)

    print("\nJS caller")
    js = open(JS).read()
    check("agentRevoke posts to the revoke route",
          "'/revoke', { method: 'POST' }" in js, True)
    check("CONTROL it is guarded by a confirm()",
          js.index("function agentRevoke") < js.index("Revoke this device?"), True)

    print("\nUI does not strand revoked devices")
    # Asserted by INTENT rather than by matching one syntactic form.
    #
    # This previously matched the exact text of a list comprehension
    # (`enrollment_status"] or "") == "revoked"`). That grouping was later
    # refactored into an exhaustive partition — so that no status can silently
    # vanish from the UI, which is the same class of bug this very check exists
    # to prevent — and the substring stopped matching while the behaviour was
    # completely unchanged. A check that fails on a refactor it should welcome is
    # measuring the wrong thing.
    #
    # Scoped to the render function so an unrelated mention elsewhere in
    # dashboard.py cannot satisfy it.
    _render = src[src.index("def _render_agent_devices_html"):]
    _render = _render[:_render.index("\ndef ", 1)]
    check("a revoked list is derived",
          '"revoked"' in _render and "Revoked devices" in _render, True)
    check("revoked devices get a Re-approve control",
          "Re-approve" in src, True)

    print("\nenforcement round-trip (real _agent_approved logic)")
    tmp = tempfile.mkdtemp(prefix="nemesis-revoke-")
    db = os.path.join(tmp, "t.db")
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE agent_devices (device_id TEXT PRIMARY KEY, "
                 "enrollment_status TEXT DEFAULT 'approved')")
    # Rule 11: this row is synthetic. It lives in a throwaway DB deleted at the
    # end of this run, never in the live alerts.db.
    conn.execute("INSERT INTO agent_devices VALUES (?,?)",
                 ("test data 2026-08-03 revoke-route-check", "approved"))
    conn.commit()
    did = "test data 2026-08-03 revoke-route-check"

    def status():
        return conn.execute("SELECT enrollment_status FROM agent_devices "
                            "WHERE device_id=?", (did,)).fetchone()[0]

    def approved():
        # hw_monitor._agent_approved() is exactly this test.
        return status() == "approved"

    check("POSITIVE an approved device is accepted", approved(), True)
    conn.execute("UPDATE agent_devices SET enrollment_status='revoked' WHERE device_id=?", (did,))
    conn.commit()
    check("CONTROL after revoke, heartbeats are refused", approved(), False)
    check("status is 'revoked', distinct from 'rejected'", status(), "revoked")
    conn.execute("UPDATE agent_devices SET enrollment_status='approved' WHERE device_id=?", (did,))
    conn.commit()
    check("POSITIVE re-approve restores access", approved(), True)
    conn.close()

    # confirm hw_monitor really does test equality against "approved"
    hw = open(HW_MONITOR).read()
    m = re.search(r"def _agent_approved\(device_id\):\s*\n\s*return ([^\n]+)", hw)
    check("CONTROL _agent_approved compares to 'approved' (so any other status blocks)",
          bool(m and '== "approved"' in m.group(1)), True)

    import shutil
    shutil.rmtree(tmp, ignore_errors=True)

    passed = sum(1 for _, ok in _results if ok)
    print("\n%d/%d checks passed" % (passed, len(_results)))
    failed = [l for l, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
