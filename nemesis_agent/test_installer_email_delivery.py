#!/usr/bin/env python3
"""Installer email delivery (roadmap: installer-email-delivery.md) — pure-function tests
plus route/schema/JS static checks.

Run: python3 nemesis_agent/test_installer_email_delivery.py

dashboard.py is not imported (it builds a live Flask app). Two pure functions
(_valid_email, _build_installer_email_body) are extracted verbatim and executed here,
same technique as test_transport_default.py's _classify_transport. Everything else
(route ordering, the no-SMTP-configured gate, Rule-8, the migration, JS/HTML field
agreement) is checked by parsing the actual source, same approach as
test_fleet_auto_typed_gate.py and test_revoke_route.py.
"""
import ast
import re
import sys
from datetime import datetime

DASHBOARD = "/opt/nemesis/dashboard.py"
DATABASE = "/opt/nemesis/alert_manager/database.py"
JS = "/opt/nemesis/static/agent-enroll.js"
EXPECTED_CHECKS = 45

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 46:
        g, w = g[:43] + "...", w[:43] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def extract(src_path, func_name, extra_ns=None):
    lines = open(src_path).read().splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("def %s(" % func_name))
    end = start + 1
    while end < len(lines) and (lines[end].startswith("    ") or not lines[end].strip()):
        end += 1
    ns = dict(extra_ns or {})
    exec(compile("\n".join(lines[start:end]), src_path, "exec"), ns)
    return ns[func_name]


def function_named(tree, name):
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return n
    return None


def main():
    src = open(DASHBOARD).read()
    db_src = open(DATABASE).read()
    js = open(JS).read()
    tree = ast.parse(src)

    print("_valid_email — extracted verbatim, executed directly")
    valid_email = extract(DASHBOARD, "_valid_email", {"re": re})
    check("POSITIVE a normal address", valid_email("admin@example.com"), True)
    check("CONTROL missing @ is rejected", valid_email("adminexample.com"), False)
    check("CONTROL missing TLD is rejected", valid_email("admin@example"), False)
    check("CONTROL empty string is rejected", valid_email(""), False)
    check("CONTROL None is rejected, not a crash", valid_email(None), False)
    check("CONTROL embedded whitespace is rejected", valid_email("a dmin@example.com"), False)

    print("\n_build_installer_email_body — extracted verbatim, executed directly")
    build_body = extract(DASHBOARD, "_build_installer_email_body", {"datetime": datetime})
    body_min = build_body("Laptop", "", "", "https://n.example/zip/abc", 1893456000)
    check("contains the device hint", "Laptop" in body_min, True)
    check("contains the download link", "https://n.example/zip/abc" in body_min, True)
    check("CONTROL omits a support line when support_contact is blank",
          "Questions?" in body_min, False)
    body_full = build_body("Laptop", "it@example.com", "Call me if it breaks.",
                            "https://n.example/zip/abc", 1893456000)
    check("POSITIVE includes the custom message when given",
          "Call me if it breaks." in body_full, True)
    check("POSITIVE includes the support contact when given",
          "it@example.com" in body_full, True)

    print("\nroute: the no-SMTP-configured precondition (installer-email-delivery.md gap)")
    fn = function_named(tree, "api_agent_installer_generate")
    check("CONTROL the route was found and parsed", fn is not None, True)
    body = ast.get_source_segment(src, fn) or ""
    check("CONTROL the body was extracted (non-trivial)", len(body) > 2000, True)
    check("the route checks recipient_email before doing anything else",
          body.index("recipient_email = ") < body.index("pasted_key = "), True)
    check("it validates the address and rejects a malformed one",
          "_valid_email(recipient_email)" in body, True)
    check("it checks BOTH env vars send_email() actually needs, not just one",
          'os.environ.get("WATCHDOG_EMAIL") and os.environ.get("WATCHDOG_PASSWORD")' in body,
          True)
    check("it fails with a distinct, named error code",
          '"error": "email_not_configured"' in body, True)
    _enc_idx = body.index('"error": "email_not_configured"')
    check("it refuses with 400, not a silent pass",
          "}), 400" in body[_enc_idx:_enc_idx + 300], True)

    print("\nroute: the send is gated on recipient_email, and never silently succeeds")
    check("CONTROL email is only attempted when recipient_email is truthy",
          "if recipient_email:" in body, True)
    check("it calls the real SMTP chokepoint, not a new one",
          "email_utils.send_email(subject, body, to=recipient_email)" in body, True)
    check("delivered_at is set ONLY on a true send result",
          bool(re.search(r"if email_sent:\s*\n\s*try:", body)), True)
    check("a failed send produces a non-empty email_error, not a silent False",
          "email_error = (" in body, True)
    check("the response never claims success it didn't have "
          "(email_sent reflects the real send_email() return)",
          '"email_sent": email_sent' in body, True)

    print("\nRule 8: recipient_email/custom_message (PII) are never logged")
    check("the audit call logs only the token prefix, like its sibling calls",
          'action="installer_email_send", rule_id=token[:8]' in body, True)
    check("CONTROL no log.* call embeds recipient_email",
          bool(re.search(r"log\.\w+\([^)]*recipient_email", body)), False)
    check("CONTROL no log.* call embeds custom_message",
          bool(re.search(r"log\.\w+\([^)]*custom_message", body)), False)

    print("\nschema: guarded migration on BOTH paths (CREATE, per the ADR 0001 DDL rule)")
    for col in ("recipient_email", "support_contact", "custom_message", "delivered_at"):
        check("CREATE TABLE declares %s" % col,
              bool(re.search(r"\b%s\s+(TEXT|REAL)" % col, db_src)), True)
        check("guarded ALTER covers %s (existing DBs)" % col,
              ('if "%s" not in _cols:' % col) in db_src, True)

    print("\nJS/HTML field agreement (a mismatch here is silent — the control renders, "
          "the click sends nothing)")
    for field in ("installerRecipient", "installerSupportContact", "installerCustomMessage"):
        check("the JS reads #%s" % field, ("getElementById('%s')" % field) in js, True)
        check("the page emits #%s" % field, ('id="%s"' % field) in src, True)
    check("the JS sends recipient_email under the field name the route reads",
          "recipient_email: recipient" in js, True)
    check("a non-2xx response surfaces the server's real error message",
          "j.detail || j.error" in js, True)

    print("\nrecipient_email is admin-typed free text reflected into innerHTML -- must be "
          "escaped (unlike zip_url/exe_url/*_warning in the same response, which are all "
          "server-authored)")
    check("d.recipient_email is escaped before display, not concatenated raw",
          "nemesisEscapeHtml(d.recipient_email)" in js, True)
    check("d.email_error is escaped too (also reflects server-derived text)",
          "nemesisEscapeHtml(d.email_error" in js, True)
    check("CONTROL the raw (unescaped) concatenation is gone, not just added alongside",
          "'✓ Emailed to ' + d.recipient_email +" in js, False)

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
