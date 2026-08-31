"""The owner-side enrollment route is reachable WITHOUT a session.

⚠ WHY THIS FILE EXISTS AT ALL. `install_windows_start` shipped broken on
2026-08-02: its endpoint was missing from `_AUTH_EXEMPT`, so it 302'd to login
and *looked like a working route to every other check* -- it passed compile,
template render, and a route audit that verified its token guard matched its
siblings. The one test nobody had written was "reach it with no session".

**A test that exercises the route while AUTHENTICATED proves nothing here** -- the
broken version passes that too. Everything below is deliberately session-free.

Static analysis, not a live server: importing dashboard.py pulls in the whole
appliance. These assertions read the source's own registries, which is exactly
where the 2026-08-02 defect lived.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DASH = os.path.join(ROOT, "dashboard.py")
ROLES = os.path.join(ROOT, "alert_manager", "roles.py")

_fail = []


def check(label, got, want):
    ok = got == want
    print("  %-66s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


src = open(DASH, encoding="utf-8").read()
roles_src = open(ROLES, encoding="utf-8").read()
_exempt_block = re.search(r"_AUTH_EXEMPT\s*=\s*\{.*?\}", src, re.S).group(0)
EXEMPT = set(re.findall(r'"([a-z_]+)"', _exempt_block))

ENDPOINTS = ("email_enroll_landing", "email_enroll_claim",
             # The step that actually stores the owner's app password. Exempt for
             # the same reason as its siblings; the write itself is performed by
             # nemesis_fwd after it consumes the single-use code.
             "email_enroll_complete")


def test_exempt_and_real():
    print("\n[the two failure modes that look like a working route]")
    for ep in ENDPOINTS:
        # 1. missing from _AUTH_EXEMPT -> 302-to-login (the 2026-08-02 defect)
        check("%s is in _AUTH_EXEMPT" % ep, ep in EXEMPT, True)
        # 2. name that resolves to nothing -> fails closed, indistinguishable
        #    from omitting the entry entirely
        check("  %s resolves to a real def" % ep,
              bool(re.search(r"^def %s\(" % ep, src, re.M)), True)
        check("  %s is decorated with @app.route" % ep,
              bool(re.search(r"@app\.route\([^)]*\)\s*\ndef %s\(" % ep, src)), True)
        # 3. roles.py must agree that it is unauthenticated. These registries are
        #    MUTUALLY EXCLUSIVE -- an entry in both fails roles.py's import-time
        #    canary ("no endpoint is in two categories at once"). An earlier draft
        #    of this test asserted ROUTE_MINIMUMS and was wrong.
        unauth = re.search(r"UNAUTHENTICATED = frozenset\(\{.*?\}\)", roles_src, re.S).group(0)
        check("  %s is in roles.UNAUTHENTICATED" % ep, '"%s"' % ep in unauth, True)
        check("  %s is NOT also in ROUTE_MINIMUMS (mutually exclusive)" % ep,
              '"%s":' % ep in roles_src, False)


def test_control_a_gated_route_is_NOT_exempt():
    """CONTROL. Without this, the assertions above would pass against a build
    where EVERY endpoint was exempt -- i.e. no authentication at all."""
    print("\n[CONTROL: authenticated routes are still NOT exempt]")
    for ep in ("dashboard", "firewall_db", "scan_page"):
        check("%s is NOT in _AUTH_EXEMPT" % ep, ep in EXEMPT, False)


def test_state_change_is_post_only():
    print("\n[GET renders; POST changes state -- never GET-as-write]")
    landing = re.search(r'@app\.route\("/email/enroll",\s*methods=\["GET"\]\)\s*\ndef email_enroll_landing',
                        src)
    claim = re.search(r'@app\.route\("/email/enroll",\s*methods=\["POST"\]\)\s*\ndef email_enroll_claim',
                      src)
    check("landing is GET-only", bool(landing), True)
    check("claim is POST-only", bool(claim), True)


def test_token_never_in_the_url():
    print("\n[the code is not a path segment -- werkzeug logs request paths]")
    check("no <token> path converter on the enroll route",
          bool(re.search(r'@app\.route\("/email/enroll/<', src)), False)
    check("claim reads the code from the FORM BODY",
          bool(re.search(r'request\.form\.get\("code"\)', src)), True)


def test_identical_rejection():
    print("\n[one rejection response -- a distinguishable one is an oracle]")
    body = re.search(r"def _enroll_reject\(\):.*?\n\n\n", src, re.S)
    check("_enroll_reject exists", bool(body), True)
    if body:
        check("  returns exactly one status", len(set(re.findall(r"status=(\d+)", body.group(0)))), 1)
    # every refusal path must funnel through it
    claim_body = re.search(r"def email_enroll_claim\(\):.*?\n\n\n", src, re.S).group(0)
    check("every refusal in claim uses _enroll_reject",
          claim_body.count("return _enroll_reject()"), 5)
    # ⚠ Check USE, not MENTION. An earlier version of this assertion tested
    # `"X-Forwarded-For" not in claim_body` and failed against correct code --
    # it matched the COMMENT saying not to trust that header. A grep for a term
    # matches the prose explaining why the term is excluded; assert on what the
    # code CALLS instead.
    check("  reads the client address from request.remote_addr",
          "request.remote_addr" in claim_body, True)
    check("  never READS a forwarded-for header (use, not mention)",
          bool(re.search(r'headers\s*(\.get\s*\(|\[)\s*["\']X-Forwarded-For', claim_body)), False)


def test_failure_is_audited_not_only_success():
    print("\n[a route with no logged failures looks identical to an unattacked one]")
    claim_body = re.search(r"def email_enroll_claim\(\):.*?\n\n\n", src, re.S).group(0)
    for action in ("email_enroll_rate_limited", "email_enroll_rejected",
                   "email_enroll_error", "email_enroll_code_ok"):
        check("claim audits %s" % action, action in claim_body, True)
    done = re.search(r"def email_enroll_complete\(\):.*?\n\n\n", src, re.S).group(0)
    for action in ("email_enroll_rate_limited", "email_enroll_rejected",
                   "email_enroll_error", "email_enroll_claimed"):
        check("complete audits %s" % action, action in done, True)


def test_claim_does_not_consume_the_code():
    """Showing a form is not a state change.

    If claim went back to consuming, a code would be burned by merely OPENING
    the link -- so anyone who mistyped their address or closed the tab would be
    locked out of an enrollment they never completed. The single-use guarantee
    does not depend on this; it lives in the helper's atomic consume.
    """
    print("\n[claim VALIDATES; only completion spends the code]")
    claim_body = re.search(r"def email_enroll_claim\(\):.*?\n\n\n", src, re.S).group(0)
    check("claim does NOT call consume_enrollment_request",
          "consume_enrollment_request" in claim_body, False)
    check("claim uses the READ-ONLY lookup instead",
          "get_enrollment_request" in claim_body, True)
    check("  and classifies it with the pure checker",
          "check_request" in claim_body, True)


def test_dashboard_never_writes_the_credential_itself():
    """The load-bearing property of the whole design.

    The dashboard is modelled as potentially compromised. It must reach the
    credential store ONLY through nemesis_fwd, which consumes the single-use code
    before writing. A direct write here would bypass that entirely -- and would
    also simply fail at runtime, since the file is 0640 root:nemesis and the
    dashboard is not root. Both reasons point the same way.
    """
    print("\n[the credential write goes through the privileged helper, always]")
    done = re.search(r"def email_enroll_complete\(\):.*?\n\n\n", src, re.S).group(0)
    check("completion calls fw_client.write_email_secret",
          "fw_client.write_email_secret" in done, True)
    # USE, not MENTION: assert on an actual open()-for-write, not on the path
    # string appearing in prose. A grep for the path matches the comment
    # explaining why the path is never opened here.
    check("dashboard.py never opens the secrets file for writing",
          bool(re.search(r"open\(\s*[^)]*EMAIL_SECRETS|open\(\s*['\"]/etc/nemesis-email-secrets",
                         src)), False)
    check("  nor imports the writer-side module",
          "import nemesis_fwd" in src, False)


def test_completion_is_post_only_and_takes_no_token_in_the_url():
    print("\n[completion: POST-only, code in the body]")
    check("complete is POST-only",
          bool(re.search(r'@app\.route\("/email/enroll/complete",\s*methods=\["POST"\]\)'
                         r'\s*\ndef email_enroll_complete', src)), True)
    check("no <code> path converter anywhere on the enroll routes",
          bool(re.search(r'@app\.route\("/email/enroll[^"]*<', src)), False)
    done = re.search(r"def email_enroll_complete\(\):.*?\n\n\n", src, re.S).group(0)
    check("reads the code from the FORM BODY",
          bool(re.search(r'request\.form\.get\("code"\)', done)), True)
    check("reads the client address from request.remote_addr",
          "request.remote_addr" in done, True)
    check("  never READS a forwarded-for header (use, not mention)",
          bool(re.search(r'headers\s*(\.get\s*\(|\[)\s*["\']X-Forwarded-For', done)), False)
    check("the owner is taken from the HELPER's reply, not the form",
          bool(re.search(r'request\.form\.get\("owner', done)), False)


def test_the_hidden_code_is_escaped():
    """The code is caller-supplied and lands in a hidden input attribute."""
    print("\n[interpolated values are escaped]")
    form = re.search(r"def _enroll_credential_form\(.*?\n\n\n", src, re.S).group(0)
    check("the code is html.escape()d before interpolation",
          "html.escape(code" in form, True)
    check("  with quote=True, so it cannot end the attribute",
          bool(re.search(r"html\.escape\(code[^)]*quote=True", form)), True)
    check("provider keys and labels are escaped too",
          form.count("html.escape(") >= 4, True)
    check("no JavaScript on the owner-facing page",
          "<script" in form, False)


if __name__ == "__main__":
    print("owner-side enrollment route -- PUBLIC reachability + hardening")
    test_exempt_and_real()
    test_control_a_gated_route_is_NOT_exempt()
    test_state_change_is_post_only()
    test_token_never_in_the_url()
    test_identical_rejection()
    test_failure_is_audited_not_only_success()
    test_claim_does_not_consume_the_code()
    test_dashboard_never_writes_the_credential_itself()
    test_completion_is_post_only_and_takes_no_token_in_the_url()
    test_the_hidden_code_is_escaped()
    print()
    if _fail:
        print("FAILED (%d)" % len(_fail))
        for f in _fail:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS")
