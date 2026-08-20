"""Route-level security checks for the licensing UI routes.

Run:  python3 alert_manager/test_licensing_routes.py

Source-level, in the same style as test_revoke_route.py, and for the same reason:
importing dashboard.py starts threads and touches the live database, which a test
has no business doing.

WHAT THIS IS GUARDING. The standing route-security practice exists because three
real bugs shipped in this codebase: an unguarded GET that mutated state, shell
injection through an interpolated value, and a second unguarded GET. All four
licensing routes are new attack surface of exactly those shapes -- two of them
change entitlements and one burns a single-use secret -- so they get the checks
that would have caught the originals.

Every check carries a CONTROL that proves the check could fail. A test that
locates nothing and asserts "no bad pattern found" passes just as happily
against an empty string.
"""

import os
import re
import sys

DASH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "dashboard.py")
SRC = open(DASH).read()

_failures = []

#: (endpoint function, expected methods, changes state?)
ROUTES = [
    ("licensing_page", {"GET"}, False),
    ("api_license_activate", {"POST"}, True),
    ("api_license_backup_codes_generate", {"POST"}, True),
    ("api_license_backup_codes_redeem", {"POST"}, True),
    # Collects a licence key from the licence server and INSTALLS it -- a state
    # change, hence POST. A GET here would be CSRF-triggerable exactly like
    # `db_action` was.
    ("api_license_rebind_status", {"POST"}, True),
]


def check(label, got, want):
    if got != want:
        _failures.append("%s: got %r, want %r" % (label, got, want))
        print("  FAIL  %s: got %r, want %r" % (label, got, want))
    else:
        print("  ok    %s" % label)


def route_block(fn):
    """The @app.route decorator line(s) + def line for a given function."""
    m = re.search(r'((?:@app\.route\([^\n]*\)\n(?:@[^\n]*\n)*)?)def %s\(' % re.escape(fn), SRC)
    if not m:
        return None
    start = SRC.rfind("@app.route", 0, m.start(0) + len(m.group(1)) + 1)
    if start == -1:
        return None
    return SRC[start:m.end(0)]


def body_of(fn):
    i = SRC.index("def %s(" % fn)
    rest = SRC[i:]
    nxt = re.search(r"\n(?:@app\.route|def |# ── )", rest[1:])
    return rest[:nxt.start() + 1] if nxt else rest


def test_routes_exist():
    print("\n[every route actually exists]")
    for fn, _m, _s in ROUTES:
        check("%s is defined" % fn, "def %s(" % fn in SRC, True)
        check("%s has an @app.route" % fn, route_block(fn) is not None, True)
    # CONTROL: the locator must be able to say NO.
    check("CONTROL locator returns None for a non-route",
          route_block("definitely_not_a_route_xyz"), None)


def test_methods():
    print("\n[state-changing routes are POST-only]")
    for fn, methods, changes in ROUTES:
        blk = route_block(fn) or ""
        declared = set(re.findall(r'"(GET|POST|PUT|DELETE|PATCH)"', blk))
        if not declared:
            declared = {"GET"}          # Flask's default
        check("%s methods == %s" % (fn, sorted(methods)), declared, methods)
        if changes:
            # The db_action defect: a GET that mutates is CSRF-triggerable from
            # an <img> tag under default SameSite=Lax cookies.
            check("%s does NOT accept GET" % fn, "GET" in declared, False)


def test_auth_gated():
    print("\n[all routes are auth-gated and NOT auth-exempt]")
    m = re.search(r"_AUTH_EXEMPT\s*=\s*\{(.*?)\}", SRC, re.S)
    check("CONTROL _AUTH_EXEMPT was located", bool(m), True)
    exempt = set(re.findall(r'"([a-z_0-9]+)"', m.group(1))) if m else set()
    check("CONTROL the exemption set parsed non-empty", len(exempt) > 3, True)
    for fn, _m, _s in ROUTES:
        blk = route_block(fn) or ""
        check("%s is @login_required" % fn, "@login_required" in blk, True)
        check("%s is NOT in _AUTH_EXEMPT" % fn, fn in exempt, False)
    # CONTROL: a genuinely exempt endpoint must still read as exempt, or the
    # membership test above proves nothing.
    check("CONTROL a known-exempt endpoint IS in the set", "login" in exempt, True)


def test_no_injection_shapes():
    print("\n[no shell / SQL string interpolation]")
    for fn, _m, _s in ROUTES:
        b = body_of(fn)
        code = "\n".join(l for l in b.splitlines() if not l.lstrip().startswith("#"))
        check("%s: no f-string SQL" % fn,
              bool(re.search(r'f"[^"]*(SELECT|INSERT|UPDATE|DELETE)', code)), False)
        check("%s: no subprocess/shell" % fn,
              bool(re.search(r"subprocess|os\.system|shell=True", code)), False)
    # CONTROL: the matcher must fire on a genuinely bad line.
    check("CONTROL f-string-SQL matcher works",
          bool(re.search(r'f"[^"]*(SELECT|INSERT)', 'x = f"SELECT {a}"')), True)


def test_activate_verifies_before_storing():
    """A bad key must not be able to overwrite a good one.

    The verify+store logic lives in `_verify_and_store_license`, which is the
    ONE path by which a licence is installed. It moved there when automatic
    rebind collection was added: a second, separately-written copy of this logic
    is how one of the two quietly ends up with a weaker check -- the same
    two-routes-one-job shape as the original `db_action`/`set_action` defect.
    """
    print("\n[the single install path verifies BEFORE it stores]")
    b = body_of("_verify_and_store_license")
    check("CONTROL body located", "license_state" in b, True)
    vi = b.find("lk.verify(")
    si = b.find("INSERT INTO license_state")
    check("verify() appears", vi > -1, True)
    check("INSERT appears", si > -1, True)
    check("verify comes BEFORE the write", vi < si, True)
    check("invalid keys return early", "if not res.valid" in b, True)
    check("binds to THIS machine's install id", "install_id=fp[" in b, True)
    check("parameterised INSERT (no interpolation)", "VALUES (1,?,?,?,?,?,?,?,?,?)" in b, True)


def test_only_one_install_path():
    """Both entry points must funnel through the shared helper.

    If either route ever grows its own verify+INSERT, this fails -- which is the
    entire point. A key arriving automatically from the licence server must be
    checked exactly as strictly as one a human pasted in.
    """
    print("\n[there is exactly ONE way a licence gets installed]")
    inserts = re.findall(r"INSERT INTO license_state", SRC)
    check("only one INSERT INTO license_state in the whole file",
          len(inserts), 1)
    for fn in ("api_license_activate", "api_license_rebind_status"):
        b = body_of(fn)
        check("%s delegates to _verify_and_store_license" % fn,
              "_verify_and_store_license(" in b, True)
        check("%s does NOT write license_state itself" % fn,
              "INSERT INTO license_state" in b, False)
    # CONTROL: the helper genuinely contains the write, so the absence above
    # means "delegated", not "the pattern never matches anywhere".
    check("CONTROL the helper DOES contain the write",
          "INSERT INTO license_state" in body_of("_verify_and_store_license"), True)


def test_rebind_never_reports_unverified_success():
    """A key that arrives but does not fit this machine must not read as success."""
    print("\n[rebind collection does not trust the licence server]")
    b = body_of("api_license_rebind_status")
    check("checks the stored result before reporting ok",
          'if not stored.get("ok")' in b, True)
    check("has an explicit verification_failed state",
          "verification_failed" in b, True)
    check("an unreachable server is distinguishable from a refusal",
          "unreachable" in b, True)
    check("a 404 from the server is its own answer", "404" in b, True)
    # The whole point of the endpoint: it must actually install on success.
    check("installs via the shared path", "_verify_and_store_license(" in b, True)


def test_redeem_is_honest_when_the_network_half_fails():
    """The code is spent before the network call; that must never be hidden.

    Un-spending is not an option -- the spend is atomic and a rollback would
    break exactly the property that stops a code being double-used. So a
    licence-server failure must still report the spend and fall back to the
    manual support path, rather than implying the same code can be retried.
    """
    print("\n[redeem stays honest when the licence server is down]")
    b = body_of("api_license_backup_codes_redeem")
    check("still returns the install id for the manual path",
          "manual_fallback" in b, True)
    # Matched on a fragment that sits inside ONE source string literal --
    # the user-facing sentence is split across two adjacent literals, so the
    # whole phrase never appears contiguously in the source.
    check("unreachable server falls back rather than failing outright",
          "licence server could not be" in b, True)
    check("a server REFUSAL surfaces the server's own reason",
          "rebind_error" in b, True)
    check("distinguishes unreachable (None) from an HTTP status",
          "if status is None" in b, True)
    # CONTROL: the fallback text must actually be the pre-existing support
    # message, not a new string that merely looks reassuring.
    check("the fallback is the original support instruction",
          "Send this installation ID to support" in b, True)


def test_redeem_is_honest_about_being_incomplete():
    """Spending a code without issuing a key must not report plain success."""
    print("\n[redeem does not claim more than it did]")
    b = body_of("api_license_backup_codes_redeem")
    check("exhaustion is its own response", "exhausted" in b, True)
    check("returns the install id for support", "install_id" in b, True)
    check("names a next step rather than 'done'", "next_step" in b, True)
    # The code must be spent atomically by backup_codes.consume, not re-implemented.
    check("delegates spending to backup_codes.consume", "bc.consume(" in b, True)


def test_audited():
    print("\n[state changes are audited]")
    for fn in ("_verify_and_store_license", "api_license_backup_codes_generate",
               "api_license_backup_codes_redeem", "api_license_rebind_status"):
        b = body_of(fn)
        check("%s calls _audit" % fn, "_audit(" in b, True)
    check("rebind requests are audited", "license_rebind_requested" in SRC, True)
    check("completed rebinds are audited", "license_rebind_completed" in SRC, True)
    # Rejections are audited too -- a failed activation attempt is exactly the
    # event a later review wants to see.
    check("rejected activations are audited",
          "license_activate_rejected" in SRC, True)
    check("rejected codes are audited",
          "license_backup_code_rejected" in SRC, True)


def test_startup_wiring():
    print("\n[init_licensing_tables is actually called at startup]")
    check("imported", "init_licensing_tables" in SRC, True)
    # A CREATE that exists but never runs is indistinguishable from no CREATE at
    # all on a fresh install -- the `devices`-table failure.
    check("called at module level (not only imported)",
          bool(re.search(r"^init_licensing_tables\(\)", SRC, re.M)), True)


def test_budget_never_renders_a_fake_zero():
    print("\n[the budget strip refuses to invent a number]")
    b = body_of("_render_remote_budget_html")
    check("CONTROL body located", "remote_device_budget" in b, True)
    check("handles the not-reconciled case", "census.reconciled" in b, True)
    check("shows 'unknown' rather than 0", "unknown" in b, True)
    check("surfaces the reason", "census.reason" in b, True)
    # Same f-string apostrophe trap the whole codebase keeps hitting.
    code = "\n".join(l for l in b.splitlines() if not l.lstrip().startswith("#"))
    bad = re.findall(r"(?<![\w&#;])'(?:s|t|re|ve|ll|d)\b", code)
    check("no raw contraction apostrophes in the f-string block", bad, [])



def test_licensing_page_is_discoverable():
    """A page nothing links to is a page that does not exist.

    /settings/licensing worked from the first commit, but the ONLY link to it sat
    inside the Devices card's budget strip — so it was reachable only by typing
    the URL, and the operator could not find it. Route coverage said "pass"
    while the feature was effectively absent.
    """
    print("\n[the licensing page is reachable from the Settings page]")
    links = SRC.count('href="/settings/licensing"')
    check("at least one link exists", links >= 1, True)
    # The Settings page itself must link to it, not only the Devices sub-card.
    settings = SRC[SRC.index("<!-- Licence -->"):SRC.index("<!-- Danger Zone -->")]
    check("a dedicated Licence card exists on Settings",
          'href="/settings/licensing"' in settings, True)
    check("the card has a heading", "<h2>" in settings, True)
    check("it shows a summary, not just a link",
          "_render_license_summary_html()" in settings, True)
    # CONTROL: the slice must be the real card, not an empty string.
    check("CONTROL the Settings slice is non-trivial", len(settings) > 400, True)


def test_license_summary_never_fakes_a_number():
    print("\n[the Settings summary refuses to invent a count]")
    b = SRC[SRC.index("def _render_license_summary_html"):]
    b = b[:b.index("\ndef _render_remote_budget_html")]
    code = "\n".join(l for l in b.splitlines() if not l.lstrip().startswith("#"))
    check("handles not-reconciled", "census.reconciled" in code, True)
    check("shows unknown rather than 0", "unknown" in code, True)
    check("surfaces the reason", "census.reason" in code, True)
    bad = re.findall(r"(?<![\w&#;])'(?:s|t|re|ve|ll|d)\b", code)
    check("no raw contraction apostrophes", bad, [])



if __name__ == "__main__":
    print("licensing route security")
    test_routes_exist()
    test_methods()
    test_auth_gated()
    test_no_injection_shapes()
    test_activate_verifies_before_storing()
    test_only_one_install_path()
    test_rebind_never_reports_unverified_success()
    test_redeem_is_honest_about_being_incomplete()
    test_redeem_is_honest_when_the_network_half_fails()
    test_audited()
    test_startup_wiring()
    test_budget_never_renders_a_fake_zero()
    test_licensing_page_is_discoverable()
    test_license_summary_never_fakes_a_number()

    print("\n" + "=" * 60)
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  - %s" % f)
        sys.exit(1)
    print("ALL PASS")
