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
    """A bad key must not be able to overwrite a good one."""
    print("\n[activate verifies BEFORE it stores]")
    b = body_of("api_license_activate")
    check("CONTROL body located", "license_state" in b, True)
    vi = b.find("lk.verify(")
    si = b.find("INSERT INTO license_state")
    check("verify() appears", vi > -1, True)
    check("INSERT appears", si > -1, True)
    check("verify comes BEFORE the write", vi < si, True)
    check("invalid keys return early", "if not res.valid" in b, True)
    check("parameterised INSERT (no interpolation)", "VALUES (1,?,?,?,?,?,?,?,?,?)" in b, True)


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
    for fn in ("api_license_activate", "api_license_backup_codes_generate",
               "api_license_backup_codes_redeem"):
        b = body_of(fn)
        check("%s calls _audit" % fn, "_audit(" in b, True)
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


if __name__ == "__main__":
    print("licensing route security")
    test_routes_exist()
    test_methods()
    test_auth_gated()
    test_no_injection_shapes()
    test_activate_verifies_before_storing()
    test_redeem_is_honest_about_being_incomplete()
    test_audited()
    test_startup_wiring()
    test_budget_never_renders_a_fake_zero()

    print("\n" + "=" * 60)
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  - %s" % f)
        sys.exit(1)
    print("ALL PASS")
