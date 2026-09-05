#!/usr/bin/env python3
"""`redact()` scope split + proof `run_check()` is wired to the DISPLAY scope.

Run: python3 diagnostics/test_display_scope.py   (exit 0 = all pass)

WHY THIS EXISTS, AND WHY IT IS A SEPARATE FILE FROM test_redact.py.
The 2026-09-05 defect was not in redact(). redact() was correct and had 35
passing tests. The defect was in the WIRING: diagnostics/__init__.py's
run_check() called the export scrubber on output destined for the appliance
owner's own browser, so Network Devices rendered all 70 devices as
[REDACTED]/[REDACTED]/[REDACTED] and the built-in AI assistant — whose prompt is
generated from these very checks — was directing people to a page that could no
longer answer them.

test_redact.py could not have caught that: it tests the function, and the
function was never wrong. Nothing anywhere asserted WHICH scope the display path
used. This file is that assertion. It is deliberately end-to-end through
run_check() rather than a unit test of redact(), because the call site is the
thing that broke.

THE LEAK/PRESENCE CHECKS CARRY THEIR OWN CONTROL, same discipline as
test_redact.py: a check that can only ever return one answer proves nothing, so
each direction is paired with a case that must come out the other way.

Addresses are RFC 5737 / RFC 3849 documentation ranges per this repo's
test-address convention.
"""
import importlib
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)                        # bare "import redact"
sys.path.insert(0, os.path.dirname(_HERE))       # repo root, for the package

# ⛔ IMPORT THE PACKAGE'S OWN redact MODULE, NOT A BARE `import redact`.
# `import redact` and `import diagnostics.redact` produce TWO DISTINCT module
# objects in sys.modules (this package is importable both ways, by design —
# each check is documented to run standalone). Patching the bare one leaves the
# copy run_check() actually calls untouched, so the patch silently does
# nothing. Caught live while writing this file: the secret assertion below
# failed while every other run_check assertion passed, i.e. the test was
# measuring the real module for some checks and a patched decoy for others.
_pkg = importlib.import_module("diagnostics")    # noqa: E402
R = importlib.import_module("diagnostics.redact")  # noqa: E402

EXPECTED_CHECKS = 73

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 55:
        g, w = g[:52] + "...", w[:52] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def _patch(mod, name, fn):
    old = getattr(mod, name)
    setattr(mod, name, fn)
    return lambda: setattr(mod, name, old)


# A fixed, synthetic world so nothing here depends on this box's live data.
FAKE_SECRET = "sk-fake-supersecret-value-123456"
FAKE_NAMES = {"Reception-Laptop"}

# One line carrying every category at once: a secret, an IP, a MAC, a known
# device name, an FQDN and an email.
SPECIMEN = ("device Reception-Laptop at 203.0.113.9 mac 00:1a:2b:3c:4d:5e "
            "host box.lan mail user.test@example.com key " + FAKE_SECRET)


class _StubCheck:
    """A check module with known output, registered into the package's map.

    Deterministic on purpose: asserting against a REAL check would make this
    test depend on whether this particular box happens to have devices
    enrolled today, and a test that silently becomes vacuous is the exact
    failure class this repo keeps getting burned by.
    """
    META = {"id": "_stub_scope_probe", "name": "Stub", "icon": "🧪",
            "descriptions": {}}

    @staticmethod
    def run():
        return {"id": "_stub_scope_probe", "name": "Stub", "icon": "🧪",
                "status": "ok", "summary": "at 203.0.113.9",
                "output": SPECIMEN}


def main():
    # ── control: the specimen really does contain what we are about to look
    #    for, so a later "still present" assertion cannot pass vacuously ──────
    print("control: specimen contains every category before any redaction")
    for label, needle in (("secret", FAKE_SECRET), ("ip", "203.0.113.9"),
                          ("mac", "00:1a:2b:3c:4d:5e"),
                          ("name", "Reception-Laptop"), ("fqdn", "box.lan"),
                          ("email", "user.test@example.com")):
        check("  specimen carries a %s" % label, needle in SPECIMEN, True)

    restore = [
        _patch(R, "_load_secrets", lambda: {FAKE_SECRET}),
        _patch(R, "_load_known_names", lambda: set(FAKE_NAMES)),
    ]
    try:
        # ── EXPORT scope: unchanged behaviour, everything goes ───────────────
        print("\nEXPORT scope (default) — identifiers AND secrets removed")
        out_exp = R.redact(SPECIMEN, scope=R.SCOPE_EXPORT)
        check("export: secret redacted", FAKE_SECRET not in out_exp, True)
        check("export: IP redacted", "203.0.113.9" not in out_exp, True)
        check("export: MAC redacted", "00:1a:2b:3c:4d:5e" not in out_exp, True)
        check("export: device name redacted",
              "Reception-Laptop" not in out_exp, True)
        check("export: FQDN redacted", "box.lan" not in out_exp, True)
        check("export: email redacted",
              "user.test@example.com" not in out_exp, True)

        # THE fail-closed default. A caller that does not pass a scope must get
        # the safe one — this is what makes "forgot to think about it" harmless.
        out_default = R.redact(SPECIMEN)
        check("NO scope argument defaults to EXPORT (fail closed)",
              out_default == out_exp, True)

        # ── DISPLAY scope: secrets only ──────────────────────────────────────
        print("\nDISPLAY scope — secrets removed, owner's own data preserved")
        out_dis = R.redact(SPECIMEN, scope=R.SCOPE_DISPLAY)
        check("display: secret STILL redacted", FAKE_SECRET not in out_dis, True)
        check("display: IP preserved", "203.0.113.9" in out_dis, True)
        check("display: MAC preserved", "00:1a:2b:3c:4d:5e" in out_dis, True)
        check("display: device name preserved",
              "Reception-Laptop" in out_dis, True)
        check("display: FQDN preserved", "box.lan" in out_dis, True)
        check("display: email preserved",
              "user.test@example.com" in out_dis, True)
        check("display: key-shaped string still redacted",
              "sk-ant-abc123DEF456ghi789JKL012mno345PQR" not in
              R.redact("key sk-ant-abc123DEF456ghi789JKL012mno345PQR",
                       scope=R.SCOPE_DISPLAY), True)

        # ── an unrecognised scope must not be the permissive one ─────────────
        print("\nunknown scope resolves to EXPORT, not to display")
        out_bogus = R.redact(SPECIMEN, scope="not-a-scope")
        check("unknown scope redacts identifiers (fail closed)",
              "203.0.113.9" not in out_bogus, True)

        # ── redact_result() carries the scope through ────────────────────────
        print("\nredact_result() honours scope on both fields")
        res = {"output": SPECIMEN, "summary": "at 203.0.113.9"}
        rr_dis = R.redact_result(res, scope=R.SCOPE_DISPLAY)
        rr_exp = R.redact_result(res)
        check("redact_result display: output keeps IP",
              "203.0.113.9" in rr_dis["output"], True)
        check("redact_result display: summary keeps IP",
              "203.0.113.9" in rr_dis["summary"], True)
        check("redact_result default: output loses IP",
              "203.0.113.9" not in rr_exp["output"], True)
        check("redact_result default: summary loses IP",
              "203.0.113.9" not in rr_exp["summary"], True)

        # ── THE WIRING TEST — the one that would have caught the defect ──────
        print("\nrun_check() is wired to DISPLAY scope (the actual 09-05 defect)")
        _pkg._CHECK_MAP["_stub_scope_probe"] = _StubCheck
        try:
            live = _pkg.run_check("_stub_scope_probe")
            check("run_check: owner's IP survives to the browser",
                  "203.0.113.9" in live["output"], True)
            check("run_check: owner's MAC survives",
                  "00:1a:2b:3c:4d:5e" in live["output"], True)
            check("run_check: device name survives",
                  "Reception-Laptop" in live["output"], True)
            check("run_check: summary survives",
                  "203.0.113.9" in live["summary"], True)
            check("run_check: secret is STILL removed",
                  FAKE_SECRET not in live["output"], True)

            # ── and the export path is still airtight over that same text ────
            # Mirrors dashboard.py api_diag_submit()'s re-redaction of what the
            # browser posts back. This is why display scope is safe: the box
            # never emits the unredacted text, it only DISPLAYS it.
            print("\nexport path re-redacts the display-scoped result "
                  "(dashboard.py:13524-13525)")
            submitted_out = R.redact(live["output"])
            submitted_sum = R.redact(live["summary"])
            check("submit: IP gone", "203.0.113.9" not in submitted_out, True)
            check("submit: MAC gone",
                  "00:1a:2b:3c:4d:5e" not in submitted_out, True)
            check("submit: device name gone",
                  "Reception-Laptop" not in submitted_out, True)
            check("submit: summary scrubbed",
                  "203.0.113.9" not in submitted_sum, True)
        finally:
            _pkg._CHECK_MAP.pop("_stub_scope_probe", None)
    finally:
        for r in restore:
            r()

    # ── DISPLAY must not depend on sources it does not use ──────────────────
    # Before this change an unreadable devices DB withheld the owner's entire
    # diagnostics page. Display never used those names, so it must not.
    print("\nDISPLAY does not consult the devices DB or the address module")

    def _raise():
        raise R.RedactionUnavailable("forced for test")

    r1 = _patch(R, "_load_secrets", lambda: {FAKE_SECRET})
    r2 = _patch(R, "_load_known_names", _raise)
    r3 = _patch(R, "_load_pseudonymize_helpers", _raise)
    try:
        out = R.redact(SPECIMEN, scope=R.SCOPE_DISPLAY)
        check("display survives an unreadable devices DB",
              out != R._WITHHELD and "203.0.113.9" in out, True)
        check("...and still strips the secret while degraded",
              FAKE_SECRET not in out, True)
        # CONTROL: the same broken sources DO withhold at export scope, proving
        # the patches above were real and the distinction is the scope.
        check("CONTROL: export scope still withholds with those sources broken",
              R.redact(SPECIMEN) == R._WITHHELD, True)
    finally:
        r3(); r2(); r1()

    # ── DISPLAY still fails closed on the source it DOES use ────────────────
    print("\nDISPLAY still fails closed when the secret list is unreadable")
    r4 = _patch(R, "_load_secrets", _raise)
    try:
        check("display withholds when secrets cannot be read",
              R.redact(SPECIMEN, scope=R.SCOPE_DISPLAY) == R._WITHHELD, True)
    finally:
        r4()

    # CONTROL: fully restored, display works again — proves withholding above
    # was caused by the patch and not by something permanent.
    check("CONTROL: sources restored -> display redaction resumes",
          R.redact("plain text", scope=R.SCOPE_DISPLAY) == "plain text", True)

    # ── key-NAME classifier: what makes a value a secret at display scope ───
    # Every name below is already present in tracked files (verified before
    # pinning them here), so this is not a Rule-8 disclosure.
    print("\ndisplay-scope secret classifier keys on the key NAME, not length")
    SECRET_NAMES = ("ABUSEIPDB_KEY", "IPINFO_TOKEN", "ANTHROPIC_API_KEY",
                    "WATCHDOG_PASSWORD", "PIHOLE_PASSWORD",
                    "TAILSCALE_OAUTH_CLIENT_SECRET", "NEMESIS_DOOR_SECRET",
                    "EMAIL_SENDER_SALT")
    CONFIG_NAMES = ("SMTP_HOST", "PIHOLE_IP", "LAN_SUBNET", "NEMESIS_GH_REPO",
                    "NEMESIS_AGENT_EXE", "NEMESIS_PUBLIC_URL",
                    "TAILSCALE_OAUTH_CLIENT_ID")
    for k in SECRET_NAMES:
        check("  %s reads as a credential" % k,
              bool(R._SECRET_NAME_PATTERN.search(k)), True)
    for k in CONFIG_NAMES:
        check("  %s does NOT read as a credential" % k,
              bool(R._SECRET_NAME_PATTERN.search(k)), False)
    # the paired-key asymmetry is the whole reason CLIENT_ID is on that list
    check("  OAuth pair splits: _SECRET matches, _ID does not",
          bool(R._SECRET_NAME_PATTERN.search("TAILSCALE_OAUTH_CLIENT_SECRET"))
          and not bool(R._SECRET_NAME_PATTERN.search(
              "TAILSCALE_OAUTH_CLIENT_ID")), True)
    # anchoring: a keyword embedded in a word is not a match
    check("  MONKEY_BUSINESS is not a credential (anchored, not substring)",
          bool(R._SECRET_NAME_PATTERN.search("MONKEY_BUSINESS")), False)
    check("  API_KEY_V2 IS a credential (interior match still anchored)",
          bool(R._SECRET_NAME_PATTERN.search("API_KEY_V2")), True)

    # ── the REAL _nonsecret_env_values(), against a real file ───────────────
    # Every other display test patches this function, so without this block its
    # classification loop is never executed and a mutation that made it return
    # every value -- leaking credentials to the screen -- survived the suite.
    # Found by mutation M9 while writing this file; the fix is to exercise the
    # branch, not to trust that the patched stub implies the real one works.
    print("\nreal _nonsecret_env_values() classifies a real env file")
    import tempfile
    fd, envpath = tempfile.mkstemp(prefix="nemesis-test-env-")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write("# comment line\n"
                     "\n"
                     "LAN_SUBNET=198.51.100.0/22\n"
                     "SMTP_HOST=mail.example.com\n"
                     "TAILSCALE_OAUTH_CLIENT_ID=public-id-value\n"
                     "WATCHDOG_PASSWORD=hunter2-not-a-real-password\n"
                     "NEMESIS_DOOR_SECRET=door-secret-value\n"
                     # in _SECRET_KEYS but its NAME does not match the
                     # keyword pattern -- the only key of that shape, and
                     # therefore the only one that proves the _SECRET_KEYS
                     # clause carries its own weight (mutation M13).
                     "WATCHDOG_EMAIL=alerts@example.com\n"
                     "EMPTY_VALUE=\n")
        rp = _patch(R, "_ENV_FILE", envpath)
        try:
            got = R._nonsecret_env_values()
        finally:
            rp()
        check("real classifier keeps LAN_SUBNET as non-secret",
              "198.51.100.0/22" in got, True)
        check("real classifier keeps SMTP_HOST as non-secret",
              "mail.example.com" in got, True)
        check("real classifier keeps OAuth CLIENT_ID as non-secret",
              "public-id-value" in got, True)
        check("real classifier EXCLUDES a _PASSWORD value",
              "hunter2-not-a-real-password" in got, False)
        check("real classifier EXCLUDES a _SECRET value",
              "door-secret-value" in got, False)
        check("real classifier EXCLUDES WATCHDOG_EMAIL via _SECRET_KEYS",
              "alerts@example.com" in got, False)
        check("...and it is _SECRET_KEYS doing that, not the name pattern",
              bool(R._SECRET_NAME_PATTERN.search("WATCHDOG_EMAIL")), False)
        check("real classifier returns exactly the three non-secrets",
              len(got), 3)
    finally:
        os.unlink(envpath)

    # ── the ufw_rules defect, end to end ────────────────────────────────────
    print("\nnon-secret config is visible on display, still stripped on export")
    CONFIG_VAL = "198.51.100.0/22"          # stands in for LAN_SUBNET
    CRED_VAL = "hunter2-not-a-real-password"
    UFW_LINE = "22/tcp   LIMIT IN   %s   # rate-limit ssh" % CONFIG_VAL
    CFG_LINE = UFW_LINE + "  token=" + CRED_VAL

    r5 = _patch(R, "_load_secrets", lambda: {CONFIG_VAL, CRED_VAL})
    r6 = _patch(R, "_nonsecret_env_values", lambda: {CONFIG_VAL})
    try:
        dis = R.redact(CFG_LINE, scope=R.SCOPE_DISPLAY)
        check("display: LAN CIDR visible (the ufw_rules defect)",
              CONFIG_VAL in dis, True)
        check("display: credential still stripped", CRED_VAL not in dis, True)

        # EXPORT MUST BE UNAFFECTED -- this is the property the whole option
        # was chosen for, so it is asserted directly rather than assumed.
        exp = R.redact(CFG_LINE)
        check("export: CIDR still stripped (export unchanged)",
              CONFIG_VAL not in exp, True)
        check("export: credential still stripped", CRED_VAL not in exp, True)

        # ...and prove export never even consults the classifier: make it claim
        # EVERY value is non-secret and confirm export output does not budge.
        r7 = _patch(R, "_nonsecret_env_values",
                    lambda: {CONFIG_VAL, CRED_VAL})
        try:
            check("export ignores the display classifier entirely",
                  R.redact(CFG_LINE) == exp, True)
        finally:
            r7()
    finally:
        r6(); r5()

    # ── classifier read failure degrades to over-redaction, never a leak ────
    print("\nan unreadable env file makes display hide MORE, never less")
    r9 = _patch(R, "_load_secrets", lambda: {CONFIG_VAL, CRED_VAL})
    try:
        # _nonsecret_env_values swallows its own read error and returns empty,
        # so nothing is subtracted and display reverts to redacting everything.
        r10 = _patch(R, "_ENV_FILE", "/nonexistent/dir/nemesis.env")
        try:
            out = R.redact(CFG_LINE, scope=R.SCOPE_DISPLAY)
            check("degraded display still strips the credential",
                  CRED_VAL not in out, True)
            check("degraded display over-redacts config rather than leaking",
                  CONFIG_VAL not in out, True)
        finally:
            r10()
        # CONTROL: with the classifier working again, config comes back --
        # proves the two checks above were caused by the patch, not permanent.
        r11 = _patch(R, "_nonsecret_env_values", lambda: {CONFIG_VAL})
        try:
            check("CONTROL: classifier restored -> config visible again",
                  CONFIG_VAL in R.redact(CFG_LINE, scope=R.SCOPE_DISPLAY), True)
        finally:
            r11()
    finally:
        r9()

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
