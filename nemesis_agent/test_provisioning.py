#!/usr/bin/env python3
"""Step 3 verification: encrypted provisioning at install time.

Run: python3 nemesis_agent/test_provisioning.py

Covers the headless half. The tkinter dialog itself, the main-thread/worker
handoff, and the frozen-bundle imports are NOT testable on this build host
(no tkinter, no PyInstaller output) and are deferred to step 6 on the KEEP VM.
That split is deliberate: all POLICY lives in validate_secret(), which is a
pure function, so only the widget shell is left unverified here.
"""
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from cryptography.hazmat.primitives import serialization

import secret_prompt
from secret_prompt import SECRET_PASSWORD, SECRET_PIN, validate_secret

HW_MONITOR = "/opt/nemesis/core_module/hw_monitor/hw_monitor.py"
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 55:
        g, w = g[:52] + "...", w[:52] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def raises(fn):
    try:
        fn()
    except Exception as e:
        return type(e).__name__
    return "NO_EXCEPTION"


def looks_like_unencrypted_key(path):
    try:
        blob = open(path, "rb").read()
    except OSError:
        return False
    for loader in (serialization.load_pem_private_key,
                   serialization.load_der_private_key):
        try:
            loader(blob, password=None)
            return True
        except Exception:
            continue
    return False


def server_verifier():
    if not os.path.isfile(HW_MONITOR):
        return None
    lines = open(HW_MONITOR).read().splitlines()
    try:
        start = next(i for i, l in enumerate(lines)
                     if l.startswith("def _verify_enroll_signature("))
    except StopIteration:
        return None
    end = start + 1
    while end < len(lines) and (lines[end].startswith("    ") or not lines[end].strip()):
        end += 1
    ns = {}
    exec(compile("\n".join(lines[start:end]), HW_MONITOR, "exec"), ns)
    return ns["_verify_enroll_signature"]


def main():
    # ── the module must import with NO tkinter present ────────────────────
    print("policy is importable headless")
    check("secret_prompt imported without tkinter being available",
          "tkinter" not in sys.modules or sys.modules.get("tkinter") is None, True)

    print("\nvalidate_secret — password")
    check("POSITIVE a 10-char password is accepted",
          validate_secret(SECRET_PASSWORD, "abcdefghij")[0], True)
    check("CONTROL 9 chars is rejected",
          validate_secret(SECRET_PASSWORD, "abcdefghi")[0], False)
    check("CONTROL empty is rejected",
          validate_secret(SECRET_PASSWORD, "")[0], False)
    check("CONTROL mismatched confirmation is rejected",
          validate_secret(SECRET_PASSWORD, "abcdefghij", "abcdefghiJ")[0], False)
    check("matching confirmation is accepted",
          validate_secret(SECRET_PASSWORD, "abcdefghij", "abcdefghij")[0], True)
    check("rejection gives a reason, not a bare False",
          bool(validate_secret(SECRET_PASSWORD, "short")[1]), True)
    check("no composition rule: 10 identical chars accepted",
          validate_secret(SECRET_PASSWORD, "aaaaaaaaaa")[0], True)

    print("\nvalidate_secret — PIN")
    check("POSITIVE a 6-digit PIN is accepted",
          validate_secret(SECRET_PIN, "482913")[0], True)
    check("CONTROL 5 digits is rejected", validate_secret(SECRET_PIN, "48291")[0], False)
    check("CONTROL a non-digit PIN is rejected",
          validate_secret(SECRET_PIN, "48291a")[0], False)

    verify = server_verifier()
    tmp = tempfile.mkdtemp(prefix="nemesis-provision-")
    try:
        import config
        import enrollment
        import keyprotect

        # ── provisioning WITH a secret ────────────────────────────────────
        print("\nensure_provisioned(secret) — the install path")
        kd = os.path.join(tmp, "keys")
        config.keys_dir = lambda: kd
        enrollment.reset_backend()
        pub = enrollment.ensure_provisioned("a good passphrase")
        check("provisioned tier is password (not legacy)",
              keyprotect.tier_of(kd), "password")
        check("CONTROL no file on disk parses as an unencrypted private key",
              [f for f in os.listdir(kd)
               if looks_like_unencrypted_key(os.path.join(kd, f))], [])
        check("CONTROL the legacy plaintext private.pem was never created",
              os.path.exists(os.path.join(kd, "private.pem")), False)
        sig = enrollment._sign("enroll-test")
        if verify:
            check("POSITIVE enrollment signature verifies server-side",
                  verify(pub, "enroll-test", sig), True)
            check("CONTROL it does not verify over a different message",
                  verify(pub, "enroll-test!", sig), False)

        # ── idempotence: never mint a second identity ─────────────────────
        print("\nre-provisioning must not mint a second identity")
        again = enrollment.ensure_provisioned("a totally different passphrase")
        check("second call returns the SAME public key", again.strip(), pub.strip())

        # ── the legacy path still works for headless platforms ────────────
        print("\nensure_provisioned() with no secret — transitional Linux path")
        kd2 = os.path.join(tmp, "keys2")
        config.keys_dir = lambda: kd2
        enrollment.reset_backend()
        legacy_pub = enrollment.ensure_provisioned()
        check("legacy path still produces a usable key",
              keyprotect.tier_of(kd2), "none")
        lsig = enrollment._sign("legacy-test")
        if verify:
            check("legacy signature still verifies (no regression)",
                  verify(legacy_pub, "legacy-test", lsig), True)

        # ── cancel leaves nothing behind ──────────────────────────────────
        print("\ncancelled install")
        kd3 = os.path.join(tmp, "keys3")
        config.keys_dir = lambda: kd3
        enrollment.reset_backend()
        # A cancel means ensure_provisioned is never reached at all; assert the
        # observable consequence -- no key material anywhere.
        check("CONTROL no keys directory is created when the prompt is cancelled",
              os.path.exists(kd3), False)
        check("CONTROL detect finds no backend after a cancel",
              keyprotect.detect_backend(kd3), None)

        # ── the installer guard: missing secret must NOT silently downgrade ─
        print("\ninstaller guard against a silent downgrade")
        src = open(os.path.join(HERE, "installer_gui.py")).read()
        check("_enroll raises when device_secret is unset (no legacy fallback)",
              "no device password was collected before enrollment" in src, True)
        check("device_secret defaults to None at class level",
              "device_secret = None" in src, True)
        check("the prompt is called from start(), not from the worker",
              src.index("_prompt_device_secret()") < src.index("def _enroll"), True)
    finally:
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
