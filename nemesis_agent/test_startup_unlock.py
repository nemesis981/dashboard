#!/usr/bin/env python3
"""Step 4 verification: startup unlock gate.

Run: python3 nemesis_agent/test_startup_unlock.py

The two checks that carry this:

  * a deployed tier-4 device must NOT be prompted -- asserted by the prompt
    never being invoked, not by observing that startup happened to work;
  * a locked key must never reach the unsigned-heartbeat path, which the
    server accepts in observe mode. That was the hole that would have made
    the whole gate cosmetic.

The Tk dialog and the frozen agent at logon are deferred to step 6 on the
KEEP VM. Everything here is the policy and control flow around them.
"""
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def _tk_really_importable():
    """Whether Tk can ACTUALLY be used on this machine, decided independently of
    the function under test.

    The checks below used to assert `_tk_available() is False` outright, because
    the build box had no python3-tk. That made the environment a silent premise:
    the moment Tk was installed (2026-08-20, to verify the agent settings window)
    both tests failed, reporting a defect in code that had not changed. A control
    whose answer depends on an unstated property of the machine is not a control.

    So the assertion becomes AGREEMENT: `_tk_available()` must match reality,
    whatever reality is here. That still catches the failure the original check
    cared about -- a `_tk_available()` stuck on one answer -- and it catches it on
    a machine WITH Tk too, which the original could not.
    """
    try:
        import tkinter                                        # noqa: PLC0415,F401
    except Exception:                                         # noqa: BLE001
        return False
    try:
        root = tkinter.Tk()
    except Exception:                                         # noqa: BLE001
        return False                    # importable but no usable display
    root.destroy()
    return True


_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 50:
        g, w = g[:47] + "...", w[:47] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def raises(fn):
    try:
        fn()
    except Exception as e:
        return type(e).__name__
    return "NO_EXCEPTION"


def main():
    tmp = tempfile.mkdtemp(prefix="nemesis-unlock-")
    try:
        import config
        import enrollment
        import keyprotect
        import secret_prompt
        import agent
        from keyprotect import PasswordBackend

        # ── is_unlocked() semantics ───────────────────────────────────────
        print("is_unlocked() — the gate's actual question")
        kd_legacy = os.path.join(tmp, "legacy")
        os.makedirs(kd_legacy)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(os.path.join(kd_legacy, "private.pem"), "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        check("legacy reports unlocked (needs no secret)",
              keyprotect.LegacyBackend(kd_legacy).is_unlocked(), True)

        kd_pw = os.path.join(tmp, "pw")
        pb = PasswordBackend(kd_pw)
        pb.provision("a good passphrase")
        check("a freshly provisioned backend is unlocked in-process",
              pb.is_unlocked(), True)
        check("CONTROL a fresh handle to the same material is LOCKED",
              PasswordBackend(kd_pw).is_unlocked(), False)
        check("CONTROL the TPM stub reports not-unlocked",
              keyprotect.TpmBackend(kd_pw).is_unlocked(), False)

        # ── the gate: tier 4 must never prompt ────────────────────────────
        print("\nstartup gate — deployed tier-4 device")
        prompts = []

        def spy(**kw):
            prompts.append(kw)
            return None            # if it IS called, treat as cancel
        real_prompt = secret_prompt.prompt_secret_auto
        secret_prompt.prompt_secret_auto = spy
        try:
            config.keys_dir = lambda: kd_legacy
            enrollment.reset_backend()
            ok = agent._unlock_key_material()
            check("POSITIVE tier-4 device is allowed to proceed", ok, True)
            check("CONTROL the prompt was NEVER invoked for tier 4",
                  len(prompts), 0)

            # ── unprovisioned device ─────────────────────────────────────
            print("\nstartup gate — unprovisioned device")
            config.keys_dir = lambda: os.path.join(tmp, "empty")
            enrollment.reset_backend()
            check("POSITIVE unprovisioned device proceeds (enrollment provisions)",
                  agent._unlock_key_material(), True)
            check("CONTROL still no prompt", len(prompts), 0)

            # ── locked device, cancelled ─────────────────────────────────
            print("\nstartup gate — locked device, user cancels")
            config.keys_dir = lambda: kd_pw
            enrollment.reset_backend()
            check("CONTROL cancel refuses to proceed", agent._unlock_key_material(), False)
            check("prompt was invoked exactly once before the cancel",
                  len(prompts), 1)
            check("prompt asked for the right secret kind",
                  prompts[0].get("kind"), "password")
            check("prompt was in unlock mode, not create",
                  prompts[0].get("mode"), secret_prompt.UNLOCK)

            # ── locked device, wrong secret N times ──────────────────────
            print("\nstartup gate — repeated wrong secret")
            prompts.clear()
            secret_prompt.prompt_secret_auto = lambda **kw: (
                prompts.append(kw) or "definitely wrong")
            enrollment.reset_backend()
            check("CONTROL repeated failure refuses to proceed",
                  agent._unlock_key_material(), False)
            check("gave exactly MAX_UNLOCK_ATTEMPTS tries",
                  len(prompts), agent.MAX_UNLOCK_ATTEMPTS)

            # ── locked device, correct secret ────────────────────────────
            print("\nstartup gate — correct secret")
            prompts.clear()
            secret_prompt.prompt_secret_auto = lambda **kw: (
                prompts.append(kw) or "a good passphrase")
            enrollment.reset_backend()
            check("POSITIVE correct secret unlocks and proceeds",
                  agent._unlock_key_material(), True)
            check("only one prompt was needed", len(prompts), 1)
            check("the unlocked backend was installed for signing",
                  enrollment.get_backend().is_unlocked(), True)
            sig = enrollment._sign("post-unlock")
            check("signing works after the gate", bool(sig), True)
        finally:
            secret_prompt.prompt_secret_auto = real_prompt

        # ── THE hole: a locked key must not become an unsigned heartbeat ──
        print("\nlocked key must NOT downgrade to an unsigned heartbeat")
        config.keys_dir = lambda: kd_pw
        enrollment.reset_backend()          # backend is now locked again
        got = raises(lambda: agent._sign_heartbeat("dev-1", b"{}"))
        check("CONTROL _sign_heartbeat RAISES rather than returning unsigned",
              got, "Locked")
        # and prove the old behaviour would have been the silent downgrade
        res = None
        try:
            res = agent._sign_heartbeat("dev-1", b"{}")
        except Exception:
            res = "raised"
        check("CONTROL it never returns the (None, None) unsigned tuple",
              res, "raised")

        # a genuinely unexpected error must STILL take the best-effort path
        import enrollment as _en
        real_sign = _en._sign
        _en._sign = lambda m: (_ for _ in ()).throw(ValueError("transient"))
        try:
            check("POSITIVE a non-key error still degrades to unsigned (unchanged)",
                  agent._sign_heartbeat("dev-1", b"{}"), (None, None))
        finally:
            _en._sign = real_sign

        # ── capability reporting ─────────────────────────────────────────
        print("\ncapability reporting")
        config.keys_dir = lambda: kd_pw
        check("reports the password tier", agent._key_protection_tier(), "password")
        config.keys_dir = lambda: kd_legacy
        check("reports the legacy tier", agent._key_protection_tier(), "none")
        config.keys_dir = lambda: os.path.join(tmp, "empty2")
        check("reports unprovisioned", agent._key_protection_tier(), "unprovisioned")

        def boom():
            raise OSError("unreadable")
        config.keys_dir = boom
        check("CONTROL an unreadable path reports 'unknown', NOT 'none'",
              agent._key_protection_tier(), "unknown")

        # ── console fallback selection (testable here: no tkinter) ────────
        print("\nprompt selection follows what Tk can actually do here")
        check("CONTROL Tk availability is detected correctly, either way",
              secret_prompt._tk_available(), _tk_really_importable())
        check("CONTROL no TTY raises NoPromptAvailable, not a silent None",
              raises(lambda: secret_prompt.prompt_secret_console(
                  kind="password", mode=secret_prompt.UNLOCK)),
              "NoPromptAvailable")
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
