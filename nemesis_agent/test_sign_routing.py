#!/usr/bin/env python3
"""Step 2 verification: signing routed through the key-protection seam.

Run: python3 nemesis_agent/test_sign_routing.py

The claim this step makes is BEHAVIOUR-PRESERVING for already-deployed agents:
a tier-4 device (unencrypted private.pem) must sign exactly as it did before,
because LegacyBackend needs no secret. This proves that by comparing against a
reference implementation of the OLD code path, byte for byte.

It also proves the fail-closed half: once a device is on tier 3, signing raises
Locked until the (not-yet-built) unlock flow supplies the password, rather than
silently falling back to something weaker.

Signature validity is checked against the server's real _verify_enroll_signature,
extracted verbatim from hw_monitor.py.
"""
import base64
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

HW_MONITOR = "/opt/nemesis/core_module/hw_monitor/hw_monitor.py"
MSG = "device-xyz|2026-08-03T10:00:00|cafebabe"

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    shown_got, shown_want = repr(got), repr(want)
    if len(shown_got) > 60:
        shown_got, shown_want = shown_got[:57] + "...", shown_want[:57] + "..."
    print("  [%s] %s   (got=%s want=%s)"
          % ("PASS" if ok else "FAIL", label, shown_got, shown_want))
    return ok


def raises(fn, exc=Exception):
    try:
        fn()
    except exc as e:
        return type(e).__name__
    return "NO_EXCEPTION"


def old_sign_reference(priv_path, message):
    """The PRE-step-2 implementation, reproduced exactly as it was.

    This is the control. Without it, "the new path signs" proves nothing about
    whether it signs the SAME WAY the deployed fleet already does.
    """
    with open(priv_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    return base64.b64encode(
        key.sign(message.encode(), padding.PKCS1v15(), hashes.SHA256())).decode()


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
    verify = server_verifier()
    print("server verifier: %s\n" % ("extracted from hw_monitor.py" if verify
                                     else "UNAVAILABLE"))
    tmp = tempfile.mkdtemp(prefix="nemesis-signroute-")
    try:
        import config
        import enrollment
        import keyprotect
        from keyprotect import PasswordBackend

        kd = os.path.join(tmp, "keys")
        os.makedirs(kd)
        # Point the agent's key directory at the throwaway dir. config.keys_dir()
        # is the single place that resolves it, so this redirects every consumer.
        config.keys_dir = lambda: kd

        # ── tier 4: an already-deployed agent ─────────────────────────────
        print("tier 4 (deployed agent, unencrypted key) -- behaviour must not change")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv_path = os.path.join(kd, "private.pem")
        with open(priv_path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        pub_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()

        enrollment.reset_backend()
        check("backend detected for a legacy device",
              enrollment.get_backend().tier_id, "none")
        new_sig = enrollment._sign(MSG)
        check("POSITIVE routed signature is byte-identical to the OLD code path",
              new_sig, old_sign_reference(priv_path, MSG))
        if verify:
            check("routed signature verifies server-side",
                  verify(pub_pem, MSG, new_sig), True)
            check("CONTROL it does not verify over a different message",
                  verify(pub_pem, MSG + "!", new_sig), False)

        # ── uninstaller de-enroll uses the same seam ──────────────────────
        print("\nuninstaller de-enroll signing")
        # uninstaller_gui imports tkinter at module level, which is absent on
        # this build host, so its "pure helpers (unit-testable off-Windows)"
        # claim does not hold as written. Stub the GUI toolkit so the SIGNING
        # helper can be exercised -- nothing under test touches tkinter.
        import types
        for name in ("tkinter", "tkinter.ttk"):
            if name not in sys.modules:
                sys.modules[name] = types.ModuleType(name)
        sys.modules["tkinter"].ttk = sys.modules["tkinter.ttk"]
        import uninstaller_gui
        signed_at = "2026-08-03T10:00:00+00:00"
        de_sig = uninstaller_gui._sign_deenroll(kd, "device-xyz", signed_at)
        expected = old_sign_reference(
            priv_path, "uninstall|device-xyz|%s" % signed_at)
        check("POSITIVE de-enroll signature matches the OLD direct-load path",
              de_sig, expected)
        if verify:
            check("de-enroll signature verifies server-side",
                  verify(pub_pem, "uninstall|device-xyz|%s" % signed_at, de_sig), True)
        check("CONTROL de-enroll on an empty keys dir raises NotProvisioned",
              raises(lambda: uninstaller_gui._sign_deenroll(
                  os.path.join(tmp, "nokeys"), "d", signed_at)), "NotProvisioned")

        # ── tier 3: fail closed until unlocked ────────────────────────────
        print("\ntier 3 (encrypted key) -- must fail CLOSED, not fall back")
        kd2 = os.path.join(tmp, "keys2")
        config.keys_dir = lambda: kd2
        PasswordBackend(kd2).provision("a passphrase")
        enrollment.reset_backend()
        check("backend detected as password tier",
              enrollment.get_backend().tier_id, "password")
        check("CONTROL signing without unlock raises Locked (no silent fallback)",
              raises(lambda: enrollment._sign(MSG)), "Locked")
        check("CONTROL de-enroll without unlock also raises Locked",
              raises(lambda: uninstaller_gui._sign_deenroll(kd2, "d", signed_at)),
              "Locked")

        # set_backend is the seam the future unlock flow uses
        unlocked = PasswordBackend(kd2)
        unlocked.unlock("a passphrase")
        enrollment.set_backend(unlocked)
        sig3 = enrollment._sign(MSG)
        if verify:
            check("POSITIVE after set_backend(unlocked), signing works and verifies",
                  verify(unlocked.public_key_pem(), MSG, sig3), True)

        # ── no key material at all ────────────────────────────────────────
        print("\nno key material")
        config.keys_dir = lambda: os.path.join(tmp, "empty")
        enrollment.reset_backend()
        check("CONTROL signing with no key raises NotProvisioned",
              raises(lambda: enrollment._sign(MSG)), "NotProvisioned")
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
