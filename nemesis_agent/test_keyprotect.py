#!/usr/bin/env python3
"""Isolated tests for the key-protection backends (tier 3 build, step 1).

Run: python3 nemesis_agent/test_keyprotect.py

Nothing here touches %APPDATA%, the live agent, or the server -- every backend
is pointed at a throwaway directory. The signature checks verify against the
server's REAL _verify_enroll_signature, extracted verbatim from hw_monitor.py
rather than reimplemented, so a drift between agent signing and server
verification fails here instead of in the field.

Every positive case is paired with a control that must fail. A check that can
only produce one answer is not a check.
"""
import base64
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from keyprotect import (Corrupt, LegacyBackend, Locked, NotProvisioned,
                        NotSupported, PasswordBackend, TpmBackend,
                        detect_backend, preferred_backend, tier_of)
from keyprotect import tpm as tpm_mod

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

MSG = "device-abc|2026-08-03T09:00:00|deadbeef"
HW_MONITOR = "/opt/nemesis/core_module/hw_monitor/hw_monitor.py"

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok, got, want))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", label, got, want))
    return ok


def raises(fn, exc):
    """Return the exception TYPE NAME raised, so a wrong-but-raising case is
    distinguishable from the right one -- 'it threw something' is not a pass."""
    try:
        fn()
    except exc as e:
        return type(e).__name__
    except Exception as e:            # noqa: BLE001 - deliberate: report, don't mask
        return "UNEXPECTED:" + type(e).__name__
    return "NO_EXCEPTION"


def server_verifier():
    """The production verifier, extracted verbatim. None if unavailable."""
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


def looks_like_unencrypted_key(path):
    """True if this file parses as an UNPROTECTED private key."""
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
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


def main():
    verify = server_verifier()
    print("server verifier: %s" % ("extracted from hw_monitor.py" if verify
                                   else "UNAVAILABLE - signature checks skipped"))
    tmp = tempfile.mkdtemp(prefix="nemesis-keyprotect-test-")
    try:
        kd = os.path.join(tmp, "keys")

        # ── password backend: provision / sign / verify ────────────────────
        print("\npassword backend")
        pb = PasswordBackend(kd)
        check("unprovisioned backend reports is_provisioned False",
              pb.is_provisioned(), False)
        check("sign before provision raises NotProvisioned",
              raises(lambda: pb.sign(MSG), NotProvisioned), "NotProvisioned")

        pub = pb.provision("correct horse battery staple")
        check("provision reports is_provisioned True", pb.is_provisioned(), True)
        sig = pb.sign(MSG)
        if verify:
            check("POSITIVE signature verifies server-side",
                  verify(pub, MSG, sig), True)
            check("CONTROL same signature over a DIFFERENT message fails",
                  verify(pub, MSG + "-tampered", sig), False)
            other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            other_pub = other.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            check("CONTROL signature does not verify under a DIFFERENT key",
                  verify(other_pub, MSG, sig), False)

        # ── the defect this backend exists to close ───────────────────────
        on_disk = [os.path.join(kd, f) for f in os.listdir(kd)]
        check("CONTROL no file on disk parses as an unencrypted private key",
              [p for p in on_disk if looks_like_unencrypted_key(p)], [])

        # ── unlock in a fresh process-equivalent ──────────────────────────
        print("\nunlock semantics")
        pb2 = PasswordBackend(kd)
        check("provisioned but not unlocked raises Locked",
              raises(lambda: pb2.sign(MSG), Locked), "Locked")
        check("CONTROL wrong password raises WrongSecret",
              raises(lambda: pb2.unlock("wrong password"), Exception), "WrongSecret")
        pb2.unlock("correct horse battery staple")
        sig2 = pb2.sign(MSG)
        check("unlocked signature is byte-identical (deterministic PKCS1v15)",
              sig2, sig)

        # ── corruption is NOT reported as a wrong password ─────────────────
        print("\ndamage vs wrong secret")
        env_path = os.path.join(kd, "private.enc.json")
        good_env = json.load(open(env_path))
        bad = dict(good_env)
        raw = bytearray(base64.b64decode(bad["ct"]))
        raw[0] ^= 0xFF                                  # flip one byte
        bad["ct"] = base64.b64encode(bytes(raw)).decode()
        json.dump(bad, open(env_path, "w"))
        pb3 = PasswordBackend(kd)
        check("CONTROL flipped ciphertext byte raises Corrupt, not WrongSecret",
              raises(lambda: pb3.unlock("correct horse battery staple"), Exception),
              "Corrupt")
        json.dump(good_env, open(env_path, "w"))        # restore

        bad2 = dict(good_env); bad2["v"] = 99
        json.dump(bad2, open(env_path, "w"))
        check("CONTROL unknown envelope version raises Corrupt",
              raises(lambda: PasswordBackend(kd).unlock("x"), Exception), "Corrupt")
        json.dump(good_env, open(env_path, "w"))

        # ── change_secret ─────────────────────────────────────────────────
        print("\nchange_secret")
        pb4 = PasswordBackend(kd)
        pb4.change_secret("correct horse battery staple", "a new passphrase")
        check("CONTROL old password no longer unlocks",
              raises(lambda: PasswordBackend(kd).unlock("correct horse battery staple"),
                     Exception), "WrongSecret")
        pb5 = PasswordBackend(kd)
        pb5.unlock("a new passphrase")
        check("public key survives a secret change",
              pb5.public_key_pem().strip(), pub.strip())

        # ── adopting an existing key (migration precondition) ─────────────
        print("\nkey adoption (migration precondition)")
        kd2 = os.path.join(tmp, "keys2")
        legacy_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        legacy_pub = legacy_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        adopted = PasswordBackend(kd2).provision("pw", existing_private_key=legacy_key)
        check("adopted key keeps the SAME public key (identity survives)",
              adopted.strip(), legacy_pub.strip())

        # ── legacy backend ────────────────────────────────────────────────
        print("\nlegacy backend")
        kd3 = os.path.join(tmp, "keys3")
        os.makedirs(kd3)
        with open(os.path.join(kd3, "private.pem"), "wb") as fh:
            fh.write(legacy_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        lb = LegacyBackend(kd3)
        check("legacy reports available when a plain key is present",
              lb.available(), True)
        check("CONTROL legacy refuses to be provisioned into",
              raises(lambda: lb.provision("pw"), NotSupported), "NotSupported")
        lsig = lb.sign(MSG)
        if verify:
            check("legacy signature verifies server-side",
                  verify(lb.public_key_pem(), MSG, lsig), True)
        check("legacy exposes its key for migration to adopt",
              lb.export_private_key().key_size, 2048)
        check("CONTROL legacy reports unavailable in an empty dir",
              LegacyBackend(os.path.join(tmp, "empty")).available(), False)

        # ── selection ─────────────────────────────────────────────────────
        print("\nbackend selection")
        check("detect finds the password backend where one is provisioned",
              detect_backend(kd).tier_id, "password")
        check("detect finds legacy where only a plain key exists",
              detect_backend(kd3).tier_id, "none")
        check("detect returns None where there is no key material",
              detect_backend(os.path.join(tmp, "empty2")), None)
        check("tier_of reports unprovisioned for an empty dir",
              tier_of(os.path.join(tmp, "empty3")), "unprovisioned")
        check("preferred is password while no TPM is available",
              preferred_backend(kd).tier_id, "password")

        # CONTROL: the selector must be provable in BOTH directions, so force
        # the TPM stub available and confirm the choice actually changes.
        tpm_mod._FORCE_AVAILABLE = True
        try:
            check("CONTROL preferred switches to TPM when one IS available",
                  preferred_backend(kd).tier_id, "tpm_pin")
            check("CONTROL detect still finds password (TPM unprovisioned)",
                  detect_backend(kd).tier_id, "password")
        finally:
            tpm_mod._FORCE_AVAILABLE = False
        check("preferred returns to password once TPM is unavailable again",
              preferred_backend(kd).tier_id, "password")
        check("CONTROL TPM stub reports unavailable by default",
              TpmBackend(kd).available(), False)

        # ── erase ─────────────────────────────────────────────────────────
        print("\nerase")
        PasswordBackend(kd).erase()
        check("erase removes the envelope", os.path.isfile(env_path), False)
        check("erase is idempotent",
              raises(lambda: PasswordBackend(kd).erase(), Exception), "NO_EXCEPTION")
        check("detect reports nothing after erase", detect_backend(kd), None)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    passed = sum(1 for _, ok, _, _ in _results if ok)
    total = len(_results)
    print("\n%d/%d checks passed" % (passed, total))
    failed = [r[0] for r in _results if not r[1]]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
