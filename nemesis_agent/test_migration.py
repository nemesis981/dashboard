#!/usr/bin/env python3
"""Step 5 verification: tier-4 -> tier-3 migration.

Run: python3 nemesis_agent/test_migration.py

Migration is the only destructive step in the tier-3 build, so most of these
checks are about what must STILL BE THERE after something goes wrong. The
one that matters most: if verification fails after the envelope is written,
the plaintext key must survive -- otherwise a bad migration is
indistinguishable from a good one right up until the device cannot sign.
"""
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import keyprotect
from keyprotect import (LegacyBackend, MigrationAborted, PasswordBackend,
                        migrate_legacy, needs_migration)

HW_MONITOR = "/opt/nemesis/core_module/hw_monitor/hw_monitor.py"
SECRET = "a good device passphrase"
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 46:
        g, w = g[:43] + "...", w[:43] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def raises(fn):
    try:
        fn()
    except Exception as e:
        return type(e).__name__
    return "NO_EXCEPTION"


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


def make_legacy(kd):
    """A tier-4 device: unencrypted private.pem + public.pem."""
    os.makedirs(kd, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(os.path.join(kd, "private.pem"), "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    with open(os.path.join(kd, "public.pem"), "w") as f:
        f.write(pub)
    return key, pub


def main():
    verify = server_verifier()
    tmp = tempfile.mkdtemp(prefix="nemesis-migrate-")
    try:
        # ── the happy path ────────────────────────────────────────────────
        print("tier 4 -> tier 3")
        kd = os.path.join(tmp, "happy")
        _key, pub_before = make_legacy(kd)
        check("a legacy device is detected as needing migration",
              needs_migration(kd), True)
        check("its tier before migration", keyprotect.tier_of(kd), "none")

        backend, pub_after = migrate_legacy(SECRET, kd)
        check("POSITIVE tier after migration", keyprotect.tier_of(kd), "password")
        check("POSITIVE the public key is UNCHANGED (identity survives)",
              pub_after.strip(), pub_before.strip())
        check("CONTROL the plaintext private.pem is gone",
              os.path.exists(os.path.join(kd, "private.pem")), False)
        check("CONTROL nothing on disk still parses as an unencrypted key",
              [f for f in os.listdir(kd)
               if _is_plain_key(os.path.join(kd, f))], [])
        check("no longer reports as needing migration", needs_migration(kd), False)

        if verify:
            sig = backend.sign("post-migration")
            check("POSITIVE the migrated key signs, and the server verifies it",
                  verify(pub_after, "post-migration", sig), True)
            check("CONTROL that signature fails over a different message",
                  verify(pub_after, "post-migration!", sig), False)

        # a fresh process can unlock what was written
        reopened = PasswordBackend(kd)
        check("CONTROL a fresh handle is locked until given the secret",
              reopened.is_unlocked(), False)
        reopened.unlock(SECRET)
        check("the migrated envelope unlocks with the secret",
              reopened.public_key_pem().strip(), pub_before.strip())

        # ── THE control: verification fails => plaintext must survive ─────
        print("\nverification failure must not destroy the old key")
        kd2 = os.path.join(tmp, "corrupt")
        _k2, pub2 = make_legacy(kd2)
        real_unlock = PasswordBackend.unlock

        def broken_unlock(self, secret):
            # Simulate the envelope being unreadable AFTER it was written --
            # i.e. the write "succeeded" but what landed is unusable.
            raise keyprotect.Corrupt("simulated damage after write")
        PasswordBackend.unlock = broken_unlock
        try:
            got = raises(lambda: migrate_legacy(SECRET, kd2))
        finally:
            PasswordBackend.unlock = real_unlock
        check("CONTROL migration aborts when verification fails",
              got, "MigrationAborted")
        check("CONTROL the plaintext key SURVIVED the failed migration",
              os.path.exists(os.path.join(kd2, "private.pem")), True)
        check("CONTROL the surviving key still works",
              LegacyBackend(kd2).public_key_pem().strip(), pub2.strip())

        # ── adopting the WRONG key must be caught ─────────────────────────
        print("\nadopting a different key must be refused")
        kd3 = os.path.join(tmp, "wrongkey")
        _k3, pub3 = make_legacy(kd3)
        # Pre-place an envelope holding a DIFFERENT key, as a crashed/partial
        # migration might. The public-key comparison is what must catch it.
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        PasswordBackend(kd3).provision(SECRET, existing_private_key=other)
        # restore the legacy public.pem that provision() just overwrote
        with open(os.path.join(kd3, "public.pem"), "w") as f:
            f.write(pub3)
        check("CONTROL a mismatched key aborts migration",
              raises(lambda: migrate_legacy(SECRET, kd3)), "MigrationAborted")
        check("CONTROL the plaintext key survived that too",
              os.path.exists(os.path.join(kd3, "private.pem")), True)

        # ── resumable half-migrated state ─────────────────────────────────
        print("\nhalf-migrated state (crash between write and delete)")
        kd4 = os.path.join(tmp, "half")
        _k4, pub4 = make_legacy(kd4)
        adopted = LegacyBackend(kd4).export_private_key()
        PasswordBackend(kd4).provision(SECRET, existing_private_key=adopted)
        check("both files present is detected as needing migration",
              needs_migration(kd4), True)
        b4, p4 = migrate_legacy(SECRET, kd4)
        check("POSITIVE resuming completes the migration",
              os.path.exists(os.path.join(kd4, "private.pem")), False)
        check("and the key is still the original one", p4.strip(), pub4.strip())

        # ── refusals that must not touch anything ─────────────────────────
        print("\nrefusals leave the directory untouched")
        kd5 = os.path.join(tmp, "nosecret")
        make_legacy(kd5)
        before = sorted(os.listdir(kd5))
        check("CONTROL an empty secret is refused",
              raises(lambda: migrate_legacy("", kd5)), "MigrationAborted")
        check("CONTROL the directory is unchanged after refusal",
              sorted(os.listdir(kd5)), before)
        check("CONTROL the plaintext key is still there",
              os.path.exists(os.path.join(kd5, "private.pem")), True)

        # ── idempotence ───────────────────────────────────────────────────
        print("\nidempotence")
        b_again, p_again = migrate_legacy(SECRET, kd)
        check("re-running on a migrated dir is a no-op",
              p_again.strip(), pub_before.strip())
        check("and does not resurrect a plaintext key",
              os.path.exists(os.path.join(kd, "private.pem")), False)
        empty = os.path.join(tmp, "empty")
        os.makedirs(empty)
        check("CONTROL an empty dir needs no migration", needs_migration(empty), False)
        check("CONTROL migrating an empty dir returns nothing, does not raise",
              migrate_legacy(SECRET, empty), (None, None))

        # ── agent wiring ──────────────────────────────────────────────────
        print("\nagent wiring")
        src = open(os.path.join(HERE, "agent.py")).read()
        check("migration runs after the unlock gate",
              src.index("_unlock_key_material()") < src.index("_migrate_key_material()"),
              True)
        check("CONTROL declining does NOT stop the agent (migrate-or-continue)",
              "DECLINED" in src and "return" in src, True)
        check("private_key_path is cleared after a successful migration",
              'conf["private_key_path"] = ""' in src, True)
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


def _is_plain_key(path):
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


if __name__ == "__main__":
    raise SystemExit(main())
