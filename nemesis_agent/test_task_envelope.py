#!/usr/bin/env python3
"""Stage 1 step 2: signed task envelopes, verified fail-closed.

Run: python3 nemesis_agent/test_task_envelope.py

Nothing is dispatched yet — this covers the two halves of the envelope and the
verifier's refusal paths. Almost every check here is a CONTROL, because the
verifier's job is to say no: a verifier that only ever says yes passes any test
that only tries valid input.
"""
import base64
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, "/opt/nemesis/alert_manager")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_results = []
DEV = "device-under-test"


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def reason(fn):
    """The typed reason a refusal carried — not just 'it raised'."""
    try:
        fn()
    except Exception as e:
        return getattr(e, "reason", type(e).__name__)
    return "ACCEPTED"


def main():
    tmp = tempfile.mkdtemp(prefix="nemesis-envelope-")
    try:
        import nemesis_paths
        import server_keys
        nemesis_paths.data_dir = lambda: tmp
        server_keys.ensure_server_keypair()

        import config
        config.CONF_PATH = os.path.join(tmp, "nemesis_agent.conf")
        import tasks

        pub = serialization.load_pem_public_key(server_keys.public_key_pem().encode())
        now = datetime(2026, 8, 3, 12, 0, 0)

        # ── the positive case ────────────────────────────────────────────
        print("a genuine task for this device")
        env = server_keys.build_task(DEV, "scan", {"path": "/"}, now=now)
        check("POSITIVE verifies",
              tasks.verify_task(dict(env), DEV, pub, now=now)["action"], "scan")
        check("device_id is inside the signed material", env["device_id"], DEV)
        check("CONTROL canonicalisation is deterministic (re-sign matches)",
              server_keys.sign_task(env), env["signature"])

        # ── the refusals ────────────────────────────────────────────────
        print("\nfail-closed refusals")
        check("CONTROL no pinned anchor -> nothing is accepted",
              reason(lambda: tasks.verify_task(dict(env), DEV, None, now=now)),
              "no_pinned_server_key")

        rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rogue_pub = serialization.load_pem_public_key(
            rogue.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo))
        check("CONTROL signed by the WRONG key -> rejected",
              reason(lambda: tasks.verify_task(dict(env), DEV, rogue_pub, now=now)),
              "bad_signature")

        check("CONTROL addressed to ANOTHER device -> rejected",
              reason(lambda: tasks.verify_task(dict(env), "someone-else", pub, now=now)),
              "wrong_device")

        tampered = dict(env)
        tampered["params"] = {"path": "C:\\Windows"}
        check("CONTROL tampered params -> rejected (signature covers the payload)",
              reason(lambda: tasks.verify_task(tampered, DEV, pub, now=now)),
              "bad_signature")

        tampered2 = dict(env)
        tampered2["action"] = "notify"
        check("CONTROL tampered action -> rejected",
              reason(lambda: tasks.verify_task(tampered2, DEV, pub, now=now)),
              "bad_signature")

        old = server_keys.build_task(DEV, "scan", ttl_seconds=60,
                                     now=now - timedelta(hours=2))
        check("CONTROL expired -> rejected",
              reason(lambda: tasks.verify_task(old, DEV, pub, now=now)), "expired")

        future = server_keys.build_task(DEV, "scan", now=now + timedelta(hours=1))
        check("CONTROL issued far in the future -> rejected",
              reason(lambda: tasks.verify_task(future, DEV, pub, now=now)), "expired")

        for missing in ("signature", "device_id", "task_id"):
            broken = {k: v for k, v in env.items() if k != missing}
            check("CONTROL missing %s -> malformed" % missing,
                  reason(lambda b=broken: tasks.verify_task(b, DEV, pub, now=now)),
                  "malformed")

        # ── replay ──────────────────────────────────────────────────────
        print("\nreplay protection")
        fresh = server_keys.build_task(DEV, "scan", now=now)
        tasks.verify_task(dict(fresh), DEV, pub, now=now)
        check("CONTROL not yet marked -> still accepted a second time",
              reason(lambda: tasks.verify_task(dict(fresh), DEV, pub, now=now)),
              "ACCEPTED")
        tasks.mark_seen(fresh["task_id"], fresh["expires_at"], now=now)
        check("CONTROL once marked, a replay is rejected",
              reason(lambda: tasks.verify_task(dict(fresh), DEV, pub, now=now)),
              "replayed")
        check("the store persists (survives a restart)",
              tasks.already_seen(fresh["task_id"], now), True)
        check("CONTROL pruned by EXPIRY, not count — gone once expired",
              tasks.already_seen(fresh["task_id"], now + timedelta(days=2)), False)

        # ── the self-test itself must be able to fail ───────────────────
        print("\nstartup self-test (and its own failure modes)")
        check("POSITIVE self-test passes with a working verifier",
              tasks.self_test(pub, DEV, now=now), None)

        real_verify = tasks.verify_task
        try:
            tasks.verify_task = lambda *a, **k: {"ok": "always"}
            check("CONTROL an always-ACCEPT verifier is caught",
                  reason(lambda: tasks.self_test(pub, DEV, now=now)),
                  "verifier_self_test_failed")
            def always_reject(*a, **k):
                raise tasks.BadSignature("stubbed")
            tasks.verify_task = always_reject
            check("CONTROL an always-REJECT verifier is caught too",
                  reason(lambda: tasks.self_test(pub, DEV, now=now)),
                  "verifier_self_test_failed")
        finally:
            tasks.verify_task = real_verify

        # ── the two canonicalisations must not drift apart ──────────────
        print("\ncanonicalisation parity (server vs agent)")
        probe = {"task_id": "t", "device_id": "d", "action": "a",
                 "params": {"z": 1, "a": [2, 3]},
                 "issued_at": "x", "expires_at": "y", "signature": "IGNORED"}
        check("CONTROL server and agent produce identical canonical bytes",
              server_keys._canonical_bytes(probe), tasks._canonical_bytes(probe))
        check("CONTROL the signature field is excluded from the signed bytes",
              b"IGNORED" in server_keys._canonical_bytes(probe), False)
        check("CONTROL key order does not change the bytes",
              server_keys._canonical_bytes(dict(reversed(list(probe.items())))),
              server_keys._canonical_bytes(probe))
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
