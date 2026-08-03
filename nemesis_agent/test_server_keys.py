#!/usr/bin/env python3
"""Stage 1 step 1: server keypair + trust-anchor delivery.

Run: python3 nemesis_agent/test_server_keys.py

Step 1 deliberately changes no behaviour — nothing signs, nothing verifies, no
task is dispatched. What it must get right is the plumbing: a keypair that is
created once and never regenerated, a privilege split that is real rather than
decorative, and an anchor that survives the journey into the agent without
disturbing the installer's 8-tuple.

That last one gets the first and loudest control. `_read_baked_config()`'s own
docstring records why: an arity slip on the no-conf path ships an exe that dies
before drawing a single screen, while the conf-present path keeps working and
hides it. That is the 2026-08-02 crash, and this step walks straight past it.
"""
import ast
import base64
import os
import shutil
import stat
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, "/opt/nemesis/alert_manager")

from cryptography.hazmat.primitives import serialization

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def raises(fn):
    try:
        fn()
    except Exception as e:
        return type(e).__name__
    return "NO_EXCEPTION"


def main():
    # ── THE arity guard — first, because it is the known killer ───────────
    print("installer conf tuple arity (the 2026-08-02 crash shape)")
    src = open(os.path.join(HERE, "installer_gui.py")).read()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "_read_baked_config")
    returns = [n for n in ast.walk(fn) if isinstance(n, ast.Return)]
    lens = [len(r.value.elts) if isinstance(r.value, ast.Tuple) else None for r in returns]
    check("both return paths still return 8 values", lens, [8, 8])

    unpack = next((n for n in ast.walk(tree)
                   if isinstance(n, ast.Assign)
                   and isinstance(n.targets[0], ast.Tuple)
                   and isinstance(n.value, ast.Call)
                   and getattr(n.value.func, "id", "") == "_read_baked_config"), None)
    check("main() still unpacks exactly 8 targets",
          len(unpack.targets[0].elts) if unpack else None, 8)
    check("CONTROL the anchor is NOT threaded through that tuple",
          "server_public_key" in ast.get_source_segment(src, fn), False)

    # ── the anchor must be captured before the conf is destroyed ─────────
    print("\nanchor is captured before _consume_conf deletes the file")
    consume = next(n for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef) and n.name == "_consume_conf")
    consume_src = ast.get_source_segment(src, consume)
    check("_consume_conf reads server_public_key",
          "server_public_key" in consume_src, True)
    check("CONTROL it reads BEFORE it removes the file",
          consume_src.index("server_public_key") < consume_src.index("os.remove"), True)
    enroll = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "_enroll")
    check("CONTROL _enroll uses the captured value, not the deleted file",
          "self.conf_path" in ast.get_source_segment(src, enroll), False)

    # ── keypair lifecycle ────────────────────────────────────────────────
    print("\nserver keypair")
    tmp = tempfile.mkdtemp(prefix="nemesis-serverkeys-")
    try:
        import nemesis_paths
        import server_keys
        nemesis_paths.data_dir = lambda: tmp

        pub1 = server_keys.ensure_server_keypair()
        check("keypair created", server_keys.have_server_keypair(), True)
        check("public key is a PEM public key",
              pub1.startswith("-----BEGIN PUBLIC KEY-----"), True)

        mode = stat.S_IMODE(os.stat(server_keys.private_path()).st_mode)
        check("CONTROL private key is 0600, never group/world readable",
              oct(mode), oct(0o600))

        pub2 = server_keys.ensure_server_keypair()
        check("POSITIVE idempotent — second call returns the SAME key", pub2, pub1)

        # The privilege split must be real: the dashboard has no private key.
        print("\nprivilege split (dashboard must not need the private half)")
        dash_only = tempfile.mkdtemp(prefix="nemesis-dashonly-")
        os.makedirs(os.path.join(dash_only, "serverkeys"))
        shutil.copy(server_keys.public_path(),
                    os.path.join(dash_only, "serverkeys", "server_public.pem"))
        nemesis_paths.data_dir = lambda: dash_only
        check("POSITIVE public_key_pem() works with ONLY the public file present",
              server_keys.public_key_pem(), pub1)
        check("CONTROL ...and the private key really is absent there",
              os.path.exists(server_keys.private_path()), False)
        b64 = server_keys.public_key_b64()
        check("CONTROL have_server_keypair() is False without the private half",
              server_keys.have_server_keypair(), False)
        shutil.rmtree(dash_only, ignore_errors=True)
        nemesis_paths.data_dir = lambda: tmp

        # ── base64 DER round-trip (the conf carries this) ────────────────
        print("\nanchor encoding round-trip")
        check("CONTROL base64 payload is single-line (INI-safe)",
              "\n" in b64 or "\r" in b64, False)
        rebuilt = serialization.load_der_public_key(base64.b64decode(b64))
        original = serialization.load_pem_public_key(pub1.encode())
        check("POSITIVE base64 DER rebuilds the identical key",
              rebuilt.public_numbers() == original.public_numbers(), True)

        # ── agent-side pinning ──────────────────────────────────────────
        print("\nagent-side pinning")
        import config
        import enrollment
        kd = os.path.join(tmp, "agentkeys")
        config.keys_dir = lambda: kd

        check("CONTROL nothing pinned yet -> None, not a default",
              enrollment.pinned_server_key(), None)
        check("POSITIVE pinning succeeds", enrollment.pin_server_key(b64), True)
        pinned = enrollment.pinned_server_key()
        check("POSITIVE pinned key matches the server's",
              pinned.public_numbers() == original.public_numbers(), True)

        check("CONTROL an empty anchor is refused", enrollment.pin_server_key(""), False)

        # Garbage must be tested against a CLEAN keys dir. Run against the dir that
        # already holds a pinned key, pin_server_key() short-circuits on its
        # idempotence guard and returns True without ever looking at the input —
        # a control that cannot fail for the reason it claims.
        kd_dirty = os.path.join(tmp, "agentkeys-garbage")
        config.keys_dir = lambda: kd_dirty
        check("CONTROL garbage is refused when nothing is pinned yet",
              enrollment.pin_server_key("not-base64-at-all!!"), False)
        check("CONTROL ...and nothing was written to disk",
              os.path.exists(os.path.join(kd_dirty, "server_public.pem")), False)
        check("CONTROL a valid-base64 NON-key is also refused",
              enrollment.pin_server_key(base64.b64encode(b"hello").decode()), False)
        config.keys_dir = lambda: kd

        # Re-pinning must NOT silently replace an existing anchor.
        other = server_keys.__dict__  # placeholder to keep flake quiet
        from cryptography.hazmat.primitives.asymmetric import rsa
        rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rogue_b64 = base64.b64encode(rogue.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
        enrollment.pin_server_key(rogue_b64)
        still = enrollment.pinned_server_key()
        check("CONTROL an already-pinned anchor is NOT overwritten",
              still.public_numbers() == original.public_numbers(), True)
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
