"""Signed file-integrity manifest -- unit tests.

The valuable cases here are the REFUSALS and the self-test's own honesty. A
checker's happy path is trivially green on a healthy box and stays green even if
the checker has stopped checking.
"""
import base64
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import integrity as ig

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_fail = []


def check(label, got, want):
    ok = got == want
    print("  %-66s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUB = KEY.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _signed(td, rel="a.py", body="x = 1\n"):
    with open(os.path.join(td, rel), "w", encoding="utf-8") as fh:
        fh.write(body)
    m = ig.build_manifest(td, files=(rel,), released_at="t")
    m["sig"] = base64.b64encode(KEY.sign(ig.canonical_bytes(m),
                                         padding.PKCS1v15(), hashes.SHA256())).decode()
    return m


def test_canonicalisation_is_stable_and_excludes_sig():
    print("\n[canonical bytes: stable, key-order independent, sig excluded]")
    a = {"version": 1, "files": {"b": "2", "a": "1"}, "released_at": None}
    b = {"released_at": None, "files": {"a": "1", "b": "2"}, "version": 1}
    check("key order does not change the signed bytes",
          ig.canonical_bytes(a) == ig.canonical_bytes(b), True)
    withsig = dict(a); withsig["sig"] = "AAAA"
    check("sig is excluded (a signature cannot cover itself)",
          ig.canonical_bytes(withsig) == ig.canonical_bytes(a), True)


def test_happy_path():
    print("\n[a genuine, unmodified, correctly-signed manifest verifies]")
    with tempfile.TemporaryDirectory() as td:
        m = _signed(td)
        check("signature verifies", ig.verify_signature(m, PUB), True)
        clean, why = ig.is_clean(m, PUB, ig.verify_files(td, m))
        check("is_clean", clean, True)
        check("  no reasons", why, [])


def test_refusals():
    print("\n[REFUSALS -- each must be caught, and named correctly]")
    with tempfile.TemporaryDirectory() as td:
        m = _signed(td)
        with open(os.path.join(td, "a.py"), "a", encoding="utf-8") as fh:
            fh.write("# tamper\n")
        check("modified file -> MODIFIED", ig.verify_files(td, m)["a.py"], ig.MODIFIED)
        check("  and is_clean is False", ig.is_clean(m, PUB, ig.verify_files(td, m))[0], False)

    with tempfile.TemporaryDirectory() as td:
        m = _signed(td)
        os.remove(os.path.join(td, "a.py"))
        check("deleted file -> MISSING", ig.verify_files(td, m)["a.py"], ig.MISSING)

    with tempfile.TemporaryDirectory() as td:
        m = _signed(td)
        forged = json.loads(json.dumps(m))
        forged["files"]["a.py"] = "0" * 64
        check("FORGED manifest -> signature rejects it",
              ig.verify_signature(forged, PUB), False)
        check("  is_clean False even though the file matches the forged hash",
              ig.is_clean(forged, PUB, {"a.py": ig.OK})[0], False)

    with tempfile.TemporaryDirectory() as td:
        m = _signed(td)
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        opub = other.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        check("valid signature, WRONG key -> rejected", ig.verify_signature(m, opub), False)


def test_ambiguity_fails_closed():
    print("\n[ambiguity is a FAILURE, never a pass]")
    check("no manifest", ig.is_clean(None, PUB, {})[0], False)
    check("unknown version", ig.is_clean({"version": 99, "files": {}}, PUB, {})[0], False)
    check("no signature at all", ig.verify_signature({"files": {}}, PUB), False)
    check("empty public key", ig.verify_signature({"sig": "AAAA"}, ""), False)
    check("garbage public key", ig.verify_signature({"sig": "AAAA"}, "not a key"), False)
    with tempfile.TemporaryDirectory() as td:
        m = _signed(td)
        check("ZERO files checked is NOT clean", ig.is_clean(m, PUB, {})[0], False)


def test_unreadable_is_not_ok_and_not_missing():
    print("\n[an unreadable file is its own state -- never 'ok', never 'missing']")
    check("hash_file(None-ish path) -> None", ig.hash_file("/nonexistent/xyz"), None)
    with tempfile.TemporaryDirectory() as td:
        m = _signed(td)
        p = os.path.join(td, "a.py")
        os.chmod(p, 0o000)
        st = ig.verify_files(td, m)["a.py"]
        os.chmod(p, 0o644)
        # root can read anything, so accept either -- but NEVER 'ok' if unreadable
        check("unreadable -> UNREADABLE (or OK when running as root)",
              st in (ig.UNREADABLE, ig.OK), True)


def test_build_refuses_incomplete():
    print("\n[building refuses to sign a manifest it could not fully read]")
    with tempfile.TemporaryDirectory() as td:
        try:
            ig.build_manifest(td, files=("does_not_exist.py",))
            check("raised on unreadable file", False, True)
        except OSError:
            check("raised on unreadable file", True, True)


def test_selftest_passes():
    print("\n[the production-path self-test]")
    ok, detail = ig.selftest()
    check("selftest ok", ok, True)
    check("  reports what it actually proved",
          all(w in detail for w in ("modified", "deleted", "forged", "wrong-key")), True)


if __name__ == "__main__":
    print("signed file-integrity manifest")
    test_canonicalisation_is_stable_and_excludes_sig()
    test_happy_path()
    test_refusals()
    test_ambiguity_fails_closed()
    test_unreadable_is_not_ok_and_not_missing()
    test_build_refuses_incomplete()
    test_selftest_passes()
    print()
    if _fail:
        print("FAILED (%d)" % len(_fail))
        for f in _fail:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS")
