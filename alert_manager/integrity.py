"""Signed file-integrity manifest for the sensitive server-side surface.

DECISION RECORD: ~/work/nemesis-internal/decisions/
                 2026-08-29-file-integrity-tamper-detection-RESOLVED.md

THE AMBITION, STATED HONESTLY AND UP FRONT
    No software is completely tamper-proof. An attacker with persistent root on
    this appliance can eventually defeat anything that runs on it -- that is a
    property of the architecture, not a gap here. **The goal is to make silent,
    undetected tampering substantially harder than the attack it enables**, so
    that every practical shortcut (edit a file, forge a manifest, kill the
    checker) produces a signal somewhere the attacker does not control.

    Read every claim below against that standard, never against "prevents
    tampering", which nothing does.

WHY SIGNED AND NOT MERELY HASHED
    An unsigned hash file is rewritten by the same attacker who edits the file,
    and the check then PASSES and reports health -- worse than no check, because
    it manufactures a reassuring answer. A hash detects corruption; only a
    signature detects an adversary.

    The private key NEVER exists on a deployed appliance. Manifests are signed
    offline at release time. The appliance holds the public half only -- the same
    privilege split `server_keys.py` already makes ("the dashboard ... holds the
    public half only, which means compromising it cannot forge a task"), taken one
    step further: here even the *server* has no private half.

RSA, DELIBERATELY, NOT Ed25519
    Matching `server_keys.py`'s stated reasoning verbatim: "Ed25519 is the better
    primitive; one convention beats one better algorithm when the alternative is
    two." A third signing convention in this codebase would be a worse outcome
    than a slightly weaker-but-uniform one.

⚠ THE CIRCULARITY, NAMED RATHER THAN HIDDEN
    This module is itself a file in the tree it verifies. An attacker who can edit
    `dashboard.py` can edit this. The manifest therefore covers this file too,
    which catches a NAIVE edit -- and does not catch an attacker who replaces both
    the file and the manifest they cannot sign, or who simply replaces the
    deployed verifier wholesale.

    That is why the resolved design puts the RUNNING checker in a root-owned 0500
    location outside this tree, and why the dead-man's-switch heartbeat is
    load-bearing rather than a nicety: killing the checker must not look like
    health. Neither property lives in this file; both are recorded here so the
    limitation of this file alone is never mistaken for the limitation of the
    design.

PURE where it can be. Hashing touches the filesystem; canonicalisation, signature
verification and the verdict logic do not, so every branch is testable.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os

log = logging.getLogger("nemesis.integrity")

#: Manifest schema version. A manifest whose version this code does not know is a
#: FAILURE, never a pass -- an unrecognised format is not permission.
MANIFEST_VERSION = 1

#: The v1 protected surface, per the resolved decision. Deliberately narrow: a
#: manifest covering everything is a manifest nobody keeps current, and a stale
#: manifest produces false alarms that train operators to ignore it.
PROTECTED_FILES = (
    "dashboard.py",
    "alert_manager/roles.py",
    "alert_manager/capabilities.py",
    "modules_loader.py",
    "alert_manager/integrity.py",          # self-coverage; see the docstring
)

OK = "ok"
MODIFIED = "modified"
MISSING = "missing"
UNREADABLE = "unreadable"
EXTRA = "unexpected"


def hash_file(path: str) -> str | None:
    """SHA-256 of a file, or None if it cannot be read.

    None is UNREADABLE, which the caller must treat as a failure. It is NOT the
    same as "absent" and must never collapse into "ok".
    """
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def canonical_bytes(manifest: dict) -> bytes:
    """The EXACT bytes that get signed and verified.

    Canonicalisation is the whole security property of this function: signer and
    verifier must agree byte-for-byte or every signature fails (loud, harmless) --
    or worse, a re-serialisation difference is treated as tampering. Sorted keys,
    no incidental whitespace, explicit UTF-8. The `sig` field is excluded because
    a signature cannot cover itself.
    """
    body = {k: v for k, v in manifest.items() if k != "sig"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def build_manifest(root: str, files=PROTECTED_FILES, *, released_at=None) -> dict:
    """Build an UNSIGNED manifest. Runs OFFLINE at release time, never on an appliance.

    An unreadable file raises rather than recording None: signing a manifest that
    says "I could not read this" would bake an unverifiable entry into a release.
    """
    entries = {}
    for rel in files:
        digest = hash_file(os.path.join(root, rel))
        if digest is None:
            raise OSError("cannot read %r while building manifest -- refusing to "
                          "sign an incomplete manifest" % rel)
        entries[rel] = digest
    return {"version": MANIFEST_VERSION,
            "released_at": released_at,
            "files": entries}


def verify_files(root: str, manifest: dict) -> dict:
    """Compare the manifest against disk. Returns {path: status}.

    Does NOT check the signature -- `verify_signature` does that, and the caller
    must do BOTH. Split deliberately so neither can be mistaken for the other.
    """
    out = {}
    files = (manifest or {}).get("files") or {}
    for rel, expected in files.items():
        full = os.path.join(root, rel)
        if not os.path.exists(full):
            out[rel] = MISSING
            continue
        got = hash_file(full)
        if got is None:
            out[rel] = UNREADABLE          # fail closed: not "ok", not "missing"
        elif got != expected:
            out[rel] = MODIFIED
        else:
            out[rel] = OK
    return out


def verify_signature(manifest: dict, public_key_pem: str) -> bool:
    """True only if `manifest['sig']` is a valid signature over its canonical bytes.

    Every failure path returns False. There is no "could not check, assume ok" --
    an unverifiable signature is indistinguishable from a forged one and must be
    treated as the worse of the two.
    """
    try:
        import base64
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        sig = manifest.get("sig")
        if not sig or not public_key_pem:
            return False
        pub = serialization.load_pem_public_key(public_key_pem.encode())
        pub.verify(base64.b64decode(sig), canonical_bytes(manifest),
                   padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:                                          # noqa: BLE001
        return False


def is_clean(manifest: dict, public_key_pem: str, file_status: dict) -> tuple:
    """(clean, reasons). Clean requires a KNOWN version, a VALID signature, and
    every file OK. Any ambiguity is a failure.
    """
    reasons = []
    if not isinstance(manifest, dict):
        return False, ["no manifest"]
    if manifest.get("version") != MANIFEST_VERSION:
        reasons.append("unknown manifest version %r" % manifest.get("version"))
    if not verify_signature(manifest, public_key_pem):
        reasons.append("manifest signature did not verify")
    for rel, status in sorted((file_status or {}).items()):
        if status != OK:
            reasons.append("%s: %s" % (rel, status))
    if not file_status:
        reasons.append("no files were checked")
    return (not reasons), reasons


# ── SELF-TEST: prove the checker can FAIL before trusting it to pass ──────────

def selftest() -> tuple:
    """(ok, detail). Runs a known-good AND several known-bad cases.

    Modelled directly on `DataManager.selftest_integrity_checker`, whose own words
    state the reason: *"A checker that only ever returns 'ok' is indistinguishable
    from a healthy system right up until the moment it matters."*

    A file-integrity checker is the archetype of that failure -- on a healthy box
    it returns "ok" every time it runs, for years, and a version that ALWAYS
    returns "ok" is observationally identical until the day it is not. So this
    runs in the PRODUCTION path on every verification cycle, not only in a suite.

    Uses a scratch directory and a throwaway keypair: it never touches the real
    protected files or the real key.
    """
    import base64
    import tempfile
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except Exception as exc:                                   # noqa: BLE001
        return False, "cryptography unavailable (%s)" % (exc,)

    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()

        with tempfile.TemporaryDirectory() as td:
            rel = "canary.py"
            full = os.path.join(td, rel)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write("# canary\nVALUE = 1\n")

            man = build_manifest(td, files=(rel,), released_at="selftest")
            man["sig"] = base64.b64encode(key.sign(
                canonical_bytes(man), padding.PKCS1v15(), hashes.SHA256())).decode()

            # 1. KNOWN GOOD -- must pass, or the checker cannot approve anything.
            clean, why = is_clean(man, pub_pem, verify_files(td, man))
            if not clean:
                return False, "known-good case FAILED: %s" % (why,)

            # 2. MODIFIED CONTENT -- one byte.
            with open(full, "a", encoding="utf-8") as fh:
                fh.write("# tampered\n")
            clean, why = is_clean(man, pub_pem, verify_files(td, man))
            if clean:
                return False, "known-bad FAILED: a modified file was reported clean"
            if not any("modified" in w for w in why):
                return False, "modified file was caught, but not reported as modified: %s" % (why,)

            # 3. DELETED -- must not read as ok.
            os.remove(full)
            clean, why = is_clean(man, pub_pem, verify_files(td, man))
            if clean:
                return False, "known-bad FAILED: a deleted file was reported clean"

            # 4. FORGED MANIFEST -- restore the file, then rewrite the recorded
            #    hash as an attacker would. The signature must reject it. This is
            #    the case that distinguishes signing from mere hashing.
            with open(full, "w", encoding="utf-8") as fh:
                fh.write("# attacker content\n")
            forged = json.loads(json.dumps(man))
            forged["files"][rel] = hash_file(full)
            clean, why = is_clean(forged, pub_pem, verify_files(td, forged))
            if clean:
                return False, ("known-bad FAILED: a FORGED manifest was accepted -- "
                               "signature verification is not working")

            # 5. UNREADABLE -- must NOT be reported clean.
            #
            # ⚠ ADDED after mutation testing 2026-08-29 found this case missing:
            # a mutant that treated an unreadable file as OK passed the whole
            # self-test. Fail-open on "cannot read" is the quietest hole this
            # checker could have, and nothing here detected it.
            #
            # A DIRECTORY is used deliberately rather than chmod 000: this may run
            # as root, and root reads anything, so a permission-based case would
            # silently become a no-op in the very context the checker ships in.
            # os.path.exists() is True for a directory and open() raises, which is
            # exactly the exists-but-unreadable shape -- and it behaves the same
            # for every user.
            dirrel = "unreadable_dir"
            os.mkdir(os.path.join(td, dirrel))
            dman = {"version": MANIFEST_VERSION, "released_at": "selftest",
                    "files": {dirrel: "0" * 64}}
            dman["sig"] = base64.b64encode(key.sign(
                canonical_bytes(dman), padding.PKCS1v15(), hashes.SHA256())).decode()
            dstat = verify_files(td, dman)
            if dstat.get(dirrel) == OK:
                return False, ("known-bad FAILED: an UNREADABLE entry was reported OK "
                               "-- the checker fails open")
            if is_clean(dman, pub_pem, dstat)[0]:
                return False, "known-bad FAILED: an unreadable entry was reported clean"

            # 6. WRONG KEY -- a valid signature from the wrong signer must fail.
            other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            other_pub = other.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            with open(full, "w", encoding="utf-8") as fh:
                fh.write("# canary\nVALUE = 1\n")
            clean, _ = is_clean(man, other_pub, verify_files(td, man))
            if clean:
                return False, "known-bad FAILED: a manifest verified against the WRONG key"

        return True, ("known-good passes; modified, deleted, forged, unreadable "
                      "and wrong-key all caught")
    except Exception as exc:                                   # noqa: BLE001
        # An exception is a FAILED self-test, never a skipped one.
        return False, "selftest raised: %r" % (exc,)
