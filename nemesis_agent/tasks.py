"""Server->agent task verification (ADR 0004 Stage 1, step 2).

The heartbeat response is about to stop being a constant `{"ok":true}` and start
carrying instructions. That inverts the trust requirement: until now nothing
authenticated the server to an agent, which was harmless because a forged
`{"ok":true}` is worthless. A forged *task* is not.

The listener is plain HTTP with no confidentiality, and local agents talk
cleartext over the LAN by design, so anyone able to answer on that socket could
otherwise task an agent — arbitrary scan paths today, and after Stage 3,
"read this process's memory". Signing the envelope closes that independently of
transport, which is the only way to close it for the LAN case at all.

EVERY check here fails closed, and each returns a distinct reason rather than a
bare False: "why was this rejected" must never have to be inferred.

The compatibility ramp for THIS direction is free, and that is worth stating.
Heartbeat auth needed an `observe` mode because failing closed would have dropped
real telemetry. Inbound tasks have no such cost: an agent with no pinned anchor
executes nothing, which is exactly what every agent does today. So there is no
observe mode here, and adding one would only be a bypass waiting to be found.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime

import config

#: Same tolerance the server applies to heartbeat `signed_at`
#: (hw_monitor `_AGENT_AUTH_SKEW_S`). Both directions should forgive the same
#: clock drift; a tighter bound here would reject tasks the server considers
#: perfectly current.
CLOCK_SKEW_S = 300

#: Directory of per-task claim markers. A DIRECTORY, not one JSON file, and the
#: reason is atomicity rather than taste.
#:
#: The obvious implementation — read a JSON map, test membership, write it back —
#: is a check-then-act pair over shared state, and it races two ways: two
#: deliveries can both pass the membership test before either writes (the same
#: task executes twice), and two writers can both read-modify-write so one entry
#: is silently lost (that task executes again later). Flagged by Window 2 as the
#: same class fixed five times elsewhere in this codebase on 2026-08-03.
#:
#: Not theoretical for this agent: multiple NemesisAgent.exe processes were
#: observed co-existing on one machine during Tier C testing, and they share this
#: directory.
#:
#: `os.open(..., O_CREAT | O_EXCL)` is atomic on both POSIX and Windows, so
#: creating the marker IS the claim — there is no window between deciding and
#: recording. flock/fcntl were not used because they are not portable to the
#: Windows agent, which is the primary target.
CLAIMS_DIR_NAME = "task_claims"


# ── typed outcomes ────────────────────────────────────────────────────────
class TaskRejected(Exception):
    """Base for every refusal. Carries a machine-readable reason."""

    reason = "rejected"


class NoAnchor(TaskRejected):
    reason = "no_pinned_server_key"


class BadSignature(TaskRejected):
    reason = "bad_signature"


class WrongDevice(TaskRejected):
    reason = "wrong_device"


class Expired(TaskRejected):
    reason = "expired"


class Replayed(TaskRejected):
    reason = "replayed"


class Malformed(TaskRejected):
    reason = "malformed"


class VerifierBroken(TaskRejected):
    reason = "verifier_self_test_failed"


def _canonical_bytes(envelope: dict) -> bytes:
    """Must match alert_manager/server_keys.py::_canonical_bytes exactly."""
    return json.dumps({k: v for k, v in envelope.items() if k != "signature"},
                      separators=(",", ":"), sort_keys=True).encode()


# ── replay store ──────────────────────────────────────────────────────────
def _claims_dir() -> str:
    return os.path.join(os.path.dirname(config.CONF_PATH), CLAIMS_DIR_NAME)


def _safe_name(task_id: str) -> str:
    # task_id is a server-generated uuid4, but it arrives over the network, so it
    # is never pasted into a path unsanitised — a crafted id containing separators
    # would otherwise write outside the directory it is meant to stay in.
    return "".join(ch for ch in str(task_id) if ch.isalnum() or ch in "-_")[:80]


def _marker_path(task_id: str) -> str:
    return os.path.join(_claims_dir(), _safe_name(task_id) + ".json")


def prune_claims(now=None) -> int:
    """Delete markers for tasks that have expired. Returns how many were removed.

    Pruned by EXPIRY, never by count. A count-capped store can evict a task_id
    still inside its validity window, silently reintroducing the duplicate
    execution it exists to prevent — and only under load, which is when it is
    hardest to notice.
    """
    now = now or datetime.now()
    removed = 0
    try:
        for name in os.listdir(_claims_dir()):
            path = os.path.join(_claims_dir(), name)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    exp = json.load(fh).get("expires_at", "")
                if datetime.fromisoformat(exp) <= now:
                    os.remove(path)
                    removed += 1
            except Exception:
                # An unreadable marker is still a claim. Leaving it costs one
                # stale file; deleting it could let a task run twice.
                continue
    except FileNotFoundError:
        pass
    return removed


def claim_task(task_id: str, expires_at: str, now=None) -> bool:
    """Atomically claim a task. True if THIS caller won it, False if already claimed.

    One operation, not a check followed by an act: `O_CREAT | O_EXCL` either
    creates the marker or fails with EEXIST, and the kernel arbitrates. Two
    concurrent deliveries of the same task therefore cannot both win, however
    they interleave.

    Returns False on any unexpected error — failing closed here means a task is
    skipped, which is recoverable by redelivery; failing open would execute it
    twice, which may not be.
    """
    now = now or datetime.now()
    try:
        os.makedirs(_claims_dir(), exist_ok=True)
        prune_claims(now)
        fd = os.open(_marker_path(task_id), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return False
    except Exception:
        return False
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump({"task_id": task_id, "expires_at": expires_at,
                       "claimed_at": now.isoformat(timespec="seconds")}, fh)
    except Exception:
        # The marker exists, so the claim stands even if the body failed to
        # write; prune_claims() treats an unreadable marker as still-claimed.
        pass
    return True


def already_claimed(task_id: str, now=None) -> bool:
    """Diagnostic only — NEVER gate execution on this.

    It is a read, so anything branching on it reintroduces the check-then-act
    race that `claim_task()` exists to remove. Use it for logging and tests.
    """
    prune_claims(now)
    return os.path.exists(_marker_path(task_id))


# ── verification ──────────────────────────────────────────────────────────
def verify_task(envelope: dict, device_id: str, pinned_key, now=None) -> dict:
    """Return the envelope if it is genuinely for this device, or raise.

    Order matters only for the quality of the reason reported; every path
    refuses. `pinned_key` is passed in rather than fetched so the caller — and
    the tests — can be explicit about which anchor is in play.
    """
    now = now or datetime.now()

    if pinned_key is None:
        raise NoAnchor("this device has no pinned server key, so no task can be trusted")

    if not isinstance(envelope, dict):
        raise Malformed("envelope is not an object")
    for field in ("task_id", "device_id", "action", "issued_at", "expires_at", "signature"):
        if not envelope.get(field):
            raise Malformed("envelope is missing %s" % field)

    # Signature first: everything below reads fields that are only meaningful
    # once we know they were not written by whoever answered the socket.
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    digest = hashlib.sha256(_canonical_bytes(envelope)).hexdigest().encode()
    try:
        pinned_key.verify(base64.b64decode(envelope["signature"]),
                          digest, padding.PKCS1v15(), hashes.SHA256())
    except Exception as exc:
        raise BadSignature("task signature did not verify: %s" % exc) from exc

    if envelope["device_id"] != device_id:
        raise WrongDevice("task is addressed to %s, not this device"
                          % envelope["device_id"])

    try:
        issued = datetime.fromisoformat(envelope["issued_at"])
        expires = datetime.fromisoformat(envelope["expires_at"])
    except Exception as exc:
        raise Malformed("unparseable timestamps: %s" % exc) from exc

    if now > expires:
        raise Expired("task expired at %s" % envelope["expires_at"])
    if (issued - now).total_seconds() > CLOCK_SKEW_S:
        raise Expired("task issued_at is too far in the future (%s)" % envelope["issued_at"])

    # Replay is NOT checked here, deliberately. A read-then-decide here plus a
    # record later is exactly the check-then-act pair that races; the caller
    # instead calls claim_task(), which decides and records in one atomic step.
    # Keeping the read out of this function means there is no second, tempting
    # place to gate execution on.
    return envelope


# ── startup self-test ─────────────────────────────────────────────────────
def self_test(pinned_key, device_id: str, now=None) -> None:
    """Prove the verifier can tell good from bad BEFORE it is trusted with real
    tasks. Raises VerifierBroken if it cannot.

    A verifier stubbed, broken or swapped such that it always returns True would
    accept anything; one that always raises would look like a server that never
    sends work. Both are invisible in production and neither shows up in a diff.
    Running a known-good and a known-bad case on every start — not only in a test
    suite — is what catches that, the same shape as
    `scripts/nemesis-fw-neverblock`'s CANARIES.

    Uses a THROWAWAY keypair rather than the real anchor: the point is to test the
    verifying machinery, and generating a local pair avoids needing the server's
    private key on the device (which would defeat the entire design).
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    now = now or datetime.now()
    probe = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = serialization.load_pem_public_key(probe.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))

    env = {
        "task_id": "selftest-known-good",
        "device_id": device_id,
        "action": "noop",
        "params": {},
        "issued_at": now.isoformat(timespec="seconds"),
        "expires_at": now.replace(microsecond=0).isoformat(timespec="seconds"),
    }
    from datetime import timedelta
    env["expires_at"] = (now + timedelta(seconds=600)).isoformat(timespec="seconds")
    digest = hashlib.sha256(_canonical_bytes(env)).hexdigest().encode()
    env["signature"] = base64.b64encode(
        probe.sign(digest, padding.PKCS1v15(), hashes.SHA256())).decode()

    # KNOWN GOOD must pass. Dedupe is bypassed by using a fresh id each run and
    # never marking it seen.
    try:
        verify_task(dict(env), device_id, pub, now=now)
    except TaskRejected as exc:
        raise VerifierBroken(
            "verifier rejected a known-good envelope (%s) — refusing all tasks" % exc)

    # KNOWN BAD must fail: same envelope, one byte of payload altered after signing.
    bad = dict(env)
    bad["action"] = "tampered"
    try:
        verify_task(bad, device_id, pub, now=now)
    except BadSignature:
        return
    except TaskRejected as exc:
        raise VerifierBroken(
            "verifier rejected a tampered envelope for the WRONG reason (%s) — "
            "the signature check may not be running" % exc)
    raise VerifierBroken(
        "verifier ACCEPTED a tampered envelope — refusing all tasks")
