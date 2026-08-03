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

SEEN_TASKS_NAME = "seen_tasks.json"


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
def _seen_path() -> str:
    return os.path.join(os.path.dirname(config.CONF_PATH), SEEN_TASKS_NAME)


def _load_seen() -> dict:
    try:
        with open(_seen_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        # A damaged or absent store must not be read as "nothing seen" silently
        # forever, but it also must not stop the agent. Starting empty means at
        # worst one task could re-execute; refusing to run at all would be worse.
        return {}


def _save_seen(seen: dict) -> None:
    tmp = _seen_path() + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(seen, fh)
        os.replace(tmp, _seen_path())
    except Exception:
        pass


def _prune(seen: dict, now: datetime) -> dict:
    """Drop entries whose task has expired.

    Pruned by EXPIRY, never by count. A count-capped ring can evict a task_id
    that is still inside its validity window, which silently reintroduces the
    duplicate execution this store exists to prevent — and it would do so only
    under load, which is exactly when it is hardest to notice.
    """
    out = {}
    for tid, exp in seen.items():
        try:
            if datetime.fromisoformat(exp) > now:
                out[tid] = exp
        except Exception:
            continue
    return out


def mark_seen(task_id: str, expires_at: str, now=None) -> None:
    now = now or datetime.now()
    seen = _prune(_load_seen(), now)
    seen[task_id] = expires_at
    _save_seen(seen)


def already_seen(task_id: str, now=None) -> bool:
    return task_id in _prune(_load_seen(), now or datetime.now())


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

    if already_seen(envelope["task_id"], now):
        raise Replayed("task %s has already been seen" % envelope["task_id"])

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
