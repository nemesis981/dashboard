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
import logging
import agent_errors
import os
from datetime import datetime, timedelta

import config

_LOG = logging.getLogger("nemesis_agent")


def _log(level, fmt, *args):
    """Log without importing agent.py (which would be circular)."""
    getattr(_LOG, level)(fmt, *args)

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

#: Result reports awaiting delivery. Same marker-file shape as the claim store,
#: for the same reason: each report is written independently by whichever process
#: executed the task, and a shared JSON file would lose reports to the identical
#: read-modify-write race.
RESULTS_DIR_NAME = "task_results"

#: Reports carried per heartbeat. Bounds the payload, not the backlog — nothing
#: is dropped, the remainder simply rides the next beat.
MAX_RESULTS_PER_BEAT = 10

#: Backstop for a server that never acknowledges. See prune_results().
RESULT_MAX_AGE_DAYS = 7

#: Truncation for the free-text detail an agent reports. The server truncates
#: independently — this bound protects the payload, the server's protects the
#: database, and neither may rely on the other.
RESULT_DETAIL_MAX = 500


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


class RotationMalformed(TaskRejected):
    reason = "rotation_malformed"


class BadProofOfPossession(TaskRejected):
    reason = "bad_proof_of_possession"


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


# ── result reports (ADR 0004 Stage 1, step 4) ─────────────────────────────
def _results_dir() -> str:
    return os.path.join(os.path.dirname(config.CONF_PATH), RESULTS_DIR_NAME)


def _result_path(task_id: str) -> str:
    return os.path.join(_results_dir(), _safe_name(task_id) + ".json")


def record_result(task_id: str, ok: bool, detail: str = "",
                  action: str = "", now=None) -> bool:
    """Record what happened to a task, for delivery on the next heartbeat.

    ON DISK, not in memory, and written the instant execution returns. A result
    held in memory is lost to exactly the event most likely to follow a failed
    task — the agent restarting — so the outcome the operator most needs is the
    one an in-memory queue reliably drops.

    FIRST RESULT WINS (`O_EXCL`). A task executes at most once, guaranteed by
    `claim_task()`, so a second report for the same id means something has gone
    wrong; overwriting would discard the first, genuine outcome in favour of the
    anomaly. Returns False if a report already existed.
    """
    now = now or datetime.now()
    try:
        os.makedirs(_results_dir(), exist_ok=True)
        fd = os.open(_result_path(task_id), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return False
    except Exception:
        return False
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump({"task_id": task_id,
                       "action": action,
                       "ok": bool(ok),
                       "detail": str(detail)[:RESULT_DETAIL_MAX],
                       "recorded_at": now.isoformat(timespec="seconds")}, fh)
    except Exception as _e:
        agent_errors.record("E-AGENT-062", "task result write failed: %s" % _e)
        return False
    return True


def pending_results(limit: int = None, now=None) -> list:
    """Result reports awaiting server acknowledgement, oldest first.

    Oldest first so a backlog drains in the order things actually happened
    rather than in whatever order the filesystem lists them.

    An unreadable report is SKIPPED and logged, never sent as a partial or
    defaulted record: a report claiming `ok` because that is the falsy-safe
    default would be indistinguishable from a task that genuinely succeeded.
    Age-pruning removes it eventually.
    """
    limit = MAX_RESULTS_PER_BEAT if limit is None else limit
    prune_results(now)
    out, unreadable = [], 0
    try:
        names = sorted(os.listdir(_results_dir()))
    except FileNotFoundError:
        return []
    for name in names:
        try:
            with open(os.path.join(_results_dir(), name), "r", encoding="utf-8") as fh:
                rec = json.load(fh)
            if not isinstance(rec, dict) or not rec.get("task_id"):
                raise ValueError("malformed result record")
            out.append(rec)
        except Exception:
            unreadable += 1
            continue
    if unreadable:
        _log("warning", "%d unreadable task-result report(s) skipped", unreadable)
    out.sort(key=lambda r: r.get("recorded_at") or "")
    return out[:limit]


def ack_results(task_ids) -> int:
    """Delete the reports the server has confirmed recording. Returns how many.

    Deleting ONLY on acknowledgement is what makes delivery at-least-once: a
    dropped response resends rather than silently discarding an outcome. The
    duplicate that produces is harmless — the server's update is keyed on
    task_id and is idempotent.
    """
    removed = 0
    for tid in (task_ids or []):
        try:
            os.remove(_result_path(tid))
            removed += 1
        except FileNotFoundError:
            continue
        except Exception:
            continue
    return removed


def prune_results(now=None) -> int:
    """Drop reports older than RESULT_MAX_AGE_DAYS. Returns how many were removed.

    The backstop for a server that never acknowledges — otherwise a permanently
    unreachable server grows this directory without bound. Age, not count: a
    count cap would evict the OLDEST reports, which are precisely the ones that
    have been failing to deliver longest and are most worth keeping.
    """
    now = now or datetime.now()
    cutoff = now - timedelta(days=RESULT_MAX_AGE_DAYS)
    removed = 0
    try:
        names = os.listdir(_results_dir())
    except FileNotFoundError:
        return 0
    for name in names:
        path = os.path.join(_results_dir(), name)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                when = datetime.fromisoformat(json.load(fh)["recorded_at"])
        except Exception:
            # Undeliverable and unreadable, so it can never be acked away. mtime
            # is a real measurement rather than a stand-in default, so ageing it
            # out on that is honest — but it is logged, because a report that
            # cannot be read is a defect, not routine housekeeping.
            try:
                when = datetime.fromtimestamp(os.path.getmtime(path))
            except Exception:
                continue
            _log("warning", "unreadable task-result report %s aged by mtime", name)
        if when <= cutoff:
            try:
                os.remove(path)
                removed += 1
            except Exception:
                continue
    return removed


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


# ── server key rotation ───────────────────────────────────────────────────
#: Must match alert_manager/server_keys.ROTATE_ACTION exactly. A mismatch would
#: not fail loudly — the rotation would simply fall through to the ordinary
#: dispatcher, which is the single path it must never take.
ROTATE_ACTION = "rotate_server_key"

#: Tier 1 attestation manifest delivery. Same hazard as ROTATE_ACTION above and
#: handled the same way — special-cased in `_handle_response_tasks`, NEVER
#: reachable from `_CommandHandler._dispatch`. The loopback listener on
#: 127.0.0.1:5002 is unauthenticated, so an action reachable from the dispatcher
#: is one any local process can invoke; a process that could install its own
#: manifest would get to define what "intact" means and make this agent report
#: `attested` against its own tampering. Must stay downstream of the signature
#: check, for exactly the reason rotation does.
ATTEST_ACTION = "attest_manifest"


def verify_rotation(envelope: dict, device_id: str):
    """Return the new public key object a rotation carries, or raise.

    DELIBERATELY DOES NOT CHECK THE ENVELOPE SIGNATURE. That is `verify_task`'s
    job and it must already have run; duplicating it here would create a second
    place where a rotation could be accepted, and the whole safety of this path
    rests on there being exactly one. Anything calling this without having
    verified the envelope first is the bug.

    What it DOES check is proof of possession. The envelope signature proves the
    server AUTHORISED handing out this public key; it proves nothing about
    whether the server holds the matching private half. A wrong or truncated key
    pasted into a rotation would be perfectly signed and would permanently brick
    every device that accepted it — with no key left that can reach them. So the
    new PRIVATE key must sign "rotate|<device_id>|<task_id>|<new_pub_b64>", and
    that message is bound to both this device and this task so a PoP cannot be
    lifted from another rotation.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    if not isinstance(envelope, dict):
        raise RotationMalformed("rotation envelope is not an object")
    params = envelope.get("params")
    if not isinstance(params, dict):
        raise RotationMalformed("rotation has no params")
    b64 = params.get("new_public_key")
    pop = params.get("pop")
    claimed_fp = params.get("new_key_sha256")
    if not b64 or not pop or not claimed_fp:
        raise RotationMalformed(
            "rotation needs new_public_key, pop and new_key_sha256")

    try:
        der = base64.b64decode(b64)
        new_pub = serialization.load_der_public_key(der)
    except Exception as exc:
        # Parsed BEFORE anything is written. A malformed anchor that reached disk
        # would fail later, at verification time, far from its cause.
        raise RotationMalformed("new_public_key does not parse: %s" % exc) from exc

    actual_fp = hashlib.sha256(new_pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    if actual_fp != claimed_fp:
        raise RotationMalformed(
            "new_key_sha256 does not match the key it accompanies")

    message = "rotate|%s|%s|%s" % (device_id, envelope.get("task_id"), b64)
    try:
        new_pub.verify(base64.b64decode(pop), message.encode(),
                       padding.PKCS1v15(), hashes.SHA256())
    except Exception as exc:
        raise BadProofOfPossession(
            "the server did not prove it holds the new private key") from exc
    return new_pub


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
