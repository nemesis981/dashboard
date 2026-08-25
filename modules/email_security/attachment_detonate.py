"""Hand email attachments to the existing malware sandbox. Build-spec stage 3.

CALLS THE ENGINE AS-IS. DOES NOT FORK OR WRAP ITS ISOLATION LOGIC.
    `DisposableSandbox.detonate()` already does clone -> isolate -> VERIFY ->
    attach read-only -> execute -> collect -> GUARANTEED teardown. This module
    supplies a file and records what came back. It does not reimplement, retry,
    soften, or "improve" any of that -- the isolation properties are the engine's
    to guarantee and re-deriving them here would create a second, weaker copy.

    ⚠ THIS IS THE ENGINE'S FIRST REAL CALLER. It has had none in production until
    now (verified: only test files construct it), so integration failures here are
    genuinely unexplored territory rather than a formality.

THE PAYLOAD PROBLEM, AND WHY MATERIALISATION IS OPT-IN
    `mime_parse` returns attachment METADATA ONLY -- name_hash, extension,
    sha256, size -- and deliberately never retains the bytes. That keeps a
    parser that runs over every arriving message from holding whole payloads of
    a person's private mail in memory, and bounds its footprint regardless of a
    50 MB attachment.

    Detonation needs a real file. So the bytes are re-extracted HERE, from the
    raw message, only for the specific attachment about to be detonated, written
    to a locked-down temp file, and deleted in a `finally`. Materialising a
    payload is thus an explicit act with a narrow lifetime, not a property the
    parser acquires for everybody.

WRITING REAL MALWARE TO THE HOST FILESYSTEM IS A REAL RISK, HANDLED EXPLICITLY
    The sample lands in a private 0700 directory, as a 0600 file, with no
    executable bit, and is removed in a `finally` that runs even when detonation
    raises. The sandbox attaches it READ-ONLY. It is never executed host-side --
    the only thing that runs it is a throwaway VM with no NIC.

STAGE 3.3 -- THE TWO FAILURES ARE NOT INTERCHANGEABLE, AND NEITHER IS "CLEAN"
    `detonate()` raises two distinct exceptions and collapsing them loses the
    only thing that matters about them:

    TeardownFailed  -- the sample RAN and the VM could NOT be confirmed
        destroyed. A VM may still be live with a running sample in it. The batch
        STOPS. Continuing to the next message would start a second VM while an
        uncontrolled one is still up, which is how one bad detonation becomes
        several. This is the halt stage 3.3 exists to require.

    IsolationUnverified -- the sandbox REFUSED and nothing ever executed. Safe,
        but the batch still stops: isolation is a property of the host/VM
        configuration, not of this sample, so every subsequent attachment would
        fail the same way. Precedent is `scan_file`'s ClamEngineUnavailable --
        "the engine being dead is not a per-file condition, and the caller must
        stop rather than grind through a filesystem accumulating identical
        failures."

    Both are RECORDED before the halt, and neither is ever written as a clean
    result. An attachment that was never executed is UNJUDGED, and a row that
    cannot distinguish that from "detonated and found nothing" is worse than no
    row at all.
"""
from __future__ import annotations

import email
import hashlib
import json
import os
import shutil
import tempfile

from modules import get_data_manager

MODULE_NAME = "email_security"

#: Refuse to materialise anything larger than this. Mirrors mime_parse's own
#: ceiling; a sample that exceeds it is recorded as skipped, never silently
#: truncated -- a truncated binary would detonate as garbage and the report would
#: describe the garbage rather than the sample.
MAX_SAMPLE_BYTES = 50 * 1024 * 1024

#: Every value `outcome` may take. Mirrors the enumeration documented in
#: database.init_email_security_tables().
OUTCOMES = ("completed", "isolation_unverified", "teardown_failed",
            "skipped_no_payload", "skipped_too_large", "error")


class DetonationHalted(RuntimeError):
    """The batch stopped deliberately. Carries WHY, and whether it is dangerous.

    `dangerous=True` means a VM could not be confirmed destroyed (TeardownFailed)
    and the host may still be running a sample. That is an operator-visible
    condition, not a retryable error, which is why it is a distinct flag rather
    than something a caller has to infer from the message text.
    """

    def __init__(self, reason, *, dangerous, outcome):
        super().__init__(reason)
        self.dangerous = dangerous
        self.outcome = outcome


def _now() -> str:
    from datetime import datetime
    return datetime.now().isoformat(timespec="seconds")


def extract_payload(raw_message: bytes, sha256: str) -> bytes | None:
    """Re-extract ONE attachment's bytes from the raw message, by content hash.

    Selected by hash rather than by filename or part index: the name is hashed
    by the time we see the metadata, and part indices shift with any re-parse.
    The hash is the only identifier that means the same thing in both places.

    Returns None when no part matches -- an explicit "not found", never b"".
    An empty bytes object is a legitimate payload and must stay distinguishable
    from a failed lookup.
    """
    msg = email.message_from_bytes(raw_message)
    for part in msg.walk():
        if part.is_multipart():
            continue
        try:
            payload = part.get_payload(decode=True)
        except Exception:                                       # noqa: BLE001
            continue
        if payload is None:
            continue
        if hashlib.sha256(payload).hexdigest() == sha256:
            return payload
    return None


def _record(verdict_id, att, outcome, *, report=None, error=None):
    """Persist one detonation result. Routed through the Data Manager (ADR 0006).

    Upserts on (verdict_id, attachment_sha256) so a re-detonation updates rather
    than duplicating, matching the table's UNIQUE constraint.
    """
    if outcome not in OUTCOMES:
        raise ValueError("unknown outcome %r" % outcome)
    dm = get_data_manager()
    dm.upsert(
        MODULE_NAME, "email_attachment_detonations",
        {"verdict_id": verdict_id,
         "attachment_sha256": att.get("sha256"),
         "name_hash": att.get("name_hash"),
         "extension": att.get("extension"),
         "detonated_at": _now(),
         "outcome": outcome,
         "report_json": json.dumps(report) if report is not None else None,
         "error": error,
         "actor": dm.current_actor()},
        conflict_cols=("verdict_id", "attachment_sha256"),
        update=["name_hash", "extension", "detonated_at", "outcome",
                "report_json", "error", "actor"])


def detonate_attachment(sandbox, verdict_id, att, raw_message, *,
                        run_cmd=None, timeout_s=120, collect=None) -> str:
    """Detonate ONE attachment. Returns its outcome string.

    Raises DetonationHalted for the two conditions that must stop a batch; every
    other failure is recorded as 'error' and returned, because one malformed
    attachment is genuinely a per-sample condition.
    """
    # Local import, and this exact form deliberately: `from malware_detection
    # import sandbox` does NOT resolve (modules/ is the package root, and
    # malware_detection is a namespace subpackage of it) -- verified, not assumed.
    # Matches how malware_detection/module.py itself reaches siblings
    # (`from modules.ai_engine import ...`). Local rather than top-of-file so
    # merely importing this module does not drag in the whole sandbox engine.
    from modules.malware_detection import sandbox as sbmod        # noqa: PLC0415

    sha = att.get("sha256")
    if not sha or not att.get("size"):
        _record(verdict_id, att, "skipped_no_payload")
        return "skipped_no_payload"
    if att["size"] > MAX_SAMPLE_BYTES:
        _record(verdict_id, att, "skipped_too_large",
                error="size %d exceeds %d" % (att["size"], MAX_SAMPLE_BYTES))
        return "skipped_too_large"

    payload = extract_payload(raw_message, sha)
    if payload is None:
        _record(verdict_id, att, "skipped_no_payload",
                error="no part in the raw message matched sha256 %s" % sha)
        return "skipped_no_payload"

    # 0700 dir, 0600 file, no exec bit, removed in the finally below.
    workdir = tempfile.mkdtemp(prefix="emailsec-detonate-")
    os.chmod(workdir, 0o700)
    # Carry the real EXTENSION but never the real name: Windows executes by
    # extension, so dropping it would silently produce a sample that cannot run
    # and a report describing nothing. The name half stays hashed.
    ext = att.get("extension")
    sample_name = "sample" + ("." + ext if ext else ".bin")
    sample_path = os.path.join(workdir, sample_name)
    try:
        fd = os.open(sample_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, payload)
        finally:
            os.close(fd)

        try:
            report = sandbox.detonate(sample_path, run_cmd or [],
                                      timeout_s=timeout_s, collect=collect)
        except sbmod.TeardownFailed as exc:
            # RAN, and the VM could not be confirmed destroyed. Record, then stop
            # the batch -- see this module's header.
            _record(verdict_id, att, "teardown_failed", error=str(exc))
            raise DetonationHalted(
                "teardown could not be confirmed for %s -- a VM may still be "
                "running this sample; not continuing to the next attachment: %s"
                % (sample_name, exc),
                dangerous=True, outcome="teardown_failed") from exc
        except sbmod.IsolationUnverified as exc:
            # REFUSED, nothing executed. Safe, but systemic -- stop.
            _record(verdict_id, att, "isolation_unverified", error=str(exc))
            raise DetonationHalted(
                "sandbox refused: isolation could not be verified, so nothing "
                "ran. This is a host/VM configuration condition, not a property "
                "of this sample: %s" % exc,
                dangerous=False, outcome="isolation_unverified") from exc
        except Exception as exc:                                # noqa: BLE001
            _record(verdict_id, att, "error",
                    error="%s: %s" % (type(exc).__name__, exc))
            return "error"

        _record(verdict_id, att, "completed", report=report)
        return "completed"
    finally:
        # Runs even when DetonationHalted propagates. Real malware does not stay
        # on the host filesystem because an exception took an early exit.
        shutil.rmtree(workdir, ignore_errors=True)


def detonate_message_attachments(sandbox, verdict_id, parsed, raw_message,
                                 **kw) -> list:
    """Detonate every attachment on one parsed message, in order.

    Returns the list of outcome strings. Propagates DetonationHalted immediately
    -- the remaining attachments are deliberately NOT attempted, and the caller
    can see how far it got from the length of the list it never received.
    """
    outcomes = []
    for att in getattr(parsed, "attachments", []) or []:
        outcomes.append(
            detonate_attachment(sandbox, verdict_id, att, raw_message, **kw))
    return outcomes
