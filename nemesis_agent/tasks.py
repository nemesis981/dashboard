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
import time
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


# ── task-action classification: DEFAULT-DENY dispatch ─────────────────────
#
# WHY THIS EXISTS. Until this landed, a signed task naming ANY action the local
# `_CommandHandler._dispatch` happened to understand was executed, because the
# dispatch chain in `agent.py` ended in a bare `else:` that forwarded everything.
# Adding a new action to that handler — for the GUI, for a local tool, for
# anything — silently made it REMOTELY executable, with no decision recorded
# anywhere that it should be.
#
# That is the `_AUTH_EXEMPT` failure shape CLAUDE.md already documents, and it
# fails in the dangerous direction: an action nobody classified runs, rather than
# being refused. Here the default is inverted. An action this module has never
# been told about is REFUSED, so the cost of forgetting is a task that does not
# run — visible, recoverable, and reported with a typed reason — instead of one
# that runs without anyone having decided it may.
#
# This is dispatch safety, NOT authorization. Membership below means only "the
# outer server signature is a sufficient basis for running this." It says nothing
# about whether a human approved it; that is a separate question with a separate
# key, and an action needing it gets a stronger disposition than EXEMPT.

#: Disposition: outer server signature alone is sufficient.
DISP_EXEMPT = "EXEMPT"
#: Disposition: this module has never been told about the action. Refuse.
DISP_UNCLASSIFIED = "UNCLASSIFIED"
DISP_LOOPBACK_ONLY = "LOOPBACK_ONLY"


class UnclassifiedAction(TaskRejected):
    reason = "action_not_classified"


class LoopbackOnlyAction(TaskRejected):
    """A DELIBERATELY local-only action, named by a signed server task.

    Distinct from `UnclassifiedAction` on purpose. That one means "nobody has
    decided about this action yet" and is a gap to close; this one means "someone
    decided, and the answer was no." Collapsing them would make a settled security
    decision indistinguishable from an oversight — and the next person to see the
    refusal would close the "gap" by classifying the action, silently reversing it.
    """

    reason = "action_is_loopback_only"


#: Actions executable on the outer signature alone. This set is the STATUS QUO at
#: the time default-deny landed — every action the dispatcher already accepted
#: from a signed task — so this change refuses nothing that previously ran. Its
#: value is entirely prospective: the NEXT action added must be classified here
#: deliberately, or it does not run remotely.
#:
#: Adding a name here is a security decision, not bookkeeping. Ask whether an
#: appliance that has been taken over should be able to invoke it on every
#: enrolled endpoint on the strength of its own signature alone. If the answer is
#: no, it does not belong in this set.
BASE_EXEMPT_ACTIONS = frozenset({
    # Read-only / self-reporting.
    "ping", "status", "scan_status",
    # Read-only, and discloses nothing the server does not already hold: the
    # findings buffer is a bounded local COPY of behavioral events already sent
    # up by heartbeat (`_drain_behavioral` feeds both). Classified 2026-08-25
    # with the GUI-findings commit.
    "findings",
    # Local-effect, already reachable unauthenticated on the loopback listener,
    # so a signed task grants nothing a local process did not already have.
    "checkin", "notify",
    # State-changing but long-established as server-driven, and each already
    # bounded by its own handler.
    #
    # `restart` LEFT THIS SET on 2026-08-30 and is now APPROVAL-REQUIRED below —
    # ADR 0026 §D3's first live consumer. Removed rather than listed in both:
    # `disposition()` checks approval-required first so the stricter reading would
    # have won anyway, but a membership that never decides anything is exactly the
    # kind of stale entry a later reader has to reverse-engineer.
    "scan", "update_rules",
    # Trust-plumbing, special-cased upstream of `_dispatch` and verified against
    # the currently-pinned anchor before either can run.
    ROTATE_ACTION, ATTEST_ACTION,
})
#
# ⚠ THIS SET CREATES A REAL CROSS-CHANGE DEPENDENCY. Any commit that adds an
# action to `_CommandHandler._dispatch` must classify it IN THE SAME COMMIT --
# here, in BASE_LOOPBACK_ONLY_ACTIONS below, or in BASE_APPROVAL_REQUIRED_ACTIONS
# -- or the action works locally over the loopback listener and is silently
# refused when the server sends it. `test_task_classification.py` fails in both
# directions -- a dispatcher action in no set, and a set entry with no handler --
# so the omission surfaces as a red suite rather than as a field report.
#
# It did exactly that on 2026-08-25: the agent-GUI commit added `findings` and
# `report_error` without classifying either, and the suite caught it before the
# commit landed. Both are now classified, in OPPOSITE directions -- see each set.


#: Actions the dispatcher handles that a signed SERVER task may NEVER invoke.
#:
#: This set exists because "deliberately not remotely invocable" and "nobody has
#: classified this yet" were previously the same state: absence. An absence cannot
#: record a decision, so a future reader finding one could only guess whether it
#: was intent or an oversight -- and the safe-looking repair (add it to the exempt
#: set, make the suite green) silently reverses a security decision nobody knew
#: had been made. Same failure shape this codebase already checks for elsewhere: a
#: default that means something is indistinguishable from a real answer.
#:
#: Membership here is not a weaker EXEMPT. It is a refusal, and `assert_dispatchable`
#: raises `LoopbackOnlyAction` for it, which the agent reports back to the server
#: rather than dropping.
BASE_LOOPBACK_ONLY_ACTIONS = frozenset({
    # WRITES to this device's own error ledger, whitelisted to E-AGENT-090 --
    # "the agent GUI is unavailable". Only the local GUI can truthfully assert
    # that, so a server has no legitimate use for it and nothing is lost by
    # refusing. What IS lost by allowing it: a compromised or confused server
    # could inject false entries into the exact ledger an operator reads when
    # diagnosing this device. No benefit against a real (if small) integrity
    # cost -- so, denied. Classified 2026-08-25 with the GUI-findings commit.
    "report_error",
})

_runtime_loopback_only = {}


#: Actions contributed at runtime by OPTIONAL modules (see `register_exempt_action`).
#: Separate from the frozen base set so the base set stays auditable as a literal.
_runtime_exempt = {}


def register_exempt_action(action: str, reason: str) -> None:
    """Let an optional module declare its own action outer-signature-exempt.

    Exists for modules whose action NAMES are not public — the Tier 2
    challenge-response action is defined in a private module, and hardcoding its
    literal in this file would move a private detail into the public repo to gain
    nothing. The module registers it at load time instead.

    `reason` is mandatory and recorded: a registration with no stated reason is
    indistinguishable from one added by accident, which is the state this whole
    mechanism exists to prevent. Registration only ever ADDS, never removes, so a
    module cannot use this to strip a classification another module relies on.
    """
    if not action or not isinstance(action, str):
        raise ValueError("register_exempt_action needs a non-empty action name")
    if not reason:
        raise ValueError("register_exempt_action requires a stated reason")
    _runtime_exempt[action] = reason
    _log("info", "task action %r registered exempt: %s", action, reason)


def disposition(action) -> str:
    """DISP_EXEMPT or DISP_UNCLASSIFIED. Never raises, never guesses.

    Returns a disposition for ANY input, including None and non-strings, because
    the caller's job is to act on the answer rather than to pre-validate the
    question — and a type error here would surface as a crash in the poll loop
    rather than as a refused task.
    """
    if isinstance(action, str) and (action in BASE_APPROVAL_REQUIRED_ACTIONS
                                    or action in _runtime_approval_required):
        # Checked FIRST. If an action were ever listed in both sets, the safe
        # reading is the stricter one -- an ambiguity resolved toward "needs an
        # approval" costs a refused task; resolved the other way it silently
        # drops the admin check entirely.
        return DISP_APPROVAL_REQUIRED
    if isinstance(action, str) and (action in BASE_LOOPBACK_ONLY_ACTIONS
                                    or action in _runtime_loopback_only):
        # Checked BEFORE the exempt set, same reasoning as approval-required
        # above: if an action were ever listed in both, the safe reading is the
        # refusal. A wrongly-refused local-only action costs a failed task; a
        # wrongly-allowed one hands the server a capability someone decided
        # against.
        return DISP_LOOPBACK_ONLY
    if isinstance(action, str) and (action in BASE_EXEMPT_ACTIONS
                                    or action in _runtime_exempt):
        return DISP_EXEMPT
    return DISP_UNCLASSIFIED


def assert_dispatchable(action) -> str:
    """Return the disposition, or raise `UnclassifiedAction`.

    Called BEFORE `claim_task`, deliberately. An unclassified action can never
    become runnable by being redelivered, so consuming its one-shot claim would
    spend a marker to learn nothing — and would make the refusal look like a
    replay to whoever read the claims directory afterwards.
    """
    disp = disposition(action)
    if disp == DISP_LOOPBACK_ONLY:
        raise LoopbackOnlyAction(
            "action %r is handled locally over the loopback listener only and is "
            "deliberately not remotely invocable; this is a recorded decision, not "
            "a missing classification" % (action,))
    if disp == DISP_UNCLASSIFIED:
        raise UnclassifiedAction(
            "action %r is not classified for remote dispatch; a signed task may "
            "only run an action explicitly listed in BASE_EXEMPT_ACTIONS or "
            "registered by a loaded module" % (action,))
    return disp


# ── inner admin-approval envelope (ADR 0026 §D3) ──────────────────────────
#
# WHY THE AGENT VERIFIES THIS ITSELF, AND WHY THAT IS THE WHOLE POINT.
#
# The outer signature above answers "did this come from the real server?". It
# cannot answer "did a human approve this?", because the APPLIANCE HOLDS THE KEY
# THAT MAKES IT. An appliance that has been taken over signs whatever it likes.
#
# ADR 0026 §D3 exists to close exactly that, by keeping the admin private key on
# the operator's phone where the appliance never has it. But the ADR also says the
# inner authorization is "verified server-side at the gate" -- and those two
# statements cannot both hold. A compromised appliance simply patches out its own
# gate, mints an envelope and signs it; an agent checking only the outer signature
# executes it, and the admin key never enters the picture. The guarantee evaporates
# precisely when it is needed. (Operator decision, 2026-08-24: resolve toward the
# stronger reading. Do not re-litigate this back to server-side-only.)
#
# So the agent checks the inner envelope against a key IT pinned at enrollment.
#
# ⚠ WHAT THIS DOES AND DOES NOT PROVE -- read before extending it.
#
# The agent has no database of pending requests, so §7 steps 1-2 ("is this request
# known, is it PENDING") are NOT meaningful here: the whole record arrives over the
# wire from the party we are defending against. What the admin signature does prove
# is that SOME genuine admin approved EXACTLY these field values, because every
# field of `P` is covered by it and the appliance cannot produce that signature.
#
# A compromised appliance is therefore reduced from "forge any approval" to "replay
# a genuine one", and the three checks below close that residue:
#
#   * `target` must be THIS device      -> cannot be replayed onto another agent
#   * `expires_at` must not have passed -> bounds the replay window
#   * `claim_approval(request_id)`       -> single-use, ON THIS AGENT, forever
#
# The claim keys on `request_id`, NOT `task_id`, deliberately: a compromised
# appliance can mint a fresh `task_id` around an old approval whenever it likes,
# so claiming the task id would defend nothing.
#
# What remains genuinely out of reach: an attacker holding the SERVER key can still
# run any EXEMPT action, because those were never meant to carry this layer. And an
# appliance compromised AT ENROLLMENT can pin its own admin key, which no
# agent-side code can detect -- that is the trust root, mitigated out of band by
# comparing `enrollment.admin_authenticators_fingerprint()` against the companion
# app, not by anything in this file.

#: Disposition: requires a verified inner admin approval as well as the outer
#: signature.
DISP_APPROVAL_REQUIRED = "APPROVAL_REQUIRED"

#: Envelope fields carrying the inner authorization. Written by
#: `core/admin_approval_gate.py`; read here.
APPROVAL_FIELD = "admin_approval"
APPROVED_PARAMS_FIELD = "action_params_b64"

#: Directory of single-use approval claims. Separate namespace from
#: `task_claims`: the two answer different questions ("has this DELIVERY run" vs
#: "has this APPROVAL ever been spent here") and sharing a directory would let one
#: id space collide with the other.
APPROVAL_CLAIMS_DIR_NAME = "approval_claims"

#: Actions that require a verified admin approval.
#:
#: WAS EMPTY until 2026-08-30, correctly so at the time: ADR §6 named
#: `push_and_run` as the first capability to need one, and that feature does not
#: exist. `restart` is here instead, and the substitution is deliberate — §6's
#: ordering predates anyone checking whether `push_and_run` existed, so waiting
#: for it would have left the whole protocol unexercised indefinitely. `restart`
#: is a REAL, already-dispatched action with a real target device, which is what
#: the gate's `target` binding needs to be meaningful.
#:
#: ⚠ AN ACTION LISTED HERE CANNOT BE QUEUED THE ORDINARY WAY. `hw_monitor.
#: enqueue_task()` queues an intent whose envelope is built at delivery, and that
#: envelope carries no inner approval block — this agent would refuse it. An
#: approval-required action must be queued via `enqueue_approved_task()` with an
#: envelope already minted by `admin_approval_gate.mint_approved_task()`. Adding
#: an action here without moving its callers is therefore not a tightening, it is
#: a break: every dispatch of it starts failing at the agent.
BASE_APPROVAL_REQUIRED_ACTIONS = frozenset({
    # ADR 0026 §D3's first live consumer, 2026-08-30. Moved out of
    # BASE_EXEMPT_ACTIONS above. Restarting an endpoint is state-changing, has a
    # real target device, and is disruptive enough to be worth a human's explicit
    # per-action approval — while being one of the few existing actions whose
    # failure mode under a bad approval is merely "the device did not restart".
    "restart",
})

_runtime_approval_required = {}


class ApprovalMissing(TaskRejected):
    reason = "admin_approval_missing"


class ApprovalMalformed(TaskRejected):
    reason = "admin_approval_malformed"


class ApprovalUnknownAuthenticator(TaskRejected):
    reason = "admin_approval_unknown_authenticator"


class ApprovalWrongTarget(TaskRejected):
    reason = "admin_approval_wrong_target"


class ApprovalExpired(TaskRejected):
    reason = "admin_approval_expired"


class ApprovalBadSignature(TaskRejected):
    reason = "admin_approval_bad_signature"


class ApprovalReplayed(TaskRejected):
    reason = "admin_approval_replayed"


def register_approval_required_action(action: str, reason: str) -> None:
    """Declare an optional module's action approval-required. See
    `register_exempt_action` for why registration exists at all."""
    if not action or not isinstance(action, str):
        raise ValueError("register_approval_required_action needs an action name")
    if not reason:
        raise ValueError("register_approval_required_action requires a reason")
    _runtime_approval_required[action] = reason
    _log("info", "task action %r registered APPROVAL-REQUIRED: %s", action, reason)


def _approval_claims_dir() -> str:
    return os.path.join(os.path.dirname(config.CONF_PATH), APPROVAL_CLAIMS_DIR_NAME)


def prune_approval_claims(now=None) -> int:
    """Delete claims for approvals that have expired. Pruned by EXPIRY, never by
    count -- same reasoning as `prune_claims`: evicting a still-valid id would
    silently re-open the replay it exists to prevent, and only under load."""
    now = int(now if now is not None else time.time())
    removed = 0
    try:
        for name in os.listdir(_approval_claims_dir()):
            path = os.path.join(_approval_claims_dir(), name)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    if int(json.load(fh).get("expires_at", 0)) <= now:
                        os.remove(path)
                        removed += 1
            except Exception:                                      # noqa: BLE001
                # An unreadable claim is still a claim. Leaving it costs one
                # stale file; removing it would re-open a replay window.
                continue
    except FileNotFoundError:
        return 0
    except Exception:                                              # noqa: BLE001
        return removed
    return removed


def claim_approval(request_id_hex: str, expires_at: int, now=None) -> bool:
    """Atomically spend an approval ON THIS AGENT. True only for the first caller.

    `O_CREAT | O_EXCL`, exactly like `claim_task` -- the kernel arbitrates, so two
    concurrent deliveries of one approval cannot both win however they interleave.

    Returns False on ANY unexpected error. Failing closed here means an approved
    action is skipped, which the operator can retry by approving again; failing
    open means a replayed approval executes, which may not be undoable.
    """
    now = int(now if now is not None else time.time())
    safe = "".join(ch for ch in str(request_id_hex) if ch.isalnum())[:80]
    if not safe:
        return False
    try:
        os.makedirs(_approval_claims_dir(), exist_ok=True)
        prune_approval_claims(now)
        fd = os.open(os.path.join(_approval_claims_dir(), safe + ".json"),
                     os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return False
    except Exception:                                              # noqa: BLE001
        return False
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump({"request_id": safe, "expires_at": int(expires_at),
                       "claimed_at": now}, fh)
    except Exception:                                              # noqa: BLE001
        pass          # the marker exists, so the claim stands
    return True


def _require(block, key, kind, what):
    v = block.get(key)
    if not isinstance(v, kind) or (kind is str and not v):
        raise ApprovalMalformed("admin_approval.%s %s" % (key, what))
    return v


def verify_admin_approval(envelope, device_id, appliance_id=None, now=None,
                          lookup=None, claim=None) -> dict:
    """Verify the inner admin approval on `envelope`. Returns it, or raises.

    Every failure path raises a DISTINCT `TaskRejected` subclass. "Why was this
    refused" must not have to be inferred -- the same discipline the outer
    verifier and spec §8 already apply.

    `lookup(authenticator_id)` resolves a PINNED registration; defaults to
    `enrollment.pinned_admin_authenticator`. It must never be satisfied from the
    envelope: a key that arrived with the assertion proves only that whoever sent
    it holds the matching private half, which the attacker minting the envelope
    trivially does.
    """
    import admin_approval as aap                                   # noqa: PLC0415
    import base64 as _b64                                          # noqa: PLC0415

    now = int(now if now is not None else time.time())
    if not isinstance(envelope, dict):
        raise ApprovalMalformed("envelope is not an object")
    block = envelope.get(APPROVAL_FIELD)
    if block is None:
        raise ApprovalMissing(
            "action %r requires an admin approval and the envelope carries none"
            % (envelope.get("action"),))
    if not isinstance(block, dict):
        raise ApprovalMalformed("%s is not an object" % APPROVAL_FIELD)

    raw_params = envelope.get(APPROVED_PARAMS_FIELD)
    if not isinstance(raw_params, str):
        raise ApprovalMalformed("%s missing or not a string" % APPROVED_PARAMS_FIELD)
    try:
        # validate=True so a tampered field RAISES instead of silently decoding
        # to something shorter that would then be hashed into a different P.
        action_params = _b64.b64decode(raw_params, validate=True)
    except Exception as exc:                                       # noqa: BLE001
        raise ApprovalMalformed("%s is not valid base64: %s"
                                % (APPROVED_PARAMS_FIELD, exc)) from exc

    auth_id = _require(block, "authenticator_id", str, "missing")
    target = block.get("target") or ""
    req_hex = _require(block, "request_id", str, "missing")

    # ── the key comes from LOCAL state, never the wire ──────────────────────
    lookup = lookup or _default_authenticator_lookup
    record = lookup(auth_id)
    if record is None:
        raise ApprovalUnknownAuthenticator(
            "no PINNED authenticator %r on this device; refusing rather than "
            "trusting a key supplied with the request" % (auth_id,))

    # ── this approval must be for THIS device ───────────────────────────────
    if target != (device_id or ""):
        raise ApprovalWrongTarget(
            "approval authorises target %r, this device is %r" % (target, device_id))
    if appliance_id is not None and block.get("appliance_id") != appliance_id:
        raise ApprovalWrongTarget(
            "approval was issued by appliance %r, this device is enrolled to %r"
            % (block.get("appliance_id"), appliance_id))

    try:
        issued_at = int(block["issued_at"])
        expires_at = int(block["expires_at"])
        match_code = int(block["match_code"])
    except Exception as exc:                                       # noqa: BLE001
        raise ApprovalMalformed("unparseable approval timestamps/code: %s" % exc)
    if now > expires_at:
        raise ApprovalExpired("approval expired at %d (now %d)" % (expires_at, now))

    # ── rebuild P and run the SAME §7 the appliance runs ────────────────────
    #
    # `action_params` comes from the bytes ABOUT TO EXECUTE, not from a separate
    # copy inside the block. That is what binds the signature to the work: alter
    # the parameters and P changes and the admin signature stops verifying.
    try:
        stored = {
            "request_id": bytes.fromhex(req_hex),
            "capability": _require(block, "capability", str, "missing"),
            "target": target,
            "action_params": action_params,
            "appliance_id": block.get("appliance_id") or "",
            "authenticator_id": auth_id,
            "issued_at": issued_at, "expires_at": expires_at,
            "match_code": match_code,
            "nonce": _b64.b64decode(block.get("nonce") or "", validate=True),
            "user_id": record.get("user_id"),
            # Steps 1-2 are appliance-DB concepts with no agent-side meaning (see
            # the block comment above). Stated explicitly rather than left for a
            # reader to deduce from a passing test.
            "state": "PENDING",
        }
        assertion = {
            "authenticator_data": _b64.b64decode(
                block.get("authenticator_data") or "", validate=True),
            "client_data_json": _b64.b64decode(
                block.get("client_data_json") or "", validate=True),
            "signature": _b64.b64decode(block.get("signature") or "", validate=True),
        }
    except Exception as exc:                                       # noqa: BLE001
        raise ApprovalMalformed("undecodable approval material: %s" % exc) from exc

    claim = claim or claim_approval
    verdict = aap.verify_approval(
        stored_request=stored, authenticator=record, assertion=assertion, now=now,
        consume=lambda _rid: claim(req_hex, expires_at, now=now))
    if not verdict.ok:
        # A lost claim is a REPLAY from this agent's point of view, and saying so
        # is more useful than "consumption race" -- there is no race here, the
        # approval was simply already spent on this device.
        if verdict.reason == aap.Reason.CONSUMPTION_RACE:
            raise ApprovalReplayed(
                "approval %s has already been spent on this device" % req_hex[:16])
        raise ApprovalBadSignature(
            "admin approval did not verify (%s at step %s): %s"
            % (verdict.reason, verdict.step, verdict.detail))
    return block


def _default_authenticator_lookup(authenticator_id):
    """Resolve a pinned authenticator. Isolated so `verify_admin_approval` has no
    import-time dependency on `enrollment` (which imports requests/psutil and is
    far heavier than this module needs to be)."""
    import enrollment                                              # noqa: PLC0415
    return enrollment.pinned_admin_authenticator(authenticator_id)


def approval_self_test() -> None:
    """Prove the approval verifier can REFUSE before it is trusted to accept.

    The dangerous mutation is one that always returns the block -- it would accept
    a compromised appliance's forged envelope while looking perfectly healthy,
    because approval-gated tasks would simply keep running. Two known-bad cases run
    on every anchor pin, in the production path, same shape as `self_test`.
    """
    try:
        verify_admin_approval({"action": "x"}, "dev-1")
    except ApprovalMissing:
        pass
    except TaskRejected:
        pass                        # any refusal is acceptable; acceptance is not
    else:
        raise VerifierBroken(
            "approval verifier ACCEPTED an envelope with no admin_approval block")

    try:
        verify_admin_approval(
            {"action": "x", APPROVAL_FIELD: {"authenticator_id": "nobody",
                                             "request_id": "aa", "target": "dev-1"},
             APPROVED_PARAMS_FIELD: ""}, "dev-1", lookup=lambda _a: None)
    except TaskRejected:
        pass
    else:
        raise VerifierBroken(
            "approval verifier ACCEPTED an approval from an UNPINNED authenticator")


def classification_self_test() -> None:
    """Prove the classifier can both ADMIT and REFUSE. Raises VerifierBroken.

    Same reasoning as `self_test` below and `nemesis-fw-neverblock`'s CANARIES: a
    classifier stubbed to return EXEMPT for everything restores the exact
    default-allow behaviour this replaced, and nothing about that looks wrong from
    the outside — tasks keep running, which is what they did before. One
    known-admit and one known-refuse case, run in the production path on every
    anchor pin, is what catches it.

    The refuse-case name is deliberately one that can never become legitimate.
    """
    if disposition("ping") != DISP_EXEMPT:
        raise VerifierBroken(
            "action classifier refused a known-exempt action ('ping') — it would "
            "refuse every task")
    canary = "__nemesis_unclassified_canary__"
    if disposition(canary) != DISP_UNCLASSIFIED:
        raise VerifierBroken(
            "action classifier admitted %r — it is admitting unknown actions, "
            "which is the default-allow behaviour it exists to replace" % canary)
    try:
        assert_dispatchable(canary)
    except UnclassifiedAction:
        pass
    else:
        raise VerifierBroken(
            "assert_dispatchable did not raise for an unclassified action")

    # Third canary, for the loopback-only tier. Uses a REAL member rather than a
    # synthetic name, deliberately: the risk being guarded against is the set
    # being emptied, reordered after the exempt check, or otherwise stopping
    # refusing — none of which a synthetic never-legitimate name would detect if
    # the set itself went unconsulted. If `report_error` is ever legitimately
    # reclassified, this line must be changed deliberately, which is the point.
    lb = "report_error"
    if disposition(lb) != DISP_LOOPBACK_ONLY:
        raise VerifierBroken(
            "action classifier no longer treats %r as loopback-only — a recorded "
            "decision that a signed server task may not invoke it has stopped "
            "being enforced" % lb)
    try:
        assert_dispatchable(lb)
    except LoopbackOnlyAction:
        pass
    else:
        raise VerifierBroken(
            "assert_dispatchable did not raise for a loopback-only action")


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

    # The action classifier is part of the same trusted path and gets the same
    # treatment: proven able to both admit and refuse before any real task is
    # dispatched, not merely assumed to work because tasks kept running.
    classification_self_test()
    approval_self_test()

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
