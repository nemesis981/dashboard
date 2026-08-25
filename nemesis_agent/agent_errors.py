"""Agent-side structured error reporting — the endpoint counterpart of the
server's `alert_manager/nemesis_errors.py`.

WHY THIS EXISTS. The agent logs its degradations (enforcement falling open, a
sensor read failing, a heartbeat going unsigned) to its own local log and
nowhere else — invisible across a fleet. An operator cannot see that endpoint X
has had its L2 blocking silently off for two hours, or that Y's self-attestation
can't run. This module gives each genuine degradation a structured code so it
can be COUNTED locally and later (stage b) ride the heartbeat as a compact
digest for centralized diagnosis. Survey + scope:
`~/work/nemesis-internal/audits/agent-error-code-survey-and-reporting-scope-2026-08-20.md`.

DISCIPLINES, inherited verbatim from the server ledger — none optional:
* **FAILURE-ONLY.** Only genuine faults call `record()`. Expected-empty/normal
  cases (a disabled feature, a platform that doesn't supply a metric, an absent
  optional file) do NOT — recording those would drown the real signal, which is
  the whole reason this is hand-curated per site rather than a blanket sweep.
* **BEST-EFFORT — recording must NEVER raise.** A broken recorder must not become
  a second failure that takes down the poll loop it rides in. Every path here is
  wrapped; the worst case is a silently-dropped record, never an exception.
* **BOUNDED BY CONSTRUCTION.** State is aggregated per code (count + first/last +
  last context), so memory is bounded by the size of the catalog (~dozens of
  codes), not by how often a site fires. A stuck error cannot grow it.

TRANSPORT (stage b, wired): the poll loop `drain()`s this into the heartbeat's
`agent_errors` field each beat and `restore()`s it if the POST fails, so a report
rides the next authenticated beat. The server ignores the unknown key until it
stores it (stage c) — "report now, display follows", same as `memory_ladder`.

CODE FORMAT: `E-AGENT-NNN`. One flat namespace — the agent is one "module" from
the server's point of view. Grouped by category in `E_AGENT_CODES` with reserved
ranges so a category can grow without renumbering.
"""
import re
import threading
from datetime import datetime, timezone

__all__ = [
    "E_AGENT_CODES", "record", "drain", "restore", "snapshot", "reset",
    "CODE_RE", "self_test",
]

#: A well-formed agent error code. Validated on record so a typo cannot silently
#: create a junk code; the server ingest (stage c) will validate the same shape.
CODE_RE = re.compile(r"^E-AGENT-\d{3}$")

#: code -> (short label, description, severity). Severity scale matches the
#: server ledger's ("low"/"medium"/"high"). Ranges are reserved per category.
E_AGENT_CODES = {
    # ── 001–019  Enforcement fail-open (protection silently degraded) ──
    "E-AGENT-001": ("L2 engine unavailable",
                    "pydivert/WinDivert could not be imported; L2 reputation "
                    "blocking is OFF and traffic passes unfiltered.", "high"),
    "E-AGENT-002": ("L2 handle open failed",
                    "The WinDivert handle failed to open; L2 blocking is OFF "
                    "and traffic passes unfiltered.", "high"),
    "E-AGENT-003": ("L2 stall force-close",
                    "A packet sat in processing past the stall timeout; the "
                    "watchdog force-closed the handle (fail-open).", "medium"),
    "E-AGENT-004": ("L2 per-packet error",
                    "A per-packet error occurred; the packet was reinjected "
                    "unfiltered (fail-open).", "low"),
    "E-AGENT-005": ("DNS enforce invocation failed",
                    "The platform call to set DNS failed; DNS enforcement was "
                    "not applied.", "medium"),
    "E-AGENT-006": ("DNS enforce set failed",
                    "Setting the DNS target failed; the original DNS was "
                    "restored (fail-open).", "medium"),
    "E-AGENT-007": ("DNS enforce no adapter",
                    "No active adapter was found to apply DNS enforcement to; "
                    "enforcement was skipped (fail-open).", "low"),
    "E-AGENT-008": ("DNS restore failed",
                    "Restoring the original DNS failed; the state file was kept "
                    "for a later attempt.", "medium"),

    # ── 020–029  Self-attestation degraded ──
    "E-AGENT-020": ("Attest manifest unreadable",
                    "The self-attestation manifest could not be read; integrity "
                    "is treated as ABSENT (cannot self-check).", "medium"),
    "E-AGENT-021": ("Attest manifest malformed",
                    "The self-attestation manifest was malformed; integrity is "
                    "treated as ABSENT.", "medium"),

    # ── 030–039  Signing / key / auth ──
    "E-AGENT-030": ("Heartbeat unsigned",
                    "Signing the heartbeat failed; it was sent UNSIGNED and an "
                    "enforce-mode server will reject it (agent unauthenticated).",
                    "high"),
    "E-AGENT-031": ("Key unlock failed",
                    "The device signing key could not be unlocked (wrong secret "
                    "or no way to prompt); the agent cannot sign.", "high"),

    # ── 040–049  Platform metric collection (degraded telemetry) ──
    "E-AGENT-040": ("CPU metric read failed",
                    "psutil cpu_percent failed; CPU telemetry is missing from "
                    "this heartbeat.", "low"),
    "E-AGENT-041": ("Memory metric read failed",
                    "psutil virtual_memory failed; memory telemetry is missing "
                    "from this heartbeat.", "low"),
    "E-AGENT-042": ("Sensor read failed",
                    "The in-process hardware sensor read failed; temperature/fan "
                    "telemetry is missing.", "low"),
    "E-AGENT-043": ("Hardware metrics failed",
                    "The platform hardware-metrics collection failed as a whole; "
                    "the server gets no hardware data this beat.", "medium"),

    # ── 050–059  Server communication ──
    "E-AGENT-050": ("Enrollment request failed",
                    "The enrollment request to the server failed; the device is "
                    "not enrolled and will not report.", "medium"),
    "E-AGENT-051": ("Enrollment status check failed",
                    "Polling the server for approval status failed; approval "
                    "state is unknown.", "low"),

    # ── 060–069  Server-dispatched task execution ──
    "E-AGENT-061": ("Task execution failed",
                    "A server-dispatched task failed to execute; the dispatcher "
                    "would otherwise not distinguish this from success.",
                    "medium"),
    "E-AGENT-062": ("Task result write failed",
                    "Persisting a task result failed; the result may not reach "
                    "the server on the next beat.", "low"),

    # ── 070–079  Roaming traffic steering (failsafe) ──
    "E-AGENT-070": ("Steering teardown not proven safe",
                    "Roaming traffic steering could not be confirmed torn down by "
                    "reading live state back; the device may still be steered. "
                    "The controller keeps retrying and fails open, but this is a "
                    "security-relevant condition an operator must see.", "high"),

    # ── 080–089  Behavioral monitoring (Windows / Sysmon arm) ──
    "E-AGENT-080": ("Sysmon collector poll failed",
                    "The Windows behavioral poller could not read new events from "
                    "the Sysmon Operational log (Get-WinEvent failed or returned "
                    "unparseable output). Behavioral coverage on this endpoint is "
                    "degraded until it recovers.", "medium"),
    "E-AGENT-081": ("Behavioral monitor start failed",
                    "The behavioral monitor could not be started although "
                    "behavioral_enabled is set (Falco tail on Linux, Sysmon poll "
                    "on Windows) — no behavioral events will be reported until "
                    "this is resolved.", "medium"),

    # ── 090–099  Agent GUI ──
    "E-AGENT-090": ("Agent GUI findings render failed",
                    "The agent GUI could not render the local findings view, so "
                    "the user cannot see their own device's findings even though "
                    "the agent may be reporting them. Reported by the GUI over the "
                    "loopback control channel.", "low"),
    "E-AGENT-091": ("Agent findings query failed",
                    "The agent could not build the local recent-findings response "
                    "for the GUI (findings buffer read failed).", "low"),

    # ── Memory-injection detection (100 block) ──
    "E-AGENT-100": ("Memory-scan capability absent",
                    "memscan is ENABLED for this device but the agent cannot read "
                    "another process's memory (capability unavailable or "
                    "undetermined). On Linux, grant CAP_SYS_PTRACE via "
                    "deploy_memscan_linux.sh; until then the memory-injection "
                    "detector cannot acquire target memory. Fail-closed, not "
                    "silently degraded.", "medium"),

    # ── Privileged IPC channel (Windows split, step 3b) ──
    "E-AGENT-110": ("Priv-channel client auth refused",
                    "The SYSTEM privileged service refused a pipe client whose SID "
                    "did not match the enrolled agent user. Expected traffic if a "
                    "local process probes the pipe; a burst may indicate a local "
                    "process attempting to drive SYSTEM-level actions.", "medium"),
    "E-AGENT-111": ("Priv-channel server not SYSTEM",
                    "The session agent connected to the privileged pipe but the "
                    "server process was NOT LocalSystem — a probable pipe-squatting "
                    "attempt by a lower-privilege local process. The client refused "
                    "to send anything and treats the channel as unavailable.", "high"),
    "E-AGENT-112": ("Priv-service SCM start failed",
                    "The SYSTEM privileged service could not start under the Service "
                    "Control Manager (dispatch/registration/status reporting failed, "
                    "or the pipe could not be created). The privileged channel is "
                    "down; the session agent runs as today without it.", "medium"),

    # -- Memory acquisition over the privileged channel (Windows, step 3c) --
    "E-AGENT-113": ("Memory inspection privilege unavailable",
                    "The privileged service could not obtain the privilege needed to "
                    "read another process's memory (SeDebugPrivilege not held, or the "
                    "adjust did not execute). Acquisition is unavailable; the service "
                    "reports this rather than returning an empty result that would "
                    "read like a clean scan.", "medium"),
    "E-AGENT-114": ("Memory inspection target protected",
                    "A requested target could not be opened because the operating "
                    "system protects it (a protected-process target refuses access "
                    "even to SYSTEM). This is a platform limitation, not a failure of "
                    "the agent, and it is reported per target so the process is never "
                    "counted as scanned.", "low"),
    "E-AGENT-115": ("Memory inspection result truncated",
                    "A target's region map exceeded the configured bounds and was "
                    "truncated. The response says so explicitly; a truncated map must "
                    "not be read as a complete picture of the process.", "low"),
    "E-AGENT-116": ("Memory-injection sweep flagged a process",
                    "The observe-only memory-injection sweep classified one or more "
                    "processes as showing a reflective-image-injection shape (an "
                    "executable image header at the base of a private, non-file-backed "
                    "region). Observe-only: nothing was blocked. Investigate the named "
                    "pid(s); reflective loading is common in real intrusions and also, "
                    "rarely, in unusual-but-benign software.", "high"),
    "E-AGENT-117": ("Signed task named an unclassified action",
                    "A task arrived with a valid server signature but named an action "
                    "this agent has not classified for remote dispatch, so it was "
                    "REFUSED rather than run. Expected after a server-side action is "
                    "added without a matching agent-side classification -- the agent "
                    "is older than the task. It is also what a compromised or confused "
                    "server probing for a reachable action looks like, so a burst of "
                    "these from actions that were never deployed is worth reading as a "
                    "signal rather than a version mismatch.", "medium"),
    "E-AGENT-119": ("Signed task named a loopback-only action",
                    "A task arrived with a valid server signature but named an action "
                    "this agent handles ONLY over its local loopback listener and has "
                    "deliberately classified as not remotely invocable, so it was "
                    "REFUSED. Distinct from E-AGENT-117 on purpose: that one means no "
                    "decision has been made about an action, this one means a decision "
                    "was made and the answer was no. A server has no legitimate reason "
                    "to send one of these, so unlike E-AGENT-117 it is NOT explained by "
                    "a version skew -- read it as a server sending work it should not "
                    "know to send, and investigate rather than reclassify the action to "
                    "make it stop.", "medium"),
    "E-AGENT-118": ("Admin approval refused for a gated task",
                    "A task requiring admin approval (ADR 0026) arrived with a valid "
                    "SERVER signature but its inner admin authorization did not "
                    "verify against this device's PINNED admin keys, so it was "
                    "REFUSED. The typed reason distinguishes the cases: missing, "
                    "malformed, an authenticator this device never pinned, bound to "
                    "another device, expired, a bad signature, or already spent "
                    "here. Benign causes exist (a device enrolled before admin keys "
                    "were paired refuses everything; an approval can legitimately "
                    "expire). But 'bad_signature' or 'unknown_authenticator' on a "
                    "correctly-provisioned device is the signature of an appliance "
                    "attempting to authorize work no human approved -- which is "
                    "precisely the case this layer exists to catch. Investigate "
                    "rather than re-issue.", "high"),
}

_MAX_CONTEXT = 300               # hard cap on a context string (bounded input)
_lock = threading.Lock()
#: code -> {"count", "first", "last", "last_context"}. Bounded by len(catalog).
_counters = {}


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _severity_of(code):
    """The catalog severity for a code (low/medium/high). The agent is the source
    of truth for this — it ships in the digest so the SERVER never has to keep a
    second copy of the severity map (which would drift). Unknown code -> None."""
    spec = E_AGENT_CODES.get(code)
    return spec[2] if spec else None


def record(code, context=None):
    """Record one occurrence of `code`. BEST-EFFORT: never raises.

    Aggregates by code (count + first/last timestamp + last context), so calling
    it in a hot loop cannot grow memory. `context` is a short human string
    (capped); never put secrets in it — this is destined for the server.
    """
    try:
        if not isinstance(code, str) or not CODE_RE.match(code):
            # A malformed code is a programming error, not telemetry. Do not
            # raise (best-effort) and do not store junk; drop it. self_test
            # guards the catalog so this stays a dev-time catch.
            return
        ctx = None
        if context is not None:
            ctx = str(context)[:_MAX_CONTEXT]
        now = _now_iso()
        with _lock:
            entry = _counters.get(code)
            if entry is None:
                _counters[code] = {"count": 1, "first": now, "last": now,
                                   "last_context": ctx}
            else:
                entry["count"] += 1
                entry["last"] = now
                if ctx is not None:
                    entry["last_context"] = ctx
    except Exception:               # noqa: BLE001 — recording must never raise
        pass


def snapshot():
    """A copy of the current aggregated state, WITHOUT clearing. For local
    inspection / the system-snapshot feature. Read-only."""
    try:
        with _lock:
            return {c: dict(v) for c, v in _counters.items()}
    except Exception:               # noqa: BLE001
        return {}


def drain():
    """Return the aggregated digest AND clear it — the read-and-clear the
    stage-(b) heartbeat field will call each beat, so a report is sent once and
    the payload stays bounded to what accrued since the last beat.

    Returns a list of {code, severity, count, first, last, context}. `severity`
    (low/medium/high) is looked up from the catalog and sent so the server gates
    on it without keeping its own severity map. Empty list when nothing accrued.
    """
    try:
        with _lock:
            out = [{"code": c, "severity": _severity_of(c), "count": v["count"],
                    "first": v["first"], "last": v["last"],
                    "context": v.get("last_context")}
                   for c, v in _counters.items()]
            _counters.clear()
        return out
    except Exception:               # noqa: BLE001
        return []


def restore(digest):
    """Merge a previously-`drain()`ed digest BACK into the counters — best-effort,
    never raises.

    The transport safety valve: the poll loop `drain()`s into the heartbeat at
    collect time, then calls this if the POST fails, so a report is retried on
    the next beat instead of being lost. Losing it on failure would
    systematically drop the MOST valuable reports — unsigned-heartbeat /
    enrollment / status errors happen exactly when the POST is failing. Counts
    add; the earliest `first` and latest `last` win; a code that re-fired since
    the drain is merged, not overwritten.
    """
    try:
        for e in (digest or []):
            code = e.get("code")
            if not isinstance(code, str) or not CODE_RE.match(code):
                continue
            cnt = int(e.get("count") or 0)
            if cnt <= 0:
                continue
            with _lock:
                cur = _counters.get(code)
                if cur is None:
                    _counters[code] = {
                        "count": cnt,
                        "first": e.get("first"), "last": e.get("last"),
                        "last_context": e.get("context")}
                else:
                    cur["count"] += cnt
                    # earliest first, latest last (ISO strings sort chronologically
                    # here because all agent stamps are aware-UTC).
                    if e.get("first") and (cur.get("first") is None or e["first"] < cur["first"]):
                        cur["first"] = e["first"]
                    if e.get("last") and (cur.get("last") is None or e["last"] > cur["last"]):
                        cur["last"] = e["last"]
    except Exception:                   # noqa: BLE001 — restore must never raise
        pass


def reset():
    """Clear all state (tests / a clean restart)."""
    try:
        with _lock:
            _counters.clear()
    except Exception:               # noqa: BLE001
        pass


def self_test():
    """Prove the recorder works and the catalog is well-formed, on every call
    that wants to trust it — same premise-proving discipline as the memory
    modules. Uses its own isolated state so it never disturbs live counters.
    """
    # 1. every catalog code is well-formed and fully specified.
    for code, spec in E_AGENT_CODES.items():
        if not CODE_RE.match(code):
            raise AssertionError("catalog code malformed: %r" % code)
        if not (isinstance(spec, tuple) and len(spec) == 3):
            raise AssertionError("catalog entry not (short,desc,severity): %r" % code)
        if spec[2] not in ("low", "medium", "high"):
            raise AssertionError("bad severity for %s: %r" % (code, spec[2]))

    # 2. record/drain round-trips, and record refuses a malformed code, on
    #    isolated state (snapshot + restore live counters).
    global _counters
    with _lock:
        saved = _counters
        _counters = {}
    try:
        record("E-AGENT-001", "self-test")
        record("E-AGENT-001", "again")
        record("E-AGENT-NOPE", "junk")     # malformed -> must be dropped
        snap = snapshot()
        if snap.get("E-AGENT-001", {}).get("count") != 2:
            raise AssertionError("self-test: count did not aggregate to 2")
        if "E-AGENT-NOPE" in snap:
            raise AssertionError("self-test: a malformed code was stored")
        drained = drain()
        if not (len(drained) == 1 and drained[0]["code"] == "E-AGENT-001"):
            raise AssertionError("self-test: drain shape wrong")
        if snapshot():
            raise AssertionError("self-test: drain did not clear")
    finally:
        with _lock:
            _counters = saved
    return True
