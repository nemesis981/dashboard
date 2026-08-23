"""privservice — the SYSTEM-privileged Nemesis service (step 3b).

Runs as a Windows service (LocalSystem) via winsvc.run_service, listens on the
ACL'd named pipe (privchannel), AUTHENTICATES every client against the enrolled
agent-user SID, and answers a minimal request set. In 3b that set is exactly one
action — `ping` — and the service does NOTHING privileged: no SeDebugPrivilege, no
memory read. The whole point of 3b is to prove the authenticated channel is sound
before any capability rides on it. 3c adds `inspect_pid` to the dispatch below, on
this same proven channel.

PURE (tested here) vs WINDOWS SHELL (VM-verified)
-------------------------------------------------
`authorize_client` (is this connecting SID the agent user?) and `dispatch` (request
-> response) are pure and unit-tested. The pipe accept loop — creating the pipe with
the SDDL, the overlapped/stoppable ConnectNamedPipe, reading the client's SID off
the connection — is the Windows-only shell, proven on the VM.
"""

from __future__ import annotations

import logging
import os
import sys

import agent_errors
import privchannel as pc

log = logging.getLogger("nemesis.privservice")

SERVICE_NAME = "nemesis-agent-priv"


# ── pure: who may talk, and what the answers are ─────────────────────────────

def authorize_client(client_sid, expected_agent_sid) -> bool:
    """True only if a connecting client is the enrolled agent user.

    A None client_sid (its token/SID could not be read) is NEVER authorized — an
    unverifiable peer is refused, not given the benefit of the doubt. This is the
    server side of the mutual auth; the ACL already restricts who can open the
    pipe, and this confirms + logs it (defence-in-depth).
    """
    if not client_sid or not expected_agent_sid:
        return False
    return pc.sids_equal(client_sid, expected_agent_sid)


#: Default and hard ceilings on what one inspect_pid response may carry. The frame
#: cap is 1 MiB (privchannel.MAX_FRAME_BYTES) and a region map is attacker-influenced
#: data, so the response is bounded twice: by region COUNT here, and by measured frame
#: SIZE before it goes out (see _bounded_response).
DEFAULT_MAX_REGIONS = 512
HARD_MAX_REGIONS = 2048

#: Ceiling on bytes read from a target while producing digests, derived from the
#: appliance model's transient reservation for this work (APPLIANCE_RESERVATIONS
#: ["memory-injection-scan"], 3% clamped to 128-384 MB). A single inspection must
#: take a small slice of that, not the whole promise.
MAX_DIGEST_BYTES = 4 << 20


def validate_inspect_pid(request):
    """PURE. Validate an inspect_pid request. Returns (params, None) or (None, error).

    The client is authenticated, which is NOT the same as trusted: it is a lower-
    privilege process asking a SYSTEM service to act on an integer it chose. Bounds
    are enforced here, on the privileged side, never assumed of the caller.
    """
    pid = request.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int):
        return None, {"ok": False, "error": "pid must be an integer"}
    if pid <= 0 or pid > 0xFFFFFFFF:
        return None, {"ok": False, "error": "pid out of range: %d" % pid}
    want = request.get("max_regions", DEFAULT_MAX_REGIONS)
    if isinstance(want, bool) or not isinstance(want, int) or want <= 0:
        want = DEFAULT_MAX_REGIONS
    return {"pid": pid, "max_regions": min(want, HARD_MAX_REGIONS)}, None


def dispatch(request: dict, inspector=None) -> dict:
    """Map a request dict to a response dict. PURE — no I/O, no privilege.

    Purity is load-bearing: it is what made 3b's logic testable while its Win32 shell
    was broken, and 3c must not spend it. Privileged work therefore arrives as an
    INJECTED `inspector` callable rather than being performed here; this function only
    validates and routes.

    Unknown actions return an explicit error rather than raising, so a
    malformed/hostile request cannot crash the accept loop.
    """
    action = request.get("action") if isinstance(request, dict) else None
    if action == "ping":
        return {"ok": True, "pong": True, "server": "SYSTEM",
                "proto": pc.PROTO_VERSION}
    if action == "inspect_pid":
        params, err = validate_inspect_pid(request)
        if err is not None:
            return err
        if inspector is None:
            # Explicit, not silent: a caller must be able to tell "no inspector on
            # this build" apart from "inspected and found nothing".
            return {"ok": False, "error": "memory inspection is not available on this "
                                          "service build", "scanned": False,
                    "state": "undetermined"}
        return inspector(params)
    return {"ok": False, "error": "unknown action: %r" % (action,)}


def _bounded_response(resp: dict) -> dict:
    """Guarantee the response fits one frame, truncating REGIONS if it would not.

    Measured, not estimated: pack the real frame and shrink until it fits. A response
    that overflows the frame is not a big answer, it is NO answer -- the client would
    fail to parse it and the whole inspection would be lost.
    """
    regions = resp.get("regions")
    if not isinstance(regions, list):
        return resp
    while True:
        try:
            if len(pc.pack_frame(resp)) <= pc.MAX_FRAME_BYTES:
                return resp
        except pc.ProtocolError:
            pass
        if not resp["regions"]:
            resp["regions"] = []
            resp["truncated"] = True
            return resp
        # Halve and retry: a linear walk over thousands of regions would be slow in
        # the privileged service for no benefit.
        resp["regions"] = resp["regions"][:max(1, len(resp["regions"]) // 2)]
        resp["region_count_returned"] = len(resp["regions"])
        resp["truncated"] = True


def make_inspector(classifier=None):
    """Build the privileged inspector used by the service. Windows-only at call time.

    Returns a callable taking the validated params dict. Kept separate from `dispatch`
    so the routing stays pure and this stays injectable in tests.

    `classifier` is the OPTIONAL private detector hook (operator decision D2: the
    RWX/private-executable heuristic is the detector's novelty and lives in the private
    module). Its ABSENCE is normal and is reported explicitly -- a response must never
    look classified when nothing classified it.

    CONTRACT: `classifier(pid, regions, reader) -> dict | None`.
      * a dict contributes VERDICT_KEYS to the response and sets classification=present
      * None / {} / a non-dict means it did NOT classify -> classification=inert
      * raising means it broke -> classification=error
    Three outcomes, three labels. `regions` may be annotated in place (that is how a
    per-region flag reaches the caller), but in-place mutation alone is NOT a verdict.
    """
    def _inspect(params):
        import winmem
        pid = params["pid"]
        resp = {"ok": True, "pid": pid, "scanned": False, "state": None,
                "regions": [], "region_count": 0, "truncated": False,
                "classification": "absent"}

        handle, state = winmem.open_target(pid)
        if handle is None:
            resp["state"] = state
            if state == winmem.PROTECTED:
                # A measured refusal with a known cause. scanned stays False so this
                # can never be tallied as a clean scan.
                log.info("priv-service: inspect_pid %d refused: protected target", pid)
                agent_errors.record("E-AGENT-114", "protected target pid=%d" % pid)
                resp["detail"] = ("target is protected by the operating system and "
                                  "cannot be opened even by the privileged service; "
                                  "it was NOT scanned")
            else:
                resp["detail"] = "target could not be opened (%s)" % state
            return resp

        try:
            regions = []
            for region in winmem.iter_regions(handle, params["max_regions"]):
                regions.append(region)
            resp["region_count"] = len(regions)
            resp["regions"] = regions
            resp["state"] = winmem.READABLE
            resp["scanned"] = True

            if classifier is not None:
                try:
                    reader = _budgeted_reader(handle)
                    verdict = classifier(pid, regions, reader)
                    merged = merge_verdict(resp, verdict)
                    if not merged:
                        # A classifier that returns nothing has not classified. Saying
                        # "present" here would let an inert hook look like a working
                        # detector -- the exact shape of instrument this codebase keeps
                        # finding broken.
                        log.warning("priv-service: classifier returned no verdict for "
                                    "pid %d - reporting inert, not present", pid)
                except Exception as exc:                     # noqa: BLE001
                    log.warning("priv-service: classifier failed for pid %d: %s",
                                pid, exc)
                    resp["classification"] = "error"
        finally:
            winmem.close(handle)

        out = _bounded_response(resp)
        if out.get("truncated"):
            agent_errors.record("E-AGENT-115",
                                "region map truncated for pid=%d (%d of %d)"
                                % (pid, len(out.get("regions", [])),
                                   out.get("region_count", 0)))
        return out

    return _inspect


#: Keys a classifier verdict may contribute to the response. Anything else is dropped
#: rather than merged: the private detector must not be able to overwrite the
#: acquisition layer's own facts (`scanned`, `state`, `regions`, `pid`), which are what
#: make a result trustworthy in the first place.
VERDICT_KEYS = ("suspicious", "findings", "score", "detector_version", "notes")


def merge_verdict(resp: dict, verdict) -> bool:
    """Merge a classifier's returned verdict into `resp`. PURE. Returns whether the
    classifier actually produced one.

    WHY THIS EXISTS (defect in 3c's first cut, found while planning step 4): the hook
    used to be called for its SIDE EFFECTS and its return value was discarded --
    `classifier(pid, regions, reader)` followed unconditionally by
    `classification = "present"`. The only way a verdict could reach the caller was if
    the classifier mutated the region dicts in place, which was implicit, undocumented,
    and indistinguishable from a hook that did nothing at all.

    Now the contract is explicit: return a dict, or you did not classify.

    The acquisition layer's own fields are NOT overwritable. A detector may say what it
    thinks; it may not restate whether the target was scanned.
    """
    if not isinstance(verdict, dict) or not verdict:
        resp["classification"] = "inert"
        return False
    for key in VERDICT_KEYS:
        if key in verdict:
            resp[key] = verdict[key]
    rejected = sorted(set(verdict) - set(VERDICT_KEYS))
    if rejected:
        resp["verdict_keys_ignored"] = rejected
    resp["classification"] = "present"
    return True


def _budgeted_reader(handle):
    """A reader the classifier may call, capped by MAX_DIGEST_BYTES in TOTAL.

    The budget belongs to the privileged side, not to the classifier: the appliance
    already promises a bounded transient reservation for this work, and a hook that
    could read without limit would turn that promise into a guess.
    """
    import winmem
    spent = {"bytes": 0}

    def read(base, size):
        remaining = MAX_DIGEST_BYTES - spent["bytes"]
        if remaining <= 0:
            return None                    # budget exhausted: explicit None, no data
        data = winmem.read_bytes(handle, base, size, cap=min(size, remaining))
        if data:
            spent["bytes"] += len(data)
        return data

    read.budget_remaining = lambda: MAX_DIGEST_BYTES - spent["bytes"]
    return read


def load_classifier():
    """Import the PRIVATE classification hook if this build has it, else None.

    Skip-if-absent, the same posture as Tier 2 attestation: the public acquisition
    layer is complete on its own, and a build without the private detector reports
    `classification: absent` rather than pretending.
    """
    try:
        import meminject_classify                            # noqa: PLC0415
        return meminject_classify.classify
    except Exception:                                        # noqa: BLE001
        return None


# ── Windows-only: the pipe accept loop + service entry ───────────────────────

#: Win32 entry points that return a HANDLE. Every one MUST get an explicit
#: restype — see _bind_win32. The test suite asserts this list is fully covered,
#: so adding a call here without typing it fails a test rather than shipping.
HANDLE_RETURNING = ("CreateNamedPipeW", "CreateEventW", "LocalFree")


def _bind_win32(k32, a32):
    """Declare argtypes/restypes for every Win32 call the pipe server makes.

    WHY THIS IS CENTRALISED — a shipped defect, caught 2026-08-22
    ------------------------------------------------------------
    ctypes defaults an unset `restype` to `c_int`: 32 bits, SIGNED. A 64-bit
    Windows HANDLE returned through that default is truncated and sign-extended,
    so it names nothing. Worse, INVALID_HANDLE_VALUE (-1 as a pointer, i.e.
    0xFFFFFFFFFFFFFFFF) then compares UNEQUAL to the -1 that actually comes back,
    so a FAILED CreateNamedPipe reads as SUCCESS and the E-AGENT-112 error path
    never runs. This file shipped with restype set on none of its calls while its
    sibling privchannel.py set them correctly — the asymmetry was the whole bug.

    Binding every call in ONE place, with a test that asserts each handle-returning
    entry got a real restype, is what stops this recurring one forgotten call at a
    time (3c adds more calls to this same shell).
    """
    import ctypes
    from ctypes import wintypes
    H, D, B = wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL
    LPCWSTR, P = wintypes.LPCWSTR, ctypes.c_void_p

    k32.CreateNamedPipeW.restype, k32.CreateNamedPipeW.argtypes = H, [LPCWSTR, D, D, D, D, D, D, P]
    k32.CreateEventW.restype, k32.CreateEventW.argtypes = H, [P, B, B, LPCWSTR]
    k32.LocalFree.restype, k32.LocalFree.argtypes = H, [H]
    k32.ConnectNamedPipe.restype, k32.ConnectNamedPipe.argtypes = B, [H, P]
    k32.DisconnectNamedPipe.restype, k32.DisconnectNamedPipe.argtypes = B, [H]
    k32.CloseHandle.restype, k32.CloseHandle.argtypes = B, [H]
    k32.SetEvent.restype, k32.SetEvent.argtypes = B, [H]
    k32.ResetEvent.restype, k32.ResetEvent.argtypes = B, [H]
    k32.FlushFileBuffers.restype, k32.FlushFileBuffers.argtypes = B, [H]
    k32.ReadFile.restype, k32.ReadFile.argtypes = B, [H, P, D, P, P]
    k32.WriteFile.restype, k32.WriteFile.argtypes = B, [H, P, D, P, P]
    k32.GetOverlappedResult.restype, k32.GetOverlappedResult.argtypes = B, [H, P, P, B]
    k32.GetNamedPipeClientProcessId.restype, k32.GetNamedPipeClientProcessId.argtypes = B, [H, P]
    k32.WaitForMultipleObjects.restype, k32.WaitForMultipleObjects.argtypes = D, [D, P, B, D]
    a32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = B
    a32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [LPCWSTR, D, P, P]
    return k32, a32


#: Tests inject (fake_kernel32, fake_advapi32) here to drive the accept loop off
#: Windows. Production leaves it None and the real DLLs are loaded. This exists
#: because the 2026-08-22 defects lived in exactly this function and it had ZERO
#: coverage — the pure helpers around it were tested, the shell was not.
_WIN32_FOR_TEST = None


def _win32():
    """The bound (kernel32, advapi32) pair — real, or a test-injected fake."""
    if _WIN32_FOR_TEST is not None:
        return _bind_win32(*_WIN32_FOR_TEST)
    import ctypes
    return _bind_win32(ctypes.WinDLL("kernel32", use_last_error=True),
                       ctypes.WinDLL("advapi32", use_last_error=True))


def _serve(stop_event, expected_agent_sid):
    """The service work function: accept authenticated clients until stop_event.

    Windows-only shell (VM-verified). Creates the pipe with the locked-down SDDL
    and PIPE_REJECT_REMOTE_CLIENTS + FIRST_PIPE_INSTANCE, then loops: wait for a
    client (overlapped, so a service STOP is responsive via stop_event), read the
    client's SID from the connection, authorize it, read one framed request,
    dispatch, write one framed response, disconnect, repeat. Never lets one
    client's error take down the loop.

    ⚠ ALL I/O on this handle is OVERLAPPED. The pipe is created with
    FILE_FLAG_OVERLAPPED so the accept can be interrupted by a service stop; Win32
    then REQUIRES a valid, unique OVERLAPPED on every ReadFile/WriteFile against
    that handle. Passing NULL there (as the first cut did) is undefined behaviour —
    it can report a completed read that never happened. Hence _ov_read/_ov_write.
    """
    if sys.platform != "win32" and _WIN32_FOR_TEST is None:
        raise pc.PrivChannelUnsupported("_serve is Windows-only")

    import ctypes
    from ctypes import wintypes

    k32, a32 = _win32()

    PIPE_ACCESS_DUPLEX = 0x00000003
    FILE_FLAG_OVERLAPPED = 0x40000000
    FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
    #: BYTE mode, deliberately. privchannel frames every message with an explicit
    #: 4-byte length prefix precisely so the transport can be a plain stream, and
    #: _recv_exact reads incrementally (header first, then the body). MESSAGE mode
    #: contradicts that: a read SMALLER than the pending message returns FALSE with
    #: ERROR_MORE_DATA rather than a partial stream read. VM-measured 2026-08-22:
    #:     ReadFile(4) -> ok=False got=4 err=234 (ERROR_MORE_DATA)
    #: The 4 header bytes were delivered and then DISCARDED by the error path, so
    #: every request died as 'truncated length prefix' and the service answered
    #: nothing while looking perfectly healthy to the SCM. Byte mode makes the
    #: transport agree with the framing.
    PIPE_TYPE_BYTE = 0x00000000
    PIPE_READMODE_BYTE = 0x00000000
    PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
    ERROR_MORE_DATA = 234
    PIPE_UNLIMITED_INSTANCES = 255
    ERROR_IO_PENDING = 997
    ERROR_PIPE_CONNECTED = 535
    WAIT_OBJECT_0 = 0
    INFINITE = 0xFFFFFFFF
    SDDL_REVISION_1 = 1
    #: -1 as a POINTER. Compare against this, never against a plain -1: with a
    #: correct HANDLE restype the failure value arrives as 0xFFFF...FFFF.
    INVALID_HANDLE = ctypes.c_void_p(-1).value

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD),
                    ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]

    class OVERLAPPED(ctypes.Structure):
        _fields_ = [("Internal", ctypes.c_void_p),
                    ("InternalHigh", ctypes.c_void_p),
                    ("Offset", wintypes.DWORD),
                    ("OffsetHigh", wintypes.DWORD),
                    ("hEvent", wintypes.HANDLE)]

    # Build the security descriptor from our SDDL (raises if the SID is bad).
    sddl = pc.build_pipe_sddl(expected_agent_sid)
    psd = ctypes.c_void_p()
    if not a32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            ctypes.c_wchar_p(sddl), SDDL_REVISION_1, ctypes.byref(psd), None):
        raise pc.PrivChannelError("failed to build security descriptor: %d"
                                  % ctypes.get_last_error())
    sa = SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
    sa.lpSecurityDescriptor = psd
    sa.bInheritHandle = False

    connect_evt = k32.CreateEventW(None, True, False, None)   # manual-reset
    io_evt = k32.CreateEventW(None, True, False, None)
    stop_evt = k32.CreateEventW(None, True, False, None)
    if not connect_evt or not io_evt or not stop_evt:
        k32.LocalFree(psd)
        agent_errors.record("E-AGENT-112", "CreateEvent failed: %d"
                            % ctypes.get_last_error())
        return

    # A background thread flips stop_evt (a Win32 event) when the python stop_event
    # is set, so WaitForMultipleObjects wakes.
    import threading
    def _bridge():
        stop_event.wait()
        k32.SetEvent(stop_evt)
    threading.Thread(target=_bridge, daemon=True).start()

    def _ov_finish(hpipe, ov, counter):
        """Common tail for an overlapped op: pending -> wait for real completion.
        Returns True only if the operation genuinely completed.

        ERROR_MORE_DATA is treated as SUCCESS: the bytes requested were delivered,
        there is simply more of the message left. Byte mode should never produce it,
        but returning False here is what silently ate the length prefix when the pipe
        was message-mode, so this stays as defence in depth -- if anyone reintroduces
        message mode, the channel degrades to correct behaviour instead of answering
        nothing while reporting healthy."""
        err = ctypes.get_last_error()
        if err == ERROR_MORE_DATA:
            return True
        if err != ERROR_IO_PENDING:
            return False
        return bool(k32.GetOverlappedResult(hpipe, ctypes.byref(ov),
                                            ctypes.byref(counter), True))

    def _ov_read(hpipe, n):
        """Read up to n bytes with a real OVERLAPPED (required on this handle)."""
        ov = OVERLAPPED()
        k32.ResetEvent(io_evt)
        ov.hEvent = io_evt
        buf = (ctypes.c_char * n)()
        got = wintypes.DWORD(0)
        ok = k32.ReadFile(hpipe, buf, n, ctypes.byref(got), ctypes.byref(ov))
        if not ok and not _ov_finish(hpipe, ov, got):
            return b""
        return bytes(buf[:got.value])

    def _ov_write(hpipe, data):
        ov = OVERLAPPED()
        k32.ResetEvent(io_evt)
        ov.hEvent = io_evt
        wrote = wintypes.DWORD(0)
        ok = k32.WriteFile(hpipe, data, len(data), ctypes.byref(wrote),
                           ctypes.byref(ov))
        if not ok and not _ov_finish(hpipe, ov, wrote):
            return 0
        return wrote.value

    def _recv_exact(hpipe, n):
        buf = b""
        while len(buf) < n:
            chunk = _ov_read(hpipe, n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    # Built once: the privilege adjust and the classifier import should not repeat
    # per connection. A privilege that cannot be obtained is reported ONCE here, not
    # silently per request.
    inspector = None
    try:
        import winmem
        priv = winmem.ensure_debug_privilege()
        if not priv.get("enabled"):
            log.warning("priv-service: SeDebugPrivilege not enabled (%s) - memory "
                        "inspection may be unavailable", priv)
            agent_errors.record("E-AGENT-113", "SeDebugPrivilege %s"
                                % ("not held" if priv.get("not_held") else priv.get("error")))
        else:
            log.info("priv-service: SeDebugPrivilege enabled")
        classifier = load_classifier()
        log.info("priv-service: classifier %s",
                 "present" if classifier else "absent (public build)")
        inspector = make_inspector(classifier)
    except Exception as exc:                                 # noqa: BLE001
        log.warning("priv-service: memory inspection unavailable: %s", exc)

    first = True
    try:
        while not stop_event.is_set():
            flags = (PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED
                     | (FILE_FLAG_FIRST_PIPE_INSTANCE if first else 0))
            hpipe = k32.CreateNamedPipeW(
                ctypes.c_wchar_p(pc.PIPE_NAME), flags,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, ctypes.byref(sa))
            first = False
            # NOTE both arms matter: a correct HANDLE restype yields None for 0 and
            # 0xFFFF...FFFF for INVALID_HANDLE_VALUE. The old `== HANDLE(-1).value`
            # against an untyped (truncated) return could never be true.
            if not hpipe or hpipe == INVALID_HANDLE:
                err = ctypes.get_last_error()
                log.error("priv-service: CreateNamedPipe failed: %d "
                          "(the channel is DOWN, service is exiting)", err)
                agent_errors.record("E-AGENT-112",
                                    "CreateNamedPipe failed: %d" % err)
                return

            ov = OVERLAPPED()
            k32.ResetEvent(connect_evt)
            ov.hEvent = connect_evt
            connected = k32.ConnectNamedPipe(hpipe, ctypes.byref(ov))
            err = ctypes.get_last_error()
            if not connected and err not in (ERROR_IO_PENDING, ERROR_PIPE_CONNECTED):
                k32.CloseHandle(hpipe)
                continue
            if err == ERROR_IO_PENDING:
                handles = (wintypes.HANDLE * 2)(connect_evt, stop_evt)
                idx = k32.WaitForMultipleObjects(2, handles, False, INFINITE)
                if idx != WAIT_OBJECT_0:                 # stop_evt (or error) -> exit
                    k32.CloseHandle(hpipe)
                    break

            try:
                cli_pid = wintypes.DWORD(0)
                client_sid = None
                if k32.GetNamedPipeClientProcessId(hpipe, ctypes.byref(cli_pid)):
                    client_sid = pc.sid_of_pid(cli_pid.value)
                if not authorize_client(client_sid, expected_agent_sid):
                    # Log AND record. agent_errors aggregates in memory for the
                    # heartbeat -- but this service sends no heartbeat, so the
                    # counter is lost on restart and the refusal would be invisible
                    # to anyone inspecting the box. An unauthorized process reaching
                    # the SYSTEM pipe is exactly the event an operator must be able
                    # to see after the fact, so it goes to the service log too.
                    log.warning("priv-service: REFUSED client pid=%s sid=%r "
                                "(enrolled sid=%r)",
                                cli_pid.value, client_sid, expected_agent_sid)
                    agent_errors.record("E-AGENT-110",
                                        "refused pipe client sid=%r" % (client_sid,))
                    continue
                log.info("priv-service: authorized client pid=%s sid=%r",
                         cli_pid.value, client_sid)
                req = pc.read_frame(lambda n: _recv_exact(hpipe, n))
                resp = dispatch(req, inspector=inspector)
                out = pc.pack_frame(resp)
                if _ov_write(hpipe, out) == len(out):
                    k32.FlushFileBuffers(hpipe)
            except pc.ProtocolError as exc:
                log.warning("priv-service: bad frame from client: %s", exc)
            except Exception as exc:                     # noqa: BLE001
                log.warning("priv-service: client handling error: %s", exc)
            finally:
                k32.DisconnectNamedPipe(hpipe)
                k32.CloseHandle(hpipe)
    finally:
        # The security descriptor is a LocalAlloc'd block; the events are handles.
        for h in (connect_evt, io_evt, stop_evt):
            if h:
                k32.CloseHandle(h)
        k32.LocalFree(psd)


def _setup_logging():
    """Send the service's log to a FILE next to this script.

    WHY (learned the hard way 2026-08-22): a LocalSystem service has no console, so
    `logging.basicConfig()` wrote to a stderr nobody could ever read. When the pipe
    transport was broken, the server logged the real cause -- "bad frame from client:
    truncated length prefix" -- into the void, while the SCM reported RUNNING and the
    client saw only a generic protocol error. The service looked healthy from every
    angle available to an operator. Diagnosis took a from-scratch reproduction that
    the log alone would have answered instantly.

    Never fails the service: if the log file cannot be opened (permissions, read-only
    install dir), fall back to basicConfig rather than refusing to start.
    """
    logfile = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "nemesis_privservice.log")
    try:
        handler = logging.FileHandler(logfile, encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s"))
        root = logging.getLogger()
        root.setLevel(logging.INFO)
        root.addHandler(handler)
        log.info("privservice logging to %s", logfile)
    except OSError as exc:                                   # noqa: BLE001
        logging.basicConfig(level=logging.INFO)
        log.warning("could not open %s (%s); logging to stderr", logfile, exc)


def main():
    """Service entry: read the enrolled agent-user SID, then run under the SCM."""
    _setup_logging()
    import winsvc
    expected = _read_expected_agent_sid()
    if not expected:
        agent_errors.record("E-AGENT-112", "no enrolled agent-user SID configured")
        log.error("privservice: no expected agent SID — refusing to start")
        return
    winsvc.run_service(SERVICE_NAME, lambda stop: _serve(stop, expected))


def _read_expected_agent_sid():
    """The agent-user SID the deploy script recorded (HKLM value the service's own
    ACL protects). Returns None if unset — the service then refuses to start rather
    than accept any client."""
    if sys.platform != "win32":
        return None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Nemesis\PrivChannel") as k:
            val, _ = winreg.QueryValueEx(k, "AgentUserSid")
            return val or None
    except OSError:
        return None


if __name__ == "__main__":                                   # pragma: no cover
    main()
