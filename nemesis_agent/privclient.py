"""privclient — the session-side driver for the privileged channel (step 3b).

The session agent uses this to reach the SYSTEM service over the ACL'd named pipe.
Before sending ANYTHING it verifies the server is actually LocalSystem — the
anti-squatting half of the mutual auth, and the reason FILE_FLAG_FIRST_PIPE_INSTANCE
on the server is not sufficient on its own: if the real service is not running, a
lower-privilege local process could create the pipe first and impersonate it. The
client refuses to talk to a non-SYSTEM server.

SKIP-IF-ABSENT: if the service is not deployed (the pipe does not exist), every
call raises PrivChannelUnavailable and the session agent behaves exactly as it does
today. The privileged channel is an ADDITION; its absence is normal, not an error.

PURE (tested here): verify_server. WINDOWS SHELL (VM-verified): the connect + I/O.
"""

from __future__ import annotations

import logging
import sys

import agent_errors
import privchannel as pc

log = logging.getLogger("nemesis.privclient")


# ── pure: verify the server before trusting it ───────────────────────────────

def verify_server(server_sid):
    """Raise PrivChannelAuthError unless `server_sid` is LocalSystem.

    A None server_sid (its identity could not be read) is treated as a FAILED
    verification, never trusted — the same fail-closed rule as the server's client
    check. Records E-AGENT-111 on a non-SYSTEM server, which is a probable squatting
    attempt worth surfacing, distinct from the channel simply being absent.
    """
    if pc.is_system_sid(server_sid):
        return
    agent_errors.record("E-AGENT-111", "priv-channel server sid=%r (not SYSTEM)"
                        % (server_sid,))
    raise pc.PrivChannelAuthError(
        "privileged-pipe server is not LocalSystem (sid=%r) — refusing to send; "
        "possible pipe squatting" % (server_sid,))


# ── Windows-only: connect, authenticate the server, exchange one message ─────

#: kernel32 entry points that return a HANDLE. Each MUST get an explicit restype
#: — see privservice._bind_win32 for the full rationale. Asserted by the tests.
HANDLE_RETURNING = ("CreateFileW",)


def _bind_win32(k32):
    """Declare argtypes/restypes for every Win32 call the client makes.

    This side already typed CreateFileW correctly while privservice/winsvc typed
    nothing — that asymmetry is what let the 2026-08-22 truncation defect ship on
    the server half only. Binding here too keeps both ends held to one rule that a
    test can check, rather than to whichever call someone remembered.

    NOTE the client pipe is opened WITHOUT FILE_FLAG_OVERLAPPED, so passing NULL
    for lpOverlapped on ReadFile/WriteFile is CORRECT here — unlike the server,
    whose handle is overlapped and therefore requires a real OVERLAPPED.
    """
    import ctypes
    from ctypes import wintypes
    H, D, B = wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL
    P, LPCWSTR = ctypes.c_void_p, wintypes.LPCWSTR
    k32.CreateFileW.restype, k32.CreateFileW.argtypes = H, [LPCWSTR, D, D, P, D, D, H]
    k32.WaitNamedPipeW.restype, k32.WaitNamedPipeW.argtypes = B, [LPCWSTR, D]
    k32.SetNamedPipeHandleState.restype = B
    k32.SetNamedPipeHandleState.argtypes = [H, P, P, P]
    k32.GetNamedPipeServerProcessId.restype = B
    k32.GetNamedPipeServerProcessId.argtypes = [H, P]
    k32.ReadFile.restype, k32.ReadFile.argtypes = B, [H, P, D, P, P]
    k32.WriteFile.restype, k32.WriteFile.argtypes = B, [H, P, D, P, P]
    k32.CloseHandle.restype, k32.CloseHandle.argtypes = B, [H]
    return k32


#: Tests inject a fake kernel32 here to drive the connect/verify/exchange path off
#: Windows — in particular to prove the server is authenticated BEFORE anything is
#: written, which no static check can establish.
_WIN32_FOR_TEST = None


def _win32():
    """The bound kernel32 — real, or a test-injected fake."""
    if _WIN32_FOR_TEST is not None:
        return _bind_win32(_WIN32_FOR_TEST)
    import ctypes
    return _bind_win32(ctypes.WinDLL("kernel32", use_last_error=True))


def _call(request: dict, timeout_ms: int = 4000) -> dict:
    """Open the pipe, verify the server is SYSTEM, send `request`, return the
    response dict. Raises PrivChannelUnavailable if the service is not reachable,
    PrivChannelAuthError if the server is not SYSTEM. Windows-only."""
    if sys.platform != "win32" and _WIN32_FOR_TEST is None:
        raise pc.PrivChannelUnsupported("_call is Windows-only")

    import ctypes
    from ctypes import wintypes

    k32 = _win32()

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    #: BYTE mode, to match the server -- see privservice._serve for why (the framing
    #: is length-prefixed and read incrementally, which message mode breaks).
    PIPE_READMODE_BYTE = 0x00000000
    ERROR_MORE_DATA = 234
    INVALID_HANDLE = wintypes.HANDLE(-1).value
    ERROR_PIPE_BUSY = 231
    ERROR_FILE_NOT_FOUND = 2

    # WaitNamedPipe if busy, then CreateFile.
    if not k32.WaitNamedPipeW(ctypes.c_wchar_p(pc.PIPE_NAME), timeout_ms):
        err = ctypes.get_last_error()
        if err == ERROR_FILE_NOT_FOUND:
            raise pc.PrivChannelUnavailable("privileged pipe does not exist "
                                            "(service not deployed)")
        # busy/timeout — try to open anyway; CreateFile reports the real outcome.

    hpipe = k32.CreateFileW(ctypes.c_wchar_p(pc.PIPE_NAME),
                            GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING,
                            0, None)
    if hpipe == INVALID_HANDLE or not hpipe:
        err = ctypes.get_last_error()
        if err in (ERROR_FILE_NOT_FOUND,):
            raise pc.PrivChannelUnavailable("privileged pipe does not exist")
        raise pc.PrivChannelUnavailable("could not open privileged pipe: %d" % err)

    try:
        # message read mode
        mode = wintypes.DWORD(PIPE_READMODE_BYTE)
        k32.SetNamedPipeHandleState(hpipe, ctypes.byref(mode), None, None)

        # AUTH: the server must be LocalSystem, checked BEFORE we send anything.
        #
        # Read the PIPE OBJECT's owner, NOT the server process's token. The old
        # route (GetNamedPipeServerProcessId -> pc.sid_of_pid) required opening the
        # LocalSystem service process, which a NON-ELEVATED caller cannot do:
        # OpenProcess returns ACCESS_DENIED(5) even for
        # PROCESS_QUERY_LIMITED_INFORMATION. server_sid was therefore always None,
        # verify_server fail-closed, and the channel was unusable by the session
        # agent -- i.e. in production. Measured on the rig 2026-08-29; an earlier
        # ELEVATED run had masked it for a week.
        #
        # build_pipe_sddl stamps the pipe O:SY, so the owner is present by
        # construction on a handle we already hold, readable unprivileged -- and it
        # authenticates the kernel object itself rather than a process holding it.
        server_sid = pc.owner_sid_of_handle(hpipe)
        verify_server(server_sid)                    # raises if not SYSTEM

        out = pc.pack_frame(request)
        written = wintypes.DWORD(0)
        if not k32.WriteFile(hpipe, out, len(out), ctypes.byref(written), None):
            raise pc.PrivChannelUnavailable("write to privileged pipe failed: %d"
                                            % ctypes.get_last_error())

        def _recv_exact(n):
            buf = b""
            while len(buf) < n:
                chunk = (ctypes.c_char * (n - len(buf)))()
                read = wintypes.DWORD(0)
                ok = k32.ReadFile(hpipe, chunk, n - len(buf),
                                  ctypes.byref(read), None)
                # ERROR_MORE_DATA means "your bytes are here, the message has more":
                # a partial read, NOT a failure. Same defence-in-depth note as the
                # server's _ov_finish.
                if not ok and ctypes.get_last_error() != ERROR_MORE_DATA:
                    break
                if read.value == 0:
                    break
                buf += bytes(chunk[:read.value])
            return buf

        return pc.read_frame(_recv_exact)
    finally:
        k32.CloseHandle(hpipe)


def ping(timeout_ms: int = 4000) -> dict:
    """Round-trip a `ping` to the SYSTEM service. Returns the response dict (with
    pong=True on success). Raises PrivChannelUnavailable / PrivChannelAuthError."""
    return _call({"action": "ping", "proto": pc.PROTO_VERSION}, timeout_ms)


def inspect_pid(pid: int, max_regions: int = None, timeout_ms: int = 8000) -> dict:
    """Ask the SYSTEM service for a bounded region map of `pid` (step 3c).

    Returns the service's response dict. Read `state` and `scanned` before anything
    else: a `protected` target is a MEASURED refusal with a known cause and carries
    `scanned: False`, so it must never be tallied as a clean scan. Raises
    PrivChannelUnavailable / PrivChannelAuthError exactly as `ping` does.
    """
    req = {"action": "inspect_pid", "pid": int(pid)}
    if max_regions is not None:
        req["max_regions"] = int(max_regions)
    return _call(req, timeout_ms)


def is_channel_healthy(timeout_ms: int = 2000) -> dict:
    """A never-raising status probe for the heartbeat: does the authenticated
    channel round-trip? Returns {"state": ok|absent|auth_failed|error, "detail":...}.
    Absence is normal (service not deployed) and is NOT an error state."""
    try:
        r = ping(timeout_ms)
        ok = bool(r.get("pong"))
        return {"state": "ok" if ok else "error",
                "detail": "pong" if ok else "no pong in response"}
    except pc.PrivChannelUnavailable as e:
        return {"state": "absent", "detail": str(e)}
    except pc.PrivChannelAuthError as e:
        return {"state": "auth_failed", "detail": str(e)}
    except Exception as e:                                    # noqa: BLE001
        return {"state": "error", "detail": str(e)}
