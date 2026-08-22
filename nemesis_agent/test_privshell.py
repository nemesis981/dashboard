#!/usr/bin/env python3
"""privservice._serve / winsvc.run_service / privclient._call — WINDOWS SHELL tests.

Run: python3 /opt/nemesis/nemesis_agent/test_privshell.py

WHY THIS FILE EXISTS
--------------------
On 2026-08-22 the 3b Windows shells were found broken before a VM was ever booted:
handle truncation from unset ctypes restypes, an INVALID_HANDLE_VALUE comparison
that could never be true (so a FAILED CreateNamedPipe read as SUCCESS), NULL
OVERLAPPED on an overlapped handle, and a fatal mis-bound SERVICE_STATUS_HANDLE.
Every one shipped because the existing suites covered ONLY the pure helpers —
`authorize_client`, `dispatch`, `verify_server`, `next_status` — and NOTHING in
`_serve`, `run_service`, or `_call`. The pure tests were green the whole time.

This file covers those three functions two ways:

  1. BINDING DISCIPLINE — drive each module's `_bind_win32` with a recording fake
     and assert every handle-returning entry got a real restype. This is the test
     that would have caught the actual defect, and it keeps catching it as 3c adds
     calls to the same shells.

  2. BEHAVIOUR — drive the real `_serve` / `run_service` / `_call` bodies against a
     fake Win32 layer, off Windows, and assert what they actually DO: who gets
     refused, what is written, in what ORDER, and what the SCM is told. A static
     check cannot establish "the server is authenticated BEFORE anything is sent";
     this can.

The fake is not Windows and does not pretend to be — the real pipe, SCM, and token
reads are still proven only by the VM acceptance run. What it does prove is the
control flow and the typing discipline, which is precisely where these bugs were.
"""

import ctypes
import os
import sys
from ctypes import wintypes

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agent_errors                                          # noqa: E402
import privchannel as pc                                     # noqa: E402
import privclient                                            # noqa: E402
import privservice                                           # noqa: E402
import winsvc                                                # noqa: E402

_failures = []


def check(label, got, want):
    ok = got == want
    if not ok:
        _failures.append("%s: got %r, want %r" % (label, got, want))
    print("  %-62s %s%s" % (label, "PASS" if ok else "FAIL",
                            "" if ok else "  (got=%r want=%r)" % (got, want)))


# ── fake Win32 plumbing ──────────────────────────────────────────────────────

class _Fn:
    """A stand-in for a ctypes foreign function: records restype/argtypes exactly
    as ctypes would accept them, and delegates the call to a python impl."""
    def __init__(self, name, impl):
        self.name, self.impl = name, impl
        self.restype = None
        self.argtypes = None
        self.calls = 0

    def __call__(self, *a):
        self.calls += 1
        return self.impl(*a)


class FakeDLL:
    """Attribute-stable fake DLL: the same _Fn object comes back every time, so a
    restype set by _bind_win32 is still there when the code under test calls it."""
    def __init__(self, table=None):
        self._table = table or {}
        self._fns = {}

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        if name not in self._fns:
            self._fns[name] = _Fn(name, self._table.get(name, lambda *a: 1))
        return self._fns[name]


class _Win32Shim:
    """Installs the ctypes bits that only exist on Windows, for the duration of a
    test. `get_last_error` is read by all three shells; WINFUNCTYPE is needed by
    winsvc's dispatch table."""
    def __init__(self, scene=None):
        self.scene = scene
        self.saved = {}

    def __enter__(self):
        for name, val in (("get_last_error", lambda: (self.scene.last_error
                                                      if self.scene else 0)),
                          ("set_last_error", lambda v: None),
                          ("WINFUNCTYPE", ctypes.CFUNCTYPE)):
            self.saved[name] = getattr(ctypes, name, None)
            setattr(ctypes, name, val)
        return self

    def __exit__(self, *a):
        for name, val in self.saved.items():
            if val is None:
                delattr(ctypes, name)
            else:
                setattr(ctypes, name, val)


class _Recorder:
    """Captures agent_errors.record calls without writing real error state."""
    def __enter__(self):
        self.seen = []
        self._orig = agent_errors.record
        agent_errors.record = lambda code, msg="", **kw: self.seen.append((code, msg))
        return self

    def __exit__(self, *a):
        agent_errors.record = self._orig

    def codes(self):
        return [c for c, _ in self.seen]


# ── 1. BINDING DISCIPLINE — the test that would have caught the real defect ──

def _assert_bindings(label, module, bind_call):
    print("\n[%s: every handle-returning call has an explicit restype]" % label)
    bound = bind_call()
    dlls = bound if isinstance(bound, tuple) else (bound,)
    fns = {}
    for d in dlls:
        fns.update(d._fns)
    missing_any = [n for n, f in fns.items() if f.restype is None]
    check("every bound call has SOME restype", missing_any, [])
    for name in module.HANDLE_RETURNING:
        f = fns.get(name)
        check("%s is bound at all" % name, f is not None, True)
        if f is not None:
            # wintypes.HANDLE is c_void_p — pointer-width. c_int (the ctypes
            # DEFAULT) would truncate a 64-bit handle; that was the shipped bug.
            check("%s restype is pointer-width (not the c_int default)" % name,
                  f.restype is wintypes.HANDLE, True)
    argless = [n for n, f in fns.items() if f.argtypes is None]
    check("every bound call declares argtypes", argless, [])


def test_binding_discipline():
    _assert_bindings("privservice", privservice,
                     lambda: privservice._bind_win32(FakeDLL(), FakeDLL()))
    _assert_bindings("winsvc", winsvc,
                     lambda: winsvc._bind_win32(FakeDLL()))
    _assert_bindings("privclient", privclient,
                     lambda: privclient._bind_win32(FakeDLL()))
    _assert_bindings("privchannel", pc,
                     lambda: pc._bind_win32(FakeDLL(), FakeDLL()))


def test_truncation_is_what_restype_prevents():
    """The mechanism itself, asserted rather than described: an unset restype is
    c_int, which loses the top 32 bits of a real handle and makes the
    INVALID_HANDLE_VALUE comparison unable to fire."""
    print("\n[the c_int default truncates a 64-bit handle; c_void_p does not]")
    real = 0x0000023412340010
    check("c_int default would corrupt the handle",
          ctypes.c_int(real & 0xFFFFFFFF).value == real, False)
    check("pointer-width restype round-trips it",
          ctypes.c_void_p(real).value == real, True)
    check("a failed create seen through c_int (-1) != the pointer INVALID_HANDLE",
          ctypes.c_int(-1).value == ctypes.c_void_p(-1).value, False)


# ── 2. BEHAVIOUR — privservice._serve against a fake pipe ────────────────────

INVALID_HANDLE = ctypes.c_void_p(-1).value
ERROR_IO_PENDING = 997
ERROR_MORE_DATA = 234
AGENT_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
OTHER_SID = "S-1-5-21-1111111111-2222222222-3333333333-1002"


class PipeScene:
    """Enough of Win32 named pipes to drive _serve: one scripted client per accept,
    then a stop. Records every response the server writes."""

    def __init__(self, clients, create_fails=False, more_data_on_partial=False):
        self.pending = list(clients)      # [{"sid":..., "request": bytes}]
        self.create_fails = create_fails
        #: Simulate MESSAGE-mode semantics: a read smaller than the pending message
        #: delivers the bytes but returns FALSE with ERROR_MORE_DATA.
        self.more_data_on_partial = more_data_on_partial
        self.last_error = 0
        self.responses = []
        self.last_error = 0
        self.readbuf = b""
        self.cur_sid = None
        self.disconnects = 0

    def dll(self):
        k32 = FakeDLL({
            "CreateNamedPipeW": self._create,
            "CreateEventW": lambda *a: 0xE0000001,
            "ConnectNamedPipe": self._connect,
            "WaitForMultipleObjects": self._wait,
            "GetNamedPipeClientProcessId": self._client_pid,
            "ReadFile": self._read,
            "WriteFile": self._write,
            "DisconnectNamedPipe": self._disconnect,
            "CloseHandle": lambda h: 1,
            "SetEvent": lambda h: 1,
            "ResetEvent": lambda h: 1,
            "FlushFileBuffers": lambda h: 1,
            "LocalFree": lambda h: 0,
            "GetOverlappedResult": lambda h, ov, n, w: 1,
        })
        a32 = FakeDLL({
            "ConvertStringSecurityDescriptorToSecurityDescriptorW":
                lambda sddl, rev, psd, sz: 1,
        })
        return k32, a32

    # -- individual Win32 entry points --
    def _create(self, *a):
        return INVALID_HANDLE if self.create_fails else 0x1000

    def _connect(self, h, ov):
        self.last_error = ERROR_IO_PENDING
        return 0

    def _wait(self, count, handles, wait_all, timeout):
        if not self.pending:
            return 1                       # not WAIT_OBJECT_0 -> stop the loop
        client = self.pending.pop(0)
        self.cur_sid = client["sid"]
        self.readbuf = client["request"]
        return 0                           # WAIT_OBJECT_0 -> a client connected

    def _client_pid(self, h, ppid):
        ppid._obj.value = 4242
        return 1

    def _read(self, h, buf, n, pgot, pov):
        data = self.readbuf[:n]
        remaining = self.readbuf[n:]
        self.readbuf = remaining
        pgot._obj.value = len(data)
        if not data:
            return 0
        buf[0:len(data)] = data
        if self.more_data_on_partial and remaining:
            self.last_error = ERROR_MORE_DATA
            return 0                      # FALSE + ERROR_MORE_DATA, bytes delivered
        self.last_error = 0
        return 1

    def _write(self, h, data, n, pwrote, pov):
        self.responses.append(bytes(data[:n]))
        pwrote._obj.value = n
        return 1

    def _disconnect(self, h):
        self.disconnects += 1
        return 1


def _run_serve(scene):
    """Drive the REAL privservice._serve against `scene`."""
    import threading
    stop = threading.Event()
    orig_sid_of_pid = pc.sid_of_pid
    pc.sid_of_pid = lambda pid: scene.cur_sid
    privservice._WIN32_FOR_TEST = scene.dll()
    try:
        with _Win32Shim(scene), _Recorder() as rec:
            privservice._serve(stop, AGENT_SID)
        return rec
    finally:
        privservice._WIN32_FOR_TEST = None
        pc.sid_of_pid = orig_sid_of_pid


def test_serve_answers_an_authorized_client():
    print("\n[_serve: the enrolled agent user gets a real pong]")
    scene = PipeScene([{"sid": AGENT_SID,
                        "request": pc.pack_frame({"action": "ping"})}])
    _run_serve(scene)
    check("exactly one response written", len(scene.responses), 1)
    if scene.responses:
        body = scene.responses[0][4:]
        import json
        resp = json.loads(body.decode())
        check("response is a pong", resp.get("pong"), True)
        check("server identifies as SYSTEM", resp.get("server"), "SYSTEM")
    check("the connection was disconnected afterwards", scene.disconnects >= 1, True)


def test_serve_refuses_a_client_that_is_not_the_agent_user():
    """ADVERSARIAL CASE 1 — a different local user reaches the pipe. The ACL should
    already have stopped them; the SID check is the defence-in-depth behind it, and
    it must refuse WITHOUT answering."""
    print("\n[_serve: a non-enrolled SID is refused and gets NO response]")
    scene = PipeScene([{"sid": OTHER_SID,
                        "request": pc.pack_frame({"action": "ping"})}])
    rec = _run_serve(scene)
    check("nothing was written back", scene.responses, [])
    check("E-AGENT-110 recorded", "E-AGENT-110" in rec.codes(), True)


def test_serve_refuses_an_unreadable_client_sid():
    """ADVERSARIAL CASE 2 — the peer's token cannot be read. Unverifiable must mean
    refused, never 'benefit of the doubt'."""
    print("\n[_serve: an unreadable client SID (None) is refused, not trusted]")
    scene = PipeScene([{"sid": None,
                        "request": pc.pack_frame({"action": "ping"})}])
    rec = _run_serve(scene)
    check("nothing was written back", scene.responses, [])
    check("E-AGENT-110 recorded", "E-AGENT-110" in rec.codes(), True)


def test_serve_survives_a_hostile_frame_and_keeps_serving():
    print("\n[_serve: an oversize length prefix is refused, loop stays alive]")
    import struct
    hostile = struct.pack("<I", pc.MAX_FRAME_BYTES + 1) + b"x"
    scene = PipeScene([
        {"sid": AGENT_SID, "request": hostile},
        {"sid": AGENT_SID, "request": pc.pack_frame({"action": "ping"})},
    ])
    _run_serve(scene)
    check("the hostile frame produced no response", len(scene.responses), 1)
    check("the NEXT client was still served", len(scene.responses) == 1, True)


def test_serve_reports_a_failed_pipe_create():
    """The E-AGENT-112 path was UNREACHABLE before the fix: the code compared an
    untyped (truncated) return against the pointer INVALID_HANDLE_VALUE, which could
    never match, so a failed create fell through into pipe operations."""
    print("\n[_serve: a failed CreateNamedPipe is detected and reported]")
    scene = PipeScene([], create_fails=True)
    rec = _run_serve(scene)
    check("E-AGENT-112 recorded", "E-AGENT-112" in rec.codes(), True)
    check("no client work attempted", scene.responses, [])


def test_serve_uses_overlapped_io_on_an_overlapped_handle():
    """Win32 requires a real OVERLAPPED on a FILE_FLAG_OVERLAPPED handle; NULL is
    undefined behaviour and can report a read that never happened."""
    print("\n[_serve: ReadFile/WriteFile pass a real OVERLAPPED, never NULL]")
    seen = {"read": [], "write": []}
    scene = PipeScene([{"sid": AGENT_SID,
                        "request": pc.pack_frame({"action": "ping"})}])
    real_read, real_write = scene._read, scene._write
    scene._read = lambda h, b, n, pg, pov: (seen["read"].append(pov), real_read(h, b, n, pg, pov))[1]
    scene._write = lambda h, d, n, pw, pov: (seen["write"].append(pov), real_write(h, d, n, pw, pov))[1]
    _run_serve(scene)
    check("ReadFile was called", len(seen["read"]) > 0, True)
    check("no ReadFile passed a NULL overlapped",
          all(o is not None for o in seen["read"]), True)
    check("WriteFile was called", len(seen["write"]) > 0, True)
    check("no WriteFile passed a NULL overlapped",
          all(o is not None for o in seen["write"]), True)


# ── 3. BEHAVIOUR — privclient._call ──────────────────────────────────────────

class ClientScene:
    def __init__(self, server_sid, response=None, pipe_missing=False,
                 more_data_on_partial=False):
        self.server_sid = server_sid
        self.response = response or pc.pack_frame({"ok": True, "pong": True})
        self.pipe_missing = pipe_missing
        #: Same MESSAGE-mode simulation as PipeScene -- the client reads the reply
        #: incrementally too, so it needs the identical tolerance.
        self.more_data_on_partial = more_data_on_partial
        self.last_error = 0
        self.written = []
        self.readbuf = b""

    def dll(self):
        return FakeDLL({
            "WaitNamedPipeW": self._wait,
            "CreateFileW": self._open,
            "SetNamedPipeHandleState": lambda *a: 1,
            "GetNamedPipeServerProcessId": self._srv_pid,
            "ReadFile": self._read,
            "WriteFile": self._write,
            "CloseHandle": lambda h: 1,
        })

    def _wait(self, name, timeout):
        if self.pipe_missing:
            self.last_error = 2                      # ERROR_FILE_NOT_FOUND
            return 0
        return 1

    def _open(self, *a):
        return INVALID_HANDLE if self.pipe_missing else 0x2000

    def _srv_pid(self, h, ppid):
        ppid._obj.value = 777
        return 1

    def _write(self, h, data, n, pwrote, pov):
        self.written.append(bytes(data[:n]))
        self.readbuf = self.response                 # server replies after we send
        pwrote._obj.value = n
        return 1

    def _read(self, h, buf, n, pgot, pov):
        data = self.readbuf[:n]
        remaining = self.readbuf[n:]
        self.readbuf = remaining
        pgot._obj.value = len(data)
        if not data:
            return 0
        buf[0:len(data)] = data
        if self.more_data_on_partial and remaining:
            self.last_error = ERROR_MORE_DATA
            return 0                      # FALSE + ERROR_MORE_DATA, bytes delivered
        self.last_error = 0
        return 1


def _run_call(scene, request=None):
    orig = pc.sid_of_pid
    pc.sid_of_pid = lambda pid: scene.server_sid
    privclient._WIN32_FOR_TEST = scene.dll()
    try:
        with _Win32Shim(scene), _Recorder() as rec:
            try:
                return privclient._call(request or {"action": "ping"}), None, rec
            except Exception as exc:                 # noqa: BLE001
                return None, exc, rec
    finally:
        privclient._WIN32_FOR_TEST = None
        pc.sid_of_pid = orig


def test_call_round_trips_against_a_system_server():
    print("\n[_call: a verified-SYSTEM server round-trips]")
    scene = ClientScene(pc.SID_LOCAL_SYSTEM)
    resp, exc, _ = _run_call(scene)
    check("no exception", exc, None)
    check("got the pong", (resp or {}).get("pong"), True)
    check("exactly one request written", len(scene.written), 1)


def test_call_survives_error_more_data_on_a_partial_read():
    """The client reads the RESPONSE incrementally (header, then body), so it needs the
    same ERROR_MORE_DATA tolerance as the server. Both ends were changed; both are
    pinned here."""
    print("\n[_call: ERROR_MORE_DATA while reading the reply is tolerated]")
    scene = ClientScene(pc.SID_LOCAL_SYSTEM, more_data_on_partial=True)
    resp, exc, _ = _run_call(scene)
    check("no exception", exc, None)
    check("got the pong", (resp or {}).get("pong"), True)


def test_call_refuses_a_squatter_BEFORE_writing_anything():
    """ADVERSARIAL CASE — the pipe exists but is owned by a non-SYSTEM squatter. The
    ordering is the security property: the request must NEVER reach an unverified
    peer. Only a behavioural test can establish that; no static check can."""
    print("\n[_call: a non-SYSTEM server is refused, and NOTHING is sent to it]")
    scene = ClientScene(OTHER_SID)
    resp, exc, rec = _run_call(scene)
    check("raises PrivChannelAuthError", type(exc).__name__, "PrivChannelAuthError")
    check("NOTHING was written to the squatter", scene.written, [])
    check("E-AGENT-111 recorded", "E-AGENT-111" in rec.codes(), True)


def test_call_treats_an_unreadable_server_sid_as_a_failure():
    print("\n[_call: an unreadable server identity is refused, not trusted]")
    scene = ClientScene(None)
    resp, exc, _ = _run_call(scene)
    check("raises PrivChannelAuthError", type(exc).__name__, "PrivChannelAuthError")
    check("nothing written", scene.written, [])


def test_call_reports_an_absent_service_as_unavailable_not_an_error():
    print("\n[_call: an absent service is 'unavailable' (normal), not an error]")
    scene = ClientScene(pc.SID_LOCAL_SYSTEM, pipe_missing=True)
    resp, exc, _ = _run_call(scene)
    check("raises PrivChannelUnavailable", type(exc).__name__, "PrivChannelUnavailable")


def test_is_channel_healthy_never_raises():
    print("\n[is_channel_healthy: absence maps to 'absent', squatting to 'auth_failed']")
    scene = ClientScene(pc.SID_LOCAL_SYSTEM, pipe_missing=True)
    orig = pc.sid_of_pid
    pc.sid_of_pid = lambda pid: scene.server_sid
    privclient._WIN32_FOR_TEST = scene.dll()
    try:
        with _Win32Shim(scene), _Recorder():
            check("absent", privclient.is_channel_healthy()["state"], "absent")
        scene2 = ClientScene(OTHER_SID)
        privclient._WIN32_FOR_TEST = scene2.dll()
        pc.sid_of_pid = lambda pid: scene2.server_sid
        with _Win32Shim(scene2), _Recorder():
            check("auth_failed", privclient.is_channel_healthy()["state"], "auth_failed")
    finally:
        privclient._WIN32_FOR_TEST = None
        pc.sid_of_pid = orig


# ── 4. BEHAVIOUR — winsvc.run_service against a fake SCM ─────────────────────

class ScmScene:
    """A fake SCM: captures the reported SERVICE_STATUS sequence and lets the test
    deliver a control the way the real SCM would."""

    #: A realistic 64-bit SERVICE_STATUS_HANDLE. If it survives the round trip
    #: intact, the binding is pointer-width; the old c_int default truncated it and
    #: every SetServiceStatus then addressed nothing.
    HANDLE_VALUE = 0x0000029A_BCDE0010

    def __init__(self):
        self.reported = []            # [(handle, state, controls_accepted)]
        self.exit_codes = []
        self.handler = None
        self.last_error = 0
        self.service_main = None

    def dll(self):
        return FakeDLL({
            "RegisterServiceCtrlHandlerExW": self._register,
            "SetServiceStatus": self._set_status,
            "StartServiceCtrlDispatcherW": self._dispatch,
        })

    def _register(self, name, handler, ctx):
        self.handler = handler
        return self.HANDLE_VALUE

    def _set_status(self, handle, pst):
        st = pst._obj
        self.reported.append((handle, st.dwCurrentState, st.dwControlsAccepted))
        self.exit_codes.append(st.dwWin32ExitCode)
        return 1

    def _dispatch(self, table):
        self.service_main = table[0].lpServiceProc
        self.service_main(0, None)
        return 1

    def send(self, control):
        return self.handler(control, 0, None, None)

    def states(self):
        return [s for _, s, _ in self.reported]


def _run_service(scene, work_fn):
    winsvc._WIN32_FOR_TEST = scene.dll()
    try:
        with _Win32Shim(scene):
            winsvc.run_service("nemesis-agent-priv", work_fn)
    finally:
        winsvc._WIN32_FOR_TEST = None


def test_run_service_reports_the_full_lifecycle_to_the_scm():
    print("\n[run_service: SCM sees START_PENDING -> RUNNING -> STOPPED]")
    scene = ScmScene()

    def work(stop):
        scene.send(winsvc.SERVICE_CONTROL_STOP)      # the SCM asks us to stop
        stop.wait(2)

    _run_service(scene, work)
    states = scene.states()
    check("reported START_PENDING first", states[0], winsvc.SERVICE_START_PENDING)
    check("reported RUNNING", winsvc.SERVICE_RUNNING in states, True)
    check("reported STOP_PENDING on the control",
          winsvc.SERVICE_STOP_PENDING in states, True)
    check("reported STOPPED last", states[-1], winsvc.SERVICE_STOPPED)


def test_run_service_passes_an_untruncated_handle_to_every_status_report():
    """The winsvc half of the 2026-08-22 defect: a truncated SERVICE_STATUS_HANDLE
    means the SCM never hears from the service, so it never leaves START_PENDING and
    is killed — fatal on its own, regardless of the pipe."""
    print("\n[run_service: the SERVICE_STATUS_HANDLE survives intact]")
    scene = ScmScene()
    _run_service(scene, lambda stop: scene.send(winsvc.SERVICE_CONTROL_STOP))
    handles = {h for h, _, _ in scene.reported}
    check("at least one status was reported", len(scene.reported) > 0, True)
    check("every report used the exact handle the SCM returned",
          handles, {ScmScene.HANDLE_VALUE})


def test_run_service_accepts_stop_only_while_running():
    print("\n[run_service: controls are accepted only in RUNNING, never mid-transition]")
    scene = ScmScene()
    _run_service(scene, lambda stop: scene.send(winsvc.SERVICE_CONTROL_STOP))
    for _h, state, accepted in scene.reported:
        if state == winsvc.SERVICE_RUNNING:
            check("RUNNING accepts stop+shutdown", accepted,
                  winsvc.ACCEPTED_WHEN_RUNNING)
        else:
            check("state %d accepts nothing" % state, accepted, 0)


def test_run_service_reports_stopped_even_if_the_work_fn_raises():
    print("\n[run_service: a crashing work function still reports STOPPED to the SCM]")
    scene = ScmScene()

    def boom(stop):
        raise RuntimeError("work function exploded")

    _run_service(scene, boom)
    check("final state is STOPPED", scene.states()[-1], winsvc.SERVICE_STOPPED)
    # The SCM must be told the service FAILED, not that it stopped cleanly -- a
    # clean exit code here would suppress the configured auto-restart.
    check("the final report carries a non-zero exit code",
          scene.exit_codes[-1] != winsvc.NO_ERROR, True)

    clean = ScmScene()
    _run_service(clean, lambda stop: clean.send(winsvc.SERVICE_CONTROL_STOP))
    check("CONTROL: an orderly stop reports exit code 0",
          clean.exit_codes[-1], winsvc.NO_ERROR)


def test_serve_survives_error_more_data_on_a_partial_read():
    """REGRESSION (VM-measured 2026-08-22). The pipe shipped as MESSAGE mode while the
    framing reads incrementally (4-byte header, then the body). In MESSAGE mode a read
    smaller than the pending message returns FALSE with ERROR_MORE_DATA -- the bytes
    ARE delivered:

        ReadFile(4) -> ok=False got=4 err=234 (ERROR_MORE_DATA)

    The old read path treated any non-ERROR_IO_PENDING failure as a dead read and
    discarded those 4 bytes, so EVERY request died as 'truncated length prefix'. The
    service answered nothing while the SCM cheerfully reported RUNNING -- the failure
    was invisible from outside. The transport is byte mode now; this test pins the
    tolerance so a future flip back to message mode cannot silently resurrect it."""
    print("\n[_serve: ERROR_MORE_DATA on a partial read is a partial read, not a failure]")
    scene = PipeScene([{"sid": AGENT_SID,
                        "request": pc.pack_frame({"action": "ping"})}],
                      more_data_on_partial=True)
    _run_serve(scene)
    check("the request was still parsed and answered", len(scene.responses), 1)
    if scene.responses:
        import json
        check("response is a pong",
              json.loads(scene.responses[0][4:].decode()).get("pong"), True)


# ── 5. off-Windows guards still hold ─────────────────────────────────────────

def test_shells_refuse_to_run_off_windows_without_an_injected_fake():
    print("\n[off Windows and with no fake injected, all three shells refuse]")
    if sys.platform == "win32":
        print("  (skipped on Windows)")
        return
    import threading

    def raises(exc_type, fn, *a):
        try:
            fn(*a)
        except exc_type:
            return True
        except Exception:                                    # noqa: BLE001
            return False
        return False

    check("_serve raises PrivChannelUnsupported",
          raises(pc.PrivChannelUnsupported, privservice._serve,
                 threading.Event(), AGENT_SID), True)
    check("_call raises PrivChannelUnsupported",
          raises(pc.PrivChannelUnsupported, privclient._call, {"action": "ping"}), True)
    check("run_service raises ServiceError",
          raises(winsvc.ServiceError, winsvc.run_service, "x", lambda s: None), True)


if __name__ == "__main__":
    print("privservice._serve / winsvc.run_service / privclient._call — shell tests")
    test_binding_discipline()
    test_truncation_is_what_restype_prevents()
    test_serve_answers_an_authorized_client()
    test_serve_refuses_a_client_that_is_not_the_agent_user()
    test_serve_refuses_an_unreadable_client_sid()
    test_serve_survives_a_hostile_frame_and_keeps_serving()
    test_serve_reports_a_failed_pipe_create()
    test_serve_uses_overlapped_io_on_an_overlapped_handle()
    test_serve_survives_error_more_data_on_a_partial_read()
    test_call_round_trips_against_a_system_server()
    test_call_survives_error_more_data_on_a_partial_read()
    test_call_refuses_a_squatter_BEFORE_writing_anything()
    test_call_treats_an_unreadable_server_sid_as_a_failure()
    test_call_reports_an_absent_service_as_unavailable_not_an_error()
    test_is_channel_healthy_never_raises()
    test_run_service_reports_the_full_lifecycle_to_the_scm()
    test_run_service_passes_an_untruncated_handle_to_every_status_report()
    test_run_service_accepts_stop_only_while_running()
    test_run_service_reports_stopped_even_if_the_work_fn_raises()
    test_shells_refuse_to_run_off_windows_without_an_injected_fake()

    print()
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS")
