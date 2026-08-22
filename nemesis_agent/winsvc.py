"""winsvc — a minimal Windows Service (SCM) host in pure ctypes, no pywin32.

The SYSTEM-privileged Nemesis component (step 3b, growing a real capability in 3c)
runs as a Windows service so it starts at boot, is managed by the SCM, and reports
health the OS can see. This module is the reusable SCM plumbing — service-control
dispatch, the control handler, and SERVICE_STATUS reporting — kept separate from
whatever the service actually DOES (privservice.py supplies that as a work function).

PURE STATE MACHINE vs WINDOWS SHELL (same discipline as privchannel)
-------------------------------------------------------------------
The part that must be RIGHT — how an incoming control (STOP/SHUTDOWN/INTERROGATE)
maps to the next state to report and whether the work loop must stop — is a pure
function, `next_status`, unit-tested anywhere. The ctypes calls
(StartServiceCtrlDispatcherW, RegisterServiceCtrlHandlerExW, SetServiceStatus) are
the Windows-only shell around it, proven on the VM. A service that mis-reports its
state to the SCM (e.g. never leaves START_PENDING, or claims STOPPED while its
threads run) is exactly the kind of silently-wrong status this split cannot afford,
so the transition logic is isolated where it can be tested.
"""

from __future__ import annotations

import sys
import threading

# ── SERVICE_STATUS constants (winsvc.h) ──────────────────────────────────────
SERVICE_WIN32_OWN_PROCESS = 0x00000010

SERVICE_STOPPED = 0x00000001
SERVICE_START_PENDING = 0x00000002
SERVICE_STOP_PENDING = 0x00000003
SERVICE_RUNNING = 0x00000004

SERVICE_CONTROL_STOP = 0x00000001
SERVICE_CONTROL_SHUTDOWN = 0x00000005
SERVICE_CONTROL_INTERROGATE = 0x00000004

SERVICE_ACCEPT_STOP = 0x00000001
SERVICE_ACCEPT_SHUTDOWN = 0x00000004

NO_ERROR = 0

#: Controls we accept once RUNNING. Deliberately minimal — this service takes no
#: pause/continue/param-change; accepting a control we do not truly handle would
#: let the SCM believe we honour it.
ACCEPTED_WHEN_RUNNING = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN


# ── pure: the control -> status transition ───────────────────────────────────

#: Actions the dispatch shell must take, returned by next_status alongside the
#: state to report. Kept as plain strings so the state machine is trivially
#: testable and carries no ctypes.
ACTION_NONE = "none"          # report the (possibly unchanged) state, keep running
ACTION_STOP = "stop"          # signal the work loop to exit, then report STOPPED


def next_status(current_state: int, control: int):
    """Given the state we last reported and an incoming SCM control, return
    (state_to_report, action).

    STOP and SHUTDOWN both mean 'wind down': report STOP_PENDING and signal the
    work loop (ACTION_STOP), after which the shell reports STOPPED. INTERROGATE
    means 'restate your status': report the CURRENT state unchanged, no action.
    Any other control is not accepted by this service and is a no-op — reporting
    the current state so the SCM sees a consistent answer, never silently changing
    state on a control we do not implement.
    """
    if control in (SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN):
        return SERVICE_STOP_PENDING, ACTION_STOP
    if control == SERVICE_CONTROL_INTERROGATE:
        return current_state, ACTION_NONE
    return current_state, ACTION_NONE


def accepted_controls(state: int) -> int:
    """Which controls the service accepts in a given state. Only a RUNNING service
    accepts STOP/SHUTDOWN; while pending or stopped it accepts none (0), which is
    what tells the SCM not to send a control mid-transition."""
    return ACCEPTED_WHEN_RUNNING if state == SERVICE_RUNNING else 0


# ── Windows-only ctypes shell (VM-verified; import-safe off Windows) ─────────

#: advapi32 entry points that return a HANDLE-like value. Each MUST get an
#: explicit restype — see _bind_win32. The test suite asserts full coverage.
HANDLE_RETURNING = ("RegisterServiceCtrlHandlerExW",)


def _bind_win32(a32):
    """Declare argtypes/restypes for the SCM calls this host makes.

    WHY — a shipped defect, caught 2026-08-22. ctypes defaults an unset `restype`
    to `c_int` (32-bit, signed), which TRUNCATES the 64-bit SERVICE_STATUS_HANDLE
    that RegisterServiceCtrlHandlerExW returns. Every later SetServiceStatus then
    addresses a handle that names nothing, so the SCM never receives a status: the
    service never leaves START_PENDING and the SCM kills it. That is fatal on its
    own, independent of whether the pipe works — and it is exactly the failure this
    module's docstring warns about ("a service that mis-reports its state to the
    SCM"), reached by mis-binding rather than by faulty transition logic.
    """
    import ctypes
    from ctypes import wintypes
    H, D, B = wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL
    a32.RegisterServiceCtrlHandlerExW.restype = H
    a32.RegisterServiceCtrlHandlerExW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p,
                                                  ctypes.c_void_p]
    a32.SetServiceStatus.restype = B
    a32.SetServiceStatus.argtypes = [H, ctypes.c_void_p]
    a32.StartServiceCtrlDispatcherW.restype = B
    a32.StartServiceCtrlDispatcherW.argtypes = [ctypes.c_void_p]
    return a32


class ServiceError(RuntimeError):
    pass


def _is_windows() -> bool:
    return sys.platform == "win32"


#: Tests inject a fake advapi32 here to drive the SCM dispatch off Windows and
#: assert what the service actually REPORTS — the half that mis-binding broke while
#: the (tested) transition logic stayed correct.
_WIN32_FOR_TEST = None


def _win32():
    """The bound advapi32 — real, or a test-injected fake."""
    if _WIN32_FOR_TEST is not None:
        return _bind_win32(_WIN32_FOR_TEST)
    import ctypes
    return _bind_win32(ctypes.WinDLL("advapi32", use_last_error=True))


def run_service(service_name: str, work_fn):
    """Run `work_fn(stop_event)` as a Windows service named `service_name`.

    `work_fn` receives a threading.Event that is SET when the SCM asks the service
    to stop; it must return promptly after the event is set. This function blocks
    in StartServiceCtrlDispatcherW until the service stops, then returns. Windows-
    only; raises ServiceError off Windows so a mis-deploy fails loudly.

    NOTE: this is the Windows-only shell; its correctness is proven on the VM
    acceptance test (install, start, SCM reports RUNNING, stop is honoured). The
    transition logic it relies on (next_status/accepted_controls) is unit-tested.
    """
    if not _is_windows() and _WIN32_FOR_TEST is None:
        raise ServiceError("run_service is Windows-only")

    import ctypes
    from ctypes import wintypes

    advapi32 = _win32()

    class SERVICE_STATUS(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wintypes.DWORD),
            ("dwCurrentState", wintypes.DWORD),
            ("dwControlsAccepted", wintypes.DWORD),
            ("dwWin32ExitCode", wintypes.DWORD),
            ("dwServiceSpecificExitCode", wintypes.DWORD),
            ("dwCheckPoint", wintypes.DWORD),
            ("dwWaitHint", wintypes.DWORD),
        ]

    LPHANDLER_FUNCTION_EX = ctypes.WINFUNCTYPE(
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p)
    LPSERVICE_MAIN_FUNCTION = ctypes.WINFUNCTYPE(
        None, wintypes.DWORD, ctypes.POINTER(ctypes.c_wchar_p))

    class SERVICE_TABLE_ENTRY(ctypes.Structure):
        _fields_ = [("lpServiceName", ctypes.c_wchar_p),
                    ("lpServiceProc", LPSERVICE_MAIN_FUNCTION)]

    state = {"handle": None, "current": SERVICE_START_PENDING, "cp": 0}
    stop_event = threading.Event()

    def _set_status(new_state, exit_code=NO_ERROR, wait_hint=0):
        state["current"] = new_state
        st = SERVICE_STATUS()
        st.dwServiceType = SERVICE_WIN32_OWN_PROCESS
        st.dwCurrentState = new_state
        st.dwControlsAccepted = accepted_controls(new_state)
        st.dwWin32ExitCode = exit_code
        st.dwServiceSpecificExitCode = 0
        if new_state in (SERVICE_START_PENDING, SERVICE_STOP_PENDING):
            state["cp"] += 1
            st.dwCheckPoint = state["cp"]
            st.dwWaitHint = wait_hint or 3000
        else:
            st.dwCheckPoint = 0
            st.dwWaitHint = 0
        advapi32.SetServiceStatus(state["handle"], ctypes.byref(st))

    def _handler(control, event_type, event_data, context):
        report_state, action = next_status(state["current"], control)
        if action == ACTION_STOP:
            _set_status(SERVICE_STOP_PENDING, wait_hint=5000)
            stop_event.set()
        else:
            _set_status(report_state)
        return NO_ERROR

    handler_ref = LPHANDLER_FUNCTION_EX(_handler)

    def _service_main(argc, argv):
        h = advapi32.RegisterServiceCtrlHandlerExW(
            ctypes.c_wchar_p(service_name), handler_ref, None)
        if not h:
            return
        state["handle"] = h
        _set_status(SERVICE_START_PENDING, wait_hint=3000)
        try:
            _set_status(SERVICE_RUNNING)
            work_fn(stop_event)                    # returns when stop_event is set
            _set_status(SERVICE_STOPPED)
        except Exception:                          # noqa: BLE001
            _set_status(SERVICE_STOPPED, exit_code=1)

    main_ref = LPSERVICE_MAIN_FUNCTION(_service_main)
    table = (SERVICE_TABLE_ENTRY * 2)()
    table[0].lpServiceName = service_name
    table[0].lpServiceProc = main_ref
    table[1].lpServiceName = None
    table[1].lpServiceProc = ctypes.cast(None, LPSERVICE_MAIN_FUNCTION)

    if not advapi32.StartServiceCtrlDispatcherW(table):
        raise ServiceError("StartServiceCtrlDispatcher failed: %d"
                           % ctypes.get_last_error())
