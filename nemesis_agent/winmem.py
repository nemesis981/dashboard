"""winmem - Windows memory ACQUISITION primitives (step 3c). PUBLIC by decision.

The Windows counterpart to the Linux acquisition in `memcap.py`. This module answers
"what is mapped in this process, and give me these bytes" -- nothing more. It does NOT
decide what any of it MEANS: the injection heuristics that classify a region as
suspicious are the detector's actual novelty and live in the private module (operator
decision 2026-08-22, D2). The split is source-visibility only, never a feature gate.

WHAT IS MEASURED, NOT ASSUMED (VM, 2026-08-22, running as the real LocalSystem service)
--------------------------------------------------------------------------------------
  * SeDebugPrivilege on the LocalSystem token is PRESENT **and already ENABLED**.
    Documented behaviour widely says "held but disabled by default"; on this build it
    is enabled out of the box. `ensure_debug_privilege()` is therefore a cheap,
    idempotent safety net for a policy that disables it -- NOT a precondition the
    caller may assume was ever needed.
  * A normal target (explorer) opened and read cleanly.
  * A PROTECTED (PPL) target (MsMpEng) refused `OpenProcess` with ERROR_ACCESS_DENIED
    (5) even as SYSTEM with SeDebugPrivilege enabled. That is a hard platform ceiling,
    not a bug and not something to work around -- see `PROTECTED` below.

HONEST PER-TARGET REPORTING
---------------------------
A protected target is a MEASURED refusal with a known cause, so it gets its own state
rather than being folded into a vague "could not tell" or -- far worse -- passed over
while the caller reports the process as scanned. Silently skipping a target you cannot
read, while reporting success, is the exact failure class this codebase keeps finding.

BOUNDED BY CONSTRUCTION
-----------------------
Region enumeration and every read are capped by the caller. The appliance model already
promises a transient reservation for this work (`APPLIANCE_RESERVATIONS
["memory-injection-scan"]`, 3% clamped to 128-384 MB), and a region map is
attacker-influenced data: a target with pathologically many mappings must not become a
memory-pressure lever against the privileged service. Caps are enforced here, never
assumed of callers.
"""

from __future__ import annotations

import sys

#: Per-target outcomes. `PROTECTED` is deliberately distinct from `UNDETERMINED`:
#: protected means "measured refusal, cause known, permanent"; undetermined means
#: "could not be measured at all". Collapsing them would hide a real, explainable
#: gap behind a shrug.
READABLE = "readable"
PROTECTED = "protected"
UNAVAILABLE = "unavailable"
UNDETERMINED = "undetermined"

#: Win32 memory constants (winnt.h).
MEM_COMMIT, MEM_RESERVE, MEM_FREE = 0x1000, 0x2000, 0x10000
MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE = 0x20000, 0x40000, 0x1000000
PAGE_NOACCESS, PAGE_GUARD = 0x01, 0x100

#: Protection flags, for rendering `protect` as text. The CLASSIFICATION of which
#: combinations are suspicious is NOT here -- that is the private detector's job.
_PROT = {
    0x01: "NOACCESS", 0x02: "READONLY", 0x04: "READWRITE", 0x08: "WRITECOPY",
    0x10: "EXECUTE", 0x20: "EXECUTE_READ", 0x40: "EXECUTE_READWRITE",
    0x80: "EXECUTE_WRITECOPY",
}
_TYPE = {MEM_PRIVATE: "PRIVATE", MEM_MAPPED: "MAPPED", MEM_IMAGE: "IMAGE"}
_STATE = {MEM_COMMIT: "COMMIT", MEM_RESERVE: "RESERVE", MEM_FREE: "FREE"}

#: Hard ceilings. A caller may ask for less, never more.
MAX_REGIONS = 4096
MAX_READ_BYTES = 1 << 20

ERROR_ACCESS_DENIED = 5
ERROR_INVALID_PARAMETER = 87

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010

#: Handle-returning entry points -- each MUST get an explicit restype. See
#: privservice._bind_win32 for the defect this convention exists to prevent
#: (ctypes defaults restype to c_int, truncating a 64-bit HANDLE).
HANDLE_RETURNING = ("OpenProcess", "GetCurrentProcess", "LocalFree")


class WinMemUnsupported(RuntimeError):
    """A Windows-only primitive was called off Windows."""


def protect_name(value: int) -> str:
    """Render a protection value as text, preserving the guard bit. Never raises."""
    base = _PROT.get(value & 0xFF, "0x%X" % (value & 0xFF))
    return base + ("|GUARD" if value & PAGE_GUARD else "")


def type_name(value: int) -> str:
    return _TYPE.get(value, "0x%X" % value)


def state_name(value: int) -> str:
    return _STATE.get(value, "0x%X" % value)


def is_windows() -> bool:
    return sys.platform == "win32"


def _require_windows(what: str):
    if not is_windows():
        raise WinMemUnsupported("%s is Windows-only" % what)


# ── Windows-only shell ───────────────────────────────────────────────────────

_WIN32_FOR_TEST = None          #: tests inject a fake kernel32/advapi32 pair here


def _bind_win32(k32, a32):
    """Declare argtypes/restypes for every Win32 call this module makes.

    Same centralised convention 3b adopted after handle truncation shipped in two of
    four modules: one place to bind, a HANDLE_RETURNING tuple the tests assert
    against, so a call added later cannot quietly miss its restype.
    """
    import ctypes
    from ctypes import wintypes
    H, D, B, P = wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL, ctypes.c_void_p
    Z = ctypes.c_size_t
    k32.OpenProcess.restype, k32.OpenProcess.argtypes = H, [D, B, D]
    k32.GetCurrentProcess.restype, k32.GetCurrentProcess.argtypes = H, []
    k32.LocalFree.restype, k32.LocalFree.argtypes = H, [H]
    k32.CloseHandle.restype, k32.CloseHandle.argtypes = B, [H]
    k32.VirtualQueryEx.restype, k32.VirtualQueryEx.argtypes = Z, [H, P, P, Z]
    k32.ReadProcessMemory.restype = B
    k32.ReadProcessMemory.argtypes = [H, P, P, Z, P]
    a32.OpenProcessToken.restype, a32.OpenProcessToken.argtypes = B, [H, D, P]
    a32.LookupPrivilegeValueW.restype = B
    a32.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, P]
    a32.AdjustTokenPrivileges.restype = B
    a32.AdjustTokenPrivileges.argtypes = [H, B, P, D, P, P]
    return k32, a32


def _win32():
    if _WIN32_FOR_TEST is not None:
        return _bind_win32(*_WIN32_FOR_TEST)
    _require_windows("winmem")
    import ctypes
    return _bind_win32(ctypes.WinDLL("kernel32", use_last_error=True),
                       ctypes.WinDLL("advapi32", use_last_error=True))


def ensure_debug_privilege() -> dict:
    """Enable SeDebugPrivilege on our own token. Idempotent; never raises.

    Returns the same THREE-way outcome the existing `tools/win_priv_probe.py` learned
    to distinguish, because `AdjustTokenPrivileges` returns TRUE even when the
    privilege was never assigned -- checking only its return value is an instrument
    that can only ever say "success":

        enabled=True    the token holds it and it is now enabled
        not_held=True   ERROR_NOT_ALL_ASSIGNED: the token does not hold it at all
        adjust_called   False means the step did not execute; its outcome is UNKNOWN
                        and must not be read as either success or failure

    MEASURED: on this Windows build LocalSystem already has it enabled, so this is a
    safety net for a hardened policy, not a precondition.
    """
    import ctypes
    from ctypes import wintypes
    res = {"privilege": "SeDebugPrivilege", "adjust_called": False,
           "enabled": False, "not_held": False, "error": None}
    TOKEN_QUERY, TOKEN_ADJUST_PRIVILEGES = 0x0008, 0x0020
    SE_PRIVILEGE_ENABLED, ERROR_NOT_ALL_ASSIGNED = 0x0002, 1300

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

    class TOKEN_PRIVILEGES_1(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD),
                    ("Privileges", LUID_AND_ATTRIBUTES * 1)]
    try:
        k32, a32 = _win32()
        luid = LUID()
        if not a32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            res["error"] = "LookupPrivilegeValueW failed: %d" % ctypes.get_last_error()
            return res
        tok = wintypes.HANDLE()
        if not a32.OpenProcessToken(k32.GetCurrentProcess(),
                                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                    ctypes.byref(tok)):
            res["error"] = "OpenProcessToken failed: %d" % ctypes.get_last_error()
            return res
        try:
            tp = TOKEN_PRIVILEGES_1(1, (LUID_AND_ATTRIBUTES * 1)(
                LUID_AND_ATTRIBUTES(luid, SE_PRIVILEGE_ENABLED)))
            ctypes.set_last_error(0)
            ok = a32.AdjustTokenPrivileges(tok, False, ctypes.byref(tp), 0, None, None)
            res["adjust_called"] = True
            last = ctypes.get_last_error()
            if not ok:
                res["error"] = "AdjustTokenPrivileges failed: %d" % last
            elif last == ERROR_NOT_ALL_ASSIGNED:
                res["not_held"] = True
            else:
                res["enabled"] = True
        finally:
            k32.CloseHandle(tok)
    except Exception as exc:                                 # noqa: BLE001
        res["error"] = "%s: %s" % (type(exc).__name__, exc)
    return res


def open_target(pid: int):
    """Open `pid` for region enumeration + reads.

    Returns (handle, state). `handle` is None unless state is READABLE-capable:
        (h, None)              opened
        (None, PROTECTED)      ACCESS_DENIED -- a protected (PPL) target, or one this
                               identity may not touch. MEASURED refusal, known cause.
        (None, UNAVAILABLE)    the target rejected us for another definite reason
        (None, UNDETERMINED)   it could not be established (gone, bad pid, odd error)
    """
    import ctypes
    k32, _a32 = _win32()
    ctypes.set_last_error(0)
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid)
    if h:
        return h, None
    err = ctypes.get_last_error()
    if err == ERROR_ACCESS_DENIED:
        return None, PROTECTED
    if err == ERROR_INVALID_PARAMETER:
        return None, UNDETERMINED           # no such pid / raced away
    return None, UNAVAILABLE


def iter_regions(handle, max_regions: int = MAX_REGIONS):
    """Yield raw region facts for an opened target: base, size, protect, state, type.

    RAW FACTS ONLY -- no judgement about which regions matter. `max_regions` is a hard
    stop: a target's mapping count is attacker-influenced, and an unbounded walk in the
    privileged service is a memory-pressure lever.
    """
    import ctypes
    from ctypes import wintypes
    k32, _a32 = _win32()

    class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_ulonglong),
                    ("AllocationBase", ctypes.c_ulonglong),
                    ("AllocationProtect", wintypes.DWORD),
                    ("__alignment1", wintypes.DWORD),
                    ("RegionSize", ctypes.c_ulonglong),
                    ("State", wintypes.DWORD), ("Protect", wintypes.DWORD),
                    ("Type", wintypes.DWORD), ("__alignment2", wintypes.DWORD)]

    cap = min(int(max_regions), MAX_REGIONS)
    mbi = MEMORY_BASIC_INFORMATION64()
    addr = 0
    seen = 0
    last_base = None
    while seen < cap:
        got = k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi),
                                 ctypes.sizeof(mbi))
        if not got:
            return
        base, size = int(mbi.BaseAddress), int(mbi.RegionSize)
        # Guard BEFORE yielding, not after. A zero-size (or non-advancing) region
        # otherwise gets emitted a second time before the walk notices it is stuck --
        # a duplicate entry in the region map, which inflates counts and would have
        # the detector weigh one mapping twice. Caught by test_winmem 2026-08-22.
        if last_base is not None and base <= last_base:
            return
        yield {"base": base, "size": size,
               "protect": int(mbi.Protect), "protect_name": protect_name(mbi.Protect),
               "state": int(mbi.State), "state_name": state_name(mbi.State),
               "type": int(mbi.Type), "type_name": type_name(mbi.Type),
               "allocation_base": int(mbi.AllocationBase)}
        seen += 1
        last_base = base
        nxt = base + size
        if nxt <= addr:                     # no forward progress -- stop, never spin
            return
        addr = nxt


def is_region_readable(region: dict) -> bool:
    """Can this region be read at all? A committed page that is neither NOACCESS nor
    guarded. This is a MECHANICAL readability test, not a judgement about interest."""
    if region.get("state") != MEM_COMMIT:
        return False
    prot = region.get("protect", 0)
    return not (prot & PAGE_GUARD) and (prot & 0xFF) != PAGE_NOACCESS


def read_bytes(handle, base: int, size: int, cap: int = MAX_READ_BYTES):
    """Read up to min(size, cap, MAX_READ_BYTES) bytes at `base`.

    Returns bytes on success, or None when the read did not happen. None is an
    explicit "no data", never an empty-bytes stand-in a caller might treat as a
    successful read of nothing.
    """
    import ctypes
    k32, _a32 = _win32()
    want = max(0, min(int(size), int(cap), MAX_READ_BYTES))
    if want == 0:
        return None
    buf = (ctypes.c_char * want)()
    nread = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, want,
                               ctypes.byref(nread))
    if not ok or nread.value == 0:
        return None
    return bytes(buf[:nread.value])


def close(handle):
    """Close a target handle. Never raises."""
    try:
        k32, _a32 = _win32()
        k32.CloseHandle(handle)
    except Exception:                                        # noqa: BLE001
        pass
