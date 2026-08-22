#!/usr/bin/env python3
"""winmem - Windows memory acquisition primitives (step 3c). Tests.

Run: python3 /opt/nemesis/nemesis_agent/test_winmem.py

Reuses the fake-Win32 harness from test_privshell rather than cloning it, so both
Windows shells are exercised through ONE simulation that cannot drift between files.

The load-bearing properties here:
  * binding discipline -- every handle-returning call has a pointer-width restype
    (the 3b defect class; 3c adds calls to the same kind of shell)
  * PROTECTED is a distinct, measured state, never folded into UNDETERMINED
  * every bound is enforced HERE, not assumed of callers (region count, read size)
  * a failed read returns None, never b"" that a caller could read as "read nothing"
"""

import ctypes
import os
import sys
from ctypes import wintypes

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import winmem                                                # noqa: E402
from test_privshell import FakeDLL, _Win32Shim               # noqa: E402

_failures = []


def check(label, got, want):
    ok = got == want
    if not ok:
        _failures.append("%s: got %r, want %r" % (label, got, want))
    print("  %-60s %s%s" % (label, "PASS" if ok else "FAIL",
                            "" if ok else "  (got=%r want=%r)" % (got, want)))


class _Scene:
    """Minimal fake kernel32/advapi32 for winmem."""
    def __init__(self, open_result=0x1000, open_error=0, regions=None,
                 read_ok=True, read_bytes_val=b"ABCDEFGH"):
        self.open_result, self.open_error = open_result, open_error
        self.regions = regions or []
        self.read_ok, self.read_bytes_val = read_ok, read_bytes_val
        self.last_error = 0
        self.reads = []
        self._idx = 0

    def dll(self):
        k32 = FakeDLL({
            "OpenProcess": self._open,
            "GetCurrentProcess": lambda: 0xFFFFFFFFFFFFFFFF,
            "CloseHandle": lambda h: 1,
            "LocalFree": lambda h: 0,
            "VirtualQueryEx": self._vq,
            "ReadProcessMemory": self._read,
        })
        a32 = FakeDLL({"OpenProcessToken": lambda *a: 1,
                       "LookupPrivilegeValueW": lambda *a: 1,
                       "AdjustTokenPrivileges": lambda *a: 1})
        return k32, a32

    def _open(self, access, inherit, pid):
        self.last_error = self.open_error
        return self.open_result

    def _vq(self, h, addr, pmbi, size):
        want = int(addr.value or 0) if hasattr(addr, "value") else int(addr or 0)
        for r in self.regions:
            if r["base"] >= want:
                m = pmbi._obj
                m.BaseAddress, m.RegionSize = r["base"], r["size"]
                m.Protect, m.State, m.Type = r["protect"], r["state"], r["type"]
                m.AllocationBase = r["base"]
                return size
        return 0

    def _read(self, h, base, buf, n, pnread):
        self.reads.append(n)
        if not self.read_ok:
            pnread._obj.value = 0
            return 0
        data = self.read_bytes_val[:n]
        buf[0:len(data)] = data
        pnread._obj.value = len(data)
        return 1


def _region(base, size=0x1000, protect=0x04, state=winmem.MEM_COMMIT,
            rtype=winmem.MEM_PRIVATE):
    return {"base": base, "size": size, "protect": protect, "state": state,
            "type": rtype}


def _with(scene, fn, *a, **kw):
    winmem._WIN32_FOR_TEST = scene.dll()
    try:
        with _Win32Shim(scene):
            return fn(*a, **kw)
    finally:
        winmem._WIN32_FOR_TEST = None


# ── binding discipline ───────────────────────────────────────────────────────

def test_binding_discipline():
    print("\n[winmem: every handle-returning call has a pointer-width restype]")
    k32, a32 = winmem._bind_win32(FakeDLL(), FakeDLL())
    fns = dict(k32._fns); fns.update(a32._fns)
    check("every bound call has SOME restype",
          [n for n, f in fns.items() if f.restype is None], [])
    check("every bound call declares argtypes",
          [n for n, f in fns.items() if f.argtypes is None], [])
    for name in winmem.HANDLE_RETURNING:
        f = fns.get(name)
        check("%s bound" % name, f is not None, True)
        if f is not None:
            check("%s restype is pointer-width (not the c_int default)" % name,
                  f.restype is wintypes.HANDLE, True)


# ── pure renderers ───────────────────────────────────────────────────────────

def test_renderers():
    print("\n[protection/type/state render, and the GUARD bit is not lost]")
    check("EXECUTE_READWRITE", winmem.protect_name(0x40), "EXECUTE_READWRITE")
    check("guard bit preserved", winmem.protect_name(0x04 | winmem.PAGE_GUARD),
          "READWRITE|GUARD")
    check("unknown protection is shown, not swallowed",
          winmem.protect_name(0x7F).startswith("0x"), True)
    check("IMAGE", winmem.type_name(winmem.MEM_IMAGE), "IMAGE")
    check("COMMIT", winmem.state_name(winmem.MEM_COMMIT), "COMMIT")


def test_readability_is_mechanical():
    print("\n[is_region_readable: committed, not NOACCESS, not guarded]")
    check("committed READWRITE is readable",
          winmem.is_region_readable(_region(0x1000)), True)
    check("RESERVE (not committed) is not",
          winmem.is_region_readable(_region(0x1000, state=winmem.MEM_RESERVE)), False)
    check("NOACCESS is not",
          winmem.is_region_readable(_region(0x1000, protect=winmem.PAGE_NOACCESS)), False)
    check("a GUARD page is not (touching it raises in the target)",
          winmem.is_region_readable(_region(0x1000, protect=0x04 | winmem.PAGE_GUARD)),
          False)
    check("EXECUTE_READWRITE is readable (classification is NOT our job)",
          winmem.is_region_readable(_region(0x1000, protect=0x40)), True)


# ── open_target state mapping ────────────────────────────────────────────────

def test_open_target_states():
    print("\n[open_target maps each failure to the RIGHT state]")
    s = _Scene(open_result=0x2000)
    h, st = _with(s, winmem.open_target, 1234)
    check("success -> handle, no state", (h, st), (0x2000, None))

    s = _Scene(open_result=0, open_error=winmem.ERROR_ACCESS_DENIED)
    check("ACCESS_DENIED -> PROTECTED (measured refusal, known cause)",
          _with(s, winmem.open_target, 1234)[1], winmem.PROTECTED)

    s = _Scene(open_result=0, open_error=winmem.ERROR_INVALID_PARAMETER)
    check("INVALID_PARAMETER (gone/bad pid) -> UNDETERMINED",
          _with(s, winmem.open_target, 1234)[1], winmem.UNDETERMINED)

    s = _Scene(open_result=0, open_error=1450)
    check("another definite error -> UNAVAILABLE",
          _with(s, winmem.open_target, 1234)[1], winmem.UNAVAILABLE)


def test_protected_is_not_undetermined():
    """The states must stay distinct: 'refused, and we know why' is different
    information from 'could not be measured', and a caller acts on them differently."""
    print("\n[PROTECTED and UNDETERMINED are distinct states]")
    check("distinct constants", winmem.PROTECTED == winmem.UNDETERMINED, False)


# ── bounds are enforced here, not assumed ────────────────────────────────────

def test_region_walk_is_bounded():
    print("\n[iter_regions honours max_regions AND the hard ceiling]")
    regions = [_region(0x1000 * (i + 1)) for i in range(50)]
    s = _Scene(regions=regions)
    got = _with(s, lambda: list(winmem.iter_regions(0x1000, max_regions=10)))
    check("stops at the caller's cap", len(got), 10)
    s2 = _Scene(regions=regions)
    got2 = _with(s2, lambda: list(winmem.iter_regions(0x1000, max_regions=10**9)))
    check("a caller cannot exceed MAX_REGIONS", len(got2) <= winmem.MAX_REGIONS, True)


def test_region_walk_cannot_spin():
    """A zero-size or non-advancing region must end the walk, not loop forever in the
    privileged service."""
    print("\n[iter_regions stops when the address does not advance]")
    s = _Scene(regions=[{"base": 0x1000, "size": 0, "protect": 0x04,
                         "state": winmem.MEM_COMMIT, "type": winmem.MEM_PRIVATE}])
    got = _with(s, lambda: list(winmem.iter_regions(0x1000, max_regions=1000)))
    check("terminated instead of spinning", len(got) <= 1, True)
    check("and emitted no duplicate region",
          len({r["base"] for r in got}), len(got))

    # A walk that goes BACKWARDS must also stop rather than re-emit.
    s2 = _Scene(regions=[_region(0x3000), _region(0x1000)])
    got2 = _with(s2, lambda: list(winmem.iter_regions(0x1000, max_regions=1000)))
    check("a non-advancing walk yields each base at most once",
          len({r["base"] for r in got2}), len(got2))


def test_read_is_capped_and_fails_closed():
    print("\n[read_bytes: capped, and a failed read is None (never empty bytes)]")
    s = _Scene(read_bytes_val=b"X" * 4096)
    data = _with(s, winmem.read_bytes, 0x1000, 0x2000, 8192, 32)
    check("honours the caller's cap", len(data or b""), 32)
    s2 = _Scene(read_bytes_val=b"X" * (1 << 21))
    _with(s2, winmem.read_bytes, 0x1000, 0x2000, 1 << 21, 1 << 21)
    check("never asks for more than MAX_READ_BYTES",
          max(s2.reads) <= winmem.MAX_READ_BYTES, True)
    s3 = _Scene(read_ok=False)
    check("a failed read returns None, not b''",
          _with(s3, winmem.read_bytes, 0x1000, 0x2000, 64), None)
    s4 = _Scene()
    check("a zero-size request returns None",
          _with(s4, winmem.read_bytes, 0x1000, 0x2000, 0), None)


# ── privilege enable: three outcomes, not two ────────────────────────────────

def test_enable_privilege_distinguishes_not_held():
    """AdjustTokenPrivileges returns TRUE even when the privilege was NOT assigned.
    Trusting its return value alone is an instrument that can only say 'success' --
    the same shape as 3a's CapEff bit-read. ERROR_NOT_ALL_ASSIGNED is the real answer."""
    print("\n[ensure_debug_privilege: enabled / not_held / did-not-execute]")
    s = _Scene(); s.last_error = 0
    r = _with(s, winmem.ensure_debug_privilege)
    check("clean enable reports enabled", r["enabled"], True)
    check("and records that the call actually ran", r["adjust_called"], True)

    s2 = _Scene(); s2.last_error = 1300                      # ERROR_NOT_ALL_ASSIGNED
    r2 = _with(s2, winmem.ensure_debug_privilege)
    check("NOT_ALL_ASSIGNED -> not_held, NOT enabled", (r2["not_held"], r2["enabled"]),
          (True, False))

    s3 = _Scene()
    s3.dll_broken = True
    k32, a32 = s3.dll()
    a32.LookupPrivilegeValueW.impl = lambda *a: 0
    winmem._WIN32_FOR_TEST = (k32, a32)
    try:
        with _Win32Shim(s3):
            r3 = winmem.ensure_debug_privilege()
    finally:
        winmem._WIN32_FOR_TEST = None
    check("a lookup failure does not claim enabled", r3["enabled"], False)
    check("and says the adjust never ran", r3["adjust_called"], False)


def test_off_windows_guard():
    print("\n[off Windows with no fake injected, winmem refuses]")
    if sys.platform == "win32":
        print("  (skipped on Windows)"); return
    try:
        winmem.open_target(1)
        check("open_target raises WinMemUnsupported", False, True)
    except winmem.WinMemUnsupported:
        check("open_target raises WinMemUnsupported", True, True)
    except Exception as e:                                   # noqa: BLE001
        check("open_target raises WinMemUnsupported", type(e).__name__, "WinMemUnsupported")


if __name__ == "__main__":
    print("winmem - Windows memory acquisition primitives")
    test_binding_discipline()
    test_renderers()
    test_readability_is_mechanical()
    test_open_target_states()
    test_protected_is_not_undetermined()
    test_region_walk_is_bounded()
    test_region_walk_cannot_spin()
    test_read_is_capped_and_fails_closed()
    test_enable_privilege_distinguishes_not_held()
    test_off_windows_guard()

    print()
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS")
