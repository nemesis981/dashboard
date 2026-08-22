#!/usr/bin/env python3
"""memcap — memory-inspection capability probe tests.

Run: python3 /opt/nemesis/nemesis_agent/test_memcap.py

The load-bearing property under test is HONEST FAIL-CLOSED three-state reporting:
a real permission denial reads `unavailable`, an unmeasurable target reads
`undetermined`, and `undetermined` is NEVER collapsed into `available`. The
functional reads are mocked so the verdicts are deterministic regardless of the
box's real privilege; a separate block runs the REAL self-test on this machine.
"""

import ctypes
import errno
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import memcap                                                # noqa: E402

_failures = []


def check(label, got, want):
    ok = got == want
    if not ok:
        _failures.append("%s: got %r, want %r" % (label, got, want))
    print("  %-58s %s%s" % (label, "PASS" if ok else "FAIL",
                            "" if ok else "  (got=%r want=%r)" % (got, want)))


class _patch:
    """Minimal attribute patcher/restorer so each test states exactly what the
    kernel-facing reads return, without touching the real /proc."""
    def __init__(self, **kw):
        self.kw = kw
        self.old = {}

    def __enter__(self):
        for k, v in self.kw.items():
            self.old[k] = getattr(memcap, k)
            setattr(memcap, k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.old.items():
            setattr(memcap, k, v)


def test_available_on_successful_read():
    print("\n[a real cross-privilege read that SUCCEEDS -> available]")
    with _patch(_iter_targets=lambda uid: iter([999]),
                _try_read_foreign_byte=lambda pid: True):
        r = memcap.probe()
    check("state", r["state"], memcap.AVAILABLE)


def test_denial_is_unavailable():
    print("\n[a measured permission DENIAL -> unavailable (confident negative)]")
    with _patch(_iter_targets=lambda uid: iter([999]),
                _try_read_foreign_byte=lambda pid: False):
        r = memcap.probe()
    check("state", r["state"], memcap.UNAVAILABLE)


def test_untestable_is_undetermined_never_available():
    print("\n[an UNMEASURABLE target -> undetermined, and NOT available (fail-closed)]")
    with _patch(_iter_targets=lambda uid: iter([999, 1000]),
                _try_read_foreign_byte=lambda pid: None):
        r = memcap.probe()
    check("state", r["state"], memcap.UNDETERMINED)
    check("undetermined is NOT collapsed to available",
          r["state"] == memcap.AVAILABLE, False)


def test_a_denial_anywhere_beats_undetermined():
    print("\n[if any target is denied, the verdict is unavailable, not undetermined]")
    seq = {999: None, 1000: False}     # first untestable, second a denial
    with _patch(_iter_targets=lambda uid: iter([999, 1000]),
                _try_read_foreign_byte=lambda pid: seq[pid]):
        r = memcap.probe()
    check("state", r["state"], memcap.UNAVAILABLE)


def test_maps_permission_error_is_a_denial():
    """REGRESSION: a permission denial on the foreign /proc/<pid>/maps read is the
    SAME ptrace gate as the memory read and must count as a denial, not be swallowed
    as 'no region' (the first cut's bug: every target came back undetermined)."""
    print("\n[a PermissionError on the maps read is a measured denial]")
    def _boom(pid, limit=16):
        raise PermissionError(13, "Permission denied")
    with _patch(_readable_regions=_boom):
        check("try_read returns False (denied)", memcap._try_read_foreign_byte(7), False)


def test_missing_target_is_untestable_not_a_denial():
    print("\n[a raced-away target (ENOENT) is untestable (None), not a denial]")
    def _gone(pid, limit=16):
        raise FileNotFoundError(2, "No such file or directory")
    with _patch(_readable_regions=_gone):
        check("try_read returns None (untestable)", memcap._try_read_foreign_byte(7), None)


def test_no_region_is_untestable():
    print("\n[a target with no readable region (kernel thread) is untestable (None)]")
    with _patch(_readable_regions=lambda pid, limit=16: []):
        check("try_read returns None", memcap._try_read_foreign_byte(7), None)


# ── regression block for the 2026-08-22 VM finding ───────────────────────────

def _fake_syscall(errno_seq):
    """A stand-in process_vm_readv. `errno_seq` is a list of (rc, errno) applied in
    order, one per region tried, so a test can script per-region outcomes."""
    calls = {"n": 0}
    def fn(pid, local, lcnt, remote, rcnt, flags):
        rc, err = errno_seq[min(calls["n"], len(errno_seq) - 1)]
        calls["n"] += 1
        ctypes.set_errno(err)
        return rc
    fn.calls = calls
    return fn


def test_acquisition_is_not_proc_pid_mem():
    """REGRESSION (VM-verified 2026-08-22): /proc/<pid>/mem is mode 0600, so opening
    it needs CAP_DAC_OVERRIDE, NOT the CAP_SYS_PTRACE this step grants. A non-root
    agent holding the cap got EACCES there while its maps read succeeded — the
    capability looked granted and the read still failed. The acquisition primitive
    must therefore never be that file."""
    print("\n[the acquisition path does NOT open /proc/<pid>/mem]")
    source = open(memcap.__file__.replace(".pyc", ".py")).read()
    body = source.split('"""', 2)[2]          # skip the module docstring, which
                                              # legitimately discusses the old path
    check("no /proc/<pid>/mem open in the code", '/proc/%d/mem' in body, False)
    check("process_vm_readv is bound", callable(memcap._process_vm_readv()), True)


def test_syscall_eperm_is_a_denial():
    """A denial can surface at the SYSCALL as well as at the maps read."""
    print("\n[EPERM from process_vm_readv is a measured denial]")
    with _patch(_readable_regions=lambda pid, limit=16: [(0x1000, 4096)],
                _process_vm_readv=lambda: _fake_syscall([(-1, errno.EPERM)])):
        check("try_read returns False (denied)", memcap._try_read_foreign_byte(7), False)


def test_syscall_efault_falls_through_to_the_next_region():
    """A region flagged readable in maps can still EFAULT ([vvar], guard pages). One
    odd mapping must not turn a real capability into `undetermined`."""
    print("\n[EFAULT on one region tries the NEXT region rather than giving up]")
    fake = _fake_syscall([(-1, errno.EFAULT), (1, 0)])
    with _patch(_readable_regions=lambda pid, limit=16: [(0x1000, 4096), (0x2000, 4096)],
                _process_vm_readv=lambda: fake):
        check("try_read returns True (second region read)",
              memcap._try_read_foreign_byte(7), True)
    check("both regions were tried", fake.calls["n"], 2)


def test_absent_syscall_is_undetermined_not_a_denial():
    """An unavailable syscall is an absence of measurement. Reporting it as a denial
    would be a default value masquerading as a real result."""
    print("\n[an unavailable process_vm_readv is untestable (None), NOT a denial]")
    with _patch(_process_vm_readv=lambda: None):
        check("try_read returns None", memcap._try_read_foreign_byte(7), None)
    with _patch(_process_vm_readv=lambda: None, _iter_targets=lambda uid: iter([999])):
        check("probe reports undetermined", memcap.probe()["state"], memcap.UNDETERMINED)


def test_esrch_is_untestable():
    print("\n[a target that races away mid-syscall (ESRCH) is untestable (None)]")
    with _patch(_readable_regions=lambda pid, limit=16: [(0x1000, 4096)],
                _process_vm_readv=lambda: _fake_syscall([(-1, errno.ESRCH)])):
        check("try_read returns None", memcap._try_read_foreign_byte(7), None)


def test_non_linux_is_undetermined():
    print("\n[non-Linux reports undetermined (Windows path is 3b/3c), never a false state]")
    with _patch(_is_linux=lambda: False):
        r = memcap.probe()
        check("probe state", r["state"], memcap.UNDETERMINED)
        st = memcap.self_test()
        check("self_test skips cleanly", st["ok"], True)


def test_selftest_passes_on_this_box():
    """The REAL self-test on this machine: own-memory read works (mechanism live)
    and a non-existent pid is not rubber-stamped."""
    print("\n[REAL self-test on this box: reader works AND does not rubber-stamp]")
    st = memcap.self_test()
    check("self_test ok", st["ok"], True)
    if not st["ok"]:
        print("        %s" % "; ".join(st["findings"]))


def test_selftest_catches_a_rubber_stamp_reader():
    """CONTROL: a reader that always returns success MUST be caught (it would
    'read' a non-existent pid). Proves the self-test measures something."""
    print("\n[CONTROL: a rubber-stamp reader (always True) is caught]")
    with _patch(_try_read_foreign_byte=lambda pid: True):
        st = memcap.self_test()
    check("self_test FAILS on a rubber-stamp reader", st["ok"], False)
    check("names the rubber-stamp", any("rubber" in f for f in st["findings"]), True)


def test_selftest_catches_a_broken_reader():
    """CONTROL: a reader that can't even read our own memory MUST be caught — every
    verdict from it would be untrustworthy."""
    print("\n[CONTROL: a reader that fails on own memory is caught]")
    with _patch(_try_read_foreign_byte=lambda pid: None):
        st = memcap.self_test()
    check("self_test FAILS when own read fails", st["ok"], False)
    check("names the broken reader", any("OWN memory" in f for f in st["findings"]), True)


def test_capeff_is_corroborating_only():
    print("\n[the CAP_SYS_PTRACE bit is reported but is not the verdict]")
    # A SET bit must NOT make an untestable/denied probe read available.
    with _patch(has_cap_sys_ptrace=lambda: True,
                _iter_targets=lambda uid: iter([999]),
                _try_read_foreign_byte=lambda pid: False):
        r = memcap.probe()
    check("denied read stays unavailable even with the cap bit set",
          r["state"], memcap.UNAVAILABLE)
    check("bit is still reported for context", r["capeff_has_ptrace"], True)


if __name__ == "__main__":
    print("memcap — memory-inspection capability probe")
    test_available_on_successful_read()
    test_denial_is_unavailable()
    test_untestable_is_undetermined_never_available()
    test_a_denial_anywhere_beats_undetermined()
    test_maps_permission_error_is_a_denial()
    test_missing_target_is_untestable_not_a_denial()
    test_no_region_is_untestable()
    test_acquisition_is_not_proc_pid_mem()
    test_syscall_eperm_is_a_denial()
    test_syscall_efault_falls_through_to_the_next_region()
    test_absent_syscall_is_undetermined_not_a_denial()
    test_esrch_is_untestable()
    test_non_linux_is_undetermined()
    test_selftest_passes_on_this_box()
    test_selftest_catches_a_rubber_stamp_reader()
    test_selftest_catches_a_broken_reader()
    test_capeff_is_corroborating_only()

    print()
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS")
