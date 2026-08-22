#!/usr/bin/env python3
"""wincap - Windows memory-inspection capability probe (step 3c). Tests.

Run: python3 /opt/nemesis/nemesis_agent/test_wincap.py

Deliberately mirrors test_memcap.py: the two platforms must satisfy the SAME
three-state, fail-closed contract, because they feed ONE heartbeat field. Where this
file differs from its Linux twin, the difference is the platform's, not the design's --
notably PROTECTED (PPL) targets, which Linux has no equivalent of.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wincap                                                # noqa: E402
import winmem                                                # noqa: E402

_failures = []


def check(label, got, want):
    ok = got == want
    if not ok:
        _failures.append("%s: got %r, want %r" % (label, got, want))
    print("  %-62s %s%s" % (label, "PASS" if ok else "FAIL",
                            "" if ok else "  (got=%r want=%r)" % (got, want)))


class _patch:
    def __init__(self, mod, **kw):
        self.mod, self.kw, self.old = mod, kw, {}

    def __enter__(self):
        for k, v in self.kw.items():
            self.old[k] = getattr(self.mod, k)
            setattr(self.mod, k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.old.items():
            setattr(self.mod, k, v)


def _on_windows(**kw):
    """Pretend we are on Windows so the real verdict logic runs off-platform."""
    base = {"_is_windows": lambda: True,
            "debug_privilege_state": lambda: {"enabled": True, "adjust_called": True,
                                              "not_held": False, "error": None}}
    base.update(kw)
    return _patch(wincap, **base)


def test_successful_read_is_available():
    print("\n[a real cross-process read that SUCCEEDS -> available]")
    with _on_windows(_iter_targets=lambda: iter([4884]),
                     _try_read_foreign=lambda pid: True):
        r = wincap.probe()
    check("state", r["state"], wincap.AVAILABLE)
    check("names the method as functional", "ReadProcessMemory" in r["method"], True)


def test_denial_is_unavailable():
    print("\n[a measured denial -> unavailable (confident negative)]")
    with _on_windows(_iter_targets=lambda: iter([4884]),
                     _try_read_foreign=lambda pid: False):
        r = wincap.probe()
    check("state", r["state"], wincap.UNAVAILABLE)


def test_untestable_is_undetermined_never_available():
    print("\n[unmeasurable targets -> undetermined, and NOT available (fail-closed)]")
    with _on_windows(_iter_targets=lambda: iter([1, 2]),
                     _try_read_foreign=lambda pid: None):
        r = wincap.probe()
    check("state", r["state"], wincap.UNDETERMINED)
    check("never collapses to available", r["state"] == wincap.AVAILABLE, False)


def test_no_targets_is_undetermined():
    print("\n[no candidate target at all -> undetermined, not a false negative]")
    with _on_windows(_iter_targets=lambda: iter([]),
                     _try_read_foreign=lambda pid: True):
        r = wincap.probe()
    check("state", r["state"], wincap.UNDETERMINED)


def test_a_denial_anywhere_beats_undetermined():
    print("\n[any measured denial outweighs an unmeasurable target]")
    seq = {1: None, 2: False}
    with _on_windows(_iter_targets=lambda: iter([1, 2]),
                     _try_read_foreign=lambda pid: seq[pid]):
        r = wincap.probe()
    check("state", r["state"], wincap.UNAVAILABLE)


def test_protected_target_does_not_condemn_the_capability():
    """MEASURED 2026-08-22: a PPL target (MsMpEng) refuses OpenProcess with
    ERROR_ACCESS_DENIED even as SYSTEM with SeDebugPrivilege enabled. That is a
    platform ceiling for THAT target and says nothing about ordinary processes -- so
    it must not drag the capability verdict to `unavailable`, which would tell the
    operator the agent cannot inspect memory at all when in fact it can."""
    print("\n[a PROTECTED (PPL) target does not make the CAPABILITY unavailable]")

    class _S:
        PROTECTED, UNAVAILABLE, UNDETERMINED = ("protected", "unavailable",
                                                "undetermined")
        @staticmethod
        def open_target(pid):
            return (None, "protected")

    with _patch(wincap, _is_windows=lambda: True):
        import types
        fake = types.SimpleNamespace(PROTECTED="protected", UNAVAILABLE="unavailable",
                                     UNDETERMINED="undetermined",
                                     open_target=lambda pid: (None, "protected"))
        real = sys.modules.get("winmem")
        sys.modules["winmem"] = fake
        try:
            check("a protected target reads as untestable (None), not a denial",
                  wincap._try_read_foreign(3088), None)
        finally:
            sys.modules["winmem"] = real

    with _on_windows(_iter_targets=lambda: iter([3088]),
                     _try_read_foreign=lambda pid: None):
        r = wincap.probe()
    check("so the verdict is undetermined, NOT unavailable", r["state"],
          wincap.UNDETERMINED)
    check("and certainly not available", r["state"] == wincap.AVAILABLE, False)


def test_same_user_target_is_not_a_discriminator():
    """REGRESSION (VM-measured 2026-08-22). A NON-elevated user, with
    SeDebugPrivilege correctly reported not_held=True, still read explorer.exe -- its
    OWN process -- and this probe called the capability `available`. Reading a
    same-user process requires no privilege, so it demonstrates nothing about the
    cross-privilege access the detector needs. memcap already guards this on Linux by
    targeting pid 1 and different-uid processes only; this is the same rule ported."""
    print("\n[a SAME-USER target is untestable, not a demonstration of capability]")
    import types
    MINE = "S-1-5-21-1-2-3-1000"
    OTHER = "S-1-5-18"

    def run(target_sid):
        fake_wm = types.SimpleNamespace(
            PROTECTED="protected", UNAVAILABLE="unavailable",
            UNDETERMINED="undetermined",
            open_target=lambda pid: (0x1000, None),
            iter_regions=lambda h, max_regions=256: iter(
                [{"base": 0x1000, "size": 0x1000, "protect": 0x04,
                  "state": 0x1000, "type": 0x20000}]),
            is_region_readable=lambda r: True,
            read_bytes=lambda h, b, n, cap=None: b"ABCDEFGH",
            close=lambda h: None)
        fake_pc = types.SimpleNamespace(
            sid_of_pid=lambda pid: MINE if pid == os.getpid() else target_sid)
        real_wm, real_pc = sys.modules.get("winmem"), sys.modules.get("privchannel")
        sys.modules["winmem"], sys.modules["privchannel"] = fake_wm, fake_pc
        try:
            return wincap._try_read_foreign(4884)
        finally:
            sys.modules["winmem"] = real_wm
            if real_pc is not None:
                sys.modules["privchannel"] = real_pc

    check("a same-user target returns None (untestable), NOT True", run(MINE), None)
    check("CONTROL: a different-user target DOES demonstrate the capability",
          run(OTHER), True)
    check("unverifiable ownership is untestable, never assumed cross-user",
          run(None), None)


def test_privilege_state_is_corroborating_only():
    """3a's lesson, ported: a held privilege is not a demonstrated capability. An
    enabled SeDebugPrivilege must not turn a denied read into `available`."""
    print("\n[SeDebugPrivilege is reported but is NEVER the verdict]")
    with _on_windows(_iter_targets=lambda: iter([4884]),
                     _try_read_foreign=lambda pid: False):
        r = wincap.probe()
    check("denied read stays unavailable even with the privilege enabled",
          r["state"], wincap.UNAVAILABLE)
    check("the privilege state is still reported for context",
          r["sedebug"]["enabled"], True)


def test_non_windows_is_undetermined():
    print("\n[off Windows: undetermined and a clean self-test skip, never a false state]")
    r = wincap.probe()
    check("probe state", r["state"], wincap.UNDETERMINED)
    check("points at the Linux path", "memcap" in r["detail"], True)
    st = wincap.self_test()
    check("self_test skips cleanly", st["ok"], True)
    check("and says WHY it skipped", st.get("skipped"), "non-Windows")


def test_selftest_catches_a_rubber_stamp_reader():
    print("\n[CONTROL: a reader that always succeeds is caught]")
    with _on_windows(_read_own_byte=lambda: True,
                     _try_read_foreign=lambda pid: True):
        st = wincap.self_test()
    check("self_test FAILS on a rubber-stamp reader", st["ok"], False)
    check("names the rubber-stamp", any("rubber" in f for f in st["findings"]), True)


def test_selftest_catches_a_broken_reader():
    print("\n[CONTROL: a reader that cannot read our own memory is caught]")
    with _on_windows(_read_own_byte=lambda: None,
                     _try_read_foreign=lambda pid: None):
        st = wincap.self_test()
    check("self_test FAILS when own read fails", st["ok"], False)
    check("names the broken reader", any("OWN memory" in f for f in st["findings"]), True)


def test_selftest_passes_a_healthy_reader():
    print("\n[CONTROL: a healthy reader passes -- the test can say yes as well as no]")
    with _on_windows(_read_own_byte=lambda: True,
                     _try_read_foreign=lambda pid: None):
        st = wincap.self_test()
    check("self_test ok", st["ok"], True)


def test_contract_matches_memcap():
    """One heartbeat field, one vocabulary. If these ever diverge, a dashboard reading
    `memscan_capability` means different things depending on the endpoint's OS."""
    print("\n[wincap and memcap expose the SAME three-state vocabulary]")
    import memcap
    check("available", wincap.AVAILABLE, memcap.AVAILABLE)
    check("unavailable", wincap.UNAVAILABLE, memcap.UNAVAILABLE)
    check("undetermined", wincap.UNDETERMINED, memcap.UNDETERMINED)
    for key in ("state", "detail", "method"):
        check("probe() reports %r on both" % key,
              key in wincap.probe() and key in memcap.probe(), True)


if __name__ == "__main__":
    print("wincap - Windows memory-inspection capability probe")
    test_successful_read_is_available()
    test_denial_is_unavailable()
    test_untestable_is_undetermined_never_available()
    test_no_targets_is_undetermined()
    test_a_denial_anywhere_beats_undetermined()
    test_protected_target_does_not_condemn_the_capability()
    test_same_user_target_is_not_a_discriminator()
    test_privilege_state_is_corroborating_only()
    test_non_windows_is_undetermined()
    test_selftest_catches_a_rubber_stamp_reader()
    test_selftest_catches_a_broken_reader()
    test_selftest_passes_a_healthy_reader()
    test_contract_matches_memcap()

    print()
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS")
