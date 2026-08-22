#!/usr/bin/env python3
"""inspect_pid - the 3c action on the proven 3b channel. Tests.

Run: python3 /opt/nemesis/nemesis_agent/test_inspect_pid.py

Properties under test, in the order they matter:
  * `dispatch` STAYS PURE. Privileged work arrives injected. Purity is what kept 3b's
    logic testable while its Win32 shell was broken; 3c must not spend it.
  * The privileged side validates its own inputs. An authenticated client is not a
    trusted one -- it is a lower-privilege process handing a SYSTEM service an integer.
  * A PROTECTED target is never counted as scanned (operator decision D3).
  * Every bound is enforced HERE: region count, response frame size, digest bytes.
  * The private classifier's ABSENCE is reported, never disguised.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import privchannel as pc                                     # noqa: E402
import privservice                                           # noqa: E402
import winmem                                                # noqa: E402

_failures = []


def check(label, got, want):
    ok = got == want
    if not ok:
        _failures.append("%s: got %r, want %r" % (label, got, want))
    print("  %-62s %s%s" % (label, "PASS" if ok else "FAIL",
                            "" if ok else "  (got=%r want=%r)" % (got, want)))


class _FakeWinmem:
    """Stands in for the winmem module inside make_inspector."""
    READABLE, PROTECTED = winmem.READABLE, winmem.PROTECTED
    UNAVAILABLE, UNDETERMINED = winmem.UNAVAILABLE, winmem.UNDETERMINED

    def __init__(self, open_state=None, regions=None, read_val=b"Z" * 64):
        self.open_state = open_state
        self.regions = regions or []
        self.read_val = read_val
        self.read_calls = []
        self.closed = 0

    def open_target(self, pid):
        return (None, self.open_state) if self.open_state else (0x1000, None)

    def iter_regions(self, handle, max_regions=512):
        return iter(self.regions[:max_regions])

    def is_region_readable(self, r):
        return True

    def read_bytes(self, handle, base, size, cap=None):
        n = min(size, cap if cap is not None else size)
        self.read_calls.append(n)
        return self.read_val[:n] if n > 0 else None

    def close(self, handle):
        self.closed += 1


def _run(fake, params, classifier=None):
    real = sys.modules.get("winmem")
    sys.modules["winmem"] = fake
    try:
        return privservice.make_inspector(classifier)(params)
    finally:
        sys.modules["winmem"] = real


def _regions(n, base0=0x10000, size=0x1000):
    return [{"base": base0 + i * size, "size": size, "protect": 0x04,
             "protect_name": "READWRITE", "state": 0x1000, "state_name": "COMMIT",
             "type": 0x20000, "type_name": "PRIVATE", "allocation_base": base0}
            for i in range(n)]


# ── purity + validation ──────────────────────────────────────────────────────

def test_dispatch_stays_pure():
    print("\n[dispatch does no I/O: with no inspector it refuses, explicitly]")
    r = privservice.dispatch({"action": "inspect_pid", "pid": 4242})
    check("refuses", r.get("ok"), False)
    check("says NOT scanned", r.get("scanned"), False)
    check("state is undetermined, never a readable-looking default",
          r.get("state"), "undetermined")


def test_validation_rejects_hostile_pids():
    """An authenticated client is a lower-privilege process choosing an integer for a
    SYSTEM service to act on. Bounds belong on the privileged side."""
    print("\n[the privileged side validates its own inputs]")
    for bad, why in ((None, "missing"), ("4", "string"), (-1, "negative"), (0, "zero"),
                     (2**33, "out of range"), (True, "bool masquerading as int")):
        params, err = privservice.validate_inspect_pid({"pid": bad})
        check("rejects pid=%r (%s)" % (bad, why), (params, err is not None),
              (None, True))
    params, err = privservice.validate_inspect_pid({"pid": 1234})
    check("accepts a sane pid", (params["pid"], err), (1234, None))
    check("applies the default region cap", params["max_regions"],
          privservice.DEFAULT_MAX_REGIONS)


def test_caller_cannot_raise_the_region_cap():
    print("\n[a caller may lower the region cap, never raise it past the hard limit]")
    p, _ = privservice.validate_inspect_pid({"pid": 1, "max_regions": 10})
    check("honours a smaller request", p["max_regions"], 10)
    p, _ = privservice.validate_inspect_pid({"pid": 1, "max_regions": 10 ** 9})
    check("clamps an absurd request to HARD_MAX_REGIONS", p["max_regions"],
          privservice.HARD_MAX_REGIONS)
    p, _ = privservice.validate_inspect_pid({"pid": 1, "max_regions": "lots"})
    check("ignores a non-integer cap", p["max_regions"],
          privservice.DEFAULT_MAX_REGIONS)


# ── D3: protected is never scanned ───────────────────────────────────────────

def test_protected_target_is_never_counted_as_scanned():
    """MEASURED on the VM: a protected target refuses OpenProcess with ACCESS_DENIED
    even as SYSTEM with SeDebugPrivilege enabled. Operator decision D3: report it
    honestly, never let it pass as a clean scan."""
    print("\n[a PROTECTED target reports state=protected and scanned=False]")
    fake = _FakeWinmem(open_state=winmem.PROTECTED)
    r = _run(fake, {"pid": 3088, "max_regions": 512})
    check("state is protected", r.get("state"), winmem.PROTECTED)
    check("scanned is explicitly False", r.get("scanned"), False)
    check("no regions are implied", r.get("regions"), [])
    check("the detail says it was NOT scanned", "NOT scanned" in r.get("detail", ""),
          True)
    check("ok stays True (the request was handled correctly)", r.get("ok"), True)


def test_unopenable_target_is_not_scanned_either():
    print("\n[an unopenable target is also never scanned]")
    for state in (winmem.UNAVAILABLE, winmem.UNDETERMINED):
        fake = _FakeWinmem(open_state=state)
        r = _run(fake, {"pid": 999, "max_regions": 512})
        check("state=%s -> scanned False" % state, r.get("scanned"), False)


def test_readable_target_is_scanned():
    print("\n[CONTROL: a readable target IS scanned - the flag discriminates]")
    fake = _FakeWinmem(regions=_regions(5))
    r = _run(fake, {"pid": 4884, "max_regions": 512})
    check("scanned True", r.get("scanned"), True)
    check("state readable", r.get("state"), winmem.READABLE)
    check("regions returned", len(r.get("regions", [])), 5)
    check("handle was closed", fake.closed, 1)


# ── bounds ───────────────────────────────────────────────────────────────────

def test_region_count_is_capped():
    print("\n[the region walk honours the validated cap]")
    fake = _FakeWinmem(regions=_regions(1000))
    r = _run(fake, {"pid": 1, "max_regions": 20})
    check("returned at most the cap", len(r["regions"]) <= 20, True)


def test_response_is_bounded_by_measured_frame_size():
    """A response that overflows the frame is not a big answer, it is NO answer: the
    client cannot parse it and the whole inspection is lost. So the bound is MEASURED
    against the real packed frame, not estimated."""
    print("\n[an oversized region map is truncated to fit one frame, and says so]")
    fake = _FakeWinmem(regions=_regions(privservice.HARD_MAX_REGIONS))
    r = _run(fake, {"pid": 1, "max_regions": privservice.HARD_MAX_REGIONS})
    packed = len(pc.pack_frame(r))
    check("the response fits in one frame", packed <= pc.MAX_FRAME_BYTES, True)
    if len(r["regions"]) < privservice.HARD_MAX_REGIONS:
        check("truncation is declared, not silent", r.get("truncated"), True)
        check("the true count is still reported",
              r.get("region_count"), privservice.HARD_MAX_REGIONS)


def test_truncation_actually_fires_and_is_declared():
    """The previous test proved the response FITS; it did not prove the shrink loop
    works, because a full region map happens to stay under the cap. An untested
    truncation path is exactly the branch that fails the first time it is needed, so
    force it by squeezing the frame cap."""
    print("\n[FORCED truncation: the shrink loop runs, and the result says so]")
    real_cap = pc.MAX_FRAME_BYTES
    pc.MAX_FRAME_BYTES = 2048                    # small enough to force the loop
    try:
        fake = _FakeWinmem(regions=_regions(400))
        r = _run(fake, {"pid": 1, "max_regions": 400})
        check("the response still fits the (squeezed) frame",
              len(pc.pack_frame(r)) <= pc.MAX_FRAME_BYTES, True)
        check("truncation is DECLARED", r.get("truncated"), True)
        check("fewer regions were returned than found",
              len(r["regions"]) < r["region_count"], True)
        check("the TRUE count is preserved, not overwritten", r["region_count"], 400)
        check("scanned is still True (we did read the process)", r.get("scanned"), True)
    finally:
        pc.MAX_FRAME_BYTES = real_cap

    # CONTROL: with the real cap and the same input, truncation must NOT fire --
    # otherwise the test above would pass for the wrong reason.
    fake2 = _FakeWinmem(regions=_regions(400))
    r2 = _run(fake2, {"pid": 1, "max_regions": 400})
    check("CONTROL: no truncation at the real frame cap", r2.get("truncated"), False)
    check("CONTROL: all regions returned", len(r2["regions"]), 400)


def test_digest_reads_are_budgeted():
    """The appliance promises a bounded transient reservation for this work. A
    classifier hook that could read without limit would turn that promise into a
    guess, so the budget lives on the privileged side."""
    print("\n[the classifier's reader is capped in TOTAL, not per call]")
    fake = _FakeWinmem(regions=_regions(4), read_val=b"Q" * (1 << 20))
    got = {"total": 0, "exhausted": False}

    def greedy(pid, regions, reader):
        for _ in range(200):
            data = reader(0x10000, 1 << 20)
            if data is None:
                got["exhausted"] = True
                break
            got["total"] += len(data)

    r = _run(fake, {"pid": 1, "max_regions": 512}, classifier=greedy)
    check("the reader eventually refuses", got["exhausted"], True)
    check("total bytes never exceeded the budget",
          got["total"] <= privservice.MAX_DIGEST_BYTES, True)
    check("an exhausted budget returns None, not empty bytes", got["exhausted"], True)
    check("classification reported present", r.get("classification"), "present")


# ── the private classifier is optional and its absence is visible ────────────

def test_classifier_absence_is_reported_not_disguised():
    print("\n[no private classifier -> classification: absent, never a fake verdict]")
    fake = _FakeWinmem(regions=_regions(3))
    r = _run(fake, {"pid": 1, "max_regions": 512}, classifier=None)
    check("classification absent", r.get("classification"), "absent")
    check("but the raw region facts are still returned", len(r["regions"]), 3)
    check("and the target is still legitimately scanned", r.get("scanned"), True)


def test_a_failing_classifier_does_not_fake_success():
    print("\n[a classifier that raises is reported as error, not as absent or present]")
    fake = _FakeWinmem(regions=_regions(3))

    def boom(pid, regions, reader):
        raise RuntimeError("classifier exploded")

    r = _run(fake, {"pid": 1, "max_regions": 512}, classifier=boom)
    check("classification error", r.get("classification"), "error")
    check("acquisition itself still succeeded", r.get("scanned"), True)


def test_load_classifier_is_skip_if_absent():
    print("\n[load_classifier returns None on a public build, never raises]")
    check("returns None when the private module is absent",
          privservice.load_classifier(), None)


if __name__ == "__main__":
    print("inspect_pid - 3c action on the 3b channel")
    test_dispatch_stays_pure()
    test_validation_rejects_hostile_pids()
    test_caller_cannot_raise_the_region_cap()
    test_protected_target_is_never_counted_as_scanned()
    test_unopenable_target_is_not_scanned_either()
    test_readable_target_is_scanned()
    test_region_count_is_capped()
    test_response_is_bounded_by_measured_frame_size()
    test_truncation_actually_fires_and_is_declared()
    test_digest_reads_are_budgeted()
    test_classifier_absence_is_reported_not_disguised()
    test_a_failing_classifier_does_not_fake_success()
    test_load_classifier_is_skip_if_absent()

    print()
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS")
