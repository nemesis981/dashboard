#!/usr/bin/env python3
"""meminject_scan - platform-agnostic detector invocation seam. Tests.

Run: python3 /opt/nemesis/nemesis_agent/test_meminject_scan.py

Closes the gap that this seam was previously covered only indirectly (VM acceptance +
the classifier suite). Uses a FAKE acquisition layer and a fake classifier so every
branch runs deterministically off any platform.

Load-bearing properties:
  * skip-if-absent: no classifier -> classification 'absent', and NOTHING is read
  * an unopenable target reports its MEASURED state (protected/unavailable/undetermined),
    never 'absent' (which means 'no classifier') and never 'scanned'
  * the reader handed to the classifier is BUDGET-capped in total
  * an exception anywhere is caught -> classification 'error', never propagated
  * the token from open_target is always closed
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import meminject_scan as ms                                  # noqa: E402

_failures = []


def check(label, got, want):
    ok = got == want
    if not ok:
        _failures.append("%s: got %r, want %r" % (label, got, want))
    print("  %-62s %s%s" % (label, "PASS" if ok else "FAIL",
                            "" if ok else "  (got=%r want=%r)" % (got, want)))


class FakeAcq:
    """A stand-in acquisition layer with the shared open/iter/read/close shape."""
    READABLE, PROTECTED = "readable", "protected"
    UNAVAILABLE, UNDETERMINED = "unavailable", "undetermined"

    def __init__(self, open_state=None, regions=None, read_val=b"X" * 4096,
                 read_raises=False):
        self.open_state = open_state
        self.regions = regions if regions is not None else [{"base": 0x1000}]
        self.read_val = read_val
        self.read_raises = read_raises
        self.closed = 0
        self.read_total = 0

    def open_target(self, pid):
        return (None, self.open_state) if self.open_state else (pid, None)

    def iter_regions(self, token):
        return iter(self.regions)

    def read_bytes(self, token, base, size):
        if self.read_raises:
            raise RuntimeError("read exploded")
        self.read_total += size
        return self.read_val[:size]

    def close(self, token):
        self.closed += 1


class _patch:
    def __init__(self, **kw):
        self.kw, self.old = kw, {}

    def __enter__(self):
        for k, v in self.kw.items():
            self.old[k] = getattr(ms, k)
            setattr(ms, k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.old.items():
            setattr(ms, k, v)


def test_skip_if_absent_reads_nothing():
    print("\n[no classifier on this build -> absent, and nothing read]")
    acq = FakeAcq()
    with _patch(_acquisition=lambda: acq, load_classifier=lambda: None):
        v = ms.scan_pid(1234)
    check("classification absent", v["classification"], "absent")
    check("nothing was read (open_target never called for a scan)", acq.read_total, 0)
    check("no 'scanned' claim", v.get("scanned"), None)


def test_unopenable_target_reports_its_real_state():
    print("\n[an unopenable target reports its measured state, never 'absent']")
    for st in (FakeAcq.PROTECTED, FakeAcq.UNAVAILABLE, FakeAcq.UNDETERMINED):
        acq = FakeAcq(open_state=st)
        with _patch(_acquisition=lambda a=acq: a,
                    load_classifier=lambda: (lambda p, r, rd: {"suspicious": False})):
            v = ms.scan_pid(1234)
        check("state %s -> classification %s (not absent)" % (st, st),
              v["classification"], st)
        check("  scanned is False for %s" % st, v.get("scanned"), False)


def test_a_clean_scan_reports_present_and_closes_the_token():
    print("\n[a readable target: classifier runs, verdict merged, token closed]")
    acq = FakeAcq(regions=[{"base": 0x1000}, {"base": 0x2000}])
    seen = {}

    def clf(pid, regions, reader):
        seen["regions"] = len(list(regions))
        reader(0x1000, 4096)                      # exercise the reader
        return {"suspicious": True, "technique": "reflective-image-injection",
                "findings": [{"base": 0x1000}], "detector_version": "test/1"}

    with _patch(_acquisition=lambda: acq, load_classifier=lambda: clf):
        v = ms.scan_pid(4242)
    check("classification present", v["classification"], "present")
    check("suspicious surfaced", v["suspicious"], True)
    check("technique surfaced", v["technique"], "reflective-image-injection")
    check("region_count reported", v["region_count"], 2)
    check("token was closed exactly once", acq.closed, 1)


def test_inert_classifier_is_inert_not_present():
    print("\n[a classifier that returns nothing -> inert, token still closed]")
    acq = FakeAcq()
    with _patch(_acquisition=lambda: acq, load_classifier=lambda: (lambda p, r, rd: None)):
        v = ms.scan_pid(1)
    check("classification inert", v["classification"], "inert")
    check("token closed", acq.closed, 1)


def test_reader_is_budget_capped_in_total():
    print("\n[the reader handed to the classifier is capped at MAX_SCAN_BYTES total]")
    acq = FakeAcq(read_val=b"Z" * (1 << 20))
    got = {"total": 0, "refused": False}

    def greedy(pid, regions, reader):
        for _ in range(100):
            d = reader(0x1000, 1 << 20)
            if d is None:
                got["refused"] = True
                break
            got["total"] += len(d)
        return {"suspicious": False}

    with _patch(_acquisition=lambda: acq, load_classifier=lambda: greedy):
        ms.scan_pid(1)
    check("reader eventually refuses", got["refused"], True)
    check("total never exceeded MAX_SCAN_BYTES", got["total"] <= ms.MAX_SCAN_BYTES, True)


def test_exceptions_are_caught_not_propagated():
    print("\n[any error -> classification 'error', never raised out; token closed]")
    acq = FakeAcq(read_raises=True)

    def clf(pid, regions, reader):
        reader(0x1000, 16)                        # this raises inside the acq layer
        return {"suspicious": False}

    with _patch(_acquisition=lambda: acq, load_classifier=lambda: clf):
        v = ms.scan_pid(1)
    check("classification error", v["classification"], "error")
    check("token still closed despite the error", acq.closed, 1)


def test_unsupported_platform():
    print("\n[no acquisition layer (unsupported platform) -> undetermined]")
    with _patch(_acquisition=lambda: None):
        v = ms.scan_pid(1)
    check("classification undetermined", v["classification"], "undetermined")


def test_sweep_aggregates_and_caps():
    print("\n[sweep: aggregates scanned/suspicious, caps the findings list]")
    acq = FakeAcq(regions=[{"base": 0x1000}])
    # classifier flags every scanned pid -> forces the cap to engage
    flag = lambda p, r, rd: {"suspicious": True, "technique": "reflective-image-injection",
                             "findings": [{"base": 0x1000}]}
    pids = list(range(1000, 1000 + ms.MAX_REPORTED_FINDINGS + 15))
    with _patch(_acquisition=lambda: acq, load_classifier=lambda: flag):
        summ = ms.sweep(pids=pids, classifier=flag)
    check("classifier present", summ["classifier"], "present")
    check("scanned all pids", summ["scanned"], len(pids))
    check("all flagged suspicious", summ["suspicious"], len(pids))
    check("findings list capped at MAX_REPORTED_FINDINGS",
          len(summ["findings"]), ms.MAX_REPORTED_FINDINGS)
    check("truncation is flagged, not silent", summ["findings_truncated"], True)


def test_sweep_counts_unscannable_by_state():
    print("\n[sweep: unscannable processes are counted by state, never dropped]")
    acq = FakeAcq(open_state=FakeAcq.PROTECTED)
    with _patch(_acquisition=lambda: acq,
                load_classifier=lambda: (lambda p, r, rd: {"suspicious": False})):
        summ = ms.sweep(pids=[10, 11, 12], classifier=lambda p, r, rd: {"suspicious": False})
    check("nothing scanned (all protected)", summ["scanned"], 0)
    check("protected counted", summ["not_scanned"].get("protected"), 3)


def test_sweep_skip_if_absent():
    print("\n[sweep: no classifier -> reports absent, scans nothing]")
    acq = FakeAcq()
    with _patch(_acquisition=lambda: acq, load_classifier=lambda: None):
        summ = ms.sweep(pids=[1, 2, 3])
    check("classifier absent", summ["classifier"], "absent")
    check("scanned 0", summ["scanned"], 0)


def test_sweep_excludes_self():
    print("\n[sweep: never scans its own pid]")
    import os
    acq = FakeAcq(regions=[{"base": 0x1000}])
    seen = []
    def clf(p, r, rd):
        seen.append(p); return {"suspicious": False}
    with _patch(_acquisition=lambda: acq, load_classifier=lambda: clf):
        ms.sweep(pids=[os.getpid(), 424242], classifier=clf)
    check("own pid excluded from the sweep", os.getpid() in seen, False)
    check("the other pid was scanned", 424242 in seen, True)


if __name__ == "__main__":
    print("meminject_scan - invocation seam")
    test_skip_if_absent_reads_nothing()
    test_unopenable_target_reports_its_real_state()
    test_a_clean_scan_reports_present_and_closes_the_token()
    test_inert_classifier_is_inert_not_present()
    test_reader_is_budget_capped_in_total()
    test_exceptions_are_caught_not_propagated()
    test_unsupported_platform()
    test_sweep_aggregates_and_caps()
    test_sweep_counts_unscannable_by_state()
    test_sweep_skip_if_absent()
    test_sweep_excludes_self()

    print()
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS")
