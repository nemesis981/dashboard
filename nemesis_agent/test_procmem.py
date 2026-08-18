"""Validation for procmem — the per-process memory sampler.

Run:  python3 nemesis_agent/test_procmem.py

THE PROPERTY THAT MATTERS MOST IS NOT "does it report numbers". It is that the
numbers it reports are the ones it actually measured, and that everything it
could NOT measure is visible as such. A sampler that quietly substitutes RSS for
USS, or sums a partial component and calls it a total, produces figures that look
exactly like real measurements to the budget and recovery layers built on top —
and those layers would then kill processes based on them.

So every check below pairs with a control that can fail in the other direction.
"""

import ast
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import procmem  # noqa: E402

_failures = []


def check(label, got, want):
    if got != want:
        _failures.append("%s: got %r, want %r" % (label, got, want))
        print("  FAIL  %s: got %r, want %r" % (label, got, want))
    else:
        print("  ok    %s" % label)


# ── fakes: deterministic, so the assertions are exact ────────────────────────

class _MI:
    def __init__(self, rss):
        self.rss = rss


class _Full:
    def __init__(self, uss):
        self.uss = uss


class _Proc:
    def __init__(self, pid, name, rss_mb, uss_mb=None, raises=False,
                 user="u"):
        self.info = {"pid": pid, "ppid": 1, "name": name, "username": user,
                     "create_time": 1.0,
                     "memory_info": _MI(int(rss_mb * 1024 * 1024))}
        self._uss = uss_mb
        self._raises = raises

    def memory_full_info(self):
        if self._raises or self._uss is None:
            raise PermissionError("access denied")
        return _Full(int(self._uss * 1024 * 1024))


class _VM:
    total = 8 * 1024 ** 3
    available = 4 * 1024 ** 3


def _fake(procs):
    class _P:
        @staticmethod
        def process_iter(*_a, **_k):
            return list(procs)

        @staticmethod
        def virtual_memory():
            return _VM()
    return _P


# ── the core correctness property ────────────────────────────────────────────

def test_incomplete_component_uss_is_none():
    """A partial sum must NOT be presented as a component total."""
    print("\n[a component with an unmeasured member reports uss_mb=None]")
    procs = [_Proc(1, "svc", 100.0, uss_mb=80.0),
             _Proc(2, "svc", 100.0, uss_mb=None)]      # unreadable
    s = procmem.sample_processes(classifier=lambda r: "svc",
                                 uss_min_rss_mb=1.0, _psutil=_fake(procs))
    c = s["components"]["svc"]
    check("uss_complete is False", c["uss_complete"], False)
    check("uss_mb is None, NOT the partial 80.0", c["uss_mb"], None)
    check("rss still reported (it was fully measured)", c["rss_mb"], 200.0)
    check("uss_state reports partial", s["uss_state"], procmem.USS_PARTIAL)


def test_complete_component_uss_is_a_number():
    """CONTROL: a sampler that always returned None would pass the test above."""
    print("\n[CONTROL: a fully-measured component DOES report a uss total]")
    procs = [_Proc(1, "svc", 100.0, uss_mb=80.0),
             _Proc(2, "svc", 100.0, uss_mb=70.0)]
    s = procmem.sample_processes(classifier=lambda r: "svc",
                                 uss_min_rss_mb=1.0, _psutil=_fake(procs))
    c = s["components"]["svc"]
    check("uss_complete is True", c["uss_complete"], True)
    check("uss_mb is the real sum", c["uss_mb"], 150.0)
    check("uss_state is measured", s["uss_state"], procmem.USS_MEASURED)


def test_uss_is_never_backfilled_from_rss():
    """The substitution that would silently inflate 'unique' with shared pages."""
    print("\n[an unreadable USS stays None — never filled in from RSS]")
    procs = [_Proc(1, "svc", 500.0, uss_mb=None)]
    s = procmem.sample_processes(classifier=lambda r: "svc",
                                 uss_min_rss_mb=1.0, _psutil=_fake(procs))
    row = s["processes"][0]
    check("process uss_mb is None", row["uss_mb"], None)
    check("...and is not equal to its rss", row["uss_mb"] == row["rss_mb"], False)
    check("rss was measured", row["rss_mb"], 500.0)


# ── failure is reported as failure ───────────────────────────────────────────

def test_enumeration_failure_is_unavailable_not_empty():
    print("\n[enumeration failure -> unavailable, never an empty process list]")

    class _Broken:
        @staticmethod
        def process_iter(*_a, **_k):
            raise RuntimeError("boom")

        @staticmethod
        def virtual_memory():
            return _VM()

    s = procmem.sample_processes(_psutil=_Broken)
    check("state", s["state"], procmem.STATE_UNAVAILABLE)
    check("no processes invented", s["processes"], [])
    check("reason is carried", "boom" in (s["reason"] or ""), True)
    check("total_seen is None, not 0", s["total_seen"], None)


def test_unreadable_processes_are_counted_not_dropped():
    print("\n[unreadable processes are counted, and downgrade the state]")

    class _Bad:
        info = property(lambda self: (_ for _ in ()).throw(OSError("gone")))

    procs = [_Proc(1, "ok", 10.0, uss_mb=5.0), _Bad()]
    s = procmem.sample_processes(classifier=lambda r: "c",
                                 uss_min_rss_mb=1.0, _psutil=_fake(procs))
    check("denied counted", s["denied"], 1)
    check("state downgraded to partial", s["state"], procmem.STATE_PARTIAL)
    check("the readable one still reported", s["reported"], 1)
    check("total_seen counts both", s["total_seen"], 2)


def test_clean_sample_is_ok():
    """CONTROL: a sampler that always said 'partial' would pass the above."""
    print("\n[CONTROL: a fully readable sample reports ok, denied=0]")
    procs = [_Proc(1, "a", 10.0, uss_mb=5.0), _Proc(2, "b", 20.0, uss_mb=9.0)]
    s = procmem.sample_processes(classifier=lambda r: r["name"],
                                 uss_min_rss_mb=1.0, _psutil=_fake(procs))
    check("state ok", s["state"], procmem.STATE_OK)
    check("denied zero", s["denied"], 0)
    check("both components present", sorted(s["components"]), ["a", "b"])


# ── the injected seam ────────────────────────────────────────────────────────

def test_classifier_drives_attribution_and_cannot_sink_the_sample():
    print("\n[the classifier seam is real, and its failures are contained]")
    procs = [_Proc(1, "x", 10.0, uss_mb=5.0), _Proc(2, "y", 10.0, uss_mb=5.0)]
    s = procmem.sample_processes(classifier=lambda r: "unit-" + r["name"],
                                 uss_min_rss_mb=1.0, _psutil=_fake(procs))
    check("attribution used the injected classifier",
          sorted(s["components"]), ["unit-x", "unit-y"])

    def _boom(_r):
        raise ValueError("classifier blew up")

    s2 = procmem.sample_processes(classifier=_boom, uss_min_rss_mb=1.0,
                                 _psutil=_fake(procs))
    check("a broken classifier does not sink the sample",
          s2["state"], procmem.STATE_OK)
    check("...its processes land in 'unclassified'",
          list(s2["components"]), ["unclassified"])


def test_no_appliance_specifics_leaked_into_the_generic_core():
    """The cross-platform requirement, enforced rather than intended."""
    print("\n[the generic sampler contains no appliance/platform specifics]")
    here = os.path.dirname(os.path.abspath(__file__))
    src = open(os.path.join(here, "procmem.py")).read()
    # AST, not line-prefix filtering. A prefix filter left the module docstring
    # in and flagged the sentence "no clamd, no systemd, no unit names" as an
    # appliance specific in the code -- a test failing on its own documentation.
    # ast.parse drops comments, and popping the leading string Expr from every
    # scope drops docstrings, so what remains is exclusively real code.
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            body = getattr(node, "body", None)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                body.pop(0)
    code = ast.unparse(tree)
    for token in ("clamd", "systemctl", "systemd", "/etc/systemd", "ufw"):
        check("no %r in the generic core" % token, token in code, False)
    # CONTROL: prove the extractor is reading real code, not an empty string.
    check("CONTROL code body was extracted", "def sample_processes" in code, True)


def test_self_test_runs_against_the_real_platform():
    print("\n[the module's own premise-proof passes on this host]")
    st = procmem.self_test()
    for f in st["findings"]:
        print("        finding: %s" % f)
    check("self_test ok", st["ok"], True)


if __name__ == "__main__":
    print("procmem — per-process memory sampling")
    test_incomplete_component_uss_is_none()
    test_complete_component_uss_is_a_number()
    test_uss_is_never_backfilled_from_rss()
    test_enumeration_failure_is_unavailable_not_empty()
    test_unreadable_processes_are_counted_not_dropped()
    test_clean_sample_is_ok()
    test_classifier_drives_attribution_and_cannot_sink_the_sample()
    test_no_appliance_specifics_leaked_into_the_generic_core()
    test_self_test_runs_against_the_real_platform()

    print("\n" + "=" * 62)
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  - %s" % f)
        sys.exit(1)
    print("ALL PASS")
