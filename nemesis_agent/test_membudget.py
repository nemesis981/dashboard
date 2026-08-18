"""Validation for membudget — the RAM budget / deviation model.

Run:  python3 nemesis_agent/test_membudget.py

THE CHECK THAT MATTERS MOST is the RSS/USS asymmetry, because getting it wrong
is silent and one-directional. USS is a subset of RSS, so:

    RSS <= budget  =>  a definite pass, even with no privileged read
    RSS >  budget  =>  proves nothing; the excess may be entirely shared pages

A model that treated the second case as a breach would throttle services that are
comfortably inside their real budget — every Python service on the box shares
libpython, and that shared page count would be charged to each of them
separately. It would look like a working detector, on a fleet that was fine.

So the asymmetry is tested in BOTH directions, and each verdict has a control
proving the model can also return the opposite.
"""

import ast
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import membudget as mb  # noqa: E402

_failures = []


def check(label, got, want):
    if got != want:
        _failures.append("%s: got %r, want %r" % (label, got, want))
        print("  FAIL  %s: got %r, want %r" % (label, got, want))
    else:
        print("  ok    %s" % label)


def sample(total_mb=8192.0, **comps):
    """comps: name=(rss, uss_or_None)"""
    out = {}
    for name, (rss, uss) in comps.items():
        out[name] = {"rss_mb": rss, "uss_mb": uss,
                     "uss_complete": uss is not None,
                     "pids": [1], "proc_count": 1}
    return {"state": "ok", "uss_state": "measured", "total_ram_mb": total_mb,
            "components": out}


# ── the asymmetry ────────────────────────────────────────────────────────────

def test_rss_over_a_uss_budget_is_not_a_breach():
    """THE test. Shared pages must never be charged as a component's own cost."""
    print("\n[rss over a USS budget -> INDETERMINATE, never BREACH]")
    budgets = {"svc": {"pct": 1.0}}                       # 81.92 MB of 8 GB
    r = mb.evaluate(sample(svc=(500.0, None)), budgets)
    c = r["components"]["svc"]
    check("verdict", c["verdict"], mb.INDETERMINATE)
    check("not counted as a breach", r["breaches"], [])
    check("listed as needing a privileged read", r["indeterminate"], ["svc"])
    check("basis recorded as rss, not uss", c["basis"], mb.MEASURE_RSS)
    check("CAP_SYS_PTRACE named in the detail",
          "CAP_SYS_PTRACE" in c["detail"], True)


def test_a_real_uss_breach_is_a_breach():
    """CONTROL: a model that never said BREACH would pass the test above."""
    print("\n[CONTROL: a measured USS over budget IS a breach]")
    budgets = {"svc": {"pct": 1.0}}
    r = mb.evaluate(sample(svc=(500.0, 400.0)), budgets)
    c = r["components"]["svc"]
    check("verdict", c["verdict"], mb.BREACH)
    check("breach listed", r["breaches"], ["svc"])
    check("basis is uss", c["basis"], mb.MEASURE_USS)
    check("over_by reported", round(c["over_by_mb"]), 318)


def test_rss_under_a_uss_budget_is_a_definite_pass():
    """The inference that makes this usable unprivileged."""
    print("\n[rss under a USS budget -> OK without any privileged read]")
    budgets = {"svc": {"pct": 5.0}}                       # 409.6 MB
    r = mb.evaluate(sample(svc=(100.0, None)), budgets)
    c = r["components"]["svc"]
    check("verdict", c["verdict"], mb.OK)
    check("not indeterminate", r["indeterminate"], [])
    check("detail explains the subset argument",
          "subset of RSS" in c["detail"], True)


def test_measured_uss_under_budget_is_ok():
    print("\n[CONTROL: a measured USS under budget is plainly OK]")
    r = mb.evaluate(sample(svc=(100.0, 60.0)), {"svc": {"pct": 5.0}})
    check("verdict", r["components"]["svc"]["verdict"], mb.OK)
    check("basis is uss", r["components"]["svc"]["basis"], mb.MEASURE_USS)


# ── percentages, and the fixed-cost problem ──────────────────────────────────

def test_budget_scales_with_the_machine():
    """The provisional-8GB requirement: no edit needed when the baseline moves."""
    print("\n[the same pct resolves differently on different machines]")
    spec = {"pct": 10.0}
    check("4 GB", mb.resolve_budget_mb(spec, 4096.0)[0], 409.6)
    check("8 GB", mb.resolve_budget_mb(spec, 8192.0)[0], 819.2)
    check("16 GB", mb.resolve_budget_mb(spec, 16384.0)[0], 1638.4)


def test_max_mb_clamp_handles_fixed_cost_components():
    """clamd costs ~968 MB regardless of machine size."""
    print("\n[a fixed-cost component is clamped, not scaled absurdly]")
    spec = {"pct": 24.0, "max_mb": 1200.0}
    check("on 4 GB the pct governs", mb.resolve_budget_mb(spec, 4096.0)[0], 983.04)
    check("on 16 GB the clamp governs", mb.resolve_budget_mb(spec, 16384.0)[0], 1200.0)
    # Without the clamp the same component would be handed ~3.9 GB on a 16 GB box.
    check("CONTROL unclamped would be absurd",
          mb.resolve_budget_mb({"pct": 24.0}, 16384.0)[0], 3932.16)


def test_min_mb_clamp_protects_small_machines():
    print("\n[a floor keeps a small box from an unmeetable budget]")
    spec = {"pct": 1.0, "min_mb": 120.0}
    check("floor applies on 4 GB", mb.resolve_budget_mb(spec, 4096.0)[0], 120.0)
    check("pct applies once large enough",
          mb.resolve_budget_mb(spec, 32768.0)[0], 327.68)


# ── refusing to fabricate ────────────────────────────────────────────────────

def test_unknown_total_ram_is_not_guessed():
    print("\n[unknown machine total -> INDETERMINATE, never an assumed size]")
    mbv, reason = mb.resolve_budget_mb({"pct": 10.0}, None)
    check("no number invented", mbv, None)
    check("reason given", "unknown" in (reason or ""), True)
    s = sample(svc=(100.0, 50.0))
    s["total_ram_mb"] = None
    r = mb.evaluate(s, {"svc": {"pct": 10.0}})
    check("verdict is indeterminate",
          r["components"]["svc"]["verdict"], mb.INDETERMINATE)
    check("not a breach", r["breaches"], [])


def test_unavailable_sample_is_not_a_clean_bill():
    print("\n[an unavailable sample is not 'everything is fine']")
    r = mb.evaluate({"state": "unavailable", "reason": "boom"}, {"svc": {"pct": 1}})
    check("state carried", r["state"], "unavailable")
    check("no components judged", r["components"], {})
    check("no breaches claimed", r["breaches"], [])


def test_unbudgeted_is_distinct_from_ok():
    print("\n[a component nobody budgeted has not passed anything]")
    r = mb.evaluate(sample(mystery=(900.0, 850.0)), {"svc": {"pct": 1.0}})
    check("verdict", r["components"]["mystery"]["verdict"], mb.UNBUDGETED)
    check("it is not OK", r["components"]["mystery"]["verdict"] == mb.OK, False)


def test_budgeted_but_absent_is_surfaced():
    print("\n[a budgeted service that is not running is reported, not passed]")
    r = mb.evaluate(sample(other=(10.0, 5.0)),
                    {"svc": {"pct": 1.0}, "other": {"pct": 1.0}})
    check("absent service listed", r["budgeted_but_absent"], ["svc"])
    check("it did not silently pass", "svc" in r["components"], False)


# ── budget-set coherence ─────────────────────────────────────────────────────

def test_overcommitted_budget_set_is_refused():
    print("\n[a budget set larger than the machine is refused at authoring]")
    v = mb.validate_budgets({"a": {"pct": 60.0}, "b": {"pct": 60.0}}, 8192.0)
    check("not ok", v["ok"], False)
    check("problem names the overcommit",
          any("unsatisfiable" in p for p in v["problems"]), True)


def test_sane_budget_set_validates():
    """CONTROL: a validator that rejected everything would pass the above."""
    print("\n[CONTROL: a sane budget set validates cleanly]")
    v = mb.validate_budgets({"a": {"pct": 10.0}, "b": {"pct": 5.0}}, 8192.0)
    check("ok", v["ok"], True)
    check("no problems", v["problems"], [])
    check("committed total", v["committed_mb"], 1228.8)


# ── structural guarantees ────────────────────────────────────────────────────

def test_model_is_pure_and_platform_neutral():
    print("\n[the model is pure: no I/O, no clock, no platform specifics]")
    here = os.path.dirname(os.path.abspath(__file__))
    tree = ast.parse(open(os.path.join(here, "membudget.py")).read())
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            b = getattr(node, "body", None)
            if (b and isinstance(b[0], ast.Expr)
                    and isinstance(b[0].value, ast.Constant)
                    and isinstance(b[0].value.value, str)):
                b.pop(0)
    code = ast.unparse(tree)
    for bad in ("import os", "import time", "import sqlite3", "open(",
                "subprocess", "psutil", "clamd", "systemctl"):
        check("no %r in the model" % bad, bad in code, False)
    check("CONTROL the model body was extracted", "def evaluate" in code, True)


def test_self_test_passes():
    print("\n[the module's own premise-proof passes]")
    st = mb.self_test()
    for f in st["findings"]:
        print("        finding: %s" % f)
    check("self_test ok", st["ok"], True)


if __name__ == "__main__":
    print("membudget — RAM budget / deviation model")
    test_rss_over_a_uss_budget_is_not_a_breach()
    test_a_real_uss_breach_is_a_breach()
    test_rss_under_a_uss_budget_is_a_definite_pass()
    test_measured_uss_under_budget_is_ok()
    test_budget_scales_with_the_machine()
    test_max_mb_clamp_handles_fixed_cost_components()
    test_min_mb_clamp_protects_small_machines()
    test_unknown_total_ram_is_not_guessed()
    test_unavailable_sample_is_not_a_clean_bill()
    test_unbudgeted_is_distinct_from_ok()
    test_budgeted_but_absent_is_surfaced()
    test_overcommitted_budget_set_is_refused()
    test_sane_budget_set_validates()
    test_model_is_pure_and_platform_neutral()
    test_self_test_passes()

    print("\n" + "=" * 64)
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  - %s" % f)
        sys.exit(1)
    print("ALL PASS")
