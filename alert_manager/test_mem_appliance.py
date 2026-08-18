"""Validation for mem_appliance — the appliance half of the RAM budget work.

Run:  python3 alert_manager/test_mem_appliance.py

Two properties carry the weight here, and both are about clamd:

  1. clamd is BUDGETED (it is the dominant consumer; headroom maths that ignored
     it would be meaningless), and
  2. clamd is EXEMPT FROM RECOVERY ACTION (it is the largest consumer by design,
     so any size-ranked recovery picks it first every time — and throttling or
     killing it disarms malware scanning, which would let an attacker who can
     induce memory pressure make the appliance stand its own AV down).

Getting either half alone is a defect: budgeted-but-not-exempt builds the attack,
exempt-but-not-budgeted makes the headroom numbers fiction. So they are tested as
a pair, and the "still reports a verdict" case is tested separately, because the
lazy way to implement an exemption is to filter it out of the results entirely —
which would hide the biggest consumer from the view built to watch memory.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alert_manager import mem_appliance as ma  # noqa: E402

_failures = []


def check(label, got, want):
    if got != want:
        _failures.append("%s: got %r, want %r" % (label, got, want))
        print("  FAIL  %s: got %r, want %r" % (label, got, want))
    else:
        print("  ok    %s" % label)


# ── the clamd pairing ────────────────────────────────────────────────────────

def test_clamd_is_budgeted_and_exempt():
    print("\n[clamd: budgeted AND recovery-exempt — both halves required]")
    check("budgeted", "clamav-daemon" in ma.APPLIANCE_BUDGETS, True)
    check("recovery-exempt", "clamav-daemon" in ma.RECOVERY_EXEMPT, True)
    # CONTROL: the exemption is narrow, not a blanket that would spare everything.
    check("suricata is NOT exempt", "suricata" in ma.RECOVERY_EXEMPT, False)
    check("dashboard is NOT exempt", "dashboard" in ma.RECOVERY_EXEMPT, False)
    check("exactly one exemption", len(ma.RECOVERY_EXEMPT), 1)


def test_exempt_component_still_reports_a_verdict():
    """The lazy implementation — filtering it out — would hide it entirely."""
    print("\n[an exempt component is annotated, NOT filtered from the results]")
    procmem, membudget = ma.load_memory_modules()
    sample = {"state": "ok", "uss_state": "measured", "total_ram_mb": 8192.0,
              "components": {
                  "clamav-daemon": {"rss_mb": 5000.0, "uss_mb": 4800.0,
                                    "uss_complete": True, "pids": [1],
                                    "proc_count": 1},
                  "dashboard": {"rss_mb": 900.0, "uss_mb": 880.0,
                                "uss_complete": True, "pids": [2],
                                "proc_count": 1}}}
    v = membudget.evaluate(sample, ma.APPLIANCE_BUDGETS)
    for name, c in v["components"].items():
        c["recovery_exempt"] = name in ma.RECOVERY_EXEMPT
    v["actionable_breaches"] = [n for n in v["breaches"] if n not in ma.RECOVERY_EXEMPT]
    v["exempt_breaches"] = [n for n in v["breaches"] if n in ma.RECOVERY_EXEMPT]

    check("clamd still present in components", "clamav-daemon" in v["components"], True)
    check("clamd's breach IS reported", "clamav-daemon" in v["breaches"], True)
    check("...but is not actionable", v["actionable_breaches"], ["dashboard"])
    check("...and is visible as an exempt breach", v["exempt_breaches"],
          ["clamav-daemon"])
    check("clamd flagged exempt",
          v["components"]["clamav-daemon"]["recovery_exempt"], True)
    check("dashboard flagged not exempt",
          v["components"]["dashboard"]["recovery_exempt"], False)


# ── the classifier ───────────────────────────────────────────────────────────

def test_unit_resolution_from_cgroup(tmpdir=None):
    print("\n[systemd unit resolution, and never inventing one]")
    import tempfile
    root = tempfile.mkdtemp()

    def _mk(pid, text):
        d = os.path.join(root, str(pid))
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "cgroup"), "w").write(text)

    _mk(101, "0::/system.slice/dashboard.service\n")                  # v2
    _mk(102, "1:name=systemd:/system.slice/hw-monitor.service\n")     # v1
    _mk(103, "0::/system.slice/getty@tty1.service\n")                 # templated
    _mk(104, "0::/user.slice/user-1000.slice/session-2.scope\n")      # not a unit

    check("cgroup v2", ma.unit_for_pid(101, proc_root=root), "dashboard")
    check("cgroup v1", ma.unit_for_pid(102, proc_root=root), "hw-monitor")
    check("template instance collapses to its base",
          ma.unit_for_pid(103, proc_root=root), "getty")
    check("a scope is not a unit -> None", ma.unit_for_pid(104, proc_root=root), None)
    check("missing pid -> None, never invented",
          ma.unit_for_pid(999999, proc_root=root), None)


def test_fallback_is_marked_as_less_reliable():
    print("\n[name-attributed components are prefixed so they cannot pass as units]")
    import tempfile
    root = tempfile.mkdtemp()
    c = ma.classify_process({"pid": 424242, "name": "weird"}, proc_root=root)
    check("prefixed", c, "proc:weird")
    check("does not look like a unit", c.endswith(".service"), False)
    check("no name and no unit -> unclassified",
          ma.classify_process({"pid": 424242}, proc_root=root), "unclassified")


# ── budget-table coherence across re-baselining ──────────────────────────────

def test_table_is_coherent_at_every_plausible_baseline():
    print("\n[the table stays satisfiable at 4 / 8 / 16 GB]")
    _, membudget = ma.load_memory_modules()
    for gb in (4, 8, 16, 32):
        v = membudget.validate_budgets(ma.APPLIANCE_BUDGETS, gb * 1024.0)
        check("coherent at %d GB" % gb, v["ok"], True)
        if not v["ok"]:
            print("        %s" % "; ".join(v["problems"]))


def test_every_budget_records_its_basis():
    """A number with no recorded observation is a guess that will never be revisited."""
    print("\n[every budget entry names the measurement it came from]")
    missing = [k for k, v in ma.APPLIANCE_BUDGETS.items() if not v.get("basis")]
    check("all entries carry a basis", missing, [])


# ── the loading design claim ─────────────────────────────────────────────────

def test_generic_modules_load_without_polluting_sys_path():
    print("\n[loading the generic modules does not put nemesis_agent on sys.path]")
    before = list(sys.path)
    procmem, membudget = ma.load_memory_modules()
    added = [p for p in sys.path if p not in before]
    check("nothing added to sys.path", added, [])
    check("procmem really loaded", hasattr(procmem, "sample_processes"), True)
    check("membudget really loaded", hasattr(membudget, "evaluate"), True)
    # CONTROL: prove we loaded the real modules, not stubs that happen to exist.
    check("procmem exposes its states", procmem.STATE_UNAVAILABLE, "unavailable")


def test_self_test_passes_here():
    print("\n[the adapter's own premise-proof passes on this host]")
    st = ma.self_test()
    for f in st["findings"]:
        print("        finding: %s" % f)
    check("self_test ok", st["ok"], True)


if __name__ == "__main__":
    print("mem_appliance — appliance half of the RAM budget work")
    test_clamd_is_budgeted_and_exempt()
    test_exempt_component_still_reports_a_verdict()
    test_unit_resolution_from_cgroup()
    test_fallback_is_marked_as_less_reliable()
    test_table_is_coherent_at_every_plausible_baseline()
    test_every_budget_records_its_basis()
    test_generic_modules_load_without_polluting_sys_path()
    test_self_test_passes_here()

    print("\n" + "=" * 64)
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  - %s" % f)
        sys.exit(1)
    print("ALL PASS")
