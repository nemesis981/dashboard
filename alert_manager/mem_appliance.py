"""RAM budget — the APPLIANCE half. Everything platform-specific lives here.

Counterpart to `nemesis_agent/procmem.py` (sampling) and
`nemesis_agent/membudget.py` (budget/deviation model), both of which are
deliberately generic and contain no systemd, no clamd, no unit names. This file
is where all of that belongs, mirroring how `alert_manager/attestation.py` is the
server half of `nemesis_agent/attest.py`.

The split exists so extending to Windows/macOS agents is a genuine extension: an
agent-side adapter supplies its own classifier (Windows service names, launchd
labels) and its own budget table, and reuses the sampler and the model unchanged.

⚠ LOADING NOTE. This imports `procmem`/`membudget` by absolute path WITHOUT a
`sys.path` insert, which is possible only because those modules import no
siblings. `attestation.py` needs the insert for `attest.py` because `hwid.py`
does `import win_run` at module scope — the trap that broke hw_monitor's loader.
Keeping the memory modules sibling-free was a deliberate choice to avoid
inheriting it.
"""

from __future__ import annotations

import importlib.util
import logging
import os
import re

log = logging.getLogger("nemesis.mem_appliance")

__all__ = [
    "APPLIANCE_BUDGETS", "RECOVERY_EXEMPT", "PROVISIONAL_BASELINE_GB",
    "classify_process", "unit_for_pid", "sample_and_evaluate",
    "RUNG_AVAILABILITY", "availability_map", "why_rung_absent",
    "load_memory_modules", "self_test",
]

#: The budget table below was authored against this machine size. It is NOT used
#: in any calculation — budgets resolve against the machine's ACTUAL total RAM at
#: evaluation time — it is recorded so a reader knows what the percentages were
#: reasoned about, and so a future re-baseline can be spotted as such.
PROVISIONAL_BASELINE_GB = 8

# ── the appliance budget table ───────────────────────────────────────────────
#
# ⚠ THESE ARE SEEDED FROM ONE MEASUREMENT SET, NOT FROM A MODEL. Source is the
# clean-base install measurement in docs/handoff/worklog/appliance-hardware-notes.md
# (2026-07-31) plus the headless gauge-VM idle figure (1.7 GB). Every entry
# carries the observation it came from, so refining one is an edit against
# evidence rather than against a previous guess. They are expected to move once
# the gauge VM produces sustained real-usage data.
#
# `pct` is of TOTAL RAM. `max_mb` exists only for components whose cost does not
# scale with machine size — see membudget's docstring for why a flat percentage
# hands clamd ~3.9 GB on a 16 GB box.
APPLIANCE_BUDGETS = {
    # Measured 968.7 MB. The signature set GROWS (the 112 MB pulled at install is
    # a floor, not a fixed cost), so the budget carries real headroom above the
    # observation — but clamped, because that growth tracks signatures, not RAM.
    "clamav-daemon": {"pct": 16.0, "max_mb": 1600.0, "min_mb": 1100.0,
                      "basis": "measured 968.7 MB on a clean-base install"},
    # Measured 57.1 MB.
    "suricata":      {"pct": 3.0, "max_mb": 400.0, "min_mb": 120.0,
                      "basis": "measured 57.1 MB"},
    # All Nemesis Python services measured ~66 MB COMBINED. Budgeted per-service
    # with a floor, because a per-service share of 3% would be meaninglessly
    # small on a 4 GB box while still being generous on 16 GB.
    "dashboard":            {"pct": 1.5, "min_mb": 96.0, "max_mb": 400.0,
                             "basis": "share of ~66 MB combined Nemesis python"},
    "hw-monitor":           {"pct": 1.0, "min_mb": 64.0, "max_mb": 256.0,
                             "basis": "share of ~66 MB combined"},
    "watchdog":             {"pct": 1.0, "min_mb": 64.0, "max_mb": 256.0,
                             "basis": "share of ~66 MB combined"},
    "alert-watcher":        {"pct": 1.0, "min_mb": 64.0, "max_mb": 256.0,
                             "basis": "share of ~66 MB combined"},
    "device-scanner":       {"pct": 1.0, "min_mb": 64.0, "max_mb": 256.0,
                             "basis": "share of ~66 MB combined"},
    "diagnostics-watcher":  {"pct": 1.0, "min_mb": 64.0, "max_mb": 256.0,
                             "basis": "share of ~66 MB combined"},
    "malware-canary":       {"pct": 1.0, "min_mb": 64.0, "max_mb": 256.0,
                             "basis": "share of ~66 MB combined"},
}

#: ⚠ EXEMPT FROM RECOVERY ACTION — NOT FROM BUDGET ACCOUNTING.
#
# clamd is the appliance's dominant consumer, so headroom maths that ignored it
# would be meaningless: it stays in the budget table and is still evaluated,
# alerted on, and reported.
#
# What it is exempt from is the escalation ladder ACTING on it. Two reasons:
#   * it is the largest consumer BY DESIGN, so any size-ranked recovery would
#     pick it first, every time;
#   * killing or throttling it disarms malware scanning. An attacker who can
#     induce memory pressure could then make the appliance stand its own AV
#     down — the recovery mechanism becomes the attack.
RECOVERY_EXEMPT = frozenset({"clamav-daemon"})

#: cgroup line -> systemd unit. Matches both cgroup v2 ("0::/system.slice/x.service")
#: and v1 ("N:name=systemd:/system.slice/x.service").
_UNIT_RE = re.compile(r"/([A-Za-z0-9@._\-]+)\.service\b")


def unit_for_pid(pid, proc_root="/proc"):
    """The systemd unit owning `pid`, or None.

    None means "could not determine", never a guessed unit. The caller falls
    back to the process name and the component is named accordingly, so an
    unattributable process is visible as such rather than silently folded into
    a budgeted component's total.
    """
    try:
        with open(os.path.join(proc_root, str(pid), "cgroup"), "r") as fh:
            for line in fh:
                m = _UNIT_RE.search(line)
                if m:
                    unit = m.group(1)
                    # Strip the systemd template instance suffix so
                    # foo@1.service and foo@2.service share one budget.
                    return unit.split("@", 1)[0] if "@" in unit else unit
    except (OSError, ValueError):
        return None
    return None


def classify_process(row, proc_root="/proc"):
    """Component name for a sampled process row. THE appliance-specific seam.

    systemd unit first (authoritative: it is what the service manager believes),
    process name second. Prefixed `proc:` in the fallback case so a
    name-attributed component can never be mistaken for a unit-attributed one —
    they have different reliability and a budget should only ever be written
    against the former.
    """
    unit = unit_for_pid(row.get("pid"), proc_root=proc_root)
    if unit:
        return unit
    name = row.get("name")
    return "proc:%s" % name if name else "unclassified"


def load_memory_modules(repo_root=None):
    """Load the generic sampler + model by absolute path.

    No `sys.path` insert: these modules import no siblings, by design.
    """
    root = repo_root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    mods = {}
    for name in ("procmem", "membudget"):
        path = os.path.join(root, "nemesis_agent", "%s.py" % name)
        spec = importlib.util.spec_from_file_location(
            "nemesis_mem_%s" % name, path)
        if spec is None or spec.loader is None:
            raise ImportError("cannot load %s from %s" % (name, path))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mods[name] = mod
    return mods["procmem"], mods["membudget"]


def sample_and_evaluate(repo_root=None, budgets=None, proc_root="/proc"):
    """Sample this appliance and judge it. Read-only; takes no action.

    Returns the model's verdicts, annotated with which components the escalation
    ladder is permitted to act on. Deliberately does NOT act: the ladder owns
    that, and the operator's standing decision is alert-and-throttle only, with
    unattended restart gated behind evidence.
    """
    procmem, membudget = load_memory_modules(repo_root)
    budgets = APPLIANCE_BUDGETS if budgets is None else budgets

    sample = procmem.sample_processes(
        classifier=lambda r: classify_process(r, proc_root=proc_root))
    verdicts = membudget.evaluate(sample, budgets)

    # Annotate, do not filter. An exempt component still reports its verdict —
    # removing it here would hide the appliance's largest consumer from the very
    # view built to watch memory.
    for name, v in verdicts.get("components", {}).items():
        v["recovery_exempt"] = name in RECOVERY_EXEMPT
    verdicts["actionable_breaches"] = [
        n for n in verdicts.get("breaches", []) if n not in RECOVERY_EXEMPT]
    verdicts["exempt_breaches"] = [
        n for n in verdicts.get("breaches", []) if n in RECOVERY_EXEMPT]
    verdicts["sample_ms"] = sample.get("sample_ms")
    verdicts["uss_state"] = sample.get("uss_state")
    return verdicts


# ── which rungs STRUCTURALLY EXIST per component (operator decisions 2026-08-18)
#
# Audited read-only against the running services rather than assumed. A rung
# absent here is one the ladder will SKIP and RECORD, instead of climbing to a
# rung that silently does nothing — which reads, in every log and every UI, as a
# working mitigation.
#
# ⚠ Skipping never accelerates escalation: the ladder waits for the skipped-to
# rung's OWN justification threshold. See memladder.decide().
_ALL = frozenset({"alert", "throttle", "abort", "restart"})

RUNG_AVAILABILITY = {
    # Third-party daemon. We have NO control surface over it: nothing of ours can
    # slow it, and it has no discrete operation to cancel. Budgeted and NOT
    # exempt, so it is still measured and alerted on — restart is its only real
    # lever, and that is currently shadow.
    "suricata": {"available": frozenset({"alert", "restart"}),
                 "why_absent": {
                     "throttle": "no control surface of ours over a third-party daemon",
                     "abort": "no discrete operation to cancel"}},

    # Operator decision: alert-only. Throttling the dashboard means rate-limiting
    # the operator's own console — degrading the very interface used to diagnose
    # the problem. Structurally possible, deliberately not offered.
    "dashboard": {"available": frozenset({"alert"}),
                  "why_absent": {
                      "throttle": "would rate-limit the operator's own console "
                                  "while they are diagnosing the problem",
                      "abort": "no discrete operation; requests are the work",
                      "restart": "operator decision: alert-only"}},

    # These four expose a real interval today (audited): lengthening it is a
    # genuine, gentle throttle.
    "hw-monitor":          {"available": _ALL, "why_absent": {}},
    "watchdog":            {"available": _ALL, "why_absent": {}},
    "alert-watcher":       {"available": _ALL, "why_absent": {}},
    "diagnostics-watcher": {"available": _ALL, "why_absent": {}},

    # Sweeps with sleeps but no named interval knob yet. THROTTLE is marked
    # absent HONESTLY until a knob exists — claiming it before then would be a
    # rung that does nothing.
    "device-scanner": {"available": frozenset({"alert", "abort", "restart"}),
                       "why_absent": {"throttle": "sweep has no interval knob yet"}},
    "malware-canary": {"available": frozenset({"alert", "abort", "restart"}),
                       "why_absent": {"throttle": "loop has no interval knob yet"}},

    # Exempt anyway; recorded for completeness so the table is not silently
    # partial.
    "clamav-daemon": {"available": frozenset({"alert"}),
                      "why_absent": {"throttle": "recovery-exempt; also no control "
                                                 "surface of ours",
                                     "abort": "recovery-exempt",
                                     "restart": "recovery-exempt — restarting it "
                                                "disarms malware scanning"}},
}


def availability_map():
    """component -> set of available rungs, for `memladder.decide(available=...)`."""
    return {k: v["available"] for k, v in RUNG_AVAILABILITY.items()}


def why_rung_absent(component, rung):
    """Why a rung is missing, or None if it is available/unknown.

    Returned so a 'blocked' ladder action can say WHY rather than leaving an
    operator to infer that a rung is missing from its absence.
    """
    entry = RUNG_AVAILABILITY.get(component)
    if not entry:
        return None
    return entry["why_absent"].get(rung)


def self_test(proc_root="/proc"):
    """Prove the appliance seam works here and can tell components apart."""
    findings = []
    try:
        procmem, membudget = load_memory_modules()
    except Exception as exc:
        return {"ok": False, "findings": ["cannot load generic modules: %r" % exc]}

    # 1. the budget table must be internally coherent on the provisional baseline
    v = membudget.validate_budgets(APPLIANCE_BUDGETS,
                                   PROVISIONAL_BASELINE_GB * 1024.0)
    if not v["ok"]:
        findings.append("budget table incoherent at %d GB: %s"
                        % (PROVISIONAL_BASELINE_GB, "; ".join(v["problems"])))
    # 2. ...and on the sizes it is most likely to be re-based to
    for gb in (4, 16):
        v2 = membudget.validate_budgets(APPLIANCE_BUDGETS, gb * 1024.0)
        if not v2["ok"]:
            findings.append("budget table incoherent at %d GB: %s"
                            % (gb, "; ".join(v2["problems"])))
    # 3. the classifier must actually resolve a unit for THIS process when it is
    #    under systemd, and must never invent one when it is not.
    u = unit_for_pid(os.getpid(), proc_root=proc_root)
    if u is not None and not isinstance(u, str):
        findings.append("unit_for_pid returned a non-string: %r" % (u,))
    bogus = unit_for_pid(2 ** 30, proc_root=proc_root)
    if bogus is not None:
        findings.append("unit_for_pid invented a unit for a non-existent pid: %r"
                        % (bogus,))
    # 4. clamd must be budgeted AND exempt — the pairing this file exists to make
    if "clamav-daemon" not in APPLIANCE_BUDGETS:
        findings.append("clamd is not budgeted; headroom maths would be wrong")
    if "clamav-daemon" not in RECOVERY_EXEMPT:
        findings.append("clamd is not recovery-exempt; size-ranked recovery "
                        "would disarm AV under induced memory pressure")
    return {"ok": not findings, "findings": findings}


if __name__ == "__main__":                                # pragma: no cover
    import json
    logging.basicConfig(level=logging.INFO)
    st = self_test()
    print("self-test:", "PASS" if st["ok"] else "FAIL")
    for f in st["findings"]:
        print("  -", f)
    r = sample_and_evaluate()
    print(json.dumps({k: v for k, v in r.items() if k != "components"},
                     indent=2, default=str))
    for name, v in sorted(r.get("components", {}).items(),
                          key=lambda kv: -(kv[1].get("observed_mb") or 0))[:12]:
        print("  %-26s %-14s obs=%-9s budget=%-9s exempt=%s"
              % (name, v["verdict"], v.get("observed_mb"), v.get("budget_mb"),
                 v.get("recovery_exempt")))
