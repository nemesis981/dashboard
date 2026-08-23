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
import json
import logging
import os
import re
import time

import throttle

log = logging.getLogger("nemesis.mem_appliance")

__all__ = [
    "APPLIANCE_BUDGETS", "APPLIANCE_RESERVATIONS", "RECOVERY_EXEMPT",
    "PROVISIONAL_BASELINE_GB",
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


# ── transient RESERVATIONS (headroom kept free, NOT steady budgets) ───────────
#
# These are RAM the appliance must keep FREE for a consumer that spikes and then
# releases — they are validated TOGETHER with APPLIANCE_BUDGETS against the one
# commit ceiling (membudget.validate_budgets(..., reservations=...)) so a steady
# service can never be budgeted the very RAM a transient consumer is promised.
# They are deliberately NOT in APPLIANCE_BUDGETS: nothing samples them against a
# running process, and they must never be recovery-throttled — the RAM is
# reserved precisely so it is there when the spike comes.
#
# Percentages WITH CLAMPS, same as the budget table: the cost of one memory read
# tracks the detector's chunk buffer, not the size of the box, so it is closer to
# fixed-cost than proportional — hence the max_mb clamp so a 32 GB workstation
# does not reserve gigabytes it will never use.
APPLIANCE_RESERVATIONS = {
    # Consumer (i) of the shared budget model: the memory-injection detector's
    # transient working set. Reading a target process's memory has a working-set
    # cost with NO disk fallback (process memory cannot be scanned from disk), so
    # the RAM to hold one bounded read window must be guaranteed, not hoped for.
    # PROVISIONAL — the detector is not built yet (step 4). The number is a
    # conservative placeholder for a bounded, chunked read (a whole target is
    # streamed in windows, never mapped at once); it is expected to converge from
    # real measurement once the detector exists, the same discipline as the 8 GB
    # baseline and every budget entry's `basis`.
    "memory-injection-scan": {
        "pct": 3.0, "min_mb": 128.0, "max_mb": 384.0,
        # Step 4 IS built now (2026-08-22): agent-side detector (meminject_scan +
        # the private classifier), bounded page-prefix reads, measured ~0.1s full
        # sweep. CONSUMER IS AGENT-SIDE, not an appliance throttle-component -- this
        # is why memory-injection is deliberately NOT in RUNG_AVAILABILITY: there is
        # no appliance service to assign ladder rungs to. If/when the appliance runs
        # its own sweep on itself (requires the classifier deployed to the appliance
        # path), THAT component gets a RUNG_AVAILABILITY entry; the reservation here
        # stands regardless, because the RAM to hold one bounded read window must be
        # guaranteed wherever the read runs. The 384 MB clamp still bounds it; the
        # number stays provisional pending real appliance-side measurement.
        "basis": "agent-side memory-injection detector (step 4, built 2026-08-22): "
                 "bounded chunked read window, no disk fallback; provisional pending "
                 "appliance-side measurement",
    },
    # Consumers (ii) tmpfs scratch bounds and (iii) a future RAM-backed detonation
    # VM share this table when they are scoped — they are the same shape (headroom
    # kept free, accounted against the ceiling), and are intentionally NOT added
    # here yet because neither is in scope for this step.
}

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

    # These three expose a real interval today (audited): lengthening it is a
    # genuine, gentle throttle.
    "hw-monitor":          {"available": _ALL, "why_absent": {}},
    "watchdog":            {"available": _ALL, "why_absent": {}},
    "alert-watcher":       {"available": _ALL, "why_absent": {}},

    # REQUIRED DETECTORS — structurally exempt from THROTTLE (2026-08-22). Both
    # DO have a real, bounded interval knob; that is precisely why they are
    # excluded. Their ceilings are justified against what the detector is for
    # (alert_manager/cadence.py), and a throttle multiplier would carry the
    # interval past its own ceiling. See THROTTLE_UNTHROTTLED_COMPONENTS.
    #
    # NOTE the change of reason for malware-canary: it previously read "loop has
    # no interval knob yet", i.e. UNAVAILABLE-and-should-be-wired. It has had one
    # all along (`canary_poll_seconds`), now bounded 5..300s — so acting on the
    # old note would have wired throttle into a required detector and re-opened
    # the exact hole this exclusion closes.
    "diagnostics-watcher": {"available": frozenset({"alert", "abort", "restart"}),
                            "why_absent": {"throttle":
                                "required detector: stretching its bounded poll "
                                "interval past the ceiling that justifies it is a "
                                "coverage disable"}},
    "malware-canary":      {"available": frozenset({"alert", "abort", "restart"}),
                            "why_absent": {"throttle":
                                "required detector: the poll interval IS the "
                                "ransomware detection latency"}},

    # Sweep with sleeps but no named interval knob yet. THROTTLE is marked absent
    # HONESTLY until a knob exists — claiming it before then would be a rung that
    # does nothing. Distinct from the two above: this one is not-yet-wired
    # (UNAVAILABLE), not excluded by design.
    "device-scanner": {"available": frozenset({"alert", "abort", "restart"}),
                       "why_absent": {"throttle": "sweep has no interval knob yet"}},

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


# ── THROTTLE status: three distinct outcomes, deliberately NOT collapsed ──────
# A component's throttle standing is exactly one of three, and a reader MUST be
# able to tell a deliberate exclusion from a missing connection — mistaking one
# for the other is the same "looks broken when it's fine / looks fine when it's
# broken" confusion RUNG_AVAILABILITY exists to prevent.
THROTTLE_THROTTLEABLE = "throttleable"   # has a real interval to slow; a live candidate
THROTTLE_UNTHROTTLED  = "unthrottled"    # NEVER a candidate BY DESIGN (see the set below)
THROTTLE_UNAVAILABLE  = "unavailable"    # SHOULD be wired but isn't yet (no interval knob)

#: Structurally excluded from THROTTLE by design — never candidates. Either there
#: is no interval of OURS to slow (suricata: third-party daemon, no control
#: surface), or slowing it would be harmful the same way restarting it would be
#: (clamav-daemon: throttling disarms AV; dashboard: rate-limits the operator's
#: own console mid-diagnosis). This is DISTINCT from "no interval knob YET"
#: (device-scanner, malware-canary), which is UNAVAILABLE and should eventually be
#: wired. Components here MUST NEVER call throttle.register_throttle_aware() — the
#: exclusion is a decision, not an oversight, and UNTHROTTLED makes that visible
#: rather than leaving them merely absent from the registry (which reads as a bug).
THROTTLE_UNTHROTTLED_COMPONENTS = frozenset({
    "clamav-daemon", "suricata", "dashboard",
    # ── Added 2026-08-22, for a DIFFERENT reason than the three above ──────────
    # The three originals are exempt because there is no interval of ours to slow,
    # or because slowing them is harmful in itself. These two are exempt because
    # they are REQUIRED DETECTORS, and a detector's poll interval is bounded by a
    # ceiling that is justified against what the detector is for
    # (alert_manager/cadence.py). The throttle multiplies that interval by up to
    # MAX_FACTOR, which would carry it past its own ceiling: measured, the
    # diagnostics watcher's justified 900s ceiling became 7,200s (2 hours) — well
    # past the point its own rationale says an outage can fall entirely between
    # two samples.
    #
    # A ceiling that another subsystem may stretch is not a ceiling. That is the
    # same coverage-disable-through-a-side-door the interval bounds were added to
    # close, arriving through cooperation rather than through a setting.
    #
    # The memory ladder keeps every other rung for these components (alert, abort,
    # restart) and keeps THROTTLE for non-detection work. Only the detector's
    # cadence is off limits.
    "diagnostics-watcher",
    "malware-canary",
})


def throttle_status(component):
    """Three-way throttle standing for `component`. The report layer uses this so
    UNTHROTTLED (excluded by design) never reads as UNAVAILABLE (not wired yet).

    UNTHROTTLED is checked FIRST, deliberately. It is a structural decision about
    whether a component may EVER be throttled; RUNG_AVAILABILITY describes what a
    component is mechanically capable of. If the two ever disagree the decision
    must win, or a stale `available` entry would quietly re-open an exclusion that
    was made on purpose. `_selftest_throttle_exclusions` makes such a disagreement
    impossible to ship, but the ordering here means it would still fail safe.
    """
    if component in THROTTLE_UNTHROTTLED_COMPONENTS:
        return THROTTLE_UNTHROTTLED
    entry = RUNG_AVAILABILITY.get(component)
    if entry and "throttle" in entry["available"]:
        return THROTTLE_THROTTLEABLE
    return THROTTLE_UNAVAILABLE


def _selftest_throttle_exclusions() -> None:
    """An UNTHROTTLED component must not also advertise THROTTLE as available.

    Runs at import, in the production path. The two structures are edited by hand
    in different places, and a component left advertising `throttle` while being
    structurally exempt is exactly the kind of half-applied change that reads as
    working -- `throttle_status()` would still say UNTHROTTLED thanks to the
    ordering above, while `RUNG_AVAILABILITY` told the ladder it was fair game.
    """
    for comp in THROTTLE_UNTHROTTLED_COMPONENTS:
        entry = RUNG_AVAILABILITY.get(comp)
        if entry and "throttle" in entry["available"]:
            raise AssertionError(
                "throttle exclusion self-test: %r is in "
                "THROTTLE_UNTHROTTLED_COMPONENTS but RUNG_AVAILABILITY still "
                "lists 'throttle' as available -- one of the two edits was "
                "missed, and the ladder would treat it as throttleable" % comp)
        if entry is not None and "throttle" not in entry.get("why_absent", {}):
            raise AssertionError(
                "throttle exclusion self-test: %r is UNTHROTTLED by design but "
                "records no why_absent['throttle'] reason -- an exclusion whose "
                "reason is not stated will not survive its first inconvenience"
                % comp)
    # CONTROL: prove this test can distinguish. A component that is genuinely
    # throttleable must NOT be in the exclusion set, or the check above would be
    # vacuously true for an empty/degenerate set.
    throttleable = [c for c, e in RUNG_AVAILABILITY.items()
                    if "throttle" in e["available"]]
    if not throttleable:
        raise AssertionError(
            "throttle exclusion self-test: NO component is throttleable, so this "
            "check proves nothing -- the throttle subsystem has no subjects left")
    for c in throttleable:
        if c in THROTTLE_UNTHROTTLED_COMPONENTS:
            raise AssertionError(
                "throttle exclusion self-test: %r is both throttleable and "
                "structurally exempt" % c)


_selftest_throttle_exclusions()


def throttle_status_map():
    """component -> throttle_status, for logs/dashboard. Covers every component in
    RUNG_AVAILABILITY plus the structural-exempt set. The single source of truth
    for surfacing UNTHROTTLED vs unavailable so the two are never conflated."""
    comps = set(RUNG_AVAILABILITY) | THROTTLE_UNTHROTTLED_COMPONENTS
    return {c: throttle_status(c) for c in sorted(comps)}


def assert_throttle_registerable(component):
    """Guard for the registration path: an UNTHROTTLED component must NOT register
    (excluded by design, loudly — never silently skipped). Raises if it tries.
    Throttleable and (not-yet-wired) UNAVAILABLE components pass — only structural
    exclusions are refused."""
    if throttle_status(component) == THROTTLE_UNTHROTTLED:
        raise ValueError(
            "component %r is UNTHROTTLED by design (see "
            "THROTTLE_UNTHROTTLED_COMPONENTS) and must not register throttle-aware"
            % (component,))


def self_test(proc_root="/proc"):
    """Prove the appliance seam works here and can tell components apart."""
    findings = []
    try:
        procmem, membudget = load_memory_modules()
    except Exception as exc:
        return {"ok": False, "findings": ["cannot load generic modules: %r" % exc]}

    # 1. the budget table must be internally coherent on the provisional baseline
    #    — WITH the transient reservations counted, since steady budgets and
    #    reserved headroom draw from the same pool and must fit together.
    v = membudget.validate_budgets(APPLIANCE_BUDGETS,
                                   PROVISIONAL_BASELINE_GB * 1024.0,
                                   reservations=APPLIANCE_RESERVATIONS)
    if not v["ok"]:
        findings.append("budget+reservation set incoherent at %d GB: %s"
                        % (PROVISIONAL_BASELINE_GB, "; ".join(v["problems"])))
    # 2. ...and on the sizes it is most likely to be re-based to (4 GB is the
    #    tightest: floors dominate and the reservation still has to fit).
    for gb in (4, 16, 32):
        v2 = membudget.validate_budgets(APPLIANCE_BUDGETS, gb * 1024.0,
                                        reservations=APPLIANCE_RESERVATIONS)
        if not v2["ok"]:
            findings.append("budget+reservation set incoherent at %d GB: %s"
                            % (gb, "; ".join(v2["problems"])))
    # 2b. the detector reservation must carry a basis and must NOT have leaked
    #     into the steady budget table (where it would be judged/throttled).
    if not APPLIANCE_RESERVATIONS.get("memory-injection-scan", {}).get("basis"):
        findings.append("memory-injection-scan reservation has no basis")
    if "memory-injection-scan" in APPLIANCE_BUDGETS:
        findings.append("a transient reservation leaked into APPLIANCE_BUDGETS — "
                        "it would be evaluated against a process and recovery-throttled")
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


# ── THROTTLE executor: makes the ladder's THROTTLE rung EXECUTE, not just decide ──
#
# The original blocker was that the ladder could DECIDE throttle but nothing could
# ACT on it (a slow interval lives inside a separate process; systemd offers no
# lever). The cooperative-throttle seam (alert_manager/throttle.py) closed that: a
# throttled service reads published intent and scales its own sleep. This is the
# other half — turning the ladder's decision into a published intent.

#: A THROTTLE means "slow this component's loop by this multiple." 4x a 300s sample
#: loop is 20 min between samples -- a real relief valve, well under throttle.py's
#: 8x clamp.
THROTTLE_FACTOR = 4.0
#: Publish with a hold longer than a few evaluation cycles so ONE missed executor
#: cycle does not drop the throttle early, but short enough that a DEAD executor
#: lets the intent auto-expire (the fail-safe throttle.py depends on). Refreshed
#: every cycle for still-throttled components; cleared immediately on de-escalation.
THROTTLE_HOLD_SECONDS = 900


def load_ladder(repo_root=None):
    """Load the pure escalation ladder by absolute path (no sys.path insert -- it
    imports no siblings), same mechanism as load_memory_modules."""
    root = repo_root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "nemesis_agent", "memladder.py")
    spec = importlib.util.spec_from_file_location("nemesis_mem_ladder", path)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load memladder from %s" % path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def execute_ladder_throttle(new_state, dm, *, ladder=None, policy=None, now=None):
    """Publish/refresh/clear throttle intent from the ladder's CURRENT per-component
    rungs. Returns a list of {component, action, ...} for the audit trail.

    STATE-DRIVEN, not transition-driven, and deliberately so: a component that
    REACHED throttle and stays there emits no new `escalate` action, but its intent
    must be REFRESHED each cycle or it expires (throttle.py's fail-safe). So each
    cycle we (re)publish for everything currently at/above THROTTLE and clear
    everything that has fallen below.

    RUNG_AVAILABILITY is respected twice: `decide()` already refuses to move a
    component onto a rung it lacks, and this asserts `"throttle" in available` again
    before publishing -- so clamav-daemon (recovery-exempt, throttle-unavailable)
    can never be handed a throttle intent even if some future caller mis-drives it.
    THROTTLE being SHADOW in the policy also suppresses publication (record-only).
    """
    ladder = load_ladder() if ladder is None else ladder
    policy = ladder.DEFAULT_POLICY if policy is None else policy
    avail = availability_map()
    throttle_i = ladder.RUNGS.index(ladder.RUNG_THROTTLE)
    live_throttle = policy["modes"].get(ladder.RUNG_THROTTLE) == ladder.MODE_LIVE

    comps = (new_state or {}).get("components", {})
    should = set()
    if live_throttle:
        for name, st in comps.items():
            rung = st.get("rung", ladder.RUNG_NONE)
            if ladder.RUNGS.index(rung) >= throttle_i \
                    and "throttle" in avail.get(name, frozenset()):
                should.add(name)

    results = []
    for name in sorted(should):
        throttle.publish_throttle(
            name, THROTTLE_FACTOR, THROTTLE_HOLD_SECONDS,
            "memory ladder: %s at rung %s" % (name, comps[name].get("rung")),
            dm, now=now)
        results.append({"component": name, "action": "throttle",
                        "factor": THROTTLE_FACTOR})

    # Clear intents for components that were throttled but should no longer be.
    try:
        stale = throttle.live_intent_components(dm, now) - should
    except Exception as e:                               # noqa: BLE001
        log.warning("throttle executor: could not read live intents to clear (%s) "
                    "-- stale intents will lapse on their own via until_ts", e)
        stale = set()
    for name in sorted(stale):
        throttle.clear_throttle(name, dm, now=now)
        results.append({"component": name, "action": "clear"})
    return results


# ── THROTTLE STATUS SURFACE — makes throttle_status_map() (incl. UNTHROTTLED) visible ──
# Combines the STATIC classification (throttleable / unthrottled / unavailable) with the
# LIVE DB state (throttle_intents + throttle_components) so a reader sees, in one place,
# both "is this a candidate by design" AND "is it throttled right now". UNTHROTTLED reads
# distinctly from unavailable — the whole point.

def throttle_status_report(conn, now=None):
    """{component: {status, throttled, factor, reason, source, registered}}.

    `conn` is any live DB connection (reads are read-any; SELECT is not guarded).
    Missing throttle tables (never initialised) degrade to static-status-only rather
    than raising — the surface still shows the design classification.
    """
    now = time.time() if now is None else now
    smap = throttle_status_map()
    intents, reg = {}, {}
    try:
        for r in conn.execute("SELECT component, factor, until_ts, reason, source "
                              "FROM throttle_intents").fetchall():
            intents[r[0]] = (r[1], r[2], r[3], r[4])
        for r in conn.execute("SELECT component FROM throttle_components").fetchall():
            reg[r[0]] = True
    except Exception as e:                                   # noqa: BLE001
        log.warning("throttle status: could not read live state (%s) — showing "
                    "static classification only", e)
    out = {}
    for comp in sorted(set(smap) | set(intents) | set(reg)):
        factor, reason, source = 1.0, None, None
        if comp in intents:
            f, until, rsn, src = intents[comp]
            factor = throttle._effective_factor({"factor": f, "until_ts": until}, now)
            reason, source = rsn, src
        out[comp] = {
            "status": smap.get(comp, THROTTLE_UNAVAILABLE),
            "throttled": factor > throttle.NORMAL,
            "factor": round(factor, 2),
            "reason": reason,
            "source": source,
            "registered": comp in reg,
        }
    return out


def log_throttle_status(conn, now=None):
    """Emit ONE summary log line distinguishing UNTHROTTLED (by design) from
    UNAVAILABLE (not wired yet), plus any currently-active throttles."""
    rep = throttle_status_report(conn, now)
    n_t = sum(1 for r in rep.values() if r["status"] == THROTTLE_THROTTLEABLE)
    unth = [c for c, r in rep.items() if r["status"] == THROTTLE_UNTHROTTLED]
    n_u = sum(1 for r in rep.values() if r["status"] == THROTTLE_UNAVAILABLE)
    active = ["%s %.0fx" % (c, r["factor"]) for c, r in rep.items() if r["throttled"]]
    log.info("throttle status: %d throttleable, %d UNTHROTTLED-by-design (%s), "
             "%d unavailable-pending; active: %s",
             n_t, len(unth), ",".join(unth) or "-", n_u, ", ".join(active) or "none")
    return rep


# ── PRODUCTION LADDER RUNNER — the periodic loop that makes the ladder REAL ────
# Without this driving the ladder, decide()/shadow_record() are never called in
# production: no shadow records accumulate, and RESTART/ABORT promotion sits at
# "0 resolved" forever (indistinguishable from "not enough evidence yet"). This is
# the loop hw_monitor's sample cycle calls each tick (its SAMPLE_INTERVAL IS the
# ladder cadence the policy thresholds are written against). State + shadow records
# PERSIST across restarts so a bounce does not reset the promotion clock to zero.

def _load_ladder_state(conn, ladder):
    row = conn.execute("SELECT state_json, sample_seq FROM mem_ladder_state "
                       "WHERE id=1").fetchone()
    if not row:
        return ladder.new_state(), 0
    try:
        return json.loads(row[0]), int(row[1] or 0)
    except Exception:                                        # noqa: BLE001
        return ladder.new_state(), int(row[1] or 0)


def _save_ladder_state(conn, state, seq, now):
    conn.execute(
        "INSERT INTO mem_ladder_state (id, state_json, sample_seq, updated_ts) "
        "VALUES (1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
        "state_json=excluded.state_json, sample_seq=excluded.sample_seq, "
        "updated_ts=excluded.updated_ts", (json.dumps(state), seq, now))


def _insert_shadow_record(conn, rec, now):
    conn.execute(
        "INSERT INTO mem_shadow_records (component, rung, decided_seq, observed_mb, "
        "budget_mb, follow_ups_json, outcome, created_ts) VALUES (?,?,?,?,?,?,?,?)",
        (rec["component"], rec["rung"], rec["decided_at"], rec.get("observed_mb"),
         rec.get("budget_mb"), json.dumps(rec.get("follow_ups") or []),
         rec.get("outcome"), now))


def _advance_and_resolve_records(conn, ladder, comps, now):
    """Append THIS sample's verdict to every UNRESOLVED shadow record (None = the
    component was absent this sample, which is meaningful), then classify. A follow-up
    is a LATER sample's observation, so this runs BEFORE new records are added, so a
    record decided this sample never gets a follow-up from its own sample."""
    rows = conn.execute(
        "SELECT id, component, rung, decided_seq, observed_mb, budget_mb, "
        "follow_ups_json FROM mem_shadow_records WHERE outcome IS NULL").fetchall()
    for rid, component, rung, decided_seq, obs, bud, fups_json in rows:
        try:
            fups = json.loads(fups_json or "[]")
        except Exception:                                    # noqa: BLE001
            fups = []
        v = (comps or {}).get(component)
        verdict = v.get("verdict") if v else None
        rec = {"component": component, "rung": rung, "decided_at": decided_seq,
               "observed_mb": obs, "budget_mb": bud, "follow_ups": fups, "outcome": None}
        rec = ladder.observe_follow_up(rec, verdict)
        outcome = ladder.classify_outcome(rec)
        conn.execute(
            "UPDATE mem_shadow_records SET follow_ups_json=?, outcome=?, resolved_ts=? "
            "WHERE id=?", (json.dumps(rec["follow_ups"]), outcome,
                           (now if outcome else None), rid))


def run_ladder_cycle(dm, conn, *, repo_root=None, now=None):
    """One production ladder cycle: sample -> decide -> resolve-existing ->
    record-new-shadow -> persist -> execute-live(throttle). Persists state + records
    across cycles. Best-effort: NEVER raises out — a cycle failure must not kill the
    hw_monitor loop it rides. Returns a summary dict."""
    now = time.time() if now is None else now
    try:
        ladder = load_ladder(repo_root)
        state, seq = _load_ladder_state(conn, ladder)
        seq += 1
        verdicts = sample_and_evaluate(repo_root)
        new_state, actions = ladder.decide(
            verdicts, state, exempt=RECOVERY_EXEMPT, available=availability_map())
        comps = verdicts.get("components", {})
        _advance_and_resolve_records(conn, ladder, comps, now)   # follow-ups first
        shadow_new = 0
        for a in actions:
            if a.get("kind") == "escalate" and a.get("mode") == ladder.MODE_SHADOW:
                _insert_shadow_record(conn, ladder.shadow_record(a, seq), now)
                shadow_new += 1
        _save_ladder_state(conn, new_state, seq, now)
        conn.commit()
        exec_results = execute_ladder_throttle(new_state, dm, ladder=ladder, now=now)
        return {"ran": True, "seq": seq, "shadow_new": shadow_new,
                "throttle_actions": len(exec_results),
                "components": len(comps)}
    except Exception as e:                                   # noqa: BLE001
        log.exception("run_ladder_cycle failed: %s", e)
        return {"ran": False, "error": str(e)}
