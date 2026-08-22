"""RAM budget and deviation model — generic, platform-neutral, stateless.

Consumes a `procmem.sample_processes()` result and answers one question per
component: is this within the budget we set for it, and how confident are we?

PURE BY DESIGN. No I/O, no clock, no persistence, no actions. Given the same
sample and the same budgets it returns the same verdicts, which is what makes it
testable against fabricated extremes that are awkward to produce on a real box.
Everything stateful — "has it breached for N consecutive samples", cooldowns,
throttling, restarts — belongs to the escalation ladder, not here. A model that
also decided when to act could not be exercised without also exercising the
actions.

────────────────────────────────────────────────────────────────────────────
BUDGETS ARE PERCENTAGES, BECAUSE THE BASELINE IS PROVISIONAL
────────────────────────────────────────────────────────────────────────────
The working appliance baseline is 8 GB, explicitly provisional — it is expected
to move once the gauge VM produces real measured data. So budgets are authored
as a PERCENTAGE OF ACTUAL TOTAL RAM and resolved to megabytes at evaluation time
against the machine the sampler actually ran on. Re-baselining from 8 GB to 4 GB
or 16 GB then requires no edit here, and an agent on a 32 GB workstation gets
sensible numbers from the same table.

⚠ BUT A PURE PERCENTAGE IS WRONG FOR FIXED-COST COMPONENTS, and the appliance's
largest consumer is exactly that case. clamd costs roughly 968 MB because of its
signature set, not because of how much RAM the box has. As a flat percentage:

    24% of  4 GB  =   983 MB   -- about right
    24% of 16 GB  = 3,932 MB   -- four times its real cost; it could leak
                                  3 GB and never trip

So a budget is a percentage WITH OPTIONAL ABSOLUTE CLAMPS (`min_mb`, `max_mb`).
The percentage remains the unit — the clamps are guards for the case where cost
genuinely does not scale with machine size. A component whose cost is
proportional (page caches, worker pools) needs no clamp at all.

────────────────────────────────────────────────────────────────────────────
THE ASYMMETRY THAT MAKES THIS USABLE WITHOUT CAP_SYS_PTRACE
────────────────────────────────────────────────────────────────────────────
Budgets are authored against USS, because USS is what a component actually costs
the machine and what killing it would give back. But USS needs PTRACE_MODE_READ,
and the appliance services run unprivileged, so USS is frequently missing.

RSS is always available, and USS is a SUBSET of RSS (RSS additionally counts
shared pages). That single containment gives a sound one-way inference:

    RSS <= budget   =>  USS <= budget too.        A DEFINITE PASS.
    RSS >  budget   =>  says NOTHING about USS.   NOT a breach.

So an RSS-only sample can still clear most components outright, and only the ones
whose RSS is already over budget come back INDETERMINATE — which is both honest
and useful, because that is precisely the short list worth spending a privileged
USS read on.

What this must never do is compare an RSS number against a USS budget and call
the result a breach. That would report shared pages — libpython counted once per
service — as a component's own consumption, and the escalation ladder would then
throttle something that is inside its real budget.
"""

from __future__ import annotations

__all__ = [
    "MEASURE_USS", "MEASURE_RSS",
    "OK", "BREACH", "INDETERMINATE", "UNBUDGETED",
    "resolve_budget_mb", "validate_budgets", "evaluate",
    "self_test",
]

MEASURE_USS = "uss"
MEASURE_RSS = "rss"

#: Per-component verdicts. UNBUDGETED is deliberately distinct from OK: a
#: component nobody wrote a budget for has not passed anything, and collapsing
#: the two would let an unbudgeted leak read as healthy forever.
OK = "ok"
BREACH = "breach"
INDETERMINATE = "indeterminate"
UNBUDGETED = "unbudgeted"

#: Fraction of total RAM the budget set may commit before it is self-inconsistent.
#: Below 1.0 on purpose: a budget set that adds up to the whole machine leaves the
#: kernel, page cache and every unbudgeted process with nothing.
DEFAULT_MAX_COMMIT_FRACTION = 0.80


def resolve_budget_mb(spec, total_ram_mb):
    """Resolve a budget spec to megabytes for THIS machine.

    `spec` is a dict: {"pct": float, "min_mb": float|None, "max_mb": float|None}
    Returns (mb, reason) — mb is None when it cannot be resolved, and `reason`
    then says why. Never returns a fabricated number: a budget of 0, or one
    silently derived from an assumed machine size, is indistinguishable from a
    real one to everything downstream.
    """
    if total_ram_mb is None:
        return None, "machine total RAM unknown"
    try:
        pct = float(spec["pct"])
    except (KeyError, TypeError, ValueError):
        return None, "budget spec has no usable 'pct'"
    if pct <= 0:
        return None, "budget pct must be > 0, got %r" % (pct,)

    mb = total_ram_mb * pct / 100.0
    lo, hi = spec.get("min_mb"), spec.get("max_mb")
    if lo is not None and hi is not None and lo > hi:
        return None, "budget spec has min_mb %.1f > max_mb %.1f" % (lo, hi)
    if lo is not None:
        mb = max(mb, float(lo))
    if hi is not None:
        mb = min(mb, float(hi))
    return round(mb, 2), None


def validate_budgets(budgets, total_ram_mb, reservations=None,
                     max_commit_fraction=DEFAULT_MAX_COMMIT_FRACTION):
    """Check a budget SET is coherent before it is ever used to judge anything.

    Catches the authoring error that is invisible per-component: budgets that
    individually look reasonable but together commit more RAM than the machine
    has. Such a set can never be satisfied, so it would generate breaches that
    no amount of fixing the software could clear — and the natural response to
    an unfixable alert is to stop believing alerts.

    ────────────────────────────────────────────────────────────────────────
    RESERVATIONS — TRANSIENT HEADROOM, NOT A STEADY BUDGET
    ────────────────────────────────────────────────────────────────────────
    `reservations` (same {pct,min_mb,max_mb} spec shape) are RAM that must be
    kept FREE for a transient consumer that spikes and then releases — the
    memory-injection detector reading a target process's working set (no disk
    fallback: process memory cannot be scanned from disk), a tmpfs scratch
    bound, a RAM-backed detonation VM. They are deliberately NOT budgets:
    nothing evaluates them against a running process (there is no steady
    process to judge), and they must never be recovery-throttled (there is
    nothing to throttle — the RAM is reserved precisely so it is available
    when the spike comes).

    But they draw from the SAME pool as the steady budgets, so coherence has
    to account for both AT ONCE: steady commitments + transient reservations
    must together fit under the ceiling, or the reservation is a lie — the RAM
    it promises has already been budgeted to a service. Validating the two
    separately would pass each while their sum overcommits, which is exactly
    the invisible authoring error this function exists to catch.
    """
    problems = []
    resolved = {}
    for name, spec in (budgets or {}).items():
        mb, reason = resolve_budget_mb(spec, total_ram_mb)
        if mb is None:
            problems.append("%s: %s" % (name, reason))
        else:
            resolved[name] = mb

    reserved = {}
    for name, spec in (reservations or {}).items():
        mb, reason = resolve_budget_mb(spec, total_ram_mb)
        if mb is None:
            problems.append("reservation %s: %s" % (name, reason))
        else:
            reserved[name] = mb

    budgets_committed = round(sum(resolved.values()), 2) if resolved else 0.0
    reserved_committed = round(sum(reserved.values()), 2) if reserved else 0.0
    committed = round(budgets_committed + reserved_committed, 2)
    ceiling = None
    if total_ram_mb is not None:
        ceiling = round(total_ram_mb * max_commit_fraction, 2)
        if committed > ceiling:
            # Name the reservation contribution explicitly: an overcommit that is
            # only over once the transient headroom is counted is a different fix
            # (shrink the reservation, or re-baseline) than a steady-budget
            # overcommit, and a reader must be able to tell which they are looking at.
            res_note = (" (incl. %.0f MB reserved headroom)" % reserved_committed
                        if reserved_committed else "")
            problems.append(
                "budget set commits %.0f MB of %.0f MB total (%.0f%%)%s, over the "
                "%.0f%% ceiling — unsatisfiable, would breach permanently"
                % (committed, total_ram_mb, 100.0 * committed / total_ram_mb,
                   res_note, 100.0 * max_commit_fraction))

    return {"ok": not problems, "problems": problems,
            "resolved_mb": resolved, "reserved_mb": reserved,
            "committed_mb": committed,
            "budgets_committed_mb": budgets_committed,
            "reserved_committed_mb": reserved_committed,
            "ceiling_mb": ceiling, "total_ram_mb": total_ram_mb}


def _component_observation(comp, measure):
    """(value_mb, basis) for a component under the requested measure.

    `basis` records which number was actually used, so a caller can never
    mistake an RSS-derived result for a USS measurement.
    """
    if measure == MEASURE_USS:
        if comp.get("uss_mb") is not None and comp.get("uss_complete"):
            return comp["uss_mb"], MEASURE_USS
        # Fall back to RSS as a BOUND, not as a substitute — see the module
        # docstring. The caller is told the basis is rss so it can apply the
        # one-way inference rather than treating this as the component's USS.
        return comp.get("rss_mb"), MEASURE_RSS
    return comp.get("rss_mb"), MEASURE_RSS


def evaluate(sample, budgets, default_measure=MEASURE_USS):
    """Judge a sample against a budget set. Pure.

    Returns per-component verdicts plus a machine-level summary. A component is
    only BREACH when the comparison is sound: either it was measured on the same
    basis the budget is authored against, or the basis available is strictly
    conservative for that budget.
    """
    if not isinstance(sample, dict) or sample.get("state") == "unavailable":
        return {"state": "unavailable",
                "reason": (sample or {}).get("reason", "no sample"),
                "components": {}, "breaches": [], "indeterminate": [],
                "total_ram_mb": None}

    total_ram_mb = sample.get("total_ram_mb")
    comps = sample.get("components") or {}
    out, breaches, indeterminate = {}, [], []

    for name, comp in comps.items():
        spec = (budgets or {}).get(name)
        if spec is None:
            out[name] = {"verdict": UNBUDGETED, "rss_mb": comp.get("rss_mb"),
                         "uss_mb": comp.get("uss_mb"), "budget_mb": None,
                         "basis": None, "detail": "no budget defined"}
            continue

        measure = spec.get("measure", default_measure)
        budget_mb, why = resolve_budget_mb(spec, total_ram_mb)
        if budget_mb is None:
            out[name] = {"verdict": INDETERMINATE, "rss_mb": comp.get("rss_mb"),
                         "uss_mb": comp.get("uss_mb"), "budget_mb": None,
                         "basis": None, "detail": "unresolvable budget: %s" % why}
            indeterminate.append(name)
            continue

        value, basis = _component_observation(comp, measure)
        if value is None:
            out[name] = {"verdict": INDETERMINATE, "rss_mb": comp.get("rss_mb"),
                         "uss_mb": comp.get("uss_mb"), "budget_mb": budget_mb,
                         "basis": None, "detail": "component has no usable measurement"}
            indeterminate.append(name)
            continue

        over = value > budget_mb
        sound = (basis == measure)
        if not sound and not over:
            # RSS is within a USS budget. USS <= RSS, so this is a DEFINITE pass
            # even though USS itself was never read.
            verdict = OK
            detail = ("rss %.1f MB within the %s budget %.1f MB — USS is a "
                      "subset of RSS, so this clears without a privileged read"
                      % (value, measure, budget_mb))
        elif not sound and over:
            # The inference does not run this way. RSS over budget says nothing
            # about USS, because the excess may be entirely shared pages.
            verdict = INDETERMINATE
            detail = ("rss %.1f MB exceeds the %s budget %.1f MB, but rss "
                      "includes shared pages — a privileged USS read is needed "
                      "to decide (CAP_SYS_PTRACE)" % (value, measure, budget_mb))
            indeterminate.append(name)
        else:
            verdict = BREACH if over else OK
            detail = "%s %.1f MB vs budget %.1f MB" % (basis, value, budget_mb)
            if over:
                breaches.append(name)

        out[name] = {"verdict": verdict, "rss_mb": comp.get("rss_mb"),
                     "uss_mb": comp.get("uss_mb"), "budget_mb": budget_mb,
                     "basis": basis, "observed_mb": value,
                     "over_by_mb": round(value - budget_mb, 2) if over else 0.0,
                     "detail": detail}

    missing = sorted(set(budgets or {}) - set(comps))
    return {
        "state": "ok",
        "reason": None,
        "total_ram_mb": total_ram_mb,
        "components": out,
        "breaches": sorted(breaches),
        "indeterminate": sorted(set(indeterminate)),
        # A budgeted component that is not running at all is NOT a pass. It is
        # reported separately so "the service is dead" cannot look like "the
        # service is comfortably inside its budget".
        "budgeted_but_absent": missing,
        "sample_state": sample.get("state"),
        "uss_state": sample.get("uss_state"),
    }


# ── premise proof ────────────────────────────────────────────────────────────

def self_test():
    """Canaries: the model must produce DIFFERENT answers for different inputs.

    Runs in the production path, not only under the test suite — a budget engine
    that returned OK for everything would be indistinguishable from a healthy
    fleet, which is the failure this project keeps finding.
    """
    findings = []
    total = 8192.0
    budgets = {"svc": {"pct": 1.0}}                       # 81.92 MB

    def _s(rss, uss, complete=True):
        return {"state": "ok", "total_ram_mb": total,
                "components": {"svc": {"rss_mb": rss, "uss_mb": uss,
                                       "uss_complete": complete,
                                       "pids": [1], "proc_count": 1}}}

    # 1. a real USS breach must be BREACH
    r = evaluate(_s(500.0, 400.0), budgets)
    if r["components"]["svc"]["verdict"] != BREACH:
        findings.append("uss over budget did not BREACH: %r"
                        % r["components"]["svc"]["verdict"])
    # 2. a comfortable component must be OK (proves it can say both words)
    r = evaluate(_s(50.0, 20.0), budgets)
    if r["components"]["svc"]["verdict"] != OK:
        findings.append("uss under budget did not report OK: %r"
                        % r["components"]["svc"]["verdict"])
    # 3. RSS over budget with USS unavailable must NOT be a breach
    r = evaluate(_s(500.0, None, complete=False), budgets)
    if r["components"]["svc"]["verdict"] != INDETERMINATE:
        findings.append("rss-over-budget without uss reported %r, expected %r"
                        % (r["components"]["svc"]["verdict"], INDETERMINATE))
    # 4. RSS under budget with USS unavailable IS a definite pass
    r = evaluate(_s(50.0, None, complete=False), budgets)
    if r["components"]["svc"]["verdict"] != OK:
        findings.append("rss-under-budget without uss reported %r, expected OK"
                        % r["components"]["svc"]["verdict"])
    # 5. an over-committed budget set must be refused
    v = validate_budgets({"a": {"pct": 60.0}, "b": {"pct": 60.0}}, total)
    if v["ok"]:
        findings.append("a 120%-committed budget set validated as ok")

    # 6. a transient RESERVATION must be counted against the ceiling: a budget
    #    set that fits ALONE but overcommits ONCE the reservation is added must
    #    be refused — else the headroom the reservation promises is a lie.
    fits_alone = validate_budgets({"a": {"pct": 50.0}}, total)          # 50% ok
    if not fits_alone["ok"]:
        findings.append("a 50%% budget set was wrongly refused on its own")
    with_res = validate_budgets({"a": {"pct": 50.0}}, total,
                                reservations={"scan": {"pct": 40.0}})   # 90% > 80%
    if with_res["ok"]:
        findings.append("50%% budget + 40%% reservation (90%%) validated as ok — "
                        "the reservation was not counted against the ceiling")
    # 7. CONTROL: a reservation that genuinely fits must still pass, so #6 is
    #    proving accounting and not a validator that refuses every reservation.
    ok_res = validate_budgets({"a": {"pct": 50.0}}, total,
                              reservations={"scan": {"pct": 10.0}})     # 60% ok
    if not ok_res["ok"]:
        findings.append("50%% budget + 10%% reservation (60%%) was wrongly refused")
    if ok_res.get("reserved_committed_mb") != round(total * 0.10, 2):
        findings.append("reserved headroom not reported: %r"
                        % ok_res.get("reserved_committed_mb"))

    return {"ok": not findings, "findings": findings}


if __name__ == "__main__":                                # pragma: no cover
    st = self_test()
    print("self-test:", "PASS" if st["ok"] else "FAIL")
    for f in st["findings"]:
        print("  -", f)
