"""Endpoint memory budget/ladder adapter — the AGENT-side counterpart of
`alert_manager/mem_appliance.py`.

WHAT THIS GOVERNS, AND — CRITICALLY — WHAT IT DOES NOT.
------------------------------------------------------
The appliance ladder governs Nemesis's OWN services (clamd, suricata, dashboard,
hw-monitor, …) and never touches anything else. This adapter is the honest
endpoint equivalent: it governs the NEMESIS AGENT'S OWN memory footprint — the
agent process and any child it spawns (a scan subprocess, a local Suricata) —
and NOTHING ELSE.

It MUST NEVER classify, act on, throttle, or terminate a user's own
applications. On a roaming personal machine those processes are the user's
browser, editor, game — not ours to police. The classifier below returns a
component name ONLY for our own process tree; every other PID is left
unclassified, which `membudget.evaluate()` ignores and the ladder can never act
on. That is the whole safety model, and it is enforced by the classifier, not by
convention.

FULLY SHADOW ON THE ENDPOINT — no rung executes, ever.
------------------------------------------------------
On the appliance, ALERT and THROTTLE execute live (throttling Nemesis's own
clamd is a safe, reversible act against our own service). On an endpoint there
is nothing safe to execute: the only thing in budget is the agent itself, and an
agent that throttled ITSELF would degrade the very protection the user relies
on. So `run_ladder_cycle_shadow()` decides and RECORDS what the ladder would do,
reports it as telemetry through the heartbeat, and executes nothing. This mirrors
the appliance's discipline of keeping unproven rungs in shadow — here every rung
is shadow, by construction, because the endpoint has no safe live executor.

REUSE. `procmem` (sampler), `membudget` (budget/deviation model) and `memladder`
(escalation decision) are all siblings in this directory and platform-neutral by
design — this adapter supplies only the endpoint's classifier and budget table,
exactly as `mem_appliance` supplies the appliance's. No sampling or ladder logic
is duplicated here.
"""
import logging
import os

import procmem
import membudget
import memladder

log = logging.getLogger("nemesis_agent.mem_agent")

__all__ = [
    "AGENT_BUDGETS", "AGENT_COMPONENT", "classify_process",
    "sample_and_evaluate", "run_ladder_cycle_shadow", "new_ladder_state",
    "self_test",
]

#: The single component this adapter budgets: the Nemesis agent's own footprint.
#: One name, because from the endpoint's point of view the agent (plus whatever
#: it spawns) is one thing to keep honest — not a fleet of services like the
#: appliance.
AGENT_COMPONENT = "nemesis-agent"

#: Budget as a PERCENTAGE OF TOTAL RAM, resolved against the machine's actual RAM
#: at evaluation time (never against a hardcoded size — see membudget). `max_mb`
#: caps it on a large machine (the agent's need does not grow with RAM); `min_mb`
#: floors it on a small one so a 4 GB netbook does not budget the agent to
#: nothing. These are a STARTING POINT, seeded from the agent's own reported
#: footprint (`agent_health.agent_ram_mb`, typically well under 150 MB), not a
#: model — expected to move once real endpoint data accrues, same status as the
#: appliance table.
AGENT_BUDGETS = {
    AGENT_COMPONENT: {"pct": 2.0, "min_mb": 128.0, "max_mb": 512.0,
                      "measured": "agent_health.agent_ram_mb, typically <150MB "
                                  "idle; 2% floors at 128MB / caps at 512MB"},
}


def _agent_pids():
    """The agent's own process tree: this process plus its descendants.

    Recomputed each cycle rather than cached — the agent spawns and reaps scan
    subprocesses over its lifetime, so the tree is not stable. Best-effort: a pid
    that vanishes mid-walk is simply not in the set, which is correct (a dead
    child is not part of our live footprint).
    """
    import psutil                                            # noqa: PLC0415
    me = os.getpid()
    pids = {me}
    try:
        proc = psutil.Process(me)
        for child in proc.children(recursive=True):
            pids.add(child.pid)
    except Exception as exc:                                 # noqa: BLE001
        # If we cannot enumerate children we still classify OURSELVES, which is
        # the dominant footprint. Never raise — a classifier failure must not
        # take down the sample.
        log.debug("could not enumerate agent children: %s", exc)
    return pids


def classify_process(proc_row, _agent_pids_set=None):
    """Map a sampled process row to a component name, or None.

    Returns `AGENT_COMPONENT` for the agent's own process tree and **None for
    everything else** — and that None is the entire safety guarantee. A row
    classified None is aggregated into no component, so `membudget.evaluate()`
    never budgets it and `memladder.decide()` can never act on it. The user's
    applications are, by construction, invisible to this ladder.
    """
    pids = _agent_pids_set if _agent_pids_set is not None else _agent_pids()
    pid = proc_row.get("pid")
    return AGENT_COMPONENT if pid in pids else None


def sample_and_evaluate(_sample=None, _pids=None):
    """Sample the agent's own footprint and judge it against AGENT_BUDGETS.

    Deliberately does NOT act — same contract as the appliance's
    `sample_and_evaluate`: the ladder owns the decision, this owns the
    measurement. `_sample`/`_pids` are test seams.
    """
    pid_set = _pids if _pids is not None else _agent_pids()
    sample = _sample if _sample is not None else procmem.sample_processes(
        classifier=lambda r: classify_process(r, _agent_pids_set=pid_set))
    verdicts = membudget.evaluate(sample, AGENT_BUDGETS)
    return verdicts


def new_ladder_state():
    """Fresh ladder state — plain dict, JSON-serialisable, held in the poll
    loop across cycles (the agent has no DB; the long-lived poll process IS the
    persistence, and re-arming on restart is acceptable for shadow observation,
    exactly as the appliance re-arms)."""
    return memladder.new_state()


def run_ladder_cycle_shadow(state, _sample=None, _pids=None):
    """One SHADOW ladder cycle: sample -> evaluate -> decide -> record intent.

    EXECUTES NOTHING. Returns (new_state, report) where `report` is telemetry for
    the heartbeat: the component verdict and the rung the ladder WOULD escalate
    to, with its mode. Every rung's mode is reported so the server can see the
    agent is self-observing without any endpoint action having been taken.

    Best-effort: never raises out — a memory-telemetry failure must not disturb
    the heartbeat it rides on. On failure it returns the state unchanged and a
    report marked unavailable, never a fabricated clean result.
    """
    try:
        verdicts = sample_and_evaluate(_sample=_sample, _pids=_pids)
        if verdicts.get("state") == "unavailable":
            return state, {"state": "unavailable",
                           "reason": verdicts.get("reason", "no sample")}

        # `available=None` -> every rung structurally exists; we then force the
        # WHOLE decision to shadow telemetry by never executing it. exempt is
        # empty: the only component here is our own, and it is not recovery-exempt
        # the way the appliance exempts clamd — but nothing executes regardless.
        new_state, actions = memladder.decide(verdicts, state)

        comp = (verdicts.get("components") or {}).get(AGENT_COMPONENT, {})
        # Edge-triggered: an escalation appears on the cycle it happens, not every
        # cycle the component stays at that rung -- same semantics as the
        # appliance's `actions`. Deliberately DROP each action's appliance-side
        # mode (live/shadow): on the endpoint NOTHING is live, so carrying the
        # appliance's rung-config mode here would falsely imply execution. The
        # top-level `mode: shadow` + `executed: []` are the honest, single answer.
        escalations = [
            {"component": a.get("component"), "rung": a.get("rung")}
            for a in actions if a.get("kind") == "escalate"
        ]
        report = {
            "state": "ok",
            "component": AGENT_COMPONENT,
            # membudget's own field names, not renamed here: verdict is one of
            # ok/breach/indeterminate/unbudgeted; the measurement is reported as
            # both uss and rss because which one the budget was judged against
            # depends on what could be measured (see membudget.evaluate).
            "verdict": comp.get("verdict"),
            "uss_mb": comp.get("uss_mb"),
            "rss_mb": comp.get("rss_mb"),
            "budget_mb": comp.get("budget_mb"),
            # What the ladder WOULD do — reported, never done. Explicit so a
            # reader can never mistake telemetry for an action taken.
            "would_escalate": escalations,
            "executed": [],                          # ALWAYS empty on the endpoint
            "mode": "shadow",
        }
        return new_state, report
    except Exception as exc:                                # noqa: BLE001
        log.debug("shadow ladder cycle failed: %s", exc)
        return state, {"state": "unavailable", "reason": str(exc)[:200]}


def self_test():
    """Prove the classifier produces BOTH answers before it is trusted — the
    same premise-check the appliance and the orphan/zombie classifiers run. A
    classifier that could only ever return None would silently make this feature
    a no-op that still LOOKS wired; one that returned the component for every pid
    would (if a live executor were ever added) act on the user's apps. Both
    failure modes are caught here on fixtures, on every call.
    """
    fake_pids = {111, 222}
    ours = classify_process({"pid": 111}, _agent_pids_set=fake_pids)
    if ours != AGENT_COMPONENT:
        raise AssertionError(
            "self-test: the agent's own pid did not classify as %s (got %r)"
            % (AGENT_COMPONENT, ours))
    theirs = classify_process({"pid": 999}, _agent_pids_set=fake_pids)
    if theirs is not None:
        raise AssertionError(
            "self-test: a NON-agent pid classified as %r — it MUST be None so "
            "the ladder can never touch a user's app" % (theirs,))

    # The budget must resolve to a real number against a real machine size, or
    # the whole evaluation is meaningless. Use a fixed size so the test is
    # deterministic.
    mb, err = membudget.resolve_budget_mb(AGENT_BUDGETS[AGENT_COMPONENT], 8192.0)
    if err or not mb:
        raise AssertionError("self-test: agent budget did not resolve: %s" % err)
    return True
