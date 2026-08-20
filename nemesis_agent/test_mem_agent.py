"""Tests for mem_agent — the endpoint memory budget/ladder adapter.

The property that matters most and is checked hardest: the ladder can NEVER act
on a user's process. That is enforced by the classifier returning None for any
non-agent pid, so these tests hammer that specifically, on fixtures, both ways.

Run: python3 nemesis_agent/test_mem_agent.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import mem_agent                                             # noqa: E402
import memladder                                            # noqa: E402

_results = []


def check(label, got, want):
    ok = got == want
    _results.append((label, ok))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", label, got, want))


def main():
    print("classifier — the safety boundary")
    pids = {100, 101}
    check("the agent's own pid -> the agent component",
          mem_agent.classify_process({"pid": 100}, _agent_pids_set=pids),
          mem_agent.AGENT_COMPONENT)
    check("a child pid in the tree -> the agent component",
          mem_agent.classify_process({"pid": 101}, _agent_pids_set=pids),
          mem_agent.AGENT_COMPONENT)
    # THE ONE THAT MATTERS: a user's app must be invisible.
    check("a NON-agent pid -> None (user apps are invisible to the ladder)",
          mem_agent.classify_process({"pid": 999}, _agent_pids_set=pids),
          None)
    check("a pid of 0 / missing -> None, never accidentally ours",
          mem_agent.classify_process({}, _agent_pids_set=pids),
          None)

    print("\nself-test proves BOTH answers on every call")
    check("self_test passes", mem_agent.self_test(), True)

    print("\nsample_and_evaluate on a fixture (no live sampling)")
    # A sample carrying ONE agent component under budget, and a user process the
    # classifier already excluded (so it never reaches a component at all).
    sample = {
        "state": "ok",
        "total_ram_mb": 8192.0,
        "components": {
            mem_agent.AGENT_COMPONENT: {"rss_mb": 40.0, "uss_mb": 30.0},
        },
    }
    verdicts = mem_agent.sample_and_evaluate(_sample=sample)
    comp = verdicts["components"][mem_agent.AGENT_COMPONENT]
    check("agent well under budget -> verdict ok", comp["verdict"], "ok")
    check("budget resolved to a real number", isinstance(comp["budget_mb"], float), True)

    print("\nshadow cycle EXECUTES NOTHING, even on a breach")
    # Force a SOUND breach: agent way over budget, with uss_complete so USS is
    # the basis the budget is judged against (without it, RSS-over-budget is
    # honestly INDETERMINATE, not a breach -- see membudget._component_observation).
    # On the appliance a sound breach could execute a live throttle; on the
    # endpoint it must only ever RECORD intent.
    breach_sample = {
        "state": "ok",
        "total_ram_mb": 8192.0,
        "components": {
            mem_agent.AGENT_COMPONENT: {"rss_mb": 5000.0, "uss_mb": 5000.0,
                                        "uss_complete": True},
        },
    }
    state = mem_agent.new_ladder_state()
    # Escalations are EDGE-triggered (they appear on the transition cycle, not
    # every cycle at that rung -- same as the appliance's actions), so collect
    # would-be actions across the run rather than reading only the last cycle.
    all_would = []
    saw_breach = False
    executed_ever = []
    for _ in range(6):
        state, report = mem_agent.run_ladder_cycle_shadow(_sample=breach_sample,
                                                          state=state)
        if report.get("verdict") == "breach":
            saw_breach = True
        all_would.extend(report.get("would_escalate", []))
        executed_ever.extend(report.get("executed", []))
        check("mode is shadow on every cycle", report["mode"], "shadow")
    check("a sustained breach is reported, not hidden", saw_breach, True)
    check("NOTHING was executed across the whole breach run", executed_ever, [])
    check("the ladder DID record what it would do (edge-triggered escalations seen)",
          len(all_would) > 0, True)
    check("every would-be action is on OUR component only",
          all(a["component"] == mem_agent.AGENT_COMPONENT for a in all_would), True)
    check("would-be actions carry no misleading live/shadow mode per action",
          all("mode" not in a for a in all_would), True)

    print("\nunavailable sample -> explicit unavailable, never a fake clean report")
    state = mem_agent.new_ladder_state()
    state2, report = mem_agent.run_ladder_cycle_shadow(
        _sample={"state": "unavailable", "reason": "psutil down"}, state=state)
    check("unavailable is surfaced", report["state"], "unavailable")
    check("state is unchanged on unavailable", state2, state)

    print("\nLIVE end-to-end on this process (stands in for the agent)")
    st = mem_agent.new_ladder_state()
    st, live = mem_agent.run_ladder_cycle_shadow(state=st)
    check("live cycle reports the agent component", live.get("component"),
          mem_agent.AGENT_COMPONENT)
    check("live cycle executed nothing", live.get("executed"), [])
    check("this process is under budget (verdict ok)", live.get("verdict"), "ok")

    passed = sum(1 for _, ok in _results if ok)
    print("\n%d/%d checks passed" % (passed, len(_results)))
    failed = [l for l, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  -", f)
        sys.exit(1)


if __name__ == "__main__":
    main()
