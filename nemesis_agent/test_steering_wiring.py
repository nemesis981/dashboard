"""Tests that the steering controller is wired into the agent SAFELY — above all,
that it is INERT by default and doubly interlocked.

The point of this suite is the negative space: with the shipped defaults, enabling
nothing, the agent must create no controller, gather no evidence that grants a
lease, and steer nothing. Plus the two helpers that decide entitlement.

Run: python3 nemesis_agent/test_steering_wiring.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import config                                                # noqa: E402
import agent                                                 # noqa: E402
import steering_lease as sl                                  # noqa: E402

_results = []


def check(label, got, want):
    ok = got == want
    _results.append((label, ok))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", label, got, want))


def main():
    print("DEFAULT OFF — the shipped config arms nothing")
    defaults = dict(config.DEFAULTS)
    check("steering_enabled ships false", defaults["steering_enabled"], "false")
    check("steering_gate_armed ships false", defaults["steering_gate_armed"], "false")
    check("_init_steering returns None on the default config",
          agent._init_steering(defaults), None)

    print("\nthe status snapshot reports steering=None when not armed")
    prev = agent._steering
    try:
        agent._steering = None
        snap = agent._status_snapshot()
        check("snapshot carries a steering key", "steering" in snap, True)
        check("...and it is None when unarmed", snap["steering"], None)
    finally:
        agent._steering = prev

    print("\nDOUBLE INTERLOCK — even enabled, a lease needs the pushed gate-armed signal")
    # evidence: approved + reachable, but gate_armed comes from steering_gate_armed
    # which no channel sets, so it is false -> evidence not ok -> lease never grants.
    conf = dict(config.DEFAULTS, enrollment_status="approved")
    ev = agent._steering_evidence(conf, appliance_reachable=True)
    check("reachable is honoured", ev.appliance_reachable, True)
    check("approved is honoured", ev.device_approved, True)
    check("gate_armed is false by default (no downward push yet)", ev.gate_armed, False)
    check("...so the evidence does NOT entitle steering", ev.ok, False)
    check("...and names gate as the missing fact",
          "gate_not_armed" in ev.missing(), True)

    # only when ALL THREE hold does it entitle
    conf2 = dict(config.DEFAULTS, enrollment_status="approved",
                 steering_gate_armed="true")
    check("all three present -> entitled",
          agent._steering_evidence(conf2, True).ok, True)
    check("...but not if the appliance is unreachable",
          agent._steering_evidence(conf2, False).ok, False)
    check("...and not if not approved",
          agent._steering_evidence(dict(conf2, enrollment_status="pending"), True).ok,
          False)

    print("\nplan parsing — no forwarder port => inert (nothing to steer to)")
    check("empty port -> None", agent._steering_plan(config.DEFAULTS)["forwarder_port"],
          None)
    check("a real port parses",
          agent._steering_plan(dict(config.DEFAULTS,
                                    steering_forwarder_port="9040"))["forwarder_port"],
          9040)
    check("a garbage port -> None (inert, not a crash)",
          agent._steering_plan(dict(config.DEFAULTS,
                                    steering_forwarder_port="xyz"))["forwarder_port"],
          None)

    print("\nttl is floor-guarded")
    check("a sane ttl passes through", agent._steering_ttl(
        dict(config.DEFAULTS, steering_lease_ttl="900")), 900)
    check("a tiny ttl is floored (can't thrash)",
          agent._steering_ttl(dict(config.DEFAULTS, steering_lease_ttl="1"))
          >= agent.POLL_INTERVAL_FLOOR * 2, True)
    check("a garbage ttl falls back, floored",
          agent._steering_ttl(dict(config.DEFAULTS, steering_lease_ttl="nope"))
          >= agent.POLL_INTERVAL_FLOOR * 2, True)

    print("\nenabled + entitled DOES arm, end to end (recording backend, no OS)")
    # Prove the wired evidence path actually grants a lease when everything holds,
    # using a controller over the recording backend so no nft/root is involved.
    backend = sl.NullRecordingBackend()

    class Clock:
        def __init__(self): self.t = 1000.0
        def __call__(self): return self.t
        def advance(self, dt): self.t += dt
    clock = Clock()
    ctrl = sl.SteeringController(backend, ttl_seconds=100.0, clock=clock)
    ctrl.reconcile_boot()
    ev_ok = agent._steering_evidence(conf2, True)
    check("the wired evidence, fed to a controller, arms steering",
          ctrl.on_heartbeat(ev_ok, plan=agent._steering_plan(config.DEFAULTS)), True)
    check("...steering active", backend.read_state().active, True)
    # and the DEFAULT evidence (gate not armed) does NOT
    backend2 = sl.NullRecordingBackend()
    ctrl2 = sl.SteeringController(backend2, ttl_seconds=100.0, clock=clock)
    ctrl2.reconcile_boot()
    ctrl2.on_heartbeat(agent._steering_evidence(conf, True))   # gate not armed
    check("default (gate-off) evidence steers NOTHING", backend2.read_state().active,
          False)

    print("\nthe appliance-pushed gate signal (downward push, tunnel-back §5.2)")
    # _gate_armed is the authoritative source; simulate the response handler setting it.
    prev_ga = agent._gate_armed
    try:
        agent._gate_armed = False
        check("with no push, gate_armed is false",
              agent._steering_evidence(dict(config.DEFAULTS,
                                            enrollment_status="approved"),
                                       True).gate_armed, False)
        agent._gate_armed = True                # appliance pushed 'armed'
        ev = agent._steering_evidence(dict(config.DEFAULTS,
                                           enrollment_status="approved"), True)
        check("a pushed 'armed' sets gate_armed", ev.gate_armed, True)
        check("...and with reachable+approved, the lease is entitled", ev.ok, True)
        # fresh-only: a failed/omitting response leaves it false
        agent._gate_armed = False
        check("push cleared -> not entitled again",
              agent._steering_evidence(dict(config.DEFAULTS,
                                            enrollment_status="approved"),
                                       True).ok, False)
    finally:
        agent._gate_armed = prev_ga

    print("\nthe receive path: a response's steering_gate_armed sets _gate_armed")
    # _handle_response_tasks reads the hint fields; with no task anchor it returns
    # after the hints, which is exactly the path we exercise.
    class _Resp:
        def __init__(self, body): self._b = body
        def json(self): return self._b
    prev_anchor = getattr(agent, "_task_anchor", None)
    prev_ga2 = agent._gate_armed
    try:
        agent._task_anchor = None
        agent._gate_armed = False
        agent._handle_response_tasks(_Resp({"ok": True, "steering_gate_armed": True}),
                                     "dev-1")
        check("a response saying armed sets _gate_armed True", agent._gate_armed, True)
        # fresh-only: a response that OMITS the field resets it to False
        agent._handle_response_tasks(_Resp({"ok": True}), "dev-1")
        check("a response omitting the field resets to False (fresh-only)",
              agent._gate_armed, False)
        # and a response saying not-armed keeps it False
        agent._gate_armed = True
        agent._handle_response_tasks(_Resp({"steering_gate_armed": False}), "dev-1")
        check("a response saying not-armed clears it", agent._gate_armed, False)
        # a non-JSON / older-server response must not crash and must not arm
        class _Bad:
            def json(self): raise ValueError("not json")
        agent._gate_armed = False
        agent._handle_response_tasks(_Bad(), "dev-1")
        check("a non-JSON response leaves _gate_armed False (no arm on garbage)",
              agent._gate_armed, False)
    finally:
        agent._task_anchor = prev_anchor
        agent._gate_armed = prev_ga2

    print("\n_gate_armed re-arms to False on module load (restart never inherits arm)")
    check("the module global defaults False", agent._gate_armed in (False,), True)

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
