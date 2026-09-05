#!/usr/bin/env python3
"""Agent check-in intervals must carry a desynchronisation splay.

Run: python3 nemesis_agent/test_poll_jitter.py   (exit 0 = all pass)

THE DEFECT (PUNCHLIST, found 2026-08-05; fixed 2026-09-05)
    `agent.py` had zero randomisation anywhere in its beat scheduling. The chain
    `_ramp_interval` -> `_clamp_poll_hint` -> `_effective_interval` is fully
    deterministic, so given the same beat index and poll interval every agent
    computes an identical sleep and they never drift apart.

    MEASURED, not theorised (gauge VM, Phase 4, 100 simulated devices, DB write
    path): 100 devices writing SIMULTANEOUSLY gave p95 3140ms / max 3541ms; the
    same 100 writing a THOUSAND times more often but staggered gave p95 105ms.
    SQLite serialises writes, so the worst case for this system is synchronised
    load, not sustained load. A power cut or a mass agent restart starts every
    clock at the same instant, and without splay the herd stays locked forever.

WHAT IS ASSERTED, AND THE ONE THING THAT IS NOT
    This proves the splay's CONTRACT: bounded, subtract-only, floor-respecting,
    and that a lockstep fleet actually separates. It does NOT re-measure the
    contention numbers above -- that needed 100 VMs and belongs to the gauge run,
    not to a unit test. A test claiming to prove those here would be measuring
    nothing and saying otherwise.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from nemesis_agent import agent  # noqa: E402

EXPECTED_CHECKS = 12
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 40:
        g, w = g[:37] + "...", w[:37] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


BASE = 300.0


def main():
    J = agent._jittered_interval
    FLOOR = agent.POLL_INTERVAL_FLOOR
    FRAC = agent.POLL_JITTER_FRACTION

    print("1. CONTROL: the underlying chain really is deterministic")
    # If this failed, the splay would not be the thing creating variation and
    # every assertion below would be measuring something else.
    a = agent._effective_interval(5, 300, None)
    b = agent._effective_interval(5, 300, None)
    check("_effective_interval is deterministic for identical inputs", a == b, True)

    print("\n2. the splay SUBTRACTS ONLY -- never lengthens an interval")
    # Security property: _effective_interval refuses to let a server hint
    # lengthen an interval. Positive jitter would be the first thing in the
    # chain able to make an agent quieter than configured.
    check("rand=0.0 -> exactly the base (no lengthening at the boundary)",
          J(BASE, _rand=lambda: 0.0), BASE)
    check("rand~1.0 -> strictly LESS than the base",
          J(BASE, _rand=lambda: 0.999999) < BASE, True)
    check("no draw ever exceeds the base",
          all(J(BASE, _rand=(lambda v=v: v)) <= BASE
              for v in (0.0, 0.25, 0.5, 0.75, 0.999999)), True)

    print("\n3. the splay is BOUNDED by POLL_JITTER_FRACTION")
    lo = min(J(BASE, _rand=(lambda v=v: v)) for v in (0.0, 0.5, 0.999999))
    check("never subtracts more than the configured fraction",
          lo >= BASE * (1.0 - FRAC) - 1e-9, True)
    check("the fraction is small (a splay, not a cadence change)",
          0.0 < FRAC <= 0.25, True)

    print("\n4. the floor is still absolute")
    check("a floor-length interval cannot be driven below the floor",
          J(float(FLOOR), _rand=lambda: 1.0) >= FLOOR, True)
    check("  ...even with an absurd fraction",
          J(float(FLOOR), _rand=lambda: 999.0) >= FLOOR, True)

    print("\n5. it actually DESYNCHRONISES -- the point of the change")
    # A fleet whose clocks start together must not stay together. Uses the real
    # random source, because "does the production default separate a herd" is
    # the question; a stubbed source would answer a different one.
    fleet = [J(BASE) for _ in range(200)]
    check("200 agents on an identical interval produce >1 distinct sleep",
          len(set(fleet)) > 1, True)
    check("  ...and spread over a meaningful share of the splay window",
          (max(fleet) - min(fleet)) > (BASE * FRAC * 0.5), True)
    check("  ...with every member still inside the contract",
          all(FLOOR <= x <= BASE for x in fleet), True)

    print("\n6. the production default is the real random source")
    # Guards against the injected seam silently becoming the default.
    import inspect
    dflt = inspect.signature(J).parameters["_rand"].default
    check("_rand defaults to random.random", dflt is __import__("random").random, True)

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [l for l, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
