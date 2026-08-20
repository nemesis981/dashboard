"""Tests for agent_errors — the agent-side structured error recorder.

Run: python3 nemesis_agent/test_agent_errors.py
"""
import io
import os
import re
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import agent_errors as ae                                    # noqa: E402

_results = []


def check(label, got, want):
    ok = got == want
    _results.append((label, ok))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", label, got, want))


def main():
    print("catalog is well-formed")
    check("self_test passes", ae.self_test(), True)
    check("every code matches E-AGENT-NNN",
          all(ae.CODE_RE.match(c) for c in ae.E_AGENT_CODES), True)
    check("every entry is (short, desc, severity)",
          all(isinstance(v, tuple) and len(v) == 3 for v in ae.E_AGENT_CODES.values()), True)
    check("every severity is low/medium/high",
          all(v[2] in ("low", "medium", "high") for v in ae.E_AGENT_CODES.values()), True)

    print("\nrecord / snapshot / drain")
    ae.reset()
    ae.record("E-AGENT-001", "ctx1")
    ae.record("E-AGENT-001", "ctx2")
    ae.record("E-AGENT-030", "signing failed")
    snap = ae.snapshot()
    check("aggregates by code (count)", snap["E-AGENT-001"]["count"], 2)
    check("last context wins", snap["E-AGENT-001"]["last_context"], "ctx2")
    check("distinct codes tracked separately", set(snap), {"E-AGENT-001", "E-AGENT-030"})
    check("snapshot does NOT clear", ae.snapshot()["E-AGENT-001"]["count"], 2)
    drained = ae.drain()
    check("drain returns one entry per code", len(drained), 2)
    check("drain clears", ae.snapshot(), {})

    print("\nfailure-only discipline + best-effort (never raises)")
    ae.reset()
    ae.record("E-AGENT-NOPE", "malformed")     # not E-AGENT-NNN
    ae.record("not a code at all")
    ae.record(None)
    ae.record(12345)
    check("malformed / non-string codes are dropped, not stored", ae.snapshot(), {})
    # best-effort: even a context that blows up on str() must not raise
    class Boom:
        def __str__(self): raise ValueError("boom")
    try:
        ae.record("E-AGENT-001", Boom())
        raised = False
    except Exception:
        raised = True
    check("record never raises, even on a hostile context", raised, False)

    print("\ncontext is length-capped (bounded input)")
    ae.reset()
    ae.record("E-AGENT-001", "x" * 5000)
    check("context capped at _MAX_CONTEXT",
          len(ae.snapshot()["E-AGENT-001"]["last_context"]) <= ae._MAX_CONTEXT, True)

    print("\nbounded by construction: N distinct codes, not N events")
    ae.reset()
    for _ in range(10000):
        ae.record("E-AGENT-001", "flood")
    check("10k records of one code -> still ONE entry", len(ae.snapshot()), 1)
    check("  ...with the real count", ae.snapshot()["E-AGENT-001"]["count"], 10000)

    print("\nthread-safe under concurrent records")
    ae.reset()
    def worker():
        for _ in range(1000):
            ae.record("E-AGENT-002", "t")
    ts = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    check("8 threads x 1000 records = 8000 (no lost/corrupt counts)",
          ae.snapshot()["E-AGENT-002"]["count"], 8000)
    ae.reset()

    print("\nCATALOG COVERAGE: every declared code is wired to a real site, and vice versa")
    src = ""
    for f in ("agent.py", "l2_windivert.py", "dns_enforce.py", "attest.py",
              "enrollment.py", "tasks.py", "platforms/windows.py",
              "platforms/linux.py", "platforms/mac.py"):
        try:
            src += io.open(os.path.join(HERE, f), encoding="utf-8").read()
        except OSError:
            pass
    wired = set(re.findall(r'record\("(E-AGENT-\d{3})"', src))
    catalog = set(ae.E_AGENT_CODES)
    check("no phantom codes (declared but never recorded)", sorted(catalog - wired), [])
    check("no undeclared codes (recorded but not in catalog)", sorted(wired - catalog), [])

    passed = sum(1 for _, ok in _results if ok)
    print("\n%d/%d checks passed" % (passed, len(_results)))
    if passed != len(_results):
        print("FAILED:", [l for l, ok in _results if not ok])
        sys.exit(1)


if __name__ == "__main__":
    main()
