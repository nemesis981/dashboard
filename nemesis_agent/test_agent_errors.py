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

    print("\nrestore() — the merge-back-on-failed-POST safety valve")
    ae.reset()
    # basic merge: a drained digest restores intact
    ae.record("E-AGENT-001", "a"); ae.record("E-AGENT-030", "b")
    d = ae.drain()
    check("drain cleared before restore", ae.snapshot(), {})
    ae.restore(d)
    check("restore re-populates the drained codes",
          set(ae.snapshot()), {"E-AGENT-001", "E-AGENT-030"})
    check("  ...with the original counts", ae.snapshot()["E-AGENT-001"]["count"], 1)

    # merge INTO an existing counter (new occurrences accrued after the drain)
    ae.reset()
    ae.record("E-AGENT-001", "first")
    d = ae.drain()                          # count 1, cleared
    ae.record("E-AGENT-001", "accrued-after-drain")   # count 1 again, live
    ae.restore(d)                           # merge the drained 1 back
    check("restore MERGES into a live counter (1 drained + 1 new = 2)",
          ae.snapshot()["E-AGENT-001"]["count"], 2)

    # earliest first / latest last survive the merge
    ae.reset()
    ae.restore([{"code": "E-AGENT-002", "count": 3,
                 "first": "2026-08-20T10:00:00+00:00",
                 "last":  "2026-08-20T10:05:00+00:00", "context": "old"}])
    ae.record("E-AGENT-002", "new")         # stamps now (>= 2026), count -> 4
    snap = ae.snapshot()["E-AGENT-002"]
    check("merged count adds (3 restored + 1 new)", snap["count"], 4)
    check("earliest first is kept", snap["first"], "2026-08-20T10:00:00+00:00")

    # malformed / hostile input never raises, and is dropped
    for bad in (None, "x", 12345, [{"code": "E-AGENT-NOPE", "count": 1}],
                [{"code": "not-a-code", "count": 5}], [{"count": 2}],
                [{"code": "E-AGENT-001", "count": 0}],
                [{"code": "E-AGENT-001", "count": -3}]):
        ae.reset()
        try:
            ae.restore(bad); raised = False
        except Exception:
            raised = True
        check("restore(%.30r) never raises" % (bad,), raised, False)
    ae.reset()
    ae.restore([{"code": "E-AGENT-NOPE", "count": 1}])
    check("a malformed code in a digest is DROPPED, not stored", ae.snapshot(), {})
    ae.reset()
    ae.restore([{"code": "E-AGENT-001", "count": 0}])
    ae.restore([{"code": "E-AGENT-001", "count": -3}])
    check("zero/negative counts are dropped", ae.snapshot(), {})

    # THE ROUND-TRIP that proves no double-counting: drain -> restore -> drain
    ae.reset()
    ae.record("E-AGENT-001"); ae.record("E-AGENT-001"); ae.record("E-AGENT-030")
    d1 = ae.drain()                         # [001:2, 030:1], cleared
    ae.restore(d1)                          # failed POST -> merged back
    d2 = ae.drain()                         # retried next beat, cleared again
    by = {e["code"]: e["count"] for e in d2}
    check("drain->restore->drain yields the SAME counts (no double-count)",
          by, {"E-AGENT-001": 2, "E-AGENT-030": 1})
    check("  ...and the recorder is empty after the second drain", ae.snapshot(), {})
    ae.reset()

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
              "platforms/linux.py", "platforms/mac.py",
              # agent_gui.py reports its OWN render failures over the control channel
              # (report_gui_error), which the daemon turns into a record() -- so the
              # GUI reporting site counts as wiring a code just as record() does.
              "agent_gui.py",
              # privileged-IPC subsystem (step 3b): the SYSTEM service and the
              # session-side client record their own auth/start failures.
              "privservice.py", "privclient.py"):
        try:
            src += io.open(os.path.join(HERE, f), encoding="utf-8").read()
        except OSError:
            pass
    wired = set(re.findall(r'(?:record|report_gui_error)\("(E-AGENT-\d{3})"', src))
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
