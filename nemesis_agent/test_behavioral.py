"""Tests for behavioral_events + behavioral_agent — the zero-day behavioral layer.

The three things that decide whether this layer helps or hurts, all tested:
  * FILTER — unmapped kernel noise is dropped at the door (the flood problem).
  * DEDUP + EXPLICIT RATE CEILING — a rule firing 500x/min is ONE finding count=500;
    beyond the cap, suppression is VISIBLE (a summary event), never silent.
  * CONSENT — no consent context, no event.
And that every event the pipeline emits passes the shared server-side schema, so a
producer bug can't smuggle a malformed record past validation.

Run: python3 nemesis_agent/test_behavioral.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import behavioral_events as be                               # noqa: E402
import behavioral_agent as ba                                # noqa: E402

_results = []


def check(label, got, want):
    ok = got == want
    _results.append((label, ok))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", label, got, want))


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def falco(rule, proc_name="evil", **fields):
    of = {"proc.name": proc_name}
    of.update(fields)
    return {"rule": rule, "output": "%s fired" % rule, "output_fields": of,
            "time": "2026-08-20T23:00:00"}


def main():
    print("schema — valid passes, malformed REJECTED (server never coerces)")
    ev = be.new_event("bulk_file_modify", "dev1", 3, "high", "falco", "Bulk file "
                      "modification", "2026-08-20T23:00:00", "dev1-1",
                      proc={"proc_name": "cryptor", "proc_pid": 42})
    check("a well-formed event validates clean", be.validate(ev), [])
    check("missing a required field -> error",
          bool(be.validate({k: v for k, v in ev.items() if k != "behavior"})), True)
    check("an unknown behavior -> error",
          any("behavior" in e for e in be.validate(dict(ev, behavior="wat"))), True)
    check("a bad severity -> error",
          any("severity" in e for e in be.validate(dict(ev, severity="apocalyptic"))),
          True)
    check("a non-int consent_version -> error",
          any("consent" in e for e in be.validate(dict(ev, consent_version="3"))), True)
    check("an over-long rule -> error",
          any("rule" in e for e in be.validate(dict(ev, rule="x" * 9999))), True)
    check("new_event truncates an over-long cmdline defensively",
          len(be.new_event("suspicious_process", "d", 1, "low", "falco", "r", "t",
                           "e", proc={"proc_cmdline": "y" * 99999})["proc_cmdline"])
          <= be._MAX_CMDLINE, True)

    print("\nFILTER — only mapped rules, at/above the severity floor, are forwarded")
    clk = Clock()
    m = ba.BehavioralMonitor("dev1", window_s=60, max_per_window=100,
                             severity_floor="low", clock=clk)
    check("an UNMAPPED falco rule is dropped",
          m.ingest_falco(falco("Some Benign Noise Rule"), 3), False)
    check("a MAPPED rule is forwarded",
          m.ingest_falco(falco("Bulk file modification"), 3), True)
    # severity floor
    m2 = ba.BehavioralMonitor("dev1", severity_floor="high", clock=Clock())
    check("a medium event is dropped under a HIGH floor",
          m2.ingest_falco(falco("Unexpected outbound connection"), 3), False)
    check("a high event passes the HIGH floor",
          m2.ingest_falco(falco("Run shell untrusted"), 3), True)

    print("\nnormalize — a mapped alert becomes the right behavior + proc context")
    m3 = ba.BehavioralMonitor("dev1", clock=Clock())
    m3.ingest_falco(falco("Non sudo setuid", proc_name="esc", **{"proc.pid": "9",
                    "user.name": "root"}), 5)
    e = m3.drain()[0]
    check("behavior mapped", e["behavior"], "privilege_escalation")
    check("severity mapped", e["severity"], "high")
    check("proc name carried", e["proc_name"], "esc")
    check("proc pid coerced to int", e["proc_pid"], 9)
    check("the emitted event passes the SERVER schema", be.validate(e), [])

    print("\nDEDUP — identical events collapse to one carrying a count")
    m4 = ba.BehavioralMonitor("dev1", clock=Clock())
    for _ in range(500):
        m4.ingest_falco(falco("Bulk file modification", proc_name="cryptor"), 3)
    drained = m4.drain()
    check("500 identical events -> ONE event", len(drained), 1)
    check("...with count=500", drained[0]["count"], 500)
    # different proc_name is a different event, not deduped together
    m5 = ba.BehavioralMonitor("dev1", clock=Clock())
    m5.ingest_falco(falco("Bulk file modification", proc_name="a"), 3)
    m5.ingest_falco(falco("Bulk file modification", proc_name="b"), 3)
    check("distinct proc names -> distinct events", len(m5.drain()), 2)

    print("\nRATE CEILING — beyond the cap, suppression is EXPLICIT (a summary event)")
    m6 = ba.BehavioralMonitor("dev1", window_s=60, max_per_window=5, clock=Clock())
    for i in range(20):                       # 20 DISTINCT events, cap is 5
        m6.ingest_falco(falco("Run shell untrusted", proc_name="p%d" % i), 3)
    out = m6.drain()
    forwarded = [e for e in out if e["rule"] != "__rate_suppressed__"]
    supp = [e for e in out if e["rule"] == "__rate_suppressed__"]
    check("only the cap's worth are forwarded", len(forwarded), 5)
    check("...and there IS an explicit suppression summary", len(supp), 1)
    check("...naming how many were suppressed", supp[0]["count"], 15)
    check("...the suppression summary itself passes schema", be.validate(supp[0]), [])

    print("\nCONSENT gate — no consent_version, no event")
    m7 = ba.BehavioralMonitor("dev1", clock=Clock())
    check("a mapped, high event with NO consent is dropped",
          m7.ingest_falco(falco("Run shell untrusted"), None), False)
    check("...and nothing is buffered", m7.drain(), [])

    print("\nwindow roll — the ceiling resets each window (a burst isn't permanent)")
    clk2 = Clock()
    m8 = ba.BehavioralMonitor("dev1", window_s=60, max_per_window=2, clock=clk2)
    for i in range(5):
        m8.ingest_falco(falco("Run shell untrusted", proc_name="p%d" % i), 3)
    m8.drain()                                 # window 1: 2 forwarded, 3 suppressed
    clk2.advance(61)                           # new window
    check("a new window forwards again (ceiling reset)",
          m8.ingest_falco(falco("Run shell untrusted", proc_name="fresh"), 3), True)

    print("\nsysmon front door normalizes the same way")
    m9 = ba.BehavioralMonitor("dev1", clock=Clock())
    check("a normalized sysmon event is accepted",
          m9.ingest_sysmon({"behavior": "suspicious_network", "severity": "high",
                            "rule": "Sysmon-3", "proc": {"proc_name": "nc.exe"}}, 2),
          True)
    check("a sysmon event with an unknown behavior is dropped",
          m9.ingest_sysmon({"behavior": "not_a_thing"}, 2), False)

    print("\nstatus_reader — reports the coverage gap when falco is absent")
    present, _, _, running = ba.status_reader()
    # on the build box falco is absent -> not present, not running
    check("falco absent here -> not present", present, False)
    check("...and not running", running, False)

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
