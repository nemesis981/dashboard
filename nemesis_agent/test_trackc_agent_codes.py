#!/usr/bin/env python3
"""Track C agent side: E-AGENT-121/122/123 from REAL failure paths.

Run: python3 nemesis_agent/test_trackc_agent_codes.py

WHAT WAS MISSING. `consent.py` and `conn_collector.py` referenced
`agent_errors` ZERO times while that catalog carried 37 codes. So:

  * a corrupt consent record failed CLOSED -- correct -- and switched off all
    six telemetry items, leaving a device that silently reports NOTHING and is
    indistinguishable from a quiet one. The only trace was a `status()` field
    nobody polls.
  * a revocation whose tombstone could not be written left collection RUNNING
    while the user believed it had stopped. Correctly reported to the caller,
    recorded nowhere.
  * every dropped connection record -- the telemetry Track C exists to collect
    -- went into a `self.stats[...]` counter and no further.

⚠ AND THE COVERAGE CHECK COULD NOT HAVE CAUGHT ANY OF IT. Neither file was in
`test_agent_errors.py`'s scanned list, so its phantom check never read them: a
file that is never scanned cannot be reported as unwired. Adding the files to
that list and adding the codes were two separate acts and both were needed.

CONTROLS THROUGHOUT. Each "it records" is paired with a healthy path that must
record NOTHING -- an ABSENT consent record in particular is a legitimate state
(the device has simply never consented) and must stay quiet, or every
un-enrolled endpoint would report a fault.
"""
import json
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import config                                                 # noqa: E402

_tmp = tempfile.mkdtemp(prefix="trackc-codes-")
config.CONF_PATH = os.path.join(_tmp, "nemesis_agent.conf")

import agent_errors as ae                                     # noqa: E402
import consent                                                # noqa: E402

EXPECTED_CHECKS = 19
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 40:
        g, w = g[:37] + "...", w[:37] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def counts():
    return {c: d["count"] for c, d in ae.snapshot().items()}


def write_state(text):
    os.makedirs(os.path.dirname(consent.state_path()), exist_ok=True)
    with open(consent.state_path(), "w", encoding="utf-8") as f:
        f.write(text)


def clear_state():
    try:
        os.remove(consent.state_path())
    except OSError:
        pass


def main():
    print("\n1. CONTROL: an ABSENT consent record is legitimate and stays quiet")
    # If this ever records, every endpoint that has simply never consented
    # reports a fault, and the signal is worthless.
    ae.reset()
    clear_state()
    rec, state = consent._read_record()
    check("absent -> STATE_ABSENT", state, consent.STATE_ABSENT)
    check("...and records NOTHING", counts().get("E-AGENT-122"), None)

    print("\n2. a CORRUPT record fails closed AND is recorded")
    ae.reset()
    write_state("{ this is not json")
    rec, state = consent._read_record()
    check("unparseable -> STATE_CORRUPT", state, consent.STATE_CORRUPT)
    check("...records E-AGENT-122", counts().get("E-AGENT-122"), 1)

    ae.reset()
    write_state('"a string, not an object"')
    rec, state = consent._read_record()
    check("valid JSON of the wrong shape -> STATE_CORRUPT", state,
          consent.STATE_CORRUPT)
    check("...also records E-AGENT-122", counts().get("E-AGENT-122"), 1)

    print("\n3. CONTROL: a VALID record records nothing")
    ae.reset()
    write_state(json.dumps({"record_schema": consent._RECORD_SCHEMA,
                            "device_id": "d1",
                            "telemetry": {consent.ITEM_CONNECTIONS: True}}))
    rec, state = consent._read_record()
    check("valid record is not CORRUPT", state != consent.STATE_CORRUPT, True)
    check("...and records nothing", counts().get("E-AGENT-122"), None)

    print("\n3b. EVERY corrupt shape records, not just the first two")
    # My first wiring covered 2 of the 6 STATE_CORRUPT returns; this suite
    # caught it. Each distinct corrupt shape is exercised separately so a
    # future unwired path fails here rather than going quiet.
    for label, body in (
            ("unrecognised schema", '{"record_schema": 99}'),
            ("telemetry not an object",
             json.dumps({"record_schema": consent._RECORD_SCHEMA,
                         "telemetry": "nope"})),
            ("unknown telemetry key",
             json.dumps({"record_schema": consent._RECORD_SCHEMA,
                         "telemetry": {"not_a_real_item": True}}))):
        ae.reset(); write_state(body)
        _r, st = consent._read_record()
        check("%-24s -> corrupt AND recorded" % label,
              (st, counts().get("E-AGENT-122")), (consent.STATE_CORRUPT, 1))

    print("\n4. the hot path aggregates rather than floods")
    # _read_record is called on every gate check. agent_errors aggregates by
    # code, which is what makes recording here safe.
    ae.reset()
    write_state("{ broken")
    for _ in range(50):
        consent._read_record()
    check("50 corrupt reads -> ONE code entry", len(counts()), 1)
    check("...with a count of 50, not 50 entries",
          counts().get("E-AGENT-122"), 50)

    print("\n5. a revocation that cannot be written is recorded")
    ae.reset()
    real_set = consent.set_enabled
    consent.set_enabled = lambda *a, **k: (_ for _ in ()).throw(
        OSError("read-only filesystem"))
    try:
        out = consent.revoke(device_id="d1")
    finally:
        consent.set_enabled = real_set
    check("caller is told it FAILED, not that it succeeded",
          out["revoked"], False)
    check("...and E-AGENT-123 is recorded", counts().get("E-AGENT-123"), 1)

    print("\n6. CONTROL: a revocation that SUCCEEDS records nothing")
    ae.reset()
    write_state(json.dumps({"record_schema": consent._RECORD_SCHEMA,
                            "device_id": "d1",
                            "telemetry": {consent.ITEM_CONNECTIONS: True}}))
    out = consent.revoke(device_id="d1")
    check("reports success", out["revoked"], True)
    check("...and records no failure code", counts().get("E-AGENT-123"), None)

    print("\n7. the collector's drop counter is wired to E-AGENT-121")
    import conn_collector                                      # noqa: PLC0415
    ae.reset()
    conn_collector._record_error("E-AGENT-121", "close")
    check("a drop records E-AGENT-121", counts().get("E-AGENT-121"), 1)
    # CONTROL: the helper must never raise into the collector, even when the
    # catalog is unavailable -- a telemetry helper must not be the reason
    # connection collection stops.
    real_imp = __builtins__.__import__ if hasattr(__builtins__, "__import__") \
        else __import__

    def blocked(name, *a, **k):
        if name == "agent_errors":
            raise ImportError("simulated: catalog unavailable")
        return real_imp(name, *a, **k)
    try:
        __builtins__.__import__ = blocked
        conn_collector._record_error("E-AGENT-121", "close")
        raised = None
    except Exception as exc:                                   # noqa: BLE001
        raised = type(exc).__name__
    finally:
        __builtins__.__import__ = real_imp
    check("CONTROL never raises when agent_errors is unavailable", raised, None)

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
