"""Track C Piece 1 — the connection-event schema validator discriminates.

Run: python3 nemesis_agent/test_conn_events.py

Every rule is asserted in BOTH directions: a record that must validate and a
near-identical one that must not. A validator suite made only of rejections would
pass against `return False, ["nope"]`, and one made only of acceptances would pass
against `return True, []` — neither would be measuring anything.

Rule 8: addresses here are documentation ranges only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import conn_events as ce            # noqa: E402

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    ok = bool(cond)
    print(("  [PASS] " if ok else "  [FAIL] ") + name + ("" if ok or not detail else "  (%s)" % detail))
    if ok:
        passed += 1
    else:
        failed += 1


def base(**over):
    rec = {
        "schema_version": ce.SCHEMA_VERSION,
        "event": ce.EVENT_OPEN, "conn_id": "c-1", "device_id": "dev-1",
        "consent_version": 1,
        "proto": "tcp", "laddr": "192.0.2.10", "lport": 51000,
        "raddr": "198.51.100.20", "rport": 443,
        "ts_open_wall": "2026-08-07T12:00:00-0500", "ts_open_mono": 1000.0,
        "ts_close_wall": None, "ts_close_mono": None,
        "pid": 4242, "proc_name": "curl", "proc_path": "/usr/bin/curl",
        "proc_signed": ce.SIGNED_UNKNOWN,
        "bytes_sent": None, "bytes_recv": None,
        "resolved_name": None, "resolved_name_source": ce.NAME_SRC_UNAVAILABLE,
    }
    rec.update(over)
    return rec


def closed(**over):
    o = {"event": ce.EVENT_CLOSE, "ts_close_wall": "2026-08-07T12:00:09-0500",
         "ts_close_mono": 1009.5}
    o.update(over)
    return base(**o)


def ok(rec):
    return ce.validate(rec)[0]


def why(rec):
    return "; ".join(ce.validate(rec)[1])


# ------------------------------------------------------------------ positives
print("valid records validate (the control — without these, rejections prove nothing)")
check("a well-formed OPEN event validates", ok(base()), why(base()))
check("a well-formed CLOSE event validates", ok(closed()), why(closed()))
check("udp is accepted", ok(base(proto="udp")))
check("port 0 and 65535 are legal", ok(base(lport=0, rport=65535)))
check("pid/proc fields may all be None", ok(base(pid=None, proc_name=None,
                                                 proc_path=None, proc_signed=None)))

# -------------------------------------------------------------- schema hygiene
print("schema hygiene")
check("unknown field is REJECTED, not ignored", not ok(base(sni="example.test")))
check("  and the error names it", "sni" in why(base(sni="example.test")))
r = base(); del r["device_id"]
check("missing required field rejected", not ok(r))
check("wrong schema_version rejected", not ok(base(schema_version=99)))
check("  with a message about interpretation, not a generic type error",
      "cannot interpret" in why(base(schema_version=99)))
check("record that is not an object rejected", not ok(["nope"]))

# ------------------------------------------------------------------- enums
print("enums are closed sets")
check("bad event value rejected", not ok(base(event="reopen")))
check("bad proto rejected (icmp is not in this tier)", not ok(base(proto="icmp")))

# ------------------------------------------------------- the bool-is-an-int trap
print("bool must not sneak through int checks (bool subclasses int in Python)")
check("lport=True REJECTED", not ok(base(lport=True)))
check("consent_version=True REJECTED", not ok(base(consent_version=True)))
check("pid=True REJECTED", not ok(base(pid=True)))
check("bytes_sent=True REJECTED", not ok(base(bytes_sent=True)))
check("ts_open_mono=True REJECTED", not ok(base(ts_open_mono=True)))

# ------------------------------------------------------------------- ranges
print("ranges and string bounds")
check("lport=-1 rejected", not ok(base(lport=-1)))
check("rport=65536 rejected", not ok(base(rport=65536)))
check("port as string rejected", not ok(base(lport="443")))
check("empty conn_id rejected", not ok(base(conn_id="")))
check("empty raddr rejected", not ok(base(raddr="")))
check("over-long proc_path rejected", not ok(base(proc_path="/x" * 400)))
check("  but a long-ish legitimate path is fine", ok(base(proc_path="/usr/lib/" + "d/" * 40 + "app")))
check("negative pid rejected", not ok(base(pid=-1)))

# ------------------------------------------------------- open/close consistency
print("open/close consistency")
r = base(); r["ts_close_mono"] = 1009.5
check("OPEN event carrying a close timestamp rejected", not ok(r))
check("CLOSE event missing ts_close_mono rejected", not ok(closed(ts_close_mono=None)))
check("CLOSE event missing ts_close_wall rejected", not ok(closed(ts_close_wall=None)))
check("CLOSE with monotonic going BACKWARDS rejected",
      not ok(closed(ts_open_mono=2000.0, ts_close_mono=1999.0)))
check("  equal open/close monotonic is allowed (sub-tick connection)",
      ok(closed(ts_open_mono=2000.0, ts_close_mono=2000.0)))

# ------------------------------------------------- proc_signed is tri-state
print("proc_signed is tri-state, never a bool")
for s in (ce.SIGNED_YES, ce.SIGNED_NO, ce.SIGNED_UNKNOWN):
    check("  %r accepted" % s, ok(base(proc_signed=s)))
check("proc_signed=True REJECTED (a bool would assert a claim we cannot make)",
      not ok(base(proc_signed=True)))
check("proc_signed=False REJECTED (this is the Linux 'unknown' case being coerced)",
      not ok(base(proc_signed=False)))
check("proc_signed='yes' REJECTED (not the vocabulary)", not ok(base(proc_signed="yes")))

# --------------------------------------------------- bytes: None != 0, and 0 is real
print("bytes: None means 'not provided', 0 means 'measured zero' — both legal, distinct")
check("bytes_sent=0 is VALID (a real measurement)", ok(base(bytes_sent=0, bytes_recv=0)))
check("bytes_sent=None is VALID (platform did not provide)", ok(base(bytes_sent=None)))
check("negative bytes rejected", not ok(base(bytes_sent=-5)))
check("bytes as string rejected", not ok(base(bytes_recv="1024")))

# ------------------------------------------------------------------ new_event
print("new_event() cannot construct an invalid record")
raised = False
try:
    ce.new_event("reopen", "c-2", "dev-1", 1, "tcp", "192.0.2.10", 5, "198.51.100.20", 443,
                 "2026-08-07T12:00:00-0500", 10.0)
except ValueError:
    raised = True
check("bad event value raises", raised)
good = ce.new_event(ce.EVENT_OPEN, "c-3", "dev-1", 1, "tcp", "192.0.2.10", 5,
                    "198.51.100.20", 443, "2026-08-07T12:00:00-0500", 10.0)
check("a good call returns a valid record", ok(good))
check("  and defaults proc_signed to 'unknown', not a claim",
      good["proc_signed"] == ce.SIGNED_UNKNOWN)
check("  and defaults bytes to None, not 0",
      good["bytes_sent"] is None and good["bytes_recv"] is None)

# ---------------------------------------------------------------- duration
print("duration_seconds reports its source and refuses when underivable")
d, src = ce.duration_seconds(closed())
check("close event yields a duration", abs(d - 9.5) < 1e-9, "d=%r" % d)
check("  sourced from monotonic", src == "monotonic")
d, src = ce.duration_seconds(base())
check("OPEN event yields None, not 0", d is None and src == "not a close event")
# The reason monotonic exists: a wall clock that jumps mid-connection must not
# corrupt the duration.
skewed = closed(ts_open_wall="2026-08-07T12:00:00-0500",
                ts_close_wall="2026-08-07T11:00:09-0500")   # NTP stepped back an hour
d, src = ce.duration_seconds(skewed)
check("wall clock stepping BACKWARDS mid-connection does not corrupt duration",
      abs(d - 9.5) < 1e-9 and src == "monotonic", "d=%r src=%s" % (d, src))

# ------------------------------------------------------------------- redaction
print("log redaction drops what a log line does not need")
line = ce.redact_for_log(base())
check("keeps the destination", "198.51.100.20" in line and "443" in line)
check("DROPS proc_path (can contain a home directory / username)",
      "/usr/bin/curl" not in line)
check("DROPS the local address", "192.0.2.10" not in line)

# ------------------------------------------------- resolved_name (schema v2)
print("resolved_name is nullable, and a name without provenance is rejected")
check("name + os_dns_event source is VALID",
      ok(base(resolved_name="example.test", resolved_name_source=ce.NAME_SRC_DNS_EVENT)))
check("no name + 'unavailable' is VALID (Linux today)",
      ok(base(resolved_name=None, resolved_name_source=ce.NAME_SRC_UNAVAILABLE)))
check("no name + 'no_dns_observed' is VALID (watched, genuinely none)",
      ok(base(resolved_name=None, resolved_name_source=ce.NAME_SRC_NONE)))
check("a NAME with NO source REJECTED (untraceable evidence)",
      not ok(base(resolved_name="example.test", resolved_name_source=None)))
check("a NAME claiming 'unavailable' REJECTED (self-contradictory)",
      not ok(base(resolved_name="example.test", resolved_name_source=ce.NAME_SRC_UNAVAILABLE)))
check("a NAME claiming 'no_dns_observed' REJECTED (self-contradictory)",
      not ok(base(resolved_name="example.test", resolved_name_source=ce.NAME_SRC_NONE)))
check("bogus source value REJECTED", not ok(base(resolved_name_source="guessed")))
check("empty name REJECTED", not ok(base(resolved_name="",
                                         resolved_name_source=ce.NAME_SRC_DNS_EVENT)))
check("over-long name REJECTED", not ok(base(resolved_name="a" * 600,
                                             resolved_name_source=ce.NAME_SRC_DNS_EVENT)))
check("schema version is now 2", ce.SCHEMA_VERSION == 2)
line = ce.redact_for_log(base(resolved_name="example.test",
                              resolved_name_source=ce.NAME_SRC_DNS_EVENT))
check("log line prefers the NAME over the raw IP", "example.test" in line)
check("  and records the provenance", "os_dns_event" in line)

print()
print("%d/%d passed" % (passed, passed + failed))
sys.exit(1 if failed else 0)
