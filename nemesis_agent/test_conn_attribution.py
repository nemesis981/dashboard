"""Process attribution on connection events -- and its failure modes.

Run: python3 nemesis_agent/test_conn_attribution.py

⚠ THE CENTRAL PROPERTY IS THAT ATTRIBUTION CAN NEVER COST AN EVENT.
It is an ENRICHMENT. A missing map, a half-built source, or a lookup that raises
must each cost a NAME and nothing more. That is not hypothetical caution: wiring
this in initially DID cost the whole event, because a bare `self.proc_map` access
sat outside the guard and raised AttributeError on a source built via __new__ --
which is exactly how the main suite constructs it. Every degradation path below is
therefore exercised, not assumed.

ASSERTION COUNT IS FIXED and self-asserted.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import conn_collector as cc         # noqa: E402
import conn_events as ce            # noqa: E402
import proc_map as pm               # noqa: E402

EXPECTED_CHECKS = 27
passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    ok = bool(cond)
    print(("  [PASS] " if ok else "  [FAIL] ") + name
          + ("" if ok or not detail else "  (%s)" % detail))
    if ok:
        passed += 1
    else:
        failed += 1


OPEN = {"connid": "0", "Task Name": "KERNEL_NETWORK_TASK_TCPIP", "PID": 4242,
        "saddr": "192.0.2.10", "sport": 51000, "daddr": "198.51.100.20",
        "rport": 0, "dport": 443, "size": 0, "mss": 1460, "rcvwin": 65535,
        "sndwinscale": 8}


def make(proc_map="unset"):
    """Build a handler-only source, mirroring how the main suite does it."""
    out = []
    dns = cc.DnsCache(available=False)
    src = cc.EtwSource.__new__(cc.EtwSource)
    src.asm = cc.ConnectionAssembler("dev", dns_cache=dns)
    src.dns, src.consent_version, src.emit = dns, 1, out.append
    src._flows, src._mono, src.stats = {}, lambda: 100.0, cc.Counter()
    if proc_map != "unset":
        src.proc_map = proc_map
    return src, out


print("with a populated map, events NAME the program")
m = pm.ProcessMap()
m.seed([(4242, "beacon.exe", "C:\\tmp\\beacon.exe")])
src, out = make(m)
src._on_network((28, dict(OPEN)))
check("an event was emitted", len(out) == 1, len(out))
rec = out[0] if out else {}
check("⭐ proc_name is populated", rec.get("proc_name") == "beacon.exe", rec.get("proc_name"))
check("⭐ proc_path is populated", rec.get("proc_path") == "C:\\tmp\\beacon.exe")
check("pid is still carried", rec.get("pid") == 4242)
check("the record is schema-valid", ce.validate(rec)[0] if rec else False)
check("⭐ proc_signed stays UNKNOWN (signature checking is NOT claimed)",
      rec.get("proc_signed") == ce.SIGNED_UNKNOWN, rec.get("proc_signed"))
check("naming was counted", src.stats.get("proc_named") == 1)

print("\n⭐ EXITED process is still named (the beacon case, end to end)")
m2 = pm.ProcessMap(retain_exited_s=300.0)
m2.seed([(4242, "gone.exe", "/gone")])
m2.note_exit(4242)
src, out = make(m2)
src._on_network((28, dict(OPEN)))
check("⭐ a process that already exited is still named",
      out and out[0].get("proc_name") == "gone.exe", out[0].get("proc_name") if out else None)

print("\n⭐ EVERY DEGRADATION PATH COSTS A NAME, NEVER AN EVENT")
src, out = make(None)
src._on_network((28, dict(OPEN)))
check("⭐ no map -> event still emitted, name None",
      len(out) == 1 and out[0].get("proc_name") is None)

src, out = make()                      # attribute never set at all
src._on_network((28, dict(OPEN)))
check("⭐ half-built source (no proc_map attr) -> event STILL emitted",
      len(out) == 1, "this is the exact regression that shipped once")


class Exploding:
    def lookup(self, pid):
        raise RuntimeError("map is broken")


src, out = make(Exploding())
src._on_network((28, dict(OPEN)))
check("⭐ a raising lookup -> event still emitted", len(out) == 1)
check("⭐ and the failure is COUNTED, not swallowed silently",
      src.stats.get("proc_lookup_errors") == 1)

print("\nan unknown pid is a miss, not a wrong name")
m3 = pm.ProcessMap()
m3.seed([(1, "other.exe", "/other")])
src, out = make(m3)
src._on_network((28, dict(OPEN)))       # PID 4242 is not in the map
check("unknown pid -> name None (never a neighbouring process's name)",
      out and out[0].get("proc_name") is None)

print("\n⭐ the UNVERIFIED Kernel-Process provider: handler logic + self-reporting")
# Every constant this exercises is documentation, not measurement. The point of
# these checks is NOT to assert the field names are right -- they cannot be, from
# here -- but that the handler behaves correctly for whichever shape arrives, and
# that it SAYS which one it saw so a probe run settles it.
m = pm.ProcessMap()
src, out = make(m)
src._on_process((cc.EtwSource.KP_EVENT_START,
                 {"ProcessID": 7001, "ImageName": "C:\\Windows\\notepad.exe"}))
check("⭐ a start event populates the map", m.lookup(7001)[0] == "notepad.exe",
      m.lookup(7001))
check("⭐ full path is kept alongside the basename",
      m.lookup(7001)[1] == "C:\\Windows\\notepad.exe")
check("⭐ it REPORTS which pid field matched",
      src.stats.get("kp_pid_from_ProcessID") == 1, dict(src.stats))
check("⭐ and which image field matched",
      src.stats.get("kp_image_from_ImageName") == 1)
check("a process handler emits NO connection events", len(out) == 0)

src2, _ = make(m)
src2._on_process((cc.EtwSource.KP_EVENT_START, {"NewProcessId": 7002,
                                                "Image": "/usr/bin/curl"}))
check("an ALTERNATE field shape is still handled", m.lookup(7002)[0] == "curl")
check("  and the alternate field is named in the stats",
      src2.stats.get("kp_pid_from_NewProcessId") == 1)

src3, _ = make(m)
src3._on_process((cc.EtwSource.KP_EVENT_STOP, {"ProcessID": 7001}))
check("⭐ a stop event marks exited but KEEPS the name resolvable",
      m.lookup(7001)[0] == "notepad.exe" and src3.stats.get("kp_stop") == 1)

src4, _ = make(m)
src4._on_process((cc.EtwSource.KP_EVENT_START, {"ImageName": "x.exe"}))
check("no pid field -> counted, not guessed",
      src4.stats.get("kp_no_pid_field") == 1)
src4._on_process((999, {"ProcessID": 1}))
check("an unmapped event id announces itself",
      src4.stats.get("kp_unmapped_event_id") == 1)
src4._on_process((cc.EtwSource.KP_EVENT_START, "not-a-dict"))
check("malformed payload -> counted, never raises",
      src4.stats.get("kp_malformed") == 1)

src5, _ = make(None)
src5._on_process((cc.EtwSource.KP_EVENT_START, {"ProcessID": 1, "ImageName": "a"}))
check("no map -> counted, never raises", src5.stats.get("kp_no_map") == 1)

print("\n⭐ a start for a KNOWN pid replaces the name even with no image")
m.note_start(7001, "old.exe", "/old.exe")
src6, _ = make(m)
src6._on_process((cc.EtwSource.KP_EVENT_START, {"ProcessID": 7001}))
check("⭐ reuse with no image clears the stale name rather than keeping it",
      m.lookup(7001)[0] is None, m.lookup(7001))

_total = passed + failed
check("assertion count matches EXPECTED_CHECKS (%d)" % EXPECTED_CHECKS,
      _total + 1 == EXPECTED_CHECKS, "ran %d" % (_total + 1))

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
