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

EXPECTED_CHECKS = 14
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

_total = passed + failed
check("assertion count matches EXPECTED_CHECKS (%d)" % EXPECTED_CHECKS,
      _total + 1 == EXPECTED_CHECKS, "ran %d" % (_total + 1))

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
