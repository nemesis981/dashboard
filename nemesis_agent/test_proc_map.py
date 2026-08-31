"""ProcessMap -- the pid->identity map that makes connection events name a program.

Run: python3 nemesis_agent/test_proc_map.py

⚠ THE TWO ASSERTIONS THAT MATTER MOST:
  * an EXITED process is still resolvable inside the retention window. That is the
    entire reason this class exists -- a beacon that connects for two seconds is
    gone before any naive lookup runs, so a map that forgets on exit fixes nothing.
  * a process START for a known pid REPLACES the entry. Windows recycles pids, and
    serving the previous process's name is CONFIDENTLY WRONG, which is worse than
    returning nothing.

Both are paired with their opposite (expiry past the window; a miss for an unknown
pid) so the suite cannot pass against a map that simply answers everything.

ASSERTION COUNT IS FIXED and self-asserted.
"""
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import proc_map as pm               # noqa: E402

EXPECTED_CHECKS = 35
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


class Clock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t
    def advance(self, s): self.t += s


print("seeding from an injected snapshot (no psutil needed)")
m = pm.ProcessMap()
n = m.seed([(10, "curl.exe", "C:\\curl.exe"), (11, "svc", "/usr/bin/svc")])
check("seed reports how many it added", n == 2, n)
check("len reflects the seed", len(m) == 2)
check("lookup returns name/path/source", m.lookup(10) == ("curl.exe", "C:\\curl.exe", pm.SRC_SEED))
check("source is SEED, not EVENT", m.lookup(11)[2] == pm.SRC_SEED)
check("unknown pid -> all None", m.lookup(999) == (None, None, None))
check("bad pid -> all None, no raise", m.lookup("abc") == (None, None, None))
check("seed tolerates a bad pid row", pm.ProcessMap().seed([("x", "n", "p"), (1, "a", "b")]) == 1)

print("\n⭐ RETAIN-AFTER-EXIT -- the whole reason this class exists")
c = Clock()
m = pm.ProcessMap(retain_exited_s=300.0, clock=c)
m.seed([(20, "beacon.exe", "C:\\beacon.exe")])
m.note_exit(20)
check("⭐ an EXITED process is still resolvable", m.lookup(20)[0] == "beacon.exe")
check("exit did NOT delete the entry", len(m) == 1)
c.advance(299)
check("⭐ still resolvable just inside the window", m.lookup(20)[0] == "beacon.exe")
c.advance(2)
check("⭐ past the window -> MISS, not a stale guess", m.lookup(20) == (None, None, None))
check("expiry is counted", m.stats.get("miss_exited_expired") == 1)
check("prune() drops the expired entry", m.prune() == 1 and len(m) == 0)

print("\n⭐ PID REUSE -- a start event REPLACES, it never merges")
m = pm.ProcessMap()
m.seed([(30, "old.exe", "/old")])
check("seeded identity is served", m.lookup(30)[0] == "old.exe")
m.note_start(30, "new.exe", "/new")
check("⭐ after reuse the NEW identity is served", m.lookup(30)[0] == "new.exe")
check("⭐ the reuse was counted, not silent", m.stats.get("replaced_on_reuse") == 1)
check("source upgrades to EVENT (confirmed, not assumed)",
      m.lookup(30)[2] == pm.SRC_EVENT)
check("a re-started pid is live again, not exited", m.note_exit(30) is True)

print("\nbad input never raises")
check("note_start bad pid -> False", pm.ProcessMap().note_start("zz", "n") is False)
check("note_exit bad pid -> False", pm.ProcessMap().note_exit(None) is False)
check("note_exit unknown pid -> False", pm.ProcessMap().note_exit(4242) is False)

print("\nbounded, and EXITED entries are evicted first")
c = Clock()
m = pm.ProcessMap(cap=pm.MIN_CAP, clock=c)
for i in range(pm.MIN_CAP):
    m.seed([(i, "p%d" % i, "/p%d" % i)])
m.note_exit(0); m.note_exit(1)
c.advance(1)
m.note_start(9000, "new", "/new")
check("never exceeds cap", len(m) <= pm.MIN_CAP, len(m))
check("⭐ an EXITED entry was evicted before any live one",
      m.stats.get("evicted_exited", 0) >= 1 and m.lookup(0) == (None, None, None))
check("a LIVE entry survived that eviction", m.lookup(5)[0] == "p5")
check("the new entry is present", m.lookup(9000)[0] == "new")

print("\ncap is clamped, never trusted")
check("cap 0 -> MIN_CAP", pm.ProcessMap(cap=0).cap == pm.MIN_CAP)
check("absurd cap -> MAX_CAP", pm.ProcessMap(cap=10**9).cap == pm.MAX_CAP)
check("non-numeric cap -> default", pm.ProcessMap(cap="big").cap == pm.DEFAULT_CAP)
check("negative retention -> 0, not negative",
      pm.ProcessMap(retain_exited_s=-5).retain_exited_s == 0.0)

print("\n⭐ REAL psutil seed (this is the shippable half, so exercise it for real)")
m = pm.ProcessMap()
n = m.seed()
check("⭐ seeded from the live process table", n > 0, "n=%d" % n)
own = m.lookup(os.getpid())
check("⭐ THIS process is in the map by pid", own[0] is not None, own)
check("and carries a path", own[1] is not None, own)

print("\nconcurrency: updates and lookups race without loss")
m = pm.ProcessMap(cap=pm.MAX_CAP)
def writer(base):
    for i in range(300):
        m.note_start(base + i, "p%d" % (base + i))
ts = [threading.Thread(target=writer, args=(b,)) for b in (0, 1000, 2000, 3000)]
for t in ts: t.start()
for t in ts: t.join()
check("every concurrent start landed", len(m) == 1200, len(m))
check("no lost counts", m.stats.get("noted_start") == 1200, m.stats.get("noted_start"))

_total = passed + failed
check("assertion count matches EXPECTED_CHECKS (%d)" % EXPECTED_CHECKS,
      _total + 1 == EXPECTED_CHECKS, "ran %d" % (_total + 1))

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
