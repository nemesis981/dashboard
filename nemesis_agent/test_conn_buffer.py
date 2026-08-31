"""Track C Piece 3 — the bounded buffer, including the claims it makes.

Run: python3 nemesis_agent/test_conn_buffer.py

⚠ THE DROP COUNTER IS THE THING UNDER TEST, not the storage.
The build plan names the failure this replaces: `conns[:50]`, a silent truncation
that made a partial picture look complete. So the assertions that matter are that a
drop is COUNTED, that the count is read-and-cleared exactly once, and that a
consent discard does NOT inflate it — conflating a privacy action with a capacity
problem would misreport why data is missing.

⚠ THE THREAD-SAFETY CLAIM IS EXERCISED, NOT ASSERTED. `put()` runs on the ETW
dispatch thread and `drain()` on the heartbeat thread; they genuinely race. A lock
that was never contended would pass any single-threaded suite while proving nothing.

ASSERTION COUNT IS FIXED and self-asserted.
"""
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import conn_buffer as cb            # noqa: E402

EXPECTED_CHECKS = 26
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


print("basic FIFO behaviour")
b = cb.ConnBuffer(cap=4)
check("empty buffer drains to nothing", b.drain() == [])
check("len of empty is 0", len(b) == 0)
b.put("a"); b.put("b")
check("put stores in order", b.drain() == ["a", "b"])
check("drain empties", len(b) == 0)
check("put(None) is refused", b.put(None) is False)

print("\n⭐ the CAP is enforced and every eviction is COUNTED")
# Sized off MIN_CAP, not a literal. A literal 3 is CLAMPED UP to MIN_CAP, so the
# buffer never overflows and the whole section silently tests nothing -- which is
# exactly what happened on the first run of this suite.
CAP = cb.MIN_CAP
OVER = 7
b = cb.ConnBuffer(cap=CAP)
for i in range(CAP + OVER):
    b.put(i)
check("never exceeds cap", len(b) == CAP, "len=%d" % len(b))
check("keeps the NEWEST (documented drop-oldest policy)",
      b.drain() == list(range(OVER, CAP + OVER)))
check("⭐ drops were counted, not silent", b.take_dropped() == OVER)
check("⭐ take_dropped RESETS (a drop is reported exactly once)",
      b.take_dropped() == 0)

print("\npartial drain")
b = cb.ConnBuffer(cap=10)
for i in range(5):
    b.put(i)
check("drain(2) returns the two oldest", b.drain(2) == [0, 1])
check("the rest stay held", len(b) == 3)
check("drain(bigger than held) returns all", b.drain(99) == [2, 3, 4])

print("\n⭐ discard() is a PRIVACY action, not an overflow")
# Isolate the property: the buffer must be BELOW cap when discard() runs, or the
# puts themselves overflow and the counter legitimately rises -- which would look
# like discard() inflating it. The first version of this test made exactly that
# mistake and blamed the code.
b = cb.ConnBuffer(cap=cb.MIN_CAP)
for i in range(cb.MIN_CAP + 3):
    b.put(i)                        # 3 real overflow drops
check("overflow drops are counted before we start", b.take_dropped() == 3)
b.drain()                           # empty it, so the next puts cannot overflow
for i in range(3):
    b.put(i)
n = b.discard()
check("discard returns how many were dropped", n == 3, "n=%d" % n)
check("discard empties the buffer", len(b) == 0)
check("⭐ discard did NOT inflate the overflow counter", b.take_dropped() == 0)

print("\ncap is CLAMPED, never trusted")
check("cap 0 clamps up to MIN_CAP", cb.ConnBuffer(cap=0).cap == cb.MIN_CAP)
check("negative clamps up", cb.ConnBuffer(cap=-5).cap == cb.MIN_CAP)
check("absurd clamps down", cb.ConnBuffer(cap=10**9).cap == cb.MAX_CAP)
check("non-numeric falls back to the default",
      cb.ConnBuffer(cap="lots").cap == cb.DEFAULT_CAP)
check("None falls back to the default", cb.ConnBuffer(cap=None).cap == cb.DEFAULT_CAP)

print("\n⭐ CONCURRENCY: put and drain actually race, and nothing is lost or doubled")
# Cap is larger than the total written, so a correct implementation loses NOTHING.
# Any loss or duplication here is a real lock defect, not an expected drop.
N_THREADS, PER_THREAD = 8, 500
b = cb.ConnBuffer(cap=N_THREADS * PER_THREAD)
collected = []
stop = threading.Event()


def writer(tid):
    for i in range(PER_THREAD):
        b.put((tid, i))


def reader():
    while not stop.is_set():
        collected.extend(b.drain())


rt = threading.Thread(target=reader, daemon=True)
rt.start()
ws = [threading.Thread(target=writer, args=(t,)) for t in range(N_THREADS)]
for t in ws:
    t.start()
for t in ws:
    t.join()
stop.set()
rt.join(timeout=5)
collected.extend(b.drain())
expected = N_THREADS * PER_THREAD
check("⭐ every record survived the race", len(collected) == expected,
      "got %d want %d" % (len(collected), expected))
check("⭐ no record was duplicated", len(set(collected)) == expected,
      "distinct=%d" % len(set(collected)))
check("no spurious overflow drops (cap was never reached)", b.take_dropped() == 0)

print("\nstats reports the shape a caller needs")
b = cb.ConnBuffer(cap=5)
b.put(1)
st = b.stats()
check("stats has held/cap/dropped/accepted",
      set(st) == {"held", "cap", "dropped", "accepted"} and st["held"] == 1)

_total = passed + failed
check("assertion count matches EXPECTED_CHECKS (%d)" % EXPECTED_CHECKS,
      _total + 1 == EXPECTED_CHECKS, "ran %d" % (_total + 1))

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
