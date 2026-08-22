#!/usr/bin/env python3
"""The clock_and_timestamp_sanity diagnostic — and proof its canary measures.

Run: python3 diagnostics/test_clock_and_timestamp_sanity.py   (exit 0 = all pass)

WHAT THIS CHECK IS FOR. Timestamps here are written by several processes in
several formats. Mixing naive and timezone-aware values in one column raises
TypeError on comparison — and, worse, does NOT raise on `sorted()`, it just
orders them wrongly. Mixing ISO strings with epoch floats is the same failure
with a different shape. Both are live classes in this repo.

TWO REGRESSIONS GUARDED HERE, both found by running the check rather than reading
it:
  * **Counters read as dates.** A name-only heuristic flagged `alerts.times_seen`
    — an occurrence count of 559 — as an epoch timestamp in 1970. A check that
    reports a counter as a broken clock is one the operator learns to ignore.
  * **Naive timestamps read as future-dated.** A naive value has no knowable
    zone, so interpreting it as local and comparing against a UTC `now` makes it
    look future-dated by the local offset. The first version flagged its own
    known-good fixture on every host west of Greenwich.

NO WRITES, NO NETWORK. The database is opened read-only; the analysis is pure.
"""
import datetime
import importlib.util
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

_SRC_PATH = os.path.join(_HERE, "clock_and_timestamp_sanity.py")
_spec = importlib.util.spec_from_file_location("clock_under_test", _SRC_PATH)
ct = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ct)

passed = failed = 0
UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 8, 22, 12, 0, tzinfo=UTC)


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


def an(values, now=NOW):
    return ct.analyse({("t", "ts"): values}, now=now)


print("\n-- the canary passes on a healthy analyser --")
ok, detail = ct._canary()
check("canary reports ok", ok, detail)

print("\n-- classification: values, not names, decide --")
check("ISO naive", ct.classify_value("2026-08-22T10:00:00") == ct.KIND_ISO_NAIVE)
check("ISO aware (+00:00)",
      ct.classify_value("2026-08-22T10:00:00+00:00") == ct.KIND_ISO_AWARE)
check("ISO aware (Z)", ct.classify_value("2026-08-22T10:00:00Z") == ct.KIND_ISO_AWARE)
check("epoch float", ct.classify_value(1787005118.9) == ct.KIND_EPOCH)
check("epoch as string", ct.classify_value("1787005118") == ct.KIND_EPOCH)
check("epoch milliseconds", ct.classify_value(1787005118000) == ct.KIND_EPOCH_MS)

print("\n-- REGRESSION: counters are NOT timestamps --")
# alerts.times_seen held 559 and a name-only heuristic called it a 1970 date.
for counter in (559, 12, 3, 1, 0, -5):
    check("a count of %r is not a timestamp" % counter,
          ct.classify_value(counter) == ct.KIND_OTHER)
res = ct.analyse({("alerts", "times_seen"): [559, 12, 3, 1]}, now=NOW)
check("a counter column is not examined at all", res["examined"] == 0, res)
check("...and produces no findings", not res["mixed"] and not res["future"], res)
check("CONTROL: a real epoch column IS examined",
      ct.analyse({("t", "ts"): [1787005118.9]}, now=NOW)["examined"] == 1)

print("\n-- incomparable mixes are detected --")
check("naive + aware is incomparable",
      ct.incomparable_mix({ct.KIND_ISO_NAIVE, ct.KIND_ISO_AWARE}))
check("ISO + epoch is incomparable",
      ct.incomparable_mix({ct.KIND_ISO_NAIVE, ct.KIND_EPOCH}))
check("epoch seconds + millis is incomparable",
      ct.incomparable_mix({ct.KIND_EPOCH, ct.KIND_EPOCH_MS}))

print("\n-- CONTROL: consistent columns are NOT flagged --")
# Without these, a function returning True unconditionally would pass everything
# above and make every column in the database a finding.
check("one representation is comparable", not ct.incomparable_mix({ct.KIND_ISO_NAIVE}))
check("empty is comparable", not ct.incomparable_mix(set()))
check("OTHER alone is comparable", not ct.incomparable_mix({ct.KIND_OTHER}))
check("all-naive column reports nothing",
      not an(["2026-08-22T10:00:00", "2026-08-21T09:00:00"])["mixed"])
check("all-epoch column reports nothing",
      not an([1787005118.9, 1787005119.1])["mixed"])

print("\n-- mixed columns ARE reported --")
check("naive+aware column is reported",
      bool(an(["2026-08-22T10:00:00", "2026-08-22T10:00:00+00:00"])["mixed"]))
check("ISO+epoch column is reported",
      bool(an(["2026-08-22T10:00:00", 1787005118.9])["mixed"]))

print("\n-- future-dating: aware values use the tight tolerance --")
check("an aware value 10 months ahead is reported",
      bool(an(["2027-06-01T00:00:00+00:00"])["future"]))
check("CONTROL: 5 minutes of skew is NOT reported",
      not an(["2026-08-22T12:05:00+00:00"])["future"])
check("CONTROL: a past value is NOT reported",
      not an(["2026-08-01T00:00:00+00:00"])["future"])

print("\n-- REGRESSION: naive values get the wider, honest tolerance --")
# A naive value's zone is unknowable within -12..+14, so it can only be called
# future-dated beyond EVERY plausible interpretation.
check("a naive value 2h in the past is NOT future-dated",
      not an(["2026-08-22T10:00:00"])["future"])
check("a naive value a few hours ahead is NOT future-dated (offset ambiguity)",
      not an(["2026-08-22T20:00:00"])["future"])
check("...but a naive value 10 months ahead IS reported",
      bool(an(["2027-06-01T00:00:00"])["future"]))
check("the naive tolerance is wider than the aware one",
      ct.FUTURE_TOLERANCE_NAIVE > ct.FUTURE_TOLERANCE)

print("\n-- sample_columns RAISES on an unreadable DB, never returns {} --")
try:
    ct.sample_columns(os.path.join(tempfile.gettempdir(), "nope-4c1a.db"))
    check("an unreadable database raises", False, "it returned a value")
except Exception:
    check("an unreadable database raises rather than returning {}", True)

print("\n-- the produced result obeys the diagnostics contract --")
res = ct.run()
check("status is ok/warn/error/info (T3)",
      res["status"] in ("ok", "warn", "error", "info"), res["status"])
check("keys are EXACTLY the six contract keys (T5)",
      set(res) == {"id", "name", "icon", "status", "summary", "output"}, sorted(res))
check("every value is a string", all(isinstance(v, str) for v in res.values()))
check("META has all three description tiers (T2)",
      set(ct.META["descriptions"]) == {"beginner", "intermediate", "pro"})
check("META id is URL/DOM safe (T10)",
      ct.META["id"].replace("_", "").isalnum() and ct.META["id"].islower())

print("\n-- MUTATION: the canary must CATCH each injected defect --")
SRC = open(_SRC_PATH, encoding="utf-8").read()

MUTATIONS = [
    ("mixed-representation detection disabled",
     "        if incomparable_mix(set(kinds)):\n            mixed.append((table, col, dict(kinds)))",
     "        if False:\n            mixed.append((table, col, dict(kinds)))"),
    ("future-dating detection disabled",
     "        if worst is not None:\n            future.append((table, col, worst[0], worst[2]))",
     "        if False:\n            future.append((table, col, worst[0], worst[2]))"),
    # NOTE: neutering the `len(real) <= 1` fast path alone is NOT a bug injection
    # — the group check below returns the same answer for a single-kind set, so
    # behaviour is unchanged. An earlier version of this list did exactly that
    # and recorded a false "not caught", which is a broken TEST reporting a
    # broken CANARY. The mutation has to replace the real decision.
    ("everything reported as incomparable (flags every column)",
     "    if len(real) <= 1:\n        return False\n    return not any(real <= g for g in _COMPARABLE_GROUPS)",
     "    return bool(real)"),
    ("REGRESSION: counters classified as epoch dates",
     "        if _EPOCH_MIN <= v <= _EPOCH_MAX:\n            return KIND_EPOCH\n        if _EPOCH_MS_MIN <= v <= _EPOCH_MS_MAX:\n            return KIND_EPOCH_MS\n        return KIND_OTHER\n    text = str(value).strip()",
     "        return KIND_EPOCH\n    text = str(value).strip()"),
    ("REGRESSION: naive values lose their wider tolerance",
     "            tolerance = (FUTURE_TOLERANCE_NAIVE if k == KIND_ISO_NAIVE\n                         else FUTURE_TOLERANCE)",
     "            tolerance = FUTURE_TOLERANCE"),
    ("the naive tolerance swallows everything (nothing is ever future)",
     "FUTURE_TOLERANCE_NAIVE = datetime.timedelta(hours=15)",
     "FUTURE_TOLERANCE_NAIVE = datetime.timedelta(days=99999)"),
]

for label, old, new in MUTATIONS:
    if old not in SRC:
        check("MUTATION anchor present: %s" % label, False,
              "anchor not found -- this TEST is stale, not the code")
        continue
    path = tempfile.mktemp(suffix=".py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(SRC.replace(old, new, 1))
    caught = False
    try:
        s2 = importlib.util.spec_from_file_location("ct_mutant", path)
        m2 = importlib.util.module_from_spec(s2)
        s2.loader.exec_module(m2)
        ok2, _d = m2._canary()
        caught = not ok2
    except Exception:
        caught = True
    finally:
        os.unlink(path)
    check("canary catches: %s" % label, caught,
          "the mutated module's canary still reported OK — it is not measuring")

print("\n-- a failed canary SUPPRESSES the verdict, not decorates it --")
path = tempfile.mktemp(suffix=".py")
with open(path, "w", encoding="utf-8") as fh:
    fh.write(SRC.replace('def _canary():\n    """Returns (ok, detail). Never raises. Runs on EVERY invocation."""',
                         'def _canary():\n    """stub"""\n    return False, "forced"', 1))
try:
    s3 = importlib.util.spec_from_file_location("ct_broken", path)
    m3 = importlib.util.module_from_spec(s3)
    s3.loader.exec_module(m3)
    r3 = m3.run()
    check("a failed canary yields status=error", r3["status"] == "error", r3["status"])
    check("...and says timestamps were NOT checked",
          "NOT checked" in r3["summary"], r3["summary"])
    check("...and does not claim consistency",
          "consistent" not in r3["summary"].lower(), r3["summary"])
finally:
    os.unlink(path)

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
