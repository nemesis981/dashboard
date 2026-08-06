#!/usr/bin/env python3
"""Checks for the canonical timestamp helper (alert_manager/nemesis_timestamp.py).

Every check that asserts a property also asserts the OPPOSITE where one exists.
A format test that only ever feeds canonical input cannot tell a working
normaliser from `return value` — this suite's controls are what make its passes
mean something.
"""

import os
import re
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nemesis_timestamp as ts  # noqa: E402

EXPECTED_CHECKS = 38

passed = 0
failed = 0


def check(name, cond, detail=""):
    global passed, failed
    mark = "PASS" if cond else "FAIL"
    suffix = f"  ({detail})" if (not cond and detail) else ""
    print(f"  [{mark}] {name}{suffix}")
    if cond:
        passed += 1
    else:
        failed += 1
    return cond


# ── now() ────────────────────────────────────────────────────────────────────
print("\n[now] emits the canonical shape")

n = ts.now()
check("now() has a T separator", "T" in n, n)
check("now() has NO space separator", " " not in n, n)
check("now() carries a UTC offset",
      bool(re.search(r"[+-]\d{2}:\d{2}$", n)), n)
check("now() parses back", isinstance(datetime.fromisoformat(n), datetime))
check("now() round-trips as canonical", ts.is_canonical(n), n)

parsed = datetime.fromisoformat(n)
check("now() is offset-AWARE, not naive", parsed.tzinfo is not None)
check("now() is within 5s of real now",
      abs((datetime.now().astimezone() - parsed).total_seconds()) < 5)
check("now() has microseconds by default", parsed.microsecond != 0 or "." in n, n)

secs = ts.now(timespec="seconds")
check("now(timespec='seconds') drops microseconds", "." not in secs, secs)
check("now(timespec='seconds') still canonical", ts.is_canonical(secs), secs)

# CONTROL: two calls must differ, or now() is a constant and every check above
# would pass on a hardcoded string.
import time as _t
_t.sleep(0.01)
check("CONTROL: now() advances between calls", ts.now() != n)


# ── normalize(): the formats this codebase actually produced ─────────────────
print("\n[normalize] converts the real historical formats")

space = "2026-08-05 11:04:15"          # nemesis_fwd's strftime form
iso_t = "2026-08-05T09:15:52.075279"   # dashboard's isoformat form

ns = ts.normalize(space)
check("space-separated -> T separator", "T" in ns, ns)
check("space-separated -> gains an offset",
      bool(re.search(r"[+-]\d{2}:\d{2}$", ns)), ns)
check("space-separated -> same wall-clock time", ns.startswith("2026-08-05T11:04:15"), ns)
check("space-separated -> no invented microseconds", "." not in ns, ns)

ni = ts.normalize(iso_t)
check("naive ISO-T -> gains an offset",
      bool(re.search(r"[+-]\d{2}:\d{2}$", ni)), ni)
check("naive ISO-T -> microseconds PRESERVED", ".075279" in ni, ni)
check("naive ISO-T -> same wall-clock time", ni.startswith("2026-08-05T09:15:52"), ni)

# THE point of the exercise: the two formats must now order correctly against
# each other. 09:15 preceded 11:04 in reality, but sorted the other way as raw
# strings — measured on the live table 2026-08-06.
check("CONTROL: raw forms sort WRONG (this is the bug)", space < iso_t,
      f"{space!r} < {iso_t!r}")
check("normalized forms sort CHRONOLOGICALLY", ni < ns, f"{ni!r} < {ns!r}")

# ── normalize(): idempotence and already-aware input ─────────────────────────
print("\n[normalize] idempotent, and does not shift aware input")

check("normalize is idempotent", ts.normalize(ns) == ns, ns)
check("normalize(now()) == now() output", ts.normalize(n) == n)

aware_utc = "2026-08-05T16:04:15+00:00"
na = ts.normalize(aware_utc)
check("already-aware input keeps ITS offset (not re-zoned)",
      na.endswith("+00:00"), na)
check("already-aware input keeps its wall-clock", na.startswith("2026-08-05T16:04:15"), na)

# DST: a fixed offset captured once would mis-stamp half the year. These two
# dates must not receive the same offset in a DST-observing zone.
jan = ts.normalize("2026-01-15T12:00:00")
jul = ts.normalize("2026-07-15T12:00:00")
local_dst = datetime(2026, 1, 15).astimezone().utcoffset() != \
            datetime(2026, 7, 15).astimezone().utcoffset()
if local_dst:
    check("DST: winter and summer get DIFFERENT offsets", jan[-6:] != jul[-6:],
          f"{jan[-6:]} vs {jul[-6:]}")
else:
    check("DST: zone does not observe DST, offsets match (skipped meaningfully)",
          jan[-6:] == jul[-6:], f"{jan[-6:]} vs {jul[-6:]}")


# ── normalize(): failure is explicit, never a substituted value ──────────────
print("\n[normalize] fails explicitly — never guesses a time")

for bad, label in ((None, "None"), ("", "empty string"), ("   ", "whitespace"),
                   ("not a timestamp", "garbage"), ("2026-13-45", "impossible date"),
                   (12345, "non-string")):
    check(f"{label} -> default (None)", ts.normalize(bad) is None, repr(ts.normalize(bad)))

check("unparseable honours an explicit default",
      ts.normalize("garbage", default="KEEP-ME") == "KEEP-ME")
check("CONTROL: a VALID value ignores the default",
      ts.normalize(space, default="KEEP-ME") != "KEEP-ME")


# ── is_canonical() ───────────────────────────────────────────────────────────
print("\n[is_canonical] both directions")

check("canonical string -> True", ts.is_canonical(ns), ns)
check("space-separated -> False", not ts.is_canonical(space))
check("naive ISO-T -> False", not ts.is_canonical(iso_t))
check("None -> False", not ts.is_canonical(None))
check("empty -> False", not ts.is_canonical(""))


print("\n" + "=" * 50)
total = passed + failed
print(f"Total: {passed} passed, {failed} failed ({total} checks)")

# The declared count is a guard against a check silently not running — it has
# caught its own author repeatedly in this repo. A mismatch fails the suite.
if total != EXPECTED_CHECKS:
    print(f"GUARD FAILED: expected {EXPECTED_CHECKS} checks, ran {total}. "
          f"A check was added or skipped without updating EXPECTED_CHECKS.")
    sys.exit(1)
print("RESULT: all checks passed" if not failed else "RESULT: FAILED")
sys.exit(0 if failed == 0 else 1)
