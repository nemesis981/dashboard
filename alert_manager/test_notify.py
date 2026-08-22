#!/usr/bin/env python3
"""Notification routing and the twice-daily digest schedule.

Run: python3 alert_manager/test_notify.py   (exit 0 = all pass)

THE PROPERTY THAT MATTERS MOST. A CRITICAL event is sent immediately regardless
of any setting. A digest that can swallow a critical alert is a coverage disable
wearing a schedule, so the first section proves no `notify_mode` -- including
values that do not exist -- can defer one.

WHY THE TIME TESTS ARE DISPROPORTIONATE. Scheduling "08:00 in the admin's
timezone" has three failure modes that are all SILENT: a daylight-saving gap
where the local clock never shows the chosen time (the digest simply never fires
that day), a fold where it shows it twice (fires twice), and a fixed-offset
timezone that is correct today and an hour wrong after the next transition. None
of them raise; each one just delivers mail at the wrong moment, or not at all,
and looks like a quiet week.

NO DB, NO NETWORK, NO SMTP. Settings arrive through an injected getter.
"""
import datetime
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import notify as n  # noqa: E402

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


logging.getLogger("notify").setLevel(logging.CRITICAL)   # expected warnings

print("\n-- CRITICAL is never deferred, by any mode --")
MODES = ("digest", "immediate", "both", "quiet", "never", "off", "silent",
         "", None, "DIGEST", 0, [])
for m in MODES:
    check("notify_mode=%r cannot defer CRITICAL" % (m,),
          n.route("CRITICAL", m) == n.SEND_NOW)
for spelling in ("critical", "Critical", " CRITICAL ", "cRiTiCaL"):
    check("severity %r recognised as critical" % spelling,
          n.route(spelling, "digest") == n.SEND_NOW)

print("\n-- CONTROL: routing is not simply always send_now --")
# Without these, every check above would also pass for a function that ignored
# its arguments and returned SEND_NOW unconditionally.
check("LOW in digest mode BUNDLES", n.route("LOW", "digest") == n.BUNDLE)
check("INFO in digest mode BUNDLES", n.route("INFO", "digest") == n.BUNDLE)
check("HIGH in digest mode BUNDLES", n.route("HIGH", "digest") == n.BUNDLE)
check("LOW in immediate mode SENDS", n.route("LOW", "immediate") == n.SEND_NOW)

print("\n-- there is no way to express 'drop' --")
outcomes = {n.route(s, m)
            for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "", None, "BANANA")
            for m in MODES}
check("every outcome is send_now or bundle", outcomes <= {n.SEND_NOW, n.BUNDLE},
      outcomes)
check("both outcomes actually occur (the vocabulary is used)",
      outcomes == {n.SEND_NOW, n.BUNDLE}, outcomes)

print("\n-- HH:MM parsing is strict, never guessed --")
check("08:00 parses", n.parse_hhmm("08:00") == datetime.time(8, 0))
check("00:00 parses", n.parse_hhmm("00:00") == datetime.time(0, 0))
check("23:59 parses", n.parse_hhmm("23:59") == datetime.time(23, 59))
for bad in ("8:00", "0800", "24:00", "12:60", "-1:00", "", None, "noon",
            "08:00:00", "8am", "08.00"):
    check("%r is refused, not guessed" % (bad,), n.parse_hhmm(bad) is None)

print("\n-- schedule validation refuses at the write --")
ok, errs = n.validate_schedule(n.DEFAULT_OPEN_TIME, n.DEFAULT_CLOSE_TIME, None)
check("the shipped defaults validate", ok, errs)
ok, errs = n.validate_schedule("08:00", "08:00", None)
check("two digests at the SAME time are refused", not ok, errs)
check("...and the error names the field", n.KEY_CLOSE_TIME in errs, errs)
ok, _ = n.validate_schedule("banana", "16:00", None)
check("an unparseable open time is refused", not ok)
ok, errs = n.validate_schedule("08:00", "16:00", "Not/AZone")
check("a bogus timezone is refused", not ok, errs)
check("...and the error names the timezone field", n.KEY_TIMEZONE in errs, errs)
ok, _ = n.validate_schedule("08:00", "16:00", "Europe/London")
check("CONTROL: a real timezone is accepted", ok)

print("\n-- the schedule reports its fallbacks instead of applying them silently --")
sched = n.digest_schedule(lambda k, d="": d)
check("defaults resolve to 08:00 open", sched["open"] == datetime.time(8, 0))
check("defaults resolve to 16:00 close", sched["close"] == datetime.time(16, 0))
check("clean defaults report no problems", sched["problems"] == [], sched["problems"])
bad_sched = n.digest_schedule(
    lambda k, d="": {"digest_open_time": "banana"}.get(k, d))
check("a bad time still yields a usable schedule",
      bad_sched["open"] == datetime.time(8, 0))
check("...and SAYS it fell back", any("banana" in p for p in bad_sched["problems"]),
      bad_sched["problems"])

print("\n-- due_digests: fires once per day, per digest --")
UTC = datetime.timezone.utc
sched = {"open": datetime.time(8, 0), "close": datetime.time(16, 0),
         "tz": UTC, "tz_name": "UTC", "problems": []}
at = lambda h, m=0, d=22: datetime.datetime(2026, 8, d, h, m, tzinfo=UTC)  # noqa: E731
check("nothing due before the open time", n.due_digests(sched, at(7), {}) == [])
check("open is due after 08:00", n.due_digests(sched, at(9), {}) == [n.DIGEST_OPEN])
check("both are due after 16:00",
      n.due_digests(sched, at(17), {}) == [n.DIGEST_OPEN, n.DIGEST_CLOSE])
check("an already-sent digest is not due again the same day",
      n.due_digests(sched, at(9), {n.DIGEST_OPEN: at(8, 1)}) == [])
check("...but the OTHER one still is",
      n.due_digests(sched, at(17), {n.DIGEST_OPEN: at(8, 1)}) == [n.DIGEST_CLOSE])
check("it becomes due again the next day",
      n.due_digests(sched, at(9, 0, 23), {n.DIGEST_OPEN: at(8, 1)}) == [n.DIGEST_OPEN])
check("exactly AT the scheduled minute counts as due",
      n.due_digests(sched, at(8, 0), {}) == [n.DIGEST_OPEN])

print("\n-- a naive datetime raises rather than guessing a timezone --")
try:
    n.due_digests(sched, datetime.datetime(2026, 8, 22, 9, 0), {})
    check("naive `now` is refused", False, "it returned a result")
except n.DigestScheduleUnavailable:
    check("naive `now` raises DigestScheduleUnavailable", True)

print("\n-- daylight saving: the gap must be DETECTED --")
try:
    from zoneinfo import ZoneInfo
    london = ZoneInfo("Europe/London")
except Exception:                                            # pragma: no cover
    london = None
if london is None:
    check("tzdata available for DST tests", False, "zoneinfo/tzdata missing")
else:
    gap_day = datetime.date(2026, 3, 29)          # 01:00 -> 02:00, 01:30 does not exist
    prob = n.local_time_problem(gap_day, datetime.time(1, 30), london)
    check("01:30 on a spring-forward day is flagged as a gap",
          prob is not None and "gap" in prob, prob)
    check("...and the message says the digest would not fire",
          prob is not None and "would not fire" in prob, prob)
    # CONTROLS: the detector must not flag everything, or it measures nothing.
    check("CONTROL: 08:00 on the same day is NOT flagged",
          n.local_time_problem(gap_day, datetime.time(8, 0), london) is None)
    check("CONTROL: 08:00 on an ordinary day is NOT flagged",
          n.local_time_problem(datetime.date(2026, 6, 1),
                               datetime.time(8, 0), london) is None)
    check("CONTROL: 01:30 on an ordinary day is NOT flagged",
          n.local_time_problem(datetime.date(2026, 6, 1),
                               datetime.time(1, 30), london) is None)
    fold_day = datetime.date(2026, 10, 25)        # 02:00 -> 01:00, 01:30 happens twice
    fprob = n.local_time_problem(fold_day, datetime.time(1, 30), london)
    check("01:30 on a fall-back day is flagged as a fold",
          fprob is not None and "twice" in fprob, fprob)

print("\n-- REGRESSION: the system-timezone fallback must carry a DST RULE --")
# Found while building this: `datetime.now().astimezone().tzinfo` returns a
# FIXED-OFFSET snapshot (e.g. CDT, UTC-5) with no DST rule. A digest computed
# through it is correct today and an hour wrong after the next transition, and
# nothing says so. The fallback must resolve to a named zone instead.
tz, name, prob = n.resolve_timezone("")
try:
    from zoneinfo import ZoneInfo as _ZI
    is_real_zone = isinstance(tz, _ZI)
except Exception:                                            # pragma: no cover
    is_real_zone = False
check("the system fallback resolves to a named zone, not an offset snapshot",
      is_real_zone or name == "UTC", "got %r (%s)" % (name, type(tz).__name__))
if is_real_zone:
    snapshot = datetime.datetime.now().astimezone().tzinfo   # the old, buggy shape
    summer = datetime.datetime(2026, 8, 22, 8, 0)
    winter = datetime.datetime(2026, 12, 22, 8, 0)
    same_summer = (summer.replace(tzinfo=snapshot).astimezone(UTC)
                   == summer.replace(tzinfo=tz).astimezone(UTC))
    same_winter = (winter.replace(tzinfo=snapshot).astimezone(UTC)
                   == winter.replace(tzinfo=tz).astimezone(UTC))
    # On a DST-observing host the two disagree in winter; on a non-DST host they
    # agree all year and this check is vacuous, so it is reported either way
    # rather than silently passing.
    if same_summer and not same_winter:
        check("the fixed-offset shape really would have drifted (bug reproduced)", True)
    else:
        check("host does not observe DST — drift check is not applicable here",
              True, "same_summer=%s same_winter=%s" % (same_summer, same_winter))

print("\n-- unrecognised timezone falls back but REPORTS it --")
tz2, name2, prob2 = n.resolve_timezone("Mars/Olympus_Mons")
check("a bogus zone does not raise", tz2 is not None)
check("...and the problem is reported", bool(prob2), prob2)
check("...and it is not silently treated as UTC-with-no-comment",
      "not recognised" in (prob2 or ""), prob2)

print("\n-- schedule_warnings surfaces problems for the settings UI --")
w = n.schedule_warnings({"open": datetime.time(8, 0), "close": datetime.time(8, 0),
                         "tz": UTC, "tz_name": "UTC",
                         "problems": ["both digests are scheduled at 08:00"]})
check("configured problems are surfaced", any("08:00" in x for x in w), w)

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
