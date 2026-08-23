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
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
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

# ── DELIVERY (appended 2026-08-22): queue -> build -> send -> mark ───────────

import sqlite3 as _sq3
import tempfile as _tf
import os as _os

def _db():
    """A throwaway DB with the real canonical DDL, not a hand-written copy.

    Loading database.py's own init is deliberate: a hand-rolled CREATE here would
    let the schema drift from production and the tests would keep passing.
    """
    d = _tf.mkdtemp(); p = _os.path.join(d, "t.db")
    import importlib.util as _ilu
    spec = _ilu.spec_from_file_location("db_under_test",
                                        _os.path.join(_HERE, "database.py"))
    dbmod = _ilu.module_from_spec(spec)
    dbmod.DB_PATH = p
    try:
        spec.loader.exec_module(dbmod)
        dbmod.DB_PATH = p
        dbmod.init_notify_tables()
    except Exception:
        # database.py has import-time side effects in some layouts; fall back to
        # executing ONLY the DDL function's SQL against a bare connection.
        c = _sq3.connect(p)
        src = open(_os.path.join(_HERE, "database.py"), encoding="utf-8").read()
        blk = src[src.index("def init_notify_tables"):]
        for stmt in blk.split('"""'):
            pass
        import re as _re
        for m in _re.finditer(r'conn\.execute\("""(.*?)"""\)', blk, _re.S):
            c.execute(m.group(1))
        for m in _re.finditer(r'conn\.execute\("(CREATE INDEX[^"]+)"', blk):
            c.execute(m.group(1))
        c.commit(); c.close()
    return _sq3.connect(p)

SCHED = {"open": datetime.time(8, 0), "close": datetime.time(16, 0),
         "tz": UTC, "tz_name": "UTC", "problems": []}

def _at(h, m=0, d=22):
    return datetime.datetime(2026, 8, d, h, m, tzinfo=UTC)

print("\n-- the canonical DDL is what we test against --")
c = _db()
tabs = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
check("notify_queue exists", "notify_queue" in tabs, tabs)
check("notify_state exists", "notify_state" in tabs, tabs)

print("\n-- enqueue / pending --")
i1 = n.enqueue(c, "LOW", "disk 80%", "detail one", surface="hw", family_key="disk", now=_at(9))
i2 = n.enqueue(c, "MEDIUM", "disk 85%", "detail two", surface="hw", family_key="disk", now=_at(10))
i3 = n.enqueue(c, "INFO", "one-off", "", surface="x", now=_at(11))
check("rows get ids", all(isinstance(i, int) for i in (i1, i2, i3)))
p = n.pending(c)
check("all three are pending", len(p) == 3, len(p))
check("oldest first", p[0]["subject"] == "disk 80%", p[0])

print("\n-- bundling pays off the measured 65% repeat rate --")
b = n.bundle(p)
check("two groups (a family of 2 + one single)", len(b) == 2, b)
counts = sorted(cnt for cnt, _e in b)
check("the family collapsed to a count of 2", counts == [1, 2], counts)
check("the family's representative carries its WORST severity, not its first",
      any(cnt == 2 and (e.get("severity") or "").upper() == "MEDIUM" for cnt, e in b), b)
check("CONTROL: an event with NO family key is never collapsed",
      any(cnt == 1 and e.get("family_key") in (None, "") for cnt, e in b), b)
solo = n.bundle([{"severity": "LOW", "subject": "a", "queued_at": "1"},
                 {"severity": "LOW", "subject": "b", "queued_at": "2"}])
check("two keyless events stay SEPARATE (no invented grouping)", len(solo) == 2, solo)

print("\n-- build_digest is pure and says the right things --")
sub, body = n.build_digest(n.DIGEST_OPEN, p, SCHED, now=_at(8))
check("subject names the count", "3 notification" in sub, sub)
check("subject names the highest severity", "MEDIUM" in sub, sub)
check("body shows the x2 bundle", "(x2)" in body, body[:200])
check("body states criticals are NOT held", "NOT held" in body)
check("CONTROL: it is not empty-shaped", "nothing to report" not in sub)

print("\n-- an EMPTY digest is still sent, deliberately --")
sub0, body0 = n.build_digest(n.DIGEST_CLOSE, [], SCHED, now=_at(16))
check("subject says nothing to report", "nothing to report" in sub0, sub0)
check("body explains WHY it is sent empty", "still working" in body0)
check("CONTROL: empty and non-empty subjects differ", sub0 != sub)

print("\n-- send_digest: marks sent ONLY after a successful send --")
sent_box = []
def good_sender(subject, body, to=None):
    sent_box.append((subject, body)); return True
r = n.send_digest(c, n.DIGEST_OPEN, SCHED, sender=good_sender, now=_at(9))
check("reports ok", r["ok"], r)
check("it actually called the sender", len(sent_box) == 1)
check("all queued rows marked", r["sent"] == 3, r)
check("nothing pending afterwards", n.pending(c) == [], n.pending(c))

print("\n-- THE SAFETY PROPERTY: a failed send loses NOTHING --")
c2 = _db()
n.enqueue(c2, "LOW", "will not send", "", family_key="k", now=_at(9))
def bad_sender(subject, body, to=None):
    return False                      # send_email returns False, does not raise
r = n.send_digest(c2, n.DIGEST_OPEN, SCHED, sender=bad_sender, now=_at(9))
check("reports failure", not r["ok"], r)
check("reports 0 sent", r["sent"] == 0, r)
check("the event is STILL QUEUED for the next attempt", len(n.pending(c2)) == 1)
check("...and was not marked", c2.execute(
      "SELECT COUNT(*) FROM notify_queue WHERE sent_at IS NOT NULL").fetchone()[0] == 0)

print("\n-- a RAISING sender is contained, and also loses nothing --")
c3 = _db()
n.enqueue(c3, "LOW", "raiser", "", now=_at(9))
def raising_sender(subject, body, to=None):
    raise RuntimeError("smtp exploded")
r = n.send_digest(c3, n.DIGEST_OPEN, SCHED, sender=raising_sender, now=_at(9))
check("a raising sender does not escape", not r["ok"], r)
check("...and the event stays queued", len(n.pending(c3)) == 1)

print("\n-- run_digest_tick is idempotent (safe on a short-interval loop) --")
c4 = _db()
n.enqueue(c4, "LOW", "one", "", now=_at(7))
calls = []
def counting_sender(subject, body, to=None):
    calls.append(subject); return True
# Pin the timezone to UTC. Without this the tick resolves the SYSTEM zone, so
# the test would pass or fail depending on where it runs — a host-timezone-
# dependent test is flaky by construction, and the first version of this was
# exactly that (it failed here because 09:00 UTC is 04:00 in America/Chicago).
gs = lambda k, d="": ("UTC" if k == n.KEY_TIMEZONE else d)
t1 = n.run_digest_tick(c4, gs, sender=counting_sender, now=_at(9))
check("first tick after 08:00 sends OPEN", t1["due"] == [n.DIGEST_OPEN], t1)
t2 = n.run_digest_tick(c4, gs, sender=counting_sender, now=_at(9, 30))
check("second tick the SAME day sends nothing again", t2["due"] == [], t2)
check("the sender was called exactly once", len(calls) == 1, calls)
t3 = n.run_digest_tick(c4, gs, sender=counting_sender, now=_at(17))
check("CLOSE still fires later the same day", t3["due"] == [n.DIGEST_CLOSE], t3)
t4 = n.run_digest_tick(c4, gs, sender=counting_sender, now=_at(9, 0, 23))
check("OPEN fires again the NEXT day", t4["due"] == [n.DIGEST_OPEN], t4)

print("\n-- an unreadable last-sent means 'never sent', not 'just sent' --")
c5 = _db()
n._set_state(c5, n._STATE_LAST_SENT % n.DIGEST_OPEN, "not-a-timestamp")
lm = n.last_sent_map(c5)
check("the unreadable entry is absent, not fabricated", n.DIGEST_OPEN not in lm, lm)
check("CONTROL: a readable entry IS returned",
      (n._set_state(c5, n._STATE_LAST_SENT % n.DIGEST_CLOSE, _at(16).isoformat()),
       n.DIGEST_CLOSE in n.last_sent_map(c5))[1])

print("\n-- a CRITICAL is never queued by the routing decision --")
check("route still sends CRITICAL immediately in every mode",
      all(n.route("CRITICAL", m) == n.SEND_NOW
          for m in ("digest", "immediate", "both", "quiet", None, "")))


print("\n-- notify(): the caller-facing entry point --")

def _gs(mode):
    """A get_setting that reports `mode`, and UTC so the schedule is fixed."""
    def g(key, default=None):
        if key == n.KEY_NOTIFY_MODE:
            return mode
        if key == n.KEY_TIMEZONE:
            return "UTC"
        return default
    return g


_c = _db()
_sent = []
_spy = lambda s, b, to=None: (_sent.append(s), True)[1]

r = n.notify("LOW", "immediate subject", "body", conn=_c,
                  sender=_spy, get_setting=_gs("immediate"), now=_at(9))
check("immediate mode sends now", r["ok"] and r["delivery"] == n.SEND_NOW)
check("...and queues nothing", not n.pending(_c))
check("...and actually called the sender", len(_sent) == 1)

r = n.notify("LOW", "bundled subject", "body", family_key="fam", conn=_c,
                  sender=_spy, get_setting=_gs("digest"), now=_at(9))
check("digest mode bundles", r["ok"] and r["delivery"] == n.BUNDLE)
check("...returns the queued row id", isinstance(r["queued_id"], int))
check("...and did NOT send", len(_sent) == 1)
check("...and the event is really queued", len(n.pending(_c)) == 1)

r = n.notify("CRITICAL", "critical subject", "body", conn=_c,
                  sender=_spy, get_setting=_gs("digest"), now=_at(9))
check("CRITICAL sends immediately even in digest mode",
      r["delivery"] == n.SEND_NOW and len(_sent) == 2)
check("...and was not queued", len(n.pending(_c)) == 1)

print("\n-- notify(): the DEFAULT is 'immediate', so an upgrade changes nothing --")
r = n.notify("HIGH", "no setting at all", "body", conn=_c, sender=_spy,
                  get_setting=lambda k, d=None: d, now=_at(9))
check("an ABSENT notify_mode setting sends immediately, never bundles",
      r["delivery"] == n.SEND_NOW)
check("CONTROL: the same call bundles when the setting says digest",
      n.notify("HIGH", "x", "b", conn=_c, sender=_spy,
                    get_setting=_gs("digest"), now=_at(9))["delivery"]
      == n.BUNDLE)


def _raising_setting(key, default=None):
    raise RuntimeError("settings table unreadable")


r = n.notify("HIGH", "unreadable setting", "body", conn=_c, sender=_spy,
                  get_setting=_raising_setting, now=_at(9))
check("an UNREADABLE setting falls back to immediate, not to route()'s BUNDLE",
      r["delivery"] == n.SEND_NOW)

print("\n-- notify(): a failed enqueue must NOT lose the event --")


class _BrokenConn:
    """A connection whose INSERT always fails."""
    def execute(self, *a, **k):
        raise _sq3.OperationalError("no such table: notify_queue")

    def commit(self):
        pass


_before = len(_sent)
r = n.notify("MEDIUM", "enqueue will fail", "body", conn=_BrokenConn(),
                  sender=_spy, get_setting=_gs("digest"), now=_at(9))
check("a failed enqueue FALLS FORWARD to an immediate send",
      r["delivery"] == n.SEND_NOW and len(_sent) == _before + 1)
check("...and says so, rather than reporting a clean bundle",
      r["fell_back"] is True)
check("...and still reports ok, because the event DID go out", r["ok"] is True)

print("\n-- notify(): never raises into the caller --")


def _boom(subject, body, to=None):
    raise RuntimeError("SMTP exploded")


r = n.notify("LOW", "raising sender", "body", conn=_c, sender=_boom,
                  get_setting=_gs("immediate"), now=_at(9))
check("a raising sender is contained", r["ok"] is False)
check("...and the reason is reported, not swallowed", bool(r["error"]))

print("\n-- notify_mode: validated at the write, like the schedule --")
for good in ("immediate", "digest", "DIGEST", "  Immediate  "):
    check("%r is accepted" % (good,), n.validate_notify_mode(good)[0])
for bad in ("", None, "banana", "quiet", "off", "never"):
    ok, errs = n.validate_notify_mode(bad)
    check("%r is refused, not silently defaulted" % (bad,),
          not ok and n.KEY_NOTIFY_MODE in errs)

# "both" is accepted by route() but behaves EXACTLY as immediate -- the
# "also include it in the digest" half was never built. Offering it would
# promise behaviour that does not exist.
ok, _ = n.validate_notify_mode("both")
check("'both' is NOT offered as a choice, though route() tolerates it", not ok)
check("CONTROL: route() really does still tolerate it",
      n.route("LOW", "both") == n.SEND_NOW)

print("\n-- all four digest settings validate as ONE form --")
ok, errs = n.validate_digest_settings("08:00", "16:00", None, "digest")
check("a wholly valid form passes", ok, errs)
ok, errs = n.validate_digest_settings("banana", "16:00", None, "banana")
check("a form with two bad fields fails", not ok)
check("...and reports BOTH, not just the first",
      n.KEY_OPEN_TIME in errs and n.KEY_NOTIFY_MODE in errs, errs)

print("\n-- saving is ALL-OR-NOTHING (no partial schedule) --")
writes = []
_w = lambda k, v, actor=None: writes.append((k, v))

ok, errs = n.save_digest_settings("08:00", "16:00", "UTC", "digest",
                                  set_setting=_w)
check("a valid save succeeds", ok, errs)
check("...and writes all FOUR keys", len(writes) == 4, writes)
check("...including the mode",
      (n.KEY_NOTIFY_MODE, "digest") in writes, writes)

writes.clear()
ok, errs = n.save_digest_settings("08:00", "banana", "UTC", "digest",
                                  set_setting=_w)
check("an invalid END time refuses the save", not ok)
check("...and writes NOTHING -- not even the valid start time",
      writes == [], writes)

writes.clear()
ok, _ = n.save_digest_settings("08:00", "16:00", "UTC", "banana",
                               set_setting=_w)
check("an invalid MODE alone also refuses the whole form", not ok)
check("...and still writes nothing", writes == [], writes)

print("\n-- MUTATION: injected delivery defects must FAIL this suite --")
# Unlike the diagnostics tools, notify.py has no import-time canary — its
# correctness is asserted by this file. So a mutation is "caught" when the
# RELEVANT ASSERTIONS above fail against the mutated module, which is what the
# runner below re-executes. The control proves the harness works at all.
import importlib.util as _ilu2

_SRC_PATH = os.path.join(_HERE, "notify.py")
_SRC = open(_SRC_PATH, encoding="utf-8").read()


def _probe(mod):
    """Re-run the delivery properties against `mod`. True = all still hold."""
    try:
        c = _db()
        mod.enqueue(c, "LOW", "a", "", family_key="f", now=_at(9))
        mod.enqueue(c, "MEDIUM", "b", "", family_key="f", now=_at(10))
        pend = mod.pending(c)
        if len(pend) != 2:
            return False
        # bundling collapses, and keeps the WORST severity
        b = mod.bundle(pend)
        if len(b) != 1 or b[0][0] != 2:
            return False
        if (b[0][1].get("severity") or "").upper() != "MEDIUM":
            return False
        # KEYLESS events must NOT be collapsed together. Without this the
        # probe never exercises that branch, and the mutation that removes the
        # guard passes unnoticed — which is exactly what happened first time.
        ck = _db()
        mod.enqueue(ck, "LOW", "one", "", now=_at(9))
        mod.enqueue(ck, "LOW", "two", "", now=_at(10))
        if len(mod.bundle(mod.pending(ck))) != 2:
            return False
        # empty digest is still produced
        s0, _b0 = mod.build_digest(mod.DIGEST_OPEN, [], SCHED, now=_at(8))
        if "nothing to report" not in s0:
            return False
        # a FAILED send must not mark anything
        r = mod.send_digest(c, mod.DIGEST_OPEN, SCHED,
                            sender=lambda s, b, to=None: False, now=_at(9))
        if r["ok"] or r["sent"] != 0 or len(mod.pending(c)) != 2:
            return False
        # a GOOD send must mark everything
        r = mod.send_digest(c, mod.DIGEST_OPEN, SCHED,
                            sender=lambda s, b, to=None: True, now=_at(9))
        if not r["ok"] or r["sent"] != 2 or mod.pending(c):
            return False
        # tick is idempotent
        c2 = _db()
        mod.enqueue(c2, "LOW", "x", "", now=_at(7))
        calls = []
        snd = lambda s, b, to=None: (calls.append(1), True)[1]
        gs2 = lambda k, d="": ("UTC" if k == mod.KEY_TIMEZONE else d)
        mod.run_digest_tick(c2, gs2, sender=snd, now=_at(9))
        mod.run_digest_tick(c2, gs2, sender=snd, now=_at(9, 30))
        if len(calls) != 1:
            return False

        # ---- notify(), the caller-facing entry point --------------------
        # The probe MUST exercise this or a mutation to it is uncatchable --
        # the same trap the keyless-bundling comment above records.
        def gs3(mode):
            return lambda k, d=None: (mode if k == mod.KEY_NOTIFY_MODE
                                      else ("UTC" if k == mod.KEY_TIMEZONE else d))

        c3 = _db()
        got = []
        sp = lambda s, b, to=None: (got.append(s), True)[1]

        # digest mode bundles and does NOT send
        r = mod.notify("LOW", "n1", "", family_key="k", conn=c3, sender=sp,
                       get_setting=gs3("digest"), now=_at(9))
        if r["delivery"] != mod.BUNDLE or got or len(mod.pending(c3)) != 1:
            return False
        # immediate mode sends and does NOT bundle
        r = mod.notify("LOW", "n2", "", conn=c3, sender=sp,
                       get_setting=gs3("immediate"), now=_at(9))
        if r["delivery"] != mod.SEND_NOW or len(got) != 1:
            return False
        # CRITICAL ignores the mode entirely
        r = mod.notify("CRITICAL", "n3", "", conn=c3, sender=sp,
                       get_setting=gs3("digest"), now=_at(9))
        if r["delivery"] != mod.SEND_NOW or len(got) != 2:
            return False
        # an ABSENT setting must resolve to immediate, never to bundle
        r = mod.notify("HIGH", "n4", "", conn=c3, sender=sp,
                       get_setting=lambda k, d=None: d, now=_at(9))
        if r["delivery"] != mod.SEND_NOW:
            return False
        # a failed enqueue must fall forward to a send, not vanish
        class _Bad:
            def execute(self, *a, **k):
                raise _sq3.OperationalError("boom")

            def commit(self):
                pass

        before = len(got)
        r = mod.notify("MEDIUM", "n5", "", conn=_Bad(), sender=sp,
                       get_setting=gs3("digest"), now=_at(9))
        if r["delivery"] != mod.SEND_NOW or len(got) != before + 1:
            return False

        # ---- settings validation + the all-or-nothing write --------------
        # Same rule as above: unexercised code cannot be mutation-tested.
        w = []
        rec = lambda k, v, actor=None: w.append((k, v))
        ok, _e = mod.save_digest_settings("08:00", "16:00", "UTC", "digest",
                                          set_setting=rec)
        if not ok or len(w) != 4:
            return False
        w.clear()
        # a bad END time must write NOTHING -- not even the valid start time
        ok, _e = mod.save_digest_settings("08:00", "banana", "UTC", "digest",
                                          set_setting=rec)
        if ok or w:
            return False
        w.clear()
        # a bad MODE alone must refuse the whole form too
        ok, _e = mod.save_digest_settings("08:00", "16:00", "UTC", "banana",
                                          set_setting=rec)
        if ok or w:
            return False
        return True
    except Exception:
        return False


def _load(text):
    fd, path = tempfile.mkstemp(suffix=".py", prefix="_mutant_", dir=_HERE)
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        spec = _ilu2.spec_from_file_location("notify_mutant", path)
        m = _ilu2.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m, None
    except Exception as exc:
        return None, exc
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


_ctl_mod, _ctl_exc = _load(_SRC)
check("CONTROL: the unmutated module loads from the mutant path",
      _ctl_mod is not None, _ctl_exc)
check("CONTROL: and the unmutated module PASSES the probe",
      _ctl_mod is not None and _probe(_ctl_mod),
      "if this fails, every 'caught' below is meaningless")

MUTATIONS = [
    ("a FAILED send marks rows sent anyway (silent event loss)",
     '    if not ok:\n        # Nothing is marked.',
     '    if False:\n        # Nothing is marked.'),
    ("rows are marked BEFORE the send instead of after",
     "    marked = mark_sent(conn, ids, which, now=now)",
     "    marked = len(ids)"),
    ("bundling keeps the FIRST member, understating severity",
     "    out = [(len(v), min(v, key=lambda e: _SEV_RANK.get(\n                (e.get(\"severity\") or \"\").upper(), 9)))\n           for v in groups.values()] + singles",
     "    out = [(len(v), v[0]) for v in groups.values()] + singles"),
    ("bundling collapses keyless events together",
     '        fk = (e.get("family_key") or "").strip()\n        if not fk:\n            singles.append((1, e))\n            continue',
     '        fk = (e.get("family_key") or "").strip()\n        if False:\n            singles.append((1, e))\n            continue'),
    ("an empty digest is silently NOT sent",
     '    if not bundled:\n        subject = "Nemesis %s digest — nothing to report" % label.lower()',
     '    if False:\n        subject = "Nemesis %s digest — nothing to report" % label.lower()'),
    ("pending() ignores sent_at (already-sent events resend forever)",
     '"FROM notify_queue WHERE sent_at IS NULL ORDER BY queued_at, id "',
     '"FROM notify_queue ORDER BY queued_at, id "'),
    ("the tick stops recording last-sent (digest resends every call)",
     "    _set_state(conn, _STATE_LAST_SENT % which, now.isoformat(timespec=\"seconds\"), now=now)",
     "    pass"),
    # ---- notify() entry-point mutations ---------------------------------
    ("the DEFAULT flips to digest (silently defers mail on upgrade)",
     'DEFAULT_NOTIFY_MODE = "immediate"',
     'DEFAULT_NOTIFY_MODE = "digest"'),
    # NOT a mutation of the `mode = DEFAULT_NOTIFY_MODE` pre-initialisation:
    # setting it to None changes NOTHING observable, because route() already
    # fails safe on an unrecognised mode and returns SEND_NOW. That pre-init
    # prevents a NameError if the getter raises; it is not what keeps delivery
    # correct. The REAL defect shape is dropping the argument, because route()'s
    # own DEFAULT PARAMETER is "digest" -- so a caller that forgets it silently
    # bundles everything.
    ("the mode argument is dropped, so route()'s 'digest' default bundles all mail",
     "    decision = route(severity, mode)",
     "    decision = route(severity)"),
    ("a failed enqueue reports success without sending (silent event loss)",
     '            log.exception("notify: enqueue failed; sending immediately instead")\n'
     "            result = _send_now(subject, body, sender)\n"
     '            result["fell_back"] = True\n'
     "            return result",
     '            log.exception("notify: enqueue failed")\n'
     '            return {"ok": True, "delivery": BUNDLE, "queued_id": None,\n'
     '                    "error": None, "fell_back": False}'),
    ("CRITICAL is routed through the mode instead of before it",
     '    if (severity or "").strip().upper() == CRITICAL:\n        return SEND_NOW',
     '    if False:\n        return SEND_NOW'),
    ("a failed validation still writes -- leaving a PARTIAL schedule stored",
     "    ok, errors = validate_digest_settings(open_text, close_text, tz_name, mode)\n"
     "    if not ok:\n        return False, errors",
     "    ok, errors = validate_digest_settings(open_text, close_text, tz_name, mode)\n"
     "    if False:\n        return False, errors"),
    ("the form drops mode errors, so an invalid mode saves silently",
     "    errors.update(mode_errors)",
     "    pass"),
]

for label, old, new in MUTATIONS:
    if old not in _SRC:
        check("MUTATION anchor present: %s" % label, False,
              "anchor not found -- this TEST is stale, not the code")
        continue
    if _ctl_mod is None:
        check("caught: %s" % label, False, "SKIPPED - control failed")
        continue
    m, exc = _load(_SRC.replace(old, new, 1))
    caught = (m is None) or (not _probe(m))
    check("caught: %s" % label, caught,
          "the mutated module still passed every delivery property")

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
