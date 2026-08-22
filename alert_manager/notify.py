"""Notification routing — immediate vs bundled, and the twice-daily digest.

WHY THIS LAYER EXISTS
---------------------
`email_utils.send_email` is already the single SMTP chokepoint and five callers
use it. None of them can answer three questions the product now needs:

  * **Should this go out at all right now, or ride in a bundle?** 28 CPU-temperature
    tickets are today 28 emails. Measured live 2026-08-22: 65% of tickets are
    repeats of a family that already sent one, and a single stuck canary once
    produced 204 tickets in two days.
  * **When does the bundle go?** Ratified 2026-08-22: twice daily, both times
    operator-settable, localized to the admin's timezone — a start-of-day OPEN
    report and an end-of-day CLOSE report.
  * **Did it actually arrive?** Every send outcome is reportable, so "no email"
    can be told apart from "no events".

So this is a layer ABOVE the chokepoint, not a sixth path through it.

THE ONE RULE THAT IS NOT CONFIGURABLE
-------------------------------------
**A CRITICAL event is always sent immediately.** There is no setting, no digest
mode, no quiet window and no credential that defers or suppresses it. That is not
politeness about important mail — it follows directly from the constraint
ratified 2026-08-22: no credential or override may disable monitoring coverage.
A digest that can swallow a critical alert is a coverage disable wearing a
schedule, so `route()` decides CRITICAL before it reads any setting at all, and
`_selftest_routing` proves on every import that no configuration changes that
answer.

Bundling a LOW/INFO notice is a different thing entirely: the event is still
detected, still recorded, still on the dashboard, and still delivered — later, in
company. Nothing is lost, only batched.

TIME IS THE HARD PART, NOT SCHEDULING
-------------------------------------
"08:00 in the admin's timezone" is not a fixed instant, and two of the three ways
to get it wrong fail silently:

  * **DST gaps.** On a spring-forward day the local clock never shows 02:30.
    Python does not object — `datetime(2026,3,29,2,30, tzinfo=ZoneInfo("Europe/London"))`
    returns a timestamp with a plausible offset for a time that did not happen.
    A digest scheduled there simply never fires that day, and nothing says so.
  * **DST folds.** On a fall-back day 01:30 happens twice, so a naive "has it
    passed?" check can fire the same digest twice.
  * **A bad zone name.** Falling back to UTC silently would move every digest by
    up to 12 hours without a word.

Each is handled explicitly below and reported rather than absorbed.
"""

from __future__ import annotations

import datetime
import logging
import re

try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except ImportError:                                          # pragma: no cover
    ZoneInfo = None
    class ZoneInfoNotFoundError(Exception):
        pass

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Vocabulary
# ─────────────────────────────────────────────────────────────────────────────

#: Delivery routing for one event.
SEND_NOW  = "send_now"     # goes out immediately
BUNDLE    = "bundle"       # accumulates into the next digest

#: The two daily reports. Named for what they are FOR, not for their clock time,
#: because the times are operator-settable and "the 8am one" stops being true the
#: moment someone changes it.
DIGEST_OPEN  = "open"      # start-of-day: what happened overnight, what needs you
DIGEST_CLOSE = "close"     # end-of-day: what happened today, what is still open

#: Severity that can never be deferred. Compared case-insensitively.
CRITICAL = "CRITICAL"

#: Settings keys.
KEY_TIMEZONE   = "digest_timezone"
KEY_OPEN_TIME  = "digest_open_time"
KEY_CLOSE_TIME = "digest_close_time"

#: Ratified defaults 2026-08-22: a sensible AM/PM split reading as
#: start-of-day open / end-of-day close.
DEFAULT_OPEN_TIME  = "08:00"
DEFAULT_CLOSE_TIME = "16:00"

_HHMM_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


class DigestScheduleUnavailable(Exception):
    """Raised when the schedule cannot be determined at all.

    An exception rather than a fallback schedule: every schedule is a legal
    answer, so a returned one would be indistinguishable from a configured one,
    and the operator would never learn their setting was ignored.
    """


# ─────────────────────────────────────────────────────────────────────────────
# Timezone
# ─────────────────────────────────────────────────────────────────────────────

def parse_hhmm(text):
    """'HH:MM' -> datetime.time, or None if it is not a valid 24-hour clock time.

    None rather than a default, so the caller decides what a bad value means.
    Strict on purpose: '8:00', '0800' and '24:00' are all rejected rather than
    guessed at, because guessing produces a digest at a time nobody chose.
    """
    if text is None:
        return None
    m = _HHMM_RE.match(str(text).strip())
    if not m:
        return None
    return datetime.time(int(m.group(1)), int(m.group(2)))


def resolve_timezone(name, system_default=None):
    """Return (ZoneInfo, resolved_name, problem_or_None).

    Never raises and never silently substitutes. An unusable zone name falls back
    to the system zone, but the PROBLEM is returned alongside so the caller can
    surface it — a digest arriving 6 hours off because a zone name had a typo is
    otherwise indistinguishable from one the operator scheduled that way.
    """
    if ZoneInfo is None:                                     # pragma: no cover
        return None, "system", "zoneinfo is unavailable on this Python"
    wanted = (name or "").strip()
    if wanted:
        try:
            return ZoneInfo(wanted), wanted, None
        except (ZoneInfoNotFoundError, ValueError, OSError) as exc:
            problem = ("timezone %r is not recognised (%s); falling back to the "
                       "system timezone" % (wanted, type(exc).__name__))
        except Exception as exc:                             # noqa: BLE001
            problem = "timezone %r could not be loaded (%s)" % (wanted, exc)
    else:
        problem = None
    # System zone. Deliberately NOT a hardcoded region: a default correct for
    # this box would be wrong for every other install (Rule 8).
    #
    # Resolved to a real IANA ZONE NAME, not to `datetime.now().astimezone()`.
    # That returns a FIXED-OFFSET snapshot of the offset in force right now
    # (e.g. `CDT`, UTC-5), frozen — it carries no DST rule, so every digest
    # computed through it would silently shift by an hour at the next
    # transition and keep shifting until the process restarted. A timezone that
    # is right today and wrong in November is the same class of instrument this
    # module's DST handling exists to refuse.
    system_name = _system_zone_name()
    if system_name:
        try:
            return ZoneInfo(system_name), system_name, problem
        except Exception:                                    # noqa: BLE001
            pass
    return (datetime.timezone.utc, "UTC",
            (problem + "; " if problem else "")
            + "system timezone could not be resolved to a named zone; using UTC, "
              "so digest times are UTC rather than local")


def _system_zone_name():
    """The host's IANA zone name (e.g. 'America/Chicago'), or None.

    Two sources, in order of reliability. Returns None rather than a guess — the
    caller falls back to UTC and SAYS it did, which is visible, whereas a guessed
    zone silently delivers every digest at the wrong hour.
    """
    import os                                                # noqa: PLC0415
    # /etc/localtime is a symlink into the zoneinfo tree on systemd hosts.
    try:
        link = os.path.realpath("/etc/localtime")
        marker = "/zoneinfo/"
        if marker in link:
            name = link.split(marker, 1)[1]
            if name:
                return name
    except Exception:                                        # noqa: BLE001
        pass
    # Debian/Ubuntu also keep the plain name here.
    try:
        with open("/etc/timezone") as fh:
            name = fh.read().strip()
            if name:
                return name
    except Exception:                                        # noqa: BLE001
        pass
    return None


def local_time_problem(day, when, tz):
    """Does `when` actually occur on `day` in `tz`? Returns a problem, or None.

    Two DST hazards, both silent in plain Python:

      * **gap** — the local clock skips this time on a spring-forward day, so a
        digest scheduled there never fires. `datetime` does NOT raise; it returns
        a timestamp with a plausible offset for a time that never happened.
      * **fold** — the local clock repeats this time on a fall-back day, so a
        naive "has it passed" test can fire the same digest twice.

    Detected by round-tripping through UTC: for a real local time the trip is
    lossless, and for a gap time it is not.
    """
    if tz is None:
        return None
    naive = datetime.datetime.combine(day, when)
    aware = naive.replace(tzinfo=tz)
    try:
        roundtrip = aware.astimezone(datetime.timezone.utc).astimezone(tz)
    except Exception:                                        # noqa: BLE001
        return None
    if roundtrip.replace(tzinfo=None) != naive:
        return ("%s does not occur on %s in this timezone (daylight-saving gap); "
                "this digest would not fire that day" % (when.strftime("%H:%M"), day))
    # A fold means the same wall-clock time happens twice that day.
    first  = aware.replace(fold=0).astimezone(datetime.timezone.utc)
    second = aware.replace(fold=1).astimezone(datetime.timezone.utc)
    if first != second:
        return ("%s occurs twice on %s in this timezone (daylight-saving fold); "
                "the first occurrence is used" % (when.strftime("%H:%M"), day))
    return None


# ─────────────────────────────────────────────────────────────────────────────
# The schedule
# ─────────────────────────────────────────────────────────────────────────────

def validate_schedule(open_text, close_text, tz_name):
    """Validate an operator-supplied schedule. Returns (ok, errors_by_field).

    Refuses at the WRITE, matching `bounded.py`'s two-gate discipline, so a bad
    value never reaches storage and the operator is told immediately rather than
    inferring it from a digest that never arrives.
    """
    errors = {}
    o = parse_hhmm(open_text)
    c = parse_hhmm(close_text)
    if o is None:
        errors[KEY_OPEN_TIME] = "must be a 24-hour time as HH:MM (e.g. 08:00)"
    if c is None:
        errors[KEY_CLOSE_TIME] = "must be a 24-hour time as HH:MM (e.g. 16:00)"
    if o is not None and c is not None and o == c:
        # Not pedantry. Two digests at the same instant are indistinguishable,
        # and whichever fires second finds an empty window — so the operator
        # silently gets one report while the UI shows two.
        errors[KEY_CLOSE_TIME] = ("must differ from the start-of-day time; two "
                                  "digests at the same time deliver one report")
    if tz_name:
        _tzobj, _name, problem = resolve_timezone(tz_name)
        if problem:
            errors[KEY_TIMEZONE] = problem
    return (not errors), errors


def digest_schedule(get_setting):
    """Resolve the live schedule. Returns a dict describing it AND its problems.

    `get_setting(key, default)` is injected so this is testable with no DB.

    Every fallback is REPORTED in `problems`, never applied silently: a digest
    arriving at 08:00 because that is the default, and one arriving at 08:00
    because the operator chose it, must not look identical to whoever is
    debugging why the 09:30 they configured never came.
    """
    problems = []
    raw_open  = get_setting(KEY_OPEN_TIME,  DEFAULT_OPEN_TIME)
    raw_close = get_setting(KEY_CLOSE_TIME, DEFAULT_CLOSE_TIME)
    raw_tz    = get_setting(KEY_TIMEZONE,   "")

    open_t = parse_hhmm(raw_open)
    if open_t is None:
        problems.append("start-of-day time %r is not HH:MM; using %s"
                        % (raw_open, DEFAULT_OPEN_TIME))
        open_t = parse_hhmm(DEFAULT_OPEN_TIME)
    close_t = parse_hhmm(raw_close)
    if close_t is None:
        problems.append("end-of-day time %r is not HH:MM; using %s"
                        % (raw_close, DEFAULT_CLOSE_TIME))
        close_t = parse_hhmm(DEFAULT_CLOSE_TIME)
    if open_t == close_t:
        problems.append("both digests are scheduled at %s; only one report will "
                        "be delivered" % open_t.strftime("%H:%M"))

    tz, tz_name, tz_problem = resolve_timezone(raw_tz)
    if tz_problem:
        problems.append(tz_problem)

    return {"open": open_t, "close": close_t, "tz": tz, "tz_name": tz_name,
            "problems": problems}


def due_digests(schedule, now, last_sent):
    """Which digests are due right now. Returns a list of DIGEST_OPEN/CLOSE.

    `now` must be timezone-aware. `last_sent` maps a digest name to the aware
    datetime it last went out (or None).

    A digest is due when its scheduled local time has passed TODAY (in the
    admin's timezone) and it has not already been sent today. Comparing local
    calendar days rather than elapsed hours is what makes this survive DST: on a
    23-hour or 25-hour day the digest still fires once, because "have I sent one
    today" does not depend on the day's length.
    """
    if now.tzinfo is None:
        raise DigestScheduleUnavailable(
            "due_digests needs an aware datetime; a naive one would be "
            "interpreted in whichever timezone the process happens to run in")
    tz = schedule.get("tz")
    local_now = now.astimezone(tz) if tz is not None else now
    today = local_now.date()
    due = []
    for name, when in ((DIGEST_OPEN, schedule["open"]),
                       (DIGEST_CLOSE, schedule["close"])):
        if when is None:
            continue
        if local_now.time() < when:
            continue                                  # not yet, today
        prev = (last_sent or {}).get(name)
        if prev is not None:
            prev_local = prev.astimezone(tz) if (tz is not None and prev.tzinfo) else prev
            if prev_local.date() >= today:
                continue                              # already sent today
        due.append(name)
    return due


def schedule_warnings(schedule, day=None):
    """Human-readable problems with the CONFIGURED schedule, including DST.

    Returned rather than logged-and-forgotten so the settings UI can show them at
    the moment of configuring, which is the only time the operator is looking.
    """
    warnings = list(schedule.get("problems", []))
    day = day or datetime.date.today()
    tz = schedule.get("tz")
    for when in (schedule.get("open"), schedule.get("close")):
        if when is None:
            continue
        problem = local_time_problem(day, when, tz)
        if problem:
            warnings.append(problem)
    return warnings


# ─────────────────────────────────────────────────────────────────────────────
# Routing
# ─────────────────────────────────────────────────────────────────────────────

def route(severity, notify_mode="digest"):
    """SEND_NOW or BUNDLE for one event. CRITICAL is decided before any setting.

    Note the ordering, which is the whole safety property: severity is checked
    FIRST, so no value of `notify_mode` — including one that does not exist yet —
    can defer a critical alert. A later mode added to the vocabulary inherits
    that guarantee automatically rather than needing to remember it.

    There is deliberately no return value meaning "drop". A bundled event is
    delivered later, not discarded, and this function has no way to express
    otherwise.
    """
    if (severity or "").strip().upper() == CRITICAL:
        return SEND_NOW
    mode = (notify_mode or "").strip().lower()
    if mode in ("immediate", "both"):
        return SEND_NOW
    if mode == "digest":
        return BUNDLE
    # An unrecognised mode sends immediately. The noisy direction is the safe one:
    # a misconfiguration that produces too much mail is visible and self-correcting,
    # whereas one that produces too little is discovered only by what never arrived.
    log.warning("notify: unrecognised notify_mode %r; sending immediately", notify_mode)
    return SEND_NOW


# ─────────────────────────────────────────────────────────────────────────────
# Canary self-test — runs at import, in the production path
# ─────────────────────────────────────────────────────────────────────────────

def _selftest_routing() -> None:
    # CRITICAL is immune to every mode, including invented ones.
    for mode in ("digest", "immediate", "both", "", None, "quiet", "never", "off"):
        if route("CRITICAL", mode) != SEND_NOW:
            raise AssertionError(
                "notify canary: CRITICAL was deferred under notify_mode %r — a "
                "digest that can swallow a critical alert is a coverage disable"
                % (mode,))
    for spelling in ("critical", "Critical", " CRITICAL "):
        if route(spelling, "digest") != SEND_NOW:
            raise AssertionError(
                "notify canary: severity %r was not recognised as CRITICAL" % spelling)
    # CONTROL: routing is not simply always SEND_NOW, or the check above is vacuous.
    if route("LOW", "digest") != BUNDLE:
        raise AssertionError(
            "notify canary: a LOW event in digest mode was not bundled — routing "
            "may be returning SEND_NOW unconditionally")
    if route("INFO", "digest") != BUNDLE:
        raise AssertionError("notify canary: INFO in digest mode was not bundled")
    if route("LOW", "immediate") != SEND_NOW:
        raise AssertionError("notify canary: immediate mode did not send immediately")
    # There must be no way to express "drop".
    outcomes = {route(s, m) for s in ("CRITICAL", "HIGH", "LOW", "INFO", "", None)
                for m in ("digest", "immediate", "both", "bogus", None)}
    if not outcomes <= {SEND_NOW, BUNDLE}:
        raise AssertionError(
            "notify canary: routing produced an outcome other than send/bundle: %r"
            % (outcomes - {SEND_NOW, BUNDLE}))


def _selftest_schedule() -> None:
    if parse_hhmm("08:00") != datetime.time(8, 0):
        raise AssertionError("notify canary: parse_hhmm rejected a valid time")
    for bad in ("8:00", "0800", "24:00", "12:60", "", None, "noon", "08:00:00"):
        if parse_hhmm(bad) is not None:
            raise AssertionError(
                "notify canary: parse_hhmm accepted %r; a guessed time delivers "
                "the digest at a moment nobody chose" % (bad,))
    ok, errs = validate_schedule("08:00", "16:00", None)
    if not ok:
        raise AssertionError("notify canary: the shipped defaults failed validation: %r" % errs)
    ok, errs = validate_schedule("08:00", "08:00", None)
    if ok or KEY_CLOSE_TIME not in errs:
        raise AssertionError(
            "notify canary: two digests at the same time were accepted; one of "
            "them would silently never deliver a report")
    ok, _ = validate_schedule("banana", "16:00", None)
    if ok:
        raise AssertionError("notify canary: an unparseable time was accepted")

    # due_digests must distinguish. Fixed instants, no wall-clock reads.
    sched = {"open": datetime.time(8, 0), "close": datetime.time(16, 0),
             "tz": datetime.timezone.utc, "tz_name": "UTC", "problems": []}
    def at(h, m=0):
        return datetime.datetime(2026, 8, 22, h, m, tzinfo=datetime.timezone.utc)
    if due_digests(sched, at(7), {}) != []:
        raise AssertionError("notify canary: a digest was due before its time")
    if due_digests(sched, at(9), {}) != [DIGEST_OPEN]:
        raise AssertionError("notify canary: the open digest was not due after 08:00")
    if due_digests(sched, at(17), {}) != [DIGEST_OPEN, DIGEST_CLOSE]:
        raise AssertionError("notify canary: both digests were not due after 16:00")
    already = {DIGEST_OPEN: at(8, 1)}
    if due_digests(sched, at(9), already) != []:
        raise AssertionError(
            "notify canary: a digest already sent today was due again — it would "
            "resend on every scheduler tick")
    # ...but it IS due again the next day.
    tomorrow = datetime.datetime(2026, 8, 23, 9, 0, tzinfo=datetime.timezone.utc)
    if due_digests(sched, tomorrow, already) != [DIGEST_OPEN]:
        raise AssertionError(
            "notify canary: the digest did not become due again the following day")
    # A naive `now` must raise rather than be interpreted in a mystery timezone.
    try:
        due_digests(sched, datetime.datetime(2026, 8, 22, 9, 0), {})
        raise AssertionError("notify canary: a naive datetime was accepted")
    except DigestScheduleUnavailable:
        pass


def _selftest_dst() -> None:
    """The DST gap must be DETECTED, not absorbed — and normal days must not be
    flagged, or the detector would be useless noise."""
    if ZoneInfo is None:                                     # pragma: no cover
        return
    try:
        london = ZoneInfo("Europe/London")
    except Exception:                                        # pragma: no cover
        return                                               # no tzdata; skip
    gap_day = datetime.date(2026, 3, 29)                     # spring forward 01:00->02:00
    problem = local_time_problem(gap_day, datetime.time(1, 30), london)
    if not problem or "gap" not in problem:
        raise AssertionError(
            "notify canary: the daylight-saving GAP was not detected; a digest "
            "scheduled there would silently never fire that day (got %r)" % problem)
    # CONTROL: an ordinary time on the same day must NOT be flagged.
    if local_time_problem(gap_day, datetime.time(8, 0), london) is not None:
        raise AssertionError(
            "notify canary: an ordinary time was flagged as a DST problem — the "
            "detector reports a problem for everything and measures nothing")
    # CONTROL: an ordinary day must not be flagged either.
    if local_time_problem(datetime.date(2026, 6, 1), datetime.time(8, 0), london) is not None:
        raise AssertionError("notify canary: an ordinary day was flagged")


def _run_selftests() -> None:
    """Run all three canaries with this module's own WARNING output suppressed.

    `_selftest_routing` deliberately feeds `route()` unrecognised modes, each of
    which logs at WARNING by design. Left unsuppressed that puts four spurious
    warnings in the journal on every import — and a warning that always fires is
    one nobody reads, which would degrade the real one. Restored in `finally` so
    a failing assertion cannot leave the logger muted.
    """
    prev_level, prev_prop = log.level, log.propagate
    log.setLevel(logging.CRITICAL)
    log.propagate = False
    try:
        _selftest_routing()
        _selftest_schedule()
        _selftest_dst()
    finally:
        log.setLevel(prev_level)
        log.propagate = prev_prop


_run_selftests()
