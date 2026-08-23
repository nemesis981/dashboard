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
KEY_NOTIFY_MODE = "notify_mode"

#: DEFAULT IS `immediate`, DELIBERATELY -- it is the pre-digest behaviour.
#:
#: Defaulting to "digest" would flip every existing installation to batched mail
#: on upgrade, which can delay a HIGH-severity alert by up to twelve hours for an
#: operator who never opened the setting and never agreed to it. Defaulting to
#: "immediate" makes this layer inert until someone opts in: the pipe is live and
#: proven, but nothing changes underfoot. Same reasoning `route()` already
#: applies to an unrecognised mode -- the noisy direction is the safe one.
#:
#: Defined HERE, with the other settings keys, rather than beside the dispatch
#: helper that reads it: `validate_notify_mode` (far above that helper) needs it,
#: and a constant defined below its first use resolves only by accident of call
#: ordering. Same trap as a default argument naming a not-yet-defined value --
#: it compiles, then raises at import.
DEFAULT_NOTIFY_MODE = "immediate"

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


# ── Delivery mode: the operator-facing vocabulary ────────────────────────────

MODE_IMMEDIATE = "immediate"
MODE_DIGEST = "digest"

#: The modes an operator may CHOOSE. Deliberately narrower than what `route()`
#: tolerates.
#:
#: `route()` also accepts "both", and treats it exactly as "immediate" -- the
#: "send now AND also include it in the digest" half was never built, and
#: `route()` structurally cannot express it because it returns one decision, not
#: a set. Nothing in the tree ever sets it (verified 2026-08-23: it appears only
#: in `route()` and its own canary). Offering it in a settings UI would therefore
#: promise behaviour that does not exist, so it is NOT offered here. Implementing
#: it properly means changing `route()`'s return type, which is its own decision.
NOTIFY_MODES = (MODE_IMMEDIATE, MODE_DIGEST)

_MODE_LABELS = {
    MODE_IMMEDIATE: "Send every notification immediately",
    MODE_DIGEST: "Bundle non-critical notifications into the twice-daily digest",
}


def mode_label(mode):
    """Human-readable label for a mode, for the settings UI."""
    return _MODE_LABELS.get((mode or "").strip().lower(), "")


def validate_notify_mode(raw):
    """Validate an operator-supplied delivery mode. Returns (ok, errors).

    Refuses at the WRITE, like `validate_schedule`. A mode that reaches storage
    unvalidated does not fail loudly -- `route()` falls back to sending
    immediately and logs a warning, so the operator's chosen setting silently
    does nothing and the only evidence is a log line nobody reads.
    """
    errors = {}
    text = (raw or "").strip().lower()
    if text not in NOTIFY_MODES:
        errors[KEY_NOTIFY_MODE] = ("must be one of: %s"
                                   % ", ".join(NOTIFY_MODES))
    return (not errors), errors


def validate_digest_settings(open_text, close_text, tz_name, mode):
    """Validate ALL FOUR digest settings together. Returns (ok, errors_by_field).

    One gate for the whole form, because the settings belong to one feature and
    an operator fixing them one refusal at a time learns about each problem only
    after fixing the last one.
    """
    ok_sched, errors = validate_schedule(open_text, close_text, tz_name)
    _ok_mode, mode_errors = validate_notify_mode(mode)
    errors = dict(errors)
    errors.update(mode_errors)
    return (not errors), errors


def save_digest_settings(open_text, close_text, tz_name, mode,
                         set_setting=None, actor=None):
    """Validate, then write all four. Returns (ok, errors_by_field).

    ALL-OR-NOTHING, deliberately: if any field is invalid, NOTHING is written.

    A partial write is the failure worth designing against here. Accepting a
    valid start time while rejecting an invalid end time leaves the stored
    schedule in a state the operator never chose and the form no longer shows --
    and a digest then fires at a time nobody picked. Refusing the whole form
    keeps stored state equal to some state the operator actually asked for.

    `set_setting` is injected so this is testable without a database.
    """
    ok, errors = validate_digest_settings(open_text, close_text, tz_name, mode)
    if not ok:
        return False, errors
    writer = set_setting
    if writer is None:
        import database                                        # noqa: PLC0415
        writer = database.set_setting
    writer(KEY_OPEN_TIME, open_text, actor=actor)
    writer(KEY_CLOSE_TIME, close_text, actor=actor)
    writer(KEY_TIMEZONE, tz_name or "", actor=actor)
    writer(KEY_NOTIFY_MODE, (mode or "").strip().lower(), actor=actor)
    return True, {}


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


# ─────────────────────────────────────────────────────────────────────────────
# DELIVERY — the half that turns a routing decision into an email
#
# Everything above decides WHETHER and WHEN. None of it sends anything, and a
# `BUNDLE` verdict with nowhere to put the event is just a drop with extra steps.
# This section closes that: queue -> build -> send -> mark sent.
#
# THE ORDERING RULE, and it is the whole safety property:
#     mark sent ONLY after the send genuinely succeeded.
# `send_email` returns False on failure rather than raising, so a caller that
# marks first and sends second loses every event in a failed digest with no
# trace. Marked-after means the worst case is a repeated digest, which an
# operator notices, rather than a silent hole, which nobody does.
# ─────────────────────────────────────────────────────────────────────────────

import sqlite3

#: notify_state keys recording when each digest last went out.
_STATE_LAST_SENT = "digest_last_sent_%s"


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def enqueue(conn, severity, subject, body="", surface=None, family_key=None,
            actor=None, now=None):
    """Hold one event for the next digest. Returns the row id.

    Callers must route() FIRST and only enqueue a BUNDLE verdict. This function
    deliberately does not call route() itself: a helper that both decides and
    stores would make "was this event held on purpose, or did the caller forget
    to send it immediately?" unanswerable after the fact.
    """
    ts = (now or _utcnow()).isoformat(timespec="seconds")
    cur = conn.execute(
        "INSERT INTO notify_queue(queued_at, severity, surface, family_key, "
        "subject, body, actor) VALUES(?,?,?,?,?,?,?)",
        (ts, (severity or "").upper(), surface, family_key, subject, body, actor))
    conn.commit()
    return cur.lastrowid


def pending(conn, limit=500):
    """Unsent queued events, oldest first. `sent_at IS NULL` is the whole test."""
    rows = conn.execute(
        "SELECT id, queued_at, severity, surface, family_key, subject, body "
        "FROM notify_queue WHERE sent_at IS NULL ORDER BY queued_at, id "
        "LIMIT ?", (int(limit),)).fetchall()
    return [dict(zip(("id", "queued_at", "severity", "surface", "family_key",
                      "subject", "body"), r)) for r in rows]


#: Severity order for digest grouping, most urgent first.
_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def bundle(events):
    """Collapse events by family_key. Returns [(count, representative)] sorted.

    This is where the measured 65% repeat rate is paid off: 28 CPU-temperature
    notices become one line reading "28x", not 28 lines. An event with NO family
    key is never collapsed — it stands alone, because inventing a grouping for
    something that has none is how unrelated events get silently merged.
    """
    groups, singles = {}, []
    for e in events:
        fk = (e.get("family_key") or "").strip()
        if not fk:
            singles.append((1, e))
            continue
        g = groups.setdefault(fk, [])
        g.append(e)
    # The representative is the MOST SEVERE member, not the first.
    #
    # Taking v[0] understates the family: a "disk 80%" LOW followed by a
    # "disk 85%" MEDIUM would report as LOW, and the digest's own subject line
    # ("highest: ...") would then be wrong about the worst thing in it. Caught by
    # a test, not by reading — the collapse looked obviously correct.
    out = [(len(v), min(v, key=lambda e: _SEV_RANK.get(
                (e.get("severity") or "").upper(), 9)))
           for v in groups.values()] + singles
    out.sort(key=lambda ce: (_SEV_RANK.get((ce[1].get("severity") or "").upper(), 9),
                             ce[1].get("queued_at") or ""))
    return out


def build_digest(which, events, schedule, now=None):
    """(subject, body) for one digest. Pure — no I/O, so it is directly testable.

    An EMPTY digest is still sent, deliberately. Twice-daily mail saying "nothing
    to report" is mildly annoying; silence is worse, because it is
    indistinguishable from a digest that has broken. The whole reason this feature
    exists is that 23 hours of DNS failure once passed unnoticed — a scheduled
    report that only appears when there is bad news cannot tell you it is alive.
    """
    now = now or _utcnow()
    tz = schedule.get("tz")
    local = now.astimezone(tz) if tz else now
    label = ("Start of day" if which == DIGEST_OPEN else "End of day")
    bundled = bundle(events)
    total = sum(c for c, _ in bundled)

    if not bundled:
        subject = "Nemesis %s digest — nothing to report" % label.lower()
        body = ("%s digest for %s.\n\nNo notifications were held since the last "
                "digest.\n\nThis report is sent even when empty, on purpose: a "
                "digest that only arrives with bad news cannot tell you it is "
                "still working.\n" % (label, local.strftime("%Y-%m-%d %H:%M %Z")))
        return subject, body

    worst = min((_SEV_RANK.get((e.get("severity") or "").upper(), 9)
                 for _c, e in bundled), default=9)
    worst_name = next((k for k, v in _SEV_RANK.items() if v == worst), "INFO")
    subject = ("Nemesis %s digest — %d notification%s (highest: %s)"
               % (label.lower(), total, "" if total == 1 else "s", worst_name))

    lines = ["%s digest for %s." % (label, local.strftime("%Y-%m-%d %H:%M %Z")),
             "", "%d notification%s held since the last digest:"
             % (total, "" if total == 1 else "s"), ""]
    for count, e in bundled:
        sev = (e.get("severity") or "INFO").upper()
        times = (" (x%d)" % count) if count > 1 else ""
        lines.append("  [%-8s] %s%s" % (sev, e.get("subject") or "(no subject)", times))
        detail = (e.get("body") or "").strip().splitlines()
        if detail:
            lines.append("             %s" % detail[0][:110])
    lines += ["", "Critical notifications are NOT held for a digest — they are "
              "sent immediately and are not listed here.", ""]
    for w in schedule_warnings(schedule):
        lines.append("  ! schedule warning: %s" % w)
    return subject, "\n".join(lines)


def mark_sent(conn, ids, which, now=None):
    """Mark rows delivered. Called ONLY after a genuinely successful send."""
    if not ids:
        return 0
    ts = (now or _utcnow()).isoformat(timespec="seconds")
    conn.executemany("UPDATE notify_queue SET sent_at=?, digest=? WHERE id=?",
                     [(ts, which, i) for i in ids])
    conn.commit()
    return len(ids)


def _get_state(conn, key, default=None):
    row = conn.execute("SELECT value FROM notify_state WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def _set_state(conn, key, value, now=None):
    conn.execute(
        "INSERT INTO notify_state(key, value, updated_at) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
        "updated_at=excluded.updated_at",
        (key, str(value), (now or _utcnow()).isoformat(timespec="seconds")))
    conn.commit()


def last_sent_map(conn):
    """{digest_name: aware datetime} for due_digests(). Unparseable -> absent.

    An unreadable timestamp is treated as "never sent", which sends one extra
    digest. The opposite default — treating it as just-sent — would suppress a
    digest on the strength of a value nobody could read.
    """
    out = {}
    for which in (DIGEST_OPEN, DIGEST_CLOSE):
        raw = _get_state(conn, _STATE_LAST_SENT % which)
        if not raw:
            continue
        try:
            dt = datetime.datetime.fromisoformat(raw)
            out[which] = dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)
        except (TypeError, ValueError):
            log.warning("notify: unreadable last-sent for %s (%r); treating as "
                        "never sent", which, raw)
    return out


def send_digest(conn, which, schedule, sender=None, recipient=None, now=None):
    """Build and deliver one digest. Returns a result dict. Never raises.

    `sender` is injected so the whole path is testable without SMTP.
    """
    now = now or _utcnow()
    events = pending(conn)
    subject, body = build_digest(which, events, schedule, now=now)
    ids = [e["id"] for e in events]

    if sender is None:
        import email_utils                                   # noqa: PLC0415
        sender = email_utils.send_email

    try:
        ok = bool(sender(subject, body, recipient) if recipient
                  else sender(subject, body))
    except Exception as exc:                                 # noqa: BLE001
        log.exception("notify: digest send raised")
        return {"ok": False, "which": which, "queued": len(ids), "sent": 0,
                "error": "%s: %s" % (type(exc).__name__, exc)}

    if not ok:
        # Nothing is marked. The events stay queued for the next attempt, which
        # is the entire reason marking happens after the send and not before.
        log.error("notify: %s digest send FAILED; %d event(s) remain queued",
                  which, len(ids))
        return {"ok": False, "which": which, "queued": len(ids), "sent": 0,
                "error": "send_email returned False"}

    marked = mark_sent(conn, ids, which, now=now)
    _set_state(conn, _STATE_LAST_SENT % which, now.isoformat(timespec="seconds"), now=now)
    return {"ok": True, "which": which, "queued": len(ids), "sent": marked,
            "subject": subject}


def run_digest_tick(conn, get_setting, sender=None, recipient=None, now=None):
    """Scheduler entry point: send whatever is due. Never raises.

    Idempotent by construction — `due_digests` consults the recorded last-sent,
    so calling this every minute sends at most one OPEN and one CLOSE per local
    day. That matters because the intended host is a loop that already runs on a
    short interval; a tick that resent on every call would mail continuously.
    """
    try:
        schedule = digest_schedule(get_setting)
        due = due_digests(schedule, now or _utcnow(), last_sent_map(conn))
    except Exception as exc:                                 # noqa: BLE001
        log.exception("notify: could not determine due digests")
        return {"ok": False, "due": [], "results": [],
                "error": "%s: %s" % (type(exc).__name__, exc)}
    results = [send_digest(conn, w, schedule, sender=sender,
                           recipient=recipient, now=now) for w in due]
    return {"ok": all(r.get("ok") for r in results), "due": due, "results": results}


# ─────────────────────────────────────────────────────────────────────────────
# THE CALLER-FACING ENTRY POINT
#
# Everything above is machinery. This is the ONE function the ~10 existing
# `send_email` call sites should use, and the reason it exists is that they must
# NOT each learn the machinery:
#
#   * `route()` needs a severity and a mode. A caller that forgets the mode gets
#     the `route()` default, which is BUNDLE -- so a caller that half-adopts this
#     layer silently starts deferring mail. One entry point means one place that
#     reads the setting.
#   * `enqueue()` needs a live sqlite3 connection. Two of the call sites are
#     MODULES, and `modules_loader` statically refuses to load a module that
#     imports sqlite3 or calls get_db (verified: it ast.walk()s module.py for
#     exactly that). A module can therefore never legally hold the connection
#     `enqueue` wants -- but it CAN call this, because the connection is acquired
#     in here, in alert_manager, which the loader does not scan.
#   * A notification path must never take down the thing that was notifying.
#
# So: callers pass what they know (severity, subject, body, family). They do not
# pass, or need, a connection, a mode, or a schedule.
# ─────────────────────────────────────────────────────────────────────────────

def _default_get_setting(key, default=None):
    """Read a setting without importing `database` at module import time."""
    import database                                            # noqa: PLC0415
    return database.get_setting(key, default)


def notify(severity, subject, body="", family_key=None, surface=None,
           actor=None, conn=None, sender=None, get_setting=None, now=None):
    """Deliver one notification: immediately, or into the next digest.

    THE ONE CALL SITES SHOULD USE. Returns an explicit result dict and NEVER
    raises -- a failure to notify must not break detection, which is the thing
    that actually matters.

    `severity` MUST be a `nemesis_severity.CANONICAL` value. CRITICAL is always
    sent immediately, before any setting is consulted (see `route`).

    `family_key` groups repeats for bundling -- 28 CPU-temperature notices become
    one "(x28)" line instead of 28 emails. Omit it and the event stands alone;
    inventing a shared key for unrelated events silently merges them, so when in
    doubt leave it out.

    Returns::

        {"ok": bool, "delivery": "send_now"|"bundle", "queued_id": int|None,
         "error": str|None, "fell_back": bool}

    `fell_back=True` means the event was routed to the digest but could not be
    queued, so it was sent immediately instead. See below -- that direction is
    deliberate.
    """
    mode = DEFAULT_NOTIFY_MODE
    try:
        getter = get_setting or _default_get_setting
        mode = getter(KEY_NOTIFY_MODE, DEFAULT_NOTIFY_MODE) or DEFAULT_NOTIFY_MODE
    except Exception:                                          # noqa: BLE001
        # `mode` keeps its pre-initialised value; this is what stops an
        # exception here from becoming a NameError below. (It is NOT what keeps
        # delivery safe -- `route()` already fails safe on any unrecognised
        # mode. Proven: mutating the pre-init to None changes nothing
        # observable, which is why no test claims otherwise.)
        log.exception("notify: could not read %s; using %r",
                      KEY_NOTIFY_MODE, DEFAULT_NOTIFY_MODE)

    # Pass `mode` EXPLICITLY. `route()`'s own default parameter is "digest", so
    # calling route(severity) here would silently bundle every non-critical
    # notification regardless of the setting. Pinned by a mutation.
    decision = route(severity, mode)

    if decision == BUNDLE:
        owned = conn is None
        try:
            if owned:
                import database                                # noqa: PLC0415
                conn = sqlite3.connect(database.DB_PATH, timeout=5.0)
            try:
                qid = enqueue(conn, severity, subject, body=body,
                              surface=surface, family_key=family_key,
                              actor=actor, now=now)
            finally:
                if owned:
                    conn.close()
            return {"ok": True, "delivery": BUNDLE, "queued_id": qid,
                    "error": None, "fell_back": False}
        except Exception as exc:                               # noqa: BLE001
            # FALL FORWARD TO AN IMMEDIATE SEND, never a silent drop.
            #
            # The queue is the only thing holding a bundled event; if the insert
            # failed, the event exists nowhere else and returning "ok" would lose
            # it permanently. Sending it now is the wrong SCHEDULE but the right
            # EVENT -- and an operator noticing an unexpected email is a far
            # better failure than an operator never learning something happened.
            log.exception("notify: enqueue failed; sending immediately instead")
            result = _send_now(subject, body, sender)
            result["fell_back"] = True
            return result

    return _send_now(subject, body, sender)


def _send_now(subject, body, sender=None):
    """Immediate delivery. Never raises; reports what happened."""
    if sender is None:
        import email_utils                                     # noqa: PLC0415
        sender = email_utils.send_email
    try:
        ok = bool(sender(subject, body))
    except Exception as exc:                                   # noqa: BLE001
        log.exception("notify: immediate send raised")
        return {"ok": False, "delivery": SEND_NOW, "queued_id": None,
                "error": "%s: %s" % (type(exc).__name__, exc), "fell_back": False}
    if not ok:
        log.error("notify: immediate send failed for %r", subject)
    return {"ok": ok, "delivery": SEND_NOW, "queued_id": None,
            "error": None if ok else "send_email returned False",
            "fell_back": False}
