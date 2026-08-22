"""Check: clock and timestamp sanity — are stored times comparable and plausible?

THE BUG CLASS THIS EXISTS FOR
    Timestamps in this database are written by several processes in several
    formats, and the failures are quiet:

      * **naive mixed with timezone-aware** in ONE column. Comparing the two
        raises TypeError in Python; sorting them is worse, because it does not
        raise — it just orders them wrongly. `hw_monitor` carries a comment about
        exactly this, from a bug where server and agent only agreed while both
        happened to run in the same timezone.
      * **epoch floats mixed with ISO strings** in one column. Every read still
        "works"; the comparisons are nonsense.
      * **timestamps in the future.** A clock that ran ahead, or a row written
        with the wrong unit (milliseconds into a seconds column), produces rows
        that sort ahead of everything and never expire from a rolling window.

WHY IT DOES NOT TRUST COLUMN NAMES
    A name-based heuristic over-matches, and the first run proved it: it flagged
    `alerts.times_seen` — an occurrence COUNTER whose value was 559 — as an epoch
    timestamp, purely because the name ends in `_seen`. A check that reports a
    counter as a broken clock is a check the operator learns to ignore.

    So a value is only treated as an epoch timestamp when it is numeric AND falls
    inside a plausible epoch range. A count of 559 is not a date in 1970; it is a
    count, and this check says nothing about it.

WHAT IT DELIBERATELY DOES NOT DO
    It does not judge whether a column SHOULD be ISO or epoch. Both are used
    consistently in different tables and converting them is a migration, not a
    diagnostic. It reports only INTERNAL inconsistency — a single column that
    cannot be compared with itself — and implausible values.

Read-only: opens the database read-only, samples rows, writes nothing.
"""

import datetime
import os
import re
import sqlite3
import sys

try:                                    # normal package import
    from . import canary as _canary_harness
except ImportError:                     # loaded by file path (tests, direct run)
    # The checks are documented as independently runnable, and the test suites
    # load them via spec_from_file_location -- neither has package context, so a
    # bare relative import fails. Falling back keeps all three entry points
    # working: `import diagnostics`, `python3 -m diagnostics.<id>`, and a direct
    # path load.
    import os as _os, sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    import canary as _canary_harness

META = {
    "id": "clock_and_timestamp_sanity",
    "name": "Clock & Timestamp Sanity",
    "icon": "🕐",
    "descriptions": {
        "beginner": "Checks that the dates and times stored in the database can "
                    "be compared with each other, and that none of them are in "
                    "the future. Mixed-up time formats make features silently "
                    "sort or expire things in the wrong order.",
        "intermediate": "Samples timestamp columns for internal inconsistency: "
                        "naive vs timezone-aware ISO in one column, ISO mixed "
                        "with epoch numbers, and values dated in the future.",
        "pro": "Per-column representation audit over sampled rows. Flags "
               "naive/aware mixing (TypeError on compare, silent mis-sort), "
               "ISO/epoch mixing, and future-dated values beyond a skew "
               "tolerance. Numeric values are only read as epochs inside a "
               "plausible range, so counters are not mistaken for dates.",
    },
}

_OK = "ok"
_DRIFT = "drift"
_PROBE_FAILED = "probe-failed"
_TAGS = {_OK: "OK", _DRIFT: "DRIFT", _PROBE_FAILED: "PROBE-FAILED"}


def _section(label, state, detail=""):
    """One labeled line. An unrecognised state raises rather than rendering OK."""
    return f"[{_TAGS[state]}] {label}" + (f": {detail}" if detail else "")


# ── Classification ───────────────────────────────────────────────────────────

_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")
#: Trailing `Z` or `+HH:MM` / `+HHMM` — what makes an ISO string timezone-aware.
_AWARE_RE = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")

#: Plausible seconds-since-epoch range. Lower bound is 2001-09-09; upper is
#: 2033-05-18. NOT arbitrary tidiness: this is what separates a timestamp from a
#: counter. `alerts.times_seen` held 559 and a name-only heuristic called it an
#: epoch date in 1970 — the false positive this range exists to prevent.
_EPOCH_MIN = 1_000_000_000
_EPOCH_MAX = 2_000_000_000

#: Milliseconds land ~1000x above the seconds range; called out separately
#: because "wrong unit" is a different fix from "wrong clock".
_EPOCH_MS_MIN = _EPOCH_MIN * 1000
_EPOCH_MS_MAX = _EPOCH_MAX * 1000

KIND_ISO_NAIVE = "iso-naive"
KIND_ISO_AWARE = "iso-aware"
KIND_EPOCH = "epoch"
KIND_EPOCH_MS = "epoch-millis"
KIND_OTHER = "other"


def classify_value(value):
    """What kind of timestamp (if any) this value is. Never raises.

    Returns KIND_OTHER for anything not recognisable as a timestamp — including
    small integers, which are counters far more often than they are dates.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return KIND_OTHER
    if isinstance(value, (int, float)):
        v = float(value)
        if _EPOCH_MIN <= v <= _EPOCH_MAX:
            return KIND_EPOCH
        if _EPOCH_MS_MIN <= v <= _EPOCH_MS_MAX:
            return KIND_EPOCH_MS
        return KIND_OTHER
    text = str(value).strip()
    if not text:
        return None
    if _ISO_RE.match(text):
        return KIND_ISO_AWARE if _AWARE_RE.search(text) else KIND_ISO_NAIVE
    # A numeric STRING can still be an epoch.
    try:
        v = float(text)
    except (TypeError, ValueError):
        return KIND_OTHER
    if _EPOCH_MIN <= v <= _EPOCH_MAX:
        return KIND_EPOCH
    if _EPOCH_MS_MIN <= v <= _EPOCH_MS_MAX:
        return KIND_EPOCH_MS
    return KIND_OTHER


#: Kinds that cannot be compared with each other without conversion.
_COMPARABLE_GROUPS = (
    {KIND_ISO_NAIVE},
    {KIND_ISO_AWARE},
    {KIND_EPOCH},
    {KIND_EPOCH_MS},
)


def incomparable_mix(kinds):
    """True when this set of kinds cannot be compared without conversion.

    `iso-naive` + `iso-aware` is the headline case: Python raises TypeError on
    `<` between them, and — worse — `sorted()` on the raw strings does not raise
    at all, it just produces the wrong order.
    """
    real = {k for k in kinds if k not in (None, KIND_OTHER)}
    if len(real) <= 1:
        return False
    return not any(real <= g for g in _COMPARABLE_GROUPS)


def to_datetime(value, kind):
    """Best-effort conversion for the future-dated check. None if not convertible."""
    try:
        if kind == KIND_EPOCH:
            return datetime.datetime.fromtimestamp(float(value), datetime.timezone.utc)
        if kind == KIND_EPOCH_MS:
            return datetime.datetime.fromtimestamp(float(value) / 1000.0,
                                                   datetime.timezone.utc)
        if kind in (KIND_ISO_NAIVE, KIND_ISO_AWARE):
            text = str(value).strip().replace("Z", "+00:00")
            dt = datetime.datetime.fromisoformat(text)
            if dt.tzinfo is None:
                # A naive stored time is assumed local, which is what wrote it.
                dt = dt.astimezone()
            return dt.astimezone(datetime.timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return None
    return None


#: How far ahead of now a timestamp may be before it is a finding. Generous on
#: purpose: a few minutes of skew between an agent and the server is ordinary and
#: flagging it would bury the real cases (a wrong unit, or a clock years out).
FUTURE_TOLERANCE = datetime.timedelta(hours=1)

#: The SAME question, asked of a NAIVE timestamp, is much weaker — and this
#: check's own canary is what forced the distinction.
#:
#: A naive timestamp carries no zone, so its absolute position is unknowable
#: within the range of real UTC offsets (-12 to +14). Interpreting it as local
#: and comparing against a UTC `now` therefore makes every naive timestamp look
#: future-dated by up to the local offset — on this box, five hours. The first
#: run of this check flagged its own known-good fixture for exactly that reason.
#:
#: Widening the tolerance to cover the full offset range is the honest fix: a
#: naive value can only be called future-dated when it is beyond EVERY plausible
#: interpretation of it. That is weaker than the aware case, and deliberately so
#: — the alternative is a check that reports a fault on every correctly-stored
#: naive timestamp west of Greenwich.
FUTURE_TOLERANCE_NAIVE = datetime.timedelta(hours=15)


# ── Sampling ─────────────────────────────────────────────────────────────────

#: Column names worth sampling. The NAME only decides what to LOOK at; the VALUE
#: decides what is reported, which is what keeps counters out of the findings.
_NAME_HINT = re.compile(r"(_at|_ts|_time|_seen|_date|^ts|^timestamp|^date)", re.I)

SAMPLE_ROWS = 200


def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resolve_db():
    root = _repo_root()
    legacy = os.path.join(root, "alert_manager", "alerts.db")
    try:
        sys.path.insert(0, os.path.join(root, "alert_manager"))
        import nemesis_paths
        return nemesis_paths.db_path(legacy)
    except Exception:
        return legacy


def sample_columns(db_path, limit=SAMPLE_ROWS):
    """{(table, column): [values]} for timestamp-looking columns. Raises on failure."""
    uri = "file:%s?mode=ro" % db_path
    conn = sqlite3.connect(uri, uri=True, timeout=5.0)
    out = {}
    try:
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'")]
        for t in tables:
            safe_t = t.replace('"', '""')
            try:
                cols = [r[1] for r in conn.execute('PRAGMA table_info("%s")' % safe_t)]
            except sqlite3.Error:
                continue
            for c in cols:
                if not _NAME_HINT.search(c):
                    continue
                safe_c = c.replace('"', '""')
                try:
                    vals = [r[0] for r in conn.execute(
                        'SELECT "%s" FROM "%s" WHERE "%s" IS NOT NULL LIMIT %d'
                        % (safe_c, safe_t, safe_c, int(limit)))]
                except sqlite3.Error:
                    continue
                if vals:
                    out[(t, c)] = vals
    finally:
        conn.close()
    return out


def analyse(samples, now=None):
    """Pure analysis over sampled values. Returns findings + coverage counts."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    mixed, future, examined = [], [], 0
    for (table, col), values in sorted(samples.items()):
        kinds = {}
        for v in values:
            k = classify_value(v)
            if k in (None, KIND_OTHER):
                continue
            kinds.setdefault(k, 0)
            kinds[k] += 1
        if not kinds:
            continue            # a counter or free text; this check says nothing
        examined += 1
        if incomparable_mix(set(kinds)):
            mixed.append((table, col, dict(kinds)))
        worst = None
        for v in values:
            k = classify_value(v)
            if k in (None, KIND_OTHER):
                continue
            dt = to_datetime(v, k)
            if dt is None:
                continue
            # A naive value's zone is unknowable, so it gets the wider tolerance
            # — see FUTURE_TOLERANCE_NAIVE.
            tolerance = (FUTURE_TOLERANCE_NAIVE if k == KIND_ISO_NAIVE
                         else FUTURE_TOLERANCE)
            if dt - now > tolerance and (worst is None or dt > worst[0]):
                worst = (dt, v, k)
        if worst is not None:
            future.append((table, col, worst[0], worst[2]))
    return {"mixed": mixed, "future": future, "examined": examined,
            "sampled": len(samples)}


# ── Canary ───────────────────────────────────────────────────────────────────

def _canary():
    """Returns (ok, detail). Never raises. Runs on EVERY invocation."""
    try:
        # Known-GOOD: one consistent representation -> nothing reported.
        good = analyse({("t", "ts"): ["2026-08-22T10:00:00", "2026-08-21T09:00:00"]},
                       now=datetime.datetime(2026, 8, 22, 12, 0,
                                             tzinfo=datetime.timezone.utc))
        if good["mixed"] or good["future"]:
            return False, "a consistent column was reported as a problem"
        if good["examined"] != 1:
            return False, "a valid timestamp column was not examined at all"

        # Known-BAD 1: naive + aware in one column.
        bad1 = analyse({("t", "ts"): ["2026-08-22T10:00:00",
                                      "2026-08-22T10:00:00+00:00"]},
                       now=datetime.datetime(2026, 8, 22, 12, 0,
                                             tzinfo=datetime.timezone.utc))
        if not bad1["mixed"]:
            return False, ("naive/aware mixing was NOT detected -- this is the "
                           "case that silently mis-sorts instead of raising")

        # Known-BAD 2: ISO + epoch in one column.
        bad2 = analyse({("t", "ts"): ["2026-08-22T10:00:00", 1787005118.9]},
                       now=datetime.datetime(2026, 8, 22, 12, 0,
                                             tzinfo=datetime.timezone.utc))
        if not bad2["mixed"]:
            return False, "ISO/epoch mixing was not detected"

        # Known-BAD 3: a future-dated row.
        bad3 = analyse({("t", "ts"): ["2027-01-01T00:00:00+00:00"]},
                       now=datetime.datetime(2026, 8, 22, 12, 0,
                                             tzinfo=datetime.timezone.utc))
        if not bad3["future"]:
            return False, "a future-dated timestamp was not detected"

        # A COUNTER must not be read as a date. This is the real false positive
        # the first run produced: alerts.times_seen held 559 and a name-only
        # heuristic reported it as an epoch timestamp in 1970.
        if classify_value(559) != KIND_OTHER:
            return False, ("a small integer was classified as a timestamp -- "
                           "counters would be reported as broken clocks")
        counter = analyse({("alerts", "times_seen"): [559, 12, 3, 1]},
                          now=datetime.datetime(2026, 8, 22, 12, 0,
                                                tzinfo=datetime.timezone.utc))
        if counter["mixed"] or counter["future"] or counter["examined"]:
            return False, "a counter column was treated as timestamps"

        # Same-kind values must NOT be called incomparable, or every column
        # becomes a finding and the check means nothing.
        if incomparable_mix({KIND_ISO_NAIVE}):
            return False, "a single-representation column was called incomparable"
        if incomparable_mix(set()):
            return False, "an empty kind set was called incomparable"
        if not incomparable_mix({KIND_ISO_NAIVE, KIND_ISO_AWARE}):
            return False, "naive+aware was not treated as incomparable"

        # Ordinary skew must not be flagged, or real drift is buried in noise.
        near = analyse({("t", "ts"): ["2026-08-22T12:05:00+00:00"]},
                       now=datetime.datetime(2026, 8, 22, 12, 0,
                                             tzinfo=datetime.timezone.utc))
        if near["future"]:
            return False, "five minutes of ordinary skew was reported as future-dated"

        # REGRESSION: a correctly-stored NAIVE timestamp must not read as
        # future-dated merely because this host is west of Greenwich. The first
        # version flagged its own known-good fixture this way, on every box with
        # a negative UTC offset.
        naive_ok = analyse({("t", "ts"): ["2026-08-22T10:00:00"]},
                           now=datetime.datetime(2026, 8, 22, 12, 0,
                                                 tzinfo=datetime.timezone.utc))
        if naive_ok["future"]:
            return False, ("a naive timestamp two hours in the past was reported "
                           "as future-dated -- the local-offset ambiguity is not "
                           "being accounted for")
        # ...but a naive timestamp beyond ANY plausible offset still IS a finding.
        naive_bad = analyse({("t", "ts"): ["2027-06-01T00:00:00"]},
                            now=datetime.datetime(2026, 8, 22, 12, 0,
                                                  tzinfo=datetime.timezone.utc))
        if not naive_bad["future"]:
            return False, ("a naive timestamp ten months in the future was NOT "
                           "reported -- the wider tolerance has swallowed the "
                           "whole check")
        return True, "known-good and 10 known-bad cases behaved correctly"
    except Exception as e:                                   # noqa: BLE001
        return False, "canary itself failed: %s: %s" % (type(e).__name__, e)


def run() -> dict:
    """Entry point. The harness runs the canary and suppresses the
    verdict entirely if it fails -- see diagnostics/canary.py."""
    return _canary_harness.guard(META, _canary, _produce,
                                 subject="timestamps")


def _produce(detail):
    sections = [_section("canary self-test", _OK, detail)]
    db_path = _resolve_db()
    try:
        samples = sample_columns(db_path)
    except Exception as e:                                   # noqa: BLE001
        return {
            "id": META["id"], "name": META["name"], "icon": META["icon"],
            "status": "error",
            "summary": "Could not sample the database",
            "output": "\n".join(sections + [
                _section("sampling", _PROBE_FAILED,
                         "%s reading %s" % (type(e).__name__,
                                            os.path.basename(db_path)))]),
        }

    result = analyse(samples)
    status = _OK
    sections.append(_section(
        "columns examined", _OK,
        "%d timestamp columns with data (%d candidates sampled, %d rows each)"
        % (result["examined"], result["sampled"], SAMPLE_ROWS)))

    if result["mixed"]:
        status = _DRIFT
        lines = []
        for table, col, kinds in result["mixed"]:
            breakdown = ", ".join("%s=%d" % (k, n) for k, n in sorted(kinds.items()))
            lines.append("%s.%s: %s" % (table, col, breakdown))
        sections.append(_section(
            "columns whose values cannot be compared with each other", _DRIFT,
            "%d — sorting these is silently wrong, comparing them raises:\n    %s"
            % (len(lines), "\n    ".join(lines))))
    else:
        sections.append(_section("every column uses one representation", _OK))

    if result["future"]:
        status = _DRIFT
        lines = ["%s.%s: %s (%s)" % (t, c, dt.isoformat(timespec="seconds"), k)
                 for t, c, dt, k in result["future"]]
        sections.append(_section(
            "future-dated values", _DRIFT,
            "%d — a clock ahead, or the wrong unit written:\n    %s"
            % (len(lines), "\n    ".join(lines))))
    else:
        sections.append(_section("no future-dated timestamps", _OK))

    n = len(result["mixed"]) + len(result["future"])
    return {
        "id": META["id"], "name": META["name"], "icon": META["icon"],
        "status": "warn" if status == _DRIFT else "ok",
        "summary": ("%d timestamp issue(s) found" % n) if n
                   else "Timestamps are internally consistent",
        "output": "\n".join(sections),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))
