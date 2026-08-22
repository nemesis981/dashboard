"""Bounded detector settings — refusing the value that goes dark quietly.

WHY THIS EXISTS
---------------
A detector setting with a floor but no ceiling is a coverage-disable with a
number on it. `max(5, int(value))` reads like validation and is not: it refuses
5 seconds and accepts 999,999,999, which parks a detector for **31.69 years**
while every status page still reports it enabled and healthy. Confirmed live
2026-08-22 in two places — `canary_poll_seconds` (the ransomware bait tripwire)
and `watcher_interval_seconds` (the connectivity watcher) — both reachable by a
single authenticated dashboard POST, and one of them through a settings endpoint
that performed no validation of any kind.

**The shape is not specific to intervals.** The same audit found the identical
defect elsewhere in `malware_detection`, in settings that are not cadences at
all — a value that silently means "never", accepted by a validator that only
ever checked one end (or had no branch at all). So this module is about BOUNDED
SETTINGS generally, not cadence specifically — it was called `cadence.py` for
about an hour, which would have made a non-cadence spec a lie about its own
contents.

This is the same attack `nemesis_agent/agent.py:319` already refuses for
server-supplied poll hints, and its reasoning transfers verbatim:

    Honouring a LONGER one would let an impersonator tell an agent to come back
    in thirty days, silencing its telemetry while it still looked healthy from
    the device's side. Refusing to lengthen means that attack does not exist,
    rather than merely being bounded.

The ratified constraint (2026-08-22) is that no credential, override or master
password may fully disable coverage — that is a capability-lift, categorically
out of reach, and only the service stopping may stop coverage. A dial that
reaches "never" is such a lift wearing a cadence's clothes, so it is closed here
rather than documented as a caveat.

THE CEILINGS ARE REAL LIMITS, NOT INPUT HYGIENE
-----------------------------------------------
Each maximum below is justified against what the detector is FOR, in the same
spirit as `REMOTE_OBSERVE_N_MAX = 48` in `alert_manager/database.py` ("beyond
that the snapshot is stale enough to stop being an observation layer and start
being a misleading one"). A ceiling picked for tidiness would be arbitrary and
would get raised the first time someone found it inconvenient; a ceiling that
names the property it protects can be argued with on the merits.

TWO GATES, NEITHER TRUSTING THE OTHER
-------------------------------------
  * `validate()` runs at the WRITE (the settings API) and REFUSES an
    out-of-range value with a message naming the bound. Refusing at the door
    means the bad value never reaches storage, so nothing downstream has to cope
    with it and the operator finds out immediately rather than from a silence.
  * `resolve()` runs at the READ (the service loop) and falls back to the
    DEFAULT for anything out of range or unparseable. Defence in depth against a
    value written before these bounds existed, by a direct DB edit, or by a code
    path that forgot to validate.

Out-of-range resolves to the DEFAULT, deliberately **not** to the nearest bound.
`alert_manager/database.py` established the reasoning and it holds here: clamping
is only safe from a value that was meaningful to begin with. Silently rewriting a
stored 999999999 to the 300s ceiling would present a deliberate attempt to park
the detector as a normal, healthy configuration — the operator would see a
plausible number and never learn their write had been overruled.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)


class BoundedSpec:
    """One bounded setting: its default, its bounds, its type, and WHY.

    `rationale` is not decoration — it is what a future maintainer reads when
    they want to raise the ceiling, and it is quoted verbatim in the error a
    rejected write receives. A bound whose reason cannot be stated is a bound
    nobody will keep.

    `kind` is `int` or `float`. It matters: `entropy_threshold` defaults to 7.2,
    and coercing it through `int()` would silently store 7 — a validator that
    corrupts the value it approves.
    """

    __slots__ = ("key", "default", "minimum", "maximum", "unit", "rationale", "kind")

    def __init__(self, key, default, minimum, maximum, unit="s", rationale="",
                 kind=int):
        if kind not in (int, float):
            raise ValueError("BoundedSpec %r: kind must be int or float" % key)
        if not (minimum <= default <= maximum):
            # A spec whose own default is out of its own bounds would make
            # resolve() return a value validate() rejects — the two gates would
            # disagree permanently and silently. Caught at import, not in prod.
            raise ValueError(
                "BoundedSpec %r is self-inconsistent: default %r outside [%r, %r]"
                % (key, default, minimum, maximum))
        self.key       = key
        self.default   = default
        self.minimum   = minimum
        self.maximum   = maximum
        self.unit      = unit
        self.rationale = rationale
        self.kind      = kind

    def describe_bounds(self) -> str:
        return "must be between %s%s and %s%s%s" % (
            self.minimum, self.unit, self.maximum, self.unit,
            (" — %s" % self.rationale) if self.rationale else "")


#: Back-compat alias. Cadences are the commonest case and reading
#: `CadenceSpec(...)` at a poll-interval definition is clearer than the generic
#: name; they are the same class.
CadenceSpec = BoundedSpec


# ─────────────────────────────────────────────────────────────────────────────
# The specs. Every ceiling names the property it protects.
# ─────────────────────────────────────────────────────────────────────────────

#: The ransomware bait tripwire. A canary trip is only ever discovered ON a poll,
#: so the poll interval IS the detection latency. Ransomware encrypts a user
#: directory in minutes; at a 5-minute ceiling the trip is still caught while the
#: encryption is in progress, which is what makes it a tripwire rather than a
#: post-mortem. Beyond that it reports the fire after the house is gone.
CANARY_POLL_SECONDS = CadenceSpec(
    "canary_poll_seconds", default=30, minimum=5, maximum=300,
    rationale="the poll interval IS the ransomware detection latency")

#: The continuous connectivity watcher. Its own sample cap (`watcher_samples_max`,
#: 2880) is sized for ~48h at the 60s default. At the 15-minute ceiling it still
#: takes ~96 samples/day — enough to characterise an outage's start, duration and
#: recovery. Beyond that a multi-hour outage can fall entirely between two
#: samples, and a watcher that can miss the whole event is not continuous.
WATCHER_INTERVAL_SECONDS = CadenceSpec(
    "watcher_interval_seconds", default=60, minimum=5, maximum=900,
    rationale="beyond this an outage can fall entirely between two samples")

# ─────────────────────────────────────────────────────────────────────────────
# Non-cadence detector bounds (added 2026-08-22). Same defect class, four of them
# found live: a value that silently means "never", accepted because the validator
# only ever checked one end — or had no branch at all.
# ─────────────────────────────────────────────────────────────────────────────

#: Shannon entropy of a byte stream, in bits/byte. **The maximum possible value
#: is exactly 8.0** (log2(256)), so `entropy >= threshold` is permanently false
#: for anything above it: entropy detection is dead while `heuristics_enabled`
#: still reads "1". The ceiling is therefore strictly below the theoretical
#: maximum, not a matter of taste.
#:
#: The floor matters too, in the other direction. Ordinary compressed media
#: (JPEG, MP4, ZIP) sits around 7.9-8.0, and general compressed data around
#: 6.x-7.x; a threshold much below that flags every photo on the box, which is a
#: false-positive flood rather than a coverage loss — but it is the shape that
#: makes an operator disable the layer, so it is bounded here as well.
ENTROPY_THRESHOLD = BoundedSpec(
    "entropy_threshold", default=7.2, minimum=6.0, maximum=7.99,
    unit=" bits/byte", kind=float,
    rationale="max possible entropy is 8.0, so a higher threshold can never match")

#: Minimum heuristic score at which Layer C (the AI verdict) is consulted.
#: `_score_for` caps at 100, so a value above that makes Layer C unreachable —
#: an off switch for a whole layer, spelled as a number.
AUTO_AI_MIN_SCORE = BoundedSpec(
    "auto_ai_min_score", default=40, minimum=1, maximum=100, unit="",
    rationale="scores are capped at 100, so a higher gate is never reachable")

#: Hours between automatic full-filesystem scans. The 24h default exists because
#: it matches the agent fleet's own staleness rule, so the appliance is held to
#: the same standard as the endpoints it protects. A ceiling above one week makes
#: the appliance the least-scanned machine on its own network.
FULL_SCAN_INTERVAL_HOURS = BoundedSpec(
    "full_scan_interval_hours", default=24, minimum=1, maximum=168,
    unit="h", kind=float,
    rationale="beyond a week the appliance is the least-scanned machine on its "
              "own network")

#: Ceiling on files examined in one full scan. **The FLOOR is the meaningful
#: bound**: below the point where a scan cannot traverse a real user home,
#: `truncated: true` is the only honest output and the scan has stopped being
#: evidence of anything. The upper bound is resource hygiene, not safety.
FULL_SCAN_MAX_FILES = BoundedSpec(
    "full_scan_max_files", default=500000, minimum=1000, maximum=100000000,
    unit=" files",
    rationale="below this a scan cannot traverse a real user home and its result "
              "is not evidence")

#: Delay before the first scan after boot, so a reboot does not immediately
#: contend with everything else starting. A ceiling of 24h keeps it a startup
#: delay; beyond that it is a way to ensure the scan never runs this boot.
FULL_SCAN_BOOT_DELAY_SECONDS = BoundedSpec(
    "full_scan_boot_delay_seconds", default=600, minimum=0, maximum=86400,
    rationale="beyond a day this is not a startup delay, it is a way to skip the "
              "scan entirely")

#: Per-canary notification suppression window. Unlike the settings above this
#: throttles NOTIFICATION, not the record — a finding row is still written on
#: every state change regardless. It is bounded anyway: at a large enough value a
#: real ransomware trip never reaches a human, and "the record exists somewhere"
#: is not detection if nobody is told. 24h is the ceiling because a tripwire
#: nobody hears about within a day has not done its job.
CANARY_ALERT_COOLDOWN_SECONDS = BoundedSpec(
    "canary_alert_cooldown_seconds", default=1800, minimum=60, maximum=86400,
    rationale="beyond a day a real trip never reaches a human")

#: How often integrity_watch re-evaluates agent scan honesty.
#:
#: The CEILING is derived, not chosen. Signal 1 (`finding_regression`) compares a
#: `WINDOW_DAYS = 30` recent window against everything prior. Running less often
#: than the window means consecutive runs no longer overlap, so a regression that
#: starts and resolves inside one un-sampled gap is never seen — while the module
#: still reports `ok`. Half the window (15 days = 360h) guarantees every
#: regression falls inside at least one evaluated window.
INTEGRITY_EVAL_INTERVAL_HOURS = BoundedSpec(
    "integrity_eval_interval_hours", default=24, minimum=1, maximum=360,
    unit="h", kind=float,
    rationale="beyond half the 30-day comparison window, consecutive runs stop "
              "overlapping and a regression can fall entirely between them")

#: Registry, so a settings endpoint can look a key up rather than hardcode a
#: branch per key — the shape that let `canary_poll_seconds` fall through
#: `_validate_setting`'s if-chain to its unconditional `return True, ""`.
SPECS = {s.key: s for s in (
    CANARY_POLL_SECONDS,
    WATCHER_INTERVAL_SECONDS,
    INTEGRITY_EVAL_INTERVAL_HOURS,
    ENTROPY_THRESHOLD,
    AUTO_AI_MIN_SCORE,
    FULL_SCAN_INTERVAL_HOURS,
    FULL_SCAN_MAX_FILES,
    FULL_SCAN_BOOT_DELAY_SECONDS,
    CANARY_ALERT_COOLDOWN_SECONDS,
)}


class CadenceUnavailable(Exception):
    """Raised when a cadence cannot be resolved AND no default can be applied.

    An exception rather than a number because every number is a legal cadence,
    so a returned one is indistinguishable from a real answer.
    """


def validate(raw, spec) -> tuple:
    """Gate for the WRITE path. Returns (ok, error_message).

    Refuses rather than clamps: the operator learns immediately that the value
    was rejected and why. A clamp here would accept the write, store something
    else, and report success — so the settings page would show a number the
    system is not using.
    """
    if isinstance(spec, str):
        spec = SPECS.get(spec)
        if spec is None:
            return False, "no cadence bounds defined for this key"
    text = str(raw).strip()
    if not text:
        return False, "must not be empty; %s" % spec.describe_bounds()
    try:
        value = _coerce(text, spec)
    except (TypeError, ValueError):
        return False, "must be %s; %s" % (
            "a number" if spec.kind is float else "a whole number",
            spec.describe_bounds())
    if value < spec.minimum or value > spec.maximum:
        return False, spec.describe_bounds()
    return True, ""


def _coerce(text, spec):
    """Parse to the spec's type. Raises ValueError on anything else.

    An int spec REFUSES "7.2" rather than truncating it to 7. Truncation would
    accept a write and store a different number than the operator typed — the
    settings page would then display a value the system is not using, which is
    the same class of lie as a clamp that silently rewrites an out-of-range value.
    """
    if spec.kind is float:
        return float(text)
    ivalue = int(text)          # int("7.2") raises, deliberately
    return ivalue


def resolve(raw, spec) -> int:
    """Gate for the READ path. Always returns a usable in-bounds cadence.

    Out-of-range or unparseable resolves to the DEFAULT (never the nearest
    bound — see the module docstring) and logs at WARNING, because a value that
    had to be overruled is an operational event: either someone tried to park a
    detector, or a legitimate write bypassed validation. Both deserve a line in
    the journal rather than a silent correction.
    """
    if isinstance(spec, str):
        spec = SPECS.get(spec)
        if spec is None:
            raise CadenceUnavailable(
                "no cadence bounds defined for that key; refusing to invent one")
    try:
        value = _coerce(str(raw).strip(), spec)
    except (TypeError, ValueError):
        log.warning("bounded %s: %r is not a valid number; using default %s%s",
                    spec.key, raw, spec.default, spec.unit)
        return spec.default
    if value < spec.minimum or value > spec.maximum:
        log.warning(
            "bounded %s: %s%s is outside [%s, %s] and was REFUSED; using default "
            "%s%s. A value outside these bounds disables coverage while the "
            "detector still reports as enabled (%s)",
            spec.key, value, spec.unit, spec.minimum, spec.maximum,
            spec.default, spec.unit, spec.rationale or "no rationale recorded")
        return spec.default
    return value


# ─────────────────────────────────────────────────────────────────────────────
# Canary self-test — runs at import, in the production path.
#
# Reference shape: `scripts/nemesis-fw-neverblock`'s CANARIES. A validator that
# accepted everything would pass every "is accepted" assertion a suite could
# write, so this proves on every import that it distinguishes cases at all — and
# specifically that the CEILING refuses, which is the whole reason this exists.
# ─────────────────────────────────────────────────────────────────────────────

def _selftest_cadence() -> None:
    # The self-test deliberately feeds resolve() out-of-range and unparseable
    # values, each of which logs at WARNING by design. Left unsuppressed that
    # puts six spurious warnings in the journal on EVERY service start, and a
    # warning that always fires is one nobody reads — which would degrade the
    # real one this module exists to emit. Suppressed only for the duration of
    # the self-test, and restored in `finally` so an assertion failure cannot
    # leave the logger muted.
    _prev_level, _prev_prop = log.level, log.propagate
    log.setLevel(logging.CRITICAL)
    log.propagate = False
    try:
        _run_cadence_cases()
    finally:
        log.setLevel(_prev_level)
        log.propagate = _prev_prop


def _run_cadence_cases() -> None:
    spec = CANARY_POLL_SECONDS

    # ---- known-good: the shipped default must be accepted -------------------
    ok, err = validate(spec.default, spec)
    if not ok:
        raise AssertionError(
            "cadence canary: the shipped default %r was rejected (%s)"
            % (spec.default, err))

    # ---- known-bad: the exact live finding must be refused -------------------
    ok, _ = validate(999999999, spec)
    if ok:
        raise AssertionError(
            "cadence canary: 999999999 was ACCEPTED — the ceiling is not "
            "enforced, which is the exact defect this module exists to close")

    # ---- the floor must still refuse (it worked before; keep it working) ----
    ok, _ = validate(1, spec)
    if ok:
        raise AssertionError("cadence canary: a below-floor value was accepted")

    # ---- boundaries are INCLUSIVE, both ends -------------------------------
    for edge in (spec.minimum, spec.maximum):
        ok, err = validate(edge, spec)
        if not ok:
            raise AssertionError(
                "cadence canary: boundary %r rejected (%s); bounds must be "
                "inclusive or the documented range is a lie" % (edge, err))
    for outside in (spec.minimum - 1, spec.maximum + 1):
        ok, _ = validate(outside, spec)
        if ok:
            raise AssertionError(
                "cadence canary: %r is outside the bounds and was accepted"
                % outside)

    # ---- resolve() falls back to DEFAULT, never the nearest bound -----------
    got = resolve(999999999, spec)
    if got == spec.maximum:
        raise AssertionError(
            "cadence canary: resolve() clamped to the ceiling (%s) instead of "
            "falling back to the default (%s). Clamping presents a deliberate "
            "park attempt as a healthy configuration" % (spec.maximum, spec.default))
    if got != spec.default:
        raise AssertionError(
            "cadence canary: resolve() returned %r for an out-of-range value; "
            "expected the default %r" % (got, spec.default))

    # ---- resolve() passes a legitimate value THROUGH unchanged -------------
    # Without this the module could satisfy every assertion above by simply
    # always returning the default — a one-answer instrument.
    legit = spec.minimum + 1
    if resolve(legit, spec) != legit:
        raise AssertionError(
            "cadence canary: resolve() did not pass a valid value through "
            "unchanged — it may be returning the default unconditionally")

    # ---- garbage and empties resolve to the default, not to zero -----------
    for junk in (None, "", "  ", "banana", "30s"):
        if resolve(junk, spec) != spec.default:
            raise AssertionError(
                "cadence canary: %r did not resolve to the default" % (junk,))

    # ---- EVERY registered spec, not just the one above ----------------------
    # Written this way deliberately: the original self-test exercised only
    # CANARY_POLL_SECONDS, so six specs added later would have inherited its
    # green tick without ever being checked.
    for key, s in SPECS.items():
        if not (s.minimum <= s.default <= s.maximum):
            raise AssertionError(
                "bounded canary: spec %r has a default outside its own bounds" % key)
        if not s.rationale:
            raise AssertionError(
                "bounded canary: spec %r has no rationale; a bound whose reason "
                "cannot be stated will not survive its first inconvenience" % key)
        # its own default must validate, or the product ships unconfigurable
        ok, err = validate(s.default, s)
        if not ok:
            raise AssertionError(
                "bounded canary: spec %r rejects its own default %r (%s)"
                % (key, s.default, err))
        # and a value one step past the ceiling must be refused
        past = s.maximum + (0.01 if s.kind is float else 1)
        ok, _ = validate(past, s)
        if ok:
            raise AssertionError(
                "bounded canary: spec %r accepted %r, past its own ceiling %r"
                % (key, past, s.maximum))
        # a legitimate value must survive resolve() unchanged
        mid = s.minimum + (s.maximum - s.minimum) / 2
        mid = float(mid) if s.kind is float else int(mid)
        if resolve(mid, s) != mid:
            raise AssertionError(
                "bounded canary: spec %r altered a legitimate value %r" % (key, mid))

    # ---- the entropy ceiling must sit below the theoretical maximum ---------
    # This one is arithmetic, not judgment: max Shannon entropy over 256 symbols
    # is exactly 8.0 bits/byte, and `entropy >= threshold` can never be true above
    # it. A ceiling at or above 8.0 would silently permit a dead detector.
    if ENTROPY_THRESHOLD.maximum >= 8.0:
        raise AssertionError(
            "bounded canary: entropy_threshold ceiling %r is at or above the "
            "theoretical maximum entropy of 8.0 bits/byte, so a value inside the "
            "allowed range can still make entropy detection permanently dead"
            % ENTROPY_THRESHOLD.maximum)

    # ---- a float spec must not be silently truncated ------------------------
    if resolve("7.2", ENTROPY_THRESHOLD) != 7.2:
        raise AssertionError(
            "bounded canary: a float setting was truncated by resolve()")
    ok, _ = validate("7.2", AUTO_AI_MIN_SCORE)
    if ok:
        raise AssertionError(
            "bounded canary: an int spec accepted '7.2'; truncating it would "
            "store a different number than the operator typed")


_selftest_cadence()
