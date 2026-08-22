"""Heuristic triage before the model — the pre-filter.

WHY THIS EXISTS
---------------
Measured live (2026-08-21, re-verified 2026-08-22): the telemetry surfaces produce
~1,630 items/day against ~13/day of genuinely distinct events — a **125:1** ratio.
Fed naively to a model for a 7-day trial that is ~11,400 calls ≈ **$20.50**, which
breaches the $10 spend ceiling partway through the week. With this ladder the same
week costs ~$0.50–$2.00. The pre-filter is therefore a prerequisite for the trial
being possible at all, not an optimisation of one that already works.

WHAT THIS GATES — AND WHAT IT CATEGORICALLY DOES NOT
----------------------------------------------------
This module decides **whether an item is worth spending a model call on.** That is
the entire scope of its authority.

It does NOT — and structurally CANNOT — decide:
  * whether an event is DETECTED
  * whether an event is RECORDED to the database
  * whether an event is shown to a human
  * whether an alert or notification is delivered

Those are coverage. Coverage is not a thing any filter, credential, override or
master password may switch off (see the constraint restated in `docs/` and
`module.py`'s authority header). The only thing that stops coverage is the service
itself stopping. This is enforced here rather than merely documented: a `Verdict`
has no field capable of expressing "do not record", and `apply()` returns only
`forward` / `defer` — never a suppression instruction. A caller that wanted to use
this module to silence monitoring would have to invent a new return value to do it.

Concretely: an item this ladder DROPS is still detected, still written to its table,
still counted, still visible on the dashboard, and still eligible to raise an alert
by the ordinary (non-AI) path. What it loses is an *AI narrative about itself*.

THE THREE RULES THIS LADDER OBEYS
---------------------------------
1. **Unknown escalates; it never drops.** An unrecognised severity, an unparseable
   timestamp, a missing family key → forward to the model. Dropping on unknown is
   the "default value that means something" shape, and it fails in the worst
   possible direction: silently, on exactly the novel input the system exists for.
2. **Shadow mode first, and it is not optional.** In `shadow` the ladder computes
   and logs every verdict but drops nothing, so the record of what it *would* have
   discarded exists before it is trusted to discard anything. Rule 1 (audit-first)
   applied to a component whose whole job is deciding what you never get to see.
3. **Sampling, not blackout, under budget pressure.** Stage 7 degrades to 1-in-N so
   the log keeps a representative trace. A blackout is indistinguishable from
   "nothing happened", which would defeat the activity log this feeds.

Pure functions only — every DB read arrives through an injected `Context`, so the
whole ladder is unit-testable with no database and no network.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timedelta

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Vocabulary
# ─────────────────────────────────────────────────────────────────────────────

#: Ordered severity ladder. Anything NOT in this map is UNKNOWN, and unknown
#: forwards (rule 1) rather than comparing as some arbitrary integer.
#:
#: Sourced from the live DB 2026-08-22: `error_codes.severity` yields
#: CRITICAL/HIGH/MEDIUM/LOW/INFO and `alerts.risk_level` yields
#: CRITICAL/MEDIUM/LOW/INFO/UNKNOWN. Note that 'UNKNOWN' is a REAL STORED VALUE in
#: production, not a hypothetical — which is precisely why rule 1 is load-bearing
#: here and not defensive padding.
SEVERITY_ORDER = {
    "INFO":     0,
    "LOW":      1,
    "MEDIUM":   2,
    "HIGH":     3,
    "CRITICAL": 4,
}

#: Verdicts. `FORWARD` spends a model call; `DROP` does not. There is deliberately
#: no third value meaning "suppress" — see the module docstring.
FORWARD = "forward"
DROP    = "drop"

#: Mode values for the `prefilter_mode` setting.
MODE_SHADOW  = "shadow"     # compute + log, drop nothing
MODE_ENFORCE = "enforce"    # act on the verdict
MODE_AUTO    = "auto"       # shadow for the first N trial days, then enforce


class PrefilterUnavailable(Exception):
    """Raised when the ladder cannot run at all (e.g. a Context is malformed).

    An exception rather than a returned verdict, on purpose: both verdicts are
    legal answers, so returning one here would be indistinguishable from a real
    measurement. The caller's correct response is to FORWARD (spend the call) —
    never to drop — but that decision belongs to the caller, explicitly.
    """


class Verdict:
    """The outcome of one pass down the ladder.

    Attributes intentionally limited to what a spend decision needs. There is no
    field that can express "do not record this event" — the type itself is the
    enforcement of the coverage constraint stated in the module docstring.
    """

    __slots__ = ("decision", "stage", "reason_code", "detail", "enforced",
                 "would_have", "mode")

    def __init__(self, decision, stage, reason_code, detail="",
                 enforced=True, would_have=None, mode=MODE_ENFORCE):
        self.decision    = decision      # what the ladder concluded
        self.stage       = stage         # which rung concluded it
        self.reason_code = reason_code   # stable machine-readable reason
        self.detail      = detail        # human-readable, may name the family
        self.enforced    = enforced      # False when shadow mode neutered it
        self.would_have  = would_have    # in shadow: the decision NOT acted on
        self.mode        = mode

    @property
    def spends(self) -> bool:
        """True when this item should be sent to the model."""
        return self.decision == FORWARD

    def as_log_kwargs(self) -> dict:
        """Shaped for `module.log_decision(stage=..., decision=..., ...)`."""
        return {
            "stage":         "prefilter",
            "decision":      self.decision,
            "reason_code":   self.reason_code,
            "reason_detail": (
                "%s [rung %s, mode=%s%s]"
                % (self.detail, self.stage, self.mode,
                   "" if self.enforced
                   else ", SHADOW: would have %s" % (self.would_have or "?"))
            ),
        }

    def __repr__(self):
        return ("<Verdict %s stage=%s reason=%s enforced=%s>"
                % (self.decision, self.stage, self.reason_code, self.enforced))


# ─────────────────────────────────────────────────────────────────────────────
# family_key — the load-bearing normalisation
# ─────────────────────────────────────────────────────────────────────────────

_FAMILY_DIGITS = re.compile(r"[\d.]+")


def family_key(title):
    """Collapse a title to its family, or None when it has no usable family.

    This is the same digits-normalised form that produced the measured 65%
    repeat rate (re-verified against live `tickets` 2026-08-22: 72 tickets → 25
    families, 47 repeats, the largest being 28 CPU-temperature tickets). It is an
    explicit named function rather than an inline regex because it is now a
    load-bearing input to a SPEND decision, and load-bearing inputs get tested.

    **Returns None for an empty/whitespace/missing title — deliberately.**
    Live data check 2026-08-22 found FOUR tickets with empty titles. Normalising
    those the obvious way yields the key `""`, which collides every one of them
    into a single bogus "family" — so the second and subsequent unrelated
    untitled events would be deduped away as repeats of the first. None means
    "no family could be determined", and per rule 1 the caller must then FORWARD
    rather than dedup. A filter is not entitled to invent the grouping it filters
    on.
    """
    if title is None:
        return None
    text = str(title).strip()
    if not text:
        return None
    return _FAMILY_DIGITS.sub("N", text)


def severity_rank(severity):
    """Integer rank, or None when the severity is not recognised.

    None (not -1, not 0) because every integer is a legal rank and would be
    indistinguishable from a real measurement. `UNKNOWN` is a real stored value
    in `alerts.risk_level`, so this path executes in production.
    """
    if severity is None:
        return None
    return SEVERITY_ORDER.get(str(severity).strip().upper())


def cache_key_for(surface, subject_key, question=""):
    """Stable key for the stage-6 response cache."""
    raw = "|".join((str(surface), str(subject_key), str(question or "")))
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Context — every external read the ladder needs, injected
# ─────────────────────────────────────────────────────────────────────────────

class Context:
    """The reads the ladder performs, supplied by the caller.

    Injected rather than imported so the ladder is testable with no DB. Every
    callable here must either return a real answer or RAISE — none of them may
    return a default that means something (a `False` from `surface_enabled` that
    actually meant "the settings read failed" would silently disable a whole
    surface's analysis).
    """

    def __init__(self, surface_enabled, severity_floor, family_last_seen,
                 family_cooldown_s, known_cause, standing_rule_blocks,
                 times_seen, cache_hit, budget_pressure, sample_rate,
                 now=None):
        self.surface_enabled      = surface_enabled       # (surface) -> bool
        self.severity_floor       = severity_floor        # (surface) -> str|None
        self.family_last_seen     = family_last_seen      # (surface, fam) -> datetime|None
        self.family_cooldown_s    = family_cooldown_s     # (surface) -> int
        self.known_cause          = known_cause           # (code, cls) -> dict|None
        self.standing_rule_blocks = standing_rule_blocks  # (subject) -> str|None
        self.times_seen           = times_seen            # (surface, key) -> int|None
        self.cache_hit            = cache_hit             # (cache_key) -> bool
        self.budget_pressure      = budget_pressure       # () -> float 0.0..1.0
        self.sample_rate          = sample_rate           # () -> int (1-in-N)
        self._now                 = now                   # () -> datetime

    def now(self):
        return self._now() if self._now else datetime.now()


# ─────────────────────────────────────────────────────────────────────────────
# The ladder — stages in ascending cost, each able to terminate
#
# Every stage returns a Verdict to terminate, or None to fall through. No stage
# may drop silently: a DROP always carries the rung and a stable reason_code.
# ─────────────────────────────────────────────────────────────────────────────

def _stage0_surface(subject, ctx):
    """Is AI ANALYSIS enabled for this surface?

    NOTE THE SCOPE CAREFULLY. This toggle governs whether the *model is asked
    about* this surface. It does not, and must not, govern whether the surface is
    monitored, recorded, or alerted on — those continue regardless. See the
    module docstring: turning AI analysis off for a surface is a spend choice;
    turning monitoring off is a capability-lift nobody is permitted to make.
    """
    if not ctx.surface_enabled(subject["surface"]):
        return Verdict(DROP, 0, "surface_ai_analysis_off",
                       "AI analysis is off for surface %r (monitoring and "
                       "recording continue unaffected)" % subject["surface"])
    return None


def _stage1_severity(subject, ctx):
    """Below the configured severity floor?

    Unknown severity forwards (rule 1). This rung executes against a real
    `UNKNOWN` value present in production `alerts.risk_level`.
    """
    floor = ctx.severity_floor(subject["surface"])
    if floor is None:
        return None                                   # no floor configured
    floor_rank = severity_rank(floor)
    item_rank  = severity_rank(subject.get("severity"))
    if floor_rank is None:
        # The FLOOR itself is unrecognised — a misconfiguration. Forward; do not
        # silently treat an unparseable floor as "everything passes" OR as
        # "nothing passes", both of which are defaults that mean something.
        log.warning("prefilter: unrecognised severity floor %r for surface %r; "
                    "forwarding", floor, subject["surface"])
        return None
    if item_rank is None:
        return None                                   # rule 1: unknown escalates
    if item_rank < floor_rank:
        return Verdict(DROP, 1, "below_severity_floor",
                       "severity %s is below floor %s"
                       % (subject.get("severity"), floor))
    return None


def _stage2_family(subject, ctx):
    """Same family seen inside the cooldown window?

    Where the measured 65% lives. A subject with NO determinable family key
    forwards — see `family_key`'s docstring for why inventing one is worse than
    spending the call.
    """
    fam = family_key(subject.get("title"))
    if fam is None:
        return None                                   # rule 1: no family, no dedup
    last = ctx.family_last_seen(subject["surface"], fam)
    if last is None:
        return None                                   # first of its family
    cooldown = ctx.family_cooldown_s(subject["surface"])
    if cooldown is None or cooldown <= 0:
        return None                                   # cooldown disabled
    if ctx.now() - last < timedelta(seconds=cooldown):
        return Verdict(DROP, 2, "family_cooldown",
                       "family %r seen %s ago, inside %ss cooldown"
                       % (fam[:60], ctx.now() - last, cooldown))
    return None


def _stage3_known_cause(subject, ctx):
    """A confirmed cause in `error_ledger_causes` already explains this.

    The cheapest possible short-circuit and the join to the diagnostic catalog
    via `check_ref`. Only a CONFIRMED cause terminates: a suspected one is
    exactly the case where a model call still earns its keep.
    """
    code = subject.get("error_code")
    cls  = subject.get("error_class")
    if not code and not cls:
        return None
    cause = ctx.known_cause(code, cls)
    if not cause:
        return None
    if str(cause.get("status", "")).strip().lower() != "confirmed":
        return None
    return Verdict(DROP, 3, "known_cause",
                   "confirmed cause %r (check_ref=%s)"
                   % (str(cause.get("cause_description", ""))[:60],
                      cause.get("check_ref") or "none"))


def _stage4_standing_rule(subject, ctx):
    """The user has already ruled on this.

    Note this rung consults rules that say "do not analyse this"; it does NOT
    consult the authority ladder, which governs whether the engine may ACT. The
    two are separate and must stay so.
    """
    rule = ctx.standing_rule_blocks(subject)
    if rule:
        return Verdict(DROP, 4, "standing_rule",
                       "user standing rule: %s" % str(rule)[:80])
    return None


def _stage5_novelty(subject, ctx):
    """An unchanged repeat of an already-analysed subject.

    `times_seen` returning None means the recurrence state could not be read —
    which forwards, because "I could not tell whether this is new" is not
    evidence that it is old.
    """
    seen = ctx.times_seen(subject["surface"], subject["subject_key"])
    if seen is None:
        return None                                   # rule 1
    if seen > 1 and not subject.get("changed_since_last"):
        return Verdict(DROP, 5, "unchanged_repeat",
                       "subject seen %d times with no change since last analysis"
                       % seen)
    return None


def _stage6_cache(subject, ctx):
    """A semantically identical question has already been answered."""
    key = cache_key_for(subject["surface"], subject["subject_key"],
                        subject.get("question", ""))
    if ctx.cache_hit(key):
        return Verdict(DROP, 6, "cache_hit", "cached answer available")
    return None


def _stage7_budget(subject, ctx):
    """Budget pressure — SAMPLE, never black out (rule 3).

    Above the pressure threshold this drops (1 - 1/N) of items, keeping a
    representative 1-in-N trace so the decision log stays continuous. Going fully
    dark here would make "budget exhausted" indistinguishable from "nothing
    happened".
    """
    pressure = ctx.budget_pressure()
    if pressure is None or pressure < 0.9:
        return None
    n = max(2, int(ctx.sample_rate() or 10))
    # Deterministic sampling off the subject key: reproducible from the log, and
    # it cannot be gamed into always-drop by retry timing the way random() can.
    h = int(hashlib.sha256(str(subject["subject_key"]).encode()).hexdigest()[:8], 16)
    if h % n != 0:
        return Verdict(DROP, 7, "budget_sampled",
                       "budget pressure %.2f, sampling 1-in-%d" % (pressure, n))
    return None


#: The ladder, in ascending cost. Order is load-bearing and tested.
LADDER = (
    _stage0_surface,
    _stage1_severity,
    _stage2_family,
    _stage3_known_cause,
    _stage4_standing_rule,
    _stage5_novelty,
    _stage6_cache,
    _stage7_budget,
)


def evaluate(subject, ctx) -> Verdict:
    """Run the ladder. Returns the terminating Verdict, or FORWARD if none fires.

    Raises PrefilterUnavailable if the subject is malformed — never a verdict,
    because both verdicts are legal answers and a caller could not tell a real
    one from a failure.
    """
    for required in ("surface", "subject_key"):
        if required not in subject:
            raise PrefilterUnavailable(
                "subject missing required field %r; refusing to guess a verdict"
                % required)
    for stage in LADDER:
        try:
            verdict = stage(subject, ctx)
        except PrefilterUnavailable:
            raise
        except Exception as exc:                                # noqa: BLE001
            # A rung that BROKE must not be read as a rung that PASSED. Forward
            # loudly: the expensive-but-safe direction, and it leaves a record.
            log.exception("prefilter: rung %s raised; forwarding", stage.__name__)
            return Verdict(FORWARD, stage.__name__, "rung_error",
                           "rung %s raised %s" % (stage.__name__, type(exc).__name__))
        if verdict is not None:
            return verdict
    return Verdict(FORWARD, None, "no_rung_matched",
                   "nothing in the ladder terminated this item")


# ─────────────────────────────────────────────────────────────────────────────
# Shadow mode and the trial clock
# ─────────────────────────────────────────────────────────────────────────────

#: Ratified 2026-08-22: a 7-day trial runs 3 days in shadow, then 4 enforcing —
#: so the week yields BOTH a measurement of what the filter would have dropped
#: and a measurement of the filter actually working.
DEFAULT_SHADOW_DAYS = 3


def resolve_mode(mode_setting, trial_started_at, shadow_days=DEFAULT_SHADOW_DAYS,
                 now=None) -> tuple:
    """Resolve the effective mode. Returns (mode, reason).

    `auto` means "shadow for the first `shadow_days` of the trial, enforcing
    after". Every failure path resolves to SHADOW, and says why:

      * no trial start recorded
      * an unparseable trial start
      * an unrecognised mode string

    Shadow is the safe direction here specifically because shadow DROPS NOTHING.
    A filter that fails into enforcing would start discarding items on the
    strength of a state it could not read — and the items it discards are, by
    construction, the ones nobody ever sees. Cost is not the thing being
    protected by this choice; the separate spend ceiling already bounds cost, and
    it fails closed on its own.

    The reason string is returned rather than logged-and-swallowed so the caller
    can put it in the decision log: "shadow because the trial start is unset" and
    "shadow because we are on day 2" must not look identical downstream.
    """
    mode = (mode_setting or "").strip().lower()
    if mode == MODE_SHADOW:
        return MODE_SHADOW, "configured shadow"
    if mode == MODE_ENFORCE:
        return MODE_ENFORCE, "configured enforce"
    if mode != MODE_AUTO:
        return MODE_SHADOW, ("unrecognised prefilter_mode %r; defaulting to "
                             "shadow (drops nothing)" % mode_setting)

    if not trial_started_at:
        return MODE_SHADOW, "auto: no trial start recorded, staying in shadow"
    try:
        started = datetime.fromisoformat(str(trial_started_at))
    except (TypeError, ValueError):
        return MODE_SHADOW, ("auto: trial start %r is unparseable, staying in "
                             "shadow" % trial_started_at)
    current = now() if callable(now) else (now or datetime.now())
    elapsed = (current - started).total_seconds() / 86400.0
    if elapsed < 0:
        return MODE_SHADOW, ("auto: trial start is in the future (%.1f days), "
                             "staying in shadow" % elapsed)
    if elapsed < shadow_days:
        return MODE_SHADOW, ("auto: day %.1f of a %d-day shadow window"
                             % (elapsed, shadow_days))
    return MODE_ENFORCE, ("auto: day %.1f is past the %d-day shadow window"
                          % (elapsed, shadow_days))


def apply(subject, ctx, mode_setting=None, trial_started_at=None,
          shadow_days=DEFAULT_SHADOW_DAYS, now=None) -> Verdict:
    """Evaluate the ladder and apply shadow-mode semantics.

    In shadow the verdict is computed and preserved in `would_have`, but the
    returned decision is always FORWARD — the filter observes without acting,
    which is the whole point of the shadow window.

    Returns only FORWARD or DROP, where DROP means "do not spend a model call on
    this". Neither value instructs any caller to stop recording, alerting, or
    displaying anything; see the module docstring.
    """
    mode, reason = resolve_mode(mode_setting, trial_started_at, shadow_days, now)
    verdict = evaluate(subject, ctx)
    verdict.mode = mode
    if mode == MODE_ENFORCE:
        verdict.enforced = True
        return verdict
    # Shadow: preserve what it WOULD have done, then forward regardless.
    shadowed = Verdict(FORWARD, verdict.stage, verdict.reason_code,
                       "%s (%s)" % (verdict.detail, reason),
                       enforced=False, would_have=verdict.decision, mode=mode)
    return shadowed


# ─────────────────────────────────────────────────────────────────────────────
# Canary self-test — runs at import, in the production path
#
# The reference shape is `scripts/nemesis-fw-neverblock`'s CANARIES. A filter
# that could only ever return one answer would pass every "is filtered" assertion
# a test suite could write; this proves, on every import, that the ladder
# distinguishes cases at all, that shadow really neuters a drop, and that the
# three rule-1 unknowns forward rather than drop.
# ─────────────────────────────────────────────────────────────────────────────

def _canary_context(**overrides):
    base = dict(
        surface_enabled      = lambda s: True,
        severity_floor       = lambda s: "MEDIUM",
        family_last_seen     = lambda s, f: None,
        family_cooldown_s    = lambda s: 1800,
        known_cause          = lambda c, k: None,
        standing_rule_blocks = lambda subj: None,
        times_seen           = lambda s, k: 1,
        cache_hit            = lambda k: False,
        budget_pressure      = lambda: 0.0,
        sample_rate          = lambda: 10,
        now                  = lambda: datetime(2026, 8, 22, 12, 0, 0),
    )
    base.update(overrides)
    return Context(**base)


def _selftest_ladder() -> None:
    def subj(**kw):
        d = {"surface": "alerts", "subject_key": "alert-1",
             "severity": "CRITICAL", "title": "Auto: CPU temperature 91C exceeds 85C"}
        d.update(kw)
        return d

    # ---- MUST FORWARD (the known-good control) -----------------------------
    v = evaluate(subj(), _canary_context())
    if v.decision != FORWARD:
        raise AssertionError(
            "prefilter canary: a critical, novel, uncached item was not forwarded "
            "(got %r at rung %s)" % (v.decision, v.stage))

    # ---- MUST DROP (the known-bad control) ---------------------------------
    v = evaluate(subj(severity="INFO"), _canary_context())
    if v.decision != DROP or v.stage != 1:
        raise AssertionError(
            "prefilter canary: an INFO item under a MEDIUM floor was not dropped "
            "at rung 1 (got %r at rung %s)" % (v.decision, v.stage))

    # ---- rule 1: each unknown must FORWARD, not drop -----------------------
    unknowns = (
        ("unrecognised severity",
         subj(severity="BANANA"), _canary_context()),
        ("empty title (no family key)",
         subj(title="   "), _canary_context(
             family_last_seen=lambda s, f: datetime(2026, 8, 22, 11, 59, 0))),
        ("unreadable recurrence state",
         subj(), _canary_context(times_seen=lambda s, k: None)),
    )
    for what, s, c in unknowns:
        v = evaluate(s, c)
        if v.decision != FORWARD:
            raise AssertionError(
                "prefilter canary: %s must FORWARD (rule 1: unknown escalates), "
                "got %r at rung %s" % (what, v.decision, v.stage))

    # ---- shadow must neuter a real drop ------------------------------------
    v = apply(subj(severity="INFO"), _canary_context(), mode_setting=MODE_SHADOW)
    if v.decision != FORWARD or v.would_have != DROP or v.enforced:
        raise AssertionError(
            "prefilter canary: shadow mode failed to neuter a drop (decision=%r, "
            "would_have=%r, enforced=%r)" % (v.decision, v.would_have, v.enforced))

    # ---- enforce must NOT neuter it ----------------------------------------
    v = apply(subj(severity="INFO"), _canary_context(), mode_setting=MODE_ENFORCE)
    if v.decision != DROP or not v.enforced:
        raise AssertionError(
            "prefilter canary: enforce mode failed to act on a drop (decision=%r, "
            "enforced=%r)" % (v.decision, v.enforced))

    # ---- every mode-resolution failure path must land in SHADOW ------------
    for bad in (None, "", "banana", "ENFORCE_LATER"):
        m, _ = resolve_mode(bad, None)
        if m != MODE_SHADOW:
            raise AssertionError(
                "prefilter canary: mode_setting %r resolved to %r, must be shadow"
                % (bad, m))
    m, _ = resolve_mode(MODE_AUTO, "not-a-date")
    if m != MODE_SHADOW:
        raise AssertionError(
            "prefilter canary: an unparseable trial start must resolve to shadow")


_selftest_ladder()
