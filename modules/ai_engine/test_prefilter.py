#!/usr/bin/env python3
"""The pre-filter ladder -- what never reaches the model, and what always does.

Run: python3 modules/ai_engine/test_prefilter.py   (exit 0 = all pass)

WHY THIS COMPONENT NEEDS UNUSUALLY HARD TESTING. Every other component in this
codebase can be checked by looking at what it produced. The pre-filter's output is
an ABSENCE: the items it drops are, by construction, the ones nobody ever sees
again. A filter that silently over-drops looks exactly like a quiet week. So the
tests here are built around CONTROLS -- for every "this is dropped" assertion
there is a paired "this is NOT dropped" assertion, because a ladder that dropped
everything would otherwise satisfy every drop assertion a suite could write.

SCOPE BOUNDARY UNDER TEST (ratified 2026-08-22). The pre-filter gates AI SPEND
only. It cannot suppress detection, recording, display or alerting -- and that is
enforced by the type, not by documentation: `Verdict` has no field capable of
expressing "do not record". The final section asserts that property directly, so
that adding such a field later fails a test rather than quietly widening what a
filter is allowed to do.

NO DB, NO NETWORK, NO MODEL. Every read is injected through `Context`.
"""
import importlib.util
import os
import sys
import tempfile
from datetime import datetime, timedelta

_HERE = os.path.dirname(os.path.abspath(__file__))

# Loaded by path, NOT as `modules.ai_engine.prefilter`: the package __init__
# imports module.py, which reaches the DB at import time and would fail here.
# That the ladder can be loaded alone is itself the design property -- pure
# functions, no I/O -- so this import doubles as a check on it.
_spec = importlib.util.spec_from_file_location(
    "prefilter", os.path.join(_HERE, "prefilter.py"))
pf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pf)

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


NOW = datetime(2026, 8, 22, 12, 0, 0)


def ctx(**overrides):
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
        now                  = lambda: NOW,
    )
    base.update(overrides)
    return pf.Context(**base)


def subj(**kw):
    d = {"surface": "alerts", "subject_key": "alert-1", "severity": "CRITICAL",
         "title": "Auto: CPU temperature 91C exceeds 85C"}
    d.update(kw)
    return d


print("\n-- the module loads standalone (it must have no DB dependency) --")
check("prefilter imported with no DB and no network", pf is not None)
check("its import-time canary ran", hasattr(pf, "_selftest_ladder"))

print("\n-- family_key: the normalisation a spend decision now rests on --")
check("digits collapse to N",
      pf.family_key("Auto: CPU temperature 91C exceeds 85C")
      == "Auto: CPU temperature NC exceeds NC")
check("the 28 real CPU-temp tickets share one family",
      pf.family_key("Auto: CPU temperature 91C exceeds 85C")
      == pf.family_key("Auto: CPU temperature 79C exceeds 85C"))
check("CONTROL: genuinely different titles do NOT share a family",
      pf.family_key("Auto: CPU temperature 91C exceeds 85C")
      != pf.family_key("Auto: GPU temperature 91C exceeds 85C"))
# Live data, 2026-08-22: four tickets have empty titles. Normalising them the
# obvious way yields the key "", colliding every unrelated untitled event into a
# single bogus family -- so the 2nd onward would be deduped away as repeats.
for empty in (None, "", "   ", "\n\t "):
    check("empty title %r yields NO family (cannot dedup)" % (empty,),
          pf.family_key(empty) is None)

print("\n-- severity_rank: unknown is None, never an integer --")
check("CRITICAL outranks INFO",
      pf.severity_rank("CRITICAL") > pf.severity_rank("INFO"))
check("case and whitespace tolerated", pf.severity_rank(" critical ") == 4)
for unknown in ("UNKNOWN", "BANANA", None, ""):
    check("severity_rank(%r) is None, not a number" % (unknown,),
          pf.severity_rank(unknown) is None)

print("\n-- rung 1: severity floor, with its control --")
v = pf.evaluate(subj(severity="INFO"), ctx())
check("INFO under a MEDIUM floor is dropped at rung 1",
      v.decision == pf.DROP and v.stage == 1, v)
v = pf.evaluate(subj(severity="CRITICAL"), ctx())
check("CONTROL: CRITICAL is forwarded", v.decision == pf.FORWARD, v)
v = pf.evaluate(subj(severity="MEDIUM"), ctx())
check("CONTROL: exactly AT the floor is forwarded", v.decision == pf.FORWARD, v)

print("\n-- rung 2: family cooldown, where the measured 65% lives --")
recent = ctx(family_last_seen=lambda s, f: NOW - timedelta(seconds=60))
v = pf.evaluate(subj(), recent)
check("a repeat inside the cooldown is dropped at rung 2",
      v.decision == pf.DROP and v.stage == 2, v)
old = ctx(family_last_seen=lambda s, f: NOW - timedelta(seconds=3600))
v = pf.evaluate(subj(), old)
check("CONTROL: the same family OUTSIDE the cooldown is forwarded",
      v.decision == pf.FORWARD, v)
v = pf.evaluate(subj(), ctx(family_last_seen=lambda s, f: NOW,
                           family_cooldown_s=lambda s: 0))
check("CONTROL: a zero cooldown disables the rung rather than dropping",
      v.decision == pf.FORWARD, v)

print("\n-- rung 3: only a CONFIRMED cause short-circuits --")
confirmed = ctx(known_cause=lambda c, k: {"status": "confirmed",
                                          "cause_description": "known fan curve",
                                          "check_ref": "hw_thermal"})
v = pf.evaluate(subj(error_code="E-HW-001"), confirmed)
check("a confirmed cause drops at rung 3",
      v.decision == pf.DROP and v.stage == 3, v)
check("the reason names the check_ref (the join to the tool catalog)",
      "hw_thermal" in v.detail, v.detail)
suspected = ctx(known_cause=lambda c, k: {"status": "suspected",
                                          "cause_description": "maybe dust"})
v = pf.evaluate(subj(error_code="E-HW-001"), suspected)
check("CONTROL: a SUSPECTED cause does not drop -- that is where a call earns "
      "its keep", v.decision == pf.FORWARD, v)

print("\n-- rung 7: budget pressure SAMPLES, it does not black out --")
# A blackout would make 'budget exhausted' indistinguishable from 'nothing
# happened', defeating the activity log this feeds.
squeezed = ctx(budget_pressure=lambda: 0.99, sample_rate=lambda: 10)
kept = sum(1 for i in range(200)
           if pf.evaluate(subj(subject_key="k-%d" % i), squeezed).decision == pf.FORWARD)
check("under pressure SOME items still get through (not a blackout)", kept > 0,
      "kept=%d" % kept)
check("under pressure MOST items are sampled out", kept < 60, "kept=%d" % kept)
relaxed = ctx(budget_pressure=lambda: 0.1)
kept_relaxed = sum(1 for i in range(50)
                   if pf.evaluate(subj(subject_key="k-%d" % i),
                                  relaxed).decision == pf.FORWARD)
check("CONTROL: with no pressure everything is forwarded", kept_relaxed == 50,
      "kept=%d" % kept_relaxed)

print("\n-- RULE 1: unknown escalates; it never drops --")
UNKNOWNS = [
    ("unrecognised severity", subj(severity="BANANA"), ctx()),
    ("severity UNKNOWN (a REAL stored value in alerts.risk_level)",
     subj(severity="UNKNOWN"), ctx()),
    ("an unrecognised FLOOR is a misconfiguration, not a licence to drop",
     subj(severity="LOW"), ctx(severity_floor=lambda s: "BANANA")),
    ("no family key, even with a hot cooldown", subj(title="  "),
     ctx(family_last_seen=lambda s, f: NOW)),
    ("unreadable recurrence state", subj(),
     ctx(times_seen=lambda s, k: None)),
]
for what, s, c in UNKNOWNS:
    v = pf.evaluate(s, c)
    check("forwards on unknown: %s" % what, v.decision == pf.FORWARD, v)

print("\n-- a rung that BREAKS must not read as a rung that PASSED --")
def boom(s, f):
    raise RuntimeError("simulated read failure")
v = pf.evaluate(subj(), ctx(family_last_seen=boom))
check("a raising rung forwards rather than dropping", v.decision == pf.FORWARD, v)
check("and it is recorded as an error, not as a clean pass",
      v.reason_code == "rung_error", v.reason_code)

print("\n-- a malformed subject raises; it never guesses a verdict --")
for bad in ({}, {"surface": "alerts"}, {"subject_key": "x"}):
    try:
        pf.evaluate(bad, ctx())
        check("malformed subject %r raises" % (bad,), False, "it returned a verdict")
    except pf.PrefilterUnavailable:
        check("malformed subject %r raises PrefilterUnavailable" % (bad,), True)

print("\n-- shadow vs enforce (ratified: 3 days shadow, 4 enforcing) --")
v = pf.apply(subj(severity="INFO"), ctx(), mode_setting=pf.MODE_SHADOW)
check("shadow forwards despite a real drop verdict", v.decision == pf.FORWARD, v)
check("shadow preserves what it WOULD have done", v.would_have == pf.DROP, v)
check("shadow marks itself unenforced", v.enforced is False, v)
check("the shadowed verdict keeps the rung that fired", v.stage == 1, v)
v = pf.apply(subj(severity="INFO"), ctx(), mode_setting=pf.MODE_ENFORCE)
check("CONTROL: enforce really drops", v.decision == pf.DROP and v.enforced, v)
v = pf.apply(subj(severity="CRITICAL"), ctx(), mode_setting=pf.MODE_ENFORCE)
check("CONTROL: enforce still forwards what the ladder keeps",
      v.decision == pf.FORWARD, v)

print("\n-- the trial clock --")
start = "2026-08-19T12:00:00"            # NOW is 2026-08-22 12:00 -> day 3.0
check("day 0 of the trial is shadow",
      pf.resolve_mode("auto", "2026-08-22T00:00:00", 3, lambda: NOW)[0]
      == pf.MODE_SHADOW)
check("day 2.9 is still shadow",
      pf.resolve_mode("auto", "2026-08-19T14:00:00", 3, lambda: NOW)[0]
      == pf.MODE_SHADOW)
check("day 3.0 flips to enforce",
      pf.resolve_mode("auto", start, 3, lambda: NOW)[0] == pf.MODE_ENFORCE)
check("day 6 (end of a 7-day trial) is enforcing",
      pf.resolve_mode("auto", "2026-08-16T12:00:00", 3, lambda: NOW)[0]
      == pf.MODE_ENFORCE)

print("\n-- EVERY mode-resolution failure lands in SHADOW (drops nothing) --")
# Shadow is the safe direction because it discards nothing. A filter that failed
# into enforcing would start discarding on the strength of state it could not
# read -- and what it discards is what nobody ever sees. Cost is not what this
# protects; the separate spend ceiling bounds cost and fails closed on its own.
FAILURES = [
    ("no mode configured", None, None),
    ("empty mode", "", None),
    ("unrecognised mode", "banana", None),
    ("auto with no trial start", "auto", None),
    ("auto with an unparseable trial start", "auto", "not-a-date"),
    ("auto with a trial start in the future", "auto", "2027-01-01T00:00:00"),
]
for what, mode, start_ in FAILURES:
    got, why = pf.resolve_mode(mode, start_, 3, lambda: NOW)
    check("shadow on: %s" % what, got == pf.MODE_SHADOW, why)
    check("  ...and it SAYS why (%s)" % what, bool(why and why.strip()), why)
# The reasons must be distinguishable downstream: "shadow because the trial start
# is unset" and "shadow because we are on day 2" must not look identical in the log.
r_unset = pf.resolve_mode("auto", None, 3, lambda: NOW)[1]
r_day2  = pf.resolve_mode("auto", "2026-08-21T12:00:00", 3, lambda: NOW)[1]
check("the two shadow reasons are distinguishable", r_unset != r_day2,
      "%r vs %r" % (r_unset, r_day2))

print("\n-- SCOPE: a Verdict cannot express 'stop monitoring' --")
# Ratified 2026-08-22: no filter, credential or override may disable coverage.
# Enforced by the type rather than by prose, so widening it fails a test.
v = pf.evaluate(subj(severity="INFO"), ctx())
check("Verdict declares __slots__ (no ad-hoc field can be attached)",
      hasattr(pf.Verdict, "__slots__"))
banned = {"suppress", "record", "silence", "notify", "detect", "alert",
          "coverage", "disable", "mute"}
overlap = banned & set(pf.Verdict.__slots__)
check("no Verdict field names a coverage concern", not overlap, overlap)
try:
    v.suppress_recording = True
    check("a coverage field cannot be bolted onto a Verdict", False,
          "the attribute was accepted")
except AttributeError:
    check("a coverage field cannot be bolted onto a Verdict", True)
check("the only decisions are forward/drop",
      {pf.FORWARD, pf.DROP} == {"forward", "drop"})
for s in (subj(), subj(severity="INFO"), subj(title="  ")):
    d = pf.evaluate(s, ctx()).decision
    check("decision %r is one of forward/drop" % d, d in (pf.FORWARD, pf.DROP))

print("\n-- MUTATION: the import-time canary must catch real defects --")
SRC = open(os.path.join(_HERE, "prefilter.py")).read()
MUTATIONS = [
    ("rule 1 broken: unknown severity now drops",
     "    if item_rank is None:\n        return None                                   # rule 1: unknown escalates",
     "    if item_rank is None:\n        return Verdict(DROP, 1, 'x', 'dropped')"),
    ("family_key stops guarding the empty title",
     '    if not text:\n        return None\n    return _FAMILY_DIGITS.sub("N", text)',
     '    return _FAMILY_DIGITS.sub("N", text)'),
    ("shadow mode stops neutering drops",
     "    if mode == MODE_ENFORCE:\n        verdict.enforced = True\n        return verdict",
     "    if True:\n        verdict.enforced = True\n        return verdict"),
    ("mode resolution fails into ENFORCE",
     '        return MODE_SHADOW, ("unrecognised prefilter_mode %r; defaulting to "\n                             "shadow (drops nothing)" % mode_setting)',
     '        return MODE_ENFORCE, "fails into enforce"'),
    ("the ladder drops everything",
     "    for stage in LADDER:",
     "    return Verdict(DROP, 99, 'x', 'drops all')\n    for stage in LADDER:"),
    ("unreadable recurrence state reads as 'old news'",
     "    if seen is None:\n        return None                                   # rule 1",
     "    if seen is None:\n        return Verdict(DROP, 5, 'x', 'treated as seen')"),
]
for label, old, new in MUTATIONS:
    if old not in SRC:
        check("MUTATION anchor present: %s" % label, False,
              "anchor not found -- this TEST is stale, not the code")
        continue
    path = tempfile.mktemp(suffix=".py")
    with open(path, "w") as fh:
        fh.write(SRC.replace(old, new, 1))
    caught = False
    try:
        s_ = importlib.util.spec_from_file_location("pf_mutant", path)
        m_ = importlib.util.module_from_spec(s_)
        s_.loader.exec_module(m_)
    except Exception:
        caught = True
    finally:
        os.unlink(path)
    check("canary catches: %s" % label, caught,
          "the mutated ladder imported cleanly -- the canary is not measuring")

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
