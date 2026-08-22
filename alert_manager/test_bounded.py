#!/usr/bin/env python3
"""Bounded monitoring cadence -- the ceiling that closes a coverage-disable.

Run: python3 alert_manager/test_bounded.py   (exit 0 = all pass)

WHAT THIS FILE PROTECTS. Until 2026-08-22 two monitoring cadences were validated
as `max(5, int(value))` -- a floor with no ceiling. That reads like validation and
is not: it refuses 5 seconds and accepts 999999999, which parks the detector for
31.69 years while the dashboard still reports it enabled and healthy. Both were
reachable by a single authenticated POST, and one of them
(`watcher_interval_seconds`) went through a settings endpoint that performed no
value validation of any kind.

THE PROPERTY UNDER TEST, in one line: an interval long enough to go dark is
refused the same way a hostile poll hint is refused in
`nemesis_agent/agent.py:319` -- so that the attack does not exist, rather than
merely being bounded.

WHY THE MUTATION SECTION IS NOT OPTIONAL. `bounded.py` carries an import-time
canary self-test, and a canary is itself an instrument that can be broken. The
final section re-runs the module with deliberately injected defects and asserts
the canary CATCHES each one. Without it, a canary that had silently degraded into
always-passing would look identical to a working one -- which is the exact failure
class (`docs`/CLAUDE.md "verification code must prove its own premise") that this
whole cadence change exists to close.

NO DB, NO NETWORK, NO FLASK. `bounded.py` is pure by design.
"""
import importlib.util
import logging
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bounded as cadence  # noqa: E402

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


SPEC = cadence.CANARY_POLL_SECONDS

print("\n-- the live finding, refused --")
ok, err = cadence.validate(999999999, SPEC)
check("999999999 is REFUSED by validate()", not ok, err)
check("the refusal names the bound", "300" in err, err)
check("the refusal states WHY the bound exists",
      "ransomware" in err.lower(), err)

print("\n-- CONTROL: it does not simply refuse everything --")
# Without these, every assertion above would also pass for a validator that
# rejected its own shipped defaults -- i.e. a module nobody could configure.
for spec in cadence.SPECS.values():
    ok, err = cadence.validate(spec.default, spec)
    check("%s: the shipped default %s is ACCEPTED" % (spec.key, spec.default),
          ok, err)

print("\n-- bounds are inclusive at both ends --")
for spec in cadence.SPECS.values():
    for edge in (spec.minimum, spec.maximum):
        ok, _ = cadence.validate(edge, spec)
        check("%s: boundary %s accepted" % (spec.key, edge), ok)
    for outside in (spec.minimum - 1, spec.maximum + 1):
        ok, _ = cadence.validate(outside, spec)
        check("%s: %s outside bounds refused" % (spec.key, outside), not ok)

print("\n-- resolve(): out-of-range falls back to the DEFAULT, not the bound --")
# The distinction matters operationally. Clamping 999999999 down to the 300s
# ceiling would store a plausible-looking number and present a deliberate park
# attempt as a healthy configuration; the operator would never learn their write
# was overruled.
logging.getLogger("bounded").setLevel(logging.CRITICAL)   # expected warnings
got = cadence.resolve(999999999, SPEC)
check("resolve(999999999) returns the default", got == SPEC.default, got)
check("resolve(999999999) did NOT clamp to the ceiling", got != SPEC.maximum, got)
got = cadence.resolve(0, SPEC)
check("resolve(0) returns the default", got == SPEC.default, got)
check("resolve(0) did NOT clamp to the floor", got != SPEC.minimum, got)

print("\n-- CONTROL: resolve() passes a legitimate value through unchanged --")
# Without this, resolve() could satisfy every check above by always returning the
# default -- a one-answer instrument.
legit = SPEC.minimum + 1
check("resolve(%d) returns %d unchanged" % (legit, legit),
      cadence.resolve(legit, SPEC) == legit)
legit2 = SPEC.maximum - 1
check("resolve(%d) returns %d unchanged" % (legit2, legit2),
      cadence.resolve(legit2, SPEC) == legit2)

print("\n-- unparseable input resolves to the default, never to zero --")
for junk in (None, "", "   ", "banana", "30s", "-1", "1e99"):
    check("resolve(%r) -> default" % (junk,),
          cadence.resolve(junk, SPEC) == SPEC.default)
    ok, _ = cadence.validate(junk, SPEC)
    check("validate(%r) refuses" % (junk,), not ok)

print("\n-- lookup by key, so a new cadence cannot inherit 'anything goes' --")
ok, _ = cadence.validate(999999999, "canary_poll_seconds")
check("validate() accepts a key string", not ok)
check("an unknown key is refused, not waved through",
      cadence.validate(1, "no_such_key")[0] is False)
try:
    cadence.resolve(1, "no_such_key")
    check("resolve() raises on an unknown key", False, "it returned a number")
except cadence.CadenceUnavailable:
    check("resolve() raises CadenceUnavailable on an unknown key", True)

print("\n-- every registered spec is self-consistent and defensible --")
for key, spec in cadence.SPECS.items():
    check("%s: default is inside its own bounds" % key,
          spec.minimum <= spec.default <= spec.maximum)
    check("%s: has a stated rationale" % key, bool(spec.rationale))
EXPECTED_SPECS = {
    # cadences
    "canary_poll_seconds", "watcher_interval_seconds",
    # non-cadence detector bounds (2026-08-22) — each one was a live
    # coverage-disable-by-value before it was bounded
    "entropy_threshold", "auto_ai_min_score", "full_scan_interval_hours",
    "full_scan_max_files", "full_scan_boot_delay_seconds",
    "canary_alert_cooldown_seconds",
    # integrity_watch's evaluation cadence, added when that module was wired up
    # (it had never run). Ceiling is DERIVED: half its 30-day comparison window,
    # so consecutive runs always overlap.
    "integrity_eval_interval_hours",
}
check("every known bounded setting is registered",
      set(cadence.SPECS) == EXPECTED_SPECS,
      "missing=%s unexpected=%s" % (sorted(EXPECTED_SPECS - set(cadence.SPECS)),
                                    sorted(set(cadence.SPECS) - EXPECTED_SPECS)))

print("\n-- the specific live findings, each refused --")
# Each of these was ACCEPTED by the real validator before this work. They are
# listed individually rather than as a loop over SPECS so that a spec quietly
# losing its ceiling fails a named check.
LIVE_FINDINGS = [
    ("canary_poll_seconds", 999999999, "parked the ransomware tripwire 31.69 years"),
    ("watcher_interval_seconds", 999999999, "parked the connectivity watcher 31.69 years"),
    ("entropy_threshold", 8.1, "above max possible entropy 8.0 -> detection dead"),
    ("entropy_threshold", 99, "same, absurd"),
    ("auto_ai_min_score", 101, "scores cap at 100 -> Layer C unreachable"),
    ("full_scan_interval_hours", 999999, "114 years between scans"),
    ("full_scan_max_files", 1, "a whole-filesystem scan that stops after one file"),
    ("full_scan_boot_delay_seconds", 999999999, "the scan never starts this boot"),
    ("canary_alert_cooldown_seconds", 999999999, "a real trip never reaches a human"),
]
for key, bad_value, why in LIVE_FINDINGS:
    ok, _ = cadence.validate(bad_value, cadence.SPECS[key])
    check("%s=%s refused (%s)" % (key, bad_value, why), not ok)

print("\n-- entropy: the ceiling is arithmetic, not taste --")
# Max Shannon entropy over a 256-symbol alphabet is exactly log2(256) = 8.0.
# A ceiling at or above that would leave a legal value that can never match.
import math  # noqa: E402
check("max byte entropy really is 8.0", math.log2(256) == 8.0)
check("the entropy ceiling sits strictly below 8.0",
      cadence.ENTROPY_THRESHOLD.maximum < 8.0, cadence.ENTROPY_THRESHOLD.maximum)
check("CONTROL: a realistic packed-binary threshold is still accepted",
      cadence.validate(7.5, cadence.ENTROPY_THRESHOLD)[0])

print("\n-- float specs are not silently truncated --")
check("resolve('7.2') keeps 7.2", cadence.resolve("7.2", cadence.ENTROPY_THRESHOLD) == 7.2)
check("validate('7.2') accepts it for a float spec",
      cadence.validate("7.2", cadence.ENTROPY_THRESHOLD)[0])
check("an INT spec refuses '7.2' rather than storing 7",
      not cadence.validate("7.2", cadence.AUTO_AI_MIN_SCORE)[0])

print("\n-- a self-inconsistent spec is refused at construction --")
try:
    cadence.CadenceSpec("bad", default=30, minimum=5, maximum=10)
    check("CadenceSpec rejects a default outside its bounds", False,
          "it was accepted")
except ValueError:
    check("CadenceSpec rejects a default outside its bounds", True)

print("\n-- the import-time canary stays quiet in the journal --")
# The self-test feeds resolve() bad values on purpose, each of which logs at
# WARNING. Unsuppressed that is six spurious warnings on EVERY service start, and
# a warning that always fires is one nobody reads.
_log = logging.getLogger("bounded")
check("the bounded logger is left at its original level after import",
      _log.level in (logging.NOTSET, logging.CRITICAL),
      "level=%s" % _log.level)
check("the bounded logger still propagates after import", _log.propagate)

print("\n-- MUTATION: the canary must CATCH each injected defect --")
SRC = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "bounded.py")).read()

MUTATIONS = [
    ("the ceiling is removed (regression to the live bug)",
     "    if value < spec.minimum or value > spec.maximum:\n"
     "        return False, spec.describe_bounds()",
     "    if value < spec.minimum:\n        return False, spec.describe_bounds()"),
    ("resolve() clamps to the nearest bound instead of the default",
     "    if value < spec.minimum or value > spec.maximum:\n        log.warning(",
     "    if value < spec.minimum or value > spec.maximum:\n"
     "        return max(spec.minimum, min(spec.maximum, value))\n"
     "    if False:\n        log.warning("),
    ("resolve() always returns the default (one-answer instrument)",
     "    try:\n        value = _coerce(str(raw).strip(), spec)",
     "    return spec.default\n    try:\n        value = _coerce(str(raw).strip(), spec)"),
    ("the entropy ceiling is raised to the theoretical maximum",
     '"entropy_threshold", default=7.2, minimum=6.0, maximum=7.99,',
     '"entropy_threshold", default=7.2, minimum=6.0, maximum=8.5,'),
    ("a float spec is silently truncated to int",
     "    if spec.kind is float:\n        return float(text)",
     "    if spec.kind is float:\n        return int(float(text))"),
    ("validate() accepts everything (the shape it replaced)",
     '    text = str(raw).strip()\n    if not text:',
     '    return True, ""\n    text = str(raw).strip()\n    if not text:'),
    ("bounds silently become exclusive",
     "    if value < spec.minimum or value > spec.maximum:\n"
     "        return False, spec.describe_bounds()",
     "    if value <= spec.minimum or value >= spec.maximum:\n"
     "        return False, spec.describe_bounds()"),
    ("a ceiling is lowered below its own default",
     '"canary_poll_seconds", default=30, minimum=5, maximum=300,',
     '"canary_poll_seconds", default=30, minimum=5, maximum=10,'),
    ("a bound loses the rationale that defends it",
     '    rationale="the poll interval IS the ransomware detection latency")',
     '    rationale="")'),
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
        spec_ = importlib.util.spec_from_file_location("cadence_mutant", path)
        mod = importlib.util.module_from_spec(spec_)
        spec_.loader.exec_module(mod)
    except (AssertionError, ValueError):
        caught = True
    except Exception:
        caught = True          # any refusal to import is a catch
    finally:
        os.unlink(path)
    check("canary catches: %s" % label, caught,
          "the mutated module imported cleanly -- the canary is not measuring")

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
