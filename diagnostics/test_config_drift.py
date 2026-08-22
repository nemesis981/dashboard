#!/usr/bin/env python3
"""The config_drift diagnostic — and proof its canary measures.

Run: python3 diagnostics/test_config_drift.py   (exit 0 = all pass)

WHAT THIS CHECK IS FOR. Anything that RESTATES a constant is a second source of
truth and desyncs by default. This repo has it on record twice: ARCHITECTURE.md
once documented an approval model that existed nowhere in the tree, and the
Settings page hardcodes a model name in prose while the engine calls whatever
`_ACTIVE_MODEL` says. Neither breaks anything; both make the product describe
itself incorrectly, which for a security tool is its own failure.

MOST OF THESE TESTS ARE ABOUT NOT REPORTING THINGS. The first run produced six
findings against one real one — four were entries in a model PRICING TABLE
(a table listing many models asserts nothing about which is active) and one was a
test file quoting the very bug it guards against. A check with a 5:1 false
positive rate is one nobody reads twice.

THE SELF-REFERENCE TRAP, GUARDED TWICE. Two sibling diagnostics shipped bugs
where a tree-scanning check matched its own fixtures — the DDL scanner found the
example in its docstring, the dependency scanner found the fake binary in its
canary. Here BOTH defences are asserted independently: fixtures are assembled at
runtime AND the `diagnostics` package is excluded from the scan. Either alone
would work today; relying on one makes the other's removal a silent regression.

NO WRITES. Files are parsed; nothing is executed.
"""
import importlib.util
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

_SRC_PATH = os.path.join(_HERE, "config_drift.py")
_spec = importlib.util.spec_from_file_location("cd_under_test", _SRC_PATH)
cd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cd)

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


print("\n-- the canary passes on a sound comparator --")
ok, detail = cd._canary()
check("canary reports ok", ok, detail)

print("\n-- action classes are parsed from the code literal --")
SRC_OK = 'ACTION_CLASS_CEILINGS = {\n    "alpha": 1,\n    "beta": 2,\n}'
check("keys parsed", cd.code_action_classes(SRC_OK) == {"alpha", "beta"})
check("a MISSING literal yields None, not an empty set",
      cd.code_action_classes("nothing here") is None)
check("an EMPTY literal yields None too",
      cd.code_action_classes("ACTION_CLASS_CEILINGS = {\n}") is None)

print("\n-- doc mentions are intersected with real classes --")
known = {"alpha", "beta"}
check("a mentioned class is found",
      cd.doc_action_classes("see `alpha` here", known) == {"alpha"})
check("an unrelated backticked identifier is ignored",
      cd.doc_action_classes("`some_function` and `alpha`", known) == {"alpha"})
check("CONTROL: nothing mentioned yields nothing",
      cd.doc_action_classes("no identifiers at all", known) == set())

print("\n-- class comparison distinguishes both directions --")
check("matching sets report no drift",
      cd.compare_classes({"a"}, {"a"}) == {"undocumented": [], "phantom": []})
check("a class missing from the doc is reported",
      cd.compare_classes({"a", "b"}, {"a"})["undocumented"] == ["b"])
check("a class the doc invents is reported",
      cd.compare_classes({"a"}, {"a", "ghost"})["phantom"] == ["ghost"])

print("\n-- the active model is parsed, and a miss is None --")
check("constant parsed", cd.active_model('_ACTIVE_MODEL = "claude-x-9"') == "claude-x-9")
check("a missing constant yields None, not a guess",
      cd.active_model("no constant") is None)
check("normalisation matches the API id spelling",
      cd.normalise_model("Sonnet", "4.6") == "claude-sonnet-4-6")

print("\n-- prose scanning: real drift IS reported --")
with tempfile.TemporaryDirectory() as d:
    with open(os.path.join(d, "page.py"), "w") as fh:
        fh.write('label = "%s"\n' % cd._fixture_model_prose("Sonnet", "4.6"))
    hits = cd.scan_model_prose(d, "claude-sonnet-5")
    check("a stale model name in prose is a finding",
          any(h[0] == "page.py" for h in hits), hits)

print("\n-- CONTROL: prose naming the ACTIVE model is NOT a finding --")
with tempfile.TemporaryDirectory() as d:
    with open(os.path.join(d, "ok.py"), "w") as fh:
        fh.write('label = "%s"\n' % cd._fixture_model_prose("Sonnet", "5"))
    check("correct documentation is clean",
          not cd.scan_model_prose(d, "claude-sonnet-5"))

print("\n-- FALSE-POSITIVE GUARDS (5 of the first run's 6 findings) --")
with tempfile.TemporaryDirectory() as d:
    # A pricing/name table enumerating many models.
    with open(os.path.join(d, "table.py"), "w") as fh:
        fh.write('RATES = {\n    "%s": 1,\n    "%s": 2,\n}\n'
                 % (cd._fixture_model_prose("Opus", "4.8").lower(),
                    cd._fixture_model_prose("Haiku", "4.5").lower()))
    # A test file quoting the bug it guards.
    with open(os.path.join(d, "test_guard.py"), "w") as fh:
        fh.write('DOC = "%s"\n' % cd._fixture_model_prose("Sonnet", "4.6"))
    # A genuine finding, so the filters cannot pass by rejecting everything.
    with open(os.path.join(d, "page.py"), "w") as fh:
        fh.write('label = "%s"\n' % cd._fixture_model_prose("Sonnet", "4.6"))
    hits = cd.scan_model_prose(d, "claude-sonnet-5")
    names = {h[0] for h in hits}
    check("a model lookup TABLE is not reported", "table.py" not in names, names)
    check("a TEST file quoting the bug is not reported",
          "test_guard.py" not in names, names)
    check("CONTROL: the genuine finding still survives filtering",
          "page.py" in names, names)

print("\n-- SELF-REFERENCE: both defences, asserted independently --")
own_src = open(_SRC_PATH, encoding="utf-8").read()
check("defence 1: the module's own source contains no matchable model literal",
      not cd._MODEL_PROSE_RE.findall(own_src),
      cd._MODEL_PROSE_RE.findall(own_src))
check("defence 2: the diagnostics package is excluded from the scan",
      "diagnostics" in cd._SCAN_SKIP_DIRS)
with tempfile.TemporaryDirectory() as d:
    os.makedirs(os.path.join(d, "diagnostics"), exist_ok=True)
    with open(os.path.join(d, "diagnostics", "self.py"), "w") as fh:
        fh.write('label = "%s"\n' % cd._fixture_model_prose("Opus", "1.0"))
    check("...and a file inside it is not scanned",
          not cd.scan_model_prose(d, "claude-sonnet-5"))
# Live: scanning the real repo must not report this package.
live = cd.scan_model_prose(cd._repo_root(), "claude-sonnet-5")
check("live scan reports nothing inside diagnostics/",
      not [h for h in live if h[0].startswith("diagnostics/")], live)
check("CONTROL: the live scan is not simply empty", len(live) > 0, live)

print("\n-- the produced result obeys the diagnostics contract --")
res = cd.run()
check("status is ok/warn/error/info (T3)",
      res["status"] in ("ok", "warn", "error", "info"), res["status"])
check("keys are EXACTLY the six contract keys (T5)",
      set(res) == {"id", "name", "icon", "status", "summary", "output"}, sorted(res))
check("every value is a string", all(isinstance(v, str) for v in res.values()))
check("META has all three description tiers (T2)",
      set(cd.META["descriptions"]) == {"beginner", "intermediate", "pro"})
check("META id is URL/DOM safe (T10)",
      cd.META["id"].replace("_", "").isalnum() and cd.META["id"].islower())

print("\n-- MUTATION: the canary must CATCH each injected defect --")
SRC = own_src

MUTATIONS = [
    ("a failed ceilings parse returns an empty set instead of None",
     "    keys = set(_CEILING_KEY_RE.findall(m.group(1)))\n    return keys or None",
     "    return set(_CEILING_KEY_RE.findall(m.group(1)))"),
    ("doc mentions are NOT intersected (every identifier becomes a class)",
     "    return mentioned & set(known)",
     "    return mentioned"),
    ("undocumented-class detection disabled",
     '    return {"undocumented": sorted(code_set - doc_set),',
     '    return {"undocumented": [],'),
    ("a missing _ACTIVE_MODEL returns a guess instead of None",
     '    return m.group(1) if m else None',
     '    return m.group(1) if m else "claude-unknown"'),
    ("prose naming the ACTIVE model is reported as drift",
     "                    if written != active:",
     "                    if True:"),
    ("model lookup TABLES are scanned again (the 4:1 false-positive bug)",
     "                if _TABLE_ENTRY_RE.match(line):\n                    continue",
     "                if False:\n                    continue"),
    ("the diagnostics package is scanned again (self-reference returns)",
     '"venv", ".venv",\n                   "diagnostics"}',
     '"venv", ".venv"}'),
]

for label, old, new in MUTATIONS:
    if old not in SRC:
        check("MUTATION anchor present: %s" % label, False,
              "anchor not found -- this TEST is stale, not the code")
        continue
    path = tempfile.mktemp(suffix=".py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(SRC.replace(old, new, 1))
    caught = False
    try:
        s2 = importlib.util.spec_from_file_location("cd_mutant", path)
        m2 = importlib.util.module_from_spec(s2)
        s2.loader.exec_module(m2)
        ok2, _d = m2._canary()
        caught = not ok2
    except Exception:
        caught = True
    finally:
        os.unlink(path)
    check("canary catches: %s" % label, caught,
          "the mutated module's canary still reported OK — it is not measuring")

print("\n-- a failed canary SUPPRESSES the verdict --")
path = tempfile.mktemp(suffix=".py")
with open(path, "w", encoding="utf-8") as fh:
    fh.write(SRC.replace('def _canary():\n    """Returns (ok, detail). Never raises. Runs on EVERY invocation."""',
                         'def _canary():\n    """stub"""\n    return False, "forced"', 1))
try:
    s3 = importlib.util.spec_from_file_location("cd_broken", path)
    m3 = importlib.util.module_from_spec(s3)
    s3.loader.exec_module(m3)
    r3 = m3.run()
    check("a failed canary yields status=error", r3["status"] == "error", r3["status"])
    check("...and says documentation was NOT checked",
          "NOT checked" in r3["summary"], r3["summary"])
    check("...and does not claim the docs match",
          "matches the code" not in r3["summary"], r3["summary"])
finally:
    os.unlink(path)

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
