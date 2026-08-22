#!/usr/bin/env python3
"""The schema_drift diagnostic — and proof its canary actually measures.

Run: python3 diagnostics/test_schema_drift.py   (exit 0 = all pass)

WHAT THIS CHECK IS FOR. A fresh install once crashed because a table had no
`CREATE` anywhere in the repo; every existing box was fine, because the table had
been created by hand long ago and simply persisted. The mirror image is a guarded
migration that never ran: the canonical CREATE gains a column, the ALTER beside it
does not execute, and code written against the new schema fails on a box that
looks healthy.

WHY THE MUTATION SECTION IS THE POINT. This tool's output is trusted by both a
human and (later) the tool-aware AI loop, so a comparison that could only ever
report "clean" would be actively dangerous — worse than no check, because it
reads as a clean bill of health. The canary runs on EVERY invocation in the
production path; the mutations here prove the canary itself is not a rubber stamp
by injecting each defect it claims to catch and asserting it fails.

TWO OF THE MUTATIONS ARE REGRESSIONS, NOT HYPOTHETICALS. The first version of
this check shipped both defects and they were caught by running it, not by
reading it:
  * DDL comments were not stripped, so English prose inside inline comments
    became phantom column names AND real columns after a comment were lost —
    seven tables reported as drifted, every one a false positive.
  * The module scanned its own source, so a DDL fixture written literally in the
    canary was picked up as a real declaration and reported as a phantom
    unresolved table on every production run.

NO WRITES. The check opens the database read-only and never executes DDL.
"""
import importlib.util
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

_SRC_PATH = os.path.join(_HERE, "schema_drift.py")
_spec = importlib.util.spec_from_file_location("schema_drift_under_test", _SRC_PATH)
sd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sd)

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


# The DDL keyword is assembled, never written literally: this test lives inside
# the tree the check scans, and a literal fixture here would be picked up as a
# real declaration by the production run. Same trap the module itself documents.
CT = "CREATE" + " TABLE"

print("\n-- the canary passes on a healthy tree --")
ok, detail = sd._canary()
check("canary reports ok", ok, detail)
check("...and says what it proved", bool(detail), detail)

print("\n-- compare(): known-good produces nothing --")
clean = sd.compare({"alpha": ["id", "name"]}, {"alpha"},
                   column_lookup=lambda t: ["id", "name"])
check("a matching schema reports no orphans", clean["orphans"] == [])
check("a matching schema reports no column drift", clean["column_drift"] == {})

print("\n-- compare(): known-bad is detected --")
orphan = sd.compare({"ghost": ["id"]}, set(), column_lookup=lambda t: [])
check("an undeclared live table is an orphan", orphan["orphans"] == ["ghost"])
drift = sd.compare({"alpha": ["id"]}, {"alpha"},
                   column_lookup=lambda t: ["id", "added_later"])
check("a declared-but-absent column is drift",
      drift["column_drift"] == {"alpha": ["added_later"]}, drift)

print("\n-- one fault, one line: an orphan is not ALSO column drift --")
both = sd.compare({"ghost": ["id"]}, set(), column_lookup=lambda t: ["id", "nope"])
check("orphan is not double-reported", both["column_drift"] == {}, both)

print("\n-- an extra LIVE column is not drift (schema ahead of code is not a fault) --")
ahead = sd.compare({"alpha": ["id", "name", "extra"]}, {"alpha"},
                   column_lookup=lambda t: ["id", "name"])
check("extra live columns are ignored", ahead["column_drift"] == {}, ahead)

print("\n-- REGRESSION: DDL comments must be stripped before parsing columns --")
body = ("\n  id INTEGER PRIMARY KEY,\n"
        "  username TEXT NOT NULL,   -- login ID, stable, lowercase\n"
        "  display_name TEXT NOT NULL,  -- shown in UI, can change\n"
        "  role TEXT NOT NULL DEFAULT 'admin'  -- 'admin'|'user'\n")
cols = sd._column_names(body)
check("real columns are all found", cols == ["id", "username", "display_name", "role"], cols)
check("prose from comments does not become a column",
      not ({"stable", "lowercase", "can", "shown", "login"} & set(cols)), cols)
check("a column following a comment is not lost", "display_name" in cols, cols)
check("block comments are stripped too",
      sd._column_names("id INTEGER, /* note, with, commas */ name TEXT")
      == ["id", "name"], sd._column_names("id INTEGER, /* note, with, commas */ name TEXT"))

print("\n-- table-level constraints are not mistaken for columns --")
cons = sd._column_names("id INTEGER, name TEXT, PRIMARY KEY(id), "
                        "UNIQUE(name), FOREIGN KEY(id) REFERENCES x(id)")
check("constraints excluded", cons == ["id", "name"], cons)

print("\n-- constant resolution (the dm_operation_log false-positive guard) --")
with tempfile.TemporaryDirectory() as d:
    with open(os.path.join(d, "m.py"), "w") as fh:
        fh.write('OP_LOG_TABLE = "resolved_name"\n'
                 'q = f"%s IF NOT EXISTS {OP_LOG_TABLE} (id INTEGER)"\n'
                 'q2 = "%s plain_literal (id INTEGER)"\n' % (CT, CT))
    names, unres = sd.declared_tables(d)
    check("an f-string CREATE with a resolvable constant IS resolved",
          "resolved_name" in names, names)
    check("a plain literal CREATE is detected", "plain_literal" in names, names)
    check("nothing spurious is reported unresolved", unres == set(), unres)

print("\n-- an UNRESOLVABLE name is reported, never silently dropped --")
with tempfile.TemporaryDirectory() as d:
    with open(os.path.join(d, "n.py"), "w") as fh:
        fh.write('q = f"%s {NAME_FROM_NOWHERE} (id INTEGER)"\n' % CT)
    names, unres = sd.declared_tables(d)
    check("it is listed as unresolved", "{NAME_FROM_NOWHERE}" in unres, unres)
    check("...and NOT counted as a declared table", names == set(), names)

print("\n-- live_schema RAISES on an unreadable DB, never returns {} --")
# An empty schema is a legal answer (a brand-new database), so returning {} on
# failure would be indistinguishable from a real measurement.
try:
    sd.live_schema(os.path.join(tempfile.gettempdir(), "definitely-not-a-db-9f3a.db"))
    check("an unreadable database raises", False, "it returned a value")
except Exception:
    check("an unreadable database raises rather than returning {}", True)

print("\n-- the produced result obeys the diagnostics contract --")
res = sd.run()
check("status is one of ok/warn/error/info (T3)",
      res["status"] in ("ok", "warn", "error", "info"), res["status"])
check("keys are EXACTLY the six contract keys (T5)",
      set(res) == {"id", "name", "icon", "status", "summary", "output"}, sorted(res))
check("every value is a string", all(isinstance(v, str) for v in res.values()))
check("id matches META", res["id"] == sd.META["id"])
check("summary is non-empty", bool(res["summary"].strip()))
check("META has all three description tiers (T2)",
      set(sd.META["descriptions"]) == {"beginner", "intermediate", "pro"})
check("META id is URL/DOM safe (T10)",
      sd.META["id"].replace("_", "").isalnum() and sd.META["id"].islower())

print("\n-- MUTATION: the canary must CATCH each injected defect --")
SRC = open(_SRC_PATH, encoding="utf-8").read()

MUTATIONS = [
    ("orphan detection disabled (reports clean always)",
     '    orphans = sorted(t for t in live if t.lower() not in declared)',
     '    orphans = []'),
    ("column-drift detection disabled",
     '            missing = [c for c in want if c not in live_cols]',
     '            missing = []'),
    ("REGRESSION: DDL comment stripping removed",
     '    body = _strip_sql_comments(body)\n    cols, depth, current = [], 0, []',
     '    cols, depth, current = [], 0, []'),
    ("constant resolution removed (dm_operation_log false positive returns)",
     '                if key in consts:\n                    names.add(consts[key].lower())',
     '                if False:\n                    names.add(consts[key].lower())'),
    ("unresolvable names silently dropped instead of reported",
     '                else:\n                    unresolved.add(raw)',
     '                else:\n                    pass'),
    ("an orphan is also double-reported as column drift",
     '            if table.lower() not in declared:\n                continue                      # already an orphan; not column drift',
     '            if False:\n                continue'),
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
        s2 = importlib.util.spec_from_file_location("sd_mutant", path)
        m2 = importlib.util.module_from_spec(s2)
        s2.loader.exec_module(m2)
        ok2, _detail = m2._canary()
        caught = not ok2
    except Exception:
        caught = True          # refusing to load at all is also a catch
    finally:
        os.unlink(path)
    check("canary catches: %s" % label, caught,
          "the mutated module's canary still reported OK — it is not measuring")

print("\n-- a failed canary must SUPPRESS the schema verdict, not decorate it --")
# The dangerous failure is a broken comparator that still emits a reassuring
# schema result. run() must refuse to report one.
path = tempfile.mktemp(suffix=".py")
with open(path, "w", encoding="utf-8") as fh:
    fh.write(SRC.replace('def _canary():\n    """Returns (ok, detail). Never raises."""',
                         'def _canary():\n    """stub"""\n    return False, "forced failure"',
                         1))
try:
    s3 = importlib.util.spec_from_file_location("sd_broken", path)
    m3 = importlib.util.module_from_spec(s3)
    s3.loader.exec_module(m3)
    r3 = m3.run()
    check("a failed canary yields status=error", r3["status"] == "error", r3["status"])
    check("...and the summary says the schema was NOT checked",
          "NOT checked" in r3["summary"] or "not checked" in r3["summary"].lower(),
          r3["summary"])
    check("...and it does not claim a clean schema",
          "matches the code" not in r3["summary"], r3["summary"])
finally:
    os.unlink(path)

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
