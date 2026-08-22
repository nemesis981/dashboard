#!/usr/bin/env python3
"""The shared canary harness — and proof it enforces what it claims to.

Run: python3 diagnostics/test_canary.py   (exit 0 = all pass)

WHY THE HARNESS NEEDS ITS OWN MUTATION SUITE. Every diagnostic's trustworthiness
now routes through this module: if `run_cases` stopped distinguishing, five checks
would keep reporting confident verdicts from unverified instruments and nothing
would look wrong. A harness that guarantees correctness for others and is not
itself checked is the same single-point-of-trust failure it exists to remove.

THE ENFORCED PROPERTY. `run_cases` REFUSES a case list without both a known-good
and a known-bad case. That is not stylistic:
  * with no BAD case, a check that reports nothing at all passes everything;
  * with no GOOD case, a check that reports everything passes everything.
A canary missing either half is not weaker — it is not a canary. It raises rather
than returning a failure, because that is a programming error in the check, not a
finding about the system, and it must be impossible to ignore.
"""
import importlib.util
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

_SRC_PATH = os.path.join(_HERE, "canary.py")
_spec = importlib.util.spec_from_file_location("canary_under_test", _SRC_PATH)
cy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cy)

passed = failed = 0
META = {"id": "x", "name": "X", "icon": "?"}


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


print("\n-- a balanced case list passes and reports its counts --")
ok, detail = cy.run_cases([cy.good("clean", lambda: None),
                           cy.bad("broken", lambda: "found")])
check("balanced list passes", ok, detail)
check("detail names the counts",
      "1 known-good" in detail and "1 known-bad" in detail, detail)

print("\n-- a false POSITIVE fails the canary --")
ok, detail = cy.run_cases([cy.good("clean", lambda: "unexpected finding"),
                           cy.bad("broken", lambda: "found")])
check("a GOOD case that reports something fails", not ok)
check("...and the detail says which case", "clean" in detail, detail)
check("...and quotes what it wrongly reported", "unexpected" in detail, detail)

print("\n-- a false NEGATIVE fails the canary --")
ok, detail = cy.run_cases([cy.good("clean", lambda: None),
                           cy.bad("broken", lambda: None)])
check("a BAD case that reports nothing fails", not ok)
check("...and the detail says which case", "broken" in detail, detail)

print("\n-- THE ENFORCED CONTRACT: an unbalanced list RAISES --")
for cases, why in (
    ([cy.good("only good", lambda: None)], "no known-bad"),
    ([cy.good("g1", lambda: None), cy.good("g2", lambda: None)], "still no known-bad"),
    ([cy.bad("only bad", lambda: "x")], "no known-good"),
):
    try:
        cy.run_cases(cases)
        check("a list with %s is refused" % why, False, "it was accepted")
    except cy.CanaryContractError as e:
        check("a list with %s raises CanaryContractError" % why, True)
        check("...and the message explains why", len(str(e)) > 60, str(e))
try:
    cy.run_cases([("mystery", "sideways", lambda: None)])
    check("an unknown case kind is refused", False, "it was accepted")
except cy.CanaryContractError:
    check("an unknown case kind raises", True)

print("\n-- a raising thunk is contained, attributed, and fails the canary --")
def _boom():
    raise ValueError("nope")
ok, detail = cy.run_cases([cy.good("clean", lambda: None), cy.bad("boom", _boom)])
check("a raising case does not escape", ok is False)
check("...and is attributed to the case", "boom" in detail, detail)
check("...naming the exception type", "ValueError" in detail, detail)

print("\n-- guard(): a failing canary SUPPRESSES the body entirely --")
ran = []
res = cy.guard(META, lambda: (False, "forced"),
               lambda d: ran.append(1) or {"status": "ok", "summary": "clean!"},
               subject="schema")
check("the body did not run", not ran)
check("status is error", res["status"] == "error", res["status"])
check("summary says NOT checked", "NOT checked" in res["summary"], res["summary"])
check("summary names the subject", "schema" in res["summary"], res["summary"])
check("the output says it is not a clean result",
      "NOT a clean result" in res["output"], res["output"][:120])
check("the suppressed body's own summary is NOT surfaced",
      "clean!" not in res["summary"] and "clean!" not in res["output"])

print("\n-- guard(): a passing canary runs the body and returns it --")
res = cy.guard(META, lambda: (True, "proof"),
               lambda d: {"status": "warn", "summary": d}, subject="schema")
check("the body ran", res["status"] == "warn")
check("the canary detail is handed to the body", res["summary"] == "proof")

print("\n-- guard(): a contract violation is caught, not propagated --")
def _bad_canary():
    return cy.run_cases([cy.good("only good", lambda: None)])
res = cy.guard(META, _bad_canary, lambda d: {"status": "ok"}, subject="thing")
check("a contract error becomes an error result", res["status"] == "error")
check("...and says the contract was violated",
      "contract" in res["output"].lower(), res["output"][:140])

print("\n-- guard(): a raising canary is contained --")
res = cy.guard(META, _boom, lambda d: {"status": "ok"}, subject="thing")
check("a raising canary yields status=error", res["status"] == "error")
check("...naming the exception", "ValueError" in res["output"], res["output"][:120])

print("\n-- guard(): a raising BODY is contained --")
res = cy.guard(META, lambda: (True, "ok"), lambda d: _boom(), subject="thing")
check("a raising body yields status=error", res["status"] == "error")
check("...and does not claim a result", "NOT checked" not in res["summary"],
      res["summary"])

print("\n-- guard(): an ILLEGAL status is refused, not rendered as grey 'Not run' --")
for bad_status in ("critical", "OK", "pass", "failed", None, "", "Warning"):
    res = cy.guard(META, lambda: (True, "ok"),
                   lambda d, s=bad_status: {"status": s, "summary": "x"},
                   subject="thing")
    check("status %r is refused" % (bad_status,),
          res["status"] == "error" and "unrenderable" in res["summary"],
          res["summary"])
print("  (CONTROL: every legal status passes through)")
for good_status in cy.LEGAL_STATUS:
    res = cy.guard(META, lambda: (True, "ok"),
                   lambda d, s=good_status: {"status": s, "summary": "x"},
                   subject="thing")
    check("status %r passes through" % good_status, res["status"] == good_status)

print("\n-- every guard() result is contract-shaped --")
for res in (cy.guard(META, lambda: (False, "f"), lambda d: {}, subject="t"),
            cy.guard(META, _boom, lambda d: {}, subject="t"),
            cy.guard(META, lambda: (True, "o"), lambda d: _boom(), subject="t"),
            cy.guard(META, lambda: (True, "o"), lambda d: {"status": "nope"}, subject="t")):
    check("result carries id/name/icon/status/summary/output",
          {"id", "name", "icon", "status", "summary", "output"} <= set(res), sorted(res))
    check("...with a legal status", res["status"] in cy.LEGAL_STATUS, res["status"])

print("\n-- MUTATION: the harness's own self-test must catch each defect --")
SRC = open(_SRC_PATH, encoding="utf-8").read()

MUTATIONS = [
    ("the known-BAD requirement is dropped (unbalanced canaries accepted)",
     "    if BAD not in kinds:\n        raise CanaryContractError(",
     "    if False:\n        raise CanaryContractError("),
    ("the known-GOOD requirement is dropped",
     "    if GOOD not in kinds:\n        raise CanaryContractError(",
     "    if False:\n        raise CanaryContractError("),
    ("false positives no longer fail (GOOD cases unchecked)",
     "            if found:\n                return False, (\"known-good case failed",
     "            if False:\n                return False, (\"known-good case failed"),
    ("false negatives no longer fail (BAD cases unchecked)",
     "            if not found:\n                return False, (\"known-bad case failed",
     "            if False:\n                return False, (\"known-bad case failed"),
    ("a raising thunk is swallowed as 'nothing found'",
     "        except Exception as e:                               # noqa: BLE001\n"
     "            # Attributed to the CASE, never allowed to escape into the check.\n"
     "            return False, \"case %r raised %s: %s\" % (label, type(e).__name__, e)",
     "        except Exception:\n            found = None"),
    ("a failed canary no longer suppresses the body",
     "    if not ok:\n        return {",
     "    if False:\n        return {"),
    ("an illegal status is passed through (renders as grey 'Not run')",
     '    if result.get("status") not in LEGAL_STATUS:',
     "    if False:"),
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
        s2 = importlib.util.spec_from_file_location("cy_mutant", path)
        m2 = importlib.util.module_from_spec(s2)
        s2.loader.exec_module(m2)   # the import-time self-test must reject it
    except Exception:
        caught = True
    finally:
        os.unlink(path)
    check("import-time self-test catches: %s" % label, caught,
          "the mutated harness imported cleanly — it is not measuring itself")

print("\n-- every registered diagnostic actually routes through the harness --")
# Otherwise a check could quietly keep its own unguarded run() and lose the
# illegal-status and suppression protections without anything failing.
import diagnostics as _pkg
guarded = []
for m in _pkg.CHECKS:
    src_path = getattr(m, "__file__", "") or ""
    try:
        text = open(src_path, encoding="utf-8").read()
    except OSError:
        continue
    if "_canary_harness.guard(" in text:
        guarded.append(m.META["id"])
check("the five new tools are all guarded",
      set(guarded) >= {"schema_drift", "clock_and_timestamp_sanity",
                       "agent_enrollment_integrity", "dependency_preflight",
                       "config_drift"}, sorted(guarded))

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
