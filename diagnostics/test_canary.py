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
               lambda d: {"status": "warn", "summary": d, "output": "body"},
               subject="schema")
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
                   lambda d, s=good_status: {"status": s, "summary": "x",
                                             "output": "o"},
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
print("\n-- guard(): the FULL result contract is enforced, not just status --")
# The 2026-09-05 defect: audit_write_liveness returned {"status","summary",
# "sections"}. No renderer reads "sections" (dashboard.py's diagnostics JS reads
# d.output), so the check reported status=ok with an empty panel from 928074a
# until it was found. guard() validated only `status` and returned the rest
# untouched, and its two FAILURE paths build complete results -- so the check
# rendered correctly while broken and blankly while healthy.
res = cy.guard(META, lambda: (True, "ok"),
               lambda d: {"status": "ok", "summary": "looks fine"}, subject="t")
check("a result with no 'output' is refused, not rendered blank",
      res["status"] == "error" and "unrenderable" in res["summary"], res["summary"])
check("...and the refusal names the offending field",
      "'output' key is missing" in res["output"], res["output"][:90])

res = cy.guard(META, lambda: (True, "ok"),
               lambda d: {"status": "ok", "summary": "s",
                          "output": [{"title": "t", "body": "b"}]}, subject="t")
check("a non-string 'output' is refused (the exact shape that shipped)",
      res["status"] == "error" and "not a string" in res["output"], res["output"][:90])

res = cy.guard(META, lambda: (True, "ok"),
               lambda d: {"status": "ok", "output": "o"}, subject="t")
check("a result with no 'summary' is refused",
      res["status"] == "error" and "'summary' key is missing" in res["output"],
      res["output"][:90])

res = cy.guard(META, lambda: (True, "ok"),
               lambda d: {"status": "ok", "summary": "   ", "output": "o"},
               subject="t")
check("a blank 'summary' is refused (the card would have no label)",
      res["status"] == "error" and "no label" in res["output"], res["output"][:90])

res = cy.guard(META, lambda: (True, "ok"),
               lambda d: {"status": "ok", "summary": "s", "output": "o"}, subject="t")
check("guard() stamps id/name/icon from META on the SUCCESS path",
      (res["id"], res["name"], res["icon"])
      == (META["id"], META["name"], META["icon"]),
      (res.get("id"), res.get("name"), res.get("icon")))
check("CONTROL: a well-formed result still passes untouched",
      res["status"] == "ok" and res["output"] == "o" and res["summary"] == "s")
# Every real check must satisfy the contract guard now enforces -- otherwise the
# enforcement above would be turning live checks into errors on the page.
print("  (CONTROL: every guard-using check in the package satisfies it)")
import importlib
_pkg = importlib.import_module("diagnostics")
_GUARDED = ("audit_write_liveness", "config_drift", "dependency_preflight",
            "schema_drift", "agent_enrollment_integrity",
            "clock_and_timestamp_sanity")
for _cid in _GUARDED:
    _mod = dict((m.META["id"], m) for m in _pkg.CHECKS).get(_cid)
    check("  %s declares the keys guard() requires" % _cid,
          _mod is not None and set(_mod.META) >= {"id", "name", "icon"})

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
    ("a missing 'output' is passed through (renders as a blank panel)",
     "        if field not in result:",
     "        if False:"),
    ("identity is no longer stamped from META (null id/name/icon reach the UI)",
     '    out["id"], out["name"], out["icon"] = meta["id"], meta["name"], meta["icon"]',
     "    pass"),
    ("the shape problems are collected but never acted on",
     "    if problems:",
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

print("\n-- scratch_dir() survives a sandbox with no usable temp directory --")
# REGRESSION GUARD, 2026-09-04. Four registered diagnostics called tempfile on their
# canary self-test path. The dashboard unit runs ProtectSystem=strict with
# ReadWritePaths=/var/lib/nemesis and PrivateTmp=no, so /tmp, /var/tmp and the working
# directory are read-only for the service and tempfile.gettempdir() itself RAISES.
# All four reported [PROBE-FAILED] in production while passing every test, because the
# tests ran from a shell with a writable /tmp. The sandbox was never in the test.
import tempfile as _tf

_real_gettempdir = _tf.gettempdir


def _no_ambient_tmp():
    """Exactly what production raised, not an approximation of it."""
    raise FileNotFoundError(
        2, "No usable temporary directory found in "
           "['/tmp', '/var/tmp', '/usr/tmp', '/opt/nemesis']")


# Control FIRST: prove the ambient path is what is normally taken, so a pass below
# cannot come from the fallback having been used all along.
check("control: with a working tmp, scratch_dir uses it",
      cy.scratch_dir() == _real_gettempdir())

_tf.gettempdir = _no_ambient_tmp
try:
    _sandboxed = cy.scratch_dir()
    check("with no ambient tmp, scratch_dir still returns a directory",
          isinstance(_sandboxed, str) and os.path.isdir(_sandboxed), repr(_sandboxed))
    check("  ...and it is NOT the unusable ambient one",
          _sandboxed != "/tmp", repr(_sandboxed))
    # It must be writable in fact, not merely named. A mode-bit check passes here
    # (/tmp is 1777); os.access is unreliable independently of any mount question, as it
    # tests the real uid and ignores ACLs. Only an actual write settles it.
    _wrote = False
    try:
        _fd, _pr = _tf.mkstemp(prefix=".canary-test-", dir=_sandboxed)
        os.close(_fd); os.unlink(_pr); _wrote = True
    except Exception:                                        # noqa: BLE001
        pass
    check("  ...and a file can actually be created and removed there", _wrote)

    # And it must FAIL LOUDLY when nothing is writable, rather than returning a path
    # that does not work — a default that reads as a real answer is the whole hazard.
    _saved_env = os.environ.get("NEMESIS_DB_PATH")
    os.environ["NEMESIS_DB_PATH"] = "/nonexistent-canary-root/db.sqlite"
    _real_mkstemp = _tf.mkstemp
    _tf.mkstemp = lambda *a, **k: (_ for _ in ()).throw(OSError("read-only file system"))
    try:
        cy.scratch_dir()
        check("with NOTHING writable, scratch_dir raises", False, "it returned instead")
    except OSError as _e:
        check("with NOTHING writable, scratch_dir raises", True)
        check("  ...and the error names what it tried", "tried:" in str(_e), str(_e)[:90])
    finally:
        _tf.mkstemp = _real_mkstemp
        if _saved_env is None:
            os.environ.pop("NEMESIS_DB_PATH", None)
        else:
            os.environ["NEMESIS_DB_PATH"] = _saved_env
finally:
    _tf.gettempdir = _real_gettempdir

check("teardown: ambient tmp restored", cy.scratch_dir() == _real_gettempdir())

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
