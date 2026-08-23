#!/usr/bin/env python3
"""Every name imported from `modules.ai_engine` must actually resolve.

WHY THIS EXISTS — the class has now recurred twice.

`modules/ai_engine/__init__.py` re-exports a curated list from `.module`. Every
consumer imports from the PACKAGE, and every registration site wraps its import
in try/except so one module cannot take the app down. That combination means a
missing export **does not crash anything** — it leaves a feature quietly off.

  * 2026-08-04: anchors. A missing export left every chat affordance
    unregistered. Caught by a render check, and `__init__.py` gained a comment
    predicting exactly this.
  * 2026-08-23: `register_undo_handler`. Present in `module.py`, never
    re-exported. `dashboard.py`'s registration block raised ImportError into its
    own `except Exception`, so alert_disposition, ip_quarantine_external and
    ip_block_permanent had NO undo handler — and `authority_raise_warnings`
    REFUSES to act at L2 without one. **The entire reversible-action tier was
    inert.** Found by Window 3 while doing unrelated work.

A comment predicting a failure did not prevent its recurrence. This test does:
the omission can no longer land unnoticed, which is the same mechanism-plus-test
pattern used for the module write gate.

SCOPE IS THE WHOLE REPO, not just dashboard.py. The defect is a property of the
package boundary, and any importer can trip it — dashboard.py was simply where it
happened to bite this time.
"""
import ast
import glob
import os
import sys
import tempfile

sys.path.insert(0, "/opt/nemesis")
os.environ.setdefault("NEMESIS_DB_PATH",
                      os.path.join(tempfile.mkdtemp(prefix="pkgexp-"), "t.db"))
import modules                                              # noqa: E402
modules.set_shared_db_path(os.environ["NEMESIS_DB_PATH"])
import modules.ai_engine as pkg                             # noqa: E402

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


def imported_names(path):
    """Names this file imports from modules.ai_engine (the package, not .module)."""
    try:
        tree = ast.parse(open(path, encoding="utf-8").read())
    except Exception:
        return []
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module == "modules.ai_engine":
            for a in n.names:
                if a.name != "*":
                    out.append(a.name)
    return out


# ═══════════════════════════════════════════════════════════════════════
print("\n== 1. every imported name resolves on the package ==")

files = [f for f in glob.glob("/opt/nemesis/**/*.py", recursive=True)
         if "__pycache__" not in f]
missing, checked, importers = [], 0, 0
for f in files:
    names = imported_names(f)
    if names:
        importers += 1
    for nm in names:
        checked += 1
        if not hasattr(pkg, nm):
            missing.append("%s imports %r" % (os.path.relpath(f, "/opt/nemesis"), nm))

check("found real importers to check", importers >= 3, "importers=%d" % importers)
check("found real names to check", checked >= 10, "names=%d" % checked)
check("every name resolves", not missing, "; ".join(sorted(set(missing))))

# MUTATION CONTROL: the check must be able to fail. Without this, "no missing
# names" is indistinguishable from a scanner that found nothing at all.
check("CONTROL: a fabricated name would be caught",
      not hasattr(pkg, "definitely_not_a_real_export_2026"))

# The specific symbol this test was born from.
for nm in ("register_undo_handler", "undo_handler_for"):
    check("%s is exported" % nm, hasattr(pkg, nm))
    check("  ...and is in __all__ (so it is intentional, not incidental)",
          nm in getattr(pkg, "__all__", []))


# ═══════════════════════════════════════════════════════════════════════
print("\n== 2. the L2 reversible tier is actually functional again ==")

from modules.ai_engine import module as ai                  # noqa: E402

# CONTROL FIRST: a class with no handler must carry the refusal warning, or the
# positive check below would prove nothing.
ai._UNDO_HANDLERS.pop("alert_disposition", None)
warns = ai.authority_raise_warnings("alert_disposition", ai.L2_ACT_REVERSIBLE)
check("CONTROL: with NO handler, L2 warns it cannot be undone",
      any("CANNOT BE UNDONE" in w for w in warns), str(warns)[:90])

# Now register through the PACKAGE export -- the path dashboard.py uses.
pkg.register_undo_handler("alert_disposition", lambda payload: (True, "reversed"))
check("the handler registers via the package export",
      ai.undo_handler_for("alert_disposition") is not None)
warns = ai.authority_raise_warnings("alert_disposition", ai.L2_ACT_REVERSIBLE)
check("L2 no longer refuses -- the tier works",
      not any("CANNOT BE UNDONE" in w for w in warns), str(warns)[:90])

# And the three classes dashboard.py registers are all L2, i.e. all were affected.
for cls in ("alert_disposition", "ip_quarantine_external", "ip_block_permanent"):
    check("%s is an L2 class (so it was affected)" % cls,
          ai.ACTION_CLASS_CEILINGS.get(cls) >= ai.L2_ACT_REVERSIBLE,
          repr(ai.ACTION_CLASS_CEILINGS.get(cls)))

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
