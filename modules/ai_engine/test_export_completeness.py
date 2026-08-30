#!/usr/bin/env python3
"""The package's export set is DERIVED from module.py, and stays complete.

Backstop for `__init__.py`'s derive logic (2026-08-30), which replaced the
hand-written re-export list that was the mechanism of four separate defects
(anchors, register_undo_handler, raise_authority, get_pricing_drift_banner_html
— each a caught ImportError and a silently absent feature).

WHAT THIS TESTS THAT `test_package_exports.py` DOES NOT. That suite is REACTIVE:
it parses the repo for `from modules.ai_engine import ...` and fails if a name
does not resolve, so it only fires once a consumer exists. A symbol added to
module.py that nobody imports yet is invisible to it — and that is precisely the
window in which the omission is born. This suite is PROACTIVE: it compares the
two namespaces directly, so the gap is caught at the moment the symbol appears.

Both are needed and neither subsumes the other. They fail in opposite directions.

⚠ THE AST CROSS-CHECK IS THE LOAD-BEARING PART. `__init__._is_local_public()`
decides membership at RUNTIME, using `__module__` for callables and an ALL-CAPS
convention for plain data. That convention is a guess about naming, and a
lowercase module-level constant would silently fall outside it. So this suite
re-derives the same set from the SOURCE with `ast` — a different mechanism, not
the same one re-run — and fails on any disagreement. A test that reused the
runtime filter would agree with itself no matter how wrong it was.

Run:  python3 modules/ai_engine/test_export_completeness.py
Exit: 0 all passed · 1 failure(s) · 3 harness could not establish its premise
"""

import ast
import os
import types as _types
import sys
import tempfile
import traceback

_PASS, _FAIL = [], []
EXPECTED_CHECKS = 18


def check(label, cond, detail=""):
    (_PASS if cond else _FAIL).append(label)
    print(("  [PASS] " if cond else "  [FAIL] ") + label
          + (("  -- " + str(detail)) if detail and not cond else ""))
    return bool(cond)


def _die(msg):
    print("\nHARNESS PRECONDITION FAILED: %s" % msg)
    sys.exit(3)


_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))
os.environ.setdefault("NEMESIS_DB_PATH",
                      os.path.join(tempfile.mkdtemp(prefix="nemesis-exports-"), "t.db"))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

try:
    import modules as _pkg
    _pkg.set_shared_db_path(os.environ["NEMESIS_DB_PATH"])
    from modules import ai_engine as ai
except Exception:
    traceback.print_exc()
    _die("could not import modules.ai_engine")


# ── the independent (AST) derivation ─────────────────────────────────────────
def ast_public_symbols(path):
    """Public top-level symbols DEFINED in `path`, from source.

    Deliberately a different mechanism from the runtime filter it checks:
    definitions only, so an imported name can never be mistaken for a local one,
    and no naming convention is consulted for constants.
    """
    tree = ast.parse(open(path).read())
    out = set()
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if not n.name.startswith("_"):
                out.add(n.name)
        elif isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name) and not t.id.startswith("_"):
                    out.add(t.id)
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
            if not n.target.id.startswith("_"):
                out.add(n.target.id)
    return out


_MODULE_PY = os.path.join(_HERE, "module.py")
if not os.path.exists(_MODULE_PY):
    _die("module.py not found next to this suite")

source_public = ast_public_symbols(_MODULE_PY)
exported = set(ai.__all__)
not_exported = set(ai._NOT_EXPORTED)

print("\n== THE DERIVATION PRODUCED SOMETHING ==")
check("module.py has a plausible number of public symbols (>=40)",
      len(source_public) >= 40, len(source_public))
check("the package exports a plausible number (>=30)", len(exported) >= 30, len(exported))
# CONTROL: an empty or near-empty export set would satisfy every "is absent"
# assertion below, so prove the set is real before trusting anything about it.
check("CONTROL: a known-core symbol is actually exported",
      "effective_ceiling" in exported, sorted(exported)[:8])


print("\n== COMPLETENESS: every public symbol is exported OR justified ==")
unclassified = sorted(source_public - exported - not_exported)
check("no public symbol is silently unexported", not unclassified,
      "add to __init__._NOT_EXPORTED with a reason, or let it export: %s" % unclassified)


print("\n== THE RUNTIME FILTER AGREES WITH THE SOURCE ==")
# The disagreement this catches: a module-level constant that is not ALL-CAPS.
# The runtime filter would drop it; the AST sees it. Reported as a real finding
# rather than papered over, because the fix is to rename it or list it.
#
# Submodules are subtracted, not ignored: they are a SECOND legitimate category
# of export (`from modules.ai_engine import context_store`) that module.py does
# not define and cannot. They are then checked on their own terms below, so
# excluding them here loses no coverage.
submodules = set(ai._SUBMODULE_EXPORTS)
runtime_only = sorted(exported - source_public - submodules)
check("nothing is exported that module.py does not define (submodules aside)",
      not runtime_only, runtime_only)

print("\n== SUBMODULE EXPORTS ARE REAL AND DELIBERATE ==")
check("every declared submodule is importable as a package attribute",
      all(hasattr(ai, m) for m in submodules),
      [m for m in submodules if not hasattr(ai, m)])
check("every declared submodule is actually a module, not a stray name",
      all(isinstance(getattr(ai, m, None), _types.ModuleType) for m in submodules),
      [m for m in submodules if not isinstance(getattr(ai, m, None), _types.ModuleType)])
# CONTROL: a .py file sitting next to __init__ must NOT be public by accident --
# the list is explicit precisely so adding a file is not an API decision.
check("CONTROL: a sibling module NOT on the list is not exported",
      "l4_ab_harness" not in exported,
      "l4_ab_harness became public without being declared")


print("\n== _NOT_EXPORTED IS HONEST ==")
check("every _NOT_EXPORTED name actually exists in module.py",
      not (not_exported - source_public), sorted(not_exported - source_public))
check("no name is both exported and listed as not-exported",
      not (not_exported & exported), sorted(not_exported & exported))
check("every exclusion carries a non-trivial reason",
      all(isinstance(v, str) and len(v) > 40 for v in ai._NOT_EXPORTED.values()),
      [k for k, v in ai._NOT_EXPORTED.items() if not (isinstance(v, str) and len(v) > 40)])


print("\n== IMPORTS DO NOT LEAK INTO THE PACKAGE SURFACE ==")
for _name in ("os", "json", "re", "logging", "datetime", "jsonify"):
    check("module.py's own import %r is not re-exported" % _name, _name not in exported)


print("\n== TOTALS ==")
_total = len(_PASS) + len(_FAIL)
check("assertion count matches EXPECTED_CHECKS (drift is a defect)",
      _total + 1 == EXPECTED_CHECKS, "ran %d, expected %d" % (_total + 1, EXPECTED_CHECKS))

print("\n%d passed, %d failed" % (len(_PASS), len(_FAIL)))
sys.exit(1 if _FAIL else 0)
