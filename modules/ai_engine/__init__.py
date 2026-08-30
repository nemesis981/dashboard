# ⚠ READ THIS BEFORE ADDING A NAME TO module.py THAT ANYTHING ELSE IMPORTS.
#
# THE RECURRING DEFECT, four times now: a bare `except` around an import turns a
# MISSING EXPORT into a feature that looks switched off. Consumers import from
# this PACKAGE, and registration sites wrap the import in try/except so one module
# cannot take the app down -- so a name that is in `module.py` but absent from the
# list below fails, gets logged, and is ignored. Nothing crashes. The capability
# is simply gone.
#
#   2026-08-04  anchors  -> every chat affordance unregistered
#   2026-08-23  register_undo_handler / undo_handler_for -> three L2 classes had
#               no undo handler, and the engine REFUSES to act at L2 without one:
#               the whole reversible-action tier was inert
#   2026-08-23  raise_authority -> /api/ai/authority/raise returned 503 on every
#               call; the ladder could not be raised at all
#   2026-08-23  get_pricing_drift_banner_html -> the operator never saw a drift
#
# The general form, worth carrying beyond this file: AN IMPORT THAT FAILS IS A
# FINDING EVEN WHEN IT IS NOT THE FINDING YOU ARE CHASING. A caught ImportError
# means a name that was supposed to exist does not, and the blast radius is never
# visible from the exception itself.
#
# `test_package_exports.py` now enforces this at the package boundary: it parses
# every repo file for `from modules.ai_engine import ...` and fails if any name
# does not resolve. A comment predicting this failure existed from 2026-08-04 and
# did not prevent its recurrence -- which is why there is a test as well.
# ─────────────────────────────────────────────────────────────────────────────
# EXPORTS ARE DERIVED, NOT MAINTAINED (2026-08-30)
#
# The hand-written list this replaces was the MECHANISM of the four defects
# above, not merely where they were noticed: adding a symbol to `module.py`
# required remembering to add it here too, and forgetting produced a caught
# ImportError and a silently absent feature. A list that must be kept in step by
# memory desynchronises by default.
#
# So the list is now COMPUTED from `module.py`'s own public surface. A new public
# symbol is exported automatically; there is nothing left to under-populate.
# Keeping one internal now requires NAMING it in `_NOT_EXPORTED` with a reason.
#
# WHY THAT SHAPE, specifically: absence used to mean three different things at
# once -- "deliberately internal", "not needed yet", and "forgotten" -- and
# nothing could tell them apart. That is the same failure `BASE_LOOPBACK_ONLY_
# ACTIONS` exists to fix in `nemesis_agent/tasks.py`, in its own words: *"an
# absence cannot record a decision, so a future reader finding one could only
# guess whether it was intent or an oversight."* Same argument, applied to the
# package boundary.
#
# ⚠ THIS WIDENS THE PACKAGE SURFACE, deliberately, and that is a real tradeoff.
# Measured 2026-08-30: `module.py` had 70 public symbols, 40 were exported, and
# NONE of the other 30 had a single real consumer outside this package -- the
# three apparent hits were comment mentions. The curation was therefore doing no
# work for any caller; it was only a source of omissions. `modules.ai_engine` is
# an internal application package, not a published library, so a wider surface
# costs little. What it costs is signal about what is "supported", which is why
# `_NOT_EXPORTED` still exists rather than exporting everything unconditionally.
#
# `test_package_exports.py` is UNCHANGED and still runs -- it catches the other
# direction (a name imported somewhere that does not resolve).
# `test_export_completeness.py` is the new backstop for this file's own logic.
# ─────────────────────────────────────────────────────────────────────────────

import types as _types

from . import module as _module

# ⚠ SUBMODULES ARE PART OF THE PACKAGE'S API TOO, and the derive logic below
# cannot supply them: `_is_local_public()` excludes every ModuleType (to stop
# `os`, `json` and friends leaking), which excludes these along with them.
#
# Consumers really do import them by name -- `from modules.ai_engine import
# context_store` appears in module.py, failsafe_decision.py, l4_ab_harness.py and
# three suites. They resolved before this rewrite only as a SIDE EFFECT of the
# old `from .module import (...)` line, which is not something to depend on.
#
# Found by `test_package_exports.py` on the first run after the rewrite — the
# reactive suite catching what the proactive one structurally cannot, which is
# the reason both exist.
from . import context_store, failsafe_decision, prefilter  # noqa: F401

#: Submodules re-exported by name. Listed explicitly rather than discovered, so
#: adding a submodule is a deliberate act: a new .py file next to this one does
#: not silently become public API.
_SUBMODULE_EXPORTS = ("context_store", "failsafe_decision", "prefilter")

#: Public symbols in `module.py` that are deliberately NOT part of the package's
#: API, each with the reason. Anything not listed here is exported.
#:
#: A name belongs here only if a consumer outside this package has no legitimate
#: use for it. "Nobody happens to call it yet" is NOT a reason -- that is exactly
#: the state that used to be indistinguishable from an oversight.
_NOT_EXPORTED = {
    "Module": (
        "the NemesisModule subclass. `modules_loader` resolves it from the module "
        "OBJECT by convention and never imports this name; exporting it would put "
        "a second, importable path to the class next to the loader's contract."
    ),
    "log_decision": (
        "the engine writes its own decision trail as it works. A caller outside "
        "the package logging a decision on the engine's behalf would be recording "
        "a reasoning step that never happened. The READER, `decision_trail`, is "
        "exported -- reading the trail is a legitimate outside concern, appending "
        "to it is not."
    ),
    "new_trace_id": (
        "minted at INGEST, before the pre-filter, so the id covers work the "
        "caller has not started. A caller minting its own would produce a trace "
        "that does not correspond to an engine run."
    ),
    "log": (
        "module.py's own `logging.Logger`. Found by the AST cross-check on this "
        "suite's first run: the runtime filter already excluded it (its "
        "`__module__` is `logging`, not this module), but it IS a public "
        "top-level assignment, so leaving it unlisted would have left one symbol "
        "in the 'silently unclassified' state this map exists to abolish. A "
        "caller wanting to log should take its own logger, not this one."
    ),
    "assert_no_action_class_disables_a_detector": (
        "a structural self-check over this module's own tables, invoked by the "
        "engine and its suites. It asserts an internal invariant and has no "
        "meaning to a caller that cannot violate it."
    ),
}

#: ⚠ FLAGGED AS GENUINELY UNCERTAIN (2026-08-30), exported pending a decision.
#: Recorded rather than resolved by guess, per the same reasoning as
#: `_NOT_EXPORTED` itself -- a silent judgement call is the thing this file is
#: meant to stop.
#:
#:   PROMOTION_THRESHOLD -- a tuning constant ("named so it is one edit to
#:     tune"), which argues internal. But a UI that says "3 more approvals to
#:     promote" would need it, which argues exported. Exported for now because a
#:     read-only constant grants nothing.
_UNCERTAIN = ("PROMOTION_THRESHOLD",)


def _is_local_public(name, obj):
    """Is `name` a public symbol DEFINED in module.py (not one of its imports)?

    Imports are the trap here: `dir(module)` includes `os`, `json`, `jsonify` and
    everything else module.py imported, and re-exporting those would make the
    package's surface meaningless. Filtered two ways because one is not enough:
      * anything that IS a module (os, json, re) is excluded outright;
      * anything carrying a `__module__` must name THIS module -- that catches
        imported functions and classes (`datetime`, `jsonify`) which are not
        module objects and would otherwise slip through.
    Plain data has no `__module__`; ALL-CAPS is this file's convention for a
    module-level constant, and the completeness test cross-checks that rule
    against the AST so a lowercase constant cannot be silently dropped.
    """
    if name.startswith("_"):
        return False
    if isinstance(obj, _types.ModuleType):
        return False
    owner = getattr(obj, "__module__", None)
    if owner is not None:
        return owner == _module.__name__
    return name.isupper()


def _derive_exports():
    return sorted(
        n for n in dir(_module)
        if _is_local_public(n, getattr(_module, n)) and n not in _NOT_EXPORTED
    )


__all__ = _derive_exports() + list(_SUBMODULE_EXPORTS)

for _n in _derive_exports():
    globals()[_n] = getattr(_module, _n)
del _n
