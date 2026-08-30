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
from .module import (
    is_enabled, get_status, analyze, get_usage_stats, get_pricing,
    get_settings,
    get_upsell_prompt_html, get_upsell_js,
    get_incident_state, is_auto_blocked,
    get_incident_banner_html, get_incident_js,
    # Graduated authority + contextual chat. These MUST be re-exported here:
    # every anchor registration imports from the package, not the submodule, and
    # each one is wrapped in a try/except so a module cannot be taken down by a
    # registration failure. That means a missing export does not crash anything
    # -- it silently leaves every chat affordance unregistered, which looks
    # exactly like "the feature is off". Caught 2026-08-04 by a render check.
    effective_ceiling, ACTION_CLASS_CEILINGS,
    UnknownActionClass, AuthorityUnavailable,
    L0_OBSERVE, L1_RECOMMEND, L2_ACT_REVERSIBLE, L3_ACT_DISRUPTIVE, L4_GOVERN,
    register_anchor, registered_anchors,
    ask_followup, get_chat_state, estimate_question_cost,
    get_chat_widget_html, get_chat_js,
    # ADDED 2026-08-23 — and this omission was not cosmetic. `register_undo_handler`
    # existed in module.py but was never re-exported, so dashboard.py's registration
    # block raised ImportError and was swallowed by its own try/except. Three L2
    # classes -- alert_disposition, ip_quarantine_external, ip_block_permanent --
    # had NO undo handler, and `_undo_warnings` refuses to act at L2 without one.
    # The entire reversible-action tier was inert. Exactly the failure the comment
    # above predicts for anchors, in a different symbol, ~3 weeks later.
    register_undo_handler, undo_handler_for,
    # Found 2026-08-23 by test_package_exports.py on its FIRST run -- two more of
    # the same class, neither of them cosmetic:
    #   raise_authority              — backs /api/ai/authority/raise. The import
    #     failed, so the route returned 503 "ai_engine unavailable" on EVERY call
    #     and the ladder could not be raised at all.
    #   get_pricing_drift_banner_html — the drift banner was swallowed by a bare
    #     `except Exception: pass`, so the operator never saw a pricing change.
    raise_authority, get_pricing_drift_banner_html,
    # ADDED 2026-08-30 with the L1 wiring — the FOURTH instance of this exact
    # omission class, and the pattern is now unmistakable: a symbol added to
    # module.py is not usable by dashboard.py until it is re-exported here, and
    # the failure is an ImportError swallowed by whatever try/except surrounds
    # the call site. The proposal loop is the ladder's L1 rung; without these
    # five names its first production writer could not import the function it
    # exists to call.
    create_proposal, get_proposal, list_proposals,
    respond_to_proposal, execute_proposal,
    #   clear_authority_override — backs /api/ai/authority/clear, the OFF half of
    #     the standing toggle. Added 2026-08-27: `raise` shipped 2026-08-23 with no
    #     counterpart, so an authority grant could be made through the UI and then
    #     only withdrawn by editing the database. The module's own docstring says
    #     "LOWERING authority is always allowed, by anyone" -- nothing implemented
    #     it. That asymmetry matters most at L4, which governs unattended action.
    clear_authority_override,
)
# ADDED 2026-08-27 — the L4 accumulating context store (DESIGN-L4 §4). Caught by
# test_package_exports.py on the very first run after the file was created: the
# FIFTH instance of this exact defect. Imported as a SUBMODULE rather than
# individual names because consumers want `context_store.retrieve(...)`, and the
# store's own `_conn()` defers `from modules import get_data_manager` to call
# time, so binding it here creates no import cycle.
from . import context_store  # noqa: E402,F401
# ADDED 2026-08-27 alongside context_store, for the same reason and pre-emptively
# this time: the engine side of the ADR 0019 failsafe decision request. Exported
# as a submodule so a consumer reaches `failsafe_decision.decide(...)` through
# the package, the way every other consumer here reaches ai_engine.
from . import failsafe_decision  # noqa: E402,F401

__all__ = [
    "context_store",
    "failsafe_decision",
    "is_enabled", "get_status", "analyze", "get_usage_stats", "get_pricing",
    "get_settings",
    "get_upsell_prompt_html", "get_upsell_js",
    "get_incident_state", "is_auto_blocked",
    "get_incident_banner_html", "get_incident_js",
    "effective_ceiling", "ACTION_CLASS_CEILINGS",
    "UnknownActionClass", "AuthorityUnavailable",
    "L0_OBSERVE", "L1_RECOMMEND", "L2_ACT_REVERSIBLE", "L3_ACT_DISRUPTIVE", "L4_GOVERN",
    "register_anchor", "registered_anchors",
    "ask_followup", "get_chat_state", "estimate_question_cost",
    "get_chat_widget_html", "get_chat_js",
    "register_undo_handler", "undo_handler_for",
    "raise_authority", "get_pricing_drift_banner_html",
    "clear_authority_override",
    "create_proposal", "get_proposal", "list_proposals",
    "respond_to_proposal", "execute_proposal",
]
