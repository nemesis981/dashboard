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
)

__all__ = [
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
]
