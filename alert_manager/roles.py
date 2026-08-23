"""Role-based access control — the decision layer.

No Flask, no DB, no I/O. Every function here is a pure decision about "may a
principal with role R perform method M on endpoint E?", so it can be tested
directly and exhaustively. The enforcement half lives in `dashboard.py`; this
file is what it asks.

THREE ROLES, AND THE DISTINCTIONS ARE REAL
    admin     full control: settings, module enable/disable, user management,
              active/remote-tasking tools, master-password authority actions.
    user      day-to-day operation: view everything, acknowledge and dismiss
              alerts, run read-only diagnostics and lookups. No destructive
              settings changes, no active or remote-tasking tools.
    viewonly  read access to dashboards, alerts and reports. No actions, no
              tool execution of any kind.

    "No tool execution of any kind" is why this module cannot classify by HTTP
    method alone. Several routes in this codebase are GETs that DO things —
    `api_diag_run_all` executes checks, `analyze_alert` spends money on an AI
    call, and `report_abuse` is a GET that POSTs a permanent report to a third
    party. Handing viewonly every GET would hand it all three. Each endpoint
    therefore carries an explicit minimum for safe methods AND for unsafe ones.

WHY THE REGISTRY IS A TABLE AND NOT DECORATORS ALONE
    `require_role` exists and decorating a view registers its minimum. But a
    decorator can only cover routes defined in `dashboard.py`. Module routes are
    registered by `modules_loader` from each module's `get_routes()`, and there
    are ~44 of them across ten modules. A decorator-only design would leave every
    one of them ungated while looking complete — the same failure shape as a
    check that can only return one answer.

    So the registry is the single source of truth, the before-request gate reads
    it for EVERY request including module routes, and the decorator is a
    convenience that writes into the same table. `assert_registry_complete()`
    (called by the test suite against the live url_map) is what makes the table's
    completeness a fact rather than an intention.

FAIL CLOSED, IN BOTH DIRECTIONS
    An unknown endpoint resolves to ADMIN, not to "allow". An unknown or absent
    role resolves to a refusal, not to a default. A new route added without a
    registry entry is therefore admin-only and safe at runtime, and the
    completeness test makes it LOUD at test time — safe by default, but never
    silently so.

    The opposite choice is what makes this class of bug ship: a default that
    "means something" is indistinguishable from a decision, and `role` defaulting
    to 'admin' in the users table (which it does, for the pre-RBAC single-user
    case) would otherwise mean any unparseable role silently became superuser.

WHAT THIS IS NOT
    This is authorization, not the display tier. `static/tier.js`'s
    beginner/intermediate/pro setting controls how much explanation the UI shows,
    lives in browser localStorage, and is a presentation preference the user sets
    for themselves. A role is a server-side security boundary set by an admin.
    They are orthogonal: a beginner-tier admin and a pro-tier viewonly are both
    normal. Never derive one from the other.
"""

import re

__all__ = [
    "ROLE_ADMIN", "ROLE_USER", "ROLE_VIEWONLY", "ROLES", "DEFAULT_ROLE",
    "RoleError", "UnknownRole",
    "normalise_role", "rank", "at_least", "role_label", "role_description",
    "SAFE_METHODS", "required_role", "may", "register_route", "require_role",
    "is_admin", "is_at_least",
    "SELF_SERVICE", "UNAUTHENTICATED",
    "ROUTE_MINIMUMS", "assert_registry_complete", "canary",
]

# ── The roles ────────────────────────────────────────────────────────────────

ROLE_ADMIN = "admin"
ROLE_USER = "user"
ROLE_VIEWONLY = "viewonly"

# Ordered least- to most-privileged. Order is the authority for `rank`; do not
# reorder without understanding that every comparison below depends on it.
ROLES = (ROLE_VIEWONLY, ROLE_USER, ROLE_ADMIN)

_RANK = {name: i for i, name in enumerate(ROLES)}

# What a NEW account gets when an admin does not choose. The least privilege
# that is still useful. Deliberately NOT the users-table column default
# ('admin'), which exists only so a pre-RBAC single-user install keeps working.
DEFAULT_ROLE = ROLE_USER

_LABELS = {
    ROLE_ADMIN: "Administrator",
    ROLE_USER: "Standard user",
    ROLE_VIEWONLY: "View only",
}

_DESCRIPTIONS = {
    ROLE_ADMIN: ("Full control, including settings, modules, user accounts, and "
                 "tools that reach out to other machines."),
    ROLE_USER: ("Day-to-day use: read everything, deal with alerts, and run "
                "look-up tools. Cannot change settings or probe other machines."),
    ROLE_VIEWONLY: ("Can read dashboards, alerts and reports. Cannot change "
                    "anything or run any tool."),
}


class RoleError(Exception):
    """Base for every refusal this module raises."""


class UnknownRole(RoleError):
    """A role string that is not one of ROLES.

    Raised rather than resolved to a default. A role we cannot parse is a role
    we cannot reason about, and the users table defaults `role` to 'admin' — so
    a silent fallback here would promote every unparseable value to superuser.
    """


def normalise_role(raw):
    """Canonicalise a stored role string. Raises UnknownRole — never guesses.

    Tolerant of the shapes a human or an old row can produce (whitespace, case,
    'view-only' vs 'viewonly'), strict about everything else.
    """
    if raw is None:
        raise UnknownRole("no role given")
    text = re.sub(r"[\s_-]+", "", str(raw).strip().lower())
    if not text:
        raise UnknownRole("empty role")
    aliases = {
        "admin": ROLE_ADMIN, "administrator": ROLE_ADMIN, "superuser": ROLE_ADMIN,
        "user": ROLE_USER, "standard": ROLE_USER, "standarduser": ROLE_USER,
        "viewonly": ROLE_VIEWONLY, "readonly": ROLE_VIEWONLY,
        "view": ROLE_VIEWONLY, "reader": ROLE_VIEWONLY,
    }
    try:
        return aliases[text]
    except KeyError:
        raise UnknownRole("%r is not a known role" % (raw,)) from None


def rank(role):
    """Numeric privilege, higher is more. Raises on an unknown role."""
    return _RANK[normalise_role(role)]


def at_least(role, minimum):
    """True if `role` is at or above `minimum`.

    Raises UnknownRole if EITHER side is unparseable. It does not return False
    for a bad minimum: a comparison against a minimum we cannot read is a broken
    question, and answering it "denied" would look like a working check while
    hiding a typo'd role name in the registry forever.
    """
    return rank(role) >= rank(minimum)


def role_label(role):
    return _LABELS[normalise_role(role)]


def role_description(role):
    return _DESCRIPTIONS[normalise_role(role)]


# ── Method classification ────────────────────────────────────────────────────

# RFC 9110 safe methods: no intended state change on the server. HEAD/OPTIONS are
# included because Flask adds them automatically to GET routes, and omitting them
# would make an auto-added HEAD resolve to the UNSAFE minimum — locking viewonly
# out of pages it is explicitly allowed to read.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


# ── The registry ─────────────────────────────────────────────────────────────
#
# endpoint -> (minimum role for SAFE methods, minimum role for UNSAFE methods)
#
# Two entries per endpoint rather than one, because ~12 routes in this codebase
# serve GET and POST from the same view function with genuinely different
# consequences (`/api/backup/schedule`, `/api/ai/settings`, `/api/tickets`, …).
# One minimum per endpoint would have to take the stricter of the two and would
# lock viewonly out of readable settings pages, or take the looser and hand
# viewonly a write.
#
# Where a SAFE method is set ABOVE viewonly, that is deliberate and marked: the
# route is a GET that executes something.

_A, _U, _V = ROLE_ADMIN, ROLE_USER, ROLE_VIEWONLY

ROUTE_MINIMUMS = {
    # ── Pages ────────────────────────────────────────────────────────────────
    "dashboard":                      (_V, _A),
    "diagnostics_page":               (_V, _A),
    "firewall_db":                    (_V, _A),
    "hardware_all_page":              (_V, _A),
    "scan_page":                      (_V, _A),
    "settings_page":                  (_V, _A),
    "licensing_page":                 (_V, _A),

    # ── Read-only status and reporting ───────────────────────────────────────
    "api_stats":                      (_V, _A),
    "api_health_score":               (_V, _A),
    "api_header_status":              (_V, _A),
    "api_dashboard_uptime":           (_V, _A),
    "api_alert_breakdown_24h":        (_V, _A),
    "api_hw_metrics":                 (_V, _A),
    "api_hw_devices":                 (_V, _A),
    "api_hw_history":                 (_V, _A),
    "api_hw_metrics_for_device":      (_V, _A),
    "api_hw_notifications":           (_V, _A),
    "api_hw_snapshot_detail":         (_V, _A),
    "api_quarantines":                (_V, _A),
    "api_review_queue":               (_V, _A),
    "api_throttle_status":            (_V, _A),
    "api_vpn_status":                 (_V, _A),
    "api_firewall_drilldown":         (_V, _A),
    "api_backup_size":                (_V, _A),
    "api_modules":                    (_V, _A),
    "api_agent_rules":                (_V, _A),
    "api_ai_authority":               (_V, _A),
    "api_ai_chat_state":              (_V, _A),
    "api_scan_conditions_get":        (_V, _A),
    "api_scan_devices":               (_V, _A),
    "api_scan_history":               (_V, _A),
    "api_scan_queue_get":             (_V, _A),
    "api_scan_results":               (_V, _A),
    "api_scan_status":                (_V, _A),
    "api_ram_recovery_candidates":    (_V, _A),

    # ── Alert triage — the day-to-day job, hence `user` ───────────────────────
    "set_action":                     (_U, _U),
    "db_action":                      (_U, _U),
    "update_device":                  (_U, _U),
    "api_update_friendly_name":       (_U, _U),

    # ── GETs that EXECUTE. Not viewonly, despite being GETs. ─────────────────
    # Each is a route where the method says "read" and the behaviour says "run".
    # Classifying by method alone would hand every one of these to viewonly.
    "api_diag_run_all":               (_U, _A),   # executes diagnostic checks
    "api_diag_run":                   (_U, _A),   # executes one check
    "analyze_alert":                  (_U, _A),   # spends money on an AI call
    "test_enrichment":                (_U, _A),   # outbound enrichment lookup
    "report_abuse":                   (_A, _A),   # GET that POSTs to AbuseIPDB
    "api_filesystem_browse":          (_A, _A),   # reads the appliance filesystem

    # ── Admin: settings and configuration ────────────────────────────────────
    "api_config_current":             (_A, _A),   # exposes configured values
    "api_config_update":              (_A, _A),
    "api_config_test_email":          (_A, _A),
    "api_config_validate_key":        (_A, _A),
    "api_set_observe_every_n":        (_A, _A),
    # Admin for both methods. It is POST-only, so the safe minimum is unreachable
    # in practice -- set to admin anyway rather than left permissive, because a
    # later GET view added to the same endpoint would otherwise inherit it.
    "api_set_digest_settings":        (_A, _A),
    "api_backup_schedule":            (_A, _A),
    "api_backup_create":              (_A, _A),
    "api_restart":                    (_A, _A),
    "api_ram_recovery_clean":         (_A, _A),   # destroys state

    # ── Admin: modules ───────────────────────────────────────────────────────
    "api_module_enable":              (_A, _A),
    "api_module_disable":             (_A, _A),

    # ── Admin: licensing ─────────────────────────────────────────────────────
    "api_license_activate":               (_A, _A),
    "api_license_backup_codes_generate":  (_A, _A),
    "api_license_backup_codes_redeem":    (_A, _A),
    "api_license_rebind_status":          (_A, _A),

    # ── Admin: agents, consent, and anything that reaches a remote machine ───
    "api_agent_approve":              (_A, _A),
    "api_agent_reject":               (_A, _A),
    "api_agent_revoke":               (_A, _A),
    "api_agent_installer_generate":   (_A, _A),
    "api_agent_notify":               (_A, _A),   # pushes to a remote agent
    "api_consent_status":             (_V, _A),
    "api_consent_grant":              (_A, _A),
    "api_consent_revoke":             (_A, _A),

    # ── Admin: protection-affecting actions ──────────────────────────────────
    # Lifting protection is admin; confirming it stands is day-to-day triage.
    # That asymmetry is deliberate and matches the standing constraint that
    # nothing may quietly reduce coverage.
    "api_quarantine_confirm":         (_U, _U),
    "api_quarantine_lift":            (_A, _A),
    "api_firewall_unblock":           (_A, _A),
    "api_firewall_credential_drop":   (_A, _A),
    "api_vpn_action":                 (_A, _A),
    "api_hw_rediscover":              (_A, _A),
    "api_hw_reset_baseline":          (_A, _A),

    # ── Admin: scanning (tasks devices, including remote agents) ─────────────
    "api_scan_trigger":               (_A, _A),
    "api_scan_schedule":              (_A, _A),
    "api_scan_queue_cancel":          (_A, _A),
    "api_scan_conditions_post":       (_A, _A),
    "api_scan_conditions_delete":     (_A, _A),

    # ── Admin: sends data off-appliance ──────────────────────────────────────
    "api_diag_submit":                (_A, _A),   # emails output externally

    # ── Admin: AI authority (ALSO master-password gated — see below) ─────────
    "api_ai_authority_raise":         (_A, _A),
    "api_ai_chat_ask":                (_U, _U),

    # ── Module routes ────────────────────────────────────────────────────────
    # Endpoint names are `module_<name>_<view_func.__name__>` as generated by
    # modules_loader.py:318 — NOT derived from the URL path. Every name below was
    # read from the live url_map after loading all ten modules, because the first
    # draft of this table guessed them from the paths and got 43 of 45 wrong.
    # `assert_registry_complete()` is what turned that from a silent hole into a
    # failure, and it is the reason it exists.

    # ai_engine
    "module_ai_engine__route_status":               (_V, _A),
    "module_ai_engine__route_usage":                (_V, _A),
    "module_ai_engine__route_settings":             (_V, _A),
    "module_ai_engine__route_automation_readiness": (_V, _A),
    "module_ai_engine__route_upsell_dismiss":       (_U, _U),
    "module_ai_engine__route_upsell_restore":       (_U, _U),
    "module_ai_engine__route_incident":             (_V, _A),
    "module_ai_engine__route_incident_simulate":    (_A, _A),

    # anomaly_detection
    "module_anomaly_detection__api_incidents":        (_V, _A),
    "module_anomaly_detection__api_incident_detail":  (_V, _A),
    "module_anomaly_detection__api_incident_close":   (_U, _U),
    "module_anomaly_detection__api_incident_analyze": (_U, _U),
    "module_anomaly_detection__api_anomaly_settings": (_V, _A),
    "module_anomaly_detection__api_anomaly_usage":    (_V, _A),

    # community_queue — `api_submit` publishes outward, hence admin.
    "module_community_queue__page_community_queue": (_V, _A),
    "module_community_queue__api_rows":             (_V, _A),
    "module_community_queue__api_analyse":          (_U, _U),
    "module_community_queue__api_submit":           (_A, _A),
    "module_community_queue__api_dismiss":          (_U, _U),

    # diagnostics
    "module_diagnostics__api_status":   (_V, _A),
    "module_diagnostics__api_settings": (_V, _A),

    # lookup — read-only investigation, so `user` may run it but viewonly may not
    # (viewonly is "no tool execution of any kind"). The two constant-serving
    # GETs are viewonly-readable so the card renders for everyone.
    "module_lookup__api_lookup":     (_U, _U),
    "module_lookup__api_rrtypes":    (_V, _V),
    "module_lookup__api_tls":        (_U, _U),
    "module_lookup__api_tls_ports":  (_V, _V),

    # netprobe — ACTIVE, reaches other machines. Admin for both probes, per the
    # operator decision that active/remote-tasking tools are admin-only. The
    # inventory restriction inside the module stays in force: this is a second,
    # independent gate, not a replacement for it.
    "module_netprobe__api_ping":     (_A, _A),
    "module_netprobe__api_trace":    (_A, _A),
    "module_netprobe__api_targets":  (_U, _A),

    # malware_detection — quarantine and scan reach a device, hence admin;
    # setting a finding's status is triage, hence user.
    "module_malware_detection__api_findings":           (_V, _A),
    "module_malware_detection__api_finding_detail":     (_V, _A),
    "module_malware_detection__api_finding_quarantine": (_A, _A),
    "module_malware_detection__api_finding_status":     (_U, _U),
    "module_malware_detection__api_scan":               (_A, _A),
    "module_malware_detection__api_scan_status":        (_V, _A),
    "module_malware_detection__api_canary_check":       (_U, _U),
    "module_malware_detection__api_settings":           (_V, _A),
    "module_malware_detection__api_yara_status":        (_V, _A),
    "module_malware_detection__api_yara_update":        (_A, _A),

    # tickets — reading is viewonly; creating and annotating is day-to-day work.
    "module_tickets__page_tickets":            (_V, _A),
    "module_tickets__api_tickets_list_create": (_V, _U),
    "module_tickets__api_ticket_detail":       (_V, _U),
    "module_tickets__api_ticket_notes":        (_V, _U),
    "module_tickets__api_ticket_related":      (_V, _A),
    "module_tickets__api_ticket_search":       (_V, _A),
    "module_tickets__api_ticket_settings":     (_V, _A),

    # ── User management (new — see dashboard.py) ─────────────────────────────
    "users_page":                     (_A, _A),
    "api_users_list":                 (_A, _A),
    "api_users_create":               (_A, _A),
    "api_users_update":               (_A, _A),
    "api_users_delete":               (_A, _A),
    "api_users_roles":                (_A, _A),
}

# Reachable by ANY authenticated principal, whatever their role. These are not
# "unprotected" — they are self-service, and gating them by role would be a bug:
# a viewonly user locked out of changing their own password, or out of logging
# out, is a worse security posture, not a better one.
SELF_SERVICE = frozenset({
    "change_password",
    "recovery_codes_page",
    "account_unlock",
    "api_session_touch",
    "logout",
})

# Reachable with NO session at all. This MIRRORS dashboard.py's `_AUTH_EXEMPT`
# and must stay in step with it; `assert_registry_complete` checks that it does,
# so a route exempted from auth but not listed here (or the reverse) is a test
# failure rather than a silent hole.
UNAUTHENTICATED = frozenset({
    "setup", "login", "login_recovery", "api_passphrase_generate", "static",
    "install_windows_download", "install_windows_exe", "install_windows_zip",
    "install_windows_start", "api_health",
})


def register_route(endpoint, safe_min, unsafe_min=None):
    """Add or override one registry entry. Used by the `require_role` decorator.

    Overwriting an existing entry is allowed but never silent to a reader: the
    registry literal above is the documented source of truth, and anything that
    changes it at import time should be visible in the decorated view.
    """
    unsafe_min = safe_min if unsafe_min is None else unsafe_min
    ROUTE_MINIMUMS[endpoint] = (normalise_role(safe_min),
                                normalise_role(unsafe_min))
    return ROUTE_MINIMUMS[endpoint]


def required_role(endpoint, method="GET"):
    """The minimum role for this endpoint+method. Unknown endpoint -> ADMIN.

    Fail closed. An endpoint with no entry is treated as the most privileged
    thing it could be, so forgetting an entry denies access rather than granting
    it. `assert_registry_complete()` turns that silent safety into a loud test
    failure, which is the half that keeps "safe" from meaning "broken".
    """
    entry = ROUTE_MINIMUMS.get(endpoint)
    if entry is None:
        return ROLE_ADMIN
    safe_min, unsafe_min = entry
    return safe_min if str(method).upper() in SAFE_METHODS else unsafe_min


def may(role, endpoint, method="GET"):
    """May a principal with `role` call `endpoint` with `method`?

    Returns a bool for a KNOWN role. Raises UnknownRole for an unparseable one
    rather than returning False — see `at_least`.
    """
    if endpoint in UNAUTHENTICATED or endpoint in SELF_SERVICE:
        return True
    return at_least(role, required_role(endpoint, method))


def is_at_least(role, minimum):
    """Non-raising variant for TEMPLATE and UI use only.

    Returns False for an unparseable role instead of raising, because a card
    should not 500 the whole dashboard over a bad role string. Never use this to
    make an enforcement decision — enforcement wants the exception, so a bad role
    is loud rather than quietly rendering a smaller page.
    """
    try:
        return at_least(role, minimum)
    except RoleError:
        return False


def is_admin(role):
    """Convenience for the common check. Non-raising, UI-safe."""
    return is_at_least(role, ROLE_ADMIN)


def require_role(minimum, unsafe_minimum=None):
    """Decorator: declare a view's minimum role, and register it.

    Enforcement does NOT depend on this decorator — the before-request gate
    reads the registry for every request, so module routes (which cannot be
    decorated from here) are covered too. The decorator exists so a view in
    dashboard.py can state its own requirement next to its code, and so that
    statement lands in the same single table.
    """
    def deco(fn):
        register_route(fn.__name__, minimum, unsafe_minimum)
        fn._nemesis_min_role = (normalise_role(minimum),
                                normalise_role(unsafe_minimum
                                               if unsafe_minimum is not None
                                               else minimum))
        return fn
    return deco


def assert_registry_complete(endpoints):
    """Every real endpoint is classified, and every classification is real.

    Raises RoleError listing BOTH directions:

      * an endpoint with no entry — safe at runtime (it resolves to admin) but
        almost certainly an oversight, and an admin-only route nobody meant to
        create looks exactly like a broken feature;
      * an entry for an endpoint that does not exist — a typo, which is worse
        than useless: it reads as coverage while protecting nothing. This is the
        `_AUTH_EXEMPT` failure mode from 2026-08-02 in the other direction.

    `endpoints` is the live set from `app.url_map`, so this measures reality
    rather than a second hand-maintained list.
    """
    known = set(endpoints)
    classified = set(ROUTE_MINIMUMS) | SELF_SERVICE | UNAUTHENTICATED
    missing = sorted(known - classified)
    phantom = sorted(classified - known)
    problems = []
    if missing:
        problems.append("%d endpoint(s) with no role assigned (they resolve to "
                        "admin, which is safe but probably not intended): %s"
                        % (len(missing), ", ".join(missing)))
    if phantom:
        problems.append("%d registry entr(ies) naming an endpoint that does not "
                        "exist (a typo protects nothing while looking like "
                        "coverage): %s" % (len(phantom), ", ".join(phantom)))
    if problems:
        raise RoleError(" | ".join(problems))
    return True


# ── Canary ───────────────────────────────────────────────────────────────────

def _load_harness():
    import importlib.util
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(os.path.dirname(here), "diagnostics", "canary.py")
    spec = importlib.util.spec_from_file_location("nemesis_roles_canary", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_H = _load_harness()


def _raises(fn, exc=RoleError):
    try:
        fn()
        return False
    except exc:
        return True
    except Exception:                                          # noqa: BLE001
        return False


_CASES = [
    # Ordering is the foundation everything else rests on.
    _H.bad("admin outranks user",
           lambda: at_least(ROLE_ADMIN, ROLE_USER) or None),
    _H.bad("user outranks viewonly",
           lambda: at_least(ROLE_USER, ROLE_VIEWONLY) or None),
    _H.bad("viewonly does NOT reach user",
           lambda: (not at_least(ROLE_VIEWONLY, ROLE_USER)) or None),
    _H.bad("user does NOT reach admin",
           lambda: (not at_least(ROLE_USER, ROLE_ADMIN)) or None),
    _H.good("CONTROL: the ordering is not vacuously true both ways",
            lambda: at_least(ROLE_VIEWONLY, ROLE_ADMIN) or None),

    # An unparseable role must never resolve to anything.
    _H.bad("an unknown role raises rather than defaulting",
           lambda: _raises(lambda: normalise_role("wizard")) or None),
    _H.bad("None raises rather than defaulting",
           lambda: _raises(lambda: normalise_role(None)) or None),
    _H.bad("empty raises rather than defaulting",
           lambda: _raises(lambda: normalise_role("   ")) or None),
    _H.bad("a bad MINIMUM raises too, not a quiet False",
           lambda: _raises(lambda: at_least(ROLE_ADMIN, "supervisor")) or None),
    _H.good("CONTROL: a real role does NOT raise",
            lambda: _raises(lambda: normalise_role("admin")) or None),

    # Unknown endpoints fail closed.
    _H.bad("an unregistered endpoint requires admin",
           lambda: (required_role("no_such_endpoint_at_all") == ROLE_ADMIN) or None),
    _H.bad("...so viewonly cannot reach it",
           lambda: (not may(ROLE_VIEWONLY, "no_such_endpoint_at_all")) or None),
    _H.bad("...and neither can user",
           lambda: (not may(ROLE_USER, "no_such_endpoint_at_all")) or None),

    # Safe vs unsafe methods resolve differently where it matters.
    _H.bad("viewonly may GET a settings page",
           lambda: may(ROLE_VIEWONLY, "settings_page", "GET") or None),
    _H.bad("viewonly may NOT POST to it",
           lambda: (not may(ROLE_VIEWONLY, "settings_page", "POST")) or None),
    _H.bad("HEAD is treated as safe, not as a write",
           lambda: may(ROLE_VIEWONLY, "dashboard", "HEAD") or None),
    _H.bad("an unrecognised method is treated as UNSAFE",
           lambda: (not may(ROLE_VIEWONLY, "dashboard", "FROB")) or None),

    # The GETs that execute must not be readable by viewonly.
    _H.bad("viewonly cannot run diagnostics (a GET that executes)",
           lambda: (not may(ROLE_VIEWONLY, "api_diag_run_all", "GET")) or None),
    _H.bad("viewonly cannot trigger an AI analysis (a GET that spends)",
           lambda: (not may(ROLE_VIEWONLY, "analyze_alert", "GET")) or None),
    _H.bad("viewonly cannot file an abuse report (a GET that POSTs outward)",
           lambda: (not may(ROLE_VIEWONLY, "report_abuse", "GET")) or None),
    _H.bad("...and neither can a plain user file one",
           lambda: (not may(ROLE_USER, "report_abuse", "GET")) or None),
    _H.bad("CONTROL: a user CAN run diagnostics (so the denials above are "
           "discrimination, not blanket refusal)",
           lambda: may(ROLE_USER, "api_diag_run_all", "GET") or None),

    # Active tooling is admin-only.
    _H.bad("user cannot ping (active, reaches another machine)",
           lambda: (not may(ROLE_USER, "module_netprobe__api_ping", "POST")) or None),
    _H.bad("viewonly cannot ping either",
           lambda: (not may(ROLE_VIEWONLY, "module_netprobe__api_ping", "POST")) or None),
    _H.bad("user CAN use the read-only lookup tool",
           lambda: may(ROLE_USER, "module_lookup__api_lookup", "POST") or None),
    _H.bad("viewonly canNOT use even the read-only lookup tool",
           lambda: (not may(ROLE_VIEWONLY, "module_lookup__api_lookup", "POST")) or None),
    _H.bad("CONTROL: admin CAN ping (the denials above are not a dead route)",
           lambda: may(ROLE_ADMIN, "module_netprobe__api_ping", "POST") or None),

    # Day-to-day triage is genuinely available to `user`.
    _H.bad("user can act on an alert",
           lambda: may(ROLE_USER, "db_action", "POST") or None),
    _H.bad("viewonly cannot act on an alert",
           lambda: (not may(ROLE_VIEWONLY, "db_action", "POST")) or None),
    _H.bad("user canNOT change settings",
           lambda: (not may(ROLE_USER, "api_config_update", "POST")) or None),
    _H.bad("user canNOT enable or disable a module",
           lambda: (not may(ROLE_USER, "api_module_disable", "POST")) or None),
    _H.bad("user canNOT manage accounts",
           lambda: (not may(ROLE_USER, "api_users_create", "POST")) or None),

    # Protection may be confirmed by a user but only lifted by an admin.
    _H.bad("user may confirm a quarantine",
           lambda: may(ROLE_USER, "api_quarantine_confirm", "POST") or None),
    _H.bad("user may NOT lift one",
           lambda: (not may(ROLE_USER, "api_quarantine_lift", "POST")) or None),
    _H.bad("user may NOT unblock a firewall entry",
           lambda: (not may(ROLE_USER, "api_firewall_unblock", "POST")) or None),

    # Self-service must survive any role, or viewonly is locked out of its own
    # account.
    _H.bad("viewonly can change its OWN password",
           lambda: may(ROLE_VIEWONLY, "change_password", "POST") or None),
    _H.bad("viewonly can log out",
           lambda: may(ROLE_VIEWONLY, "logout", "GET") or None),
    _H.bad("viewonly can touch its session",
           lambda: may(ROLE_VIEWONLY, "api_session_touch", "POST") or None),

    # Unauthenticated routes are role-independent.
    _H.bad("the login page needs no role",
           lambda: may(ROLE_VIEWONLY, "login", "POST") or None),
    _H.bad("the health endpoint needs no role",
           lambda: may(ROLE_VIEWONLY, "api_health", "GET") or None),

    # The registry itself must be well-formed.
    _H.bad("every registry entry names two KNOWN roles",
           lambda: (all(s in _RANK and u in _RANK
                        for s, u in ROUTE_MINIMUMS.values())) or None),
    _H.bad("no endpoint is in two categories at once",
           lambda: (not (set(ROUTE_MINIMUMS) & (SELF_SERVICE | UNAUTHENTICATED))
                    and not (SELF_SERVICE & UNAUTHENTICATED)) or None),
    _H.bad("the safe minimum is never STRICTER than the unsafe one",
           lambda: (all(_RANK[s] <= _RANK[u]
                        for s, u in ROUTE_MINIMUMS.values())) or None),
    _H.bad("the registry is not trivially small",
           lambda: (len(ROUTE_MINIMUMS) > 100) or None),
    _H.good("CONTROL: not every route is admin-only",
            lambda: (all(s == ROLE_ADMIN for s, _u in ROUTE_MINIMUMS.values()))
                    or None),
    _H.good("CONTROL: not every route is viewonly",
            lambda: (all(s == ROLE_VIEWONLY for s, _u in ROUTE_MINIMUMS.values()))
                    or None),

    # Labels exist for every role, or the UI renders a blank selector.
    _H.bad("every role has a label and a description",
           lambda: (all(role_label(r) and role_description(r) for r in ROLES))
                   or None),
    _H.bad("the default role for a new account is not admin",
           lambda: (DEFAULT_ROLE != ROLE_ADMIN) or None),
]


def canary():
    """Run the self-test. Returns (ok, detail)."""
    return _H.run_cases(_CASES)


def _assert_canary_at_import():
    ok, detail = canary()
    if not ok:
        raise RuntimeError("roles.py canary FAILED: %s" % detail)


_assert_canary_at_import()
