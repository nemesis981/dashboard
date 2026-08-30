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
ROLE_SUB_ADMIN = "sub_admin"
ROLE_USER = "user"
ROLE_VIEWONLY = "viewonly"

# Ordered least- to most-privileged. Order is the authority for `rank`; do not
# reorder without understanding that every comparison below depends on it.
#
# SUB_ADMIN INSERTED 2026-08-23 (ADR 0026 D1), between user and admin. The
# insertion is deliberately ADDITIVE — it does not change what any existing role
# may do:
#
#   * an entry whose minimum is `admin` still excludes sub_admin (3 > 2), which is
#     correct: a sub-admin reaches those routes only by unlocking the capability
#     that covers them, never by rank alone;
#   * an entry whose minimum is `user` or `viewonly` admits sub_admin, which is
#     also correct — a sub-admin is at least an ordinary user.
#
# So no per-entry review of the registry was required, and none was done by hand.
# That property is ASSERTED rather than assumed: the canary below pins every
# existing role's answer for every registry entry against the pre-insertion
# ranking, so a future reorder that silently changed one cannot pass.
ROLES = (ROLE_VIEWONLY, ROLE_USER, ROLE_SUB_ADMIN, ROLE_ADMIN)

_RANK = {name: i for i, name in enumerate(ROLES)}

# What a NEW account gets when an admin does not choose. The least privilege
# that is still useful. Deliberately NOT the users-table column default
# ('admin'), which exists only so a pre-RBAC single-user install keeps working.
DEFAULT_ROLE = ROLE_USER

_LABELS = {
    ROLE_ADMIN: "Administrator",
    ROLE_SUB_ADMIN: "Delegated operator",
    ROLE_USER: "Standard user",
    ROLE_VIEWONLY: "View only",
}

_DESCRIPTIONS = {
    ROLE_ADMIN: ("Full control, including settings, modules, user accounts, and "
                 "tools that reach out to other machines."),
    # Deliberately describes what they can EARN, not what they hold. A sub-admin
    # with no unlocks is exactly a standard user, and the label would otherwise
    # promise access the account does not have.
    ROLE_SUB_ADMIN: ("Everything a standard user can do, plus any powerful tools "
                     "they have earned by completing that tool's training. Starts "
                     "with none of them."),
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
    # Note the normalisation above strips [\s_-], so "sub_admin", "sub-admin" and
    # "Sub Admin" all arrive here as "subadmin". Listing the punctuated spellings
    # would be dead code, not extra safety.
    aliases = {
        "admin": ROLE_ADMIN, "administrator": ROLE_ADMIN, "superuser": ROLE_ADMIN,
        "subadmin": ROLE_SUB_ADMIN, "delegated": ROLE_SUB_ADMIN,
        "delegatedoperator": ROLE_SUB_ADMIN,
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
    # ⚠ THESE FOUR BECAME POST-ONLY ON 2026-08-25 (the GET-that-acts CSRF fix), AND
    # THAT SILENTLY CHANGED WHICH HALF OF THE PAIR APPLIES. Each was (_U, _A): user for
    # the safe method, admin for the unsafe one. While they were GET-only, `_U` was the
    # effective minimum and `_A` was an unreachable placeholder for a POST that did not
    # exist. Converting the method promoted them to admin-only and locked every plain
    # user out of running a diagnostic -- caught by test_roles' "user CAN run
    # diagnostics" control, which is exactly what that control is for.
    #
    # Set to (_U, _U) to PRESERVE the access these routes have always granted. The CSRF
    # fix is about the method, not about who may call them; changing both at once would
    # have been two variables in one pass, and the access change would have shipped as
    # an invisible side effect of a security fix.
    "api_diag_run_all":               (_U, _U),   # executes diagnostic checks (POST-only)
    "api_diag_run":                   (_U, _U),   # executes one check (POST-only)
    "analyze_alert":                  (_U, _U),   # spends money on an AI call (POST-only)
    "test_enrichment":                (_U, _U),   # outbound enrichment lookup (POST-only)
    # These two were admin on BOTH halves already, so the conversion changed nothing.
    "report_abuse":                   (_A, _A),   # POSTs a permanent report to AbuseIPDB
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
    # Revoking an enrollment token is the same class of action as minting one —
    # it acts on a credential that grants a machine access — so it carries the
    # same admin floor as its sibling above. Deliberately NOT looser on the
    # reasoning that "revoking is safe": a caller who can revoke arbitrary tokens
    # can deny enrollment to every pending install.
    "api_agent_installer_revoke":     (_A, _A),
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
    # ADMIN, same as its sibling above — and the reasoning is worth stating
    # because the two routes are deliberately asymmetric elsewhere. Clearing
    # needs no MASTER PASSWORD (lowering authority removes risk, so demanding a
    # second credential to undo a grant would be backwards), but it is still a
    # change to authority configuration on the same object, and two routes
    # configuring one thing at different ROLE minimums is the divergence shape
    # the route-audit practice looks for. The credential asymmetry already
    # carries the risk difference; the role gate need not carry it twice.
    "api_ai_authority_clear":         (_A, _A),
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

    # lan_integrity — read side is VIEWONLY: which DHCP servers answered on your
    # own LAN is network-health information, not private content, and the whole
    # point of the card is that a non-expert sees the warning. The two WRITE
    # routes are ADMIN, and `_api_pin` especially so: pinning a server declares it
    # legitimate, which SUPPRESSES future findings about it. That is a
    # detection-disabling action wearing the clothes of a settings change, so it
    # gets the same gate as any other security-default change.
    "module_lan_integrity__api_status":   (_V, _A),
    "module_lan_integrity__api_servers":  (_V, _A),
    "module_lan_integrity__api_findings": (_V, _A),
    "module_lan_integrity__api_pin":      (_A, _A),
    "module_lan_integrity__api_close":    (_A, _A),

    # email_security — BOTH admin, which is stricter than the dominant
    # (viewonly, admin) shape here, deliberately:
    #   * the quarantine LIST is not neutral metadata. It exposes who emails the
    #     operator, what was blocked and why — private-mail detail. A viewonly
    #     account reading lookup's RR-type constants is not comparable, so the
    #     read side is admin too.
    #   * RELEASE is a state change on quarantined mail, matching the
    #     malware_detection quarantine precedent below, which is admin on both.
    # This makes the CURRENT behaviour deliberate rather than changing it: both
    # endpoints already resolved to admin via the unclassified fail-closed path.
    # ADR 0028 D7's reasoning applies — collapsing distinct cases into one policy
    # over- or under-serves, and that holds for the roles reaching them too.
    "module_email_security_api_quarantine_list": (_A, _A),
    "module_email_security_api_release":         (_A, _A),
    # ADR 0028 D11.5 Option C: the ADMIN-side half. Capability-gated (D11.6) so a
    # sub_admin may hold it. GET is unused; both slots are admin so a stray GET
    # cannot become a read side-channel.
    "module_email_security_api_enroll_create":   (_A, _A),

    # ai_engine §4.5 review surface — "what your AI has learned" (DESIGN-L4 §4).
    # ADMIN ON BOTH VERBS, INCLUDING READ, and that is deliberate:
    #   * REVOKE is not merely a delete. Revoking a RESTRICTIVE entry LOOSENS
    #     the system, which is the same class of act as granting authority — so
    #     it belongs at the same bar as the grant itself, not a tier below.
    #   * RESOLVE-SUSPENSION decides a vendor-baseline conflict (§4.7). Neither
    #     side silently wins, so the deciding role must be the accountable one.
    #   * The READ side stays admin because the page's entire content is the
    #     verbatim reasoning behind security decisions. Splitting view down to
    #     a lower role was considered and declined (operator, 2026-08-27).
    # Same ADR 0028 D7 reasoning the email_security block above cites: collapsing
    # distinct cases into one policy over- or under-serves. Here they genuinely
    # agree, so one policy is the right answer rather than the lazy one.
    "module_ai_engine__route_context_page":      (_A, _A),
    "module_ai_engine__route_context_learned":   (_A, _A),
    "module_ai_engine__route_context_revoke":    (_A, _A),
    "module_ai_engine__route_context_resolve":   (_A, _A),

    # malware_detection — quarantine and scan reach a device, hence admin;
    # setting a finding's status is triage, hence user.
    "module_malware_detection__api_findings":           (_V, _A),
    "module_malware_detection__api_finding_detail":     (_V, _A),
    "module_malware_detection__api_finding_quarantine": (_A, _A),
    "module_malware_detection__api_finding_status":     (_U, _U),
    "module_malware_detection__api_scan":               (_A, _A),
    "module_malware_detection__api_scan_status":        (_V, _A),
    "module_malware_detection__api_canary_check":       (_U, _U),
    # ADMIN, deliberately a tier above its canary sibling above. `canary/check`
    # POLLS existing bait — a read of the filesystem with alerting side effects,
    # hence user. `canary/plant` WRITES FILES into a real user's home directory,
    # which is the action that caused the 2026-08-25 false-ransomware incident
    # when a test triggered it. Creating files on someone's disk is an admin act
    # even though the two routes sit next to each other and sound alike.
    "module_malware_detection__api_canary_plant":       (_A, _A),
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

    # ── Learning gate (ADR 0026 D4) ──────────────────────────────────────────
    # `user` AND ABOVE -- NOT sub_admin-and-above, which is what this first said.
    #
    # The import canary rejected the stricter version, and it was right to. D1's
    # invariant is that a sub_admin is EXACTLY a user plus their unlocks: the
    # base rank grants nothing a user lacks, and `_sub_admin_equals_user_without
    # _unlocks()` checks that over every endpoint. A training page only a
    # sub_admin could open would have been a rank-granted power with no unlock
    # behind it -- a real break of the property, caught mechanically rather than
    # by review.
    #
    # The reasoning that produced the stricter version was: only a sub_admin's
    # unlocks are ever consulted, so training anyone else "unlocks nothing".
    # That extends D2 rule 4 from CAPABILITY STATE (declared vs built, which the
    # ADR does say) to TAKER'S ROLE (which it does not). Pre-training before a
    # promotion is a sensible order to do things in, and the unlock row is
    # already inert until the account is a sub_admin.
    #
    # viewonly is below the floor because submitting a quiz WRITES, and a role
    # defined as read-only should not hold the only action this page offers. A
    # page it could read but never use is a worse dead end than a clean refusal.
    #
    # Both minimums are the same. The POST records an unlock against the
    # caller's OWN user id and nothing else, so it is exactly as privileged as
    # the GET that renders the questions.
    "training_page":                  (_U, _U),
    "training_quiz":                  (_U, _U),
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
    # ADR 0028 D11.5 Option C -- owner-side email enrollment. The owner is a
    # household member with NO dashboard account; the CODE is the credential and
    # is deliberately not in the URL (werkzeug logs request paths).
    #
    # DELIBERATELY ABSENT FROM ROUTE_MINIMUMS -- the categories are MUTUALLY
    # EXCLUSIVE and roles.py's import-time canary enforces it ("no endpoint is
    # in two categories at once"). Listing them in both, as a first attempt did,
    # fails at import. Same shape as the ADR 0019 failsafe endpoint above.
    "email_enroll_landing", "email_enroll_claim",
    # ADR 0019 Amendment 03 §4 — the lockout-failsafe revert endpoint.
    #
    # NO SESSION BY DESIGN, and this is the one entry where that is the POINT
    # rather than a concession. The endpoint exists for an admin who CANNOT log
    # in, because the firewall change under test can be exactly what broke their
    # route to the dashboard. A role minimum would make it useless in the only
    # circumstance it is for.
    #
    # It is NOT unprotected, and it is deliberately absent from ROUTE_MINIMUMS
    # (which must not overlap this set): the credential is a single-use,
    # 30-minute, hashed-at-rest token scoped to one change_id, and it is
    # validated by `nemesis_fwd` — a privileged helper — NOT by the dashboard.
    # So the check does not depend on the web process being trustworthy, which
    # is a stronger position than a session check, not a weaker one.
    #
    # `fw_revert_landing` is a GET that renders a form and changes nothing;
    # `fw_revert_action` is POST-only and performs the revert.
    "fw_revert_landing", "fw_revert_action",
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


# ── Capabilities (ADR 0026 D2) ───────────────────────────────────────────────

class UnknownCapability(RoleError):
    """A capability name that is not in CAPABILITY_ROUTES.

    RAISED, never treated as "not unlocked". A typo'd capability that reads as
    merely-locked is the `_AUTH_EXEMPT` failure in a new place: it looks like
    coverage and protects nothing, and every caller would see a plausible denial
    instead of a broken name.
    """


#: Capability -> the endpoints unlocking it grants a sub-admin.
#:
#: `approve_enrollment` IS POPULATED (2026-08-24 -- ADR 0026 §6 step 5, first
#: real capability). The other two stay empty, for two different reasons that
#: should not be confused:
#:
#:  * `push_and_run` -- THE FEATURE DOES NOT EXIST. ADR §6 names it as the first
#:    capability to build, but a repo-wide search on 2026-08-24 found no
#:    push/run-command endpoint anywhere; the only near hit is
#:    `/api/agent/<id>/notify`, which pushes a notification, not a command. So
#:    populating it is a feature build, not a wiring job, and its agent-side half
#:    additionally needs admin-approval signing (blocked on Stage 0: WebAuthn
#:    requires a secure context, and the appliance serves plain HTTP on a bare-IP
#:    server_name -- verified live). §6's "push_and_run first" ordering predates
#:    anyone checking whether it existed.
#:  * `firewall_change` -- the endpoints DO exist (`api_firewall_unblock`,
#:    `api_firewall_credential_drop`, `api_quarantine_lift`, all admin-only and
#:    all confirmed to pass the D2 rules). Held back deliberately, one capability
#:    at a time: `api_firewall_unblock` REMOVES a deny rule, which is the least
#:    defensible thing to hand a newly-qualified sub-admin first.
#:
#: An empty capability remains a legal, meaningful state -- see `capability_state`.
CAPABILITY_ROUTES = {
    "push_and_run": frozenset(),
    "firewall_change": frozenset(),
    # Approving and revoking a device: one coherent concept, both actions
    # reversible, both already route-audited, and both admin-only today. That
    # bounded blast radius is why this is the capability that goes first.
    "approve_enrollment": frozenset({"api_agent_approve", "api_agent_revoke"}),
    # ADR 0028 D11.6, ruled 2026-08-29. Registered WITH its endpoint, never ahead
    # of it: an empty frozenset yields CAP_DECLARED, and offering a quiz for a
    # capability that unlocks nothing reads as a broken reward.
    "enroll_email_account": frozenset({"module_email_security_api_enroll_create"}),
}

#: A capability that is declared but has no endpoints yet.
CAP_DECLARED = "declared"
#: A capability with at least one endpoint -- actually unlockable.
CAP_BUILT = "built"


def capability_state(capability):
    """CAP_DECLARED or CAP_BUILT. Raises UnknownCapability for a bad name.

    The UI MUST distinguish these. Offering a quiz for a declared-but-unbuilt
    capability would let someone complete training that unlocks nothing, which
    reads to them as a broken reward rather than an unfinished feature.
    """
    try:
        routes = CAPABILITY_ROUTES[capability]
    except KeyError:
        raise UnknownCapability("%r is not a declared capability" % (capability,)) from None
    return CAP_BUILT if routes else CAP_DECLARED


def capability_for_endpoint(endpoint):
    """Which capability covers this endpoint, or None.

    One endpoint may belong to at most ONE capability -- enforced by
    `assert_capabilities_sane()`. Two capabilities covering the same route makes
    "which unlock applies" unanswerable the moment they disagree.
    """
    for name, routes in CAPABILITY_ROUTES.items():
        if endpoint in routes:
            return name
    return None


#: Capabilities whose endpoints are correctly registered in ROUTE_MINIMUMS but
#: absent from the live url_map because their module is disabled. Populated by
#: `assert_capabilities_sane`. Dormant, NOT broken -- and visible rather than
#: silently skipped.
_dormant_capabilities = {}


def assert_capabilities_sane(endpoints=None):
    """The four D2 rules, checked mechanically. Raises RoleError listing failures.

    `endpoints` is the live set from `app.url_map` when available; pass it and the
    existence rule is checked against reality rather than a second hand-kept list.
    """
    problems = []
    seen = {}
    for name, routes in CAPABILITY_ROUTES.items():
        for ep in routes:
            if ep in seen:
                problems.append("endpoint %r is claimed by BOTH %r and %r; "
                                "which unlock applies is unanswerable"
                                % (ep, seen[ep], name))
            seen[ep] = name
            # A capability may only cover endpoints that are admin-only for
            # unsafe methods. Elevating to something a plain user already has is
            # decoration, and a reader would reasonably assume it did something.
            entry = ROUTE_MINIMUMS.get(ep)
            if entry is None:
                # ⚠ THE GAP THIS CLOSES. Until 2026-08-24 this branch did not
                # exist, and the `endpoints is not None` block below was the ONLY
                # existence check -- so a bare `assert_capabilities_sane()` call
                # silently accepted an endpoint name that matched nothing at all.
                # A typo passed clean and read as a verified capability, which is
                # the `_AUTH_EXEMPT` shape exactly: looks like coverage, protects
                # nothing. Callers SHOULD still pass `endpoints=app.url_map` (the
                # live map is a stronger source than this table), but the bare
                # call must not be the weak one -- a check whose strictness
                # depends on which arguments the caller remembered is a check
                # nobody can reason about.
                problems.append(
                    "capability %r covers %r, which is not in ROUTE_MINIMUMS at "
                    "all -- a name that matches no registered route protects "
                    "nothing while looking like coverage" % (name, ep))
            elif entry[1] != ROLE_ADMIN:
                problems.append("capability %r covers %r, whose unsafe minimum is "
                                "%r rather than admin -- unlocking it would grant "
                                "nothing" % (name, ep, entry[1]))
    if endpoints is not None:
        known = set(endpoints)
        for name, routes in CAPABILITY_ROUTES.items():
            missing = sorted(set(routes) - known)
            # ⚠ A MODULE ROUTE IS CONDITIONAL ON ITS MODULE BEING ENABLED, and
            # treating its absence as a typo took the dashboard down.
            #
            # LIVE OUTAGE 2026-08-30: `enroll_email_account` names
            # `module_email_security_api_enroll_create`. The name is CORRECT and
            # matches at all three sites (views.routes(), ROUTE_MINIMUMS,
            # CAPABILITY_ROUTES) -- but `email_security` ships
            # `enabled_by_default: false`, so its routes never register and the
            # endpoint is legitimately absent from `app.url_map`. This rule then
            # raised at startup on EVERY boot: a permanent crash-loop, not a race.
            #
            # The typo protection this rule exists for is NOT weakened, because a
            # typo is caught by a DIFFERENT and stronger check above: an endpoint
            # absent from ROUTE_MINIMUMS raises there, and `modules_loader`
            # additionally REFUSES to register any module endpoint missing from
            # ROUTE_MINIMUMS. So a misspelled module endpoint is still fatal; only
            # a correctly-registered one whose module is switched off is tolerated.
            #
            # CORE endpoints are deliberately still checked against the live map:
            # a core route always registers, so its absence really is a defect.
            deferred = sorted(
                ep for ep in missing
                if ep.startswith("module_") and ep in ROUTE_MINIMUMS)
            missing = [ep for ep in missing if ep not in deferred]
            if deferred:
                # Surfaced, never silent -- a capability that grants nothing today
                # because its module is off is a real (if benign) state, and the
                # operator should be able to see it rather than infer it.
                _dormant_capabilities[name] = deferred
            if missing:
                problems.append("capability %r names endpoint(s) that do not exist "
                                "(a typo protects nothing while looking like "
                                "coverage): %s" % (name, ", ".join(missing)))
    if problems:
        raise RoleError(" | ".join(problems))
    return True


def may_with_unlocks(role, unlocks, endpoint, method="GET"):
    """May this PRINCIPAL call `endpoint`, given the capabilities they have earned?

    `unlocks` is an explicit iterable of capability names -- this module never
    reads them itself. That is the whole reason `roles.py` still has no I/O and
    can run its canary at import, in the production path (ADR 0026 D1). The gate
    fetches unlocks from the DB and hands them in. DO NOT "simplify" this later by
    having this function look them up.

    Semantics: rank first, then -- for a sub-admin only -- an unlocked capability
    covering this endpoint. A sub-admin with no unlocks is exactly a standard user.
    An unlock NEVER lowers a requirement for any other role, and never grants
    anything to viewonly or user, who cannot hold unlocks at all.
    """
    if may(role, endpoint, method):
        return True
    # Rank was not enough. Only a sub-admin can make up the difference.
    if normalise_role(role) != ROLE_SUB_ADMIN:
        return False
    covering = capability_for_endpoint(endpoint)
    if covering is None:
        return False
    for name in (unlocks or ()):
        # Raises on an unknown name rather than skipping it: a typo in stored
        # unlock rows must be loud, not silently equivalent to "not unlocked".
        if capability_state(name) and name == covering:
            return True
    return False


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


#: The role ordering as it shipped 2026-08-22, BEFORE sub_admin was inserted.
#: Frozen deliberately: it is the baseline the additivity check measures against,
#: so it must not be derived from ROLES or it would move with the thing it checks.
_PRE_SUBADMIN_ORDER = ("viewonly", "user", "admin")


def _additivity_pairs():
    """Every (role, endpoint, method) an existing role could ask about."""
    eps = list(ROUTE_MINIMUMS) + sorted(SELF_SERVICE | UNAUTHENTICATED)
    for ep in eps:
        for role in _PRE_SUBADMIN_ORDER:
            for method in ("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"):
                yield role, ep, method


def _additivity_sample_size():
    return sum(1 for _ in _additivity_pairs())


def _additivity_holds():
    """True if inserting sub_admin changed NO answer for any pre-existing role.

    Recomputes each answer under the ORIGINAL 3-role ranking and compares it to
    what `may()` says now. This is the check that makes "additive" a measured
    property rather than an intention -- and it is why no hand review of the 135
    registry entries was needed or done.
    """
    old = {name: i for i, name in enumerate(_PRE_SUBADMIN_ORDER)}
    for role, ep, method in _additivity_pairs():
        if ep in UNAUTHENTICATED or ep in SELF_SERVICE:
            continue                                    # unconditionally allowed
        entry = ROUTE_MINIMUMS.get(ep)
        need = ROLE_ADMIN if entry is None else (
            entry[0] if str(method).upper() in SAFE_METHODS else entry[1])
        if (old[role] >= old[need]) != may(role, ep, method):
            return False
    return True


def _sub_admin_equals_user_without_unlocks():
    """A sub-admin holding no unlocks must answer identically to a user."""
    eps = list(ROUTE_MINIMUMS) + sorted(SELF_SERVICE | UNAUTHENTICATED)
    for ep in eps:
        for method in ("GET", "POST"):
            if (may_with_unlocks(ROLE_SUB_ADMIN, (), ep, method)
                    != may(ROLE_USER, ep, method)):
                return False
    return True


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

    # ── sub_admin sits BETWEEN user and admin (ADR 0026 D1) ─────────────────
    _H.bad("sub_admin outranks user",
           lambda: at_least(ROLE_SUB_ADMIN, ROLE_USER) or None),
    _H.bad("sub_admin does NOT reach admin by rank alone",
           lambda: (not at_least(ROLE_SUB_ADMIN, ROLE_ADMIN)) or None),
    _H.bad("admin outranks sub_admin",
           lambda: at_least(ROLE_ADMIN, ROLE_SUB_ADMIN) or None),
    _H.bad("its punctuated spellings all normalise",
           lambda: (normalise_role("sub-admin") == normalise_role("Sub Admin")
                    == normalise_role("SUB_ADMIN") == ROLE_SUB_ADMIN) or None),

    # THE ADDITIVITY PROPERTY. Inserting a rank must not change what any
    # PRE-EXISTING role may do. Recomputed here against the original 3-role
    # ordering rather than trusted -- a future reorder that silently altered one
    # answer would otherwise pass every other check in this file.
    _H.bad("inserting sub_admin changed NO answer for viewonly/user/admin",
           lambda: (_additivity_holds() or None)),
    _H.good("CONTROL: that comparison is not vacuous (it really compares)",
            lambda: (None if _additivity_sample_size() > 100 else "too few cases"),),

    # ── capability layer (ADR 0026 D2) ──────────────────────────────────────
    _H.bad("an unknown capability RAISES rather than reading as locked",
           lambda: _raises(lambda: capability_state("no_such_capability"),
                           UnknownCapability) or None),
    _H.bad("a declared-but-empty capability is distinguishable from a built one",
           lambda: (capability_state("push_and_run") == CAP_DECLARED) or None),
    _H.bad("an unlock grants NOTHING while its capability has no endpoints",
           lambda: (not may_with_unlocks(ROLE_SUB_ADMIN, ["push_and_run"],
                                         "settings_page", "POST")) or None),
    _H.bad("a sub_admin with no unlocks is exactly a standard user",
           lambda: _sub_admin_equals_user_without_unlocks() or None),
    _H.bad("an unlock never elevates viewonly or user",
           lambda: (not may_with_unlocks(ROLE_USER, ["push_and_run"],
                                         "settings_page", "POST")
                    and not may_with_unlocks(ROLE_VIEWONLY, ["push_and_run"],
                                             "settings_page", "POST")) or None),
    _H.bad("the capability rules hold for the shipped table",
           lambda: assert_capabilities_sane() or None),

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

    # These execute/spend/report outward. POST-only since 2026-08-25 -- asserted on
    # POST because that is now the only method they accept; asserting on GET would
    # consult the safe half of the pair and no longer describe a reachable request.
    _H.bad("viewonly cannot run diagnostics (executes)",
           lambda: (not may(ROLE_VIEWONLY, "api_diag_run_all", "POST")) or None),
    _H.bad("viewonly cannot trigger an AI analysis (spends)",
           lambda: (not may(ROLE_VIEWONLY, "analyze_alert", "POST")) or None),
    _H.bad("viewonly cannot file an abuse report (reports outward)",
           lambda: (not may(ROLE_VIEWONLY, "report_abuse", "POST")) or None),
    _H.bad("...and neither can a plain user file one",
           lambda: (not may(ROLE_USER, "report_abuse", "POST")) or None),
    _H.bad("CONTROL: a user CAN run diagnostics (so the denials above are "
           "discrimination, not blanket refusal)",
           lambda: may(ROLE_USER, "api_diag_run_all", "POST") or None),

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
