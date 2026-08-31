"""email_security route registry completeness. Standing practice, 2026-08-30.

WHY THIS FILE IS LOAD-BEARING RATHER THAN NICE TO HAVE
    `8a8580f` fixed a live crash-loop: `assert_capabilities_sane` used to treat
    any ROUTE_MINIMUMS entry absent from the LIVE url_map as a fatal typo. That
    was wrong for a DISABLED module -- `email_security` ships
    `enabled_by_default: false`, so its routes legitimately never register, and
    the check raised on every boot.

    The fix is correct and necessary, and it has a consequence: the runtime now
    DEFERS on any `module_`-prefixed endpoint missing from the live map, recording
    it as "dormant" rather than raising. That is EXACTLY the shape a real
    declared-route/registry mismatch takes when the module happens to be
    disabled. So this static test is now the only thing that catches that
    mismatch class loudly and deterministically, independent of whether the
    module is enabled at test time.

    For a module that is disabled by default -- which this one is, deliberately,
    because it reads a person's private mail -- the runtime check is dormant
    essentially always. This file is the whole coverage.

THE TWO FAILURE MODES, WHICH LOOK NOTHING ALIKE FROM OUTSIDE
    A route declared but missing from ROUTE_MINIMUMS: `modules_loader` REFUSES to
    register it and the route 404s -- reading as "that feature does not exist".
    A ROUTE_MINIMUMS entry naming an endpoint nothing declares: a typo that, in
    roles.py's own words, "protects nothing while looking like coverage."

    Both directions are asserted. One alone would miss half of it.
"""
import os
import sys

sys.path.insert(0, "/opt/nemesis")
sys.path.insert(0, "/opt/nemesis/alert_manager")

import roles                                                    # noqa: E402

MODULE_NAME = "email_security"
PASS = FAIL = 0


def check(label, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print("  [PASS] %s" % label)
    else:
        FAIL += 1
        print("  [FAIL] %s\n         got=%r want=%r" % (label, got, want))


def declared_routes():
    """What the module actually declares, via its real get_routes()."""
    from modules.email_security import views                     # noqa: PLC0415
    return views.routes()


print("== declared routes vs ROUTE_MINIMUMS, in BOTH directions ==")
routes = declared_routes()
# CONTROL. Without this the two checks below would both pass vacuously against a
# module that declares nothing at all -- an empty set is a subset of everything.
check("CONTROL: the module actually declares routes", len(routes) >= 1)

missing = []
for rule, view, _opts in routes:
    endpoint = "module_%s_%s" % (MODULE_NAME, view.__name__)
    if endpoint not in roles.ROUTE_MINIMUMS:
        missing.append(endpoint)
check("every declared route has a ROUTE_MINIMUMS entry (else it 404s)",
      missing, [])

declared = {"module_%s_%s" % (MODULE_NAME, v.__name__) for _r, v, _o in routes}
stale = [e for e in roles.ROUTE_MINIMUMS
         if e.startswith("module_%s_" % MODULE_NAME) and e not in declared]
check("no ROUTE_MINIMUMS entry names an endpoint nothing declares", stale, [])

print("\n== the capability registry agrees with both ==")
# enroll_email_account is what lets a household sub_admin mint an enrollment link
# without being a full admin. If it names an endpoint that does not exist, the
# capability grants nothing while appearing to grant something.
for cap, eps in roles.CAPABILITY_ROUTES.items():
    for ep in eps:
        if ep.startswith("module_%s_" % MODULE_NAME):
            check("capability %r names a declared endpoint (%s)" % (cap, ep),
                  ep in declared)
            check("  ...which also has a ROUTE_MINIMUMS entry",
                  ep in roles.ROUTE_MINIMUMS)

print("\n== module routes are NEVER public ==")
# The registries are mutually exclusive and roles.py's import-time canary
# enforces it. The owner-facing enrollment pages are unauthenticated BY DESIGN,
# but they live in dashboard.py as hand-placed _AUTH_EXEMPT entries precisely
# BECAUSE a module route cannot be public -- see this module's views.py header.
overlap = {e for e in roles.ROUTE_MINIMUMS
           if e.startswith("module_%s_" % MODULE_NAME)} & set(roles.UNAUTHENTICATED)
check("no email_security MODULE endpoint is in UNAUTHENTICATED",
      sorted(overlap), [])
# The reverse reassurance: the three owner-facing routes ARE public, and are NOT
# module routes. They must not have acquired a module_ prefix.
for ep in ("email_enroll_landing", "email_enroll_claim", "email_enroll_complete"):
    check("%s is public and is NOT a module route" % ep,
          ep in roles.UNAUTHENTICATED
          and not ep.startswith("module_"))

print("\n== state-changing module routes require admin ==")
_A = roles.ROLE_ADMIN
check("enroll/create is admin on both axes (it mints a bearer credential)",
      roles.ROUTE_MINIMUMS.get("module_email_security_api_enroll_create"),
      (_A, _A))

print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
