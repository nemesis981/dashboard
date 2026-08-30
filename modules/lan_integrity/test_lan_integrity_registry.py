"""Registry completeness for lan_integrity — the checks the module's own logic tests CANNOT make.

WHY THIS FILE EXISTS AS A SEPARATE SUITE
    `data_manager.py`'s own comment states the trap outright: *"ADDING THE NAME
    HERE IS NOT OPTIONAL AND IS NOT COVERED BY THE TESTS. A module writing an
    ungranted table is refused at RUNTIME; the module's own suite builds its
    tables on a plain sqlite3 connection, so a missing grant passes every test and
    only appears in production as a `WOULD DENY` log line with the write silently
    not happening."*

    There is a second, differently-shaped version of the same trap on the routes
    side: `modules_loader` REFUSES to register any endpoint absent from
    `roles.ROUTE_MINIMUMS`, and the route then **404s** — which reads as "no such
    route" rather than "misconfigured". Two registries, two silent failures, and
    neither is visible from a passing logic test.

    So this suite asserts the module against the registries themselves, and
    asserts BOTH DIRECTIONS: a table the module creates must be granted, and a
    grant must correspond to a table the module actually creates. One direction
    alone lets a stale grant outlive the table it was for.
"""
import ast
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _REPO)
sys.path.insert(0, os.path.join(_REPO, "alert_manager"))

import roles                                    # noqa: E402
import data_manager                             # noqa: E402

_fail = []
_count = 0
EXPECTED_CHECKS = 16

MODULE_NAME = "lan_integrity"


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-66s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def _tables_created_by_module():
    """Table names from the module's ACTUAL DDL, read out of the source.

    Parsed rather than hand-listed on purpose: a hand-listed copy is a second
    source of truth that desyncs the moment someone adds a CREATE TABLE, which is
    exactly the drift this file exists to catch.
    """
    src = open(os.path.join(_HERE, "module.py"), encoding="utf-8").read()
    found = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
            marker = "CREATE TABLE IF NOT EXISTS "
            idx = 0
            while True:
                i = text.find(marker, idx)
                if i < 0:
                    break
                rest = text[i + len(marker):].strip()
                found.add(rest.split()[0].split("(")[0])
                idx = i + len(marker)
    return found


def test_ddl_was_actually_found():
    print("\n[CONTROL: the parser found real DDL -- an empty set would pass everything below]")
    tables = _tables_created_by_module()
    check("parser found at least one CREATE TABLE", len(tables) >= 1, True)
    check("parser found exactly the four expected tables", len(tables), 4)
    check("state table found", "lan_integrity_state" in tables, True)
    check("servers table found", "lan_integrity_dhcp_servers" in tables, True)
    check("findings table found", "lan_integrity_findings" in tables, True)
    check("arp bindings table found", "lan_integrity_arp_bindings" in tables, True)


def test_namespace_grant_matches_ddl():
    print("\n[every table the module CREATES must be granted, and vice versa]")
    grant = data_manager.NAMESPACES.get(MODULE_NAME)
    check("module has a namespace entry at all", grant is not None, True)
    check("grant is the EXACT-match dict form, not a prefix tuple",
          isinstance(grant, dict), True)
    granted = set(grant.get("tables", ())) if isinstance(grant, dict) else set()
    tables = _tables_created_by_module()
    check("no table is created without a grant (WOULD DENY at runtime)",
          sorted(tables - granted), [])
    check("no grant outlives the table it was for",
          sorted(granted - tables), [])


def test_routes_are_registered():
    print("\n[a route missing from ROUTE_MINIMUMS is REFUSED by the loader and 404s]")
    import importlib
    mod = importlib.import_module("modules.lan_integrity.module")
    inst = mod.Module({"name": MODULE_NAME})
    routes = inst.get_routes()
    check("CONTROL: the module actually declares routes", len(routes) >= 1, True)
    missing = []
    for rule, view, _opts in routes:
        endpoint = "module_%s_%s" % (MODULE_NAME, view.__name__)
        if endpoint not in roles.ROUTE_MINIMUMS:
            missing.append(endpoint)
    check("every declared route has a ROUTE_MINIMUMS entry", missing, [])

    # The reverse: an entry naming an endpoint that does not exist is a typo that
    # "protects nothing while looking like coverage" (roles.py's own words).
    declared = {"module_%s_%s" % (MODULE_NAME, v.__name__) for _r, v, _o in routes}
    stale = [e for e in roles.ROUTE_MINIMUMS
             if e.startswith("module_%s_" % MODULE_NAME) and e not in declared]
    check("no ROUTE_MINIMUMS entry names a non-existent endpoint", stale, [])


def test_write_routes_are_admin():
    print("\n[pinning a server SUPPRESSES findings -- it is detection-disabling, not cosmetic]")
    admin = roles.ROLE_ADMIN
    check("pin is admin on both axes",
          roles.ROUTE_MINIMUMS["module_lan_integrity__api_pin"], (admin, admin))
    check("close is admin on both axes",
          roles.ROUTE_MINIMUMS["module_lan_integrity__api_close"], (admin, admin))


def test_not_unauthenticated():
    print("\n[module routes can never be public -- the registries are mutually exclusive]")
    overlap = {e for e in roles.ROUTE_MINIMUMS
               if e.startswith("module_lan_integrity_")} & set(roles.UNAUTHENTICATED)
    check("no lan_integrity endpoint is in UNAUTHENTICATED", sorted(overlap), [])


if __name__ == "__main__":
    print("lan_integrity -- registry completeness")
    test_ddl_was_actually_found()
    test_namespace_grant_matches_ddl()
    test_routes_are_registered()
    test_write_routes_are_admin()
    test_not_unauthenticated()
    print()
    if _count != EXPECTED_CHECKS:
        print("SUITE DRIFT: ran %d checks, expected %d" % (_count, EXPECTED_CHECKS))
        sys.exit(1)
    if _fail:
        print("FAILED (%d of %d)" % (len(_fail), _count))
        for f in _fail:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS (%d checks)" % _count)
