#!/usr/bin/env python3
"""Role-based access control — the decision layer AND the live gate.

Run: python3 alert_manager/test_roles.py     (exit 0 = all pass)

TWO HALVES, AND THE SECOND IS THE ONE THAT MATTERS.

The first half tests `roles.py` in isolation: ordering, fail-closed behaviour,
method classification, the registry's shape. That is necessary and cheap.

The second half logs in as a real admin, a real user and a real viewonly account
against a real Flask test client and asserts the ACTUAL HTTP STATUS returned by
the real before_request gate. It exists because a correct decision table proves
nothing on its own — a table that says "viewonly may not POST here" and a gate
that never consults it would both pass the first half. Only the live half can
tell the difference between authorization and a lookup table nobody reads.

This is the same lesson as the module-loader defect found earlier today: a check
that cannot reproduce the production path is not evidence about the production
path.

NO NETWORK, NO WRITES TO THE LIVE DB. The live half runs against a COPY of the
database in a temp directory, pointed at by NEMESIS_DB_PATH, and the accounts it
creates exist only in that copy.
"""
import importlib.util
import os
import shutil
import sqlite3
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)

_SRC = os.path.join(_HERE, "roles.py")
_spec = importlib.util.spec_from_file_location("roles_under_test", _SRC)
roles = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(roles)

A, U, V = roles.ROLE_ADMIN, roles.ROLE_USER, roles.ROLE_VIEWONLY

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


def raises(fn, exc=roles.RoleError):
    try:
        fn()
        return False
    except exc:
        return True
    except Exception:                                          # noqa: BLE001
        return False


def snapshot_db(src, dst):
    """A CONSISTENT copy of the live WAL database.

    NOT `shutil.copy`. The live DB runs in WAL mode with the dashboard, watchdog
    and alert-watcher all writing to it, so its `-wal` sidecar can hold committed
    transactions the main file does not have yet. Copying the main file alone can
    produce a torn snapshot, and the symptom is an intermittent harness-startup
    failure carrying no useful message -- the kind of unattributable flake that
    gets re-run until it passes and is then trusted.

    sqlite3's backup API opens a read transaction and copies a coherent view,
    uncheckpointed pages included.

    It RAISES rather than falling back to `shutil.copy`. A fallback would restore
    the original hazard silently, leaving a harness that reports a clean run over
    a database it may have mangled.
    """
    src_conn = sqlite3.connect("file:%s?mode=ro" % src, uri=True)
    try:
        dst_conn = sqlite3.connect(dst)
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
    finally:
        src_conn.close()


# ═══════════════════════════════════════════════════════════════════════════
print("\n== PART 1: the decision layer ==")
print("\n-- ordering --")
check("admin > user", roles.rank(A) > roles.rank(U))
check("user > viewonly", roles.rank(U) > roles.rank(V))
check("admin reaches every minimum",
      all(roles.at_least(A, m) for m in roles.ROLES))
check("viewonly reaches ONLY viewonly",
      [m for m in roles.ROLES if roles.at_least(V, m)] == [V])
check("CONTROL: the ordering is not vacuous", not roles.at_least(V, A))

print("\n-- an unparseable role never resolves --")
for bad in ("wizard", "", "   ", None, "adminx", "root", 0, [], "user;--"):
    check("%r raises" % (bad,), raises(lambda b=bad: roles.normalise_role(b)))
check("CONTROL: real roles do NOT raise",
      all(not raises(lambda r=r: roles.normalise_role(r)) for r in roles.ROLES))
check("a bad MINIMUM raises rather than quietly denying",
      raises(lambda: roles.at_least(A, "supervisor")))
check("aliases normalise", roles.normalise_role("View-Only") == V
      and roles.normalise_role(" ADMIN ") == A
      and roles.normalise_role("read_only") == V)
check("the users-table DEFAULT ('admin') is NOT what new accounts get",
      roles.DEFAULT_ROLE != A)

print("\n-- unknown endpoints fail CLOSED --")
check("an unregistered endpoint needs admin",
      roles.required_role("totally_made_up") == A)
check("viewonly cannot reach it", not roles.may(V, "totally_made_up"))
check("user cannot reach it", not roles.may(U, "totally_made_up"))
check("admin CAN (or it is a dead route, not a gated one)",
      roles.may(A, "totally_made_up"))

print("\n-- safe vs unsafe methods --")
check("GET is safe", "GET" in roles.SAFE_METHODS)
check("HEAD is safe (Flask adds it to every GET route)",
      "HEAD" in roles.SAFE_METHODS)
check("POST is not", "POST" not in roles.SAFE_METHODS)
check("an UNKNOWN method is treated as unsafe",
      not roles.may(V, "settings_page", "FROB"))
check("viewonly may GET the settings page",
      roles.may(V, "settings_page", "GET"))
check("viewonly may NOT POST it", not roles.may(V, "settings_page", "POST"))

print("\n-- GETs that EXECUTE are not readable by viewonly --")
for ep, who in (("api_diag_run_all", "runs checks"),
                ("api_diag_run", "runs one check"),
                ("analyze_alert", "spends money"),
                ("test_enrichment", "outbound lookup"),
                ("report_abuse", "POSTs to a third party"),
                ("api_filesystem_browse", "reads the filesystem")):
    check("viewonly cannot GET %s (%s)" % (ep, who), not roles.may(V, ep, "GET"))
check("CONTROL: user CAN run diagnostics", roles.may(U, "api_diag_run_all", "GET"))
check("report_abuse is admin-only even for a user",
      not roles.may(U, "report_abuse", "GET"))

print("\n-- the three roles are genuinely different, not cosmetic --")
eps = sorted(roles.ROUTE_MINIMUMS)
reach = {r: sum(1 for e in eps
                if roles.may(r, e, "GET") or roles.may(r, e, "POST"))
         for r in roles.ROLES}
check("admin reaches strictly more than user", reach[A] > reach[U], reach)
check("user reaches strictly more than viewonly", reach[U] > reach[V], reach)
check("viewonly reaches a useful amount (not locked out entirely)",
      reach[V] > 30, reach)
check("viewonly is denied a large surface (not admin in disguise)",
      reach[A] - reach[V] > 40, reach)

print("\n-- active tooling is admin-only --")
for ep in ("module_netprobe__api_ping", "module_netprobe__api_trace",
           "api_scan_trigger", "api_agent_notify",
           "module_malware_detection__api_scan"):
    check("user cannot reach %s" % ep, not roles.may(U, ep, "POST"))
    check("viewonly cannot reach %s" % ep, not roles.may(V, ep, "POST"))
check("CONTROL: admin CAN ping", roles.may(A, "module_netprobe__api_ping", "POST"))
check("user CAN use the read-only lookup", roles.may(U, "module_lookup__api_lookup", "POST"))

print("\n-- protection may be confirmed by a user, lifted only by an admin --")
check("user may confirm a quarantine", roles.may(U, "api_quarantine_confirm", "POST"))
check("user may NOT lift one", not roles.may(U, "api_quarantine_lift", "POST"))
check("user may NOT unblock the firewall", not roles.may(U, "api_firewall_unblock", "POST"))
check("user may NOT drop a firewall credential",
      not roles.may(U, "api_firewall_credential_drop", "POST"))

print("\n-- nothing may disable coverage below admin --")
# The standing hard constraint: no credential or override may silently reduce
# monitoring. Role does not create such a path -- module disable stays admin.
for ep in ("api_module_disable", "api_module_enable", "api_consent_revoke",
           "api_hw_reset_baseline"):
    check("%s is admin-only" % ep, roles.required_role(ep, "POST") == A)

print("\n-- self-service survives every role --")
for ep in sorted(roles.SELF_SERVICE):
    check("viewonly may reach %s" % ep, roles.may(V, ep, "POST"))
check("CONTROL: self-service is not empty", len(roles.SELF_SERVICE) >= 4)

print("\n-- registry hygiene --")
check("every entry names two known roles",
      all(s in roles.ROLES and u in roles.ROLES
          for s, u in roles.ROUTE_MINIMUMS.values()))
check("no safe minimum is stricter than its unsafe minimum",
      all(roles.rank(s) <= roles.rank(u)
          for s, u in roles.ROUTE_MINIMUMS.values()))
check("no endpoint is in two categories",
      not (set(roles.ROUTE_MINIMUMS) & (roles.SELF_SERVICE | roles.UNAUTHENTICATED)))
check("registry covers the whole surface (>130 entries)",
      len(roles.ROUTE_MINIMUMS) > 130, len(roles.ROUTE_MINIMUMS))

print("\n-- assert_registry_complete reports BOTH directions --")
check("a missing endpoint is reported",
      raises(lambda: roles.assert_registry_complete(
          set(roles.ROUTE_MINIMUMS) | {"brand_new_route"})))


def _err(fn):
    try:
        fn()
        return ""
    except Exception as e:                                     # noqa: BLE001
        return str(e)


msg = _err(lambda: roles.assert_registry_complete(
    set(roles.ROUTE_MINIMUMS) | roles.SELF_SERVICE | roles.UNAUTHENTICATED
    | {"brand_new_route"}))
check("a missing endpoint is NAMED in the error", "brand_new_route" in msg, msg)
msg2 = _err(lambda: roles.assert_registry_complete({"dashboard"}))
check("a phantom entry is reported too", "does not exist" in msg2, msg2[:120])
check("CONTROL: a matching set passes",
      roles.assert_registry_complete(
          set(roles.ROUTE_MINIMUMS) | roles.SELF_SERVICE | roles.UNAUTHENTICATED))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== PART 2: the LIVE gate (real login, real HTTP status) ==")

_tmp = tempfile.mkdtemp(prefix="nemesis_roles_test_")
_live_ok = False
client = None
app = None
try:
    src_db = os.environ.get("NEMESIS_TEST_SRC_DB", "/var/lib/nemesis/alerts.db")
    db = os.path.join(_tmp, "alerts.db")
    if os.path.exists(src_db):
        snapshot_db(src_db, db)
    os.environ["NEMESIS_DB_PATH"] = db
    for p in (_REPO, _HERE, os.path.join(_REPO, "core_module", "hw_monitor")):
        if p not in sys.path:
            sys.path.insert(0, p)
    import logging
    logging.disable(logging.CRITICAL)
    import dashboard                                           # noqa: E402
    app = dashboard.app
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    import modules_loader as ml                                # noqa: E402
    for n in sorted(ml._manifests or {}):
        try:
            ml._load_module(n)
        except Exception:                                      # noqa: BLE001
            pass
    _live_ok = True
except Exception as exc:                                       # noqa: BLE001
    check("live gate harness starts", False,
          "%s: %s — PART 2 cannot run" % (type(exc).__name__, exc))

if _live_ok:
    PW = "correct-horse-battery-staple-77"
    accounts = {}
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        for role in (A, U, V):
            uname = "zz_test_%s" % role
            conn.execute("DELETE FROM users WHERE username=?", (uname,))
            conn.commit()
            uid = dashboard._create_user(
                uname, "test data %s RBAC probe" % role, PW, role)
            accounts[role] = (uid, uname)
        conn.commit()
    finally:
        conn.close()

    check("three test accounts exist, one per role", len(accounts) == 3, accounts)

    def as_role(role):
        """A test client with a real logged-in session for `role`."""
        c = app.test_client()
        r = c.post("/login", data={"username": accounts[role][1], "password": PW},
                   follow_redirects=False)
        return c, r

    sessions = {}
    for role in (A, U, V):
        c, r = as_role(role)
        sessions[role] = c
        check("%s can log in (status %s)" % (role, r.status_code),
              r.status_code in (200, 302), r.status_code)

    def status(role, method, path, **kw):
        c = sessions[role]
        fn = getattr(c, method.lower())
        return fn(path, **kw).status_code

    print("\n-- the six formerly-GET action routes REFUSE GET (2026-08-25 CSRF fix) --")
    # Each of these performed a write, a spend or an outbound call while answering GET,
    # so `<img src=...>` on any page the operator visited was enough to trigger it under
    # default SameSite=Lax cookies. 405 (not 403) is the proof the method itself is gone:
    # a 403 would mean the route still ACCEPTS GET and merely refused this role.
    for _p in ("/api/report/1", "/api/analyze/1", "/api/diagnostics/run/dns",
               "/api/diagnostics/run-all", "/api/test-enrichment/192.0.2.5",
               "/api/filesystem/browse"):
        check("GET %s is 405 Method Not Allowed" % _p,
              status(A, "GET", _p) == 405, str(status(A, "GET", _p)))
    # ...and POST without a JSON content-type is refused 415, which is the half that
    # stops a cross-origin HTML form (a form cannot set application/json).
    for _p in ("/api/report/1", "/api/analyze/1", "/api/diagnostics/run-all",
               "/api/filesystem/browse"):
        check("POST %s without JSON content-type is 415" % _p,
              status(A, "POST", _p, data="x") == 415, str(status(A, "POST", _p, data="x")))

    print("\n-- viewonly is READ-ONLY, enforced server-side --")
    check("viewonly CAN read the dashboard", status(V, "GET", "/") == 200)
    check("viewonly CAN read stats", status(V, "GET", "/api/stats") == 200)
    check("viewonly is DENIED an alert action (403)",
          status(V, "POST", "/api/db-action/1/dismiss") == 403)
    check("viewonly is DENIED a settings write (403)",
          status(V, "POST", "/api/config/update", json={}) == 403)
    check("viewonly is DENIED module disable (403)",
          status(V, "POST", "/api/modules/lookup/disable") == 403)
    check("viewonly is DENIED running diagnostics (403)",
          status(V, "POST", "/api/diagnostics/run-all", json={}) == 403)
    check("viewonly is DENIED the lookup tool (403)",
          status(V, "POST", "/api/lookup/domain", json={"target": "example.com"}) == 403)
    check("viewonly is DENIED ping (403)",
          status(V, "POST", "/api/netprobe/ping", json={"target": "x"}) == 403)
    check("viewonly is DENIED user management (403)",
          status(V, "GET", "/api/users") == 403)
    check("viewonly is DENIED the abuse report GET (403)",
          status(V, "POST", "/api/report/1", json={"ip": "192.0.2.5"}) == 403)

    print("\n-- user: day-to-day yes, admin no --")
    check("user CAN read the dashboard", status(U, "GET", "/") == 200)
    check("user CAN run diagnostics (not 403)",
          status(U, "POST", "/api/diagnostics/run-all", json={}) != 403)
    check("user CAN use the lookup tool (not 403)",
          status(U, "POST", "/api/lookup/domain",
                 json={"target": "example.com"}) != 403)
    check("user is DENIED a settings write (403)",
          status(U, "POST", "/api/config/update", json={}) == 403)
    check("user is DENIED module disable (403)",
          status(U, "POST", "/api/modules/lookup/disable") == 403)
    check("user is DENIED ping (403)",
          status(U, "POST", "/api/netprobe/ping", json={"target": "x"}) == 403)
    check("user is DENIED user management (403)",
          status(U, "GET", "/api/users") == 403)
    check("user is DENIED lifting a quarantine (403)",
          status(U, "POST", "/api/quarantine/1/lift") == 403)
    check("user is DENIED the abuse report GET (403)",
          status(U, "POST", "/api/report/1", json={"ip": "192.0.2.5"}) == 403)

    print("\n-- admin: the CONTROL. If these 403 too, nothing above is meaningful --")
    check("admin CAN read the dashboard", status(A, "GET", "/") == 200)
    check("admin is NOT denied a settings write",
          status(A, "POST", "/api/config/update", json={}) != 403)
    check("admin is NOT denied user management",
          status(A, "GET", "/api/users") == 200)
    check("admin is NOT denied ping",
          status(A, "POST", "/api/netprobe/ping", json={"target": "x"}) != 403)
    check("admin is NOT denied module disable",
          status(A, "POST", "/api/modules/lookup/disable") != 403)
    check("admin is NOT denied diagnostics",
          status(A, "POST", "/api/diagnostics/run-all", json={}) != 403)

    print("\n-- self-service works at EVERY role --")
    for role in (A, U, V):
        check("%s can reach its own password page" % role,
              status(role, "GET", "/account/password") == 200)
        check("%s can touch its session" % role,
              status(role, "POST", "/api/session/touch") != 403)

    print("\n-- the gate covers MODULE routes, not just dashboard.py routes --")
    # The reason the gate is a before_request hook rather than a decorator.
    check("a module route is gated for viewonly",
          status(V, "POST", "/api/netprobe/ping", json={"target": "x"}) == 403)
    check("a module route is gated for user",
          status(U, "GET", "/api/malware/settings") != 403
          and status(U, "POST", "/api/malware/settings", json={}) == 403,
          "GET should pass, POST should 403")

    print("\n-- denial SHAPE: 403, not a redirect to login --")
    r = sessions[V].post("/api/config/update", json={})
    check("API denial is 403", r.status_code == 403)
    check("API denial is JSON", r.is_json, r.content_type)
    check("API denial names the required role",
          r.is_json and r.get_json().get("required_role") == A, r.get_json())
    check("API denial does not leak a redirect to login",
          "login" not in (r.headers.get("Location") or ""))
    rp = sessions[V].get("/settings/users")
    check("page denial is 403, NOT a 302 to login (they ARE logged in)",
          rp.status_code == 403, rp.status_code)
    check("page denial is readable HTML", b"Not permitted" in rp.data)

    print("\n-- the last administrator cannot be removed --")
    admin_id = accounts[A][0]

    # Force the precondition rather than skipping when it is absent. The copied
    # DB carries whatever admins the live system has, so an earlier version of
    # this test SKIPPED the demotion check whenever there were two -- reporting
    # a pass for the one invariant that, if broken, locks everyone out of the
    # product permanently. Deactivating the others (in the COPY) makes the test
    # measure the thing it claims to measure, every run.
    conn = sqlite3.connect(db)
    try:
        conn.execute("UPDATE users SET is_active=0 WHERE id != ? AND role='admin'",
                     (admin_id,))
        conn.commit()
        left = conn.execute(
            "SELECT COUNT(*) FROM users WHERE is_active=1 AND role='admin'"
        ).fetchone()[0]
    finally:
        conn.close()
    check("CONTROL: exactly one active admin remains, so the check can bite",
          left == 1, left)

    r = sessions[A].post("/api/users/%d/update" % admin_id, json={"role": U})
    check("demoting the ONLY admin is refused (409)", r.status_code == 409,
          (r.status_code, r.get_json()))
    r = sessions[A].post("/api/users/%d/update" % admin_id, json={"is_active": False})
    check("deactivating the ONLY admin is refused (409)", r.status_code == 409,
          (r.status_code, r.get_json()))
    r = sessions[A].post("/api/users/%d/delete" % admin_id, json={})
    check("an admin cannot delete the account it is signed in as",
          r.status_code == 409, (r.status_code, r.get_json()))

    # CONTROL: the refusals above must be about ADMINDNESS, not a dead route.
    r = sessions[A].post("/api/users/%d/update" % accounts[V][0],
                         json={"display_name": "test data RBAC probe renamed"})
    check("CONTROL: a harmless update on a non-admin DOES succeed",
          r.status_code == 200, (r.status_code, r.get_json()))
    r = sessions[A].post("/api/users/%d/update" % accounts[U][0], json={"role": A})
    check("CONTROL: promoting someone else to admin succeeds",
          r.status_code == 200, (r.status_code, r.get_json()))
    r = sessions[A].post("/api/users/%d/update" % admin_id, json={"role": U})
    check("...and NOW demoting the original admin is allowed (a second exists)",
          r.status_code == 200, (r.status_code, r.get_json()))

    print("\n-- an account with a CORRUPT role is refused, not promoted --")
    corrupt_id = accounts[V][0]
    conn = sqlite3.connect(db)
    try:
        conn.execute("UPDATE users SET role='wizard' WHERE id=?", (corrupt_id,))
        conn.commit()
    finally:
        conn.close()
    c = app.test_client()
    c.post("/login", data={"username": accounts[V][1], "password": PW})
    check("a corrupt role cannot read the dashboard",
          c.get("/").status_code == 403)
    check("a corrupt role certainly cannot write",
          c.post("/api/config/update", json={}).status_code == 403)
    check("...but can still reach its own account page (self-service)",
          c.get("/account/password").status_code == 200)

    print("\n-- roles.UNAUTHENTICATED must stay in step with _AUTH_EXEMPT --")
    # Two hand-maintained sets naming the same concept in two files is a drift
    # risk by construction. Reconciled here rather than trusted: a route added to
    # one and not the other is either an unauthenticated route the role gate
    # still tries to gate (breaks it), or an authenticated route the role gate
    # skips (a hole). `logout` legitimately lives in SELF_SERVICE rather than
    # UNAUTHENTICATED, so both are allowed to account for a name.
    import re as _re
    _src = open(os.path.join(_REPO, "dashboard.py"), encoding="utf-8").read()
    _m = _re.search(r"_AUTH_EXEMPT\s*=\s*\{(.*?)\n\n", _src, _re.S)
    exempt = set(_re.findall(r'"([a-z_0-9]+)"', _m.group(1))) if _m else set()
    check("CONTROL: _AUTH_EXEMPT was actually parsed", len(exempt) >= 8, exempt)
    check("nothing is auth-exempt but unaccounted for by roles.py",
          not (exempt - roles.UNAUTHENTICATED - roles.SELF_SERVICE),
          sorted(exempt - roles.UNAUTHENTICATED - roles.SELF_SERVICE))
    check("roles.py claims nothing unauthenticated that the auth gate gates",
          not (roles.UNAUTHENTICATED - exempt),
          sorted(roles.UNAUTHENTICATED - exempt))

    print("\n-- static/role.js RANK must mirror roles.ROLES --")
    # The same drift shape as the pair above, in a different language. role.js
    # hides controls a role cannot use; its RANK map is a hand-written copy of
    # the server's ordering. It DID drift -- `sub_admin` shipped server-side on
    # 2026-08-22 and was missing here until 2026-08-24, during which a sub_admin
    # scored rankOf() === -1, below every minimum, and saw fewer controls than a
    # view-only account. Nothing caught it because nothing FAILED: no request was
    # refused, no error logged, the page just quietly rendered less.
    #
    # Order matters as much as membership: the ranks are compared with >=, so a
    # correct set in the wrong order silently rewrites who sees what.
    _rjs = open(os.path.join(_REPO, "static", "role.js"), encoding="utf-8").read()
    _rm = _re.search(r"var RANK\s*=\s*\{([^}]*)\}", _rjs)
    js_rank = ({k: int(v) for k, v in _re.findall(r"(\w+)\s*:\s*(\d+)", _rm.group(1))}
               if _rm else {})
    check("CONTROL: role.js RANK was actually parsed (not an empty match)",
          len(js_rank) >= 3, js_rank)
    check("role.js names exactly the roles roles.py does",
          set(js_rank) == set(roles.ROLES),
          "js=%s py=%s" % (sorted(js_rank), sorted(roles.ROLES)))
    check("role.js ranks them in the SAME ORDER as roles.ROLES",
          [r for r in sorted(js_rank, key=js_rank.get)] == list(roles.ROLES),
          "js=%s py=%s" % (sorted(js_rank, key=js_rank.get), list(roles.ROLES)))
    check("no role in roles.py would score -1 in role.js "
          "(which is below every minimum, hiding the whole product)",
          all(r in js_rank for r in roles.ROLES),
          sorted(set(roles.ROLES) - set(js_rank)))

    print("\n-- registry completeness against the LIVE url_map --")
    live_eps = {r.endpoint for r in app.url_map.iter_rules()}
    ok = True
    try:
        roles.assert_registry_complete(live_eps)
    except roles.RoleError as e:
        ok = False
        detail = str(e)
    check("every live endpoint has a role assignment",
          ok, "" if ok else detail)
    check("CONTROL: the live url_map is not trivially small",
          len(live_eps) > 130, len(live_eps))

    # Clean up the probe accounts from the COPY (belt and braces -- the copy is
    # deleted below anyway, and nothing here ever touched the live DB).
    conn = sqlite3.connect(db)
    try:
        conn.execute("DELETE FROM users WHERE username LIKE 'zz_test_%'")
        conn.commit()
    finally:
        conn.close()

shutil.rmtree(_tmp, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== PART 3: MUTATION — the canary must CATCH each injected defect ==")

src = open(_SRC, encoding="utf-8").read()


def _load(text):
    """Mutants beside the real file — a /tmp copy cannot resolve the shared
    canary harness and would die before any mutation mattered."""
    fd, path = tempfile.mkstemp(suffix=".py", prefix="_mutant_", dir=_HERE)
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        spec = importlib.util.spec_from_file_location("roles_mutant", path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return True, None
    except Exception as exc:                                   # noqa: BLE001
        return False, exc
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


_ctl_ok, _ctl_exc = _load(src)
check("CONTROL: the unmutated source imports from the mutant path",
      _ctl_ok, "every catch below would be this instead: %r" % (_ctl_exc,))

MUTATIONS = [
    ("SECURITY: an unknown endpoint resolves to ALLOW instead of admin",
     "    entry = ROUTE_MINIMUMS.get(endpoint)\n    if entry is None:\n        return ROLE_ADMIN",
     "    entry = ROUTE_MINIMUMS.get(endpoint)\n    if entry is None:\n        return ROLE_VIEWONLY"),
    ("SECURITY: an unparseable role defaults to admin instead of raising",
     '        raise UnknownRole("%r is not a known role" % (raw,)) from None',
     "        return ROLE_ADMIN"),
    # Anchor updated 2026-08-23 when sub_admin was inserted. The previous anchor
    # named the 3-role tuple and stopped matching, which this suite reported as
    # "anchor not found -- this TEST is stale, not the code" rather than passing.
    # That is the behaviour to preserve: a mutation whose anchor has drifted must
    # fail loudly, because a silently-unapplied mutation is a check that cannot
    # fail.
    ("SECURITY: the ordering is inverted",
     "ROLES = (ROLE_VIEWONLY, ROLE_USER, ROLE_SUB_ADMIN, ROLE_ADMIN)",
     "ROLES = (ROLE_ADMIN, ROLE_SUB_ADMIN, ROLE_USER, ROLE_VIEWONLY)"),
    ("SECURITY: at_least becomes an equality test (admin loses everything)",
     "    return rank(role) >= rank(minimum)",
     "    return rank(role) == rank(minimum)"),
    ("SECURITY: every method is treated as safe (writes use the read minimum)",
     'SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})',
     'SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "DELETE", "PUT"})'),
    ("SECURITY: netprobe drops to user (active tooling stops being admin-only)",
     '    "module_netprobe__api_ping":     (_A, _A),',
     '    "module_netprobe__api_ping":     (_U, _U),'),
    ("SECURITY: module disable drops to user (coverage becomes disableable)",
     '    "api_module_disable":             (_A, _A),',
     '    "api_module_disable":             (_U, _U),'),
    ("the abuse-report route becomes viewonly-reachable",
     '    "report_abuse":                   (_A, _A),   # POSTs a permanent report to AbuseIPDB',
     '    "report_abuse":                   (_V, _V),'),
    ("diagnostics execution becomes viewonly-reachable",
     '    "api_diag_run_all":               (_U, _U),   # executes diagnostic checks (POST-only)',
     '    "api_diag_run_all":               (_V, _V),'),
    ("self-service is gated by role (viewonly locked out of its own password)",
     'SELF_SERVICE = frozenset({\n    "change_password",',
     'SELF_SERVICE = frozenset({\n    "_change_password_disabled",'),
    ("a bad MINIMUM quietly denies instead of raising",
     "    return rank(role) >= rank(minimum)",
     "    try:\n        return rank(role) >= rank(minimum)\n    except Exception:\n        return False"),
]

for label, old, new in MUTATIONS:
    if old not in src:
        check("MUTATION anchor present: %s" % label, False,
              "anchor not found -- this TEST is stale, not the code")
        continue
    if not _ctl_ok:
        check("canary catches: %s" % label, False, "SKIPPED - control failed")
        continue
    imported, _exc = _load(src.replace(old, new, 1))
    check("canary catches: %s" % label, not imported,
          "the mutated module imported cleanly - the canary is not measuring")

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
