#!/usr/bin/env python3
"""Synthetic injection test for the alert_watcher quarantine flow.

Exercises three end-to-end scenarios without waiting for a real P1+CRITICAL alert:

  1. confirm  inject P1+CRITICAL -> banner -> /api/quarantine/<id>/confirm -> action=block
  2. lift     inject P1+CRITICAL -> banner -> /api/quarantine/<id>/lift    -> action=pending
  3. expire   inject P1+CRITICAL -> backdate expires_at -> sweep auto-lifts

Dry-run by default: enrichment, ufw, and email are monkeypatched so this script
has no firewall or network side effects. Pass --live to actually invoke ufw
(requires root). Synthetic rule_ids 9999991-3 and src_ip 203.0.113.99 (TEST-NET-3)
are used and cleaned up before and after each scenario.

The dashboard service must be reachable at http://127.0.0.1:5000 for the HTTP
checks. The alert-watcher service does NOT need to be running -- this script
calls handle_line() and expiry_sweep() in-process.

AUTHENTICATION: every dashboard route this suite calls is auth-gated (none of
them appear in dashboard.py's _AUTH_EXEMPT), so the HTTP half needs a logged-in
session. Pass --username/--password, or set NEMESIS_TEST_USER /
NEMESIS_TEST_PASSWORD. No dashboard credential is stored anywhere in the repo,
and local-config.md records the production host as "reference only, no stored
password" -- so an unattended run legitimately has none. Without credentials the
HTTP checks report as SKIPPED and the suite exits 3 (incomplete), never 0: a
check that could not run is not a check that passed.
"""

import argparse
import http.cookiejar
import json
import os
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

_HERE = os.path.dirname(os.path.abspath(__file__))

# alert_watcher.py lives in core_module/alert_watcher/ after the 2026-07-28
# layout move; its siblings (database, firewall, email_utils, ip_enrichment,
# nemesis_paths) are still here in alert_manager/. Both directories are needed,
# with core_module first so this resolves to the relocated copy.
sys.path.insert(0, _HERE)  # alert_manager/ — alert_watcher's sibling imports
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "core_module", "alert_watcher"))
import alert_watcher  # noqa: E402
import nemesis_paths  # noqa: E402

# Same resolution alert_watcher itself uses, so the test reads the database the
# watcher actually writes. Computing it from this file's location instead was a
# silent failure: alerts.db no longer sits in the tree, so sqlite3.connect()
# created an empty stray DB here and every check ran against it. (ADR 0001.)
DB_PATH = nemesis_paths.db_path(os.path.join(_HERE, "alerts.db"))
DASHBOARD = "http://127.0.0.1:5000"
TEST_IP = "203.0.113.99"
# Correct here, and ONLY because this test monkeypatches enrich_ip below.
#
# RFC 5737 addresses (192.0.2.x, 198.51.100.x, 203.0.113.x) are classified
# PRIVATE by Python: `ipaddress.ip_address("203.0.113.99").is_private` is True.
# Any code that branches on address scope therefore SKIPS them —
# `ip_enrichment.enrich_ip()` early-returns for private/loopback/link-local, and
# anomaly_detection's AbuseIPDB path filters them out of its resolved set.
#
# The failure mode is silent and looks like success: a test that never reaches
# the logic reports zero external lookups, which is indistinguishable from
# perfect deduplication. (Confirmed the hard way, 2026-08-03.)
#
# So: keep RFC 5737 for DB row content, where Rule 11's labelling convention
# intends it. If a test needs to exercise an is_private branch for real, use
# TEST_IP_PUBLIC below instead.
#
# 192.88.99.x is the deliberate choice over 8.8.8.8/1.1.1.1: it is IANA-reserved
# and deprecated (RFC 7526, the retired 6to4 relay anycast prefix), so nothing
# operates it and an accidental real connection goes nowhere — yet Python
# classifies it as public, so it exercises the code path. Verified 2026-08-03
# against every documentation/reserved range; the RFC 2544 benchmarking and
# TEST-NET blocks are all is_private=True, and 100.64.0.0/10 reads as public but
# is the tailnet range and would be actively misleading here.
TEST_IP_PUBLIC = "192.88.99.1"
RULE_IDS = {"confirm": "9999991", "lift": "9999992", "expire": "9999993"}

passed = 0
failed = 0
skipped = 0


def check(name, cond, detail=""):
    global passed, failed
    mark = "PASS" if cond else "FAIL"
    suffix = f"  ({detail})" if (not cond and detail) else ""
    print(f"  [{mark}] {name}{suffix}")
    if cond:
        passed += 1
    else:
        failed += 1
    return cond


def skip(name, reason):
    """Record a check that did NOT run, as its own state — never as a pass.

    A check that cannot run is not a check that succeeded. Counting it as either
    a pass or a failure loses the distinction the reader needs: `failed=0` has to
    mean "everything was measured and held", not "some of it was never asked".
    The exit code in main() treats a skip as an incomplete run for the same
    reason.
    """
    global skipped
    skipped += 1
    print(f"  [SKIP] {name}  ({reason})")
    return False


def fake_line(rule_id, ip=TEST_IP):
    """One synthetic Suricata alert line, labelled for later cleanup (Rule 11).

    Every row this suite writes to the live alerts.db must carry the literal
    phrase "test data" AND the date, so a cleanup pass finds it with a single
    `LIKE '%test data%'` sweep instead of guessing which rows are synthetic.

    alert_watcher hardcodes `explanation` to '' in its INSERT and every other
    alerts column is structured, so the label has to ride in on the parsed text.
    It is placed in BOTH the rule-name segment and the Classification, on purpose:

    `parse_alert` (alert_manager/firewall.py) splits on "[**]" and takes
    `parts[2]` as rule_name — but in Suricata's fast.log format the rule name is
    in `parts[1]`; `parts[2]` is the Classification/Priority block. So today the
    label only reaches the row via the Classification, and a label placed solely
    in the rule-name position would silently never arrive. That parser bug is
    reported separately and is NOT assumed fixed here — putting the phrase in
    both places means this label keeps working whether or not it is corrected,
    rather than quietly breaking the day someone fixes it.

    Kept early and short deliberately: process_new_alert stores `rule_name[:50]`,
    so a label further right would be truncated away and the sweep would miss the
    very rows it exists to find.

    KNOWN GAP, recorded rather than papered over: the `quarantines` row this
    alert causes CANNOT be labelled. That table is (id, ip, rule_id, expires_at,
    created_at, status, actor) — every column structured, no free-text field —
    exactly the shape Rule 11 already documents as the `audit_log` exception. Its
    rows are instead findable by their RFC 5737 address (TEST_IP) and by the
    RULE_IDS below, both of which are reserved for this suite.
    """
    now = datetime.now()
    label = "test data %s" % now.strftime("%Y-%m-%d")
    return (f"{now.strftime('%m/%d/%Y-%H:%M:%S.%f')}  [**] [1:{rule_id}:1] "
            f"TEST Synthetic Quarantine {label} "
            f"[**] [Classification: Test {label}] [Priority: 1] {{TCP}} "
            f"{ip}:55555 -> 192.168.1.10:443")


# ── HTTP layer ───────────────────────────────────────────────────────────────
#
# Two defects lived in the previous four-line version of this section, and both
# are the same family: an instrument that could only ever return one answer.
#
# 1. It followed redirects. Every route this suite exercises is auth-gated
#    (absent from dashboard.py's _AUTH_EXEMPT, gate at `_enforce_setup_and_auth`),
#    and the gate answers an unauthenticated request with a 302 to /login.
#    urllib.request.urlopen follows that by default, so the LOGIN PAGE arrived
#    as a 200 and `check("/api/quarantines status=200", status == 200)` PASSED
#    on it — three green checks, in three scenarios, measuring nothing but the
#    existence of a login form. Measured 2026-08-06.
# 2. It only ever issued GET. The confirm/lift routes were hardened to
#    methods=["POST"] on 2026-07-28 (8c8bce9) and have returned 405 ever since.
#
# Fixing (2) alone would not have turned a single check green: a POST from an
# unauthenticated client is still 302'd to /login, so `success=true` and both DB
# transitions stay red. The method and the session had to be fixed together.
#
# Hence both halves below: an opener that does NOT chase redirects, so a 302
# surfaces as a 302 and reads as the result it is; and json_response(), which
# requires a 200 to actually carry the ROUTE's JSON rather than any 200-shaped
# page that happens to come back.


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Surface a redirect instead of chasing it.

    The auth gate's 302 is a RESULT this suite needs to see, not an obstacle to
    route around. Returning None here makes urllib raise HTTPError(302), which
    the callers below report as the status.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_cookies = http.cookiejar.CookieJar()
_opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(_cookies), _NoRedirect)

# Set by authenticate() and ONLY by a positively-verified login. It gates the
# auth-dependent checks; nothing infers it from a status code alone.
AUTHENTICATED = False


def http_request(path, method="GET", data=None):
    """One request on the shared (cookie-carrying) session. Never follows redirects."""
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(DASHBOARD + path, data=body, method=method)
    try:
        with _opener.open(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def http_get(path):
    return http_request(path)


def json_response(path, method="GET", data=None):
    """(status, parsed) where `parsed` is non-None ONLY for real JSON from the route.

    An HTML page — the login form especially — parses as None, so a caller
    asserting on `parsed` cannot be satisfied by the auth gate the way a bare
    status check could.
    """
    status, body = http_request(path, method=method, data=data)
    try:
        return status, json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return status, None


def authenticate(username, password):
    """Log the shared session in. Returns True only on POSITIVELY verified auth.

    Verified in both directions, because a one-directional check here would be
    the same non-measurement this module already shipped once: first confirm the
    session is genuinely unauthenticated (the gate 302s), then log in, then
    confirm the SAME request now returns the route's own JSON. Without the
    before-half, a dashboard with the gate disabled would look like a successful
    login; without the after-half, any 200 would.
    """
    global AUTHENTICATED

    before, _ = http_request("/api/quarantines")
    if before != 302:
        print(f"  [WARN] pre-login control: expected 302 from the auth gate, got {before}. "
              f"Not treating this run as authenticated — the gate is not behaving as "
              f"this check assumes, so a later 200 would prove nothing.")
        return False

    status, _ = http_request("/login", method="POST",
                             data={"username": username, "password": password})
    if status not in (200, 302):
        print(f"  [WARN] login POST returned {status}")
        return False

    after, parsed = json_response("/api/quarantines")
    if after == 200 and isinstance(parsed, dict) and "quarantines" in parsed:
        AUTHENTICATED = True
        return True

    print(f"  [WARN] login did not take: /api/quarantines returned {after} "
          f"{'(HTML, not JSON — still the login page)' if parsed is None else ''}")
    return False


def db_row(query, params=()):
    conn = sqlite3.connect(DB_PATH)
    try:
        c = conn.cursor()
        c.execute(query, params)
        return c.fetchone()
    finally:
        conn.close()


def cleanup(rule_id):
    conn = sqlite3.connect(DB_PATH)
    try:
        c = conn.cursor()
        c.execute("DELETE FROM alerts WHERE rule_id=?", (rule_id,))
        c.execute("DELETE FROM quarantines WHERE rule_id=?", (rule_id,))
        conn.commit()
    finally:
        conn.close()


def patch_externals(live):
    # 2026-07-28: alert_watcher no longer calls ufw_delete. The expiry path is
    # expire_quarantine(), a narrower op the helper only honours after
    # independently confirming the quarantines row is active and past its
    # expires_at. The key is still called "ufw_delete" so the existing
    # assertions below read unchanged — it now counts expiry calls.
    calls = {"ufw_insert": [], "ufw_delete": [], "emails": []}
    saved = {
        "enrich": alert_watcher.enrich_ip,
        "insert": alert_watcher.ufw_insert_top,
        "delete": alert_watcher.expire_quarantine,
        "email": alert_watcher.send_email,
    }

    alert_watcher.enrich_ip = lambda ip: {
        "ip": ip, "country": "XX", "city": "Testville",
        "isp": "TestISP", "org": None,
        "is_tor": False, "is_vpn": False,
        "abuse_confidence_score": 95, "total_reports": 42,
        "last_reported": None, "threat_level": "CRITICAL",
        "summary": f"{ip} - synthetic test (CRITICAL)",
    }

    def fake_email(subj, body):
        calls["emails"].append(subj)
        return True

    alert_watcher.send_email = fake_email

    if not live:
        def fake_insert(ip):
            calls["ufw_insert"].append(ip)
            return True

        def fake_delete(ip):
            calls["ufw_delete"].append(ip)
            return True

        alert_watcher.ufw_insert_top = fake_insert
        alert_watcher.expire_quarantine = fake_delete

    return calls, saved


def restore(saved):
    alert_watcher.enrich_ip = saved["enrich"]
    alert_watcher.ufw_insert_top = saved["insert"]
    alert_watcher.expire_quarantine = saved["delete"]
    alert_watcher.send_email = saved["email"]


def inject_and_verify(rule_id, calls):
    """Inject one fake alert, verify watcher created a quarantine. Returns qid or None."""
    alert_watcher.handle_line(fake_line(rule_id))

    a = db_row("SELECT action, risk_level, src_ip FROM alerts WHERE rule_id=?", (rule_id,))
    if not check("alerts row inserted", a is not None):
        return None
    check("alerts.action=auto-quarantine", a[0] == "auto-quarantine", a[0])
    check("alerts.risk_level=CRITICAL", a[1] == "CRITICAL", a[1])
    check("alerts.src_ip captured", a[2] == TEST_IP, a[2])

    q = db_row("SELECT id, ip, status, expires_at FROM quarantines WHERE rule_id=?", (rule_id,))
    if not check("quarantines row inserted", q is not None):
        return None
    qid, qip, qstatus, qexp = q
    check("quarantine.status=active", qstatus == "active", qstatus)
    check("quarantine.ip=test_ip", qip == TEST_IP, qip)
    remaining = (datetime.fromisoformat(qexp) - datetime.now()).total_seconds()
    check("expires_at ~1h in future", 3500 < remaining < 3700, f"{remaining:.0f}s")
    check("ufw_insert_top called once", len(calls["ufw_insert"]) == 1, repr(calls["ufw_insert"]))
    check("email sent once", len(calls["emails"]) == 1, repr(calls["emails"]))

    if not AUTHENTICATED:
        for name in ("/api/quarantines returns the route's JSON",
                     "quarantine appears in /api/quarantines",
                     "dashboard ip=test_ip",
                     "dashboard minutes_remaining ~60",
                     "test_ip appears in banner on /"):
            skip(name, "no authenticated session — pass --username/--password")
        return qid

    status, data = json_response("/api/quarantines")
    # Asserts on the parsed body, not just the status: a 200 alone was
    # satisfiable by the login page (see the HTTP layer note above).
    check("/api/quarantines returns the route's JSON",
          status == 200 and isinstance(data, dict) and "quarantines" in data,
          f"status={status} parsed={'None (HTML)' if data is None else type(data).__name__}")
    items = (data or {}).get("quarantines", []) if isinstance(data, dict) else []
    ours = next((x for x in items if x["rule_id"] == rule_id), None)
    check("quarantine appears in /api/quarantines", ours is not None)
    if ours:
        check("dashboard ip=test_ip", ours["ip"] == TEST_IP)
        check("dashboard minutes_remaining ~60",
              55 <= ours.get("minutes_remaining", 0) <= 60,
              str(ours.get("minutes_remaining")))

    status, body = http_get("/")
    check("test_ip appears in banner on /", status == 200 and TEST_IP in body,
          f"status={status}")

    return qid


def scenario_confirm(live):
    print("\n[Scenario 1] inject -> confirm via dashboard")
    rule_id = RULE_IDS["confirm"]
    cleanup(rule_id)
    calls, saved = patch_externals(live)
    try:
        qid = inject_and_verify(rule_id, calls)
        if qid is None:
            return
        if not AUTHENTICATED:
            for name in ("confirm endpoint status=200", "confirm success=true",
                         "alerts.action=block after confirm",
                         "quarantine.status=confirmed"):
                skip(name, "no authenticated session — pass --username/--password")
        else:
            # POST, not GET: hardened to methods=["POST"] on 2026-07-28 (8c8bce9).
            status, data = json_response(f"/api/quarantine/{qid}/confirm", method="POST")
            check("confirm endpoint status=200", status == 200, str(status))
            check("confirm success=true",
                  isinstance(data, dict) and data.get("success") is True, repr(data)[:120])
            a = db_row("SELECT action FROM alerts WHERE rule_id=?", (rule_id,))
            check("alerts.action=block after confirm", a and a[0] == "block", repr(a))
            q = db_row("SELECT status FROM quarantines WHERE id=?", (qid,))
            check("quarantine.status=confirmed", q and q[0] == "confirmed", repr(q))
        # Independent of the HTTP session: counts an in-process monkeypatch, so it
        # stays a real check even on an unauthenticated run.
        check("ufw_delete NOT called by confirm", len(calls["ufw_delete"]) == 0)
    finally:
        restore(saved)
        cleanup(rule_id)


def scenario_lift(live):
    print("\n[Scenario 2] inject -> lift via dashboard")
    rule_id = RULE_IDS["lift"]
    cleanup(rule_id)
    calls, saved = patch_externals(live)
    try:
        qid = inject_and_verify(rule_id, calls)
        if qid is None:
            return
        if not AUTHENTICATED:
            for name in ("lift endpoint status=200", "lift success=true",
                         "alerts.action=pending after lift",
                         "quarantine.status=lifted"):
                skip(name, "no authenticated session — pass --username/--password")
            return
        # POST, not GET: hardened to methods=["POST"] on 2026-07-28 (8c8bce9).
        status, data = json_response(f"/api/quarantine/{qid}/lift", method="POST")

        # The dashboard runs in a SEPARATE process, so this suite's in-process
        # monkeypatching does not reach its firewall calls. lift() asks
        # nemesis-fwd to remove the rule with a per-action credential, and on
        # refusal it returns an error and deliberately leaves the DB untouched —
        # showing a lifted quarantine whose ufw rule is still installed would be
        # worse than refusing. That refusal is CORRECT product behaviour, not a
        # test failure, so it is reported as its own outcome. Asserting
        # status=200 through it would make this suite red whenever the box has no
        # firewall credential, which is the normal state for an operator run.
        kind = data.get("kind") if isinstance(data, dict) else None
        if kind in ("credential_denied", "admin_denied", "locked_out",
                    "unavailable", "peer_denied"):
            check("lift endpoint reached and failed CLOSED (no credential)",
                  status in (401, 403, 423, 503), f"status={status} kind={kind}")
            q = db_row("SELECT status FROM quarantines WHERE id=?", (qid,))
            check("quarantine NOT lifted when the firewall refused",
                  q and q[0] == "active", repr(q))
            for name in ("lift success=true", "alerts.action=pending after lift",
                         "quarantine.status=lifted"):
                skip(name, f"firewall refused the unblock ({kind}) — "
                           f"the lift path cannot be exercised without a credential")
            return

        check("lift endpoint status=200", status == 200, str(status))
        check("lift success=true",
              isinstance(data, dict) and data.get("success") is True, repr(data)[:120])
        a = db_row("SELECT action FROM alerts WHERE rule_id=?", (rule_id,))
        check("alerts.action=pending after lift", a and a[0] == "pending", repr(a))
        q = db_row("SELECT status FROM quarantines WHERE id=?", (qid,))
        check("quarantine.status=lifted", q and q[0] == "lifted", repr(q))
        if isinstance(data, dict):
            for k in ("ufw_ok", "ufw_rc"):
                if k in data:
                    print(f"    (dashboard reported {k}={data[k]})")
                    break
    finally:
        restore(saved)
        cleanup(rule_id)


def scenario_expire(live):
    print("\n[Scenario 3] inject -> backdate expires_at -> expiry_sweep auto-lifts")
    rule_id = RULE_IDS["expire"]
    cleanup(rule_id)
    calls, saved = patch_externals(live)
    try:
        qid = inject_and_verify(rule_id, calls)
        if qid is None:
            return
        past = (datetime.now() - timedelta(minutes=1)).isoformat()
        conn = sqlite3.connect(DB_PATH)
        try:
            c = conn.cursor()
            c.execute("UPDATE quarantines SET expires_at=? WHERE id=?", (past, qid))
            conn.commit()
        finally:
            conn.close()
        check("backdated expires_at by 1 min", True)

        alert_watcher.expiry_sweep()

        a = db_row("SELECT action FROM alerts WHERE rule_id=?", (rule_id,))
        check("alerts.action=pending after expiry", a and a[0] == "pending", repr(a))
        q = db_row("SELECT status FROM quarantines WHERE id=?", (qid,))
        check("quarantine.status=expired", q and q[0] == "expired", repr(q))
        check("ufw_delete called by sweep", len(calls["ufw_delete"]) == 1, repr(calls["ufw_delete"]))
        # A "blocked_cache pruned" check used to sit here. It is REMOVED
        # deliberately, not dropped by accident: alert_watcher no longer keeps an
        # in-memory blocked-IP cache, so handle_line() and expiry_sweep() take no
        # such argument. Rewritten against a plain local set it would have been
        # vacuously true -- a check that can only ever pass, which is worse than
        # no check at all because it reports a non-measurement as a result.
        #
        # Its intent -- "the IP is no longer treated as blocked" -- is carried by
        # the two checks immediately above: the quarantine row reaching 'expired',
        # and ufw_delete actually being called. There is no in-memory cache left
        # to prune, and no load_blocked_ips() oracle exists to assert against.
    finally:
        restore(saved)
        cleanup(rule_id)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--live", action="store_true",
                    help="actually invoke ufw insert/delete (requires root)")
    ap.add_argument("--scenario", choices=["confirm", "lift", "expire", "all"],
                    default="all")
    ap.add_argument("--username", default=os.environ.get("NEMESIS_TEST_USER"),
                    help="dashboard login for the auth-gated HTTP checks "
                         "(or set NEMESIS_TEST_USER)")
    ap.add_argument("--password", default=os.environ.get("NEMESIS_TEST_PASSWORD"),
                    help="dashboard password (or set NEMESIS_TEST_PASSWORD). No "
                         "credential is stored in the repo or in local-config.md, "
                         "so the HTTP checks are SKIPPED unless one is supplied.")
    args = ap.parse_args()

    if args.live and os.geteuid() != 0:
        print("--live requires root (re-run with sudo)", file=sys.stderr)
        sys.exit(2)

    # Pre-flight: dashboard must be reachable. A 302 to /login is a perfectly
    # good liveness answer here — it proves the app is up and routing. What it
    # must NOT do is pass silently as evidence that the API itself works, which
    # is what the old redirect-following version of this check did.
    try:
        status, _ = http_get("/api/stats")
        if status not in (200, 302):
            print(f"dashboard /api/stats returned {status}; is the service running?",
                  file=sys.stderr)
            sys.exit(2)
    except Exception as e:
        print(f"cannot reach dashboard at {DASHBOARD}: {e}", file=sys.stderr)
        sys.exit(2)

    if args.username and args.password:
        if authenticate(args.username, args.password):
            print(f"authenticated to {DASHBOARD} as {args.username}")
        else:
            print("authentication FAILED — the auth-gated HTTP checks will be "
                  "skipped, not silently passed", file=sys.stderr)
    else:
        print("no credentials supplied: the auth-gated HTTP checks will be SKIPPED.\n"
              "  Every route this suite calls is behind the login gate, so without a\n"
              "  session they cannot be measured. Pass --username/--password (or set\n"
              "  NEMESIS_TEST_USER / NEMESIS_TEST_PASSWORD) for a complete run.")

    alert_watcher.init_quarantines_db()

    if args.scenario in ("confirm", "all"):
        scenario_confirm(args.live)
    if args.scenario in ("lift", "all"):
        scenario_lift(args.live)
    if args.scenario in ("expire", "all"):
        scenario_expire(args.live)

    print(f"\n{'=' * 50}")
    print(f"Total: {passed} passed, {failed} failed, {skipped} skipped")

    # Three outcomes, deliberately not two. A run with skips is INCOMPLETE, and
    # exiting 0 on it would let "no failures" be read as "the quarantine flow is
    # verified" when the entire dashboard half of it was never exercised.
    if failed:
        print("RESULT: FAILED")
        sys.exit(1)
    if skipped:
        print(f"RESULT: INCOMPLETE — {skipped} checks did not run. "
              f"Supply credentials for a full pass.")
        sys.exit(3)
    print("RESULT: all checks passed")
    sys.exit(0)


if __name__ == "__main__":
    main()
