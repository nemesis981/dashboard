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
"""

import argparse
import json
import os
import sqlite3
import sys
import urllib.error
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
RULE_IDS = {"confirm": "9999991", "lift": "9999992", "expire": "9999993"}

passed = 0
failed = 0


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


def fake_line(rule_id, ip=TEST_IP):
    now = datetime.now().strftime("%m/%d/%Y-%H:%M:%S.%f")
    return (f"{now}  [**] [1:{rule_id}:1] TEST Synthetic Quarantine "
            f"[**] [Classification: Test] [Priority: 1] {{TCP}} "
            f"{ip}:55555 -> 192.168.1.10:443")


def http_get(path):
    try:
        with urllib.request.urlopen(DASHBOARD + path, timeout=5) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def http_json(path):
    status, body = http_get(path)
    try:
        return status, json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return status, None


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
    blocked_cache = set()
    alert_watcher.handle_line(fake_line(rule_id), blocked_cache)

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

    status, data = http_json("/api/quarantines")
    check("/api/quarantines status=200", status == 200, str(status))
    items = (data or {}).get("quarantines", []) if isinstance(data, dict) else []
    ours = next((x for x in items if x["rule_id"] == rule_id), None)
    check("quarantine appears in /api/quarantines", ours is not None)
    if ours:
        check("dashboard ip=test_ip", ours["ip"] == TEST_IP)
        check("dashboard minutes_remaining ~60",
              55 <= ours.get("minutes_remaining", 0) <= 60,
              str(ours.get("minutes_remaining")))

    _, body = http_get("/")
    check("test_ip appears in banner on /", TEST_IP in body)

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
        status, data = http_json(f"/api/quarantine/{qid}/confirm")
        check("confirm endpoint status=200", status == 200, str(status))
        check("confirm success=true", isinstance(data, dict) and data.get("success") is True)
        a = db_row("SELECT action FROM alerts WHERE rule_id=?", (rule_id,))
        check("alerts.action=block after confirm", a and a[0] == "block", repr(a))
        q = db_row("SELECT status FROM quarantines WHERE id=?", (qid,))
        check("quarantine.status=confirmed", q and q[0] == "confirmed", repr(q))
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
        status, data = http_json(f"/api/quarantine/{qid}/lift")
        check("lift endpoint status=200", status == 200, str(status))
        check("lift success=true", isinstance(data, dict) and data.get("success") is True)
        a = db_row("SELECT action FROM alerts WHERE rule_id=?", (rule_id,))
        check("alerts.action=pending after lift", a and a[0] == "pending", repr(a))
        q = db_row("SELECT status FROM quarantines WHERE id=?", (qid,))
        check("quarantine.status=lifted", q and q[0] == "lifted", repr(q))
        # The dashboard runs in a separate process, so our in-process monkeypatch
        # of firewall.ufw_delete does NOT reach it. The dashboard's ufw_ok field
        # reports whether its own ufw_delete succeeded; expect False under the
        # default non-root, non-NOPASSWD context. DB transitions are the canonical signal.
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

        blocked_cache = {TEST_IP}
        alert_watcher.expiry_sweep(blocked_cache)

        a = db_row("SELECT action FROM alerts WHERE rule_id=?", (rule_id,))
        check("alerts.action=pending after expiry", a and a[0] == "pending", repr(a))
        q = db_row("SELECT status FROM quarantines WHERE id=?", (qid,))
        check("quarantine.status=expired", q and q[0] == "expired", repr(q))
        check("ufw_delete called by sweep", len(calls["ufw_delete"]) == 1, repr(calls["ufw_delete"]))
        check("blocked_cache pruned", TEST_IP not in blocked_cache)
    finally:
        restore(saved)
        cleanup(rule_id)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--live", action="store_true",
                    help="actually invoke ufw insert/delete (requires root)")
    ap.add_argument("--scenario", choices=["confirm", "lift", "expire", "all"],
                    default="all")
    args = ap.parse_args()

    if args.live and os.geteuid() != 0:
        print("--live requires root (re-run with sudo)", file=sys.stderr)
        sys.exit(2)

    # Pre-flight: dashboard must be reachable
    try:
        status, _ = http_get("/api/stats")
        if status != 200:
            print(f"dashboard /api/stats returned {status}; is the service running?",
                  file=sys.stderr)
            sys.exit(2)
    except Exception as e:
        print(f"cannot reach dashboard at {DASHBOARD}: {e}", file=sys.stderr)
        sys.exit(2)

    alert_watcher.init_quarantines_db()

    if args.scenario in ("confirm", "all"):
        scenario_confirm(args.live)
    if args.scenario in ("lift", "all"):
        scenario_lift(args.live)
    if args.scenario in ("expire", "all"):
        scenario_expire(args.live)

    print(f"\n{'=' * 50}")
    print(f"Total: {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
