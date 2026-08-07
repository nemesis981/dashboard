#!/usr/bin/env python3
"""
Tests for `nemesis_connectivity_notify` — episode tracking and notification.

RUNS ENTIRELY AGAINST A DATABASE COPY. Nothing here touches the live database,
sends real mail, or changes any host network state. The 2026-08-07 incident that
motivated this whole feature was caused by a test that altered real host network
state on a claim it would revert itself, so a test suite for the notifier must
not repeat the shape it exists to catch.

Every assertion group carries a CONTROL that must produce the opposite result.
An assertion that can only pass is not a test — that is the single most repeated
finding in this codebase, and this suite is written to be falsifiable.
"""

import os
import sqlite3
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

_PASS = 0
_FAIL = 0
_EXPECTED_CHECKS = 66


def check(label, got, want):
    global _PASS, _FAIL
    if got == want:
        _PASS += 1
        print("  PASS  %-58s %r" % (label, got))
    else:
        _FAIL += 1
        print("  ****  %-58s got=%r want=%r" % (label, got, want))


def section(t):
    print("\n== %s ==" % t)


# --------------------------------------------------------------------------- #
# Harness — DB copy + stubbed outbound channels
# --------------------------------------------------------------------------- #

def make_db():
    """A real schema on a throwaway file. Built by the CANONICAL init, not by
    hand-written DDL — a test that creates its own copy of the schema stops
    testing the schema the product actually ships."""
    fd, path = tempfile.mkstemp(prefix="nemtest_conn_", suffix=".db")
    os.close(fd)
    os.unlink(path)
    import database
    database.DB_PATH = path
    database.init_db()                          # alerts
    database.init_connectivity_episodes_table()  # the table under test
    return path


SENT_EMAILS = []
OPENED_TICKETS = []
TICKET_NOTES = []


def install_stubs(notify):
    """Replace the three outbound channels. Returns nothing; mutates the module.

    Stubbing at the notifier's own seam (not at smtplib) keeps the test honest
    about WHAT it is proving: episode/dedupe logic, not SMTP.
    """
    SENT_EMAILS.clear(); OPENED_TICKETS.clear(); TICKET_NOTES.clear()

    def fake_email(subject, body):
        SENT_EMAILS.append((subject, body))
        return True

    def fake_ticket(source, verdict, severity, title, body):
        OPENED_TICKETS.append((source, verdict, severity, title))
        return 1000 + len(OPENED_TICKETS)

    def fake_note(source, text):
        TICKET_NOTES.append((source, text))
        return 1

    def fake_record_error(code, context):
        return None

    notify._notify_email = fake_email
    notify._notify_ticket = fake_ticket
    notify._ticket_note = fake_note
    notify._record_error = fake_record_error


def rows(path, sql, args=()):
    conn = sqlite3.connect(path)
    try:
        cur = conn.execute(sql, args)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        conn.close()


def alert_count(path):
    return rows(path, "SELECT count(*) n FROM alerts")[0]["n"]


def episodes(path, source="diagnostics"):
    return rows(path, "SELECT * FROM connectivity_episodes WHERE source=? "
                      "ORDER BY id", (source,))


# --------------------------------------------------------------------------- #

def main():
    path = make_db()
    import database
    import nemesis_connectivity_notify as notify
    install_stubs(notify)

    section("0. Self-test of the harness (a control that MUST hold)")
    check("db starts with zero alerts", alert_count(path), 0)
    check("db starts with zero episodes", len(episodes(path)), 0)
    check("debounce constant is 3", notify.FAILURE_DEBOUNCE, 3)

    section("1. Passing cycles never create an episode")
    for _ in range(3):
        r = notify.observe("diagnostics", ok=True)
    check("action on healthy cycle", r["action"], "ok")
    check("no episode rows created", len(episodes(path)), 0)
    check("no alerts raised", alert_count(path), 0)

    section("2. Below the threshold: counted, but NOBODY is told")
    r1 = notify.observe("diagnostics", ok=False, verdict="LOCAL_FAIL", detail="dns resolution failed")
    check("first failure -> counting", r1["action"], "counting")
    check("consecutive == 1", r1["consecutive"], 1)
    r2 = notify.observe("diagnostics", ok=False, verdict="LOCAL_FAIL", detail="dns resolution failed")
    check("second failure -> still counting", r2["action"], "counting")
    check("consecutive == 2", r2["consecutive"], 2)
    check("STILL no alert at 2 failures", alert_count(path), 0)
    check("STILL no email at 2 failures", len(SENT_EMAILS), 0)
    check("STILL no ticket at 2 failures", len(OPENED_TICKETS), 0)
    check("episode row exists but is 'counting'", episodes(path)[0]["state"], "counting")

    section("3. Threshold crossed -> ONE episode, all three channels fire")
    r3 = notify.observe("diagnostics", ok=False, verdict="LOCAL_FAIL", detail="dns resolution failed")
    check("third failure -> opened", r3["action"], "opened")
    check("severity mapped from LOCAL_FAIL", r3["severity"], "HIGH")
    check("dashboard alert raised", alert_count(path), 1)
    check("email sent", len(SENT_EMAILS), 1)
    check("ticket opened", len(OPENED_TICKETS), 1)
    check("ticket carries HIGH severity", OPENED_TICKETS[0][2], "HIGH")
    ep = episodes(path)[0]
    check("episode state now open", ep["state"], "open")
    check("opened_at recorded", bool(ep["opened_at"]), True)
    check("email_sent flag persisted", ep["email_sent"], 1)
    check("ticket id persisted", ep["ticket_id"], 1001)
    check("alert rule_id persisted", ep["alert_rule_id"], "NEM-CONN-diagnostics-1")

    section("4. DEDUPE — the whole point. 24 more failures, zero new notifications")
    for _ in range(24):
        rn = notify.observe("diagnostics", ok=False, verdict="LOCAL_FAIL", detail="dns resolution failed")
    check("subsequent failures report 'ongoing'", rn["action"], "ongoing")
    check("STILL exactly 1 alert (not 25)", alert_count(path), 1)
    check("STILL exactly 1 email", len(SENT_EMAILS), 1)
    check("STILL exactly 1 ticket", len(OPENED_TICKETS), 1)
    check("consecutive count kept climbing", episodes(path)[0]["consecutive_failures"], 27)

    section("5. Recovery notifies and closes")
    rr = notify.observe("diagnostics", ok=True)
    check("recovery detected", rr["action"], "recovered")
    check("recovery alert raised (now 2 total)", alert_count(path), 2)
    check("recovery email sent (now 2 total)", len(SENT_EMAILS), 2)
    check("recovery note added to ticket", len(TICKET_NOTES), 1)
    ep = episodes(path)[0]
    check("episode closed", ep["state"], "closed")
    check("closed_at recorded", bool(ep["closed_at"]), True)
    check("no ticket auto-closed (note only)", len(OPENED_TICKETS), 1)

    section("6. CONTROL — a second passing cycle must NOT re-notify")
    notify.observe("diagnostics", ok=True)
    check("still 2 alerts after extra OK", alert_count(path), 2)
    check("still 2 emails after extra OK", len(SENT_EMAILS), 2)

    section("7. Sub-threshold blip closes silently (near-miss kept for evidence)")
    notify.observe("diagnostics", ok=False, verdict="LOCAL_FAIL", detail="dns resolution failed")
    notify.observe("diagnostics", ok=False, verdict="LOCAL_FAIL", detail="dns resolution failed")
    rb = notify.observe("diagnostics", ok=True)
    check("blip ended without escalating", rb["action"], "blip_ended")
    check("no new alert from the blip", alert_count(path), 2)
    check("no new email from the blip", len(SENT_EMAILS), 2)
    check("near-miss row RETAINED for tuning evidence", len(episodes(path)), 2)
    check("near-miss recorded its depth", episodes(path)[1]["consecutive_failures"], 2)

    section("8. Severity split — UPSTREAM_FAIL is NOT treated like LOCAL_FAIL")
    check("LOCAL_FAIL -> HIGH", notify.VERDICT_SEVERITY["LOCAL_FAIL"], "HIGH")
    check("UPSTREAM_FAIL -> MEDIUM", notify.VERDICT_SEVERITY["UPSTREAM_FAIL"], "MEDIUM")
    check("DEGRADED -> MEDIUM", notify.VERDICT_SEVERITY["DEGRADED"], "MEDIUM")
    # CONTROL: prove the mapping is actually consulted, not hardcoded downstream.
    for _ in range(3):
        ru = notify.observe("vpn_dns_guard", ok=False, verdict="DEGRADED",
                            detail="vpn dns upstream did not resolve")
    check("vpn_dns_guard episode opened", ru["action"], "opened")
    check("...with MEDIUM, not HIGH", ru["severity"], "MEDIUM")
    check("sources tracked independently", len(episodes(path, "vpn_dns_guard")), 1)

    section("9. Worst verdict is retained, not the latest")
    for _ in range(3):
        notify.observe("worsttest", ok=False, verdict="UPSTREAM_FAIL", detail="x")
    notify.observe("worsttest", ok=False, verdict="LOCAL_FAIL", detail="x")
    notify.observe("worsttest", ok=False, verdict="UPSTREAM_FAIL", detail="x")
    ew = episodes(path, "worsttest")[0]
    check("worst verdict kept after downgrade", ew["verdict"], "LOCAL_FAIL")
    check("worst severity kept after downgrade", ew["severity"], "HIGH")

    section("10. Restart survival — state is durable, not in-memory")
    # Simulate a service restart mid-episode: drop the module and re-import it,
    # which is the closest in-process equivalent of the process dying. The 5
    # diagnostics-watcher restarts observed on 2026-08-07 make this a real case,
    # not a hypothetical — in-memory counters would have re-alerted each time.
    del sys.modules["nemesis_connectivity_notify"]
    import nemesis_connectivity_notify as notify2
    install_stubs(notify2)
    rs = notify2.observe("worsttest", ok=False, verdict="UPSTREAM_FAIL", detail="x")
    check("post-restart continues the SAME episode", rs["action"], "ongoing")
    check("post-restart raised NO duplicate alert", len(SENT_EMAILS), 0)
    check("count carried across restart", episodes(path, "worsttest")[0]["consecutive_failures"], 6)

    section("11. Import resolution under each service's real sys.path")
    # vpn-dns-guard's unit sets NO PYTHONPATH — it reaches alert_manager only via
    # a sys.path.insert under __main__. Verified here rather than assumed.
    import subprocess
    repo = os.path.dirname(_HERE)
    prog = ("import sys, os;"
            "sys.path.insert(0, os.path.join(%r, 'alert_manager'));"
            "import nemesis_connectivity_notify as n;"
            "print('OK', bool(n.observe))" % repo)
    p = subprocess.run([sys.executable, "-c", prog], capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": ""})
    check("importable via vpn_dns_guard's sys.path shape", p.stdout.strip().startswith("OK"), True)
    # CONTROL: without that path it must FAIL, or the check above proves nothing.
    p2 = subprocess.run([sys.executable, "-c",
                         "import nemesis_connectivity_notify"],
                        capture_output=True, text=True,
                        env={**os.environ, "PYTHONPATH": ""}, cwd="/")
    check("CONTROL: unimportable without the path", p2.returncode != 0, True)
    # diagnostics-watcher's unit DOES set PYTHONPATH=/opt/nemesis/alert_manager.
    p3 = subprocess.run([sys.executable, "-c",
                         "import nemesis_connectivity_notify as n; print('OK')"],
                        capture_output=True, text=True,
                        env={**os.environ,
                             "PYTHONPATH": os.path.join(repo, "alert_manager")})
    check("importable via diagnostics-watcher's PYTHONPATH", p3.stdout.strip(), "OK")

    section("12. observe() never raises, even when everything is broken")
    broken = notify2.observe("nosuch", ok=False, verdict="LOCAL_FAIL", detail=None)
    check("unknown verdict/detail still handled", broken["action"] in ("counting",), True)
    saved = database.DB_PATH
    try:
        database.DB_PATH = "/nonexistent/dir/nope.db"
        r = notify2.observe("diagnostics", ok=False, verdict="LOCAL_FAIL", detail="x")
        check("unreachable DB returns error, does NOT raise", r["action"], "error")
    finally:
        database.DB_PATH = saved

    section("13. REAL tickets-module integration (no stub) — signature and gate")
    # Sections 3-5 stubbed the ticket channel, so they proved the episode logic
    # and nothing about whether the real call actually works. A stub that matches
    # a signature the product does not have is the classic green-suite-broken-
    # product failure, so the real path is exercised here against the same DB copy.
    # ⚠ A FRESH module object is required. `import x as y` returns the SAME
    # cached object, so re-importing after install_stubs() would hand back the
    # STUBBED module and this section would test the stub while claiming to test
    # the real path — which is exactly what it did on first run, passing while
    # proving nothing. Drop it from sys.modules to force a clean load.
    del sys.modules["nemesis_connectivity_notify"]
    import nemesis_connectivity_notify as notify3   # NO install_stubs() here
    check("CONTROL: fresh module really is unstubbed",
          notify3._notify_ticket.__module__, "nemesis_connectivity_notify")
    tid = notify3._notify_ticket("selftest", "LOCAL_FAIL", "HIGH",
                                 "test data 2026-08-07 — connectivity notifier self-test",
                                 "test data 2026-08-07 — verifying open_ticket integration")
    # `> 0`, NOT isinstance(int): open_ticket's contract is "id, or 0 on failure",
    # and 0 is an int — so a type check cannot tell success from failure. That
    # weaker assertion passed against a failed call on the first run.
    check("real open_ticket returned a REAL id (>0, not the 0 sentinel)",
          isinstance(tid, int) and tid > 0, True)
    trows = rows(path, "SELECT * FROM tickets WHERE sensor_key=?",
                 ("connectivity.selftest",))
    check("ticket row actually written", len(trows), 1)
    check("ticket priority is the severity passed", trows[0]["priority"], "HIGH")
    nid = notify3._ticket_note("selftest",
                               "test data 2026-08-07 — verifying add_note integration")
    check("real add_note returned a row id", isinstance(nid, int), True)
    # CONTROL: the severity gate must actually decline something, or "it opened a
    # ticket" proves the gate is absent rather than satisfied.
    low = notify3._notify_ticket("selftest2", "UPSTREAM_FAIL", "LOW",
                                 "test data 2026-08-07 — below-threshold control",
                                 "test data 2026-08-07 — must be declined by the gate")
    check("CONTROL: LOW severity declined by the ticket gate (0, not None)", low, 0)

    print("\n%s" % ("-" * 72))
    print("checks run: %d   passed: %d   failed: %d" % (_PASS + _FAIL, _PASS, _FAIL))
    if _PASS + _FAIL != _EXPECTED_CHECKS:
        print("**** DECLARED %d CHECKS BUT RAN %d — the declaration is wrong, "
              "or a check did not execute" % (_EXPECTED_CHECKS, _PASS + _FAIL))
    os.unlink(path)
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
