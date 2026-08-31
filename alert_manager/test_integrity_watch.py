"""Fact-file -> ticket poller. Every branch, no root, no DB, no ticket module."""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import integrity_watch as iw

_fail = []


def check(label, got, want):
    ok = got == want
    print("  %-64s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


NOW = 1_000_000.0


def _status(**kw):
    d = {"verdict": "clean", "findings": [], "checked_at": "t", "exit_code": 0}
    d.update(kw)
    return d


def test_clean_files_nothing():
    print("\n[a clean verdict files nothing]")
    d, sig, _ = iw.assess(_status(), NOW, None, NOW)
    check("decision", d, iw.NOTHING)
    check("no signature retained", sig, None)


def test_tampered_files_once_only():
    print("\n[one incident, one ticket -- an hourly checker must not ticket hourly]")
    st = _status(verdict="tampered", findings=["dashboard.py: modified"])
    d1, sig1, detail = iw.assess(st, NOW, None, NOW)
    check("first sighting files", d1, iw.FILE_TICKET)
    check("  detail names the file", "dashboard.py" in detail, True)
    d2, sig2, _ = iw.assess(st, NOW, sig1, NOW)
    check("same finding again -> already filed", d2, iw.ALREADY_FILED)
    check("  signature stable", sig2 == sig1, True)


def test_a_changed_finding_is_new_information():
    print("\n[a SECOND modified file is new information, not a repeat]")
    a = _status(verdict="tampered", findings=["dashboard.py: modified"])
    b = _status(verdict="tampered", findings=["dashboard.py: modified",
                                              "alert_manager/roles.py: modified"])
    _, sig_a, _ = iw.assess(a, NOW, None, NOW)
    d, _, _ = iw.assess(b, NOW, sig_a, NOW)
    check("escalation files a new ticket", d, iw.FILE_TICKET)


def test_finding_order_does_not_create_duplicates():
    print("\n[the same findings in a different order are the SAME incident]")
    a = _status(verdict="tampered", findings=["a: modified", "b: modified"])
    b = _status(verdict="tampered", findings=["b: modified", "a: modified"])
    _, sa, _ = iw.assess(a, NOW, None, NOW)
    d, _, _ = iw.assess(b, NOW, sa, NOW)
    check("reordering does NOT re-ticket", d, iw.ALREADY_FILED)


def test_missing_file_is_not_clean():
    print("\n[ABSENCE IS NOT HEALTH -- a missing fact file must not read as clean]")
    d, _, detail = iw.assess(None, NOW, None, None)
    check("decision", d, iw.UNREADABLE)
    check("  says so", "missing or unreadable" in detail, True)


def test_stale_is_detected_and_uses_mtime_not_self_report():
    print("\n[staleness uses the FILE's mtime, not the checker's own claim]")
    st = _status(checked_at="2026-01-01T00:00:00+00:00")     # self-report says old
    d, _, _ = iw.assess(st, NOW, None, NOW)                   # but mtime is fresh
    check("fresh mtime + stale self-report -> NOT stale", d, iw.NOTHING)
    d2, _, detail = iw.assess(st, NOW, None, NOW - iw.STALE_AFTER_S - 1)
    check("old mtime -> STALE", d2, iw.STALE)
    check("  reports how long", "minutes" in detail, True)


def test_cannot_verify_is_ticketed():
    print("\n[cannot_verify is a finding, not a shrug]")
    d, _, _ = iw.assess(_status(verdict="cannot_verify",
                                findings=["manifest unreadable"]), NOW, None, NOW)
    check("files a ticket", d, iw.FILE_TICKET)


def test_read_status_rejects_garbage():
    print("\n[unparseable / wrong-shaped files are UNREADABLE, never clean]")
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "s.json")
        open(p, "w").write("{not json")
        check("garbage -> None", iw.read_status(p), None)
        open(p, "w").write('["a list, not an object"]')
        check("wrong shape -> None", iw.read_status(p), None)
        check("absent -> None", iw.read_status(os.path.join(td, "nope.json")), None)


def test_poll_once_end_to_end_and_ticket_failure_retries():
    print("\n[poll_once: files via the injected opener; a failure RETRIES next cycle]")
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "status.json")
        json.dump(_status(verdict="tampered", findings=["x: modified"]), open(p, "w"))
        seen = []
        d, sig = iw.poll_once(p, None, time.time(), opener=lambda **kw: seen.append(kw))
        check("filed", d, iw.FILE_TICKET)
        check("  one ticket", len(seen), 1)
        check("  body states the local/off-box split",
              "does NOT detect an attacker with root" in seen[0]["body"], True)
        check("  rule_id set for correlation", seen[0]["rule_id"], "integrity_manifest")

        def boom(**kw):
            raise RuntimeError("tickets down")
        d2, sig2 = iw.poll_once(p, None, time.time(), opener=boom)
        check("ticket failure does not raise", d2, iw.FILE_TICKET)
        check("  signature NOT advanced, so it retries", sig2, None)


def test_every_ticket_decision_dedups():
    """⛔ THE REGRESSION GUARD FOR THE 606-TICKET FLOOD (2026-08-30/31).

    The dedup used to run ONLY on the tampered path. UNREADABLE and STALE
    returned above it, and UNREADABLE also returned a None signature, so the
    caller stored None and suppression could never engage. Result: one ticket
    every 66 seconds for 11 hours.

    This asserts the property, not the incident: EVERY decision that files a
    ticket must suppress its own repeat. A new filing decision that forgets to
    is caught here.
    """
    print("\n[EVERY ticket-filing decision suppresses its own repeat]")
    cases = {
        iw.FILE_TICKET: (_status(verdict="tampered", findings=["x: modified"]), NOW, True),
        iw.STALE: (_status(), NOW - iw.STALE_AFTER_S - 1, True),
        iw.UNREADABLE: (None, NOW, True),
        iw.NEVER_DEPLOYED: (None, NOW, False),
    }
    check("all filing decisions are covered by this test",
          set(cases) == set(iw.TICKET_DECISIONS), True)
    for want, (st, mtime, installed) in cases.items():
        d1, sig1, _ = iw.assess(st, NOW, None, mtime, installed)
        check("%s files on first sighting" % want, d1, want)
        # THE ROOT CAUSE: a None signature makes suppression impossible.
        check("  %s returns a NON-NULL signature" % want, sig1 is not None, True)
        d2, sig2, _ = iw.assess(st, NOW, sig1, mtime, installed)
        check("  %s repeat -> already filed" % want, d2, iw.ALREADY_FILED)
        check("  %s signature stable across the repeat" % want, sig2, sig1)


def test_never_deployed_is_distinct_from_a_deleted_fact_file():
    """The distinction the noise fix must NOT collapse.

    read_status returns None for both "never set up" and "an attacker deleted
    it". Suppressing the noisy case without separating them would silently
    downgrade a tamper signal into a setup reminder.
    """
    print("\n[never-deployed and deleted-fact-file stay DIFFERENT facts]")
    d_new, sig_new, det_new = iw.assess(None, NOW, None, None, checker_installed=False)
    d_gone, sig_gone, det_gone = iw.assess(None, NOW, None, None, checker_installed=True)
    check("no checker installed -> NEVER_DEPLOYED", d_new, iw.NEVER_DEPLOYED)
    check("installed but file gone -> UNREADABLE", d_gone, iw.UNREADABLE)
    check("  the two are NOT the same decision", d_new == d_gone, False)
    check("  ...nor the same signature", sig_new == sig_gone, False)
    check("  never-deployed says it is a setup state", "not set up" in det_new, True)
    check("  missing-file still says missing or unreadable",
          "missing or unreadable" in det_gone, True)
    # A never-deployed signature must not suppress a later real disappearance.
    d_after, _, _ = iw.assess(None, NOW, sig_new, None, checker_installed=True)
    check("⚠ a never-deployed ticket does NOT suppress a later UNREADABLE",
          d_after, iw.UNREADABLE)


def test_conservative_default_when_the_caller_cannot_tell():
    print("\n[unknown deployment state defaults to SUSPICIOUS, not to 'not set up']")
    d, _, _ = iw.assess(None, NOW, None, None)      # checker_installed omitted
    check("default treats a missing file as UNREADABLE", d, iw.UNREADABLE)


def test_never_deployed_files_a_low_setup_ticket_not_a_high_incident():
    print("\n[an unconfigured optional feature is not a security incident]")
    with tempfile.TemporaryDirectory() as td:
        # A path whose PARENT does not exist -> checker never deployed.
        p = os.path.join(td, "nope", "status.json")
        seen = []
        d, sig = iw.poll_once(p, None, NOW, opener=lambda **kw: seen.append(kw))
        check("decision", d, iw.NEVER_DEPLOYED)
        check("  one ticket filed", len(seen), 1)
        check("  priority is LOW, not High", seen[0]["priority"], "Low")
        check("  title says setup, not failure",
              seen[0]["title"], "File integrity checking is not set up")
        # The standard body credits a checker for reporting. On this path no
        # checker exists, so that sentence would be a lie.
        check("  body does NOT claim a checker reported it",
              "was reported by the root-owned integrity checker" in seen[0]["body"], False)
        check("  body says it will not repeat", "ONE of these" in seen[0]["body"], True)
        # And the second poll files nothing at all.
        d2, _ = iw.poll_once(p, sig, NOW, opener=lambda **kw: seen.append(kw))
        check("  second poll files NOTHING", d2, iw.ALREADY_FILED)
        check("  still only one ticket", len(seen), 1)


def test_poll_once_detects_deployment_from_the_directory():
    print("\n[deployment is detected from the status DIRECTORY]")
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "status.json")          # dir exists, file absent
        seen = []
        d, _ = iw.poll_once(p, None, NOW, opener=lambda **kw: seen.append(kw))
        check("dir present + file absent -> UNREADABLE (suspicious)", d, iw.UNREADABLE)
        check("  filed at High", seen[0]["priority"], "High")


if __name__ == "__main__":
    print("integrity fact-file poller")
    for t in (test_clean_files_nothing, test_tampered_files_once_only,
              test_a_changed_finding_is_new_information,
              test_finding_order_does_not_create_duplicates,
              test_missing_file_is_not_clean,
              test_stale_is_detected_and_uses_mtime_not_self_report,
              test_cannot_verify_is_ticketed, test_read_status_rejects_garbage,
              test_poll_once_end_to_end_and_ticket_failure_retries,
              test_every_ticket_decision_dedups,
              test_never_deployed_is_distinct_from_a_deleted_fact_file,
              test_conservative_default_when_the_caller_cannot_tell,
              test_never_deployed_files_a_low_setup_ticket_not_a_high_incident,
              test_poll_once_detects_deployment_from_the_directory):
        t()
    print()
    if _fail:
        print("FAILED (%d)" % len(_fail))
        for f in _fail:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS")
