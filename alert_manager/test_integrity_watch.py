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


if __name__ == "__main__":
    print("integrity fact-file poller")
    for t in (test_clean_files_nothing, test_tampered_files_once_only,
              test_a_changed_finding_is_new_information,
              test_finding_order_does_not_create_duplicates,
              test_missing_file_is_not_clean,
              test_stale_is_detected_and_uses_mtime_not_self_report,
              test_cannot_verify_is_ticketed, test_read_status_rejects_garbage,
              test_poll_once_end_to_end_and_ticket_failure_retries):
        t()
    print()
    if _fail:
        print("FAILED (%d)" % len(_fail))
        for f in _fail:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS")
