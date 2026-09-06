#!/usr/bin/env python3
"""send_email -- logging shape (FINDING 6, route-security-audit-learning-custom-2026-09-05.md).

`send_email` used to log ONLY its failure path (`log.error`). A caller checking "did
this actually happen" from the journal could prove a failure but never a success --
"sent" and "never attempted" were indistinguishable, exactly the shape the 2026-09-05
Learning Center notification investigation lost real time to. This suite pins that
success now logs too, and that success/failure are distinguishable BY LEVEL, without
touching real SMTP.

ASSERTION COUNT IS FIXED. Every check below runs unconditionally -- none sits inside a
success-path `if`. A suite whose total shrinks under failure cannot be compared between
runs (CLAUDE.md, 2026-08-29).

Run: python3 alert_manager/test_email_utils.py
"""
import logging
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import email_utils                                                 # noqa: E402

EXPECTED_CHECKS = 12
PASS = FAIL = 0


def check(label, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] %s" % label)
    else:
        FAIL += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


class _FakeSMTP:
    """Same shape whether reached via SMTP() or SMTP_SSL() -- send_email treats both
    identically, so one fake stands in for both."""

    next_fails = False
    instances = []

    def __init__(self, host, port, timeout=30):
        self.host, self.port, self.timeout = host, port, timeout
        self.calls = []
        self.fail = _FakeSMTP.next_fails
        _FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self):
        self.calls.append("starttls")

    def login(self, user, pw):
        self.calls.append(("login", user, pw))

    def send_message(self, msg):
        self.calls.append(("send_message", msg))
        if self.fail:
            raise RuntimeError("simulated SMTP failure")


class _LogSpy(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


def _send(fail=False, missing_creds=False, to=None):
    """One isolated send_email call: fake transport, disposable env, captured log.
    Restores smtplib and the environment in a `finally` regardless of outcome."""
    _FakeSMTP.instances.clear()
    _FakeSMTP.next_fails = fail
    orig_smtp, orig_ssl = email_utils.smtplib.SMTP, email_utils.smtplib.SMTP_SSL
    email_utils.smtplib.SMTP = _FakeSMTP
    email_utils.smtplib.SMTP_SSL = _FakeSMTP
    orig_environ = dict(os.environ)
    os.environ["WATCHDOG_EMAIL"] = "watchdog@example.com"
    os.environ["WATCHDOG_PASSWORD"] = "x"
    os.environ["SMTP_HOST"] = "smtp.example.com"
    os.environ["SMTP_PORT"] = "587"
    if missing_creds:
        os.environ.pop("WATCHDOG_EMAIL", None)
        os.environ.pop("WATCHDOG_PASSWORD", None)
    spy = _LogSpy()
    email_utils.log.addHandler(spy)
    email_utils.log.setLevel(logging.DEBUG)
    try:
        result = email_utils.send_email("Test Subject", "body", to=to)
    finally:
        email_utils.log.removeHandler(spy)
        email_utils.smtplib.SMTP = orig_smtp
        email_utils.smtplib.SMTP_SSL = orig_ssl
        os.environ.clear()
        os.environ.update(orig_environ)
    return result, spy.records


def test_success_returns_true_and_logs_at_INFO():
    ok, records = _send(fail=False)
    info = [r for r in records if r.levelno == logging.INFO]
    error = [r for r in records if r.levelno == logging.ERROR]
    check("send_email reports success", ok)
    check("exactly one INFO record on success", len(info) == 1, "n=%d" % len(info))
    check("...and no ERROR record", len(error) == 0, "n=%d" % len(error))
    check("the INFO record names the subject",
          bool(info) and "Test Subject" in info[0].getMessage())


def test_failure_returns_false_and_logs_at_ERROR_not_INFO():
    """CONTROL for the test above: without this, the instrument could log INFO
    regardless of outcome and the success test would not have proven anything."""
    ok, records = _send(fail=True)
    info = [r for r in records if r.levelno == logging.INFO]
    error = [r for r in records if r.levelno == logging.ERROR]
    check("send_email reports failure", ok is False)
    check("no INFO record on failure", len(info) == 0, "n=%d" % len(info))
    check("exactly one ERROR record", len(error) == 1, "n=%d" % len(error))


def test_missing_credentials_is_still_an_ERROR_not_a_silent_skip():
    """Pre-existing behavior, not this fix -- pinned so a later change to the logging
    shape cannot quietly merge this path into the new success log."""
    ok, records = _send(missing_creds=True)
    error = [r for r in records if r.levelno == logging.ERROR]
    info = [r for r in records if r.levelno == logging.INFO]
    check("send_email reports failure", ok is False)
    check("exactly one ERROR record", len(error) == 1, "n=%d" % len(error))
    check("no INFO record", len(info) == 0, "n=%d" % len(info))


def test_INFO_and_ERROR_are_never_both_present_for_the_same_call():
    """The property FINDING 6 actually needs: success and failure are distinguishable
    from the journal by level alone, on every call, not just in the happy-path test."""
    for fail in (False, True):
        _, records = _send(fail=fail)
        levels = {r.levelno for r in records}
        check("send_email(fail=%s) logs exactly one of INFO/ERROR" % fail,
              len(levels & {logging.INFO, logging.ERROR}) == 1, "levels=%r" % levels)


if __name__ == "__main__":
    for fn in (
        test_success_returns_true_and_logs_at_INFO,
        test_failure_returns_false_and_logs_at_ERROR_not_INFO,
        test_missing_credentials_is_still_an_ERROR_not_a_silent_skip,
        test_INFO_and_ERROR_are_never_both_present_for_the_same_call,
    ):
        print("\n%s" % fn.__name__)
        fn()

    print("\n" + "=" * 70)
    ran = PASS + FAIL
    print("checks: %d passed, %d failed (%d run)" % (PASS, FAIL, ran))
    if ran != EXPECTED_CHECKS:
        print("EXPECTED_CHECKS MISMATCH: declared %d, ran %d" % (EXPECTED_CHECKS, ran))
        sys.exit(1)
    sys.exit(1 if FAIL else 0)
