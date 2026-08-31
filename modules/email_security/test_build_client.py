#!/usr/bin/env python3
"""`supervisor._build_client` is actually CALLED here. Nothing else calls it.

Run: python3 modules/email_security/test_build_client.py

WHY THIS FILE EXISTS — a regression got through a fully green suite
    On 2026-08-31 the refactor to `settings_resolve.for_account()` renamed the
    provider dict from `prov` to `cfg` and missed one reference:

        strip_inner_whitespace=prov.get("strip_inner_whitespace", True)

    `prov` was then unbound, so EVERY watcher build raised NameError. It was
    caught by `MailboxSupervisor._run`'s broad handler and filed as
    CONFIG_ERROR — a state whose own comment says "a human's to fix" — so an
    operator would have been told their transport was misconfigured while the
    real fault was a typo. All 25 email_security suites passed.

    THE REASON THEY PASSED IS THE POINT: `test_supervisor.py` injects a
    `client_factory` (its lines 85 and 174), so the real `_build_client` is
    never executed by any test. A green suite and a suite that never ran the
    function are indistinguishable from their own output. This file closes that
    specific hole by calling the real thing.

NO NETWORK, NO CREDENTIALS, NO DB. `credential_store.get_secret` and
`imap_idle.ImapIdleClient` are replaced with fakes; `_build_client` resolves
its lazy `from . import ...` against the patched module objects.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "..")))

from modules.email_security import credential_store as _cs      # noqa: E402
from modules.email_security import imap_idle as _imap           # noqa: E402
from modules.email_security import supervisor as sup            # noqa: E402

EXPECTED_CHECKS = 24

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 52:
        g, w = g[:49] + "...", w[:49] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


class _FakeClient:
    """Captures the kwargs _build_client passes, instead of opening a socket."""
    last = None

    def __init__(self, address, secret, **kw):
        _FakeClient.last = dict(kw, address=address, secret=secret)


def _install_fakes():
    _cs.get_secret = lambda ref: "app-password-for-%s" % ref
    _imap.ImapIdleClient = _FakeClient


def _build(account):
    """Call the REAL _build_client and return the captured kwargs."""
    _FakeClient.last = None
    sup._build_client(account, on_message=lambda *a, **k: None)
    return _FakeClient.last


GMAIL_ROW = {"id": 1, "address": "someone@gmail.com", "provider": "gmail",
             "imap_host": "imap.gmail.com", "imap_port": 993,
             "mailbox": "INBOX", "credential_ref": "EMAIL_SEC_APPPW_1",
             "tls_mode": "implicit", "authserv_id": None}

CUSTOM_ROW = {"id": 2, "address": "me@example.com", "provider": "custom",
              "imap_host": "mail.example.com", "imap_port": 993,
              "mailbox": "INBOX", "credential_ref": "EMAIL_SEC_APPPW_2",
              "tls_mode": "implicit", "authserv_id": None}

PROTON_ROW = {"id": 3, "address": "me@proton.example", "provider": "proton",
              "imap_host": "127.0.0.1", "imap_port": 1143,
              "mailbox": "INBOX", "credential_ref": "EMAIL_SEC_APPPW_3",
              "tls_mode": "starttls", "authserv_id": None}


def main():
    _install_fakes()

    # ── THE REGRESSION GUARD ────────────────────────────────────────────────
    # Not "does it return the right value" but "does it run at all". The bug
    # this file was written for was an unbound name: any NameError/KeyError
    # inside _build_client fails here rather than being laundered into
    # CONFIG_ERROR by the supervisor's broad handler.
    print("\nREGRESSION GUARD: _build_client executes without raising")
    for name, row in (("gmail", GMAIL_ROW), ("custom", CUSTOM_ROW),
                      ("proton", PROTON_ROW)):
        try:
            _build(row)
            err = None
        except Exception as exc:                               # noqa: BLE001
            err = "%s: %s" % (type(exc).__name__, exc)
        check("%s row builds a client" % name, err, None)

    print("\nevery constructor argument is populated (no silent None)")
    kw = _build(GMAIL_ROW)
    for field in ("address", "secret", "host", "port", "mailbox", "tls_mode",
                  "allow_self_signed", "provider", "strip_inner_whitespace",
                  "on_message"):
        check("%s is passed" % field, field in kw, True)

    print("\nvalues are the RESOLVED ones, not provider-table defaults")
    check("host from the row", kw["host"], "imap.gmail.com")
    check("port from the row", kw["port"], 993)
    check("tls from the row", kw["tls_mode"], "implicit")
    check("provider key", kw["provider"], "gmail")
    # Gmail is the ONLY provider that displays app passwords in spaced groups,
    # so it is the one row where this must be True. It is also the exact field
    # the regression dropped.
    check("gmail strips inner whitespace", kw["strip_inner_whitespace"], True)

    kwc = _build(CUSTOM_ROW)
    check("custom does NOT strip inner whitespace (conservative default)",
          kwc["strip_inner_whitespace"], False)
    check("custom gets no self-signed privilege",
          kwc["allow_self_signed"], False)
    kwp = _build(PROTON_ROW)
    check("proton keeps its self-signed privilege",
          kwp["allow_self_signed"], True)
    check("proton keeps starttls", kwp["tls_mode"], "starttls")

    # ── CONTROL: this harness can actually FAIL ─────────────────────────────
    # Without this, every check above could be passing because the fake client
    # accepts anything. Prove an unbound name inside _build_client is caught.
    print("\nCONTROL: the guard detects a broken _build_client")
    real = sup._build_client

    def _broken(account, on_message):
        return undefined_name_like_the_regression      # noqa: F821

    sup._build_client = _broken
    try:
        _build(GMAIL_ROW)
        caught = None
    except NameError as exc:
        caught = type(exc).__name__
    except Exception as exc:                                   # noqa: BLE001
        caught = type(exc).__name__
    finally:
        sup._build_client = real
    check("CONTROL an unbound name inside _build_client surfaces as NameError",
          caught, "NameError")
    # and that restoring worked, so the control cannot poison later runs
    check("CONTROL the real function was restored",
          sup._build_client is real, True)

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [lbl for lbl, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
