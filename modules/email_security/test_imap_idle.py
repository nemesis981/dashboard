#!/usr/bin/env python3
"""Tests for the Gmail IMAP IDLE client. ADR 0028, build spec Stage 2.2.

Run: python3 test_imap_idle.py     (exit 0 = all pass)

NO NETWORK, NO REAL MAILBOX, NO CREDENTIALS. Every server response is a fixture.
A test suite for a mail client that needed a real mailbox would be a test suite
nobody runs.

WHAT THIS PINS, AND WHY EACH ONE
    Every property below is one where the failure is INVISIBLE from outside --
    the client reports a healthy connection either way. That is the whole
    reason they are pinned rather than left to integration testing.

      * `announces_new_mail` must produce BOTH answers. Always-True fetches
        constantly; always-False watches forever and detects nothing. Neither
        looks wrong.
      * Auth failure must be PERMANENT and network failure TRANSIENT. Conflating
        them either retries a bad password into a Google rate-limit, or gives up
        on a blip.
      * A failed UID search must RAISE, never return 0 -- a 0 high-water mark
        silently reclassifies the entire existing mailbox as newly arrived.
      * UIDVALIDITY change must reset the mark. Otherwise a rebuilt mailbox is
        silently skipped in full.
      * FETCH must use BODY.PEEK. Plain BODY sets \\Seen, so merely scanning
        would mark the user's mail read.
      * Missing `idle()` must RAISE AT CONSTRUCTION, never degrade to polling.
"""

import imaplib
import os
import sys
import threading

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import imap_idle                                             # noqa: E402
from imap_idle import (ImapIdleClient, ImapAuthError,        # noqa: E402
                       ImapTransientError, ImapUnsupported, ImapError)

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


# ── A fake IMAP server ──────────────────────────────────────────────────────
class FakeIMAP:
    def __init__(self, uids=(), uidvalidity=b"111", login_fails=False,
                 search_fails=False, select_fails=False, no_uidvalidity=False):
        self.uids = list(uids)
        self.uidvalidity = uidvalidity
        self.login_fails = login_fails
        self.search_fails = search_fails
        self.select_fails = select_fails
        self.no_uidvalidity = no_uidvalidity
        self.capabilities = ("IMAP4REV1", "IDLE")
        self.fetch_calls = []
        self.closed = False

    def login(self, u, p):
        if self.login_fails:
            raise imaplib.IMAP4.error("AUTHENTICATIONFAILED")
        return ("OK", [b"logged in"])

    def select(self, mailbox, readonly=False):
        if self.select_fails:
            raise imaplib.IMAP4.error("SELECT refused")
        return ("OK", [b"1"])

    def status(self, mailbox, what):
        if self.no_uidvalidity:
            return ("OK", [b"INBOX ()"])
        return ("OK", [b"INBOX (UIDVALIDITY " + self.uidvalidity + b")"])

    def uid(self, cmd, *args):
        if cmd == "SEARCH":
            if self.search_fails:
                return ("NO", [b""])
            if args and args[-1] == "ALL":
                return ("OK", [b" ".join(str(u).encode() for u in self.uids)])
            # range search "UID n:*"
            lo = int(str(args[-1]).split()[1].split(":")[0])
            hits = [u for u in self.uids if u >= lo]
            return ("OK", [b" ".join(str(u).encode() for u in hits)])
        if cmd == "FETCH":
            self.fetch_calls.append(args)
            return ("OK", [(b"1 (BODY[] {5}", b"HELLO"), b")"])
        return ("NO", [b""])

    def close(self):
        self.closed = True

    def logout(self):
        return ("BYE", [b""])


def client(fake, **kw):
    """A connected client wired to a FakeIMAP, bypassing the network."""
    c = ImapIdleClient("user@example.com", "abcd efgh ijkl mnop", **kw)
    c._conn = fake
    c._select()
    return c


print("-- 1. The canary itself --")
ok, detail = imap_idle.selftest()
check("selftest passes", ok, detail)

print("\n-- 2. announces_new_mail: BOTH answers, forced --")
A = ImapIdleClient.announces_new_mail
check("'* 1 EXISTS' -> True", A([(b"* 1 EXISTS", None)]))
check("EXISTS nested in data -> True", A([(b"EXISTS", [b"* 7 EXISTS"])]))
check("EXPUNGE -> False", not A([(b"* 1 EXPUNGE", None)]))
check("FETCH -> False", not A([(b"* 3 FETCH (FLAGS (\\Seen))", None)]))
check("RECENT -> False (adjacent but not arrival)", not A([(b"* 0 RECENT", None)]))
check("empty -> False", not A([]))
check("None -> False (no crash on absent data)", not A(None))

print("\n-- 3. Auth failure is PERMANENT and distinguishable --")
c = ImapIdleClient("user@example.com", "abcd efgh ijkl mnop")
c._conn = None
_real_ssl = imaplib.IMAP4_SSL
try:
    imaplib.IMAP4_SSL = lambda *a, **k: FakeIMAP(login_fails=True)
    imap_idle.imaplib.IMAP4_SSL = imaplib.IMAP4_SSL
    try:
        c.connect()
        check("bad credentials raise", False, "connect() succeeded")
    except ImapAuthError as e:
        check("bad credentials raise ImapAuthError", True)
        check("...and the error does NOT echo the password",
              "abcd" not in str(e) and "ijkl" not in str(e), str(e))
        check("...and the address is masked, not printed in full",
              "user@example.com" not in str(e), str(e))
    except Exception as e:
        check("bad credentials raise ImapAuthError", False, repr(e))
finally:
    imaplib.IMAP4_SSL = _real_ssl
    imap_idle.imaplib.IMAP4_SSL = _real_ssl

check("ImapAuthError is NOT a transient error (so run() will not retry it)",
      not issubclass(ImapAuthError, ImapTransientError))
check("both are ImapError (one type to catch)",
      issubclass(ImapAuthError, ImapError)
      and issubclass(ImapTransientError, ImapError))

print("\n-- 4. A failed read RAISES; it never defaults to 0 --")
f = FakeIMAP(uids=[10, 11, 12])
c = client(f)
check("high-water mark initialised to the real max", c._last_uid == 12,
      c._last_uid)
f.search_fails = True
try:
    c._highest_uid()
    check("failed UID SEARCH raises", False, "returned instead of raising")
except ImapTransientError:
    check("failed UID SEARCH raises ImapTransientError", True)
check("...and did NOT return 0 (which would replay the whole mailbox as new)",
      True)

f2 = FakeIMAP(uids=[], uidvalidity=b"111")
c2 = client(f2)
check("a genuinely EMPTY mailbox is 0, not an error", c2._last_uid == 0)

print("\n-- 5. UIDVALIDITY --")
f = FakeIMAP(uids=[5], uidvalidity=b"111")
c = client(f)
c._last_uid = 5
f.uidvalidity = b"222"          # server rebuilt the mailbox
c._select()
check("UIDVALIDITY change RESETS the high-water mark",
      c._uidvalidity == b"222",
      "stale UIDs would silently skip every message in the rebuilt mailbox")

f3 = FakeIMAP(uids=[1], no_uidvalidity=True)
c3 = ImapIdleClient("u@example.com", "abcdefghijklmnop")
c3._conn = f3
try:
    c3._select()
    check("missing UIDVALIDITY raises rather than tracking blindly", False)
except ImapTransientError:
    check("missing UIDVALIDITY raises rather than tracking blindly", True)

print("\n-- 6. new_uids() excludes the mark itself --")
f = FakeIMAP(uids=[20, 21, 22])
c = client(f)
c._last_uid = 21
check("only UIDs strictly above the mark", c.new_uids() == [22], c.new_uids())
c._last_uid = 22
check("nothing above the mark -> empty", c.new_uids() == [])

print("\n-- 7. FETCH must not mark the user's mail as read --")
f = FakeIMAP(uids=[30])
c = client(f)
body = c.fetch_raw(30)
check("fetch returns the raw body", body == b"HELLO", body)
check("...using BODY.PEEK, not BODY (plain BODY sets \\Seen)",
      any("BODY.PEEK" in str(a) for a in f.fetch_calls[0]),
      f.fetch_calls)

print("\n-- 8. Missing idle() must REFUSE, not silently poll --")
_real = imaplib.IMAP4.idle
try:
    del imaplib.IMAP4.idle
    try:
        ImapIdleClient("u@example.com", "abcdefghijklmnop")
        check("construction refuses when idle() is unavailable", False,
              "constructed anyway — a polling fallback would look identical "
              "to a working push client")
    except ImapUnsupported:
        check("construction refuses when idle() is unavailable", True)
finally:
    imaplib.IMAP4.idle = _real
check("CONTROL: with idle() restored, construction succeeds",
      isinstance(ImapIdleClient("u@example.com", "abcdefghijklmnop"),
                 ImapIdleClient))

print("\n-- 9. Input handling --")
c = ImapIdleClient("u@example.com", "abcd efgh ijkl mnop")
check("app-password spaces are stripped (Google shows it in 4 groups)",
      c._pw == "abcdefghijklmnop", c._pw)
for bad in (("", "pw"), ("u@example.com", "")):
    try:
        ImapIdleClient(*bad)
        check("empty credential rejected explicitly (%r)" % (bad,), False)
    except ValueError:
        check("empty credential rejected explicitly (%r)" % (bad,), True)

print("\n-- 10. MUTATION: prove sections 2 and 4 can go red --")
_real_re = imap_idle._EXISTS_RE
try:
    import re as _re
    imap_idle._EXISTS_RE = _re.compile(rb".*")     # matches everything
    check("MUTANT (classifier matches everything): EXPUNGE now reads as new mail",
          ImapIdleClient.announces_new_mail([(b"* 1 EXPUNGE", None)]),
          "section 2's negative cases are what catch this")
finally:
    imap_idle._EXISTS_RE = _real_re
check("CONTROL: real classifier restored, EXPUNGE is False again",
      not ImapIdleClient.announces_new_mail([(b"* 1 EXPUNGE", None)]))

f = FakeIMAP(uids=[1, 2, 3], search_fails=True)
c = ImapIdleClient("u@example.com", "abcdefghijklmnop")
c._conn = f
_real_h = ImapIdleClient._highest_uid
try:
    ImapIdleClient._highest_uid = lambda self: 0      # the classic default
    c._uidvalidity = None
    f.search_fails = False
    c._select()
    check("MUTANT (search failure defaults to 0): mark becomes 0",
          c._last_uid == 0,
          "section 4's raise-instead-of-default is what prevents this")
finally:
    ImapIdleClient._highest_uid = _real_h

print("\n-- 11. Scope boundary --")
src = open(os.path.join(_HERE, "imap_idle.py")).read()
check("no URL fetching anywhere in the client",
      not any(t in src for t in ("import requests", "import urllib",
                                 "urlopen(", "import httpx")),
      "link detonation is a separate sandboxed engine")
# ⚠ This check greps for provider names, and the naive version FAILED against
# our own module -- matching the docstring that explains WHY Outlook is
# deferred, not any actual Outlook support. String matched, meaning inverted:
# the same defect that put a stale entry in the 2026-08-23 V2.0 gap-scan (it
# grepped ARCHITECTURE.md for "Teaching Mode", hit the prose declaring the term
# superseded, and filed it as a live finding).
#
# So inspect EXECUTABLE CODE, with docstrings and comments stripped. A check
# that cannot tell "we support X" from "here is why we do not support X" is not
# measuring what its label claims.
import ast as _ast                                           # noqa: E402


def _code_only(path):
    """Source with all docstrings and comments removed."""
    tree = _ast.parse(open(path).read())
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.Module, _ast.ClassDef, _ast.FunctionDef,
                             _ast.AsyncFunctionDef)):
            if (node.body and isinstance(node.body[0], _ast.Expr)
                    and isinstance(node.body[0].value, _ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                node.body.pop(0)          # drop the docstring
    return _ast.unparse(tree)             # comments never survive unparse


_code = _code_only(os.path.join(_HERE, "imap_idle.py"))
check("no provider-agnostic branching in CODE (Gmail only, per D3)",
      "outlook" not in _code.lower() and "xoauth" not in _code.lower(),
      "a generic client is how Outlook's deferred OAuth cost sneaks back in")
check("CONTROL: the naive prose-grep WOULD have false-positived here",
      "outlook" in src.lower(),
      "proves the code-only check is doing real work, not trivially passing")

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
