#!/usr/bin/env python3
"""Tests for the email_security module scaffold. ADR 0028, build spec 2.1.

Run: python3 test_module.py     (exit 0 = all pass)

WHY A SCAFFOLD GETS A TEST SUITE AT ALL
    Because the scaffold's whole job is REPORTING STATE, and this project's
    standing lesson is that a state-reporting function which can only produce
    one answer looks identical to one that measured something. `status()` has
    four distinct outcomes and every one of them is a claim about whether mail
    is actually being examined -- the exact place a reassuring default would do
    the most damage.

    Three days in one week produced the same bug: a new branch or default that
    nothing exercised, shipping green because every test took a different path
    (`capabilities._conn()`, `role.js`'s missing `sub_admin`, the unwired unlock
    gate). Every branch below is forced deliberately, and section 5 mutates the
    module to prove these checks can go red.

NO NETWORK, NO REAL MAILBOX, NO CREDENTIALS. Every fixture is synthetic.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, "/opt/nemesis")
# Mirror the dashboard unit's real PYTHONPATH
# (Environment=PYTHONPATH=/opt/nemesis/alert_manager:...), read from
# `systemctl cat dashboard.service`. `start()` imports `database` to create this
# module's tables, and that import resolves only with alert_manager/ on the path
# -- database.py imports `nemesis_paths` itself. Without this the suite would test
# an import environment production does not have.
sys.path.insert(0, "/opt/nemesis/alert_manager")

import modules_loader                                       # noqa: E402
import tempfile                                             # noqa: E402
import database                                             # noqa: E402

# ── start() creates real tables via real sqlite3, NOT through the stubbed Data
# Manager -- canonical DDL owns its own connection (same as every other
# init_*_tables). Point it at a throwaway file so this suite keeps its promise
# that no real DB is touched; otherwise `m.start()` below would CREATE TABLE in
# the live /var/lib/nemesis/alerts.db.
_TMPDB = os.path.join(tempfile.mkdtemp(prefix="emailsec-test-"), "t.db")
database.DB_PATH = _TMPDB

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


# ── A fake Data Manager, so no real DB is touched ───────────────────────────
class _FakeCursor:
    def __init__(self, rows):
        self._rows = list(rows)

    def fetchone(self):
        return self._rows.pop(0) if self._rows else None


class _FakeConn:
    """Minimal connection double. `behaviour` decides what the module sees."""

    def __init__(self, behaviour):
        self.behaviour = behaviour
        self.closed = False

    def execute(self, sql, *a):
        if self.behaviour == "raise":
            raise RuntimeError("simulated DB failure")
        if "sqlite_master" in sql:
            # None => table absent (pre-2.6); a row => table exists
            return _FakeCursor([None] if self.behaviour == "no_table"
                               else [("email_accounts",)])
        if "COUNT(*)" in sql:
            n = {"zero_accounts": 0, "two_accounts": 2}.get(self.behaviour, 0)
            return _FakeCursor([(n,)])
        return _FakeCursor([])

    def close(self):
        self.closed = True


def load_module(behaviour):
    """Fresh Module instance with the Data Manager stubbed to `behaviour`."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "email_security_under_test", os.path.join(_HERE, "module.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod._dm = lambda: _FakeConn(behaviour)
    import json
    manifest = json.load(open(os.path.join(_HERE, "manifest.json")))
    return mod, mod.Module(manifest)


print("-- 1. Loader enforcement (ADR 0006), with its own control --")
check("the real module is ACCEPTED by loader enforcement",
      _accepted := (lambda: (modules_loader._check_data_manager_contract(
          "email_security", os.path.join(_HERE, "module.py")) or True))())

import tempfile                                             # noqa: E402


def _probe(src):
    p = os.path.join(tempfile.mkdtemp(), "module.py")
    open(p, "w").write(src)
    try:
        modules_loader._check_data_manager_contract("probe", p)
        return "ACCEPTED"
    except modules_loader.ModuleEnforcementError:
        return "REJECTED"


check("CONTROL: enforcement REJECTS raw sqlite3 — so the pass above means something",
      _probe("import sqlite3\n") == "REJECTED",
      "if this ever ACCEPTS, the check above is vacuous")
check("CONTROL: enforcement REJECTS a bare get_db call",
      _probe("def f():\n    return get_db()\n") == "REJECTED")

print("\n-- 1b. start() actually CREATES the tables (the call site exists) --")
# The orphaned-CREATE check: init_email_security_tables() was defined with no
# caller anywhere, which on a fresh install is indistinguishable from having no
# DDL at all -- the `devices`-table failure. These assertions fail if the call
# site is ever removed again.
check("CONTROL: throwaway DB path is in use, not the live one",
      database.DB_PATH == _TMPDB and "/var/lib/nemesis" not in database.DB_PATH,
      database.DB_PATH)
check("CONTROL: tables do NOT exist before start()",
      not os.path.exists(_TMPDB),
      "if this file already exists the next check proves nothing")

mod, m = load_module("zero_accounts")
m.start()
import sqlite3 as _sq
_c = _sq.connect(_TMPDB)
_tables = {r[0] for r in _c.execute(
    "SELECT name FROM sqlite_master WHERE type='table'")}
check("start() created email_accounts", "email_accounts" in _tables, _tables)
check("start() created email_message_verdicts",
      "email_message_verdicts" in _tables, _tables)
_c.close()
m.stop()

print("\n-- 2. Lifecycle is idempotent --")
mod, m = load_module("zero_accounts")
m.start(); m.start()
check("start() twice leaves it running", m._running is True)
m.stop(); m.stop()
check("stop() twice leaves it stopped", m._running is False)
check("stop() clears the client handle", m._client is None)

print("\n-- 3. status(): FOUR distinct states, each forced deliberately --")

mod, m = load_module("zero_accounts")
s = m.status()
check("stopped -> state 'stopped'", s["state"] == "stopped", s)

m.start()
s = m.status()
check("enabled + NO mailbox -> says no mail is being examined",
      s["state"] == "running" and "no mailbox configured" in s["detail"],
      s)
check("...and does NOT imply coverage it lacks",
      "no mail is being examined" in s["detail"], s)

mod, m = load_module("two_accounts")
m.start()
s = m.status()
check("configured but no client -> reports NOT connected, with the count",
      "2 mailbox(es) configured, not connected" in s["detail"], s)

m._client = object()
s = m.status()
check("configured + client -> 'connected'",
      s["state"] == "running" and "2 mailbox(es) connected" in s["detail"], s)

print("\n-- 4. A failed read is an ERROR, never a zero --")
mod, m = load_module("raise")
m.start()
s = m.status()
check("unreadable account table -> state 'error'", s["state"] == "error", s)
check("...and does NOT report 'no mailbox configured'",
      "no mailbox configured" not in s["detail"],
      "a DB failure reading as 'no mailboxes' is the default-that-means-something bug")

mod, m = load_module("no_table")
m.start()
s = m.status()
check("table ABSENT (pre-2.6) is a legitimate zero, not an error",
      s["state"] == "running" and "no mailbox configured" in s["detail"], s)

print("\n-- 5. MUTATION: prove the section-3/4 checks can go red --")

mod, m = load_module("raise")
m.start()
_real = mod.Module._configured_account_count
try:
    # The classic bug: swallow the failure and return a legal-looking zero.
    mod.Module._configured_account_count = lambda self: 0
    s = m.status()
    check("MUTANT (swallows DB error, returns 0): now reports 'no mailbox configured'",
          "no mailbox configured" in s["detail"],
          "section 4's check is what catches this")
finally:
    mod.Module._configured_account_count = _real
check("CONTROL: real method restored, the error surfaces again",
      m.status()["state"] == "error")

mod, m = load_module("two_accounts")
m.start()
m._client = object()
_real_status = mod.Module.status
try:
    mod.Module.status = lambda self: {"state": "running", "detail": "running"}
    s = m.status()
    check("MUTANT (status collapses all states to 'running'): loses the mailbox count",
          "mailbox(es) connected" not in s["detail"],
          "section 3's checks are what catch this")
finally:
    mod.Module.status = _real_status
check("CONTROL: real status restored, the count is back",
      "2 mailbox(es) connected" in m.status()["detail"])

print("\n-- 6. Scope boundaries that must survive later stages --")
src = open(os.path.join(_HERE, "module.py")).read()
check("module fetches no URLs (no requests/urllib/httpx import)",
      not any(t in src for t in ("import requests", "import urllib",
                                 "import httpx", "urlopen(")),
      "link detonation is a separate sandboxed engine — never a convenience fetch here")
check("dashboard card is None while nothing is being examined",
      load_module("zero_accounts")[1].get_dashboard_card() is None,
      "a card implying mail is watched, before any is read, is false assurance")

import json                                                 # noqa: E402
mf = json.load(open(os.path.join(_HERE, "manifest.json")))
check("manifest: NOT enabled by default", mf["enabled_by_default"] is False,
      "this module holds a credential to a personal mailbox")
check("manifest: confirmation required", mf["confirmation_required"] is True)
check("manifest: not marked required", mf["required"] is False)

print("\n-- 7. Dashboard card: honest, escaped, genuinely tiered --")
mod7, m7 = load_module("zero_accounts")
check("None when the module has never run (no honest card exists)",
      m7.get_dashboard_card() is None)

m7.start()
card = m7.get_dashboard_card()
check("a started module DOES render a card", card and "Email Security" in card, card)
check("...and it carries status()'s own wording, not a cheerful summary",
      "no mailbox configured" in card, card)

mod8, m8 = load_module("two_accounts")
m8.start()
card8 = m8.get_dashboard_card()
check("⚠ 'configured but NOT connected' is stated on the card, not hidden",
      "not connected" in card8, card8)

# tier.js contract: all three attrs, and they must be DISTINCT -- three
# identical strings satisfy a naive presence check while defeating the feature.
import re as _re
attrs = dict(_re.findall(r'data-(beginner|intermediate|pro)="([^"]*)"', card8))
check("all three tier variants present", len(attrs) == 3, sorted(attrs))
check("...and genuinely DISTINCT (not the same string three times)",
      len(set(attrs.values())) == 3, attrs)
check("...element carries class=tier-text so tier.js finds it",
      'class="tier-text"' in card8)

print("\n-- 7b. HTML ESCAPING -- detail can carry server-influenced text --")
# `_last_error` only reaches `detail` when accounts > 0 AND client is None --
# verified against status() after a zero_accounts fixture silently failed to
# deliver the payload at all. A fixture that cannot deliver its own input is
# testing nothing, and it PASSED two of the three assertions while doing so.
mod9, m9 = load_module("two_accounts")
m9.start()
m9._client = None
m9._last_error = '"><script>alert(1)</script>'
card9 = m9.get_dashboard_card()
check("raw <script> never reaches the card", "<script>" not in card9, card9[:120])
check("the quote that would break out of an attribute is escaped",
      '"><script' not in card9, card9[:120])
check("...and the text is still PRESENT, escaped rather than dropped",
      "&lt;script&gt;" in card9 or "&quot;" in card9, card9[:160])

print("\n-- 7c. MUTATION: prove the escaping check is not vacuous --")
from html import escape as _esc
check("MUTANT (unescaped) WOULD contain raw <script> -> 7b is a real check",
      "<script>" in ('<p data-x="%s">' % '"><script>alert(1)</script>'))
check("CONTROL: escaping the same string removes it",
      "<script>" not in ('<p data-x="%s">' % _esc('"><script>alert(1)</script>', quote=True)))

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
