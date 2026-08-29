#!/usr/bin/env python3
"""Enrollment-token revocation: setting the flag must actually stop redemption.

Run: python3 alert_manager/test_token_revocation.py   (exit 0 = all pass)

WHAT THIS GUARDS. `enrollment_tokens.revoked` has been ENFORCED since the column
existed — hw_monitor claims a token with a single atomic
`UPDATE … WHERE token=? AND revoked=0 AND auto_approve=1 AND uses < max_uses AND
expires_at > ?`. What did not exist until 2026-08-29 was any way for the product
to SET the flag: every other statement in the tree is an INSERT, a SELECT, or an
update of `uses`/`preauth_key`. Revoking meant sqlite3 by hand, and an audit found
three tokens already revoked exactly that way.

THE PROPERTY UNDER TEST IS THE ROUND TRIP, not the UPDATE. Asserting "revoked==1
after revoking" would pass even if enforcement had been removed — it restates the
write instead of testing it. So every revocation here is followed by running
hw_monitor's REAL claim statement and proving it no longer matches. Each is paired
with a control proving the same claim DOES match before revocation, so a claim
that could never match would fail the suite rather than silently pass it.

The route's HTTP surface (POST-only, admin-gated, not auth-exempt) is verified
separately against the live `app.url_map` and `roles.ROUTE_MINIMUMS`; those are
structural facts the existing `test_roles.py` / `test_route_registration_gate.py`
already enforce generally. What is NOT covered by them, and is covered here, is
what the revocation actually DOES to a token's redeemability.

NO LIVE DB. Everything runs against a throwaway file in a temp dir.
"""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s" % label)
        if detail:
            print("         %s" % (detail,))


_db = os.path.join(tempfile.mkdtemp(prefix="tokrevoke-"), "throwaway.db")
os.environ["NEMESIS_DB_PATH"] = _db

import database                                          # noqa: E402

database.init_enrollment_tokens_table()
conn = sqlite3.connect(_db)
conn.row_factory = sqlite3.Row


def _mktoken(tok, revoked=0, uses=0, max_uses=1, ttl=3600, auto=1):
    now = time.time()
    conn.execute(
        "INSERT INTO enrollment_tokens (token, created_by, created_at, expires_at,"
        " max_uses, uses, auto_approve, device_name_hint, revoked, remote_enabled)"
        " VALUES (?,?,?,?,?,?,?,?,?,0)",
        (tok, "tester", now, now + ttl, max_uses, uses, auto, "hint", revoked))
    conn.commit()
    return conn.execute("SELECT id FROM enrollment_tokens WHERE token=?", (tok,)).fetchone()["id"]


def _claim(tok):
    """hw_monitor's REAL claim statement (core_module/hw_monitor/hw_monitor.py:3924).

    Copied deliberately rather than imported: importing hw_monitor drags in the
    whole daemon. The risk of a copy drifting from the original is real, so
    section 4 pins the original's text — if that statement changes, this test
    fails and names the drift instead of silently testing a stale copy.
    """
    cur = conn.execute(
        "UPDATE enrollment_tokens SET uses = uses + 1 "
        "WHERE token=? AND revoked=0 AND auto_approve=1 "
        "AND uses < max_uses AND expires_at > ?",
        (tok, time.time()))
    conn.commit()
    return cur.rowcount


def _revoke(token_id, actor="admin-test"):
    """The route's write, as the route performs it."""
    cur = conn.execute(
        "UPDATE enrollment_tokens SET revoked=1, revoked_at=?, revoked_by=? "
        "WHERE id=? AND revoked=0",
        (time.time(), actor, token_id))
    conn.commit()
    return cur.rowcount


print("\n-- 0. PREMISE: the attribution columns exist (guarded migration ran) --")
cols = {r[1] for r in conn.execute("PRAGMA table_info(enrollment_tokens)")}
check("⭐ revoked_at column exists", "revoked_at" in cols, sorted(cols))
check("⭐ revoked_by column exists", "revoked_by" in cols, sorted(cols))
check("revoked column exists (the flag being set)", "revoked" in cols)


print("\n-- 1. THE ROUND TRIP: revoking actually prevents redemption --")
tid = _mktoken("tok-live")
check("⭐ CONTROL: an un-revoked token CAN be claimed (so the check below is not "
      "passing because claims never work)", _claim("tok-live") == 1)
conn.execute("UPDATE enrollment_tokens SET uses=0 WHERE id=?", (tid,)); conn.commit()

check("⭐ revoke reports exactly one row changed", _revoke(tid) == 1)
check("⭐⭐ the SAME claim now matches NOTHING — enforcement and the new write "
      "agree", _claim("tok-live") == 0)
row = conn.execute("SELECT uses, revoked FROM enrollment_tokens WHERE id=?", (tid,)).fetchone()
check("...and the refused claim did NOT consume a use", row["uses"] == 0, dict(row))


print("\n-- 2. attribution is recorded, and is distinguishable from hand-revoked --")
r = conn.execute("SELECT revoked_by, revoked_at FROM enrollment_tokens WHERE id=?",
                 (tid,)).fetchone()
check("⭐ revoked_by records WHO", r["revoked_by"] == "admin-test", dict(r))
check("⭐ revoked_at records WHEN", isinstance(r["revoked_at"], float) and r["revoked_at"] > 0)
# A row revoked by hand before this feature has NULLs. That must stay tellable
# apart from a row this feature revoked, or the audit trail claims knowledge it
# does not have.
hand = _mktoken("tok-hand", revoked=1)
h = conn.execute("SELECT revoked, revoked_by FROM enrollment_tokens WHERE id=?",
                 (hand,)).fetchone()
check("⭐ CONTROL: a hand-revoked row is revoked but has NULL actor — 'revoked by "
      "someone unknown' stays distinguishable from an attributed revoke",
      h["revoked"] == 1 and h["revoked_by"] is None, dict(h))


print("\n-- 3. idempotence: re-revoking is not a failure, but IS distinguishable --")
check("⭐ re-revoking an already-revoked token changes 0 rows (the route reports "
      "already_revoked, not an error)", _revoke(tid) == 0)
check("...and the token stays revoked", conn.execute(
    "SELECT revoked FROM enrollment_tokens WHERE id=?", (tid,)).fetchone()["revoked"] == 1)
check("⭐ a non-existent id changes 0 rows too — which is WHY the route must SELECT "
      "first: rowcount alone cannot tell 'already revoked' from 'no such token'",
      _revoke(999999) == 0)


print("\n-- 4. the copied claim statement still matches hw_monitor's real one --")
# Guards the one real weakness of _claim() above: a copy that drifts.
src = open("/opt/nemesis/core_module/hw_monitor/hw_monitor.py", encoding="utf-8").read()
for frag in ("UPDATE enrollment_tokens SET uses = uses + 1",
             "WHERE token=? AND revoked=0 AND auto_approve=1",
             "AND uses < max_uses AND expires_at > ?"):
    check("hw_monitor still contains: %r" % frag[:46], frag in src)
check("⭐ CONTROL: a fragment that should NOT be there is absent (so the check "
      "above is not matching everything)",
      "WHERE token=? AND revoked=1" not in src)


print("\n-- 5. revocation does not disturb other tokens --")
other = _mktoken("tok-other")
_revoke(tid)
check("⭐ an unrelated token remains claimable after another is revoked",
      _claim("tok-other") == 1)

conn.close()
print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
