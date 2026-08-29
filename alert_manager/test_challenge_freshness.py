#!/usr/bin/env python3
"""An expired Tier 2 challenge must be REFUSED, not verified.

Run: python3 alert_manager/test_challenge_freshness.py   (exit 0 = all pass)

WHAT THIS GUARDS. `CHALLENGE_TTL_SECONDS`' docstring has always claimed "a stale
nonce past this is not accepted (freshness)". Until 2026-08-29 nothing
implemented it: `expires_at` was written at issue time and read by nothing — the
ingest SELECT filtered on `device_id` alone, `verify_and_record_tier2()` did not
check it, and no sweeper pruned expired rows. A nonce stayed answerable forever.

**A stated security property that is not implemented is worse than an absent
one**, because a reader who checks the constant concludes freshness is handled.
That is the defect this file pins.

THE CONTROL IS LOAD-BEARING. Every "expired is refused" assertion is paired with
a fresh challenge that IS accepted, on the same code path. Without that pairing,
an ingest that refused *everything* — a plausible way to break this while
"fixing" it — would satisfy every refusal assertion and prove nothing.

WHY THE PRIVATE MODULE IS STUBBED. `ingest_challenge_response()` returns early if
`tier2_available()` is False, which it is on any host without the private Tier 2
module. Stubbing it is what makes the code under test REACHABLE; without it this
file would pass by never executing the branch it exists to check.

NO LIVE DB, NO NETWORK. Throwaway DB in a temp dir; schema from the shipped init.
"""
import os
import sys
import tempfile
import types
import sqlite3

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (_ROOT, _HERE, os.path.join(_ROOT, "nemesis_agent")):
    if p not in sys.path:
        sys.path.insert(0, p)

_db = os.path.join(tempfile.mkdtemp(prefix="freshness-"), "alerts.db")
os.environ["NEMESIS_DB_PATH"] = _db

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


import database                                            # noqa: E402
from alert_manager import attestation as att                # noqa: E402

# Schema from the SHIPPED init, never hand-rolled — a fixture that drifts from
# the real DDL reports defects that do not exist (learned the hard way earlier
# the same day; see test_attest_challenge_dispatch.py).
database.init_attestation_challenge_table()

DEV = "dev-fresh"
NONCE = "n" * 32

# Stub the deliberately-absent private module so the branch is reachable.
att._tier2 = types.SimpleNamespace(
    augment_manifest=lambda m, covered, root: m.update(
        {"code_digests": {"a.py": "d" * 64}, "code_digest_python": "e" * 64}),
    new_nonce=lambda: NONCE,
    verify_response=lambda manifest, nonce_hex, resp: {"state": "attested",
                                                       "detail": "stub ok"},
)


def _conn():
    c = sqlite3.connect(_db)
    return c


def _seed(expires_at, device=DEV):
    """Put one challenge row in place with a chosen expiry."""
    c = _conn()
    c.execute("DELETE FROM agent_attestation_challenges WHERE device_id=?", (device,))
    c.execute("DELETE FROM attestation_tier2_state WHERE device_id=?", (device,))
    c.execute("INSERT INTO agent_attestation_challenges "
              "(device_id, nonce, code_digests, code_python, issued_at, expires_at) "
              "VALUES (?,?,?,?,?,?)",
              (device, NONCE, '{"a.py": "%s"}' % ("d" * 64), "e" * 64, 0.0, expires_at))
    c.commit(); c.close()


def _rows(device=DEV):
    c = _conn()
    ch = c.execute("SELECT count(*) FROM agent_attestation_challenges WHERE device_id=?",
                   (device,)).fetchone()[0]
    st = c.execute("SELECT state FROM attestation_tier2_state WHERE device_id=?",
                   (device,)).fetchone()
    c.close()
    return ch, (st[0] if st else None)


NOW = 1_000_000.0

print("\n-- 0. PREMISE: the branch under test is reachable --")
check("⭐ tier2_available() is True with the stub installed (without this the "
      "function returns early and every assertion below is vacuous)",
      att.tier2_available() is True)
check("the shipped init created both tables",
      all(_conn().execute(
          "SELECT count(*) FROM sqlite_master WHERE name=?", (t,)).fetchone()[0] == 1
          for t in ("agent_attestation_challenges", "attestation_tier2_state")))


print("\n-- 1. CONTROL: a FRESH challenge is accepted (proves refusal is selective) --")
_seed(expires_at=NOW + 60)
state = att.ingest_challenge_response(_conn_ := _conn(), DEV, {"any": "response"}, now=NOW)
_conn_.commit(); _conn_.close()
check("⭐ fresh challenge verifies", state == "attested", state)
ch, st = _rows()
check("...the verdict is recorded", st == "attested", st)
check("...and the challenge is consumed", ch == 0, ch)


print("\n-- 2. EXPIRED is refused, and leaves no verdict --")
_seed(expires_at=NOW - 1)
state = att.ingest_challenge_response(_c2 := _conn(), DEV, {"any": "response"}, now=NOW)
_c2.commit(); _c2.close()
check("⭐⭐ expired challenge returns None (NOT verified)", state is None, state)
ch, st = _rows()
check("⭐⭐ NO verdict was recorded — the whole point: a stale nonce must not "
      "produce an 'attested'", st is None, st)
check("⭐ the expired row is CLEARED, not left to be raced again", ch == 0, ch)


print("\n-- 3. boundary: expires_at exactly == now is EXPIRED (<=, not <) --")
_seed(expires_at=NOW)
state = att.ingest_challenge_response(_c3 := _conn(), DEV, {"r": 1}, now=NOW)
_c3.commit(); _c3.close()
check("⭐ expiry is inclusive — a challenge at its exact deadline is refused",
      state is None, state)


# ── NOT TESTED, AND DELIBERATELY SO: the NULL-expiry branch ──────────────────
# `ingest_challenge_response()` guards `_exp is None` before comparing. That
# branch is UNREACHABLE through this table: the shipped DDL declares
# `expires_at REAL NOT NULL`, and an attempt to seed one fails with
# `IntegrityError: NOT NULL constraint failed` (confirmed — this file originally
# tried to test it and could not).
#
# The guard is kept anyway, because without it a NULL would reach `float(None)`
# and raise TypeError, which the caller's broad handler would swallow into "no
# tasks this beat". But it is NOT asserted here: a test that manufactures a
# schema the product does not have would be testing the fixture, and claiming
# coverage of a branch nothing can reach is exactly the "green suite that never
# walked the code" shape. Recorded rather than silently omitted.


print("\n-- 4. CONTROL: refusal is not global — a fresh one still works afterwards --")
# Guards the plausible mis-fix of refusing everything. Runs LAST so it also
# proves the earlier refusals left no poisoned state behind.
_seed(expires_at=NOW + 3600)
state = att.ingest_challenge_response(_c5 := _conn(), DEV, {"r": 1}, now=NOW)
_c5.commit(); _c5.close()
check("⭐⭐ a fresh challenge still verifies after the two refusals above — the "
      "check is selective, not a blanket deny", state == "attested", state)


EXPECTED_CHECKS = 10
_total = passed + failed
if _total != EXPECTED_CHECKS:
    print("  [FAIL] ⭐ assertion COUNT drifted: ran %d, expected %d — coverage "
          "changed, so this run is not comparable to earlier ones"
          % (_total, EXPECTED_CHECKS))
    failed += 1

print("\n%d passed, %d failed  (of %d expected)" % (passed, failed, EXPECTED_CHECKS))
sys.exit(1 if failed else 0)
