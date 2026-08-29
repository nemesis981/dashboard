#!/usr/bin/env python3
"""Dispatching a Tier 2 `attest_challenge` task must actually store the challenge.

Run: python3 alert_manager/test_attest_challenge_dispatch.py   (exit 0 = all pass)

WHAT THIS GUARDS, AND WHY IT DID NOT EXIST. `_tasks_for_response()` opened a
connection for its pending-task SELECT, closed it in that block's own `finally`,
and then passed the CLOSED connection to
`attestation.build_and_store_challenge()`. Any write on it raises
`sqlite3.ProgrammingError: Cannot operate on a closed database`.

**Nothing caught this because the path had never executed.** It is gated twice
over — on an `attest_challenge` task existing (none ever had:`scan_tasks` held
only `scan` actions) and on the private Tier 2 module being deployed
(`tier2_available()` is False on the dev box, and it returns None *before*
touching the connection). Both gates had to be opened to reach the defect, so no
amount of running the existing suite would have found it.

THE FAILURE MODE IS A POISON PILL, not a crash. The raise is caught by
`_tasks_for_response()`'s outer handler, which logs `could not build tasks for
device=…` and returns `[]` — so NO tasks go out that beat, including unrelated
scan tasks. The task stays pending, the next beat fails identically, and task
dispatch to that device stalls permanently.

SO THIS TEST OPENS BOTH GATES DELIBERATELY: it queues a real `attest_challenge`
row in `scan_tasks` and stubs the absent private module so `tier2_available()` is
True, then drives the REAL `_tasks_for_response()`. Asserting on a stub of the
function under test would have proved nothing — the bug lived in the caller's
connection lifetime, not in the challenge builder.

NO LIVE DB, NO NETWORK. Throwaway DB in a temp dir; the signing layer is stubbed
(it is covered by test_attestation.py and is not what broke).
"""
import json
import os
import sqlite3
import sys
import tempfile
import types

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (_ROOT, _HERE, os.path.join(_ROOT, "core_module", "hw_monitor"),
          os.path.join(_ROOT, "nemesis_agent")):
    if p not in sys.path:
        sys.path.insert(0, p)

_dbdir = tempfile.mkdtemp(prefix="attchal-")
_db = os.path.join(_dbdir, "alerts.db")
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


import hw_monitor as hm                                   # noqa: E402
from alert_manager import attestation as att              # noqa: E402
import server_keys                                        # noqa: E402

DEV = "dev-under-test"


def _schema():
    """Build fixture schema from the SHIPPED DDL, never hand-rolled.

    ⚠ Learned the hard way in this very file: a hand-written `scan_tasks` was
    missing `dispatch_count`, and the test failed with `no such column` —
    reporting a defect that did not exist while the real bug sat elsewhere. The
    house practice is already documented in `test_layer_c.py` ("run against the
    REAL schema and cannot drift from it") and `nemesis_agent/test_task_results.py`
    lifts this same inline DDL by index for exactly this reason.

    `agent_attestation_challenges` has a canonical init function; `scan_tasks`'
    DDL is inline in hw_monitor, so it is extracted rather than retyped — a
    column added to the shipped CREATE then shows up here instead of silently
    diverging.
    """
    import database as _dbmod
    _dbmod.init_attestation_challenge_table()

    src = open(os.path.join(_ROOT, "core_module", "hw_monitor", "hw_monitor.py"),
               encoding="utf-8").read()
    start = src.index("CREATE TABLE IF NOT EXISTS scan_tasks")
    ddl = src[start:src.index('"""', start)]
    c = sqlite3.connect(_db)
    c.execute(ddl)
    c.commit(); c.close()


def _queue(action="attest_challenge", task_id="t-1"):
    c = sqlite3.connect(_db)
    c.execute("INSERT INTO scan_tasks (task_id, device_id, action, params_json,"
              " status, created_at) VALUES (?,?,?,?, 'pending', 0)",
              (task_id, DEV, action, json.dumps({})))
    c.commit(); c.close()


def _challenge_rows():
    c = sqlite3.connect(_db)
    n = c.execute("SELECT count(*) FROM agent_attestation_challenges").fetchone()[0]
    c.close()
    return n


# ── stubs: the signing layer, and the deliberately-absent private module ──────
server_keys.have_server_keypair = lambda: True
server_keys.signing_key_for_fingerprint = lambda fp: "/tmp/fake-signer.key"
# Envelope shape copied from the REAL build_task (alert_manager/server_keys.py):
# the dispatch block downstream reads env["expires_at"] and env["task_id"], so a
# stub omitting them fails with KeyError. Second time in this file a too-thin
# stub broke the test rather than the code — a stub that does not honour the real
# contract tests the stub, not the system.
server_keys.build_task = lambda device_id, action, params=None, task_id=None, \
    sign_with=None, now=None: {
        "task_id": task_id or "generated", "action": action,
        "params": params or {}, "expires_at": "2026-01-01T00:00:00",
        "signature": "stub-signature"}
hm._requeue_expired_tasks = lambda device_id: None

# Key names taken from the REAL consumer, not guessed: build_and_store_challenge
# reads manifest["code_digests"] and manifest["code_digest_python"]. My first
# stub used "python" and the test failed with KeyError 'code_digest_python' —
# the stub was wrong, not the code. Worth stating: a stub that does not honour
# the real contract tests the stub.
_fake_tier2 = types.SimpleNamespace(
    augment_manifest=lambda manifest, covered, root: manifest.update(
        {"code_digests": {"a.py": "d" * 64}, "code_digest_python": "e" * 64}),
    new_nonce=lambda: "n" * 32,
)

_schema()


print("\n-- 0. PREMISES: both gates are genuinely shut by default --")
check("⭐ the private Tier 2 module really is absent here (gate 2), so the real "
      "path returns None before touching the connection",
      att.tier2_available() is False)
check("⭐ no attest_challenge task exists yet (gate 1)", _challenge_rows() == 0)

att._tier2 = _fake_tier2
check("⭐ CONTROL: with the stub installed, tier2_available() is now True — both "
      "gates open, so the code under test is actually reachable",
      att.tier2_available() is True)


print("\n-- 1. THE REGRESSION: the old shape raises on a closed connection --")
# Reproduces the exact defect: a connection closed by its own `finally`, then
# used for the challenge write. Proves the bug was real, and that this test
# would have caught it.
_c = sqlite3.connect(_db)
_c.close()
try:
    att.build_and_store_challenge(_c, DEV, agent_root=_ROOT, now=1.0)
    check("⭐ old shape (closed conn) raises", False, "no exception raised")
except sqlite3.ProgrammingError as e:
    check("⭐ old shape (closed conn) raises ProgrammingError — the defect, "
          "reproduced", "closed database" in str(e).lower(), str(e))
except Exception as e:                                    # noqa: BLE001
    check("old shape raises", False, "unexpected: %s: %s" % (type(e).__name__, e))
check("...and nothing was stored by that failed attempt", _challenge_rows() == 0)


print("\n-- 2. THE FIX: dispatching a REAL attest_challenge task stores it --")
_queue()
envelopes = hm._tasks_for_response(DEV)
check("⭐⭐ the challenge row is STORED — this path had never completed once "
      "before today", _challenge_rows() == 1, "rows=%d" % _challenge_rows())
check("⭐ an envelope was returned for the task (not swallowed by the outer "
      "handler returning [])", len(envelopes) == 1, envelopes)
# ⚠ DELIBERATELY UNCONDITIONAL — these used to sit under `if envelopes:`.
# That made the ASSERTION COUNT ITSELF vary: on failure the suite silently
# reported 12 checks instead of 14, so a run with less coverage looked like a
# different, smaller suite rather than a failing one. Window 2 hit exactly that
# on 2026-08-29 and reported "3/12 failing", which did not match any count this
# file produces when healthy. A test whose total changes under failure cannot be
# compared between runs. `_env0` degrades to {} so these still evaluate.
_env0 = envelopes[0] if envelopes else {}
check("...and it is the attest_challenge task",
      _env0.get("action") == "attest_challenge", _env0)
check("...carrying the nonce the server stored",
      (_env0.get("params") or {}).get("nonce") == "n" * 32, _env0)

row = sqlite3.connect(_db).execute(
    "SELECT device_id, nonce FROM agent_attestation_challenges").fetchone()
check("the stored row is keyed to this device", row and row[0] == DEV, row)
check("⭐ the stored nonce MATCHES the one sent — a challenge whose stored and "
      "delivered nonce differ can never verify", row and row[1] == "n" * 32, row)


print("\n-- 3. CONTROL: an ordinary task still dispatches (fix is not too broad) --")
c = sqlite3.connect(_db); c.execute("DELETE FROM scan_tasks"); c.commit(); c.close()
_queue(action="scan", task_id="t-2")
env2 = hm._tasks_for_response(DEV)
check("⭐ a plain scan task still produces an envelope", len(env2) == 1, env2)
check("...and did NOT add a challenge row", _challenge_rows() == 1)


print("\n-- 4. the poison-pill shape is gone --")
# Before the fix, ANY attest_challenge task made _tasks_for_response return []
# for that beat, dropping unrelated tasks with it. Both queued together proves
# the challenge no longer takes the batch down.
c = sqlite3.connect(_db); c.execute("DELETE FROM scan_tasks"); c.commit(); c.close()
c = sqlite3.connect(_db)
c.execute("DELETE FROM agent_attestation_challenges"); c.commit(); c.close()
_queue(action="scan", task_id="t-3")
_queue(action="attest_challenge", task_id="t-4")
env3 = hm._tasks_for_response(DEV)
check("⭐⭐ a challenge queued ALONGSIDE a scan no longer takes the whole batch "
      "down — both dispatch", len(env3) == 2, env3)

# The count is part of the contract: if this file ever reports a different total,
# coverage changed and the comparison to any earlier run is invalid. Asserted
# rather than trusted, for the reason in section 2's comment.
EXPECTED_CHECKS = 14
_total = passed + failed
if _total != EXPECTED_CHECKS:
    print("  [FAIL] ⭐ assertion COUNT drifted: ran %d, expected %d — coverage "
          "changed, so this run is not comparable to earlier ones"
          % (_total, EXPECTED_CHECKS))
    failed += 1

print("\n%d passed, %d failed  (of %d expected)" % (passed, failed, EXPECTED_CHECKS))
sys.exit(1 if failed else 0)
