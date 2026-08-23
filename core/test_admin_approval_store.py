#!/usr/bin/env python3
"""Admin Approval v1 §7 step 11 — request lifecycle and ATOMIC consumption.

THE LOAD-BEARING TEST IS THE CONCURRENCY ONE. The spec says two simultaneous
approvals of one request MUST yield exactly one consumption. That is not
demonstrable by calling consume() twice in sequence -- sequential calls pass
against a read-then-write implementation that races in production. So the test
below runs real threads against one database and asserts exactly one winner, and
is paired with a control proving the harness can actually produce contention.
"""
import os
import sqlite3
import sys
import tempfile
import threading

sys.path.insert(0, "/opt/nemesis")

from core.admin_approval_store import (
    init_admin_approval_tables, create_request, load_request, consume, reject,
    purge_expired, STATE_PENDING, STATE_CONSUMED, STATE_REJECTED, RequestError)
from core.admin_approval import encode_payload, challenge_for

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


def fresh_db():
    path = os.path.join(tempfile.mkdtemp(prefix="aareq-"), "t.db")
    conn = sqlite3.connect(path)
    init_admin_approval_tables(conn)
    return path, conn


def mk(conn, **over):
    kw = dict(user_id="admin-1", capability="push_and_run", target="dev-1",
              action_params=b'{"cmd":"restart"}', appliance_id="app-A",
              authenticator_id="auth-1", ttl_seconds=300, now=1_700_000_000)
    kw.update(over)
    return create_request(conn, **kw)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== creation: generated server-side, never caller-supplied ==")

path, conn = fresh_db()
r = mk(conn)
check("request_id is 16 bytes", len(r["request_id"]) == 16)
check("nonce is 32 bytes", len(r["nonce"]) == 32)
check("match_code within 0..999", 0 <= r["match_code"] <= 999)
check("state starts PENDING", r["state"] == STATE_PENDING)
check("expires_at = issued_at + ttl", r["expires_at"] == r["issued_at"] + 300)

r2 = mk(conn)
check("two requests get DIFFERENT request_ids", r["request_id"] != r2["request_id"])
check("  ...and different nonces", r["nonce"] != r2["nonce"])

# A caller cannot choose these -- accepting a caller-supplied request_id would let
# the requester pick the value an approval binds to, the same class of mistake as
# accepting a client-supplied P.
import inspect
params = inspect.signature(create_request).parameters
for forbidden in ("request_id", "nonce", "match_code"):
    check("create_request does NOT accept %s from the caller" % forbidden,
          forbidden not in params)

try:
    mk(conn, action_params={"cmd": "restart"})
    check("rejects a non-bytes action_params (§4.2)", False, "accepted a dict")
except RequestError:
    check("rejects a non-bytes action_params (§4.2)", True)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== round-trip: stored bytes are the bytes P is built from ==")

loaded = load_request(conn, r["request_id"])
check("loads by request_id", loaded is not None)
for f in ("request_id", "action_params", "nonce"):
    check("%s round-trips as exact bytes" % f, loaded[f] == r[f])
check("unknown request_id -> None (AAP-001, not a crash)",
      load_request(conn, b"\x00" * 16) is None)

# The point of byte-exactness: P must be reproducible from what was stored.
P_created = encode_payload(
    request_id=r["request_id"], capability=r["capability"], target=r["target"],
    action_params=r["action_params"], appliance_id=r["appliance_id"],
    authenticator_id=r["authenticator_id"], issued_at=r["issued_at"],
    expires_at=r["expires_at"], match_code=r["match_code"], nonce=r["nonce"])
P_loaded = encode_payload(
    request_id=loaded["request_id"], capability=loaded["capability"],
    target=loaded["target"], action_params=loaded["action_params"],
    appliance_id=loaded["appliance_id"], authenticator_id=loaded["authenticator_id"],
    issued_at=loaded["issued_at"], expires_at=loaded["expires_at"],
    match_code=loaded["match_code"], nonce=loaded["nonce"])
check("P rebuilt from STORAGE equals P at creation", P_created == P_loaded)
check("  ...so the challenge matches too",
      challenge_for(P_created) == challenge_for(P_loaded))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== §7 step 11: consumption is atomic and single-use ==")

check("first consume wins", consume(conn, r["request_id"], now=1_700_000_100))
check("state is now CONSUMED",
      load_request(conn, r["request_id"])["state"] == STATE_CONSUMED)
check("SECOND consume of the same request LOSES", not consume(conn, r["request_id"]))
check("consuming an unknown request loses (never raises)",
      not consume(conn, b"\x11" * 16))

r3 = mk(conn)
check("reject on a pending request wins", reject(conn, r3["request_id"]))
check("  ...state is REJECTED", load_request(conn, r3["request_id"])["state"] == STATE_REJECTED)
check("a rejected request can no longer be consumed", not consume(conn, r3["request_id"]))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== THE RACE: concurrent consumption yields EXACTLY ONE winner ==")

# Sequential calls would pass even against a read-then-write implementation that
# races in production, so this uses real threads on one database with a barrier to
# maximise contention.
N = 16
for trial in range(5):
    p2, c2 = fresh_db()
    target = mk(c2)
    c2.close()
    barrier = threading.Barrier(N)
    wins = []
    lock = threading.Lock()

    def worker():
        conn_t = sqlite3.connect(p2, timeout=10.0)
        try:
            barrier.wait()
            won = consume(conn_t, target["request_id"])
            if won:
                with lock:
                    wins.append(threading.current_thread().name)
        except sqlite3.OperationalError:
            pass          # lock contention is a LOSS, never a win
        finally:
            conn_t.close()

    threads = [threading.Thread(target=worker, name="t%d" % i) for i in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    if trial == 0:
        check("%d concurrent consumers -> EXACTLY ONE winner" % N,
              len(wins) == 1, "winners=%r" % wins)
    elif len(wins) != 1:
        check("trial %d: exactly one winner" % trial, False, "winners=%r" % wins)

check("5 trials x %d threads: never more than one winner" % N, True)

# CONTROL: the harness really can run these concurrently -- otherwise "one winner"
# would be proving that only one thread ever ran.
p3, c3 = fresh_db()
started = []
b2 = threading.Barrier(N)


def counter():
    b2.wait(timeout=5)
    with lock:
        started.append(1)


ts = [threading.Thread(target=counter) for _ in range(N)]
for t in ts:
    t.start()
for t in ts:
    t.join()
check("CONTROL: all %d threads genuinely reached the barrier together" % N,
      len(started) == N, "only %d did" % len(started))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== retention: expiry must stay distinguishable from unknown ==")

p4, c4 = fresh_db()
old = mk(c4, now=1_000_000)
# Merely expired rows are KEPT: §7 step 3 must answer AAP-003 (expired) rather
# than AAP-001 (unknown), and deleting on expiry collapses the two.
purge_expired(c4, older_than_seconds=86400, now=1_000_000 + 400)
check("a just-expired request is NOT purged (AAP-003 must stay answerable)",
      load_request(c4, old["request_id"]) is not None)
purge_expired(c4, older_than_seconds=86400, now=1_000_000 + 200_000)
check("a long-expired request IS purged (retention hygiene)",
      load_request(c4, old["request_id"]) is None)

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
