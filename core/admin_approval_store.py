"""Admin Approval Protocol v1 — request lifecycle and ATOMIC consumption (§7 step 11).

IMPLEMENTS `docs/protocol/admin-approval-v1.md`. The spec is the contract.

WHAT THIS ADDS to the verifier: `verify_approval()` is pure policy and takes `consume`
as an injected callable. This module is the storage half — creating requests, and the
one operation the spec singles out as needing atomicity:

    §7 step 11: Mark `request_id` and `nonce` consumed, ATOMICALLY. Two simultaneous
    approvals of one request MUST result in exactly one consumption and one
    authorized action.

⚠ THE ATOMICITY IS THE WHOLE POINT, AND IT IS NOT A TRANSACTION WRAPPER.
`consume()` is a single conditional UPDATE:

    UPDATE ... SET state='CONSUMED' WHERE request_id=? AND state='PENDING'

and the caller wins only if it changed exactly one row. A read-then-write
("SELECT state; if PENDING: UPDATE") is the obvious implementation and it is WRONG:
two threads both read PENDING, both write, both believe they won, and one approval
authorizes two actions. The conditional UPDATE makes the check and the write the same
operation, which is what makes the race unwinnable rather than merely unlikely.

⚠ DDL PLACEMENT (ADR 0001). `SCHEMA` below is the ONE canonical CREATE for this table
anywhere in the repo. `alert_manager/database.py` must CALL `init_admin_approval_tables`
alongside `init_licensing_tables()` — it must not restate the DDL, or there would be two
sources of truth for one table, which is exactly what ADR 0001 forbids.
"""

import os
import secrets
import sqlite3
import time

__all__ = ["SCHEMA", "init_admin_approval_tables", "create_request",
           "load_request", "consume", "reject", "purge_expired",
           "STATE_PENDING", "STATE_CONSUMED", "STATE_REJECTED", "RequestError"]

STATE_PENDING = "PENDING"
STATE_CONSUMED = "CONSUMED"
STATE_REJECTED = "REJECTED"

#: The single canonical DDL. See the DDL-placement note above.
SCHEMA = """
CREATE TABLE IF NOT EXISTS admin_approval_requests (
    request_id       BLOB PRIMARY KEY,      -- 16 random bytes (spec §4.1)
    user_id          TEXT NOT NULL,
    capability       TEXT NOT NULL,
    target           TEXT NOT NULL,
    action_params    BLOB NOT NULL,         -- opaque, pre-serialized (§4.2)
    appliance_id     TEXT NOT NULL,
    authenticator_id TEXT NOT NULL,
    issued_at        INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    match_code       INTEGER NOT NULL,
    nonce            BLOB NOT NULL,         -- 32 random bytes, single-use
    state            TEXT NOT NULL DEFAULT 'PENDING',
    consumed_at      INTEGER,
    created_by       TEXT                   -- actor seam (multi-user readiness)
)
"""

#: A nonce is single-use across ALL requests, not merely within one (§4.1). Without
#: this a nonce could be reused in a second request and the "single-use" property
#: would be a comment rather than a constraint.
NONCE_INDEX = ("CREATE UNIQUE INDEX IF NOT EXISTS "
               "idx_admin_approval_nonce ON admin_approval_requests(nonce)")


class RequestError(ValueError):
    """A request could not be created. An appliance-side input problem, not a rejection."""


def init_admin_approval_tables(conn=None):
    """Create the table + indexes. Idempotent.

    MATCHES THE SIBLING CONVENTION: called with no arguments it opens its own
    connection, exactly like `init_licensing_tables()`, so the call site is
    identical to its neighbours rather than a special case someone has to think
    about. `conn` is accepted for tests, which need a throwaway database.

    ⚠ CALL SITE — verified, not assumed (2026-08-23). `database.py` must NOT import
    this at module top level. Measured from a neutral cwd:

        PYTHONPATH=/opt/nemesis/alert_manager:/opt/nemesis   -> core importable
        PYTHONPATH=/opt/nemesis/alert_manager                -> ModuleNotFoundError

    and `nemesis-fw-watch.service` runs with exactly that second path, while
    `dashboard.service` sets `/opt/nemesis/alert_manager:/opt/nemesis/core_module/hw_monitor`
    and gets `core` only because dashboard.py inserts the repo root itself. A
    top-level `from core...` in database.py would therefore break a service that
    merely imports database.py without needing this table at all.

    So: call it the way `init_licensing_tables()` is called -- from dashboard.py's
    startup block -- or import it lazily INSIDE a function in database.py. Not at
    module scope.
    """
    own = conn is None
    if own:
        import sqlite3 as _sq
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        import sys as _sys
        amgr = os.path.join(here, "alert_manager")
        if amgr not in _sys.path:
            _sys.path.insert(0, amgr)
        import nemesis_paths
        conn = _sq.connect(nemesis_paths.db_path(None), timeout=5.0)
    try:
        conn.execute(SCHEMA)
        conn.execute(NONCE_INDEX)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_admin_approval_state "
                     "ON admin_approval_requests(state, expires_at)")
        conn.commit()
    finally:
        if own:
            conn.close()


def create_request(conn, *, user_id, capability, target, action_params,
                   appliance_id, authenticator_id, ttl_seconds=300,
                   now=None, created_by=None):
    """Create a PENDING approval request. Returns the stored record.

    `request_id`, `nonce` and `match_code` are generated HERE with a CSPRNG and are
    never accepted from a caller (§4.1). A caller-supplied request_id would let the
    requester choose the value an approval is bound to, which is the same class of
    mistake as accepting a client-supplied `P`.
    """
    now = int(now if now is not None else time.time())
    if ttl_seconds < 1:
        raise RequestError("ttl_seconds must be >= 1")
    if not isinstance(action_params, bytes):
        # §4.2 -- opaque and ALREADY serialized. This layer must never serialize it,
        # because a round-trip can reorder keys and the signature would then be over
        # bytes that no longer exist.
        raise RequestError("action_params must be bytes, already serialized (§4.2)")

    rec = {
        "request_id": secrets.token_bytes(16),
        "user_id": user_id,
        "capability": capability,
        "target": target or "",
        "action_params": action_params,
        "appliance_id": appliance_id,
        "authenticator_id": authenticator_id,
        "issued_at": now,
        "expires_at": now + int(ttl_seconds),
        # 0..999 inclusive (§4.1). secrets.randbelow(1000) is uniform; a modulo of a
        # wider random would be biased, which matters for a 3-digit code a human
        # compares by eye.
        "match_code": secrets.randbelow(1000),
        "nonce": secrets.token_bytes(32),
        "state": STATE_PENDING,
        "consumed_at": None,
        "created_by": created_by,
    }
    conn.execute(
        "INSERT INTO admin_approval_requests (request_id, user_id, capability, "
        "target, action_params, appliance_id, authenticator_id, issued_at, "
        "expires_at, match_code, nonce, state, created_by) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (rec["request_id"], rec["user_id"], rec["capability"], rec["target"],
         rec["action_params"], rec["appliance_id"], rec["authenticator_id"],
         rec["issued_at"], rec["expires_at"], rec["match_code"], rec["nonce"],
         rec["state"], rec["created_by"]))
    conn.commit()
    return rec


def load_request(conn, request_id):
    """Fetch a request as the dict `verify_approval()` expects, or None.

    Returning None for unknown is deliberate: §7 step 1 distinguishes "unknown"
    (AAP-001) from "already consumed" (AAP-002), so this must not conflate them by
    filtering on state.
    """
    row = conn.execute(
        "SELECT request_id, user_id, capability, target, action_params, "
        "appliance_id, authenticator_id, issued_at, expires_at, match_code, "
        "nonce, state, consumed_at FROM admin_approval_requests "
        "WHERE request_id=?", (request_id,)).fetchone()
    if row is None:
        return None
    keys = ("request_id", "user_id", "capability", "target", "action_params",
            "appliance_id", "authenticator_id", "issued_at", "expires_at",
            "match_code", "nonce", "state", "consumed_at")
    rec = dict(zip(keys, row))
    # SQLite hands BLOBs back as bytes already, but a driver returning memoryview
    # would silently break the byte-exact encoding in §4. Normalise rather than
    # assume.
    for b in ("request_id", "action_params", "nonce"):
        if rec[b] is not None and not isinstance(rec[b], bytes):
            rec[b] = bytes(rec[b])
    return rec


def consume(conn, request_id, now=None):
    """§7 step 11 — atomically mark consumed. True for EXACTLY ONE caller.

    ONE conditional UPDATE, deliberately. See the module docstring: a read-then-write
    lets two concurrent verifications both believe they won, so one approval would
    authorize two actions. `rowcount == 1` is the win condition because the database
    performed the check and the write as a single operation.
    """
    now = int(now if now is not None else time.time())
    cur = conn.execute(
        "UPDATE admin_approval_requests SET state=?, consumed_at=? "
        "WHERE request_id=? AND state=?",
        (STATE_CONSUMED, now, request_id, STATE_PENDING))
    conn.commit()
    return cur.rowcount == 1


def reject(conn, request_id, now=None):
    """Mark a pending request rejected (the operator declined). Same atomicity."""
    now = int(now if now is not None else time.time())
    cur = conn.execute(
        "UPDATE admin_approval_requests SET state=?, consumed_at=? "
        "WHERE request_id=? AND state=?",
        (STATE_REJECTED, now, request_id, STATE_PENDING))
    conn.commit()
    return cur.rowcount == 1


def purge_expired(conn, older_than_seconds=86400, now=None):
    """Delete long-expired requests. Retention hygiene, not a security control.

    Deliberately does NOT delete merely-expired rows: §7 step 3 must be able to
    answer AAP-003 (expired) rather than AAP-001 (unknown), and deleting on expiry
    would collapse those two into one. Only rows old enough that the distinction no
    longer helps anyone are removed.
    """
    now = int(now if now is not None else time.time())
    cur = conn.execute(
        "DELETE FROM admin_approval_requests WHERE expires_at < ?",
        (now - int(older_than_seconds),))
    conn.commit()
    return cur.rowcount
