#!/usr/bin/env python3
"""Admin Approval Protocol v1 §5 — PERSISTENCE for authenticator registrations.

IMPLEMENTS the storage half of `admin-approval-v1.md` §5 (held private per the
Rule 10 decision of 2026-08-23). `admin_approval_pairing.build_registration()`
VALIDATES and returns a registration record; this module is what keeps one.

WHY THIS EXISTS AS ITS OWN COMMIT
---------------------------------
It was missing, and its absence was invisible. `build_registration()` returned a
dict that nothing stored -- verified 2026-08-24: exactly one `CREATE TABLE` existed
across the whole admin-approval backend (`admin_approval_requests`), no
authenticator table existed anywhere, and `build_registration` had no caller outside
its own test file.

The consequence was not a missing convenience. With nowhere to keep a registration:

  * `verify_approval()` (§7 step 4) had no source for the `authenticator` argument
    it requires, so nothing could ever verify;
  * `can_unlock()`'s two-device floor had no set of records to count;
  * the installer had nothing to bake into an agent's conf, so no agent could ever
    pin an admin key -- and agent-side verification is the whole of ADR 0026 §D3.

So the feature could not function at all, while reading as "backend landed" from a
module listing. Recorded here because the failure mode -- a plausible-looking set of
modules with no storage between them -- is not visible from any one file.

⚠ ADR 0001 -- DDL PLACEMENT. `SCHEMA` below is the ONE canonical `CREATE` for this
table anywhere in the repo. Nothing else may restate it. `dashboard.py` CALLS
`init_authenticator_tables()` at startup, alongside `init_admin_approval_tables()`,
for the measured PYTHONPATH reason documented at that call site -- a top-level
`from core...` in `alert_manager/database.py` breaks `nemesis-fw-watch`, whose
PYTHONPATH carries `/opt/nemesis/alert_manager` ONLY.

⚠ REVOCATION IS RECORDED, NEVER DELETED. `revoke()` sets a flag and a timestamp.
Deleting the row would destroy the evidence of which key approved past actions,
and every recorded approval attributes to an `authenticator_id` that must remain
resolvable afterwards. Readers that must not honour a revoked key filter on it --
`active()` here, and `enrollment.pinned_admin_authenticator()` on the agent, which
treats a revoked record as absent so revocation is not merely advisory.
"""

import json
import os
import sqlite3
import sys
import time

__all__ = ["SCHEMA", "init_authenticator_tables", "register", "get", "active",
           "all_records", "revoke", "update_sign_count", "export_for_installer",
           "AuthenticatorError"]


def _aap():
    """The protocol module, under whichever name this process has it.

    `core/admin_approval.py` is mirrored byte-for-byte into the agent payload as a
    FLAT `admin_approval`, so on the appliance it is importable both ways depending
    on how the caller set up `sys.path`. Resolved at call time rather than with a
    top-level `from core...`, which would break any process whose PYTHONPATH does
    not carry the repo root.
    """
    try:
        from core import admin_approval as m                       # noqa: PLC0415
        return m
    except Exception:                                              # noqa: BLE001
        import admin_approval as m                                 # noqa: PLC0415
        return m


class AuthenticatorError(ValueError):
    """A registration could not be stored or read back. Never a silent no-op."""


#: The ONE canonical DDL for this table (ADR 0001).
#:
#: `public_key` is TEXT holding the tagged-JSON encoding from
#: `admin_approval.tag_bytes` -- the SAME encoder the agent's pinned store and the
#: installer conf use, so one format crosses all three. A COSE key is a mapping
#: with INTEGER labels and byte values; neither survives plain JSON, and a
#: per-consumer encoder is precisely the drift that produces an agent which
#: silently pins nothing.
#:
#: `rp_id_hash` is a BLOB and stays raw: it is a fixed 32 bytes, has no structure to
#: encode, and the §7 step-7 binding check compares it as bytes.
SCHEMA = """
CREATE TABLE IF NOT EXISTS admin_approval_authenticators (
    authenticator_id TEXT PRIMARY KEY,      -- §4.1, addressed by approvals
    user_id          TEXT NOT NULL,         -- §7 step 4: ownership is checked
    mode             INTEGER NOT NULL,      -- 1 WEBAUTHN / 2 NATIVE (§3)
    cose_alg         INTEGER NOT NULL,      -- §2, by COSE id never library name
    public_key       TEXT NOT NULL,         -- tagged-JSON COSE_Key (see above)
    rp_id_hash       BLOB,                  -- 32 bytes, WEBAUTHN only
    sign_count       INTEGER NOT NULL DEFAULT 0,   -- §7 step 10, regression check
    registered_at    INTEGER NOT NULL,
    revoked          INTEGER NOT NULL DEFAULT 0,
    revoked_at       INTEGER,
    -- Multi-user-ready seam (CLAUDE.md): record WHO registered/revoked this, even
    -- though today there is one operator. Retrofitting attribution later means
    -- touching every write.
    created_by       TEXT,
    revoked_by       TEXT
)
"""


def init_authenticator_tables(conn=None):
    """Create the table. Idempotent; safe to call on every start."""
    owned = conn is None
    if owned:
        conn = _default_conn()
    try:
        conn.execute(SCHEMA)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_admin_auth_user "
                     "ON admin_approval_authenticators (user_id, revoked)")
        conn.commit()
    finally:
        if owned:
            conn.close()


def _default_conn():
    """Open the shared DB the way `init_admin_approval_tables` does.

    Same shape deliberately, rather than a second path-resolution scheme: the two
    tables live in one database and a divergence here would put them in two.
    """
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    amgr = os.path.join(here, "alert_manager")
    if amgr not in sys.path:
        sys.path.insert(0, amgr)
    import nemesis_paths                                           # noqa: PLC0415
    return sqlite3.connect(nemesis_paths.db_path(None), timeout=5.0)


def _row_to_record(row):
    """Rebuild the in-memory registration shape `verify_approval` expects.

    The COSE key comes back with INTEGER labels and byte coordinates -- the shape
    `cose_key_to_public()` needs. A record that decoded to string labels would fail
    later as an unexplained AAP-010, so decoding is strict and raises here.
    """
    aap = _aap()
    try:
        public_key = aap.untag_bytes(json.loads(row["public_key"]))
    except Exception as exc:                                       # noqa: BLE001
        raise AuthenticatorError(
            "stored public_key for %r is undecodable: %s"
            % (row["authenticator_id"], exc)) from exc
    return {
        "authenticator_id": row["authenticator_id"],
        "user_id": row["user_id"],
        "mode": row["mode"],
        "cose_alg": row["cose_alg"],
        "public_key": public_key,
        "rp_id_hash": row["rp_id_hash"],
        "sign_count": row["sign_count"],
        "registered_at": row["registered_at"],
        "revoked": bool(row["revoked"]),
        "revoked_at": row["revoked_at"],
        "created_by": row["created_by"],
    }


def register(conn, record, actor=None):
    """Persist a `build_registration()` record. Returns it as stored.

    REFUSES to overwrite an existing `authenticator_id`. Re-registering an id with
    different key material is how an attacker with a registration endpoint would
    replace the operator's phone with their own, and it is never a legitimate
    operation: adding a device uses a NEW id, replacing one is revoke-then-add.

    The record is re-validated through `build_registration` semantics before it is
    written -- key material that cannot be parsed must never reach the table, or the
    failure surfaces much later as an unexplained signature rejection.
    """
    aap = _aap()
    if not isinstance(record, dict):
        raise AuthenticatorError("record must be a registration mapping")
    for field in ("authenticator_id", "user_id", "mode", "cose_alg", "public_key"):
        if record.get(field) in (None, ""):
            raise AuthenticatorError("registration is missing %s" % field)
    if record["cose_alg"] not in aap.SUPPORTED_ALGS:
        raise AuthenticatorError("unsupported cose_alg %r" % (record["cose_alg"],))
    if record["mode"] == aap.MODE_WEBAUTHN:
        rp = record.get("rp_id_hash")
        if not isinstance(rp, bytes) or len(rp) != 32:
            raise AuthenticatorError(
                "a WEBAUTHN registration requires a 32-byte rp_id_hash")
    try:
        aap.cose_key_to_public(record["public_key"])
    except Exception as exc:                                       # noqa: BLE001
        raise AuthenticatorError("public_key is not usable: %s" % exc) from exc

    blob = json.dumps(aap.tag_bytes(record["public_key"]),
                      separators=(",", ":"), sort_keys=True)
    try:
        conn.execute(
            "INSERT INTO admin_approval_authenticators "
            "(authenticator_id, user_id, mode, cose_alg, public_key, rp_id_hash, "
            " sign_count, registered_at, revoked, created_by) "
            "VALUES (?,?,?,?,?,?,?,?,0,?)",
            (record["authenticator_id"], record["user_id"], int(record["mode"]),
             int(record["cose_alg"]), blob, record.get("rp_id_hash"),
             int(record.get("sign_count") or 0),
             int(record.get("registered_at") or time.time()), actor))
        conn.commit()
    except sqlite3.IntegrityError as exc:
        raise AuthenticatorError(
            "authenticator_id %r is already registered; adding a device uses a new "
            "id and replacing one is revoke-then-add"
            % (record["authenticator_id"],)) from exc
    return get(conn, record["authenticator_id"])


def get(conn, authenticator_id):
    """One registration by id, or None. Revoked records ARE returned -- callers
    that must not honour them use `active()`, and an attribution lookup for a past
    approval must still resolve a since-revoked key."""
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM admin_approval_authenticators "
                       "WHERE authenticator_id=?", (authenticator_id,)).fetchone()
    return _row_to_record(row) if row else None


def all_records(conn):
    """Every registration, revoked included. Ordered for reproducibility."""
    conn.row_factory = sqlite3.Row
    return [_row_to_record(r) for r in conn.execute(
        "SELECT * FROM admin_approval_authenticators ORDER BY authenticator_id")]


def active(conn, user_id=None):
    """Registered and NOT revoked -- optionally for one user.

    This is what `admin_approval_pairing.can_unlock()` counts against its
    two-device floor, and what the installer exports.
    """
    conn.row_factory = sqlite3.Row
    if user_id is None:
        rows = conn.execute(
            "SELECT * FROM admin_approval_authenticators WHERE revoked=0 "
            "ORDER BY authenticator_id")
    else:
        rows = conn.execute(
            "SELECT * FROM admin_approval_authenticators WHERE revoked=0 "
            "AND user_id=? ORDER BY authenticator_id", (user_id,))
    return [_row_to_record(r) for r in rows]


def revoke(conn, authenticator_id, actor=None, now=None):
    """Mark a registration revoked. True only if THIS call revoked it.

    ONE conditional UPDATE, so the check and the write are a single operation --
    same reasoning as the request store's `consume()`. A read-then-write would let
    two concurrent revocations both report success, which matters here because the
    return value is what an audit trail records as "who revoked it".

    False means "already revoked, or no such id" -- deliberately not an exception,
    because revoking an already-revoked device is a benign repeat, not an error.
    """
    now = int(now if now is not None else time.time())
    cur = conn.execute(
        "UPDATE admin_approval_authenticators SET revoked=1, revoked_at=?, "
        "revoked_by=? WHERE authenticator_id=? AND revoked=0",
        (now, actor, authenticator_id))
    conn.commit()
    return cur.rowcount == 1


def update_sign_count(conn, authenticator_id, new_count):
    """Advance the stored WebAuthn signature counter (§7 step 10).

    MONOTONIC: refuses to move the counter backwards or leave it unchanged. The
    counter exists to detect a CLONED authenticator, so accepting a non-increasing
    value would quietly disable the very check it serves -- and the natural
    implementation (`SET sign_count=?`) does exactly that.

    False means the update did not apply, which the caller must treat as a
    regression signal rather than a no-op.
    """
    cur = conn.execute(
        "UPDATE admin_approval_authenticators SET sign_count=? "
        "WHERE authenticator_id=? AND sign_count < ?",
        (int(new_count), authenticator_id, int(new_count)))
    conn.commit()
    return cur.rowcount == 1


def export_for_installer(conn, user_id=None):
    """The ACTIVE registrations, tagged-JSON encoded, for an installer conf.

    Returns a list ready for `json.dumps` -- the same tagged shape the agent's
    `enrollment.pin_admin_authenticators()` decodes, produced by the SAME encoder
    in `admin_approval`, so there is one format end to end rather than one per side.

    PUBLIC KEY MATERIAL ONLY. The admin private key lives on the operator's phone
    and the appliance never holds it (ADR 0026 §D3), so nothing here is secret --
    but `created_by`/`revoked_by` are operator identity and are deliberately NOT
    exported: the agent has no use for them and an installer conf is one careless
    paste from somewhere public (Rule 8).
    """
    aap = _aap()
    out = []
    for rec in active(conn, user_id=user_id):
        out.append(aap.tag_bytes({
            "authenticator_id": rec["authenticator_id"],
            "user_id": rec["user_id"],
            "mode": rec["mode"],
            "cose_alg": rec["cose_alg"],
            "public_key": rec["public_key"],
            "rp_id_hash": rec["rp_id_hash"],
            "sign_count": rec["sign_count"],
            "registered_at": rec["registered_at"],
            "revoked": False,
        }))
    return out
