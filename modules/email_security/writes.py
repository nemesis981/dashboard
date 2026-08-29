"""Every write this module makes, routed through the Data Manager (ADR 0006).

Build-spec stage 2.7. Stages 2.1-2.4 read and judge mail; this is the first code
that PERSISTS anything, and it is deliberately the only place that does -- one
file to audit when asking "what can this module change".

WHY A SEPARATE FILE, NOT MORE OF module.py
    Same reason imap_idle/mime_parse/fast_check are separate: one concern per
    file. It also makes the write surface enumerable by reading a single module,
    which matters more here than elsewhere because these tables hold verdicts
    about a person's private mail.

ADR 0006 -- NO RAW sqlite3, NO BARE get_db, EVER
    `modules_loader` statically REFUSES to load a module that imports raw sqlite3
    or calls a bare `get_db()`, before any of its code runs. Every write below
    goes through `get_data_manager()`, which access-checks against this module's
    namespace grant and appends an op-log row.

TWO DIFFERENT ACTORS, AND CONFLATING THEM LOSES ONE OF THEM
    The Data Manager stamps `current_actor()` onto the OP LOG automatically, for
    atomic-helper and raw passthrough writes alike (data_manager._log_op -- every
    write path funnels through it). That is the audit trail, and it is free.

    It is NOT the same as this module's own `created_actor` / `quarantine_actor`
    COLUMNS. Those are the multi-user-ready seam on our own rows, they live in
    our tables, and nothing populates them unless we do it explicitly -- which is
    exactly what the functions below do. Assuming the automatic op-log stamping
    covers them is how a seam column stays NULL forever while looking wired.

THE UPSERT DEFAULT WOULD SILENTLY UN-QUARANTINE A MESSAGE
    `DataManager.upsert` with `update` omitted sets EVERY non-conflict column to
    its excluded value. For `record_verdict` that is actively wrong: re-scanning
    a message whose verdict row already exists would reset `quarantine_state` to
    the incoming default and blank `quarantine_at`/`quarantine_actor` -- turning a
    quarantined message back into an ordinary one, in a table whose whole purpose
    is remembering that it was quarantined. Every upsert here therefore passes an
    EXPLICIT update list. Do not "simplify" them back to the default.
"""
from __future__ import annotations

from datetime import datetime

from modules import get_data_manager

#: Must match module.MODULE_NAME and the data_manager NAMESPACES key.
MODULE_NAME = "email_security"

#: Reachable states of the non-atomic Gmail quarantine sequence. Mirrors the
#: enumeration documented in database.init_email_security_tables(); kept here so
#: callers have a name to use instead of a bare string literal.
QUARANTINE_STATES = ("none", "copied", "flagged", "quarantined", "torn", "failed")


def _now() -> str:
    """Local ISO to seconds. Deliberately NOT utcnow() -- ADR 0004 settled on
    local ISO for stored timestamps, and the rest of the modules follow it."""
    return datetime.now().isoformat(timespec="seconds")


def add_account(address: str, imap_host: str, credential_ref: str, *,
                mailbox: str = "INBOX", provider: str = "gmail",
                imap_port: int = 993, enabled: bool = False) -> None:
    """Register (or re-register) one mailbox. Disabled unless asked otherwise.

    `credential_ref` NAMES a key in /etc/nemesis.env -- it is never the password
    itself. See init_email_security_tables()'s docstring for why the secret does
    not enter alerts.db.

    Defaults to `enabled=False` deliberately: adding a mailbox and beginning to
    read it are two different consents, and a row that starts watching on
    creation collapses them.

    On conflict (same address+mailbox) the CONNECTION settings update but
    `created_at`/`created_actor` do NOT -- "created" means created, and letting a
    re-registration rewrite them would quietly erase who first added the mailbox.
    """
    dm = get_data_manager()
    dm.upsert(
        MODULE_NAME, "email_accounts",
        {"address": address, "provider": provider, "imap_host": imap_host,
         "imap_port": imap_port, "mailbox": mailbox,
         "credential_ref": credential_ref, "enabled": 1 if enabled else 0,
         "created_at": _now(), "created_actor": dm.current_actor()},
        conflict_cols=("address", "mailbox"),
        # Explicit, and note what is ABSENT: created_at, created_actor.
        update=["provider", "imap_host", "imap_port", "credential_ref",
                "enabled"])


def set_account_enabled(address: str, enabled: bool, *,
                        mailbox: str = "INBOX") -> int:
    """Turn scanning on or off for one mailbox. Returns rows affected.

    Returns 0 when no such mailbox exists rather than creating one: enabling a
    mailbox that was never registered is a caller bug, and silently inventing the
    row would hide it behind a write that looks successful.
    """
    conn = get_data_manager().connect(MODULE_NAME)
    try:
        cur = conn.execute(
            "UPDATE email_accounts SET enabled=? WHERE address=? AND mailbox=?",
            (1 if enabled else 0, address, mailbox))
        # REQUIRED. GuardedConnection guards and op-logs the write but does NOT
        # commit -- only the atomic helpers (upsert/increment_counter) do. Without
        # this the UPDATE is discarded at close() while `cur.rowcount` still
        # reports 1, so the caller sees a successful write that never happened.
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def record_verdict(account_id: int, uidvalidity: int, uid: int, *,
                   verdict: str | None = None, confidence: float | None = None,
                   reason: str | None = None, signals_json: str | None = None,
                   message_id_hdr: str | None = None,
                   received_at: str | None = None,
                   auth_spf: str | None = None, auth_dkim: str | None = None,
                   auth_dmarc: str | None = None,
                   dmarc_policy: str | None = None,
                   auth_problems: str | None = None,
                   sender_hash: str | None = None) -> None:
    """Persist the scan result for ONE message. Re-scanning updates in place.

    `verdict` stays None when the message was scanned but not judged -- that is a
    real state (fast_check returns signals and auth facts and deliberately no
    verdict), and writing 'clean' to fill the gap would manufacture a judgement
    nothing made.

    `(account_id, uidvalidity, uid)` is the conflict key, matching the table's
    UNIQUE constraint. uidvalidity is part of it because a UID is only unique
    within one mailbox at one UIDVALIDITY -- see the DDL docstring.

    QUARANTINE COLUMNS ARE NOT IN THE UPDATE LIST. They are owned by
    set_quarantine_state() and must survive a re-scan; see this module's header.
    """
    get_data_manager().upsert(
        MODULE_NAME, "email_message_verdicts",
        {"account_id": account_id, "uidvalidity": uidvalidity, "uid": uid,
         "message_id_hdr": message_id_hdr, "received_at": received_at,
         "scanned_at": _now(), "verdict": verdict, "confidence": confidence,
         "reason": reason, "signals_json": signals_json,
         "auth_spf": auth_spf, "auth_dkim": auth_dkim, "auth_dmarc": auth_dmarc,
         "dmarc_policy": dmarc_policy, "auth_problems": auth_problems,
         # D4 recurrence token, NOT the address -- see sender_id.py. None is
         # a legitimate value (no salt / no parseable From) = UNKNOWN.
         "sender_hash": sender_hash},
        conflict_cols=("account_id", "uidvalidity", "uid"),
        # Explicit, and note what is ABSENT: quarantine_state, quarantine_at,
        # quarantine_actor. Omitting this list entirely would un-quarantine the
        # message on every re-scan.
        update=["message_id_hdr", "received_at", "scanned_at", "verdict",
                "confidence", "reason", "signals_json", "auth_spf",
                "auth_dkim", "auth_dmarc", "dmarc_policy", "auth_problems",
                "sender_hash"])


def create_enrollment_request(token_hash: str, owner_user_id: int, *,
                              created_by: int | None = None,
                              address_hint: str | None = None,
                              created_at: str | None = None,
                              expires_at: str) -> None:
    """Persist ONE enrollment request. ADR 0028 D11.5 Option C.

    `token_hash` ONLY -- the plaintext exists solely in the code handed to the
    owner. A readable token column would let anyone with DB access complete
    someone else's enrollment, the exact power Option C withholds from the admin.

    `created_by` is the ADMIN who initiated; `owner_user_id` is whose mailbox it
    is. Deliberately separate (D11.6). NULL created_by is pure self-service --
    a real state, not a missing value.
    """
    # The Data Manager exposes upsert / next_sequence / increment_counter as its
    # atomic helpers -- there is NO insert(). `token_hash` is UNIQUE, so upsert on
    # it is the correct primitive.
    dm = get_data_manager()
    dm.upsert(
        MODULE_NAME, "email_enrollment_requests",
        {"token_hash": token_hash, "owner_user_id": owner_user_id,
         "created_by": created_by, "address_hint": address_hint,
         "created_at": created_at or _now(), "expires_at": expires_at,
         "used_at": None, "account_id": None, "actor": dm.current_actor()},
        conflict_cols=("token_hash",),
        # update=None is the DOCUMENTED "DO NOTHING". A token-hash collision must
        # NEVER extend an existing request's expiry or reassign its owner -- that
        # would turn a collision into a live privilege transfer.
        update=None)


def consume_enrollment_request(token_hash: str, now_iso: str) -> bool:
    """ATOMICALLY consume one enrollment request. True only if THIS call won it.

    ⚠ THE ATOMICITY IS THE SECURITY PROPERTY, NOT A PERFORMANCE DETAIL.
    A read-then-write ("check says ok, so mark it used") has a window where two
    simultaneous requests both read `used_at IS NULL` and BOTH proceed -- a
    single-use token used twice, exactly what single-use exists to prevent. The
    check and the consume must be ONE statement.

    `rowcount == 1` means this caller consumed it; `0` means already used, expired
    or never existed. The caller cannot distinguish those and MUST NOT try -- see
    the identical-reject rule for unauthenticated routes.
    """
    dm = get_data_manager()
    conn = dm.connect(MODULE_NAME)
    try:
        # `with conn:` is sqlite3's TRANSACTION manager -- commits on success,
        # rolls back on exception. It does NOT close, hence the finally.
        with conn:
            cur = conn.execute(
                "UPDATE email_enrollment_requests "
                "   SET used_at = ?, actor = ? "
                " WHERE token_hash = ? "
                "   AND used_at IS NULL "
                "   AND expires_at > ?",
                (now_iso, dm.current_actor(), token_hash, now_iso))
            return cur.rowcount == 1
    finally:
        conn.close()


def set_quarantine_state(account_id: int, uidvalidity: int, uid: int,
                         state: str) -> int:
    """Record how far the non-atomic quarantine sequence actually got.

    Gmail has no MOVE, so quarantine is COPY -> \\Deleted -> EXPUNGE and can fail
    between any two steps. The caller records what COMPLETED, not what it
    intended -- 'torn' is a legitimate value and means the mailbox is
    known-inconsistent and needs reconciliation.

    Raises on an unknown state rather than storing it. A typo'd state would sit
    in the column looking like data and would never match any reconciliation
    query, so the row would be silently unreachable by the sweep meant to fix it.
    """
    if state not in QUARANTINE_STATES:
        raise ValueError("unknown quarantine state %r (expected one of %s)"
                         % (state, ", ".join(QUARANTINE_STATES)))
    dm = get_data_manager()
    conn = dm.connect(MODULE_NAME)
    try:
        cur = conn.execute(
            "UPDATE email_message_verdicts SET quarantine_state=?, "
            "quarantine_at=?, quarantine_actor=? "
            "WHERE account_id=? AND uidvalidity=? AND uid=?",
            (state, _now(), dm.current_actor(), account_id, uidvalidity, uid))
        # REQUIRED -- see set_account_enabled. A quarantine that reports success
        # and silently rolls back is the worst possible version of this bug: the
        # mailbox really was modified by the IMAP sequence, so the DB and the
        # mailbox would disagree about whether the message is quarantined.
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()
