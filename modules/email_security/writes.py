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


def get_account(address: str, mailbox: str = "INBOX"):
    """One mailbox row, or None. Read-only.

    Exists so an enrollment can refuse to TAKE OVER a mailbox that already
    belongs to someone else -- see the route that calls it. `add_account`'s
    upsert updates `credential_ref` and `enabled` in place, so without this check
    one code holder can repoint another household member's mailbox at their own
    credential slot and reset `enabled` to 0, silently stopping that person's
    mail being scanned.
    """
    conn = get_data_manager().connect(MODULE_NAME)
    try:
        cur = conn.execute(
            "SELECT id, address, mailbox, owner_user_id, credential_ref, enabled "
            "  FROM email_accounts WHERE address=? AND mailbox=?",
            (address, mailbox))
        row = cur.fetchone()
        if row is None:
            return None
        return dict(zip([d[0] for d in cur.description], row))
    finally:
        conn.close()


def add_account(address: str, imap_host: str, credential_ref: str, *,
                mailbox: str = "INBOX", provider: str = "gmail",
                imap_port: int = 993, enabled: bool = False,
                owner_user_id: int | None = None,
                tls_mode: str | None = None) -> None:
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
         # Recorded on the ROW so a self-hosted mailbox has a transport at all
         # (providers.get("custom") raises) and so a later provider-table edit
         # cannot silently downgrade an existing mailbox's TLS. NOT
         # allow_self_signed -- that stays a provider-table privilege and is
         # deliberately not settable from an enrollment. See
         # settings_resolve.for_account().
         "tls_mode": tls_mode,
         "credential_ref": credential_ref, "enabled": 1 if enabled else 0,
         "created_at": _now(), "created_actor": dm.current_actor(),
         # ⚠ WAS NEVER WRITTEN UNTIL 2026-08-31, and the enrollment route's own
         # docstring claimed otherwise. The helper returns the authoritative
         # owner from the consumed enrollment row precisely so it can be stored;
         # it was being used only in a log line, leaving this column uniformly
         # NULL while the code above it said the opposite. Harmless only while
         # nothing authorises on it -- and it would have become a privilege
         # boundary the moment any per-owner scoping was added on top of a column
         # that is always NULL, with the docstring still asserting it was set.
         "owner_user_id": owner_user_id},
        conflict_cols=("address", "mailbox"),
        # Explicit, and note what is ABSENT: created_at, created_actor.
        #
        # `owner_user_id` IS updatable, deliberately: a row predating this column
        # has NULL there, and a legitimate re-enrollment by its real owner should
        # populate it. Taking over a row owned by someone ELSE is prevented by
        # the caller (see get_account), not here -- this function has no way to
        # know whether the caller is authorised, and a guess either direction
        # would be wrong.
        # `tls_mode` IS updatable -- a re-enrollment that moves a mailbox to a
        # different transport must actually move it, or the row would keep a
        # stale mode and fail the handshake.
        #
        # `authserv_id` is deliberately ABSENT from both the values and this
        # list, and the two halves matter separately: absent from values means a
        # NEW row starts NULL, which resolves to an unmatchable sentinel and
        # trusts nothing (fail closed). Absent from the update list means an
        # admin's CONFIRMED anchor survives an ordinary re-enrollment, which is
        # right -- rotating an app password does not change who signs the
        # provider's Authentication-Results header. ⚠ Moving a mailbox to a
        # different PROVIDER is the case that invalidates it; clear it
        # explicitly with set_account_authserv_id(None) if that happens.
        update=["provider", "imap_host", "imap_port", "credential_ref",
                "enabled", "owner_user_id", "tls_mode"])


def set_account_authserv_id(address: str, authserv_id, *,
                            mailbox: str = "INBOX") -> int:
    """Record (or clear) the CONFIRMED Authentication-Results identity.

    THE ONLY WAY THIS VALUE IS EVER SET, and it is set from OBSERVATION, never
    derivation. The workflow it completes:

      1. A mailbox scans with an unconfirmed anchor, so fast_check finds a
         mismatch and refuses to read the header's verdicts.
      2. The mismatch is recorded as `authserv_id_mismatch:<the real id>` in
         email_message_verdicts.auth_problems -- that record exists precisely
         so the true value can be read off a real message.
      3. An admin reads it, confirms it belongs to the provider, and calls this.

    ⛔ DO NOT DERIVE THIS FROM THE ACCOUNT'S IMAP HOST. Considered and rejected
    2026-08-31: an IMAP hostname is guessable, and a self-hosted MTA that adds
    no Authentication-Results header of its own leaves the SENDER'S forged
    header topmost -- so a derived anchor would match the forgery and cause it
    to be trusted. The unconfirmed sentinel cannot be matched by any real
    header. "We do not know" must resolve to "trust nothing", not to a
    plausible guess.

    Passing None CLEARS it, returning the mailbox to the fail-closed default.
    """
    value = (authserv_id or "").strip() or None
    dm = get_data_manager()
    conn = dm.connect(MODULE_NAME)
    try:
        cur = conn.execute(
            "UPDATE email_accounts SET authserv_id = ? "
            " WHERE address = ? AND mailbox = ?", (value, address, mailbox))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def set_account_enabled(address: str, enabled: bool, *,
                        mailbox: str = "INBOX") -> int:
    """Turn scanning on or off for one mailbox. Returns rows affected.

    Returns 0 when no such mailbox exists rather than creating one: enabling a
    mailbox that was never registered is a caller bug, and silently inventing the
    row would hide it behind a write that looks successful.
    """
    dm = get_data_manager()
    conn = dm.connect(MODULE_NAME)
    try:
        # ⚠ THE ACTOR AND TIMESTAMP ARE WRITTEN HERE, NOT LEFT TO THE OP LOG.
        # The Data Manager's op log records module/table/operation/actor/rowcount
        # /ts and NO parameters -- so it can say "somebody updated email_accounts"
        # and never which mailbox or in which direction. For the decision to begin
        # or end reading a person's mail, that is precisely the question an audit
        # has to answer, which is why these are columns on the row itself. Same
        # reasoning as record_verdict's quarantine_actor.
        cur = conn.execute(
            "UPDATE email_accounts SET enabled=?, enabled_actor=?, enabled_at=? "
            " WHERE address=? AND mailbox=?",
            (1 if enabled else 0, dm.current_actor(), _now(), address, mailbox))
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


#: The autodiscovery columns on email_enrollment_requests, and the
#: DiscoveryResult attribute each is fed from.
_DISCOVERY_MAP = (
    ("disc_host", "imap_host"),
    ("disc_port", "imap_port"),
    ("disc_tls", "tls_mode"),
    ("disc_source", "source"),
    ("disc_provider", "provider_hint"),
)


def _discovery_columns(discovery) -> dict:
    """Flatten an autodiscover result into its stored columns.

    ⚠ A result that did NOT find settings stores its PROBLEMS but no host/port.
    That distinction is the whole point: "discovery ran and found nothing, for
    these reasons" and "discovery never ran" are different states, and an admin
    debugging a failed enrollment needs to tell them apart. Writing a host from
    a not-found result would be worse still -- `DiscoveryResult` leaves those
    None when `found` is False, but relying on that silently is exactly the
    shape this codebase distrusts, so `found` is checked explicitly here.
    """
    out = {c: None for c, _ in _DISCOVERY_MAP}
    out["disc_problems"] = None
    out["disc_at"] = None
    if not discovery:
        return out
    d = discovery if isinstance(discovery, dict) else discovery.to_dict()
    out["disc_at"] = _now()
    probs = d.get("problems") or []
    # Stored as a plain comma-joined string, not JSON: these are short
    # machine-generated tokens ("dns_NXDOMAIN", "ispdb_skipped"), the column is
    # read by humans debugging an enrollment, and a JSON blob for a flat list of
    # slugs is ceremony that makes it harder to read in a sqlite3 shell.
    out["disc_problems"] = ",".join(str(p) for p in probs) or None
    if not d.get("found"):
        return out
    for col, attr in _DISCOVERY_MAP:
        out[col] = d.get(attr)
    return out


def create_enrollment_request(token_hash: str, owner_user_id: int, *,
                              created_by: int | None = None,
                              address_hint: str | None = None,
                              created_at: str | None = None,
                              expires_at: str,
                              discovery: dict | None = None) -> None:
    """Persist ONE enrollment request. ADR 0028 D11.5 Option C.

    `token_hash` ONLY -- the plaintext exists solely in the code handed to the
    owner. A readable token column would let anyone with DB access complete
    someone else's enrollment, the exact power Option C withholds from the admin.

    `created_by` is the ADMIN who initiated; `owner_user_id` is whose mailbox it
    is. Deliberately separate (D11.6). NULL created_by is pure self-service --
    a real state, not a missing value.

    `discovery` is an OPTIONAL autodiscover result dict (see
    `_discovery_columns`). It is resolved by the CALLER, admin-side, because the
    owner-facing pages are unauthenticated and must never be able to trigger
    outbound lookups -- see the DDL comment in alert_manager/database.py. Passing
    None stores NULLs, which is a legitimate state: discovery genuinely fails for
    most custom domains.
    """
    # The Data Manager exposes upsert / next_sequence / increment_counter as its
    # atomic helpers -- there is NO insert(). `token_hash` is UNIQUE, so upsert on
    # it is the correct primitive.
    dm = get_data_manager()
    values = {"token_hash": token_hash, "owner_user_id": owner_user_id,
              "created_by": created_by, "address_hint": address_hint,
              "created_at": created_at or _now(), "expires_at": expires_at,
              "used_at": None, "account_id": None, "actor": dm.current_actor()}
    values.update(_discovery_columns(discovery))
    dm.upsert(
        MODULE_NAME, "email_enrollment_requests",
        values,
        conflict_cols=("token_hash",),
        # update=None is the DOCUMENTED "DO NOTHING". A token-hash collision must
        # NEVER extend an existing request's expiry or reassign its owner -- that
        # would turn a collision into a live privilege transfer.
        update=None)


def get_enrollment_request(token_hash: str):
    """Read ONE enrollment request by token hash, or None. NEVER consumes it.

    ⚠ THIS IS NOT AN ALTERNATIVE TO consume_enrollment_request AND MUST NOT BE
    USED AS ONE. It exists so the owner-facing page can decide whether to render
    the credential form for a code that has not been spent yet -- showing the
    walkthrough is not a state change, and spending the code merely to display a
    form would burn it for anyone who opens the link twice or abandons at the
    password step.

    THE AUTHORISATION IS STILL THE ATOMIC CONSUME, WHICH HAPPENS LATER AND
    ELSEWHERE. A check here followed by an action later is a check-then-act
    window by construction; that is acceptable ONLY because nothing is authorised
    on the strength of this read. The real single-use enforcement lives in the
    privileged helper's conditional UPDATE, where the predicates are in the WHERE
    clause and two simultaneous completions cannot both win.

    Pair with `enrollment.check_request(row, now)`, which is pure and classifies
    the row into OK / NOT_FOUND / EXPIRED / ALREADY_USED.
    """
    conn = get_data_manager().connect(MODULE_NAME)
    try:
        cur = conn.execute(
            "SELECT token_hash, owner_user_id, created_by, address_hint, "
            "       created_at, expires_at, used_at, account_id, "
            "       disc_host, disc_port, disc_tls, disc_source, "
            "       disc_provider, disc_problems, disc_at "
            "  FROM email_enrollment_requests WHERE token_hash = ?",
            (token_hash,))
        row = cur.fetchone()
        if row is None:
            return None
        cols = [d[0] for d in cur.description]
        return dict(zip(cols, row))
    finally:
        conn.close()


def allocate_credential_slot() -> int:
    """Atomically reserve the next `EMAIL_SEC_APPPW_<N>` slot. Returns N.

    ⚠ NOT `max(existing) + 1`, AND THE DIFFERENCE IS A REAL BUG, NOT A STYLE
    CHOICE. Two household members completing their enrollment links at the same
    moment would both read the same maximum, both pick the same slot, and the
    second write would SILENTLY OVERWRITE the first person's app password --
    leaving a mailbox whose stored credential belongs to somebody else's account.
    Nothing about that failure is visible at write time; it surfaces later as an
    unexplained auth failure on a mailbox nobody touched.

    `next_sequence` (ADR 0006) allocates with no read-modify-write window. It is
    the same primitive, for the same reason, as the `tickets_seq` v0 fix.

    Allocation is MONOTONIC AND SLOTS ARE NEVER REUSED. A slot freed by a removed
    mailbox stays retired rather than being handed to the next enrollment: reuse
    would let a stale entry left in the credential file be inherited by a
    different person's mailbox.

    The caller must convert this to a key with `credential_store.slot_ref()`,
    which enforces the same 0-999 range the privileged writer's regex allows.
    Exhausting the range raises there rather than producing a key the writer
    would refuse after the enrollment code has already been spent.
    """
    return get_data_manager().next_sequence(MODULE_NAME, "email_credential_seq")


# ⛔ THERE IS DELIBERATELY NO consume_enrollment_request() HERE. DO NOT ADD ONE.
#
# There was one until 2026-08-31, and by then it had ZERO production callers and
# had already DRIFTED from the copy that actually runs: it stamped
# `dm.current_actor()` where the live consume stamps the literal
# "token:email-enrollment". A future edit to this "documented" version would have
# changed nothing while looking like it had -- exactly the hazard
# `_merge_write_env_file`'s extraction comment argues against ("the copy is the
# hazard"), applied to a security control rather than a file write.
#
# THE ONE REAL CONSUME LIVES IN `nemesis_fwd.op_write_email_secret`, and it has
# to: the dashboard is modelled as potentially compromised, so the process that
# validates and spends the single-use code must NOT be the web process. A
# consume reachable from here would be a second, weaker path to the same
# authority. See ADR 0028 D11.5 Option C and that function's docstring for the
# atomicity argument, which is unchanged -- only its location is.


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
