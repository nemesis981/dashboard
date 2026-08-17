"""Licence backup codes -- 5 one-time codes that rebind a licence to new hardware.

Issued at install. Redeemed when the install id no longer matches (reinstall,
disk swap, machine migration) to obtain a fresh licence key for the new hardware.

── THIS IS A PORT OF `recovery_codes`, NOT A NEW DESIGN ────────────────────
`dashboard.py`'s account-recovery codes already solve one-time codes properly and
have been live in production. Everything load-bearing is carried over verbatim in
shape: bcrypt at rest, batch model with supersede, supersede-then-insert in ONE
transaction, atomic single spend, corrupt-hash tolerance, a remaining() counter.

── ...BUT A SEPARATE TABLE, DELIBERATELY ───────────────────────────────────
`recovery_codes` authenticates a HUMAN into an account. These authorise an
INSTALL to move its licence. Sharing one table would let an account-recovery code
rebind a licence and a licence code unlock an account -- two different trust
domains joined by an implementation detail. Copy the pattern; keep the rows apart.

── WHAT HAPPENS WHEN ALL 5 ARE SPENT (operator decision, 2026-08-17) ───────
**Contact support for manual identity verification.** This is the DEFINED answer,
not an open question, and it is deliberately NOT self-serve: after five
rebindings an automated sixth is indistinguishable from licence sharing, so a
human check is the correct control.

It is a documented support process rather than code, so nothing here implements
it -- but `remaining() == 0` is a real, reachable state and `exhaustion_notice()`
exists so the product can NAME the route at the moment of failure. A user who
cannot tell whether they are stuck or merely inconvenienced will assume stuck.

── LOW-WATER WARNING AT 2 (operator decision, 2026-08-17) ──────────────────
Warn at 2 remaining, not only at 0. One comparison, and it converts a hard stop
into a scheduled task.
"""

import os
import secrets
import sqlite3
from datetime import datetime

__all__ = ["generate_batch", "remaining", "consume", "status",
           "BATCH_SIZE", "LOW_WATER", "exhaustion_notice", "BackupCodeError"]

#: Operator decision 2026-08-17: FIVE codes, not two.
BATCH_SIZE = 5

#: Warn the operator at this many remaining. Operator decision 2026-08-17.
LOW_WATER = 2

#: Same alphabet/shape as account recovery codes: 16 chars from 31 symbols
#: (~79 bits), grouped for transcription. Ambiguous glyphs are already excluded
#: upstream -- reproduced here rather than imported, because importing from
#: dashboard.py would drag a Flask app into a module that must be usable from a
#: CLI and from tests.
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_GROUPS = 4
_GROUP_LEN = 4


class BackupCodeError(RuntimeError):
    pass


def _db_path():
    import nemesis_paths
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return nemesis_paths.db_path(os.path.join(here, "alert_manager", "alerts.db"))


def _conn(path=None):
    c = sqlite3.connect(path or _db_path(), timeout=5.0)
    c.execute("PRAGMA busy_timeout=5000")
    return c


def _generate_code():
    pick = "".join(secrets.choice(_ALPHABET) for _ in range(_GROUPS * _GROUP_LEN))
    return "-".join(pick[i:i + _GROUP_LEN] for i in range(0, len(pick), _GROUP_LEN))


def _storage_form(code):
    """Normalise before hashing/comparing: case and grouping are cosmetic.

    A user retyping a code from paper will get the dashes and the case wrong, and
    neither carries information. Normalising here means the hash is over the
    canonical form, so 'abcd efgh' and 'ABCD-EFGH' compare equal.
    """
    if not code:
        return b""
    return "".join(str(code).split()).replace("-", "").upper().encode()


def generate_batch(install_id="", actor=None, db_path=None):
    """Issue a fresh batch of BATCH_SIZE codes. Returns the plaintext codes.

    They are returned ONCE and never recoverable afterwards -- only bcrypt hashes
    are stored.

    Supersede-then-insert runs in ONE transaction, carried over from the account
    recovery implementation along with its reasoning: if the supersede committed
    and the insert then failed, the operator would be left with ZERO valid codes
    and no warning -- strictly worse than the batch being replaced. Either the
    swap happens whole, or the previous batch stays live.
    """
    import bcrypt
    codes = [_generate_code() for _ in range(BATCH_SIZE)]
    now = datetime.now().isoformat(timespec="seconds")
    batch_id = secrets.token_hex(8)
    # Hashing is ~1.6s for a batch; done BEFORE the transaction opens so the
    # write lock is held for as short a time as possible.
    hashes = [bcrypt.hashpw(_storage_form(c), bcrypt.gensalt()).decode()
              for c in codes]
    conn = _conn(db_path)
    try:
        with conn:
            conn.execute(
                "UPDATE license_backup_codes SET superseded_at=? "
                "WHERE used_at IS NULL AND superseded_at IS NULL", (now,))
            conn.executemany(
                "INSERT INTO license_backup_codes"
                "(code_hash, batch_id, install_id, created_at, created_actor) "
                "VALUES(?,?,?,?,?)",
                [(h, batch_id, install_id, now, actor) for h in hashes])
    finally:
        conn.close()
    return codes


def remaining(db_path=None):
    """How many codes are live. A code is live only while unused and unsuperseded."""
    conn = _conn(db_path)
    try:
        return conn.execute(
            "SELECT count(*) FROM license_backup_codes "
            "WHERE used_at IS NULL AND superseded_at IS NULL").fetchone()[0]
    finally:
        conn.close()


def consume(submitted, new_install_id="", ip=None, db_path=None):
    """Verify and SPEND one code. True only if it was live and now is not.

    The UPDATE re-asserts the validity predicate and success is decided by
    `rowcount == 1`, so two simultaneous redemptions of the same code cannot both
    win. Checking-then-updating would leave exactly that race on the one path
    where a double-spend hands out two licences.
    """
    import bcrypt
    normalized = _storage_form(submitted)
    if not normalized:
        return False
    spent = False
    conn = _conn(db_path)
    try:
        rows = conn.execute(
            "SELECT id, code_hash FROM license_backup_codes "
            "WHERE used_at IS NULL AND superseded_at IS NULL ORDER BY id").fetchall()
        for row_id, code_hash in rows:
            try:
                if not bcrypt.checkpw(normalized, str(code_hash).encode()):
                    continue
            except (ValueError, TypeError):
                # A corrupt hash must not crash the rebinding path -- that path
                # runs when the licence is ALREADY broken.
                continue
            cur = conn.execute(
                "UPDATE license_backup_codes SET used_at=?, used_ip=?, "
                "used_for_install=? WHERE id=? "
                "  AND used_at IS NULL AND superseded_at IS NULL",
                (datetime.now().isoformat(timespec="seconds"), ip,
                 new_install_id, row_id))
            conn.commit()
            spent = cur.rowcount == 1
            break
    finally:
        conn.close()
    return spent


def exhaustion_notice():
    """The message shown when codes run out. The support route, named explicitly."""
    return ("All licence backup codes have been used. To move this licence to "
            "new hardware, contact support to verify your identity manually. "
            "Your existing installation keeps working with local protection "
            "unchanged in the meantime.")


def ever_issued(db_path=None):
    """Has ANY batch ever been issued, in any state (used or superseded)?

    The distinction between "never issued" and "all spent" cannot be made from
    the live count alone -- both are zero -- and they mean opposite things to the
    operator. One is "you have not set this up yet"; the other is "you are out of
    recovery options, call support".
    """
    conn = _conn(db_path)
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM license_backup_codes").fetchone()[0] > 0
    finally:
        conn.close()


def status(db_path=None):
    """(remaining, level, message) for the UI. Never a bare number.

    Levels: 'none_issued' | 'ok' | 'low' | 'exhausted'.

    ⚠ `none_issued` is NOT cosmetic. Before it existed, a fresh install reported
    "All licence backup codes have been used -- contact support", because zero
    live codes was assumed to mean zero REMAINING. Nobody had used anything; none
    had ever been issued. That is the standing absent-vs-zero conflation in
    user-facing form, and it told a new operator their recovery options were
    exhausted before they had set any up.
    """
    n = remaining(db_path)
    if n == 0 and not ever_issued(db_path):
        return (0, "none_issued",
                "No backup codes have been issued yet. Issue a set now and store "
                "them somewhere safe — each one lets you move this licence to new "
                "hardware once, after a reinstall or a hardware change.")
    if n == 0:
        return n, "exhausted", exhaustion_notice()
    if n <= LOW_WATER:
        return (n, "low",
                "Only %d licence backup code%s left. Each one lets you move this "
                "licence to new hardware once. When they run out, moving it "
                "requires contacting support to verify your identity."
                % (n, "" if n == 1 else "s"))
    return n, "ok", "%d licence backup codes remaining." % n
