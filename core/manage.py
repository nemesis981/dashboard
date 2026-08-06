#!/usr/bin/env python3
"""
Nemesis admin recovery CLI — the "SSH escape hatch".

Operates directly on the users table in the shared alerts.db. Usable over SSH
when locked out of the dashboard (e.g. from Wisconsin if auth misbehaves on the
remote box).

  python3 core/manage.py list-users
  python3 core/manage.py reset-password <username>
  python3 core/manage.py create-user <username> <display_name>
  python3 core/manage.py unlock <username>
"""

import os
import sys
import getpass
import sqlite3
from datetime import datetime

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "alert_manager"))

import bcrypt
import database                      # alert_manager/database.py (provides DB_PATH + init_users_table)
import nemesis_timestamp             # alert_manager/nemesis_timestamp.py (canonical audit_log.ts)
from core import passphrase

USAGE = """Nemesis admin recovery CLI

  python3 core/manage.py list-users
  python3 core/manage.py reset-password <username>
  python3 core/manage.py create-user <username> <display_name>
  python3 core/manage.py unlock <username>
"""


def _conn():
    # Reference database.DB_PATH dynamically so it stays correct (and testable).
    conn = sqlite3.connect(database.DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


def _hash(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def _actor() -> str:
    """Who ran this CLI, in a form that cannot be mistaken for a dashboard user.

    `audit_log.user` holds a DASHBOARD username in every row written so far —
    both the dashboard and nemesis-fwd record the identity they authenticated.
    This script authenticates nobody: it is gated on root, and the operating
    system has already decided who the caller is. Writing a bare system username
    into that column would put two namespaces in one field, so a system account
    sharing a name with a dashboard account would read as that dashboard user
    having done it.

    Hence the prefix — `cli:paul`, never `paul`. Same reasoning as
    database.record_auth_failure's 'local-socket' sentinel: deliberately
    distinguishable from what the other path writes into the same column.

    SUDO_USER names the human who ran `sudo`. A direct root shell leaves no such
    record, so that case is reported honestly as `cli:root` rather than guessed at.
    """
    return "cli:" + (os.environ.get("SUDO_USER") or "root")


def _audit(action: str, target: str):
    """Append ONE row to `audit_log` for a credential mutation. NEVER raises.

    WHY THIS EXISTS. Until now the three mutating commands in this file changed
    credentials and left no queryable record anywhere — the most privileged path
    in the system was the only unaudited one, while the dashboard's far less
    privileged actions (`password_change`, `recovery_codes_generated`) have been
    audited all along. Confirmed live 2026-07-31, when the operator's own lockout
    recoveries left no trail behind them.

    BEST-EFFORT, AFTER THE FACT, and deliberately so. This is the documented SSH
    escape hatch — the path used precisely when the dashboard is unreachable. If
    the audit insert fails the operator must still end up unlocked, so the
    credential change commits FIRST and a failure here costs evidence rather than
    the recovery itself. Same stance and same reasoning as
    database.record_auth_failure. It is not silent, though: the failure prints,
    because this is an interactive CLI and a lost audit row on the recovery path
    is worth seeing at the moment it happens.

    COLUMN CHOICES, so they are not later read as arbitrary:
      ts       `datetime.now().isoformat()` — matches dashboard `_audit()`, the
               writer this most resembles (an account action, same family as
               `password_change`). Local time, like every other auth-adjacent
               table. NOTE: `audit_log` already holds two ts FORMATS from its two
               existing writers; this deliberately adds no third.
      action   prefixed `cli_` so the escape hatch stays distinguishable from the
               same action taken through the dashboard. They are not equivalent
               events and must never aggregate as one.
      rule_id  the TARGET username. The table has no dedicated target column, and
               the dashboard already uses rule_id this way for non-alert actions
               (`agent_approve` writes a device_id). Distinct from the nemesis_fwd
               mistake the DDL comment records — that put a request_id here, a
               value which has its own column.
      ip       NULL. In this table `ip` is the TARGET ADDRESS of a firewall
               action, not the client's; a credential change has no address.
      user     see _actor().

    Raw sqlite3, like the rest of this file: init_audit_log_table() is documented
    as running on a raw connection precisely so any process may call it with no
    Data Manager grant. This CLI is not a loaded module, so the modules_loader
    restriction does not apply to it.
    """
    try:
        database.init_audit_log_table()
        conn = sqlite3.connect(database.DB_PATH, timeout=5.0)
        try:
            conn.execute(
                "INSERT INTO audit_log (ts, rule_id, ip, action, user) VALUES (?,?,?,?,?)",
                (nemesis_timestamp.now(), target, None, action, _actor()),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"WARNING: audit_log write failed for {action}/{target}: {e}", file=sys.stderr)
        print("         The credential change itself SUCCEEDED — only its audit "
              "record was lost.", file=sys.stderr)


def list_users():
    database.init_users_table()
    rows = _conn().execute(
        "SELECT username, display_name, role, last_login, is_active FROM users ORDER BY id"
    ).fetchall()
    if not rows:
        print("(no users)")
        return
    print(f"  {'USERNAME':20s} {'DISPLAY NAME':24s} {'ROLE':8s} {'ACTIVE':7s} LAST LOGIN")
    for r in rows:
        print(f"  {r['username']:20s} {r['display_name']:24s} {r['role']:8s} "
              f"{('yes' if r['is_active'] else 'no'):7s} {r['last_login'] or '-'}")


def _choose_password() -> str:
    suggested = passphrase.generate()
    print(f"Suggested passphrase: {suggested}")
    try:
        pw = getpass.getpass("New password (blank = use the suggested): ")
    except (EOFError, KeyboardInterrupt):
        pw = ""
    if not pw:
        return suggested
    pw = pw.strip()          # same normalisation the dashboard applies on set
    ok, reason = passphrase.validate(pw)
    if not ok:
        print(f"Weak password: {reason}")
        sys.exit(1)
    return pw


def reset_password(username: str):
    database.init_users_table()
    conn = _conn()
    row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        print(f"No such user: {username}")
        sys.exit(1)
    pw = _choose_password()
    # password_changed_at moves WITH the hash. This is the documented lockout
    # recovery path: without the stamp, an operator who resets here would still
    # carry the OLD change date, and the 30-day expiry check would declare the
    # password they just set already expired — the recovery path failing at
    # exactly the moment it is needed.
    now = datetime.now().isoformat(timespec="seconds")
    conn.execute(
        "UPDATE users SET password_hash=?, password_changed_at=?, failed_attempts=0, "
        "lockout_until=NULL, lockout_tier=0 WHERE id=?",
        (_hash(pw), now, row["id"]),
    )
    conn.commit()
    _audit("cli_reset_password", username)
    print(f"Password reset for '{username}'. Lockout cleared. You can now log in with the new password.")


def create_user(username: str, display_name: str):
    database.init_users_table()
    conn = _conn()
    if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        print(f"User already exists: {username}")
        sys.exit(1)
    pw = passphrase.generate()
    now = datetime.now().isoformat(timespec="seconds")
    # Stamped at creation, not left NULL — the expiry check reads NULL as
    # "due for a change", which would mark a brand-new account expired on sight.
    # Same fix as dashboard._create_user().
    conn.execute(
        "INSERT INTO users(username, display_name, password_hash, role, is_active, "
        "created_at, password_changed_at) VALUES(?,?,?,?,1,?,?)",
        (username, display_name, _hash(pw), "admin", now, now),
    )
    conn.commit()
    _audit("cli_create_user", username)
    print(f"Created user '{username}' ({display_name}), role=admin.")
    print(f"  Passphrase: {pw}")
    print("  Save this now — it is stored only as a bcrypt hash, never in plaintext.")


def unlock(username: str):
    database.init_users_table()
    conn = _conn()
    cur = conn.execute(
        "UPDATE users SET failed_attempts=0, lockout_until=NULL, lockout_tier=0 WHERE username=?", (username,)
    )
    conn.commit()
    if cur.rowcount:
        # Inside the rowcount branch on purpose: `unlock` on a nonexistent user
        # changes nothing, and an audit row for a no-op would be a false record
        # of a credential action that never occurred.
        _audit("cli_unlock", username)
        print(f"Unlocked '{username}' (failed_attempts=0, lockout cleared).")
    else:
        print(f"No such user: {username}")
        sys.exit(1)


_MUTATING = {"reset-password", "create-user", "unlock"}


def _require_root(cmd):
    """Mutating commands are root-only. Read-only ones are not.

    WHAT THIS IS: the documented last-resort recovery path, held to the same bar
    as ADR 0019's console-recovery precedent. Root already implies total control
    of this machine, so requiring it grants an attacker nothing they did not
    already have, while removing the casual path in which anyone who happens to
    be able to reach the database file can silently take over the admin account.

    WHAT THIS IS NOT: a security boundary against a compromised dashboard. The
    dashboard runs as `nemesis-dash`, whose PRIMARY group is `nemesis-db`, and
    `alerts.db` is group-writable — so that process can rewrite `users` directly
    with plain SQL and never touch this script. Closing THAT would mean moving
    credential writes behind `nemesis-fwd` (or off this database entirely), which
    is real architectural work, not a guard clause. Stating it here so this check
    is not later mistaken for the thing that makes the admin account safe from an
    application compromise. It does not.
    """
    if os.geteuid() != 0:
        print(f"'{cmd}' changes account credentials and must be run as root:\n"
              f"  sudo python3 /opt/nemesis/core/manage.py {cmd} ...")
        sys.exit(1)


def main():
    args = sys.argv[1:]
    if not args:
        print(USAGE)
        sys.exit(1)
    cmd = args[0]
    if cmd in _MUTATING:
        _require_root(cmd)
    if cmd == "list-users" and len(args) == 1:
        list_users()
    elif cmd == "reset-password" and len(args) == 2:
        reset_password(args[1])
    elif cmd == "create-user" and len(args) == 3:
        create_user(args[1], args[2])
    elif cmd == "unlock" and len(args) == 2:
        unlock(args[1])
    else:
        print(USAGE)
        sys.exit(1)


if __name__ == "__main__":
    main()
