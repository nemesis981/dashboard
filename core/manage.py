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
        print(f"Unlocked '{username}' (failed_attempts=0, lockout cleared).")
    else:
        print(f"No such user: {username}")
        sys.exit(1)


def main():
    args = sys.argv[1:]
    if not args:
        print(USAGE)
        sys.exit(1)
    cmd = args[0]
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
