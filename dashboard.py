from flask import Flask, jsonify, request, redirect, url_for, render_template, session, abort, Response
import requests
import subprocess
import sqlite3
import json
import shlex
import html
import os
import re
import sys
import time
import secrets
from urllib.parse import urlparse
import logging
import threading
import tarfile
import shutil
import socket
import ipaddress
import uuid as _uuid_mod
from datetime import datetime, timedelta

# Root logger configuration. UNRELATED to the Data Manager work below — this
# restores visibility that was already coded and silently discarded.
#
# Without this the root logger has NO handlers, so Python falls back to
# `logging.lastResort`, which is fixed at WARNING. Every log.info() in this file
# was therefore written, formatted, and thrown away — and the warnings and
# .exception() tracebacks that did survive arrived unformatted, with no level and
# no logger name, because lastResort applies no formatter. Confirmed by the
# error-code audit, 2026-07-29.
#
# No timestamp in the format on purpose: systemd's journal stamps every line, and
# a second timestamp inside the message is noise. Called before Flask serves
# anything so werkzeug finds a root handler already present and does not attach
# its own — otherwise every HTTP request line would be logged twice.
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(name)s: %(message)s",
)

log = logging.getLogger(__name__)

_suricata_cache = {"ts": 0.0, "lines": []}
_SURICATA_CACHE_TTL = 5.0

_alert_24h_cache = {"ts": 0.0, "data": None}
_ALERT_24H_CACHE_TTL = 60.0
_alert_counts_cache = {"ts": 0.0, "data": None, "date": None}
_ALERT_COUNTS_CACHE_TTL = 60.0
_svc_cache = {"ts": 0.0, "data": None}
_SVC_CACHE_TTL = 30.0
_vpn_cache = {"ts": 0.0, "data": None}
_VPN_CACHE_TTL = 30.0
_drilldown_cache = {"ts": 0.0, "data": None, "date": None}
_DRILLDOWN_CACHE_TTL = 30.0

# External OS / third-party services Nemesis depends on but does NOT own: they
# ship no repo `.service` unit and never will (OS packages), so they stay an
# explicit list. This is the external-dependency set, NOT a duplicate registry
# of Nemesis units — those are discovered from their unit files below.
EXTERNAL_HEALTH_SERVICES = ["pihole-FTL", "clamav-daemon", "suricata"]


def _discover_health_services():
    """Build the health-check target list: external OS deps + auto-discovered
    Nemesis units. Nemesis units are discovered by scanning the repo's
    `*.service` unit files under alert_manager/ and core/ (the same files
    install.sh deploys), so a newly-added unit is health-checked the moment it
    exists — no hand-maintained list to drift out of sync. (ADR 0001 Stage 5.)
    """
    here = os.path.dirname(os.path.abspath(__file__))
    discovered = set()
    for sub in ("alert_manager", "core"):
        unit_dir = os.path.join(here, sub)
        try:
            for fname in os.listdir(unit_dir):
                if fname.endswith(".service"):
                    discovered.add(fname[:-len(".service")])
        except FileNotFoundError:
            continue
    return list(EXTERNAL_HEALTH_SERVICES) + sorted(discovered)


HEALTH_SERVICES = _discover_health_services()

_HERE = os.path.dirname(os.path.abspath(__file__))
WATCHDOG_LOG_PATH = os.path.join(_HERE, "alert_manager", "watchdog.log")
# "HW alert sent: KEY (breach message)"  — breach present
_HW_ALERT_SENT_RE   = re.compile(r"HW alert sent: (\S+) \((.+)\)")
# "HW alert email failed: KEY (...)"     — no breach, key only
_HW_ALERT_FAILED_RE = re.compile(r"HW alert email failed: (\S+)")
_SVC_ALERT_RE = re.compile(r"(?:Sent|Failed to send) alert email for (\S+)")
_FAST_LOG_RULE_RE = re.compile(r'\[1:(\d+):\d+\] (.+?) \[\*\*\]')
_FAST_LOG_CLASS_RE = re.compile(r'\[Classification: ([^\]]+)\]')

sys.path.insert(0, os.path.join(_HERE, "alert_manager"))
import database          # module handle: canonical DDL owner (init_audit_log_table)
from database import (init_db as init_alerts_db, init_quarantines_table,
                      init_devices_table, init_users_table, init_login_events_table,
                      init_enrollment_tokens_table, init_recovery_codes_table,
                      init_settings_table)
from ip_enrichment import enrich_ip
import tailscale_api
from firewall import (parse_alert, ufw_delete, ufw_deny_append,
                      FirewallError, FirewallDenied, FirewallUnavailable)
import hw_monitor
import modules_loader
import diagnostics as _diag
import email_utils

import bcrypt
import psutil
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from core import entitlements, passphrase

init_alerts_db()
hw_monitor.init_db()
init_users_table()
init_login_events_table()
init_recovery_codes_table()
init_enrollment_tokens_table()
# Self-heal the core `devices` table (LAN-scan inventory) before any unguarded
# device reads in the routes. Canonical DDL in database.init_devices_table();
# also created create-before-write by the device_scanner. Dual-safety-net,
# mirroring quarantines — no systemd ordering between the two processes.
init_devices_table()
# Core key/value settings (general-purpose, ADR 0001 core-owned). Canonical DDL
# in database.init_settings_table(). Created before any route reads it.
init_settings_table()

app = Flask(__name__)

PIHOLE_IP = os.environ.get("PIHOLE_IP", "127.0.0.1:8080")
PIHOLE_PASSWORD = os.environ.get("PIHOLE_PASSWORD", "")
sys.path.insert(0, os.path.join(_HERE, "alert_manager"))
import nemesis_paths  # noqa: E402
import data_manager  # noqa: E402

# HANDOFF §9 phase 1: register dashboard's namespace mode before anything can
# open a guarded connection. WARN, not ENFORCE — the 40 direct sqlite3 sites are
# migrating one at a time, and seven of the eleven tables dashboard writes are
# owned by another namespace pending an ownership decision. WARN runs the full
# check and logs `WOULD DENY` without blocking the write, so neither the
# migration nor the ownership evidence can take production down. Do not flip this
# to ENFORCE until every site is migrated AND the seven are resolved.
#
# THIS LINE'S POSITION IS LOAD-BEARING — keep it immediately after
# `import data_manager`, above every DM connection in the process.
# `namespace_mode()` returns MODE_ENFORCE for any module it has not been told
# about (data_manager.py: `_MODES.get(module, MODE_ENFORCE)`), so a guarded
# connection opened before this call runs is an ENFORCING one. In that window a
# dashboard write to any of the seven conflicted tables raises AccessDenied and
# FAILS, instead of logging WOULD DENY and succeeding. Moving this below any
# `connect()`, wrapping it in a conditional, or importing this module from
# something that skips it converts a warning into an outage.
data_manager.set_namespace_mode("dashboard", data_manager.MODE_WARN)

DB_PATH = nemesis_paths.db_path(os.path.join(_HERE, "alert_manager", "alerts.db"))

_DM = None


def _dm():
    """Lazy DataManager for dashboard's own access. Mirrors nemesis_fwd's `_dm()`.

    Deliberately a dedicated instance rather than `modules.get_data_manager()`:
    that one only exists after `modules_loader.init()` has run, and dashboard has
    DB call sites that must work regardless of module-loading state. Neither
    instance holds a persistent connection, so having both is free.
    """
    global _DM
    if _DM is None:
        _DM = data_manager.DataManager(DB_PATH)
    return _DM


def _dm_conn():
    """Guarded replacement for `sqlite3.connect(DB_PATH, timeout=5.0)`.

    Reads pass straight through the guard and return the same raw cursor, so
    `SELECT *`, positional row access, joins and `fetchall()` all behave exactly
    as before. Writes are access-checked and logged — WARN mode today, so nothing
    is denied yet.

    `row_factory = None` is the load-bearing line. `DataManager.connect()` sets
    `row_factory = sqlite3.Row` unconditionally, which would silently change every
    migrated read from returning tuples to returning Rows. Measured consequence:
    positional access and unpacking still work, but `json.dumps(row)` raises
    `TypeError: Object of type Row is not JSON serializable` and
    `isinstance(row, tuple)` flips to False — and 14 dashboard functions both
    fetch rows and serialise them. Resetting it here keeps this swap a true
    drop-in, so a de-privileging migration cannot change response payloads.
    Sites that genuinely want Row (e.g. `_users_conn`) set it themselves, after.

    NOT a context manager, and it does NOT auto-close: `GuardedConnection`
    delegates `__enter__`/`__exit__` to sqlite3's TRANSACTION context manager,
    exactly like a raw connection, so every existing `close()` / try-finally stays
    correct unchanged. (Assuming otherwise is what produced the nemesis_fwd fd
    leak — see its `_db()`.)
    """
    conn = _dm().connect("dashboard")
    conn.row_factory = None
    return conn
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")
MODULES_DIR = os.path.join(_HERE, "modules")
# State, not code — so it belongs in DATA_DIR, not the tree. It was written to
# _HERE, which worked only because the service ran as an account that owned the
# repo. nemesis-dash does not, and ProtectSystem=strict makes /opt read-only to
# the service regardless, so a schedule save would fail on both counts.
_BACKUP_CFG_PATH = os.path.join(nemesis_paths.data_dir(), "backup_config.json")

# ── Authentication (Flask-Login) ──────────────────────────────────────────────
auth_log = logging.getLogger("nemesis.auth")
# Sessions need a STABLE secret key — persist one outside the repo (0600,
# gitignored) so a restart doesn't invalidate everyone's session.
# Lives in the DATA directory, not the code tree. Under ProtectSystem=strict
# /opt/nemesis is read-only, so a missing secret here could be read but never
# regenerated — turning a self-healing case into an unrecoverable startup
# failure exactly when the file is absent. Falls back to the legacy in-tree
# path if that is where it already lives, so this is safe pre- and post-move.
#
# RESOLVED THROUGH data_dir(), NOT THE DATA_DIR CONSTANT — same for
# _BACKUP_CFG_PATH above, and the two are deliberately kept identical.
#
# DATA_DIR is the hardcoded string "/var/lib/nemesis". data_dir() is
# dirname(db_path()), so it honours $NEMESIS_DB_PATH — the one knob that relocates
# Nemesis state. Using the constant meant these two files did NOT follow the
# database when it moved: a harness pointing NEMESIS_DB_PATH at a scratch
# directory got a scratch database but reached for the REAL /var/lib/nemesis for
# its secret key and backup config, so a test could read (or create, or chmod)
# production state while believing it was fully isolated.
#
# A NO-OP ON THIS BOX, AND THAT IS THE POINT. dashboard.service sets
# NEMESIS_DB_PATH=/var/lib/nemesis/alerts.db, so both expressions resolve
# identically here and the running system sees no change — which is exactly why
# the divergence survived unnoticed. It only bites off the default path.
_LEGACY_SECRET_PATH = os.path.join(_HERE, "alert_manager", ".flask_secret")
_SECRET_KEY_PATH = os.path.join(nemesis_paths.data_dir(), ".flask_secret")
if not os.path.exists(_SECRET_KEY_PATH) and os.path.exists(_LEGACY_SECRET_PATH):
    _SECRET_KEY_PATH = _LEGACY_SECRET_PATH


def _load_secret_key() -> str:
    try:
        with open(_SECRET_KEY_PATH) as f:
            data = f.read().strip()
            if data:
                return data
    except FileNotFoundError:
        pass
    key = os.urandom(32).hex()
    try:
        with open(_SECRET_KEY_PATH, "w") as f:
            f.write(key)
        os.chmod(_SECRET_KEY_PATH, 0o600)
    except Exception:
        auth_log.warning("auth: could not persist secret key to %s", _SECRET_KEY_PATH)
    return key


app.secret_key = _load_secret_key()

# Session cookie posture, stated explicitly rather than inherited.
#
# SAMESITE="Lax" is the one that matters. Several state-changing endpoints are
# POST-only, but POST alone does not stop a cross-origin form submission — the
# browser would still attach the session cookie. Lax withholds it on cross-site
# POSTs, so a forged request arrives unauthenticated and is rejected by the
# normal auth gate. Modern browsers default to Lax already; setting it here
# means the protection is a property of this application rather than of whatever
# the visitor's browser happens to default to.
#
# HTTPONLY=True is Flask's default too — pinned so it cannot be silently lost.
#
# SECURE is deliberately NOT set. This dashboard is served over plain HTTP on
# the LAN (nginx :80, no TLS configured), and Secure=True would stop the browser
# sending the cookie at all — every login would appear to succeed and then bounce
# straight back to the login page. It becomes correct the moment TLS is in front
# of this, and should be set THEN, not now.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access Nemesis."


def _users_conn():
    # HANDOFF §9 phase 1 (was sqlite3.connect(DB_PATH, timeout=5.0)). This site
    # wants Row and sets it itself, after _dm_conn() has reset it — unchanged
    # behaviour, and it stays correct if _dm_conn's default ever changes.
    conn = _dm_conn()
    conn.row_factory = sqlite3.Row
    return conn


def _load_user_row(field: str, value) -> "sqlite3.Row | None":
    # field is an internal literal ('id' / 'username'), never user input.
    try:
        conn = _users_conn()
        row = conn.execute(f"SELECT * FROM users WHERE {field}=?", (value,)).fetchone()
        conn.close()
        return row
    except Exception:
        auth_log.exception("auth: user load failed")
        return None


def _user_count() -> int:
    try:
        conn = _users_conn()
        n = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        conn.close()
        return int(n)
    except Exception:
        return 0


class User(UserMixin):
    """A dashboard user loaded from the core `users` table."""
    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]
        self.display_name = row["display_name"]
        self.role = row["role"]
        self._active = bool(row["is_active"])

    @property
    def is_active(self):           # Flask-Login: inactive users cannot log in
        return self._active


@login_manager.user_loader
def load_user(user_id):
    row = _load_user_row("id", user_id)
    return User(row) if row else None


# ── Auth helpers ──────────────────────────────────────────────────────────────
_USERNAME_RE   = re.compile(r"^[a-z0-9_]{3,20}$")
# Tiered lockout: (cumulative_failed_attempts, lockout_minutes, severity, send_email)
_LOCKOUT_TIERS = [
    (3,  5,  "MEDIUM",   False),
    (5,  15, "HIGH",     True),
    (10, 60, "CRITICAL", True),
]
# Endpoints reachable WITHOUT auth (Part 3 exemptions). 'static' covers assets.
_AUTH_EXEMPT   = {"setup", "login", "login_recovery", "logout", "api_passphrase_generate", "static",
                  "install_windows_download", "install_windows_exe", "install_windows_zip",
                  # The pre-warn page is reached by the SAME people as /exe and /zip — end
                  # users holding an installer link, who have no dashboard account. Gating
                  # it behind login bounces them to a sign-in page they cannot pass, so it
                  # must share its siblings' exemption or it silently does nothing. The
                  # token remains the credential: install_windows_start() still calls
                  # _valid_installer_token() and 410s without a good one.
                  "install_windows_start",
                  "api_health"}


def _hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def _check_password(pw: str, pw_hash: str) -> bool:
    """Verify a password, tolerating whitespace a paste may have carried in.

    RAW IS TRIED FIRST, and that order is not cosmetic. Some accounts already
    have padding baked into their hash from before passwords were normalised on
    the way in; checking raw first means those keep working exactly as they did.
    Only if raw fails do we retry the stripped form, which rescues the far more
    common case: a clean stored password and a paste that dragged in a trailing
    newline from a password manager or text file.

    Stripping the input FIRST would have inverted this into a regression —
    a padded stored hash would stop matching its own correct password.

    The equivalence this admits is trivial (a password and its whitespace
    variants), and it costs one extra bcrypt (~157ms) only on an attempt that
    contained whitespace and already failed.
    """
    try:
        if bcrypt.checkpw((pw or "").encode(), (pw_hash or "").encode()):
            return True
        stripped = (pw or "").strip()
        if stripped and stripped != pw:
            return bcrypt.checkpw(stripped.encode(), (pw_hash or "").encode())
        return False
    except (ValueError, TypeError):
        return False

# ── Recovery codes ────────────────────────────────────────────────────────────
# Ambiguous glyphs removed: no 0/O, no 1/I/L. These codes get written down on
# paper and typed back months later under stress, which is exactly the condition
# in which "was that a one or an ell?" turns a valid code into a failed attempt
# that also burns a slice of the lockout budget.
_RECOVERY_ALPHABET   = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
_RECOVERY_GROUPS     = 4
_RECOVERY_GROUP_LEN  = 4
_RECOVERY_BATCH_SIZE = 10


def _generate_recovery_code() -> str:
    """One code, grouped for transcription: XXXX-XXXX-XXXX-XXXX.

    16 chars from a 31-symbol alphabet is ~79 bits. Far past brute force, but the
    real defence is that attempts are rate-limited on the shared lockout budget —
    the entropy is what makes an OFFLINE guess against a stolen hash pointless.
    """
    pick = "".join(secrets.choice(_RECOVERY_ALPHABET)
                   for _ in range(_RECOVERY_GROUPS * _RECOVERY_GROUP_LEN))
    return "-".join(pick[i:i + _RECOVERY_GROUP_LEN]
                    for i in range(0, len(pick), _RECOVERY_GROUP_LEN))


def _normalize_recovery_code(submitted: str) -> str:
    """Accept what a human types; compare what the machine stored.

    Dashes, spaces and case are presentation, not secret. Someone reading a code
    off paper may add spaces, drop dashes, or use lowercase, and none of that
    should be the difference between recovering an account and not.
    """
    return "".join(ch for ch in (submitted or "").upper() if ch.isalnum())


def _recovery_code_storage_form(code: str) -> bytes:
    """Hash the NORMALIZED form so display formatting can change without
    invalidating every code already printed and stored in a drawer."""
    return _normalize_recovery_code(code).encode()


def generate_recovery_batch(user_id: int, actor=None):
    """Issue a fresh batch, invalidating any previous one. Returns plaintext codes.

    This is the ONLY moment the plaintext exists — the caller must display it,
    because it cannot be recovered afterwards. Only bcrypt hashes are stored.

    Supersede-then-insert runs in ONE transaction, deliberately. The failure this
    prevents is the dangerous ordering: if superseding committed and the insert
    then failed, the operator would be left with ZERO valid codes and no warning
    — strictly worse than the old batch they were replacing. Either the swap
    happens whole or the previous batch stays live.
    """
    codes = [_generate_recovery_code() for _ in range(_RECOVERY_BATCH_SIZE)]
    now      = datetime.now().isoformat(timespec="seconds")
    batch_id = secrets.token_hex(8)
    hashes   = [bcrypt.hashpw(_recovery_code_storage_form(c), bcrypt.gensalt()).decode()
                for c in codes]                     # ~1.6s; done before the txn opens
    conn = _users_conn()
    try:
        with conn:                                   # commit on success, rollback on raise
            conn.execute(
                "UPDATE recovery_codes SET superseded_at=? "
                "WHERE user_id=? AND used_at IS NULL AND superseded_at IS NULL",
                (now, user_id))
            conn.executemany(
                "INSERT INTO recovery_codes(user_id, code_hash, batch_id, created_at, "
                "created_actor) VALUES(?,?,?,?,?)",
                [(user_id, h, batch_id, now, actor) for h in hashes])
    finally:
        conn.close()
    return codes


def recovery_codes_remaining(user_id: int) -> int:
    conn = _users_conn()
    try:
        return conn.execute(
            "SELECT count(*) FROM recovery_codes WHERE user_id=? "
            "AND used_at IS NULL AND superseded_at IS NULL", (user_id,)).fetchone()[0]
    finally:
        conn.close()


def consume_recovery_code(user_id: int, submitted: str, ip=None) -> bool:
    """Verify and SPEND a code. True only if it was live and now is not.

    Single use is enforced by the UPDATE's own WHERE clause, not by a
    check-then-write: the row is only marked if it is still unspent at the
    moment of writing, so two simultaneous submissions of the same code cannot
    both succeed (`cur.rowcount` decides the winner). Guessing at concurrency
    here would be a real bug — the dashboard already runs multiple writers.
    """
    normalized = _recovery_code_storage_form(submitted)
    if not normalized:
        return False
    # `spent` rather than an early return from inside the loop: the alert below
    # must run with this connection already CLOSED. Building it needs two more
    # reads, and opening a second connection while this write connection is
    # still open is a self-inflicted lock contention on the recovery path — the
    # one path that has to work when everything else has failed. Same winner,
    # same short-circuit on first match; only the exit point moved.
    spent = False
    conn = _users_conn()
    try:
        rows = conn.execute(
            "SELECT id, code_hash FROM recovery_codes WHERE user_id=? "
            "AND used_at IS NULL AND superseded_at IS NULL ORDER BY id", (user_id,)).fetchall()
        for r in rows:
            try:
                if not bcrypt.checkpw(normalized, r["code_hash"].encode()):
                    continue
            except (ValueError, TypeError):
                continue                              # corrupt hash: skip, never crash recovery
            cur = conn.execute(
                "UPDATE recovery_codes SET used_at=?, used_ip=? "
                "WHERE id=? AND used_at IS NULL AND superseded_at IS NULL",
                (datetime.now().isoformat(timespec="seconds"), ip, r["id"]))
            conn.commit()
            spent = cur.rowcount == 1
            break
    finally:
        conn.close()
    if spent:
        _alert_recovery_code_used(user_id, ip)
    return spent


def _alert_recovery_code_used(user_id: int, ip=None):
    """Email the operator that a single-use recovery code was just spent.

    WHY THIS EVENT EARNS AN EMAIL WHEN OTHERS DO NOT. Routine events — sign-ins,
    and the idle-lock that lands next — fire constantly, and alerting on them
    would train the operator to ignore Nemesis mail, which is the same
    alert-fatigue trap the watchdog's HIGH/CRITICAL tiering exists to avoid. A
    recovery code is the opposite shape: rare, and asymmetric in what it means.
    It says someone authenticated WITHOUT the password. That is either the
    legitimate operator recovering from a lockout — who already knows and can
    ignore one mail — or someone who obtained a code, who must be caught. The
    cost of a false positive is one ignorable email; the cost of a miss is a
    silent account takeover.

    LIVES INSIDE consume_recovery_code() rather than at the route, deliberately.
    "Every successful consumption alerts" is then a structural property of
    spending a code, not a promise each future caller has to remember to keep.

    FIRES ON CONSUMPTION, not on completed login — and that is the intended
    reading. A code that has been burned is worth knowing about even if whatever
    followed it did not finish; the secret is spent either way.

    CONTEXT IS CAPTURED HERE, IN THE REQUEST THREAD. `request` is thread-local
    and `datetime.now()` would drift to whenever the worker happens to run, so
    both are read now and passed by value. The send itself is off-thread.

    CARRIES NO SECRET. Not the code, not its hash, not the password. Only who,
    when, from where, and how many codes remain — enough to judge whether it was
    you, and useless to anyone who intercepts the mail.
    """
    try:
        try:
            ua = request.headers.get("User-Agent", "")[:120] or "(not reported)"
        except Exception:
            ua = "(no request context)"
        row = _load_user_row("id", user_id)
        username  = row["username"] if row else f"user id {user_id}"
        remaining = recovery_codes_remaining(user_id)
        when      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        subject = f"[Nemesis] HIGH: recovery code used for '{username}'"
        body = (
            "A single-use recovery code was accepted for the Nemesis dashboard.\n"
            "This means someone signed in WITHOUT the account password.\n"
            "\n"
            f"  Account:       {username}\n"
            f"  When:          {when} (server local time)\n"
            f"  Source IP:     {ip or 'unknown'}\n"
            f"  Browser/agent: {ua}\n"
            f"  Codes left:    {remaining} of {_RECOVERY_BATCH_SIZE}\n"
            "\n"
            "IF THIS WAS YOU, recovering from a lockout: no action needed. You were\n"
            "sent to the change-password page, and the code just used can never be\n"
            "reused by anyone.\n"
            "\n"
            "IF THIS WAS NOT YOU, treat the account as compromised:\n"
            "  1. Change the password immediately.\n"
            "  2. Regenerate the recovery codes — this invalidates every code still\n"
            "     outstanding, including any the other party may hold.\n"
            "  3. Review recent sign-in activity on the dashboard.\n"
            "\n"
            "If you cannot reach the dashboard at all, the SSH recovery CLI on the\n"
            "Nemesis host still works:\n"
            f"  sudo python3 /opt/nemesis/core/manage.py reset-password {username}\n"
            "\n"
            "Nemesis sends this every time a recovery code is used. It does not email\n"
            "routine sign-ins, so this message always means something worth reading.\n"
        )
        _notify_email_async(subject, body)
    except Exception:
        # Never let alerting affect the unlock that just succeeded.
        auth_log.exception("auth: recovery-code alert failed")


def _register_credential_failure(row, username, ip, ua,
                                 reason="bad_password", source="login", action=None):
    """Increment the failed-attempt budget and escalate lockout tiers on 3/5/10.

    ONE copy of the tier table's consequences. Login is no longer the only form
    that verifies this password — the change-password form checks the CURRENT
    one — and a second copy of this logic is how the two drift until only one of
    them still locks out.

    The budget is shared between them ON PURPOSE. If each form had its own
    counter, an attacker who exhausted login's allowance would simply move to
    the change-password form and get a fresh one; the throttle would be
    arithmetic, not a limit. Sharing it also means an authenticated form cannot
    become an unmetered password oracle for a hijacked session.

    Returns (locked, minutes, tier). Callers render their own message — this
    decides consequences, not presentation.
    """
    conn = _users_conn()
    try:
        # Increment IN THE DATABASE and read back the post-increment value.
        #
        # `row` was read by the CALLER, before a bcrypt verify that takes ~100ms,
        # so computing fa = row[...] + 1 here and writing that absolute number
        # lost increments under concurrency: two failed attempts both read N and
        # both wrote N+1, advancing the budget by one instead of two. Flask is
        # threaded, so two POSTs is all it takes. A throttle that under-counts
        # gives an attacker extra attempts, and this budget is SHARED with the
        # change-password form and with nemesis_fwd by design (see the docstring
        # above), so the losses compound across all three surfaces.
        #
        # failed_attempts = failed_attempts + 1 cannot lose an increment: the
        # database serializes the writes and each applies to whatever the last
        # one left. RETURNING gives the value OUR increment produced, which is
        # what the tier decision has to be based on.
        r = conn.execute(
            "UPDATE users SET failed_attempts = COALESCE(failed_attempts, 0) + 1 "
            "WHERE id=? RETURNING failed_attempts, lockout_tier",
            (row["id"],)).fetchone()
        conn.commit()
        fa   = int(r[0] or 0) if r else int(row["failed_attempts"] or 0) + 1
        tier = int(r[1] or 0) if r else int(row["lockout_tier"] or 0)

        triggered = None
        for idx, (thr, mins, severity, do_email) in enumerate(_LOCKOUT_TIERS, start=1):
            if fa >= thr and tier < idx:
                triggered = (idx, mins, severity, do_email)   # keep the highest crossed tier

        if triggered:
            tnum, mins, severity, do_email = triggered
            lock_until = (datetime.now() + timedelta(minutes=mins)).isoformat(timespec="seconds")
            # `COALESCE(lockout_tier,0) < ?` so a concurrent failure that already
            # applied a HIGHER tier is not walked backwards into a shorter lockout.
            conn.execute("UPDATE users SET lockout_until=?, lockout_tier=? "
                         "WHERE id=? AND COALESCE(lockout_tier, 0) < ?",
                         (lock_until, tnum, row["id"], tnum))
            conn.commit()
    finally:
        conn.close()

    if triggered:
        tnum, mins, severity, do_email = triggered
        _log_login_event(username, ip, False, f"lockout_tier_{tnum}", tnum, ua,
                         source=source, action=action)
        if tnum == 3:
            _log_login_event(username, ip, False, "persistent_brute_force", 3, ua,
                             source=source, action=action)
        _open_security_ticket(
            f"Login lockout tier {tnum} ({severity}) for {username}",
            (f"{fa} failed credential attempts for '{username}' from {ip} "
             f"(source: {source}). Account locked for {mins} minutes (tier {tnum})."),
            severity)
        if do_email:
            _notify_email_async(
                f"[Nemesis] Login lockout tier {tnum} ({severity}) for {username}",
                f"{fa} failed credential attempts for '{username}' from {ip} "
                f"(source: {source}). Locked for {mins} minutes.")
        return True, mins, tnum

    _log_login_event(username, ip, False, reason, tier, ua, source=source, action=action)
    return False, 0, tier


def _set_password(user_id: int, new_password: str):
    """The single place a password is changed IN THE DASHBOARD. Returns (ok, reason).

    Every in-app path — the authenticated change form, the recovery-code flow —
    goes through here, so policy cannot drift between them. A second setter is
    how one path ends up skipping validation.

    NOT the only writer in the repo, and the comment says so deliberately rather
    than asserting a tidier invariant than actually holds: `core/manage.py`
    (reset-password / create-user) is a separate root-only process that must keep
    working when the dashboard does not, so it writes the same columns directly.
    Both were audited on 2026-07-31 and BOTH were missing `password_changed_at` —
    which is exactly the drift this docstring exists to warn about. If a third
    writer ever appears, fold it in here or fix it there; do not leave it silent.

    Three things happen together, deliberately in one statement:

      password_hash        the new bcrypt hash
      password_changed_at  stamped NOW. Updated in the SAME UPDATE as the hash,
                           never separately: if the two could diverge, a
                           just-changed password could still read as expired,
                           which is the failure that makes users distrust the
                           expiry prompt and start writing passwords down.
      lockout state        cleared. Completing an authenticated change is proof
                           of control, so carrying a lockout forward past it
                           would punish the legitimate owner for an attacker's
                           failed attempts.

    Validation is applied here rather than trusted from the caller — the same
    reasoning as the helper validating write_env server-side.
    """
    # Normalise BEFORE validating, so the value that is checked is byte-for-byte
    # the value that gets hashed. Validating the raw form and hashing a different
    # one is how a password passes the policy and then cannot be typed back in.
    new_password = (new_password or "").strip()
    ok, reason = passphrase.validate(new_password)
    if not ok:
        return False, reason
    conn = _users_conn()
    try:
        now = datetime.now().isoformat(timespec="seconds")
        conn.execute(
            "UPDATE users SET password_hash=?, password_changed_at=?, "
            "failed_attempts=0, lockout_until=NULL, lockout_tier=0, "
            "recovery_grace_until=NULL WHERE id=?",
            (_hash_password(new_password), now, user_id),
        )
        conn.commit()
        return True, None
    finally:
        conn.close()


def _create_user(username: str, display_name: str, password: str, role: str = "admin") -> int:
    conn = _users_conn()
    try:
        now = datetime.now().isoformat(timespec="seconds")
        # password_changed_at is stamped HERE, not left to default.
        #
        # The column is nullable, and the 30-day expiry check treats NULL as
        # "unknown — due for a change". Omitting it would therefore mark every
        # freshly created account as already expired, forcing the operator to
        # change the password they chose seconds earlier on a brand-new install.
        # Caught by probe 2026-07-31 before the expiry check existed to expose it.
        cur = conn.execute(
            "INSERT INTO users(username, display_name, password_hash, role, is_active, "
            "created_at, password_changed_at) VALUES(?,?,?,?,1,?,?)",
            (username, display_name, _hash_password(password), role, now, now),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


#: Body fields that carry the admin credential rather than payload data. Any
#: route that both takes a credential and treats the body as data must exclude
#: these, or the credential is processed as if it were data.
_CREDENTIAL_FIELDS = frozenset({"password"})


def _fw_credential():
    """Admin password for a privileged firewall action, from the POST body.

    Never stored, never logged, never cached on this side. It is forwarded to
    nemesis-fwd, which verifies it against the stored bcrypt hash itself — this
    process deliberately has no way to assert "already verified", so a
    compromised dashboard has no boolean to forge.
    """
    data = request.get_json(silent=True) or {}
    return data.get("password")


def _fw_session_id():
    try:
        return session.get("_id")
    except Exception:
        return None


def _fw_error_response(exc):
    """Map a helper refusal to an HTTP response. Fails CLOSED and says so."""
    if isinstance(exc, FirewallUnavailable):
        return jsonify({"error": "firewall service unavailable — no rule was "
                                 "changed", "kind": "unavailable"}), 503
    kind = getattr(exc, "kind", "internal")
    status = {"credential_denied": 401, "admin_denied": 403, "locked_out": 423,
              "peer_denied": 403, "bad_request": 400,
              # never_block: refused locally by the chokepoint guard before the
              # helper was ever contacted. 400 — the request itself is the problem.
              "never_block": 400}.get(kind, 502)
    return jsonify({"error": str(exc), "kind": kind}), status


def _actor() -> str:
    """Attribution actor for Flask request contexts: the logged-in username
    (Part 3 upgrade from IP). Falls back to the client IP pre-auth."""
    try:
        if current_user.is_authenticated:
            return current_user.username
    except Exception:
        pass
    return request.remote_addr or "unknown"


# ── Auth audit + tiered-lockout side effects ──────────────────────────────────
def _log_login_event(username, ip, success, failure_reason=None, lockout_tier=None,
                     user_agent=None, session_id=None, tailscale_ip=None,
                     source="login", action=None):
    """One row per login attempt (success AND failure). geo_*/device_id are seams.

    source/action default to the login path's values so every existing caller is
    unchanged. They exist because login is no longer the only place a password is
    verified — nemesis-fwd checks it for privileged ops, and the change-password
    form checks the CURRENT password. All of it belongs in one table or the
    picture of "who has been guessing at this password" is split across three.
    """
    try:
        conn = _users_conn()
        # `timestamp` supplied explicitly — see the note in database.py's
        # init_login_events_table(). The column DEFAULT was UTC while every sibling
        # column is local, and SQLite cannot alter a default in place, so the
        # writers are what fix it on an existing database.
        conn.execute(
            "INSERT INTO login_events(username, timestamp, ip_address, success, failure_reason, "
            "lockout_tier, user_agent, session_id, tailscale_ip, source, action) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (username, datetime.now().isoformat(timespec="seconds"),
             ip or "unknown", 1 if success else 0, failure_reason,
             lockout_tier, (user_agent or "")[:300], session_id, tailscale_ip,
             source, action),
        )
        conn.commit()
        conn.close()
    except Exception:
        auth_log.exception("auth: login_event log failed")


def _open_security_ticket(title, body, severity):
    try:
        from modules.tickets.module import open_ticket as _open_ticket
        _open_ticket(sensor_key="auth_security", title=title[:200], body=body,
                     priority=severity, actor="system")
    except Exception:
        auth_log.exception("auth: security ticket creation failed")


def _notify_email(subject, body):
    try:
        email_utils.send_email(subject, body)
    except Exception:
        auth_log.exception("auth: email notify failed")


def _notify_email_async(subject, body):
    """Send an alert email WITHOUT holding the request open.

    `_notify_email` is best-effort but BLOCKING: email_utils.send_email uses a
    30-second SMTP timeout, so calling it inline on an auth path can stall the
    response for half a minute — and on the recovery-code path that lands at
    precisely the moment an operator is locked out and in a hurry.

    Daemon thread, so it can never hold up interpreter shutdown, and it inherits
    _notify_email's swallow-everything contract: a mail problem must never
    become an authentication outcome. Even the thread START is guarded — a
    failure to spawn must not propagate into the caller either.

    USED BY THE LOCKOUT-TIER CALLER TOO as of 2026-08-02, in its own commit as
    planned when this wrapper landed. The lockout path has the same shape as the
    recovery-code one and arguably a worse version of it: it runs on a FAILED
    credential attempt, so the 30s stall was reachable by anyone who could type
    a wrong password enough times — an unauthenticated caller could hold a
    request thread for half a minute, repeatedly. Moving the send off-thread
    removes that without changing when mail is sent or what it says.

    THE TRADEOFF, STATED: a daemon thread is abandoned at interpreter exit, so a
    send still in flight during a shutdown is lost. That is deliberate and is
    the same bargain the recovery-code path already makes — mail is best-effort
    by contract here (`_notify_email` swallows everything), and losing a
    notification is strictly better than letting mail latency, or a mail
    failure, become an authentication outcome.
    """
    try:
        threading.Thread(target=_notify_email, args=(subject, body),
                         name="nemesis-alert-mail", daemon=True).start()
    except Exception:
        auth_log.exception("auth: could not start alert-mail thread")


def _auth_threat_level() -> str:
    """'' / 'amber' / 'red' for the header indicator: active lockouts + recent
    concurrent-session events. tier>=2 or a concurrent flag => red; tier1 => amber."""
    try:
        now = datetime.now()
        conn = _users_conn()
        tiers = []
        for r in conn.execute("SELECT lockout_tier, lockout_until FROM users "
                              "WHERE lockout_until IS NOT NULL"):
            try:
                if r["lockout_until"] and now < datetime.fromisoformat(r["lockout_until"]):
                    tiers.append(int(r["lockout_tier"] or 0))
            except ValueError:
                pass
        # Cutoff computed in Python, not by SQLite's datetime('now').
        #
        # This is a STRING comparison, so it is only correct when both sides share a
        # timezone AND a format. It previously worked by coincidence: the column
        # default was UTC and datetime('now') is UTC.
        #
        # THE FORMAT MATTERS MORE THAN THE OFFSET, which is not obvious and was
        # measured rather than reasoned out. Rows are now ISO 'T'; datetime('now')
        # emits a space. 'T' is 0x54 and ' ' is 0x20, so against an unchanged
        # datetime('now') bound the comparison short-circuits TRUE at index 10 for
        # any row sharing the bound's date — the time digits are never reached. The
        # window would not have gone blind, it would have gone OVER-INCLUSIVE: a
        # 14-hour-old event satisfying a 1-hour window, latching this indicator red
        # on stale data. Deriving the bound exactly as the row is written keeps
        # timezone and format matched by construction.
        concurrent = conn.execute(
            "SELECT 1 FROM login_events WHERE failure_reason='concurrent_session_detected' "
            "AND timestamp > ? LIMIT 1",
            ((datetime.now() - timedelta(hours=1)).isoformat(timespec="seconds"),)).fetchone()
        conn.close()
        if concurrent or any(t >= 2 for t in tiers):
            return "red"
        if tiers:
            return "amber"
    except Exception:
        pass
    return ""


def _threat_indicator_html() -> str:
    lvl = _auth_threat_level()
    if lvl == "red":
        return ('<a href="/settings" style="color:#ff4444;text-decoration:none" '
                'title="Security: failed logins or concurrent session — review">&#9888; Security</a>'
                '&nbsp;|&nbsp;')
    if lvl == "amber":
        return ('<span style="color:#ffcc00" title="Elevated failed logins">&#9888; Login alerts</span>'
                '&nbsp;|&nbsp;')
    return ""


def _safe_next(target):
    """Return `target` only if it is a same-origin relative path, else None.

    This is the open-redirect guard. `next` arrives from the URL, so it is
    attacker-controllable: without this check, a link to
    `/login?next=https://evil.example/` would render OUR login page and then hand
    the freshly-authenticated operator straight to someone else's site — a
    credible phish, because every visible detail up to that point is genuine.

    Rejected: absolute URLs, protocol-relative `//host` (scheme-less but still
    off-site), and backslashes, which some browsers normalise to `/` and which
    are the classic way to smuggle `//` past a naive startswith check.
    """
    if not target or not target.startswith("/") or target.startswith("//"):
        return None
    if "\\" in target:
        return None
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return None
    return target


# ── No-store on everything the browser could replay after a lock ─────────────
@app.after_request
def _no_store(resp):
    """Stop the browser retaining authenticated pages — and their form state.

    THE BUG THIS CLOSES (found 2026-08-04, Firefox): from the lock screen,
    BACK restored the previous authenticated page *including the password field
    the operator had typed into it*. Clicking unlock then submitted a real
    credential the person at the keyboard never knew. The server behaved
    correctly throughout — it verified a genuine password — which is exactly
    why this was invisible to server-side checks. The browser was handing out
    the credential, and idle-lock's entire threat model is someone walking up
    to an unattended machine.

    `no-store` is the part that matters: Firefox will not put a no-store
    response in its back-forward cache, so there is no restored page and no
    restored form value. `no-cache`/`must-revalidate`/`Pragma` cover
    intermediaries and older clients; `private` keeps any shared proxy out.

    Applied to everything EXCEPT `static`, deliberately. Static assets carry no
    session state and no form values, and blanket no-store on them would cost
    real performance on every page load for no security gain. Anything that
    renders session-scoped content or accepts a credential is not served from
    that endpoint.

    Set with setdefault semantics: a route that has deliberately chosen its own
    caching (a download, a long-lived asset) keeps it rather than being
    overridden from here.
    """
    if (request.endpoint or "").startswith("static"):
        return resp
    if not resp.headers.get("Cache-Control"):
        resp.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, private")
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    return resp


def _modules_dm():
    """The modules-side DataManager, or raise if the loader has not run yet.

    Kept as a function rather than a module-level import so that a dashboard
    started before `modules_loader.init()` still boots — the caller treats a
    raise as "no attribution available", never as a fatal error.
    """
    from modules import get_data_manager
    return get_data_manager()


# ── Attribution: stamp the acting user on every logged DB write ──────────────
@app.before_request
def _set_dm_actor():
    """Tell the Data Manager who is acting, for the duration of this request.

    ADR 0006 stamps `current_actor()` on every logged write automatically, so
    once this is set no per-write plumbing is needed. Until 2026-08-04 nothing
    called `set_actor()` outside tests, so every row in `dm_operation_log`
    recorded a NULL actor — the audit trail existed but never said who.

    Unauthenticated requests set None EXPLICITLY rather than leaving the
    previous value: see _clear_dm_actor for why that distinction is the whole
    safety property here.
    """
    # BOTH DataManager instances, deliberately. dashboard keeps its own via
    # _dm() (see its docstring) while modules use modules.get_data_manager().
    # The actor is per-instance thread-local state, so setting one leaves every
    # write through the other unattributed — half-wired attribution that reads
    # as complete. Having two instances is free for connections; it is NOT free
    # here.
    actor = None
    try:
        if current_user.is_authenticated:
            # username, not display name: the stable identifier the users table
            # is keyed on. Display names are editable.
            actor = f"user:{current_user.username}"
    except Exception:
        actor = None
    for _get in (_dm, _modules_dm):
        try:
            _get().set_actor(actor)
        except Exception:
            # Attribution must never take the dashboard down. A missing actor
            # is a NULL in the audit trail — exactly the pre-2026-08-04 state,
            # degraded rather than broken.
            auth_log.exception("actor: set failed")


def _current_actor_label():
    """The acting user as a stable label, or None when unauthenticated.

    Same derivation as _set_dm_actor above (username, not the editable display
    name). Kept as its own helper for callers that need to RECORD the actor on
    a row of their own rather than rely on the Data Manager stamping it -- the
    chat turn log is the first of those.
    """
    try:
        if current_user.is_authenticated:
            return f"user:{current_user.username}"
    except Exception:
        pass
    return None


@app.teardown_request
def _clear_dm_actor(exc=None):
    """Clear the actor when the request ends. THIS IS THE LOAD-BEARING HALF.

    The actor is `threading.local()` and Flask reuses worker threads, so a
    value left set here is inherited by whatever request lands on that thread
    next. That would attribute one user's writes to another — and unlike a NULL
    actor, which is honestly empty, a leaked actor is confidently wrong. Every
    background write that happens to run on a request thread would inherit it
    too.

    teardown_request rather than after_request: teardown runs even when the
    view raised, and an actor surviving an exception is exactly the case that
    would be hardest to notice.
    """
    for _get in (_dm, _modules_dm):
        try:
            _get().clear_actor()
        except Exception:
            auth_log.exception("actor: clear failed")


# ── First-run + auth guard (covers dashboard.py AND all module routes) ────────
@app.before_request
def _enforce_setup_and_auth():
    ep = request.endpoint
    if ep is None:
        return  # let Flask 404 unknown paths
    if ep in _AUTH_EXEMPT or ep.startswith("static"):
        return
    # First run: no users yet → force the setup wizard (runs before login).
    if _user_count() == 0:
        return redirect(url_for("setup"))
    # Otherwise every route requires an authenticated session.
    if not current_user.is_authenticated:
        # Carry where they were going. Dropping it here is what sent an operator
        # to the dashboard instead of the page they asked for, with no clue that
        # a redirect had happened (found live 2026-07-31 via /account/recovery-codes).
        # Only for GET: replaying a POST as a GET after login would be wrong, and
        # silently re-submitting one would be worse.
        nxt = None
        if request.method == "GET":
            nxt = request.full_path if request.query_string else request.path
        return redirect(url_for("login", next=nxt) if nxt else url_for("login"))

    # Walk-away protection. Runs BEFORE the expiry check below, deliberately:
    # presence has to be proven before anything else is allowed, including
    # changing a password. Both policies confine, so if a session is locked AND
    # expired the order decides which one wins — and "prove a human is here"
    # must win, or an unattended session could be used to set a new password.
    if ep not in _IDLE_LOCK_ALLOWED:
        try:
            state = _session_lock_state()
            if state:
                return _locked_response(state)
            # Only human traffic refreshes the clock — see _is_background_poll.
            # Write-coalesced (see _touch_interval) so the signed cookie is not
            # re-sent on every response.
            if not _is_background_poll():
                last = session.get(_SESSION_LAST_SEEN) or 0
                if (time.time() - last) >= _touch_interval():
                    session[_SESSION_LAST_SEEN] = time.time()
        except Exception:
            # Same stance as the expiry check below, and for the same reason: a
            # bug in this policy must never take the dashboard down — and here it
            # must never lock the operator out of their own dashboard either.
            auth_log.exception("auth: idle-lock check failed")

    # Authenticated but the password is past its maximum age: confine the session
    # to changing it. NOT a rejection — they are logged in and stay logged in.
    if ep not in _EXPIRED_ALLOWED:
        try:
            if _password_expired(_load_user_row("id", current_user.id)):
                return redirect(url_for("change_password"))
        except Exception:
            # A failure to evaluate the policy must not take the dashboard down.
            auth_log.exception("auth: password-expiry check failed")


# ── Auth routes ───────────────────────────────────────────────────────────────
@app.route("/api/passphrase/generate")
def api_passphrase_generate():
    """Pre-auth: used by the setup page's 'generate another' button."""
    return jsonify({"passphrase": passphrase.generate()})


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if _user_count() > 0:
        return redirect(url_for("login"))         # setup already done
    if request.method == "GET":
        return render_template("setup.html", suggested=passphrase.generate())

    username     = (request.form.get("username") or "").strip().lower()
    display_name = (request.form.get("display_name") or "").strip()
    password     = (request.form.get("password") or "").strip()
    confirm      = (request.form.get("confirm_password") or "").strip()

    errors = []
    if not _USERNAME_RE.match(username):
        errors.append("Login ID must be 3-20 chars: lowercase letters, numbers, or underscore.")
    elif username == "admin":
        errors.append("Choose a more specific login ID than 'admin' (e.g. your name).")
    if not (1 <= len(display_name) <= 50):
        errors.append("Display name must be 1-50 characters.")
    ok, reason = passphrase.validate(password)
    if not ok:
        errors.append(reason)
    if password != confirm:
        errors.append("Passwords do not match.")

    if errors:
        return render_template("setup.html", suggested=passphrase.generate(),
                               errors=errors, username=username, display_name=display_name)

    uid = _create_user(username, display_name, password, role="admin")
    row = _load_user_row("id", uid)
    if row:
        login_user(User(row))
        _stamp_session_start()

    # Ordering is deliberate: account -> batch -> display, never the reverse.
    # Generating first and creating the account afterwards would mean a failure
    # here costs the operator the account they just set up. This way the account
    # always survives, and a missing batch is recoverable — regenerating issues a
    # fresh one and retires whatever came before, so a half-finished batch cannot
    # leave anything stale behind.
    try:
        codes = generate_recovery_batch(uid)
    except Exception:
        auth_log.exception("auth: recovery-code generation failed at setup for uid=%s", uid)
        _audit("recovery_codes_generate_failed", ip=request.remote_addr or "unknown")
        # Do NOT block the operator: they have a working account and can issue a
        # set from Settings. Silently redirecting would hide it, so say it plainly.
        return render_template("recovery_codes.html", codes=[], first_run=True,
                               generated_at="—", error=(
                                   "Your account was created, but recovery codes could not be "
                                   "generated. You can issue a set from Settings -> Recovery Codes."))
    _audit("recovery_codes_generated", ip=request.remote_addr or "unknown")
    return render_template("recovery_codes.html", codes=codes, first_run=True,
                           generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "GET":
        notice = None
        if request.args.get("changed"):
            notice = "Password changed. Sign in with your new password."
        elif request.args.get("timeout"):
            # Reached the absolute session cap. Worded as an expected policy
            # outcome, not a failure — nothing went wrong and nothing was lost.
            notice = ("Your session reached its maximum length and was signed out. "
                      "Sign in again to continue.")
        return render_template("login.html", next=_safe_next(request.args.get("next")),
                               notice=notice)

    username = (request.form.get("username") or "").strip().lower()
    password = request.form.get("password") or ""
    ip = request.remote_addr or "unknown"
    ua = request.headers.get("User-Agent", "")
    # Validated on the way IN, not just on the way out, so an unsafe value can
    # never be echoed back into the form and survive to the next attempt.
    nxt = _safe_next(request.form.get("next"))
    row = _load_user_row("username", username)

    # Active lockout?
    if row and row["lockout_until"]:
        try:
            until = datetime.fromisoformat(row["lockout_until"])
            if datetime.now() < until:
                mins = int((until - datetime.now()).total_seconds() // 60) + 1
                _log_login_event(username, ip, False, "locked_out", row["lockout_tier"], ua)
                return render_template("login.html", next=nxt,
                                       error=f"Account locked. Try again in {mins} minute(s).")
        except ValueError:
            pass

    # Success
    if row and row["is_active"] and _check_password(password, row["password_hash"]):
        # Concurrent-session check against PRIOR successful logins (before logging this one).
        prior_ip = None
        try:
            conn = _users_conn()
            # Same matched-format rule as _auth_threat_level()'s cutoff above. Left
            # as datetime('now'), this window would accept logins well outside 24
            # hours — verified against a 30-hour-old row — while still returning a
            # plausible-looking IP. A wrong answer that looks right is worse here
            # than no answer: this feeds concurrent-session detection.
            pr = conn.execute(
                "SELECT ip_address FROM login_events WHERE username=? AND success=1 "
                "AND ip_address<>? AND timestamp > ? "
                "ORDER BY timestamp DESC LIMIT 1",
                (username, ip,
                 (datetime.now() - timedelta(hours=24)).isoformat(timespec="seconds"))).fetchone()
            conn.close()
            prior_ip = pr["ip_address"] if pr else None
        except Exception:
            auth_log.exception("auth: concurrent-session check failed")
        # Reset ALL counters + stamp last_login
        conn = _users_conn()
        conn.execute("UPDATE users SET failed_attempts=0, lockout_until=NULL, lockout_tier=0, "
                     "last_login=? WHERE id=?",
                     (datetime.now().isoformat(timespec="seconds"), row["id"]))
        conn.commit()
        conn.close()
        _log_login_event(username, ip, True, None, None, ua, session_id=session.get("_id"))
        login_user(User(row))
        _stamp_session_start()
        if prior_ip:
            _log_login_event(username, ip, True, "concurrent_session_detected", None, ua)
            _open_security_ticket(
                f"Concurrent session detected for {username}",
                (f"Active session from {prior_ip}, new login from {ip}. Was this you? "
                 f"If not, use core/manage.py to reset your password immediately."),
                "HIGH")
        return redirect(nxt or url_for("dashboard"))

    # Failure — unknown user (still logged; no row to update)
    if not row:
        _log_login_event(username, ip, False, "unknown_user", None, ua)
        return render_template("login.html", error="Invalid username or password.", next=nxt)

    # Failure — known user. The escalation itself lives in
    # _register_credential_failure() because login is no longer the only form
    # that verifies this password; see that function for why the budget is shared.
    locked, mins, _tier = _register_credential_failure(row, username, ip, ua)
    if locked:
        return render_template("login.html", next=nxt,
                               error=f"Too many failed attempts. Account locked for {mins} minutes.")
    # Never reveal which field was wrong (security best practice).
    return render_template("login.html", error="Invalid username or password.", next=nxt)


@app.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    """Authenticated password change.

    Requires the CURRENT password even though the caller is already logged in.
    That is the whole point of the form: a hijacked session must not be able to
    change the password and lock the real owner out of their own firewall. Being
    logged in proves the session was valid at some point; re-entering the
    password proves it is the owner sitting there now.

    Failures are throttled on the SAME budget as login (see
    _register_credential_failure) so this form cannot be used to guess the
    password without limit.
    """
    row = _load_user_row("id", current_user.id)
    if not row:
        logout_user()
        return redirect(url_for("login"))

    recovery = _recovery_grace_active(row)
    if request.method == "GET":
        return render_template("change_password.html", username=row["username"],
                               recovery=recovery,
                               expired=_password_expired(row),
                               age_days=_password_age_days(row),
                               remaining_codes=(recovery_codes_remaining(row["id"])
                                                if recovery else None))

    ip  = request.remote_addr or "unknown"   # same derivation as login()
    ua  = request.headers.get("User-Agent", "")
    cur = request.form.get("current_password") or ""
    # Stripped here too: otherwise "do these match?" could disagree with what is
    # actually stored, and the mismatch error would name a difference the user
    # cannot see.
    new = (request.form.get("new_password") or "").strip()
    cfm = (request.form.get("confirm_password") or "").strip()

    # An account already locked out cannot change its way out of the lockout.
    if row["lockout_until"]:
        try:
            if datetime.fromisoformat(row["lockout_until"]) > datetime.now():
                return render_template("change_password.html", username=row["username"],
                                       error="Account is locked out. Try again later.")
        except (TypeError, ValueError):
            pass

    # A session that just signed in with a recovery code is exempt from the
    # current-password requirement — demonstrably it does not have one. The code
    # itself was the proof of control, and it was single-use and already spent.
    # The exemption is time-boxed (see _RECOVERY_GRACE_SECONDS) so a session
    # stolen later in the day does not inherit it.
    if not recovery and not _check_password(cur, row["password_hash"]):
        locked, mins, _t = _register_credential_failure(
            row, row["username"], ip, ua,
            reason="bad_current_password", source="password-change",
            action="change_password")
        _audit("password_change_denied", ip=ip)
        if locked:
            return render_template("change_password.html", username=row["username"],
                                   error=f"Too many failed attempts. Account locked for {mins} minutes.")
        return render_template("change_password.html", username=row["username"],
                               error="Current password is incorrect.")

    if new != cfm:
        return render_template("change_password.html", username=row["username"],
                               recovery=recovery,
                               remaining_codes=(recovery_codes_remaining(row["id"])
                                                if recovery else None),
                               error="New passwords do not match.")
    if not recovery and new == cur:
        return render_template("change_password.html", username=row["username"],
                               error="New password must be different from the current one.")
    if recovery and _check_password(new, row["password_hash"]):
        # Recovery gives no `cur` to compare against, so compare against the hash:
        # re-setting the forgotten password would leave them exactly as stuck.
        return render_template("change_password.html", username=row["username"],
                               recovery=True,
                               remaining_codes=recovery_codes_remaining(row["id"]),
                               error="New password must be different from your current one.")

    ok, reason = _set_password(row["id"], new)
    if not ok:
        return render_template("change_password.html", username=row["username"],
                               recovery=recovery,
                               remaining_codes=(recovery_codes_remaining(row["id"])
                                                if recovery else None),
                               error=reason or "Password does not meet requirements.")

    # audit_log, not login_events: login_events records attempts to AUTHENTICATE.
    # A completed password change is an administrative action on the account, and
    # belongs with the other attributed state changes.
    session.pop("pw_recovery_at", None)   # consumed; not left open for the session
    _audit("password_change", ip=ip)
    auth_log.info("auth: password changed for %s from %s%s", row["username"], ip,
                  " (via recovery code)" if recovery else "")
    # End the session and send them to the login screen.
    #
    # Re-rendering the form here was the bug: the page came back looking almost
    # unchanged (banner aside), which reads as "nothing happened" — worst of all
    # on the recovery path, where the person has just clawed their way back in
    # and is the least oriented user in the system.
    #
    # Re-authenticating is the deliberate choice over bouncing to the dashboard.
    # It makes the operator TYPE the new password once, immediately, while the
    # tab that generated it is still open — so a typo, a mangled paste, or a
    # password manager that saved the old value surfaces now rather than at the
    # next login when the old one is gone for good. It also drops the pre-change
    # session rather than carrying it forward.
    logout_user()
    return redirect(url_for("login", changed=1))


@app.route("/account/recovery-codes", methods=["GET", "POST"])
@login_required
def recovery_codes_page():
    """Show how many codes remain, and issue a fresh set.

    Regenerating requires the current password for the same reason changing it
    does: a hijacked session that could silently rotate the recovery codes would
    strip the real owner of their way back in, quietly, with the account still
    looking normal. It is also throttled on the shared lockout budget, so this
    form cannot be used as a password oracle either.

    The remaining COUNT is shown, never the codes — they exist in plaintext only
    on the page that issued them.
    """
    row = _load_user_row("id", current_user.id)
    if not row:
        logout_user()
        return redirect(url_for("login"))

    remaining = recovery_codes_remaining(row["id"])
    if request.method == "GET":
        return render_template("recovery_codes_manage.html",
                               username=row["username"], remaining=remaining)

    ip  = request.remote_addr or "unknown"
    ua  = request.headers.get("User-Agent", "")
    cur = request.form.get("current_password") or ""

    if row["lockout_until"]:
        try:
            if datetime.fromisoformat(row["lockout_until"]) > datetime.now():
                return render_template("recovery_codes_manage.html",
                                       username=row["username"], remaining=remaining,
                                       error="Account is locked out. Try again later.")
        except (TypeError, ValueError):
            pass

    if not _check_password(cur, row["password_hash"]):
        locked, mins, _t = _register_credential_failure(
            row, row["username"], ip, ua,
            reason="bad_password", source="recovery-codes", action="regenerate")
        _audit("recovery_codes_regenerate_denied", ip=ip)
        msg = (f"Too many failed attempts. Account locked for {mins} minutes."
               if locked else "Password is incorrect.")
        return render_template("recovery_codes_manage.html", username=row["username"],
                               remaining=remaining, error=msg)

    try:
        codes = generate_recovery_batch(row["id"])
    except Exception:
        auth_log.exception("auth: recovery-code regeneration failed for uid=%s", row["id"])
        _audit("recovery_codes_generate_failed", ip=ip)
        return render_template("recovery_codes_manage.html", username=row["username"],
                               remaining=remaining,
                               error="Could not issue a new set. Your existing codes are unchanged.")

    _audit("recovery_codes_generated", ip=ip)
    auth_log.info("auth: recovery codes regenerated for %s from %s", row["username"], ip)
    return render_template("recovery_codes.html", codes=codes, first_run=False,
                           generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"))


# How long a recovery-code sign-in may set a new password without supplying the
# old one. Bounded deliberately: the exemption exists because someone who used a
# code demonstrably does NOT have the password, but leaving it open for the life
# of the session would mean a session stolen hours later inherits the exemption.
_RECOVERY_GRACE_SECONDS = 15 * 60


# Password age policy. Expiry NEVER rejects the credential — see _password_expired.
_PASSWORD_MAX_AGE_DAYS = 30
_PASSWORD_WARN_DAYS    = 7
# Endpoints still reachable while a password is expired. Deliberately tiny: enough
# to change the password (and to leave), nothing else.
# `unlock` is here because idle-lock is evaluated BEFORE expiry: a session that is
# both locked and expired must be able to reach /unlock, or the two policies
# redirect at each other forever.
_EXPIRED_ALLOWED = {"change_password", "logout", "login", "setup", "static",
                    "api_passphrase_generate", "api_health", "account_unlock"}


# ── Idle-lock / walk-away protection ─────────────────────────────────────────
#
# Two independent limits:
#
#   idle      no human interaction for N minutes -> LOCK. Confines the session to
#             /account/unlock; the session itself survives, so nothing in
#             progress is lost.
#   absolute  the session has simply existed too long -> FULL LOGOUT. Re-auth
#             starts a genuinely new session with a fresh clock. Confining and
#             unlocking here instead would make the cap meaningless, since every
#             unlock would extend the very thing the cap is meant to bound.
#
# NEITHER CAN BE CONFIGURED OFF (operator decision 2026-08-01). The requirement
# is explicit — no live authenticated session sits open unattended — and a
# silent "0 disables it" would let that requirement be switched off without the
# decision ever being visible. A value below the minimum falls back to the
# default rather than disabling. Backing this out is a git revert plus a restart.
#
# Session state lives in Flask's SIGNED cookie: it cannot be forged without the
# server key, and a replayed older cookie only ever carries an OLDER
# last_activity, which locks sooner rather than later. What this does NOT cover
# is written up in known-limitations/, not here.
def _env_int(name, default, minimum=1):
    """Read an int from the environment, falling back to `default`.

    Deliberately total: malformed, empty, or below-minimum values yield the
    default rather than raising. Read at import, so an exception here would stop
    the dashboard from starting at all — a typo in nemesis.env must not be able
    to do that, and must not be able to disable a control either.
    """
    try:
        raw = (os.environ.get(name) or "").strip()
        value = int(raw) if raw else int(default)
    except (TypeError, ValueError):
        return int(default)
    return value if value >= minimum else int(default)


#: Minutes of no human interaction before the session locks.
_IDLE_TIMEOUT_SECONDS = _env_int("IDLE_LOCK_MINUTES", 15) * 60
#: Hard ceiling on total session age regardless of activity.
_SESSION_MAX_SECONDS  = _env_int("SESSION_MAX_HOURS", 8) * 3600

#: Endpoints reachable while LOCKED. Smaller than _EXPIRED_ALLOWED on purpose: a
#: locked session has not proven a human is present, so it may only prove that
#: (/account/unlock) or leave (/logout). `change_password` is deliberately ABSENT
#: — someone who walks up to an unattended session must not be able to set a new
#: password from it. `login`/`setup` are absent too: they bounce an already
#: authenticated session onward, which is pointless here.
_IDLE_LOCK_ALLOWED = {"account_unlock", "logout", "static", "api_health"}

_SESSION_LOGIN_AT   = "login_at"
_SESSION_LAST_SEEN  = "last_activity"
#: Set once per lock so the audit row is written once, not on every blocked request.
_SESSION_LOCK_LOGGED = "idle_lock_logged"


def _stamp_session_start():
    """Mark a session as freshly authenticated. Call wherever login_user() is."""
    now = time.time()
    session[_SESSION_LOGIN_AT] = now
    session[_SESSION_LAST_SEEN] = now
    session.pop(_SESSION_LOCK_LOGGED, None)


def _session_lock_state():
    """'expired' (log out), 'locked' (confine to unlock), or None (carry on).

    MISSING STAMPS FAIL CLOSED — an unstampable session is treated as locked,
    not as one starting now. Same posture as _password_expired(), where an
    unknown password age counts as expired: a control that cannot evaluate its
    own precondition must not conclude "fine". The cost is that sessions open
    across the deploy lock once and unlock normally; the alternative is that
    anything which loses its stamps silently becomes exempt.
    """
    now = time.time()
    login_at  = session.get(_SESSION_LOGIN_AT)
    last_seen = session.get(_SESSION_LAST_SEEN)
    if not isinstance(last_seen, (int, float)) or not isinstance(login_at, (int, float)):
        return "locked"
    if (now - login_at) >= _SESSION_MAX_SECONDS:
        return "expired"
    if (now - last_seen) >= _IDLE_TIMEOUT_SECONDS:
        return "locked"
    return None


def _touch_interval():
    """How often `last_activity` is actually rewritten into the cookie.

    Coalesced so the signed cookie is not re-sent on every single response, but
    always kept WELL INSIDE the idle window. A fixed interval was wrong: at or
    above the configured timeout it means an actively-used session never
    refreshes and locks anyway — invisible at the 15-minute default, and it
    immediately breaks any shortened timeout (VM demonstrations, tests, or an
    operator who simply wants a tighter window). Caught by test 4 of the
    enforcement harness, which is exactly the shortened-timeout scenario.
    """
    return max(1, min(30, _IDLE_TIMEOUT_SECONDS // 4))


def _is_background_poll():
    """True when the request came from a background refresh, not a human.

    Set by static/nemesis-activity.js at the setInterval CALL SITE. The absence
    of the header means activity, so a client that fails to send it can only
    make itself lock sooner — never keep a walked-away session alive.
    """
    return request.headers.get("X-Nemesis-Poll") == "1"


def _wants_json():
    """True when the caller is script, not a browser navigation.

    Used so the unlock flow can answer an in-page overlay with JSON instead of a
    redirect. The overlay's whole purpose is to never navigate — a 302 would
    reload the page and discard exactly the unsaved work it exists to protect.
    """
    if request.is_json:
        return True
    return "application/json" in (request.headers.get("Accept") or "")


def _locked_response(state):
    """How a locked/expired session is told, in the shape the caller can use.

    API and polling callers get JSON with an explicit flag, not a 302 to an HTML
    page — a redirect there lands HTML in a .json() parser and surfaces as a
    confusing parse error instead of "you are locked out".

    The lock transition is audited ONCE per lock, not on every subsequent
    blocked request: while a page sits locked its pollers keep firing, and an
    audit row per blocked poll would bury the one event that matters under
    dozens of duplicates.
    """
    wants_json = request.path.startswith("/api/") or _is_background_poll()
    if state == "expired":
        logout_user()
        session.clear()
        if wants_json:
            return jsonify({"error": "session_expired", "session_expired": True}), 401
        return redirect(url_for("login", timeout="1"))

    if not session.get(_SESSION_LOCK_LOGGED):
        session[_SESSION_LOCK_LOGGED] = True
        try:
            _audit("session_idle_locked", ip=request.remote_addr or "unknown")
        except Exception:
            auth_log.exception("auth: idle-lock audit row failed")

    if wants_json:
        return jsonify({"error": "session_locked", "session_locked": True}), 401
    nxt = None
    if request.method == "GET":
        nxt = request.full_path if request.query_string else request.path
    return redirect(url_for("account_unlock", next=nxt) if nxt
                    else url_for("account_unlock"))


def _password_age_days(row):
    """Days since the password was last set, or None if unknowable."""
    if not row:
        return None
    changed = row["password_changed_at"] if "password_changed_at" in row.keys() else None
    if not changed:
        return None
    try:
        return (datetime.now() - datetime.fromisoformat(changed)).days
    except (TypeError, ValueError):
        return None


def _password_expired(row):
    """True when the password is past its maximum age.

    An expired password STILL AUTHENTICATES. Expiry restricts the session to
    changing the password; it never refuses the login. That distinction is the
    whole safety property: a policy that rejected the credential would mean
    "expired -> must use a recovery code -> none left -> locked out of your own
    firewall", turning a hygiene rule into a lockout mechanism. Nothing here may
    ever become a reason someone cannot get in.

    Unknown age (NULL) counts as expired. Both writers now stamp the column, so
    this should only ever be a pre-migration row — and prompting for a change is
    the safe response to "we do not know how old this password is", precisely
    because the prompt cannot lock anyone out.
    """
    age = _password_age_days(row)
    if age is None:
        return bool(row) and not (row["password_changed_at"]
                                  if "password_changed_at" in row.keys() else None)
    return age >= _PASSWORD_MAX_AGE_DAYS


def _password_expiry_warning(row):
    """Days remaining if inside the warning window, else None."""
    age = _password_age_days(row)
    if age is None:
        return None
    left = _PASSWORD_MAX_AGE_DAYS - age
    return left if 0 < left <= _PASSWORD_WARN_DAYS else None


def _recovery_grace_active(row):
    """True only if BOTH the session and the database still say the window is open.

    Two checks, and both earn their place:

      session flag  proves THIS session is the one that used the code, so another
                    session belonging to the same user does not inherit the
                    exemption just because a window happens to be open.
      users.recovery_grace_until  is the AUTHORITY on whether the window is still
                    open at all. Flask sessions are client-side signed cookies, so
                    clearing a session key cannot invalidate a cookie already
                    issued — a captured cookie could otherwise be replayed to set
                    a password without the old one, defeating the very protection
                    `change_password` requires the current password to provide.
                    Clearing the column closes every outstanding cookie at once.

    Session-only would be replayable; DB-only would be over-broad. Neither alone.
    """
    if not session.get("pw_recovery_at"):
        return False
    until = row["recovery_grace_until"] if row else None
    if not until:
        return False
    try:
        return datetime.now() < datetime.fromisoformat(until)
    except (TypeError, ValueError):
        return False


@app.route("/login/recovery", methods=["GET", "POST"])
def login_recovery():
    """Sign in with a single-use recovery code instead of the password.

    This is the break-glass path, so it is held to the SAME limits as the front
    door rather than looser ones: it shares the failed-attempt budget, and an
    active lockout blocks it outright. A recovery path exempt from the lockout
    would not be a recovery path — it would be a way around the lockout, and an
    attacker would simply use it instead of the password form.

    The refusal is stated honestly ("locked out, try again in N minutes") rather
    than shown as a generic failure. A silent refusal here trains the real
    operator to keep burning codes against a door that cannot open.
    """
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "GET":
        return render_template("login_recovery.html")

    username = (request.form.get("username") or "").strip().lower()
    code     = request.form.get("recovery_code") or ""
    ip       = request.remote_addr or "unknown"
    ua       = request.headers.get("User-Agent", "")
    row      = _load_user_row("username", username)

    if row and row["lockout_until"]:
        try:
            until = datetime.fromisoformat(row["lockout_until"])
            if datetime.now() < until:
                mins = int((until - datetime.now()).total_seconds() // 60) + 1
                _log_login_event(username, ip, False, "locked_out", row["lockout_tier"], ua,
                                 source="recovery-code", action="login")
                return render_template("login_recovery.html", error=(
                    f"Account is locked for another {mins} minute(s). Recovery codes are "
                    f"blocked during a lockout — wait it out, then try again. Your code "
                    f"has NOT been used."))
        except (TypeError, ValueError):
            pass

    # Unknown user: same generic wording as a wrong code, so this form cannot be
    # used to discover which usernames exist.
    if not row or not row["is_active"]:
        _log_login_event(username, ip, False, "unknown_user", None, ua,
                         source="recovery-code", action="login")
        return render_template("login_recovery.html",
                               error="That username and recovery code do not match.")

    if not consume_recovery_code(row["id"], code, ip=ip):
        locked, mins, _t = _register_credential_failure(
            row, username, ip, ua,
            reason="bad_recovery_code", source="recovery-code", action="login")
        if locked:
            return render_template("login_recovery.html", error=(
                f"Too many failed attempts. Account locked for {mins} minutes."))
        return render_template("login_recovery.html",
                               error="That username and recovery code do not match.")

    # Success — the code is now spent and cannot be replayed.
    conn = _users_conn()
    try:
        conn.execute("UPDATE users SET failed_attempts=0, lockout_until=NULL, lockout_tier=0, "
                     "last_login=?, recovery_grace_until=? WHERE id=?",
                     (datetime.now().isoformat(timespec="seconds"),
                      (datetime.now() + timedelta(seconds=_RECOVERY_GRACE_SECONDS))
                      .isoformat(timespec="seconds"),
                      row["id"]))
        conn.commit()
    finally:
        conn.close()
    _log_login_event(username, ip, True, None, None, ua,
                     session_id=session.get("_id"), source="recovery-code", action="login")
    login_user(User(row))
    _stamp_session_start()
    session["pw_recovery_at"] = datetime.now().isoformat(timespec="seconds")
    _audit("login_recovery_code_used", ip=ip)
    auth_log.info("auth: %s signed in with a recovery code from %s (%d left)",
                  username, ip, recovery_codes_remaining(row["id"]))
    return redirect(url_for("change_password"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/account/unlock", methods=["GET", "POST"])
@login_required
def account_unlock():
    """Re-authenticate an idle-locked session WITHOUT ending it.

    The session is deliberately kept alive. Everything server-side survives, and
    the browser page is never navigated away from by the client-side overlay, so
    work in progress is still there afterwards. That is the whole reason this is
    a confinement rather than a logout.

    PASSWORD ONLY — recovery codes are not accepted here, and that is a security
    decision rather than an omission. A recovery code exists to recover an
    account that CANNOT be authenticated; this session is already authenticated
    and merely needs a human proven present. Accepting one would let whoever
    walked up burn a single-use code — often the one written down near the
    machine — to seize a live session. Anyone who genuinely cannot recall the
    password can sign out and use the full recovery flow, which is unchanged.

    Failures spend the SAME lockout budget as the login form. A confined session
    that could guess at the password without limit would be an unmetered oracle,
    which is precisely what _register_credential_failure exists to prevent.
    """
    row = _load_user_row("id", current_user.id)
    if not row:
        logout_user()
        session.clear()
        return redirect(url_for("login"))

    display = row["display_name"] or row["username"]
    # Carried through the whole flow so an unlock returns the operator to the page
    # they were actually on, not the dashboard. Validated on the way IN as well as
    # OUT, so an unsafe value can never survive in the form to the next attempt —
    # same handling as login's `next`.
    nxt = _safe_next(request.values.get("next"))
    if request.method == "GET":
        # View-only health summary above the form. _header_status_data() returns
        # {"status", "counts"} and NOTHING else — no address, identifier, rule
        # detail, device note, or account/auth state — so nothing sensitive can
        # reach a screen that has not yet proven a human is present. It is also
        # exception-safe: every read inside it is individually guarded and it
        # still returns a well-formed dict if the DB is unreachable, so a failed
        # summary can never block an unlock.
        #
        # GET ONLY, deliberately. The POST error paths below re-render this
        # template WITHOUT `health`, so submitting wrong passwords cannot be
        # turned into a way to poll live status on a locked screen. The template
        # guards on the variable being defined and simply omits the block.
        return render_template("unlock.html", display_name=display, next=nxt,
                               health=_header_status_data())

    ip = request.remote_addr or "unknown"
    ua = request.headers.get("User-Agent", "")
    # Form for the standalone page, JSON for the in-page overlay. Same route and
    # the same checks either way — only the transport differs.
    password = (request.form.get("password")
                or (request.get_json(silent=True) or {}).get("password") or "")

    # An account locked out by other means cannot be unlocked from here either —
    # otherwise this form would be a way around the lockout it shares a budget with.
    if row["lockout_until"]:
        try:
            until = datetime.fromisoformat(row["lockout_until"])
            if datetime.now() < until:
                mins = int((until - datetime.now()).total_seconds() // 60) + 1
                _log_login_event(row["username"], ip, False, "locked_out",
                                 row["lockout_tier"], ua,
                                 source="idle_unlock", action="unlock")
                msg = f"Account is locked for another {mins} minute(s)."
                if _wants_json():
                    return jsonify({"error": msg, "kind": "locked_out"}), 423
                return render_template("unlock.html", display_name=display, next=nxt,
                                       error=msg)
        except (TypeError, ValueError):
            pass

    if not _check_password(password, row["password_hash"]):
        locked, mins, _tier = _register_credential_failure(
            row, row["username"], ip, ua,
            reason="idle_unlock_failed", source="idle_unlock", action="unlock")
        if locked:
            # The budget is spent: a session that cannot be unlocked has no
            # reason to stay confined, so end it rather than strand the browser
            # on a form that can no longer succeed. The overlay is told to give
            # up and reload, because there is now nothing behind it to return to.
            logout_user()
            session.clear()
            if _wants_json():
                return jsonify({"error": f"Too many attempts. Account locked for "
                                         f"{mins} minute(s).",
                                "kind": "locked_out", "session_ended": True}), 423
            return redirect(url_for("login"))
        if _wants_json():
            return jsonify({"error": "Incorrect password.",
                            "kind": "credential_denied"}), 401
        return render_template("unlock.html", display_name=display, next=nxt,
                               error="Incorrect password.")

    # Success. Refresh ONLY last_activity — NOT login_at. Re-stamping login_at
    # here would let each unlock extend the absolute cap, so a session unlocked
    # often enough would never reach it and the cap would mean nothing.
    session[_SESSION_LAST_SEEN] = time.time()
    # ...except when there is no login_at at all. Since a missing stamp now fails
    # CLOSED, a session that reached here without one would re-lock immediately on
    # the next request and could never be unlocked. setdefault fills the gap
    # without ever moving an existing value, so the cap is still never extended.
    session.setdefault(_SESSION_LOGIN_AT, time.time())
    session.pop(_SESSION_LOCK_LOGGED, None)     # re-arm the once-per-lock audit
    conn = _users_conn()
    try:
        conn.execute("UPDATE users SET failed_attempts=0, lockout_until=NULL, "
                     "lockout_tier=0 WHERE id=?", (row["id"],))
        conn.commit()
    finally:
        conn.close()
    _log_login_event(row["username"], ip, True, None, None, ua,
                     session_id=session.get("_id"), source="idle_unlock", action="unlock")
    auth_log.info("auth: session unlocked for %s from %s", row["username"], ip)
    if _wants_json():
        return jsonify({"ok": True})
    return redirect(nxt or url_for("dashboard"))


@app.route("/api/session/touch", methods=["POST"])
@login_required
def api_session_touch():
    """Heartbeat proving a human is still present. Returns the time left.

    The refresh itself is not done here — _enforce_setup_and_auth() already
    stamps `last_activity` on any request that is not a background poll, and
    this endpoint is deliberately not marked as one. So reaching this handler
    at all IS the refresh; the body just reports the resulting deadline so the
    client's countdown tracks the server instead of drifting against it.

    NOT in _IDLE_LOCK_ALLOWED, and that is the point: once a session is locked
    this endpoint is blocked exactly like any other, so a stuck or hostile tab
    cannot heartbeat its way out of a lock it never proved a human for. Only a
    successful /account/unlock clears it.

    The client only calls this when real interaction has occurred since the last
    call — see static/nemesis-idle-lock.js. A timer alone would defeat the
    feature just as surely as an unmarked poller would.
    """
    last = session.get(_SESSION_LAST_SEEN) or time.time()
    login_at = session.get(_SESSION_LOGIN_AT) or time.time()
    idle_left = int(_IDLE_TIMEOUT_SECONDS - (time.time() - last))
    cap_left = int(_SESSION_MAX_SECONDS - (time.time() - login_at))
    return jsonify({
        "idle_timeout": _IDLE_TIMEOUT_SECONDS,
        # Whichever runs out first is what the client should count down to. The
        # absolute cap ends the session outright, so the overlay must not promise
        # an unlock that will not work.
        "expires_in": max(0, min(idle_left, cap_left)),
        "ends_session": cap_left <= idle_left,
    })


modules_loader.init(app, DB_PATH, MODULES_DIR)

pihole_session = {"sid": None}

def get_pihole_token():
    try:
        if pihole_session["sid"]:
            headers = {"sid": pihole_session["sid"]}
            test = requests.get(f"http://{PIHOLE_IP}/api/auth", headers=headers, timeout=3)
            if test.json().get("session", {}).get("valid"):
                return pihole_session["sid"]
        r = requests.post(f"http://{PIHOLE_IP}/api/auth", json={"password": PIHOLE_PASSWORD}, timeout=3)
        sid = r.json().get("session", {}).get("sid")
        pihole_session["sid"] = sid
        return sid
    except Exception as e:
        log.exception("get_pihole_token failed: %s", e)
        return None

def get_pihole_stats():
    try:
        token = get_pihole_token()
        if not token:
            return None
        headers = {"sid": token}
        response = requests.get(f"http://{PIHOLE_IP}/api/stats/summary", headers=headers, timeout=3)
        return response.json()
    except Exception as e:
        log.exception("get_pihole_stats failed: %s", e)
        return None

def get_clamav_status():
    try:
        # No sudo: `systemctl status` is readable unprivileged. The sudo here was
        # gratuitous, and it became actively harmful once this service stopped
        # running as an account with any sudo rights (2026-07-31 de-privileging) —
        # it would have turned a working status read into a permanent "Unknown".
        result = subprocess.run(
            ["systemctl", "status", "clamav-daemon"],
            capture_output=True, text=True
        )
        return "Running" if "active (running)" in result.stdout else "Stopped"
    except Exception as e:
        log.exception("get_clamav_status failed: %s", e)
        return "Unknown"

def get_system_status():
    try:
        cpu = subprocess.run(["top", "-bn1"], capture_output=True, text=True)
        memory = subprocess.run(["free", "-h"], capture_output=True, text=True)
        disk = subprocess.run(["df", "-h", "/"], capture_output=True, text=True)
        return {
            "cpu": cpu.stdout.split("\n")[2],
            "memory": memory.stdout.split("\n")[1],
            "disk": disk.stdout.split("\n")[1]
        }
    except Exception as e:
        log.exception("get_system_status failed: %s", e)
        return {"cpu": "Unknown", "memory": "Unknown", "disk": "Unknown"}

def get_suricata_alerts():
    now = time.monotonic()
    if now - _suricata_cache["ts"] < _SURICATA_CACHE_TTL:
        return _suricata_cache["lines"]
    try:
        result = subprocess.run(
            ["tail", "-n", "100", "/var/log/suricata/fast.log"],
            capture_output=True, text=True
        )
        lines = [l for l in result.stdout.strip().split("\n") if l]
        _suricata_cache["lines"] = lines
        _suricata_cache["ts"] = now
        return lines
    except Exception as e:
        log.exception("get_suricata_alerts failed: %s", e)
        return []

def get_db_alert(rule_id):
    try:
        conn = _dm_conn()   # HANDOFF §9 phase 1 (was sqlite3.connect(DB_PATH))
        c = conn.cursor()
        c.execute("SELECT * FROM alerts WHERE rule_id = ?", (rule_id,))
        result = c.fetchone()
        conn.close()
        return result
    except Exception as e:
        log.exception("get_db_alert failed for rule_id=%s: %s", rule_id, e)
        return None

def get_alert_counts():
    """Count today's Suricata fast.log P1/P2/P3 alerts.

    Reads a deep tail of fast.log and filters by the today date prefix.
    The previous version only sampled the last 100 lines, so a burst of P3 noise
    would push P1/P2 entries off the window and report counts as 0.
    """
    try:
        today = datetime.now().strftime("%m/%d/%Y")
        now_mono = time.monotonic()
        cached = _alert_counts_cache.get("data")
        if (cached
                and _alert_counts_cache.get("date") == today
                and now_mono - _alert_counts_cache["ts"] < _ALERT_COUNTS_CACHE_TTL):
            return cached
        result = subprocess.run(
            ["tail", "-n", "200000", "/var/log/suricata/fast.log"],
            capture_output=True, text=True, timeout=30,
        )
        prefix = today + "-"
        p1 = p2 = p3 = 0
        for line in result.stdout.splitlines():
            if not line.startswith(prefix):
                continue
            if "Priority: 1" in line:
                p1 += 1
            elif "Priority: 2" in line:
                p2 += 1
            elif "Priority: 3" in line:
                p3 += 1
        data = {"total": p1 + p2 + p3, "p1": p1, "p2": p2, "p3": p3}
        _alert_counts_cache["data"] = data
        _alert_counts_cache["ts"] = now_mono
        _alert_counts_cache["date"] = today
        log.info("get_alert_counts: today=%s p1=%d p2=%d p3=%d total=%d",
                 today, p1, p2, p3, data["total"])
        return data
    except Exception as e:
        log.exception("get_alert_counts failed: %s", e)
        return {"total": 0, "p1": 0, "p2": 0, "p3": 0}

def _get_today_drilldown():
    """Parse today's fast.log lines and aggregate by rule_id.

    Returns a dict keyed by rule_id (str) with:
      priority, rule_name, classification, count, last_ts
    Result is cached for _DRILLDOWN_CACHE_TTL seconds.
    """
    today = datetime.now().strftime("%m/%d/%Y")
    now_mono = time.monotonic()
    cached = _drilldown_cache["data"]
    if (cached
            and _drilldown_cache.get("date") == today
            and now_mono - _drilldown_cache["ts"] < _DRILLDOWN_CACHE_TTL):
        return cached

    result = subprocess.run(
        ["tail", "-n", "200000", "/var/log/suricata/fast.log"],
        capture_output=True, text=True, timeout=30,
    )
    prefix = today + "-"
    rules = {}
    for line in result.stdout.splitlines():
        if not line.startswith(prefix):
            continue
        m_rule = _FAST_LOG_RULE_RE.search(line)
        if not m_rule:
            continue
        rule_id = m_rule.group(1)
        rule_name = m_rule.group(2).strip()
        m_cls = _FAST_LOG_CLASS_RE.search(line)
        classification = m_cls.group(1).strip() if m_cls else ""
        priority = 3
        if "Priority: 1" in line:
            priority = 1
        elif "Priority: 2" in line:
            priority = 2
        ts_raw = line.split(" ", 1)[0]
        if rule_id in rules:
            rules[rule_id]["count"] += 1
            rules[rule_id]["last_ts"] = ts_raw
            if priority < rules[rule_id]["priority"]:
                rules[rule_id]["priority"] = priority
        else:
            rules[rule_id] = {
                "rule_id": rule_id,
                "priority": priority,
                "rule_name": rule_name,
                "classification": classification,
                "count": 1,
                "last_ts": ts_raw,
            }

    _drilldown_cache["data"] = rules
    _drilldown_cache["ts"] = now_mono
    _drilldown_cache["date"] = today
    return rules


def _enrich_drilldown_with_db(rules: dict) -> dict:
    """Add action/risk_level from DB to each rule entry. Returns new dict."""
    if not rules:
        return rules
    try:
        conn = _dm_conn()   # §9 batch 2 (_enrich_drilldown_with_db)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        ids = list(rules.keys())
        placeholders = ",".join("?" * len(ids))
        c.execute(
            f"SELECT rule_id, action, risk_level FROM alerts WHERE rule_id IN ({placeholders})",
            ids,
        )
        db_rows = {r["rule_id"]: dict(r) for r in c.fetchall()}
        conn.close()
    except Exception:
        log.exception("_enrich_drilldown_with_db failed")
        db_rows = {}

    enriched = {}
    for rid, entry in rules.items():
        e = dict(entry)
        db = db_rows.get(rid, {})
        e["action"] = db.get("action", "none")
        e["risk_level"] = db.get("risk_level", "")
        enriched[rid] = e
    return enriched


def _drilldown_status_reason(entry: dict) -> tuple:
    """Return (reason_short, reason_long) explaining why rule is not in the attention list."""
    action = entry.get("action", "none")
    risk = entry.get("risk_level", "")
    priority = entry.get("priority", 3)
    if action == "ignore":
        return (
            "Reviewed — ignored",
            "You previously reviewed this rule and marked it as safe to ignore. It is suppressed from the Alerts Requiring Attention list.",
        )
    if action == "block":
        return (
            "Blocked",
            "The source IP for this rule was blocked. It no longer needs active attention.",
        )
    if action == "monitor":
        return (
            "Monitoring",
            "This rule is being watched passively. It will not re-appear in the attention list unless conditions change.",
        )
    if action == "pending" and risk == "HIGH":
        return (
            "In review queue",
            "This HIGH risk rule is sitting in the Review Queue waiting for your decision.",
        )
    if action == "pending":
        return (
            "In attention list",
            "This rule is actively shown in the Alerts Requiring Attention section.",
        )
    if priority == 3:
        return (
            "P3 — informational",
            "P3 alerts are informational only. They are intentionally excluded from the attention list, AI analysis, and email alerts.",
        )
    return (
        "Not yet logged",
        "This rule fired today but has not been individually processed by the AI analysis pipeline yet. It will appear in the attention list once the watchdog picks it up.",
    )


def get_active_alerts():
    try:
        alerts = get_suricata_alerts()
        today = datetime.now().strftime("%m/%d/%Y")
        active = []
        seen_rules = set()
        for alert in reversed(alerts):
            if today not in alert:
                continue
            if "Priority: 1" not in alert and "Priority: 2" not in alert:
                continue
            parsed = parse_alert(alert)
            if not parsed or parsed["rule_id"] in seen_rules:
                continue
            seen_rules.add(parsed["rule_id"])
            db_alert = get_db_alert(parsed["rule_id"])
            if db_alert and db_alert[7] == "ignore":
                continue
            active.append(parsed)
        return active[:10]
    except Exception as e:
        log.exception("get_active_alerts failed: %s", e)
        return []

def get_review_queue():
    try:
        conn = _dm_conn()   # §9 batch 2 (get_review_queue)
        c = conn.cursor()
        c.execute("""
            SELECT rule_id, rule_name, classification, times_seen, last_seen, src_ip
            FROM alerts
            -- UPPER(COALESCE(...)): case-insensitive, matching the pattern already
            -- used by _header_status_data. alerts.risk_level is uppercase today, but a
            -- case-sensitive filter fails silently -- it returns rows, just not all of
            -- them -- so it is the wrong shape for a review queue regardless.
            WHERE UPPER(COALESCE(risk_level,'')) = 'HIGH' AND action = 'pending'
            ORDER BY last_seen DESC
            LIMIT 20
        """)
        rows = c.fetchall()
        conn.close()
        return [
            {
                "rule_id": r[0] or "",
                "rule_name": r[1] or "",
                "classification": r[2] or "",
                "times_seen": r[3] or 1,
                "last_seen": r[4] or "",
                "src_ip": r[5] or "",
            }
            for r in rows
        ]
    except Exception as e:
        log.exception("get_review_queue failed: %s", e)
        return []

def get_device_name(mac, ip):
    try:
        conn = _dm_conn()   # §9 batch 2 (get_device_name)
        c = conn.cursor()
        c.execute("SELECT friendly_name, device_type, trusted FROM devices WHERE mac = ?", (mac.lower(),))
        result = c.fetchone()
        conn.close()
        if result:
            return result
        return (ip, "Unknown", 0)
    except Exception as e:
        log.exception("get_device_name failed for mac=%s ip=%s: %s", mac, ip, e)
        return (ip, "Unknown", 0)

def get_network_devices():
    try:
        conn = _dm_conn()   # §9 batch 2 (get_network_devices)
        c = conn.cursor()
        c.execute("SELECT mac, ip, friendly_name, device_type, trusted FROM devices ORDER BY ip")
        db_devices = c.fetchall()
        conn.close()
        devices = []
        for d in db_devices:
            devices.append({
                "ip": d[1],
                "mac": d[0],
                "vendor": d[3],
                "friendly_name": d[2],
                "device_type": d[3],
                "trusted": d[4],
                "offline": False
            })
        return sorted(devices, key=lambda x: x["ip"])
    except Exception as e:
        return []

def _ensure_audit_log_table():
    """Delegates to the canonical DDL owner (§9, 2026-07-29).

    The CREATE used to live here, which made dashboard the de-facto schema owner
    of a table it merely shares — nemesis_fwd writes attribution rows to
    `audit_log` too. The DDL now sits in alert_manager/database.py beside the
    other five core tables. Kept as a thin wrapper rather than replacing the call
    sites, so the create-before-write guarantee stays exactly where it was.
    """
    database.init_audit_log_table()


def _audit(action, rule_id=None, ip=None):
    """Record a state-changing decision, attributed to the logged-in USERNAME.

    This used to store ``request.remote_addr``, which meant every row on a
    locally-reached dashboard read ``127.0.0.1``: the column is named `user`,
    but the audit log could not tell you who did anything. `_actor()` is the
    existing resolver (Flask-Login username, client IP only when nobody is
    authenticated), so audit attribution now matches what nemesis-fwd records
    for the same action instead of contradicting it.

    The `ip` argument is the TARGET of the action (the address being blocked or
    unblocked), not the client — the two were never the same field.
    """
    try:
        _ensure_audit_log_table()
        try:
            user = _actor()
        except RuntimeError:
            # No request context: scheduled sweeps and other unattended callers.
            user = "system"
        conn = _dm_conn()   # §9 batch 4 (_audit)
        try:
            c = conn.cursor()
            c.execute(
                "INSERT INTO audit_log (ts, rule_id, ip, action, user) VALUES (?, ?, ?, ?, ?)",
                (datetime.now().isoformat(), rule_id, ip, action, user),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        log.exception("audit log insert failed (action=%s rule_id=%s ip=%s): %s",
                      action, rule_id, ip, e)


def _ensure_quarantines_table():
    # Lazy self-heal — canonical DDL lives in database.init_quarantines_table()
    # (one source of truth, shared with alert_watcher's startup init). This call
    # site is kept: it fires before the UNguarded SELECT in get_active_quarantines(),
    # so the dashboard can't hit a missing-table crash regardless of whether
    # alert_watcher has started yet (no systemd ordering). Pass 0 Stage 4.
    init_quarantines_table()




def get_active_quarantines():
    _ensure_quarantines_table()
    conn = _dm_conn()   # HANDOFF §9 phase 1 (was sqlite3.connect(DB_PATH, timeout=5.0))
    try:
        c = conn.cursor()
        c.execute("""
            SELECT q.id, q.ip, q.rule_id, q.expires_at, q.created_at,
                   a.rule_name, a.priority, a.risk_level
            FROM quarantines q
            LEFT JOIN alerts a ON q.rule_id = a.rule_id
            WHERE q.status = 'active'
            ORDER BY q.created_at DESC
        """)
        rows = c.fetchall()
        # enrichment is in a separate table; query individually to keep the join simple
        enrich = {}
        if rows:
            ips = list({r[1] for r in rows})
            placeholders = ",".join("?" * len(ips))
            c.execute(
                f"SELECT ip, country, city, threat_level FROM ip_enrichment WHERE ip IN ({placeholders})",
                ips,
            )
            for ip, country, city, threat in c.fetchall():
                enrich[ip] = {"country": country, "city": city, "threat_level": threat}
    finally:
        conn.close()
    out = []
    now = datetime.now()
    for q_id, ip, rule_id, expires_at, created_at, rule_name, priority, risk_level in rows:
        try:
            exp_dt = datetime.fromisoformat(expires_at)
            minutes_remaining = max(0, int((exp_dt - now).total_seconds() / 60))
        except ValueError:
            minutes_remaining = 0
        e = enrich.get(ip, {})
        out.append({
            "id": q_id,
            "ip": ip,
            "rule_id": rule_id,
            "rule_name": rule_name or "",
            "priority": priority,
            "risk_level": risk_level or e.get("threat_level") or "",
            "country": e.get("country"),
            "city": e.get("city"),
            "expires_at": expires_at,
            "created_at": created_at,
            "minutes_remaining": minutes_remaining,
        })
    return out


def render_quarantine_banner_html(quarantines):
    if not quarantines:
        return ""
    rows = []
    for q in quarantines:
        loc_parts = [p for p in (q.get("city"), q.get("country")) if p]
        loc = f" ({html.escape(', '.join(loc_parts))})" if loc_parts else ""
        rows.append(f"""<div class="q-row">
            <div class="q-info">
                <strong style="color:#ff4444">{html.escape(q['ip'])}</strong>{loc}
                &mdash; rule {html.escape(str(q['rule_id']))} {html.escape(q['rule_name'][:60])}
                <br><span style="color:#ccc;font-size:0.85em">Expires in {q['minutes_remaining']} min</span>
            </div>
            <div class="q-actions">
                <button class="btn btn-block" onclick="confirmQuarantine({q['id']})">✓ Confirm</button>
                <button class="btn btn-ignore" onclick="liftQuarantine({q['id']}, &quot;{html.escape(q['ip'])}&quot;)">↻ Lift</button>
            </div>
        </div>""")
    return "".join(rows)


def render_alerts_html(active_alerts):
    if not active_alerts:
        return ("<tr><td colspan=5 style='color:#00ff88'>"
                "<span class='tier-text'"
                " data-beginner='✓ All clear — no threats need your attention right now'"
                " data-intermediate='✓ No active P1/P2 alerts requiring attention'"
                " data-pro='✓ No active P1/P2'"
                ">✓ No active P1/P2 alerts requiring attention</span></td></tr>")
    parts = []
    for alert in active_alerts:
        priority = alert["priority"]
        color = "#ff4444" if priority == 1 else "#ffaa00"
        label = "P1 CRITICAL" if priority == 1 else "P2 HIGH"
        rule_name = alert["rule_name"][:50] if alert["rule_name"] else "Unknown"
        timestamp = alert.get("timestamp", "") or "—"
        onclick = html.escape(f"viewAlert({json.dumps(str(alert['rule_id']))}, {json.dumps(alert['raw'])})")
        parts.append(f"""<tr class="hw-clickable" style="cursor:pointer" onclick="{onclick}">
            <td><span style="color:{color}">{label}</span></td>
            <td style="font-size:0.8em;white-space:nowrap;color:#ccc">{html.escape(timestamp)}</td>
            <td style="font-size:0.8em">{html.escape(rule_name)}</td>
            <td style="font-size:0.8em">{html.escape(alert["src_ip"])}</td>
            <td style="color:#00d4ff;font-size:0.8em;padding-left:6px">▸</td>
        </tr>""")
    return "".join(parts)

def render_review_queue_html(items):
    if not items:
        return ("<tr><td colspan=6 style='color:#00ff88;padding:10px'>"
                "<span class='tier-text'"
                " data-beginner='✓ Nothing suspicious needs your review right now'"
                " data-intermediate='✓ Review queue is clear — no HIGH risk alerts pending'"
                " data-pro='✓ Queue empty'"
                ">✓ Review queue is clear — no HIGH risk alerts pending</span></td></tr>")
    parts = []
    for item in items:
        ts = item["last_seen"][:16].replace("T", " ") if item["last_seen"] else "—"
        rule_name = item["rule_name"][:50] if item["rule_name"] else "Unknown"
        classification = item["classification"][:35] if item["classification"] else "—"
        src_ip = item["src_ip"] or "—"
        onclick = html.escape(f"viewAlert({json.dumps(str(item['rule_id']))}, {json.dumps('')})")
        parts.append(f"""<tr class="hw-clickable" style="cursor:pointer" onclick="{onclick}">
            <td style="font-size:0.8em;white-space:nowrap;color:#ccc">{html.escape(ts)}</td>
            <td style="font-size:0.8em">{html.escape(rule_name)}</td>
            <td style="font-size:0.8em">{html.escape(src_ip)}</td>
            <td style="font-size:0.8em;color:#ccc">{html.escape(classification)}</td>
            <td style="font-size:0.8em;text-align:center">{html.escape(str(item['times_seen']))}</td>
            <td style="color:#ff8800;font-size:0.8em;padding-left:6px">▸</td>
        </tr>""")
    return "".join(parts)

def render_devices_html(devices):
    parts = []
    for d in devices:
        trusted = d.get("trusted", 0)
        offline = d.get("offline", False)
        trust_icon = "✅" if trusted else "❓"
        status_color = "#888" if offline else "#eee"
        status = " (offline)" if offline else ""
        onclick = html.escape(f"editDevice({json.dumps(d['mac'])}, {json.dumps(d['friendly_name'])}, {json.dumps(d['device_type'])})")
        parts.append(f"""<tr style="color:{status_color}">
            <td>{html.escape(d["ip"])}{status}</td>
            <td>
                <span id="name-{d["mac"].replace(":","")}">{html.escape(d["friendly_name"])}</span>
                <button onclick="{onclick}"
                    style="background:none;border:1px solid #00d4ff;color:#00d4ff;padding:2px 6px;cursor:pointer;border-radius:3px;margin-left:5px;font-size:0.75em">
                    ✏️</button>
            </td>
            <td style="font-size:0.8em">{html.escape(d["device_type"])}</td>
            <td style="font-size:0.8em">{html.escape(d["mac"])}</td>
            <td>{trust_icon}</td>
        </tr>""")
    return "".join(parts)

def get_pihole_summary():
    stats = get_pihole_stats()
    if not stats:
        return {"total": "N/A", "blocked": "N/A", "percent": "N/A"}
    q = stats.get("queries", {})
    percent = q.get("percent_blocked", "N/A")
    if isinstance(percent, (int, float)):
        percent = f"{round(percent, 1):g}"
    return {
        "total": q.get("total", "N/A"),
        "blocked": q.get("blocked", "N/A"),
        "percent": percent,
    }

def _get_incident_stats():
    try:
        from modules.ai_engine import get_incident_banner_html as _ibanner, get_incident_state as _istate
        return {
            "incident_banner_html": _ibanner(),
            "incident_state": _istate(),
        }
    except Exception:
        return {"incident_banner_html": "", "incident_state": {}}

@app.route("/api/stats")
def api_stats():
    quarantines = get_active_quarantines()
    try:
        hw_live = hw_monitor.get_live_metrics()
    except Exception as e:
        log.exception("hw_monitor.get_live_metrics failed: %s", e)
        hw_live = None
    alerts_24h = get_24h_alert_stats()
    svc_status = get_services_status()
    health = compute_health_score(hw_live, alerts_24h, svc_status)
    review_queue = get_review_queue()
    vpn = get_vpn_status()
    vpn_status_str = vpn.get("status", "Disconnected")
    try:
        hw_alerts = hw_monitor.get_hw_alerts()
    except Exception:
        hw_alerts = []
    return jsonify({
        "now": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "pihole": get_pihole_summary(),
        "alert_counts": get_alert_counts(),
        "alerts_html": render_alerts_html(get_active_alerts()),
        "devices_html": render_devices_html(get_network_devices()),
        "quarantines": quarantines,
        "quarantine_banner_html": render_quarantine_banner_html(quarantines),
        "hw": hw_live,
        "hw_alerts": hw_alerts,
        "alert_24h": {"total": alerts_24h["total"], "color": alert_color(alerts_24h["total"])},
        "health": {"score": health["score"], "color": health["color"]},
        "review_queue_count": len(review_queue),
        "review_queue_html": render_review_queue_html(review_queue),
        "vpn": {
            "provider": vpn.get("provider"),
            "status": vpn_status_str,
            "vpn_ip": vpn.get("vpn_ip"),
        },
        "module_cards_html": "".join(
            h for name, h in modules_loader.get_module_cards()
            if name != "community_queue"
        ),
        "community_queue_badge": (
            (lambda m: m.get_dashboard_card() or "")(
                modules_loader.get_loaded_modules().get("community_queue")
            )
            if modules_loader.get_loaded_modules().get("community_queue")
            else ""
        ),
        **_get_incident_stats(),
    })


@app.route("/api/firewall/drilldown")
def api_firewall_drilldown():
    kind = request.args.get("kind", "total")
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        per_page = max(1, min(500, int(request.args.get("per_page", 10))))
    except (ValueError, TypeError):
        per_page = 10

    try:
        rules = _get_today_drilldown()
        rules = _enrich_drilldown_with_db(rules)

        if kind == "p1":
            filtered = [e for e in rules.values() if e["priority"] == 1]
        elif kind == "p2":
            filtered = [e for e in rules.values() if e["priority"] == 2]
        elif kind == "review_queue":
            # Show HIGH risk_level regardless of action, pending first
            filtered = [e for e in rules.values() if e.get("risk_level") == "HIGH"]
            filtered.sort(key=lambda e: (0 if e.get("action") == "pending" else 1, e["rule_id"]))
        else:  # total
            filtered = list(rules.values())

        if kind not in ("review_queue",):
            filtered.sort(key=lambda e: (-e["count"], e["rule_id"]))

        total_rules = len(filtered)
        total_pages = max(1, (total_rules + per_page - 1) // per_page)
        page = min(page, total_pages)
        start = (page - 1) * per_page
        page_rows = filtered[start:start + per_page]

        rows_html = []
        for e in page_rows:
            reason_short, reason_long = _drilldown_status_reason(e)
            pri_label = {1: "P1", 2: "P2", 3: "P3"}.get(e["priority"], "P?")
            pri_color = {1: "#ff4444", 2: "#ff8800", 3: "#888"}.get(e["priority"], "#888")
            action = e.get("action", "none")
            action_color = {
                "ignore": "#888", "block": "#ff4444",
                "monitor": "#00d4ff", "pending": "#ff8800",
            }.get(action, "#666")
            note_html = (
                f'<div style="color:#ccc;font-size:0.8em;margin-top:2px;font-style:italic">'
                f'{html.escape(e["note"][:120])}</div>'
            ) if e.get("note") else ""
            rows_html.append(
                f'<tr>'
                f'<td style="color:{pri_color};font-weight:bold">{pri_label}</td>'
                f'<td style="font-family:monospace;color:#ccc">{html.escape(e["rule_id"])}</td>'
                f'<td style="color:#eee">{html.escape(e["rule_name"][:60])}{note_html}</td>'
                f'<td style="color:#ccc;font-size:0.85em">{html.escape(e["classification"][:40])}</td>'
                f'<td style="text-align:right;color:#00d4ff">{e["count"]}</td>'
                f'<td style="color:{action_color};font-size:0.85em">{html.escape(reason_short)}'
                f'<span class="tier-text" style="display:none" '
                f'data-beginner="" data-intermediate="" data-pro=""></span>'
                f'</td>'
                f'<td style="color:#777;font-size:0.8em" title="{html.escape(reason_long)}" class="dd-reason-cell">'
                f'<span class="tier-text" '
                f'data-beginner="{html.escape(reason_long)}" '
                f'data-intermediate="{html.escape(reason_short)}" '
                f'data-pro="{html.escape(reason_short)}">'
                f'{html.escape(reason_short)}</span>'
                f'</td>'
                f'</tr>'
            )

        table_html = (
            '<table style="width:100%;border-collapse:collapse;font-size:0.88em">'
            '<thead><tr style="color:#00d4ff;border-bottom:1px solid #333">'
            '<th style="text-align:left;padding:4px 6px">Pri</th>'
            '<th style="text-align:left;padding:4px 6px">Rule ID</th>'
            '<th style="text-align:left;padding:4px 6px">Rule Name</th>'
            '<th style="text-align:left;padding:4px 6px">Classification</th>'
            '<th style="text-align:right;padding:4px 6px">Hits</th>'
            '<th style="text-align:left;padding:4px 6px" colspan="2">Status</th>'
            '</tr></thead>'
            '<tbody>' + "".join(rows_html) + '</tbody>'
            '</table>'
        ) if page_rows else '<p style="color:#ccc">No rules found for today.</p>'

        return jsonify({
            "ok": True,
            "kind": kind,
            "total_rules": total_rules,
            "total_pages": total_pages,
            "page": page,
            "per_page": per_page,
            "table_html": table_html,
        })
    except Exception:
        log.exception("api_firewall_drilldown failed")
        return jsonify({"ok": False, "error": "Server error"}), 500


def get_24h_alert_stats():
    """Count hardware/system alerts emitted by the watchdog in the last 24h.

    Sources: thermal/fan threshold breaches ("HW alert sent: <key>" or
    "HW alert email failed: <key>") and service-down escalations
    ("Sent alert email for <svc>" or "Failed to send alert email for <svc>").
    Suricata network alerts are intentionally excluded — those are surfaced
    by the AI Firewall section's get_alert_counts().
    """
    now = time.monotonic()
    cached = _alert_24h_cache["data"]
    if cached and now - _alert_24h_cache["ts"] < _ALERT_24H_CACHE_TTL:
        return cached
    cutoff = datetime.now() - timedelta(days=1)
    thermal_fan = service_down = 0
    # breakdown[key] = {"count": N, "occurrences": [{"ts": str, "breach": str|None}, ...]}
    breakdown = {}
    try:
        with open(WATCHDOG_LOG_PATH) as f:
            for line in f:
                try:
                    ts = datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    continue
                if ts < cutoff:
                    continue
                ts_str = line[:19]

                m = _HW_ALERT_SENT_RE.search(line)
                if m:
                    thermal_fan += 1
                    key = f"thermal/fan: {m.group(1)}"
                    occ = {"ts": ts_str, "breach": m.group(2)}
                    entry = breakdown.setdefault(key, {"count": 0, "occurrences": []})
                    entry["count"] += 1
                    entry["occurrences"].append(occ)
                    continue

                m = _HW_ALERT_FAILED_RE.search(line)
                if m:
                    thermal_fan += 1
                    key = f"thermal/fan: {m.group(1)}"
                    occ = {"ts": ts_str, "breach": None}
                    entry = breakdown.setdefault(key, {"count": 0, "occurrences": []})
                    entry["count"] += 1
                    entry["occurrences"].append(occ)
                    continue

                m = _SVC_ALERT_RE.search(line)
                if m:
                    service_down += 1
                    key = f"service down: {m.group(1)}"
                    occ = {"ts": ts_str, "breach": None}
                    entry = breakdown.setdefault(key, {"count": 0, "occurrences": []})
                    entry["count"] += 1
                    entry["occurrences"].append(occ)
    except FileNotFoundError:
        log.warning("get_24h_alert_stats: %s not found", WATCHDOG_LOG_PATH)
    except Exception as e:
        log.exception("get_24h_alert_stats failed: %s", e)

    # Most recent first; cap at 50 occurrences per key to limit JSON size
    for entry in breakdown.values():
        entry["occurrences"] = list(reversed(entry["occurrences"]))[:50]

    bd_list = sorted(
        ({"type": k, "count": v["count"], "occurrences": v["occurrences"]}
         for k, v in breakdown.items()),
        key=lambda x: -x["count"],
    )
    data = {
        "total": thermal_fan + service_down,
        "thermal_fan": thermal_fan,
        "service_down": service_down,
        "breakdown": bd_list,
    }
    _alert_24h_cache["data"] = data
    _alert_24h_cache["ts"] = now
    return data


def alert_color(total):
    if total == 0:
        return "green"
    if total <= 5:
        return "yellow"
    return "red"


def get_services_status():
    now = time.monotonic()
    cached = _svc_cache["data"]
    if cached and now - _svc_cache["ts"] < _SVC_CACHE_TTL:
        return cached
    results = []
    for svc in HEALTH_SERVICES:
        try:
            r = subprocess.run(
                ["systemctl", "is-active", "--quiet", svc],
                timeout=5,
            )
            results.append({"name": svc, "active": r.returncode == 0})
        except Exception:
            results.append({"name": svc, "active": False})
    data = {
        "active": sum(1 for r in results if r["active"]),
        "total": len(results),
        "services": results,
    }
    _svc_cache["data"] = data
    _svc_cache["ts"] = now
    return data


def _header_status_data() -> dict:
    """Aggregate global health into one verdict for the header status light.
    Read-only (no schema changes). RED dominates AMBER dominates GREEN."""
    counts = {"critical": 0, "high": 0, "medium": 0, "services_down": 0,
              "open_tickets": 0, "findings_open": 0, "findings_high": 0}
    quar_pending = 0
    diag_verdict = None
    hw = None
    try:
        conn = _dm_conn()   # §9 batch 2 (_header_status_data)
        c = conn.cursor()

        def _alerts(level):
            try:
                return c.execute(
                    "SELECT COUNT(*) FROM alerts WHERE action='pending' "
                    "AND UPPER(COALESCE(risk_level,''))=?", (level,)).fetchone()[0]
            except Exception:
                return 0
        counts["critical"] = _alerts("CRITICAL")
        counts["high"]     = _alerts("HIGH")
        counts["medium"]   = _alerts("MEDIUM")
        try:
            counts["open_tickets"] = c.execute(
                "SELECT COUNT(*) FROM tickets WHERE type='ticket' "
                "AND LOWER(COALESCE(status,'')) NOT IN ('closed','resolved')").fetchone()[0]
        except Exception:
            pass
        # RENAMED 2026-08-02: this was `canary_trips`, which is not what it counts.
        # It counts EVERY unreviewed malware finding regardless of layer — the
        # canary layer merely happened to be 100% of them, so the misnomer was
        # invisible. A name that is only accurate by coincidence is a name that
        # will mislead the first time the coincidence ends.
        #
        # Split by severity because the old single bucket also drove the header
        # light: any unreviewed finding, of any severity, pinned it RED forever.
        # An unreviewed INFO/LOW finding is a queue to work through, not an active
        # incident, and a light that is permanently red communicates nothing.
        try:
            counts["findings_high"] = c.execute(
                "SELECT COUNT(*) FROM malware_findings "
                "WHERE status IN ('new','investigating') "
                "AND UPPER(COALESCE(severity,'')) IN ('HIGH','CRITICAL')").fetchone()[0]
            counts["findings_open"] = c.execute(
                "SELECT COUNT(*) FROM malware_findings WHERE status IN ('new','investigating')"
            ).fetchone()[0]
        except Exception:
            pass
        try:
            quar_pending = c.execute(
                "SELECT COUNT(*) FROM quarantines WHERE status='active'").fetchone()[0]
        except Exception:
            pass
        try:
            r = c.execute("SELECT verdict FROM diagnostics_connectivity_samples "
                          "ORDER BY ts DESC LIMIT 1").fetchone()
            diag_verdict = r[0] if r else None
        except Exception:
            pass
        # Hardware snapshot for the lock-screen card. DISPLAY-ONLY — see the
        # note above the return.
        #
        # READ THE TABLE, not hw_monitor.get_live_metrics(). That helper spawns
        # `sensors -u` and `nvidia-smi` on every call: measured 98ms against
        # 0.4ms for this indexed SELECT, a 245x difference. The lock screen
        # re-renders itself every 30s and is reachable before anyone has proven
        # a human is present, so a per-render pair of subprocess spawns is both
        # slow and an avoidable thing to hand an unattended screen. hw_monitor
        # already writes this row every SAMPLE_INTERVAL (300s), so the data is
        # at most five minutes old — exactly the "snapshot" the card says it is.
        #
        # device_id='local' pins this to THIS box. Without it the newest row can
        # belong to a remote agent, and the lock screen would report someone
        # else's hardware as though it were this machine's.
        try:
            r = c.execute(
                "SELECT cpu_percent, ram_used_gb, cpu_temp FROM hw_metrics "
                "WHERE device_id='local' ORDER BY timestamp DESC LIMIT 1").fetchone()
            if r:
                cpu_pct, ram_gb, cpu_t = r
                # RAM as a PERCENTAGE, not the stored GB figure. Measured here:
                # 16.28 GB used reads as alarming alone and is in fact 26% of
                # 62.25 GB. A bare GB number cannot be read without knowing the
                # total, which this card has no room for — and it would mean
                # something different on every install.
                ram_pct = None
                if ram_gb is not None:
                    total_gb = psutil.virtual_memory().total / (1024 ** 3)
                    if total_gb > 0:
                        ram_pct = round(100.0 * ram_gb / total_gb)
                # Each value stays independently None-able: a VM reports CPU and
                # RAM but usually has no thermal sensor at all, so cpu_temp being
                # absent must not blank the other two.
                hw = {"cpu_percent": round(cpu_pct) if cpu_pct is not None else None,
                      "ram_percent": ram_pct,
                      "cpu_temp":    round(cpu_t) if cpu_t is not None else None}
        except Exception:
            pass
        conn.close()
    except Exception:
        auth_log.exception("header status: db read failed")

    try:
        svc = get_services_status()
        counts["services_down"] = max(0, svc.get("total", 0) - svc.get("active", 0))
    except Exception:
        pass

    red = bool(counts["critical"] or counts["high"] or counts["services_down"]
               or counts["findings_high"] or quar_pending or diag_verdict == "LOCAL_FAIL")
    amber = bool(counts["medium"] or counts["open_tickets"] or counts["findings_open"]
                 or diag_verdict in ("DEGRADED", "UPSTREAM_FAIL"))
    status = "red" if red else ("amber" if amber else "green")
    # `hw` is DISPLAY-ONLY and deliberately absent from the red/amber decision
    # above. A hot CPU is a hardware-health matter the hardware card already
    # owns; folding it in here would make the global header light — present on
    # every page, not just this one — go red for a reason unrelated to the
    # security posture that light exists to report.
    return {"status": status, "counts": counts, "hw": hw}


@app.route("/api/header/status")
def api_header_status():
    """Global health verdict for the header light (auth-guarded; no exemption)."""
    return jsonify(_header_status_data())


# ── Agent enrollment approval (owner action; auth-guarded dashboard routes) ────
@app.route("/api/agent/<device_id>/approve", methods=["POST"])
def api_agent_approve(device_id):
    try:
        conn = _dm_conn()   # §9 batch 4 (api_agent_approve)
        # Read the PRIOR status BEFORE the UPDATE. Reading it afterwards would
        # always return 'approved' and the trust-boundary crossing would be
        # undetectable — the check would run, report nothing, and look correct.
        prior = conn.execute(
            "SELECT enrollment_status FROM agent_devices WHERE device_id=?",
            (device_id,)).fetchone()
        prior_status = (prior[0] if prior else "") or ""
        conn.execute(
            "UPDATE agent_devices SET enrollment_status='approved', enrolled_by=?, enrolled_at=? "
            "WHERE device_id=?",
            (_actor(), datetime.now().isoformat(timespec="seconds"), device_id))
        conn.commit()
        conn.close()
        _audit(action="agent_approve", rule_id=device_id)

        # ── trust-boundary crossing → MANDATORY scan ──
        # A device returning from 'revoked' or 'uninstalled' is being readmitted
        # after trust was deliberately withdrawn. The length of the gap is
        # irrelevant: an hour is enough to introduce something, and the existing
        # time-based triggers cannot help (extended_absence needs 24h, and
        # first_connect never fires because the agent_devices row survived the
        # revocation).
        resp = {"ok": True, "status": "approved"}
        if prior_status in hw_monitor.TRUST_WITHDRAWN_STATUSES:
            queued, why = hw_monitor.queue_reinstatement_scan(
                device_id, prior_status, _actor())
            resp["reinstated_from"] = prior_status
            resp["mandatory_scan"] = why
            if not queued and not why.startswith("already"):
                # Surfaced, not swallowed: readmitting a device whose mandatory
                # scan failed to queue is the one outcome the operator must see.
                log.error("device %s readmitted from %s but its mandatory scan "
                          "did NOT queue: %s", device_id, prior_status, why)
        return jsonify(resp)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/<device_id>/reject", methods=["POST"])
def api_agent_reject(device_id):
    try:
        conn = _dm_conn()   # §9 batch 4 (api_agent_reject)
        conn.execute("UPDATE agent_devices SET enrollment_status='rejected' WHERE device_id=?",
                     (device_id,))
        conn.commit()
        conn.close()
        _audit(action="agent_reject", rule_id=device_id)
        return jsonify({"ok": True, "status": "rejected"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/<device_id>/revoke", methods=["POST"])
def api_agent_revoke(device_id):
    """Owner action (auth-gated): withdraw an ALREADY-APPROVED device.

    Deliberately a separate route from /reject rather than a reuse of it.
    "Rejected" means an enrollment request was denied; "revoked" means a device
    that WAS trusted has been withdrawn. Collapsing the two destroys that
    distinction in the audit trail, which is the one place it matters most.

    Security posture is identical to its siblings by design -- POST-only,
    auth-gated (absent from _AUTH_EXEMPT), parameterized SQL, audited. The
    route-audit defect signature is sibling routes whose posture DIVERGES, not
    sibling routes existing; same guard, different semantics is correct.

    No server-side enforcement change is needed: hw_monitor's _agent_approved()
    tests == "approved", so any other status stops that device's heartbeats
    within one poll interval.
    """
    try:
        conn = _dm_conn()   # §9 batch 4 (api_agent_revoke)
        # Timestamp + actor recorded ON THE ROW, mirroring the uninstall path's
        # uninstalled_at/uninstalled_by. Without these the revocation left no mark
        # on the device itself, so nothing could later ask "was this work queued
        # before this device was revoked?" — the question a trust-boundary check
        # has to answer. The _audit call below still records the event; this
        # records the STATE, which is what per-device logic reads.
        conn.execute("UPDATE agent_devices SET enrollment_status='revoked', "
                     "revoked_at=?, revoked_by=? WHERE device_id=?",
                     (datetime.now().isoformat(timespec="seconds"), _actor(),
                      device_id))
        conn.commit()
        conn.close()
        _audit(action="agent_revoke", rule_id=device_id)
        return jsonify({"ok": True, "status": "revoked"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Windows installer generator (token-based auto-approve enrollment) ─────────
#: Tailscale hands out addresses from the CGNAT range. An agent target inside it
#: reaches the server through WireGuard; anything else is cleartext HTTP on the
#: wire, because nothing in this product terminates TLS.
_TAILNET_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _classify_transport(host: str):
    """(verdict, detail) for an agent-facing host. Never guesses.

    verdict is "tailnet", "cleartext", or "unknown". A hostname cannot be
    classified without resolving it, and a DNS lookup does not belong in a
    request path — so it returns "unknown" EXPLICITLY rather than assuming
    either answer. An unclassifiable host is not evidence of safety.
    """
    bare = (host or "").split("://")[-1].split("/")[0].split(":")[0].strip()
    if not bare:
        return "unknown", "no host to classify"
    try:
        ip = ipaddress.ip_address(bare)
    except ValueError:
        return "unknown", "host is a name, not an address — cannot classify without DNS"
    if ip in _TAILNET_CGNAT:
        return "tailnet", "inside the Tailscale CGNAT range"
    if ip.is_loopback:
        return "tailnet", "loopback — never leaves the machine"
    return "cleartext", "not a tailnet address — traffic to it is unencrypted"


def _nemesis_tailnet_host() -> str:
    """Bare host to bake into a generated installer as the agent's server target.
    Media + enrollment are intended to ride the TAILNET (ADR 0011), so prefer the
    tailnet address: env NEMESIS_TAILNET_ADDR, else NEMESIS_SERVER_IP, else the host
    the dashboard was reached on (Rule-8 safe — no hardcoded box specifics). The agent
    posts to this host on the hw_monitor port (5001).

    The env vars are not merely a convenience. Without one, this falls back to the
    host of whatever request happened to fetch the installer — so whether an agent
    talks over WireGuard or in cleartext for its entire life is decided by a URL,
    silently, with nothing recording which was chosen. Configuring
    NEMESIS_TAILNET_ADDR makes that a deliberate decision instead of an accident.
    The fallback is kept because a LAN-only deployment with no tailnet is a
    supported configuration — but it now says so out loud.
    """
    configured = (os.environ.get("NEMESIS_TAILNET_ADDR", "").strip()
                  or os.environ.get("NEMESIS_SERVER_IP", "").strip())
    if configured:
        return configured.split(":")[0]

    host = (request.host or "127.0.0.1").split(":")[0]
    verdict, detail = _classify_transport(host)
    if verdict != "tailnet":
        log.warning(
            "installer target resolved from the request host and is %s (%s); "
            "agents built from it will use that address for every heartbeat. "
            "Set NEMESIS_TAILNET_ADDR to make this deterministic.",
            verdict, detail)
    return host


def _valid_installer_token(token):
    """Return the token row if it exists, is not revoked, not expired, and not yet used.
    A spent (used), revoked, or expired token HARD-FAILS the download — no fallback
    (ADR 0011 immediate hardening; Phase 1 delivery, Fork 3 uses-check)."""
    try:
        conn = _dm_conn()   # §9 batch 2 (_valid_installer_token)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM enrollment_tokens "
            "WHERE token=? AND revoked=0 AND uses < max_uses AND expires_at > ?",
            (token, time.time())).fetchone()
        conn.close()
        return row
    except Exception:
        return None


def _render_install_conf(server_host: str, token: str, hint: str,
                         preauth_key: str = "", poll_interval=None) -> str:
    """Build the per-installer nemesis_install.conf baked into the served frozen-exe
    zip. Matches the frozen installer's reader (nemesis_agent/installer_gui.py
    `_read_baked_config`). `preauth_key` = single-use Tailscale pre-auth key; the
    installer MUST consume-and-delete this conf right after reading it so the live
    credentials do not linger in plaintext on disk (installer-consumption follow-up,
    see installer-roadmap). Rule-8: the live token/key never hit logs."""
    safe_hint = re.sub(r"[^A-Za-z0-9 _.-]", "", hint or "Windows Device")[:60] or "Windows Device"
    lines = ["[nemesis]",
             f"nemesis_ip = {server_host}",
             "nemesis_port = 5001",
             f"device_name = {safe_hint}",
             f"enrollment_token = {token}"]
    # Trust anchor for server->agent task signing (ADR 0004 Stage 1). Delivered
    # HERE, in the token-gated download, rather than over the wire at enrollment:
    # pinning on first contact is trust-on-first-use, and an attacker who owns the
    # network at that exact moment can pin their own key. This file already travels
    # with a credential the operator handed over deliberately, so the anchor arrives
    # by the same out-of-band path at no extra cost.
    #
    # Base64 DER, not PEM: this is INI read by configparser, where a multi-line PEM
    # needs continuation-line indentation that breaks the moment anyone hand-edits
    # the sidecar.
    #
    # Best-effort by design — a missing key must not break installer generation.
    # An agent that pins nothing simply executes no tasks, which is exactly what
    # every agent does today, so the degradation is a no-op rather than a hole.
    try:
        import server_keys
        lines.append(f"server_public_key = {server_keys.public_key_b64()}")
    except Exception as exc:
        log.warning("no server public key to bake into the installer conf (%s); "
                    "agents from this installer will not accept signed tasks", exc)
    if preauth_key:
        lines.append(f"preauth_key = {preauth_key}")
    if poll_interval:
        lines.append(f"poll_interval = {int(poll_interval)}")
    return "\n".join(lines) + "\n"


@app.route("/api/agent/installer/generate", methods=["POST"])
def api_agent_installer_generate():
    """Owner action (auth-gated): mint a single-use, short-TTL enrollment token and
    return the download link for the v1.0.6 FROZEN-exe installer bundle (zip = generic
    frozen exe + a per-installer nemesis_install.conf). Optionally bakes a single-use
    Tailscale pre-auth key (admin-pasted) so the agent self-joins the tailnet. The
    legacy system-Python .ps1 path is RETIRED for this flow (PL-8). Rule-8: the live
    token/pre-auth-key are never logged."""
    data = request.get_json(silent=True) or request.form
    hint = (data.get("device_name_hint") or "Windows Device").strip()[:60] or "Windows Device"
    # Tailscale pre-auth key — HYBRID (ADR 0011): prefer programmatic minting via the
    # Tailscale OAuth API; on failure fall back to an admin-pasted key; else no baked key
    # (the installer hand-joins via _ensure_tailscale). NEVER hard-fail generate. Rule 8:
    # the minted key / client_secret are never logged.
    pasted_key = (data.get("preauth_key") or "").strip()[:256]
    preauth_key = ""
    preauth_source = "none"
    preauth_warning = ""
    if tailscale_api.is_configured():
        try:
            minted, _kid = tailscale_api.mint_preauth_key(device_hint=hint, ttl_seconds=2 * 3600)
            preauth_key, preauth_source = minted, "api"
        except tailscale_api.TailscaleAPIError as e:
            _audit(action="tailscale_key_mint_fail", rule_id=str(e)[:40])
            if pasted_key:
                preauth_key, preauth_source = pasted_key, "pasted_fallback"
            else:
                preauth_source = "none"
                preauth_warning = ("Tailscale key minting is unavailable right now — this "
                                   "installer has no baked key, so the device will need a "
                                   "manual tailnet join.")
    elif pasted_key:
        preauth_key, preauth_source = pasted_key, "pasted"
    # Auto-approve is OPT-IN (ADR 0012): default 0 (manual approval via Settings ->
    # Devices). Only an explicit truthy flag from the form flips it to 1. Absent or
    # falsy -> 0. Handles JSON bool/int and form strings.
    _aa = data.get("auto_approve")
    auto_approve = 1 if (_aa in (True, 1)
                         or str(_aa).strip().lower() in ("1", "true", "on", "yes")) else 0
    # Optional custom heartbeat cadence (seconds). Floor-clamped at 15s so a mis-typed
    # tiny value can't hammer the server; blank/invalid => NULL (agent uses its 300s
    # default). The agent re-clamps on read (defence in depth).
    _pi = str(data.get("poll_interval") or "").strip()
    poll_interval = None
    if _pi:
        try:
            poll_interval = max(15, int(float(_pi)))
        except (TypeError, ValueError):
            poll_interval = None
    token   = secrets.token_hex(16)
    now     = time.time()
    expires = now + 2 * 3600   # short TTL (ADR 0011: 1-2h), was 24h
    creator = current_user.username if current_user.is_authenticated else "unknown"
    try:
        conn = _dm_conn()   # §9 batch 4 (api_agent_installer_generate)
        conn.execute(
            "INSERT INTO enrollment_tokens "
            "(token, created_by, created_at, expires_at, max_uses, uses, auto_approve, "
            " device_name_hint, revoked, preauth_key, poll_interval) VALUES (?,?,?,?,1,0,?,?,0,?,?)",
            (token, creator, now, expires, auto_approve, hint, preauth_key or None, poll_interval))
        conn.commit()
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    # Rule-8: log the token prefix only; NEVER the pre-auth key.
    _audit(action="installer_token_generate", rule_id=token[:8])
    # Shareable links should ride the TAILNET (ADR 0011). NEMESIS_PUBLIC_URL overrides
    # (operator sets it to the tailnet URL); else build from NEMESIS_TAILNET_ADDR; else
    # fall back to the request host. (:80-cleartext->tailnet-only enforcement = infra
    # punchlist, not code — see PUNCHLIST.md.)
    tailnet_addr = os.environ.get("NEMESIS_TAILNET_ADDR", "").strip()
    base = (os.environ.get("NEMESIS_PUBLIC_URL", "").strip().rstrip("/")
            or (f"http://{tailnet_addr}" if tailnet_addr else "")
            or request.host_url.rstrip("/"))
    # Transport verdict for THIS link, surfaced to the operator at the one moment
    # they can still act on it. Nothing in this product terminates TLS, so a
    # non-tailnet target means the installer download (which carries a live
    # enrollment token and pre-auth key) and every later heartbeat cross the
    # network in clear. Previously this was decided silently by whichever URL was
    # in play, and nothing anywhere recorded the outcome.
    _t_verdict, _t_detail = _classify_transport(base)
    transport_warning = ""
    if _t_verdict == "cleartext":
        transport_warning = (
            "This link points at an address that is not on your tailnet, and Nemesis "
            "does not use HTTPS — the download (which contains a one-time enrollment "
            "token and Tailscale key) and this device's later reporting will not be "
            "encrypted. Set NEMESIS_TAILNET_ADDR, or share a tailnet link instead.")
    elif _t_verdict == "unknown":
        transport_warning = (
            "Could not confirm whether this link rides your tailnet, so its traffic "
            "may not be encrypted. Set NEMESIS_TAILNET_ADDR to a tailnet address to "
            "make this certain.")
    if transport_warning:
        log.warning("installer link transport: %s (%s)", _t_verdict, _t_detail)
    return jsonify({
        "ok": True,
        "token": token,
        "transport": _t_verdict,
        "transport_warning": transport_warning,
        "device_name_hint": hint,
        "expires_at": expires,
        "preauth_key_baked": bool(preauth_key),
        "preauth_source": preauth_source,       # api | pasted_fallback | pasted | none
        "preauth_warning": preauth_warning,     # non-empty => show the user a caution note
        "zip_url": f"{base}/install/windows/{token}/zip",   # primary: frozen exe + baked conf
        "exe_url": f"{base}/install/windows/{token}/exe",   # advanced: generic exe, no baked conf
    })


@app.route("/api/health")
def api_health():
    """PUBLIC (auth-exempt): lightweight reachability probe for the agent installer to
    verify the server is reachable before it starts installing. Version is env-driven
    (Rule 8 — no hardcoded box specifics); defaults to the current agent version."""
    return jsonify({"status": "ok",
                    "version": os.environ.get("NEMESIS_AGENT_VERSION", "1.0.8")})


@app.route("/install/windows/<token>")
def install_windows_download(token):
    """PUBLIC: the legacy system-Python PowerShell installer is RETIRED for this flow
    (PL-8 — it required Python the clean box lacks). Old links hard-fail with a pointer
    to the frozen-exe bundle (the /zip link your admin generated)."""
    return Response(
        "The PowerShell installer has been retired in v1.0.6. Ask your administrator "
        "to generate a new installer link — it now delivers the self-contained Windows "
        "installer (no Python required).\n",
        status=410, mimetype="text/plain")


@app.route("/install/windows/<token>/start")
def install_windows_start(token):
    """PUBLIC (token is the credential): plain-language forewarning of the Windows
    security prompts, shown BEFORE the download link is handed over.

    WHY THIS PAGE EXISTS OUTSIDE THE INSTALLER. SmartScreen gates the double-click and
    UAC gates process start, so BOTH fire before a single line of installer_gui.py runs —
    the installer itself can never forewarn about them. A page on this side of the
    download is the only place the warning can land before Windows speaks.

    TOKEN IS NOT CONSUMED HERE. _valid_installer_token() is a read-only SELECT and the
    download routes do not increment `uses` either (consumption happens at enrollment),
    so landing here first cannot burn a link the user has not used yet.

    ADDITIVE: /exe and /zip keep working exactly as before for any link already handed
    out. Nothing routes THROUGH this page; it is an alternative entry point."""
    if not _valid_installer_token(token):
        return Response("This installer link is invalid, revoked, expired, or already "
                        "used. Ask your administrator to generate a new one.\n",
                        status=410, mimetype="text/plain")
    return render_template("install_prewarn.html", token=token,
                           support_contact="your administrator")


@app.route("/install/windows/<token>/exe")
def install_windows_exe(token):
    """PUBLIC: redirect to the CI-built Windows .exe (latest GitHub release asset).
    Repo is env-driven (NEMESIS_GH_REPO) — no account/repo hardcoded (Rule 8)."""
    if not _valid_installer_token(token):
        return Response("This installer link is invalid, revoked, expired, or already "
                        "used. Ask your administrator to generate a new one.\n",
                        status=410, mimetype="text/plain")
    repo = os.environ.get("NEMESIS_GH_REPO", "").strip()
    if not repo:
        return Response("The generic Windows .exe target is not configured yet "
                        "(set NEMESIS_GH_REPO). Use the bundle (/zip) link instead.\n",
                        status=503, mimetype="text/plain")
    return redirect(f"https://github.com/{repo}/releases/latest/download/NemesisAgent-Setup.exe")


@app.route("/install/windows/<token>/zip")
def install_windows_zip(token):
    """PUBLIC (token is the credential): serve the v1.0.6 FROZEN-exe installer bundle —
    a zip of the prebuilt generic NemesisAgent-Setup.exe + a per-installer
    nemesis_install.conf carrying this token, the (single-use) Tailscale pre-auth key,
    and the box's tailnet target. Assembled on the box (NO per-request PyInstaller); the
    generic exe is a CI/Windows artifact staged at NEMESIS_AGENT_EXE. Spent/expired token
    or unstaged exe => hard fail, no legacy fallback. Rule-8: token/key never logged."""
    row = _valid_installer_token(token)
    if not row:
        return Response("This installer link is invalid, revoked, expired, or already "
                        "used. Ask your administrator to generate a new one.\n",
                        status=410, mimetype="text/plain")
    exe_path = os.environ.get("NEMESIS_AGENT_EXE", "").strip()
    if not (exe_path and os.path.isfile(exe_path)):
        return Response("The Windows installer bundle is not available yet — the frozen "
                        "agent exe is not staged on the server (set NEMESIS_AGENT_EXE to "
                        "the built NemesisAgent-Setup.exe). Contact your administrator.\n",
                        status=503, mimetype="text/plain")
    preauth = row["preauth_key"] if "preauth_key" in row.keys() else ""
    poll_interval = row["poll_interval"] if "poll_interval" in row.keys() else None
    conf = _render_install_conf(_nemesis_tailnet_host(), token,
                                row["device_name_hint"] or "Windows Device",
                                preauth or "", poll_interval=poll_interval)
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(exe_path, arcname="NemesisAgent-Setup.exe")
        zf.writestr("nemesis_install.conf", conf)
    return Response(buf.getvalue(), mimetype="application/zip", headers={
        "Content-Disposition": f'attachment; filename="NemesisAgent-Setup-{token[:8]}.zip"'})


#: How long without a check-in before the explanatory note appears. Deliberately
#: generous — 6x the agent's 300s default — because the server does not store each
#: device's poll_interval, so a tighter bound would call a slow-polling device
#: "silent" when it is merely early.
_AGENT_STALE_AFTER_S = 30 * 60

#: Tolerance for an agent clock running ahead of the server's. `agent_last_seen`
#: comes from the AGENT's clock (payload["timestamp"]), and unlike the heartbeat
#: signature's signed_at it is not skew-checked, so a future value is possible.
_AGENT_CLOCK_SKEW_S = 300


def _agent_checkin_state(last_seen, now=None):
    """(label, note) describing an agent's check-in state.

    Deliberately never returns "online" or "offline". The server cannot tell a
    powered-off device from one off the network from one waiting at its unlock
    prompt — distinguishing them would need an unauthenticated "I'm locked"
    beacon, which an attacker could forge just as easily and which would add a
    new unauthenticated ingress to the listener Stage 1 exists to authenticate.
    So this states what is known and names what is not.

    Every failure mode gets its own explicit label rather than falling through to
    something that reads as healthy: a missing timestamp, an unparseable one, and
    one from a disagreeing clock are three different situations, and none of them
    is "reporting normally".
    """
    raw = str(last_seen or "").strip()
    if not raw or raw == "-":
        return ("has never checked in",
                "This device enrolled but has never reported. It may not have "
                "finished installing, or it may be waiting for its device password.")
    try:
        seen = datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        # An unreadable timestamp is NOT evidence of freshness. Say so.
        return ("check-in time unreadable (%s)" % raw,
                "Nemesis could not read this device's last check-in time, so its "
                "status is unknown.")

    now = now or datetime.now()
    age = (now - seen).total_seconds()
    if age < -_AGENT_CLOCK_SKEW_S:
        return ("check-in time is in the future (%s)" % raw,
                "This device's clock disagrees with the server's, so its "
                "check-in time cannot be trusted as a freshness signal.")
    if age < _AGENT_STALE_AFTER_S:
        return ("last check-in %s" % _human_age(age), "")
    return ("no check-in since %s" % raw,
            "This device may be powered off, off the network, or waiting for its "
            "device password after a restart. Nemesis cannot tell these apart. If "
            "you think it may be lost or stolen, revoke it.")


def _human_age(seconds):
    """Coarse age for display. Never negative — a small negative age is clock
    jitter, not the future, and rendering '-3s ago' would look like a bug."""
    s = max(0, int(seconds))
    if s < 90:
        return "just now" if s < 15 else "%ds ago" % s
    if s < 5400:
        return "%dm ago" % (s // 60)
    if s < 172800:
        return "%dh ago" % (s // 3600)
    return "%dd ago" % (s // 86400)


def _render_agent_devices_html() -> str:
    """Settings -> Devices: pending enrollments (approve/reject) + enrolled list."""
    try:
        conn = _dm_conn()   # §9 batch 2 (_render_agent_devices_html)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT device_id, device_name, os, os_version, hardware_summary, "
            "enrollment_status, connection_type, lhm_available, agent_last_seen, "
            "pre_enrollment_scan, enrollment_has_findings, link_type "
            "FROM agent_devices ORDER BY agent_last_seen DESC").fetchall()
        conn.close()
    except Exception:
        return ('<div class="card" id="section-devices-enroll"><h2>&#128421; Devices</h2>'
                '<p style="color:#888">No device data available.</p></div>')
    # ── EXHAUSTIVE partition, not a set of independent allowlists ──
    #
    # This grouping has silently swallowed devices three times: 'revoked' first
    # (see below), then 'pending_unverified' nearly, then 'rejected' and
    # 'uninstalled' — 4 real rows on the box where this was found, invisible with
    # no way to act on them. Every previous fix added one more allowlist, which
    # is why the bug kept recurring: an unlisted status matched nothing and
    # disappeared, and disappearing looks exactly like "no such device".
    #
    # So every row is now assigned to exactly one bucket, and anything unmatched
    # falls into `unknown` and is RENDERED rather than dropped. A status nobody
    # anticipated becomes a visible oddity instead of a silent deletion.
    PENDING_STATUSES = ("pending", "pending_with_findings", "pending_unverified")
    pending, enrolled, revoked, rejected, uninstalled, unknown = [], [], [], [], [], []
    for r in rows:
        st = (r["enrollment_status"] or "").strip()
        if st in PENDING_STATUSES:
            pending.append(r)
        elif st == "approved":
            enrolled.append(r)
        # Revoked devices need their own list or they vanish from the UI entirely
        # -- which would make revocation irreversible through the product.
        elif st == "revoked":
            revoked.append(r)
        # Rejected devices are re-approvable and it is meaningful: the agent
        # SERVICE is still installed (it exited on rejection rather than being
        # removed), so on its next start it polls, sees 'approved', and proceeds.
        elif st == "rejected":
            rejected.append(r)
        # Uninstalled is historical. The agent deleted its own config, so its
        # device_id no longer exists on that machine and a reinstall enrols as a
        # NEW device. Re-approving this row would restore nothing, which is why
        # it is shown without an approve action rather than with one that quietly
        # does nothing.
        elif st == "uninstalled":
            uninstalled.append(r)
        else:
            unknown.append(r)
    h = ['<div class="card" id="section-devices-enroll" style="margin-bottom:16px">'
         '<h2>&#128421; Devices</h2>',
         # ── Windows installer generator ──
         '<div style="background:#0d0d1e;border:1px solid #00d4ff33;border-radius:8px;'
         'padding:10px 12px;margin-bottom:14px">'
         '<h3 style="color:#00d4ff;font-size:0.95em;margin-top:0">Generate Windows Installer</h3>'
         '<p style="color:#888;font-size:0.82em;margin:4px 0">Creates a single-use link '
         '(expires in about 2 hours) that delivers the self-contained Windows installer '
         'for this device &mdash; no Python required.</p>'
         '<input id="installerHint" type="text" value="Windows Device" maxlength="60" '
         'style="background:#11111f;border:1px solid #333;color:#ddd;border-radius:6px;'
         'padding:5px 8px;font-size:0.85em;width:200px" placeholder="Device name"> '
         '<input id="installerPreauth" type="text" maxlength="256" '
         'style="background:#11111f;border:1px solid #333;color:#ddd;border-radius:6px;'
         'padding:5px 8px;font-size:0.85em;width:280px;margin-left:6px" '
         'placeholder="Tailscale pre-auth key (optional)"> '
         '<div style="color:#666;font-size:0.78em;margin:4px 0 6px">Paste a single-use '
         'pre-auth key from the Tailscale admin console to let the agent self-join the '
         'tailnet. Leave blank to join the device by hand.</div>'
         '<input id="installerPoll" type="number" min="15" max="86400" '
         'style="background:#11111f;border:1px solid #333;color:#ddd;border-radius:6px;'
         'padding:5px 8px;font-size:0.85em;width:180px" '
         'placeholder="Heartbeat seconds (default 300)"> '
         '<div style="color:#666;font-size:0.78em;margin:2px 0 6px">Optional: how often the '
         'agent reports (seconds). Blank = 300 (5&nbsp;min). Minimum 15s. Lower = fresher '
         'data + faster trip troubleshooting, but more traffic.</div>'
         '<div style="margin:4px 0 8px">'
         '<label style="color:#ddd;font-size:0.82em;cursor:pointer">'
         '<input id="installerAutoApprove" type="checkbox" '
         'style="vertical-align:middle;margin-right:5px">'
         'Auto-approve devices enrolled with this installer</label>'
         '<div style="color:#ffcc00;font-size:0.78em;margin:2px 0 0 20px">&#9888; '
         'Only enable for devices you own and physically control.</div>'
         '</div>'
         '<button onclick="genWindowsInstaller()" style="background:#00d4ff22;color:#00d4ff;'
         'border:1px solid #00d4ff;border-radius:6px;padding:5px 14px;cursor:pointer">'
         'Generate Windows Installer</button>'
         '<div id="installerResult" style="margin-top:8px;font-size:0.84em"></div>'
         '</div>',
         '<h3 style="color:#ffcc00;font-size:0.95em">Pending approval</h3>']
    if not pending:
        h.append('<p style="color:#888;font-size:0.86em">No devices awaiting approval.</p>')
    for r in pending:
        did = html.escape(r["device_id"], quote=True)
        scan = {}
        if r["pre_enrollment_scan"]:
            try:
                scan = json.loads(r["pre_enrollment_scan"])
            except Exception:
                scan = {}
        sstatus = scan.get("scan_status")
        clam = int(scan.get("clamav_findings") or 0)
        yara = int(scan.get("yara_findings") or 0)
        total = clam + yara
        findings = bool(r["enrollment_has_findings"]) or sstatus == "findings" or total > 0
        if findings:
            badge = (f'<span style="color:#ffcc00">&#9888; {total} finding(s)</span>'
                     f'<br><span style="color:#aaa;font-size:0.8em">ClamAV: {clam} finding(s) &nbsp; YARA: {yara} finding(s)</span>'
                     '<details style="margin-top:4px">'
                     '<summary style="cursor:pointer;color:#ffcc00;font-size:0.82em">View findings</summary>'
                     '<div style="color:#aaa;font-size:0.8em;margin-top:4px">'
                     f'Status: {html.escape(str(sstatus or "?"))}<br>'
                     f'ClamAV findings: {clam}<br>YARA findings: {yara}<br>'
                     f'Scan roots: {html.escape(str(scan.get("clamav_scan_path") or "-"))}<br>'
                     f'Duration: {html.escape(str(scan.get("scan_duration_seconds") or "-"))}s<br>'
                     f'Scanned (UTC): {html.escape(str(scan.get("scan_timestamp") or "-"))}'
                     '</div></details>')
            buttons = (
                f'<button onclick="agentApproveAnyway(\'{did}\')" style="background:#ffcc0022;color:#ffcc00;'
                'border:1px solid #ffcc00;border-radius:6px;padding:5px 14px;cursor:pointer;margin-top:6px">Approve anyway</button> '
                f'<button onclick="agentReject(\'{did}\')" style="background:#ff444422;color:#ff6666;'
                'border:1px solid #ff4444;border-radius:6px;padding:5px 14px;cursor:pointer;margin-top:6px">Reject</button>')
        else:
            if sstatus == "clean":
                badge = ('<span style="color:#00ff88">&#9989; Clean</span>'
                         f'<br><span style="color:#aaa;font-size:0.8em">ClamAV: {clam} findings &nbsp; YARA: {yara} findings</span>')
            elif sstatus == "scan_failed":
                badge = '<span style="color:#ffcc00">&#9888; Scan failed (could not complete)</span>'
            else:
                badge = ('<span style="color:#00d4ff">&#8505; Not available</span>'
                         '<br><span style="color:#aaa;font-size:0.8em">(scanner not installed on this device)</span>')
            buttons = (
                f'<button onclick="agentApprove(\'{did}\')" style="background:#00ff8822;color:#00ff88;'
                'border:1px solid #00ff88;border-radius:6px;padding:5px 14px;cursor:pointer;margin-top:6px">Approve</button> '
                f'<button onclick="agentReject(\'{did}\')" style="background:#ff444422;color:#ff6666;'
                'border:1px solid #ff4444;border-radius:6px;padding:5px 14px;cursor:pointer;margin-top:6px">Reject</button>')
        border = '#ff444466' if findings else '#ffcc0044'
        h.append(
            f'<div style="background:#0d0d1e;border:1px solid {border};border-radius:8px;'
            'padding:10px 12px;margin-bottom:8px">'
            f'<strong>{html.escape(r["device_name"] or "?")}</strong> '
            f'<span style="color:#aaa;font-size:0.84em">{html.escape((r["os"] or "") + " " + (r["os_version"] or "")[:40])}</span><br>'
            f'<span style="color:#888;font-size:0.82em">{html.escape(r["hardware_summary"] or "")}</span><br>'
            f'<span style="font-size:0.84em">Pre-enrollment scan: {badge}</span><br>'
            f'{buttons}'
            '</div>')
    h.append('<h3 style="color:#00d4ff;font-size:0.95em;margin-top:14px">Enrolled devices</h3>')
    if not enrolled:
        h.append('<p style="color:#888;font-size:0.86em">No enrolled devices yet.</p>')
    for r in enrolled:
        did = html.escape(r["device_id"], quote=True)
        lhm = ('&#9989; sensors' if r["lhm_available"]
               else '&#9888; no LHM (temps/fans need LibreHardwareMonitor)')
        lt = (r["link_type"] or "").lower()
        link_label = {"wifi": "WiFi", "ethernet": "Ethernet"}.get(lt, "")
        conn_raw = (r["connection_type"] or "").lower()
        conn_label = {"vpn_remote": "VPN remote", "local": "Local"}.get(
            conn_raw, html.escape(r["connection_type"] or "unknown"))
        net_label = (link_label + " &middot; " + conn_label) if link_label else conn_label
        wifi_note = ('<br><span style="color:#ffcc00;font-size:0.8em">'
                     '&#9888; WiFi — Suricata coverage via Mode 2 (v2)</span>') if lt == "wifi" else ""
        # No online/offline badge, deliberately: a binary indicator would assert a
        # determination the server cannot make. The Revoke control sits directly
        # below the note because "I can't tell whether this is stolen" is exactly
        # the situation revoke exists for.
        _ck_label, _ck_note = _agent_checkin_state(r["agent_last_seen"])
        checkin_label = html.escape(_ck_label)
        checkin_note = (
            '<div style="background:#ffcc0018;border:1px solid #ffcc0055;color:#ddb857;'
            'border-radius:6px;padding:6px 10px;margin:6px 0;font-size:0.82em">'
            + html.escape(_ck_note) + '</div>') if _ck_note else ""
        h.append(
            '<div style="background:#0d0d1e;border:1px solid #222;border-radius:8px;'
            'padding:8px 12px;margin-bottom:6px;font-size:0.85em">'
            f'<strong>{html.escape(r["device_name"] or "?")}</strong> '
            f'<span style="color:#aaa">{html.escape(r["os"] or "")}</span> &middot; '
            f'<span style="color:#888">{net_label}</span> &middot; '
            f'<span style="color:#888">{checkin_label}</span> &middot; '
            f'<span style="color:#888">{lhm}</span>{wifi_note}<br>'
            f'{checkin_note}'
            f'<button onclick="agentRevoke(\'{did}\')" style="background:#ff444422;color:#ff6666;'
            'border:1px solid #ff4444;border-radius:6px;padding:4px 12px;cursor:pointer;'
            'margin-top:6px;font-size:0.92em">Revoke</button>'
            '</div>')
    if revoked:
        h.append('<h3 style="color:#ff6666;font-size:0.95em;margin-top:14px">Revoked devices</h3>')
        h.append('<p style="color:#888;font-size:0.8em;margin:0 0 6px">'
                 'These devices are blocked from reporting. Re-approving restores '
                 'access using the key they already hold.</p>')
        for r in revoked:
            did = html.escape(r["device_id"], quote=True)
            h.append(
                '<div style="background:#0d0d1e;border:1px solid #ff444444;border-radius:8px;'
                'padding:8px 12px;margin-bottom:6px;font-size:0.85em">'
                f'<strong>{html.escape(r["device_name"] or "?")}</strong> '
                f'<span style="color:#aaa">{html.escape(r["os"] or "")}</span> &middot; '
                f'<span style="color:#888">last seen: {html.escape(str(r["agent_last_seen"] or "-"))}</span><br>'
                f'<button onclick="agentApprove(\'{did}\')" style="background:#00ff8822;color:#00ff88;'
                'border:1px solid #00ff88;border-radius:6px;padding:4px 12px;cursor:pointer;'
                'margin-top:6px;font-size:0.92em">Re-approve</button>'
                '</div>')

    if rejected:
        h.append('<h3 style="color:#ff9944;font-size:0.95em;margin-top:14px">Rejected devices</h3>')
        h.append('<p style="color:#888;font-size:0.8em;margin:0 0 6px">'
                 'These enrollment requests were refused. Re-approving admits the '
                 'device and forces a fresh scan before it is trusted.</p>')
        for r in rejected:
            did = html.escape(r["device_id"], quote=True)
            h.append(
                '<div style="background:#0d0d1e;border:1px solid #ff994444;border-radius:8px;'
                'padding:8px 12px;margin-bottom:6px;font-size:0.85em">'
                f'<strong>{html.escape(r["device_name"] or "?")}</strong> '
                f'<span style="color:#aaa">{html.escape(r["os"] or "")}</span> &middot; '
                f'<span style="color:#888">last seen: {html.escape(str(r["agent_last_seen"] or "-"))}</span><br>'
                f'<button onclick="agentApprove(\'{did}\')" style="background:#00ff8822;color:#00ff88;'
                'border:1px solid #00ff88;border-radius:6px;padding:4px 12px;cursor:pointer;'
                'margin-top:6px;font-size:0.92em">Re-approve</button>'
                '</div>')

    if uninstalled:
        h.append('<h3 style="color:#888;font-size:0.95em;margin-top:14px">Uninstalled devices '
                 '<span style="font-weight:normal;font-size:0.85em">(historical)</span></h3>')
        h.append('<p style="color:#888;font-size:0.8em;margin:0 0 6px">'
                 'These devices removed their own agent. They are kept for history '
                 'and cannot be re-approved &mdash; reinstalling enrolls as a new '
                 'device, which is scanned before it is trusted.</p>')
        for r in uninstalled:
            h.append(
                '<div style="background:#0d0d1e;border:1px solid #33333366;border-radius:8px;'
                'padding:8px 12px;margin-bottom:6px;font-size:0.85em;opacity:0.75">'
                f'<strong>{html.escape(r["device_name"] or "?")}</strong> '
                f'<span style="color:#aaa">{html.escape(r["os"] or "")}</span> &middot; '
                f'<span style="color:#888">last seen: {html.escape(str(r["agent_last_seen"] or "-"))}</span>'
                '</div>')

    # The catch-all. Rendering an unrecognised status as a visible oddity is the
    # whole point: this bug has recurred because unmatched rows disappeared, and a
    # disappearance is indistinguishable from "no such device". A row here means
    # someone added a status without adding it above -- which should look wrong on
    # screen rather than silently reduce the device count.
    if unknown:
        h.append('<h3 style="color:#ffcc00;font-size:0.95em;margin-top:14px">'
                 'Devices in an unrecognised state</h3>')
        h.append('<p style="color:#888;font-size:0.8em;margin:0 0 6px">'
                 'These devices have an enrollment status this page does not know '
                 'how to group. They are shown here so they cannot disappear &mdash; '
                 'this usually means a new status was added without updating this '
                 'view.</p>')
        for r in unknown:
            h.append(
                '<div style="background:#0d0d1e;border:1px solid #ffcc0044;border-radius:8px;'
                'padding:8px 12px;margin-bottom:6px;font-size:0.85em">'
                f'<strong>{html.escape(r["device_name"] or "?")}</strong> '
                f'<span style="color:#aaa">{html.escape(r["os"] or "")}</span> &middot; '
                f'<span style="color:#ffcc00">status: '
                f'{html.escape(str(r["enrollment_status"] or "(none)"))}</span>'
                '</div>')
    h.append('</div>')
    return "".join(h)


_TUNNEL_IFACES = ["tun0", "tun1", "wg0", "wg1", "nordlynx", "proton0"]

def get_vpn_status():
    now = time.monotonic()
    if _vpn_cache["data"] and now - _vpn_cache["ts"] < _VPN_CACHE_TTL:
        return _vpn_cache["data"]

    result = {"provider": None, "status": "Disconnected", "vpn_ip": None, "protocol": None, "server_location": None}

    def _cache(r):
        _vpn_cache["data"] = r
        _vpn_cache["ts"] = time.monotonic()
        return r

    # PIA VPN
    try:
        r = subprocess.run(["piactl", "get", "connectionstate"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            state = r.stdout.strip()
            result["provider"] = "PIA VPN"
            result["status"] = state.capitalize() if state else "Unknown"
            if state.lower() == "connected":
                for flag, cmd in [("vpn_ip", ["piactl", "get", "vpnip"]),
                                   ("server_location", ["piactl", "get", "region"]),
                                   ("protocol", ["piactl", "get", "protocol"])]:
                    try:
                        cr = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                        if cr.returncode == 0:
                            result[flag] = cr.stdout.strip()
                    except Exception:
                        pass
            return _cache(result)
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass

    # Mullvad
    try:
        r = subprocess.run(["mullvad", "status"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            out = r.stdout.strip()
            result["provider"] = "Mullvad"
            if "Connected" in out:
                result["status"] = "Connected"
                for line in out.splitlines():
                    if "Tunnel type:" in line:
                        result["protocol"] = line.split(":", 1)[1].strip()
                    elif "Location:" in line:
                        result["server_location"] = line.split(":", 1)[1].strip()
                    elif "IP:" in line:
                        result["vpn_ip"] = line.split(":", 1)[1].strip()
            elif "Connecting" in out:
                result["status"] = "Connecting"
            return _cache(result)
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass

    # ProtonVPN
    try:
        r = subprocess.run(["protonvpn-cli", "status"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            out = r.stdout.strip()
            result["provider"] = "ProtonVPN"
            if "Connected" in out:
                result["status"] = "Connected"
                for line in out.splitlines():
                    if "IP:" in line:
                        result["vpn_ip"] = line.split(":", 1)[1].strip()
                    elif "Server:" in line:
                        result["server_location"] = line.split(":", 1)[1].strip()
                    elif "Protocol:" in line:
                        result["protocol"] = line.split(":", 1)[1].strip()
            return _cache(result)
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass

    # Fallback: check tunnel interfaces via `ip addr show`
    try:
        ip_r = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True, timeout=5)
        if ip_r.returncode == 0:
            for iface in _TUNNEL_IFACES:
                if re.search(rf'^\d+: {re.escape(iface)}:', ip_r.stdout, re.MULTILINE):
                    vpn_ip = None
                    for line in ip_r.stdout.splitlines():
                        if f" {iface} " in line or f" {iface}:" in line:
                            pass
                        if "inet " in line:
                            m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                            if m:
                                vpn_ip = m.group(1)
                    if iface == "nordlynx":
                        provider, proto = "NordVPN", "WireGuard"
                    elif iface.startswith("wg"):
                        provider, proto = "WireGuard VPN", "WireGuard"
                    elif iface == "proton0":
                        provider, proto = "ProtonVPN", "WireGuard"
                    else:
                        provider, proto = "Unknown Provider", "OpenVPN"
                    result.update({"provider": provider, "status": "Connected",
                                   "vpn_ip": vpn_ip, "protocol": proto,
                                   "server_location": f"via {iface}"})
                    return _cache(result)
    except Exception:
        pass

    return _cache(result)


def get_vpn_split_tunnel_apps():
    try:
        r = subprocess.run(["piactl", "get", "splittunnelapps"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return [a for a in r.stdout.strip().splitlines() if a.strip()]
    except Exception:
        pass
    return []


def _temp_score(temp, threshold, healthy_max):
    """100 when temp <= healthy_max, 0 when temp >= threshold, linear between."""
    if temp is None:
        return 100.0
    if temp <= healthy_max:
        return 100.0
    if temp >= threshold:
        return 0.0
    return 100.0 * (threshold - temp) / (threshold - healthy_max)


def _fan_score(sample, fan_status=None):
    """100% when all ever-active fans spin > 200 RPM; 100% if none are tracked.

    fan_status: {unique_key: {"ever_active": bool, ...}} from get_fan_status().
    When provided, fans whose unique_key has ever_active=False are excluded so
    empty motherboard headers at 0 RPM don't penalise the health score.
    Fans missing from fan_status default to included (safe fallback for old
    historical samples that don't carry a unique_key field).
    """
    fans = sample.get("fans", [])
    if not fans:
        return 100.0
    if fan_status:
        relevant = [f for f in fans
                    if fan_status.get(f.get("unique_key"), {}).get("ever_active", True)]
    else:
        relevant = fans
    if not relevant:
        return 100.0
    spinning = sum(1 for f in relevant if f.get("rpm") and f["rpm"] > 200)
    return 100.0 * spinning / len(relevant)


def _alert_score(total):
    if total == 0:
        return 100.0
    if total <= 5:
        # 1 -> 90, 5 -> 50
        return 100.0 - (total / 5.0) * 50.0
    if total <= 20:
        # 6 -> ~47, 20 -> 0
        return max(0.0, 50.0 - ((total - 5) / 15.0) * 50.0)
    return 0.0


def _score_color(score):
    if score >= 80:
        return "green"
    if score >= 50:
        return "yellow"
    return "red"


def compute_health_score(hw_live, alerts_24h, svc_status):
    hw = hw_live or {}
    cpu_t = hw.get("cpu_temp")
    gpu_t = hw.get("gpu_temp")
    cpu_score = _temp_score(cpu_t, 85, 70)
    gpu_score = _temp_score(gpu_t, 85, 75)
    fan_status = hw.get("fan_status", {})
    fans_list = hw.get("fans", [])
    fan_score = _fan_score(hw, fan_status)
    svc_active = svc_status.get("active", 0)
    svc_total = max(1, svc_status.get("total", 1))
    svc_score = 100.0 * svc_active / svc_total
    alert_total = alerts_24h.get("total", 0)
    alrt_score = _alert_score(alert_total)
    relevant_fans = [f for f in fans_list
                     if fan_status.get(f.get("unique_key"), {}).get("ever_active", True)]
    spinning = sum(1 for f in relevant_fans if f.get("rpm") and f["rpm"] > 200)
    fan_detail = (f"{spinning}/{len(relevant_fans)} tracked fans above 200 RPM"
                  if relevant_fans else "no fans tracked")

    components = [
        {"name": "CPU temperature", "weight": 25, "score": round(cpu_score, 1),
         "detail": f"{cpu_t if cpu_t is not None else '—'}°C / threshold 85°C (healthy ≤70°C)"},
        {"name": "GPU temperature", "weight": 25, "score": round(gpu_score, 1),
         "detail": f"{gpu_t if gpu_t is not None else '—'}°C / threshold 85°C (healthy ≤75°C)"},
        {"name": "Fan speeds", "weight": 20, "score": round(fan_score, 1),
         "detail": fan_detail},
        {"name": "Services running", "weight": 20, "score": round(svc_score, 1),
         "detail": f"{svc_active}/{svc_status.get('total', 0)} monitored services active"},
        {"name": "System alerts (24h)", "weight": 10, "score": round(alrt_score, 1),
         "detail": f"{alert_total} thermal/fan/service alerts in last 24h"},
    ]
    for c in components:
        c["contribution"] = round(c["score"] * c["weight"] / 100.0, 1)
    total = sum(c["contribution"] for c in components)
    return {
        "score": round(total, 1),
        "color": _score_color(total),
        "components": components,
        "services": svc_status.get("services", []),
    }


def compute_health_sparkline(samples, fan_status=None):
    """Per-sample simplified score (CPU 40, GPU 40, fans 20) for the trend line."""
    out = []
    for s in samples:
        cpu = _temp_score(s.get("cpu_temp"), 85, 70)
        gpu = _temp_score(s.get("gpu_temp"), 85, 75)
        fans = _fan_score(s, fan_status)
        out.append(round(cpu * 0.4 + gpu * 0.4 + fans * 0.2, 1))
    return out


@app.route("/api/alert-breakdown-24h")
def api_alert_breakdown_24h():
    return jsonify(get_24h_alert_stats())


@app.route("/api/health-score")
def api_health_score():
    try:
        hw_live = hw_monitor.get_live_metrics()
    except Exception:
        hw_live = {}
    return jsonify(compute_health_score(hw_live, get_24h_alert_stats(), get_services_status()))


@app.route("/api/hw-metrics")
def api_hw_metrics():
    try:
        samples = hw_monitor.get_recent_samples(288)
        fan_status = hw_monitor.get_fan_status()
        return jsonify({
            "live": hw_monitor.get_live_metrics(),
            "samples": samples,
            "health_sparkline": {
                "labels": [s.get("timestamp") for s in samples],
                "scores": compute_health_sparkline(samples, fan_status),
            },
        })
    except Exception as e:
        log.exception("api_hw_metrics failed: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/vpn-status")
def api_vpn_status():
    vpn = get_vpn_status()
    split_tunnel = []
    if vpn.get("provider") and "pia" in vpn["provider"].lower():
        split_tunnel = get_vpn_split_tunnel_apps()
    return jsonify({**vpn, "split_tunnel_apps": split_tunnel})


@app.route("/api/vpn/<action>", methods=["POST"])
def api_vpn_action(action):
    """Connect/disconnect the VPN. POST-only, and not forgeable cross-origin.

    This was a bare GET, so a plain <img src="/api/vpn/disconnect"> on any page
    the operator visited while signed in would drop the tunnel silently. The
    action allowlist below was already here; what was missing was any protection
    against the request being made on the operator's behalf without their intent.

    POST alone is not sufficient — an HTML form can POST cross-origin. Requiring
    a JSON content-type is what closes it: forms can only send urlencoded,
    multipart or text/plain, so a JSON body cannot be produced by form
    submission, and a cross-origin fetch/XHR that sets the header is blocked by
    CORS preflight. Paired with SESSION_COOKIE_SAMESITE, that is two independent
    reasons a forged request fails.

    Deliberately NOT credential-gated: this process cannot verify a credential
    itself (see _fw_credential — verification lives in nemesis-fwd, tied to a
    privileged op), and VPN control is not a helper operation. Adding one would
    be new helper surface, not a small fix; scoped out rather than faked with a
    check this process cannot actually perform.
    """
    if action not in ("connect", "disconnect"):
        return jsonify({"error": "invalid action"}), 400
    if not request.is_json:
        return jsonify({"error": "JSON content-type required"}), 415
    vpn = get_vpn_status()
    provider = (vpn.get("provider") or "").lower()
    try:
        if "pia" in provider:
            cmd = ["piactl", action]
        elif "mullvad" in provider:
            cmd = ["mullvad", action]
        elif "proton" in provider:
            cmd = ["protonvpn-cli", "c" if action == "connect" else "disconnect"]
        else:
            return jsonify({"error": "No supported VPN CLI detected"}), 400
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        _vpn_cache["ts"] = 0.0
        _vpn_cache["data"] = None
        if r.returncode == 0:
            return jsonify({"success": True, "output": r.stdout.strip()})
        return jsonify({"error": r.stderr.strip() or "Command failed"})
    except FileNotFoundError:
        return jsonify({"error": "VPN CLI not found"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/review-queue")
def api_review_queue():
    items = get_review_queue()
    return jsonify({"count": len(items), "html": render_review_queue_html(items)})


@app.route("/api/quarantines")
def api_quarantines():
    return jsonify({"quarantines": get_active_quarantines()})


@app.route("/api/quarantine/<int:q_id>/confirm", methods=["POST"])
def api_quarantine_confirm(q_id):
    try:
        conn = _dm_conn()   # §9 batch 4 (api_quarantine_confirm)
        c = conn.cursor()
        c.execute("SELECT ip, rule_id, status FROM quarantines WHERE id = ?", (q_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "quarantine not found"}), 404
        ip, rule_id, status = row
        if status != "active":
            conn.close()
            return jsonify({"error": f"quarantine status is {status}, cannot confirm"}), 409
        c.execute("UPDATE alerts SET action='block' WHERE rule_id=?", (rule_id,))
        c.execute("UPDATE quarantines SET status='confirmed', actor=? WHERE id=?", (_actor(), q_id))
        conn.commit()
        conn.close()
        _audit(action="confirm", rule_id=rule_id, ip=ip)
        return jsonify({"success": True, "ip": ip, "rule_id": rule_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/firewall/credential/drop", methods=["POST"])
def api_firewall_credential_drop():
    """Immediately invalidate this session's cached view credential.

    Called by the page on visibility/focus loss. Dropping your OWN cached
    credential is never a privileged act, so it needs no credential — requiring
    one would be circular. Best-effort: the helper's idle timeout is the actual
    guarantee and holds regardless of whether this is ever called.
    """
    try:
        import fw_client
        fw_client.drop_credential(_actor(), _fw_session_id())
        return jsonify({"success": True})
    except Exception as exc:
        # Never surface an error for this — it is an optimisation, and a failed
        # drop must not break page teardown.
        auth_log.info("firewall credential drop failed (non-fatal): %s", exc)
        return jsonify({"success": False}), 200


@app.route("/api/quarantine/<int:q_id>/lift", methods=["POST"])
def api_quarantine_lift(q_id):
    try:
        conn = _dm_conn()   # §9 batch 4 (api_quarantine_lift)
        c = conn.cursor()
        c.execute("SELECT ip, rule_id, status FROM quarantines WHERE id = ?", (q_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "quarantine not found"}), 404
        ip, rule_id, status = row
        if status != "active":
            conn.close()
            return jsonify({"error": f"quarantine status is {status}, cannot lift"}), 409
        # Admin-initiated unblock: a fresh credential is required every time,
        # verified by nemesis-fwd against the stored hash. If it refuses, the DB
        # is NOT updated — showing a lifted quarantine whose ufw rule is still
        # in place would be worse than refusing.
        try:
            ufw_delete(ip, _actor(), _fw_session_id(), _fw_credential())
        except FirewallError as exc:
            conn.close()
            return _fw_error_response(exc)
        ufw_ok = True
        c.execute("UPDATE alerts SET action='pending' WHERE rule_id=?", (rule_id,))
        c.execute("UPDATE quarantines SET status='lifted', actor=? WHERE id=?", (_actor(), q_id))
        conn.commit()
        conn.close()
        _audit(action="lift", rule_id=rule_id, ip=ip)
        return jsonify({"success": True, "ip": ip, "rule_id": rule_id, "ufw_ok": ufw_ok})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/firewall/unblock", methods=["POST"])
def api_firewall_unblock():
    """Remove a deny rule applied by the admin-initiated block path.

    Added 2026-07-31. Until now the dashboard could CREATE a permanent block it
    had no way to remove: /api/quarantine/<id>/lift is the only other unblock
    route and it requires a `quarantines` row, which block_ip_permanent()
    deliberately never creates. The result was a two-click action with no
    in-product undo — recovery meant `ufw delete` at a terminal, which is exactly
    the expertise this product exists to not require.

    Nothing new is granted to reach this: op `unblock_ip` was already implemented
    in nemesis_fwd.OPS, already wrapped by fw_client, and already present in
    PEER_POLICY["dashboard"]. Only the route and the button were missing.

    Ordering mirrors api_quarantine_lift deliberately: the firewall call goes
    FIRST and the DB is touched only if it succeeded. Reporting an alert as
    unblocked while its ufw rule is still in place would be worse than refusing.

    Resetting action -> 'pending' is load-bearing, not tidying. alert_watcher's
    handle_line() re-applies block_ip_permanent() on the NEXT sighting for any
    rule whose action is 'block', so leaving it would silently re-block the
    address the user just released.
    """
    data = request.get_json(force=True, silent=True) or {}
    ip = (data.get("ip") or "").strip()
    rule_id = (data.get("rule_id") or "").strip()
    if not ip:
        return jsonify({"error": "ip is required"}), 400

    # Admin-initiated unblock — a fresh credential every time, verified by
    # nemesis-fwd against the stored hash. Same rule as block.
    try:
        ufw_delete(ip, _actor(), _fw_session_id(), _fw_credential())
    except FirewallError as exc:
        return _fw_error_response(exc)

    try:
        if rule_id:
            conn = _dm_conn()
            try:
                c = conn.cursor()
                c.execute("UPDATE alerts SET action='pending' WHERE rule_id=?", (rule_id,))
                conn.commit()
            finally:
                conn.close()
        _audit(action="unblock", rule_id=rule_id or None, ip=ip)
        return jsonify({"success": True, "ip": ip, "rule_id": rule_id})
    except Exception as e:
        # The rule IS gone at this point. Report success for the firewall action
        # and surface the bookkeeping failure separately rather than implying the
        # unblock did not happen.
        log.exception("unblock succeeded for %s but bookkeeping failed", ip)
        return jsonify({"success": True, "ip": ip, "warning": f"unblocked, but record update failed: {e}"})


@app.route("/api/update-device", methods=["POST"])
def update_device():
    try:
        data = request.json
        conn = _dm_conn()   # §9 batch 4 (update_device)
        c = conn.cursor()
        c.execute("""UPDATE devices SET friendly_name=?, device_type=?, notes=?, trusted=? 
                     WHERE mac=?""",
                  (data["friendly_name"], data["device_type"], 
                   data.get("notes", ""), data.get("trusted", 1), data["mac"]))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/analyze/<rule_id>")
def analyze_alert(rule_id):
    try:
        raw_alert = request.args.get("raw", "")
        parsed = parse_alert(raw_alert) if raw_alert else None
        src_ip = parsed["src_ip"] if parsed else ""
        enrichment = None
        if src_ip:
            try:
                enrichment = enrich_ip(src_ip)
            except Exception:
                enrichment = None
        conn = _dm_conn()   # §9 batch 4 (analyze_alert)
        c = conn.cursor()
        c.execute("SELECT * FROM alerts WHERE rule_id = ?", (rule_id,))
        existing = c.fetchone()
        if existing and existing[4]:
            # Fall back to DB-stored src_ip when raw alert had no parseable IP
            if not src_ip and len(existing) > 11 and existing[11]:
                src_ip = existing[11]
                if enrichment is None:
                    try:
                        enrichment = enrich_ip(src_ip)
                    except Exception:
                        enrichment = None
            conn.close()
            return jsonify({
                "explanation": existing[4],
                "risk_level": existing[5],
                "action": existing[7],
                "times_seen": existing[8] or 1,
                "last_seen": existing[10] or "",
                "rule_name": existing[2] or "",
                "recommended_action": "See previous decision",
                "reason": "Retrieved from local database",
                "cached": True,
                "src_ip": src_ip,
                "enrichment": enrichment
            })
        from modules.ai_engine import analyze as ai_analyze
        ai_result = ai_analyze(
            f"""You are Nemesis, an AI security assistant for a home network firewall.
Analyze this Suricata alert and respond in JSON only, no markdown:

Alert: {raw_alert}

{{
    "explanation": "Plain English explanation for home user",
    "risk_level": "LOW/MEDIUM/HIGH",
    "is_threat": true/false,
    "recommended_action": "Block/Ignore/Monitor",
    "reason": "Brief reason"
}}""",
            max_tokens=500,
            cache_key=f"alert_{rule_id}",
            cache_hours=24,
            # job_id engages ai_engine's in-flight dedup. The mechanism already
            # existed but this caller never passed one, so two concurrent
            # requests for the same uncached rule_id each made — and were each
            # BILLED FOR — a separate Claude call. Flask is threaded, so that
            # needed nothing more exotic than a double-click.
            job_id=f"alert_{rule_id}",
        )
        if not ai_result.get("ok"):
            return jsonify({"error": ai_result.get("reason", "AI unavailable")}), 503
        response_text = ai_result["text"]
        try:
            analysis = json.loads(response_text)
        except Exception as e:
            log.warning("analyze_alert: failed to parse Claude response as JSON: %s", e)
            analysis = {
                "explanation": response_text,
                "risk_level": "UNKNOWN",
                "is_threat": False,
                "recommended_action": "Monitor",
                "reason": "Could not parse response"
            }
        now = datetime.now().isoformat()
        new_action = "ignore" if analysis.get("risk_level") == "LOW" else "pending"
        # Decide from the CURRENT state, not from `existing` — that was read
        # before a Claude call that takes seconds, so by now another request may
        # already have inserted this rule_id. `alerts.rule_id` carries no UNIQUE
        # constraint, so a blind INSERT on the stale branch duplicated the row.
        #
        # UPDATE-first tells us whether it exists right now; the INSERT is then
        # guarded by NOT EXISTS in the same statement, so it cannot duplicate
        # even if a third writer lands between the two. No schema change and no
        # transaction held across the API call.
        c.execute("UPDATE alerts SET explanation=?, risk_level=? WHERE rule_id=?",
                  (analysis["explanation"], analysis["risk_level"], rule_id))
        if c.rowcount == 0:
            c.execute("""INSERT INTO alerts
                (rule_id, rule_name, classification, priority, explanation, risk_level, action, times_seen, first_seen, last_seen)
                SELECT ?, ?, ?, ?, ?, ?, ?, 1, ?, ?
                WHERE NOT EXISTS (SELECT 1 FROM alerts WHERE rule_id = ?)""",
                (rule_id, raw_alert[:50], "", 1, analysis["explanation"],
                 analysis["risk_level"], new_action, now, now, rule_id))
        conn.commit()
        conn.close()
        return jsonify({**analysis, "cached": False, "src_ip": src_ip,
                        "enrichment": enrichment, "times_seen": 1,
                        "last_seen": now, "action": new_action, "rule_name": ""})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────────────────────────────────────
# Contextual chat — the alert anchor, plus the two routes the UI talks to.
#
# Core owns the `alerts` table, so the alert loader lives here rather than in
# ai_engine. Same rule the three module anchors follow: whoever owns the schema
# supplies the loader.
# ─────────────────────────────────────────────────────────────────────────────

def _anchor_load_alert(rule_id) -> str:
    """Rebuild an alert's facts + the analysis already shown, for a follow-up.

    Anchored on rule_id (TEXT) because that is what analyze_alert() keys on and
    what the cached analysis is stored under -- not on alerts.id.
    """
    try:
        conn = _dm_conn()
        try:
            r = conn.execute(
                "SELECT rule_id, rule_name, classification, priority, explanation, "
                "risk_level, action, times_seen, first_seen, last_seen, src_ip, "
                "dst_ip, protocol FROM alerts WHERE rule_id=?",
                (rule_id,),
            ).fetchone()
            # The analysis the user is looking at lives in ai_cache, written by
            # analyze_alert() under this exact key.
            cached = conn.execute(
                "SELECT response_text FROM ai_cache WHERE cache_key=?",
                (f"alert_{rule_id}",),
            ).fetchone()
        finally:
            conn.close()
    except Exception:
        log.exception("chat: alert anchor loader failed for %s", rule_id)
        return ""
    if not r:
        return ""

    lines = [
        f"Alert rule {r['rule_id']} ({r['rule_name'] or 'unnamed'})",
        f"Classification: {r['classification'] or 'none'}   Priority: {r['priority']}",
        f"Risk level: {r['risk_level'] or 'unassessed'}",
        f"Source IP: {r['src_ip'] or 'n/a'}   Destination: {r['dst_ip'] or 'n/a'}"
        f"   Protocol: {r['protocol'] or 'n/a'}",
        f"Times seen: {r['times_seen']}  (first {r['first_seen']}, last {r['last_seen']})",
        f"Action taken so far: {r['action']}",
    ]
    if r["explanation"]:
        lines.append(f"Explanation on record:\n{r['explanation']}")

    # ── Path 1 auto-context ──────────────────────────────────────────────
    # Facts the server can already read, pulled in without the user asking.
    # Read from the DB and from never_block_set() rather than via
    # firewall.list_blocked(), which needs session credentials a loader does
    # not have. Reading `quarantines` is also strictly better here: it carries
    # HISTORY, so "first time" and "fifth time this week" are distinguishable.
    src = (r["src_ip"] or "").strip()
    if src:
        extra = []
        try:
            conn = _dm_conn()
            try:
                q_now = conn.execute(
                    "SELECT expires_at FROM quarantines WHERE ip=? AND status='active' "
                    "ORDER BY id DESC LIMIT 1", (src,)).fetchone()
                q_hist = conn.execute(
                    "SELECT COUNT(*) AS n FROM quarantines WHERE ip=?", (src,)).fetchone()
                dev = conn.execute(
                    "SELECT friendly_name, device_type, trusted, mac FROM devices "
                    "WHERE ip=?", (src,)).fetchone()
            finally:
                conn.close()

            if q_now:
                extra.append(f"This address is CURRENTLY quarantined "
                             f"(expires {q_now['expires_at']}).")
            prior = int(q_hist["n"]) if q_hist else 0
            extra.append(f"Times this address has been quarantined before: {prior}"
                         + (" (first time seen)" if prior == 0 else ""))
            if dev:
                # Changes the question entirely: a known trusted device behaving
                # oddly is a different problem from an unknown external host.
                extra.append(
                    f"This address belongs to a KNOWN DEVICE on this network: "
                    f"{dev['friendly_name'] or 'unnamed'} "
                    f"(type {dev['device_type'] or 'unknown'}, MAC {dev['mac']}, "
                    f"{'trusted' if dev['trusted'] else 'NOT marked trusted'}).")
            else:
                extra.append("This address does not match any known device on this network.")
        except Exception:
            # Enrichment is additive. If it cannot be read, say so rather than
            # omitting it silently -- an absent line is indistinguishable from
            # "there was nothing to report", which is a different fact.
            log.exception("chat: alert enrichment failed for %s", rule_id)
            extra.append("(current firewall/device context could not be read)")

        try:
            from firewall import never_block_set
            if src in never_block_set():
                extra.append("PROTECTED ADDRESS: this is on the never-block list "
                             "(this host's own address or gateway) and cannot be "
                             "blocked by any action, at any authority level.")
        except Exception:
            log.exception("chat: never_block_set check failed")
            extra.append("(never-block status could not be checked)")

        if extra:
            lines.append("\nCURRENT STATE (read now, not when the alert fired):")
            lines.extend(f"- {e}" for e in extra)

    if cached and cached["response_text"]:
        lines.append(f"\nAnalysis already shown to the user:\n{cached['response_text']}")
    return "\n".join(lines)


try:
    from modules.ai_engine import register_anchor as _ai_register_anchor
    _ai_register_anchor(
        "alert",
        _anchor_load_alert,
        action_classes=("ip_quarantine_external", "ip_block_permanent"),
        label="Firewall alert",
    )
except Exception:
    log.exception("chat: could not register the alert anchor")


@app.route("/api/settings/observe-every-n", methods=["POST"])
def api_set_observe_every_n():
    """Set the remote-agent observation divisor (core settings table).

    POST, never GET: it changes behaviour on every remote agent, so a GET would
    be CSRF-triggerable by an <img> tag under default SameSite=Lax cookies.
    Auth-gated by absence from _AUTH_EXEMPT, matching every other state-changing
    route.

    Validated HERE as well as in database.get_remote_observe_every_n() and again
    on the agent. Three checks is not redundancy: this one produces a useful
    error for the person typing, the storage layer protects readers from a value
    written by any other path, and the agent refuses to trust the server. Only
    the first can tell the user WHY their input was rejected.
    """
    data = request.get_json(silent=True) or {}
    raw = data.get("value")
    try:
        n = int(str(raw).strip())
    except (TypeError, ValueError):
        return jsonify({"ok": False,
                        "error": f"'{raw}' is not a whole number"}), 400
    lo, hi = database.REMOTE_OBSERVE_N_MIN, database.REMOTE_OBSERVE_N_MAX
    if n < lo or n > hi:
        return jsonify({"ok": False,
                        "error": f"must be between {lo} and {hi} "
                                 f"({lo} = report as often as local devices, "
                                 f"{hi} = about once every 4 hours)"}), 400
    if not database.set_setting("agent_remote_observe_every_n", n,
                                actor=_current_actor_label()):
        return jsonify({"ok": False, "error": "could not save the setting"}), 500
    # Echo back what will actually be used, read back through the same path the
    # agents will get it from -- so the UI confirms the STORED value rather than
    # the submitted one.
    return jsonify({"ok": True, "value": database.get_remote_observe_every_n()})


@app.route("/api/ai/chat/state")
def api_ai_chat_state():
    """Read-only: what the chat affordance should show for one anchored finding.

    GET is correct here -- it reads state and bills nothing. Its sibling below is
    POST precisely because that one spends money.
    """
    surface = (request.args.get("surface") or "").strip()
    row_id  = (request.args.get("row_id") or "").strip()
    if not surface or not row_id:
        return jsonify({"ok": False, "reason": "surface and row_id are required"}), 400
    try:
        from modules.ai_engine import get_chat_state
        return jsonify(get_chat_state(surface, row_id))
    except Exception as e:
        log.exception("chat: state lookup failed")
        return jsonify({"ok": False, "reason": str(e)}), 500


@app.route("/api/ai/chat/ask", methods=["POST"])
def api_ai_chat_ask():
    """Ask one follow-up question about an anchored finding.

    POST, never GET: every call here is a real billed API request, so a GET
    would make it CSRF-triggerable by a plain <img> tag under default
    SameSite=Lax cookies -- i.e. an attacker could spend the owner's money.
    Auth-gated by absence from _AUTH_EXEMPT, matching every other spending or
    state-changing route.

    The client sends only (surface, row_id, question). It CANNOT send context:
    ask_followup() rebuilds that server-side from the row, so a caller cannot
    steer the model with facts of its own choosing.
    """
    data    = request.get_json(silent=True) or {}
    surface = str(data.get("surface") or "").strip()
    row_id  = str(data.get("row_id") or "").strip()
    question = str(data.get("question") or "").strip()
    if not surface or not row_id:
        return jsonify({"ok": False, "code": "bad_request",
                        "reason": "surface and row_id are required"}), 400
    try:
        from modules.ai_engine import ask_followup
        # tier is a client-supplied hint, not a model ID. resolve_chat_tier()
        # inside ask_followup defaults DOWN on anything unrecognised, so a
        # malformed or hostile value cannot raise spend.
        result = ask_followup(surface, row_id, question,
                              actor=_current_actor_label(),
                              tier=str(data.get("tier") or "").strip())
        return jsonify(result), (200 if result.get("ok") else 400)
    except Exception as e:
        log.exception("chat: ask_followup failed")
        return jsonify({"ok": False, "code": "server_error", "reason": str(e)}), 500


@app.route("/api/report/<rule_id>")
def report_abuse(rule_id):
    try:
        ip = request.args.get("ip", "").strip()
        if not ip:
            return jsonify({"error": "IP required"}), 400
        if not ABUSEIPDB_KEY:
            return jsonify({"error": "ABUSEIPDB_KEY not configured"}), 500
        categories = request.args.get("categories", "14,15")
        comment = request.args.get(
            "comment",
            f"Reported from Nemesis Firewall - Suricata rule {rule_id}"
        )
        resp = requests.post(
            "https://api.abuseipdb.com/api/v2/report",
            data={"ip": ip, "categories": categories, "comment": comment},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=10,
        )
        try:
            payload = resp.json()
        except ValueError:
            payload = {}
        if resp.status_code >= 400:
            errors = payload.get("errors") or [{"detail": "Unknown error"}]
            detail = errors[0].get("detail") if isinstance(errors, list) and errors else str(errors)
            return jsonify({"error": detail, "status": resp.status_code}), resp.status_code
        data = payload.get("data", {})
        return jsonify({
            "success": True,
            "ip": ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/test-enrichment/<ip>")
def test_enrichment(ip):
    try:
        return jsonify(enrich_ip(ip))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/action/<rule_id>/<action>", methods=["POST"])
def set_action(rule_id, action):
    try:
        src_ip = request.args.get("ip", "")
        # The firewall call goes FIRST, before any write transaction is opened
        # here. Two independent reasons, the first learned the hard way:
        #
        #  1. nemesis-fwd writes its OWN audit row into this same database. When
        #     this route held an uncommitted write txn across the helper call,
        #     that write hit SQLITE_BUSY -> "database is locked", so every
        #     admin-initiated block silently lost its helper-side audit record
        #     while still applying the rule and returning 200. A privileged
        #     firewall write with no audit trail is exactly what this helper
        #     exists to prevent.
        #  2. If the block fails, nothing should have been recorded as blocked.
        #
        # This mirrors the lift route, which has always ordered it this way.
        if action == "block" and src_ip:
            # Admin-initiated permanent block — fresh credential each time.
            try:
                ufw_deny_append(src_ip, _actor(), _fw_session_id(), _fw_credential())
            except FirewallError as exc:
                return _fw_error_response(exc)
        conn = _dm_conn()   # §9 batch 4 (set_action)
        c = conn.cursor()
        c.execute("UPDATE alerts SET action=? WHERE rule_id=?", (action, rule_id))
        if c.rowcount == 0:
            now = datetime.now().isoformat()
            # NOT EXISTS guard: `rowcount == 0` was read a moment ago and
            # `alerts.rule_id` has no UNIQUE constraint, so two concurrent POSTs
            # could both see 0 and both insert. Guarding inside the statement
            # closes that without a schema change.
            c.execute("""INSERT INTO alerts
                (rule_id, rule_name, classification, priority, explanation, risk_level, action, times_seen, first_seen, last_seen)
                SELECT ?, ?, ?, ?, ?, ?, ?, 1, ?, ?
                WHERE NOT EXISTS (SELECT 1 FROM alerts WHERE rule_id = ?)""",
                (rule_id, "", "", 1, "", "UNKNOWN", action, now, now, rule_id))
        conn.commit()
        conn.close()
        _audit(action=action, rule_id=rule_id, ip=(src_ip or None))
        return jsonify({"success": True, "action": action})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def _settings_incident_panel(inc: dict) -> str:
    import time as _time
    active    = inc.get("active", False)
    severity  = inc.get("severity", "")
    name      = inc.get("name", "")
    update    = inc.get("update", "")
    source    = inc.get("source", "")
    fail_cnt  = inc.get("failure_count", 0)
    last_poll = inc.get("last_poll", 0.0)
    indicator = inc.get("poll_indicator", "none")
    poll_err  = inc.get("poll_error", "")

    if active:
        sev_color = "#ff4444" if severity in ("major", "critical") else "#ffaa00"
        sev_label = severity.capitalize() if severity else "Active"
        src_label = "Own-call failures" if source == "own_calls" else "Status page poll"
        panel_color = sev_color
        status_line = f'<span style="color:{sev_color};font-weight:bold">⚠️ {sev_label} Incident</span>'
        details = ""
        if name:
            details += f'<div style="margin-top:6px;font-size:0.85em;color:#eee">{name}</div>'
        if update:
            details += f'<div style="margin-top:4px;font-size:0.8em;color:#bbb">{update}</div>'
        details += f'<div style="margin-top:4px;font-size:0.75em;color:#888">Source: {src_label}'
        if fail_cnt:
            details += f" &mdash; {fail_cnt} failure(s) recorded"
        details += "</div>"
    else:
        panel_color = "#00ff88"
        ind_map = {"none": ("Operational", "#00ff88"), "minor": ("Minor", "#ffaa00"),
                   "major": ("Degraded", "#ff4444"), "critical": ("Critical", "#ff4444")}
        ind_label, ind_color = ind_map.get(indicator, ("Unknown", "#888"))
        status_line = f'<span style="color:{ind_color}">✓ {ind_label}</span>'
        details = ""
        if poll_err:
            details = f'<div style="margin-top:4px;font-size:0.75em;color:#888">Poll error: {poll_err[:80]}</div>'

    if last_poll:
        age_s = int(_time.time() - last_poll)
        if age_s < 60:
            poll_str = f"{age_s}s ago"
        elif age_s < 3600:
            poll_str = f"{age_s // 60}m ago"
        else:
            poll_str = f"{age_s // 3600}h ago"
        last_checked = f'<div style="margin-top:6px;font-size:0.72em;color:#666">Last checked: {poll_str} &mdash; <a href="https://status.claude.com" target="_blank" rel="noopener" style="color:#555">status.claude.com ↗</a></div>'
    else:
        last_checked = f'<div style="margin-top:6px;font-size:0.72em;color:#666">Not yet polled &mdash; <a href="https://status.claude.com" target="_blank" rel="noopener" style="color:#555">status.claude.com ↗</a></div>'

    return f"""<div style="font-size:0.85em">{status_line}{details}{last_checked}</div>"""


@app.route("/settings")
def settings_page():
    # Detect windows_agent mode for restart button
    try:
        hw_map_data = hw_monitor._load_hw_map() or {}
        _is_windows_agent = hw_map_data.get("source") == "windows_agent"
        _agent_ip = hw_map_data.get("agent_ip", "")
    except Exception:
        _is_windows_agent = False
        _agent_ip = ""

    # Remote-observation cadence (core settings table). Bounds come from
    # database.py so the input's limits and the server-side clamp cannot drift.
    try:
        obs_n_value = database.get_remote_observe_every_n()
        obs_n_min   = database.REMOTE_OBSERVE_N_MIN
        obs_n_max   = database.REMOTE_OBSERVE_N_MAX
    except Exception:
        obs_n_value, obs_n_min, obs_n_max = 6, 1, 48

    # Read AI Engine settings from the shared DB via the ai_engine module API
    # (ADR 0001 Stage 3 — no longer reaches into modules/ai_engine/ai_engine.db).
    _ai_rate_h   = "10"
    _ai_spend_cap = ""
    _ai_rate_d   = "50"
    _ai_upsell_dismissed = False
    _ai_input_price  = float(os.environ.get("ANTHROPIC_INPUT_PRICE_PER_MTOK",  "3.00") or "3.00")
    _ai_output_price = float(os.environ.get("ANTHROPIC_OUTPUT_PRICE_PER_MTOK", "15.00") or "15.00")
    try:
        from modules.ai_engine import get_settings as _ai_get_settings
        _ai_s = _ai_get_settings()
        _ai_rate_h = _ai_s["rate_per_hour"]
        _ai_spend_cap = _ai_s.get("spend_cap_monthly_usd", "") or ""
        _ai_rate_d = _ai_s["rate_per_day"]
        _ai_upsell_dismissed = _ai_s["ai_upsell_dismissed"]
    except Exception:
        pass
    _ai_incident = {}
    try:
        from modules.ai_engine import get_incident_state as _ai_get_inc
        _ai_incident = _ai_get_inc()
    except Exception:
        pass
    _ai_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if len(_ai_key) >= 8:
        _ai_key_display = "…" + _ai_key[-8:]
        _ai_key_color   = "#00ff88"
    elif _ai_key:
        _ai_key_display = "(set — too short to display)"
        _ai_key_color   = "#ffaa00"
    else:
        _ai_key_display = "(not configured)"
        _ai_key_color   = "#ff4444"

    # Read anomaly_detection settings from DB
    _ad_manual = True
    try:
        conn = _dm_conn()   # §9 batch 2 (settings_page)
        def _ad_st(k, d=""):
            r = conn.execute(
                "SELECT value FROM anomaly_state WHERE key=?", (k,)
            ).fetchone()
            return r[0] if r else d
        _ad_manual = _ad_st("ai_allow_manual_override", "1") == "1"
        # Phase 3: AbuseIPDB + CISA threshold settings
        _ad_ab_active  = _ad_st("abuseipdb_active_control", "dropdown")
        _ad_ab_mode    = _ad_st("abuseipdb_dropdown_mode",  "off")
        _ad_ab_score   = _ad_st("abuseipdb_slider_score",   "40")
        _ad_cisa_active = _ad_st("cisa_active_control", "dropdown")
        _ad_cisa_mode   = _ad_st("cisa_dropdown_mode",  "high_only")
        _ad_cisa_score  = _ad_st("cisa_slider_score",   "60")
        conn.close()
    except Exception:
        _ad_ab_active  = "dropdown"; _ad_ab_mode  = "off";       _ad_ab_score  = "40"
        _ad_cisa_active = "dropdown"; _ad_cisa_mode = "high_only"; _ad_cisa_score = "60"

    # Build module rows dynamically from discovered manifests
    manifests = modules_loader.get_all_manifests()
    module_rows_html = ""
    for name, m in sorted(manifests.items(), key=lambda kv: kv[1].get("display_name", kv[0])):
        enabled = modules_loader.is_enabled(name)
        display_name = html.escape(m.get("display_name", name))
        description = html.escape(m.get("description", ""))
        category = html.escape(m.get("category", ""))
        confirm_required = "true" if m.get("confirmation_required") else "false"
        confirm_msg = html.escape(m.get("confirmation_message", ""), quote=True)
        is_required = m.get("required", False)
        toggle_checked = "checked" if enabled else ""
        status_label = "Enabled" if enabled else "Disabled"
        status_color = "#00ff88" if enabled else "#666"
        if is_required:
            module_rows_html += f"""
        <div class="module-row" id="mod-row-{name}">
            <div class="module-info">
                <div class="module-name">{display_name}
                    <span class="module-cat">{category}</span>
                    <span class="tier-text" style="background:#0a2a1a;color:#00ff88;border:1px solid #00ff8844;border-radius:8px;padding:1px 7px;font-size:0.72em;margin-left:6px;font-weight:bold"
                        data-beginner="Required &#8212; cannot be disabled; other modules depend on it"
                        data-intermediate="Required &#8212; hard-imported by other modules at startup"
                        data-pro="required: true &#8212; load-order guaranteed; set_enabled raises ValueError">core</span>
                </div>
                <div class="module-desc">{description}</div>
                <div class="module-status" id="mod-status-{name}" style="color:{status_color}">{status_label}</div>
            </div>
            <span title="Required module &#8212; cannot be disabled"
                  style="color:#556;font-size:1.4em;cursor:not-allowed;user-select:none"
                  aria-label="Required module">&#128274;</span>
        </div>"""
        else:
            module_rows_html += f"""
        <div class="module-row" id="mod-row-{name}">
            <div class="module-info">
                <div class="module-name">{display_name}
                    <span class="module-cat">{category}</span>
                </div>
                <div class="module-desc">{description}</div>
                <div class="module-status" id="mod-status-{name}" style="color:{status_color}">{status_label}</div>
            </div>
            <label class="toggle-switch" title="{'Enable' if not enabled else 'Disable'} {display_name}">
                <input type="checkbox" id="mod-toggle-{name}" {toggle_checked}
                    onchange="handleModuleToggle('{name}', this.checked, {confirm_required}, '{confirm_msg}')">
                <span class="toggle-slider"></span>
            </label>
        </div>"""

        # AI Engine: inject rate limits, cost estimates, usage, and key status
        if name == "ai_engine":
            module_rows_html += f"""
        <div id="ai-engine-subsettings" class="module-subsettings"
             style="display:{'block' if enabled else 'none'}">
            <div id="ai-engine" style="scroll-margin-top:20px"></div>

            <div class="module-subsettings-row">
                <span class="module-subsettings-label">
                    <span class="tier-text"
                        data-beginner="Anthropic API Key — required for all AI features"
                        data-intermediate="ANTHROPIC_API_KEY"
                        data-pro="API key">Anthropic API Key</span>
                </span>
                <span style="color:{_ai_key_color};font-family:monospace;font-size:0.88em">{html.escape(_ai_key_display)}</span>
                <span style="color:#888;font-size:0.78em;margin-left:10px">
                    Edit: <code style="color:#bbb">sudo nano /etc/nemesis.env</code>
                </span>
            </div>
            <div class="module-subsettings-row">
                <span class="module-subsettings-label">Max automatic AI analyses per hour</span>
                <input type="number" id="ai-rate-hour" value="{html.escape(_ai_rate_h)}"
                       min="0" max="100" class="module-subsettings-input"
                       onchange="saveAIEngineSettings()" oninput="updateAICostEstimate()">
            </div>
            <div class="module-subsettings-row">
                <span class="module-subsettings-label">Max automatic AI analyses per day</span>
                <input type="number" id="ai-rate-day" value="{html.escape(_ai_rate_d)}"
                       min="0" max="1000" class="module-subsettings-input"
                       onchange="saveAIEngineSettings()" oninput="updateAICostEstimate()">
            </div>
            <div class="module-subsettings-row">
                <span class="module-subsettings-label">
                    <span class="tier-text"
                        data-beginner="Stop making AI calls once this much has been spent this calendar month. Leave empty for no limit."
                        data-intermediate="Monthly spend cap (USD). Empty = no cap."
                        data-pro="spend_cap_monthly_usd — enforced in _check_rate_limit from recorded tokens">Monthly spend cap (USD)</span>
                </span>
                <input type="text" id="ai-spend-cap" value="{html.escape(_ai_spend_cap)}"
                       placeholder="no limit" class="module-subsettings-input"
                       onchange="saveAIEngineSettings()">
            </div>

            <div id="ai-cost-estimate" style="background:#060b12;border:1px solid #1e2d4e;
                 border-radius:6px;padding:10px 14px;margin:8px 0 10px 0;font-size:0.83em">

                <div style="margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid #1e2d4e22">
                    <div style="color:#00d4ff;font-weight:bold;margin-bottom:6px;font-size:0.92em">
                        <span class="tier-text"
                            data-beginner="AI Pricing (used for cost estimates below)"
                            data-intermediate="Configured Pricing — Claude Sonnet 4.6"
                            data-pro="Pricing ($/MTok)">Configured Pricing</span>
                    </div>
                    <div style="display:flex;gap:20px;flex-wrap:wrap;margin-bottom:5px">
                        <div>
                            <span style="color:#bbb">
                                <span class="tier-text"
                                    data-beginner="Cost per million tokens sent to AI:"
                                    data-intermediate="Input ($/MTok):"
                                    data-pro="In $/MTok:">Input ($/MTok):</span>
                            </span>
                            <span style="color:#eee;margin-left:6px;font-weight:bold">${html.escape(f"{_ai_input_price:.2f}")}</span>
                        </div>
                        <div>
                            <span style="color:#bbb">
                                <span class="tier-text"
                                    data-beginner="Cost per million tokens received from AI:"
                                    data-intermediate="Output ($/MTok):"
                                    data-pro="Out $/MTok:">Output ($/MTok):</span>
                            </span>
                            <span style="color:#eee;margin-left:6px;font-weight:bold">${html.escape(f"{_ai_output_price:.2f}")}</span>
                        </div>
                    </div>
                    <div style="color:#bbb;font-size:0.88em;line-height:1.5">
                        <span class="tier-text"
                            data-beginner="Last verified: June 2026. If Anthropic changes their prices, update ANTHROPIC_INPUT_PRICE_PER_MTOK and ANTHROPIC_OUTPUT_PRICE_PER_MTOK in /etc/nemesis.env. Check current pricing at"
                            data-intermediate="Last verified: June 2026 · Update in /etc/nemesis.env if pricing changes ·"
                            data-pro="Last verified June 2026 · /etc/nemesis.env ·">Last verified: June 2026 ·</span>
                        <a href="https://claude.com/pricing" target="_blank" rel="noopener"
                           style="color:#00d4ff;text-decoration:none">claude.com/pricing ↗</a>
                    </div>
                </div>

                <div style="color:#00d4ff;font-weight:bold;margin-bottom:6px">
                    <span class="tier-text"
                        data-beginner="Estimated Max AI Cost (based on your rate limits)"
                        data-intermediate="Approx. AI Analysis Cost"
                        data-pro="Cost Estimate (Sonnet 4.6)">Approx. AI Analysis Cost</span>
                </div>
                <div style="display:flex;gap:24px;flex-wrap:wrap;margin-bottom:8px">
                    <div>
                        <span style="color:#bbb">
                            <span class="tier-text"
                                data-beginner="Cost per check:"
                                data-intermediate="Per analysis:"
                                data-pro="Per call (~350in/150out tok):">Per analysis:</span>
                        </span>
                        <span style="color:#eee;margin-left:6px;font-weight:bold" id="ai-cost-per-call">~${html.escape(f"{(350*_ai_input_price/1e6 + 150*_ai_output_price/1e6):.4f}")}</span>
                    </div>
                    <div>
                        <span style="color:#bbb">
                            <span class="tier-text"
                                data-beginner="Max hourly cost:"
                                data-intermediate="Max cost / hour:"
                                data-pro="Max cost/hr:">Max cost / hour:</span>
                        </span>
                        <span style="color:#eee;margin-left:6px;font-weight:bold" id="ai-cost-hour">~${html.escape(f"{float(_ai_rate_h)*(350*_ai_input_price/1e6 + 150*_ai_output_price/1e6):.3f}")}</span>
                    </div>
                    <div>
                        <span style="color:#bbb">
                            <span class="tier-text"
                                data-beginner="Max daily cost:"
                                data-intermediate="Max cost / day:"
                                data-pro="Max cost/day:">Max cost / day:</span>
                        </span>
                        <span style="color:#eee;margin-left:6px;font-weight:bold" id="ai-cost-day">~${html.escape(f"{float(_ai_rate_d)*(350*_ai_input_price/1e6 + 150*_ai_output_price/1e6):.3f}")}</span>
                    </div>
                </div>

                <div style="margin-top:8px;padding-top:8px;border-top:1px solid #1e2d4e22">
                    <div style="display:flex;align-items:center;gap:10px;margin-bottom:7px;flex-wrap:wrap">
                        <span style="color:#00d4ff;font-weight:bold;font-size:0.92em">
                            <span class="tier-text"
                                data-beginner="Actual AI Calls Made (real API calls, not estimates)"
                                data-intermediate="Actual AI Usage"
                                data-pro="Actual Usage">Actual AI Usage</span>
                        </span>
                        <span style="color:#333">|</span>
                        <label style="color:#ccc;font-size:0.82em;cursor:pointer;white-space:nowrap">
                            <input type="radio" name="ai-usage-period" value="hour"
                                   style="accent-color:#00d4ff;cursor:pointer;margin-right:3px"
                                   onchange="switchUsagePeriod('hour')">
                            <span class="tier-text" data-beginner="By Hour (today)" data-intermediate="Hourly" data-pro="1h">Hourly</span>
                        </label>
                        <label style="color:#ccc;font-size:0.82em;cursor:pointer;white-space:nowrap">
                            <input type="radio" name="ai-usage-period" value="day" checked
                                   style="accent-color:#00d4ff;cursor:pointer;margin-right:3px"
                                   onchange="switchUsagePeriod('day')">
                            <span class="tier-text" data-beginner="Today" data-intermediate="Today" data-pro="Today">Today</span>
                        </label>
                        <label style="color:#ccc;font-size:0.82em;cursor:pointer;white-space:nowrap">
                            <input type="radio" name="ai-usage-period" value="week"
                                   style="accent-color:#00d4ff;cursor:pointer;margin-right:3px"
                                   onchange="switchUsagePeriod('week')">
                            <span class="tier-text" data-beginner="This Week" data-intermediate="7 days" data-pro="7d">7 days</span>
                        </label>
                        <label style="color:#ccc;font-size:0.82em;cursor:pointer;white-space:nowrap">
                            <input type="radio" name="ai-usage-period" value="month"
                                   style="accent-color:#00d4ff;cursor:pointer;margin-right:3px"
                                   onchange="switchUsagePeriod('month')">
                            <span class="tier-text" data-beginner="This Month" data-intermediate="30 days" data-pro="30d">30 days</span>
                        </label>
                    </div>
                    <div id="ai-usage-display" style="color:#ccc;font-size:0.88em;min-height:1.4em">
                        <span style="color:#444">Loading usage…</span>
                    </div>
                    <div style="color:#bbb;font-size:0.8em;margin-top:4px">
                        <span class="tier-text"
                            data-beginner="Counts only real API calls — cache hits (where a previous analysis is reused) are free and not counted here."
                            data-intermediate="Cache hits excluded — only new API calls counted."
                            data-pro="Cache hits not counted.">Cache hits excluded — only new API calls counted.</span>
                    </div>
                </div>

                <div style="color:#bbb;font-size:0.9em;line-height:1.5;border-top:1px solid #1e2d4e22;padding-top:7px;margin-top:8px">
                    <strong style="color:#bbb">⚠ Estimates only.</strong>
                    <span class="tier-text"
                        data-beginner="These are rough estimates. Actual cost depends on alert complexity. If Anthropic changes their prices, update ANTHROPIC_INPUT_PRICE_PER_MTOK and ANTHROPIC_OUTPUT_PRICE_PER_MTOK in /etc/nemesis.env."
                        data-intermediate="Based on ~350 input / ~150 output tokens per call at configured prices. Actual varies ±50%. If pricing changes, update ANTHROPIC_INPUT/OUTPUT_PRICE_PER_MTOK in /etc/nemesis.env."
                        data-pro="~350in/~150out tok at configured prices. Varies ±50%. Update ANTHROPIC_IN/OUTPUT_PRICE_PER_MTOK in /etc/nemesis.env if pricing changes.">
                        Based on typical prompt size. Actual costs vary. Update /etc/nemesis.env if pricing changes.
                    </span>
                </div>
            </div>

            <div class="module-subsettings-row" style="margin-top:8px">
                <span class="module-subsettings-label">
                    <span class="tier-text"
                        data-beginner="Show AI suggestions on scan results (a hint to enable AI when it could add context)"
                        data-intermediate="Show AI upsell prompts on findings and incidents when AI is off"
                        data-pro="ai_upsell_dismissed &#8212; 0=show suggestions, 1=hidden">Show AI suggestions on results</span>
                </span>
                <input type="checkbox" id="ai-upsell-show"
                       {'checked' if not _ai_upsell_dismissed else ''}
                       onchange="toggleAIUpsell(this.checked)"
                       style="accent-color:#00d4ff;width:16px;height:16px;cursor:pointer"
                       title="When checked, a small prompt appears on findings suggesting you enable AI for context">
            </div>

            <div id="ai-engine-settings-status"
                 style="height:1.2em;font-size:0.8em;margin-top:8px;color:#00ff88"></div>

            <div style="margin-top:18px;padding:12px;background:#0d1b2e;border-radius:8px;
                        border:1px solid #1e3a5f">
                <div style="color:#00d4ff;font-size:0.75em;text-transform:uppercase;
                            letter-spacing:1px;margin-bottom:10px">
                    <span data-beginner="Is Anthropic&#39;s AI service healthy right now?"
                          data-intermediate="Anthropic service health — drives auto-block and banner"
                          data-pro="Anthropic incident state (poll + own-call failure tracking)">
                        Anthropic Service Status
                    </span>
                </div>
                {_settings_incident_panel(_ai_incident)}
            </div>

        </div>"""

        # Anomaly detection: manual override toggle + AbuseIPDB + CISA thresholds
        elif name == "anomaly_detection":
            _manual_checked  = "checked" if _ad_manual else ""
            # AbuseIPDB radio states
            _ab_drop_chk   = "checked" if _ad_ab_active  == "dropdown" else ""
            _ab_score_chk  = "checked" if _ad_ab_active  == "slider"   else ""
            _ab_off_sel    = "selected" if _ad_ab_mode   == "off"         else ""
            _ab_med_sel    = "selected" if _ad_ab_mode   == "medium_plus" else ""
            _ab_hi_sel     = "selected" if _ad_ab_mode   == "high_only"   else ""
            # CISA radio states
            _ci_drop_chk   = "checked" if _ad_cisa_active == "dropdown" else ""
            _ci_score_chk  = "checked" if _ad_cisa_active == "slider"   else ""
            _ci_hi_sel     = "selected" if _ad_cisa_mode  == "high_only"    else ""
            _ci_crit_sel   = "selected" if _ad_cisa_mode  == "critical_only" else ""
            module_rows_html += f"""
        <div id="ad-subsettings" class="module-subsettings"
             style="display:{'block' if enabled else 'none'}">

            <div class="module-subsettings-row">
                <span class="module-subsettings-label">
                    Allow manual AI analysis when automatic rate limit is reached
                </span>
                <label class="toggle-switch" style="flex-shrink:0">
                    <input type="checkbox" id="ad-allow-manual" {_manual_checked}
                           onchange="saveAnomalySettings()">
                    <span class="toggle-slider"></span>
                </label>
            </div>

            <div style="color:#00d4ff;font-size:0.75em;text-transform:uppercase;
                        letter-spacing:0.06em;margin:14px 0 6px;font-weight:bold">
                AbuseIPDB Auto-Reporting Threshold
                <span style="color:#bbb;font-weight:normal;font-size:0.88em;margin-left:6px;
                             text-transform:none;letter-spacing:0">
                  — select which control is active (●)
                </span>
            </div>
            <div class="module-subsettings-row" style="gap:8px">
                <input type="radio" name="ad-ab-ctrl" id="ad-ab-use-drop" value="dropdown"
                       {_ab_drop_chk} onchange="saveAnomalySettings()"
                       style="accent-color:#00d4ff;flex-shrink:0;cursor:pointer">
                <label for="ad-ab-use-drop" class="module-subsettings-label"
                       style="cursor:pointer">Named level</label>
                <select id="ad-abuseipdb-mode" onchange="saveAnomalySettings()"
                        style="background:#1a1a2e;border:1px solid #333;color:#eee;
                               padding:3px 6px;border-radius:4px;font-size:0.86em">
                    <option value="off" {_ab_off_sel}>Off (default)</option>
                    <option value="medium_plus" {_ab_med_sel}>Medium-and-above (score ≥ 30)</option>
                    <option value="high_only"   {_ab_hi_sel}>High-only (score ≥ 60)</option>
                </select>
            </div>
            <div class="module-subsettings-row" style="gap:8px">
                <input type="radio" name="ad-ab-ctrl" id="ad-ab-use-score" value="slider"
                       {_ab_score_chk} onchange="saveAnomalySettings()"
                       style="accent-color:#00d4ff;flex-shrink:0;cursor:pointer">
                <label for="ad-ab-use-score" class="module-subsettings-label"
                       style="cursor:pointer">Custom score</label>
                <input type="number" id="ad-abuseipdb-score" value="{html.escape(_ad_ab_score)}"
                       min="0" max="100" class="module-subsettings-input"
                       onchange="saveAnomalySettings()">
                <span style="color:#bbb;font-size:0.82em">≥ score</span>
            </div>

            <div style="color:#00d4ff;font-size:0.75em;text-transform:uppercase;
                        letter-spacing:0.06em;margin:14px 0 6px;font-weight:bold">
                CISA Button Threshold
                <span style="color:#bbb;font-weight:normal;font-size:0.88em;margin-left:6px;
                             text-transform:none;letter-spacing:0">
                  — sets when "CISA" button appears on incidents
                </span>
            </div>
            <div class="module-subsettings-row" style="gap:8px">
                <input type="radio" name="ad-cisa-ctrl" id="ad-cisa-use-drop" value="dropdown"
                       {_ci_drop_chk} onchange="saveAnomalySettings()"
                       style="accent-color:#ffaa00;flex-shrink:0;cursor:pointer">
                <label for="ad-cisa-use-drop" class="module-subsettings-label"
                       style="cursor:pointer">Named level</label>
                <select id="ad-cisa-mode" onchange="saveAnomalySettings()"
                        style="background:#1a1a2e;border:1px solid #333;color:#eee;
                               padding:3px 6px;border-radius:4px;font-size:0.86em">
                    <option value="high_only"    {_ci_hi_sel}>High-and-above (score ≥ 60)</option>
                    <option value="critical_only" {_ci_crit_sel}>Critical-only (score ≥ 80)</option>
                </select>
            </div>
            <div class="module-subsettings-row" style="gap:8px">
                <input type="radio" name="ad-cisa-ctrl" id="ad-cisa-use-score" value="slider"
                       {_ci_score_chk} onchange="saveAnomalySettings()"
                       style="accent-color:#ffaa00;flex-shrink:0;cursor:pointer">
                <label for="ad-cisa-use-score" class="module-subsettings-label"
                       style="cursor:pointer">Custom score</label>
                <input type="number" id="ad-cisa-score" value="{html.escape(_ad_cisa_score)}"
                       min="0" max="100" class="module-subsettings-input"
                       onchange="saveAnomalySettings()">
                <span style="color:#bbb;font-size:0.82em">≥ score</span>
            </div>

            <div id="ad-settings-status"
                 style="height:1.2em;font-size:0.8em;margin-top:8px;color:#00ff88"></div>
        </div>"""

        # Tickets module: inject settings sub-section below its module row
        if name == "tickets":
            try:
                from modules.tickets.module import _get_settings as _tk_settings
                _tk = _tk_settings()
            except Exception:
                _tk = {"relevance_threshold": 70, "auto_ticket_on_alert": True,
                       "min_severity_for_auto_ticket": "HIGH", "max_related_results": 5}
            _tk_auto_chk = "checked" if _tk.get("auto_ticket_on_alert") else ""
            _tk_sev      = str(_tk.get("min_severity_for_auto_ticket", "HIGH"))
            module_rows_html += f"""
        <div id="tk-subsettings" class="module-subsettings"
             style="display:{'block' if enabled else 'none'}">
            <div style="color:#00d4ff;font-size:0.75em;text-transform:uppercase;
                        letter-spacing:0.06em;margin-bottom:10px;font-weight:bold">
                Ticket &amp; Note Settings
            </div>

            <div class="module-subsettings-row">
                <span class="module-subsettings-label">
                    <span class="tier-text"
                        data-beginner="Auto-create a ticket when a new high-severity alert fires"
                        data-intermediate="Auto-open ticket on alert"
                        data-pro="Auto-ticket on alert">Auto-open ticket on alert</span>
                </span>
                <label class="toggle-switch" style="flex-shrink:0">
                    <input type="checkbox" id="tk-auto-ticket" {_tk_auto_chk}
                           onchange="saveTicketSettings()">
                    <span class="toggle-slider"></span>
                </label>
            </div>

            <div class="module-subsettings-row">
                <span class="module-subsettings-label">
                    <span class="tier-text"
                        data-beginner="Minimum alert severity level that triggers auto-ticket creation"
                        data-intermediate="Min severity for auto-ticket"
                        data-pro="Min severity">Min severity for auto-ticket</span>
                </span>
                <select id="tk-min-severity" onchange="saveTicketSettings()"
                        style="background:#1a1a2e;border:1px solid #333;color:#eee;
                               padding:3px 6px;border-radius:4px;font-size:0.86em">
                    <option value="LOW"      {"selected" if _tk_sev=="LOW"      else ""}>LOW</option>
                    <option value="MEDIUM"   {"selected" if _tk_sev=="MEDIUM"   else ""}>MEDIUM</option>
                    <option value="HIGH"     {"selected" if _tk_sev=="HIGH"     else ""}>HIGH</option>
                    <option value="CRITICAL" {"selected" if _tk_sev=="CRITICAL" else ""}>CRITICAL</option>
                </select>
            </div>

            <div class="module-subsettings-row">
                <span class="module-subsettings-label">
                    <span class="tier-text"
                        data-beginner="How similar (0–100) another ticket must be before it's shown as possibly related to a new one"
                        data-intermediate="Relevance threshold for related tickets (0–100)"
                        data-pro="Relevance threshold (0–100)">Relevance threshold (0–100)</span>
                </span>
                <input type="number" id="tk-threshold"
                       value="{html.escape(str(_tk.get('relevance_threshold', 70)))}"
                       min="0" max="100" class="module-subsettings-input"
                       onchange="saveTicketSettings()" oninput="saveTicketSettings()">
            </div>

            <div class="module-subsettings-row">
                <span class="module-subsettings-label">
                    <span class="tier-text"
                        data-beginner="Maximum number of related tickets to surface per new ticket"
                        data-intermediate="Max related results shown"
                        data-pro="Max related results">Max related results</span>
                </span>
                <input type="number" id="tk-max-related"
                       value="{html.escape(str(_tk.get('max_related_results', 5)))}"
                       min="1" max="20" class="module-subsettings-input"
                       onchange="saveTicketSettings()" oninput="saveTicketSettings()">
            </div>

            <div id="tk-settings-status"
                 style="height:1.2em;font-size:0.8em;margin-top:8px;color:#00ff88"></div>
        </div>"""

    if not module_rows_html:
        module_rows_html = '<p style="color:#bbb;font-style:italic">No modules found in modules/ directory.</p>'

    # Users section — multi-user is a commercial-tier feature (entitlements gate).
    if entitlements.is_commercial():
        _add_user_html = (
            '<div class="card" style="margin-bottom:16px"><h2>&#128101; Users</h2>'
            '<button onclick="alert(&#39;User management UI coming soon.&#39;)" '
            'style="background:#00d4ff22;color:#00d4ff;border:1px solid #00d4ff;border-radius:6px;'
            'padding:7px 16px;cursor:pointer">+ Add User</button></div>'
        )
    else:
        _add_user_html = (
            '<div class="card" style="margin-bottom:16px;opacity:0.75"><h2>&#128101; Users</h2>'
            '<button disabled title="Available in the commercial tier" '
            'style="background:#222;color:#888;border:1px solid #444;border-radius:6px;'
            'padding:7px 16px;cursor:not-allowed">+ Add User (Commercial)</button>'
            '<p style="color:#888;font-size:0.85em;margin-top:8px">Multi-user accounts are part of '
            'the commercial tier. You&#39;re running the free tier &mdash; a single admin account.</p></div>'
        )

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Nemesis — Settings</title>
    <script src="/static/tier.js"></script>
    <script src="/static/fw-credential.js"></script>
    <script src="/static/nemesis-idle-lock.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; background: #1a1a2e; color: #eee;
               padding: 24px; max-width: 700px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; margin-bottom: 4px; }}
        h2 {{ color: #00d4ff; font-size: 1.05em; margin: 28px 0 8px 0;
             border-bottom: 1px solid #1e2d4e; padding-bottom: 6px; }}
        .back {{ color: #00d4ff; text-decoration: none; font-size: 0.9em; }}
        .back:hover {{ text-decoration: underline; }}
        .settings-section {{ margin-bottom: 32px; }}
        .tier-option {{ display: flex; align-items: flex-start; gap: 12px;
                       padding: 12px 14px; border-radius: 6px; cursor: pointer;
                       border: 1px solid transparent; margin-bottom: 8px;
                       transition: background 0.15s, border-color 0.15s; }}
        .tier-option:hover {{ background: rgba(0,212,255,0.06); }}
        .tier-option.selected {{ background: rgba(0,212,255,0.1);
                                border-color: rgba(0,212,255,0.4); }}
        .tier-option input[type=radio] {{ margin-top: 3px; flex-shrink: 0;
                                          accent-color: #00d4ff; width: 16px; height: 16px; }}
        .tier-label {{ flex: 1; }}
        .tier-label strong {{ color: #eee; font-size: 1em; }}
        .tier-label em {{ color: #bbb; font-size: 0.85em; margin-left: 6px; }}
        .tier-label p {{ color: #ccc; font-size: 0.85em; margin: 4px 0 0 0; line-height: 1.5; }}
        .save-note {{ color: #00ff88; font-size: 0.82em; margin-top: 6px; display: none; }}
        .settings-intro {{ color: #ccc; font-size: 0.9em; margin: 0 0 18px 0; line-height: 1.6; }}
        /* Module rows */
        .module-row {{ display: flex; align-items: center; gap: 14px;
                       padding: 14px 0; border-bottom: 1px solid #1e2d4e; }}
        .module-row:last-child {{ border-bottom: none; }}
        .module-info {{ flex: 1; }}
        .module-name {{ font-weight: bold; color: #eee; margin-bottom: 3px; }}
        .module-cat {{ display: inline-block; font-size: 0.72em; color: #00d4ff;
                       background: rgba(0,212,255,0.1); padding: 1px 7px;
                       border-radius: 10px; margin-left: 8px; font-weight: normal;
                       vertical-align: middle; }}
        .module-desc {{ color: #ccc; font-size: 0.84em; line-height: 1.5; margin-bottom: 4px; }}
        .module-status {{ font-size: 0.78em; font-weight: bold; }}
        /* Module sub-settings (e.g. anomaly detection AI config) */
        .module-subsettings {{ background: rgba(0,212,255,0.03);
                                border: 1px solid #1e2d4e; border-radius: 6px;
                                padding: 12px 16px; margin: -6px 0 4px 0; }}
        .module-subsettings-row {{ display: flex; align-items: center; gap: 12px;
                                    padding: 7px 0; border-bottom: 1px solid #1e2d4e44; }}
        .module-subsettings-row:last-of-type {{ border-bottom: none; }}
        .module-subsettings-label {{ color: #ccc; font-size: 0.86em; flex: 1; }}
        .module-subsettings-input {{ background: #1a1a2e; border: 1px solid #333; color: #eee;
                                      padding: 4px 8px; border-radius: 4px; width: 60px;
                                      text-align: center; font-size: 0.9em; }}
        /* Toggle switch */
        .toggle-switch {{ position: relative; display: inline-block;
                          width: 48px; height: 26px; flex-shrink: 0; }}
        .toggle-switch input {{ opacity: 0; width: 0; height: 0; }}
        .toggle-slider {{ position: absolute; cursor: pointer; inset: 0;
                          background: #333; border-radius: 26px;
                          transition: background 0.2s; }}
        .toggle-slider:before {{ content: ""; position: absolute;
                                  width: 20px; height: 20px; left: 3px; bottom: 3px;
                                  background: #888; border-radius: 50%;
                                  transition: transform 0.2s, background 0.2s; }}
        input:checked + .toggle-slider {{ background: rgba(0,212,255,0.25); }}
        input:checked + .toggle-slider:before {{ transform: translateX(22px); background: #00d4ff; }}
        /* Confirmation modal */
        .confirm-overlay {{ display: none; position: fixed; inset: 0;
                             background: rgba(0,0,0,0.85); z-index: 100; }}
        .confirm-box {{ background: #16213e; border: 1px solid #ffaa00;
                         border-radius: 10px; padding: 24px; max-width: 500px;
                         margin: 100px auto; }}
        .confirm-box h3 {{ color: #ffaa00; margin-top: 0; }}
        .confirm-box p {{ color: #ccc; font-size: 0.9em; line-height: 1.6; }}
        .confirm-check {{ display: flex; align-items: flex-start; gap: 10px;
                           margin: 16px 0; cursor: pointer; }}
        .confirm-check input {{ flex-shrink: 0; margin-top: 3px;
                                  accent-color: #ffaa00; width: 16px; height: 16px; }}
        .confirm-check span {{ color: #eee; font-size: 0.9em; }}
        .confirm-actions {{ display: flex; gap: 10px; margin-top: 16px; }}
        .btn-confirm {{ padding: 9px 20px; background: #ffaa00; color: #1a1a2e;
                         border: none; border-radius: 5px; cursor: pointer;
                         font-weight: bold; opacity: 0.4; }}
        .btn-confirm.ready {{ opacity: 1; cursor: pointer; }}
        .btn-cancel {{ padding: 9px 20px; background: #333; color: #eee;
                        border: none; border-radius: 5px; cursor: pointer; }}
        /* Danger zone */
        .danger-zone {{ margin-top: 40px; border: 1px solid #8b0000;
                         border-radius: 8px; padding: 16px 20px;
                         background: #0d0608; }}
        .danger-zone h2 {{ margin-top: 0; color: #ff4444; font-size: 1em;
                            letter-spacing: 0.05em; text-transform: uppercase; }}
        .danger-zone p {{ color: #aaa; font-size: 0.85em; margin: 6px 0 14px; }}
        .btn-uninstall {{ background: transparent; color: #ff4444;
                           border: 1px solid #8b0000; padding: 9px 20px;
                           border-radius: 6px; cursor: pointer; font-size: 0.9em;
                           font-weight: bold; }}
        .btn-uninstall:hover {{ background: #8b0000; color: #fff; }}
        /* Uninstall modal */
        .uninstall-overlay {{ display: none; position: fixed; inset: 0;
                               background: rgba(0,0,0,0.9); z-index: 200; }}
        .uninstall-box {{ background: #0d0608; border: 1px solid #8b0000;
                           border-radius: 10px; padding: 28px; max-width: 520px;
                           margin: 80px auto; }}
        .uninstall-box h3 {{ color: #ff4444; margin-top: 0; }}
        .uninstall-box p {{ color: #ccc; font-size: 0.88em; line-height: 1.6;
                             margin: 6px 0; }}
        .uninstall-box .safe-note {{ color: #4caf50; font-size: 0.85em;
                                      margin-top: 10px; }}
        .uninstall-yes-row {{ margin: 18px 0 8px; }}
        .uninstall-yes-row label {{ color: #eee; font-size: 0.85em;
                                     display: block; margin-bottom: 6px; }}
        .uninstall-yes-input {{ background: #1a0608; border: 1px solid #8b0000;
                                  color: #ff4444; padding: 8px 12px; border-radius: 4px;
                                  font-size: 1em; font-family: monospace; width: 100px;
                                  letter-spacing: 0.1em; }}
        .uninstall-yes-input:focus {{ outline: none; border-color: #ff4444; }}
        .uninstall-actions {{ display: flex; gap: 10px; margin-top: 18px; }}
        .btn-uninstall-confirm {{ padding: 9px 20px; background: #8b0000;
                                   color: #fff; border: none; border-radius: 5px;
                                   cursor: pointer; font-weight: bold;
                                   opacity: 0.35; pointer-events: none; }}
        .btn-uninstall-confirm.ready {{ opacity: 1; pointer-events: auto; }}
        .btn-uninstall-confirm.ready:hover {{ background: #cc0000; }}
        .uninstall-result {{ margin-top: 14px; padding: 12px;
                              background: #111; border-radius: 4px;
                              color: #ffaa00; font-size: 0.83em;
                              line-height: 1.6; display: none; }}
        /* Backup UI */
        .btn-backup {{ background: transparent; color: #4ca1ff;
                       border: 1px solid #1e4a80; padding: 9px 20px;
                       border-radius: 6px; cursor: pointer; font-size: 0.9em;
                       font-weight: bold; }}
        .btn-backup:hover {{ background: #1e3060; color: #7cc8ff; }}
        .dz-field-label {{ color: #aaa; font-size: 0.78em;
                           display: block; margin-bottom: 4px; }}
        .schedule-toggle {{ display: flex; align-items: center; gap: 8px;
                            cursor: pointer; color: #aaa; font-size: 0.85em;
                            margin-top: 14px; user-select: none; }}
        .schedule-toggle input {{ accent-color: #4ca1ff; cursor: pointer; }}
        .schedule-select {{ background: #1a1a2e; border: 1px solid #333;
                            color: #eee; padding: 7px 10px; border-radius: 4px;
                            font-size: 0.88em; }}
        .backup-path-input {{ background: #1a1a2e; border: 1px solid #333;
                              color: #eee; padding: 7px 10px; border-radius: 4px;
                              font-size: 0.88em; }}
        .btn-save-sched {{ background: transparent; color: #4ca1ff;
                           border: 1px solid #1e4a80; padding: 7px 16px;
                           border-radius: 4px; cursor: pointer; font-size: 0.85em; }}
        .btn-save-sched:hover {{ background: #1e3060; }}
        .backup-overlay {{ display: none; position: fixed; inset: 0;
                           background: rgba(0,0,0,0.88); z-index: 200; }}
        .backup-box {{ background: #080d1a; border: 1px solid #1e4a80;
                       border-radius: 10px; padding: 28px; max-width: 520px;
                       margin: 80px auto; }}
        .backup-box h3 {{ color: #4ca1ff; margin-top: 0; }}
        .backup-box p {{ color: #ccc; font-size: 0.88em; line-height: 1.6;
                         margin: 6px 0; }}
        .backup-file-list {{ list-style: none; padding: 0; margin: 8px 0 14px; }}
        .backup-file-list li {{ color: #bbb; font-size: 0.84em; padding: 3px 0; }}
        .backup-file-list li::before {{ content: "✓  "; color: #4ca1ff; }}
        .file-hint {{ color: #555; font-size: 0.88em; font-family: monospace; }}
        .backup-size-text {{ color: #aaa; font-size: 0.82em; margin: 10px 0 4px; }}
        .backup-path-row {{ margin-top: 14px; }}
        .backup-result {{ padding: 10px 12px; background: #111; border-radius: 4px;
                          font-size: 0.82em; line-height: 1.6; color: #4ca1ff; }}
        .backup-result.error {{ color: #ff6666; }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
        .backup-spinner {{ display: inline-block; width: 14px; height: 14px;
                           border: 2px solid #222; border-top-color: #4ca1ff;
                           border-radius: 50%; animation: spin 0.8s linear infinite;
                           vertical-align: middle; margin-right: 6px; }}
        /* Filesystem browser */
        .fs-browse-btn {{ background: #1a2a4a; border: 1px solid #2a4a7a; color: #7cc8ff;
                          padding: 5px 12px; border-radius: 4px; cursor: pointer;
                          font-size: 0.85em; white-space: nowrap; }}
        .fs-browse-btn:hover {{ background: #1e3060; border-color: #00d4ff; color: #eee; }}
        .fs-browser {{ background: #0d1117; border: 1px solid #2a3a5a; border-radius: 6px;
                       padding: 10px; max-height: 220px; overflow-y: auto; }}
        .fs-browser-path {{ color: #00d4ff; font-size: 0.8em; font-family: monospace;
                            margin-bottom: 8px; word-break: break-all; }}
        .fs-browser-item {{ display: block; padding: 5px 8px; color: #ccc; cursor: pointer;
                            border-radius: 4px; font-size: 0.84em; font-family: monospace; }}
        .fs-browser-item:hover {{ background: rgba(0,212,255,0.08); color: #00d4ff; }}
        .fs-browser-select {{ background: #00d4ff; color: #1a1a2e; border: none;
                              padding: 5px 14px; border-radius: 4px; cursor: pointer;
                              font-size: 0.82em; font-weight: bold; margin-top: 8px; }}
        /* Config Wizard */
        .wizard-overlay {{ display: none; position: fixed; inset: 0;
                           background: rgba(0,0,0,0.88); z-index: 300; overflow-y: auto; }}
        .wizard-box {{ background: #080d1a; border: 1px solid #00d4ff; border-radius: 10px;
                       padding: 28px; max-width: 640px; width: 90%; margin: 60px auto; }}
        .wizard-box h3 {{ color: #00d4ff; margin-top: 0; }}
        .wizard-steps {{ display: flex; gap: 4px; margin-bottom: 20px; flex-wrap: wrap; }}
        .wizard-step-dot {{ padding: 3px 10px; border-radius: 10px; font-size: 0.78em;
                            font-weight: bold; cursor: default; white-space: nowrap; }}
        .wizard-step-dot.active {{ background: #00d4ff; color: #1a1a2e; }}
        .wizard-step-dot.done {{ background: #00ff8833; color: #00ff88;
                                 border: 1px solid #00ff8855; }}
        .wizard-step-dot.idle {{ background: #1a2a3a; color: #666;
                                 border: 1px solid #2a3a5a; }}
        .wizard-field {{ margin-bottom: 14px; }}
        .wizard-label {{ display: block; color: #ccc; font-size: 0.85em; margin-bottom: 4px; }}
        .wizard-input {{ background: #1a1a2e; border: 1px solid #333; color: #eee;
                         padding: 7px 10px; border-radius: 4px; width: 100%;
                         box-sizing: border-box; font-size: 0.9em; }}
        .wizard-input:focus {{ outline: none; border-color: #00d4ff; }}
        .wizard-input[readonly] {{ color: #888; cursor: default; }}
        .wizard-row {{ display: flex; gap: 8px; align-items: center; }}
        .wizard-row .wizard-input {{ flex: 1; }}
        .wizard-show-btn {{ background: transparent; border: 1px solid #444; color: #bbb;
                            padding: 6px 10px; border-radius: 4px; cursor: pointer;
                            font-size: 0.8em; white-space: nowrap; flex-shrink: 0; }}
        .wizard-validate-btn {{ background: #1a2a4a; border: 1px solid #2a4a7a;
                                color: #7cc8ff; padding: 6px 12px; border-radius: 4px;
                                cursor: pointer; font-size: 0.8em; white-space: nowrap;
                                flex-shrink: 0; }}
        .wizard-validate-btn:hover {{ background: #1e3060; }}
        .wizard-key-status {{ font-size: 0.78em; margin-top: 4px; }}
        .wizard-nav {{ display: flex; gap: 10px; margin-top: 20px; flex-wrap: wrap; }}
        .wizard-btn-next {{ background: #00d4ff; color: #1a1a2e; border: none;
                            padding: 10px 24px; border-radius: 5px; cursor: pointer;
                            font-weight: bold; font-size: 0.95em; }}
        .wizard-btn-back {{ background: #333; color: #eee; border: none;
                            padding: 10px 20px; border-radius: 5px; cursor: pointer; }}
        .wizard-btn-save {{ background: #00ff88; color: #1a1a2e; border: none;
                            padding: 10px 24px; border-radius: 5px; cursor: pointer;
                            font-weight: bold; font-size: 0.95em; }}
        .wizard-status {{ font-size: 0.82em; margin-left: 10px; }}
        .wizard-test-btn {{ background: transparent; border: 1px solid #4ca1ff;
                            color: #4ca1ff; padding: 7px 14px; border-radius: 4px;
                            cursor: pointer; font-size: 0.85em; }}
        .wizard-test-btn:hover {{ background: #1e3060; }}
        .wizard-review-row {{ display: flex; gap: 10px; padding: 6px 0;
                              border-bottom: 1px solid #1e2d4e; font-size: 0.88em; }}
        .wizard-review-key {{ color: #00d4ff; font-family: monospace; min-width: 180px;
                              flex-shrink: 0; }}
        .wizard-review-val {{ color: #eee; word-break: break-all; }}
        .wizard-section-title {{ color: #00d4ff; font-size: 0.8em; text-transform: uppercase;
                                 letter-spacing: 0.06em; margin: 14px 0 8px; }}
    </style>
</head>
<body>
    <h1>⚙️ Settings
        <a href="/diagnostics" target="_blank" rel="noopener"
           style="float:right;font-size:0.42em;color:#bbb;text-decoration:none;font-weight:normal;margin-top:10px"
           title="Diagnostics &amp; Support">🔍 Diagnostics</a>
    </h1>
    <p><a class="back" href="/">← Back to Dashboard</a></p>

    {_add_user_html}
    <script src="/static/agent-enroll.js"></script>
    {_render_agent_devices_html()}

    <div id="moduleRestartBanner" style="display:none;background:#2a1800;border:1px solid #ffaa00;border-radius:8px;padding:12px 16px;margin-bottom:16px;align-items:center;gap:12px;flex-wrap:wrap">
        <span class="tier-text"
            data-beginner="⚠️ The Nemesis dashboard needs to restart to apply this change — this only takes a few seconds and won't affect your other running programs."
            data-intermediate="⚠️ Dashboard restart required for module changes to take effect."
            data-pro="⚠️ Module route changes require Flask restart.">⚠️ Dashboard restart required for module changes to take effect.</span>
        <span style="display:flex;gap:8px;flex-shrink:0;margin-left:auto">
            <button onclick="restartFromModuleBanner()"
                style="background:#ff4444;color:#fff;border:none;padding:7px 16px;border-radius:5px;cursor:pointer;font-weight:bold;font-size:0.9em">Restart Dashboard</button>
            <button onclick="dismissModuleRestartBanner()"
                style="background:#333;color:#ccc;border:1px solid #555;padding:7px 14px;border-radius:5px;cursor:pointer;font-size:0.9em">Later</button>
        </span>
    </div>

    <div class="settings-section" style="background:#0d1117;border:1px solid #1e2d4e;border-radius:8px;padding:16px 20px">
        <h2 style="margin-top:0;color:#00d4ff">System Control</h2>
        <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:center">
            <button id="restartDashBtn" onclick="restartDashboard()"
                style="background:#ff4444;color:#fff;border:none;padding:10px 20px;border-radius:6px;cursor:pointer;font-weight:bold;font-size:0.95em">
                🔄 Restart Dashboard
            </button>
            <button onclick="openConfigWizard()"
                style="background:#00d4ff;color:#1a1a2e;border:none;padding:10px 20px;border-radius:6px;cursor:pointer;font-weight:bold;font-size:0.95em">
                ⚙️ Configuration Wizard
            </button>
            <span id="dashUptimeLabel" style="color:#ccc;font-size:0.85em">Loading uptime…</span>
            <span id="restartDashMsg" style="color:#ffaa00;font-size:0.85em;display:none">Restarting — page will reload in 5 seconds…</span>
            {'<button id="restartAgentBtn" onclick="restartWindowsAgent()"style="background:#ff8800;color:#fff;border:none;padding:10px 20px;border-radius:6px;cursor:pointer;font-weight:bold;font-size:0.95em;margin-left:4px">🖥️ Restart Windows Agent</button><span id="restartAgentMsg" style="color:#ffaa00;font-size:0.85em;display:none">Restart command sent…</span>' if _is_windows_agent else ''}
        </div>
        <p style="color:#ccc;font-size:0.82em;margin:10px 0 0 0">Restart applies configuration changes and clears cached state. The page will auto-reload after 5 seconds.</p>
    </div>

    <div class="settings-section">
        <h2>Explanation Detail Level</h2>
        <p class="settings-intro">
            Controls how labels, descriptions, and explanatory text are displayed across
            the dashboard. Your preference is saved per browser and takes effect immediately.
        </p>

        <div class="tier-option" id="optBeginner" onclick="chooseTier('beginner')">
            <input type="radio" name="tier" id="radioBeginner" value="beginner">
            <div class="tier-label">
                <strong>Beginner</strong>
                <p>Full plain-English explanations with context. Best for users new to
                   network security — explains what each alert means, whether to worry,
                   and what to do. Nothing is assumed.</p>
            </div>
        </div>

        <div class="tier-option" id="optIntermediate" onclick="chooseTier('intermediate')">
            <input type="radio" name="tier" id="radioIntermediate" value="intermediate">
            <div class="tier-label">
                <strong>Intermediate</strong> <em>(default)</em>
                <p>Balanced detail — clear labels with enough context to act, without
                   over-explaining fundamentals. Good for users comfortable with the
                   basics of networking and security.</p>
            </div>
        </div>

        <div class="tier-option" id="optPro" onclick="chooseTier('pro')">
            <input type="radio" name="tier" id="radioPro" value="pro">
            <div class="tier-label">
                <strong>Pro</strong>
                <p>Concise technical language for experienced users. Abbreviations,
                   protocol names, and security terminology used without explanation.
                   Maximum signal, minimum prose.</p>
            </div>
        </div>

        <p class="save-note" id="saveNote">✓ Saved — takes effect immediately on all pages</p>
    </div>

    <div class="settings-section">
        <h2>Modules</h2>
        <p class="settings-intro">
            Optional features that can be enabled or disabled independently.
            Disabled modules are not loaded at all — they have zero runtime cost.
            Changes take effect immediately.
        </p>
        <div id="moduleList">
        {module_rows_html}
        </div>
        <p id="moduleMsg" style="display:none;font-size:0.85em;margin-top:10px"></p>
    </div>

    <div class="settings-card">
        <h2>🌡️ Hardware Tools</h2>
        <div style="display:flex;flex-direction:column;gap:16px">
            <div>
                <div style="color:#ccc;font-size:0.9em;margin-bottom:8px;font-weight:bold">Reset Sensor Baselines</div>
                <div style="color:#bbb;font-size:0.82em;margin-bottom:10px">
                    Clears the anomaly history used to calculate the rolling baseline for each sensor.
                    Use this after a hardware change (new cooler, replaced fan, etc.) so the new readings
                    are not flagged as anomalous.
                </div>
                <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
                    <select id="hw-baseline-sensor"
                            style="background:#0d1117;border:1px solid #333;color:#eee;padding:5px 10px;border-radius:4px;font-size:0.85em">
                        <option value="all">All sensors</option>
                        <option value="cpu_temp">CPU temperature</option>
                        <option value="gpu_temp">GPU temperature</option>
                        <option value="ambient_temp">Ambient temperature</option>
                        <option value="nvme_temp">NVMe temperature</option>
                        <option value="cpu_percent">CPU load %</option>
                        <option value="ram_used_gb">RAM used</option>
                    </select>
                    <button onclick="hwResetBaseline()"
                            style="background:#333;border:1px solid #555;color:#eee;padding:5px 14px;cursor:pointer;border-radius:4px;font-size:0.85em">
                        Reset baseline
                    </button>
                    <span id="hw-baseline-status" style="font-size:0.82em;color:#bbb"></span>
                </div>
            </div>
            <div style="border-top:1px solid #1e2d4e;padding-top:16px">
                <div style="color:#ccc;font-size:0.9em;margin-bottom:8px;font-weight:bold">Re-run Hardware Discovery</div>
                <div style="color:#bbb;font-size:0.82em;margin-bottom:10px">
                    Re-runs hw_discover.py to rebuild the sensor map (hw_map.json).
                    Use this if sensors have changed or auto-discovery is picking up the wrong readings.
                    hw_monitor will pick up the new map on its next sample cycle.
                </div>
                <div style="display:flex;align-items:center;gap:10px">
                    <button onclick="hwRediscover()"
                            style="background:#333;border:1px solid #555;color:#eee;padding:5px 14px;cursor:pointer;border-radius:4px;font-size:0.85em">
                        Re-run discovery
                    </button>
                    <span id="hw-rediscover-status" style="font-size:0.82em;color:#bbb"></span>
                </div>
                <div id="hw-rediscover-output"
                     style="display:none;margin-top:10px;background:#0d1117;border:1px solid #333;border-radius:4px;padding:10px;font-size:0.75em;color:#ccc;white-space:pre-wrap;max-height:200px;overflow-y:auto"></div>
            </div>
        </div>
    </div>

    <!-- Agents -->
    <div class="card">
        <h2>📡 <span class="tier-text"
            data-beginner="Devices Away From Home"
            data-intermediate="Agent Devices"
            data-pro="Agents">Agent Devices</span></h2>
        <div style="padding:0 4px">
            <p style="margin:0 0 10px;font-size:0.86em;color:#bbb">
                <span class="tier-text"
                    data-beginner="Devices on your own network send Nemesis a detailed report every few minutes &mdash; that costs nothing, because the data never leaves your network. A device somewhere else (hotel, coffee shop, phone hotspot) sends the same full report less often, so it does not eat your mobile data or broadband allowance."
                    data-intermediate="Local agents send a full observation snapshot every heartbeat. Remote (VPN/roaming) agents send a complete snapshot every Nth heartbeat instead, to limit WAN data use."
                    data-pro="Local: observe every beat (~0.02% of a 1Gb LAN at 100 agents). Remote: full snapshot every Nth beat. ~659MB/month/device at N=1 vs ~161MB at N=6.">Devices on your own network report in full every few minutes.</span>
            </p>
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
                <label style="font-size:0.86em;color:#eee">
                    <span class="tier-text"
                        data-beginner="How often should devices away from home send a full report?"
                        data-intermediate="Remote observation: every"
                        data-pro="observe_every_n">Remote observation: every</span>
                </label>
                <input id="obsEveryN" type="number" min="{obs_n_min}" max="{obs_n_max}" step="1"
                       value="{obs_n_value}"
                       style="width:80px;background:#0d1117;border:1px solid #00d4ff;color:#eee;padding:5px;border-radius:3px;margin:0">
                <span style="font-size:0.86em;color:#bbb">
                    <span class="tier-text"
                        data-beginner="heartbeats (higher = less data used)"
                        data-intermediate="heartbeats"
                        data-pro="beats">heartbeats</span>
                </span>
                <button onclick="saveObsEveryN()"
                        style="background:#00d4ff;color:#1a1a2e;border:none;padding:5px 14px;cursor:pointer;border-radius:3px;font-weight:bold">Save</button>
                <span id="obsEveryNStatus" style="font-size:0.82em;color:#bbb"></span>
            </div>
            <p style="margin:8px 0 0;font-size:0.78em;color:#888">
                <span class="tier-text"
                    data-beginner="1 means report as often as devices at home (uses the most data). Higher numbers report less often and use less data. Nothing is left out of a report either way &mdash; there is just more time between them."
                    data-intermediate="1 = full fidelity everywhere. Higher = less frequent, still complete. Local agents are unaffected."
                    data-pro="Range {obs_n_min}&ndash;{obs_n_max}. Takes effect on the next heartbeat; no agent restart. Snapshots are always COMPLETE &mdash; cadence changes, contents do not.">Reports are always complete; only how often they arrive changes.</span>
            </p>
        </div>
    </div>

    <!-- Danger Zone -->
    <div class="danger-zone">
        <h2>⚠ Danger Zone</h2>

        <!-- Backup sub-section -->
        <div style="margin-bottom:20px;padding-bottom:20px;border-bottom:1px solid #2a1010">
            <p style="margin:0 0 10px">
                <span class="tier-text"
                      data-beginner="Save a copy of your alerts history, tickets, and settings. Store it on a USB drive or cloud folder so you can restore everything if this machine needs to be reinstalled."
                      data-intermediate="Back up alerts.db, tickets.db, hw_map.json, and /etc/nemesis.env to a timestamped local archive."
                      data-pro="tar.gz snapshot: alerts.db, tickets.db, hw_map.json, anomaly DBs, /etc/nemesis.env.">Back up alerts history, tickets, sensor map, and configuration to a local archive.</span>
            </p>
            <button class="btn-backup" onclick="openBackupModal()">Back Up Nemesis Data</button>

            <!-- Scheduled backups -->
            <div style="margin-top:16px">
                <label class="schedule-toggle">
                    <input type="checkbox" id="scheduleToggle" onchange="toggleScheduleForm()">
                    <span class="tier-text"
                          data-beginner="Automatically back up on a schedule (recommended — set it and forget it)"
                          data-intermediate="Enable scheduled automatic backups"
                          data-pro="Scheduled backups">Enable automatic backups</span>
                </label>
                <div id="scheduleForm" style="display:none;margin-top:12px">
                    <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end">
                        <div>
                            <label class="dz-field-label" for="scheduleFreq">Frequency</label>
                            <select id="scheduleFreq" class="schedule-select">
                                <option value="daily">Daily</option>
                                <option value="weekly">Weekly</option>
                                <option value="monthly">Monthly</option>
                            </select>
                        </div>
                        <div>
                            <label class="dz-field-label" for="scheduleDestPath">Destination folder</label>
                            <div style="display:flex;gap:6px;align-items:center">
                                <input id="scheduleDestPath" type="text" class="backup-path-input"
                                       value="{_default_backup_dir()}" placeholder="{_default_backup_dir()}"
                                       style="width:200px">
                                <button onclick="openFsBrowser('scheduleDestPath','schedFsBrowser')"
                                        class="fs-browse-btn">Browse</button>
                            </div>
                            <div id="schedFsBrowser" class="fs-browser" style="display:none;margin-top:6px;width:300px"></div>
                        </div>
                        <button class="btn-save-sched" onclick="saveSchedule()">Save Schedule</button>
                    </div>
                    <div id="scheduleResult" style="display:none;margin-top:8px;font-size:0.82em;color:#aaa"></div>
                </div>
            </div>
        </div>

        <!-- Uninstall sub-section -->
        <p style="margin:0 0 10px;color:#aaa;font-size:0.85em">
            Permanently remove Nemesis Firewall from this system. All services will be
            stopped and system configuration will be deleted.
        </p>
        <button class="btn-uninstall" onclick="openUninstallModal()">
            Uninstall Nemesis Firewall
        </button>
    </div>

    <!-- Backup modal -->
    <div class="backup-overlay" id="backupOverlay">
        <div class="backup-box">
            <h3>Back Up Nemesis Data</h3>
            <div id="backupLoadingDiv" style="color:#aaa;font-size:0.88em;padding:8px 0">
                <span class="backup-spinner"></span>Calculating backup size&hellip;
            </div>
            <div id="backupContentDiv" style="display:none">
                <p class="tier-text"
                   data-beginner="The following files will be saved — they contain your security history, tickets, and settings. Logs are not included because they are large and regenerate automatically."
                   data-intermediate="Archive contents (logs excluded — they regenerate):"
                   data-pro="Archive contents (no logs):">The following will be included in the backup:</p>
                <ul class="backup-file-list">
                    <li>Alert history <span class="file-hint">(alert_manager/alerts.db)</span></li>
                    <li>Tickets &amp; notes <span class="file-hint">(modules/tickets/tickets.db)</span></li>
                    <li>Hardware sensor map <span class="file-hint">(alert_manager/hw_map.json)</span></li>
                    <li>Configuration &amp; API keys <span class="file-hint">(/etc/nemesis.env)</span></li>
                </ul>
                <p class="backup-size-text">Estimated size: <strong id="backupSizeDisplay">&mdash;</strong></p>
                <p class="backup-size-text">Free at destination: <strong id="backupFreeDisplay">&mdash;</strong></p>
                <p class="tier-text"
                   data-beginner="&#x1F4A1; Tip: choose a USB drive or cloud folder (e.g. ~/Dropbox/) so the backup survives if this machine is wiped or fails."
                   data-intermediate="Recommended: a removable drive or cloud-synced path."
                   data-pro="Store off-machine for durability.">Store backups on removable media or a cloud-synced path.</p>
                <div class="backup-path-row">
                    <label class="dz-field-label" for="backupDestPath">Destination folder</label>
                    <div style="display:flex;gap:8px;align-items:center">
                        <input id="backupDestPath" type="text" class="backup-path-input"
                               value="{_default_backup_dir()}" placeholder="{_default_backup_dir()}"
                               style="flex:1;min-width:0;box-sizing:border-box">
                        <button onclick="openFsBrowser('backupDestPath','backupFsBrowser')"
                                class="fs-browse-btn">Browse</button>
                    </div>
                    <div id="backupFsBrowser" class="fs-browser" style="display:none"></div>
                </div>
                <div class="uninstall-actions" style="margin-top:18px">
                    <button class="btn-backup" id="btnCreateBackup" onclick="createBackup()">Create Backup</button>
                    <button class="btn-cancel" onclick="closeBackupModal()">Cancel</button>
                </div>
                <div id="backupResult" class="backup-result" style="display:none;margin-top:12px"></div>
            </div>
        </div>
    </div>

    <!-- Uninstall confirmation modal (2-step: backup prompt → YES confirmation) -->
    <div class="uninstall-overlay" id="uninstallOverlay">
        <div class="uninstall-box">
            <!-- Step 1: Backup prompt -->
            <div id="uninstallStep1">
                <h3>Back Up Before Uninstalling?</h3>
                <p>Your alerts history, tickets, and configuration can be saved now and
                   restored after a fresh reinstall.</p>
                <p class="safe-note">&#x1F4BE; Backup will be saved to {_default_backup_dir()}</p>
                <div id="preBackupResult" class="backup-result" style="display:none;margin-bottom:12px"></div>
                <div class="uninstall-actions">
                    <button class="btn-backup" id="btnPreBackup" onclick="doPreUninstallBackup()">Back Up Now</button>
                    <button class="btn-cancel" onclick="goToUninstallStep2()">Skip Backup</button>
                </div>
            </div>
            <!-- Step 2: YES confirmation -->
            <div id="uninstallStep2" style="display:none">
                <h3>&#x26A0; Uninstall Nemesis Firewall</h3>
                <p>This will permanently remove Nemesis Firewall from this system.
                   All services will be stopped and configuration will be deleted.</p>
                <p class="safe-note">&#x2713; Your /opt/nemesis directory and data will NOT be deleted.</p>
                <div class="uninstall-yes-row">
                    <label for="uninstallYesInput">Type <strong>YES</strong> to confirm:</label>
                    <input id="uninstallYesInput" class="uninstall-yes-input"
                           type="text" autocomplete="off" spellcheck="false"
                           oninput="uninstallTypingCheck()" placeholder="YES">
                </div>
                <div class="uninstall-actions">
                    <button class="btn-uninstall-confirm" id="btnUninstallConfirm"
                            onclick="doUninstall()">Confirm Uninstall</button>
                    <button class="btn-cancel" onclick="closeUninstallModal()">Cancel</button>
                </div>
                <div class="uninstall-result" id="uninstallResult"></div>
            </div>
        </div>
    </div>

    <!-- Confirmation modal for dangerous toggles -->
    <div class="confirm-overlay" id="confirmOverlay">
        <div class="confirm-box">
            <h3>⚠️ Important — read before enabling</h3>
            <p id="confirmMsg"></p>
            <label class="confirm-check">
                <input type="checkbox" id="confirmCheck" onchange="confirmCheckChanged()">
                <span>I understand the implications and have already taken the required steps.</span>
            </label>
            <div class="confirm-actions">
                <button class="btn-confirm" id="btnConfirmEnable" disabled onclick="doConfirmEnable()">
                    Enable anyway
                </button>
                <button class="btn-cancel" onclick="cancelConfirm()">Cancel</button>
            </div>
        </div>
    </div>

    <!-- Config Wizard modal -->
    <div class="wizard-overlay" id="wizardOverlay"
         onclick="if(event.target===this)closeConfigWizard()">
        <div class="wizard-box">
            <h3 id="wizardTitle">&#x2699;&#xFE0F; Configuration Wizard</h3>
            <div class="wizard-steps" id="wizardStepDots"></div>
            <div id="wizardBody"></div>
            <div class="wizard-nav" id="wizardNav"></div>
        </div>
    </div>

    <script>
        // --- Tier selector ---
        function chooseTier(tier) {{
            setTier(tier);
            document.getElementById('radioBeginner').checked    = (tier === 'beginner');
            document.getElementById('radioIntermediate').checked = (tier === 'intermediate');
            document.getElementById('radioPro').checked         = (tier === 'pro');
            ['Beginner','Intermediate','Pro'].forEach(function(t) {{
                document.getElementById('opt' + t).classList.toggle(
                    'selected', t.toLowerCase() === tier);
            }});
            var note = document.getElementById('saveNote');
            note.style.display = 'block';
            clearTimeout(note._t);
            note._t = setTimeout(function() {{ note.style.display = 'none'; }}, 3000);
        }}
        (function() {{
            var t = getTier();
            document.getElementById('radio' + t.charAt(0).toUpperCase() + t.slice(1)).checked = true;
            document.getElementById('opt'   + t.charAt(0).toUpperCase() + t.slice(1))
                .classList.add('selected');
        }})();

        // --- Module toggles ---
        var _pendingModule = null;

        function handleModuleToggle(name, wantEnabled, confirmRequired, confirmMsg) {{
            if (wantEnabled && confirmRequired) {{
                // Show confirmation modal; revert toggle visually until confirmed
                document.getElementById('mod-toggle-' + name).checked = false;
                _pendingModule = name;
                document.getElementById('confirmMsg').textContent = confirmMsg;
                document.getElementById('confirmCheck').checked = false;
                document.getElementById('btnConfirmEnable').disabled = true;
                document.getElementById('btnConfirmEnable').classList.remove('ready');
                document.getElementById('confirmOverlay').style.display = 'block';
            }} else {{
                setModuleEnabled(name, wantEnabled);
            }}
        }}

        function confirmCheckChanged() {{
            var ready = document.getElementById('confirmCheck').checked;
            document.getElementById('btnConfirmEnable').disabled = !ready;
            document.getElementById('btnConfirmEnable').classList.toggle('ready', ready);
        }}

        function doConfirmEnable() {{
            document.getElementById('confirmOverlay').style.display = 'none';
            if (_pendingModule) {{
                document.getElementById('mod-toggle-' + _pendingModule).checked = true;
                setModuleEnabled(_pendingModule, true);
                _pendingModule = null;
            }}
        }}

        function cancelConfirm() {{
            document.getElementById('confirmOverlay').style.display = 'none';
            _pendingModule = null;
        }}

        function setModuleEnabled(name, enabled) {{
            var url = '/api/modules/' + name + '/' + (enabled ? 'enable' : 'disable');
            var statusEl = document.getElementById('mod-status-' + name);
            statusEl.style.color = '#ffaa00';
            statusEl.textContent = enabled ? 'Enabling…' : 'Disabling…';

            fetch(url, {{method: 'POST'}})
                .then(function(r) {{ return r.json(); }})
                .then(function(d) {{
                    if (d.error) {{
                        statusEl.style.color = '#ff4444';
                        statusEl.textContent = 'Error: ' + d.error;
                        document.getElementById('mod-toggle-' + name).checked = !enabled;
                    }} else {{
                        statusEl.style.color = enabled ? '#00ff88' : '#666';
                        statusEl.textContent = enabled ? 'Enabled' : 'Disabled';
                        // Show/hide module sub-settings when toggled
                        var subIds = {{anomaly_detection: 'ad-subsettings', tickets: 'tk-subsettings'}};
                        var subId = subIds[name];
                        if (subId) {{
                            var sub = document.getElementById(subId);
                            if (sub) sub.style.display = enabled ? 'block' : 'none';
                        }}
                        showModuleRestartBanner();
                    }}
                }})
                .catch(function(e) {{
                    statusEl.style.color = '#ff4444';
                    statusEl.textContent = 'Request failed';
                    document.getElementById('mod-toggle-' + name).checked = !enabled;
                }});
        }}

        function saveAIEngineSettings() {{
            var rateH = parseInt(document.getElementById('ai-rate-hour').value) || 10;
            var rateD = parseInt(document.getElementById('ai-rate-day').value) || 50;
            /* Sent as the RAW string, deliberately. Coercing here (parseFloat ||
               0) would turn a typo into 0, and a 0 cap reads as "no cap" on the
               server — silently removing the user's protection while the save
               reported success. The server validates and returns 400 on
               garbage, leaving any existing cap untouched. */
            var spendCapEl = document.getElementById('ai-spend-cap');
            var spendCap = spendCapEl ? spendCapEl.value.trim() : null;
            var status = document.getElementById('ai-engine-settings-status');
            if (status) {{ status.style.color = '#aaa'; status.textContent = 'Saving…'; }}
            fetch('/api/ai/settings', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify(spendCap === null
                    ? {{ rate_per_hour: rateH, rate_per_day: rateD }}
                    : {{ rate_per_hour: rateH, rate_per_day: rateD,
                         spend_cap_monthly_usd: spendCap }})
            }})
            .then(function(r) {{ return r.json(); }})
            .then(function(d) {{
                if (status) {{
                    status.style.color = d.ok ? '#00ff88' : '#ff4444';
                    status.textContent = d.ok ? '✓ Saved' : 'Error: ' + (d.error || 'unknown');
                    clearTimeout(status._t);
                    status._t = setTimeout(function() {{ status.textContent = ''; }}, 3000);
                }}
            }})
            .catch(function() {{
                if (status) {{ status.style.color = '#ff4444'; status.textContent = 'Request failed'; }}
            }});
        }}

        function toggleAIUpsell(show) {{
            fetch(show ? '/api/ai/upsell_restore' : '/api/ai/upsell_dismiss', {{method: 'POST'}});
        }}

        function saveAnomalySettings() {{
            var manual = (document.getElementById('ad-allow-manual') || {{}}).checked ? '1' : '0';
            // AbuseIPDB
            var abCtrlEl = document.querySelector('input[name="ad-ab-ctrl"]:checked');
            var abCtrl   = abCtrlEl ? abCtrlEl.value : 'dropdown';
            var abMode   = (document.getElementById('ad-abuseipdb-mode') || {{}}).value || 'off';
            var abScore  = parseInt((document.getElementById('ad-abuseipdb-score') || {{}}).value) || 40;
            // CISA
            var ciCtrlEl = document.querySelector('input[name="ad-cisa-ctrl"]:checked');
            var ciCtrl   = ciCtrlEl ? ciCtrlEl.value : 'dropdown';
            var ciMode   = (document.getElementById('ad-cisa-mode') || {{}}).value || 'high_only';
            var ciScore  = parseInt((document.getElementById('ad-cisa-score') || {{}}).value) || 60;

            var status = document.getElementById('ad-settings-status');
            if (status) {{ status.style.color = '#aaa'; status.textContent = 'Saving…'; }}
            fetch('/api/anomaly/settings', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{
                    allow_manual_override: manual,
                    abuseipdb_active_control: abCtrl,
                    abuseipdb_dropdown_mode: abMode,
                    abuseipdb_slider_score: abScore,
                    cisa_active_control: ciCtrl,
                    cisa_dropdown_mode: ciMode,
                    cisa_slider_score: ciScore
                }})
            }})
            .then(function(r) {{ return r.json(); }})
            .then(function(d) {{
                if (status) {{
                    status.style.color = d.ok ? '#00ff88' : '#ff4444';
                    status.textContent = d.ok ? '✓ Saved' : 'Error: ' + (d.error || 'unknown');
                    clearTimeout(status._t);
                    status._t = setTimeout(function() {{ status.textContent = ''; }}, 3000);
                }}
            }})
            .catch(function() {{
                if (status) {{ status.style.color = '#ff4444'; status.textContent = 'Request failed'; }}
            }});
        }}

        var _COST_PER_ANALYSIS = {(350*_ai_input_price/1e6 + 150*_ai_output_price/1e6):.6f};
        function updateAICostEstimate() {{
            var h = parseFloat((document.getElementById('ai-rate-hour') || {{}}).value) || 0;
            var d = parseFloat((document.getElementById('ai-rate-day') || {{}}).value) || 0;
            var hEl = document.getElementById('ai-cost-hour');
            var dEl = document.getElementById('ai-cost-day');
            if (hEl) hEl.textContent = '~$' + (h * _COST_PER_ANALYSIS).toFixed(3);
            if (dEl) dEl.textContent = '~$' + (d * _COST_PER_ANALYSIS).toFixed(3);
        }}
        updateAICostEstimate();

        function saveTicketSettings() {{
            var status = document.getElementById('tk-settings-status');
            if (!status) return;
            status.style.color = '#aaa';
            status.textContent = 'Saving…';
            var payload = {{
                auto_ticket_on_alert:         document.getElementById('tk-auto-ticket')  ? document.getElementById('tk-auto-ticket').checked  : true,
                min_severity_for_auto_ticket: document.getElementById('tk-min-severity') ? document.getElementById('tk-min-severity').value    : 'HIGH',
                relevance_threshold:          parseInt(document.getElementById('tk-threshold')   ? document.getElementById('tk-threshold').value   : 70),
                max_related_results:          parseInt(document.getElementById('tk-max-related') ? document.getElementById('tk-max-related').value : 5),
            }};
            fetch('/api/tickets/settings', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify(payload)
            }})
            .then(function(r) {{ return r.json(); }})
            .then(function(d) {{
                status.style.color = d.ok ? '#00ff88' : '#ff4444';
                status.textContent = d.ok ? '✓ Saved' : 'Error: ' + (d.error || 'unknown');
                clearTimeout(status._t);
                status._t = setTimeout(function() {{ status.textContent = ''; }}, 3000);
            }})
            .catch(function() {{
                status.style.color = '#ff4444';
                status.textContent = 'Request failed';
            }});
        }}

        function hwResetBaseline() {{
            var sensor = document.getElementById('hw-baseline-sensor').value || 'all';
            var status = document.getElementById('hw-baseline-status');
            status.style.color = '#aaa';
            status.textContent = 'Resetting…';
            fetch('/api/hw/reset-baseline?sensor=' + encodeURIComponent(sensor), {{method: 'POST'}})
                .then(function(r) {{ return r.json(); }})
                .then(function(d) {{
                    status.style.color = d.ok ? '#00ff88' : '#ff4444';
                    status.textContent = d.ok
                        ? '✓ Baseline cleared for ' + sensor
                        : 'Error: ' + (d.error || 'unknown');
                    setTimeout(function() {{ status.textContent = ''; }}, 4000);
                }})
                .catch(function() {{
                    status.style.color = '#ff4444';
                    status.textContent = 'Request failed';
                }});
        }}

        function saveObsEveryN() {{
            var el = document.getElementById('obsEveryN');
            var st = document.getElementById('obsEveryNStatus');
            st.style.color = '#bbb';
            st.textContent = 'saving…';
            fetch('/api/settings/observe-every-n', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{value: el.value}})
            }})
              .then(function(r) {{ return r.json(); }})
              .then(function(d) {{
                  if (!d.ok) {{
                      // Show the server's reason verbatim -- it names the valid
                      // range and what the ends mean, which a generic failure
                      // message would throw away.
                      st.style.color = '#ff8800';
                      st.textContent = d.error || 'could not save';
                      return;
                  }}
                  // Reflect the STORED value, not what was typed: if the server
                  // resolved it differently the user must see that.
                  el.value = d.value;
                  st.style.color = '#00ff88';
                  st.textContent = 'saved — applies on each agent\u2019s next check-in';
              }})
              .catch(function(e) {{
                  st.style.color = '#ff4444';
                  st.textContent = 'error: ' + e;
              }});
        }}

        function hwRediscover() {{
            var status  = document.getElementById('hw-rediscover-status');
            var outDiv  = document.getElementById('hw-rediscover-output');
            status.style.color = '#aaa';
            status.textContent = 'Running discovery…';
            outDiv.style.display = 'none';
            outDiv.textContent = '';
            fetch('/api/hw/rediscover', {{method: 'POST'}})
                .then(function(r) {{ return r.json(); }})
                .then(function(d) {{
                    status.style.color = d.ok ? '#00ff88' : '#ff4444';
                    status.textContent = d.ok ? '✓ Discovery complete' : '✗ Discovery failed';
                    var out = d.output || d.error || '';
                    if (out) {{
                        outDiv.textContent = out;
                        outDiv.style.display = 'block';
                    }}
                    setTimeout(function() {{ status.textContent = ''; }}, 6000);
                }})
                .catch(function() {{
                    status.style.color = '#ff4444';
                    status.textContent = 'Request failed';
                }});
        }}

        var _aiUsageCache = null;
        function switchUsagePeriod(period) {{
            var display = document.getElementById('ai-usage-display');
            if (!display) return;

            function render(d) {{
                /* A failed read returns ok:false and NO numbers, so there is
                   nothing to render as usage. Showing 0 calls / $0.0000 here
                   would report a DB failure as a real measurement of no spend. */
                if (!d || d.ok === false) {{
                    display.innerHTML = '<span style="color:#ff4444">'
                        + tierText('Usage data unavailable — could not read the usage table',
                                   'Usage data unavailable', 'usage read failed')
                        + '</span>';
                    return;
                }}
                var count, label, cost, tok;
                var C = d.cost || {{}}, T = d.tokens || {{}};
                if (period === 'hour') {{
                    var hr = String(new Date().getHours());
                    count = (d.hourly && d.hourly[hr]) ? d.hourly[hr] : 0;
                    cost  = (C.hourly && C.hourly[hr]) || 0;
                    tok   = (T.hourly && T.hourly[hr]) || null;
                    label = tierText(
                        'calls in the current hour (today)',
                        'this hour (today)',
                        'current hr'
                    );
                }} else if (period === 'week') {{
                    count = d.week || 0;
                    cost  = C.week || 0;
                    tok   = T.week || null;
                    label = tierText('calls in the last 7 days', 'last 7 days', '7d');
                }} else if (period === 'month') {{
                    count = d.month || 0;
                    cost  = C.month || 0;
                    tok   = T.month || null;
                    label = tierText('calls in the last 30 days', 'last 30 days', '30d');
                }} else {{
                    count = d.today || 0;
                    cost  = C.today || 0;
                    tok   = T.today || null;
                    label = tierText('AI analysis calls made today', 'calls today', 'today');
                }}
                var head = '<span style="color:#eee;font-weight:bold">' + count + '</span>'
                    + ' <span style="color:#bbb">'
                    + tierText('AI analysis calls', 'calls', 'calls')
                    + ' (' + label + ')</span>';
                /* Rates are a maintained constant, not a live feed — there is no
                   pricing API. So every dollar figure carries the date those
                   rates were last confirmed, the same rule the backup
                   free-space reading follows. An absent date is stated rather
                   than hidden: unvouched-for rates must not look authoritative.
                   `updated` is null when the operator overrode the rates without
                   supplying a date, which get_pricing() deliberately does not
                   paper over. */
                var pu = (d.pricing && d.pricing.updated) || null;
                var priceAge = '<span style="color:#667;font-size:0.85em" title="'
                    + 'Maintained per-MTok rates, not a live price feed">'
                    + (pu ? ' (rates as of ' + pu + ')' : ' (pricing date unknown)')
                    + '</span>';
                /* Per-install monthly average. Rendered only when a full calendar
                   month was actually observed; otherwise it reports how much
                   history exists instead of extrapolating an average from a
                   part-month. get_monthly_cost() returns average_cost null in
                   that case, never 0. */
                var mo = d.monthly || null, moLine = '';
                if (mo && mo.ok !== false) {{
                    if (mo.sufficient && mo.average_cost !== null
                        && mo.average_cost !== undefined) {{
                        moLine = '<div style="color:#8a8f98;font-size:0.85em;'
                            + 'margin-top:3px">'
                            + tierText('average per month for this server',
                                       'monthly average', 'avg/mo')
                            + ': <span style="color:#00ff88">$'
                            + Number(mo.average_cost).toFixed(2) + '</span> '
                            + tierText('over ' + mo.months_counted
                                       + ' full month(s) observed',
                                       'over ' + mo.months_counted + ' mo',
                                       mo.months_counted + 'mo')
                            + '</div>';
                        /* Comparison against the consumer-subscription price
                           point. Deliberately prominent when exceeded — the
                           whole point is that the operator notices — but worded
                           as a comparison, never a recommendation. A Claude Pro
                           subscription issues OAuth tokens meant for
                           interactive/CLI use; this server authenticates with a
                           pay-per-token API key. They are different products,
                           so we state both numbers and let the operator decide.
                           Only ever reached on a measured month: the
                           insufficient-history branch below carries no
                           comparison at all. */
                        var cmp = mo.comparison || null;
                        if (cmp && cmp.exceeds) {{
                            var subCompare = '<div style="margin-top:5px;'
                                + 'padding:7px 10px;border-radius:6px;'
                                + 'background:#3a2d0033;border:1px solid #ffaa0066;'
                                + 'color:#ffd479;font-size:0.85em;line-height:1.5">'
                                + '<b>Above the $' + Number(cmp.threshold_usd).toFixed(0)
                                + '/mo ' + cmp.label + ' price point.</b> '
                                + 'This server averages $'
                                + Number(mo.average_cost).toFixed(2)
                                + '/mo in API usage. '
                                + '<span style="color:#bba">' + cmp.caveat + '</span>'
                                + ' <span style="color:#887;font-size:0.92em">('
                                + cmp.label + ' price as of ' + cmp.confirmed
                                + ')</span></div>';
                            moLine += subCompare;
                        }}
                    }} else {{
                        var dobs = (mo.days_observed || 0);
                        moLine = '<div style="color:#667;font-size:0.85em;'
                            + 'margin-top:3px">'
                            + tierText('monthly average needs a full calendar month; '
                                       + 'this server has ' + dobs + ' days so far',
                                       'insufficient history (' + dobs + ' days)',
                                       'insufficient history (' + dobs + 'd)')
                            + '</div>';
                    }}
                }}
                /* Three distinct states, deliberately. A zero-dollar figure is a
                   legitimate-looking measurement, so it is shown only when it is
                   one: no calls at all is not $0.00, it is nothing to price. */
                if (count === 0) {{
                    display.innerHTML = head + ' &mdash; <span style="color:#666">'
                        + tierText('no calls yet, so nothing to cost',
                                   'no calls yet', 'none')
                        + '</span>' + moLine;
                }} else if (tok && (tok.in || 0) === 0 && (tok.out || 0) === 0) {{
                    display.innerHTML = head + ' &mdash; <span style="color:#00ff88;'
                        + 'font-weight:bold">$0.0000</span> <span style="color:#666">'
                        + tierText('served from cache, so no tokens were billed',
                                   'all from cache', 'cached')
                        + '</span>' + moLine;
                }} else {{
                    display.innerHTML = head + ' &mdash; '
                        + tierText('cost from recorded token usage',
                                   'cost (recorded)', 'cost')
                        + ' <span style="color:#00ff88;font-weight:bold">$'
                        + Number(cost).toFixed(4) + '</span>' + priceAge + moLine;
                }}
            }}

            if (_aiUsageCache) {{
                render(_aiUsageCache);
                return;
            }}

            display.innerHTML = '<span style="color:#444">'
                + tierText('Loading usage data…', 'Loading…', '…')
                + '</span>';
            fetch('/api/ai/usage')
                .then(function(r) {{ return r.json(); }})
                .then(function(d) {{
                    _aiUsageCache = d;
                    // Invalidate cache after 60 s so the next switch re-fetches
                    setTimeout(function() {{ _aiUsageCache = null; }}, 60000);
                    render(d);
                }})
                .catch(function() {{
                    display.innerHTML = '<span style="color:#ff4444">'
                        + tierText('Could not load usage data', 'Load failed', 'Error')
                        + '</span>';
                }});
        }}
        switchUsagePeriod('day');

        fetch('/api/dashboard/uptime')
            .then(function(r) {{ return r.json(); }})
            .then(function(d) {{
                var el = document.getElementById('dashUptimeLabel');
                if (el) el.textContent = 'Last started: ' + d.started_at + '  (uptime ' + d.uptime + ')';
            }})
            .catch(function() {{
                var el = document.getElementById('dashUptimeLabel');
                if (el) el.textContent = '';
            }});

        function restartDashboard() {{
            var btn = document.getElementById('restartDashBtn');
            var msg = document.getElementById('restartDashMsg');
            btn.disabled = true;
            btn.textContent = 'Restarting…';
            btn.style.opacity = '0.6';
            msg.style.display = 'inline';
            /* Restart is privileged now — it goes through nemesis-fwd. */
            fwPrompt('restart the dashboard service').then(function (pw) {{
              if (!pw) return;
              fetch('/api/restart', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{password: pw}})
              }})
                .catch(function() {{}});
              /* Reload only after a real attempt — inside the prompt callback,
                 so cancelling does not reload a page that never restarted. */
              setTimeout(function() {{ location.reload(); }}, 5000);
            }});   /* close fwPrompt().then( */
        }}

        // --- Module restart banner ---
        var _MODULE_RESTART_KEY = 'nemesisModuleRestartPending';

        function showModuleRestartBanner() {{
            try {{ localStorage.setItem(_MODULE_RESTART_KEY, '1'); }} catch(e) {{}}
            var el = document.getElementById('moduleRestartBanner');
            if (el) {{ el.style.display = 'flex'; applyTierText(); }}
        }}

        function dismissModuleRestartBanner() {{
            try {{ localStorage.removeItem(_MODULE_RESTART_KEY); }} catch(e) {{}}
            var el = document.getElementById('moduleRestartBanner');
            if (el) el.style.display = 'none';
        }}

        function restartFromModuleBanner() {{
            try {{ localStorage.removeItem(_MODULE_RESTART_KEY); }} catch(e) {{}}
            restartDashboard();
        }}

        (function() {{
            try {{
                if (localStorage.getItem(_MODULE_RESTART_KEY)) {{
                    var el = document.getElementById('moduleRestartBanner');
                    if (el) el.style.display = 'flex';
                }}
            }} catch(e) {{}}
        }})();

        // --- Uninstall modal ---
        function openUninstallModal() {{
            document.getElementById('uninstallStep1').style.display = 'block';
            document.getElementById('uninstallStep2').style.display = 'none';
            document.getElementById('preBackupResult').style.display = 'none';
            document.getElementById('preBackupResult').textContent = '';
            var preBtn = document.getElementById('btnPreBackup');
            preBtn.disabled = false;
            preBtn.textContent = 'Back Up Now';
            document.getElementById('uninstallYesInput').value = '';
            document.getElementById('btnUninstallConfirm').classList.remove('ready');
            document.getElementById('uninstallResult').style.display = 'none';
            document.getElementById('uninstallResult').textContent = '';
            document.getElementById('uninstallOverlay').style.display = 'block';
        }}

        function closeUninstallModal() {{
            document.getElementById('uninstallOverlay').style.display = 'none';
        }}

        function goToUninstallStep2() {{
            document.getElementById('uninstallStep1').style.display = 'none';
            document.getElementById('uninstallStep2').style.display = 'block';
            document.getElementById('uninstallYesInput').focus();
        }}

        function doPreUninstallBackup() {{
            var btn = document.getElementById('btnPreBackup');
            var result = document.getElementById('preBackupResult');
            btn.disabled = true;
            btn.textContent = 'Backing up…';
            result.className = 'backup-result';
            result.style.display = 'none';
            fetch('/api/backup/create', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{dest_path: '{_default_backup_dir()}'}})
            }})
            .then(function(r) {{ return r.json(); }})
            .then(function(data) {{
                if (data.status === 'ok') {{
                    result.textContent = '✓ Backup saved to: ' + data.path + ' (' + data.size_mb.toFixed(1) + ' MB) — continuing to uninstall…';
                    result.style.display = 'block';
                    setTimeout(goToUninstallStep2, 2000);
                }} else {{
                    result.textContent = '✗ Backup failed: ' + (data.error || 'Unknown error');
                    result.className = 'backup-result error';
                    result.style.display = 'block';
                    btn.disabled = false;
                    btn.textContent = 'Try Again';
                }}
            }})
            .catch(function() {{
                result.textContent = '✗ Request failed — check that the dashboard service is running.';
                result.className = 'backup-result error';
                result.style.display = 'block';
                btn.disabled = false;
                btn.textContent = 'Try Again';
            }});
        }}

        function uninstallTypingCheck() {{
            var val = document.getElementById('uninstallYesInput').value;
            var btn = document.getElementById('btnUninstallConfirm');
            if (val === 'YES') {{
                btn.classList.add('ready');
            }} else {{
                btn.classList.remove('ready');
            }}
        }}

        function doUninstall() {{
            var btn = document.getElementById('btnUninstallConfirm');
            var cancelBtn = document.querySelector('#uninstallStep2 .btn-cancel');
            var result = document.getElementById('uninstallResult');
            if (document.getElementById('uninstallYesInput').value !== 'YES') return;
            // The /api/uninstall endpoint was REMOVED 2026-07-31 (see dashboard.py).
            // A web-reachable root uninstall is not a capability that should exist,
            // so this no longer calls the server at all.
            if (btn) btn.classList.remove('ready');
            if (cancelBtn) cancelBtn.disabled = false;
            result.textContent = 'Uninstall is no longer available from the web interface. '
                + 'Run the uninstall script from a terminal on the server.';
            result.style.display = 'block';
        }}

        // --- Backup modal ---
        function renderBackupMedia(media) {{
            var el = document.getElementById('backupFreeDisplay');
            // No row for this destination, or a null reading: say so plainly.
            // A zero here would read as a full drive, which is a different and
            // far more alarming claim than "we have never looked".
            if (!media || media.free_bytes === null || media.free_bytes === undefined) {{
                el.textContent = 'never checked';
                el.style.color = '#8a8f98';
                return;
            }}
            var gb = media.free_bytes / (1024 * 1024 * 1024);
            // The age is not decoration. ADR 0018 keeps the backup medium
            // unmounted except during a write, so every reading is historical by
            // the time anyone reads it. A bare number would be taken as current,
            // so the figure never renders without its age attached.
            var age = ' (age unknown)';
            if (media.checked_at) {{
                var ms = Date.now() - new Date(media.checked_at).getTime();
                if (!isNaN(ms)) {{
                    var days = Math.floor(ms / 86400000);
                    if (days < 1) {{
                        var hours = Math.floor(ms / 3600000);
                        age = hours < 1 ? ' (checked just now)'
                                        : ' (checked ' + hours + 'h ago)';
                    }} else {{
                        age = ' (as of ' + days + ' day' + (days === 1 ? '' : 's') + ' ago)';
                    }}
                }}
            }}
            el.textContent = gb.toFixed(1) + ' GB free' + age;
            el.style.color = '';
        }}

        function refreshBackupMedia() {{
            var destEl = document.getElementById('backupDestPath');
            var dest = destEl ? destEl.value : '';
            fetch('/api/backup/size?dest=' + encodeURIComponent(dest))
                .then(function(r) {{ return r.json(); }})
                .then(function(data) {{ renderBackupMedia(data.media); }})
                .catch(function() {{ renderBackupMedia(null); }});
        }}

        function openBackupModal() {{
            var overlay = document.getElementById('backupOverlay');
            document.getElementById('backupLoadingDiv').style.display = 'block';
            document.getElementById('backupContentDiv').style.display = 'none';
            document.getElementById('backupResult').style.display = 'none';
            overlay.style.display = 'block';
            fetch('/api/backup/size')
                .then(function(r) {{ return r.json(); }})
                .then(function(data) {{
                    var mb = data.size_mb || 0;
                    document.getElementById('backupSizeDisplay').textContent =
                        mb < 1 ? Math.round(mb * 1024) + ' KB' : mb.toFixed(1) + ' MB';
                    document.getElementById('backupLoadingDiv').style.display = 'none';
                    document.getElementById('backupContentDiv').style.display = 'block';
                    renderBackupMedia(data.media);
                    if (typeof applyTierText === 'function') applyTierText();
                }})
                .catch(function() {{
                    document.getElementById('backupSizeDisplay').textContent = '(unknown)';
                    renderBackupMedia(null);
                    document.getElementById('backupLoadingDiv').style.display = 'none';
                    document.getElementById('backupContentDiv').style.display = 'block';
                }});
        }}

        function closeBackupModal() {{
            document.getElementById('backupOverlay').style.display = 'none';
        }}

        function createBackup() {{
            var btn = document.getElementById('btnCreateBackup');
            var result = document.getElementById('backupResult');
            var dest = (document.getElementById('backupDestPath').value || '').trim()
                       || '{_default_backup_dir()}';
            btn.disabled = true;
            btn.textContent = 'Creating…';
            result.className = 'backup-result';
            result.style.display = 'none';
            fetch('/api/backup/create', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{dest_path: dest}})
            }})
            .then(function(r) {{ return r.json(); }})
            .then(function(data) {{
                if (data.status === 'ok') {{
                    result.textContent = '✓ Backup created: ' + data.path
                                       + ' (' + data.size_mb.toFixed(1) + ' MB)';
                }} else {{
                    result.textContent = '✗ ' + (data.error || 'Backup failed');
                    result.className = 'backup-result error';
                }}
                result.style.display = 'block';
                btn.disabled = false;
                btn.textContent = 'Create Backup';
            }})
            .catch(function() {{
                result.textContent = '✗ Request failed — check that the dashboard service is running.';
                result.className = 'backup-result error';
                result.style.display = 'block';
                btn.disabled = false;
                btn.textContent = 'Create Backup';
            }});
        }}

        // --- Scheduled backups ---
        function loadScheduleConfig() {{
            fetch('/api/backup/schedule')
                .then(function(r) {{ return r.json(); }})
                .then(function(cfg) {{
                    if (cfg.enabled) {{
                        document.getElementById('scheduleToggle').checked = true;
                        document.getElementById('scheduleForm').style.display = 'block';
                    }}
                    if (cfg.schedule) document.getElementById('scheduleFreq').value = cfg.schedule;
                    if (cfg.destination) document.getElementById('scheduleDestPath').value = cfg.destination;
                }})
                .catch(function() {{}});
        }}

        function toggleScheduleForm() {{
            var on = document.getElementById('scheduleToggle').checked;
            document.getElementById('scheduleForm').style.display = on ? 'block' : 'none';
            if (!on) {{
                fetch('/api/backup/schedule', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{enabled: false}})
                }});
                var r = document.getElementById('scheduleResult');
                r.textContent = 'Automatic backups disabled.';
                r.style.color = '#aaa';
                r.style.display = 'block';
            }}
        }}

        function saveSchedule() {{
            var result = document.getElementById('scheduleResult');
            var freq = document.getElementById('scheduleFreq').value;
            var dest = (document.getElementById('scheduleDestPath').value || '').trim()
                       || '{_default_backup_dir()}';
            result.textContent = 'Saving…';
            result.style.color = '#aaa';
            result.style.display = 'block';
            fetch('/api/backup/schedule', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{enabled: true, schedule: freq, destination: dest}})
            }})
            .then(function(r) {{ return r.json(); }})
            .then(function(data) {{
                if (data.status === 'ok') {{
                    result.textContent = '✓ Schedule saved — ' + freq + ' backups to ' + dest;
                    result.style.color = '#4ca1ff';
                }} else {{
                    result.textContent = '✗ ' + (data.error || 'Failed to save schedule');
                    result.style.color = '#ff6666';
                }}
            }})
            .catch(function() {{
                result.textContent = '✗ Request failed';
                result.style.color = '#ff6666';
            }});
        }}

        loadScheduleConfig();

        {'function restartWindowsAgent() {var btn=document.getElementById("restartAgentBtn");var msg=document.getElementById("restartAgentMsg");btn.disabled=true;btn.style.opacity="0.6";msg.style.display="inline";fetch("http://' + _agent_ip + ':5001/control",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:"restart"})}).then(function(){msg.textContent="Restart command sent.";}).catch(function(e){msg.textContent="Error: "+e;msg.style.color="#ff4444";});}' if _is_windows_agent else ''}

        // ═══════════════════════════════════════════════════════
        // Filesystem browser (used by backup modal & scheduled backup)
        // ═══════════════════════════════════════════════════════
        function openFsBrowser(inputId, browserId) {{
            var browser = document.getElementById(browserId);
            if (!browser) return;
            if (browser.style.display !== 'none') {{
                browser.style.display = 'none';
                return;
            }}
            var input = document.getElementById(inputId);
            var startPath = ((input ? input.value : '') || '{_default_backup_dir()}').trim();
            browser.style.display = 'block';
            _fsBrowse(inputId, browserId, startPath);
        }}

        function _fsBrowse(inputId, browserId, path) {{
            var browser = document.getElementById(browserId);
            if (!browser) return;
            browser.innerHTML = '<div style="color:#aaa;font-size:0.82em;padding:4px">Loading&hellip;</div>';
            fetch('/api/filesystem/browse?path=' + encodeURIComponent(path))
                .then(function(r) {{ return r.json(); }})
                .then(function(d) {{
                    var h = '<div class="fs-browser-path">&#x1F4C1; ' + d.path + '</div>';
                    if (d.error) h += '<div style="color:#ff6666;font-size:0.82em">' + d.error + '</div>';
                    if (d.parent && d.parent !== d.path) {{
                        h += '<div class="fs-browser-item" onclick="_fsBrowse(' + JSON.stringify(inputId) + ',' + JSON.stringify(browserId) + ',' + JSON.stringify(d.parent) + ')">&#x1F4C2; ..</div>';
                    }}
                    (d.dirs || []).forEach(function(dir) {{
                        var full = d.path.replace(/[/]+$/,'') + '/' + dir;
                        h += '<div class="fs-browser-item" onclick="_fsBrowse(' + JSON.stringify(inputId) + ',' + JSON.stringify(browserId) + ',' + JSON.stringify(full) + ')">&#x1F4C1; ' + dir + '</div>';
                    }});
                    h += '<div style="border-top:1px solid #2a3a5a;margin-top:6px;padding-top:8px">'
                       + '<button class="fs-browser-select" onclick="_fsSelect(' + JSON.stringify(inputId) + ',' + JSON.stringify(browserId) + ',' + JSON.stringify(d.path) + ')">&#x2713; Select This Folder</button>'
                       + '<button data-bid="' + browserId + '" onclick="document.getElementById(this.dataset.bid).style.display=\\'none\\'"'
                       + ' style="background:transparent;color:#888;border:none;cursor:pointer;font-size:0.82em;margin-left:10px">Cancel</button>'
                       + '</div>';
                    browser.innerHTML = h;
                }})
                .catch(function() {{
                    browser.innerHTML = '<div style="color:#ff4444;font-size:0.82em;padding:4px">Failed to load directory</div>';
                }});
        }}

        function _fsSelect(inputId, browserId, path) {{
            var inp = document.getElementById(inputId);
            if (inp) inp.value = path + '/';
            var b = document.getElementById(browserId);
            if (b) b.style.display = 'none';
        }}

        // ═══════════════════════════════════════════════════════
        // Configuration Wizard
        // ═══════════════════════════════════════════════════════
        var _wiz = {{
            step: 1,
            totalSteps: 5,
            cfg: {{}},      // loaded from /api/config/current
            changes: {{}},  // key → new value (only fields user changed)
            stepTitles: ['Email & Alerts','API Keys','Network','Pi-hole','Review & Save'],
        }};

        function openConfigWizard() {{
            _wiz.step = 1;
            _wiz.changes = {{}};
            document.getElementById('wizardOverlay').style.display = 'block';
            fetch('/api/config/current')
                .then(function(r) {{ return r.json(); }})
                .then(function(cfg) {{
                    _wiz.cfg = cfg;
                    _wizRender();
                }})
                .catch(function() {{
                    document.getElementById('wizardBody').innerHTML =
                        '<p style="color:#ff4444">Failed to load current configuration.</p>';
                }});
        }}

        function closeConfigWizard() {{
            document.getElementById('wizardOverlay').style.display = 'none';
        }}

        function _wizRender() {{
            _wizRenderDots();
            document.getElementById('wizardTitle').textContent = '⚙️ Configuration Wizard — Step ' + _wiz.step + ' of ' + _wiz.totalSteps + ': ' + _wiz.stepTitles[_wiz.step-1];
            var body = '';
            if (_wiz.step === 1) body = _wizStep1();
            else if (_wiz.step === 2) body = _wizStep2();
            else if (_wiz.step === 3) body = _wizStep3();
            else if (_wiz.step === 4) body = _wizStep4();
            else if (_wiz.step === 5) body = _wizStep5();
            document.getElementById('wizardBody').innerHTML = body;
            _wizRenderNav();
            if (typeof applyTierText === 'function') applyTierText();
        }}

        function _wizRenderDots() {{
            var h = '';
            for (var i = 1; i <= _wiz.totalSteps; i++) {{
                var cls = i === _wiz.step ? 'active' : (i < _wiz.step ? 'done' : 'idle');
                h += '<span class="wizard-step-dot ' + cls + '">' + i + '. ' + _wiz.stepTitles[i-1] + '</span>';
            }}
            document.getElementById('wizardStepDots').innerHTML = h;
        }}

        function _wizRenderNav() {{
            var h = '';
            if (_wiz.step < _wiz.totalSteps) {{
                h += '<button class="wizard-btn-next" onclick="_wizNext()">Next &rarr;</button>';
            }} else {{
                h += '<button class="wizard-btn-save" onclick="_wizSave()" id="wizSaveBtn">Save Changes &amp; Restart</button>';
                h += '<span class="wizard-status" id="wizSaveStatus"></span>';
            }}
            if (_wiz.step > 1) {{
                h += '<button class="wizard-btn-back" onclick="_wizBack()">&larr; Back</button>';
            }}
            h += '<button class="wizard-btn-back" onclick="closeConfigWizard()" style="margin-left:auto">Cancel</button>';
            document.getElementById('wizardNav').innerHTML = h;
        }}

        function _wizNext() {{
            _wizCollectChanges();
            if (_wiz.step < _wiz.totalSteps) {{ _wiz.step++; _wizRender(); }}
        }}
        function _wizBack() {{
            _wizCollectChanges();
            if (_wiz.step > 1) {{ _wiz.step--; _wizRender(); }}
        }}

        function _wizField(id, label, value, type, readonly, hint, linkText, linkUrl) {{
            type = type || 'text';
            readonly = readonly ? 'readonly' : '';
            var inputStyle = readonly ? 'color:#888' : '';
            var h = '<div class="wizard-field">';
            h += '<label class="wizard-label" for="wf_' + id + '">' + label;
            if (linkText) h += ' <a href="' + linkUrl + '" target="_blank" rel="noopener" style="color:#7cc8ff;font-size:0.9em">' + linkText + '</a>';
            h += '</label>';
            if (type === 'password') {{
                h += '<div class="wizard-row">'
                   + '<input class="wizard-input" id="wf_' + id + '" type="password" value="' + (value||'') + '" ' + readonly + ' style="' + inputStyle + '">'
                   + '<button class="wizard-show-btn" data-key="' + id + '" onclick="_wizToggleShow(&#39;wf_&#39;+this.dataset.key,this)">Show</button>'
                   + '</div>';
            }} else {{
                h += '<input class="wizard-input" id="wf_' + id + '" type="' + type + '" value="' + (value||'') + '" ' + readonly + ' style="' + inputStyle + '">';
            }}
            if (hint) h += '<div style="color:#888;font-size:0.78em;margin-top:3px">' + hint + '</div>';
            h += '</div>';
            return h;
        }}

        function _wizToggleShow(inputId, btn) {{
            var inp = document.getElementById(inputId);
            if (!inp) return;
            if (inp.type === 'password') {{ inp.type = 'text'; btn.textContent = 'Hide'; }}
            else {{ inp.type = 'password'; btn.textContent = 'Show'; }}
        }}

        function _wizApiKeyField(id, label, linkText, linkUrl) {{
            var status = _wiz.cfg[id] || '(not set)';
            var statusColor = status === '(not set)' ? '#ff4444' : '#00ff88';
            var h = '<div class="wizard-field">';
            h += '<label class="wizard-label">' + label;
            if (linkText) h += ' <a href="' + linkUrl + '" target="_blank" rel="noopener" style="color:#7cc8ff;font-size:0.9em">' + linkText + '</a>';
            h += '</label>';
            h += '<div class="wizard-row">'
               + '<input class="wizard-input" id="wf_' + id + '" type="password" placeholder="Paste new key here (leave blank to keep current)" autocomplete="off">'
               + '<button class="wizard-show-btn" data-key="' + id + '" onclick="_wizToggleShow(&#39;wf_&#39;+this.dataset.key,this)">Show</button>'
               + '<button class="wizard-validate-btn" data-key="' + id + '" onclick="_wizValidate(this.dataset.key)">Validate</button>'
               + '</div>';
            h += '<div class="wizard-key-status" id="ws_' + id + '">'
               + 'Current: <span style="color:' + statusColor + '">' + status + '</span></div>';
            h += '</div>';
            return h;
        }}

        function _wizValidate(keyName) {{
            var inp = document.getElementById('wf_' + keyName);
            var statusEl = document.getElementById('ws_' + keyName);
            var keyVal = inp ? inp.value.trim() : '';
            if (statusEl) statusEl.innerHTML = 'Validating&hellip;';
            fetch('/api/config/validate-key', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{ key_name: keyName, key_value: keyVal }})
            }})
            .then(function(r) {{ return r.json(); }})
            .then(function(d) {{
                if (statusEl) statusEl.innerHTML = d.ok
                    ? '<span style="color:#00ff88">&#x2713; ' + (d.detail||'Valid') + '</span>'
                    : '<span style="color:#ff4444">&#x2717; ' + (d.error||'Invalid') + '</span>';
            }})
            .catch(function() {{
                if (statusEl) statusEl.innerHTML = '<span style="color:#ff4444">Request failed</span>';
            }});
        }}

        function _wizStep1() {{
            var c = _wiz.cfg;
            var h = '<p class="tier-text" style="color:#ccc;font-size:0.88em;margin-bottom:14px"'
              + ' data-beginner="These are the email settings Nemesis uses to send you security alerts. WATCHDOG_EMAIL is the address that sends the emails. WATCHDOG_TO is where they are delivered."'
              + ' data-intermediate="SMTP credentials and recipient for alert emails."'
              + ' data-pro="SMTP send/receive config for alert notifications.">'
              + 'Email address and SMTP settings for security alert notifications.</p>';
            h += _wizField('WATCHDOG_EMAIL',    'Outbound sender email',     c.WATCHDOG_EMAIL||'', 'email', false, 'The address Nemesis sends alerts from (must match your SMTP credentials)');
            h += _wizField('WATCHDOG_PASSWORD', 'Email password / app password', '', 'password', false, 'Use an app-specific password if your provider supports 2FA (recommended)');
            h += _wizField('WATCHDOG_TO',       'Alert recipient email',      c.WATCHDOG_TO||'', 'email', false, 'Where security alerts are delivered — can be the same as sender or a different address');
            h += _wizField('SMTP_HOST', 'SMTP server',  c.SMTP_HOST||'smtp.gmail.com', 'text', false, 'e.g. smtp.gmail.com, smtp-mail.outlook.com, mail.example.com');
            h += _wizField('SMTP_PORT', 'SMTP port',    c.SMTP_PORT||'587', 'number', false, '587 for STARTTLS (recommended), 465 for implicit SSL');
            h += '<div style="margin-top:12px">'
               + '<button class="wizard-test-btn" onclick="_wizTestEmail()">&#x2709; Send Test Email</button>'
               + '<span id="wizEmailStatus" class="wizard-status"></span>'
               + '</div>';
            return h;
        }}

        function _wizTestEmail() {{
            _wizCollectChanges();
            var status = document.getElementById('wizEmailStatus');
            if (status) status.textContent = 'Sending…';
            fetch('/api/config/test-email', {{method:'POST'}})
                .then(function(r){{ return r.json(); }})
                .then(function(d){{
                    if (status) status.innerHTML = d.ok
                        ? '<span style="color:#00ff88">&#x2713; Sent! Check your inbox.</span>'
                        : '<span style="color:#ff4444">&#x2717; ' + (d.error||'Failed') + '</span>';
                }})
                .catch(function(){{
                    if (status) status.innerHTML = '<span style="color:#ff4444">Request failed</span>';
                }});
        }}

        function _wizStep2() {{
            var h = '<p class="tier-text" style="color:#ccc;font-size:0.88em;margin-bottom:14px"'
              + ' data-beginner="API keys let Nemesis connect to external services. Anthropic enables the AI analysis features. AbuseIPDB and IPInfo help identify threats. Leave a field blank to keep the current key."'
              + ' data-intermediate="Third-party API keys for AI, threat intel, and IP lookup features. Paste a new key to update; leave blank to keep current."'
              + ' data-pro="API credentials: Anthropic (AI), AbuseIPDB (threat reporting), IPInfo (geo/ASN lookup).">'
              + 'API keys for AI and threat intelligence features. Each key is stored in /etc/nemesis.env.</p>';
            h += _wizApiKeyField('ANTHROPIC_API_KEY', 'Anthropic API key (AI features)', '↗ console.anthropic.com', 'https://console.anthropic.com/');
            h += _wizApiKeyField('ABUSEIPDB_KEY',     'AbuseIPDB key (threat reporting)', '↗ abuseipdb.com', 'https://www.abuseipdb.com/');
            h += _wizApiKeyField('IPINFO_TOKEN',      'IPInfo token (IP geo lookup)',     '↗ ipinfo.io', 'https://ipinfo.io/');
            return h;
        }}

        function _wizStep3() {{
            var n = _wiz.cfg.network || {{}};
            var h = '<p class="tier-text" style="color:#ccc;font-size:0.88em;margin-bottom:14px"'
              + ' data-beginner="These settings identify this machine on your home network. The IP address and subnet are read-only — to change your IP permanently, set a DHCP reservation on your router."'
              + ' data-intermediate="Network interface and IP configuration. IP/subnet auto-detected — use router DHCP reservation to make static."'
              + ' data-pro="NIC binding and CIDR. Read-only IP/subnet — set static via router DHCP. Override interface name if auto-detection is wrong.">'
              + 'Network interface and address configuration for this machine.</p>';
            h += _wizField('NETWORK_IFACE', 'Network interface name', n.interface||'', 'text', false, 'Auto-detected — override only if Nemesis is monitoring the wrong interface');
            h += _wizField('_NET_IP',       'This machine&#39;s IP address', n.ip||'', 'text', true,
                           'Read-only — to assign a permanent IP, set a DHCP reservation on your router using the MAC address of this machine');
            h += _wizField('_NET_SUBNET',   'Local subnet (CIDR)',         n.subnet||'', 'text', true,
                           'Auto-derived from network interface — read-only');
            return h;
        }}

        function _wizStep4() {{
            var c = _wiz.cfg;
            var h = '<p class="tier-text" style="color:#ccc;font-size:0.88em;margin-bottom:14px"'
              + ' data-beginner="Pi-hole is the DNS ad-blocker running on your network. Nemesis connects to it to show stats and control blocklists."'
              + ' data-intermediate="Pi-hole admin credentials for the stats API and dashboard integration."'
              + ' data-pro="PIHOLE_PASSWORD for /api/auth. Pi-hole URL auto-detected from PIHOLE_IP env var.">'
              + 'Pi-hole credentials for dashboard integration and stats display.</p>';
            h += _wizField('PIHOLE_PASSWORD', 'Pi-hole admin password', '', 'password', false, 'The password set in Pi-hole settings → admin password');
            h += '<div class="wizard-field"><div class="wizard-label">Pi-hole admin URL</div>'
               + '<div style="font-family:monospace;color:#ccc;padding:7px 0;font-size:0.9em">' + (c.pihole_url||'(auto-detected)') + '</div>'
               + '<div style="color:#888;font-size:0.78em">Auto-detected from PIHOLE_IP — update that env var if your Pi-hole is at a different address</div>'
               + '</div>';
            h += '<div style="margin-top:8px">'
               + '<button class="wizard-test-btn" onclick="_wizTestPihole()">Test Pi-hole Connection</button>'
               + '<span id="wizPiholeStatus" class="wizard-status"></span>'
               + '</div>';
            return h;
        }}

        function _wizTestPihole() {{
            _wizCollectChanges();
            var status = document.getElementById('wizPiholeStatus');
            if (status) status.textContent = 'Testing…';
            var pw = (document.getElementById('wf_PIHOLE_PASSWORD')||{{}}).value || '';
            var keyName = 'PIHOLE_PASSWORD';
            fetch('/api/config/validate-key', {{
                method: 'POST',
                headers: {{'Content-Type':'application/json'}},
                body: JSON.stringify({{ key_name: keyName, key_value: pw }})
            }})
            .then(function(r) {{ return r.json(); }})
            .then(function(d) {{
                if (status) status.innerHTML = d.ok
                    ? '<span style="color:#00ff88">&#x2713; ' + (d.detail||'Connected') + '</span>'
                    : '<span style="color:#ff4444">&#x2717; ' + (d.error||'Failed') + '</span>';
            }})
            .catch(function() {{
                if (status) status.innerHTML = '<span style="color:#ff4444">Request failed</span>';
            }});
        }}

        function _wizStep5() {{
            var keys = Object.keys(_wiz.changes);
            var h = '<p class="tier-text" style="color:#ccc;font-size:0.88em;margin-bottom:14px"'
              + ' data-beginner="Review the changes you have made. Click Save Changes to write them to /etc/nemesis.env. The dashboard will restart automatically so the new settings take effect."'
              + ' data-intermediate="Summary of changed values. Save writes to /etc/nemesis.env and triggers a dashboard restart."'
              + ' data-pro="Diff of /etc/nemesis.env changes. Save → write + systemctl restart dashboard.">'
              + 'Review all changes before saving. Saving restarts the dashboard.</p>';
            if (keys.length === 0) {{
                h += '<div style="color:#bbb;padding:12px;font-style:italic;background:#0d1117;border-radius:6px">No changes made — nothing to save.</div>';
            }} else {{
                h += '<div style="margin-bottom:4px;color:#888;font-size:0.78em;text-transform:uppercase;letter-spacing:0.05em">' + keys.length + ' value(s) to update:</div>';
                keys.forEach(function(k) {{
                    if (k.startsWith('_')) return;
                    h += '<div class="wizard-review-row">'
                       + '<span class="wizard-review-key">' + k + '</span>'
                       + '<span class="wizard-review-val">' + (k.toLowerCase().includes('password')||k.toLowerCase().includes('key')||k.toLowerCase().includes('token') ? '••••••••' : _wiz.changes[k]) + '</span>'
                       + '</div>';
                }});
            }}
            return h;
        }}

        function _wizCollectChanges() {{
            var fields = [
                'WATCHDOG_EMAIL','WATCHDOG_PASSWORD','WATCHDOG_TO','SMTP_HOST','SMTP_PORT',
                'ANTHROPIC_API_KEY','ABUSEIPDB_KEY','IPINFO_TOKEN',
                'NETWORK_IFACE','PIHOLE_PASSWORD'
            ];
            fields.forEach(function(k) {{
                var el = document.getElementById('wf_' + k);
                if (!el) return;
                var v = el.value.trim();
                if (!v) return;                       /* blank never clears a stored value */
                /* Only fields the user actually EDITED. el.defaultValue is the
                   value this input was RENDERED with, so this compares against
                   what was on screen rather than against stored config.
                
                   That distinction is the whole fix. NETWORK_IFACE is rendered
                   from live auto-detection, not from the stored value, so
                   comparing to stored config would mark it "changed" whenever
                   detection disagreed — which is exactly what happened on
                   2026-07-31: two saves that touched only SMTP_HOST silently
                   rewrote NETWORK_IFACE to the VPN interface, because the
                   wizard sent every populated field rather than the edited one.
                
                   Secret fields render EMPTY (defaultValue ''), so typing any
                   value counts as a change — which is correct, since there is
                   nothing on screen to compare against. */
                if (el.value !== el.defaultValue) _wiz.changes[k] = v;
            }});
        }}

        function _wizSave() {{
            _wizCollectChanges();
            var toSave = {{}};
            Object.keys(_wiz.changes).forEach(function(k) {{
                if (!k.startsWith('_')) toSave[k] = _wiz.changes[k];
            }});
            if (Object.keys(toSave).length === 0) {{
                closeConfigWizard(); return;
            }}
            var btn = document.getElementById('wizSaveBtn');
            var status = document.getElementById('wizSaveStatus');
            if (btn) {{ btn.disabled = true; btn.textContent = 'Saving…'; }}
            if (status) status.textContent = '';
            /* Config save writes secrets into a root-owned file that seven
               services source, so it is a privileged act and takes a fresh
               admin password — same rule as block/unblock. */
            fwPrompt('save configuration changes').then(function (pw) {{
              if (!pw) {{
                  if (btn) {{ btn.disabled = false; btn.textContent = 'Save Changes'; }}
                  return;
              }}
              toSave.password = pw;
              fetch('/api/config/update', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify(toSave)
              }})
            .then(function(r) {{ return r.json(); }})
            .then(function(d) {{
                if (d.ok) {{
                    if (status) status.innerHTML = '<span style="color:#00ff88">&#x2713; Saved ' + (d.updated||[]).length + ' value(s) — restarting in 5s&hellip;</span>';
                    setTimeout(function() {{ location.reload(); }}, 5000);
                }} else {{
                    if (btn) {{ btn.disabled = false; btn.textContent = 'Save Changes & Restart'; }}
                    if (status) status.innerHTML = '<span style="color:#ff4444">&#x2717; ' + (d.error||'Save failed') + '</span>';
                }}
            }})
              .catch(function() {{
                if (btn) {{ btn.disabled = false; btn.textContent = 'Save Changes & Restart'; }}
                if (status) status.innerHTML = '<span style="color:#ff4444">Request failed</span>';
              }});
            }});   /* close fwPrompt().then( */
        }}

        loadScheduleConfig();

        {'function restartWindowsAgent() {var btn=document.getElementById("restartAgentBtn");var msg=document.getElementById("restartAgentMsg");btn.disabled=true;btn.style.opacity="0.6";msg.style.display="inline";fetch("http://' + _agent_ip + ':5001/control",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:"restart"})}).then(function(){msg.textContent="Restart command sent.";}).catch(function(e){msg.textContent="Error: "+e;msg.style.color="#ff4444";});}' if _is_windows_agent else ''}
    </script>
</body>
</html>"""


@app.route("/api/diagnostics/run/<check_id>")
def api_diag_run(check_id):
    result = _diag.run_check(check_id)
    return jsonify(result)


@app.route("/api/diagnostics/run-all")
def api_diag_run_all():
    results = [_diag.run_check(m.META["id"]) for m in _diag.CHECKS]
    return jsonify(results)


@app.route("/api/diagnostics/submit", methods=["POST"])
def api_diag_submit():
    data = request.get_json(force=True, silent=True) or {}
    user_notes = _diag.redact(str(data.get("notes", "")).strip())
    results = data.get("results", [])
    hostname = subprocess.run(
        ["hostname"], capture_output=True, text=True
    ).stdout.strip() or "unknown"

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"Nemesis Firewall Diagnostics Report",
        f"Generated: {now_str}  |  Host: {hostname}",
        "=" * 70,
        "",
        "USER NOTES:",
        user_notes if user_notes else "(none provided)",
        "",
        "=" * 70,
        "DIAGNOSTIC RESULTS:",
        "",
    ]
    for res in results:
        name   = res.get("name", res.get("id", "?"))
        status = res.get("status", "?").upper()
        summary = _diag.redact(res.get("summary", ""))
        output  = _diag.redact(res.get("output", ""))
        lines.append(f"[{status}] {name}")
        lines.append(f"  Summary: {summary}")
        lines.append("-" * 60)
        lines.append(output)
        lines.append("")

    body = "\n".join(lines)

    sender = os.environ.get("WATCHDOG_EMAIL", "")
    if not sender or not os.environ.get("WATCHDOG_PASSWORD", ""):
        return jsonify({"ok": False, "error": "WATCHDOG_EMAIL / WATCHDOG_PASSWORD not configured in nemesis.env — cannot send email."})

    subject = f"[Nemesis Support] Diagnostics — {hostname} — {now_str}"
    ok = email_utils.send_email(subject, body, to="support@nemesis-sw.com", cc=sender)
    if ok:
        log.info("diagnostics: support email sent from %s", sender)
        return jsonify({"ok": True, "sent_from": sender})
    else:
        return jsonify({"ok": False, "error": "Email send failed — check SMTP settings and credentials in nemesis.env (SMTP_HOST, SMTP_PORT, WATCHDOG_EMAIL, WATCHDOG_PASSWORD)."})


@app.route("/diagnostics")
def diagnostics_page():
    # Build check cards entirely in Python — avoids JS string/quote escaping bugs.
    check_ids_js = "[" + ",".join(f'"{m.META["id"]}"' for m in _diag.CHECKS) + "]"

    cards_html = ""
    for m in _diag.CHECKS:
        cid   = html.escape(m.META["id"])
        name  = html.escape(m.META["name"])
        icon  = html.escape(m.META["icon"])
        db    = html.escape(m.META["descriptions"]["beginner"],  quote=True)
        di    = html.escape(m.META["descriptions"]["intermediate"], quote=True)
        dp    = html.escape(m.META["descriptions"]["pro"],       quote=True)
        cards_html += f"""
    <div class="check-card" id="card-{cid}">
        <div class="check-header">
            <span class="check-icon">{icon}</span>
            <div class="check-title">
                <div class="check-name">{name}</div>
                <div class="check-desc tier-text"
                     data-beginner="{db}"
                     data-intermediate="{di}"
                     data-pro="{dp}">{di}</div>
            </div>
            <span class="check-status status-idle" id="badge-{cid}">Not run</span>
            <button class="run-btn" id="btn-{cid}"
                    onclick="runCheck(this.dataset.id)" data-id="{cid}">Run</button>
        </div>
        <div class="check-output" id="out-{cid}">
            <div class="check-summary" id="sum-{cid}"></div>
            <pre id="pre-{cid}"></pre>
        </div>
    </div>"""

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Nemesis — Diagnostics</title>
    <script src="/static/tier.js"></script>
    <script src="/static/fw-credential.js"></script>
    <script src="/static/nemesis-idle-lock.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; background: #1a1a2e; color: #eee;
               padding: 24px; max-width: 900px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; margin-bottom: 4px; }}
        h2 {{ color: #00d4ff; font-size: 1.05em; margin: 28px 0 10px 0;
             border-bottom: 1px solid #1e2d4e; padding-bottom: 6px; }}
        a.back {{ color: #00d4ff; text-decoration: none; font-size: 0.9em; }}
        a.back:hover {{ text-decoration: underline; }}
        .intro {{ color: #ccc; font-size: 0.9em; margin: 0 0 20px 0; line-height: 1.6; }}
        .check-card {{ background: #0d1117; border: 1px solid #1e2d4e; border-radius: 8px;
                       padding: 14px 16px; margin-bottom: 12px; }}
        .check-header {{ display: flex; align-items: center; gap: 12px; }}
        .check-icon {{ font-size: 1.4em; flex-shrink: 0; }}
        .check-title {{ flex: 1; min-width: 0; }}
        .check-name {{ font-weight: bold; color: #eee; font-size: 1em; }}
        .check-desc {{ color: #bbb; font-size: 0.83em; margin-top: 2px; line-height: 1.4; }}
        .check-status {{ font-size: 0.78em; font-weight: bold; padding: 3px 8px;
                         border-radius: 10px; flex-shrink: 0; white-space: nowrap; }}
        .status-ok    {{ background: rgba(0,255,136,0.15); color: #00ff88; }}
        .status-warn  {{ background: rgba(255,136,0,0.15);  color: #ff8800; }}
        .status-error {{ background: rgba(255,68,68,0.15);  color: #ff4444; }}
        .status-info  {{ background: rgba(0,212,255,0.1);   color: #00d4ff; }}
        .status-idle  {{ background: rgba(100,100,100,0.15); color: #bbb; }}
        .run-btn {{ background: #00d4ff; color: #1a1a2e; border: none;
                    padding: 6px 16px; border-radius: 4px; cursor: pointer;
                    font-weight: bold; font-size: 0.88em; flex-shrink: 0;
                    transition: background 0.15s; }}
        .run-btn:hover {{ background: #00b8d9; }}
        .run-btn:disabled {{ background: #333; color: #bbb; cursor: not-allowed; }}
        .check-output {{ margin-top: 12px; display: none; }}
        .check-output.visible {{ display: block; }}
        .check-summary {{ font-size: 0.85em; color: #ccc; margin: 4px 0 2px 0; }}
        .check-output pre {{ background: #060b12; border: 1px solid #1e2d4e; border-radius: 4px;
                              padding: 12px; font-size: 0.8em; line-height: 1.5;
                              color: #ccc; white-space: pre-wrap; word-break: break-word;
                              max-height: 350px; overflow-y: auto; margin: 0; }}
        .top-actions {{ display: flex; gap: 10px; align-items: center;
                        margin-bottom: 20px; flex-wrap: wrap; }}
        .btn-run-all {{ background: #16213e; border: 1px solid #00d4ff; color: #00d4ff;
                        padding: 9px 20px; border-radius: 5px; cursor: pointer;
                        font-weight: bold; font-size: 0.95em; transition: background 0.15s; }}
        .btn-run-all:hover {{ background: rgba(0,212,255,0.1); }}
        .btn-run-all:disabled {{ border-color: #444; color: #bbb; cursor: not-allowed; }}
        .btn-submit {{ background: #00ff88; color: #1a1a2e; border: none;
                       padding: 9px 20px; border-radius: 5px; cursor: pointer;
                       font-weight: bold; font-size: 0.95em; transition: background 0.15s; }}
        .btn-submit:hover {{ background: #00cc6a; }}
        .btn-submit:disabled {{ background: #333; color: #bbb; cursor: not-allowed; }}
        .notes-area {{ width: 100%; box-sizing: border-box; background: #0d1117;
                       border: 1px solid #333; color: #eee; border-radius: 6px;
                       padding: 10px 12px; font-size: 0.9em; resize: vertical;
                       font-family: Arial, sans-serif; }}
        .notes-area:focus {{ outline: none; border-color: #00d4ff; }}
        .redact-notice {{ background: rgba(0,212,255,0.07); border: 1px solid rgba(0,212,255,0.2);
                          border-radius: 6px; padding: 10px 14px; font-size: 0.83em;
                          color: #ccc; margin-bottom: 18px; }}
        .submit-status {{ font-size: 0.88em; margin-top: 8px; }}
        #runAllProgress {{ font-size: 0.85em; color: #ccc; }}
    </style>
</head>
<body>
    <h1>🔍 Nemesis Diagnostics
        <span style="float:right;font-size:0.42em">
            <a class="back" href="/">← Dashboard</a>
            &nbsp;|&nbsp;
            <a class="back" href="/settings" target="_blank" rel="noopener">⚙️ Settings</a>
        </span>
    </h1>
    <p class="intro">
        <span class="tier-text"
            data-beginner="Run these checks to see the current health of your Nemesis Firewall. Each check examines a different part of the system. When you&apos;re done, you can send the results to support — all API keys and passwords are automatically hidden before anything is sent."
            data-intermediate="Run individual or all diagnostic checks. Sensitive values (API keys, passwords) are automatically redacted server-side before display or submission. Use the free-text box to describe your issue before submitting."
            data-pro="Diagnostic runner for Nemesis components. Each check is independently runnable (python3 -m diagnostics.&lt;id&gt;). Redaction applied server-side before all output. Submit POSTs to support@nemesis-sw.com via WATCHDOG_EMAIL SMTP.">
            Run these checks to see the current health of your Nemesis Firewall.
        </span>
    </p>

    <div class="redact-notice">
        🔒 <strong>Automatic redaction:</strong>
        <span class="tier-text"
            data-beginner="Your API keys, email passwords, and other private settings are automatically hidden before any results are displayed or sent — you never need to scrub them yourself."
            data-intermediate="All sensitive values from /etc/nemesis.env (API keys, passwords, tokens) are redacted server-side before output reaches your browser or a support email."
            data-pro="Redaction: loads /etc/nemesis.env + live os.environ at run time; replaces all secret values ≥8 chars with [REDACTED] before JSON response is serialized.">
            Your API keys, email passwords, and other private settings are automatically hidden.
        </span>
    </div>

    <div class="top-actions">
        <button class="btn-run-all" id="btnRunAll" onclick="runAll()">▶ Run All Checks</button>
        <span id="runAllProgress"></span>
    </div>

    <h2><span class="tier-text"
        data-beginner="Individual Checks — click Run to see results"
        data-intermediate="Diagnostic Checks"
        data-pro="Checks ({len(_diag.CHECKS)})">Diagnostic Checks</span></h2>

{cards_html}

    <h2><span class="tier-text"
        data-beginner="Describe What&apos;s Happening (optional)"
        data-intermediate="Notes for Support"
        data-pro="Notes for Support">Notes for Support</span></h2>
    <p style="color:#bbb;font-size:0.85em;margin:0 0 8px 0">
        <span class="tier-text"
            data-beginner="Describe what&apos;s wrong, what you expected to happen, or any question you have. This will be included in your report alongside the diagnostic results."
            data-intermediate="Free-text description included with submitted reports. Sensitive values are redacted before sending."
            data-pro="Included in email body as USER NOTES. Redacted server-side before SMTP send.">
            Describe what's wrong or any question you have.
        </span>
    </p>
    <textarea id="supportNotes" class="notes-area" rows="5"
        placeholder="e.g. The anomaly detection module stopped sending alerts after I restarted the server..."></textarea>

    <div style="margin-top:16px;display:flex;gap:12px;align-items:flex-start;flex-wrap:wrap">
        <button class="btn-submit" onclick="submitReport()">📧 Submit to Support</button>
        <div>
            <div class="submit-status" id="submitStatus" style="color:#ccc"></div>
            <div style="color:#bbb;font-size:0.78em;margin-top:4px">
                <span class="tier-text"
                    data-beginner="Sends an email with your notes and whichever diagnostic results you&apos;ve run. You&apos;ll get a copy at your configured alert email address."
                    data-intermediate="Sends to support@nemesis-sw.com via WATCHDOG_EMAIL SMTP. CC&apos;d to WATCHDOG_EMAIL."
                    data-pro="POST /api/diagnostics/submit → SMTP to support@nemesis-sw.com, Cc: WATCHDOG_EMAIL.">
                    Sends to support@nemesis-sw.com. You get a copy at your alert email.
                </span>
            </div>
        </div>
    </div>

    <script>
    var CHECK_IDS = {check_ids_js};
    var _results = {{}};
    var _running = {{}};

    function _statusClass(s) {{
        return 'status-' + ({{ok:'ok',warn:'warn',error:'error',info:'info'}}[s] || 'idle');
    }}
    function _statusLabel(s) {{
        return ({{ok:'✓ OK', warn:'⚠ Warning', error:'✗ Error', info:'ℹ Info'}})[s] || 'Not run';
    }}

    function runCheck(id) {{
        if (_running[id]) return;
        _running[id] = true;
        var btn   = document.getElementById('btn-'   + id);
        var badge = document.getElementById('badge-' + id);
        var out   = document.getElementById('out-'   + id);
        var pre   = document.getElementById('pre-'   + id);
        var sum   = document.getElementById('sum-'   + id);
        btn.disabled = true;
        btn.textContent = 'Running…';
        badge.className = 'check-status status-info';
        badge.textContent = '⌛ Running';
        out.classList.add('visible');
        pre.textContent = 'Running check…';
        sum.textContent = '';
        fetch('/api/diagnostics/run/' + id, {{cache: 'no-store'}})
            .then(function(r) {{ return r.json(); }})
            .then(function(d) {{
                _results[id] = d;
                badge.className = 'check-status ' + _statusClass(d.status);
                badge.textContent = _statusLabel(d.status);
                sum.textContent = d.summary || '';
                pre.textContent = d.output || '(no output)';
                btn.disabled = false;
                btn.textContent = 'Re-run';
            }})
            .catch(function(e) {{
                badge.className = 'check-status status-error';
                badge.textContent = '✗ Error';
                pre.textContent = 'Request failed: ' + String(e);
                btn.disabled = false;
                btn.textContent = 'Retry';
            }})
            .finally(function() {{ _running[id] = false; }});
    }}

    async function runAll() {{
        var btn  = document.getElementById('btnRunAll');
        var prog = document.getElementById('runAllProgress');
        btn.disabled = true;
        for (var i = 0; i < CHECK_IDS.length; i++) {{
            var id = CHECK_IDS[i];
            var name = (document.getElementById('card-' + id)
                           .querySelector('.check-name') || {{}}).textContent || id;
            prog.textContent = 'Running ' + (i + 1) + ' / ' + CHECK_IDS.length + ': ' + name + '…';
            await new Promise(function(resolve) {{
                var cid  = id;
                if (_running[cid]) {{ resolve(); return; }}
                _running[cid] = true;
                var badge = document.getElementById('badge-' + cid);
                var out   = document.getElementById('out-'   + cid);
                var pre   = document.getElementById('pre-'   + cid);
                var sum   = document.getElementById('sum-'   + cid);
                var cbtn  = document.getElementById('btn-'   + cid);
                cbtn.disabled = true;
                cbtn.textContent = 'Running…';
                badge.className = 'check-status status-info';
                badge.textContent = '⌛ Running';
                out.classList.add('visible');
                pre.textContent = 'Running…';
                fetch('/api/diagnostics/run/' + cid, {{cache: 'no-store'}})
                    .then(function(r) {{ return r.json(); }})
                    .then(function(d) {{
                        _results[cid] = d;
                        badge.className = 'check-status ' + _statusClass(d.status);
                        badge.textContent = _statusLabel(d.status);
                        sum.textContent = d.summary || '';
                        pre.textContent = d.output || '(no output)';
                        cbtn.disabled = false;
                        cbtn.textContent = 'Re-run';
                    }})
                    .catch(function(e) {{
                        badge.className = 'check-status status-error';
                        badge.textContent = '✗ Error';
                        pre.textContent = 'Request failed: ' + String(e);
                        cbtn.disabled = false;
                        cbtn.textContent = 'Retry';
                    }})
                    .finally(function() {{ _running[cid] = false; resolve(); }});
            }});
        }}
        prog.textContent = 'All ' + CHECK_IDS.length + ' checks complete.';
        btn.disabled = false;
    }}

    function submitReport() {{
        var notes = document.getElementById('supportNotes').value.trim();
        var runResults = Object.values(_results);
        var statusEl = document.getElementById('submitStatus');
        if (runResults.length === 0 && !notes) {{
            statusEl.textContent = 'Run at least one check or add a note before submitting.';
            statusEl.style.color = '#ff8800';
            return;
        }}
        var btn = document.querySelector('.btn-submit');
        btn.disabled = true;
        statusEl.style.color = '#aaa';
        statusEl.textContent = 'Sending…';
        fetch('/api/diagnostics/submit', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify({{notes: notes, results: runResults}}),
        }})
            .then(function(r) {{ return r.json(); }})
            .then(function(d) {{
                if (d.ok) {{
                    statusEl.textContent = '✓ Sent! You’ll receive a copy at ' + (d.sent_from || 'your alert email') + '.';
                    statusEl.style.color = '#00ff88';
                }} else {{
                    statusEl.textContent = '✗ Failed: ' + (d.error || 'unknown error');
                    statusEl.style.color = '#ff4444';
                }}
            }})
            .catch(function(e) {{
                statusEl.textContent = '✗ Request error: ' + String(e);
                statusEl.style.color = '#ff4444';
            }})
            .finally(function() {{ btn.disabled = false; }});
    }}
    </script>
</body>
</html>"""


@app.route("/firewall-db")
def firewall_db():
    # Tiered tooltip descriptions for known Suricata rule IDs.
    # Each entry: (beginner, intermediate, pro)
    RULE_TIPS = {
        # Device Retrieving External IP Address family
        "2054140": (
            "A device on your network checked what its public internet address is — like asking 'what is my IP?' Very common and almost always harmless. Browsers, apps, and smart devices do this regularly.",
            "ET INFO: device queried an external IP-echo service (ipify, ifconfig.me, etc.). Routine behavior on home networks; fires on IoT, browsers, and apps needing WAN IP awareness.",
            "ET INFO Device Retrieving External IP. HTTP/DNS to IP-echo service. Expected on NAT'd LAN; low signal."
        ),
        "2054168": (
            "A device checked its own public internet address using a slightly different method than the most common pattern. Still routine and harmless.",
            "ET INFO external IP retrieval via alternate endpoint. Same class as 2054140; different URL/method signature.",
            "ET INFO Device Retrieving External IP. Alt-endpoint variant of 2054140."
        ),
        "2054169": (
            "Another variant of the 'device checking its public IP' pattern. Normal background behaviour.",
            "ET INFO external IP retrieval, third endpoint variant. Same risk profile as 2054140/2054168.",
            "ET INFO Device Retrieving External IP. Endpoint variant #3."
        ),
        "2025331": (
            "A device asked an external service for its public IP address — routine and expected.",
            "ET INFO external IP lookup via a specific service endpoint. Low risk, routine on home networks.",
            "ET INFO Device Retrieving External IP. Service-specific signature."
        ),
        "2039594": (
            "A device checked its public IP address using yet another external service. Completely routine.",
            "ET INFO external IP retrieval, additional service variant. Same class and risk as other 205xxxx rules.",
            "ET INFO Device Retrieving External IP. Additional service variant."
        ),
        "2026718": (
            "A device on your network looked up its own public IP address. Normal behaviour.",
            "ET INFO external IP lookup. One occurrence; same low-risk class as other IP-retrieval rules.",
            "ET INFO Device Retrieving External IP. Single occurrence."
        ),
        # Potentially Bad Traffic — identified apps
        "2027758": (
            "Wondershare software (PDF editor, video tools, etc.) on your network sent data back to Wondershare's servers — likely telemetry or licence checks. Not malicious, but it does track usage.",
            "ET POLICY Wondershare software telemetry/licensing traffic. 'Potentially Bad Traffic' reflects privacy concern, not active threat.",
            "ET POLICY Wondershare telemetry/licensing C2. Privacy flag; not malicious."
        ),
        "2028651": (
            "Steam (Valve's PC gaming platform) is communicating with its servers. Completely normal when the Steam app or a Steam game is running.",
            "ET POLICY Steam gaming client protocol detected. 'Corporate Privacy Violation' is Suricata's DPI classification for recognisable platform traffic, not an actual threat.",
            "ET POLICY Steam client traffic. Corporate privacy classification (DPI); expected. Not a threat."
        ),
        "2027867": (
            "An Amazon Fire TV or Echo device is talking to Amazon's servers — normal operation for streaming and smart-home devices. The 'dewrain' label refers to the traffic pattern Amazon uses.",
            "ET POLICY dewrain — Amazon Fire TV/Echo traffic to AWS. Pattern matches Amazon streaming device cloud communication.",
            "ET dewrain. Fire TV/Echo → AWS traffic. Amazon streaming infra pattern. Not a threat."
        ),
        # Potentially Bad Traffic — generic patterns
        "2029340": (
            "Suricata spotted a traffic pattern it considers potentially suspicious, but assessed it as low risk. Likely an app communicating in an unusual but harmless way.",
            "ET POLICY Potentially Bad Traffic. LOW risk; specific trigger context is in the raw alert. Review source/destination if unexpected.",
            "ET POLICY Potentially Bad Traffic. LOW. Check raw alert for signature context."
        ),
        "2027757": (
            "A network traffic pattern that Suricata flags as potentially suspicious, though it was rated low risk. Probably routine application traffic.",
            "ET POLICY Potentially Bad Traffic, low frequency. LOW risk classification; check raw alert for specific trigger.",
            "ET POLICY Potentially Bad Traffic. LOW. 3 occurrences."
        ),
        "2037042": (
            "Another low-risk 'potentially bad traffic' pattern. Usually means an app doing something slightly unusual but not actually harmful.",
            "ET POLICY Potentially Bad Traffic. LOW risk; infrequent. Examine raw alert for source application context.",
            "ET POLICY Potentially Bad Traffic. LOW. Infrequent."
        ),
        "2027863": (
            "A traffic pattern Suricata flagged as potentially suspicious but rated low risk. Very rare — only seen twice.",
            "ET POLICY Potentially Bad Traffic. LOW risk; 2 occurrences. Check raw alert for specific context.",
            "ET POLICY Potentially Bad Traffic. LOW. 2 hits."
        ),
        # ICMP / Misc Attack
        "2400016": (
            "An ICMP 'ping' was detected — this is how computers check if another device is reachable, like knocking on a door. On a home network this is almost always harmless.",
            "GPL ICMP_INFO PING *NIX — ICMP echo request. 'Misc Attack' is a legacy Snort/GPL classification; ICMP pings are routine on home LANs. Worth reviewing src/dst if unexpected.",
            "GPL ICMP_INFO PING *NIX. Legacy Misc Attack class. ICMP echo; routine on home LAN. Verify src/dst."
        ),
        "2400038": (
            "Another ICMP ping alert — a device checked if another device was reachable. The difference from the other ping alert is the format of the ping, not the risk level.",
            "GPL ICMP_INFO PING BSDtype — BSD-format ICMP echo variant. Same classification and risk as 2400016; distinguishes OS-specific ICMP payload format.",
            "GPL ICMP_INFO PING BSDtype. BSD-format ICMP echo variant of 2400016. Same risk profile."
        ),
    }
    GENERIC_TIP = (
        "This Suricata rule fired for traffic that matched a known pattern. The AI rated it LOW risk — click 'View' on the main dashboard alert list to see the full AI analysis.",
        "Suricata signature match; LOW risk per AI analysis. See the dashboard alert view for explanation and raw alert context.",
        "Suricata sig match. LOW risk. See alert view for raw context."
    )

    # Shared chat widget for the full alert view. This page anchors on the same
    # TEXT rule_id the "alert" chat surface is registered with (dashboard.py's
    # _anchor_load_alert), so the existing anchor serves it as-is -- no second
    # surface to register. Empty string when ai_engine is unavailable, so the
    # page renders identically minus the affordance.
    chat_js_html = ""
    try:
        from modules.ai_engine import get_chat_js as _ai_cjs
        chat_js_html = _ai_cjs()
    except Exception:
        pass

    try:
        conn = _dm_conn()   # §9 batch 2 (firewall_db)
        c = conn.cursor()
        c.execute("SELECT * FROM alerts ORDER BY last_seen DESC")
        alerts = c.fetchall()
        conn.close()
        rows = ""
        for a in alerts:
            aid = int(a[0])
            rule_id_raw = str(a[1] or "")
            rule_id = html.escape(rule_id_raw)
            rule_name = html.escape((a[3] or a[2] or "")[:50])
            risk_level = html.escape(str(a[6] or ""))
            action_val = html.escape(str(a[7] or ""))
            times_seen = html.escape(str(a[8] or ""))
            last_seen = html.escape(str(a[10] or ""))
            rule_id_js = json.dumps(rule_id_raw)
            row_notes_onclick = html.escape(f"openDbNotes({rule_id_js})")

            # Row styling by action status
            if action_val == "pending":
                row_style = "background:rgba(255,170,0,0.08);border-left:3px solid #ffaa00;"
                action_color = "color:#ffaa00;font-weight:bold"
            elif action_val == "ignore":
                row_style = "opacity:0.55;"
                action_color = "color:#bbb"
            elif action_val == "block":
                row_style = "background:rgba(255,68,68,0.08);border-left:3px solid #ff4444;"
                action_color = "color:#ff4444;font-weight:bold"
            elif action_val == "monitor":
                row_style = "background:rgba(0,212,255,0.05);border-left:3px solid #00d4ff;"
                action_color = "color:#00d4ff"
            else:
                row_style = ""
                action_color = ""

            tip_b, tip_m, tip_p = RULE_TIPS.get(rule_id_raw, GENERIC_TIP)
            tip_b = html.escape(tip_b, quote=True)
            tip_m = html.escape(tip_m, quote=True)
            tip_p = html.escape(tip_p, quote=True)

            # Unblock hand-off (2026-07-31). Blocking an alert flips it out of the
            # dashboard's pending views, so the modal carrying the Unblock button —
            # and the credential prompt it needs — is no longer reachable from
            # there. This page is where a blocked alert IS still listed, so it has
            # to offer the way back.
            #
            # A LINK, not an action: it opens the alert modal on the main page
            # rather than unblocking directly. Two reasons. The credential prompt
            # (fwPrompt/fwHandleError) is defined only in dashboard()'s template,
            # and duplicating a password dialog is exactly the kind of thing that
            # drifts out of sync. More importantly, a privileged firewall change
            # must never be triggerable by following a URL — that is CSRF-shaped,
            # and no confirmation dialog makes it acceptable.
            unblock_link = ""
            if a[7] == "block" and a[11]:
                unblock_link = (
                    f"""<a href="/?alert={html.escape(str(a[1]), quote=True)}" """
                    f"""onclick="event.stopPropagation()" """
                    f"""style="display:inline-block;margin-left:8px;color:#00d4ff;font-size:0.85em" """
                    f"""title="Opens this alert so you can unblock {html.escape(str(a[11]), quote=True)}">&#128275; Unblock</a>"""
                )

            rows += f"""<tr class="db-row-click" style="{row_style}cursor:pointer" onclick="{row_notes_onclick}">
                <td style="color:#bbb">{rule_id}</td>
                <td class="rule-name-cell" data-tip-beginner="{tip_b}" data-tip-intermediate="{tip_m}" data-tip-pro="{tip_p}" title="{tip_m}">{rule_name}</td>
                <td style="color:{'#00ff88' if a[6]=='LOW' else '#ffaa00' if a[6]=='MEDIUM' else '#ff4444'}">{risk_level}</td>
                <td style="{action_color}">{action_val}</td>
                <td style="color:#ccc;text-align:right">{times_seen}</td>
                <td style="color:#ccc">{last_seen}</td>
                <td onclick="event.stopPropagation()">
                    <select data-prev="{a[7]}" onchange="changeAction({aid}, this)">
                        <option {"selected" if a[7]=="pending" else ""}>pending</option>
                        <option {"selected" if a[7]=="ignore" else ""}>ignore</option>
                        <option {"selected" if a[7]=="block" else ""}>block</option>
                        <option {"selected" if a[7]=="monitor" else ""}>monitor</option>
                    </select>
                    {unblock_link}
                </td>
                <td style="color:#bbb;font-size:0.85em;white-space:nowrap">Notes ▸</td>
            </tr>"""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Nemesis - Alert Database</title>
    <script src="/static/tier.js"></script>
    <script src="/static/fw-credential.js"></script>
    <script src="/static/nemesis-idle-lock.js"></script>
    <style>
        body {{ font-family: Arial; background: #1a1a2e; color: #eee; padding: 20px; }}
        h1 {{ color: #00d4ff; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #16213e; color: #00d4ff; padding: 10px; text-align: left; }}
        td {{ padding: 8px; border-bottom: 1px solid #222; font-size: 0.85em; }}
        tr.db-row-click:hover td {{ background: rgba(0,212,255,0.05); }}
        select {{ background: #16213e; color: #eee; border: 1px solid #333; padding: 3px; border-radius:3px; }}
        a {{ color: #00d4ff; }}
        .db-modal {{ display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.8); z-index:1000; }}
        .db-modal-inner {{ background:#16213e; border:1px solid #00d4ff; border-radius:10px; padding:20px; max-width:560px; width:90%; max-height:85vh; overflow-y:auto; margin:60px auto; position:relative; }}
        .db-modal-inner h3 {{ color:#00d4ff; margin-top:0; }}
        .note-item {{ border-left:2px solid #333; padding:6px 10px; margin-bottom:8px; }}
        .note-text {{ color:#ddd; font-size:0.85em; white-space:pre-wrap; }}
        .note-meta {{ color:#bbb; font-size:0.75em; margin-top:3px; }}
    </style>
    <script>
        function escHtml(s) {{
            return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
        }}

        function changeAction(id, sel) {{
            var action = sel.value;
            var prev = sel.getAttribute("data-prev") || "pending";
            function send(pw) {{
                return fetch("/api/db-action/" + id + "/" + action, {{
                    method: "POST",
                    headers: {{"Content-Type": "application/json"}},
                    body: JSON.stringify(pw ? {{password: pw}} : {{}})
                }})
                    .then(function(r) {{ return r.json(); }})
                    .then(function(d) {{
                        if (d && d.error) {{
                            /* Nothing changed server-side — do not leave the
                               select showing a state the database does not hold. */
                            if (window.fwHandleError) fwHandleError(d, d.error);
                            else alert(d.error);
                            sel.value = prev;
                            return;
                        }}
                        sel.setAttribute("data-prev", action);
                    }})
                    .catch(function(e) {{ alert("Error: " + e); sel.value = prev; }});
            }}
            /* 'block' applies a real ufw rule through nemesis-fwd, so it needs
               the admin credential — same prompt every other privileged action
               uses. Cancelling must revert the select rather than imply a block. */
            if (action === "block") {{
                fwPrompt("block this address").then(function(pw) {{
                    if (!pw) {{ sel.value = prev; return; }}
                    send(pw);
                }});
            }} else {{
                send(null);
            }}
        }}

        // Apply tier-appropriate tooltip text to rule name cells.
        // Called on load and whenever the tier changes.
        function applyTierTooltips() {{
            var tier = getTier();
            var attr = "data-tip-" + tier;
            document.querySelectorAll(".rule-name-cell[" + attr + "]").forEach(function(el) {{
                el.title = el.getAttribute(attr) || el.getAttribute("data-tip-intermediate") || "";
            }});
        }}
        window.onTierChange = applyTierTooltips;
        window.addEventListener("storage", function(e) {{
            if (e.key === "explanationTier") applyTierTooltips();
        }});
        document.addEventListener("DOMContentLoaded", applyTierTooltips);

        // ── Notes panel ──────────────────────────────────────────
        var _dbNotesRuleId = null;
        var _dbAllNotes = [];
        var _dbNotesPage = 0;
        var _dbNotesSortDesc = true;

        function openDbNotes(ruleId) {{
            _dbNotesRuleId = ruleId;
            _dbAllNotes = [];
            _dbNotesPage = 0;
            _dbNotesSortDesc = true;
            document.getElementById("dbNotesModal").style.display = "block";
            document.getElementById("dbNoteRuleLabel").textContent = ruleId;
            document.getElementById("dbRelatedNotesList").style.display = "none";
            document.getElementById("dbNoteStatus").textContent = "";
            document.getElementById("dbNoteInput").value = "";
            document.getElementById("dbNotesList").innerHTML =
                "<span style='color:#bbb;font-size:0.85em'>Loading notes…</span>";
            if (window.nemChatAttach) {{
                nemChatAttach(document.getElementById("_dbChatHost"), "alert", ruleId);
            }}
            fetch("/api/tickets/notes/" + encodeURIComponent(ruleId))
                .then(function(r) {{ return r.json(); }})
                .then(function(notes) {{
                    _dbAllNotes = notes;
                    _renderDbNotes();
                }})
                .catch(function() {{
                    document.getElementById("dbNotesList").innerHTML =
                        "<span style='color:#ff4444;font-size:0.85em'>Failed to load notes</span>";
                }});
        }}

        function closeDbNotes() {{
            document.getElementById("dbNotesModal").style.display = "none";
            if (window.nemChatClose) nemChatClose();
            _dbNotesRuleId = null;
        }}

        function _renderDbNotes() {{
            var el = document.getElementById("dbNotesList");
            var perPage = 5;
            var sorted = _dbNotesSortDesc ? _dbAllNotes : _dbAllNotes.slice().reverse();
            var visible = sorted.slice(0, (_dbNotesPage + 1) * perPage);
            if (_dbAllNotes.length === 0) {{
                el.innerHTML = "<span style='color:#bbb;font-size:0.85em'>No notes yet. Add one below.</span>";
                return;
            }}
            var sortBtn = "<button onclick='_toggleDbNoteSort()' style='background:transparent;border:none;color:#ccc;cursor:pointer;font-size:0.75em;padding:0;float:right'>" +
                (_dbNotesSortDesc ? "↓ Newest first" : "↑ Oldest first") + "</button>";
            var items = visible.map(function(n) {{
                return '<div class="note-item"><div class="note-text">' + escHtml(n.note) + '</div>' +
                    '<div class="note-meta">' + escHtml(n.author) + ' · ' + escHtml(n.created_at) + '</div></div>';
            }}).join("");
            var moreCount = _dbAllNotes.length - visible.length;
            var moreBtn = moreCount > 0
                ? '<button onclick="_showMoreDbNotes()" style="background:transparent;border:1px solid #444;color:#ccc;padding:3px 8px;cursor:pointer;border-radius:3px;font-size:0.8em">Show ' + Math.min(perPage, moreCount) + ' more…</button>'
                : "";
            el.innerHTML = sortBtn + items + moreBtn;
        }}

        function _toggleDbNoteSort() {{
            _dbNotesSortDesc = !_dbNotesSortDesc;
            _dbNotesPage = 0;
            _renderDbNotes();
        }}

        function _showMoreDbNotes() {{
            _dbNotesPage++;
            _renderDbNotes();
        }}

        function addDbNote() {{
            var text = (document.getElementById("dbNoteInput").value || "").trim();
            if (!text || !_dbNotesRuleId) {{ return; }}
            var status = document.getElementById("dbNoteStatus");
            status.style.color = "#aaa";
            status.textContent = "Saving…";
            fetch("/api/tickets/notes/" + encodeURIComponent(_dbNotesRuleId), {{
                method: "POST",
                headers: {{"Content-Type": "application/json"}},
                body: JSON.stringify({{note: text}})
            }})
            .then(function(r) {{ return r.json(); }})
            .then(function(d) {{
                if (d.ok) {{
                    document.getElementById("dbNoteInput").value = "";
                    status.style.color = "#00ff88";
                    status.textContent = "Saved";
                    openDbNotes(_dbNotesRuleId);
                    setTimeout(function() {{ status.textContent = ""; }}, 2000);
                }} else {{
                    status.style.color = "#ff4444";
                    status.textContent = "Error: " + escHtml(d.error || "unknown");
                }}
            }})
            .catch(function() {{
                status.style.color = "#ff4444";
                status.textContent = "Error saving note";
            }});
        }}

        function loadDbRelatedNotes() {{
            if (!_dbNotesRuleId) {{ return; }}
            var el = document.getElementById("dbRelatedNotesList");
            el.style.display = "block";
            el.innerHTML = "<span style='color:#ccc;font-size:0.85em'>Searching for related notes…</span>";
            fetch("/api/tickets/related/" + encodeURIComponent(_dbNotesRuleId))
                .then(function(r) {{ return r.json(); }})
                .then(function(notes) {{
                    if (notes.length === 0) {{
                        el.innerHTML = "<div style='color:#bbb;font-size:0.85em'>No related notes found (no other alerts share the same source IP with notes).</div>";
                        return;
                    }}
                    var header = "<div style='color:#ccc;font-size:0.75em;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px'>Related Notes (same source IP)</div>";
                    var items = notes.map(function(n) {{
                        return '<div style="border-left:2px solid #444;padding:6px 10px;margin-bottom:8px">' +
                            '<div style="color:#bbb;font-size:0.75em;margin-bottom:2px">' + escHtml(n.rule_name || n.rule_id) + '</div>' +
                            '<div class="note-text">' + escHtml(n.note) + '</div>' +
                            '<div class="note-meta">' + escHtml(n.author) + ' · ' + escHtml(n.created_at) + '</div></div>';
                    }}).join("");
                    el.innerHTML = header + items;
                }})
                .catch(function() {{
                    el.innerHTML = "<span style='color:#ff4444;font-size:0.85em'>Failed to load related notes</span>";
                }});
        }}

        // ── Keyword search ────────────────────────────────────────
        function searchNotes() {{
            var q = (document.getElementById("noteSearchInput").value || "").trim();
            var resEl = document.getElementById("noteSearchResults");
            if (!q) {{
                resEl.style.display = "none";
                return;
            }}
            resEl.style.display = "block";
            resEl.innerHTML = "<span style='color:#ccc;font-size:0.85em'>Searching…</span>";
            fetch("/api/tickets/search?q=" + encodeURIComponent(q))
                .then(function(r) {{ return r.json(); }})
                .then(function(results) {{
                    if (results.length === 0) {{
                        resEl.innerHTML = "<span style='color:#bbb;font-size:0.85em'>No notes match <em>" + escHtml(q) + "</em></span>";
                        return;
                    }}
                    var items = results.map(function(n) {{
                        return '<div style="border-left:2px solid #00d4ff;padding:6px 10px;margin-bottom:8px;background:#0d1117;border-radius:0 4px 4px 0">' +
                            '<div style="color:#ccc;font-size:0.75em;margin-bottom:2px">' +
                            'Rule ' + escHtml(n.rule_id) + (n.rule_name ? ' — ' + escHtml(n.rule_name) : '') + '</div>' +
                            '<div style="color:#ddd;font-size:0.85em;white-space:pre-wrap">' + escHtml(n.note) + '</div>' +
                            '<div style="color:#bbb;font-size:0.75em;margin-top:3px">' + escHtml(n.author) + ' · ' + escHtml(n.created_at) +
                            ' <button onclick="openDbNotes(' + JSON.stringify(n.rule_id) + ')" style="background:transparent;border:none;color:#00d4ff;cursor:pointer;font-size:0.85em;padding:0 4px">→ Notes</button></div>' +
                            '</div>';
                    }}).join("");
                    resEl.innerHTML = '<div style="color:#ccc;font-size:0.8em;margin-bottom:8px">' + results.length + ' note(s) matching <em>' + escHtml(q) + '</em></div>' + items;
                }})
                .catch(function() {{
                    resEl.innerHTML = "<span style='color:#ff4444;font-size:0.85em'>Search failed</span>";
                }});
        }}

        document.addEventListener("DOMContentLoaded", function() {{
            document.getElementById("noteSearchInput").addEventListener("keydown", function(e) {{
                if (e.key === "Enter") searchNotes();
            }});
        }});
    </script>
</head>
<body>
    <h1>🛡️ Nemesis - Alert Database</h1>
    <p><a href="javascript:window.close()" style="color:#bbb">✕ Close this tab</a></p>
    <p style="background:#0d1117;border-left:3px solid #00d4ff;padding:10px 14px;font-size:0.85em;color:#ccc;border-radius:0 4px 4px 0;margin-bottom:16px">
        ℹ️ <strong style="color:#00d4ff">This database shows P1/P2 alerts that required review or action.</strong>
        Routine informational (P3) traffic — DNS lookups, ET POLICY notices, protocol scans — is not individually logged here,
        but is counted in the dashboard's Total and can be inspected in Suricata's fast.log directly.
    </p>
    <div style="margin-bottom:16px;display:flex;gap:8px;align-items:center">
        <input type="text" id="noteSearchInput" placeholder="Search all notes…"
            style="background:#16213e;border:1px solid #333;color:#eee;padding:6px 10px;border-radius:4px;width:280px;font-size:0.9em">
        <button onclick="searchNotes()"
            style="background:#00d4ff;color:#1a1a2e;border:none;padding:6px 14px;cursor:pointer;border-radius:4px;font-weight:bold;font-size:0.9em">Search Notes</button>
    </div>
    <div id="noteSearchResults" style="display:none;background:#0d1117;border:1px solid #333;border-radius:6px;padding:12px;margin-bottom:16px;max-height:300px;overflow-y:auto"></div>
    <!-- Standing note, not decoration. The dropdown below sets FUTURE policy and
         never touches the firewall; setting it to "block" applied nothing, and
         setting it back to "pending" removed nothing. That read as an immediate
         control twice on 2026-07-31 — once during testing and once on production,
         where a rule that was never created appeared to be successfully removed. -->
    <div style="background:#1c1f26;border-left:3px solid #ffaa00;border-radius:4px;
                padding:10px 14px;margin-bottom:16px;color:#ddd;font-size:0.9em">
        <strong style="color:#ffaa00">These settings apply to the NEXT alert, not right now.</strong><br>
        Changing the dropdown decides what Nemesis does the next time a rule fires. It does
        <strong>not</strong> block or unblock anything immediately, and changing it back does
        <strong>not</strong> remove a block that is already in place.<br>
        To block or unblock an address <em>now</em>, open the alert and use
        &#128683; Block IP / &#128275; Unblock IP.
    </div>
    <table>
        <tr><th>Rule ID</th><th>Rule Name</th><th>Risk</th><th>Current Policy</th><th>Times Seen</th><th>Last Seen</th><th title="Sets what happens the NEXT time this rule fires. It does not block or unblock anything right now — use the alert view for that.">Policy on next alert &#9432;</th><th>Notes</th></tr>
        {rows}
    </table>

    {chat_js_html}

    <!-- Notes panel modal -->
    <div class="db-modal" id="dbNotesModal" onclick="if(event.target.id==='dbNotesModal')closeDbNotes()">
        <div class="db-modal-inner">
            <h3>📝 Admin Notes — <span id="dbNoteRuleLabel" style="font-weight:normal;font-size:0.8em;color:#ccc"></span></h3>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
                <div id="dbNotesList" style="flex:1;font-size:0.85em"></div>
            </div>
            <div id="dbRelatedNotesList" style="display:none;border-top:1px solid #222;padding-top:10px;margin-bottom:10px"></div>
            <!-- Chat host for the full alert view. Single page-wide widget
                 instance, injected by ai_engine's get_chat_js() and relocated
                 here by nemChatAttach(). -->
            <div id="_dbChatHost"></div>
            <div style="border-top:1px solid #333;padding-top:12px;margin-top:4px">
                <textarea id="dbNoteInput" placeholder="Add a note…" rows="3"
                    style="width:100%;background:#0d1117;border:1px solid #333;color:#eee;padding:8px;border-radius:4px;font-size:0.85em;resize:vertical;box-sizing:border-box"></textarea>
                <div style="margin-top:8px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
                    <button onclick="addDbNote()"
                        style="background:#00d4ff;color:#1a1a2e;border:none;padding:5px 14px;cursor:pointer;border-radius:3px;font-weight:bold">Add Note</button>
                    <button onclick="loadDbRelatedNotes()"
                        style="background:transparent;border:1px solid #555;color:#ccc;padding:5px 10px;cursor:pointer;border-radius:3px;font-size:0.85em">Find Related Notes</button>
                    <span id="dbNoteStatus" style="font-size:0.8em;color:#ccc"></span>
                    <button onclick="closeDbNotes()"
                        style="background:transparent;border:1px solid #555;color:#bbb;padding:5px 10px;cursor:pointer;border-radius:3px;font-size:0.85em;margin-left:auto">✕ Close</button>
                </div>
            </div>
        </div>
    </div>
</body>
</html>"""
    except Exception as e:
        return str(e)

#: The only values this endpoint may write. Exactly the options the UI's select
#: offers — an allowlist rather than free text, so `action` cannot become an
#: arbitrary string in both `alerts` and `audit_log`.
_ALERT_ACTIONS = {"pending", "ignore", "block", "monitor"}


@app.route("/api/db-action/<int:alert_id>/<action>", methods=["POST"])
def db_action(alert_id, action):
    """Set an alert's action. POST-only, allowlisted, and credential-gated.

    This used to be a bare GET that took any string and wrote it straight into
    `alerts.action` and `audit_log`. Two problems, one of which the surrounding
    page already documents:

      1. A state-changing write reachable by URL is CSRF-shaped — an <img> tag
         was enough. The Unblock control ~40 lines above is a LINK rather than an
         action for exactly this reason ("a privileged firewall change must never
         be triggerable by following a URL"). The select beside it did not follow
         the same rule.
      2. Writing action='block' here recorded a block while applying no firewall
         rule at all. The audit trail then asserted a protection that did not
         exist — worse than no record, because it reads as evidence.

    So `block` now goes through the SAME path as its sibling set_action(): the
    real ufw rule, via nemesis-fwd, with the admin credential the helper itself
    verifies. If the rule cannot be applied, nothing is recorded as blocked.

    The firewall call happens BEFORE any write transaction is opened here, and
    the read connection is closed first — same ordering, and the same reason, as
    set_action(): nemesis-fwd writes its own audit row into this database, and
    holding a transaction across the helper call made that write hit
    SQLITE_BUSY, silently losing the helper-side audit record.

    Non-block actions need no credential, matching set_action() exactly — they
    change a label, not the firewall.
    """
    if action not in _ALERT_ACTIONS:
        return jsonify({"error": "invalid action"}), 400
    try:
        conn = _dm_conn()   # §9 batch 4 (db_action)
        c = conn.cursor()
        c.execute("SELECT rule_id, src_ip FROM alerts WHERE id=?", (alert_id,))
        row = c.fetchone()
        rule_id = row[0] if row else None
        src_ip = row[1] if row else None
        conn.close()                      # closed BEFORE the helper call

        if action == "block" and src_ip:
            try:
                ufw_deny_append(src_ip, _actor(), _fw_session_id(), _fw_credential())
            except FirewallError as exc:
                return _fw_error_response(exc)

        conn = _dm_conn()
        c = conn.cursor()
        c.execute("UPDATE alerts SET action=? WHERE id=?", (action, alert_id))
        conn.commit()
        conn.close()
        _audit(action=action, rule_id=rule_id, ip=src_ip)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500




@app.route("/api/modules")
def api_modules():
    """List all discovered modules with their enabled state and runtime status."""
    manifests = modules_loader.get_all_manifests()
    result = []
    for name, m in manifests.items():
        result.append({
            "name": name,
            "display_name": m.get("display_name", name),
            "description": m.get("description", ""),
            "category": m.get("category", ""),
            "enabled": modules_loader.is_enabled(name),
            "status": modules_loader.module_status(name),
            "confirmation_required": m.get("confirmation_required", False),
            "confirmation_message": m.get("confirmation_message", ""),
        })
    return jsonify({"modules": result})


@app.route("/api/modules/<name>/enable", methods=["POST"])
def api_module_enable(name):
    try:
        modules_loader.set_enabled(name, True, actor=_actor())
        return jsonify({"success": True, "status": modules_loader.module_status(name)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/modules/<name>/disable", methods=["POST"])
def api_module_disable(name):
    try:
        modules_loader.set_enabled(name, False, actor=_actor())
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/hw/history")
def api_hw_history():
    """GET /api/hw/history?sensor=<key>&range=1h|6h|24h|7d|30d

    Returns time-series data for one sensor plus any anomaly snapshots in range.
    Sensor keys: cpu_temp, gpu_temp, ambient_temp, nvme_temp, cpu_percent,
                 ram_used_gb, gpu_fan_percent, gpu_power_watts,
                 fan/<unique_key>
    """
    sensor = request.args.get("sensor", "cpu_temp")
    rng = request.args.get("range", "24h")
    range_map = {"1h": "-1 hours", "6h": "-6 hours", "24h": "-24 hours",
                 "7d": "-7 days", "30d": "-30 days"}
    since = range_map.get(rng, "-24 hours")

    # Determine whether it's a scalar column or a fan from fans_json
    fan_key = None
    if sensor.startswith("fan/"):
        fan_key = sensor[4:]
        col = None
    else:
        valid_cols = {"cpu_temp", "ambient_temp", "nvme_temp", "gpu_temp",
                      "cpu_percent", "ram_used_gb", "gpu_fan_percent", "gpu_power_watts",
                      "disk_pct_used"}
        col = sensor if sensor in valid_cols else "cpu_temp"

    try:
        conn = _dm_conn()   # §9 batch 1 (api_hw_history)  # hw_monitor.DB_PATH == DB_PATH (both /var/lib/nemesis/alerts.db)
        if fan_key:
            rows = conn.execute(
                f"SELECT timestamp, fans_json, is_anomalous FROM hw_metrics "
                f"WHERE timestamp >= datetime('now',?) ORDER BY timestamp",
                (since,),
            ).fetchall()
            samples = []
            for ts, fans_json, is_anom in rows:
                fans = json.loads(fans_json) if fans_json else []
                rpm = next((f.get("rpm") for f in fans if f.get("unique_key") == fan_key), None)
                if rpm is None:
                    # fallback: match by label
                    rpm = next((f.get("rpm") for f in fans if f.get("label") == fan_key), None)
                samples.append({"timestamp": ts, "value": rpm, "is_anomalous": bool(is_anom)})
        else:
            rows = conn.execute(
                f"SELECT timestamp, {col}, is_anomalous FROM hw_metrics "
                f"WHERE timestamp >= datetime('now',?) ORDER BY timestamp",
                (since,),
            ).fetchall()
            samples = [{"timestamp": r[0], "value": r[1], "is_anomalous": bool(r[2])} for r in rows]
        conn.close()

        # Anomaly snapshots in range
        cutoff_iso = (datetime.now() -
                      __import__("datetime").timedelta(
                          hours={"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}.get(rng, 24)
                      )).isoformat(timespec="seconds")
        snapshots = hw_monitor.get_anomaly_snapshots(
            sensor_key=(None if fan_key else sensor),
            since_ts=cutoff_iso,
            limit=100,
        )
        # Strip top_processes from list view (too large); keep for detail popup
        for snap in snapshots:
            snap.pop("top_processes", None)

        # Throttle warning: any throttle_detected=1 snapshot in range
        throttle_snaps = [s for s in
                          hw_monitor.get_anomaly_snapshots(sensor_key=None, since_ts=cutoff_iso, limit=200)
                          if s.get("throttle_detected")]
        throttle_warning = None
        if throttle_snaps:
            freqs = [s["throttle_freq_mhz"] for s in throttle_snaps if s.get("throttle_freq_mhz")]
            min_freq = min(freqs) if freqs else None
            throttle_warning = {
                "detected": True,
                "min_freq_mhz": min_freq,
                "event_count": len(throttle_snaps),
            }

        return jsonify({
            "sensor": sensor,
            "range": rng,
            "samples": samples,
            "anomaly_snapshots": snapshots,
            "anomaly_count": sum(1 for s in samples if s.get("is_anomalous")),
            "throttle_warning": throttle_warning,
        })
    except Exception as e:
        log.exception("api_hw_history error: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/hw/reset-baseline", methods=["POST"])
def api_hw_reset_baseline():
    sensor = request.args.get("sensor", "all")
    try:
        hw_monitor.reset_baseline(sensor if sensor != "all" else None)
        return jsonify({"ok": True, "sensor": sensor})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/hw/rediscover", methods=["POST"])
def api_hw_rediscover():
    """Run hw_discover.py non-interactively to rebuild hw_map.json.

    hw_discover.py is interactive; this endpoint runs it with --auto flag
    (which we add to hw_discover.py) or falls back to hw_monitor auto-discovery
    by deleting hw_map.json so the daemon picks up sensors fresh next cycle.
    """
    import subprocess as _sp
    discover_path = os.path.join(os.path.dirname(hw_monitor.DB_PATH), "hw_discover.py")
    try:
        if os.path.exists(discover_path):
            result = _sp.run(
                [sys.executable, discover_path, "--auto"],
                capture_output=True, text=True, timeout=30,
                cwd=os.path.dirname(discover_path),
            )
            output = (result.stdout + result.stderr).strip()[:2000]
            ok = result.returncode == 0
        else:
            output = "hw_discover.py not found — hardware map will be rebuilt from auto-discovery on next hw_monitor cycle."
            ok = True
        # Reset the in-memory cache so hw_monitor re-reads hw_map.json
        hw_monitor._hw_map = None
        hw_monitor._hw_map_loaded = False
        hw_monitor._sensor_map_logged = False
        return jsonify({"ok": ok, "output": output})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/hw/notifications")
def api_hw_notifications():
    try:
        return jsonify({"notifications": hw_monitor.get_hw_notifications()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/hw/snapshots/<int:snap_id>")
def api_hw_snapshot_detail(snap_id):
    """Return a single hw_anomaly_snapshots row including top_processes."""
    try:
        conn = _dm_conn()   # §9 batch 1 (api_hw_snapshot_detail)  # hw_monitor.DB_PATH == DB_PATH (both /var/lib/nemesis/alerts.db)
        row = conn.execute(
            """SELECT id, sensor_key, reading_value, baseline_avg, deviation,
                      captured_at, top_processes, cpu_pct, ram_mb,
                      net_mb_in, net_mb_out, disk_mb_read, disk_mb_write,
                      throttle_detected, throttle_freq_mhz, sustained,
                      top_processes_ref
               FROM hw_anomaly_snapshots WHERE id=?""",
            (snap_id,),
        ).fetchone()
        conn.close()
        if not row:
            return jsonify({"error": "not found"}), 404
        cols = ("id", "sensor_key", "reading_value", "baseline_avg", "deviation",
                "captured_at", "top_processes", "cpu_pct", "ram_mb",
                "net_mb_in", "net_mb_out", "disk_mb_read", "disk_mb_write",
                "throttle_detected", "throttle_freq_mhz", "sustained",
                "top_processes_ref")
        return jsonify(dict(zip(cols, row)))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/restart", methods=["POST"])
def api_restart():
    """Restart this service via nemesis-fwd. Requires a fresh admin credential.

    The credential is read HERE, inside the request context, and passed into the
    worker thread. _fw_credential() reads the POST body, which does not exist
    once the request ends — reading it inside the thread would silently yield
    None and every restart would be refused.

    Still threaded with a short delay, for the original reason: this response has
    to reach the browser before the process it came from is stopped.
    """
    import fw_client
    actor, sid, cred = _actor(), _fw_session_id(), _fw_credential()

    def _do_restart():
        time.sleep(2)
        try:
            fw_client.restart_dashboard(actor, sid, cred)
        except Exception as exc:
            # Nothing can be returned to the caller by now — the response was
            # sent two seconds ago. Log it rather than fail silently.
            log.error("restart via helper failed: %s", exc)

    threading.Thread(target=_do_restart, daemon=True).start()
    return jsonify({"status": "restarting"})


# REMOVED 2026-07-31 — POST /api/uninstall (operator decision).
#
# It ran `sudo bash uninstall.sh --yes`: a web-reachable, root-privileged removal
# of the entire product. Deleted outright rather than routed through the
# privileged helper, because this is not a capability that should exist behind
# any gate, however narrow — the blast radius of a dashboard compromise included
# destroying the installation, and no allowlist makes that acceptable.
#
# Uninstall is CLI-only now: run the uninstall script from a terminal on the
# server. The Settings UI still has the modal, but its confirm button no longer
# calls an endpoint (see doUninstall() in the rendered JS).


def _backup_candidates():
    """Return list of (src_path, archive_name) tuples for backup."""
    files = [
        # ADR 0001 Stage 6: tickets data now lives in the shared alerts.db
        # (tickets/tickets_seq/tickets_settings), captured by the alerts.db entry above.
        # The old per-module tickets.db has been retired, so it is no longer a candidate.
        (DB_PATH, "alerts.db"),   # resolver-derived; follows the /var/lib/nemesis move
        (os.path.join(_HERE, "alert_manager", "hw_map.json"), "alert_manager/hw_map.json"),
        ("/etc/nemesis.env", "etc_nemesis.env"),
    ]
    anomaly_dir = os.path.join(_HERE, "modules", "anomaly_detection")
    if os.path.isdir(anomaly_dir):
        for fn in sorted(os.listdir(anomaly_dir)):
            fp = os.path.join(anomaly_dir, fn)
            if os.path.isfile(fp) and fn.endswith(".db"):
                files.append((fp, f"modules/anomaly_detection/{fn}"))
    return files


def _browse_roots():
    """Directory roots the filesystem browser may show.

    Was `[f"/home/{getpass.getuser()}", "/media", "/mnt"]`, which silently assumed
    the service runs as a human with a real home directory. That stopped being
    true on 2026-07-31: dashboard runs as `nemesis-dash`, a --no-create-home
    system account whose passwd home field (`/home/nemesis-dash`) does not exist.
    `expanduser("~")` still RESOLVES to it, so the old code would have offered an
    uncreatable path as its default and fallback rather than failing usefully.

    Removable media first — it is the correct destination for a backup anyway
    (Rule 6: independent storage). NEMESIS_BROWSE_ROOTS (colon-separated) lets an
    install add its own; the install user's home only appears if it is configured
    AND exists, so this degrades instead of breaking.

    Note for the hardening step: ProtectHome=yes makes /home appear empty to this
    service, so any /home root becomes unusable regardless of what is configured.
    """
    roots = ["/media", "/mnt"]
    extra = os.environ.get("NEMESIS_BROWSE_ROOTS", "").strip()
    if extra:
        roots = [r for r in extra.split(":") if r.strip()] + roots
    return [r for r in roots if os.path.isdir(r)] or ["/media"]


def _default_backup_dir():
    """Default backup destination when the caller does not supply one.

    NOT `~/nemesis-backup/` — see _browse_roots() for why `~` is meaningless for
    this service now. NEMESIS_BACKUP_DIR overrides.

    The default lives under the state dir because that is reliably writable by
    the nemesis-db group. It is deliberately NOT a Rule-6-compliant location: a
    backup on the same disk as the original dies with it, and one sitting beside
    the live DB is the exact restore-trap removed from /var/lib/nemesis earlier
    today. Operators should point this at removable media; the default only
    guarantees the feature works, not that the result is a durable backup.
    """
    return os.environ.get("NEMESIS_BACKUP_DIR", "/var/lib/nemesis/backups")


@app.route("/api/filesystem/browse")
def api_filesystem_browse():
    path_raw = request.args.get("path", "").strip()
    allowed_roots = _browse_roots()
    fallback = allowed_roots[0]

    path = os.path.realpath(os.path.expanduser(path_raw)) if path_raw else fallback
    if not any(path.startswith(r) for r in allowed_roots):
        path = fallback

    parent = os.path.dirname(path)
    if not any(parent.startswith(r) for r in allowed_roots):
        parent = path

    try:
        entries = [
            d for d in os.listdir(path)
            if os.path.isdir(os.path.join(path, d)) and not d.startswith(".")
        ]
        dirs = sorted(entries)
        return jsonify({"path": path, "parent": parent, "dirs": dirs, "error": None})
    except PermissionError:
        return jsonify({"path": path, "parent": parent, "dirs": [], "error": "Permission denied"})
    except Exception as e:
        return jsonify({"path": path, "parent": parent, "dirs": [], "error": str(e)})


def _read_nemesis_env() -> dict:
    """Read /etc/nemesis.env and return key→value dict (comments stripped)."""
    env = {}
    try:
        with open("/etc/nemesis.env") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip()
    except Exception:
        pass
    return env


def _update_nemesis_env(updates: dict) -> list:
    """Ask nemesis-fwd to merge these keys into /etc/nemesis.env.

    Returns the list of updated key names. Raises on failure.

    This process no longer touches the file. It used to build the new contents
    itself, stage them in /tmp and shell out to `sudo cp` — which stopped working
    entirely when dashboard was de-privileged (2026-07-31: no sudo, and
    NoNewPrivileges=yes means the kernel would ignore it even if it were
    restored). The merge, the key allowlist and the atomic write now all happen
    helper-side.

    Sending intent rather than content is the security property, not an
    implementation detail: /etc/nemesis.env is sourced by seven services via
    EnvironmentFile, so its keys become their process environment. This route
    previously accepted ARBITRARY keys and appended any it did not recognise.
    The helper's allowlist cannot be bypassed by a compromised dashboard; a
    check here could be.
    """
    import fw_client
    result = fw_client.write_env(
        {str(k): str(v) for k, v in updates.items()},
        _actor(), _fw_session_id(), _fw_credential(),
    )
    return list(result.get("updated") or [])


@app.route("/api/config/current")
def api_config_current():
    """Return current config values (secrets masked) and auto-detected network info."""
    env = _read_nemesis_env()

    def _masked(key):
        v = env.get(key, "")
        return "(set)" if v else "(not set)"

    def _val(key, default=""):
        return env.get(key, default)

    # Auto-detect network
    iface = ip_addr = subnet = ""
    try:
        r = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"],
            capture_output=True, text=True, timeout=3,
        )
        parts = r.stdout.split()
        for i, p in enumerate(parts):
            if p == "dev" and i + 1 < len(parts):
                iface = parts[i + 1]
            if p == "src" and i + 1 < len(parts):
                ip_addr = parts[i + 1]
    except Exception:
        pass
    if iface:
        try:
            r2 = subprocess.run(
                ["ip", "addr", "show", iface],
                capture_output=True, text=True, timeout=3,
            )
            import re as _re
            m = _re.search(r"inet (\S+)", r2.stdout)
            if m:
                subnet = m.group(1)
        except Exception:
            pass

    pihole_url = f"http://{PIHOLE_IP}/admin"

    return jsonify({
        "WATCHDOG_EMAIL":    _val("WATCHDOG_EMAIL"),
        "WATCHDOG_PASSWORD": _masked("WATCHDOG_PASSWORD"),
        "WATCHDOG_TO":       _val("WATCHDOG_TO"),
        "SMTP_HOST":         _val("SMTP_HOST", "smtp.gmail.com"),
        "SMTP_PORT":         _val("SMTP_PORT", "587"),
        "ANTHROPIC_API_KEY": _masked("ANTHROPIC_API_KEY"),
        "ABUSEIPDB_KEY":     _masked("ABUSEIPDB_KEY"),
        "IPINFO_TOKEN":      _masked("IPINFO_TOKEN"),
        "PIHOLE_PASSWORD":   _masked("PIHOLE_PASSWORD"),
        "network": {
            "interface": iface or env.get("NETWORK_IFACE", ""),
            "ip":        ip_addr,
            "subnet":    subnet,
        },
        "pihole_url": pihole_url,
    })


@app.route("/api/config/update", methods=["POST"])
def api_config_update():
    """Update specified keys in /etc/nemesis.env then restart services."""
    data = request.get_json(force=True, silent=True) or {}
    # The admin credential travels in the SAME body as the config values, so it
    # has to be excluded before they are treated as keys to write. Without this
    # it is forwarded to the helper as a config key named "password" and refused
    # ("invalid key name: 'password'") — which is the helper validating
    # correctly, and this route handing it a malformed payload.
    #
    # Filtered by NAME rather than by trusting the caller to send it separately:
    # the credential field is defined here, so the exclusion belongs here too.
    updates = {k: str(v) for k, v in data.items()
               if k not in _CREDENTIAL_FIELDS and v is not None and str(v).strip()}
    if not updates:
        return jsonify({"ok": False, "error": "No values provided"}), 400
    try:
        updated = _update_nemesis_env(updates)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    # Attribution seam (readiness Tier B): config edits previously left NO record.
    # Log only the KEY NAMES changed — never the values (they include secrets).
    _audit("config_update: " + ", ".join(sorted(updated)))

    # Same credential-capture rule as api_restart(): read in the request
    # context, use in the thread.
    import fw_client
    _actor_v, _sid_v, _cred_v = _actor(), _fw_session_id(), _fw_credential()

    def _restart():
        time.sleep(2)
        try:
            fw_client.restart_dashboard(_actor_v, _sid_v, _cred_v)
        except Exception as exc:
            log.error("post-config restart via helper failed: %s", exc)

    threading.Thread(target=_restart, daemon=True).start()
    return jsonify({"ok": True, "updated": updated})


@app.route("/api/config/test-email", methods=["POST"])
def api_config_test_email():
    """Send a test email using current SMTP settings."""
    sender   = os.environ.get("WATCHDOG_EMAIL", "")
    password = os.environ.get("WATCHDOG_PASSWORD", "")
    to_addr  = os.environ.get("WATCHDOG_TO", sender)
    host     = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    try:
        port = int(os.environ.get("SMTP_PORT", "587"))
    except ValueError:
        port = 587
    if not sender or not password:
        return jsonify({"ok": False, "error": "WATCHDOG_EMAIL / WATCHDOG_PASSWORD not configured"})
    ok = email_utils.send_email(
        subject="[Nemesis] Test email from Configuration Wizard",
        body=(
            "This is a test email sent from the Nemesis Firewall Configuration Wizard.\n\n"
            "If you received this, your email settings are working correctly.\n"
        ),
        to=to_addr or sender,
    )
    if ok:
        return jsonify({"ok": True})
    return jsonify({"ok": False,
                    "error": "Send failed — check SMTP settings and credentials"})


@app.route("/api/config/validate-key", methods=["POST"])
def api_config_validate_key():
    """Basic validation that a given API key appears functional."""
    data   = request.get_json(force=True, silent=True) or {}
    key_name = data.get("key_name", "")
    key_val  = data.get("key_value", os.environ.get(key_name, "")).strip()
    if not key_val:
        return jsonify({"ok": False, "error": "Key is not set"})

    if key_name == "ANTHROPIC_API_KEY":
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=key_val)
            client.models.list()
            return jsonify({"ok": True, "detail": "Key is valid"})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)[:120]})

    if key_name == "ABUSEIPDB_KEY":
        try:
            from urllib import request as _urlreq
            req = _urlreq.Request(
                "https://api.abuseipdb.com/api/v2/check?ipAddress=127.0.0.1",
                headers={"Key": key_val, "Accept": "application/json"},
            )
            with _urlreq.urlopen(req, timeout=8) as resp:
                body = json.loads(resp.read())
                if "data" in body:
                    return jsonify({"ok": True, "detail": "Key is valid"})
                return jsonify({"ok": False, "error": "Unexpected response"})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)[:120]})

    if key_name == "IPINFO_TOKEN":
        try:
            from urllib import request as _urlreq
            req = _urlreq.Request(
                f"https://ipinfo.io/8.8.8.8?token={key_val}",
                headers={"Accept": "application/json"},
            )
            with _urlreq.urlopen(req, timeout=8) as resp:
                body = json.loads(resp.read())
                if "ip" in body:
                    return jsonify({"ok": True, "detail": "Key is valid"})
                return jsonify({"ok": False, "error": "Unexpected response"})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)[:120]})

    if key_name == "PIHOLE_PASSWORD":
        try:
            r = requests.post(f"http://{PIHOLE_IP}/api/auth",
                              json={"password": key_val}, timeout=5)
            if r.json().get("session", {}).get("valid"):
                return jsonify({"ok": True, "detail": "Pi-hole connection successful"})
            return jsonify({"ok": False, "error": "Authentication failed — check password"})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)[:120]})

    return jsonify({"ok": False, "error": f"No validator for {key_name}"})


@app.route("/api/backup/size")
def api_backup_size():
    total = sum(
        os.path.getsize(src) for src, _ in _backup_candidates() if os.path.isfile(src)
    )
    # Last-known free space for the destination the operator is actually looking
    # at. `media` is null when that destination has never been backed up to —
    # the caller renders "never checked", never a zero.
    dest = (request.args.get("dest") or _default_backup_dir()).strip()
    return jsonify({
        "size_mb": round(total / (1024 * 1024), 2),
        "dest": os.path.expanduser(dest),
        "media": _read_backup_media_status(os.path.expanduser(dest)),
    })


def _record_backup_media_status(dest, actor=None):
    """Record free space at `dest`. Only meaningful while the medium is mounted.

    A FAILED reading is deliberately not written. Overwriting a real (if old)
    number with nulls would destroy the only figure the card has, and "we looked
    and could not tell" is not more informative than "here is what it was last
    time, and when". Returns (free, total) or None.
    """
    try:
        usage = shutil.disk_usage(dest)
    except OSError as e:
        app.logger.warning("backup media: cannot stat %s: %s", dest, e)
        return None
    try:
        conn = _dm_conn()
        conn.execute(
            "INSERT INTO backup_media_status(path, free_bytes, total_bytes, checked_at, actor) "
            "VALUES(?,?,?,?,?) "
            "ON CONFLICT(path) DO UPDATE SET free_bytes=excluded.free_bytes, "
            "total_bytes=excluded.total_bytes, checked_at=excluded.checked_at, "
            "actor=excluded.actor",
            (dest, usage.free, usage.total,
             datetime.now().isoformat(timespec="seconds"), actor),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        # Never fail a completed backup because the bookkeeping write failed.
        app.logger.warning("backup media: status write failed for %s: %s", dest, e)
    return (usage.free, usage.total)


def _read_backup_media_status(dest):
    """Last-known reading for `dest`, or None if it has never been checked.

    Returns None rather than zeros on an absent row or a failed read. Zero free
    bytes is a legal-looking value that reads as a full disk; the caller must be
    able to tell "never measured" apart from "measured, and it is full".
    """
    try:
        conn = _dm_conn()
        row = conn.execute(
            "SELECT free_bytes, total_bytes, checked_at FROM backup_media_status "
            "WHERE path=?", (dest,)
        ).fetchone()
        conn.close()
    except Exception as e:
        app.logger.warning("backup media: status read failed for %s: %s", dest, e)
        return None
    if not row:
        return None
    return {"free_bytes": row[0], "total_bytes": row[1], "checked_at": row[2]}


@app.route("/api/backup/create", methods=["POST"])
def api_backup_create():
    """Create a backup archive. Serialized — only one may run at a time.

    The lock is not defensive tidiness. This route is reachable from the UI
    button AND from the cron line api_backup_schedule writes, which POSTs to
    this same endpoint; Flask is threaded, so both can execute at once. The
    archive name has one-second granularity and `tarfile.open(..., "w:gz")`
    truncates, so two runs landing in the same second silently overwrote one
    another's archive — and BOTH returned {"status": "ok"}. A backup you were
    told succeeded, which no longer exists, is worse than a backup that failed.

    job_lock rather than a transaction: the work here is filesystem I/O, which
    no database transaction can roll back.
    """
    data = request.get_json(force=True, silent=True) or {}
    dest_raw = (data.get("dest_path") or _default_backup_dir()).strip()
    dest = os.path.expanduser(dest_raw)
    try:
        with _dm().job_lock("backup_create"):
            return _api_backup_create_locked(dest)
    except data_manager.JobLockBusy:
        return jsonify({
            "status": "error",
            "error": "A backup is already running. Wait for it to finish and try again.",
        })


def _api_backup_create_locked(dest):
    """Body of api_backup_create, called with the backup_create job lock held."""
    try:
        os.makedirs(dest, exist_ok=True)
    except OSError as e:
        return jsonify({"status": "error", "error": f"Cannot create directory: {e}"})

    # Destination free-space pre-check. Without it, a full destination surfaces
    # only as a generic exception AFTER a partial archive has been written.
    #
    # `need` is the UNCOMPRESSED total, so this deliberately over-estimates — the
    # gzip archive is typically a fraction of it. Refusing a backup that might
    # just have fit is the safe direction to be wrong in: the alternative is
    # failing mid-write and leaving a truncated archive that looks like a backup.
    # The message states the requirement so the operator can act on it.
    need = sum(os.path.getsize(src) for src, _ in _backup_candidates()
               if os.path.isfile(src))
    try:
        avail = shutil.disk_usage(dest).free
    except OSError:
        avail = None   # cannot tell — proceed and let the write surface the truth
    if avail is not None and avail < need:
        return jsonify({
            "status": "error",
            "error": (f"Not enough free space at destination: needs up to "
                      f"{need // (1024 * 1024)} MB uncompressed, "
                      f"{avail // (1024 * 1024)} MB free."),
        })

    ts = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    archive_path = os.path.join(dest, f"nemesis-backup-{ts}.tar.gz")

    try:
        with tarfile.open(archive_path, "w:gz") as tar:
            for src, arcname in _backup_candidates():
                if os.path.isfile(src):
                    tar.add(src, arcname=arcname)
        os.chmod(archive_path, 0o600)
        size_mb = os.path.getsize(archive_path) / (1024 * 1024)
        # The medium is provably mounted right now — this is the ONLY moment a
        # reading can be taken (ADR 0018 keeps it unmounted otherwise). Taken
        # AFTER the write so the recorded figure reflects the space remaining
        # once this archive is on disk.
        _record_backup_media_status(dest)
        return jsonify({"status": "ok", "path": archive_path, "size_mb": round(size_mb, 2)})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})


@app.route("/api/backup/schedule", methods=["GET", "POST"])
def api_backup_schedule():
    default_cfg = {"enabled": False, "schedule": "daily", "destination": _default_backup_dir()}

    if request.method == "GET":
        try:
            with open(_BACKUP_CFG_PATH) as f:
                return jsonify(json.load(f))
        except (FileNotFoundError, json.JSONDecodeError):
            return jsonify(default_cfg)

    data = request.get_json(force=True, silent=True) or {}
    enabled = bool(data.get("enabled", False))
    schedule = data.get("schedule", "daily")
    destination = (data.get("destination") or _default_backup_dir()).strip()
    cfg = {"enabled": enabled, "schedule": schedule, "destination": destination}

    try:
        with open(_BACKUP_CFG_PATH, "w") as f:
            json.dump(cfg, f)
    except OSError as e:
        return jsonify({"status": "error", "error": f"Cannot save config: {e}"})

    cron_marker = "# nemesis-backup-scheduled"
    cron_exprs = {"daily": "0 3 * * *", "weekly": "0 3 * * 0", "monthly": "0 3 1 * *"}

    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        existing = r.stdout if r.returncode == 0 else ""
        lines = [ln for ln in existing.splitlines() if cron_marker not in ln]
        if enabled:
            dest_exp = os.path.expanduser(destination)
            # The destination is operator-supplied and ends up inside a line that
            # CRON later executes via /bin/sh -c. Writing the crontab is not
            # itself a shell call, so the danger is deferred, not absent: an
            # unescaped quote closed the JSON argument and everything after it
            # ran as this service account, on a schedule, indefinitely.
            #
            # Two separate escapes are needed, and quoting alone is not enough:
            #
            #   quotes/metacharacters  handled by shlex.quote() below, which is
            #                          what makes the value a single inert word.
            #   NEWLINES               shlex.quote() would happily return a
            #                          quoted string containing a newline — and
            #                          crontab treats a newline as the end of the
            #                          entry, so the remainder becomes a NEW cron
            #                          line. No amount of quoting fixes that,
            #                          because the injection is into the crontab
            #                          format rather than into the shell.
            #
            # Hence: reject structurally invalid input first, then quote.
            if any(ch in dest_exp for ch in "\n\r"):
                return jsonify({"status": "error",
                                "error": "Destination must not contain line breaks."})
            if not os.path.isabs(dest_exp):
                return jsonify({"status": "error",
                                "error": "Destination must be an absolute path."})
            expr = cron_exprs.get(schedule, "0 3 * * *")
            # json.dumps builds the payload so the path is escaped as JSON, and
            # shlex.quote makes the whole argument a single shell word.
            payload = shlex.quote(json.dumps({"dest_path": dest_exp}))
            lines.append(
                f'{expr} curl -sf -X POST http://localhost:5000/api/backup/create'
                f' -H "Content-Type: application/json"'
                f' -d {payload}'
                f' >> /tmp/nemesis-backup.log 2>&1 {cron_marker}'
            )
        new_crontab = "\n".join(lines) + ("\n" if lines else "")
        subprocess.run(["crontab", "-"], input=new_crontab, text=True, check=True)
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "error", "error": f"Failed to update crontab: {e}"})


@app.route("/api/dashboard/uptime")
def api_dashboard_uptime():
    try:
        r = subprocess.run(
            ["systemctl", "show", "dashboard", "--property=ActiveEnterTimestamp"],
            capture_output=True, text=True, timeout=5,
        )
        raw = r.stdout.strip()
        # raw is like: ActiveEnterTimestamp=Mon 2026-06-22 13:21:05 CDT
        ts_str = raw.split("=", 1)[-1].strip()
        # Parse: strip weekday prefix then parse
        parts = ts_str.split(" ", 1)
        ts_str_clean = parts[1] if len(parts) == 2 else ts_str
        # Format: "2026-06-22 13:21:05 CDT" — strip timezone for strptime
        ts_no_tz = " ".join(ts_str_clean.split()[:2])
        started_dt = datetime.strptime(ts_no_tz, "%Y-%m-%d %H:%M:%S")
        started_at = started_dt.strftime("%Y-%m-%d %H:%M:%S")
        delta = datetime.now() - started_dt
        total_s = int(delta.total_seconds())
        h, remainder = divmod(total_s, 3600)
        m = remainder // 60
        uptime = f"{h}h {m}m" if h else f"{m}m"
        return jsonify({"started_at": started_at, "uptime": uptime})
    except Exception as e:
        log.exception("api_dashboard_uptime failed: %s", e)
        return jsonify({"started_at": "unknown", "uptime": "unknown"})


# ══════════════════════════════════════════════════════════════════════════════
# Nemesis Agent API — device hardware, scan, notify, rules
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/hw/devices")
def api_hw_devices():
    """Return devices seen in hw_metrics last 24h, joined with agent_devices info."""
    try:
        hw_devs  = {d["device_id"]: d for d in hw_monitor.get_hw_devices()}
        ag_devs  = {d["device_id"]: d for d in hw_monitor.get_agent_devices()}
        all_ids  = set(hw_devs) | set(ag_devs)
        result   = []
        for did in all_ids:
            hw = hw_devs.get(did, {})
            ag = ag_devs.get(did, {})
            # Friendly name: prefer devices table lookup by device_id, then agent name
            friendly = ag.get("device_name") or did
            try:
                conn = _dm_conn()   # §9 batch 1 (api_hw_devices)
                row = conn.execute(
                    "SELECT friendly_name FROM devices WHERE mac=?", (did,)
                ).fetchone()
                conn.close()
                if row and row[0]:
                    friendly = row[0]
            except Exception:
                pass
            result.append({
                "device_id":       did,
                "friendly_name":   friendly,
                "device_type":     ag.get("device_type", "unknown"),
                "ip_address":      ag.get("ip_address", ""),
                "connection_type": ag.get("connection_type", "local" if did == "local" else ""),
                "agent_last_seen": ag.get("agent_last_seen") or hw.get("last_seen", ""),
                "suricata_running": bool(ag.get("suricata_running")),
                "suricata_profile": ag.get("suricata_profile", ""),
                "last_scan_at":    ag.get("last_scan_at", ""),
                "last_scan_result": ag.get("last_scan_result", "never"),
                "cpu_temp":        hw.get("cpu_temp"),
                "gpu_temp":        hw.get("gpu_temp"),
                "cpu_percent":     hw.get("cpu_percent"),
                "ram_used_gb":     hw.get("ram_used_gb"),
                "hw_last_seen":    hw.get("last_seen", ""),
            })
        return jsonify({"devices": result})
    except Exception as e:
        log.exception("api_hw_devices failed: %s", e)
        return jsonify({"devices": [], "error": str(e)})


@app.route("/api/hw/metrics-for-device")
def api_hw_metrics_for_device():
    """GET /api/hw/metrics-for-device?device_id=<id>"""
    device_id = request.args.get("device_id", "local")
    try:
        samples = hw_monitor.get_recent_samples_for_device(device_id, 288)
        return jsonify({"device_id": device_id, "samples": samples})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _hw_health_from_temp(cpu_t):
    if cpu_t is None:
        return "unknown"
    if cpu_t > 90:
        return "critical"
    if cpu_t > 75:
        return "warning"
    return "ok"


def _agent_status_from_seen(agent_seen, now_ts):
    if not agent_seen:
        return "no_agent"
    try:
        seen_dt = datetime.fromisoformat(agent_seen)
        if (now_ts - seen_dt).total_seconds() / 60 <= 10:
            return "online"
    except Exception:
        pass
    return "offline"


@app.route("/api/scan/devices")
def api_scan_devices():
    """All devices with agent status, last scan, hardware health, connection type.

    The Nemesis host (device_id='local') is always returned first as a first-class
    device regardless of agent deployment.
    """
    try:
        hw_devs      = {d["device_id"]: d for d in hw_monitor.get_hw_devices()}
        ag_devs      = {d["device_id"]: d for d in hw_monitor.get_agent_devices()}
        net_devs     = get_network_devices()
        pending_map  = hw_monitor.get_pending_count_per_device()
        now_ts       = datetime.now()

        conn = _dm_conn()   # §9 batch 1 (api_scan_devices)

        def _last_scan(did):
            row = conn.execute(
                "SELECT status, completed_at, threats_found FROM scan_jobs "
                "WHERE device_id=? ORDER BY started_at DESC LIMIT 1", (did,)
            ).fetchone()
            if row:
                return row[0], row[1], row[2] or 0
            return "never", "", 0

        # ── Nemesis host: always first, special agent_status ──────────────────
        local_hw  = hw_devs.get("local", {})
        local_cpu = local_hw.get("cpu_temp")
        local_scan_status, local_scan_at, local_scan_threats = _last_scan("local")
        local_entry = {
            "device_id":        "local",
            "friendly_name":    socket.gethostname(),
            "device_type":      "linux",
            "ip_address":       "",
            "connection_type":  "local",
            "agent_status":     "nemesis_host",
            "agent_last_seen":  local_hw.get("last_seen", ""),
            "suricata_running": False,
            "suricata_profile": "",
            "last_scan_at":     local_scan_at,
            "last_scan_status": local_scan_status,
            "last_scan_threats": local_scan_threats,
            "hw_health":        _hw_health_from_temp(local_cpu),
            "cpu_temp":         local_cpu,
            "clamav_available": bool(shutil.which("clamscan")),
            "pending_scans":    pending_map.get("local", 0),
        }

        # ── Remote / network devices ──────────────────────────────────────────
        all_ids = (set(hw_devs) | set(ag_devs)) - {"local"}
        for nd in net_devs:
            nid = nd.get("mac", nd.get("ip", ""))
            if nid:
                all_ids.add(nid)

        remote = []
        for did in all_ids:
            hw = hw_devs.get(did, {})
            ag = ag_devs.get(did, {})

            friendly = ag.get("device_name") or did
            try:
                row = conn.execute(
                    "SELECT friendly_name FROM devices WHERE mac=?", (did,)
                ).fetchone()
                if row and row[0]:
                    friendly = row[0]
            except Exception:
                pass

            scan_status, scan_at, scan_threats = _last_scan(did)
            if scan_status == "never":
                scan_status = ag.get("last_scan_result", "never")
                scan_at     = ag.get("last_scan_at", "")

            agent_seen   = ag.get("agent_last_seen") or hw.get("last_seen", "")
            agent_status = _agent_status_from_seen(agent_seen, now_ts)
            cpu_t        = hw.get("cpu_temp")

            remote.append({
                "device_id":        did,
                "friendly_name":    friendly,
                "device_type":      ag.get("device_type", "unknown"),
                "ip_address":       ag.get("ip_address", ""),
                "connection_type":  ag.get("connection_type", ""),
                "agent_status":     agent_status,
                "agent_last_seen":  agent_seen,
                "suricata_running": bool(ag.get("suricata_running")),
                "suricata_profile": ag.get("suricata_profile", ""),
                "last_scan_at":     scan_at,
                "last_scan_status": scan_status,
                "last_scan_threats": scan_threats,
                "hw_health":        _hw_health_from_temp(cpu_t),
                "cpu_temp":         cpu_t,
                "clamav_available": False,
                "pending_scans":    pending_map.get(did, 0),
            })

        conn.close()
        return jsonify({"devices": [local_entry] + remote})
    except Exception as e:
        log.exception("api_scan_devices failed: %s", e)
        return jsonify({"devices": [], "error": str(e)})


def _run_local_clamscan(scan_id, path):
    """Background thread: run clamscan on the Nemesis host and stream progress to scan_jobs."""
    log_file = f"/tmp/nemesis-scan-{scan_id}.log"
    try:
        if not shutil.which("clamscan"):
            raise RuntimeError("clamscan not found on PATH")

        proc = subprocess.Popen(
            ["clamscan", "-r", path, "--no-summary", f"--log={log_file}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        log.info("local clamscan started: scan_id=%s pid=%d path=%s", scan_id, proc.pid, path)

        while proc.poll() is None:
            time.sleep(3)
            _update_local_scan_progress(scan_id, log_file, "running")

        _update_local_scan_progress(scan_id, log_file, "running")  # final read before status flip

        # Parse threats from completed log
        threats = []
        try:
            with open(log_file) as f:
                for line in f:
                    if "FOUND" in line:
                        line = line.strip()
                        # Format: "/path/to/file: ThreatName FOUND"
                        if ": " in line:
                            file_path, rest = line.split(": ", 1)
                            threat_name = rest.replace(" FOUND", "").strip()
                        else:
                            file_path, threat_name = line, "Unknown"
                        threats.append((file_path, threat_name))
        except Exception as e:
            log.warning("local scan log parse error: %s", e)

        final_status = "threats_found" if threats else "clean"

        conn = _dm_conn()   # §9 batch 3 (_run_local_clamscan) — INSERT scan_threats / UPDATE scan_jobs (granted)
        row = conn.execute("SELECT id, files_scanned FROM scan_jobs WHERE scan_id=?", (scan_id,)).fetchone()
        job_id      = row[0] if row else None
        files_count = row[1] if row else 0
        for file_path, threat_name in threats:
            conn.execute(
                # detected_at supplied explicitly (ADR 0004 step 2). It used to
                # come from DEFAULT CURRENT_TIMESTAMP, which is UTC; that default
                # is gone, so omitting the column would now write NULL.
                "INSERT INTO scan_threats (scan_job_id, device_id, file_path, threat_name, "
                "action_taken, detected_at) "
                "VALUES (?, 'local', ?, ?, 'detected', ?)",
                (job_id, file_path, threat_name,
                 datetime.now().isoformat(timespec="seconds")),
            )
        conn.execute(
            "UPDATE scan_jobs SET status=?, threats_found=?, progress_pct=100, completed_at=? "
            "WHERE scan_id=?",
            (final_status, len(threats), datetime.now().isoformat(), scan_id),
        )
        conn.commit()
        conn.close()
        log.info("local clamscan done: scan_id=%s status=%s threats=%d files=%d",
                 scan_id, final_status, len(threats), files_count)

    except Exception as e:
        log.exception("local clamscan failed (scan_id=%s): %s", scan_id, e)
        try:
            conn = _dm_conn()   # §9 batch 3 (_run_local_clamscan) — UPDATE scan_jobs (granted)
            conn.execute(
                "UPDATE scan_jobs SET status='error', completed_at=? WHERE scan_id=?",
                (datetime.now().isoformat(), scan_id),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass
    finally:
        try:
            os.unlink(log_file)
        except Exception:
            pass


def _update_local_scan_progress(scan_id, log_file, status):
    """Read log file and update scan_jobs progress counters."""
    try:
        files_scanned = 0
        threats_found = 0
        with open(log_file) as f:
            for line in f:
                if ": " in line:
                    files_scanned += 1
                if "FOUND" in line:
                    threats_found += 1
        conn = _dm_conn()   # §9 batch 3 (_update_local_scan_progress) — UPDATE scan_jobs (granted)
        conn.execute(
            "UPDATE scan_jobs SET status=?, files_scanned=?, threats_found=? WHERE scan_id=?",
            (status, files_scanned, threats_found, scan_id),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


@app.route("/api/scan/trigger", methods=["POST"])
def api_scan_trigger():
    """POST {device_id, path} → triggers scan. Local device runs ClamAV directly; remote via agent."""
    data      = request.get_json(force=True) or {}
    device_id = data.get("device_id", "")
    path      = data.get("path", "/")
    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    scan_id = str(_uuid_mod.uuid4())
    try:
        conn = _dm_conn()   # §9 api_scan_trigger — INSERT scan_jobs (granted)
        conn.execute(
            "INSERT INTO scan_jobs (device_id, scan_id, path, status, started_at) "
            "VALUES (?, ?, ?, 'running', ?)",
            (device_id, scan_id, path, datetime.now().isoformat()),
        )
        conn.commit()
        conn.close()

        if device_id == "local":
            # Run ClamAV directly on the Nemesis host
            if not shutil.which("clamscan"):
                conn = _dm_conn()   # §9 api_scan_trigger — UPDATE scan_jobs status=error (granted)
                conn.execute("UPDATE scan_jobs SET status='error' WHERE scan_id=?", (scan_id,))
                conn.commit()
                conn.close()
                return jsonify({"error": "clamscan not found — install clamav"}), 500
            t = threading.Thread(target=_run_local_clamscan, args=(scan_id, path),
                                 daemon=True, name=f"clamscan-{scan_id[:8]}")
            t.start()
        else:
            # Queue the scan as a task (ADR 0004 Stage 1) rather than pushing it.
            #
            # This replaced a direct POST to `http://{agent_ip}:5002`. The agent's
            # command listener binds 127.0.0.1 (agent.py `_start_command_listener`),
            # so that push could only ever connect for a device whose recorded
            # address was loopback — the Nemesis box itself. Every remote device
            # failed to connect and fell through to the offline branch, which means
            # the "reachable" path was dead code everywhere it mattered.
            #
            # The action is unchanged: tasks ride the heartbeat response and execute
            # through the same `_CommandHandler._dispatch` the push targeted. Only
            # the transport is retired.
            #
            # The eager scan_jobs row is now KEPT rather than deleted. Under the push
            # it was deleted because an unreachable agent meant the scan would never
            # run; a queued task does run, at the next check-in, and the agent reports
            # against this scan_id.
            task_id = hw_monitor.enqueue_task(
                device_id, "scan", {"path": path, "scan_id": scan_id})
            return jsonify({
                "ok": True, "scan_id": scan_id, "queued": True, "task_id": task_id,
                "message": "Scan queued — runs at the device's next check-in",
            })

        return jsonify({"ok": True, "scan_id": scan_id, "queued": False})
    except Exception as e:
        log.exception("api_scan_trigger failed: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/status")
def api_scan_status():
    """GET /api/scan/status?scan_id=<id>"""
    scan_id = request.args.get("scan_id", "")
    if not scan_id:
        return jsonify({"error": "scan_id required"}), 400
    try:
        conn = _dm_conn()   # §9 batch 1 (api_scan_status)
        row = conn.execute(
            "SELECT device_id, path, status, progress_pct, files_scanned, threats_found, "
            "started_at, completed_at FROM scan_jobs WHERE scan_id=?", (scan_id,)
        ).fetchone()
        conn.close()
        if not row:
            return jsonify({"error": "not found"}), 404
        return jsonify(dict(zip(
            ["device_id", "path", "status", "progress_pct", "files_scanned",
             "threats_found", "started_at", "completed_at"], row
        )))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/results")
def api_scan_results():
    """GET /api/scan/results?device_id=<id>"""
    device_id = request.args.get("device_id", "")
    try:
        conn = _dm_conn()   # §9 batch 1 (api_scan_results)
        if device_id:
            rows = conn.execute(
                "SELECT t.file_path, t.threat_name, t.action_taken, t.detected_at, "
                "j.scan_id, j.started_at "
                "FROM scan_threats t JOIN scan_jobs j ON t.scan_job_id=j.id "
                "WHERE t.device_id=? ORDER BY t.detected_at DESC LIMIT 100", (device_id,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT t.file_path, t.threat_name, t.action_taken, t.detected_at, "
                "j.scan_id, j.started_at "
                "FROM scan_threats t JOIN scan_jobs j ON t.scan_job_id=j.id "
                "ORDER BY t.detected_at DESC LIMIT 20"
            ).fetchall()
        conn.close()
        return jsonify({"threats": [
            dict(zip(["file_path", "threat_name", "action_taken", "detected_at",
                      "scan_id", "scan_started_at"], r)) for r in rows
        ]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/schedule", methods=["POST"])
def api_scan_schedule():
    """POST {device_id, schedule_type, scheduled_time} → save scan schedule."""
    data = request.get_json(force=True) or {}
    device_id     = data.get("device_id", "")
    schedule_type = data.get("schedule_type", "weekly")
    scheduled_time= data.get("scheduled_time", "")
    if not device_id:
        return jsonify({"error": "device_id required"}), 400
    try:
        conn = _dm_conn()   # §9 batch 3 (api_scan_schedule) — INSERT scan_schedules (granted)
        conn.execute(
            "INSERT INTO scan_schedules (device_id, schedule_type, scheduled_time) "
            "VALUES (?, ?, ?)", (device_id, schedule_type, scheduled_time)
        )
        conn.commit()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/history")
def api_scan_history():
    """GET all scan history, optionally filtered by device_id."""
    device_id = request.args.get("device_id", "")
    try:
        conn = _dm_conn()   # §9 batch 1 (api_scan_history)
        if device_id:
            rows = conn.execute(
                "SELECT scan_id, device_id, path, status, progress_pct, files_scanned, "
                "threats_found, started_at, completed_at FROM scan_jobs "
                "WHERE device_id=? ORDER BY started_at DESC LIMIT 50", (device_id,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT scan_id, device_id, path, status, progress_pct, files_scanned, "
                "threats_found, started_at, completed_at FROM scan_jobs "
                "ORDER BY started_at DESC LIMIT 50"
            ).fetchall()
        conn.close()
        cols = ["scan_id", "device_id", "path", "status", "progress_pct",
                "files_scanned", "threats_found", "started_at", "completed_at"]
        return jsonify({"history": [dict(zip(cols, r)) for r in rows]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/notify", methods=["POST"])
def api_agent_notify():
    """POST {device_id, title, message, severity, suggested_action} → push notification to agent."""
    data = request.get_json(force=True) or {}
    device_id = data.get("device_id", "")
    if not device_id:
        return jsonify({"error": "device_id required"}), 400
    try:
        # Existence, not address. This checked `ip_address` because the retired
        # push needed somewhere to POST; delivery no longer depends on the
        # device's address, but "unknown device" is still worth a 404 rather
        # than silently queuing a task nothing will ever claim.
        conn = _dm_conn()   # §9 batch 1 (api_agent_notify)
        row = conn.execute(
            "SELECT 1 FROM agent_devices WHERE device_id=?", (device_id,)
        ).fetchone()
        conn.close()
        if not row:
            return jsonify({"error": "unknown device"}), 404

        # Queued, not pushed — see api_scan_trigger for why the direct
        # `http://{agent_ip}:5002` POST could never reach a remote device.
        #
        # This route is now ASYNCHRONOUS, and says so. It previously returned the
        # agent's own reply (`agent_response`), which it can no longer know at
        # request time. Reporting a synthesized success would assert a delivery
        # that has not happened yet — the caller gets `task_id` instead and can
        # follow the real outcome through task result reporting.
        task_id = hw_monitor.enqueue_task(device_id, "notify", {
            "title":            data.get("title", "Nemesis"),
            "message":          data.get("message", ""),
            "severity":         data.get("severity", "info"),
            "suggested_action": data.get("suggested_action", ""),
        })
        return jsonify({
            "ok": True, "queued": True, "task_id": task_id,
            "message": "Notification queued — delivered at next check-in",
        })
    except Exception as e:
        log.exception("api_agent_notify failed: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/agent/rules")
def api_agent_rules():
    """GET /api/agent/rules?profile=office|roaming — serve Suricata rule file to agents."""
    # Resolution lives in alert_manager/rules_dist.py, shared with the code that
    # computes the digest bound into a signed update task. Two copies of the
    # search-path list would drift, and the resulting failure is silent: the
    # server would attest to one file's digest while serving another, and agents
    # would refuse every legitimate update with no visible cause.
    import rules_dist
    profile = request.args.get("profile", "office")
    try:
        _path, content = rules_dist.resolve_rules(profile)
    except rules_dist.RulesUnavailable as exc:
        if profile not in rules_dist.VALID_PROFILES:
            return jsonify({"error": "profile must be one of %s"
                                     % ", ".join(rules_dist.VALID_PROFILES)}), 400
        return jsonify({"error": str(exc)}), 404
    return Response(content, mimetype="text/plain",
                    headers={"Content-Disposition":
                             f"attachment; filename={profile}.rules"})


@app.route("/api/devices/update-friendly-name", methods=["POST"])
def api_update_friendly_name():
    """POST {device_id, friendly_name} → update friendly name for an agent device."""
    data = request.get_json(force=True) or {}
    device_id     = data.get("device_id", "")
    friendly_name = data.get("friendly_name", "")
    if not device_id or not friendly_name:
        return jsonify({"error": "device_id and friendly_name required"}), 400
    try:
        conn = _dm_conn()   # §9 batch 3 (api_update_friendly_name) — UPDATE agent_devices.device_name (COLUMN grant) + devices (granted)
        conn.execute(
            "UPDATE agent_devices SET device_name=? WHERE device_id=?",
            (friendly_name, device_id)
        )
        # Also update devices table if a matching MAC exists
        conn.execute(
            "UPDATE devices SET friendly_name=? WHERE mac=?",
            (friendly_name, device_id)
        )
        conn.commit()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Scan queue & conditions API ──────────────────────────────────────────────

@app.route("/api/scan/queue")
def api_scan_queue_get():
    """GET /api/scan/queue?status=pending|executing|completed — list queue entries."""
    status = request.args.get("status", "")
    items = hw_monitor.get_scan_queue(status=status or None)
    return jsonify({"queue": items})


@app.route("/api/scan/queue/cancel", methods=["POST"])
def api_scan_queue_cancel():
    """POST {queue_id} → cancel a pending queue entry."""
    data = request.get_json(force=True) or {}
    queue_id = data.get("queue_id")
    if not queue_id:
        return jsonify({"error": "queue_id required"}), 400
    ok = hw_monitor.cancel_queue_item(int(queue_id))
    return jsonify({"ok": ok})


@app.route("/api/scan/conditions")
def api_scan_conditions_get():
    """GET — list all scan conditions."""
    return jsonify({"conditions": hw_monitor.get_scan_conditions()})


@app.route("/api/scan/conditions", methods=["POST"])
def api_scan_conditions_post():
    """POST {condition_type, condition_value?, device_id?, enabled, scan_path} — add condition."""
    data = request.get_json(force=True) or {}
    ctype = data.get("condition_type", "")
    if not ctype:
        return jsonify({"error": "condition_type required"}), 400
    ok = hw_monitor.add_scan_condition(
        device_id       = data.get("device_id") or None,
        condition_type  = ctype,
        condition_value = data.get("condition_value") or None,
        enabled         = data.get("enabled", True),
        scan_path       = data.get("scan_path") or "/",
    )
    return jsonify({"ok": ok})


@app.route("/api/scan/conditions/<int:condition_id>", methods=["DELETE"])
def api_scan_conditions_delete(condition_id):
    """DELETE /api/scan/conditions/<id>"""
    ok = hw_monitor.delete_scan_condition(condition_id)
    return jsonify({"ok": ok})


# ── Scan page (/scan) ─────────────────────────────────────────────────────────

@app.route("/scan")
def scan_page():
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Nemesis — Device Security Scanner</title>
    <!-- First script on the page, deliberately: it wraps window.fetch, so any
         script loaded ahead of it could capture the unwrapped original. -->
    <script src="/static/nemesis-activity.js"></script>
    <script src="/static/tier.js"></script>
    <script src="/static/fw-credential.js"></script>
    <script src="/static/nemesis-idle-lock.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; background: #1a1a2e; color: #eee;
               padding: 24px; max-width: 1400px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; margin-bottom: 4px; }}
        h2 {{ color: #00d4ff; font-size: 1.05em; margin: 20px 0 10px 0;
             border-bottom: 1px solid #1e2d4e; padding-bottom: 6px; }}
        a.back {{ color: #00d4ff; text-decoration: none; font-size: 0.9em; }}
        .device-grid {{ display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 16px; margin: 16px 0; }}
        .device-card {{
            background: #0d1117; border: 1px solid #1e2d4e; border-radius: 8px;
            padding: 16px; position: relative; }}
        .device-card.nemesis-host-card {{ border-color: #00d4ff; background: #06101e; }}
        .device-card.agent-online {{ border-color: #00ff88; }}
        .device-card.hw-critical {{ border-color: #ff4444; }}
        .device-name {{ font-size: 1.1em; font-weight: bold; color: #fff;
            cursor: pointer; margin-bottom: 6px; }}
        .device-name:hover {{ color: #00d4ff; }}
        .badge {{ display: inline-block; padding: 2px 7px; border-radius: 10px;
            font-size: 0.72em; font-weight: bold; margin: 2px; }}
        .badge-green  {{ background: #003a1a; color: #00ff88; border: 1px solid #00ff88; }}
        .badge-yellow {{ background: #2a1f00; color: #ffaa00; border: 1px solid #ffaa00; }}
        .badge-grey   {{ background: #1a1a1a; color: #888;    border: 1px solid #444; }}
        .badge-blue   {{ background: #001a2a; color: #00d4ff; border: 1px solid #00d4ff; }}
        .badge-red    {{ background: #2a0000; color: #ff4444; border: 1px solid #ff4444; }}
        .device-meta {{ font-size: 0.8em; color: #888; margin: 4px 0 10px 0; }}
        .device-actions {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }}
        .btn {{ padding: 5px 12px; border-radius: 4px; border: none; cursor: pointer;
            font-size: 0.82em; font-weight: bold; }}
        .btn-blue   {{ background: #003a50; color: #00d4ff; border: 1px solid #00d4ff; }}
        .btn-green  {{ background: #003a1a; color: #00ff88; border: 1px solid #00ff88; }}
        .btn-orange {{ background: #2a1500; color: #ff8800; border: 1px solid #ff8800; }}
        .btn-grey   {{ background: #1a1a1a; color: #888;    border: 1px solid #444; opacity: 0.5; cursor: not-allowed; }}
        .btn:hover:not(:disabled) {{ opacity: 0.85; }}
        .panel {{ background: #0d1117; border: 1px solid #1e2d4e; border-radius: 8px;
            padding: 16px; margin-bottom: 16px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.85em; }}
        th {{ text-align: left; color: #888; padding: 6px; border-bottom: 1px solid #222; }}
        td {{ padding: 6px; border-bottom: 1px solid #1a1a2e; }}
        .alert-banner {{ background: #1a0000; border: 1px solid #ff4444;
            border-radius: 6px; padding: 12px 16px; margin-bottom: 16px; color: #ff8888; }}
        .modal-overlay {{ display:none; position:fixed; top:0; left:0; width:100%; height:100%;
            background:rgba(0,0,0,0.7); z-index:1000; }}
        .modal {{ background:#0d1117; border:1px solid #1e2d4e; border-radius:8px;
            padding:24px; max-width:480px; margin:10% auto; position:relative; }}
        .modal h3 {{ color:#00d4ff; margin-top:0; }}
        input, select, textarea {{ background:#1a1a2e; color:#eee; border:1px solid #333;
            padding:8px; border-radius:4px; width:100%; box-sizing:border-box; margin:6px 0; }}
        .progress-bar {{ height:8px; background:#1a1a2e; border-radius:4px; overflow:hidden; }}
        .progress-fill {{ height:100%; background:#00d4ff; transition:width 0.3s; }}
        .badge-purple {{ background:#1a0030; color:#cc88ff; border: 1px solid #cc88ff; }}
        .toast {{ position:fixed; bottom:24px; right:24px; background:#1e2d4e;
            border:1px solid #00d4ff; border-radius:8px; padding:14px 20px;
            color:#eee; font-size:0.9em; z-index:2000; opacity:0; transition:opacity 0.3s;
            max-width:360px; pointer-events:none; }}
        .toast.show {{ opacity:1; pointer-events:auto; }}
        .conditions-table {{ width:100%; border-collapse:collapse; font-size:0.83em; }}
        .conditions-table th {{ color:#888; padding:6px 8px; border-bottom:1px solid #222;
            text-align:left; }}
        .conditions-table td {{ padding:6px 8px; border-bottom:1px solid #111; }}
        details summary {{ cursor:pointer; color:#00d4ff; font-size:1em;
            padding:6px 0; user-select:none; list-style:none; }}
        details summary::before {{ content:'▶ '; }}
        details[open] summary::before {{ content:'▼ '; }}
    </style>
</head>
<body>
<h1>🔬 Device Security Scanner</h1>
<p><a class="back" href="/">← Back to Dashboard</a></p>

<div id="alertBanner" style="display:none" class="alert-banner"></div>

<div style="display:flex;align-items:center;gap:16px;margin-bottom:8px">
    <button class="btn btn-blue" onclick="scanAllDevices()">⚡ Scan All Online Devices</button>
    <span style="color:#888;font-size:0.85em">Last full scan: <span id="lastFullScan">—</span></span>
</div>

<h2>Device Overview</h2>
<div class="device-grid" id="deviceGrid">
    <div style="color:#888">Loading devices…</div>
</div>

<h2>Pending Scans <span id="pendingBadge" style="font-size:0.75em;color:#cc88ff;font-weight:normal"></span></h2>
<div class="panel" id="pendingScansPanel">
    <div style="color:#888;font-size:0.85em">No pending scans.</div>
</div>

<h2>Active Scans</h2>
<div class="panel" id="activeScansPanel">
    <div style="color:#888;font-size:0.85em">No active scans.</div>
</div>

<h2>Recent Findings</h2>
<div class="panel">
    <table id="findingsTable">
        <thead><tr><th>Device</th><th>File</th><th>Threat</th><th>Action</th><th>Time</th></tr></thead>
        <tbody id="findingsBody"><tr><td colspan="5" style="color:#888">No findings.</td></tr></tbody>
    </table>
</div>

<h2>Scheduled Scans</h2>
<div class="panel" id="schedulesPanel">
    <div style="color:#888;font-size:0.85em">No scheduled scans.</div>
</div>

<!-- Scan Conditions Section -->
<div class="panel" style="margin-top:24px">
    <details>
    <summary><strong>Scan Conditions</strong></summary>
    <p style="color:#888;font-size:0.82em;margin:8px 0">
        Conditions that automatically queue a scan when an agent payload is received.
        <span data-beginner="These are rules that tell Nemesis when to automatically run a security scan. For example, 'first_connect' means scan a device the very first time it checks in.">ℹ️</span>
        <span data-intermediate="Trigger logic runs on every nemesis_agent payload POST. Conditions fire only once per trigger event — duplicate pending scans are suppressed."></span>
        <span data-pro="Evaluated in _check_and_queue_scan_triggers() in hw_monitor.py. Known users/USB sets are persisted in agent_devices.known_users_json / known_usb_json columns."></span>
    </p>
    <table class="conditions-table" id="conditionsTable">
        <thead><tr>
            <th>Type</th><th>Value</th><th>Scope</th><th>Path</th><th>Enabled</th><th></th>
        </tr></thead>
        <tbody id="conditionsBody"><tr><td colspan="6" style="color:#888">Loading…</td></tr></tbody>
    </table>
    <div style="margin-top:10px">
        <button class="btn btn-blue" onclick="openAddConditionModal()">+ Add Condition</button>
    </div>
    </details>
</div>

<!-- Add Condition Modal -->
<div class="modal-overlay" id="conditionModal" onclick="if(event.target===this)closeConditionModal()">
<div class="modal">
    <h3>+ Add Scan Condition</h3>
    <label style="color:#aaa;font-size:0.85em">Condition Type</label>
    <select id="condType" onchange="condTypeChanged()">
        <option value="first_connect">first_connect — First time a device checks in</option>
        <option value="return_from_remote">return_from_remote — Device returns from VPN/remote</option>
        <option value="extended_absence">extended_absence — Device absent for N hours</option>
        <option value="new_login">new_login — Previously unseen user logs in</option>
        <option value="usb_inserted">usb_inserted — New USB device plugged in</option>
    </select>
    <div id="condValueRow" style="display:none">
        <label style="color:#aaa;font-size:0.85em" id="condValueLabel">Hours</label>
        <input type="text" id="condValue" placeholder="24">
    </div>
    <label style="color:#aaa;font-size:0.85em">Scan Path</label>
    <input type="text" id="condPath" value="/">
    <label style="color:#aaa;font-size:0.85em">Device Scope (blank = all devices)</label>
    <input type="text" id="condDevice" placeholder="device_id or leave blank">
    <div style="margin-top:16px;display:flex;gap:8px">
        <button class="btn btn-green" onclick="saveCondition()">Save</button>
        <button class="btn btn-grey" style="opacity:1;cursor:pointer" onclick="closeConditionModal()">Cancel</button>
    </div>
    <div id="condResult" style="margin-top:8px;font-size:0.85em"></div>
</div>
</div>

<!-- Toast notification -->
<div class="toast" id="toastEl"></div>

<!-- Send Alert Modal -->
<div class="modal-overlay" id="notifyModal" onclick="if(event.target===this)closeNotifyModal()">
<div class="modal">
    <h3>📢 Send Alert to Device</h3>
    <input type="hidden" id="notifyDeviceId">
    <label style="color:#aaa;font-size:0.85em">Message</label>
    <textarea id="notifyMessage" rows="3" placeholder="Alert message..."></textarea>
    <label style="color:#aaa;font-size:0.85em">Severity</label>
    <select id="notifySeverity" onchange="notifySeverityChanged()">
        <option value="info">ℹ️ Info</option>
        <option value="warning">⚠️ Warning</option>
        <option value="critical">🚨 Critical</option>
    </select>
    <label style="color:#aaa;font-size:0.85em">Suggested Action</label>
    <input type="text" id="notifySuggestedAction" placeholder="What the user should do...">
    <div style="margin-top:16px;display:flex;gap:8px">
        <button class="btn btn-blue" onclick="sendNotify()">Send</button>
        <button class="btn btn-grey" style="opacity:1;cursor:pointer" onclick="closeNotifyModal()">Cancel</button>
    </div>
    <div id="notifyResult" style="margin-top:8px;font-size:0.85em"></div>
</div>
</div>

<!-- Schedule Modal -->
<div class="modal-overlay" id="scheduleModal" onclick="if(event.target===this)closeScheduleModal()">
<div class="modal">
    <h3>📅 Schedule Scan</h3>
    <input type="hidden" id="scheduleDeviceId">
    <label style="color:#aaa;font-size:0.85em">Frequency</label>
    <select id="scheduleType">
        <option value="daily">Daily</option>
        <option value="weekly" selected>Weekly</option>
        <option value="on_reconnect">On Reconnect</option>
        <option value="on_demand">On Demand only</option>
    </select>
    <label style="color:#aaa;font-size:0.85em">Time (HH:MM)</label>
    <input type="text" id="scheduleTime" placeholder="02:00">
    <label style="color:#aaa;font-size:0.85em">Path to scan</label>
    <input type="text" id="schedulePath" value="/">
    <div style="margin-top:16px;display:flex;gap:8px">
        <button class="btn btn-green" onclick="saveSchedule()">Save</button>
        <button class="btn btn-grey" style="opacity:1;cursor:pointer" onclick="closeScheduleModal()">Cancel</button>
    </div>
    <div id="scheduleResult" style="margin-top:8px;font-size:0.85em"></div>
</div>
</div>

<script>
var _devices = [];
var _activeScans = {{}};
var _SEVERITY_ACTIONS = {{
    info:     "No action required.",
    warning:  "Please review the alert and take appropriate action.",
    critical: "Please save your work and contact your IT administrator immediately."
}};

function loadDevices() {{
    fetch('/api/scan/devices')
        .then(function(r){{return r.json();}})
        .then(function(d){{
            _devices = d.devices || [];
            renderDeviceGrid(_devices);
            checkAlertBanner(_devices);
        }})
        .catch(function(e){{console.error('loadDevices:', e);}});
}}

function renderDeviceGrid(devs) {{
    var grid = document.getElementById('deviceGrid');
    if (!devs.length) {{
        grid.innerHTML = '<div style="color:#888">No devices found. Install the Nemesis Agent on endpoint devices to enable scanning.</div>';
        return;
    }}
    grid.innerHTML = devs.map(function(d) {{
        var isLocal   = d.device_id === 'local';
        var agentBadge = agentStatusBadge(d.agent_status);
        var connBadge  = (!isLocal && d.connection_type) ? connTypeBadge(d.connection_type) : '';
        var idsBadge   = d.suricata_running
            ? '<span class="badge badge-blue">IDS: Active (' + (d.suricata_profile||'?') + ')</span>'
            : '';
        var hwBadge    = hwHealthBadge(d.hw_health);
        var scanBadge  = scanStatusBadge(d.last_scan_status, d.last_scan_at, d.last_scan_threats);
        var pendingBadge = (d.pending_scans > 0)
            ? '<span class="badge badge-purple">🕐 ' + d.pending_scans + ' pending</span>'
            : '';
        var canScan    = isLocal ? d.clamav_available
                                 : (d.agent_status === 'online' || d.agent_status === 'offline');
        var scanBtnTitle = isLocal
            ? (d.clamav_available ? '' : 'ClamAV not installed on this host')
            : (d.agent_status === 'offline' ? 'Agent offline — scan will be queued' : 'Install Nemesis Agent to enable scanning');
        var scanBtn = canScan
            ? '<button class="btn btn-green" onclick="triggerScan(\\'' + d.device_id + '\\')">🔬 Scan Now</button>'
            : '<button class="btn btn-grey" title="' + scanBtnTitle + '">🔬 Scan Now</button>';
        var alertBtn = isLocal
            ? ''  // no push notification needed for local machine
            : '<button class="btn btn-orange" onclick="openNotifyModal(\\'' + d.device_id + '\\')">📢 Alert</button>';
        var hwLink = isLocal
            ? '<a class="btn btn-blue" href="/hardware/all#local" target="_blank">🌡️ Hardware</a>'
            : (d.hw_health !== 'unknown'
                ? '<a class="btn btn-blue" href="/hardware/all#' + escHtml(d.device_id) + '" target="_blank">🌡️ HW</a>'
                : '');
        var cardClass = 'device-card' +
            (isLocal ? ' nemesis-host-card' : '') +
            (d.agent_status === 'online' ? ' agent-online' : '') +
            (d.hw_health === 'critical' ? ' hw-critical' : '');
        var nameEl = isLocal
            ? '<div class="device-name">' + escHtml(d.friendly_name) + '</div>'
            : '<div class="device-name" onclick="editFriendlyName(\\'' + d.device_id + '\\', this)">' + escHtml(d.friendly_name) + '</div>';
        return '<div class="' + cardClass + '">' +
            nameEl +
            '<div class="device-meta">' + escHtml(d.device_type || 'unknown') +
                (d.ip_address ? ' &nbsp;·&nbsp; ' + escHtml(d.ip_address) : '') + '</div>' +
            '<div>' + agentBadge + connBadge + idsBadge + hwBadge + pendingBadge + '</div>' +
            '<div style="margin-top:6px;font-size:0.8em;color:#aaa">' + scanBadge + '</div>' +
            '<div class="device-actions">' +
                scanBtn + alertBtn +
                '<button class="btn btn-grey" style="opacity:1;cursor:pointer" onclick="openScheduleModal(\\'' + d.device_id + '\\')">📅 Schedule</button>' +
                hwLink +
            '</div>' +
        '</div>';
    }}).join('');
}}

function agentStatusBadge(status) {{
    if (status === 'nemesis_host') return '<span class="badge badge-blue">🏠 Nemesis Host</span>';
    if (status === 'online')       return '<span class="badge badge-green">🟢 Agent Online</span>';
    if (status === 'offline')      return '<span class="badge badge-yellow">🟡 Agent Offline</span>';
    return '<span class="badge badge-grey">⚪ No Agent</span>';
}}
function connTypeBadge(conn) {{
    if (conn === 'local') return '<span class="badge badge-green">Local</span>';
    if (conn === 'vpn_remote') return '<span class="badge badge-blue">Remote (VPN)</span>';
    return '';
}}
function hwHealthBadge(health) {{
    if (health === 'ok')       return '<span class="badge badge-green">🟢 HW OK</span>';
    if (health === 'warning')  return '<span class="badge badge-yellow">🟡 HW Warning</span>';
    if (health === 'critical') return '<span class="badge badge-red">🔴 HW Critical</span>';
    return '';
}}
function scanStatusBadge(status, at, threats) {{
    if (!status || status === 'never') return 'Last scan: Never';
    var ts = at ? new Date(at).toLocaleString() : '';
    if (status === 'clean')          return 'Last scan: ✅ Clean (' + ts + ')';
    if (status === 'threats_found')  return 'Last scan: 🚨 ' + threats + ' threat(s) (' + ts + ')';
    if (status === 'in_progress')    return 'Scan in progress…';
    return 'Last scan: ' + status + (ts ? ' (' + ts + ')' : '');
}}

function checkAlertBanner(devs) {{
    var critical = devs.filter(function(d){{ return d.hw_health === 'critical'; }});
    var banner = document.getElementById('alertBanner');
    if (critical.length) {{
        banner.style.display = 'block';
        banner.innerHTML = '⚠️ ' + critical.length + ' device(s) require attention: ' +
            critical.map(function(d){{ return escHtml(d.friendly_name); }}).join(', ');
    }} else {{
        banner.style.display = 'none';
    }}
}}

function triggerScan(deviceId) {{
    fetch('/api/scan/trigger', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{device_id: deviceId, path: '/'}})
    }}).then(function(r){{return r.json();}}).then(function(d){{
        if (d.ok && d.queued) {{
            showToast('🕐 ' + (d.message || 'Scan queued for next reconnect'), 4000);
            loadPendingScans();
            loadDevices();
        }} else if (d.ok) {{
            _activeScans[d.scan_id] = {{device_id: deviceId, started: new Date()}};
            renderActiveScans();
        }} else {{
            alert('Scan trigger failed: ' + (d.error || 'unknown error'));
        }}
    }});
}}

function scanAllDevices() {{
    var scannable = _devices.filter(function(d){{
        return d.agent_status === 'online' ||
               (d.agent_status === 'nemesis_host' && d.clamav_available);
    }});
    if (!scannable.length) {{ alert('No scannable devices found.'); return; }}
    scannable.forEach(function(d){{ triggerScan(d.device_id); }});
}}

function renderActiveScans() {{
    var ids = Object.keys(_activeScans);
    var panel = document.getElementById('activeScansPanel');
    if (!ids.length) {{
        panel.innerHTML = '<div style="color:#888;font-size:0.85em">No active scans.</div>';
        return;
    }}
    panel.innerHTML = ids.map(function(sid) {{
        var j = _activeScans[sid];
        var pct = j.progress_pct || 0;
        return '<div style="margin-bottom:12px">' +
            '<div style="font-size:0.85em;margin-bottom:4px">' +
                escHtml(deviceName(j.device_id)) + ' — ' + (j.status || 'running') +
                (j.files_scanned ? ' (' + j.files_scanned + ' files)' : '') +
            '</div>' +
            '<div class="progress-bar"><div class="progress-fill" style="width:' + pct + '%"></div></div>' +
        '</div>';
    }}).join('');
}}

function deviceName(id) {{
    var d = _devices.find(function(x){{ return x.device_id === id; }});
    return d ? d.friendly_name : id;
}}

function pollActiveScans() {{
    var ids = Object.keys(_activeScans);
    ids.forEach(function(sid) {{
        fetch('/api/scan/status?scan_id=' + sid)
            .then(function(r){{return r.json();}})
            .then(function(d){{
                if (d.status === 'clean' || d.status === 'threats_found' || d.status === 'error') {{
                    delete _activeScans[sid];
                    loadFindings();
                    loadDevices();
                }} else {{
                    _activeScans[sid] = Object.assign(_activeScans[sid], d);
                }}
                renderActiveScans();
            }});
    }});
}}

function loadFindings() {{
    fetch('/api/scan/results')
        .then(function(r){{return r.json();}})
        .then(function(d){{
            var tbody = document.getElementById('findingsBody');
            if (!d.threats || !d.threats.length) {{
                tbody.innerHTML = '<tr><td colspan="5" style="color:#888">No findings.</td></tr>';
                return;
            }}
            tbody.innerHTML = d.threats.map(function(t){{
                return '<tr>' +
                    '<td>' + escHtml(t.device_id) + '</td>' +
                    '<td style="word-break:break-all">' + escHtml(t.file_path) + '</td>' +
                    '<td style="color:#ff4444">' + escHtml(t.threat_name) + '</td>' +
                    '<td>' + escHtml(t.action_taken||'—') + '</td>' +
                    '<td>' + escHtml(t.detected_at||'') + '</td>' +
                '</tr>';
            }}).join('');
        }});
}}

function loadSchedules() {{
    // Schedules are stored per device — show from DB (simple display)
    document.getElementById('schedulesPanel').innerHTML =
        '<div style="color:#888;font-size:0.85em">Use the Schedule button on a device card to add schedules.</div>';
}}

function openNotifyModal(deviceId) {{
    document.getElementById('notifyDeviceId').value = deviceId;
    document.getElementById('notifyMessage').value = '';
    document.getElementById('notifyResult').textContent = '';
    document.getElementById('notifySeverity').value = 'info';
    document.getElementById('notifySuggestedAction').value = _SEVERITY_ACTIONS.info;
    document.getElementById('notifyModal').style.display = 'block';
}}
function closeNotifyModal() {{ document.getElementById('notifyModal').style.display = 'none'; }}

function notifySeverityChanged() {{
    var sev = document.getElementById('notifySeverity').value;
    document.getElementById('notifySuggestedAction').value = _SEVERITY_ACTIONS[sev] || '';
}}

function sendNotify() {{
    var payload = {{
        device_id:        document.getElementById('notifyDeviceId').value,
        title:            'Nemesis Security Alert',
        message:          document.getElementById('notifyMessage').value,
        severity:         document.getElementById('notifySeverity').value,
        suggested_action: document.getElementById('notifySuggestedAction').value
    }};
    document.getElementById('notifyResult').textContent = 'Sending…';
    fetch('/api/agent/notify', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify(payload)
    }}).then(function(r){{return r.json();}}).then(function(d){{
        document.getElementById('notifyResult').textContent = d.ok ? '✅ Queued for next check-in' : '❌ ' + (d.error||'failed');
    }});
}}

function openScheduleModal(deviceId) {{
    document.getElementById('scheduleDeviceId').value = deviceId;
    document.getElementById('scheduleResult').textContent = '';
    document.getElementById('scheduleModal').style.display = 'block';
}}
function closeScheduleModal() {{ document.getElementById('scheduleModal').style.display = 'none'; }}

function saveSchedule() {{
    var payload = {{
        device_id:     document.getElementById('scheduleDeviceId').value,
        schedule_type: document.getElementById('scheduleType').value,
        scheduled_time:document.getElementById('scheduleTime').value
    }};
    fetch('/api/scan/schedule', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify(payload)
    }}).then(function(r){{return r.json();}}).then(function(d){{
        document.getElementById('scheduleResult').textContent = d.ok ? '✅ Saved' : '❌ ' + (d.error||'failed');
    }});
}}

function editFriendlyName(deviceId, el) {{
    var current = el.textContent;
    var input = document.createElement('input');
    input.value = current;
    input.style.cssText = 'background:#1a1a2e;color:#fff;border:1px solid #00d4ff;padding:2px 6px;border-radius:3px;width:180px;font-size:1em';
    el.innerHTML = '';
    el.appendChild(input);
    input.focus();
    input.select();
    function save() {{
        var val = input.value.trim() || current;
        fetch('/api/devices/update-friendly-name', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify({{device_id: deviceId, friendly_name: val}})
        }}).then(function(){{ el.textContent = val; }})
          .catch(function(){{ el.textContent = current; }});
    }}
    input.addEventListener('blur', save);
    input.addEventListener('keydown', function(e){{ if (e.key==='Enter') input.blur(); if (e.key==='Escape') {{ el.textContent = current; }} }});
}}

function escHtml(s) {{
    if (!s) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}}

// ── Toast ─────────────────────────────────────────────────────────────────────
var _toastTimer = null;
function showToast(msg, ms) {{
    var el = document.getElementById('toastEl');
    el.textContent = msg;
    el.classList.add('show');
    if (_toastTimer) clearTimeout(_toastTimer);
    _toastTimer = setTimeout(function(){{ el.classList.remove('show'); }}, ms || 3000);
}}

// ── Pending Scans ─────────────────────────────────────────────────────────────
function loadPendingScans() {{
    fetch('/api/scan/queue?status=pending')
        .then(function(r){{return r.json();}})
        .then(function(d){{
            var items = d.queue || [];
            var panel = document.getElementById('pendingScansPanel');
            var badge = document.getElementById('pendingBadge');
            if (!items.length) {{
                panel.innerHTML = '<div style="color:#888;font-size:0.85em">No pending scans.</div>';
                badge.textContent = '';
                return;
            }}
            badge.textContent = '(' + items.length + ')';
            panel.innerHTML = '<table style="width:100%;border-collapse:collapse;font-size:0.83em">' +
                '<thead><tr><th style="color:#888;padding:4px 6px;text-align:left">Device</th>' +
                '<th style="color:#888;padding:4px 6px;text-align:left">Trigger</th>' +
                '<th style="color:#888;padding:4px 6px;text-align:left">Detail</th>' +
                '<th style="color:#888;padding:4px 6px;text-align:left">Path</th>' +
                '<th style="color:#888;padding:4px 6px;text-align:left">Queued</th>' +
                '<th></th>' +
                '</tr></thead><tbody>' +
                items.map(function(q){{
                    var dn = deviceName(q.device_id) || q.device_id;
                    var qt = q.queued_at ? new Date(q.queued_at).toLocaleString() : '';
                    return '<tr>' +
                        '<td style="padding:4px 6px">' + escHtml(dn) + '</td>' +
                        '<td style="padding:4px 6px"><span class="badge badge-purple">' + escHtml(q.trigger_type) + '</span></td>' +
                        '<td style="padding:4px 6px;color:#888">' + escHtml(q.trigger_detail||'') + '</td>' +
                        '<td style="padding:4px 6px;color:#888">' + escHtml(q.scan_path||'/') + '</td>' +
                        '<td style="padding:4px 6px;color:#888">' + qt + '</td>' +
                        '<td style="padding:4px 6px">' +
                            '<button class="btn btn-grey" style="opacity:1;cursor:pointer;font-size:0.75em" ' +
                            'onclick="cancelQueueItem(' + q.id + ')">Cancel</button>' +
                        '</td>' +
                    '</tr>';
                }}).join('') +
                '</tbody></table>';
        }})
        .catch(function(e){{console.error('loadPendingScans:', e);}});
}}

function cancelQueueItem(queueId) {{
    fetch('/api/scan/queue/cancel', {{
        method: 'POST',
        headers: {{'Content-Type':'application/json'}},
        body: JSON.stringify({{queue_id: queueId}})
    }}).then(function(){{ loadPendingScans(); loadDevices(); }});
}}

// ── Scan Conditions ───────────────────────────────────────────────────────────
var _COND_LABELS = {{
    first_connect:      'First Connect',
    return_from_remote: 'Return from Remote',
    extended_absence:   'Extended Absence',
    new_login:          'New Login',
    usb_inserted:       'USB Inserted',
}};
var _COND_EXPLAIN = {{
    first_connect:      'Queues a scan the very first time a device checks in.',
    return_from_remote: 'Queues a scan when a device transitions from VPN/remote back to local network.',
    extended_absence:   'Queues a scan when a device has been offline for longer than N hours.',
    new_login:          'Queues a scan when a user that has never been seen before logs into the device.',
    usb_inserted:       'Queues a scan when a new USB device (never seen before) is plugged into the device.',
}};

function loadScanConditions() {{
    fetch('/api/scan/conditions')
        .then(function(r){{return r.json();}})
        .then(function(d){{
            var rows = d.conditions || [];
            var tbody = document.getElementById('conditionsBody');
            if (!rows.length) {{
                tbody.innerHTML = '<tr><td colspan="6" style="color:#888">No conditions defined.</td></tr>';
                return;
            }}
            tbody.innerHTML = rows.map(function(c){{
                var label = _COND_LABELS[c.condition_type] || c.condition_type;
                var explain = _COND_EXPLAIN[c.condition_type] || '';
                var val = (c.condition_type === 'extended_absence')
                    ? (c.condition_value || '24') + 'h' : (c.condition_value || '—');
                var scope = c.device_id ? escHtml(c.device_id) : '<em style="color:#888">All devices</em>';
                var enabledDot = c.enabled
                    ? '<span style="color:#00ff88">●</span>'
                    : '<span style="color:#444">●</span>';
                return '<tr title="' + escHtml(explain) + '">' +
                    '<td><strong>' + escHtml(label) + '</strong></td>' +
                    '<td>' + escHtml(val) + '</td>' +
                    '<td>' + scope + '</td>' +
                    '<td>' + escHtml(c.scan_path||'/') + '</td>' +
                    '<td>' + enabledDot + '</td>' +
                    '<td><button class="btn btn-grey" style="opacity:1;cursor:pointer;font-size:0.75em" ' +
                        'onclick="deleteCondition(' + c.id + ')">Delete</button></td>' +
                '</tr>';
            }}).join('');
        }});
}}

function deleteCondition(cid) {{
    if (!confirm('Delete this scan condition?')) return;
    fetch('/api/scan/conditions/' + cid, {{method:'DELETE'}})
        .then(function(){{ loadScanConditions(); }});
}}

function openAddConditionModal() {{
    document.getElementById('condResult').textContent = '';
    document.getElementById('condType').value = 'first_connect';
    document.getElementById('condValue').value = '';
    document.getElementById('condPath').value = '/';
    document.getElementById('condDevice').value = '';
    condTypeChanged();
    document.getElementById('conditionModal').style.display = 'block';
}}
function closeConditionModal() {{ document.getElementById('conditionModal').style.display = 'none'; }}

function condTypeChanged() {{
    var t = document.getElementById('condType').value;
    var row = document.getElementById('condValueRow');
    var lbl = document.getElementById('condValueLabel');
    if (t === 'extended_absence') {{
        row.style.display = 'block';
        lbl.textContent = 'Absence threshold (hours)';
        document.getElementById('condValue').placeholder = '24';
    }} else {{
        row.style.display = 'none';
    }}
}}

function saveCondition() {{
    var payload = {{
        condition_type:  document.getElementById('condType').value,
        condition_value: document.getElementById('condValue').value || null,
        scan_path:       document.getElementById('condPath').value || '/',
        device_id:       document.getElementById('condDevice').value || null,
        enabled:         true,
    }};
    document.getElementById('condResult').textContent = 'Saving…';
    fetch('/api/scan/conditions', {{
        method: 'POST',
        headers: {{'Content-Type':'application/json'}},
        body: JSON.stringify(payload)
    }}).then(function(r){{return r.json();}}).then(function(d){{
        if (d.ok) {{
            closeConditionModal();
            loadScanConditions();
        }} else {{
            document.getElementById('condResult').textContent = '❌ ' + (d.error||'failed');
        }}
    }});
}}

// Init
loadDevices();
loadFindings();
loadSchedules();
loadPendingScans();
loadScanConditions();
setInterval(nemPoll(function() {{ loadDevices(); pollActiveScans(); loadPendingScans(); }}), 5000);
setInterval(nemPoll(loadFindings), 30000);
</script>
</body>
</html>"""


# ── Fleet hardware overview (/hardware/all) ────────────────────────────────────

@app.route("/hardware/all")
def hardware_all_page():
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Nemesis — All Device Hardware</title>
    <!-- Must precede any other script: it wraps window.fetch. -->
    <script src="/static/nemesis-activity.js"></script>
    <script src="/static/tier.js"></script>
    <script src="/static/fw-credential.js"></script>
    <script src="/static/nemesis-idle-lock.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; background: #1a1a2e; color: #eee;
               padding: 24px; max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; margin-bottom: 4px; }}
        a.back {{ color: #00d4ff; text-decoration: none; font-size: 0.9em; }}
        .alert-banner {{ background: #1a0000; border: 1px solid #ff4444;
            border-radius: 6px; padding: 12px 16px; margin: 12px 0; color: #ff8888; }}
        .device-section {{ background: #0d1117; border: 1px solid #1e2d4e;
            border-radius: 8px; margin-bottom: 12px; overflow: hidden; }}
        .device-header {{ padding: 14px 18px; cursor: pointer; display: flex;
            align-items: center; gap: 14px; user-select: none; }}
        .device-header:hover {{ background: #0a1020; }}
        .health-dot {{ width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0; }}
        .health-green  {{ background: #00ff88; }}
        .health-yellow {{ background: #ffaa00; }}
        .health-red    {{ background: #ff4444; }}
        .health-grey   {{ background: #444; }}
        .device-header-name {{ font-weight: bold; font-size: 1em; color: #fff; flex: 1; }}
        .device-header-meta {{ font-size: 0.8em; color: #888; }}
        .device-header-summary {{ font-size: 0.82em; color: #aaa; margin-left: auto; }}
        .device-body {{ display: none; padding: 16px 18px; border-top: 1px solid #1e2d4e; }}
        .device-body.expanded {{ display: block; }}
        .sensor-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
            gap: 10px; }}
        .sensor-tile {{ background: #1a1a2e; border: 1px solid #1e2d4e; border-radius: 6px;
            padding: 10px 12px; text-align: center; }}
        .sensor-label {{ font-size: 0.75em; color: #888; margin-bottom: 4px; }}
        .sensor-value {{ font-size: 1.3em; font-weight: bold; color: #00d4ff; }}
        .sensor-value.warn {{ color: #ffaa00; }}
        .sensor-value.crit {{ color: #ff4444; }}
        .badge {{ display: inline-block; padding: 2px 7px; border-radius: 10px;
            font-size: 0.72em; font-weight: bold; margin: 2px; }}
        .badge-green  {{ background: #003a1a; color: #00ff88; border: 1px solid #00ff88; }}
        .badge-yellow {{ background: #2a1f00; color: #ffaa00; border: 1px solid #ffaa00; }}
        .badge-grey   {{ background: #1a1a1a; color: #888;    border: 1px solid #444; }}
        .badge-blue   {{ background: #001a2a; color: #00d4ff; border: 1px solid #00d4ff; }}
    </style>
</head>
<body>
<h1>🖥️ All Device Hardware</h1>
<p><a class="back" href="/">← Back to Dashboard</a> &nbsp;|&nbsp;
   <a class="back" href="/scan">🔬 Scanner</a></p>

<div id="alertBanner" style="display:none" class="alert-banner"></div>
<div id="deviceList"><div style="color:#888">Loading devices…</div></div>

<script>
function loadAllHw() {{
    fetch('/api/scan/devices')
        .then(function(r){{return r.json();}})
        .then(function(d){{
            renderDevices(d.devices||[]);
        }});
}}

function renderDevices(devs) {{
    var list = document.getElementById('deviceList');
    var faults = devs.filter(function(d){{ return d.hw_health === 'critical'; }});
    var banner = document.getElementById('alertBanner');
    if (faults.length) {{
        banner.style.display = 'block';
        banner.innerHTML = '⚠️ ' + faults.length + ' device(s) require attention: ' +
            faults.map(function(d){{ return escHtml(d.friendly_name); }}).join(', ');
    }}
    if (!devs.length) {{
        list.innerHTML = '<div style="color:#888">No devices with hardware data. Install the Nemesis Agent to enable hardware monitoring from remote devices.</div>';
        return;
    }}
    // Sort: faults first, then by name
    devs.sort(function(a,b){{
        var score = function(d) {{
            if (d.hw_health==='critical') return 0;
            if (d.hw_health==='warning')  return 1;
            return 2;
        }};
        return score(a)-score(b) || (a.friendly_name||'').localeCompare(b.friendly_name||'');
    }});
    list.innerHTML = devs.map(function(d){{
        var hcls  = healthClass(d.hw_health);
        var htext = healthText(d.hw_health, d);
        var connB = d.connection_type ? connBadge(d.connection_type) : '';
        var lastSeen = d.agent_last_seen || d.hw_last_seen || '';
        var summary  = buildSummary(d);
        var bodyId   = 'body-' + d.device_id.replace(/[^a-z0-9]/gi,'_');
        return '<div class="device-section" id="' + escHtml(d.device_id) + '">' +
            '<div class="device-header" onclick="toggleBody(\\'' + bodyId + '\\')">' +
                '<div class="health-dot ' + hcls + '"></div>' +
                '<div class="device-header-name">' + escHtml(d.friendly_name) + '</div>' +
                connB +
                '<div class="device-header-meta">' +
                    escHtml(d.device_type||'') +
                    (lastSeen ? ' &nbsp;·&nbsp; Last seen: ' + relTime(lastSeen) : '') +
                '</div>' +
                '<div class="device-header-summary">' + summary + '</div>' +
                '<span style="color:#00d4ff;margin-left:8px">▶</span>' +
            '</div>' +
            '<div class="device-body" id="' + bodyId + '">' +
                buildSensorGrid(d) +
                '<div style="margin-top:12px">' +
                    '<a href="/hardware/all?device=' + encodeURIComponent(d.device_id) + '" ' +
                       'style="color:#00d4ff;font-size:0.85em" target="_blank">View Full Detail ▶</a>' +
                    ' &nbsp; <a href="/scan" style="color:#00d4ff;font-size:0.85em">🔬 Scan Device</a>' +
                '</div>' +
            '</div>' +
        '</div>';
    }}).join('');
}}

function toggleBody(id) {{
    var el = document.getElementById(id);
    if (!el) return;
    el.classList.toggle('expanded');
    var chevron = el.previousElementSibling.querySelector('span:last-child');
    if (chevron) chevron.textContent = el.classList.contains('expanded') ? '▼' : '▶';
}}

function healthClass(h) {{
    if (h==='critical') return 'health-red';
    if (h==='warning')  return 'health-yellow';
    if (h==='ok')       return 'health-green';
    return 'health-grey';
}}
function healthText(h, d) {{
    if (h==='critical') return '🔴 Fault';
    if (h==='warning')  return '🟡 Concerning';
    if (h==='ok')       return '🟢 Healthy';
    return '⚫ Offline';
}}
function connBadge(conn) {{
    if (conn==='local')      return '<span class="badge badge-green">Local</span>';
    if (conn==='vpn_remote') return '<span class="badge badge-blue">Remote (VPN)</span>';
    return '';
}}
function buildSummary(d) {{
    var parts = [];
    if (d.cpu_temp != null)     parts.push('CPU ' + d.cpu_temp + '°C');
    if (d.ram_used_gb != null)  parts.push('RAM ' + d.ram_used_gb + ' GB');
    if (d.cpu_percent != null)  parts.push('Load ' + d.cpu_percent + '%');
    return parts.join(' | ') || '—';
}}
function buildSensorGrid(d) {{
    var tiles = [];
    function tile(label, val, unit, warn, crit) {{
        var vcls = '';
        if (val != null && crit != null && val >= crit) vcls = 'crit';
        else if (val != null && warn != null && val >= warn) vcls = 'warn';
        var display = val != null ? val + (unit||'') : '—';
        tiles.push('<div class="sensor-tile">' +
            '<div class="sensor-label">' + escHtml(label) + '</div>' +
            '<div class="sensor-value ' + vcls + '">' + escHtml(display) + '</div>' +
        '</div>');
    }}
    tile('CPU Temp',  d.cpu_temp,    '°C',  75, 90);
    tile('GPU Temp',  d.gpu_temp,    '°C',  80, 95);
    tile('CPU Load',  d.cpu_percent, '%',   80, 95);
    tile('RAM Used',  d.ram_used_gb, ' GB', null, null);
    return '<div class="sensor-grid">' + tiles.join('') + '</div>';
}}
function relTime(ts) {{
    if (!ts) return '—';
    var d = new Date(ts);
    if (isNaN(d)) return ts;
    var s = Math.floor((Date.now() - d) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return Math.floor(s/60) + 'm ago';
    if (s < 86400) return Math.floor(s/3600) + 'h ago';
    return Math.floor(s/86400) + 'd ago';
}}
function escHtml(s) {{
    if (!s && s!==0) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}}

// Anchor scrolling for ?device= or #device_id
(function() {{
    var target = (location.hash||'').replace('#','') ||
                 (new URLSearchParams(location.search)).get('device');
    if (target) {{
        setTimeout(function() {{
            var el = document.getElementById(target);
            if (el) {{ el.scrollIntoView({{behavior:'smooth'}}); }}
        }}, 600);
    }}
}})();

loadAllHw();
setInterval(nemPoll(loadAllHw), 30000);
</script>
</body>
</html>"""


@app.route("/")
def dashboard():
    clamav_status = get_clamav_status()
    system_status = get_system_status()
    alert_counts = get_alert_counts()
    initial_total = alert_counts["total"]
    pihole = get_pihole_summary()
    total = pihole["total"]
    blocked = pihole["blocked"]
    percent = pihole["percent"]
    try:
        hw_live = hw_monitor.get_live_metrics()
    except Exception:
        hw_live = {}
    hw_cpu = hw_live.get("cpu_temp")
    hw_ambient = hw_live.get("ambient_temp")
    hw_nvme = hw_live.get("nvme_temp")
    hw_gpu = hw_live.get("gpu_temp")
    hw_fans = hw_live.get("fans", [])
    hw_gpu_fan = hw_live.get("gpu_fan_percent")
    hw_cpu_pct = hw_live.get("cpu_percent")
    hw_ram_pct = hw_live.get("ram_percent")
    hw_ram_used_gb = hw_live.get("ram_used_gb")
    hw_ram_total_gb = hw_live.get("ram_total_gb")
    hw_ram_free_gb = (
        round(hw_ram_total_gb - hw_ram_used_gb, 1)
        if hw_ram_total_gb is not None and hw_ram_used_gb is not None
        else None
    )
    hw_disk_pct = hw_live.get("disk_pct_used")
    hw_disk_free_gb = hw_live.get("disk_free_gb")
    # An absent or failed capacity reading renders as "unknown" — deliberately
    # distinct from both a healthy disk and a full one.
    #
    # Note classify_pct(None) returns "error", not "unknown", and that is not an
    # inconsistency: the diagnostics check must never let a failed read report as
    # healthy, so it errs. The card has a different job — a human reading it needs
    # "we do not know" rather than a red 90%+ implying a real measurement that was
    # never taken. Both refuse to claim health; they differ in what they claim
    # instead. NULL is legitimate here for remote-agent rows (agent-side disk
    # reporting is deliberately out of scope) as well as for a genuine read failure.
    if hw_disk_pct is None:
        hw_disk_value = "unknown"
        hw_disk_style = 'style="color:#8a8f98"'
        hw_disk_sub = "no reading"
    else:
        _disk_color = {"ok": "", "warn": "#ffaa00", "error": "#ff4444"}[
            _diag.disk_space.classify_pct(hw_disk_pct)
        ]
        hw_disk_value = f"{hw_disk_pct}%"
        hw_disk_style = f'style="color:{_disk_color}"' if _disk_color else ""
        hw_disk_sub = (
            f"{hw_disk_free_gb} GB free" if hw_disk_free_gb is not None else ""
        )
    hw_fans_js = json.dumps(hw_fans)
    hw_cpu_pct_js = "null" if hw_cpu_pct is None else str(hw_cpu_pct)
    fan_status_js = json.dumps(hw_live.get("fan_status", {}))
    try:
        hw_alerts_init = hw_monitor.get_hw_alerts()
    except Exception:
        hw_alerts_init = []
    hw_alerts_js = json.dumps(hw_alerts_init)
    def _fmt(v, suffix=""):
        return "—" if v is None else f"{v}{suffix}"

    try:
        alerts_24h_init = get_24h_alert_stats()
        svc_status_init = get_services_status()
        health_init = compute_health_score(hw_live, alerts_24h_init, svc_status_init)
    except Exception:
        alerts_24h_init = {"total": 0}
        health_init = {"score": 0.0, "color": "red"}
    color_map = {"green": "#00ff88", "yellow": "#ffaa00", "red": "#ff4444"}
    alert_24h_total = alerts_24h_init.get("total", 0)
    alert_24h_color = color_map[alert_color(alert_24h_total)]
    health_score = health_init["score"]
    health_color = color_map[health_init["color"]]

    vpn = get_vpn_status()
    vpn_status_str = vpn.get("status", "Disconnected")
    vpn_provider = vpn.get("provider") or "VPN"
    _vpn_color_map = {"connected": "#00ff88", "connecting": "#ffaa00", "reconnecting": "#ffaa00"}
    vpn_color = _vpn_color_map.get(vpn_status_str.lower(), "#ff4444")
    vpn_label = f"{vpn_provider} — {vpn_status_str}" if vpn.get("provider") else f"VPN — {vpn_status_str}"

    alerts_html = render_alerts_html(get_active_alerts())
    devices_html = render_devices_html(get_network_devices())
    review_queue = get_review_queue()
    review_queue_html = render_review_queue_html(review_queue)
    review_queue_count = len(review_queue)
    quarantines = get_active_quarantines()
    quarantine_banner_html = render_quarantine_banner_html(quarantines)
    quarantine_banner_display = "block" if quarantines else "none"

    module_cards_html = "".join(
        card_html for name, card_html in modules_loader.get_module_cards()
        if name != "community_queue"
    )

    # Community queue header badge (injected into h1, not the grid)
    cq_badge_html = ""
    try:
        cq_mod = modules_loader.get_loaded_modules().get("community_queue")
        if cq_mod:
            cq_badge_html = cq_mod.get_dashboard_card() or ""
    except Exception:
        pass

    incident_banner_html = ""
    incident_js_html = ""
    incident_state_js = "window._nemesisIncidentState={};"
    # Shared chat widget. Empty strings when ai_engine is unavailable, so the
    # template renders identically minus the affordance.
    chat_js_html = ""
    try:
        from modules.ai_engine import get_chat_js as _ai_cjs
        chat_js_html = _ai_cjs()
    except Exception:
        pass
    try:
        from modules.ai_engine import get_incident_banner_html as _ai_ibanner, get_incident_js as _ai_ijs, get_incident_state as _ai_istate
        incident_banner_html = _ai_ibanner()
        # Pricing drift rides the same banner slot as the Anthropic incident
        # banner — same module, same shape of news ("something changed on
        # Anthropic's side that you should know about"), so it reuses the
        # surface rather than inventing a second one.
        try:
            from modules.ai_engine import get_pricing_drift_banner_html as _ai_dbanner
            incident_banner_html = (_ai_dbanner() or "") + incident_banner_html
        except Exception:
            pass
        incident_js_html = _ai_ijs()
        incident_state_js = f"window._nemesisIncidentState={json.dumps(_ai_istate())};"
    except Exception:
        pass

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Nemesis Firewall</title>
    <!-- Must precede any other script: it wraps window.fetch. -->
    <script src="/static/nemesis-activity.js"></script>
    <link rel="icon" type="image/x-icon" href="/static/favicon.ico">
    <style>
        body {{ font-family: Arial; background: #1a1a2e; color: #eee; padding: 20px; margin: 0; }}
        h1 {{ color: #00d4ff; margin-bottom: 5px; }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }}
        .card {{ background: #16213e; padding: 15px; border-radius: 10px; border: 1px solid #00d4ff; }}
        .card h2 {{ color: #00d4ff; margin-top: 0; font-size: 1em; }}
        .stat {{ font-size: 1.8em; color: #00ff88; }}
        .full-width {{ grid-column: span 2; }}
        .running {{ color: #00ff88; }}
        .stopped {{ color: #ff4444; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ text-align: left; padding: 5px; border-bottom: 1px solid #00d4ff; font-size: 0.85em; color: #00d4ff; }}
        td {{ padding: 5px; border-bottom: 1px solid #222; font-size: 0.85em; }}
        .counter-box {{ display: inline-block; background: #0d1117; border-radius: 8px; padding: 10px 15px; margin: 5px; text-align: center; }}
        .counter-clickable {{ cursor: pointer; transition: background 0.15s, border-color 0.15s; border: 1px solid transparent; }}
        .counter-clickable:hover {{ background: #141d2e; border-color: #00d4ff; }}
        .counter-num {{ font-size: 1.8em; font-weight: bold; }}
        .p1 {{ color: #ff4444; }}
        .p2 {{ color: #ffaa00; }}
        .p3 {{ color: #aaaaaa; }}
        .total {{ color: #00d4ff; }}
        .modal {{ display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.8); z-index:1000; }}
        .modal-content {{ background:#16213e; border:1px solid #00d4ff; border-radius:10px; padding:20px; max-width:600px; margin:80px auto; }}
        .modal h3 {{ color:#00d4ff; }}
        .btn {{ padding:8px 16px; border:none; border-radius:5px; cursor:pointer; margin:5px; font-weight:bold; }}
        .btn-block {{ background:#ff4444; color:white; }}
        .btn-ignore {{ background:#aaaaaa; color:#1a1a2e; }}
        .btn-monitor {{ background:#ffaa00; color:#1a1a2e; }}
        .btn-close {{ background:#333; color:#eee; }}
        .btn-save {{ background:#00ff88; color:#1a1a2e; }}
        .btn-report {{ background:#8800ff; color:white; }}
        input, select {{ background:#0d1117; color:#eee; border:1px solid #00d4ff; padding:5px; border-radius:3px; width:100%; margin:3px 0; }}
        a {{ color: #00d4ff; }}
        .enrichment-card {{ background:#0d1117; border:1px solid #333; border-radius:6px; padding:10px; margin:10px 0; }}
        .enrichment-card h4 {{ color:#00d4ff; margin:0 0 8px 0; font-size:0.95em; }}
        .enrichment-card p {{ margin:4px 0; font-size:0.9em; }}
        .flag {{ font-size:1.3em; vertical-align:middle; }}
        .warn-tor {{ color:#ff4444; font-weight:bold; }}
        .warn-vpn {{ color:#ffaa00; font-weight:bold; }}
        .quarantine-banner {{ background:#2a0d0d; border:2px solid #ff4444; border-radius:10px; padding:15px; margin-bottom:15px; }}
        .quarantine-banner h2 {{ color:#ff4444; margin-top:0; }}
        .q-row {{ display:flex; justify-content:space-between; align-items:center; padding:8px; border-bottom:1px solid #4a1010; flex-wrap:wrap; gap:8px; }}
        .q-row:last-child {{ border-bottom:none; }}
        .q-info {{ flex:1; min-width:200px; }}
        .q-actions {{ display:flex; gap:5px; }}
        .devices-table td {{ border-bottom: 1px solid #1e3a5f; }}
        .hw-overview-btn {{ float:right; background:transparent; border:1px solid #00d4ff; color:#00d4ff; padding:3px 10px; border-radius:4px; cursor:pointer; font-size:0.75em; margin-top:2px; }}
        .hw-overview-btn:hover {{ background:#00d4ff; color:#1a1a2e; }}
        .sensor-popup-modal {{ background:#16213e; border:1px solid #00d4ff; border-radius:10px; padding:20px; max-width:720px; width:95%; max-height:90vh; overflow-y:auto; margin:40px auto; position:relative; }}
        .sensor-range-btn {{ background:#0d1117; border:1px solid #333; color:#bbb; padding:4px 12px; border-radius:4px; cursor:pointer; font-size:0.82em; margin-right:4px; }}
        .sensor-range-btn.active {{ border-color:#00d4ff; color:#00d4ff; background:#0a1a2e; }}
        .anomaly-banner {{ background:#2a1000; border-left:3px solid #ff8800; padding:8px 12px; border-radius:4px; margin:8px 0; font-size:0.85em; color:#ffaa00; }}
        .throttle-banner {{ background:#2a0000; border-left:3px solid #ff4444; padding:8px 12px; border-radius:4px; margin:8px 0; font-size:0.85em; color:#ff6666; }}
        .process-modal {{ background:#111; border:1px solid #333; border-radius:8px; padding:18px; max-width:700px; width:95%; max-height:85vh; overflow-y:auto; margin:50px auto; position:relative; }}
        .process-modal pre {{ font-size:0.75em; color:#ccc; white-space:pre-wrap; word-break:break-all; background:#0d1117; padding:10px; border-radius:4px; max-height:350px; overflow-y:auto; }}
        .hw-notification-bar {{ background:#1a1000; border:1px solid #ff8800; border-radius:6px; padding:8px 14px; margin-bottom:10px; font-size:0.85em; display:flex; align-items:center; gap:10px; }}
        .hw-notification-bar button {{ background:transparent; border:1px solid #555; color:#ccc; padding:2px 8px; cursor:pointer; border-radius:3px; font-size:0.8em; }}
        .hw-card:hover {{ background:#1a2950; }}
        .hw-grid {{ display:grid; grid-template-columns: repeat(4, 1fr); gap:10px; margin-top:8px; }}
        .hw-stat {{ background:#0d1117; border-radius:6px; padding:8px 10px; text-align:center; }}
        .hw-label {{ color:#ccc; font-size:0.75em; text-transform:uppercase; letter-spacing:0.05em; }}
        .hw-value {{ color:#00ff88; font-size:1.4em; font-weight:bold; margin-top:2px; }}
        .hw-clickable {{ cursor:pointer; transition:background 0.15s; }}
        .hw-clickable:hover {{ background:#1a2950; outline:1px solid #00d4ff; }}
        .breakdown-table {{ width:100%; border-collapse:collapse; margin-top:10px; }}
        .breakdown-table th, .breakdown-table td {{ padding:6px 10px; border-bottom:1px solid #2a3a5a; text-align:left; font-size:0.85em; }}
        .breakdown-table th {{ color:#00d4ff; background:#0d1117; }}
        .health-bar {{ height:8px; background:#0d1117; border-radius:4px; overflow:hidden; }}
        .health-bar-fill {{ height:100%; background:#00ff88; }}
        .hw-modal-content {{ background:#16213e; border:1px solid #00d4ff; border-radius:10px; padding:20px; max-width:900px; width:90%; max-height:90vh; overflow-y:auto; margin:40px auto; position:relative; }}
        .hw-close-x {{ position:sticky; top:0; float:right; background:#16213e; color:#00d4ff; border:1px solid #00d4ff; border-radius:50%; width:32px; height:32px; font-size:1.1em; line-height:1; cursor:pointer; z-index:10; }}
        .hw-close-x:hover {{ background:#ff4444; color:#fff; border-color:#ff4444; }}
        .chart-box {{ background:#0d1117; border-radius:6px; padding:10px; margin-bottom:12px; }}
        .chart-box h4 {{ color:#00d4ff; margin:0 0 6px 0; font-size:0.9em; }}
        .fan-section {{ margin-top:10px; border-top:1px solid #1e2d4e; padding-top:6px; }}
        .fan-summary {{ display:flex; align-items:center; cursor:pointer; padding:6px 4px; border-radius:4px; user-select:none; gap:8px; border:1px solid transparent; }}
        .fan-summary:hover {{ background:rgba(0,212,255,0.06); }}
        .fan-summary.fan-alert {{ background:rgba(255,68,68,0.12); border-color:rgba(255,68,68,0.5); }}
        .fan-summary.fan-alert:hover {{ background:rgba(255,68,68,0.18); }}
        .fan-toggle {{ color:#00d4ff; font-size:0.75em; display:inline-block; width:10px; flex-shrink:0; }}
        .fan-dot {{ width:9px; height:9px; border-radius:50%; display:inline-block; flex-shrink:0; }}
        .fan-summary-text {{ color:#ccc; font-size:0.85em; }}
        .fan-detail-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(110px,1fr)); gap:8px; margin-top:8px; }}
        .fan-tile {{ background:#0d1117; border-radius:6px; padding:8px 6px; text-align:center; }}
        .fan-tile-lbl {{ color:#ccc; font-size:0.65em; text-transform:uppercase; letter-spacing:0.04em; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
        .fan-tile-rpm {{ font-size:1.15em; font-weight:bold; margin-top:3px; }}
        .fan-rpm-active {{ color:#00ff88; }}
        .fan-rpm-idle {{ color:#777; }}
        .fan-rpm-concern {{ color:#ff4444; }}
        .hw-alerts-section {{ margin-top:10px; border-top:1px solid #1e2d4e; padding-top:8px; }}
        .hw-alerts-header {{ color:#ccc; font-size:0.75em; text-transform:uppercase; letter-spacing:0.06em; margin-bottom:6px; }}
        .hw-alert-row {{ display:flex; align-items:center; gap:10px; padding:7px 10px; border-radius:5px; cursor:pointer; background:rgba(255,68,68,0.08); border:1px solid rgba(255,68,68,0.3); margin-bottom:4px; }}
        .hw-alert-row:hover {{ background:rgba(255,68,68,0.16); border-color:rgba(255,68,68,0.5); }}
        .hw-alert-icon {{ font-size:1.1em; flex-shrink:0; }}
        .hw-alert-body {{ flex:1; min-width:0; }}
        .hw-alert-msg {{ color:#ff9999; font-size:0.85em; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
        .hw-alert-meta {{ color:#ccc; font-size:0.72em; margin-top:2px; }}
        .hw-alert-sev-CRITICAL {{ color:#ff4444; font-weight:bold; font-size:0.72em; flex-shrink:0; }}
        .hw-alert-sev-HIGH {{ color:#ff8800; font-weight:bold; font-size:0.72em; flex-shrink:0; }}
        .hw-alert-sev-MEDIUM {{ color:#ffcc00; font-weight:bold; font-size:0.72em; flex-shrink:0; }}
        .hw-alert-empty {{ color:#bbb; font-size:0.82em; padding:5px 2px; }}
        .hw-alert-detail-modal {{ background:#16213e; border:1px solid #ff4444; border-radius:10px; padding:20px; max-width:600px; width:90%; max-height:85vh; overflow-y:auto; margin:60px auto; position:relative; }}
        .hw-alert-detail-modal h3 {{ color:#ff6666; margin-top:0; }}
        .hw-alert-detail-field {{ margin-bottom:12px; }}
        .hw-alert-detail-label {{ color:#ccc; font-size:0.75em; text-transform:uppercase; letter-spacing:0.05em; }}
        .hw-alert-detail-value {{ color:#ddd; font-size:0.9em; margin-top:3px; white-space:pre-wrap; }}
        /* Sticky jump menu */
        .jump-nav {{ position:sticky; top:0; z-index:50; background:#111827; border-bottom:1px solid #1e2d4e;
                     padding:6px 0; margin:0 -20px 12px -20px; display:flex; gap:4px; flex-wrap:wrap;
                     align-items:center; padding-left:20px; padding-right:20px; }}
        .jump-nav a {{ color:#bbb; text-decoration:none; font-size:0.8em; padding:4px 10px;
                       border-radius:4px; border:1px solid #1e2d4e; white-space:nowrap; transition:all 0.15s; }}
        .jump-nav a:hover {{ color:#00d4ff; border-color:#00d4ff; background:rgba(0,212,255,0.07); }}
        /* Collapsible sections */
        .section-chevron {{ font-size:0.7em; color:#bbb; flex-shrink:0; transition:transform 0.2s; }}
        .section-badge {{ display:none; background:#ff4444; color:#fff; border-radius:10px;
                          padding:2px 8px; font-size:0.7em; font-weight:bold; margin-left:6px; }}
        .ph-reset-times {{ font-size:0.82em; font-weight:normal; color:#bbb; margin-left:10px; }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <script src="/static/tier.js"></script>
    <script src="/static/fw-credential.js"></script>
    <script src="/static/nemesis-idle-lock.js"></script>
    {incident_js_html}
    {chat_js_html}
    <script>{incident_state_js}</script>
</head>
<body>
    <h1><a id="hdrStatusLight" href="#section-firewall" title="Loading status…"
           style="text-decoration:none;color:#888;font-size:0.66em;vertical-align:middle;margin-right:9px;cursor:pointer"
           ><span id="hdrStatusShape">●</span><span id="hdrStatusCount" style="font-size:0.62em;color:#ccc"></span></a>🛡️ Nemesis Firewall
        <a id="ai-status-badge" href="/settings#ai-engine" target="_blank" rel="noopener"
           title="AI Engine status — click to configure"
           style="font-size:0.42em;font-weight:normal;margin-left:12px;vertical-align:middle;
                  text-decoration:none;color:#888;cursor:pointer">AI ○</a>
        <span id="cq-badge-container">{cq_badge_html}</span>
        <span style="float:right;font-size:0.45em;font-weight:normal;margin-top:8px">
            {_threat_indicator_html()}<span style="color:#00d4ff" title="Logged in">👤 {html.escape(current_user.display_name)}</span>
            &nbsp;<a href="/logout" style="color:#bbb;text-decoration:none" title="Log out">Logout</a>
            &nbsp;|&nbsp;
            <a href="/settings" target="_blank" rel="noopener" style="color:#bbb;text-decoration:none" title="Settings">⚙️ Settings</a>
            &nbsp;|&nbsp;
            <a href="/diagnostics" target="_blank" rel="noopener" style="color:#bbb;text-decoration:none" title="Diagnostics &amp; Support">🔍 Diagnostics</a>
        </span>
    </h1>
    <script src="/static/header-status.js"></script>
    <p style="color:#ccc;margin-top:0">Last updated: <span id="lastUpdated">{now}</span> | Stats refresh every 60s, tables every 5 min | Uptime: <span id="dashUptime">…</span></p>

    <nav class="jump-nav">
        <a href="#" onclick="window.scrollTo(0,0);return false;" style="color:#00d4ff;border-color:#00d4ff">↑ Top</a>
        <span style="color:#333;margin:0 2px">|</span>
        <a href="#section-hw">🌡️ Hardware</a>
        <a href="#section-firewall">🔥 AI Firewall</a>
        <a href="#section-devices">🖥️ Devices</a>
        <a href="#section-anomaly">🔍 Anomaly</a>
        <a href="#section-tickets">🎫 Tickets</a>
        <span style="color:#333;margin:0 2px">|</span>
        <a href="/scan" target="_blank" rel="noopener">🔬 Scan</a>
        <a href="/hardware/all" target="_blank" rel="noopener">🖥️ All Devices</a>
        <span style="color:#333;margin:0 2px">|</span>
        <a href="/settings" target="_blank" rel="noopener">⚙️ Settings</a>
        <a href="/diagnostics" target="_blank" rel="noopener">🔍 Diagnostics</a>
    </nav>

    <div id="nemesisIncidentBannerWrap">{incident_banner_html}</div>

    <div class="quarantine-banner" id="quarantineBanner" style="display:{quarantine_banner_display}">
        <h2>🚨 Auto-Quarantined IPs</h2>
        <div id="quarantineList">{quarantine_banner_html}</div>
    </div>

    <div class="grid">
        <!-- Pi-hole and System Status cards are always-visible at-a-glance status widgets;
             intentionally excluded from collapsible sections. -->
        <div class="card">
            <h2><span class="tier-text" data-beginner="Pi-hole — DNS Ad &amp; Tracker Blocker" data-intermediate="Pi-hole DNS Protection" data-pro="Pi-hole DNS">Pi-hole DNS Protection</span><span class="ph-reset-times" id="phResetTimes"></span></h2>
            <p>
                <span class="tier-text" data-beginner="DNS Queries Today (all devices):" data-intermediate="Queries Today:" data-pro="Queries:">Queries Today:</span>
                <span class="stat" id="phTotal">{total}</span>
            </p>
            <p><span class="tier-text" data-beginner="Blocked (ads, trackers, malware domains):" data-intermediate="Blocked:" data-pro="Blocked:">Blocked:</span> <span class="stat" id="phBlocked">{blocked}</span></p>
            <p><span class="tier-text" data-beginner="Block Rate (higher = more protection):" data-intermediate="Percent Blocked:" data-pro="Block %:">Percent Blocked:</span> <span class="stat" id="phPercent">{percent}%</span></p>
        </div>

        <div class="card">
            <h2><span class="tier-text" data-beginner="Security Services Status" data-intermediate="System Status" data-pro="Services">System Status</span></h2>
            <p><span class="tier-text" data-beginner="ClamAV Antivirus:" data-intermediate="ClamAV:" data-pro="ClamAV:">ClamAV:</span> <span class="{"running" if clamav_status == "Running" else "stopped"}">{clamav_status}</span></p>
            <p><span class="tier-text" data-beginner="VPN (encrypts your traffic):" data-intermediate="VPN:" data-pro="VPN:">VPN:</span> <span id="vpnStatusText" onclick="openVpnModal()"
                style="color:{vpn_color};cursor:pointer;text-decoration:underline dotted"
                title="Click for details">{html.escape(vpn_label)}</span></p>
            <p style="font-size:0.8em">CPU: {system_status.get("cpu", "N/A")}</p>
            <p style="font-size:0.8em">Memory: {system_status.get("memory", "N/A")}</p>
            <p style="font-size:0.8em">Disk: {system_status.get("disk", "N/A")}</p>
        </div>

        <div class="card full-width hw-card" id="section-hw">
            <h2 style="cursor:pointer" onclick="toggleSection('hw')" data-section-badge="{len(hw_alerts_init)}">
                <span class="section-chevron" id="chevron-hw">▼</span>
                🌡️ <span class="tier-text" data-beginner="Hardware Health &amp; Temperatures" data-intermediate="Hardware Stats" data-pro="Hardware">Hardware Stats</span>
                <span class="section-badge" id="badge-hw"></span>
                <button onclick="event.stopPropagation();openHwModal()" class="hw-overview-btn" title="Open 24-hour combined graphs">
                    <span class="tier-text" data-beginner="Overview graphs ▸" data-intermediate="Overview ▸" data-pro="Overview ▸">Overview ▸</span>
                </button>
                <a href="/hardware/all" target="_blank" rel="noopener" onclick="event.stopPropagation()"
                   style="float:right;font-size:0.75em;color:#00d4ff;text-decoration:none;margin-right:10px;padding:4px 8px;border:1px solid #00d4ff;border-radius:4px"
                   title="Fleet hardware overview">All Devices ▶</a>
            </h2>
            <div id="section-hw-body">
            <div style="margin-bottom:10px;display:flex;align-items:center;gap:12px" onclick="event.stopPropagation()">
                <label style="color:#aaa;font-size:0.85em">Device:</label>
                <select id="hwDeviceSelect" onchange="hwDeviceChanged()"
                        style="background:#1a1a2e;color:#eee;border:1px solid #333;padding:4px 8px;border-radius:4px;font-size:0.85em">
                    <option value="local">Nemesis Host (this machine)</option>
                </select>
                <span id="hwDeviceConnBadge" style="font-size:0.75em;color:#888"></span>
            </div>
            <div class="hw-grid">
                <div class="hw-stat hw-clickable" onclick="openSensorPopup('cpu_temp')" title="Click for sensor history">
                    <div class="hw-label"><span class="tier-text" data-beginner="CPU Temperature" data-intermediate="CPU Temp" data-pro="CPU °C">CPU Temp</span></div>
                    <div class="hw-value" id="hwCpuTemp">{_fmt(hw_cpu, "°C")}</div>
                </div>
                <div class="hw-stat hw-clickable" onclick="openSensorPopup('gpu_temp')" title="Click for sensor history">
                    <div class="hw-label"><span class="tier-text" data-beginner="GPU Temperature" data-intermediate="GPU Temp" data-pro="GPU °C">GPU Temp</span></div>
                    <div class="hw-value" id="hwGpuTemp">{_fmt(hw_gpu, "°C")}</div>
                </div>
                <div class="hw-stat hw-clickable" onclick="openSensorPopup('ambient_temp')" title="Click for sensor history">
                    <div class="hw-label"><span class="tier-text" data-beginner="Case / Ambient Temp" data-intermediate="Ambient" data-pro="Ambient °C">Ambient</span></div>
                    <div class="hw-value" id="hwAmbient">{_fmt(hw_ambient, "°C")}</div>
                </div>
                <div class="hw-stat hw-clickable" onclick="openSensorPopup('nvme_temp')" title="Click for sensor history">
                    <div class="hw-label"><span class="tier-text" data-beginner="SSD Temperature (NVMe)" data-intermediate="NVMe" data-pro="NVMe °C">NVMe</span></div>
                    <div class="hw-value" id="hwNvme">{_fmt(hw_nvme, "°C")}</div>
                </div>
                <div class="hw-stat hw-clickable" onclick="openSensorPopup('cpu_percent')" title="Click for sensor history">
                    <div class="hw-label"><span class="tier-text" data-beginner="CPU Usage" data-intermediate="CPU Load" data-pro="CPU %">CPU Load</span></div>
                    <div class="hw-value" id="hwCpuPct">{_fmt(hw_cpu_pct, "%")}</div>
                </div>
                <div class="hw-stat hw-clickable" onclick="openSensorPopup('ram_used_gb')" title="Click for sensor history">
                    <div class="hw-label"><span class="tier-text" data-beginner="RAM / Memory Used" data-intermediate="RAM Used" data-pro="RAM %">RAM Used</span></div>
                    <div class="hw-value" id="hwRamPct">{_fmt(hw_ram_pct, "%")}</div>
                    <div class="hw-label" id="hwRamFree" style="margin-top:3px;font-size:0.85em">{_fmt(hw_ram_free_gb, " GB free") if hw_ram_free_gb is not None else ""}</div>
                </div>
                <div class="hw-stat hw-clickable" onclick="openSensorPopup('disk_pct_used')" title="Click for sensor history">
                    <div class="hw-label"><span class="tier-text" data-beginner="Disk Space Used" data-intermediate="Disk Used" data-pro="Disk %">Disk Used</span></div>
                    <div class="hw-value" id="hwDiskPct" {hw_disk_style}>{hw_disk_value}</div>
                    <div class="hw-label" id="hwDiskFree" style="margin-top:3px;font-size:0.85em">{hw_disk_sub}</div>
                </div>
                <div class="hw-stat hw-clickable" onclick="openSensorPopup('gpu_fan_percent')" title="Click for sensor history">
                    <div class="hw-label"><span class="tier-text" data-beginner="GPU Fan Speed" data-intermediate="GPU Fan" data-pro="GPU Fan %">GPU Fan</span></div>
                    <div class="hw-value" id="hwGpuFan">{_fmt(hw_gpu_fan, "%")}</div>
                </div>
                <div class="hw-stat hw-clickable" onclick="openAlertBreakdownModal()">
                    <div class="hw-label"><span class="tier-text" data-beginner="System Alerts (last 24h)" data-intermediate="24h System Alerts" data-pro="24h Alerts">24h System Alerts</span></div>
                    <div class="hw-value" id="hwAlert24h" style="color:{alert_24h_color}">{alert_24h_total}</div>
                </div>
                <div class="hw-stat hw-clickable" onclick="openHealthModal()">
                    <div class="hw-label"><span class="tier-text" data-beginner="Overall System Health" data-intermediate="System Health" data-pro="Health">System Health</span></div>
                    <div class="hw-value" id="hwHealthScore" style="color:{health_color}">{health_score}%</div>
                </div>
            </div>
            <div class="fan-section" onclick="event.stopPropagation()">
                <div class="fan-summary" id="fanSummaryRow" onclick="toggleFanSection()">
                    <span class="fan-toggle" id="fanToggleIcon">▶</span>
                    <span class="fan-dot" id="fanStatusDot" style="background:#444"></span>
                    <span class="fan-summary-text" id="fanSummaryText">Fans: loading…</span>
                </div>
                <div id="fanDetailGrid" class="fan-detail-grid" style="display:none"></div>
            </div>
            <div class="hw-alerts-section" onclick="event.stopPropagation()">
                <div class="hw-alerts-header"><span class="tier-text"
                    data-beginner="Hardware Problems"
                    data-intermediate="Hardware Alerts"
                    data-pro="HW Alerts">Hardware Alerts</span></div>
                <div id="hwAlertsList"></div>
            </div>
            </div><!-- end section-hw-body -->
        </div>

        <div class="card full-width" id="section-firewall">
            <h2 style="cursor:pointer" onclick="toggleSection('firewall')" data-section-badge="{alert_counts['p1'] + alert_counts['p2']}">
                <span class="section-chevron" id="chevron-firewall">▼</span>
                🔥 <span class="tier-text" data-beginner="AI Firewall — Security Events Detected Today" data-intermediate="AI Firewall — Today's Activity" data-pro="AI Firewall">AI Firewall — Today's Activity</span>
                <span class="section-badge" id="badge-firewall"></span>
                <span style="float:right;font-size:0.8em" onclick="event.stopPropagation()">
                    <label style="color:#ccc;cursor:pointer;margin-right:15px" title="Show informational Priority-3 alerts (DNS lookups, ET POLICY notices, etc.)">
                        <input type="checkbox" id="showP3Toggle" onchange="toggleP3()" style="width:auto;margin-right:5px;vertical-align:middle">
                        <span class="tier-text"
                              data-beginner="Show background/informational traffic (P3)"
                              data-intermediate="Show P3 (info)"
                              data-pro="P3">Show P3 (info)</span>
                    </label>
                    <a href="/firewall-db" target="_blank" rel="noopener" style="color:#00d4ff;text-decoration:none">📋 Alert Database</a>
                </span>
            </h2>
            <div id="section-firewall-body">
            <div>
                <div class="counter-box counter-clickable" onclick="openFwDrilldown('total')" title="Click to see all rules firing today"><div class="counter-num total" id="cntTotal">{initial_total}</div>
                    <div><span class="tier-text" data-beginner="All Alerts Today" data-intermediate="Total" data-pro="Total">Total</span></div>
                    <div style="color:#bbb;font-size:0.65em;margin-top:2px"><span class="tier-text" data-beginner="includes routine traffic" data-intermediate="incl. P3 info" data-pro="P1+P2+P3">incl. P3 info</span></div>
                </div>
                <div class="counter-box counter-clickable" onclick="openFwDrilldown('p1')" title="Click to see all Critical P1 rules today"><div class="counter-num p1" id="cntP1">{alert_counts["p1"]}</div>
                    <div><span class="tier-text" data-beginner="Critical Threats" data-intermediate="Critical P1" data-pro="P1">Critical P1</span></div>
                </div>
                <div class="counter-box counter-clickable" onclick="openFwDrilldown('p2')" title="Click to see all High P2 rules today"><div class="counter-num p2" id="cntP2">{alert_counts["p2"]}</div>
                    <div><span class="tier-text" data-beginner="High Risk" data-intermediate="High P2" data-pro="P2">High P2</span></div>
                </div>
                <div class="counter-box" id="p3Box" style="display:none"><div class="counter-num p3" id="cntP3">{alert_counts["p3"]}</div>
                    <div><span class="tier-text" data-beginner="Background Traffic" data-intermediate="Info P3" data-pro="P3">Info P3</span></div>
                </div>
                <div class="counter-box counter-clickable" onclick="openFwDrilldown('review_queue')" title="Click to see all HIGH risk rules today"><div class="counter-num" id="cntReviewQueue" style="color:#ff8800">{review_queue_count}</div>
                    <div style="color:#ff8800"><span class="tier-text" data-beginner="Needs Your Review" data-intermediate="Review Queue" data-pro="Queue">Review Queue</span></div>
                </div>
            </div>
            <div id="p3Note" style="display:none;color:#ccc;font-size:0.85em;margin-top:8px;padding:10px;background:#0d1117;border-radius:4px;border-left:3px solid #00d4ff">
                <span class="tier-text"
                    data-beginner="ℹ️ These are not threats. P3 alerts are routine background traffic your firewall notices but automatically ignores — things like DNS queries (when your devices look up website names), software checking for updates, or standard protocol handshakes. Your network is safe. Nothing here needs action; these events are filtered out of all security checks and email alerts."
                    data-intermediate="ℹ️ P3 alerts are informational only — not an issue. These are typically DNS queries, ET POLICY notices, common protocol scans, or device chatter that Suricata flags by convention. They do not represent threats and do not require any action. The watchdog, AI analysis, and auto-quarantine pipelines all ignore P3."
                    data-pro="P3: informational. ET POLICY, DNS queries, protocol-scan signatures. Not actionable; excluded from watchdog, AI analysis, and quarantine pipelines.">ℹ️ P3 alerts are informational only — not an issue. These are typically DNS queries, ET POLICY notices, common protocol scans, or device chatter that Suricata flags by convention. They do not represent threats and do not require any action. The watchdog, AI analysis, and auto-quarantine pipelines all ignore P3.</span>
            </div>
            <div style="margin-top:15px;background:#1a0d00;border:1px solid #ff8800;border-radius:8px;padding:12px">
                <h3 style="color:#ff8800;margin:0 0 10px 0;font-size:1em"><span class="tier-text"
                    data-beginner="🔎 Suspicious Activity — Needs Your Decision"
                    data-intermediate="🔎 Review Queue — HIGH Risk Pending"
                    data-pro="🔎 Review Queue (HIGH, unresolved)">🔎 Review Queue — HIGH Risk Pending</span></h3>
                <table>
                    <thead><tr>
                        <th style="color:#ff8800">Time</th>
                        <th style="color:#ff8800">Rule</th>
                        <th style="color:#ff8800">Source IP</th>
                        <th style="color:#ff8800">Classification</th>
                        <th style="color:#ff8800;text-align:center">Seen</th>
                        <th style="color:#ff8800"></th>
                    </tr></thead>
                    <tbody id="reviewQueueRows">
                    {review_queue_html}
                    </tbody>
                </table>
            </div>
            <h3 style="color:#ffaa00;margin-top:15px"><span class="tier-text"
                data-beginner="⚠️ Active Threats — These Need Your Attention"
                data-intermediate="⚠️ Alerts Requiring Attention"
                data-pro="⚠️ Active P1/P2">⚠️ Alerts Requiring Attention</span></h3>
            <table>
                <thead><tr><th>Priority</th><th>Time</th><th>Alert</th><th>Source IP</th><th></th></tr></thead>
                <tbody id="alertsRows">
                {alerts_html}
                </tbody>
            </table>
            </div><!-- end section-firewall-body -->
        </div>

        <div class="card full-width" id="section-devices">
            <h2 style="cursor:pointer" onclick="toggleSection('devices')" data-section-badge="0">
                <span class="section-chevron" id="chevron-devices">▼</span>
                🖥️ <span class="tier-text" data-beginner="Devices on Your Network" data-intermediate="Network Devices" data-pro="Devices">Network Devices</span>
                <span class="section-badge" id="badge-devices"></span>
                <span style="float:right;font-size:0.8em;color:#ccc" onclick="event.stopPropagation()"><span class="tier-text" data-beginner="✅ You trust this device &nbsp; ❓ Not yet verified" data-intermediate="✅ Trusted &nbsp; ❓ Unverified" data-pro="✅ Trusted ❓ Unknown">✅ Trusted &nbsp; ❓ Unverified</span></span>
            </h2>
            <div id="section-devices-body">
            <table class="devices-table">
                <thead><tr><th>IP</th><th>Friendly Name</th><th>Type</th><th>MAC</th><th>Trust</th></tr></thead>
                <tbody id="devicesRows">
                {devices_html}
                </tbody>
            </table>
            </div><!-- end section-devices-body -->
        </div>

        <div id="moduleCardsContainer" style="display:contents">
        {module_cards_html}
        </div>
    </div>

    <!-- Alert Modal -->
     shared with settings_page(). Removed from this template 2026-07-31. -->

    <div class="modal" id="alertModal">
        <div class="modal-content" style="max-height:85vh;overflow-y:auto">
            <h3>🔍 Nemesis AI Analysis</h3>
            <div id="modalContent">Analyzing...</div>
            <div style="margin-top:15px">
                <button class="btn btn-block" onclick="takeAction('block')" id="btnBlock">🚫 Block IP</button>
                <button class="btn btn-monitor" onclick="unblockIp()" id="btnUnblock">🔓 Unblock IP</button>
                <button class="btn btn-ignore" onclick="takeAction('ignore')" id="btnIgnore">✓ Ignore Rule</button>
                <button class="btn btn-monitor" onclick="takeAction('monitor')" id="btnMonitor">👁 Monitor</button>
                <button class="btn btn-report" id="btnReport" onclick="reportAbuse()" style="display:none">🚨 Report to AbuseIPDB</button>
                <button class="btn btn-close" onclick="closeModal()">✕ Close</button>
            </div>
            <!-- Chat host. The widget itself is a single page-wide instance
                 injected by ai_engine's get_chat_js(); nemChatAttach() moves it
                 in here when an alert is opened. Do NOT embed the widget markup
                 here again -- see _chat_widget_markup() for the duplicate-id
                 collision that caused. -->
            <div id="_alertChatHost"></div>
            <div id="alertNotesSection" style="display:none;margin-top:20px;border-top:1px solid #333;padding-top:15px">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
                    <strong style="color:#00d4ff;font-size:0.95em">
                        <span class="tier-text"
                              data-beginner="Your Notes for this Alert Type"
                              data-intermediate="Admin Notes (this rule)"
                              data-pro="Notes">Admin Notes</span>
                    </strong>
                    <button onclick="loadRelatedNotes()" style="background:transparent;border:1px solid #555;color:#ccc;padding:3px 8px;cursor:pointer;border-radius:3px;font-size:0.8em">
                        <span class="tier-text"
                              data-beginner="Find notes from the same source IP"
                              data-intermediate="Find Related Notes"
                              data-pro="Related Notes">Find Related Notes</span>
                    </button>
                </div>
                <div id="notesList" style="margin-bottom:12px;font-size:0.85em;color:#ccc"></div>
                <div id="relatedNotesList" style="display:none;margin-bottom:12px;border-top:1px solid #222;padding-top:10px"></div>
                <div>
                    <textarea id="noteInput" placeholder="Add a note…" rows="3"
                        style="width:100%;background:#0d1117;border:1px solid #333;color:#eee;padding:8px;border-radius:4px;font-size:0.85em;resize:vertical;box-sizing:border-box"></textarea>
                    <div style="margin-top:6px;display:flex;gap:8px;align-items:center">
                        <button onclick="addNote()"
                            style="background:#00d4ff;color:#1a1a2e;border:none;padding:5px 14px;cursor:pointer;border-radius:3px;font-weight:bold">
                            <span class="tier-text"
                                  data-beginner="Save Note"
                                  data-intermediate="Add Note"
                                  data-pro="Add">Add Note</span>
                        </button>
                        <span id="noteStatus" style="font-size:0.8em;color:#ccc"></span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Hardware Stats Modal -->
    <div class="modal" id="hwModal">
        <div class="hw-modal-content">
            <button class="hw-close-x" onclick="closeHwModal()" title="Close (Esc)">✕</button>
            <h3 style="color:#00d4ff;margin-top:0">🌡️ <span class="tier-text" data-beginner="Hardware History — last 24 hours" data-intermediate="Hardware — last 24 hours" data-pro="Hardware 24h">Hardware — last 24 hours</span></h3>
            <div id="hwModalStatus" style="color:#ccc;font-size:0.85em">Loading…</div>
            <div class="chart-box"><h4><span class="tier-text" data-beginner="Temperatures — how hot each component is running (°C)" data-intermediate="Temperatures (°C)" data-pro="Temps °C">Temperatures (°C)</span></h4><canvas id="chartTemp" height="120"></canvas></div>
            <div class="chart-box"><h4><span class="tier-text" data-beginner="Fan Speeds — higher RPM = better cooling" data-intermediate="Fan Speeds (RPM)" data-pro="Fans RPM">Fan Speeds (RPM)</span></h4><canvas id="chartFans" height="120"></canvas></div>
            <div class="chart-box"><h4><span class="tier-text" data-beginner="CPU &amp; RAM Usage (%)" data-intermediate="CPU &amp; RAM (%)" data-pro="CPU/RAM %">CPU &amp; RAM (%)</span></h4><canvas id="chartUsage" height="120"></canvas></div>
            <div class="chart-box"><h4><span class="tier-text" data-beginner="Disk &amp; Network activity (MB per 5 minutes)" data-intermediate="Disk &amp; Network (MB / 5 min)" data-pro="Disk/Net MB/5m">Disk &amp; Network (MB / 5 min)</span></h4><canvas id="chartIo" height="120"></canvas></div>
            <div class="chart-box"><h4><span class="tier-text" data-beginner="System Health Score over time (100% = fully healthy)" data-intermediate="System Health Score (24h)" data-pro="Health % 24h">System Health Score (24h)</span></h4><canvas id="chartHealth" height="120"></canvas></div>
            <div style="text-align:right">
                <button class="btn btn-close" onclick="closeHwModal()">✕ Close</button>
            </div>
        </div>
    </div>

    <!-- Per-sensor history popup -->
    <div class="modal" id="sensorPopupModal" onclick="if(event.target.id==='sensorPopupModal')closeSensorPopup()">
        <div class="sensor-popup-modal">
            <button class="hw-close-x" onclick="closeSensorPopup()" title="Close (Esc)">✕</button>
            <h3 id="sensorPopupTitle" style="color:#00d4ff;margin-top:0"></h3>
            <div id="sensorNotificationBar"></div>
            <div id="sensorThrottleBanner"></div>
            <div id="sensorAnomalyBanner"></div>
            <div style="margin:10px 0 14px 0">
                <button class="sensor-range-btn" onclick="switchSensorRange('1h')">1h</button>
                <button class="sensor-range-btn" onclick="switchSensorRange('6h')">6h</button>
                <button class="sensor-range-btn active" onclick="switchSensorRange('24h')">24h</button>
                <button class="sensor-range-btn" onclick="switchSensorRange('7d')">7d</button>
                <button class="sensor-range-btn" onclick="switchSensorRange('30d')">30d</button>
                <span id="sensorPopupStatus" style="margin-left:12px;color:#bbb;font-size:0.8em"></span>
            </div>
            <div class="chart-box" style="margin-bottom:10px">
                <canvas id="sensorPopupChart" height="140"></canvas>
            </div>
            <div id="sensorAnomalyLink" style="display:none;margin-top:8px">
                <a href="#" onclick="openProcessModal(); return false;"
                   style="color:#ffaa00;font-size:0.85em;text-decoration:none">
                    ⚠ What was running? (<span id="sensorAnomalyCount">0</span> anomalous events)
                </a>
            </div>
            <div style="text-align:right;margin-top:14px">
                <button class="btn btn-close" onclick="closeSensorPopup()">✕ Close</button>
            </div>
        </div>
    </div>

    <!-- "What was running?" process detail popup -->
    <div class="modal" id="processModal" onclick="if(event.target.id==='processModal')closeProcessModal()">
        <div class="process-modal">
            <button class="hw-close-x" onclick="closeProcessModal()" title="Close (Esc)">✕</button>
            <h3 style="color:#ffaa00;margin-top:0">⚠ Anomaly Detail — What was running?</h3>
            <div id="processModalBody" style="color:#ccc;font-size:0.85em">Loading…</div>
            <div style="text-align:right;margin-top:12px">
                <button class="btn btn-close" onclick="closeProcessModal()">✕ Close</button>
            </div>
        </div>
    </div>

    <!-- 24h Alert Breakdown Modal -->
    <div class="modal" id="alertBreakdownModal">
        <div class="hw-modal-content">
            <button class="hw-close-x" onclick="closeAlertBreakdownModal()" title="Close (Esc)">✕</button>
            <h3 style="color:#00d4ff;margin-top:0"><span class="tier-text" data-beginner="🛠️ What triggered alerts in the last 24 hours?" data-intermediate="🛠️ 24h System Alert Breakdown" data-pro="🛠️ 24h Alerts">🛠️ 24h System Alert Breakdown</span></h3>
            <div id="alertBreakdownBody" style="color:#ccc;font-size:0.9em">Loading…</div>
            <div style="text-align:right;margin-top:10px">
                <button class="btn btn-close" onclick="closeAlertBreakdownModal()">✕ Close</button>
            </div>
        </div>
    </div>

    <!-- Health Score Breakdown Modal -->
    <div class="modal" id="healthModal">
        <div class="hw-modal-content">
            <button class="hw-close-x" onclick="closeHealthModal()" title="Close (Esc)">✕</button>
            <h3 style="color:#00d4ff;margin-top:0"><span class="tier-text" data-beginner="💚 How healthy is your system right now?" data-intermediate="💚 System Health Score" data-pro="💚 Health Score">💚 System Health Score</span></h3>
            <div id="healthModalBody" style="color:#ccc;font-size:0.9em">Loading…</div>
            <div style="text-align:right;margin-top:10px">
                <button class="btn btn-close" onclick="closeHealthModal()">✕ Close</button>
            </div>
        </div>
    </div>

    <!-- Hardware Alert Detail Modal -->
    <div class="modal" id="hwAlertDetailModal" onclick="if(event.target.id==='hwAlertDetailModal')closeHwAlertDetailModal()">
        <div class="hw-alert-detail-modal">
            <button class="hw-close-x" onclick="closeHwAlertDetailModal()" title="Close (Esc)">✕</button>
            <h3 id="hwAlertDetailTitle">Hardware Alert</h3>
            <div id="hwAlertDetailBody"></div>
            <div id="hwAlertNotesSection" style="display:none;margin-top:20px;border-top:1px solid #333;padding-top:15px">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
                    <strong style="color:#00d4ff;font-size:0.95em">
                        <span class="tier-text"
                              data-beginner="Your Notes for this Alert Type"
                              data-intermediate="Admin Notes (this alert key)"
                              data-pro="Notes">Admin Notes</span>
                    </strong>
                    <button onclick="loadHwRelatedNotes()" style="background:transparent;border:1px solid #555;color:#ccc;padding:3px 8px;cursor:pointer;border-radius:3px;font-size:0.8em">
                        <span class="tier-text"
                              data-beginner="Find notes from the same source"
                              data-intermediate="Find Related Notes"
                              data-pro="Related Notes">Find Related Notes</span>
                    </button>
                </div>
                <div id="hwNotesList" style="margin-bottom:12px;font-size:0.85em;color:#ccc"></div>
                <div id="hwRelatedNotesList" style="display:none;margin-bottom:12px;border-top:1px solid #222;padding-top:10px"></div>
                <div>
                    <textarea id="hwNoteInput" placeholder="Add a note…" rows="3"
                        style="width:100%;background:#0d1117;border:1px solid #333;color:#eee;padding:8px;border-radius:4px;font-size:0.85em;resize:vertical;box-sizing:border-box"></textarea>
                    <div style="margin-top:6px;display:flex;gap:8px;align-items:center">
                        <button onclick="addHwNote()"
                            style="background:#00d4ff;color:#1a1a2e;border:none;padding:5px 14px;cursor:pointer;border-radius:3px;font-weight:bold">
                            <span class="tier-text"
                                  data-beginner="Save Note"
                                  data-intermediate="Add Note"
                                  data-pro="Add">Add Note</span>
                        </button>
                        <span id="hwNoteStatus" style="font-size:0.8em;color:#ccc"></span>
                    </div>
                </div>
            </div>
            <div style="text-align:right;margin-top:12px">
                <button class="btn btn-close" onclick="closeHwAlertDetailModal()">✕ Close</button>
            </div>
        </div>
    </div>

    <!-- VPN Status Modal -->
    <div class="modal" id="vpnModal" onclick="if(event.target.id==='vpnModal')closeVpnModal()">
        <div class="modal-content">
            <h3>🔒 VPN Status</h3>
            <div id="vpnModalContent" style="min-height:80px">Loading…</div>
            <div style="margin-top:15px" id="vpnModalActions">
                <button class="btn btn-monitor" onclick="vpnAction('connect')">🔄 Reconnect</button>
                <button class="btn btn-ignore" onclick="vpnAction('disconnect')">⏹ Disconnect</button>
                <button class="btn btn-close" onclick="closeVpnModal()">✕ Close</button>
            </div>
        </div>
    </div>

    <!-- Firewall Counter Drilldown Modal -->
    <div class="modal" id="fwDrillModal" onclick="if(event.target.id==='fwDrillModal')closeFwDrilldown()">
        <div class="hw-modal-content" style="max-width:1100px">
            <button class="hw-close-x" onclick="closeFwDrilldown()" title="Close (Esc)">✕</button>
            <h3 style="color:#00d4ff;margin-top:0" id="fwDrillTitle">Loading…</h3>
            <div id="fwDrillSubtitle" style="color:#ccc;font-size:0.85em;margin-bottom:12px"></div>
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;flex-wrap:wrap">
                <span style="color:#bbb;font-size:0.85em" id="fwDrillPagInfo"></span>
                <span style="flex:1"></span>
                <label style="color:#ccc;font-size:0.85em">
                    <span class="tier-text"
                        data-beginner="Rows per page:"
                        data-intermediate="Per page:"
                        data-pro="Per page:">Per page:</span>
                    <input id="fwDrillPerPageInput" type="number" min="1" max="500" value="10"
                        style="width:60px;margin-left:4px;background:#0d1117;border:1px solid #333;color:#eee;padding:3px 6px;border-radius:4px"
                        onchange="fwSetPerPage(this.value)">
                </label>
            </div>
            <div id="fwDrillBody" style="overflow-x:auto">Loading…</div>
            <div id="fwDrillPagin" style="margin-top:12px;display:flex;gap:6px;flex-wrap:wrap;align-items:center"></div>
            <div style="text-align:right;margin-top:14px">
                <button class="btn btn-close" onclick="closeFwDrilldown()">✕ Close</button>
            </div>
        </div>
    </div>

    <!-- Device Edit Modal -->
    <div class="modal" id="deviceModal">
        <div class="modal-content">
            <h3>✏️ Edit Device</h3>
            <input type="hidden" id="editMac">
            <label>Friendly Name</label>
            <input type="text" id="editName">
            <label>Device Type</label>
            <select id="editType">
                <option>Router</option>
                <option>Switch</option>
                <option>Desktop</option>
                <option>Laptop</option>
                <option>Phone</option>
                <option>Tablet</option>
                <option>Smart Home</option>
                <option>Entertainment</option>
                <option>Security Camera</option>
                <option>Printer</option>
                <option>Unknown</option>
            </select>
            <label>Notes</label>
            <input type="text" id="editNotes">
            <label>
                <input type="checkbox" id="editTrusted" style="width:auto"> Trusted Device
            </label>
            <div style="margin-top:15px">
                <button class="btn btn-save" onclick="saveDevice()">💾 Save</button>
                <button class="btn btn-close" onclick="closeDeviceModal()">✕ Cancel</button>
            </div>
        </div>
    </div>

    <script>
        // ── Pi-hole reset times (shown inline next to card title) ─────────────
        function _initPhResetTimes() {{
            var now = new Date();
            var nextUtcMidnight = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1));
            var localStr = nextUtcMidnight.toLocaleTimeString(undefined, {{hour: '2-digit', minute: '2-digit', timeZoneName: 'short'}});
            var el = document.getElementById('phResetTimes');
            if (el) el.textContent = '— resets UTC 00:00 / local ' + localStr;
        }}
        document.addEventListener('DOMContentLoaded', _initPhResetTimes);

        // ── Collapsible sections ───────────────────────────────────────────────
        var _sectionIds = ['hw', 'firewall', 'devices', 'anomaly', 'tickets', 'malware'];

        function toggleSection(id) {{
            var body = document.getElementById('section-' + id + '-body');
            var chevron = document.getElementById('chevron-' + id);
            if (!body) return;
            var collapsed = body.style.display === 'none';
            body.style.display = collapsed ? '' : 'none';
            if (chevron) chevron.textContent = collapsed ? '▼' : '▶';
            localStorage.setItem('sec-collapsed-' + id, collapsed ? '0' : '1');
            _updateBadge(id);
        }}

        function _getBadgeCount(id) {{
            var h2 = document.querySelector('#section-' + id + ' > h2');
            if (!h2) return 0;
            var base = parseInt(h2.getAttribute('data-section-badge') || '0', 10);
            // Live-update from DOM for sections we can read
            if (id === 'firewall') {{
                var p1 = parseInt((document.getElementById('cntP1') || {{}}).textContent || '0', 10);
                var p2 = parseInt((document.getElementById('cntP2') || {{}}).textContent || '0', 10);
                base = p1 + p2;
            }} else if (id === 'hw') {{
                var alerts = document.querySelectorAll('#hwAlertsList .hw-alert-row');
                base = alerts.length || base;
            }}
            return base;
        }}

        function _updateBadge(id) {{
            var body = document.getElementById('section-' + id + '-body');
            var badge = document.getElementById('badge-' + id);
            if (!badge) return;
            var collapsed = body && body.style.display === 'none';
            if (!collapsed) {{ badge.style.display = 'none'; return; }}
            var count = _getBadgeCount(id);
            if (count > 0) {{
                badge.textContent = count + ' new';
                badge.style.display = 'inline-block';
                badge.style.background = (id === 'firewall') ? '#ff4444' : '#ff8800';
            }} else {{
                badge.style.display = 'none';
            }}
        }}

        function _initCollapseSections() {{
            _sectionIds.forEach(function(id) {{
                var stored = localStorage.getItem('sec-collapsed-' + id);
                if (stored === '1') {{
                    var body = document.getElementById('section-' + id + '-body');
                    var chevron = document.getElementById('chevron-' + id);
                    if (body) {{ body.style.display = 'none'; }}
                    if (chevron) chevron.textContent = '▶';
                    _updateBadge(id);
                }}
            }});
        }}

        // Also update badges when hw alerts list is updated
        function _refreshSectionBadges() {{
            _sectionIds.forEach(function(id) {{
                _updateBadge(id);
            }});
        }}

        var currentRuleId = "";
        var currentSrcIp = "";

        function escapeHtml(s) {{
            if (s === null || s === undefined) return "";
            return String(s).replace(/[&<>"']/g, function(c) {{
                return {{"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;"}}[c];
            }});
        }}

        function countryFlag(cc) {{
            if (!cc || cc.length !== 2) return "";
            return cc.toUpperCase().replace(/./g, function(c) {{
                return String.fromCodePoint(127397 + c.charCodeAt(0));
            }});
        }}

        function threatColor(level) {{
            if (level === "CRITICAL") return "#ff0000";
            if (level === "HIGH") return "#ff4444";
            if (level === "MEDIUM") return "#ffaa00";
            return "#00ff88";
        }}

        function renderEnrichment(enr) {{
            if (!enr) return "";
            var flag = countryFlag(enr.country);
            var loc = [enr.city, enr.country].filter(Boolean).map(escapeHtml).join(", ") || "Unknown location";
            var isp = escapeHtml(enr.isp || enr.org || "Unknown ISP");
            var level = enr.threat_level || "LOW";
            var color = threatColor(level);
            var score = (enr.abuse_confidence_score == null) ? "n/a" : enr.abuse_confidence_score;
            var reports = (enr.total_reports == null) ? 0 : enr.total_reports;
            var lastRep = enr.last_reported ? escapeHtml(enr.last_reported) : "never";
            var warnings = "";
            if (enr.is_tor) warnings += '<p class="warn-tor">⚠ TOR exit node</p>';
            if (enr.is_vpn) warnings += '<p class="warn-vpn">⚠ VPN / Proxy / Hosting</p>';
            return `
                <div class="enrichment-card">
                    <h4>🌍 IP Intelligence — ${{escapeHtml(enr.ip)}}</h4>
                    <p><span class="flag">${{flag}}</span> <strong>${{loc}}</strong></p>
                    <p><strong>ISP:</strong> ${{isp}}</p>
                    <p><strong>Threat Level:</strong> <span style="color:${{color}};font-weight:bold">${{escapeHtml(level)}}</span></p>
                    <p><strong>Abuse Score:</strong> ${{escapeHtml(score)}}/100 &nbsp; <strong>Reports:</strong> ${{escapeHtml(reports)}} &nbsp; <strong>Last:</strong> ${{lastRep}}</p>
                    ${{warnings}}
                </div>
            `;
        }}

        var _currentNotesRuleId = null;
        var _notesPage = 0;
        var _allNotes = [];
        var _notesSortDesc = true;

        function _actionBadge(action) {{
            var colors = {{
                block:   "#ff4444", ignore: "#555", monitor: "#00d4ff",
                pending: "#ffaa00", none:   "#555"
            }};
            var labels = {{
                block:   tierText("Blocked — source IP is blocked", "Blocked",        "block"),
                ignore:  tierText("Ignored — alert suppressed",     "Ignored",        "ignore"),
                monitor: tierText("Monitoring — kept under watch",   "Monitoring",     "monitor"),
                pending: tierText("Pending Review — needs a decision","Pending Review","pending"),
                none:    tierText("No action taken yet",             "No action",      "none"),
            }};
            var a = action || "none";
            return "<span style='display:inline-block;padding:2px 8px;border-radius:3px;"
                + "background:#0d1117;border:1px solid " + (colors[a]||"#555") + "33;"
                + "color:" + (colors[a]||"#555") + ";font-size:0.78em;font-weight:bold'>"
                + (labels[a] || a) + "</span>";
        }}

        function _tierExplanation(data) {{
            var seen = data.times_seen || 1;
            var action = data.action || "none";
            var risk   = data.risk_level || "UNKNOWN";
            var b = 'This alert has been seen ' + seen + ' time(s) and is currently marked as "' + action + '". Risk level: ' + risk + '.';
            var m = 'Seen ' + seen + '×. Action: ' + action + '. Risk: ' + risk + '.';
            var p = "seen=" + seen + " action=" + action + " risk=" + risk;
            return "<div style='font-size:0.82em;color:#bbb;margin:4px 0 8px 0;border-left:2px solid #1e2d4e;padding:4px 8px'>"
                + tierText(b, m, p) + "</div>";
        }}

        function viewAlert(ruleId, rawAlert) {{
            currentRuleId = ruleId;
            currentSrcIp = "";
            document.getElementById("btnReport").style.display = "none";
            document.getElementById("alertModal").style.display = "block";
            document.getElementById("modalContent").innerHTML =
                "<p>🤖 " + tierText(
                    "Nemesis AI is checking this alert — this takes a few seconds…",
                    "Nemesis AI analyzing...",
                    "Analyzing…"
                ) + "</p>";
            loadNotes(ruleId);
            if (window.nemChatAttach) {{
                nemChatAttach(document.getElementById("_alertChatHost"), "alert", ruleId);
            }}
            fetch("/api/analyze/" + ruleId + "?raw=" + encodeURIComponent(rawAlert))
                .then(r => r.json())
                .then(data => {{
                    currentSrcIp = data.src_ip || "";
                    var seen = data.times_seen || 1;

                    // 1. Prior action badge
                    var actionBadge = _actionBadge(data.action);

                    // 2. Previous instances row (only when seen > 1)
                    var prevInstances = "";
                    if (seen > 1) {{
                        var lastTs = (data.last_seen || "").substring(0, 16).replace("T", " ");
                        prevInstances = "<details style='margin:4px 0 8px;font-size:0.82em'>"
                            + "<summary style='cursor:pointer;color:#ccc'>"
                            + tierText(
                                "Seen " + seen + " times — expand for details",
                                "Previous instances (" + seen + ")",
                                seen + "× seen"
                              )
                            + "</summary>"
                            + "<div style='color:#bbb;padding:4px 0 0 10px'>"
                            + tierText(
                                "This alert has triggered " + seen + " times. Last occurrence: " + (lastTs||"unknown") + ".",
                                "Count: " + seen + " · Last seen: " + (lastTs||"—"),
                                "n=" + seen + " last=" + (lastTs||"?")
                              )
                            + "</div></details>";
                    }}

                    // 3. AI status indicator
                    var aiStatus = data.cached
                        ? " <span style='color:#ccc;font-size:0.78em'>(" + tierText("previously analysed — from cache", "cached result", "cached") + ")</span>"
                        : " <span style='color:#00ff88;font-size:0.78em'>(" + tierText("freshly analysed by AI just now", "AI analyzed", "fresh") + ")</span>";

                    var riskColor = data.risk_level === "HIGH" ? "#ff4444" : data.risk_level === "MEDIUM" ? "#ffaa00" : "#00ff88";
                    var riskLabel = tierText(
                        {{HIGH:"HIGH — Investigate this now", MEDIUM:"MEDIUM — Worth reviewing", LOW:"LOW — Likely safe"}}[data.risk_level] || data.risk_level,
                        data.risk_level || "UNKNOWN",
                        data.risk_level || "?"
                    );

                    // 5. Tiered explanation block
                    var tierExpl = _tierExplanation(data);

                    document.getElementById("modalContent").innerHTML =
                        // action badge at top
                        "<div style='margin-bottom:8px'>" + actionBadge + "</div>"
                        + tierExpl
                        + prevInstances
                        + "<p><strong>" + tierText("Threat Level","Risk Level","Risk") + ":</strong>"
                        + " <span style='color:" + riskColor + "'>" + escapeHtml(riskLabel) + "</span>" + aiStatus + "</p>"
                        + "<p><strong>" + tierText("What is this?","Explanation","Detail") + ":</strong> " + escapeHtml(data.explanation || "No explanation available") + "</p>"
                        + "<p><strong>" + tierText("What should I do?","Recommended Action","Action") + ":</strong> " + escapeHtml(data.recommended_action || "Monitor") + "</p>"
                        + "<p><strong>" + tierText("Why?","Reason","Reason") + ":</strong> " + escapeHtml(data.reason || "") + "</p>"
                        + renderEnrichment(data.enrichment);
                    if (data.enrichment && data.enrichment.abuse_confidence_score !== null && currentSrcIp) {{
                        document.getElementById("btnReport").style.display = "inline-block";
                    }}
                }})
                .catch(e => {{
                    document.getElementById("modalContent").innerHTML = "<p style='color:#ff4444'>Error: " + escapeHtml(e) + "</p>";
                }});
        }}

        /* ── Privileged firewall actions ──────────────────────────────
           Every ufw change is performed by nemesis-fwd, which verifies the
           admin password itself against the stored hash. This page cannot
           assert "already verified" — there is no such field to send. */
        /* In-page modal with a real masked field. Deliberately NOT
           window.prompt(): that renders the password in plaintext as it is
           typed, which would undercut the credential verification this whole
           path exists to enforce. Returns a Promise so callers can await it. */
        /* fwPrompt / fwCredOk / fwCredCancel / fwHandleError now live in
           the same prompt for Settings-save and Restart. */

        /* Best-effort acceleration ONLY. The server enforces a short idle
           timeout regardless of whether this ever fires; a hostile or
           non-cooperating client simply does not send it.
           Honest limitation: browsers expose no true "screen locked" event.
           Locking the screen does trigger this (the browser loses focus), but
           so does switching tabs — an accepted tradeoff that errs toward
           prompting more often. */
        function fwDropCredential() {{
            try {{
                navigator.sendBeacon("/api/firewall/credential/drop");
            }} catch (e) {{ /* never block page teardown on this */ }}
        }}
        document.addEventListener("visibilitychange", function () {{
            if (document.visibilityState === "hidden") fwDropCredential();
        }});
        window.addEventListener("blur", fwDropCredential);

        function takeAction(action) {{
            var url = "/api/action/" + currentRuleId + "/" + action;
            if (action === "block" && currentSrcIp) url += "?ip=" + encodeURIComponent(currentSrcIp);
            var body = {{}};
            var pwPromise = (action === "block")
                /* Writes always require a fresh credential — never cached. */
                ? fwPrompt("block " + (currentSrcIp || "this source"))
                : Promise.resolve("");
            pwPromise.then(function (pw) {{
              if (action === "block") {{
                  if (!pw) return;
                  body.password = pw;
              }}
              fetch(url, {{
                method: "POST",
                headers: {{"Content-Type": "application/json"}},
                body: JSON.stringify(body)
              }}).then(r => r.json()).then(data => {{
                  if (data && data.error) {{ fwHandleError(data, "Action failed"); return; }}
                  closeModal();
                  location.reload();
              }}).catch(e => alert("Error: " + e));
            }});
        }}

        /* Symmetric counterpart to takeAction('block'). Deliberately placed on the
           same modal: the block is applied from here, so the undo belongs here too
           rather than somewhere the user has to go hunting for. */
        function unblockIp() {{
            if (!currentSrcIp) {{ alert("No source IP on this alert to unblock."); return; }}
            /* Same rule as block — an unblock is a firewall write, so it takes a
               fresh credential and never a cached one. */
            fwPrompt("unblock " + currentSrcIp).then(function (pw) {{
                if (!pw) return;
                fetch("/api/firewall/unblock", {{
                    method: "POST",
                    headers: {{"Content-Type": "application/json"}},
                    body: JSON.stringify({{ip: currentSrcIp, rule_id: currentRuleId, password: pw}})
                }}).then(r => r.json()).then(data => {{
                    if (data && data.error) {{ fwHandleError(data, "Unblock failed"); return; }}
                    if (data && data.warning) {{ alert("Unblocked " + currentSrcIp + " — note: " + data.warning); }}
                    closeModal();
                    location.reload();
                }}).catch(e => alert("Error: " + e));
            }});
        }}

        function reportAbuse() {{
            if (!currentSrcIp) {{ alert("No source IP to report"); return; }}
            if (!confirm("Report " + currentSrcIp + " to AbuseIPDB?")) return;
            fetch("/api/report/" + currentRuleId + "?ip=" + encodeURIComponent(currentSrcIp))
                .then(r => r.json())
                .then(d => {{
                    if (d.success) {{
                        alert("Reported to AbuseIPDB. Current confidence score: " + (d.abuse_confidence_score == null ? "unknown" : d.abuse_confidence_score));
                    }} else {{
                        alert("Report failed: " + (d.error || "unknown error"));
                    }}
                }})
                .catch(e => alert("Error: " + e));
        }}

        function closeModal() {{
            document.getElementById("alertModal").style.display = "none";
            document.getElementById("btnReport").style.display = "none";
            nemChatClose();
            document.getElementById("alertNotesSection").style.display = "none";
            document.getElementById("relatedNotesList").style.display = "none";
            document.getElementById("noteInput").value = "";
            document.getElementById("noteStatus").textContent = "";
            _currentNotesRuleId = null;
            _allNotes = [];
            _notesPage = 0;
        }}

        function loadNotes(ruleId) {{
            _currentNotesRuleId = ruleId;
            _notesPage = 0;
            _allNotes = [];
            var sec = document.getElementById("alertNotesSection");
            sec.style.display = "block";
            document.getElementById("relatedNotesList").style.display = "none";
            document.getElementById("noteStatus").textContent = "";
            document.getElementById("notesList").innerHTML =
                "<span style='color:#bbb;font-size:0.85em'>Loading notes…</span>";
            fetch("/api/tickets/notes/" + encodeURIComponent(ruleId))
                .then(function(r) {{ return r.json(); }})
                .then(function(notes) {{
                    _allNotes = notes;
                    _renderNotesList();
                }})
                .catch(function() {{
                    document.getElementById("notesList").innerHTML =
                        "<span style='color:#ff4444;font-size:0.85em'>Failed to load notes</span>";
                }});
        }}

        function _renderNotesList() {{
            var el = document.getElementById("notesList");
            var perPage = 5;
            var visible = _notesSortDesc
                ? _allNotes.slice(0, (_notesPage + 1) * perPage)
                : _allNotes.slice().reverse().slice(0, (_notesPage + 1) * perPage);
            if (_allNotes.length === 0) {{
                el.innerHTML = "<span style='color:#bbb;font-size:0.85em'>" +
                    tierText("No notes yet. Add the first one below.", "No notes yet.", "—") + "</span>";
                return;
            }}
            var sortBtn = "<button onclick='_toggleNoteSort()' style='background:transparent;border:none;color:#ccc;cursor:pointer;font-size:0.75em;padding:0;float:right'>" +
                (_notesSortDesc ? "↓ Newest first" : "↑ Oldest first") + "</button>";
            var items = visible.map(function(n) {{
                return '<div style="border-left:2px solid #333;padding:6px 10px;margin-bottom:8px">' +
                    '<div style="color:#ddd;font-size:0.85em;white-space:pre-wrap">' + escapeHtml(n.note) + '</div>' +
                    '<div style="color:#bbb;font-size:0.75em;margin-top:3px">' +
                    escapeHtml(n.author) + ' · ' + escapeHtml(n.created_at) + '</div>' +
                    '</div>';
            }}).join("");
            var moreCount = _allNotes.length - visible.length;
            var moreBtn = moreCount > 0
                ? '<button onclick="_showMoreNotes()" style="background:transparent;border:1px solid #444;color:#ccc;padding:3px 8px;cursor:pointer;border-radius:3px;font-size:0.8em">Show ' + Math.min(perPage, moreCount) + ' more…</button>'
                : "";
            el.innerHTML = sortBtn + items + moreBtn;
        }}

        function _toggleNoteSort() {{
            _notesSortDesc = !_notesSortDesc;
            _notesPage = 0;
            _renderNotesList();
        }}

        function _showMoreNotes() {{
            _notesPage++;
            _renderNotesList();
        }}

        function addNote() {{
            var text = (document.getElementById("noteInput").value || "").trim();
            if (!text || !_currentNotesRuleId) {{ return; }}
            var status = document.getElementById("noteStatus");
            status.style.color = "#aaa";
            status.textContent = tierText("Saving…", "Saving…", "…");
            fetch("/api/tickets/notes/" + encodeURIComponent(_currentNotesRuleId), {{
                method: "POST",
                headers: {{"Content-Type": "application/json"}},
                body: JSON.stringify({{note: text}})
            }})
            .then(function(r) {{ return r.json(); }})
            .then(function(d) {{
                if (d.ok) {{
                    document.getElementById("noteInput").value = "";
                    status.style.color = "#00ff88";
                    status.textContent = tierText("Note saved", "Saved", "✓");
                    loadNotes(_currentNotesRuleId);
                    setTimeout(function() {{ status.textContent = ""; }}, 2000);
                }} else {{
                    status.style.color = "#ff4444";
                    status.textContent = "Error: " + escapeHtml(d.error || "unknown");
                }}
            }})
            .catch(function() {{
                status.style.color = "#ff4444";
                status.textContent = "Error saving note";
            }});
        }}

        function loadRelatedNotes() {{
            if (!_currentNotesRuleId) {{ return; }}
            var el = document.getElementById("relatedNotesList");
            el.style.display = "block";
            el.innerHTML = "<span style='color:#ccc;font-size:0.85em'>Searching for related notes…</span>";
            fetch("/api/tickets/related/" + encodeURIComponent(_currentNotesRuleId))
                .then(function(r) {{ return r.json(); }})
                .then(function(notes) {{
                    if (notes.length === 0) {{
                        el.innerHTML = "<div style='color:#bbb;font-size:0.85em'>" +
                            tierText(
                                "No notes found for other alerts from the same source IP.",
                                "No related notes found.",
                                "No related notes."
                            ) + "</div>";
                        return;
                    }}
                    var header = "<div style='color:#ccc;font-size:0.75em;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px'>" +
                        tierText("Notes from other alerts by the same source", "Related Notes (same source IP)", "Related Notes") +
                        "</div>";
                    var items = notes.map(function(n) {{
                        return '<div style="border-left:2px solid #444;padding:6px 10px;margin-bottom:8px">' +
                            '<div style="color:#bbb;font-size:0.75em;margin-bottom:2px">' + escapeHtml(n.rule_name || n.rule_id) + '</div>' +
                            '<div style="color:#ddd;font-size:0.85em;white-space:pre-wrap">' + escapeHtml(n.note) + '</div>' +
                            '<div style="color:#bbb;font-size:0.75em;margin-top:3px">' +
                            escapeHtml(n.author) + ' · ' + escapeHtml(n.created_at) + '</div>' +
                            '</div>';
                    }}).join("");
                    el.innerHTML = header + items;
                }})
                .catch(function() {{
                    el.innerHTML = "<span style='color:#ff4444;font-size:0.85em'>Failed to load related notes</span>";
                }});
        }}

        function editDevice(mac, name, type) {{
            document.getElementById("editMac").value = mac;
            document.getElementById("editName").value = name;
            document.getElementById("editType").value = type;
            document.getElementById("deviceModal").style.display = "block";
        }}

        function saveDevice() {{
            var data = {{
                mac: document.getElementById("editMac").value,
                friendly_name: document.getElementById("editName").value,
                device_type: document.getElementById("editType").value,
                notes: document.getElementById("editNotes").value,
                trusted: document.getElementById("editTrusted").checked ? 1 : 0
            }};
            fetch("/api/update-device", {{
                method: "POST",
                headers: {{"Content-Type": "application/json"}},
                body: JSON.stringify(data)
            }}).then(r => r.json()).then(d => {{
                closeDeviceModal();
                location.reload();
            }});
        }}

        function closeDeviceModal() {{
            document.getElementById("deviceModal").style.display = "none";
        }}

        var hwCharts = {{}};

        function isP3Shown() {{
            var el = document.getElementById("showP3Toggle");
            return !!(el && el.checked);
        }}

        function applyP3Visibility(show) {{
            document.getElementById("p3Box").style.display = show ? "" : "none";
            document.getElementById("p3Note").style.display = show ? "" : "none";
        }}

        function toggleP3() {{
            var show = isP3Shown();
            try {{ localStorage.setItem("showP3", show ? "1" : "0"); }} catch (e) {{}}
            applyP3Visibility(show);
        }}

        (function initP3Toggle() {{
            var stored = null;
            try {{ stored = localStorage.getItem("showP3"); }} catch (e) {{}}
            var show = stored === "1";
            document.getElementById("showP3Toggle").checked = show;
            applyP3Visibility(show);
        }})();

        function fmtHw(v, suffix) {{
            return (v === null || v === undefined) ? "—" : v + suffix;
        }}

        // ── Fan section ───────────────────────────────────────────────────────
        function toggleFanSection() {{
            var grid = document.getElementById("fanDetailGrid");
            setFanSectionExpanded(grid.style.display === "none");
        }}
        function setFanSectionExpanded(expanded) {{
            var grid = document.getElementById("fanDetailGrid");
            var icon = document.getElementById("fanToggleIcon");
            grid.style.display = expanded ? "grid" : "none";
            icon.textContent = expanded ? "▼" : "▶";
            try {{ localStorage.setItem("fansExpanded", expanded ? "1" : "0"); }} catch(e) {{}}
        }}
        function renderFanSection(fans, cpuPct, fanStatus) {{
            fans = fans || [];
            fanStatus = fanStatus || {{}};
            var highLoad = cpuPct !== null && cpuPct !== undefined && cpuPct >= 40;
            var nActive = 0, nIdle = 0, nConcern = 0, nHidden = 0;
            var tiles = [];
            fans.forEach(function(f) {{
                var ukey = f.unique_key;
                // Fans with no status entry default to visible (safe fallback)
                var status = ukey ? (fanStatus[ukey] || {{}}) : {{}};
                var everActive = "ever_active" in status ? status.ever_active : true;
                var rpm = f.rpm;
                // Never-active fan at 0: hide entirely — presumed-empty header
                if (!everActive && (rpm === null || rpm === undefined || rpm <= 0)) {{
                    nHidden++;
                    return;
                }}
                var lbl = escapeHtml(String(f.label || "Fan"));
                var rpmText, cls;
                if (rpm === null || rpm === undefined) {{
                    rpmText = "—"; cls = "fan-rpm-idle"; nIdle++;
                }} else if (rpm > 200) {{
                    rpmText = rpm + " RPM"; cls = "fan-rpm-active"; nActive++;
                }} else if (rpm <= 50 && highLoad) {{
                    // Ever-active fan stopped under load — real concern
                    rpmText = rpm + " RPM"; cls = "fan-rpm-concern"; nConcern++;
                }} else {{
                    rpmText = rpm === 0 ? "0 RPM (idle)" : rpm + " RPM";
                    cls = "fan-rpm-idle"; nIdle++;
                }}
                var fanClickKey = ukey || lbl;
                var fanLabelStr = String(f.label || "Fan");
                tiles.push('<div class="fan-tile hw-clickable"' +
                           ' data-fkey="' + escapeHtml(fanClickKey) + '"' +
                           ' data-flabel="' + escapeHtml(fanLabelStr) + '"' +
                           ' onclick="openSensorPopupFan(this.dataset.fkey, this.dataset.flabel)"' +
                           ' title="Click for fan history"><div class="fan-tile-lbl" title="' + lbl + '">' + lbl +
                           '</div><div class="fan-tile-rpm ' + cls + '">' + rpmText + '</div></div>');
            }});
            var grid = document.getElementById("fanDetailGrid");
            if (grid) grid.innerHTML = tiles.join("");

            var visibleCount = nActive + nIdle + nConcern;
            var hiddenNote = nHidden > 0
                ? ' <span style="color:#bbb;font-size:0.9em">(' + nHidden + ' unused header' + (nHidden > 1 ? 's' : '') + ' not shown)</span>'
                : '';
            var el = document.getElementById("fanSummaryText");
            var summaryRow = document.getElementById("fanSummaryRow");

            if (nConcern > 0) {{
                // Alert state: row background turns red, text changes to urgent message
                if (summaryRow) summaryRow.classList.add("fan-alert");
                if (el) el.innerHTML =
                    '<span style="color:#ff4444;font-weight:bold">&#9888; ' + nConcern +
                    ' fan' + (nConcern > 1 ? 's' : '') + ' stopped under load</span>' +
                    ' <span style="color:#ff9999">— click to expand</span>' + hiddenNote;
            }} else {{
                // Normal state
                if (summaryRow) summaryRow.classList.remove("fan-alert");
                var parts = [];
                if (nActive > 0) parts.push('<span style="color:#00ff88;font-weight:bold">' + nActive + ' active</span>');
                if (nIdle   > 0) parts.push('<span style="color:#777">' + nIdle + ' idle</span>');
                if (el) el.innerHTML = 'Fans (' + visibleCount + '):&ensp;' +
                    (parts.length ? parts.join('&ensp;') : '<span style="color:#ccc">none configured</span>') +
                    hiddenNote;
            }}

            var dot = document.getElementById("fanStatusDot");
            if (dot) dot.style.background = nConcern > 0 ? "#ff4444"
                : nActive > 0 ? "#00ff88"
                : visibleCount > 0 ? "#ffaa00" : "#555";
        }}
        (function initFanSection() {{
            var stored = null;
            try {{ stored = localStorage.getItem("fansExpanded"); }} catch(e) {{}}
            setFanSectionExpanded(stored === "1");
            renderFanSection({hw_fans_js}, {hw_cpu_pct_js}, {fan_status_js});
        }})();

        // ── Hardware Alerts ───────────────────────────────────────────────
        var _hwAlertIcons = {{
            "cpu_temp": "🌡️", "ambient_temp": "🌡️", "nvme_temp": "💾",
            "gpu_temp": "🎮", "cpu_sustained_load": "⚡"
        }};
        function _hwAlertIcon(key) {{
            if (key.startsWith("fan_stopped/")) return "🌀";
            return _hwAlertIcons[key] || "⚠️";
        }}
        function _fmtTs(ts) {{
            if (!ts) return "—";
            var d = new Date(ts * 1000);
            return d.toLocaleString();
        }}

        var _currentHwAlerts = [];
        function renderHwAlerts(alerts) {{
            _currentHwAlerts = alerts || [];
            var el = document.getElementById("hwAlertsList");
            if (!el) return;
            if (!_currentHwAlerts.length) {{
                el.innerHTML = '<div class="hw-alert-empty">' + tierText(
                    '✓ All hardware operating normally — no problems detected',
                    '✓ No active hardware alerts',
                    '✓ No active HW alerts'
                ) + '</div>';
                return;
            }}
            el.innerHTML = _currentHwAlerts.map(function(a, i) {{
                var icon = _hwAlertIcon(a.alert_key);
                var sevClass = "hw-alert-sev-" + (a.severity || "HIGH");
                var since = _fmtTs(a.first_triggered_ts);
                return '<div class="hw-alert-row" onclick="openHwAlertDetailModal(' + i + ')">' +
                    '<span class="hw-alert-icon">' + icon + '</span>' +
                    '<span class="' + sevClass + '">' + (a.severity || "") + '</span>' +
                    '<span class="hw-alert-body">' +
                        '<div class="hw-alert-msg">' + (a.breach || "") + '</div>' +
                        '<div class="hw-alert-meta">Since ' + since + '</div>' +
                    '</span>' +
                    '<span style="color:#bbb;font-size:0.8em">▸</span>' +
                '</div>';
            }}).join("");
            _refreshSectionBadges();
        }}

        function openHwAlertDetailModal(idx) {{
            var a = _currentHwAlerts[idx];
            if (!a) return;
            var icon = _hwAlertIcon(a.alert_key);
            document.getElementById("hwAlertDetailTitle").textContent =
                icon + " " + (a.severity || "Alert") + " — Hardware Alert";
            document.getElementById("hwAlertDetailBody").innerHTML =
                '<div class="hw-alert-detail-field">' +
                    '<div class="hw-alert-detail-label">Condition</div>' +
                    '<div class="hw-alert-detail-value">' + (a.breach || "—") + '</div>' +
                '</div>' +
                '<div class="hw-alert-detail-field">' +
                    '<div class="hw-alert-detail-label">Recommendation</div>' +
                    '<div class="hw-alert-detail-value">' + (a.recommendation || "—") + '</div>' +
                '</div>' +
                '<div class="hw-alert-detail-field">' +
                    '<div class="hw-alert-detail-label">First triggered</div>' +
                    '<div class="hw-alert-detail-value">' + _fmtTs(a.first_triggered_ts) + '</div>' +
                '</div>' +
                '<div class="hw-alert-detail-field">' +
                    '<div class="hw-alert-detail-label">Last confirmed</div>' +
                    '<div class="hw-alert-detail-value">' + _fmtTs(a.last_triggered_ts) + '</div>' +
                '</div>' +
                '<div class="hw-alert-detail-field">' +
                    '<div class="hw-alert-detail-label">Alert key</div>' +
                    '<div class="hw-alert-detail-value" style="color:#ccc;font-size:0.85em">' +
                        (a.alert_key || "—") +
                    '</div>' +
                '</div>';
            document.getElementById("hwAlertDetailModal").style.display = "block";
            loadHwNotes(a.alert_key);
        }}

        function closeHwAlertDetailModal() {{
            document.getElementById("hwAlertDetailModal").style.display = "none";
            document.getElementById("hwAlertNotesSection").style.display = "none";
            document.getElementById("hwRelatedNotesList").style.display = "none";
            document.getElementById("hwNoteInput").value = "";
            document.getElementById("hwNoteStatus").textContent = "";
            _hwNotesKey = null;
            _hwAllNotes = [];
            _hwNotesPage = 0;
        }}

        var _hwNotesKey = null;
        var _hwAllNotes = [];
        var _hwNotesPage = 0;
        var _hwNotesSortDesc = true;

        function loadHwNotes(alertKey) {{
            _hwNotesKey = alertKey;
            _hwNotesPage = 0;
            _hwAllNotes = [];
            _hwNotesSortDesc = true;
            document.getElementById("hwAlertNotesSection").style.display = "block";
            document.getElementById("hwRelatedNotesList").style.display = "none";
            document.getElementById("hwNoteStatus").textContent = "";
            document.getElementById("hwNotesList").innerHTML =
                "<span style='color:#bbb;font-size:0.85em'>Loading notes…</span>";
            fetch("/api/tickets/notes/" + encodeURIComponent(alertKey))
                .then(function(r) {{ return r.json(); }})
                .then(function(notes) {{
                    _hwAllNotes = notes;
                    _renderHwNotesList();
                }})
                .catch(function() {{
                    document.getElementById("hwNotesList").innerHTML =
                        "<span style='color:#ff4444;font-size:0.85em'>Failed to load notes</span>";
                }});
        }}

        function _renderHwNotesList() {{
            var el = document.getElementById("hwNotesList");
            var perPage = 5;
            var sorted = _hwNotesSortDesc ? _hwAllNotes : _hwAllNotes.slice().reverse();
            var visible = sorted.slice(0, (_hwNotesPage + 1) * perPage);
            if (_hwAllNotes.length === 0) {{
                el.innerHTML = "<span style='color:#bbb;font-size:0.85em'>" +
                    tierText("No notes yet. Add one below.", "No notes yet.", "—") + "</span>";
                return;
            }}
            var sortBtn = "<button onclick='_toggleHwNoteSort()' style='background:transparent;border:none;color:#ccc;cursor:pointer;font-size:0.75em;padding:0;float:right'>" +
                (_hwNotesSortDesc ? "↓ Newest first" : "↑ Oldest first") + "</button>";
            var items = visible.map(function(n) {{
                return '<div style="border-left:2px solid #333;padding:6px 10px;margin-bottom:8px">' +
                    '<div style="color:#ddd;font-size:0.85em;white-space:pre-wrap">' + escapeHtml(n.note) + '</div>' +
                    '<div style="color:#bbb;font-size:0.75em;margin-top:3px">' +
                    escapeHtml(n.author) + ' · ' + escapeHtml(n.created_at) + '</div></div>';
            }}).join("");
            var moreCount = _hwAllNotes.length - visible.length;
            var moreBtn = moreCount > 0
                ? '<button onclick="_showMoreHwNotes()" style="background:transparent;border:1px solid #444;color:#ccc;padding:3px 8px;cursor:pointer;border-radius:3px;font-size:0.8em">Show ' + Math.min(perPage, moreCount) + ' more…</button>'
                : "";
            el.innerHTML = sortBtn + items + moreBtn;
        }}

        function _toggleHwNoteSort() {{
            _hwNotesSortDesc = !_hwNotesSortDesc;
            _hwNotesPage = 0;
            _renderHwNotesList();
        }}

        function _showMoreHwNotes() {{
            _hwNotesPage++;
            _renderHwNotesList();
        }}

        function addHwNote() {{
            var text = (document.getElementById("hwNoteInput").value || "").trim();
            if (!text || !_hwNotesKey) {{ return; }}
            var status = document.getElementById("hwNoteStatus");
            status.style.color = "#aaa";
            status.textContent = tierText("Saving…", "Saving…", "…");
            fetch("/api/tickets/notes/" + encodeURIComponent(_hwNotesKey), {{
                method: "POST",
                headers: {{"Content-Type": "application/json"}},
                body: JSON.stringify({{note: text}})
            }})
            .then(function(r) {{ return r.json(); }})
            .then(function(d) {{
                if (d.ok) {{
                    document.getElementById("hwNoteInput").value = "";
                    status.style.color = "#00ff88";
                    status.textContent = tierText("Note saved", "Saved", "✓");
                    loadHwNotes(_hwNotesKey);
                    setTimeout(function() {{ status.textContent = ""; }}, 2000);
                }} else {{
                    status.style.color = "#ff4444";
                    status.textContent = "Error: " + escapeHtml(d.error || "unknown");
                }}
            }})
            .catch(function() {{
                status.style.color = "#ff4444";
                status.textContent = "Error saving note";
            }});
        }}

        function loadHwRelatedNotes() {{
            if (!_hwNotesKey) {{ return; }}
            var el = document.getElementById("hwRelatedNotesList");
            el.style.display = "block";
            el.innerHTML = "<span style='color:#ccc;font-size:0.85em'>Searching…</span>";
            fetch("/api/tickets/related/" + encodeURIComponent(_hwNotesKey))
                .then(function(r) {{ return r.json(); }})
                .then(function(notes) {{
                    if (notes.length === 0) {{
                        el.innerHTML = "<div style='color:#bbb;font-size:0.85em'>" +
                            tierText(
                                "No related notes found — hardware alert keys are not linked to source IPs.",
                                "No related notes found.",
                                "No related notes."
                            ) + "</div>";
                        return;
                    }}
                    var header = "<div style='color:#ccc;font-size:0.75em;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px'>" +
                        tierText("Notes from other alerts by same source", "Related Notes", "Related Notes") + "</div>";
                    var items = notes.map(function(n) {{
                        return '<div style="border-left:2px solid #444;padding:6px 10px;margin-bottom:8px">' +
                            '<div style="color:#bbb;font-size:0.75em;margin-bottom:2px">' + escapeHtml(n.rule_name || n.rule_id) + '</div>' +
                            '<div style="color:#ddd;font-size:0.85em;white-space:pre-wrap">' + escapeHtml(n.note) + '</div>' +
                            '<div style="color:#bbb;font-size:0.75em;margin-top:3px">' +
                            escapeHtml(n.author) + ' · ' + escapeHtml(n.created_at) + '</div></div>';
                    }}).join("");
                    el.innerHTML = header + items;
                }})
                .catch(function() {{
                    el.innerHTML = "<span style='color:#ff4444;font-size:0.85em'>Failed to load</span>";
                }});
        }}

        renderHwAlerts({hw_alerts_js});

        function applyHwLive(hw) {{
            if (!hw) return;
            document.getElementById("hwCpuTemp").textContent = fmtHw(hw.cpu_temp, "°C");
            document.getElementById("hwGpuTemp").textContent = fmtHw(hw.gpu_temp, "°C");
            document.getElementById("hwAmbient").textContent = fmtHw(hw.ambient_temp, "°C");
            document.getElementById("hwNvme").textContent = fmtHw(hw.nvme_temp, "°C");
            document.getElementById("hwCpuPct").textContent = fmtHw(hw.cpu_percent, "%");
            document.getElementById("hwRamPct").textContent = fmtHw(hw.ram_percent, "%");
            var ramFreeEl = document.getElementById("hwRamFree");
            if (ramFreeEl) {{
                var freeGb = (hw.ram_total_gb != null && hw.ram_used_gb != null)
                    ? Math.round((hw.ram_total_gb - hw.ram_used_gb) * 10) / 10
                    : null;
                ramFreeEl.textContent = freeGb != null ? freeGb + " GB free" : "";
            }}
            document.getElementById("hwGpuFan").textContent = fmtHw(hw.gpu_fan_percent, "%");
            renderFanSection(hw.fans, hw.cpu_percent, hw.fan_status);
        }}

        // ── Device selector for hardware card ─────────────────────────────────
        var _hwSelectedDevice = 'local';

        function loadHwDevices() {{
            fetch('/api/hw/devices', {{cache: 'no-store'}})
                .then(function(r){{return r.json();}})
                .then(function(d){{
                    var sel = document.getElementById('hwDeviceSelect');
                    if (!sel) return;
                    var devs = (d.devices || []).filter(function(x){{return x.device_id!=='local';}});
                    // Remove old non-local options
                    while (sel.options.length > 1) sel.remove(1);
                    devs.forEach(function(dev){{
                        var opt = document.createElement('option');
                        opt.value = dev.device_id;
                        opt.textContent = dev.friendly_name + (dev.connection_type ? ' (' + dev.connection_type + ')' : '');
                        sel.appendChild(opt);
                    }});
                }})
                .catch(function(){{}});
        }}

        function hwDeviceChanged() {{
            var sel = document.getElementById('hwDeviceSelect');
            if (!sel) return;
            _hwSelectedDevice = sel.value;
            var badge = document.getElementById('hwDeviceConnBadge');
            if (badge) {{
                badge.textContent = _hwSelectedDevice === 'local' ? '' : '';
            }}
            if (_hwSelectedDevice === 'local') return; // local metrics come from normal refresh
            fetch('/api/hw/metrics-for-device?device_id=' + encodeURIComponent(_hwSelectedDevice))
                .then(function(r){{return r.json();}})
                .then(function(d){{
                    var samples = d.samples || [];
                    if (!samples.length) return;
                    var latest = samples[samples.length-1];
                    // Remap to live format
                    var live = {{
                        cpu_temp:        latest.cpu_temp,
                        gpu_temp:        latest.gpu_temp,
                        ambient_temp:    latest.ambient_temp,
                        nvme_temp:       latest.nvme_temp,
                        cpu_percent:     latest.cpu_percent,
                        ram_percent:     latest.ram_used_gb != null ? null : null,
                        ram_used_gb:     latest.ram_used_gb,
                        ram_total_gb:    null,
                        gpu_fan_percent: latest.gpu_fan_percent,
                        fans:            latest.fans || [],
                    }};
                    applyHwLive(live);
                }})
                .catch(function(){{}});
        }}

        loadHwDevices();
        setInterval(nemPoll(loadHwDevices), 60000);

        function openHwModal() {{
            document.getElementById("hwModal").style.display = "block";
            document.getElementById("hwModalStatus").textContent = "Loading…";
            fetch("/api/hw-metrics", {{cache: "no-store"}})
                .then(r => r.json())
                .then(d => {{
                    if (d.error) {{
                        document.getElementById("hwModalStatus").textContent = "Error: " + d.error;
                        return;
                    }}
                    applyHwLive(d.live);
                    renderHwCharts(d.samples || [], (d.health_sparkline || {{}}).scores || []);
                    var n = (d.samples || []).length;
                    document.getElementById("hwModalStatus").textContent =
                        n ? n + " samples (5 min each, oldest → newest)"
                          : "No samples yet — the monitor records one every 5 minutes.";
                }})
                .catch(e => {{
                    document.getElementById("hwModalStatus").textContent = "Error: " + e;
                }});
        }}

        function closeHwModal() {{
            document.getElementById("hwModal").style.display = "none";
        }}

        // ── Per-sensor history popup ──────────────────────────────────────────
        var _sensorPopupKey  = null;
        var _sensorPopupRange = "24h";
        var _sensorChart     = null;
        var _sensorSnapshots = [];

        var _SENSOR_META = {{
            cpu_temp:        {{label: "CPU Temperature", unit: "°C",  color: "#ff4444"}},
            gpu_temp:        {{label: "GPU Temperature", unit: "°C",  color: "#00ff88"}},
            ambient_temp:    {{label: "Ambient Temp",    unit: "°C",  color: "#ffaa00"}},
            nvme_temp:       {{label: "NVMe Temp",       unit: "°C",  color: "#00d4ff"}},
            cpu_percent:     {{label: "CPU Load",        unit: "%",   color: "#ff4444"}},
            ram_used_gb:     {{label: "RAM Used",        unit: " GB", color: "#00ff88"}},
            gpu_fan_percent: {{label: "GPU Fan",         unit: "%",   color: "#8800ff"}},
        }};

        function openSensorPopup(key) {{
            _sensorPopupKey   = key;
            _sensorPopupRange = "24h";
            document.getElementById("sensorPopupModal").style.display = "block";
            var meta = _SENSOR_META[key] || {{label: key, unit: "", color: "#00d4ff"}};
            document.getElementById("sensorPopupTitle").textContent = "📈 " + meta.label + " — History";
            document.querySelectorAll(".sensor-range-btn").forEach(function(b) {{
                b.classList.toggle("active", b.textContent.trim() === "24h");
            }});
            _loadSensorHistory();
        }}

        function openSensorPopupFan(fanKey, fanLabel) {{
            _sensorPopupKey   = "fan/" + fanKey;
            _sensorPopupRange = "24h";
            document.getElementById("sensorPopupModal").style.display = "block";
            document.getElementById("sensorPopupTitle").textContent = "📈 " + escapeHtml(fanLabel) + " — History";
            document.querySelectorAll(".sensor-range-btn").forEach(function(b) {{
                b.classList.toggle("active", b.textContent.trim() === "24h");
            }});
            _loadSensorHistory();
        }}

        function closeSensorPopup() {{
            document.getElementById("sensorPopupModal").style.display = "none";
            if (_sensorChart) {{ _sensorChart.destroy(); _sensorChart = null; }}
        }}

        function switchSensorRange(range) {{
            _sensorPopupRange = range;
            document.querySelectorAll(".sensor-range-btn").forEach(function(b) {{
                b.classList.toggle("active", b.textContent.trim() === range);
            }});
            _loadSensorHistory();
        }}

        function _loadSensorHistory() {{
            var statusEl = document.getElementById("sensorPopupStatus");
            statusEl.textContent = "Loading…";
            document.getElementById("sensorThrottleBanner").innerHTML = "";
            document.getElementById("sensorAnomalyBanner").innerHTML = "";
            document.getElementById("sensorAnomalyLink").style.display = "none";
            document.getElementById("sensorNotificationBar").innerHTML = "";

            fetch("/api/hw/history?sensor=" + encodeURIComponent(_sensorPopupKey) +
                  "&range=" + _sensorPopupRange, {{cache: "no-store"}})
                .then(function(r) {{ return r.json(); }})
                .then(function(d) {{
                    if (d.error) {{ statusEl.textContent = "Error: " + d.error; return; }}
                    _sensorSnapshots = d.anomaly_snapshots || [];

                    var meta = _SENSOR_META[_sensorPopupKey] || {{label: _sensorPopupKey, unit: "", color: "#00d4ff"}};
                    var samples = d.samples || [];
                    var labels  = samples.map(function(s) {{ return shortTs(s.timestamp); }});
                    var values  = samples.map(function(s) {{ return s.value; }});
                    var anomIdx = [];
                    samples.forEach(function(s, i) {{ if (s.is_anomalous) anomIdx.push(i); }});

                    // Destroy existing chart and draw new one
                    var ctx = document.getElementById("sensorPopupChart").getContext("2d");
                    if (_sensorChart) _sensorChart.destroy();
                    _sensorChart = new Chart(ctx, {{
                        type: "line",
                        data: {{
                            labels: labels,
                            datasets: [
                                {{
                                    label: meta.label,
                                    data: values,
                                    borderColor: meta.color,
                                    backgroundColor: meta.color.replace(")", ",0.1)").replace("rgb", "rgba"),
                                    borderWidth: 1.5,
                                    tension: 0.25,
                                    pointRadius: values.map(function(_, i) {{
                                        return anomIdx.indexOf(i) >= 0 ? 5 : 0;
                                    }}),
                                    pointBackgroundColor: values.map(function(_, i) {{
                                        return anomIdx.indexOf(i) >= 0 ? "#ff4444" : meta.color;
                                    }}),
                                    pointBorderColor: values.map(function(_, i) {{
                                        return anomIdx.indexOf(i) >= 0 ? "#ff4444" : meta.color;
                                    }}),
                                    fill: anomIdx.length === 0,
                                }}
                            ]
                        }},
                        options: {{
                            responsive: true,
                            interaction: {{mode: "index", intersect: false}},
                            plugins: {{
                                legend: {{labels: {{color: "#ccc", boxWidth: 12}}}},
                                tooltip: {{enabled: true}}
                            }},
                            scales: {{
                                x: {{ticks: {{color: "#888", maxTicksLimit: 8, autoSkip: true}}, grid: {{color: "#222"}}}},
                                y: {{ticks: {{color: "#888"}}, grid: {{color: "#222"}},
                                    title: {{display: true, text: meta.unit || "", color: "#888"}}}}
                            }},
                            elements: {{line: {{tension: 0.25}}}}
                        }}
                    }});

                    var n = samples.length;
                    statusEl.textContent = n + " sample" + (n !== 1 ? "s" : "") +
                        (anomIdx.length ? " · " + anomIdx.length + " anomalous" : "");

                    // Throttle banner
                    var tw = d.throttle_warning;
                    if (tw && tw.detected) {{
                        document.getElementById("sensorThrottleBanner").innerHTML =
                            '<div class="throttle-banner">⚡ CPU throttling detected during this period' +
                            (tw.min_freq_mhz ? ' — clock dropped to ' + tw.min_freq_mhz.toFixed(0) + ' MHz' : '') +
                            ' (' + tw.event_count + ' event' + (tw.event_count !== 1 ? 's' : '') + ')</div>';
                    }}

                    // Anomaly banner and link
                    var ac = d.anomaly_count || 0;
                    if (ac > 0) {{
                        document.getElementById("sensorAnomalyBanner").innerHTML =
                            '<div class="anomaly-banner">⚠ ' + ac + ' reading' + (ac !== 1 ? 's' : '') +
                            ' outside normal baseline for this time-of-day were detected in this range.</div>';
                        document.getElementById("sensorAnomalyLink").style.display = "block";
                        document.getElementById("sensorAnomalyCount").textContent = ac;
                    }}

                    // Notifications for this sensor
                    fetch("/api/hw/notifications")
                        .then(function(r) {{ return r.json(); }})
                        .then(function(nd) {{
                            var notifs = (nd.notifications || []).filter(function(n) {{
                                return n.sensor_key === _sensorPopupKey;
                            }});
                            if (notifs.length) {{
                                document.getElementById("sensorNotificationBar").innerHTML =
                                    notifs.map(function(n) {{
                                        return '<div class="hw-notification-bar">🔔 ' + escapeHtml(n.message) +
                                               ' <button onclick="dismissHwNotif(this.dataset.key)" data-key="' + escapeHtml(n.sensor_key) + '">Dismiss &amp; Reset</button></div>';
                                    }}).join("");
                            }}
                        }}).catch(function() {{}});
                }})
                .catch(function(e) {{ statusEl.textContent = "Error: " + e; }});
        }}

        function dismissHwNotif(sensorKey) {{
            fetch("/api/hw/reset-baseline?sensor=" + encodeURIComponent(sensorKey), {{method: "POST"}})
                .then(function() {{ _loadSensorHistory(); }});
        }}

        function openProcessModal() {{
            document.getElementById("processModal").style.display = "block";
            var body = document.getElementById("processModalBody");
            if (!_sensorSnapshots.length) {{
                body.innerHTML = '<p style="color:#bbb">No anomaly snapshots in this range.</p>';
                return;
            }}
            // Load full detail for all snapshots (fetch each individually, debounced)
            body.innerHTML = '<span style="color:#444">Loading…</span>';
            var fetches = _sensorSnapshots.slice(0, 10).map(function(snap) {{
                return fetch("/api/hw/snapshots/" + snap.id).then(function(r) {{ return r.json(); }});
            }});
            Promise.all(fetches).then(function(details) {{
                body.innerHTML = details.map(function(d) {{
                    var throttleNote = d.throttle_detected
                        ? '<span style="color:#ff4444">⚡ CPU throttled to ' + (d.throttle_freq_mhz || "?") + ' MHz</span><br>'
                        : '';
                    var sustained = d.sustained
                        ? '<span style="color:#ff8800">🔴 Sustained anomaly (part of consecutive run)</span><br>'
                        : '';
                    return '<div style="border:1px solid #333;border-radius:6px;padding:12px;margin-bottom:14px">' +
                        '<div style="color:#00d4ff;font-size:0.85em;margin-bottom:6px">' + escapeHtml(d.captured_at) + '</div>' +
                        sustained + throttleNote +
                        '<div style="display:grid;grid-template-columns:1fr 1fr;gap:4px 12px;font-size:0.82em;margin-bottom:8px">' +
                        '<span style="color:#bbb">Value:</span><span style="color:#eee">' + (d.reading_value !== null ? d.reading_value.toFixed(1) : "—") + '</span>' +
                        '<span style="color:#bbb">Baseline avg:</span><span style="color:#eee">' + (d.baseline_avg !== null ? d.baseline_avg.toFixed(1) : "—") + '</span>' +
                        '<span style="color:#bbb">Deviation:</span><span style="color:#ffaa00">' + (d.deviation !== null ? d.deviation.toFixed(2) + 'σ' : "—") + '</span>' +
                        '<span style="color:#bbb">CPU%:</span><span style="color:#eee">' + (d.cpu_pct !== null ? d.cpu_pct.toFixed(1) + "%" : "—") + '</span>' +
                        '<span style="color:#bbb">RAM:</span><span style="color:#eee">' + (d.ram_mb !== null ? (d.ram_mb / 1024).toFixed(1) + " GB" : "—") + '</span>' +
                        '<span style="color:#bbb">Net in/out:</span><span style="color:#eee">' + (d.net_mb_in !== null ? d.net_mb_in.toFixed(1) : "—") + ' / ' + (d.net_mb_out !== null ? d.net_mb_out.toFixed(1) : "—") + ' MB</span>' +
                        '</div>' +
                        (d.top_processes
                            ? '<div style="font-size:0.75em;color:#bbb;margin-bottom:4px">Top processes:</div><pre>' + escapeHtml(d.top_processes.substring(0, 1500)) + '</pre>'
                            : d.top_processes_ref
                                ? '<div style="font-size:0.75em;color:#bbb;margin-bottom:4px">Top processes:</div><div style="font-size:0.78em;color:#8a8f98">Archived to <code>' + escapeHtml(d.top_processes_ref) + '</code> in the archives directory. The snapshot itself is unchanged; only the process list was moved.</div>'
                                : '') +
                        '</div>';
                }}).join("") +
                (_sensorSnapshots.length > 10 ? '<p style="color:#bbb;font-size:0.8em">Showing first 10 of ' + _sensorSnapshots.length + ' events.</p>' : '');
            }}).catch(function(e) {{
                body.innerHTML = '<p style="color:#ff4444">Error loading details: ' + escapeHtml(String(e)) + '</p>';
            }});
        }}

        function closeProcessModal() {{
            document.getElementById("processModal").style.display = "none";
        }}

        function colorForCount(n) {{
            if (n === 0) return "#00ff88";
            if (n <= 5) return "#ffaa00";
            return "#ff4444";
        }}

        function colorForScore(s) {{
            if (s >= 80) return "#00ff88";
            if (s >= 50) return "#ffaa00";
            return "#ff4444";
        }}

        function openAlertBreakdownModal() {{
            document.getElementById("alertBreakdownModal").style.display = "block";
            document.getElementById("alertBreakdownBody").innerHTML = "Loading…";
            fetch("/api/alert-breakdown-24h", {{cache: "no-store"}})
                .then(r => r.json())
                .then(d => {{
                    window._breakdown24h = d.breakdown || [];
                    var rows = window._breakdown24h.map(function(b, idx) {{
                        var nc = b.note_count || 0;
                        var noteStyle = nc > 0 ? 'color:#00d4ff;font-weight:bold' : 'color:#bbb';
                        var noteLabel = nc > 0 ? String(nc) : 'None';
                        return '<tr class="hw-clickable" style="cursor:pointer" onclick="open24hAlertDetail(' + idx + ')">' +
                               '<td>' + escapeHtml(b.type) + '</td>' +
                               '<td style="text-align:right">' + b.count + '</td>' +
                               '<td style="' + noteStyle + ';font-size:0.85em">' + noteLabel + '</td>' +
                               '<td style="color:#00d4ff;font-size:0.8em;padding-left:6px">▸</td>' +
                               '</tr>';
                    }}).join("");
                    if (!rows) rows = `<tr><td colspan=4 style="color:#00ff88">${{tierText(
                        "✓ No hardware or service alerts in the last 24 hours — everything is running normally",
                        "No system alerts in the last 24 hours.",
                        "No alerts (24h)"
                    )}}</td></tr>`;
                    var ct = d.thermal_fan || 0, cs = d.service_down || 0;
                    var intro = tierText(
                        "These are hardware and service alerts from the background watchdog — things like overheating, fan failures, or a security service going down. Click any row for full detail. Network intrusion alerts are shown separately in the AI Firewall section below.",
                        "Thermal, fan-failure, and service-down alerts from the watchdog. Click a row for detail. Suricata network alerts appear in the AI Firewall section.",
                        "Watchdog alerts (thermal/fan/service). Click row for detail. Network alerts → AI Firewall."
                    );
                    document.getElementById("alertBreakdownBody").innerHTML = `
                        <p style="color:#ccc;font-size:0.85em;margin:0 0 10px 0">${{intro}}</p>
                        <div style="display:flex;gap:20px;margin:10px 0">
                            <div><span style="color:#ccc">${{tierText("Total alerts:","Total:","Total:")}}</span> <strong style="color:${{colorForCount(d.total || 0)}};font-size:1.2em">${{d.total || 0}}</strong></div>
                            <div><span style="color:#ccc">${{tierText("Overheating / fan:","Thermal/Fan:","Thermal:")}}</span> <strong style="color:${{colorForCount(ct)}}">${{ct}}</strong></div>
                            <div><span style="color:#ccc">${{tierText("Service went down:","Service down:","Svc down:")}}</span> <strong style="color:${{colorForCount(cs)}}">${{cs}}</strong></div>
                        </div>
                        <table class="breakdown-table">
                            <thead><tr><th>${{tierText("What triggered it","Alert type","Type")}}</th><th style="text-align:right">${{tierText("How many times","Count","#")}}</th><th>${{tierText("Notes","Notes","Notes")}}</th><th></th></tr></thead>
                            <tbody>${{rows}}</tbody>
                        </table>
                    `;
                }})
                .catch(e => {{
                    document.getElementById("alertBreakdownBody").innerHTML = `<p style="color:#ff4444">Error: ${{escapeHtml(e)}}</p>`;
                }});
        }}

        function closeAlertBreakdownModal() {{
            document.getElementById("alertBreakdownModal").style.display = "none";
        }}

        function _hw24hRec(alertType) {{
            var k = alertType.replace(/^thermal[/]fan: /, "");
            var recs = {{
                "cpu_temp":          "Check CPU fan and case airflow. Consider reducing load until temps recover.",
                "ambient_temp":      "Check room ventilation, dust filters, and chassis fan operation.",
                "nvme_temp":         "Verify NVMe heatsink contact and ambient airflow over the M.2 slot.",
                "gpu_temp":          "Check GPU fan and case airflow. Reduce GPU load (gaming, compute, ML) until temps recover.",
                "cpu_sustained_load":"Investigate runaway processes with `top` / `ps auxf`. May indicate stuck job or attack.",
                "cpu_fan_failure":   "Inspect the CPU fan immediately. Risk of thermal damage if not addressed."
            }};
            if (recs[k]) return recs[k];
            if (k.indexOf("fan_stopped") === 0) return "Inspect the fan. A stopped fan under sustained load will raise temperatures.";
            if (alertType.indexOf("service down:") === 0)
                return "Check service status with `systemctl status " + escapeHtml(k) + "`. Restart if needed and investigate root cause.";
            return "";
        }}

        function open24hAlertDetail(idx) {{
            var b = (window._breakdown24h || [])[idx];
            if (!b) return;
            var rec  = _hw24hRec(b.type);
            var icon = b.type.indexOf("service") === 0 ? "🔧" : "🌡️";
            document.getElementById("hwAlertDetailTitle").textContent = icon + " " + b.type;

            var occs = (b.occurrences || []).map(function(o) {{
                return '<div style="padding:4px 0;border-bottom:1px solid #1e2d4e;font-size:0.88em">' +
                       '<span style="color:#00d4ff">' + escapeHtml(o.ts) + '</span>' +
                       (o.breach ? ' &mdash; <span style="color:#ddd">' + escapeHtml(o.breach) + '</span>'
                                 : ' <span style="color:#bbb">(email delivery failed — breach detail not logged)</span>') +
                       '</div>';
            }}).join("") || '<div style="color:#bbb;font-size:0.88em">No occurrence detail captured in log</div>';

            document.getElementById("hwAlertDetailBody").innerHTML =
                '<div class="hw-alert-detail-field">' +
                    '<div class="hw-alert-detail-label">Alert key</div>' +
                    '<div class="hw-alert-detail-value">' + escapeHtml(b.type) +
                        ' <span style="color:#bbb;font-size:0.85em">(' + b.count +
                        ' occurrence' + (b.count !== 1 ? 's' : '') + ' in last 24h)</span></div>' +
                '</div>' +
                (rec ?
                    '<div class="hw-alert-detail-field">' +
                        '<div class="hw-alert-detail-label">Recommendation</div>' +
                        '<div class="hw-alert-detail-value">' + escapeHtml(rec) + '</div>' +
                    '</div>'
                : '') +
                '<div class="hw-alert-detail-field">' +
                    '<div class="hw-alert-detail-label">' +
                        (b.count > 1 ? 'Occurrences (most recent first)' : 'Occurrence') +
                    '</div>' +
                    '<div class="hw-alert-detail-value">' + occs + '</div>' +
                '</div>';

            document.getElementById("hwAlertDetailModal").style.display = "block";
            loadHwNotes(b.type);
        }}

        function openHealthModal() {{
            document.getElementById("healthModal").style.display = "block";
            document.getElementById("healthModalBody").innerHTML = "Loading…";
            fetch("/api/health-score", {{cache: "no-store"}})
                .then(r => r.json())
                .then(d => {{
                    var totalColor = colorForScore(d.score);
                    var rows = (d.components || []).map(c => {{
                        var barColor = colorForScore(c.score);
                        return `<tr>
                            <td><strong>${{escapeHtml(c.name)}}</strong><br><span style="color:#ccc;font-size:0.85em">${{escapeHtml(c.detail)}}</span></td>
                            <td style="width:100px"><div class="health-bar"><div class="health-bar-fill" style="width:${{c.score}}%;background:${{barColor}}"></div></div><div style="text-align:right;color:#ccc;font-size:0.8em">${{c.score}}%</div></td>
                            <td style="text-align:right;width:60px" title="${{tierText('How much this factor contributes to the total score','Weight','Weight')}}">${{c.weight}}%</td>
                            <td style="text-align:right;width:80px;color:${{barColor}};font-weight:bold">${{c.contribution}}</td>
                        </tr>`;
                    }}).join("");
                    var svcList = (d.services || []).map(s =>
                        `<span style="color:${{s.active ? '#00ff88' : '#ff4444'}};margin-right:12px">${{s.active ? '●' : '○'}} ${{escapeHtml(s.name)}}</span>`
                    ).join("");
                    var overallLabel = tierText("Overall Health Score", "Overall", "Score");
                    var noAlerts = `<tr><td colspan=2 style="color:#00ff88">${{tierText("✓ No system alerts in the last 24 hours — all clear","No system alerts in the last 24 hours.","No alerts (24h)")}}</td></tr>`;
                    document.getElementById("healthModalBody").innerHTML = `
                        <div style="margin:10px 0">
                            <div style="font-size:0.85em;color:#ccc">${{overallLabel}}</div>
                            <div style="font-size:2.5em;font-weight:bold;color:${{totalColor}}">${{d.score}}%</div>
                        </div>
                        <table class="breakdown-table">
                            <thead><tr>
                                <th>${{tierText("Factor","Component","Component")}}</th>
                                <th style="text-align:right">${{tierText("Health","Score","Score")}}</th>
                                <th style="text-align:right">${{tierText("Importance","Weight","Wt")}}</th>
                                <th style="text-align:right">${{tierText("Points","Points","Pts")}}</th>
                            </tr></thead>
                            <tbody>${{rows}}</tbody>
                        </table>
                        <div style="margin-top:15px">
                            <div style="color:#ccc;font-size:0.85em;margin-bottom:4px">${{tierText("Security services running","Services","Services")}}</div>
                            ${{svcList}}
                        </div>
                    `;
                }})
                .catch(e => {{
                    document.getElementById("healthModalBody").innerHTML = `<p style="color:#ff4444">Error: ${{escapeHtml(e)}}</p>`;
                }});
        }}

        function closeHealthModal() {{
            document.getElementById("healthModal").style.display = "none";
        }}

        function vpnStatusColor(status) {{
            if (!status) return "#ff4444";
            var s = status.toLowerCase();
            if (s === "connected") return "#00ff88";
            if (s === "connecting" || s === "reconnecting") return "#ffaa00";
            return "#ff4444";
        }}

        function openVpnModal() {{
            document.getElementById("vpnModal").style.display = "block";
            document.getElementById("vpnModalContent").innerHTML = "Loading…";
            document.getElementById("vpnModalActions").style.display = "block";
            fetch("/api/vpn-status", {{cache: "no-store"}})
                .then(r => r.json())
                .then(d => {{
                    var color = vpnStatusColor(d.status);
                    var html = `
                        <p><strong>${{tierText("VPN Service:","Provider:","Provider:")}}</strong> ${{escapeHtml(d.provider || "Unknown")}}</p>
                        <p><strong>${{tierText("Connection Status:","Status:","Status:")}}</strong> <span style="color:${{color}};font-weight:bold">${{escapeHtml(d.status || "Unknown")}}</span></p>
                        <p><strong>${{tierText("Your VPN IP Address:","VPN IP:","VPN IP:")}}</strong> ${{escapeHtml(d.vpn_ip || "—")}}</p>
                        <p><strong>${{tierText("Connected Server:","Server / Location:","Server:")}}</strong> ${{escapeHtml(d.server_location || "—")}}</p>
                        <p><strong>${{tierText("Encryption Protocol:","Protocol:","Protocol:")}}</strong> ${{escapeHtml(d.protocol || "—")}}</p>
                    `;
                    if (d.split_tunnel_apps && d.split_tunnel_apps.length) {{
                        html += `<p style="margin-bottom:2px"><strong>${{tierText("Apps bypassing VPN (split tunnel):","Split Tunnel Apps:","Split tunnel:")}}</strong></p><ul style="font-size:0.85em;color:#ccc;margin:4px 0 0 18px">`;
                        d.split_tunnel_apps.forEach(function(app) {{ html += `<li>${{escapeHtml(app)}}</li>`; }});
                        html += `</ul>`;
                    }} else if (d.provider && d.provider.toLowerCase().includes("pia")) {{
                        html += `<p style="color:#ccc;font-size:0.85em">${{tierText("Split tunnel: no apps are bypassing the VPN","Split tunnel: none configured","Split tunnel: none")}}</p>`;
                    }}
                    document.getElementById("vpnModalContent").innerHTML = html;
                    // Hide action buttons if no supported CLI
                    if (!d.provider) {{
                        document.getElementById("vpnModalActions").style.display = "none";
                    }}
                }})
                .catch(function(e) {{
                    document.getElementById("vpnModalContent").innerHTML = `<p style="color:#ff4444">Error: ${{escapeHtml(String(e))}}</p>`;
                }});
        }}

        function closeVpnModal() {{
            document.getElementById("vpnModal").style.display = "none";
        }}

        function vpnAction(action) {{
            var btn = event.target;
            btn.disabled = true;
            btn.textContent = action === "connect" ? "Connecting…" : "Disconnecting…";
            fetch("/api/vpn/" + action, {{
                method: "POST",
                cache: "no-store",
                headers: {{"Content-Type": "application/json"}},
                body: "{{}}"
            }})
                .then(r => r.json())
                .then(function(d) {{
                    if (d.error) {{
                        alert("VPN error: " + d.error);
                        btn.disabled = false;
                        btn.textContent = action === "connect" ? "🔄 Reconnect" : "⏹ Disconnect";
                    }} else {{
                        setTimeout(openVpnModal, 2500);
                    }}
                }})
                .catch(function(e) {{
                    alert("Error: " + e);
                    btn.disabled = false;
                }});
        }}

        document.addEventListener("keydown", function(e) {{
            if (e.key !== "Escape") return;
            if (document.getElementById("hwModal").style.display === "block") closeHwModal();
            if (document.getElementById("sensorPopupModal").style.display === "block") closeSensorPopup();
            if (document.getElementById("processModal").style.display === "block") closeProcessModal();
            if (document.getElementById("alertBreakdownModal").style.display === "block") closeAlertBreakdownModal();
            if (document.getElementById("healthModal").style.display === "block") closeHealthModal();
            if (document.getElementById("vpnModal").style.display === "block") closeVpnModal();
            if (document.getElementById("hwAlertDetailModal").style.display === "block") closeHwAlertDetailModal();
        }});
        document.getElementById("hwModal").addEventListener("click", function(e) {{
            if (e.target.id === "hwModal") closeHwModal();
        }});
        document.getElementById("alertBreakdownModal").addEventListener("click", function(e) {{
            if (e.target.id === "alertBreakdownModal") closeAlertBreakdownModal();
        }});
        document.getElementById("healthModal").addEventListener("click", function(e) {{
            if (e.target.id === "healthModal") closeHealthModal();
        }});

        function shortTs(ts) {{
            if (!ts) return "";
            var t = ts.replace("T", " ");
            return t.length > 16 ? t.slice(5, 16) : t;
        }}

        function makeChart(canvasId, labels, datasets, yLabel) {{
            var ctx = document.getElementById(canvasId).getContext("2d");
            if (hwCharts[canvasId]) hwCharts[canvasId].destroy();
            hwCharts[canvasId] = new Chart(ctx, {{
                type: "line",
                data: {{labels: labels, datasets: datasets}},
                options: {{
                    responsive: true,
                    interaction: {{mode: "index", intersect: false}},
                    plugins: {{
                        legend: {{labels: {{color: "#ccc", boxWidth: 12}}}},
                        tooltip: {{enabled: true}}
                    }},
                    scales: {{
                        x: {{ticks: {{color: "#888", maxTicksLimit: 8, autoSkip: true}},
                             grid: {{color: "#222"}}}},
                        y: {{ticks: {{color: "#888"}},
                             grid: {{color: "#222"}},
                             title: {{display: !!yLabel, text: yLabel || "", color: "#888"}}}}
                    }},
                    elements: {{point: {{radius: 0}}, line: {{tension: 0.25, borderWidth: 1.5}}}}
                }}
            }});
        }}

        function pick(samples, key) {{ return samples.map(s => s[key]); }}

        function renderHwCharts(samples, healthScores) {{
            var labels = samples.map(s => shortTs(s.timestamp));
            makeChart("chartTemp", labels, [
                {{label: "CPU",     data: pick(samples, "cpu_temp"),     borderColor: "#ff4444", backgroundColor: "rgba(255,68,68,0.1)"}},
                {{label: "GPU",     data: pick(samples, "gpu_temp"),     borderColor: "#00ff88", backgroundColor: "rgba(0,255,136,0.1)"}},
                {{label: "Ambient", data: pick(samples, "ambient_temp"), borderColor: "#ffaa00", backgroundColor: "rgba(255,170,0,0.1)"}},
                {{label: "NVMe",    data: pick(samples, "nvme_temp"),    borderColor: "#00d4ff", backgroundColor: "rgba(0,212,255,0.1)"}}
            ], "°C");
            // Fan chart: use array position as the primary key so duplicate
            // human-readable labels (e.g. 8× "Chassis Motherboard Fan") each
            // get their own line.  Append " #N" suffix to distinguish repeats.
            var _fanCount = 0;
            samples.forEach(function(s) {{ _fanCount = Math.max(_fanCount, (s.fans || []).length); }});
            var _fanLabels = [];
            for (var _si = 0; _si < samples.length; _si++) {{
                if (samples[_si].fans && samples[_si].fans.length > 0) {{
                    var _seen = {{}};
                    samples[_si].fans.forEach(function(f, fi) {{
                        var base = String(f.label || ("Fan " + (fi + 1)));
                        var lbl = base, n = 1;
                        while (_seen[lbl]) {{ lbl = base + " #" + (++n); }}
                        _seen[lbl] = true;
                        _fanLabels[fi] = lbl;
                    }});
                    break;
                }}
            }}
            for (var _fi = _fanLabels.length; _fi < _fanCount; _fi++) {{
                _fanLabels[_fi] = "Fan " + (_fi + 1);
            }}
            var fanPalette = ["#00ff88","#00d4ff","#8800ff","#ffaa00","#ff4444","#ff00ff","#ffffff","#88ffcc","#ffbb44","#aa88ff"];
            makeChart("chartFans", labels, _fanLabels.map(function(lbl, fi) {{
                var posIdx = fi;
                return {{
                    label: lbl,
                    data: samples.map(function(s) {{
                        var fa = s.fans || [];
                        return posIdx < fa.length ? fa[posIdx].rpm : null;
                    }}),
                    borderColor: fanPalette[fi % fanPalette.length]
                }};
            }}), "RPM");
            makeChart("chartUsage", labels, [
                {{label: "CPU %",      data: pick(samples, "cpu_percent"), borderColor: "#ff4444"}},
                {{label: "RAM (GB)",   data: pick(samples, "ram_used_gb"), borderColor: "#00ff88", yAxisID: "y"}}
            ], "%");
            makeChart("chartIo", labels, [
                {{label: "Disk Read",  data: pick(samples, "disk_read_mb"),  borderColor: "#00d4ff"}},
                {{label: "Disk Write", data: pick(samples, "disk_write_mb"), borderColor: "#8800ff"}},
                {{label: "Net In",     data: pick(samples, "net_in_mb"),     borderColor: "#00ff88"}},
                {{label: "Net Out",    data: pick(samples, "net_out_mb"),    borderColor: "#ffaa00"}}
            ], "MB");
            makeChart("chartHealth", labels, [
                {{label: "Health", data: healthScores || [],
                  borderColor: "#00d4ff",
                  backgroundColor: "rgba(0,212,255,0.15)",
                  fill: true}}
            ], "%");
        }}

        var refreshTick = 0;
        function refreshDashboard() {{
            fetch("/api/stats", {{cache: "no-store"}})
                .then(r => r.json())
                .then(d => {{
                    document.getElementById("lastUpdated").textContent = d.now;
                    document.getElementById("phTotal").textContent = d.pihole.total;
                    document.getElementById("phBlocked").textContent = d.pihole.blocked;
                    document.getElementById("phPercent").textContent = d.pihole.percent + "%";
                    document.getElementById("cntTotal").textContent = d.alert_counts.total;
                    document.getElementById("cntP1").textContent = d.alert_counts.p1;
                    document.getElementById("cntP2").textContent = d.alert_counts.p2;
                    document.getElementById("cntP3").textContent = d.alert_counts.p3;
                    applyP3Visibility(isP3Shown());
                    _refreshSectionBadges();
                    var banner = document.getElementById("quarantineBanner");
                    var list = document.getElementById("quarantineList");
                    if (d.quarantines && d.quarantines.length) {{
                        banner.style.display = "block";
                        list.innerHTML = d.quarantine_banner_html;
                    }} else {{
                        banner.style.display = "none";
                        list.innerHTML = "";
                    }}
                    if (d.hw) applyHwLive(d.hw);
                    if (d.hw_alerts !== undefined) renderHwAlerts(d.hw_alerts);
                    if (d.alert_24h) {{
                        var ael = document.getElementById("hwAlert24h");
                        ael.textContent = d.alert_24h.total;
                        ael.style.color = colorForCount(d.alert_24h.total);
                    }}
                    if (d.health) {{
                        var hel = document.getElementById("hwHealthScore");
                        hel.textContent = d.health.score + "%";
                        hel.style.color = colorForScore(d.health.score);
                    }}
                    if (d.review_queue_count !== undefined) {{
                        document.getElementById("cntReviewQueue").textContent = d.review_queue_count;
                    }}
                    if (d.vpn) {{
                        var vpnEl = document.getElementById("vpnStatusText");
                        var vpnLabel = d.vpn.provider
                            ? d.vpn.provider + " — " + d.vpn.status
                            : "VPN — " + d.vpn.status;
                        vpnEl.textContent = vpnLabel;
                        vpnEl.style.color = vpnStatusColor(d.vpn.status);
                    }}
                    if (d.community_queue_badge !== undefined) {{
                        var cqEl = document.getElementById("cq-badge-container");
                        if (cqEl) cqEl.innerHTML = d.community_queue_badge || '';
                    }}
                    if (d.incident_state) {{
                        window._nemesisIncidentState = d.incident_state;
                    }}
                    if (d.incident_banner_html !== undefined) {{
                        var ibWrap = document.getElementById("nemesisIncidentBannerWrap");
                        if (ibWrap) {{
                            var dismissed = window.sessionStorage && d.incident_state && d.incident_state.name
                                ? sessionStorage.getItem('nemesisBannerDismissed') === d.incident_state.name
                                : false;
                            if (!dismissed) {{
                                ibWrap.innerHTML = d.incident_banner_html;
                                if (typeof applyTierText === 'function') applyTierText();
                            }} else {{
                                ibWrap.innerHTML = '';
                            }}
                        }}
                    }}
                    refreshTick++;
                    if (refreshTick % 5 === 0) {{
                        document.getElementById("alertsRows").innerHTML = d.alerts_html;
                        document.getElementById("devicesRows").innerHTML = d.devices_html;
                        document.getElementById("reviewQueueRows").innerHTML = d.review_queue_html;
                        if (d.module_cards_html !== undefined) {{
                            document.getElementById("moduleCardsContainer").innerHTML = d.module_cards_html;
                        }}
                        applyTierText();
                    }}
                }})
                .catch(e => console.error("refresh failed", e));
        }}
        setInterval(nemPoll(refreshDashboard), 60000);

        // Re-apply tier-dependent JS content when the user changes tier from /settings
        // (localStorage storage events fire across tabs).
        window.onTierChange = function() {{
            applyTierText();
            updateActionButtonLabels();
        }};
        window.addEventListener("storage", function(e) {{
            if (e.key === "explanationTier") {{
                applyTierText();
                updateActionButtonLabels();
            }}
        }});

        function updateActionButtonLabels() {{
            var b = document.getElementById("btnBlock");
            var ig = document.getElementById("btnIgnore");
            var mo = document.getElementById("btnMonitor");
            if (b)  b.textContent  = tierText("🚫 Block this IP address", "🚫 Block IP", "🚫 Block");
            if (ig) ig.textContent = tierText("✓ Ignore — stop alerting on this rule", "✓ Ignore Rule", "✓ Ignore");
            if (mo) mo.textContent = tierText("👁 Keep watching (monitor only)", "👁 Monitor", "👁 Monitor");
        }}
        updateActionButtonLabels();

        /* Deep link from the alert database page: /?alert=<rule_id> opens that
           alert's modal, so the Unblock button and its credential prompt stay
           reachable for an alert that has dropped out of the pending views.
           Deliberately only OPENS the modal — following a link must never
           perform a privileged firewall change. */
        (function () {{
            try {{
                var deepLink = new URLSearchParams(window.location.search).get("alert");
                if (deepLink) {{ viewAlert(deepLink, ""); }}
            }} catch (e) {{ /* convenience only — never break the page over it */ }}
        }})();

        function confirmQuarantine(id) {{
            if (!confirm("Confirm this block permanently? The ufw rule will be kept and the alert marked 'block'.")) return;
            fetch("/api/quarantine/" + id + "/confirm", {{method: "POST"}})
                .then(r => r.json())
                .then(d => {{
                    if (d.success) {{ refreshDashboard(); }}
                    else {{ alert("Confirm failed: " + (d.error || "unknown")); }}
                }})
                .catch(e => alert("Error: " + e));
        }}

        function liftQuarantine(id, ip) {{
            if (!confirm("Lift this quarantine for " + ip + "? The ufw rule will be removed.")) return;
            fwPrompt("lift the quarantine on " + ip).then(function (pw) {{
                if (!pw) return;
                fetch("/api/quarantine/" + id + "/lift", {{
                    method: "POST",
                    headers: {{"Content-Type": "application/json"}},
                    body: JSON.stringify({{password: pw}})
                }})
                    .then(r => r.json())
                    .then(d => {{
                        if (d.success) {{ refreshDashboard(); }}
                        else {{ fwHandleError(d, "Lift failed"); }}
                    }})
                    .catch(e => alert("Error: " + e));
            }});
        }}

        /* ── Firewall counter drilldown ── */
        var _fwDrillKind = "total";
        var _fwDrillPage = 1;
        var _fwDrillPerPage = (function() {{
            var v = parseInt(localStorage.getItem("fwDrillPerPage") || "10", 10);
            return (isNaN(v) || v < 1) ? 10 : Math.min(v, 500);
        }})();

        function openFwDrilldown(kind) {{
            _fwDrillKind = kind;
            _fwDrillPage = 1;
            var modal = document.getElementById("fwDrillModal");
            modal.style.display = "flex";
            document.getElementById("fwDrillPerPageInput").value = _fwDrillPerPage;
            var titles = {{
                total: [
                    tierText("All Firewall Alerts Today", "Today's Firewall Alerts — All Rules", "All Rules Today"),
                    tierText(
                        "Every type of network alert that fired today, including routine background traffic. Click a rule to open the Alert Database.",
                        "All unique rules that fired today (P1 + P2 + P3), grouped by rule ID.",
                        "All rules: P1+P2+P3, deduplicated by rule_id."
                    )
                ],
                p1: [
                    tierText("Critical Threats Detected Today", "Critical P1 Rules — Today", "P1 Rules Today"),
                    tierText(
                        "These are the most serious alerts — the firewall saw something that looks like a real attack. Includes all Critical rules, even ones already reviewed or set to ignore.",
                        "All P1 (Critical priority) rules that fired today, including those already reviewed, ignored, or blocked.",
                        "P1 rules today; incl. ignored/blocked. Reason column shows why each is/isn't in the attention list."
                    )
                ],
                p2: [
                    tierText("High Risk Alerts Today", "High P2 Rules — Today", "P2 Rules Today"),
                    tierText(
                        "High-risk alerts detected today. Includes all P2 rules even if you've already reviewed them.",
                        "All P2 (High priority) rules that fired today, including reviewed/ignored/blocked entries.",
                        "P2 rules today; incl. ignored/blocked. Status column explains current disposition."
                    )
                ],
                review_queue: [
                    tierText("Everything Flagged as High Risk", "Review Queue — HIGH Risk Rules Today", "HIGH Risk Rules Today"),
                    tierText(
                        "Every rule the AI flagged as high risk today. Pending items need your decision. Others have already been handled.",
                        "All rules with risk_level=HIGH that fired today. Pending items shown first.",
                        "risk_level=HIGH rules today; pending-first sort."
                    )
                ]
            }};
            var t = titles[kind] || titles["total"];
            document.getElementById("fwDrillTitle").textContent = t[0];
            document.getElementById("fwDrillSubtitle").textContent = t[1];
            document.getElementById("fwDrillBody").innerHTML =
                "<p style='color:#ccc'>Loading…</p>";
            document.getElementById("fwDrillPagin").innerHTML = "";
            document.getElementById("fwDrillPagInfo").textContent = "";
            _fwDrillFetch();
        }}

        function closeFwDrilldown() {{
            document.getElementById("fwDrillModal").style.display = "none";
        }}

        function _fwDrillFetch() {{
            var url = "/api/firewall/drilldown?kind=" + encodeURIComponent(_fwDrillKind)
                    + "&page=" + _fwDrillPage
                    + "&per_page=" + _fwDrillPerPage;
            fetch(url, {{cache: "no-store"}})
                .then(function(r) {{ return r.json(); }})
                .then(function(d) {{
                    if (!d.ok) {{
                        document.getElementById("fwDrillBody").innerHTML =
                            "<p style='color:#ff4444'>Error: " + escapeHtml(d.error || "unknown") + "</p>";
                        return;
                    }}
                    document.getElementById("fwDrillBody").innerHTML = d.table_html;
                    applyTierText();
                    _fwDrillPage = d.page;
                    var start = (d.page - 1) * d.per_page + 1;
                    var end   = Math.min(d.page * d.per_page, d.total_rules);
                    document.getElementById("fwDrillPagInfo").textContent =
                        (d.total_rules === 0) ? "No results"
                        : "Showing " + start + "–" + end + " of " + d.total_rules + " rules";
                    _fwRenderPagin(d.total_pages, d.page);
                }})
                .catch(function(e) {{
                    document.getElementById("fwDrillBody").innerHTML =
                        "<p style='color:#ff4444'>Request failed: " + escapeHtml(String(e)) + "</p>";
                }});
        }}

        function _fwRenderPagin(totalPages, currentPage) {{
            var el = document.getElementById("fwDrillPagin");
            if (totalPages <= 1) {{ el.innerHTML = ""; return; }}
            var html = "";
            var btnStyle = "padding:4px 10px;border-radius:4px;border:1px solid #333;cursor:pointer;font-size:0.85em;";
            var activStyle = btnStyle + "background:#00d4ff;color:#1a1a2e;font-weight:bold;border-color:#00d4ff;";
            var normStyle  = btnStyle + "background:#0d1117;color:#ccc;";
            html += "<button style='" + normStyle + "' " + (currentPage===1?"disabled":"") +
                    " onclick='fwGoPage(1)'>&laquo;</button>";
            html += "<button style='" + normStyle + "' " + (currentPage===1?"disabled":"") +
                    " onclick='fwGoPage(" + (currentPage-1) + ")'>&lsaquo;</button>";
            var lo = Math.max(1, currentPage - 2);
            var hi = Math.min(totalPages, currentPage + 2);
            for (var p = lo; p <= hi; p++) {{
                var s = (p === currentPage) ? activStyle : normStyle;
                html += "<button style='" + s + "' onclick='fwGoPage(" + p + ")'>" + p + "</button>";
            }}
            html += "<button style='" + normStyle + "' " + (currentPage===totalPages?"disabled":"") +
                    " onclick='fwGoPage(" + (currentPage+1) + ")'>&rsaquo;</button>";
            html += "<button style='" + normStyle + "' " + (currentPage===totalPages?"disabled":"") +
                    " onclick='fwGoPage(" + totalPages + ")'>&raquo;</button>";
            el.innerHTML = html;
        }}

        function fwGoPage(p) {{
            _fwDrillPage = p;
            document.getElementById("fwDrillBody").innerHTML =
                "<p style='color:#ccc'>Loading…</p>";
            _fwDrillFetch();
        }}

        function fwSetPerPage(val) {{
            var n = parseInt(val, 10);
            if (isNaN(n) || n < 1) n = 10;
            if (n > 500) n = 500;
            _fwDrillPerPage = n;
            localStorage.setItem("fwDrillPerPage", String(n));
            _fwDrillPage = 1;
            _fwDrillFetch();
        }}

        document.addEventListener("keydown", function(e) {{
            if (e.key === "Escape") {{
                var m = document.getElementById("fwDrillModal");
                if (m && m.style.display !== "none") closeFwDrilldown();
            }}
        }});

        // Initialize collapsible sections on load and fetch uptime once
        document.addEventListener("DOMContentLoaded", function() {{
            _initCollapseSections();
            fetch('/api/dashboard/uptime')
                .then(function(r) {{ return r.json(); }})
                .then(function(d) {{
                    var el = document.getElementById('dashUptime');
                    if (el) el.textContent = d.uptime;
                }})
                .catch(function() {{}});
            // AI status badge
            (function() {{
                var badge = document.getElementById('ai-status-badge');
                if (!badge) return;
                function _setAiBadge(state) {{
                    if (state === 'active') {{
                        badge.textContent = 'AI ●';
                        badge.style.color = '#00ff88';
                        badge.title = tierText(
                            'AI Engine is active — your firewall can analyse threats automatically',
                            'AI Engine: active',
                            'AI: active'
                        );
                    }} else if (state === 'no_key') {{
                        badge.textContent = 'AI ✕';
                        badge.style.color = '#ff4444';
                        badge.title = tierText(
                            'AI Engine is on but has no API key — go to Settings → AI Engine to add one',
                            'AI Engine: enabled, no API key',
                            'AI: no key'
                        );
                    }} else {{
                        badge.textContent = 'AI ○';
                        badge.style.color = '#888';
                        badge.title = tierText(
                            'AI Engine is turned off — click here to go to Settings and toggle it on under Modules',
                            'AI Engine: disabled — click to enable in Settings → Modules',
                            'AI: off — enable in Settings'
                        );
                    }}
                }}
                fetch('/api/ai/status')
                    .then(function(r) {{
                        if (!r.ok) {{ _setAiBadge('disabled'); return null; }}
                        return r.json();
                    }})
                    .then(function(d) {{ if (d) _setAiBadge(d.state); }})
                    .catch(function() {{ _setAiBadge('disabled'); }});
            }})();
        }});
    </script>
</body>
</html>"""

if __name__ == "__main__":
    # Assert the privilege boundary against the kernel before serving anything.
    # Inert until the unit sets NEMESIS_EXPECT_USER (see nemesis_privsep).
    #
    # Added 2026-07-31 with the nemesis-dash cutover. Without this call the
    # unit's NEMESIS_EXPECT_USER would be decorative — exactly the false-
    # attestation state corrected in nemesis-fwd's unit earlier today, where a
    # comment claimed a check that no code performed. systemd's hardening
    # directives fail open, so the unit file is never evidence of confinement.
    import nemesis_privsep
    nemesis_privsep.attest_from_env("dashboard")
    app.run(host="0.0.0.0", port=5000)