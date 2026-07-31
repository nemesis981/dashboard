#!/usr/bin/env python3
"""nemesis-fwd — privileged ufw helper.

The ONLY path from Nemesis to ufw. Dashboard no longer calls ufw at all; it
talks to this process over a local socket, and this process owns the privilege.

Why it exists: ufw performs an application-level real-UID check
(`ufw/util.py`: `if do_checks and os.getuid() != 0: raise OSError(EPERM)`), so
no capability grant lets a non-root process drive it — capabilities change what
a process may DO, never what getuid() RETURNS. Relocating ufw into this helper
lets dashboard run under the same full hardening block as every other service.

Be clear about what this achieves: privilege is RELOCATED, not eliminated. Root
now lives in one small single-purpose process behind three verification layers,
instead of in a Flask app with ten sudo call sites.

THREE LAYERS, each verified HERE against ground truth. Nothing is taken on the
caller's word, because the caller is explicitly modelled as potentially
compromised:

  1. SO_PEERCRED        kernel-supplied (pid, uid, gid) of the connecting
                        process. Unspoofable. Must match the dashboard user.
  2. users table        the named account must exist, be active, have
                        role='admin', and not be locked out. Read from the DB
                        here — never a "this user is admin" claim in the request.
  3. bcrypt.checkpw     the password is verified against the stored hash HERE.
                        There is deliberately no "verified: true" field in the
                        protocol, so there is nothing for a compromised caller
                        to forge.

Threat model result: an attacker with full control of the dashboard process,
correct OS identity, and a stolen admin session cookie passes layer 1, passes
layer 2 if they name a real admin — and fails layer 3, because they cannot
produce a password they do not know.

See ~/work/DESIGN-ufw-helper-2026-07-28.md for the full design record.
"""

import errno
import grp
import json
import logging
import os
import pwd
import re
import selectors
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import nemesis_paths  # noqa: E402
import data_manager  # noqa: E402

try:
    import bcrypt
except ImportError:  # pragma: no cover
    bcrypt = None

SOCKET_PATH = os.environ.get("NEMESIS_FWD_SOCKET", "/run/nemesis/fwd.sock")

#: The dashboard peer's OS user. DELIBERATELY HAS NO DEFAULT.
#:
#: This is the identity layer 1 authorises — get it wrong and either the real
#: dashboard cannot connect, or some other account is treated as the dashboard
#: peer. A fallback value could not be right for both this install and any
#: other, so it would silently paper over a misconfigured unit at exactly the
#: point where being wrong matters most. Consistent with the fail-loud stance
#: the rest of this helper is built on: unset is a configuration error, and it
#: is reported as one at startup (see main()) rather than guessed at.
DASH_USER = os.environ.get("NEMESIS_DASH_USER")
#: Unattended caller. Adds automatic blocks; never removes one, never reads the
#: ruleset. See PEER_POLICY.
ALERTW_USER = os.environ.get("NEMESIS_ALERTW_USER", "nemesis-alertw")
#: fail2ban's own service account. Same shape as ALERTW_USER: an unattended peer
#: with no human behind it, controlled by a structural op-allowlist rather than a
#: credential. See PEER_POLICY["fail2ban"].
FAIL2BAN_USER = os.environ.get("NEMESIS_FAIL2BAN_USER", "nemesis-f2b")
SOCKET_GROUP = os.environ.get("NEMESIS_FWD_GROUP", "nemesis-fw")
UFW_BIN = "/usr/sbin/ufw"

#: Idle timeout for the view-credential cache. Configurable, not hardcoded, so
#: it can be tuned without a design change. 300s matches sudo's long-standing
#: timestamp_timeout default.
DEFAULT_CACHE_IDLE_SECONDS = 300

HDR = struct.Struct("!I")
MAX_REQUEST_BYTES = 64 * 1024

log = logging.getLogger("nemesis.fwd")

#: Tiered account lockout — IDENTICAL thresholds to the dashboard login path
#: (dashboard.py `_LOCKOUT_TIERS`). The two paths share the SAME lockout columns
#: on `users`, by design: a brute-force attempt is a brute-force attempt whether
#: it arrives at the login form or this socket, and it should count toward one
#: budget, not two independent ones. (attempts_threshold, lockout_minutes).
#: Kept in sync deliberately — if the dashboard policy changes, change it here.
_LOCKOUT_TIERS = ((3, 5), (5, 15), (10, 60))

# Operations that only READ firewall state. Everything else is a write and can
# never be satisfied from cache.
READ_OPS = {"list_blocked", "list_rules"}
# Keep this set exactly equal to the write ops that EXIST in OPS below. `add_rule`
# and `remove_rule` were listed here until 2026-07-29 without ever being
# implemented, appearing in OPS, or being granted to any peer — a declared-but-
# absent op in a security allowlist reads as capability that is not there, and
# invites designing against it. Removed rather than implemented: the Fork B work
# that might have used them established that `ufw route` cannot gate
# tunnel-sourced forwarded traffic at all (Tailscale's ts-forward ACCEPTs it ahead
# of every ufw chain), so there is no route op for these names to become.
WRITE_OPS = {"block_ip", "deny_ip", "unblock_ip", "expire_quarantine"}
NO_CREDENTIAL_OPS = {"ping", "drop_credential"}

#: audit_log action name per op. Introduced 2026-07-31, replacing a hardcoded
#: `"fw_%s" % op` at both audit call sites.
#:
#: The prefix was fine while every op was a firewall operation. It stops being
#: fine the moment this helper carries an op that is not — a service restart
#: logged as `fw_restart_dashboard` would be actively misleading to anyone
#: reading the audit trail or filtering it by prefix.
#:
#: The existing four names are reproduced EXACTLY. Renaming any of them would
#: orphan the audit rows already written under the old name — audit_log is
#: append-only and its history has to stay queryable.
AUDIT_ACTION = {
    "block_ip":          "fw_block_ip",
    "deny_ip":           "fw_deny_ip",
    "unblock_ip":        "fw_unblock_ip",
    "expire_quarantine": "fw_expire_quarantine",
}


def audit_action_for(op):
    """audit_log action name for an op.

    Unmapped ops fall back to the op name UNPREFIXED rather than guessing a
    prefix: a wrong-but-plausible `fw_` name is harder to notice than a bare
    one, and every op that should carry a prefix is listed above.
    """
    return AUDIT_ACTION.get(op, op)

#: Authorisation is a property of WHICH PROCESS CONNECTED, resolved from the
#: kernel-supplied peer uid — never from anything in the request, so a caller
#: cannot claim to be a different peer.
#:
#: The unattended entry is NOT "the 3-layer model, weakened". There is no
#: credential because there is no human, and the control substituted for it is a
#: hard op allowlist: alert_watcher adds blocks and nothing else. It is made
#: STRUCTURALLY incapable of lifting a block or enumerating the ruleset,
#: regardless of what its own code does or is made to do.
PEER_POLICY = {
    "dashboard": {
        "ops": {"list_blocked", "list_rules", "block_ip", "deny_ip", "unblock_ip"},
        "require_credential": True,
        "audit_actor": None,          # the verified admin username
    },
    "alert-watcher": {
        # Adds blocks (temporary and permanent) and releases ONLY quarantines the
        # database independently confirms have already expired. It cannot lift an
        # arbitrary block, and cannot enumerate the ruleset.
        "ops": {"block_ip", "deny_ip", "expire_quarantine"},
        "require_credential": False,
        "audit_actor": "alert-watcher",
    },
    "fail2ban": {
        # Same structural pattern as alert-watcher, deliberately NOT a new trust
        # mechanism: an unattended peer, no credential because there is no human,
        # and a hard op allowlist as the substituted control.
        #
        # NARROWER than alert-watcher on purpose. fail2ban adds blocks and
        # nothing else — it has no expire_quarantine, because it does not own the
        # `quarantines` table and must not be able to release anything recorded
        # there. Unbanning is fail2ban's own bantime expiring and re-running its
        # actionunban, which routes back through block-removal on ITS side, not
        # through a lift op here. It is structurally incapable of lifting a block
        # placed by the dashboard or by alert-watcher, and of enumerating the
        # ruleset, regardless of what fail2ban's own config is made to say.
        #
        # record_fail2ban_quarantine (2026-07-30) does not change any of this:
        # nemesis_fwd writes that row itself, server-side, after block_ip has
        # already run — fail2ban's own op set stays exactly {block_ip, deny_ip}.
        "ops": {"block_ip", "deny_ip"},
        "require_credential": False,
        "audit_actor": "fail2ban",
    },
}

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_IPV6 = re.compile(r"^[0-9a-fA-F:]{2,45}$")


class Denied(Exception):
    """A verification layer refused the request."""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


# ── validation ───────────────────────────────────────────────────────────────

def valid_ip(value):
    """Strict IP validation. The helper builds ufw argv itself from validated
    fields — a caller never supplies raw ufw arguments, so `--rootdir=` and
    friends cannot be injected."""
    if not isinstance(value, str) or len(value) > 45:
        return False
    if _IPV4.match(value):
        return all(0 <= int(o) <= 255 for o in value.split("."))
    return bool(_IPV6.match(value)) and value.count(":") >= 2


# ── credential cache (view ops only) ─────────────────────────────────────────

class CredentialCache:
    """In-memory only. Never written to disk or the DB, never returned to the
    caller, and dropped entirely when this process restarts.

    Stores a verification FACT plus a timestamp — never the password, which is
    discarded as soon as bcrypt.checkpw returns.

    Idle timeout, not absolute: last_used refreshes on each accepted use, so an
    active admin is not re-prompted mid-session, while walking away expires it.
    """

    def __init__(self, idle_seconds):
        self._idle = idle_seconds
        self._entries = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(peer_uid, username, session_id):
        return (peer_uid, username, session_id or "")

    def remember(self, peer_uid, username, session_id):
        with self._lock:
            self._entries[self._key(peer_uid, username, session_id)] = time.monotonic()

    def check_and_refresh(self, peer_uid, username, session_id):
        """True if a live cache entry exists; refreshes its idle window."""
        k = self._key(peer_uid, username, session_id)
        now = time.monotonic()
        with self._lock:
            last = self._entries.get(k)
            if last is None:
                return False
            if now - last > self._idle:
                self._entries.pop(k, None)
                return False
            self._entries[k] = now
            return True

    def drop(self, peer_uid, username, session_id):
        with self._lock:
            return self._entries.pop(self._key(peer_uid, username, session_id), None) is not None

    def sweep(self):
        now = time.monotonic()
        with self._lock:
            for k in [k for k, t in self._entries.items() if now - t > self._idle]:
                self._entries.pop(k, None)


# ── database (ground truth for layers 2 and 3) ───────────────────────────────

@contextmanager
def _db():
    """Connection scope that GUARANTEES close(), for the helper's plain reads.

    Until 2026-07-29 this returned a bare ``sqlite3.Connection`` used as
    ``with _db() as conn:`` at all four call sites. That shape looks correct and
    still leaks: sqlite3's connection context manager is a TRANSACTION context
    manager — it commits or rolls back on exit and never closes — so every call
    leaked a connection and its file descriptor until the cyclic GC happened to
    collect it. Same mechanism, same anti-pattern, and the same warning already
    written up in ``modules/anomaly_detection/module.py``'s ``_db()``, whose
    docstring records the 2026-07-18 fd-exhaustion incident it caused there.

    It matters more in this process than in a periodic detection cycle: this is a
    long-lived socket server, so the leak accrues per REQUEST — up to three
    connections for a single deny (load_admin, a failed-attempt record, audit)
    with no natural process restart to reset the count.

    The inner ``with conn:`` preserves the exact commit/rollback semantics the
    call sites had before, so this change adds close() and nothing else. (This
    is why it is not a verbatim copy of anomaly_detection's close-only version.)
    """
    import sqlite3
    conn = sqlite3.connect(nemesis_paths.db_path(), timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def load_admin(username):
    """Layer 2. Read the account from the DB and apply every check here.

    Returns the row, or raises Denied. Deliberately does NOT distinguish
    'no such user' from 'not an admin' in the message returned to the caller —
    that would turn this into a username oracle.
    """
    if not isinstance(username, str) or not (1 <= len(username) <= 64):
        raise Denied("bad_request", "invalid username")
    try:
        with _db() as conn:
            row = conn.execute(
                "SELECT username, password_hash, role, is_active, lockout_until, "
                "failed_attempts, lockout_tier FROM users WHERE username = ?", (username,)
            ).fetchone()
    except Exception as exc:
        log.exception("fwd: user lookup failed")
        raise Denied("internal", "could not verify account: %s" % exc)

    if row is None or not row["is_active"] or row["role"] != "admin":
        raise Denied("admin_denied", "not an active admin account")

    lock = row["lockout_until"]
    if lock:
        try:
            from datetime import datetime
            if datetime.fromisoformat(lock) > datetime.now():
                raise Denied("locked_out", "account is locked out")
        except Denied:
            raise
        except Exception:
            pass
    return row


def verify_credential(row, password):
    """Layer 3. bcrypt check performed HERE against the stored hash."""
    if bcrypt is None:
        raise Denied("internal", "bcrypt unavailable in the helper")
    if not isinstance(password, str) or not password:
        raise Denied("credential_denied", "password required")
    try:
        ok = bcrypt.checkpw(password.encode(), (row["password_hash"] or "").encode())
    except Exception:
        log.exception("fwd: bcrypt check errored")
        raise Denied("internal", "credential check failed")
    if not ok:
        # Log the ACCOUNT and the fact of failure — never any property of the
        # password itself, including its length. Length is not harmless: it
        # narrows a brute-force space, and a security product has no business
        # recording it.
        _note_failed_attempt(row["username"])
        raise Denied("credential_denied", "invalid credentials")
    # Success: clear any accumulated failure/lockout state for this account.
    _clear_failed_attempts(row)
    return True


_DM = None


def _dm():
    """Lazy Data Manager, used ONLY for the helper's `users`-table writes.

    Routing these through the guard is what makes the column grant real rather
    than a comment: the DM physically refuses any UPDATE that touches a column
    outside {failed_attempts, lockout_until, lockout_tier}, so even a coding
    error in THIS file cannot make the firewall helper write password_hash,
    role, or is_active. Mode is ENFORCE, not warn — every users write here is
    new, deliberate code with a known column set, so there is no unknown legacy
    traffic to discover first, and a violation should be BLOCKED, not logged.
    Reads stay on the plain _db() connection (read-any; no guard needed).
    """
    global _DM
    if _DM is None:
        _DM = data_manager.DataManager(nemesis_paths.db_path())
        data_manager.set_namespace_mode("nemesis_fwd", data_manager.MODE_ENFORCE)
    return _DM


def _note_failed_attempt(username):
    """Record a failed credential attempt AND apply the tiered lockout.

    This is the throttle that stops the socket being used as an unthrottled
    password oracle. Incrementing a counter is not enough on its own — until
    2026-07-28 the helper incremented `failed_attempts` but never set a lockout,
    so an attacker hitting the socket directly got unlimited attempts while the
    counter climbed harmlessly. This now mirrors the dashboard login path: cross
    a tier and the account is locked for that tier's window, against the SAME
    shared lockout columns, so attempts from either surface count as one budget.

    Best-effort: a failure to record must never turn a refusal into anything
    else, so every error is logged and swallowed.
    """
    try:
        with _db() as conn:
            row = conn.execute(
                "SELECT id, failed_attempts, lockout_tier FROM users WHERE username=?",
                (username,)).fetchone()
        if row is None:
            return
        fa = int(row["failed_attempts"] or 0) + 1
        tier = int(row["lockout_tier"] or 0)

        # Highest tier newly crossed by this attempt (mirrors dashboard: keep the
        # highest, and never re-trigger a tier already applied).
        triggered = None
        for idx, (threshold, minutes) in enumerate(_LOCKOUT_TIERS, start=1):
            if fa >= threshold and tier < idx:
                triggered = (idx, minutes)

        guard = _dm().connect("nemesis_fwd")
        try:
            if triggered:
                tnum, minutes = triggered
                from datetime import datetime, timedelta
                lock_until = (datetime.now() + timedelta(minutes=minutes)).isoformat(
                    timespec="seconds")
                guard.execute(
                    "UPDATE users SET failed_attempts=?, lockout_until=?, lockout_tier=? "
                    "WHERE id=?", (fa, lock_until, tnum, row["id"]))
                guard.commit()
                log.warning("fwd: account %r locked out (tier %d, %d min) after "
                            "%d failed attempts", username, tnum, minutes, fa)
            else:
                guard.execute(
                    "UPDATE users SET failed_attempts=? WHERE id=?", (fa, row["id"]))
                guard.commit()
        finally:
            guard.close()
    except Exception:
        log.exception("fwd: could not record failed attempt for %s", username)


def _clear_failed_attempts(row):
    """Reset the lockout state after a SUCCESSFUL credential verification.

    Without this the counter only ever climbs: a legitimate admin who mistypes
    a few times then succeeds would march toward a lockout on their next
    honest slip. Mirrors the dashboard's reset-on-success. No-op when already
    clear, so the common success path does not write.
    """
    try:
        if not (row["failed_attempts"] or row["lockout_until"] or row["lockout_tier"]):
            return
    except Exception:
        pass
    try:
        guard = _dm().connect("nemesis_fwd")
        try:
            guard.execute(
                "UPDATE users SET failed_attempts=0, lockout_until=NULL, lockout_tier=0 "
                "WHERE username=?", (row["username"],))
            guard.commit()
        finally:
            guard.close()
    except Exception:
        log.exception("fwd: could not clear failed attempts for %s", row["username"])


# ── degraded-state signalling ────────────────────────────────────────────────
#
# PRE-WORK FOR THE STRUCTURED ERROR-CODE SYSTEM (intentional, 2026-07-28).
#
# This is deliberately NOT a bespoke alerting mechanism to be ripped out later.
# It is the first registered code of the error-code system that is still to be
# built, introduced here because this failure is REAL and already reproduced
# rather than hypothetical: until the lock-ordering fix in dashboard.py's
# `set_action`, every admin-initiated block lost its helper-side audit row to
# SQLITE_BUSY while still applying the ufw rule and returning 200. A privileged
# firewall change with no audit record is precisely what this helper exists to
# prevent, and it happened silently.
#
# Whoever builds the error-code system should design against THIS case first.
# The record shape below is kept minimal and stable on purpose — code, severity,
# timestamp, human-readable message, structured context — so it can be lifted
# into that system without reinterpretation. Consumers should match on `code`,
# never on the message text.
#
ERR_AUDIT_WRITE_FAILED = "NEM-FWD-0001"

#: Append-only degraded-state journal. Deliberately a FILE, not a DB table: the
#: canonical trigger for writing here is "the database was unwritable", so a
#: signal that also needs the database would be lost in exactly the case it
#: exists to report.
DEGRADED_LOG = os.environ.get(
    "NEMESIS_DEGRADED_LOG", "/var/lib/nemesis/degraded.jsonl")


def signal_degraded(code, message, severity="error", **context):
    """Record a non-fatal integrity failure that an operator MUST be able to see.

    POLICY (confirmed 2026-07-28): fail-open on the ACTION. A firewall change
    that has already been applied is never rolled back because its audit write
    failed — reverting a completed security control to preserve bookkeeping
    would be the worse failure. What is not acceptable is the failure being
    INVISIBLE, so this raises the signal on two independent channels:

      1. the journal, at ERROR, tagged with the stable code; and
      2. this append-only file, which the dashboard can surface.

    Best-effort by construction: signalling degradation must never itself become
    a new failure path, so every error here is swallowed after being logged.
    """
    log.error("fwd: [%s] %s | %s", code, message,
              " ".join("%s=%s" % kv for kv in sorted(context.items())))
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "code": code,
        "severity": severity,
        "message": message,
        "context": context,
    }
    try:
        # Opened per-write and closed immediately: this path is rare, and a
        # long-lived handle to a file that exists to report breakage is a
        # liability during exactly the incidents it must survive.
        fd = os.open(DEGRADED_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        try:
            os.write(fd, (json.dumps(rec, sort_keys=True) + "\n").encode())
        finally:
            os.close(fd)
    except Exception:
        # Two channels precisely so one surviving is enough.
        log.exception("fwd: could not append to degraded log %s", DEGRADED_LOG)


def audit(action, actor, ip=None, detail=None):
    """Per-action attribution, written by the helper using the identity IT
    verified — not the identity the caller claimed.

    Returns True if the record landed. Fail-open: a False return does NOT undo
    the action, but it is never silent — see signal_degraded above.

    Routed through the Data Manager (2026-07-29). This write used to go out on the
    plain `_db()` connection, which meant the helper's registered `audit_log`
    grant enforced nothing about it — the namespace said "nemesis_fwd may write
    audit_log" while the actual statement bypassed the guard entirely. The grant
    is now what permits the write, so the registry and the code agree, and the
    insert is recorded in dm_operation_log like every other mediated write.
    """
    guard = None
    try:
        guard = _dm().connect("nemesis_fwd")
        guard.execute(
            "INSERT INTO audit_log(ts, request_id, ip, action, user) VALUES (?,?,?,?,?)",
            (time.strftime("%Y-%m-%d %H:%M:%S"), detail, ip, action, actor))
        guard.commit()
        return True
    except Exception as exc:
        log.exception("fwd: audit write failed for %s/%s", action, actor)
        signal_degraded(
            ERR_AUDIT_WRITE_FAILED,
            "privileged firewall action succeeded but its audit record was lost",
            severity="error",
            # `audit_action`, not `op`: this is the already-prefixed audit_log
            # action name (e.g. "fw_deny_ip"), not the raw protocol op. Named
            # for what it actually holds so the error-code system inherits an
            # accurate field rather than one needing a footnote.
            audit_action=action, actor=actor, target_ip=ip, request_id=detail,
            cause=type(exc).__name__, detail=str(exc)[:200])
        return False
    finally:
        # GuardedConnection wraps sqlite3's TRANSACTION context manager and does
        # NOT close — the same shape that leaked an fd per request here until
        # 2026-07-29. Closed explicitly, matching _note_failed_attempt and
        # _clear_failed_attempts below.
        if guard is not None:
            guard.close()


def record_fail2ban_quarantine(ip, jail):
    """Give a fail2ban ban the same dashboard-visible record alert-watcher's
    own auto-quarantines get (2026-07-30).

    Before this, a fail2ban ban wrote only an audit_log row — real attribution,
    but not a first-class, actionable record. jail.local's own action config
    promises "lift from the Nemesis dashboard if required" (unban is a
    deliberate no-op — see PEER_POLICY["fail2ban"] and action.d/nemesis-fwd.conf),
    but with nothing in `quarantines`, there was nothing there to lift. This
    closes that gap: same table, same "Lift" button alert-watcher's rows
    already use.

    Does NOT change what fail2ban's peer may do. This is called from HERE,
    server-side, after nemesis_fwd itself has already executed block_ip on
    fail2ban's behalf — fail2ban never touches this table, never gets
    expire_quarantine or unblock_ip, and still cannot release a block placed by
    itself, the dashboard, or alert-watcher. It only makes what nemesis_fwd
    already did visible and liftable the normal way.

    expires_at is informational only, matching the no-op-unban contract: fail2ban
    still has no expire_quarantine grant, so nothing ever auto-releases this row
    on that timer. Only an admin's dashboard lift (a real, credentialed
    unblock_ip) changes its status.

    Best-effort: failure here must never be mistaken for the ban itself having
    failed. The ufw rule from op_block_ip is already in place by the time this
    runs; a failure recording the quarantine is a visibility gap, not an
    enforcement one, so it degrades the same way `audit`'s own failures do.
    """
    # jail comes from our own action config's <name> macro, not attacker
    # input, but the socket protocol doesn't type-check it — clamp defensively,
    # same posture as every other value this file takes from a caller.
    jail = re.sub(r"[^A-Za-z0-9_-]", "", (jail or "sshd"))[:64] or "sshd"
    rule_id = "fail2ban-%s" % jail
    now = datetime.now()
    expires = now + timedelta(hours=24)
    guard = None
    try:
        guard = _dm().connect("nemesis_fwd")
        existing = guard.execute(
            "SELECT id FROM quarantines WHERE ip=? AND rule_id=? AND status='active'",
            (ip, rule_id)).fetchone()
        if existing:
            return True
        guard.execute(
            "INSERT INTO quarantines (ip, rule_id, expires_at, created_at, status, actor) "
            "VALUES (?, ?, ?, ?, 'active', ?)",
            (ip, rule_id, expires.isoformat(), now.isoformat(), "fail2ban"))
        guard.commit()
        return True
    except Exception:
        log.exception("fwd: quarantine record failed for fail2ban ban of %s", ip)
        signal_degraded(
            ERR_AUDIT_WRITE_FAILED,
            "fail2ban ban succeeded but its dashboard quarantine record was lost",
            severity="warning", audit_action="fail2ban_quarantine_record",
            actor="fail2ban", target_ip=ip)
        return False
    finally:
        if guard is not None:
            guard.close()


# ── ufw operations (argv built here, never supplied by the caller) ───────────

def _run_ufw(*args):
    p = subprocess.run([UFW_BIN, *args], capture_output=True, text=True, timeout=30)
    return p.returncode, p.stdout, p.stderr


def op_list_blocked(params):
    rc, out, err = _run_ufw("status")
    if rc != 0:
        raise Denied("ufw_failed", err.strip() or "ufw status failed")
    ips = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1].upper() in ("DENY", "REJECT"):
            cand = parts[-1]
            if valid_ip(cand):
                ips.append(cand)
    return {"blocked": sorted(set(ips)), "raw_status": out}


def op_list_rules(params):
    rc, out, err = _run_ufw("status", "numbered")
    if rc != 0:
        raise Denied("ufw_failed", err.strip() or "ufw status numbered failed")
    return {"rules": out}


def _require_ip(params):
    ip = (params or {}).get("ip")
    if not valid_ip(ip):
        raise Denied("bad_request", "invalid or missing ip")
    return ip


def op_block_ip(params):
    ip = _require_ip(params)
    rc, out, err = _run_ufw("insert", "1", "deny", "from", ip)
    if rc != 0:
        raise Denied("ufw_failed", err.strip() or "ufw insert failed")
    return {"ip": ip, "output": out.strip()}


def op_deny_ip(params):
    ip = _require_ip(params)
    rc, out, err = _run_ufw("deny", "from", ip)
    if rc != 0:
        raise Denied("ufw_failed", err.strip() or "ufw deny failed")
    return {"ip": ip, "output": out.strip()}


def op_unblock_ip(params):
    ip = _require_ip(params)
    rc, out, err = _run_ufw("delete", "deny", "from", ip)
    if rc != 0:
        raise Denied("ufw_failed", err.strip() or "ufw delete failed")
    return {"ip": ip, "output": out.strip()}


def op_expire_quarantine(params):
    """Remove a deny rule ONLY for a quarantine the DB says has already expired.

    This exists so the unattended caller can run the expiry sweep without being
    given a general unblock capability. The authority is deliberately narrow:
    the helper re-derives, from the database, whether this specific IP has an
    `active` quarantine row whose `expires_at` is genuinely in the past. A
    compromised alert_watcher therefore cannot lift a block it merely WANTS
    lifted — only one the database independently says is already due.

    Without this check, `expire_quarantine` would just be `unblock_ip` wearing a
    different name.
    """
    ip = _require_ip(params)
    try:
        with _db() as conn:
            row = conn.execute(
                "SELECT id, expires_at FROM quarantines "
                "WHERE ip = ? AND status = 'active' "
                "ORDER BY id DESC LIMIT 1", (ip,)).fetchone()
    except Exception as exc:
        raise Denied("internal", "could not verify quarantine state: %s" % exc)

    if row is None:
        raise Denied("admin_denied",
                     "no active quarantine for %s — refusing to remove a rule "
                     "this caller cannot justify" % ip)

    from datetime import datetime
    try:
        expired = datetime.fromisoformat(row["expires_at"]) <= datetime.now()
    except Exception:
        raise Denied("internal", "unparseable expires_at for quarantine %s" % row["id"])
    if not expired:
        raise Denied("admin_denied",
                     "quarantine %s for %s has not expired yet" % (row["id"], ip))

    rc, out, err = _run_ufw("delete", "deny", "from", ip)
    if rc != 0:
        # ufw exits non-zero when no matching rule exists. That is not a failure
        # for expiry — the desired end state (no rule) already holds.
        log.info("fwd: expire_quarantine %s — ufw delete rc=%d (%s)", ip, rc, err.strip())
    return {"ip": ip, "quarantine_id": row["id"], "output": out.strip()}


OPS = {
    "expire_quarantine": op_expire_quarantine,
    "list_blocked": op_list_blocked,
    "list_rules": op_list_rules,
    "block_ip": op_block_ip,
    "deny_ip": op_deny_ip,
    "unblock_ip": op_unblock_ip,
}


# ── wire protocol ────────────────────────────────────────────────────────────

def send_msg(sock, obj):
    b = json.dumps(obj).encode()
    sock.sendall(HDR.pack(len(b)) + b)


def recv_msg(sock):
    hdr = b""
    while len(hdr) < 4:
        c = sock.recv(4 - len(hdr))
        if not c:
            return None
        hdr += c
    n = HDR.unpack(hdr)[0]
    if n > MAX_REQUEST_BYTES:
        raise Denied("bad_request", "request too large")
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            return None
        buf += c
    return json.loads(buf.decode())


def peer_credentials(conn):
    """Layer 1 — from the kernel, not from the request."""
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    return pid, uid, gid


class Helper:
    def __init__(self, peer_uids, cache):
        #: uid -> policy name. Resolved once at startup.
        self.peer_uids = peer_uids
        self.cache = cache

    def handle(self, req, peer):
        pid, uid, _gid = peer

        # ---- layer 1: which process is this, per the kernel ---------------
        peer_name = self.peer_uids.get(uid)
        if peer_name is None:
            raise Denied("peer_denied",
                         "caller uid %d is not an authorised peer" % uid)
        policy = PEER_POLICY[peer_name]

        if not isinstance(req, dict):
            raise Denied("bad_request", "malformed request")
        op = req.get("op")
        if op == "ping":
            return {"pong": True}

        actor = req.get("actor") or {}
        username = actor.get("username")
        session_id = actor.get("session_id")

        if op == "drop_credential":
            # Dropping your own cached credential is never a privileged act, so
            # it needs no credential — requiring one would be circular.
            dropped = self.cache.drop(uid, username, session_id)
            return {"dropped": dropped}

        if op not in OPS:
            raise Denied("bad_request", "unknown op: %r" % (op,))

        # ---- op allowlist for THIS peer ------------------------------------
        # Checked before anything else touches the DB: an unauthorised op is
        # refused on identity alone, and never becomes a credential probe.
        if op not in policy["ops"]:
            raise Denied("peer_denied",
                         "peer %r may not invoke %r" % (peer_name, op))

        if not policy["require_credential"]:
            # Unattended path. Layer 1 + the narrow allowlist ARE the control.
            params = req.get("params") or {}
            result = OPS[op](params)
            actor = policy["audit_actor"]
            audit(audit_action_for(op), actor, ip=params.get("ip"),
                  detail=req.get("request_id"))
            if peer_name == "fail2ban" and op == "block_ip":
                # See record_fail2ban_quarantine's docstring: this makes the
                # ban dashboard-visible and liftable. It does not give fail2ban
                # any new op — the write happens here, not through the peer.
                record_fail2ban_quarantine(params.get("ip"), params.get("jail"))
            log.info("fwd: %s ok for peer=%s (pid=%d, unattended)", op, peer_name, pid)
            return result

        # ---- layer 2 -------------------------------------------------------
        row = load_admin(username)

        # ---- layer 3 -------------------------------------------------------
        # Writes ALWAYS require a fresh password. The view cache can never
        # satisfy a write, regardless of its state.
        if op in READ_OPS and self.cache.check_and_refresh(uid, username, session_id):
            fresh = False
        else:
            verify_credential(row, (req.get("credential") or {}).get("password"))
            fresh = True
            if op in READ_OPS:
                self.cache.remember(uid, username, session_id)

        result = OPS[op](req.get("params") or {})

        if op in WRITE_OPS:
            audit(audit_action_for(op), row["username"],
                  ip=(req.get("params") or {}).get("ip"),
                  detail=req.get("request_id"))
        log.info("fwd: %s ok for %s (pid=%d, fresh_credential=%s)",
                 op, row["username"], pid, fresh)
        return result


def serve(helper, sock_path, group_name):
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    os.makedirs(os.path.dirname(sock_path), exist_ok=True)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    try:
        os.chown(sock_path, 0, grp.getgrnam(group_name).gr_gid)
    except KeyError:
        log.warning("fwd: group %s missing — socket left root-owned", group_name)
    os.chmod(sock_path, 0o660)
    srv.listen(32)
    log.info("fwd: listening on %s (mode 0660, group %s)", sock_path, group_name)

    sel = selectors.DefaultSelector()
    sel.register(srv, selectors.EVENT_READ, None)
    last_sweep = time.monotonic()

    while True:
        for key, _ in sel.select(timeout=1.0):
            if key.data is None:
                conn, _ = srv.accept()
                sel.register(conn, selectors.EVENT_READ, True)
                continue
            conn = key.fileobj
            try:
                req = recv_msg(conn)
                if req is None:
                    sel.unregister(conn); conn.close(); continue
                resp = {"ok": True, "request_id": (req or {}).get("request_id"),
                        "result": helper.handle(req, peer_credentials(conn)),
                        "error": None, "error_kind": None}
            except Denied as d:
                log.warning("fwd: denied (%s): %s", d.kind, d)
                resp = {"ok": False, "request_id": None, "result": None,
                        "error": str(d), "error_kind": d.kind}
            except Exception as exc:
                log.exception("fwd: internal error")
                resp = {"ok": False, "request_id": None, "result": None,
                        "error": str(exc), "error_kind": "internal"}
            try:
                send_msg(conn, resp)
            except Exception:
                pass
            try:
                sel.unregister(conn); conn.close()
            except Exception:
                pass

        if time.monotonic() - last_sweep > 60:
            helper.cache.sweep()
            last_sweep = time.monotonic()


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s",
                        stream=sys.stdout)
    if os.geteuid() != 0:
        print("FATAL: nemesis-fwd must run as root — ufw enforces a real-UID "
              "check that no capability grant satisfies.", file=sys.stderr)
        sys.exit(78)

    # No default, no guess: an unset peer identity is a configuration error and
    # is reported as one. Refusing to start is the loud failure — the quiet one
    # would be starting with some assumed account and authorising the wrong
    # process, or silently locking the real dashboard out of the firewall.
    if not DASH_USER:
        print("FATAL: NEMESIS_DASH_USER is not set. It has no default: this is "
              "the OS user authorised as the dashboard peer, and guessing it "
              "would either lock out the real dashboard or authorise the wrong "
              "account. Set it in the unit (Environment=NEMESIS_DASH_USER=...).",
              file=sys.stderr)
        sys.exit(78)

    # Ensure the audit table exists BEFORE serving. This helper is one of the
    # table's two writers but was never one of its creators: the only creation
    # path was dashboard's _ensure_audit_log_table(), called LAZILY from _audit()
    # — so on a fresh install, any firewall action occurring before the first
    # dashboard action wrote into a table that did not exist yet.
    #
    # That is the normal case, not an edge case, and the 2026-07-31 VM install
    # test hit it immediately: a fail2ban ban and an alert-watcher block both
    # applied their ufw rules successfully and both LOST their audit records
    # ("no such table: audit_log"). The fail-open design meant the firewall still
    # worked and the loss was signalled loudly in two channels rather than being
    # silent — which is why it was findable — but a privileged action with no
    # audit trail is exactly what this helper exists to prevent.
    #
    # Safe from here: init_audit_log_table() is IF NOT EXISTS, idempotent, and
    # documented as runnable from any process on a raw connection (no Data
    # Manager grant needed). Failure is non-fatal — the helper's whole point is
    # to keep the firewall working — but it is logged, and the per-write
    # signal_degraded path still reports any record that is subsequently lost.
    try:
        import database
        database.init_audit_log_table()
        log.info("fwd: audit_log table ensured at startup")
    except Exception as exc:
        log.error("fwd: could not ensure audit_log table (%s) — firewall actions "
                  "will still apply, but their audit records may be lost", exc)

    peer_uids = {}
    for policy_name, user in (("dashboard", DASH_USER), ("alert-watcher", ALERTW_USER),
                              ("fail2ban", FAIL2BAN_USER)):
        try:
            peer_uids[pwd.getpwnam(user).pw_uid] = policy_name
        except KeyError:
            if policy_name == "dashboard":
                print("FATAL: dashboard user %r does not exist" % user, file=sys.stderr)
                sys.exit(78)
            log.warning("fwd: %s user %r absent — that peer cannot connect", policy_name, user)
    log.info("fwd: authorised peers: %s",
             ", ".join("%s(uid=%d)" % (n, u) for u, n in sorted(peer_uids.items())))

    idle = DEFAULT_CACHE_IDLE_SECONDS
    try:
        idle = int(os.environ.get("NEMESIS_FWD_CACHE_IDLE", idle))
    except ValueError:
        pass
    log.info("fwd: credential cache idle=%ds", idle)

    helper = Helper(peer_uids, CredentialCache(idle))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    serve(helper, SOCKET_PATH, SOCKET_GROUP)


if __name__ == "__main__":
    main()
