"""Client for nemesis-fwd, the privileged ufw helper.

Callers never touch ufw. They send a request over the local socket and the
helper — which owns the privilege — verifies identity, authorisation and (for
admin actions) a credential before doing anything.

FAIL LOUD, NEVER FAIL QUIET. The predecessor of this module,
`firewall.load_blocked_ips()`, returned an empty set when the ufw call failed:

    rc, out, _err = _run_ufw("status")
    if rc != 0:
        return set()

That is how alert_watcher spent a day reporting "loaded 0 already-blocked IPs"
while ufw actually held four deny rules, with nothing logged and the service
looking healthy. Every function here raises FirewallUnavailable on transport
failure and FirewallDenied on refusal. Nothing converts a failure into a
plausible-looking empty result.
"""

import json
import logging
import os
import socket
import struct
import uuid

SOCKET_PATH = os.environ.get("NEMESIS_FWD_SOCKET", "/run/nemesis/fwd.sock")
HDR = struct.Struct("!I")
TIMEOUT = 35.0

log = logging.getLogger("nemesis.fw_client")


class FirewallError(Exception):
    """Base for every failure reaching or being refused by the helper."""


class FirewallUnavailable(FirewallError):
    """The helper could not be reached. Callers MUST fail closed."""


class FirewallDenied(FirewallError):
    """The helper refused. `kind` is the protocol error_kind enum value."""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


def _request(op, params=None, username=None, session_id=None, password=None):
    req = {
        "op": op,
        "params": params or {},
        "actor": {"username": username, "session_id": session_id},
        "request_id": str(uuid.uuid4()),
    }
    if password is not None:
        req["credential"] = {"password": password}

    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect(SOCKET_PATH)
    except OSError as exc:
        # Not running, socket missing, permission denied — all fail closed.
        raise FirewallUnavailable(
            "nemesis-fwd unreachable at %s: %s" % (SOCKET_PATH, exc)) from exc

    try:
        body = json.dumps(req).encode()
        s.sendall(HDR.pack(len(body)) + body)

        hdr = b""
        while len(hdr) < 4:
            c = s.recv(4 - len(hdr))
            if not c:
                raise FirewallUnavailable("helper closed the connection mid-request")
            hdr += c
        n = HDR.unpack(hdr)[0]
        buf = b""
        while len(buf) < n:
            c = s.recv(n - len(buf))
            if not c:
                raise FirewallUnavailable("helper closed the connection mid-response")
            buf += c
        resp = json.loads(buf.decode())
    except FirewallError:
        raise
    except Exception as exc:
        raise FirewallUnavailable("nemesis-fwd transport error: %s" % exc) from exc
    finally:
        try:
            s.close()
        except Exception:
            pass

    if not resp.get("ok"):
        kind = resp.get("error_kind") or "internal"
        msg = resp.get("error") or "request refused"
        # Deliberately logged at WARNING, not swallowed: a refused firewall
        # action must be visible in the journal.
        log.warning("fw_client: %s refused (%s): %s", op, kind, msg)
        raise FirewallDenied(kind, msg)
    return resp.get("result") or {}


def ping():
    """Liveness check. Raises FirewallUnavailable if the helper is not there."""
    return _request("ping")


# ── unattended path (alert_watcher) ──────────────────────────────────────────

def block_ip(ip, username=None, session_id=None, password=None):
    """Add a deny rule at the top. The only op alert_watcher may invoke.

    Idempotent at the ufw level, which is why alert_watcher no longer keeps a
    dedup cache — the cache was an optimisation, and the empty-set-on-failure
    it relied on is exactly what hid the outage.
    """
    return _request("block_ip", {"ip": ip}, username, session_id, password)


def expire_quarantine(ip):
    """Release a quarantine the helper independently confirms has expired.

    Narrower than unblock by design: the helper checks the `quarantines` table
    itself, so this cannot be used to lift an arbitrary block.
    """
    return _request("expire_quarantine", {"ip": ip})


# ── admin path (dashboard) — every write needs a fresh credential ────────────

def deny_ip(ip, username, session_id, password):
    return _request("deny_ip", {"ip": ip}, username, session_id, password)


def unblock_ip(ip, username, session_id, password):
    return _request("unblock_ip", {"ip": ip}, username, session_id, password)


def list_blocked(username, session_id, password=None):
    """Password may be omitted if the helper still holds a live cached
    verification for this (peer, user, session). The helper decides — the
    caller cannot assert that it is cached."""
    return _request("list_blocked", {}, username, session_id, password)


def list_rules(username, session_id, password=None):
    return _request("list_rules", {}, username, session_id, password)


def drop_credential(username, session_id):
    """Immediately invalidate this session's cached view credential.

    Called on tab visibility/focus loss. Best-effort acceleration only — the
    helper's idle timeout is the guarantee that holds regardless of whether a
    client ever sends this.
    """
    return _request("drop_credential", {}, username, session_id)
