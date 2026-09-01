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

def block_ip(ip, username=None, session_id=None, password=None, jail=None):
    """Add a deny rule at the top. The only op alert_watcher may invoke.

    Idempotent at the ufw level, which is why alert_watcher no longer keeps a
    dedup cache — the cache was an optimisation, and the empty-set-on-failure
    it relied on is exactly what hid the outage.

    `jail` (2026-07-30): fail2ban's ban shim only — which jail triggered this
    ban (e.g. "sshd", "sshd-tailnet"), so nemesis_fwd can tag the resulting
    quarantine record with it. Ignored by every other caller.
    """
    params = {"ip": ip}
    if jail:
        params["jail"] = jail
    return _request("block_ip", params, username, session_id, password)


def failsafe_revert(token, source_ip=None):
    """Revert the ONE pending firewall change a revert token was minted for.

    ADR 0019 Amendment 03 §4. Same shape as `expire_quarantine` above and for the
    same reason: the helper validates independently rather than trusting the
    caller. Here that matters more, because this is the one op reachable from an
    UNAUTHENTICATED request.

    THE TOKEN IS THE CREDENTIAL, AND THE HELPER — NOT THE DASHBOARD — CHECKS IT.
    Every other write op takes a username/session/password because a logged-in
    human is behind it. This endpoint exists precisely for the case where the
    admin CANNOT log in (the firewall change may have broken their path to the
    dashboard), so a session credential would make it useless exactly when it is
    needed. Moving validation helper-side is what keeps that safe: the dashboard
    forwards what the caller presented and learns nothing from the outcome it
    could not already see, so a COMPROMISED DASHBOARD STILL CANNOT REVERT without
    a valid, unspent token. That is strictly stronger than validating in the web
    process, not a relaxation of it.

    `source_ip` is recorded by the helper for the audit row. It is caller-supplied
    and therefore NOT trusted as identity — it is a log field, never a check.
    """
    params = {"token": token}
    if source_ip:
        params["source_ip"] = source_ip
    return _request("failsafe_revert", params)


def expire_quarantine(ip):
    """Release a quarantine the helper independently confirms has expired.

    Narrower than unblock by design: the helper checks the `quarantines` table
    itself, so this cannot be used to lift an arbitrary block.
    """
    return _request("expire_quarantine", {"ip": ip})


def magicdns_switch(enable):
    """Ask the helper to toggle Tailscale's accept-dns. UNATTENDED path.

    Narrower than it looks, by design: the helper RE-MEASURES the DNS conflict
    itself and refuses when its own verdict disagrees. This sends a REQUEST, never
    a VERDICT -- the same shape as expire_quarantine, where the helper checks the
    table rather than trusting the caller. A compromised caller gains nothing it
    could not already have by breaking its own DNS.
    """
    return _request("magicdns_switch", {"enable": bool(enable)})


def resolvconf_repair():
    """Ask the helper to make on-disk resolv.conf ownership match the preference.

    Takes no arguments BY DESIGN: the caller names no target and picks no action.
    The helper measures everything and can only ever create one fixed symlink.
    """
    return _request("resolvconf_repair", {})


# ── admin path (dashboard) — every write needs a fresh credential ────────────

def deny_ip(ip, username, session_id, password):
    return _request("deny_ip", {"ip": ip}, username, session_id, password)


def unblock_ip(ip, username, session_id, password):
    return _request("unblock_ip", {"ip": ip}, username, session_id, password)


# ── admin path: privileged non-firewall ops (2026-07-31) ─────────────────────
#
# These are NOT firewall operations, and they are the point at which this client
# stops being purely a ufw front-end. They exist because dashboard was
# de-privileged: it has no sudo at all now, so restarting itself and writing
# /etc/nemesis.env both have to be asked of the helper.
#
# Same credential rule as every other write: a fresh admin password each time,
# verified by nemesis-fwd against the stored hash. Nothing is cached this side.

def write_env(values, username, session_id, password):
    """Merge key/value pairs into /etc/nemesis.env.

    `values` is a plain {KEY: value} dict — never a file body. The helper owns
    the allowlist, the value validation and the file write; this side sends
    intent, not content. That is deliberate: a check performed here would be
    bypassed by exactly the compromise the helper is designed to contain.
    """
    return _request("write_env", {"values": values}, username, session_id, password)


def gateway_switch(enable, iface, cidr, username, session_id, password):
    """Enable or disable Gateway Mode. Transactional, with verified rollback.

    Sends INTENT only -- `enable` plus, when enabling, the LAN interface and its
    CIDR. Every check that matters (the interface exists on the box, the CIDR is
    private IPv4, the canonical spelling) is the helper's, for the same reason
    write_env states: a check performed here is one a compromised dashboard skips.

    The whole switch is ONE op deliberately. It is a transaction that rolls back
    in reverse order on any failed step; splitting it across three calls would put
    that transaction across three round-trips, where a crash in between leaves a
    half-applied state with nothing left to undo it.

    Returns the helper's result dict: {"ok", "phase", "reason", ...}. A failure is
    a returned result, not an exception -- `phase` says how far it got and
    `restored` says whether the box was measurably put back.
    """
    return _request("gateway_switch",
                    {"enable": bool(enable), "iface": iface, "cidr": cidr},
                    username, session_id, password)


def write_email_secret(key, value, token, source_ip=None):
    """Write ONE email app password, authorised by an enrollment code.

    NO username/session/password, and that is the point: the caller is a
    household member completing an enrollment link, who has no dashboard login at
    all (ADR 0028 D11.5 Option C). The enrollment CODE is the credential.

    This side does not validate the code and deliberately cannot -- the helper
    hashes it, consumes it atomically against a single-use TTL-bounded row, and
    only then writes the file. A compromised dashboard forwards bytes it cannot
    forge, so it still cannot write a credential without a valid unspent code.

    Returns the helper's reply, which carries the authoritative `owner_user_id`
    read from the consumed row -- use THAT to attribute the mailbox, never a
    value chosen on this side.

    `source_ip` is recorded by the helper for the audit row. Caller-supplied and
    therefore NOT trusted as identity -- a log field, never a check, exactly as
    in `failsafe_revert`.
    """
    return _request("write_email_secret",
                    {"values": {key: value}, "token": token,
                     "source_ip": source_ip})


def restart_dashboard(username, session_id, password):
    """Restart dashboard.service. Takes no target — the helper restarts one
    named unit and offers no way to name another."""
    return _request("restart_dashboard", {}, username, session_id, password)


def reclaim_shm(shmid, username, session_id, password):
    """Release one orphaned SysV shared-memory segment, via the privileged helper.

    Only an integer shmid crosses the boundary. This side deliberately does NOT
    send an "it is orphaned" assertion: the helper re-derives all three orphan
    conditions itself (nattch==0, absent from every /proc/*/maps, creator pid
    dead) immediately before removing anything. Vouching from here would both
    trust the unprivileged process the split exists to constrain, and leave the
    listing->action race open on the wrong side of the boundary.
    """
    return _request("reclaim_shm", {"shmid": int(shmid)},
                    username, session_id, password)


def reap_zombie(pid, username, session_id, password):
    """Clear one zombie process, via the privileged helper.

    Only an integer pid crosses the boundary -- deliberately NOT the parent,
    the case, the unit or the starttime, even though this side computed all of
    them for the listing. The helper re-derives every one of them, and confirms
    the pid really is a zombie before acting on its parent.

    That is not redundancy. This process cannot terminate or restart anything
    it does not own (uid 973, CapEff=0), so the privilege genuinely lives over
    there; and the values this side computed came from a classifier that, run
    from here, CANNOT see a user's systemd manager. Sending them would be
    forwarding a known-unreliable answer under the authority of a root helper.
    """
    return _request("reap_zombie", {"pid": int(pid)},
                    username, session_id, password)


def deny_port_on_interface(iface, port, proto="tcp",
                           username=None, session_id=None, password=None):
    """Ask the helper to drop inbound tcp/`port` arriving on `iface` (raw table).

    The helper allowlists BOTH arguments, so this cannot become a general
    port-blocking call however it is invoked. See nemesis_fwd.DENY_IFACE_ALLOWED.
    """
    return _request("deny_port_on_interface",
                    {"iface": iface, "port": int(port), "proto": proto},
                    username=username, session_id=session_id, password=password)


def allow_port_on_interface(iface, port, proto="tcp",
                            username=None, session_id=None, password=None):
    """Remove that rule -- the revert half, as a first-class operation."""
    return _request("allow_port_on_interface",
                    {"iface": iface, "port": int(port), "proto": proto},
                    username=username, session_id=session_id, password=password)


def reassert_port_deny_on_interface(iface, port, proto="tcp",
                                    username=None, session_id=None, password=None):
    """Ask the helper to ensure the deny rule is present AND at position 1.

    Not the same call as deny_port_on_interface: that one is idempotent on existence
    and so cannot repair a rule that exists but is no longer reached. See
    nemesis_fwd.op_reassert_port_deny_on_interface.
    """
    return _request("reassert_port_deny_on_interface",
                    {"iface": iface, "port": int(port), "proto": proto},
                    username=username, session_id=session_id, password=password)


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
