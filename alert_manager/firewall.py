"""Shared helpers for parsing Suricata fast.log lines and managing UFW rules.

The ADR-0005 firewall chokepoint. Nothing in Nemesis calls ufw directly any
more: every operation goes through nemesis-fwd, the privileged helper that owns
the privilege and verifies the caller before acting.

WHY THIS CHANGED (2026-07-28). ufw enforces an application-level real-UID check
(`ufw/util.py`: `if do_checks and os.getuid() != 0: raise OSError(EPERM)`), so a
hardened, de-privileged service can never drive it — capabilities change what a
process may DO, never what getuid() RETURNS. When alert_watcher was
de-privileged its `sudo -n ufw` calls began failing, and the previous
`load_blocked_ips()` turned that failure into an empty set with nothing logged:

    rc, out, _err = _run_ufw("status")
    if rc != 0:
        return set()          # indistinguishable from "nothing is blocked"

FAIL LOUD. Every function here now raises on transport failure or refusal. A
firewall action that silently does nothing is worse than one that loudly
refuses, and the silent version is precisely what hid the outage.

`load_blocked_ips()` is GONE, not reimplemented. alert_watcher used it for a
dedup cache; block operations are idempotent at the ufw level, so the cache was
an optimisation whose only real effect was to hide this failure.

TWO CALLER PATHS, distinguished by the helper's peer policy, not by anything
asserted here:
  * unattended (alert_watcher) — no credential. Allowed block_ip, deny_ip and
    expire_quarantine; structurally incapable of anything else.
  * admin (dashboard) — every write needs a fresh admin password, verified by
    the helper against the stored bcrypt hash.
"""

import logging
import ipaddress
from datetime import datetime

import fw_client
from fw_client import (  # noqa: F401  (re-exported for callers)
    FirewallError, FirewallDenied, FirewallUnavailable,
)

log = logging.getLogger(__name__)


def _valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False


# ── unattended path (alert_watcher) ──────────────────────────────────────────

def ufw_insert_top(ip):
    """Auto-quarantine: deny rule at position 1. Raises on failure.

    Idempotent at the ufw level — re-adding an existing deny is harmless, which
    is why the dedup cache was removed rather than replaced.
    """
    if not _valid_ip(ip):
        raise ValueError("refusing to block invalid IP: %r" % (ip,))
    fw_client.block_ip(ip)
    log.info("firewall: block_ip %s applied via nemesis-fwd", ip)
    return True


def ufw_deny_append(ip, username=None, session_id=None, password=None):
    """Append a deny rule (permanent block).

    Reached both unattended (alert_watcher's `block` action) and by an admin.
    Credential arguments are forwarded untouched; the HELPER decides what its
    peer policy requires. This side never asserts privilege on its own behalf.
    """
    if not _valid_ip(ip):
        raise ValueError("refusing to deny invalid IP: %r" % (ip,))
    fw_client.deny_ip(ip, username, session_id, password)
    log.info("firewall: deny_ip %s applied via nemesis-fwd", ip)
    return True


def expire_quarantine(ip):
    """Release a quarantine the DATABASE confirms has already expired.

    Deliberately NOT a general unblock. The helper independently re-derives from
    the `quarantines` table whether this IP has an active row past its
    expires_at, and refuses otherwise — so an unattended caller cannot lift a
    block it merely wants lifted, only one already due for release.
    """
    if not _valid_ip(ip):
        raise ValueError("refusing to expire invalid IP: %r" % (ip,))
    fw_client.expire_quarantine(ip)
    log.info("firewall: expire_quarantine %s applied via nemesis-fwd", ip)
    return True


# ── admin path (dashboard) — fresh credential required for every write ───────

def ufw_delete(ip, username, session_id, password):
    """Admin-initiated unblock. The password is verified by the helper against
    the stored hash; this process never sees a verification result it could
    forge."""
    if not _valid_ip(ip):
        raise ValueError("refusing to unblock invalid IP: %r" % (ip,))
    fw_client.unblock_ip(ip, username, session_id, password)
    log.info("firewall: unblock_ip %s applied via nemesis-fwd by %s", ip, username)
    return True


def list_blocked(username, session_id, password=None):
    """Admin view of blocked IPs. Gated by the same credential as writes; the
    helper may satisfy it from its short idle-timeout cache."""
    return fw_client.list_blocked(username, session_id, password).get("blocked", [])


def list_rules(username, session_id, password=None):
    """Full numbered ruleset, for the queued rules-management feature."""
    return fw_client.list_rules(username, session_id, password).get("rules", "")


def parse_alert(alert_line):
    """Parse a Suricata fast.log line into a structured dict, or None on failure."""
    try:
        timestamp = ""
        ts_token = alert_line.split(" ", 1)[0] if alert_line else ""
        if "/" in ts_token and "-" in ts_token:
            try:
                dt = datetime.strptime(ts_token, "%m/%d/%Y-%H:%M:%S.%f")
                timestamp = dt.strftime("%H:%M:%S")
            except ValueError:
                timestamp = ""
        priority = 3
        if "Priority: 1" in alert_line:
            priority = 1
        elif "Priority: 2" in alert_line:
            priority = 2
        rule_id = ""
        rule_name = ""
        classification = ""
        src_ip = ""
        dst_ip = ""
        protocol = ""
        if "[**] [" in alert_line:
            rule_part = alert_line.split("[**] [")[1].split("]")[0]
            rule_id = rule_part.split(":")[1] if ":" in rule_part else rule_part
        if "[**]" in alert_line:
            parts = alert_line.split("[**]")
            if len(parts) > 2:
                rule_name = parts[2].strip()
        if "[Classification:" in alert_line:
            classification = alert_line.split("[Classification:")[1].split("]")[0].strip()
        if "{" in alert_line and "}" in alert_line:
            protocol = alert_line.split("{")[1].split("}")[0]
        if "->" in alert_line and "} " in alert_line:
            flow = alert_line.split("} ")[1]
            if "->" in flow:
                parts = flow.split("->")
                src_ip = parts[0].strip().split(":")[0]
                dst_ip = parts[1].strip().split(":")[0]
        return {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "classification": classification,
            "priority": priority,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "raw": alert_line,
        }
    except Exception as e:
        log.warning("parse_alert failed: %s", e)
        return None
