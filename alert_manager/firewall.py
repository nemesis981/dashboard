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

import os
import socket
import struct
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


# ── never-block guard ────────────────────────────────────────────────────────
#
# Lives HERE, at the ADR-0005 chokepoint, rather than in any one caller. It used
# to exist only as alert_watcher._blockable(), which guarded the AUTOMATED
# quarantine path — so the automated path was protected and the human-triggered
# one was not. The dashboard would happily insert a deny rule against this host's
# own LAN address, which is the opposite of the protection you would expect.
# Putting it at the chokepoint means every caller inherits it, including callers
# that do not exist yet.
#
# Loopback is unconditional. The rest comes from two sources, deliberately both:
#
#   1. RUNTIME-DERIVED local addresses. The host's own addresses are discovered
#      from the live interface list, so this cannot be forgotten at install time,
#      cannot go stale when DHCP moves the LAN address, and covers the tailnet
#      address without anyone naming it. Configuration that must be remembered is
#      configuration that gets missed — NEMESIS_NEVER_BLOCK is unset on a fresh
#      install today for exactly that reason.
#   2. RUNTIME-DERIVED default gateways, from /proc. Not local, so interface
#      enumeration cannot see them, and the single most damaging address to block.
#   3. NEMESIS_NEVER_BLOCK — the operator escape hatch, and ONLY that. Local
#      addresses and gateways are covered automatically above, so this is for
#      things automation cannot infer: an internal DNS server, a NAS, a
#      management host. Ships EMPTY.
#
# Applied to the BLOCK paths only. It is deliberately NOT applied to unblock or
# expire: refusing to REMOVE a rule on a protected address would block the exact
# repair someone would need if one ever got there by another route.

_NEVER_BLOCK_ALWAYS = {"127.0.0.1", "::1"}


def _local_addresses():
    """Every address currently configured on this host.

    Best-effort by design: if the interface list cannot be read, the guard falls
    back to loopback + NEMESIS_NEVER_BLOCK rather than failing the block. A
    firewall that refuses to work because it could not enumerate interfaces would
    be a worse failure than the one this guards against — but the degradation is
    logged, never silent.
    """
    found = set()
    try:
        import psutil
        for _iface, snics in psutil.net_if_addrs().items():
            for snic in snics:
                if snic.family in (socket.AF_INET, socket.AF_INET6):
                    addr = (snic.address or "").split("%")[0]  # strip zone id
                    if addr:
                        found.add(addr)
    except Exception as exc:
        log.warning("firewall: could not enumerate local addresses (%s) — "
                    "never-block guard falls back to loopback + "
                    "NEMESIS_NEVER_BLOCK only", exc)
    return found


def _default_gateways():
    """Default-route gateway addresses, read from /proc.

    The one protected address that is NOT local, so runtime interface enumeration
    cannot find it — and the most damaging single address to block, since denying
    the gateway cuts this host off its own network entirely.

    Read from /proc/net/route and /proc/net/ipv6_route rather than shelling out to
    `ip route`: a file read needs no subprocess and no iproute2 binary inside a
    sandboxed unit, matching the reasoning device_scanner uses for /proc/net/arp.

    Derived per call rather than configured, for the same reason as the local
    addresses: a gateway written into config at install time goes stale the moment
    DHCP hands out a different one, and a stale protection is worse than none
    because it reads as covered.
    """
    gws = set()
    try:
        with open("/proc/net/route") as fh:
            next(fh, None)                      # header
            for line in fh:
                f = line.split()
                # Destination 00000000 == default route; Gateway 0 == on-link.
                if len(f) > 2 and f[1] == "00000000" and f[2] != "00000000":
                    gws.add(socket.inet_ntoa(struct.pack("<L", int(f[2], 16))))
    except Exception as exc:
        log.warning("firewall: could not read IPv4 default route (%s) — "
                    "gateway not added to the never-block set", exc)
    try:
        with open("/proc/net/ipv6_route") as fh:
            for line in fh:
                f = line.split()
                # dest prefix all-zero == default; field 4 is the next hop.
                if len(f) > 4 and f[0] == "0" * 32 and f[4] != "0" * 32:
                    gws.add(socket.inet_ntop(socket.AF_INET6, bytes.fromhex(f[4])))
    except Exception as exc:
        log.warning("firewall: could not read IPv6 default route (%s) — "
                    "gateway not added to the never-block set", exc)
    return gws


def never_block_set():
    """Addresses this host must never deny. Recomputed per call, not cached:
    interfaces come and go (tailnet up/down, DHCP renewal) and blocks are rare,
    so a stale cache buys nothing and could miss a current address."""
    never = set(_NEVER_BLOCK_ALWAYS)
    never |= {a.strip() for a in os.environ.get("NEMESIS_NEVER_BLOCK", "").split(",")
              if a.strip()}
    never |= _local_addresses()
    never |= _default_gateways()
    return never


def _guard_never_block(ip, op):
    """Refuse a block against a protected address. Raises FirewallDenied."""
    if ip in never_block_set():
        log.error("REFUSING %s for %s — address is this host's own or is listed "
                  "in NEMESIS_NEVER_BLOCK. No rule was applied.", op, ip)
        raise FirewallDenied(
            "never_block",
            f"refusing to block {ip}: this is one of this host's own addresses "
            f"(or is listed in NEMESIS_NEVER_BLOCK). Blocking it could cut the "
            f"host off from its own network. No rule was applied.")


# ── unattended path (alert_watcher) ──────────────────────────────────────────

def ufw_insert_top(ip):
    """Auto-quarantine: deny rule at position 1. Raises on failure.

    Idempotent at the ufw level — re-adding an existing deny is harmless, which
    is why the dedup cache was removed rather than replaced.
    """
    if not _valid_ip(ip):
        raise ValueError("refusing to block invalid IP: %r" % (ip,))
    _guard_never_block(ip, "block_ip")
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
    _guard_never_block(ip, "deny_ip")
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
            # fast.log shape:
            #   <ts>  [**] [gid:sid:rev] Rule message [**] [Classification: ...] ...
            # splitting on "[**]" gives:
            #   parts[0] timestamp
            #   parts[1] "[gid:sid:rev] Rule message"   <- the rule name lives HERE
            #   parts[2] "[Classification: ...] [Priority: N] {PROTO} src -> dst"
            #
            # This read parts[2] until 2026-08-04, so `rule_name` held the
            # Classification/Priority block and the real rule message was
            # discarded. It stayed invisible because the wrong value is
            # plausible text of about the right length, truncated to 50 chars on
            # insert — nothing errored and nothing was empty. `classification`
            # is parsed separately below and was always correct, so the alert
            # email showed the same classification twice and the rule name never.
            parts = alert_line.split("[**]")
            if len(parts) > 1:
                seg = parts[1].strip()
                # Drop the leading "[gid:sid:rev]" so the name is the rule
                # message alone. Split once only: a message may legitimately
                # contain further brackets, and those belong to the name.
                if seg.startswith("[") and "]" in seg:
                    seg = seg.split("]", 1)[1].strip()
                rule_name = seg
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
