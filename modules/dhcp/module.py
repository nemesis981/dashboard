"""
DHCP module — Nemesis owns dnsmasq directly.

WHY THIS REPLACED THE PI-HOLE API WRAPPER (2026-08-06)
------------------------------------------------------
The previous module was a thin remote control for Pi-hole's built-in DHCP: it
PATCHed `dhcp.active` through FTL's REST API and read a lease count. It never
wrote a config file and never touched the device inventory.

It was replaced because **every config failure during the 2026-08-06 gateway
build originated in Pi-hole/FTL's config layer, not in DHCP**: a `dhcp-range`
in an `/etc/dnsmasq.d/` drop-in duplicating Pi-hole's native `[dhcp]` aborted
the ENTIRE dnsmasq config and took DNS down with it (twice); `/etc/dnsmasq.d/`
is silently ignored unless `misc.etc_dnsmasq_d = true`; FTL running as `pihole`
could not write its own lease file, which also aborts the config. Those are
Pi-hole's merge semantics, its gating flag, and its service-user choice — all of
which can change under us at upgrade time.

So this module runs **its own dnsmasq instance**, DHCP-only, with its own config
file, its own systemd unit and its own lease file. Pi-hole keeps DNS and
blocking, untouched.

    clients --DHCP--> nemesis-dhcpd (this)   port=0, :67 only
                        |
                        +-- hands out dhcp-option=6 -> Pi-hole
    clients --DNS---> pihole-FTL             :53, [dhcp] active=false

`port=0` is load-bearing twice over: it prevents `:53` contention with Pi-hole,
and it makes ADR 0002's ruling structural rather than conventional — that ADR
rejected coupling DNS-killswitch safety to this optional module, and an instance
that serves no DNS at all cannot take on DNS responsibility even by mistake.

WHAT THIS MODULE DOES NOT DO
----------------------------
  * No DNS. Pi-hole's job, unchanged (see `port=0` above).
  * Never touches `/etc/dnsmasq.d/`, `pihole.toml`, or `dns.upstreams`.
    `dns.upstreams` belongs to `vpn-dns-guard` (ADR 0002) — different layer
    entirely (upstream forwarding policy under a VPN killswitch, not address
    assignment). This module cannot affect it in either direction.
  * Does not write the `devices` table. `devices` is core-owned and unprefixed
    (ADR 0001: modules read any table, write only their own prefixed ones), so
    lease->inventory reconciliation belongs in core, with this module supplying
    data via its own `dhcp_*` tables.

ERROR CODES
-----------
Every failure path records a structured tier-1 code via `nemesis_errors`
rather than only logging.

That API is CONNECTION-FIRST (`record_error(conn, code, ...)`), so codes are
registered in `start()` via `ensure_codes_registered()` — never at import,
because importing a module must not write to the database.

`nemesis_errors` ships its own DDL but, as of 2026-08-06, nothing calls
`init_error_tables()` in core init, so the `error_*` tables may not exist yet.
`_record()` therefore degrades to logging and says explicitly that the
occurrence was NOT persisted. DHCP must not fail because error recording is
unavailable — but a gap in the ledger must never be silent either.
"""

import json
import logging
from datetime import datetime, timezone
import os
import re
import shutil
import socket
import subprocess
import time
import threading
import tempfile

from modules import NemesisModule, get_data_manager

try:  # import shape differs by caller PYTHONPATH
    import nemesis_errors
    import database
except ImportError:  # pragma: no cover
    from alert_manager import nemesis_errors  # type: ignore
    from alert_manager import database  # type: ignore

log = logging.getLogger("nemesis.dhcp")


def _dm_conn():
    """DB access via the Data Manager (ADR 0006), never a bare `get_db()`.

    `modules_loader` REFUSES to load a module that calls `get_db()` — statically,
    before any of its code runs. Verified the hard way 2026-08-06: an earlier
    revision used `self.get_db()` and the loader rejected the whole module.
    """
    return get_data_manager().connect(MODULE_NAME)


def _now_iso():
    """Local ISO timestamp, matching the convention every sibling table uses.

    Deliberately not `datetime.utcnow()`: ADR 0004 settled on local ISO for this
    database, and login_events already had to be migrated once for drifting from
    it (its column DEFAULT was SQLite's UTC `datetime('now')` while every Python
    writer used local time, giving the same event two timestamps five hours
    apart).
    """
    return datetime.now().isoformat(timespec="seconds")

MODULE_NAME = "dhcp"

#: How often the lease->inventory sync runs while serving. Leases change on human
#: timescales (a device joining), so a tight loop would burn cycles re-reading an
#: unchanged file. 60s bounds how long a newly-joined device stays unnamed in the
#: inventory without making the loop a busy-wait.
SYNC_INTERVAL_SECONDS = 60

# ── DHCP authority: a three-way, OPERATOR-FACING choice ──────────────────────
#
# WHY THIS IS A SETTING AND NOT A DEFAULT. Not every network can give Nemesis
# DHCP duty. Locked-down ISP hardware often cannot be taken out of it at all; an
# operator may want to hand DHCP back temporarily while diagnosing something;
# and there will be reasons neither of us has predicted. A product that assumes
# one topology excludes those users silently.
#
# The important half is that each mode SAYS WHAT IT COSTS. A mode that quietly
# disables device tiering and hostname capture, leaving the operator to wonder
# why device names never appear, is worse than one that states the trade plainly
# at the point of choosing. `MODE_CAPABILITIES` below is written to be rendered
# in the UI, not just consulted in code.
MODE_NEMESIS = "nemesis"
MODE_PIHOLE = "pihole"
MODE_PROVIDER = "provider"
MODES = (MODE_NEMESIS, MODE_PIHOLE, MODE_PROVIDER)

#: Default is PROVIDER — touch nothing. A DHCP module that takes over address
#: assignment on first load could break every device on the operator's network.
#: Matches the manifest's `enabled_by_default: false` + `confirmation_required`.
DEFAULT_MODE = MODE_PROVIDER

MODE_CAPABILITIES = {
    MODE_NEMESIS: {
        "label": "Nemesis serves DHCP",
        "serves_dhcp": True,
        "lease_time_tiering": True,
        "hostname_capture": "at lease time (DHCP option 12)",
        "segmentation": "possible — still requires layer-2 separation (see scope §L2c)",
        "degraded": [],
        "notes": "Full capability. Nemesis owns its own dnsmasq instance; Pi-hole "
                 "keeps DNS. Requires the operator to disable DHCP on their router "
                 "first — two DHCP servers on one network cause address conflicts "
                 "for every device.",
    },
    MODE_PIHOLE: {
        "label": "Pi-hole serves DHCP",
        "serves_dhcp": False,
        "lease_time_tiering": False,
        "hostname_capture": "polled from Pi-hole's lease API, not at lease time",
        "segmentation": "UNAVAILABLE",
        "degraded": [
            "No device tiering at lease time — Pi-hole's DHCP is single-scope, "
            "with no tag support, so a device cannot be placed on a segment as it "
            "joins.",
            "Segmentation unavailable regardless of network hardware.",
            "Hostname capture depends on Pi-hole's REST API and is polled rather "
            "than immediate, so a new device is not classified the moment it "
            "connects.",
            "Re-introduces the Pi-hole config coupling this module was built to "
            "remove: Pi-hole upgrades can change its config layer underneath us "
            "(the 2026-08-06 outage originated there, not in DHCP).",
        ],
        "notes": "Useful as a fallback if Nemesis's own DHCP has a problem, or "
                 "where Pi-hole is already established as the DHCP server.",
    },
    MODE_PROVIDER: {
        "label": "Your router or ISP gateway serves DHCP",
        "serves_dhcp": False,
        "lease_time_tiering": False,
        "hostname_capture": "NONE",
        "segmentation": "UNAVAILABLE",
        "degraded": [
            "No lease data at all. The router holds it and Nemesis cannot read "
            "it, so there is nothing to capture.",
            "No hostname capture. Device identification falls back to reverse DNS, "
            "which resolved 1 of 41 devices when measured on the development "
            "network (2026-08-06).",
            "Device categorisation stays signal-starved as a direct result — the "
            "classifier's hostname-based iOS detection cannot fire at all.",
            "No device tiering at lease time.",
            "Segmentation unavailable REGARDLESS of network hardware — even with "
            "VLAN-capable switches and APs, nothing assigns devices to segments.",
        ],
        "notes": "The honest floor, and the right choice when the router cannot be "
                 "taken out of DHCP duty — common with locked-down ISP hardware. "
                 "Nemesis touches nothing; everything else it does still works.",
    },
}


def mode_capabilities(mode):
    """Capability/degradation record for a mode. Raises on an unknown mode.

    Refuses rather than defaulting: silently falling back to one mode's
    capabilities while running in another would misreport what the product can
    currently do, which is the specific failure this table exists to prevent.
    """
    try:
        return MODE_CAPABILITIES[mode]
    except KeyError:
        raise ValueError(
            "unknown DHCP mode %r; expected one of %s" % (mode, ", ".join(MODES)))


# ── Error codes ──────────────────────────────────────────────────────────────
# One code per FAILURE SITE, not per enclosing function — the convention the
# error-code pilot settled on, because a single umbrella code cannot say which of
# several independently-failable checks actually broke.
#
# ⚠ REGISTRATION IS DEFERRED, NOT DONE AT IMPORT. `nemesis_errors`' real API
# takes a DB connection as its first argument, so registration cannot happen at
# import time — and should not: importing a module must never write to the
# database. `ensure_codes_registered(conn)` is called from `start()` instead.
E_CONFIG_INVALID   = "E-DHCP-001"
E_PIHOLE_DHCP_ON   = "E-DHCP-002"
E_PORT_BOUND       = "E-DHCP-003"
E_IFACE_UNUSABLE   = "E-DHCP-004"
E_LEASE_DIR        = "E-DHCP-005"
E_DAEMON_FAILED    = "E-DHCP-006"
E_IFACE_NOT_ALLOWED = "E-DHCP-007"
E_RELOAD_FAILED    = "E-DHCP-008"
# ── mode-switch fail-over (2026-08-07) ───────────────────────────────────────
E_SWITCH_VERIFY_FAILED = "E-DHCP-009"
E_ROLLBACK_FAILED      = "E-DHCP-010"
E_ROLLBACK_TO_BASELINE = "E-DHCP-011"
E_BASELINE_FAILED      = "E-DHCP-012"
E_OVERRIDE_USED        = "E-DHCP-013"
# ── steady-state health (2026-08-07) ─────────────────────────────────────────
# Every code above fires at a TRANSITION — start, reload, switch, rollback. None
# of them can fire while the module is simply running, which is why a daemon that
# crash-looped for hours produced no occurrence at all. These three are the
# operating-state codes: they exist to be recorded by the periodic health sample,
# not by an operation the operator just performed.
E_DAEMON_CRASH_LOOP    = "E-DHCP-014"
E_SERVING_UNVERIFIED   = "E-DHCP-015"
E_HEALTH_UNMEASURABLE  = "E-DHCP-016"

#: The failure family shared by 002-005 and 007: a precondition that must hold
#: before this module may serve DHCP at all. Grouped so one confirmed cause
#: ("the gateway VM was re-imaged and the static address never applied") can
#: explain an occurrence at any of them, rather than each site relearning it.
_CLASS_PRECONDITION = "dhcp-precondition-refused"

#: The failure family shared by 014-016: the module IS meant to be serving and
#: the periodic health sample says it is not (or cannot tell). Separate from the
#: precondition family on purpose — a precondition failure means we correctly
#: refused to start, which is the system working; these mean we believed we were
#: serving and the readback disagreed, which is the system lying to itself.
_CLASS_HEALTH = "dhcp-serving-unhealthy"

_CODES = (
    (E_CONFIG_INVALID, "Rendered dnsmasq config failed validation; nothing applied",
     "HIGH", None),
    (E_PIHOLE_DHCP_ON, "Pi-hole's own DHCP is active — refusing to start a second DHCP server",
     "CRITICAL", _CLASS_PRECONDITION),
    (E_PORT_BOUND, "UDP :67 is already bound by another process", "HIGH",
     _CLASS_PRECONDITION),
    (E_IFACE_UNUSABLE, "Served interface missing, without carrier, or not holding its "
     "expected static address", "HIGH", _CLASS_PRECONDITION),
    (E_LEASE_DIR, "Lease directory missing or not writable", "HIGH", _CLASS_PRECONDITION),
    (E_DAEMON_FAILED, "dnsmasq failed to start or exited unexpectedly", "HIGH", None),
    (E_IFACE_NOT_ALLOWED, "Interface is not in the serve allowlist — refusing", "CRITICAL",
     _CLASS_PRECONDITION),
    (E_RELOAD_FAILED, "Config reload (SIGHUP) failed", "MEDIUM", None),
    # ── mode-switch fail-over ────────────────────────────────────────────────
    # One code per failure SITE in the switch/rollback cascade. The tier and
    # attempt number ride in `context` rather than multiplying codes: a rollback
    # failing is the same failure shape whichever tier was being tried, and a
    # code per tier would fragment one condition across four catalogue entries.
    (E_SWITCH_VERIFY_FAILED,
     "Mode switch applied but post-change readback did not confirm the intended "
     "state — rolling back", "HIGH", None),
    (E_ROLLBACK_FAILED,
     "A rollback attempt failed its own verification (see context for tier/attempt)",
     "HIGH", None),
    (E_ROLLBACK_TO_BASELINE,
     "All rolling snapshot tiers exhausted — restored from the permanent install "
     "baseline", "HIGH", None),
    (E_BASELINE_FAILED,
     "Install-baseline restore ALSO failed — daemon stopped, DHCP needs manual "
     "attention", "CRITICAL", None),
    (E_OVERRIDE_USED,
     "Operator forced a mode switch that failed verification (override) — "
     "automatic rollback suppressed", "MEDIUM", None),
    # ── steady-state health ──────────────────────────────────────────────────
    (E_DAEMON_CRASH_LOOP,
     "DHCP daemon is restarting repeatedly — it is up at any given instant but "
     "not staying up, so leases are being served intermittently or not at all",
     "CRITICAL", _CLASS_HEALTH),
    (E_SERVING_UNVERIFIED,
     "DHCP daemon is active but could not be confirmed to be serving (UDP :67 "
     "not bound, or a served interface lost its address)", "HIGH", _CLASS_HEALTH),
    (E_HEALTH_UNMEASURABLE,
     "Health could not be measured — the check itself failed, so the daemon's "
     "true state is UNKNOWN and must not be reported as healthy", "MEDIUM",
     _CLASS_HEALTH),
)

# ── Mode-switch fail-over: snapshot chain ────────────────────────────────────
#
# THREE ROLLING TIERS PLUS ONE PERMANENT BASELINE. A single last-known-good slot
# answers "what was the last state?" but not "how PROVEN is it?" — a state that
# barely passed its first readback and one that has run untouched for three weeks
# are very different bets to roll back onto, and one slot cannot tell them apart.
#
# Promotion is EVENT-driven, not time-driven: the chain shifts only when a switch
# SUCCEEDS. So "trusted" means "this state stayed live, undisturbed, all the way
# through to the next successful change" — however long that actually was. That is
# a stronger proof of stability than any fixed soak timer, and it costs nothing
# extra to compute because it falls out of the promotion rule itself.
SNAP_DIR = "/var/lib/nemesis/dhcp_snapshots"
TIER_THOUGHT = "thought-trusted"
TIER_TRUSTED = "trusted"
TIER_AGING = "aging"
TIER_BASELINE = "install-baseline"

#: Rolling tiers, newest first. Order IS the rollback order (§3c).
ROLLING_TIERS = (TIER_THOUGHT, TIER_TRUSTED, TIER_AGING)

#: Full rollback cascade: most-proven-recent first, ending at the one snapshot
#: guaranteed to exist and guaranteed never to mutate.
ROLLBACK_ORDER = ROLLING_TIERS + (TIER_BASELINE,)

#: Attempts per tier before moving to the next, and the gap between them.
#:
#: TWO, not one (operator decision 2026-08-07): a first failure may be a transient
#: fault rather than a real problem with the target state, and spending the whole
#: budget on the least-proven tier would defeat the point of having the others.
#: Bounded by construction — 4 tiers x 2 attempts x 30s is a few minutes, never an
#: unbounded retry loop.
ROLLBACK_ATTEMPTS_PER_TIER = 2
ROLLBACK_RETRY_DELAY_SECONDS = 30

def ensure_codes_registered(conn):
    """Declare this module's codes in the catalog. Idempotent.

    Called from `start()` rather than at import, because the real error system's
    API is connection-first (see the note above `_CODES`).
    """
    for code, desc, sev, cls in _CODES:
        nemesis_errors.register_error_code(
            conn, code, MODULE_NAME, desc, sev, error_class=cls)


def _record(code, context=None, conn=None):
    """Record one occurrence, degrading LOUDLY when recording is impossible.

    DELEGATES to `nemesis_errors.record_error_best_effort()` rather than
    reimplementing it. An earlier version of this function hand-rolled the
    never-raise behaviour because that function did not exist yet; it landed in
    `db9e0c4`, so this now calls it. Two implementations of "record without
    raising" is exactly the drift this codebase keeps having to undo.

    Its contract is the one this module needs, for the reason its own docstring
    gives: almost every call site here is already inside an `except:`, and a
    recording failure that raised would REPLACE the original fault with the
    error system's own — handing the operator the wrong exception entirely.

    The one thing still handled here is `conn=None`. Pure callers
    (`check_preconditions()`, tests) have no database, and the upstream function
    reasonably requires one. A missing connection is logged and explicitly
    reported as not persisted.

    **"Recorded" and "logged because recording was impossible" must never look
    the same** to whoever reads the journal later, or the ledger appears to have
    gaps it cannot account for.
    """
    if conn is None:
        log.error("[%s] %s | NOT PERSISTED (no DB connection at this call site)",
                  code, context)
        return None
    rid = nemesis_errors.record_error_best_effort(
        conn, code, context=context, logger=log)
    if rid is None:
        # The upstream helper already logged the cause. This line states the
        # consequence in this module's own terms, so a journal reader sees that
        # a DHCP failure went unrecorded rather than only that the error system
        # had a problem.
        log.error("[%s] %s | NOT PERSISTED (error system could not record it)",
                  code, context)
    return rid


# ── Paths ────────────────────────────────────────────────────────────────────
# Deliberately OUTSIDE anything Pi-hole reads. Nothing here is under
# /etc/dnsmasq.d/ or /etc/pihole/ — that separation is the whole point.
CONF_DIR      = "/etc/nemesis/dhcp"
CONF_PATH     = os.path.join(CONF_DIR, "nemesis-dhcp.conf")
HOSTS_DIR     = os.path.join(CONF_DIR, "hosts.d")   # dhcp-host entries, SIGHUP-reloadable
LEASE_PATH    = "/var/lib/nemesis/dhcp.leases"
SERVICE_NAME  = "nemesis-dhcpd"
PIHOLE_TOML   = "/etc/pihole/pihole.toml"


class DhcpConfigError(ValueError):
    """Raised when a config cannot be rendered or does not validate."""


class PreconditionFailed(RuntimeError):
    """Raised when the environment is not safe to serve DHCP on."""


# ── Config model ─────────────────────────────────────────────────────────────

class Scope:
    """One DHCP range, optionally tagged for a segmentation tier.

    Multi-scope from the outset rather than retrofitted: the segmentation model
    (agent / agent-capable / IoT / never-agentable) needs tagged ranges, and a
    single-range design would have to be rewritten rather than extended.
    """

    def __init__(self, start, end, lease_time, tag=None, router=None,
                 dns=None, netmask=None):
        self.start = start
        self.end = end
        self.lease_time = lease_time
        self.tag = tag
        self.router = router
        self.dns = dns
        self.netmask = netmask

    def render(self, other_tags=(), is_default=False):
        """Render this scope's dhcp-range and options.

        `tag:` NOT `set:` — this is the segmentation bug found on the first live
        run, 2026-08-07. `set:X` TAGS a client that receives an address from the
        range; it does NOT restrict the range to clients already tagged X. So a
        per-device tier assignment in `dhcp-hostsfile` had no effect on which
        range served the device: a client tagged `iot` was still handed a general
        address, every time. Unit tests asserted the rendered TEXT and so could
        not tell the two apart. Only dnsmasq's own behaviour could.

        THE DEFAULT SCOPE IS THE QUARANTINE TIER (operator decision, 2026-08-07),
        consistent with the mode-failover design's default-to-quarantine
        principle. It renders with NEGATED tags — `tag:!iot,tag:!general,` — so a
        device carrying ANY tier tag is excluded from it, and an untagged/unknown
        device can land nowhere else. Negation rather than ordering: relying on
        which range dnsmasq happens to try first would be a guess about
        implementation detail, and this is the range an unknown device falls into.
        """
        lines = []
        if is_default:
            prefix = "".join("tag:!%s," % t for t in sorted(other_tags))
        else:
            prefix = "tag:%s," % self.tag if self.tag else ""
        parts = [self.start, self.end]
        if self.netmask:
            parts.append(self.netmask)
        parts.append(self.lease_time)
        lines.append("dhcp-range=%s%s" % (prefix, ",".join(parts)))
        tagsel = "tag:%s," % self.tag if self.tag else ""
        if self.router:
            lines.append("dhcp-option=%s3,%s" % (tagsel, self.router))
        if self.dns:
            lines.append("dhcp-option=%s6,%s" % (tagsel, self.dns))
        return lines


class DhcpConfig:
    """The full rendered config for our dnsmasq instance.

    `default_tag` names the scope an UNKNOWN device lands in. It must be the
    most restrictive tier: containment happens before classification, not after.
    This is the actual security property of segmentation — it does not depend on
    how fast leases are observed, only on which range answers first.
    """

    def __init__(self, interfaces, scopes, default_tag=None,
                 lease_path=LEASE_PATH, hosts_dir=HOSTS_DIR,
                 dhcp_script=None, authoritative=True):
        self.interfaces = list(interfaces)
        self.scopes = list(scopes)
        self.default_tag = default_tag
        self.lease_path = lease_path
        self.hosts_dir = hosts_dir
        self.dhcp_script = dhcp_script
        self.authoritative = authoritative

    def render(self):
        if not self.interfaces:
            # An empty interface list must never render to "serve everywhere".
            # dnsmasq with no `interface=` binds all of them, which on this
            # product means serving DHCP onto the operator's live LAN.
            raise DhcpConfigError(
                "refusing to render: no interfaces specified (an empty list "
                "would make dnsmasq serve on ALL interfaces)")
        if not self.scopes:
            raise DhcpConfigError("refusing to render: no DHCP scopes defined")
        tags = [s.tag for s in self.scopes if s.tag]
        if self.default_tag and self.default_tag not in tags:
            raise DhcpConfigError(
                "default_tag %r has no matching scope (have: %s)"
                % (self.default_tag, ", ".join(tags) or "none"))

        out = [
            "# Generated by Nemesis dhcp module — DO NOT EDIT BY HAND.",
            "# Hand edits are overwritten on the next apply. Change the module's",
            "# config instead. This file is Nemesis-owned; Pi-hole never reads it.",
            "",
            "# DHCP ONLY. port=0 disables DNS entirely so this instance cannot",
            "# contend with Pi-hole on :53, and cannot take on DNS duties that",
            "# ADR 0002 placed outside this optional module.",
            "port=0",
            "",
            "# No pidfile. The unit is Type=simple with --keep-in-foreground, so",
            "# systemd tracks the process directly and dnsmasq's default",
            "# /var/run/dnsmasq.pid is not needed -- and cannot be written anyway",
            "# under ProtectSystem=strict, which made it crash-loop on the first",
            "# live run 2026-08-07 (\"failed to open pidfile ... Read-only file",
            "# system\"). Disabling it is correct here, not a workaround.",
            "pid-file=",
            "",
            "# Do not let dnsmasq drop to its packaged dnsmasq:dip identity. The",
            "# privilege model here is systemd's (narrow AmbientCapabilities +",
            "# SupplementaryGroups), and the internal drop both FAILS under that",
            "# capability set (\"failed to change group-id to dip: Operation not",
            "# permitted\", live run 2026-08-07) and would discard the nemesis-db",
            "# membership the lease file depends on.",
            "user=root",
            "group=root",
            "",
            "# bind-interfaces is deliberately ABSENT. Measured 2026-08-06: with",
            "# it, DHCP never answered a single Request — DHCP needs broadcasts",
            "# to 255.255.255.255 that a strictly-bound socket does not receive.",
        ]
        for iface in self.interfaces:
            out.append("interface=%s" % iface)
        out.append("no-dhcp-interface=lo")
        if self.authoritative:
            out.append("dhcp-authoritative")
        out.append("")
        out.append("dhcp-leasefile=%s" % self.lease_path)
        if self.hosts_dir:
            # Re-read on SIGHUP, so tier assignments can be added without a
            # restart and without disturbing existing leases.
            out.append("dhcp-hostsfile=%s" % self.hosts_dir)
        if self.dhcp_script:
            out.append("dhcp-script=%s" % self.dhcp_script)
        out.append("")
        for scope in self.scopes:
            other = [t for t in (sc.tag for sc in self.scopes)
                     if t and t != scope.tag]
            out.extend(scope.render(other_tags=other,
                                    is_default=bool(self.default_tag)
                                    and scope.tag == self.default_tag))
        out.append("")
        return "\n".join(out)


# ── Declarative interface addressing + service unit ──────────────────────────
#
# ⚠ THE BOOT DEADLOCK THIS EXISTS TO AVOID. `systemd-networkd-wait-online` can
# block FOREVER on an interface whose only possible DHCP server is on the same
# box — the interface waits for a lease, the lease waits for the DHCP service,
# and the DHCP service waits for the boot that the interface is blocking. It
# takes the whole machine down, not just DHCP, and it fails at boot: the hardest
# time to debug, on a headless appliance, with no network to reach it by.
#
# Two independent things break the cycle, and BOTH are required:
#   1. `optional: true` in the netplan stanza — tells wait-online not to block on
#      this interface at all. This is the direct fix.
#   2. A STATIC address, applied declaratively at network-config time. The
#      interface must never need a lease to come up.
#
# The module NEVER runs `ip addr add` at service start. Its precondition check
# instead ASSERTS the address is already present (see `check_preconditions`) and
# refuses to start if it is not — because an absent address means the
# declarative config did not apply, and serving DHCP from an unaddressed
# interface is worse than not serving at all.

NETPLAN_PATH = "/etc/netplan/60-nemesis-dhcp.yaml"
UNIT_PATH = "/etc/systemd/system/%s.service" % SERVICE_NAME


def render_netplan(interface, address, prefix_len):
    """Netplan stanza pinning a static address on a served interface.

    `dhcp4: false` because this interface is where Nemesis SERVES DHCP — asking
    it to also be a DHCP client there would have it try to lease an address from
    itself.
    """
    if not interface or not address:
        raise DhcpConfigError(
            "refusing to render netplan: interface and address are both required")
    return (
        "# Generated by the Nemesis dhcp module — DO NOT EDIT BY HAND.\n"
        "#\n"
        "# `optional: true` is load-bearing, not tidiness: without it\n"
        "# systemd-networkd-wait-online blocks the entire boot waiting for an\n"
        "# interface whose only DHCP server is this machine — a circular wait\n"
        "# that never resolves and takes the whole box down with it.\n"
        "#\n"
        "# `dhcp4: false` because Nemesis SERVES DHCP on this interface; a client\n"
        "# here would be trying to lease an address from itself.\n"
        "network:\n"
        "  version: 2\n"
        "  ethernets:\n"
        "    %s:\n"
        "      dhcp4: false\n"
        "      dhcp6: false\n"
        "      optional: true\n"
        "      addresses:\n"
        "        - %s/%s\n" % (interface, address, prefix_len)
    )


def render_systemd_unit(conf_path=CONF_PATH):
    """The unit for our own dnsmasq instance.

    `After=network.target` and deliberately NOT `network-online.target`: waiting
    for the network to be "online" is the other half of the deadlock above, since
    this service is what would make it online.

    `ExecReload` sends SIGHUP, which is how a device's tier assignment changes —
    dnsmasq re-reads `dhcp-hostsfile` without dropping existing leases. A restart
    would be both unnecessary and disruptive to every device holding a lease.
    """
    return (
        "# Generated by the Nemesis dhcp module — DO NOT EDIT BY HAND.\n"
        "[Unit]\n"
        "Description=Nemesis DHCP server (dnsmasq, DHCP-only)\n"
        "Documentation=file://%s\n"
        "After=network.target\n"
        "# NOT network-online.target -- see the boot-deadlock note in module.py.\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file=%s\n"
        "ExecReload=/bin/kill -HUP $MAINPID\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "# :67 is privileged and DHCP needs raw access to answer broadcasts.\n"
        "# Granted narrowly rather than running unconfined as root.\n"
        "AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN "
        "CAP_SETGID CAP_SETUID\n"
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN "
        "CAP_SETGID CAP_SETUID\n"
        # THE LEASE FILE NEEDS GROUP ACCESS, NOT MORE CAPABILITY. Found on the
        # first live run 2026-08-07: dnsmasq crash-looped with "cannot open or
        # create lease file ... Permission denied" DESPITE running as root with
        # ReadWritePaths set. Cause: CapabilityBoundingSet above deliberately
        # excludes CAP_DAC_OVERRIDE, so root IS subject to ordinary permission
        # checks -- and /var/lib/nemesis is 0770 root-excluded (group nemesis-db,
        # per the data-directory model). The fix is to join the group that owns
        # the directory, NOT to widen the capability set: the hardening is
        # correct, the group membership was simply missing.
        "SupplementaryGroups=nemesis-db\n"
        "NoNewPrivileges=true\n"
        "ProtectSystem=strict\n"
        "ProtectHome=true\n"
        "PrivateTmp=true\n"
        "# The only paths it may write: its lease file and its runtime dir.\n"
        "ReadWritePaths=%s\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
        % (conf_path, conf_path, os.path.dirname(LEASE_PATH))
    )


# ── Validation gate ──────────────────────────────────────────────────────────

def _dnsmasq_binary():
    return shutil.which("dnsmasq") or "/usr/sbin/dnsmasq"


def validate_config_text(text):
    """Run `dnsmasq --test` against rendered config. Returns (ok, detail).

    Syntax-only. Runtime preconditions are checked separately (see
    `check_preconditions`) because a config can be perfectly valid and still be
    unsafe to apply — e.g. valid while Pi-hole's own DHCP is running.
    """
    binary = _dnsmasq_binary()
    if not os.path.exists(binary):
        return False, "dnsmasq binary not found at %s" % binary
    # ⚠ NOT the system temp dir. The dashboard unit runs `ProtectSystem=strict`
    # with `ReadWritePaths=/var/lib/nemesis`, so /tmp is READ-ONLY to the process
    # that loads this module — `tempfile.mkstemp()` with no `dir=` raised OSError
    # there, escaped `start()`, and made the whole module fail to load (verified
    # live 2026-08-07). The data directory is the one path the module is
    # guaranteed to be able to write, and it is already a precondition
    # (`E_LEASE_DIR`) that it is writable, so nothing new is being assumed here.
    tmp_dir = os.path.dirname(LEASE_PATH)
    try:
        fd, path = tempfile.mkstemp(prefix="nemesis-dhcp-", suffix=".conf",
                                    dir=tmp_dir)
    except OSError as e:
        # An explicit failure, never a pass: if the validator cannot run, the
        # config is UNVALIDATED, which must not be reported as valid.
        return False, ("validator could not create a temp file in %s: %s"
                       % (tmp_dir, e))
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        r = subprocess.run([binary, "--test", "-C", path],
                           capture_output=True, text=True, timeout=30)
        detail = (r.stderr or r.stdout or "").strip()
        return r.returncode == 0, detail
    except Exception as e:  # noqa: BLE001 - reported, not swallowed
        return False, "validator failed to run: %s" % e
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def selftest_validator():
    """Prove the validator can REJECT before trusting it to accept.

    Standing practice in this codebase: a checker that has only ever returned OK
    has not been shown to be a checker. Two cases every invocation — a config
    that must pass and one that must fail. Same shape as
    `nemesis-fw-neverblock`'s CANARIES.
    """
    good = "port=0\ninterface=lo\ndhcp-range=10.0.0.50,10.0.0.60,1h\n"
    # Two independent defects: a bogus directive, and the duplicate-keyword
    # shape that actually took DNS down on 2026-08-06.
    bad = ("port=0\nthis-is-not-a-dnsmasq-directive=1\n"
           "dhcp-range=10.0.0.50,10.0.0.60,1h\n"
           "dhcp-range=10.0.0.50,10.0.0.60,1h\n")
    ok_good, d_good = validate_config_text(good)
    ok_bad, _ = validate_config_text(bad)
    if not ok_good:
        return False, "validator rejected a known-good config: %s" % d_good
    if ok_bad:
        return False, "validator ACCEPTED a known-bad config — it is not validating"
    return True, "ok"


# ── Preconditions ────────────────────────────────────────────────────────────

def _iface_exists(iface):
    return os.path.exists("/sys/class/net/%s" % iface)


def _iface_carrier(iface):
    try:
        with open("/sys/class/net/%s/carrier" % iface) as f:
            return f.read().strip() == "1"
    except OSError:
        return False


def _iface_addresses(iface):
    try:
        r = subprocess.run(["ip", "-json", "addr", "show", "dev", iface],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return []
        data = json.loads(r.stdout or "[]")
        out = []
        for entry in data:
            for a in entry.get("addr_info", []):
                if a.get("family") == "inet" and a.get("local"):
                    out.append(a["local"])
        return out
    except Exception:  # noqa: BLE001
        return []


def port67_state():
    """Is UDP :67 free? Returns "free" | "bound" | "unknown".

    Binds a probe socket rather than parsing `ss` output — the kernel is the
    authority on whether a port is free, and parsing someone else's text output
    is the kind of instrument that reports confidently from a format it no
    longer matches.

    ⚠ THE ERRNO DISTINCTION IS THE WHOLE POINT, and getting it wrong is how this
    check becomes useless. A first draft caught bare `OSError` and returned
    "bound" — but :67 is a privileged port, so an UNPRIVILEGED caller always gets
    EACCES, and the check would have reported "bound" every single time it ran
    without root. That is an instrument that can only ever return one answer,
    reporting it as a measurement.

      EADDRINUSE -> genuinely bound by another process
      EACCES     -> we lack privilege; we CANNOT TELL. Not the same thing.

    "unknown" is returned explicitly rather than collapsed into either answer,
    and the caller treats it as a precondition failure — refusing beats assuming
    a port is free when two DHCP servers is the failure being guarded against.
    """
    import errno as _errno
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", 67))
        return "free"
    except OSError as e:
        if e.errno == _errno.EADDRINUSE:
            return "bound"
        return "unknown"
    finally:
        s.close()


def _udp_ports_in_use():
    """Local UDP ports from /proc/net/{udp,udp6}. Returns a set, or None.

    None means the read failed — not "no ports are in use". An empty set is a
    legitimate (if unlikely) measurement; a failed read is not a measurement at
    all, and the two must not be the same value.
    """
    ports = set()
    read_any = False
    for path in ("/proc/net/udp", "/proc/net/udp6"):
        try:
            with open(path) as f:
                lines = f.read().splitlines()
        except OSError:
            continue
        read_any = True
        for line in lines[1:]:                      # skip the header row
            cols = line.split()
            if len(cols) < 2 or ":" not in cols[1]:
                continue
            try:
                ports.add(int(cols[1].rsplit(":", 1)[1], 16))
            except ValueError:
                continue
    return ports if read_any else None


def port67_bound_via_proc():
    """Is UDP :67 bound, read from /proc? Returns True | False | None.

    ⚠ WHY THIS EXISTS ALONGSIDE `port67_state()`, WHICH ALREADY ANSWERS THIS.
    That function binds a probe socket, and :67 is privileged — so from any
    unprivileged caller it returns EACCES -> "unknown", ALWAYS. Its own docstring
    says exactly that, and treating "unknown" as a precondition failure is right
    for the pre-start check: refusing to assume a port is free is the correct bias
    when the hazard is two DHCP servers.

    But that bias inverts for a STEADY-STATE health check. The dashboard runs as
    the unprivileged `nemesis-dash` (verified live 2026-08-07 — the unit sets
    `User=nemesis-dash`, and an unprivileged bind on :67 returns errno 13 EACCES
    on that box). So a health check built on the bind probe would return "cannot
    confirm serving" on every single sample of a perfectly healthy daemon — an
    instrument that can only ever produce one answer, which is the exact defect
    this health work exists to remove, reintroduced one layer up.

    /proc/net/udp is world-readable (confirmed `-r--r--r--` on the live gateway,
    showing `00000000:0043`), so this reads the same fact at the privilege level
    the code actually runs at. It proves the port is HELD, not by whom — pair it
    with the systemd state, which is what identifies the holder.
    """
    ports = _udp_ports_in_use()
    if ports is None:
        return None
    return 67 in ports


def selftest_proc_port_probe():
    """Prove the /proc probe can return BOTH answers. Returns (ok, detail).

    Two-sided and REAL, not synthetic: it binds an actual UDP socket on an
    ephemeral port and requires the probe to see it (positive control), then
    requires that same port to read as free once closed (negative control). A
    probe that always says "bound" and one that always says "free" both fail
    here, which is the whole point — the bind-probe's EACCES blind spot was
    invisible precisely because nothing ever asked it to produce a second answer.
    """
    ports = _udp_ports_in_use()
    if ports is None:
        return False, "/proc/net/udp unreadable — cannot verify the probe at all"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", 0))
        probe_port = s.getsockname()[1]
        seen = _udp_ports_in_use()
        if seen is None or probe_port not in seen:
            return False, ("positive control FAILED: a socket bound on %d was "
                           "not visible in /proc" % probe_port)
    finally:
        s.close()
    after = _udp_ports_in_use()
    if after is None:
        return False, "negative control FAILED: /proc became unreadable"
    if probe_port in after:
        # Not fatal on its own — the kernel can hold a closed socket briefly —
        # but it means the negative side was not demonstrated on this run.
        return True, ("positive control passed; negative control inconclusive "
                      "(port %d still listed after close)" % probe_port)
    return True, "probe sees a bound port and not a freed one"


# ── :67 ownership — the two-DHCP-servers guard, made measurable ──────────────
#
# WHAT THIS CHANGES AND WHAT IT DELIBERATELY DOES NOT.
#
# The guard's purpose is unchanged and must stay unchanged: Nemesis must never
# start a second DHCP server alongside somebody else's. What was wrong was not
# the policy but the INSTRUMENT. `check_preconditions()` asked `port67_state()`,
# which binds a probe socket on a privileged port — so from the unprivileged
# dashboard user it returns EACCES -> "unknown" -> refuse, ALWAYS. The module
# therefore could not start itself at all: not when :67 was busy, and not when it
# was free either. A guard that refuses unconditionally is not protecting
# anything, it is just broken in the safe direction, and it is why the live
# daemon had to be started by hand.
#
# Two separate facts are needed, and the old check conflated them:
#   1. IS :67 held?            — answerable unprivileged via /proc.
#   2. Is it held BY US?       — answerable from our own unit's state.
#
# The exemption is narrow: :67 held while OUR OWN unit is active. dnsmasq runs
# with --keep-in-foreground and exits if it cannot bind, so a unit that is active
# and stable is what holds the port; a foreign holder would leave our unit dead
# or restart-looping instead. Every other combination still refuses, including
# both "cannot tell" cases.

PORT67_FREE    = "free"      # nothing holds it — safe to start
PORT67_OURS    = "ours"      # held by our own active unit — adoption, not a conflict
PORT67_FOREIGN = "foreign"   # held by something else — THE hazard; refuse
PORT67_UNKNOWN = "unknown"   # cannot tell — refuse, never assume


def classify_port67(held, unit_active):
    """Pure truth table: (is :67 held?, is our unit active?) -> verdict.

    Split from the measurement so the SAFETY property can be tested directly and
    exhaustively, rather than inferred from whatever state the machine running
    the tests happens to be in. `held` and `unit_active` are True/False/None,
    where None means "could not determine" — and None on either axis refuses.
    """
    if held is None:
        return PORT67_UNKNOWN
    if held is False:
        return PORT67_FREE
    if unit_active is True:
        return PORT67_OURS
    if unit_active is False:
        return PORT67_FOREIGN
    return PORT67_UNKNOWN


#: (label, held, unit_active, expected). The FOREIGN and UNKNOWN rows are the
#: safety property: if a future edit ever lets either resolve to a permitted
#: verdict, the self-test fails and the module refuses to start rather than
#: shipping a weakened two-DHCP-servers guard.
_PORT67_CANARIES = (
    ("free, unit down",          False, False, PORT67_FREE),
    ("free, unit up",            False, True,  PORT67_FREE),
    ("held by our active unit",  True,  True,  PORT67_OURS),
    ("HELD, our unit is DOWN",   True,  False, PORT67_FOREIGN),
    ("held, ownership unknown",  True,  None,  PORT67_UNKNOWN),
    ("cannot tell if held",      None,  True,  PORT67_UNKNOWN),
    ("cannot tell either way",   None,  None,  PORT67_UNKNOWN),
)


def selftest_port67_classifier():
    """Prove the classifier discriminates before the guard relies on it."""
    for label, held, active, expected in _PORT67_CANARIES:
        got = classify_port67(held, active)
        if got != expected:
            return False, ("canary %r -> %r, expected %r" % (label, got, expected))
    # The property that matters most, asserted as a property and not only as rows:
    # nothing may be permitted while the port is held and our unit is not up.
    if classify_port67(True, False) in (PORT67_FREE, PORT67_OURS):
        return False, "FOREIGN holder would be permitted — guard is broken"
    return True, "%d port-ownership canaries classify correctly" % len(_PORT67_CANARIES)


def port67_availability(service=None):
    """Measure :67 ownership. Returns (verdict, readback dict).

    The readback carries the RAW inputs — which instrument answered, what it
    said, what our unit's state was — because "refused: foreign holder" is only
    actionable if the operator can see what led to it.
    """
    readback = {}

    held = None
    state = port67_state()
    readback["bind_probe"] = state
    readback["source"] = "bind"
    if state == "bound":
        held = True
    elif state == "free":
        held = False
    else:
        # Privileged-port EACCES from an unprivileged caller. Fall back to /proc,
        # but only if that probe can prove it discriminates.
        ok_probe, probe_detail = selftest_proc_port_probe()
        readback["proc_selftest"] = probe_detail
        if ok_probe:
            held = port67_bound_via_proc()
            readback["source"] = "proc"
        else:
            readback["source"] = "none"
    readback["held"] = held

    unit_active = None
    props = _systemd_props(service)
    if props is not None:
        try:
            pid = int(props.get("ExecMainPID") or 0)
        except (TypeError, ValueError):
            pid = 0
        unit_active = (props.get("ActiveState") == "active" and pid > 0)
        readback["unit_active_state"] = props.get("ActiveState")
        readback["unit_main_pid"] = pid
    else:
        readback["unit_active_state"] = None
    readback["unit_active"] = unit_active

    verdict = classify_port67(held, unit_active)
    readback["verdict"] = verdict
    return verdict, readback


# ── Daemon health: measurement, then derivation ──────────────────────────────
#
# WHY THIS EXISTS AT ALL. `status()` used to be one line: `systemctl is-active`,
# mapped "active" -> "running". That is process PRESENCE, not health, and the two
# come apart in exactly the case that matters. Under `Restart=on-failure` +
# `RestartSec=5` a daemon that cannot start is genuinely `active` for the fraction
# of each 5-second cycle it is up — so a status sample lands on "active" and the
# module reports `running` while no device on the network can get a lease. That is
# not hypothetical: it happened on the first live run (2026-08-07), and the
# dashboard said "running" throughout.
#
# The fix is not a better guess about `is-active`. It is to MEASURE the things
# that distinguish the two states and derive the verdict from them:
#
#   * `NRestarts`  — systemd's count of AUTOMATIC restarts. `systemctl restart`
#     does NOT increment it, so a non-zero value means the daemon FAILED and was
#     restarted, never that an operator bounced it. This is the signal the old
#     status() had no access to, because `is-active` does not carry it.
#   * current-run uptime — `NRestarts` alone is not enough: it is cumulative and
#     never resets, so a daemon that looped three times at boot and has since run
#     for three hours still reads `NRestarts=3`. "Has restarted AND the current
#     run is young" is what actually means "looping right now".
#   * UDP :67 actually bound, and the served interfaces still holding their
#     addresses — the same readback `verify_mode()` already does after a switch.
#     A daemon can be up, stable, and still not serving.
#
#: A current run younger than this, on a service that has auto-restarted at least
#: once, reads as an active crash loop. `RestartSec=5` means a real loop cycles
#: every few seconds, so anything genuinely recovered clears this almost at once;
#: the window is deliberately generous because a false "healthy" is far more
#: expensive here than a false "still settling".
CRASH_LOOP_YOUNG_SECONDS = 90

#: Health states. `unknown` is a first-class value, not an error case: a health
#: check that could not run must never collapse into either "healthy" or "down".
HEALTH_SERVING     = "serving"        # measured, confirmed, actually handing out leases
HEALTH_CRASH_LOOP  = "crash_looping"  # up at this instant, not staying up
HEALTH_UNVERIFIED  = "unverified"     # active but readback does not confirm serving
HEALTH_DOWN        = "down"           # not active, and not looping
HEALTH_UNKNOWN     = "unknown"        # the instrument failed; state is NOT known

_SYSTEMD_TS_FMT = "%a %Y-%m-%d %H:%M:%S %Z"


def _parse_systemd_timestamp(raw):
    """systemd's `ExecMainStartTimestamp` -> epoch seconds, or None.

    None is returned for an empty, malformed, or unparseable value — never a
    default of 0 or `now`. Both of those are legal-looking numbers that would
    silently become an uptime of "56 years" or "0 seconds", and a 0-second uptime
    is precisely the input that makes the crash-loop check fire. A broken clock
    read must not be able to manufacture a verdict.
    """
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        # systemd renders e.g. "Fri 2026-08-07 19:04:31 UTC". %Z parses the name
        # but does not apply an offset, so parse as naive and treat as UTC when
        # the zone says UTC; otherwise fall back to naive-local.
        parts = raw.split()
        if len(parts) < 4:
            return None
        dt = datetime.strptime(" ".join(parts[:3]), "%a %Y-%m-%d %H:%M:%S")
        if parts[3] == "UTC":
            return dt.replace(tzinfo=timezone.utc).timestamp()
        # Any other zone name: systemd renders local time, so parse as naive
        # local. Guests on this fleet run UTC while the host is -0500, which is
        # exactly why the zone field is read rather than assumed either way.
        return dt.timestamp()
    except (ValueError, IndexError):
        return None


def _systemd_props(service=None):
    """Read the systemd properties health is derived from. Returns dict or None.

    None means THE READ FAILED — the caller must treat that as "cannot tell",
    not as "nothing is running". Returning `{}` here would be the exact defect
    this codebase keeps finding: an empty result that every downstream `.get()`
    turns into a confident, wrong answer.
    """
    service = service or SERVICE_NAME
    keys = ("ActiveState", "SubState", "NRestarts", "ExecMainPID",
            "ExecMainStartTimestamp", "Result")
    try:
        r = subprocess.run(
            ["systemctl", "show", service, "-p", ",".join(keys)],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    out = {}
    for line in (r.stdout or "").splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    # A successful call that carried none of the keys is a failed read wearing a
    # success exit code — refuse it rather than deriving from an empty dict.
    if "ActiveState" not in out:
        return None
    return out


def derive_health(props, port67, addr_problems, now_epoch, prev_nrestarts=None):
    """Pure derivation: measured inputs -> health verdict. No I/O, no guessing.

    Split out from the measurement deliberately so it can be exercised against
    known-good AND known-bad inputs without a live daemon — which is what
    `selftest_health_derivation()` below does on every real call. A derivation
    that has only ever been run against the one state the machine happens to be
    in is not known to discriminate at all.

    `prev_nrestarts` is the restart count from the PREVIOUS sample, when one
    exists. A count that has increased between two samples is direct evidence of
    a loop in progress and does not depend on the uptime heuristic at all; the
    heuristic is what catches a loop on the FIRST sample, before there is a
    previous one to compare against.
    """
    if props is None:
        return {"state": HEALTH_UNKNOWN,
                "detail": "systemd properties could not be read",
                "serving": None}

    active_state = props.get("ActiveState") or ""
    sub_state = props.get("SubState") or ""
    try:
        nrestarts = int(props.get("NRestarts") or 0)
    except (TypeError, ValueError):
        nrestarts = 0
    started = _parse_systemd_timestamp(props.get("ExecMainStartTimestamp"))
    uptime = None if (started is None or now_epoch is None) else max(
        0.0, now_epoch - started)

    facts = {
        "active_state": active_state,
        "sub_state": sub_state,
        "nrestarts": nrestarts,
        "uptime_seconds": None if uptime is None else round(uptime, 1),
        "port67": port67,
        "addr_problems": list(addr_problems or ()),
        "main_pid": props.get("ExecMainPID"),
        "result": props.get("Result"),
    }

    # 1. A restart count that GREW since the last sample is unambiguous.
    restarted_since = (None if prev_nrestarts is None
                       else nrestarts - int(prev_nrestarts))
    facts["restarts_since_last_sample"] = restarted_since
    if restarted_since:
        return {"state": HEALTH_CRASH_LOOP, "serving": False, "facts": facts,
                "detail": "daemon auto-restarted %d time(s) since the last health "
                          "sample — it is not staying up" % restarted_since}

    # 2. First-sample case: has auto-restarted, and the current run is young.
    if nrestarts > 0 and uptime is not None and uptime < CRASH_LOOP_YOUNG_SECONDS:
        return {"state": HEALTH_CRASH_LOOP, "serving": False, "facts": facts,
                "detail": "daemon has auto-restarted %d time(s) and the current "
                          "run is only %.0fs old" % (nrestarts, uptime)}

    # 3. `activating` under auto-restart backoff is DOWN, not "starting up".
    if active_state == "activating" and sub_state == "auto-restart":
        return {"state": HEALTH_CRASH_LOOP, "serving": False, "facts": facts,
                "detail": "systemd is in auto-restart backoff (%s/%s)"
                          % (active_state, sub_state)}

    if active_state != "active":
        return {"state": HEALTH_DOWN, "serving": False, "facts": facts,
                "detail": "daemon is %s/%s" % (active_state or "?",
                                               sub_state or "?")}

    # 4. Active and stable — but is it SERVING? `unknown` from the port probe is
    #    not a pass. This is the same rule verify_mode() applies after a switch:
    #    refusing beats assuming, because the hazard being guarded is a network
    #    with no working DHCP that looks fine on the dashboard.
    if port67 != "bound":
        return {"state": HEALTH_UNVERIFIED, "serving": False, "facts": facts,
                "detail": "UDP :67 reads %r, expected 'bound' — %s"
                          % (port67, "cannot determine, refusing to assume"
                             if port67 == "unknown" else "the daemon is not serving")}
    if addr_problems:
        return {"state": HEALTH_UNVERIFIED, "serving": False, "facts": facts,
                "detail": "; ".join(addr_problems)}

    return {"state": HEALTH_SERVING, "serving": True, "facts": facts,
            "detail": "active, stable (%s), :67 bound"
                      % ("uptime unknown" if uptime is None
                         else "up %.0fs" % uptime)}


#: Known-good / known-bad inputs the derivation MUST classify differently.
#: Each entry is (label, props, port67, addr_problems, prev_nrestarts, expected).
#: The crash-loop rows are the ones that matter: they are all `ActiveState=active`
#: — i.e. every one of them is a case the old `is-active` status() reported as
#: "running". If the derivation ever collapses back to reading only ActiveState,
#: these stop discriminating and the self-test fails loudly.
_HEALTH_CANARIES = (
    ("healthy",
     {"ActiveState": "active", "SubState": "running", "NRestarts": "0",
      "ExecMainStartTimestamp": "Fri 2026-08-07 19:04:31 UTC"},
     "bound", (), 0, HEALTH_SERVING),
    ("crash-loop via restart delta",
     {"ActiveState": "active", "SubState": "running", "NRestarts": "7",
      "ExecMainStartTimestamp": "Fri 2026-08-07 19:04:31 UTC"},
     "bound", (), 4, HEALTH_CRASH_LOOP),
    ("crash-loop via young run",
     {"ActiveState": "active", "SubState": "running", "NRestarts": "3",
      "ExecMainStartTimestamp": "Fri 2026-08-07 19:04:31 UTC"},
     "bound", (), None, HEALTH_CRASH_LOOP),
    ("active but :67 not bound",
     {"ActiveState": "active", "SubState": "running", "NRestarts": "0",
      "ExecMainStartTimestamp": "Fri 2026-08-07 19:04:31 UTC"},
     "free", (), 0, HEALTH_UNVERIFIED),
    ("active but port unknowable",
     {"ActiveState": "active", "SubState": "running", "NRestarts": "0",
      "ExecMainStartTimestamp": "Fri 2026-08-07 19:04:31 UTC"},
     "unknown", (), 0, HEALTH_UNVERIFIED),
    ("stopped",
     {"ActiveState": "inactive", "SubState": "dead", "NRestarts": "0",
      "ExecMainStartTimestamp": ""},
     "free", (), 0, HEALTH_DOWN),
    ("unreadable properties",
     None, "unknown", (), None, HEALTH_UNKNOWN),
)


def selftest_health_derivation():
    """Prove the derivation discriminates, BEFORE trusting what it reports.

    Returns (ok, detail). Runs on every real health check, not only under the
    test suite — the standing practice in this repo after nine instruments in one
    day reported a non-measurement as a result. The reference shape is
    `scripts/nemesis-fw-neverblock`'s CANARIES block and `selftest_validator()`
    above: inputs that MUST pass and inputs that MUST fail, both checked, so an
    instrument that can only ever return one answer is caught here rather than
    after it has vouched for something real.

    The crash-loop canaries are the point. Every one of them is `active` — the
    exact input the old status() called "running".
    """
    for label, props, port, addrs, prev, expected in _HEALTH_CANARIES:
        # The young-run canary is relative to a fixed start; evaluate it against
        # a `now` just after that start so the case stays deterministic forever.
        base = _parse_systemd_timestamp("Fri 2026-08-07 19:04:31 UTC")
        now = (base + 10) if base is not None else None
        if label == "healthy" or label.startswith("active"):
            now = (base + 7200) if base is not None else None
        got = derive_health(props, port, addrs, now, prev_nrestarts=prev)
        if got["state"] != expected:
            return False, ("canary %r classified as %r, expected %r"
                           % (label, got["state"], expected))
    return True, "%d health canaries classify correctly" % len(_HEALTH_CANARIES)


_PIHOLE_DHCP_ACTIVE_RE = re.compile(
    r"^\s*\[dhcp\]\s*$(.*?)(?=^\s*\[|\Z)", re.M | re.S)


def pihole_dhcp_active(toml_path=PIHOLE_TOML):
    """Is Pi-hole's own DHCP server enabled? Returns True/False/None(unknown).

    Read-only. This module never writes Pi-hole's config, even to 'fix' this —
    that surface belongs to Pi-hole, and writing it is what produced the
    2026-08-06 outage. If Pi-hole's DHCP is on, we refuse and say so.

    Section-scoped deliberately: a naive substring search for `active = true`
    matches the wrong section of `pihole.toml` (that exact mistake was made on
    2026-08-06). The regex captures the `[dhcp]` block only, up to the next
    section header.

    Returns None when the file is absent or unreadable — an explicit unknown,
    never a default of False. Treating "cannot tell" as "safe" is how two DHCP
    servers end up running.
    """
    try:
        with open(toml_path) as f:
            text = f.read()
    except OSError:
        return None
    m = _PIHOLE_DHCP_ACTIVE_RE.search(text)
    if not m:
        return False  # no [dhcp] section at all => not enabled
    block = m.group(1)
    am = re.search(r"^\s*active\s*=\s*(true|false)\s*$", block, re.M)
    if not am:
        return None
    return am.group(1) == "true"


def check_preconditions(interfaces, allowlist, expected_addrs=None,
                        lease_path=LEASE_PATH, toml_path=PIHOLE_TOML,
                        conn=None):
    """Every condition that must hold before serving. Returns list of failures.

    Each failure is `(code, detail)`. Recording is done here rather than by the
    caller so a precondition can never be checked without its occurrence being
    recorded — the two would otherwise drift apart.
    """
    failures = []
    expected_addrs = expected_addrs or {}

    # Gate: allowlist. Default-deny, and an EMPTY allowlist serves nowhere.
    # An exclusion list would be wrong the moment a NIC is added.
    if not allowlist:
        failures.append((E_IFACE_NOT_ALLOWED,
                         "serve allowlist is empty — refusing to serve anywhere"))
    for iface in interfaces:
        if iface not in allowlist:
            failures.append((E_IFACE_NOT_ALLOWED,
                             "interface %r is not in the allowlist %r"
                             % (iface, sorted(allowlist))))

    # Pi-hole's DHCP must be off. This is the assembled-config check: under
    # direct ownership the duplicate-writer risk is two DAEMONS, not two files,
    # and that failure is silent (conflicting leases) rather than loud.
    active = pihole_dhcp_active(toml_path)
    if active is True:
        failures.append((E_PIHOLE_DHCP_ON,
                         "Pi-hole [dhcp] active=true in %s" % toml_path))
    elif active is None:
        failures.append((E_PIHOLE_DHCP_ON,
                         "could not determine Pi-hole DHCP state from %s — "
                         "refusing rather than assuming it is off" % toml_path))

    # The classifier must prove it still refuses a foreign holder BEFORE it is
    # used to permit anything. A guard that cannot demonstrate it discriminates
    # does not get to authorise a start — fail closed, loudly.
    ok_cls, cls_detail = selftest_port67_classifier()
    if not ok_cls:
        failures.append((E_PORT_BOUND,
                         "UDP :67 ownership check FAILED ITS OWN SELF-TEST (%s) — "
                         "refusing to start rather than trust a guard that cannot "
                         "prove it discriminates" % cls_detail))
    else:
        verdict, readback = port67_availability()
        if verdict == PORT67_FOREIGN:
            failures.append((E_PORT_BOUND,
                             "UDP :67 is held by another process and %s is not "
                             "active — refusing to start a second DHCP server "
                             "(readback: %s)" % (SERVICE_NAME, readback)))
        elif verdict == PORT67_UNKNOWN:
            failures.append((E_PORT_BOUND,
                             "could not determine whether UDP :67 is free — "
                             "refusing rather than assuming it is (readback: %s)"
                             % (readback,)))
        elif verdict == PORT67_OURS:
            # Not a failure. Our own daemon already holds the port, which is the
            # normal state when the dashboard restarts while DHCP keeps serving,
            # or when the module adopts a daemon that is already up. `systemctl
            # start` on an active unit is a no-op, so this path is idempotent.
            log.info("dhcp: UDP :67 is held by our own active %s — adopting the "
                     "running daemon rather than refusing", SERVICE_NAME)

    for iface in interfaces:
        if not _iface_exists(iface):
            failures.append((E_IFACE_UNUSABLE, "interface %r does not exist" % iface))
            continue
        if not _iface_carrier(iface):
            failures.append((E_IFACE_UNUSABLE, "interface %r has no carrier" % iface))
        want = expected_addrs.get(iface)
        if want:
            # The interface must ALREADY hold its address. This module never
            # assigns one at start: an interface whose only DHCP server is on
            # this box can deadlock systemd-networkd-wait-online and stall the
            # entire boot, including this service. Addressing is declarative,
            # applied at network-config time; this only verifies it landed.
            have = _iface_addresses(iface)
            if want not in have:
                failures.append((
                    E_IFACE_UNUSABLE,
                    "interface %r does not hold its expected static address %s "
                    "(has: %s) — declarative addressing did not apply; refusing "
                    "rather than assigning it here"
                    % (iface, want, ", ".join(have) or "none")))

    lease_dir = os.path.dirname(lease_path)
    if not os.path.isdir(lease_dir):
        failures.append((E_LEASE_DIR, "lease directory %s does not exist" % lease_dir))
    elif not os.access(lease_dir, os.W_OK):
        failures.append((E_LEASE_DIR, "lease directory %s is not writable" % lease_dir))

    # Recording happens here rather than in the caller so a precondition can
    # never be checked without its occurrence being recorded — the two would
    # otherwise drift. With conn=None (pure callers, tests) the failures are
    # still returned; they are logged as not-persisted rather than silently
    # dropped.
    for code, detail in failures:
        _record(code, context={"detail": detail}, conn=conn)
    return failures


# ── Module ───────────────────────────────────────────────────────────────────

class Module(NemesisModule):
    """Nemesis-owned DHCP. See the module docstring for why it owns dnsmasq."""

    def __init__(self, manifest: dict):
        super().__init__(manifest)
        self._cfg = self._load_config()
        self._stop_evt = threading.Event()
        self._thread = None
        #: Why serving is not running, when it is not. Surfaced on the dashboard
        #: card so a failed start explains itself instead of the module simply
        #: appearing inert.
        self._last_error = None
        #: Restart count at the previous health sample, for delta detection. None
        #: until the first sample — deliberately NOT 0, because 0 would make the
        #: very first reading of a daemon that has already restarted look like a
        #: fresh loop that just began.
        self._prev_nrestarts = None

    # -- config ------------------------------------------------------------

    def _config_path(self):
        """Where this module's runtime config lives: `/etc/nemesis/dhcp/config.json`.

        ⚠ THIS USED TO READ `<module_dir>/config.json` (`manifest["_dir"]`, with
        CONF_DIR only as a fallback for when `_dir` was absent). The loader ALWAYS
        sets `_dir`, so the fallback never applied in production and the module
        read a path inside its own CODE tree — where no config has ever existed.
        Every load therefore hit FileNotFoundError, took the serve-nowhere
        default, and reported `mode=provider`: the module loaded, announced it was
        deliberately not serving DHCP, and looked entirely healthy doing it, while
        the real config at `/etc/nemesis/dhcp/config.json` said `mode=nemesis`.
        Caught live 2026-08-07 on the first load through the real loader.

        Config belongs in /etc, not beside the code: the module directory is
        replaced on upgrade and is inside the git working tree, so
        `_write_config_json()` writing there would both dirty the repo and lose the
        operator's settings on the next update.

        `_config_path` in the manifest overrides, for tests that need a path
        guaranteed not to exist. That is an EXPLICIT seam — the previous behaviour
        was an accidental one, which is precisely how it went unnoticed.
        """
        override = self.manifest.get("_config_path")
        if override:
            return override
        return os.path.join(CONF_DIR, "config.json")

    def _load_config(self):
        """Read module config. Absent config yields a SERVE-NOWHERE default.

        No hardcoded network defaults. The previous module fell back to
        192.168.1.100-200 — an environment-specific guess baked into shipped
        code (already a Rule 8 PUNCHLIST item). A DHCP server that guesses a
        range is worse than one that refuses to start.
        """
        path = self._config_path()
        try:
            with open(path) as f:
                raw = json.load(f)
        except FileNotFoundError:
            return {"interfaces": [], "allowlist": [], "scopes": [],
                    "default_tag": None, "expected_addrs": {}}
        except Exception as e:  # noqa: BLE001
            log.exception("dhcp: config.json unreadable (%s) — serving nowhere", e)
            return {"interfaces": [], "allowlist": [], "scopes": [],
                    "default_tag": None, "expected_addrs": {}}
        return raw

    def build_config(self):
        scopes = [Scope(**s) for s in self._cfg.get("scopes", [])]
        return DhcpConfig(
            interfaces=self._cfg.get("interfaces", []),
            scopes=scopes,
            default_tag=self._cfg.get("default_tag"),
            dhcp_script=self._cfg.get("dhcp_script"),
        )

    # -- error-system plumbing --------------------------------------------

    def _err_conn(self):
        """A connection for error recording, or None if unavailable.

        Returns None rather than raising: DHCP must not fail to start because
        the error-recording facility is unavailable. `_record()` states plainly
        in the log when an occurrence could not be persisted, so a None here is
        visible rather than silent.
        """
        try:
            conn = _dm_conn()
            ensure_codes_registered(conn)
            return conn
        except Exception as e:  # noqa: BLE001
            log.warning("dhcp: error-code system unavailable (%s); failures will "
                        "be logged but NOT recorded as occurrences", e)
            return None

    @property
    def mode(self):
        raw = self._cfg.get("mode", DEFAULT_MODE)
        if raw not in MODES:
            # An unrecognised mode must not silently become "serve DHCP".
            log.error("dhcp: unknown mode %r in config; falling back to %r "
                      "(serve nothing)", raw, DEFAULT_MODE)
            return DEFAULT_MODE
        return raw

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Bring the module up. MUST NOT raise, and MUST NOT block.

        ⚠ BOTH CONSTRAINTS COME FROM THE LOADER, verified 2026-08-06 rather than
        assumed:

        * `modules_loader._load_module()` calls `instance.start()` **inline**
          during dashboard boot, so anything that blocks here stalls the whole
          dashboard from starting.
        * Its caller wraps load in `except Exception: log.exception("failed to
          load %s")`. So a raise does not surface as a DHCP problem — **the
          module silently does not load at all**: no dashboard card, no status,
          no explanation. An earlier version of this method raised on
          precondition failure and would have vanished exactly that way.

        So an operational failure (preconditions unmet, daemon refused to start)
        is RECORDED and stored in `self._last_error`, and the module stays
        loaded to report it. A module that can explain why it is not serving is
        worth more than one that disappears.
        """
        conn = self._err_conn()
        mode = self.mode
        self._last_error = None

        # Modes 2 and 3 are not "the module is broken" — they are supported
        # configurations in which Nemesis deliberately does not serve leases.
        # Starting is a no-op that reports what is unavailable, rather than an
        # error, so the operator sees a chosen state and not a failure.
        if mode != MODE_NEMESIS:
            caps = mode_capabilities(mode)
            log.info("dhcp: mode=%s (%s) — Nemesis is NOT serving DHCP. "
                     "Unavailable in this mode: %s",
                     mode, caps["label"],
                     "; ".join(caps["degraded"]) or "nothing")
            return

        try:
            self._start_serving(conn)
        except (DhcpConfigError, PreconditionFailed, RuntimeError) as e:
            # Already recorded as a structured code by the raising site. Kept
            # here so the dashboard card can say WHY, and swallowed so the
            # module stays loaded (see the docstring).
            self._last_error = str(e)
            log.error("dhcp: not serving — %s", e)
            return
        except Exception as e:  # noqa: BLE001
            # ⚠ THE CATCH-ALL IS THE CONTRACT, not laziness. This method's
            # docstring says it MUST NOT raise, because the loader turns any
            # escape into "module silently does not load at all". The narrow
            # tuple above enumerated the exceptions this code MEANT to raise —
            # and then an OSError from `tempfile.mkstemp()` (read-only /tmp under
            # the dashboard's sandbox) went straight past it and did exactly what
            # the docstring warns about: no card, no status, no explanation,
            # 2026-08-07. An unexpected exception is precisely the case the
            # module most needs to survive in order to report.
            self._last_error = "unexpected error while starting: %s" % e
            log.exception("dhcp: not serving — unexpected error during start")
            _record(E_DAEMON_FAILED,
                    context={"phase": "start", "error": repr(e)}, conn=conn)
            return

        # The bind settle lives in `_start_serving()` (see the note there), so it
        # covers the rollback path too — not just this one.

        # First health sample BEFORE the loop starts, so the record begins at the
        # moment serving began rather than one sync interval later. A start that
        # comes straight up crash-looping is visible immediately.
        try:
            self.record_health_sample(conn)
        except Exception:  # noqa: BLE001
            log.exception("dhcp: initial health sample failed")

        self._start_sync_thread()

    def _start_serving(self, conn):
        """Validate, apply config, start the daemon. Raises on any failure."""
        ok, detail = selftest_validator()
        if not ok:
            _record(E_CONFIG_INVALID, context={"selftest": detail}, conn=conn)
            raise DhcpConfigError("validator self-test failed: %s" % detail)

        try:
            text = self.build_config().render()
        except DhcpConfigError as e:
            _record(E_CONFIG_INVALID, context={"render": str(e)}, conn=conn)
            raise

        ok, detail = validate_config_text(text)
        if not ok:
            _record(E_CONFIG_INVALID, context={"dnsmasq_test": detail}, conn=conn)
            raise DhcpConfigError("rendered config failed dnsmasq --test: %s" % detail)

        failures = check_preconditions(
            self._cfg.get("interfaces", []),
            set(self._cfg.get("allowlist", [])),
            expected_addrs=self._cfg.get("expected_addrs", {}),
            conn=conn,
        )
        if failures:
            raise PreconditionFailed("; ".join("%s: %s" % f for f in failures))

        os.makedirs(CONF_DIR, exist_ok=True)
        with open(CONF_PATH, "w") as f:
            f.write(text)

        r = subprocess.run(["systemctl", "start", SERVICE_NAME],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            _record(E_DAEMON_FAILED,
                    context={"rc": r.returncode,
                             "stderr": (r.stderr or "").strip()[:400]}, conn=conn)
            raise RuntimeError("failed to start %s" % SERVICE_NAME)
        log.info("dhcp: started %s on %s", SERVICE_NAME,
                 ", ".join(self._cfg.get("interfaces", [])))

        # ⚠ WAIT FOR THE BIND HERE, not in the callers. `systemctl start` returns
        # once the unit is ACTIVE, which is before dnsmasq has bound :67 — and
        # EVERY caller then immediately measures that port:
        #   * start()        -> the first health sample, which read `free` at 0.2s
        #     uptime and logged a spurious serving->unverified->serving flap;
        #   * _apply_state() -> verify_mode(), which is far worse. Measured live
        #     2026-08-07: a rollback restored a genuinely working daemon, verify
        #     sampled :67 microseconds later, read `free`, and declared the tier
        #     failed. Both attempts on every tier failed the same way, the cascade
        #     escalated, and it STOPPED nemesis-dhcpd — a real DHCP outage caused
        #     entirely by measuring too early.
        # Putting the settle in `_start_serving` rather than in each caller is the
        # point: a caller added later cannot forget it.
        self._await_bind()

    # -- lease sync loop ---------------------------------------------------

    #: Longest wait for the daemon to bind :67 after `systemctl start` returns.
    #: Bounded and short because `start()` runs INLINE during dashboard boot (see
    #: that method's docstring) — a healthy bind is sub-second, and a daemon that
    #: has not bound within this window is reported honestly rather than waited on.
    BIND_SETTLE_SECONDS = 3.0
    BIND_POLL_INTERVAL = 0.2

    def _await_bind(self, timeout=None, _sleep=time.sleep):
        """Poll until :67 is bound, or the bounded timeout expires.

        Returns True if the bind was observed. A False return is NOT treated as a
        failure by the caller — it just means the health sample that follows will
        report what it measures, which may legitimately be `unverified`.
        """
        timeout = self.BIND_SETTLE_SECONDS if timeout is None else timeout
        deadline = time.time() + timeout
        while time.time() < deadline:
            verdict, _ = port67_availability()
            if verdict in (PORT67_OURS, PORT67_FOREIGN):   # i.e. held
                return True
            _sleep(self.BIND_POLL_INTERVAL)
        return False

    def _start_sync_thread(self):
        """Spawn the periodic lease->inventory sync.

        On this module's OWN lifecycle rather than `device_scanner`'s cycle or a
        separate timer unit (Window 1's recommendation, 2026-08-06). The reason
        is blast radius: `device_scanner`'s loop has no exception handling and
        runs on a tight restart cycle, so folding a DHCP-sync failure into it
        would turn a 5-minute scanner into a crash-restart hot loop instead of
        degrading quietly. Here, a sync failure costs one skipped cycle.
        """
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._sync_loop, name="dhcp-lease-sync", daemon=True)
        self._thread.start()
        log.info("dhcp: lease sync every %ds", SYNC_INTERVAL_SECONDS)

    def _sync_loop(self):
        """Sync leases, then promote hostnames. Survives its own failures.

        Per-cycle try/except, matching `anomaly_detection`'s loop: one bad cycle
        must not kill the thread, because a dead sync thread and an idle one are
        indistinguishable from outside — the exact silent-failure shape this
        codebase keeps finding.

        `Event.wait()` rather than `sleep()` so `stop()` interrupts immediately
        instead of waiting out a full interval.
        """
        while not self._stop_evt.is_set():
            try:
                conn = _dm_conn()
                try:
                    summary = self.sync_leases(conn)
                    # Health rides on THIS loop rather than a timer of its own.
                    # The sync thread is already the module's proof-of-life: if
                    # it dies, health sampling stops too, and the resulting gap
                    # in `dhcp_health_samples` is exactly the signal that the
                    # module stopped watching — which a separate timer would
                    # hide by carrying on cheerfully without it.
                    self.record_health_sample(
                        conn, lease_count=summary.get("seen"))
                finally:
                    conn.close()
                # ⚠ DELIBERATELY on core's OWN connection, not the one above.
                # This module's Data Manager namespace grants `dhcp_leases` and
                # nothing else, so an `UPDATE devices` issued through it is
                # REFUSED at runtime. That refusal is the ADR 0001 boundary
                # being enforced rather than merely documented — core opens its
                # own connection to write the table core owns.
                database.reconcile_dhcp_hostnames()
            except Exception:
                log.exception("dhcp: lease sync cycle failed")
            self._stop_evt.wait(SYNC_INTERVAL_SECONDS)

    def stop(self) -> None:
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None
        r = subprocess.run(["systemctl", "stop", SERVICE_NAME],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            _record(E_DAEMON_FAILED,
                    context={"action": "stop",
                             "stderr": (r.stderr or "").strip()[:400]},
                    conn=self._err_conn())
        log.info("dhcp: stopped %s", SERVICE_NAME)

    def reload(self) -> None:
        """SIGHUP — re-reads `dhcp-hostsfile` without disturbing live leases.

        This is how a device's tier assignment changes: write its `dhcp-host`
        entry into hosts.d, reload, and it moves range on next renewal. A full
        restart would be both unnecessary and disruptive.
        """
        r = subprocess.run(["systemctl", "reload", SERVICE_NAME],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            _record(E_RELOAD_FAILED,
                    context={"stderr": (r.stderr or "").strip()[:400]},
                    conn=self._err_conn())
            raise RuntimeError("reload failed")

    def health(self, advance=True):
        """MEASURE the daemon's real state and derive a verdict. Never raises.

        This is what `status()` is now built on. It exists as its own method
        because health is also what the periodic sample records — the dashboard
        and the history must not be able to disagree about what "running" means,
        which they would the moment each derived it separately.

        `advance=False` reads without consuming the restart-delta: `status()` can
        be called many times between sync cycles (every dashboard render), and if
        each call advanced `_prev_nrestarts` the sampler would find the delta
        already eaten and a real crash loop would go unrecorded.

        The self-test runs FIRST and its failure is fatal to the result. An
        instrument that cannot prove it discriminates does not get to return a
        verdict — it returns `unknown`, which is a state the caller must handle.
        """
        ok, detail = selftest_health_derivation()
        if not ok:
            log.error("dhcp: health self-test FAILED (%s) — refusing to report a "
                      "health verdict derived from an unproven instrument", detail)
            return {"state": HEALTH_UNKNOWN, "serving": None,
                    "detail": "health self-test failed: %s" % detail,
                    "facts": {"selftest": detail}}

        props = _systemd_props()

        # Bind-probe first; fall back to /proc when it cannot tell. From the
        # unprivileged dashboard user the bind probe ALWAYS says "unknown"
        # (EACCES on a privileged port), so without this fallback every sample of
        # a healthy daemon would read `unverified`. See port67_bound_via_proc().
        port = port67_state()
        port_source = "bind"
        if port == "unknown":
            ok_probe, probe_detail = selftest_proc_port_probe()
            if ok_probe:
                via_proc = port67_bound_via_proc()
                if via_proc is not None:
                    port = "bound" if via_proc else "free"
                    port_source = "proc"
            else:
                # The fallback could not prove itself, so it does not get used.
                # `unknown` stands, and health reports `unverified` — refusing,
                # not assuming, exactly as the pre-start check does.
                log.warning("dhcp: /proc port probe self-test failed (%s) — "
                            "leaving :67 state unknown", probe_detail)

        addr_problems = []
        expected = self._cfg.get("expected_addrs", {}) or {}
        for iface in (self._cfg.get("interfaces", []) or []):
            want = expected.get(iface)
            if want and want not in _iface_addresses(iface):
                addr_problems.append("%s lost expected address %s" % (iface, want))

        result = derive_health(props, port, addr_problems, time.time(),
                               prev_nrestarts=self._prev_nrestarts)
        # Which instrument answered is itself diagnostic — a sample that says
        # "bound" via /proc and one that says so via a successful privileged bind
        # are different observations, and a later reader should not have to guess.
        result.setdefault("facts", {})["port67_source"] = port_source
        if advance and props is not None:
            try:
                self._prev_nrestarts = int(props.get("NRestarts") or 0)
            except (TypeError, ValueError):
                self._prev_nrestarts = None
        return result

    #: Health states that mean "the module believes it is serving and it is not".
    _UNHEALTHY_CODE = {
        HEALTH_CRASH_LOOP: E_DAEMON_CRASH_LOOP,
        HEALTH_UNVERIFIED: E_SERVING_UNVERIFIED,
        HEALTH_UNKNOWN: E_HEALTH_UNMEASURABLE,
    }

    def status(self) -> dict:
        """Current state, DERIVED FROM MEASURED HEALTH — not from process presence.

        The old implementation mapped `systemctl is-active == "active"` straight
        to `"running"`. See the health section above for why that reports a
        crash-looping daemon as healthy; that is the defect this rewrite closes.

        `state` can now be any of: `serving`, `crash_looping`, `unverified`,
        `down`, `unknown`, or `not_serving` (a chosen mode, not a fault).
        `unknown` is deliberately not collapsed into either good or bad.
        """
        leases = self.read_leases()
        mode = self.mode
        caps = mode_capabilities(mode)
        if not caps["serves_dhcp"]:
            # Not an error state. Report the chosen configuration and what it
            # costs, so "no device names appear" is explained rather than
            # left for the operator to discover and misdiagnose.
            return {
                "state": "not_serving",
                "mode": mode,
                "mode_label": caps["label"],
                "detail": caps["label"],
                "lease_count": 0,
                "interfaces": [],
                "degraded": caps["degraded"],
            }
        h = self.health(advance=False)
        healthy = h["state"] == HEALTH_SERVING

        # The lease count is only meaningful alongside a health verdict. "2
        # leases" on a crash-looping daemon is a stale file, not evidence of
        # service, so the detail line leads with health whenever it is not good.
        if healthy:
            detail = "%d lease%s" % (len(leases), "" if len(leases) == 1 else "s")
        else:
            detail = h["detail"]

        return {
            "state": h["state"],
            "healthy": healthy,
            "mode": mode,
            "mode_label": caps["label"],
            "detail": detail,
            "health_detail": h["detail"],
            "health_facts": h.get("facts", {}),
            "lease_count": len(leases),
            "interfaces": self._cfg.get("interfaces", []),
            "degraded": caps["degraded"],
            "last_error": self._last_error,
        }

    # -- lease capture: the module's side of the ADR 0001 boundary ----------

    def init_lease_table(self, conn):
        """DDL for `dhcp_leases` — this module's OWN table.

        Prefixed, therefore module-owned and writable by this module under ADR
        0001's write-own/read-any rule. The core `devices` table is NOT writable
        from here; `database.reconcile_dhcp_hostnames()` is the only thing that
        promotes an observation from this table into the shared inventory.

        This table IS the interface between the two sides. Keeping it explicit
        means the module can be disabled, replaced, or run in a mode that never
        serves a lease, without any of that reaching the inventory's schema.
        """
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dhcp_leases (
                mac        TEXT PRIMARY KEY,
                ip         TEXT,
                hostname   TEXT,
                expiry     TEXT,
                first_seen TEXT,
                last_seen  TEXT
            )
        """)
        conn.commit()

    # -- steady-state observability ---------------------------------------
    #
    # WHAT WAS ALREADY HERE, AND WHY IT WAS NOT ENOUGH (assessed 2026-08-07).
    # The module had three channels before this: `dhcp_mode_change_log`, the
    # `E-DHCP-0XX` codes, and `dhcp_leases`. Every one of them is a TRANSITION
    # channel — they fire when something is being CHANGED (start, reload, mode
    # switch, rollback) or record only the current snapshot. None of them can
    # answer a question about how the module has BEHAVED over a period:
    #
    #   * `dhcp_mode_change_log` gets zero rows on a module that never switches
    #     mode, which is the normal case and was the actual live state.
    #   * the error codes all fire at transition sites, so hours of crash-looping
    #     produced no occurrence at all.
    #   * `dhcp_leases` is a CURRENT-STATE table — `last_seen` is overwritten on
    #     every sync, so an address change, a device appearing, or a device going
    #     away leaves no trace once the next sync runs.
    #   * dnsmasq's own journal has the real DHCPACK/REQUEST traffic, but it is
    #     unstructured, rotates away, and is not reachable from the dashboard.
    #
    # So the module could say what it IS, and what was last DONE to it, but not
    # what it had been doing. These two tables are that missing channel.

    #: How often a health sample is written when nothing has changed. Every
    #: CHANGE is always recorded; this is the heartbeat that proves the sampler
    #: itself was alive in between. Without it, a gap in the table is ambiguous
    #: between "nothing happened" and "nothing was watching" — and those need to
    #: be distinguishable, since the second is the failure mode being guarded.
    HEALTH_HEARTBEAT_SECONDS = 900

    #: Health samples are telemetry, not forensic evidence, so unlike
    #: `dhcp_mode_change_log` they are prunable. The mode-change log must survive
    #: the operation it records; a health heartbeat from five weeks ago has no
    #: such duty and would otherwise grow the shared DB without bound.
    HEALTH_RETENTION_DAYS = 30

    def init_health_table(self, conn):
        """DDL for `dhcp_health_samples` — the periodic operating-state record.

        This is the table that would have made the first live run's crash loop
        visible while it was happening rather than by reading the journal
        afterwards. It stores the RAW measured facts next to the derived state,
        deliberately: "state=crash_looping" tells you what was concluded, and
        "nrestarts=7, uptime=3s, port67=free" is what lets someone check whether
        the conclusion was right. A verdict without its inputs cannot be audited.
        """
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dhcp_health_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                state TEXT NOT NULL,
                serving INTEGER,
                mode TEXT,
                active_state TEXT,
                sub_state TEXT,
                nrestarts INTEGER,
                restarts_since_last INTEGER,
                uptime_seconds REAL,
                port67 TEXT,
                lease_count INTEGER,
                detail TEXT,
                facts TEXT,
                is_change INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dhcp_health_ts "
                     "ON dhcp_health_samples(ts)")
        conn.commit()

    def init_lease_event_table(self, conn):
        """DDL for `dhcp_lease_events` — APPEND-ONLY lease history.

        `dhcp_leases` answers "who holds what right now". This answers "what has
        happened" — a device joining, an address changing, a device going away.
        The two are different questions and the snapshot table structurally
        cannot answer the second, because every sync overwrites the answer.

        Append-only as a code property, same as `dhcp_mode_change_log`: nothing
        in this module issues UPDATE or DELETE against it.
        """
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dhcp_lease_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                event TEXT NOT NULL,
                mac TEXT NOT NULL,
                ip TEXT,
                prev_ip TEXT,
                hostname TEXT,
                prev_hostname TEXT,
                expiry TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dhcp_lease_events_mac "
                     "ON dhcp_lease_events(mac)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dhcp_lease_events_ts "
                     "ON dhcp_lease_events(ts)")
        conn.commit()

    def record_health_sample(self, conn=None, health=None, lease_count=None):
        """Take (or accept) a health reading and record it. Returns the reading.

        Writes on CHANGE always, and on the heartbeat interval otherwise — see
        `HEALTH_HEARTBEAT_SECONDS` for why the heartbeat is not optional.

        An unhealthy verdict ALSO records the matching `E-DHCP-01X` code, so an
        operating-state problem reaches the same error ledger a transition
        failure would. That is the gap that let a crash loop run for hours
        without producing a single recorded occurrence.

        Never raises: observability failing must not take down the sync loop it
        rides on. It logs loudly instead — a health sample that could not be
        stored is itself a fact worth seeing in the journal.
        """
        # `self.health()` is called INSIDE the try on purpose. It shells out to
        # systemctl and binds a probe socket, so it can fail — and this runs on
        # the sync thread, where an escaping exception costs the cycle that also
        # syncs leases. Observability must never be able to take down the thing
        # it observes.
        h = {"state": HEALTH_UNKNOWN, "serving": None, "facts": {},
             "detail": "health check did not complete"}
        own = conn is None
        try:
            if health is not None:
                h = health
            else:
                h = self.health()
            if own:
                conn = _dm_conn()
            self.init_health_table(conn)
            facts = h.get("facts", {}) or {}

            row = conn.execute(
                "SELECT state, ts FROM dhcp_health_samples ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_state = row[0] if row else None
            prev_ts = row[1] if row else None
            changed = (prev_state != h["state"])

            due = True
            if not changed and prev_ts:
                try:
                    age = (datetime.now()
                           - datetime.fromisoformat(prev_ts)).total_seconds()
                    due = age >= self.HEALTH_HEARTBEAT_SECONDS
                except (TypeError, ValueError):
                    due = True  # unparseable timestamp -> record, never skip

            if changed or due:
                if lease_count is None:
                    lease_count = len(self.read_leases())
                conn.execute(
                    "INSERT INTO dhcp_health_samples "
                    "(ts,state,serving,mode,active_state,sub_state,nrestarts,"
                    " restarts_since_last,uptime_seconds,port67,lease_count,"
                    " detail,facts,is_change) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (_now_iso(), h["state"],
                     None if h.get("serving") is None else int(h["serving"]),
                     self.mode, facts.get("active_state"), facts.get("sub_state"),
                     facts.get("nrestarts"), facts.get("restarts_since_last_sample"),
                     facts.get("uptime_seconds"), facts.get("port67"),
                     lease_count, h.get("detail"), json.dumps(facts),
                     1 if changed else 0))
                self._prune_health_samples(conn)
                conn.commit()

            if changed:
                line = ("dhcp/health %s -> %s: %s"
                        % (prev_state or "(first sample)", h["state"], h.get("detail")))
                if h["state"] == HEALTH_SERVING:
                    log.info(line)
                else:
                    log.warning(line)

            code = self._UNHEALTHY_CODE.get(h["state"])
            if code and changed:
                # On the TRANSITION only. A crash loop sampled every 60s would
                # otherwise write an occurrence a minute and bury the ledger in
                # repetitions of one ongoing condition.
                _record(code, context={"detail": h.get("detail"), "facts": facts},
                        conn=conn)
        except Exception:  # noqa: BLE001
            log.exception("dhcp: could not record health sample (state=%s)",
                          h.get("state"))
        finally:
            if own and conn is not None:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
        return h

    def _prune_health_samples(self, conn):
        """Drop samples past the retention window. Caller commits."""
        cutoff = datetime.now().timestamp() - self.HEALTH_RETENTION_DAYS * 86400
        conn.execute("DELETE FROM dhcp_health_samples WHERE ts < ?",
                     (datetime.fromtimestamp(cutoff).isoformat(timespec="seconds"),))

    # -- mode-switch fail-over: trace log ---------------------------------

    def init_mode_change_log(self, conn):
        """DDL for `dhcp_mode_change_log` — the INSERT-ONLY diagnostic trace.

        WHY A DB TABLE AND NOT A FILE NEXT TO THE SNAPSHOTS. This log has to
        survive the very operation it records. The tier snapshots are overwritten
        and read back by design, so a trace living in or beside them could be
        clobbered by exactly the rollback it exists to explain. The switch
        mechanism otherwise touches ONLY filesystem and process state — never this
        database — so a table here is STRUCTURALLY outside anything a restore can
        reach, rather than merely conventionally separate.

        INSERT-ONLY, and that is a code property rather than a policy statement:
        nothing in this module issues UPDATE or DELETE against this table, at any
        tier, for any reason. A successful restore appends "restored"; a failed one
        appends "failed". Recovering access must never erase the evidence of why it
        was needed — the gap that made 2026-08-07's outage take three days to
        explain.

        Distinct from the error codes: `E-DHCP-0XX` marks THAT something happened
        in a coarse category; this is the step-by-step record with raw readback
        values and a timestamp per step, which is what actually lets someone
        reconstruct a cascade after the fact.
        """
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dhcp_mode_change_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                event TEXT NOT NULL,
                trigger TEXT,
                from_mode TEXT,
                to_mode TEXT,
                tier TEXT,
                attempt INTEGER,
                ok INTEGER,
                readback TEXT,
                detail TEXT,
                actor TEXT
            )
        """)
        conn.commit()

    def _trace(self, event, trigger=None, from_mode=None, to_mode=None,
               tier=None, attempt=None, ok=None, readback=None, detail=None):
        """Append one step to the trace log AND the log stream. Never raises.

        Two channels on purpose: the table is the durable, survives-rollback
        record; the log stream is what a person is actually watching while
        something is going wrong. Same split `_record()` already uses for codes.

        `readback` carries the RAW measured values, not a pass/fail verdict —
        "port67=unknown, active=failed" is diagnosable after the fact; "verify
        failed" is not.
        """
        line = ("dhcp/switch %s trigger=%s %s->%s tier=%s attempt=%s ok=%s "
                "readback=%s detail=%s" % (event, trigger, from_mode, to_mode,
                                           tier, attempt, ok, readback, detail))
        if ok is False:
            log.warning(line)
        else:
            log.info(line)
        try:
            conn = _dm_conn()
            try:
                self.init_mode_change_log(conn)
                conn.execute(
                    "INSERT INTO dhcp_mode_change_log "
                    "(ts,event,trigger,from_mode,to_mode,tier,attempt,ok,"
                    " readback,detail,actor) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (_now_iso(), event, trigger, from_mode, to_mode, tier,
                     attempt, None if ok is None else (1 if ok else 0),
                     json.dumps(readback) if readback is not None else None,
                     detail, "system"))
                conn.commit()
            finally:
                conn.close()
        except Exception:  # noqa: BLE001
            # A trace that cannot persist must not take down the switch it is
            # describing — but it must not vanish either, hence the log line
            # above always happening first.
            log.exception("dhcp/switch: trace row NOT persisted (event=%s)", event)

    # -- mode-switch fail-over: snapshot chain -----------------------------

    def _snapshot_path(self, tier):
        return os.path.join(SNAP_DIR, "%s.json" % tier)

    def _capture_state(self):
        """Current state as a snapshot record. Includes what was MEASURED.

        `verified` holds real readbacks rather than intentions, so a snapshot can
        later be compared against reality instead of trusted on its own say-so.
        """
        return {
            "mode": self.mode,
            "config": self._cfg,
            "daemon_was_active": self._daemon_active(),
            "captured_at": _now_iso(),
            "verified": {
                "port67_state": port67_state(),
                "pihole_dhcp_active": pihole_dhcp_active(),
            },
        }

    def _write_snapshot(self, tier, record):
        """Write a tier atomically. Returns True on success.

        Atomic rename, not a plain write: a snapshot half-written by a crash is
        worse than an absent one, because the cascade would read it, parse-fail or
        act on partial config, and burn a tier that might have been recoverable.
        """
        try:
            os.makedirs(SNAP_DIR, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=SNAP_DIR, prefix=".%s." % tier)
            with os.fdopen(fd, "w") as f:
                json.dump(record, f, indent=2)
            os.replace(tmp, self._snapshot_path(tier))
            return True
        except Exception:  # noqa: BLE001
            log.exception("dhcp/switch: could not write snapshot tier %s", tier)
            return False

    def _read_snapshot(self, tier):
        """Read a tier, or None if absent/unreadable.

        Absent and unreadable both return None deliberately: the cascade SKIPS a
        tier it cannot use rather than attempting a restore against nothing, and
        an unparseable file is exactly as unusable as a missing one. The caller
        distinguishes "skipped" from "tried and failed" in the trace.
        """
        try:
            with open(self._snapshot_path(tier)) as f:
                return json.load(f)
        except FileNotFoundError:
            return None
        except Exception:  # noqa: BLE001
            log.exception("dhcp/switch: snapshot tier %s unreadable — treating "
                          "as absent", tier)
            return None

    def ensure_install_baseline(self):
        """Capture the permanent factory-floor snapshot ONCE, if absent.

        Never overwritten. This is what guarantees the cascade always has a final
        target, which is what removes the old "no snapshot exists yet" edge case
        entirely — even a box's very first mode switch has somewhere to fall back
        to.

        Records whatever was ACTUALLY true at first load rather than assuming the
        shipped default. On a normal install that is `provider` (the manifest ships
        `enabled_by_default: false`), but a box provisioned some other way gets its
        own real floor rather than a hardcoded guess about it.
        """
        if os.path.exists(self._snapshot_path(TIER_BASELINE)):
            return False
        rec = self._capture_state()
        if self._write_snapshot(TIER_BASELINE, rec):
            self._trace("baseline-captured", to_mode=rec.get("mode"),
                        detail="permanent install baseline written (once, never "
                               "overwritten)")
            return True
        return False

    def _rotate_chain(self, new_record):
        """Shift the rolling chain after a SUCCESSFUL switch: aging<-trusted<-thought.

        Oldest first, so nothing is overwritten before it has been copied forward.
        A FAILED switch never calls this — the attempted state simply never earns
        a tier, which is why the pre-change state is still sitting in
        `thought-trusted` for the cascade to find.
        """
        aging_src = self._read_snapshot(TIER_TRUSTED)
        if aging_src is not None:
            self._write_snapshot(TIER_AGING, aging_src)
        thought_src = self._read_snapshot(TIER_THOUGHT)
        if thought_src is not None:
            self._write_snapshot(TIER_TRUSTED, thought_src)
        self._write_snapshot(TIER_THOUGHT, new_record)

    # -- mode-switch fail-over: verification -------------------------------

    def _daemon_active(self):
        r = subprocess.run(["systemctl", "is-active", SERVICE_NAME],
                           capture_output=True, text=True, timeout=10)
        return (r.stdout or "").strip() == "active"

    def verify_mode(self, mode):
        """Post-change READBACK. Returns (ok, readback_dict, detail).

        Rule 13 applied here rather than merely cited: nothing in this function
        trusts a `systemctl` exit code. It measures the resulting state — is the
        socket actually bound, is the daemon actually active, does the interface
        still hold its address — because "the command returned 0" and "the system
        is now in the intended state" are different claims, and this codebase has
        already shipped the gap between them three times.

        `unknown` from `port67_state()` is a FAILURE, never a pass. Refusing beats
        assuming a port is free when two DHCP servers is the hazard being guarded.
        """
        active = self._daemon_active()
        readback = {"systemctl_is_active": active}

        if mode == MODE_NEMESIS:
            # ⚠ `port67_availability()`, NOT the raw `port67_state()` bind probe.
            # This is the same unprivileged blind spot that broke health(), and
            # here it was far more damaging: from the dashboard user the bind
            # probe always returns "unknown", so EVERY rollback tier failed its
            # own verification even though the rollback had mechanically
            # succeeded and the daemon was serving. The cascade then exhausted
            # all four tiers, escalated, and DELIBERATELY STOPPED nemesis-dhcpd —
            # turning a recoverable failure into a real DHCP outage.
            #
            # Measured live 2026-08-07: a deliberate bad switch to `pihole` was
            # correctly rejected, the rollback to install-baseline genuinely
            # restored a working daemon, and the mechanism reported "EVERY
            # rollback tier failed" and took DHCP down anyway. This could not
            # have been caught with stubbed systemd — the stub returned "bound".
            #
            # `OURS` rather than merely "held" is also STRICTER than the old
            # check: it distinguishes our own daemon holding the port from some
            # other process holding it, which "bound" could never tell apart.
            port_verdict, port_rb = port67_availability()
            port = "bound" if port_verdict == PORT67_OURS else port_verdict
            readback["port67_state"] = port
            readback["port67_verdict"] = port_verdict
            readback["port67_readback"] = port_rb
            ifaces = self._cfg.get("interfaces", []) or []
            expected = self._cfg.get("expected_addrs", {}) or {}
            addr_ok, addr_detail = True, []
            for iface in ifaces:
                have = _iface_addresses(iface)
                readback["addrs_%s" % iface] = have
                want = expected.get(iface)
                if want and want not in have:
                    addr_ok = False
                    addr_detail.append("%s lost expected address" % iface)
            if not active:
                return False, readback, "daemon is not active after switch"
            if port != "bound":
                return False, readback, (
                    "UDP :67 reads %r, expected 'bound' — %s"
                    % (port, "cannot determine, refusing to assume"
                       if port == "unknown" else "the daemon is not serving"))
            if not addr_ok:
                return False, readback, "; ".join(addr_detail)
            return True, readback, "serving and verified"

        # pihole / provider: this module must NOT be serving.
        if active:
            return False, readback, (
                "%s is still active but mode %s means Nemesis must not serve"
                % (SERVICE_NAME, mode))

        if mode == MODE_PIHOLE:
            ph = pihole_dhcp_active()
            readback["pihole_dhcp_active"] = ph
            if ph is not True:
                # False or None both fail. Handing authority to Pi-hole while
                # Pi-hole is not configured to serve is the ZERO-DHCP-servers
                # case, and "cannot tell" is not evidence that it is fine.
                return False, readback, (
                    "Pi-hole DHCP reads %r, expected active — handing DHCP to a "
                    "server that is not serving would leave the network with none"
                    % (ph,))
            return True, readback, "Pi-hole confirmed serving"

        # MODE_PROVIDER — the honest floor.
        #
        # The router is UNVERIFIABLE from this box. All that can be confirmed is
        # that this module stopped. That limit is stated in the detail string and
        # carried into the trace, rather than being dressed up as a pass; it is
        # also exactly why switching to this mode requires an explicit operator
        # affirmation at the UI layer.
        return True, readback, ("nemesis-dhcpd stopped; router/ISP DHCP is "
                                "UNVERIFIABLE from this host")

    # -- mode-switch fail-over: the operation ------------------------------

    def _apply_state(self, mode, cfg):
        """Put the module into (mode, cfg) — the SAME path a normal switch uses.

        Rollback deliberately routes through here too rather than getting a
        special-cased shortcut. That is what guarantees a rollback re-runs the
        full precondition gate (Pi-hole-DHCP-off, :67 free, interface holds its
        address) instead of blindly forcing a state that may itself now conflict
        with something that changed since the snapshot was taken. A snapshot's own
        recorded readings are NEVER trusted as still current.
        """
        self._cfg = dict(cfg or {})
        self._cfg["mode"] = mode
        self._write_config_json()
        # Stop first, unconditionally: every transition either ends with the
        # daemon down, or wants it restarted against new config anyway.
        subprocess.run(["systemctl", "stop", SERVICE_NAME],
                       capture_output=True, text=True, timeout=30)
        if mode != MODE_NEMESIS:
            return True, "stopped (mode %s does not serve)" % mode
        conn = self._err_conn()
        try:
            self._start_serving(conn)
            self._start_sync_thread()
            return True, "started"
        except (DhcpConfigError, PreconditionFailed, RuntimeError) as e:
            self._last_error = str(e)
            return False, str(e)
        finally:
            if conn is not None:
                conn.close()

    def _write_config_json(self):
        # Same resolution as the read side — they MUST agree, or a mode switch
        # persists to a file the next load never reads, and the switch silently
        # un-does itself on restart.
        path = self._config_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".config.")
        with os.fdopen(fd, "w") as f:
            json.dump(self._cfg, f, indent=2)
        os.replace(tmp, path)

    def switch_mode(self, new_mode, new_config=None, force=False,
                    _sleep=time.sleep):
        """Switch DHCP authority, verify the result, and roll back if it failed.

        The single entry point: a route calls this rather than reimplementing the
        sequence. Returns a result dict; NEVER raises.

        `force=True` suppresses automatic rollback ONLY — the operator accepting a
        state that did not verify. It does NOT bypass `check_preconditions()`'s
        hard conflict gates, which are what stop two DHCP servers running at once:
        that is the catastrophic, cheaply-detectable case this module exists to
        prevent, and convenience is not a reason to relax it.

        `_sleep` is injected so tests can exercise the retry cascade without
        actually waiting minutes. Production callers never pass it.
        """
        try:
            return self._switch_mode(new_mode, new_config, force, _sleep)
        except Exception as e:  # noqa: BLE001
            log.exception("dhcp/switch: unexpected failure")
            self._last_error = "switch_mode crashed: %s" % e
            self._trace("switch-crashed", to_mode=new_mode, ok=False, detail=str(e))
            return {"ok": False, "action": "error", "detail": str(e)}

    def _switch_mode(self, new_mode, new_config, force, _sleep):
        if new_mode not in MODES:
            return {"ok": False, "action": "rejected",
                    "detail": "unknown mode %r; expected one of %s"
                              % (new_mode, ", ".join(MODES))}

        self.ensure_install_baseline()
        from_mode = self.mode
        prev_state = self._capture_state()
        trigger = "operator-force" if force else "operator"
        self._trace("switch-requested", trigger=trigger, from_mode=from_mode,
                    to_mode=new_mode, detail="force=%s" % force)

        target_cfg = dict(new_config) if new_config is not None else dict(self._cfg)
        applied, detail = self._apply_state(new_mode, target_cfg)
        if not applied:
            self._trace("apply-failed", trigger=trigger, from_mode=from_mode,
                        to_mode=new_mode, ok=False, detail=detail)

        ok, readback, vdetail = self.verify_mode(new_mode)
        self._trace("verify", trigger=trigger, from_mode=from_mode,
                    to_mode=new_mode, ok=ok, readback=readback, detail=vdetail)

        if applied and ok:
            self._rotate_chain(self._capture_state())
            self._trace("switch-succeeded", trigger=trigger, from_mode=from_mode,
                        to_mode=new_mode, ok=True, readback=readback,
                        detail="snapshot chain rotated")
            self._last_error = None
            return {"ok": True, "action": "switched", "mode": new_mode,
                    "readback": readback, "detail": vdetail}

        # ---- verification failed ----
        _record(E_SWITCH_VERIFY_FAILED,
                context={"from": from_mode, "to": new_mode, "detail": vdetail,
                         "readback": readback}, conn=self._err_conn())

        if force:
            # Accepted deliberately by the operator. Recorded as its own code so
            # "a human chose this" is never confused with "the system gave up",
            # and the chain is NOT rotated — an unverified state must not become
            # a rollback target for some later failure.
            _record(E_OVERRIDE_USED,
                    context={"to": new_mode, "detail": vdetail}, conn=self._err_conn())
            self._last_error = ("mode %s did not verify (%s) — accepted via "
                                "operator override" % (new_mode, vdetail))
            self._trace("override-accepted", trigger=trigger, from_mode=from_mode,
                        to_mode=new_mode, ok=False, readback=readback,
                        detail="rollback SUPPRESSED by operator override; "
                               "snapshot chain deliberately NOT rotated")
            return {"ok": False, "action": "forced", "mode": new_mode,
                    "readback": readback, "detail": vdetail,
                    "rolled_back": False}

        return self._rollback_cascade(from_mode, new_mode, vdetail, prev_state, _sleep)

    def _rollback_cascade(self, from_mode, failed_mode, why, prev_state, _sleep):
        """Walk the tiers most-proven-recent first until one VERIFIES.

        Every tier is verified with the same readback a normal switch gets — a
        tier is only reported as the recovery point after it proves itself. That
        is the exact gap `nemesis_fw_watch.py` shipped (its "auto-restored" line
        fires outside its own readback check), and it is not repeated here.
        """
        attempts_log = []
        for tier in ROLLBACK_ORDER:
            snap = self._read_snapshot(tier)
            if snap is None:
                self._trace("rollback-skip", from_mode=from_mode, tier=tier,
                            detail="tier absent or unreadable — skipped, not "
                                   "attempted")
                continue
            if tier == TIER_BASELINE:
                _record(E_ROLLBACK_TO_BASELINE,
                        context={"failed_mode": failed_mode}, conn=self._err_conn())

            for attempt in range(1, ROLLBACK_ATTEMPTS_PER_TIER + 1):
                tmode = snap.get("mode", DEFAULT_MODE)
                applied, adetail = self._apply_state(tmode, snap.get("config") or {})
                ok, readback, vdetail = self.verify_mode(tmode)
                self._trace("rollback-attempt", from_mode=failed_mode,
                            to_mode=tmode, tier=tier, attempt=attempt, ok=ok,
                            readback=readback,
                            detail=vdetail if applied else adetail)
                if applied and ok:
                    self._last_error = (
                        "mode %s failed verification (%s); rolled back to %s "
                        "snapshot (%s)" % (failed_mode, why, tier, tmode))
                    self._trace("rollback-succeeded", from_mode=failed_mode,
                                to_mode=tmode, tier=tier, attempt=attempt,
                                ok=True, readback=readback,
                                detail="recovery point verified")
                    return {"ok": False, "action": "rolled_back",
                            "mode": tmode, "tier": tier, "attempt": attempt,
                            "detail": why, "rolled_back": True,
                            "attempts": attempts_log}
                attempts_log.append({"tier": tier, "attempt": attempt,
                                     "detail": vdetail if applied else adetail})
                _record(E_ROLLBACK_FAILED,
                        context={"tier": tier, "attempt": attempt,
                                 "detail": vdetail}, conn=self._err_conn())
                if attempt < ROLLBACK_ATTEMPTS_PER_TIER:
                    # A first failure may be transient rather than a real problem
                    # with the target state — hence a second attempt, spaced.
                    _sleep(ROLLBACK_RETRY_DELAY_SECONDS)

        # ---- every tier exhausted, including the permanent baseline ----
        #
        # Land in the safest MECHANICAL state this module can guarantee: its own
        # daemon stopped, so whatever else is wrong, Nemesis is definitely not
        # contributing a second DHCP server. Then stop — no infinite retry — and
        # say so loudly enough that it cannot read as a working system.
        subprocess.run(["systemctl", "stop", SERVICE_NAME],
                       capture_output=True, text=True, timeout=30)
        _record(E_BASELINE_FAILED,
                context={"failed_mode": failed_mode, "attempts": attempts_log},
                conn=self._err_conn())
        self._last_error = (
            "DHCP NEEDS ATTENTION — mode %s failed verification (%s) and EVERY "
            "rollback tier failed too, including the permanent install baseline. "
            "nemesis-dhcpd has been stopped. Nemesis is not serving DHCP."
            % (failed_mode, why))
        self._trace("escalated", from_mode=failed_mode, ok=False,
                    detail=self._last_error)
        return {"ok": False, "action": "escalated", "detail": self._last_error,
                "rolled_back": False, "attempts": attempts_log}

    def sync_leases(self, conn=None):
        """Read the lease file into `dhcp_leases`. Returns a summary.

        Upserts on MAC. `first_seen` is preserved across updates — it is the
        only record of when a device was first observed on the network, and
        overwriting it on every renewal would silently destroy that.

        Hostnames are stored EXACTLY as the client sent them. Normalisation
        belongs to whatever displays or classifies them; storing a cleaned-up
        value would discard what was actually observed, which is the thing worth
        keeping.

        Does nothing in modes where Nemesis serves no leases — there is no lease
        file to read, and inventing one would misreport the network.
        """
        if not mode_capabilities(self.mode)["serves_dhcp"]:
            return {"served": False, "seen": 0, "written": 0}

        own = conn is None
        if own:
            conn = _dm_conn()
        try:
            self.init_lease_table(conn)
            self.init_lease_event_table(conn)
            leases = self.read_leases()
            now = _now_iso()

            # Read the PRIOR snapshot before overwriting it — this is the only
            # moment the change is knowable. The upsert below destroys it.
            prior = {r[0]: {"ip": r[1], "hostname": r[2]}
                     for r in conn.execute(
                         "SELECT mac, ip, hostname FROM dhcp_leases")}

            written = 0
            events = []
            seen_macs = set()
            for lease in leases:
                mac = (lease.get("mac") or "").lower()
                if not mac:
                    continue
                seen_macs.add(mac)
                ip = lease.get("ip")
                hostname = lease.get("hostname")
                was = prior.get(mac)
                if was is None:
                    events.append(("new", mac, ip, None, hostname, None))
                else:
                    if was["ip"] != ip:
                        events.append(("ip_changed", mac, ip, was["ip"],
                                       hostname, was["hostname"]))
                    if was["hostname"] != hostname:
                        events.append(("hostname_changed", mac, ip, was["ip"],
                                       hostname, was["hostname"]))
                conn.execute(
                    "INSERT INTO dhcp_leases (mac, ip, hostname, expiry, "
                    "first_seen, last_seen) VALUES (?,?,?,?,?,?) "
                    "ON CONFLICT(mac) DO UPDATE SET "
                    "  ip=excluded.ip, hostname=excluded.hostname, "
                    "  expiry=excluded.expiry, last_seen=excluded.last_seen",
                    (mac, ip, hostname, lease.get("expiry"), now, now))
                written += 1

            # A MAC that was in the table and is no longer in the lease file has
            # had its lease expire or be released. The row is deliberately LEFT
            # in `dhcp_leases` — it is the inventory's record that the device was
            # seen — so the event log is the only place this becomes visible.
            for mac in set(prior) - seen_macs:
                events.append(("gone", mac, None, prior[mac]["ip"],
                               None, prior[mac]["hostname"]))

            for ev, mac, ip, prev_ip, hostname, prev_hostname in events:
                conn.execute(
                    "INSERT INTO dhcp_lease_events "
                    "(ts,event,mac,ip,prev_ip,hostname,prev_hostname,expiry) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (now, ev, mac, ip, prev_ip, hostname, prev_hostname,
                     next((l.get("expiry") for l in leases
                           if (l.get("mac") or "").lower() == mac), None)))
            if events:
                log.info("dhcp: lease events: %s",
                         ", ".join("%s %s" % (e[0], e[1]) for e in events))
            conn.commit()
            return {"served": True, "seen": len(leases), "written": written,
                    "events": len(events)}
        finally:
            if own:
                conn.close()

    def read_leases(self):
        """Parse the lease file. Absent file is an empty list, not an error.

        Format is dnsmasq's documented `<expiry> <mac> <ip> <hostname> <clientid>`
        with `*` for absent fields. NOT verified against a live lease on this
        box — no lease file has ever been populated here — so treat a parse
        surprise as the format, not the data.
        """
        out = []
        try:
            with open(LEASE_PATH) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    hostname = parts[3]
                    out.append({
                        "expiry": parts[0],
                        "mac": parts[1],
                        "ip": parts[2],
                        "hostname": None if hostname == "*" else hostname,
                    })
        except FileNotFoundError:
            return []
        except Exception as e:  # noqa: BLE001
            log.exception("dhcp: lease file unreadable: %s", e)
            return []
        return out

    # -- dashboard ---------------------------------------------------------

    #: (dot, colour, label) per health state. `crash_looping` and `unverified`
    #: are RED, not grey: the old card had two visual states, so a daemon that
    #: was failing rendered identically to one deliberately turned off. "Broken"
    #: and "off" must not look the same at a glance — that similarity is what let
    #: the first live run's crash loop sit unnoticed on the dashboard.
    _CARD_STYLE = {
        HEALTH_SERVING:    ("🟢", "#00ff88", "Serving"),
        HEALTH_CRASH_LOOP: ("🔴", "#ff4444", "Crash-looping"),
        HEALTH_UNVERIFIED: ("🔴", "#ff8800", "Not confirmed serving"),
        HEALTH_DOWN:       ("⚫", "#888",    "Stopped"),
        HEALTH_UNKNOWN:    ("⚠️", "#ffcc00", "Unknown"),
        "not_serving":     ("⚫", "#888",    "Inactive"),
    }

    def get_dashboard_card(self) -> str:
        s = self.status()
        dot, colour, label = self._CARD_STYLE.get(
            s["state"], ("⚠️", "#ffcc00", "Unknown"))
        ifaces = ", ".join(s["interfaces"]) or "none configured"
        return (
            '<div class="card">'
            '<h2>📡 DHCP Server</h2>'
            '<p style="margin:4px 0">%s <span style="color:%s">%s</span></p>'
            '<p style="color:#888;font-size:0.82em;margin:4px 0">%s</p>'
            '<p style="color:#888;font-size:0.78em;margin:4px 0">Interfaces: %s</p>'
            '</div>' % (dot, colour, label, s["detail"], ifaces)
        )

    def get_routes(self):
        return None
