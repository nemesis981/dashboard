"""Appliance self-identity — the ONE answer to "is this address/MAC us?".

Consolidates three drifting runtime copies of the same enumeration:
  * firewall._local_addresses()            -- IPs, for the never-block guard
  * lan_behavior_monitor._refresh_local_identity() -- IPs + MACs, self-exclusion
  * post_detection._pde_refresh_local_ips()        -- IPs, self-exclusion

Two of today's false positives (lan_behavior flagging the appliance's own scanner,
post_detection correlating the appliance with itself) came from these being separate
and incomplete. One definition removes that drift.

⛔ NOT CACHED, DELIBERATELY. firewall.py recomputes per call on purpose: interfaces
come and go (tailnet up/down, DHCP renewal) and a stale set could MISS a current
address -- for the firewall path that means blocking the host's OWN new address, the
exact catastrophe the never-block guard exists to prevent. Measured cost is ~0.47ms
per call, ~1.35ms/day aggregate across all consumers, so there is nothing worth
trading that freshness for. This consolidation is for CORRECTNESS (one definition, no
drift) and maintenance, NOT speed -- and a cache would silently contradict firewall's
own reasoning.

Best-effort, EMPTY-on-failure (logged, never raised). Consumers that need
keep-previous-on-failure (the self-exclusion callers) layer that themselves: they
update their cached set only when the return is non-empty. This preserves BOTH failure
policies -- firewall wants the empty (fall back to loopback + NEMESIS_NEVER_BLOCK),
the self-exclusion callers keep their last-good set.

The Suricata @NEMESIS_HOST@ exclusion is intentionally NOT a consumer: it is resolved
at rule-DEPLOY time (deploy-suricata-rules.sh) and baked literally into the rules file,
because Suricata cannot call a Python function at match time. Different layer.

Three OTHER `net_if_addrs()` call sites exist and are deliberately NOT consumers here —
checked individually (2026-09-02 duplication sweep), not overlooked:
  * hw_monitor.agent_source_guard -- RAISES on failure, by design. Folding it into
    this module's empty-on-failure contract would silently weaken a fail-loud guard.
  * remote_census._own_tailnet_addresses() -- answers a narrower question
    (tailnet interfaces only), not "every local address".
  * nemesis_agent/agent.py -- runs ON THE MONITORED DEVICE, a different machine and
    package boundary; it cannot import this (server-side-only) module.
If you're about to add a fourth "is this us" copy, check whether it is actually one of
these three shapes before assuming it belongs here too.
"""
import logging
import socket

log = logging.getLogger("nemesis.net_identity")

_ALL_ZERO_MAC = "00:00:00:00:00:00"


def local_identity():
    """(ips, macs) for this host, enumerated in ONE pass. Empty sets on failure.

    ips  : every v4+v6 address, zone id (%iface) stripped, empties excluded.
    macs : every interface MAC, lowercased, all-zero and empty excluded.
    """
    ips, macs = set(), set()
    try:
        import psutil
        af_packet = getattr(socket, "AF_PACKET", None)   # Linux
        af_link = getattr(psutil, "AF_LINK", None)        # BSD/macOS
        for _iface, snics in psutil.net_if_addrs().items():
            for snic in snics:
                fam = snic.family
                if fam in (socket.AF_INET, socket.AF_INET6):
                    addr = (snic.address or "").split("%")[0]   # strip zone id
                    if addr:
                        ips.add(addr)
                elif (af_packet is not None and fam == af_packet) or \
                     (af_link is not None and fam == af_link):
                    mac = (snic.address or "").strip().lower()
                    if mac and mac != _ALL_ZERO_MAC:
                        macs.add(mac)
    except Exception as exc:  # noqa: BLE001
        log.warning("net_identity: could not enumerate local identity (%s) -- returning "
                    "empty; callers fall back per their own policy", exc)
    return ips, macs


def local_ip_addresses():
    """Every IP (v4+v6, zone-stripped) configured on this host. Empty on failure.

    Behaviour-identical to firewall._local_addresses() historically, so it is a
    drop-in for that and its consumers (ip_enrichment)."""
    return local_identity()[0]


def local_macs():
    """Every interface MAC (lowercased, all-zero/empty excluded). Empty on failure."""
    return local_identity()[1]
