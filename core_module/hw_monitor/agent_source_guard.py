"""Source-address admission control for the :5001 agent channel.

Added 2026-08-16 to close GAP 3 of the licensing/security readiness audit.

── Why this exists ───────────────────────────────────────────────────────────
Before this module, :5001 bound 0.0.0.0 and the ONLY thing deciding who could
reach it was ufw. That is one mechanism, held in a configuration file that the
installer rewrites, the enforcement engine rewrites, and operators edit by hand.
One `ufw disable`, one botched `ufw reset`, one move to a network whose subnet
does not match what the installer detected, and the agent enrollment/heartbeat
port is world-reachable with nothing behind it.

The requirement being enforced is: **the server accepts local traffic and VPN
traffic, and nothing else.** ufw expresses that today; this makes the
application express it too, so the guarantee survives the firewall being wrong.

This is defence-in-depth, NOT a firewall replacement. It cannot stop a packet
arriving; it stops the packet being answered.

── What it does NOT protect against ──────────────────────────────────────────
A router that source-NATs forwarded traffic presents its own LAN address as the
source, so WAN-originated traffic lands inside the LAN allow and is accepted
here exactly as it is accepted by ufw. That residual gap is real, is documented
as GAP 4 of the same audit, and is a *detection* problem rather than an
enforcement one — the packets are genuinely indistinguishable at this layer.
Nothing in this module should be read as closing it.

── The allowlist ─────────────────────────────────────────────────────────────
Always present, never derived:
    127.0.0.0/8, ::1        loopback — the box talking to itself
    100.64.0.0/10           Tailscale CGNAT (the VPN path, IPv4)
    fd7a:115c:a1e0::/48     Tailscale ULA (the VPN path, IPv6)

The IPv6 tailnet range is included deliberately. install.sh's tailnet anti-spoof
guard writes a rule for it precisely because omitting it would leave the v6 path
unprotected while v4 was covered; the same asymmetry would apply here.

Plus, unless NEMESIS_5001_ALLOW is set explicitly, every directly-connected IPv4
network this host holds — a real measurement of what LANs the box is attached
to, not a guess at what they might be. tailscale0 and /32 host routes are
excluded: the tunnel's reachability is the CGNAT entry above, and a /32
describes one address rather than a network anything can be reached from.

── Failure behaviour ─────────────────────────────────────────────────────────
If interface enumeration fails, the LAN entries are simply absent. The guard
then permits loopback and VPN only, and says so at ERROR. That is deliberate:
an unreadable answer must not render as a permissive one. The cost is bounded
and visible — tailnet agents keep working, LAN agents start failing loudly, and
the journal names the cause — rather than silent, unbounded exposure.

── Proving its own premise ───────────────────────────────────────────────────
Per the standing practice, a check that can only ever return one answer is not a
check. `_self_test()` runs on every construction (production path, not just
tests) with addresses that MUST be permitted and addresses that MUST be refused.
If the matcher cannot produce both answers, construction raises rather than
vouching for anything real. See scripts/nemesis-fw-neverblock's CANARIES for the
pattern this follows.
"""

import ipaddress
import os
import socket

__all__ = ["SourceGuard", "from_env", "local_ipv4_networks", "GuardError"]


class GuardError(RuntimeError):
    """The guard could not establish that it works. Never swallow this."""


#: Permitted regardless of what the host's interfaces look like.
BASE_ALLOW = (
    "127.0.0.0/8",
    "::1/128",
    "100.64.0.0/10",
    "fd7a:115c:a1e0::/48",
)

#: MUST be permitted by any correctly-built guard.
_CANARY_ALLOW = ("127.0.0.1", "100.64.0.1", "100.127.255.254")

#: MUST be refused. 192.88.99.x is IANA-reserved/deprecated, so it routes
#: nowhere, but Python classifies it as public — which is what makes it usable
#: here, where TEST-NET (RFC 5737) would not be: `ipaddress` reports all three
#: TEST-NET blocks as is_private, so they are the wrong tool for exercising any
#: public/private branch. Same convention as alert_manager/test_quarantine.py.
_CANARY_DENY = ("192.88.99.1", "8.8.8.8", "203.0.113.7")


def _parse_addr(raw):
    """ip_address for a client address, or None if it is not one.

    Handles the IPv4-mapped form (``::ffff:172.20.0.5``) that a dual-stack
    socket can present, so a LAN address does not read as an unknown v6 address
    and get refused. Also strips a zone index (``fe80::1%eth0``), which
    ip_address rejects outright.
    """
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    s = s.split("%")[0]
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


def local_ipv4_networks():
    """Directly-connected IPv4 networks, as a list of ip_network.

    Raises GuardError if the interface table cannot be read. The caller decides
    what to do about that — but it is never handed back an empty list that is
    indistinguishable from "this host has no networks", because those two facts
    call for different responses and one of them is an alarm.
    """
    try:
        import psutil
    except Exception as e:  # pragma: no cover - psutil is a hard hw_monitor dep
        raise GuardError("psutil unavailable: %s" % e)

    try:
        table = psutil.net_if_addrs()
    except Exception as e:
        raise GuardError("could not read interface addresses: %s" % e)

    nets = []
    for iface, addrs in table.items():
        if iface == "lo" or iface.startswith("tailscale"):
            continue
        for a in addrs:
            if a.family != socket.AF_INET:
                continue
            if not a.address or not a.netmask:
                continue
            try:
                net = ipaddress.ip_interface(
                    "%s/%s" % (a.address, a.netmask)).network
            except ValueError:
                continue
            if net.prefixlen == 32:
                continue
            # 169.254.0.0/16 is never a configured LAN — it is what an interface
            # gives itself when DHCP fails. Found live on the dev box: an
            # unconfigured second NIC had self-assigned one, which would have
            # put the whole link-local /16 in the allowlist. Any host on that
            # segment can claim an address in it without asking anything, so
            # admitting it would be admitting an unauthenticated range.
            # (install.sh's shell equivalent gets this for free by filtering on
            # `scope global`; psutil carries no scope, so it is explicit here.)
            if net.is_link_local:
                continue
            if net not in nets:
                nets.append(net)
    return nets


class SourceGuard:
    """Decides whether a client address may be served on :5001."""

    __slots__ = ("networks", "lan_enumeration_error", "stats")

    def __init__(self, networks, lan_enumeration_error=None):
        parsed = []
        for n in networks:
            net = (n if isinstance(n, (ipaddress.IPv4Network, ipaddress.IPv6Network))
                   else ipaddress.ip_network(str(n), strict=False))
            if net not in parsed:
                parsed.append(net)
        if not parsed:
            raise GuardError("refusing to build a guard with an empty allowlist")
        self.networks = tuple(parsed)
        self.lan_enumeration_error = lan_enumeration_error
        self.stats = {"allowed": 0, "denied": 0, "unparseable": 0}
        self._self_test()

    # ── the premise check ────────────────────────────────────────────────────
    def _self_test(self):
        """Prove this instance can return BOTH answers before it is trusted.

        A guard whose allowlist accidentally matched everything would permit
        every request and look perfectly healthy doing it. The only way to know
        the difference is to hand it something that must be refused and check
        that it refuses.
        """
        for addr in _CANARY_ALLOW:
            if not self._match(_parse_addr(addr)):
                raise GuardError(
                    "self-test FAILED: %s must be permitted but was refused "
                    "(allowlist=%s)" % (addr, [str(n) for n in self.networks]))

        # A deny canary that happens to sit inside a real local network is not a
        # guard failure — it is an unusable canary. Skip it and say so, but
        # require that at least one survives, or nothing has been proven.
        usable = 0
        for addr in _CANARY_DENY:
            ip = _parse_addr(addr)
            if any(ip in n for n in self.networks):
                continue
            usable += 1
            if self._match(ip):
                raise GuardError(
                    "self-test FAILED: %s must be refused but was permitted "
                    "(allowlist=%s)" % (addr, [str(n) for n in self.networks]))
        if usable == 0:
            raise GuardError(
                "self-test INCONCLUSIVE: every deny canary falls inside the "
                "allowlist, so the guard was never shown to refuse anything "
                "(allowlist=%s)" % [str(n) for n in self.networks])

    def _match(self, ip):
        if ip is None:
            return False
        for net in self.networks:
            if ip.version == net.version and ip in net:
                return True
        return False

    # ── public API ───────────────────────────────────────────────────────────
    def allows(self, raw_addr):
        """True if `raw_addr` may be served. Unparseable is refused, not ignored."""
        ip = _parse_addr(raw_addr)
        if ip is None:
            self.stats["unparseable"] += 1
            return False
        if self._match(ip):
            self.stats["allowed"] += 1
            return True
        self.stats["denied"] += 1
        return False

    def describe(self):
        return ", ".join(str(n) for n in self.networks)

    def snapshot(self):
        return dict(self.stats, networks=[str(n) for n in self.networks])


def from_env(prefix="NEMESIS_5001"):
    """Build a guard from the environment, or None if explicitly disabled.

    NEMESIS_5001_SOURCE_GUARD  1/0  master switch                    (default 1)
    NEMESIS_5001_ALLOW         csv  REPLACES the auto-detected LAN networks.
                                    The base loopback/tailnet entries are always
                                    added on top, so setting this cannot lock the
                                    box out of its own agent channel.

    Returns (guard, note) where note is a human-readable string for the caller
    to log — including the enumeration failure, if there was one, so the reason
    the LAN is absent reaches the journal instead of dying in here.
    """
    if os.environ.get("%s_SOURCE_GUARD" % prefix, "1").strip() not in ("1", "true", "yes"):
        return None, "disabled by %s_SOURCE_GUARD" % prefix

    nets = [ipaddress.ip_network(n) for n in BASE_ALLOW]
    note = ""

    configured = os.environ.get("%s_ALLOW" % prefix, "").strip()
    if configured:
        bad = []
        for raw in (p.strip() for p in configured.split(",")):
            if not raw:
                continue
            try:
                nets.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                bad.append(raw)
        if bad:
            # Loud, and NOT fatal-by-silence: the entries that parsed are still
            # applied, but an operator who fat-fingered a CIDR must not have to
            # infer it from agents mysteriously failing.
            raise GuardError(
                "%s_ALLOW contains unparseable networks: %s" % (prefix, bad))
        note = "allowlist from %s_ALLOW" % prefix
    else:
        try:
            lan = local_ipv4_networks()
            nets.extend(lan)
            note = ("auto-detected %d local network(s)" % len(lan)) if lan else \
                   "auto-detection found NO local networks — LAN agents will be refused"
        except GuardError as e:
            return SourceGuard(nets, lan_enumeration_error=str(e)), (
                "LAN ENUMERATION FAILED (%s) — permitting loopback and VPN only; "
                "LAN agents will be refused until this is fixed or "
                "%s_ALLOW is set" % (e, prefix))

    return SourceGuard(nets), note
