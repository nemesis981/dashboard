#!/usr/bin/env python3
"""Who is connecting to the appliance's local ports, and is that a device we know?

⚠ THIS IS VISIBILITY, NOT ACCESS CONTROL. READ THIS BEFORE RELYING ON IT.
------------------------------------------------------------------------
Nothing here blocks anything, and nothing here may ever become the thing that
does. The access-control mechanism for the plain-HTTP port is an
INTERFACE-SCOPED PACKET FILTER (`iptables -t raw -i tailscale0 ... -j DROP`),
which cannot be bypassed by anything this module gets wrong.

The reason that separation is load-bearing rather than tidy: **the device
inventory is incomplete and stale by nature.** It is populated by network
scanning and by agent enrolment, so a brand-new laptop, a phone that just joined
the wifi, or a device whose DHCP lease moved are all "unknown" while being
entirely legitimate. A gate built on that would deny real users and would be
switched off within a week -- at which point it protects nothing while still
appearing in the architecture.

So: an unknown source is reported, and a human decides. That is a genuinely
useful signal precisely because Nemesis already knows what is on this network,
and it is the kind of thing this product exists to surface.

WHAT IT WATCHES. Established inbound connections to the appliance's own service
ports. Loopback is excluded -- the dashboard binds loopback and nginx proxies to
it, so every request would otherwise self-report as an unknown connection from
127.0.0.1 and bury the real signal.
"""

import ipaddress
import logging
import os
import time

log = logging.getLogger("nemesis.local_port_watch")

__all__ = ["WATCHED_PORTS", "known_addresses", "current_connections",
           "classify", "scan", "LocalPortWatchError"]

#: Ports whose inbound connections are worth attributing. The dashboard's own
#: loopback port is deliberately ABSENT: nginx proxies to it on every single
#: request, so including it would report the appliance connecting to itself
#: thousands of times a day and drown the signal this exists to produce.
WATCHED_PORTS = frozenset(
    int(p) for p in os.environ.get("NEMESIS_WATCHED_PORTS", "80,443").split(",")
    if p.strip().isdigit())

#: How long an unknown source stays suppressed after being reported once. A device
#: that keeps a connection open, or reconnects in a loop, is ONE finding -- not one
#: per sample. Without this the first misconfigured device would generate a finding
#: every scan interval until someone turned the whole feature off.
REPEAT_SUPPRESS_S = int(os.environ.get("NEMESIS_LPW_SUPPRESS_S", "3600"))

_last_reported = {}


class LocalPortWatchError(RuntimeError):
    """A scan could not be performed. Raised rather than returning an empty
    result: "no unknown connections" and "I could not look" must never be the
    same answer, because the first is reassuring and the second is not."""


def known_addresses(conn):
    """Every IP this appliance already knows about, from BOTH inventories.

    `devices` is network-scan discovery; `agent_devices` is enrolled agents. They
    overlap but neither contains the other -- an enrolled agent on a subnet the
    scanner does not reach appears only in the second, and an unmanaged printer
    only in the first. Checking one would report the other's devices as unknown.
    """
    known = set()
    for table, column in (("devices", "ip"), ("agent_devices", "ip_address")):
        try:
            rows = conn.execute(
                "SELECT %s FROM %s WHERE %s IS NOT NULL AND %s != ''"
                % (column, table, column, column)).fetchall()
        except Exception as exc:                                   # noqa: BLE001
            # One missing table must not silently shrink the known set -- that
            # would turn every device in it into a false "unknown". Loud, and
            # the caller decides.
            raise LocalPortWatchError(
                "could not read %s.%s: %s" % (table, column, exc)) from exc
        for (value,) in rows:
            for part in str(value).replace(";", ",").split(","):
                part = part.strip()
                if not part:
                    continue
                try:
                    known.add(str(ipaddress.ip_address(part)))
                except ValueError:
                    continue
    return known


def current_connections(_probe=None):
    """(remote_ip, local_port) for established inbound connections we watch.

    `_probe` is for tests only.
    """
    if _probe is not None:
        conns = _probe
    else:
        try:
            import psutil                                          # noqa: PLC0415
        except ImportError as exc:
            raise LocalPortWatchError("psutil unavailable: %s" % exc) from exc
        try:
            conns = [
                (c.raddr.ip if c.raddr else None,
                 c.laddr.port if c.laddr else None,
                 c.status)
                for c in psutil.net_connections(kind="inet")
            ]
        except Exception as exc:                                   # noqa: BLE001
            # Typically permissions: net_connections needs privilege for sockets
            # owned by other users. Raising means a half-visible scan is never
            # mistaken for a clean one.
            raise LocalPortWatchError(
                "could not enumerate connections (privilege?): %s" % exc) from exc

    out = []
    for raddr, lport, status in conns:
        if not raddr or lport not in WATCHED_PORTS:
            continue
        if status != "ESTABLISHED":
            continue
        try:
            ip = ipaddress.ip_address(raddr)
        except ValueError:
            continue
        if ip.is_loopback:
            continue          # nginx -> dashboard, on every request
        out.append((str(ip), lport))
    return out


def classify(remote_ip, known):
    """'known' | 'unknown'. No third state, and no guessing.

    A private/LAN address that is not in the inventory is still UNKNOWN. Treating
    "it is on my subnet" as "it is mine" is precisely the assumption an intruder
    on the LAN benefits from, and it is the assumption this check exists to stop
    anyone making silently.
    """
    return "known" if str(remote_ip) in known else "unknown"


def scan(conn, now=None, _probe=None, suppress=True):
    """Report unknown sources connected to watched ports. Never raises on 'none'.

    Returns a dict with `checked`, `known`, `unknown` (a list of findings) and
    `suppressed`. `unknown == []` means the scan ran and found nothing; a scan
    that could not run RAISES, so the two are distinguishable by the caller.
    """
    now = float(now if now is not None else time.time())
    known = known_addresses(conn)
    conns = current_connections(_probe=_probe)

    findings, n_known, n_suppressed = [], 0, 0
    for ip, port in conns:
        if classify(ip, known) == "known":
            n_known += 1
            continue
        last = _last_reported.get(ip)
        if suppress and last is not None and (now - last) < REPEAT_SUPPRESS_S:
            n_suppressed += 1
            continue
        _last_reported[ip] = now
        findings.append({
            "ip": ip,
            "port": port,
            "first_seen": now,
            # Stated in the finding itself, so an operator reading it in a ticket
            # a month later is not left to infer how much it proves.
            "detail": ("connection to local port %d from %s, which is in neither "
                       "the scanned-device nor the enrolled-agent inventory. This "
                       "is a VISIBILITY signal, not a block: the inventory is "
                       "incomplete by nature, so an unknown source is frequently "
                       "a legitimate new device." % (port, ip)),
        })
        log.warning("local-port watch: unknown source %s -> port %d", ip, port)
    return {"checked": len(conns), "known": n_known,
            "unknown": findings, "suppressed": n_suppressed}


def reset_suppression():
    """Clear the repeat-suppression memory (tests, and after a config change)."""
    _last_reported.clear()
