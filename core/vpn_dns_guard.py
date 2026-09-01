#!/usr/bin/env python3
"""
VPN-Aware Upstream DNS Guard  (core service — see docs/architecture/0002)

Problem it solves
-----------------
Nemesis runs Pi-hole as its DNS core. Security-conscious users run a VPN with a
killswitch (PIA, Mullvad, Proton, Nord ...). A killswitch blocks every egress that
is not the tunnel — which includes Pi-hole's UPSTREAM forwarding to a public
resolver (1.1.1.1). Result: Pi-hole keeps answering LAN clients (job 1) but can no
longer resolve cache-misses upstream (job 2). FTL logs
`failed to send UDP request (Operation not permitted)`.

What this guard does
--------------------
Watches THIS host for a tunnel coming up / going down and keeps Pi-hole's UPSTREAM
DNS reachable through whatever egress is currently allowed:

  * tunnel up   -> point Pi-hole upstreams at a DNS server that is reachable
                   THROUGH the tunnel (so the killswitch permits it), verify it
                   actually resolves, and roll back if it does not.
  * tunnel down -> restore the exact upstreams that were in place before.
  * cold start  -> reconcile: if we boot with the tunnel already up, apply; if we
                   boot with a stale "applied" state but no tunnel, restore.

Hard constraints (do not violate)
---------------------------------
  * Touch ONLY Nemesis's own Pi-hole config, and ONLY `dns.upstreams`.
    Never touch the user's VPN or killswitch rules — a security tool must not
    weaken the user's own security control.
  * NEVER change Pi-hole's listening/answering posture (`dns.interface`,
    `dns.listeningMode`). Upstream egress and listening restriction are controlled
    independently; we only move the upstream.

Placement
---------
Core service, not a module: DNS uptime must not sit behind a module toggle. It
reuses the `modules/dhcp` Pi-hole v6 API *pattern* (session auth + /api/config),
not the module itself.

CLI (for the live-test harness and manual ops)
----------------------------------------------
  vpn_dns_guard.py              run the daemon loop (systemd ExecStart)
  vpn_dns_guard.py --detect     print tunnel-detection JSON and exit
  vpn_dns_guard.py --status     print guard + Pi-hole upstream state and exit
  vpn_dns_guard.py --once       run a single reconcile cycle and exit
  vpn_dns_guard.py --apply      force-apply the fix now (assume tunnel up), verify
  vpn_dns_guard.py --restore    force-restore the saved upstreams now
"""

import json
import logging
import os
import shutil
import socket
import struct
import subprocess
import sys
import time

import requests

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)

PIHOLE_IP = os.environ.get("PIHOLE_IP", "127.0.0.1:8080")
PIHOLE_PASSWORD = os.environ.get("PIHOLE_PASSWORD", "")

# $LOGS_DIRECTORY (set by the unit) before the in-tree default: /opt is
# read-only under ProtectSystem=strict.
LOG_PATH = os.environ.get("VPN_DNS_GUARD_LOG") or os.path.join(
    os.environ.get("LOGS_DIRECTORY", _HERE), "vpn_dns_guard.log")
# State persists across restarts so we can restore the pre-VPN upstreams even if
# the service (or the whole box) was restarted while the tunnel was up.
# STATE LIVES IN THE DATA DIRECTORY, NOT THE REPO TREE.
#
# It defaulted to <repo>/alert_manager/vpn_dns_guard.state.json, which this unit
# CANNOT WRITE: it runs ProtectSystem=strict with ReadWritePaths=/var/lib/nemesis,
# so /opt is read-only to it. Every save raised
# `OSError: [Errno 30] Read-only file system` and _save_state swallowed it.
#
# Measured before the fix: 5,655 apply cycles since 2026-07-29, 5,655 persist
# failures — a 100% failure rate over four days, while the log line immediately
# after each one read "fix applied". The on-disk state stayed
# {"applied": false, "saved_upstreams": null} with an mtime from 2026-07-06.
#
# THE CONSEQUENCE WAS NOT COSMETIC. restore() returns early unless
# state["applied"] is true, so with the flag permanently false the
# tunnel-down path was a no-op: on VPN disconnect Pi-hole would keep upstreams
# that are only reachable THROUGH the tunnel, breaking DNS for every client it
# serves, with no saved value to roll back to. It also meant the guard re-applied
# every 20s forever, never recording that it had already succeeded.
#
# Same defect class as the YARA rules directory fixed earlier the same day: a
# writer aimed at the read-only tree, working in a developer checkout and failing
# on every real install.
_LEGACY_STATE_PATH = os.path.join(_ROOT, "alert_manager", "vpn_dns_guard.state.json")
STATE_PATH = os.environ.get(
    "VPN_DNS_GUARD_STATE",
    os.path.join("/var/lib/nemesis", "vpn_dns_guard.state.json"),
)

CHECK_INTERVAL_SECONDS = int(os.environ.get("VPN_DNS_GUARD_INTERVAL", "20"))
# A tunnel must be up AND carrying the default route for this long before we act,
# to debounce the flapping that happens during connect/reconnect.
DEBOUNCE_SECONDS = int(os.environ.get("VPN_DNS_GUARD_DEBOUNCE", "8"))

# Kernel interface kinds we treat as "a tunnel". Matched by TYPE/driver, never by
# name pattern (vendor WireGuard builds use arbitrary device names).
TUNNEL_KINDS = {"tun", "tap", "wireguard", "vti", "vti6", "ppp", "gre", "ip6tnl"}

# Names we will probe to confirm upstream resolution actually works. Random label
# under a real zone -> forces an UPSTREAM lookup (never a cache hit). NXDOMAIN is a
# PASS (the upstream answered); SERVFAIL/REFUSED/timeout is a FAIL.
VERIFY_ZONES = ("cloudflare.com", "google.com", "wikipedia.org")

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("vpn_dns_guard")


# --------------------------------------------------------------------------- #
# E-FORKB-* error codes
# --------------------------------------------------------------------------- #
#
# Recorded HERE rather than in forkb_policy_route.py, which is PURE: it returns
# its outcomes as result dicts and must stay free of I/O. Same division applied
# to gateway_mode.py, conn_consent.py and the email-security pure modules.
#
# ⛔ NOT RECORDED WHEN RUNNING AS ROOT, and that is not caution for its own
# sake. This file is BOTH a long-lived daemon (User=nemesis-vpndns, which is in
# the nemesis-db group and may write alerts.db) AND a CLI that install.sh
# invokes as root (`--egress-iface`). A root process writing alerts.db creates
# ROOT-OWNED WAL siblings that lock nemesis-dash out of its own database --
# the exact hazard drift_watch.py's header documents and works around. So the
# daemon records and the root CLI logs instead, which is the honest split
# rather than a silent one.

E_MASQ_KIND_UNDETERMINED = "E-FORKB-001"
E_COMMAND_UNRUNNABLE     = "E-FORKB-002"
E_RECONCILE_REFUSED      = "E-FORKB-003"
E_RECONCILE_FAILED       = "E-FORKB-004"
E_RECONCILE_CYCLE_ERROR  = "E-FORKB-005"
E_MAGICDNS_CONFLICT      = "E-FORKB-006"
E_MAGICDNS_UNDETERMINED  = "E-FORKB-007"

#: Fork B is not doing what it was asked to do.
_CLASS_FORKB_DEGRADED = "forkb-routing-degraded"

_ERR_CODES = {
    E_MASQ_KIND_UNDETERMINED: (
        "Masquerade egress refused: an interface's link kind could not be "
        "determined, and an undetermined kind reads as 'physical' to the "
        "classifier. Refusing rather than risk NATing tailnet traffic outside "
        "the VPN", "HIGH", _CLASS_FORKB_DEGRADED),
    E_COMMAND_UNRUNNABLE: (
        "A required command could not be RUN (missing binary, timeout or "
        "permission); every routing decision downstream of it is degraded",
        "MEDIUM", _CLASS_FORKB_DEGRADED),
    E_RECONCILE_REFUSED: (
        "Reconcile REFUSED to touch routing (self-test failed, or the bypass "
        "table is not ours). Correct behaviour, recorded because a persistent "
        "refusal means Fork B is not working", "HIGH", _CLASS_FORKB_DEGRADED),
    E_RECONCILE_FAILED: (
        "Reconcile ran and did not achieve the intended routing state "
        "(teardown did not take, or the rule installed but is not winning)",
        "HIGH", _CLASS_FORKB_DEGRADED),
    E_RECONCILE_CYCLE_ERROR: (
        "The reconcile cycle raised; Fork B routing was not evaluated this "
        "interval", "HIGH", _CLASS_FORKB_DEGRADED),
    E_MAGICDNS_CONFLICT: (
        "Tailscale's resolver is the ONLY resolver in resolv.conf and does not "
        "answer, while the fallback resolver does -- DNS is fully broken for "
        "this host. Detected but NOT yet mitigated: the actuator needs a "
        "privileged op (see ADR 0002 amendment)", "HIGH", _CLASS_FORKB_DEGRADED),
    E_MAGICDNS_UNDETERMINED: (
        "The MagicDNS conflict probe could not determine the state (resolv.conf "
        "unreadable, or a resolver could not be probed). Failing closed: no "
        "action taken", "MEDIUM", _CLASS_FORKB_DEGRADED),
}

_recorder = None


def _record(code, context=None):
    """Record one occurrence. NEVER raises, and NEVER writes as root.

    See the block comment above for why the root path logs instead: it is the
    install-time CLI, and a root write here would leave root-owned WAL files
    that lock the dashboard out of alerts.db.
    """
    global _recorder
    try:
        if os.geteuid() == 0:
            log.warning("[%s] %s | NOT RECORDED (running as root; a root write "
                        "to alerts.db would leave root-owned WAL siblings)",
                        code, context)
            return None
        if _recorder is None:
            import sqlite3 as _sqlite3                        # noqa: PLC0415
            sys.path.insert(0, os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "alert_manager"))
            import nemesis_errors                             # noqa: PLC0415
            import nemesis_paths                              # noqa: PLC0415
            _recorder = nemesis_errors.make_recorder(
                "vpn_dns_guard",
                lambda: _sqlite3.connect(nemesis_paths.db_path(), timeout=5.0),
                _ERR_CODES, logger=log)
        return _recorder(code, context=context)
    except Exception:                                          # noqa: BLE001
        log.warning("vpn_dns_guard: could not record %s", code, exc_info=True)
        return None


# --------------------------------------------------------------------------- #
# Small shell helpers
# --------------------------------------------------------------------------- #

def _run(cmd, timeout=6):
    """Run a command, return (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:  # noqa: BLE001
        # Logged, because until 2026-08-31 this was silent: a missing `ip`
        # binary, a timeout or a permission failure all became a bare rc=1 that
        # callers could not tell from "the command ran and said no".
        log.warning("vpn_dns_guard: %s could not run: %s",
                    cmd[0] if cmd else "?", e)
        _record(E_COMMAND_UNRUNNABLE,
                {"cmd": cmd[0] if cmd else "?",
                 "error": "%s: %s" % (type(e).__name__, e)})
        return 1, "", str(e)


def _run_json(cmd, timeout=6):
    rc, out, _ = _run(cmd, timeout=timeout)
    if rc != 0 or not out.strip():
        return None
    try:
        return json.loads(out)
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- #
# Tunnel detection — by interface TYPE carrying the default route
# --------------------------------------------------------------------------- #

def _iface_kind_ex(iface):
    """(kind, determined). `determined` is False when the kind is UNKNOWN.

    ⛔ THE DISTINCTION THIS FUNCTION EXISTS TO MAKE, and the security bug it
    fixes. `_iface_kind` returns '' for BOTH "the kernel says this is a plain
    physical NIC" and "the lookup failed" -- and `classify_by_resolution`'s
    contract states that '' or missing means PHYSICAL, not unknown (correctly:
    a normal ethernet NIC genuinely has no linkinfo.info_kind).

    So ANY failure of `ip -d -j link show` -- a missing binary, a timeout, a
    permission error, an iproute2 build change -- classified the interface as
    physical-not-tunnel. That is the permissive direction: it is what lets
    `masquerade_egress_iface()` hand back an interface it should have refused,
    and NAT forwarded tailnet traffic outside the user's VPN. Same consequence
    as the /1-straddle bug fixed in 707bf2f, arriving by a different route and
    producing no output at all.

    The sysfs fallback below is definitive for tun/tap but says NOTHING about
    WireGuard, so it does not close the gap on its own.
    """
    data = _run_json(["ip", "-d", "-j", "link", "show", iface])
    if data:
        try:
            info = data[0].get("linkinfo", {}) or {}
            kind = info.get("info_kind", "")
            if kind:
                return kind, True
            # linkinfo present and carrying no info_kind IS a real answer: a
            # plain NIC. Determined.
            return "", True
        except Exception:  # noqa: BLE001
            pass
    # Fallback for iproute2 builds that omit linkinfo for tun/tap devices: the
    # presence of tun_flags in sysfs is a definitive "this is a tun/tap device".
    if os.path.exists(f"/sys/class/net/{iface}/tun_flags"):
        return "tun", True
    # ⚠ Reached when the lookup produced nothing usable. If the interface does
    # not exist at all this is also where we land -- and "I could not determine
    # what this is" is the honest answer for that too.
    return "", False


def _iface_kind(iface):
    """Return the kernel link kind for an iface (e.g. 'tun', 'wireguard'), or ''.

    ⚠ CANNOT DISTINGUISH "plain NIC" FROM "lookup failed" -- both are ''. Kept
    for the detection/reporting callers whose contract predates the split; any
    caller making a SECURITY decision must use `_iface_kind_ex` and refuse on
    `determined=False`. See that function.
    """
    return _iface_kind_ex(iface)[0]


def _default_route_ifaces():
    """Interfaces carrying a default route in the MAIN table (preferred signal)."""
    ifaces = []
    routes = _run_json(["ip", "-j", "route", "show", "default"]) or []
    for r in routes:
        dev = r.get("dev")
        if dev and dev not in ifaces:
            ifaces.append(dev)
    return ifaces


def _policy_default_route_ifaces():
    """
    Interfaces carrying a default route in ANY routing table (main + policy
    tables). Needed because some VPNs (notably PIA) keep the MAIN default route on
    the physical NIC and divert host traffic through the tunnel via fwmark/source
    policy routing — the tunnel's default route lives in a *separate* table
    (e.g. `piavpnrt`), not `main`.

    Reading an actual default-route entry (not the `ip rule` entries) avoids PIA's
    stale rules that persist while disconnected: when the VPN is down those policy
    tables hold no tunnel default route / the tunnel iface is gone.
    """
    ifaces = []
    routes = _run_json(["ip", "-j", "route", "show", "table", "all"]) or []
    for r in routes:
        if r.get("dst") == "default":
            dev = r.get("dev")
            if dev and dev not in ifaces:
                ifaces.append(dev)
    return ifaces


def masquerade_egress_iface():
    """The interface Fork B's NAT should masquerade out of, or None.

    Returns the first MAIN-table default-route interface whose kernel kind is NOT a
    tunnel. Added 2026-07-29 for ADR-0009 Fork B Piece 2 (tunnel-routed Suricata),
    which must source-NAT forwarded tailnet traffic to whatever egress is currently
    real.

    WHY THIS SHAPE, rather than trusting `_default_route_ifaces()` wholesale or
    pinning an interface name at install time:

      * Pinning a name (`-o enp131s0`) silently stops masquerading correctly the
        moment the egress changes. It cannot be right in both VPN states.
      * Trusting the main default route alone is wrong for the redirect-gateway
        case, where that route IS the tunnel — it would hand back a tunnel device
        and NAT would be applied to the wrong egress.
      * Kind-matching (never name-matching) is the same rule TUNNEL_KINDS already
        enforces elsewhere in this module: vendor WireGuard builds use arbitrary
        device names, so `tun0`-style heuristics are not safe.

    **Full-tunnel VPNs return None, and the caller must refuse to install a masquerade
    rule** rather than guess an interface and silently NAT to the wrong egress. Do not
    "fix" that by falling back to the first interface found.

    ⚠ HOW THAT IS DECIDED CHANGED ON 2026-08-31, AND THE OLD REASONING WAS WRONG.
    This used to walk `ip route show default` and return the first non-tunnel interface,
    on the stated theory that a redirect-gateway VPN "replaces the main default route
    with the tunnel, every candidate is a tunnel kind, and this returns None."

    That theory only holds when the tunnel REPLACES the main default. The commonest
    full-tunnel form does not: OpenVPN's `redirect-gateway` installs a `0.0.0.0/1` +
    `128.0.0.0/1` straddle and LEAVES the physical `default` in place. Both /1s are more
    specific, so they win for every destination — but `ip route show default` cannot see
    them. Measured live against a connected full tunnel: this function returned
    `enp131s0` with exit 0 while `ip route get 1.1.1.1` resolved to `tun0`. It did not
    fail visibly; it answered confidently and wrongly, and `install.sh` would have
    persisted `-A POSTROUTING -s 100.64.0.0/10 -o enp131s0 -j MASQUERADE` into
    `before.rules` — pinning forwarded tailnet traffic OUTSIDE the user's VPN.

    Egress is now decided by MEASURED routing outcome (`ip route get` across probe
    destinations spanning both halves of the address space), the same mechanism and the
    same operator ruling as `forkb_policy_route.classify_by_resolution`. Under a full
    tunnel, or whenever coverage cannot be computed confidently, this returns None.

    ⚠ Provider-agnostic by construction, per that ruling: no client name, no
    vendor-specific table name. The same client can be split or full-tunnel depending on
    its configuration, so identity implies nothing — live state is re-read every call.
    """
    # Imported lazily to avoid a module-scope cycle: forkb_policy_route imports
    # TUNNEL_KINDS from here. At call time both modules are fully loaded. _HERE is put
    # on the path because this module is also imported as `core.vpn_dns_guard`, where
    # core/ is not otherwise importable as a flat directory.
    if _HERE not in sys.path:
        sys.path.insert(0, _HERE)
    from forkb_policy_route import (                                # noqa: PLC0415
        PROBE_DESTINATIONS, NO_VPN, SPLIT_TUNNEL,
        classify_by_resolution, parse_route_get, resolved_egress)

    resolutions = {}
    for dest in PROBE_DESTINATIONS:
        rc, out, _ = _run(["ip", "route", "get", dest])
        # A failed lookup is an explicit non-measurement, never "no route that way":
        # classify_by_resolution treats any None as a confidence failure and declines.
        resolutions[dest] = parse_route_get(out) if rc == 0 else None

    # ⛔ AN UNDETERMINED KIND IS A NON-MEASUREMENT AND MUST DECLINE, exactly as
    # a failed `ip route get` does two lines above. Until 2026-08-31 this used
    # `_iface_kind`, whose '' means BOTH "plain NIC" and "lookup failed" -- and
    # classify_by_resolution reads '' as PHYSICAL by contract. So any failure of
    # `ip -d -j link show` made a tunnel look like a physical NIC and could hand
    # back an interface that should have been refused, NATing forwarded tailnet
    # traffic OUTSIDE the user's VPN. Refusing costs a masquerade rule; guessing
    # wrong silently defeats the VPN.
    kinds, undetermined = {}, []
    for i in {v for v in resolutions.values() if v}:
        kind, determined = _iface_kind_ex(i)
        if not determined:
            undetermined.append(i)
        kinds[i] = kind
    if undetermined:
        log.warning("masquerade egress: REFUSING -- could not determine the link "
                    "kind of %s, and an undetermined kind reads as 'physical' to "
                    "the classifier. Not guessing; a wrong answer here NATs "
                    "tailnet traffic outside the VPN.", ", ".join(sorted(undetermined)))
        _record(E_MASQ_KIND_UNDETERMINED,
                {"interfaces": sorted(undetermined)})
        return None

    topology, reason = classify_by_resolution(resolutions, kinds, TUNNEL_KINDS)
    if topology not in (NO_VPN, SPLIT_TUNNEL):
        # Raised from info to warning: this is the security-relevant decision in
        # this module and it was the quietest line in it.
        log.warning("masquerade egress: refusing (topology=%s) -- %s",
                    topology, reason)
        return None
    return resolved_egress(resolutions, kinds, TUNNEL_KINDS)


def detect_tunnel():
    """
    Detect whether THIS host has a usable VPN tunnel up.

    Signal (vendor-neutral): a tunnel-TYPE interface (matched by kernel link
    kind/driver, never by name) that is carrying a default route — in the MAIN
    table if the VPN replaces the default route (OpenVPN/WireGuard redirect-gateway),
    OR in any policy routing table if the VPN uses fwmark/source routing (PIA).

    Deliberately ignores interface name patterns and PIA's stale `ip rule` entries.
    """
    result = {"up": False, "iface": None, "kind": None, "table": None,
              "default_ifaces": []}
    main = _default_route_ifaces()
    result["default_ifaces"] = main

    # Prefer the main-table default; fall back to policy-table defaults.
    for iface in main:
        kind = _iface_kind(iface)
        if kind in TUNNEL_KINDS:
            result.update({"up": True, "iface": iface, "kind": kind, "table": "main"})
            return result
    for iface in _policy_default_route_ifaces():
        if iface in main:
            continue
        kind = _iface_kind(iface)
        if kind in TUNNEL_KINDS:
            result.update({"up": True, "iface": iface, "kind": kind, "table": "policy"})
            return result
    return result


# --------------------------------------------------------------------------- #
# Tunnel-DNS discovery — generic, "reachable only through the tunnel"
# --------------------------------------------------------------------------- #

def _resolvectl_link_dns(iface):
    """DNS servers systemd-resolved associates with a link (OpenVPN/WG + resolved)."""
    servers = []
    rc, out, _ = _run(["resolvectl", "status", iface])
    if rc != 0:
        return servers
    capture = False
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("Current DNS Server:") or s.startswith("DNS Servers:"):
            capture = True
            s = s.split(":", 1)[1]
        elif capture and (":" in line and not line.startswith(" ")):
            capture = False
        if capture:
            for tok in s.replace(",", " ").split():
                if _looks_like_ip(tok):
                    servers.append(tok)
    return servers


def _resolv_conf_servers():
    servers = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2 and _looks_like_ip(parts[1]):
                        servers.append(parts[1])
    except Exception:  # noqa: BLE001
        pass
    return servers


def _looks_like_ip(tok):
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, tok.split("%")[0])
            return True
        except OSError:
            continue
    return False


def _routes_via(iface, addr):
    """True if a packet to addr would egress through iface (generic tunnel test)."""
    data = _run_json(["ip", "-j", "route", "get", addr])
    if not data:
        return False
    try:
        return data[0].get("dev") == iface
    except Exception:  # noqa: BLE001
        return False


def _is_loopback(addr):
    a = addr.split("%")[0]
    return a.startswith("127.") or a == "::1"


def discover_tunnel_dns(iface):
    """
    Find a DNS server that is reachable THROUGH the tunnel, so the killswitch
    permits Pi-hole's upstream queries to it.

    Strategy, vendor-neutral, most-reliable first:
      1. DNS the tunnel pushed into systemd-resolved for this link.
      2. Non-loopback nameservers in /etc/resolv.conf.
    Then keep only candidates that actually route via the tunnel iface
    (`ip route get`) — that is the generic "this DNS lives behind the VPN" test.
    """
    candidates = []
    for src in (_resolvectl_link_dns(iface), _resolv_conf_servers()):
        for ip in src:
            if ip not in candidates and not _is_loopback(ip):
                candidates.append(ip)

    via_tunnel = [ip for ip in candidates if _routes_via(iface, ip)]
    log.info("tunnel-dns candidates=%s via_tunnel=%s", candidates, via_tunnel)
    return via_tunnel


# --------------------------------------------------------------------------- #
# Pi-hole v6 API client (reuses the modules/dhcp pattern, not the module)
# --------------------------------------------------------------------------- #

class Pihole:
    def __init__(self, ip=PIHOLE_IP, password=PIHOLE_PASSWORD):
        self._ip = ip
        self._pw = password
        self._sid = None

    def _auth(self):
        if self._sid:
            try:
                r = requests.get(
                    f"http://{self._ip}/api/auth",
                    headers={"sid": self._sid}, timeout=4,
                )
                if r.json().get("session", {}).get("valid"):
                    return self._sid
            except Exception:  # noqa: BLE001
                pass
        r = requests.post(
            f"http://{self._ip}/api/auth", json={"password": self._pw}, timeout=4,
        )
        self._sid = r.json().get("session", {}).get("sid")
        return self._sid

    def get_dns(self):
        """Return the full dns config subtree (upstreams, interface, listeningMode)."""
        sid = self._auth()
        if not sid:
            raise RuntimeError("Pi-hole auth failed")
        r = requests.get(
            f"http://{self._ip}/api/config/dns", headers={"sid": sid}, timeout=5,
        )
        r.raise_for_status()
        return r.json().get("config", {}).get("dns", {})

    def get_upstreams(self):
        return list(self.get_dns().get("upstreams", []))

    def set_upstreams(self, upstreams):
        """PATCH ONLY dns.upstreams. Listening posture is never touched here."""
        sid = self._auth()
        if not sid:
            raise RuntimeError("Pi-hole auth failed")
        payload = {"config": {"dns": {"upstreams": list(upstreams)}}}
        r = requests.patch(
            f"http://{self._ip}/api/config", headers={"sid": sid},
            json=payload, timeout=6,
        )
        r.raise_for_status()
        log.info("set dns.upstreams=%s (HTTP %s)", upstreams, r.status_code)


# --------------------------------------------------------------------------- #
# Verification — does Pi-hole actually resolve upstream right now?
# --------------------------------------------------------------------------- #

def verify_upstream_resolves(tries_per_zone=2):
    """
    Query Pi-hole (127.0.0.1) for a random label under real zones. PASS if any
    returns NOERROR or NXDOMAIN (upstream answered); FAIL on SERVFAIL / REFUSED /
    timeout (upstream unreachable — the killswitch symptom).
    """
    stamp = f"{int(time.time())}-{os.getpid()}"
    for zone in VERIFY_ZONES:
        name = f"nemesis-vpndns-{stamp}.{zone}"
        for _ in range(tries_per_zone):
            rc, out, _ = _run(
                ["dig", "+tries=1", "+time=3", "@127.0.0.1", name, "A"], timeout=8,
            )
            if rc == 0 and "status:" in out:
                status = out.split("status:", 1)[1].split(",", 1)[0].strip()
                log.info("verify %s -> %s", name, status)
                if status in ("NOERROR", "NXDOMAIN"):
                    return True
    return False


# --------------------------------------------------------------------------- #
# State persistence
# --------------------------------------------------------------------------- #

def _load_state():
    """Current state, reading the legacy location once so the move is not a reset.

    The legacy path is read ONLY if the new one is absent. A file at the new path
    always wins — otherwise a stale copy in the read-only tree would keep
    overriding real state forever, which is a variant of the bug this move fixes.
    """
    for path in (STATE_PATH, _LEGACY_STATE_PATH):
        try:
            with open(path) as f:
                st = json.load(f)
            if path is _LEGACY_STATE_PATH:
                log.warning("migrated state from legacy path %s", _LEGACY_STATE_PATH)
            return st
        except FileNotFoundError:
            continue
        except Exception:  # noqa: BLE001
            log.exception("state at %s unreadable; treating as absent", path)
            continue
    return {"applied": False, "saved_upstreams": None, "tunnel_iface": None}


def _save_state(state) -> bool:
    """Persist state. Returns True on success, False on failure.

    RETURNS A RESULT RATHER THAN SWALLOWING THE ERROR. This previously logged the
    exception and returned None, and the caller carried on to log "fix applied" —
    so four days of 100%-failed writes were reported as successful applies. A
    failed write that the caller cannot detect is indistinguishable from a
    successful one, which is the failure shape this codebase keeps rediscovering.
    """
    try:
        tmp = STATE_PATH + ".tmp"
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        with open(tmp, "w") as f:
            json.dump(state, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, STATE_PATH)
        return True
    except Exception:  # noqa: BLE001
        log.exception("could not persist state to %s", STATE_PATH)
        return False


# --------------------------------------------------------------------------- #
# Core actions
# --------------------------------------------------------------------------- #

def apply_fix(ph, tunnel, state):
    """
    Tunnel is up. Move Pi-hole upstream onto a tunnel-reachable resolver, verify,
    roll back on failure. Idempotent: if already applied, only re-verify.
    """
    current = ph.get_upstreams()

    if state.get("applied"):
        # Already applied earlier; just make sure DNS still resolves.
        if verify_upstream_resolves():
            return True
        log.warning("previously-applied fix no longer resolves; re-applying")

    tun_dns = discover_tunnel_dns(tunnel["iface"])

    # BASELINE CAPTURE — deliberately AFTER tunnel-DNS discovery, so the value we
    # are about to write can be compared against what is already there.
    #
    # A BASELINE WE CANNOT VOUCH FOR IS WORSE THAN NONE. If persistence had ever
    # failed (it failed 5,655 consecutive times before 2026-08-02), `applied`
    # stays false on disk, so every subsequent cycle re-entered this branch and
    # re-captured `current` — which by then was the guard's OWN previous write,
    # not a pre-VPN value. Saving that would make restore() put the tunnel
    # resolver back on disconnect: precisely the outage it exists to prevent,
    # performed deliberately and logged as a success.
    #
    # So: refuse to record a baseline that equals what we are about to set. Same
    # rule as the canary planter refusing a baseline it cannot verify — record
    # nothing rather than record a fiction.
    if not state.get("applied"):
        if tun_dns and current == tun_dns:
            log.error(
                "REFUSING to baseline upstreams %s: identical to the tunnel resolver "
                "we are about to apply, so this is our own earlier write, not a "
                "pre-VPN value. saved_upstreams left unset — restore-on-disconnect "
                "will NOT be able to roll back until a genuine pre-VPN value is "
                "supplied (see PUNCHLIST).", current)
            state["saved_upstreams"] = None
        else:
            # First time, and the current value is genuinely not ours: remember it.
            state["saved_upstreams"] = current
            log.info("baselined pre-VPN upstreams %s", current)
    if not tun_dns:
        # No tunnel-reachable resolver found. Re-verify with the existing public
        # upstreams (they may already egress via the tunnel); if they fail there is
        # no Pi-hole-config-only remedy and we leave config untouched.
        log.warning("no tunnel-reachable DNS discovered on %s; leaving upstreams=%s",
                    tunnel["iface"], current)
        ok = verify_upstream_resolves()
        if ok:
            state.update({"applied": True, "tunnel_iface": tunnel["iface"]})
            if not _save_state(state):
                log.error("marked applied (no tunnel DNS needed) but state did NOT "
                          "persist — this cycle will repeat indefinitely")
        return ok

    ph.set_upstreams(tun_dns)
    if verify_upstream_resolves():
        state.update({"applied": True, "tunnel_iface": tunnel["iface"]})
        persisted = _save_state(state)
        if persisted:
            log.info("fix applied: upstreams now %s (verified resolving)", tun_dns)
        else:
            # Do NOT report a clean apply. The DNS change itself succeeded, but
            # the record that makes it reversible did not, so restore-on-disconnect
            # cannot work and the next cycle will re-apply as if it were the first.
            log.error("fix applied to DNS (upstreams now %s) but state did NOT "
                      "persist — restore-on-disconnect is NOT armed and this will "
                      "re-apply every cycle. Fix the state path before relying on "
                      "tunnel-down recovery.", tun_dns)
        return True

    # Verify failed -> roll back to whatever we saved and report.
    log.error("verify FAILED after pointing upstream at %s; rolling back to %s",
              tun_dns, state.get("saved_upstreams"))
    if state.get("saved_upstreams") is not None:
        ph.set_upstreams(state["saved_upstreams"])
    return False


def restore(ph, state):
    """Tunnel is down (or stale state). Put the saved upstreams back."""
    if not state.get("applied"):
        return True
    saved = state.get("saved_upstreams")
    if saved is not None:
        ph.set_upstreams(saved)
        # Rule 13 / Rule 3: prove the revert, don't assert it. set_upstreams()'s
        # only failure signal is raise_for_status() on the PATCH, which sees
        # transport and auth failures but NOT "Pi-hole accepted the PATCH and the
        # config never actually took" (async/eventually-consistent config-apply in
        # some FTL versions, partial apply, config-reload race). apply_fix() above
        # already verifies before claiming success; this is the same evidence
        # standard applied to the restore path, which is the asymmetry that made
        # a false "restored" claim possible.
        try:
            readback = ph.get_upstreams()
        except Exception:  # noqa: BLE001
            readback = None
            log.exception("restore: could not read upstreams back from Pi-hole")
        # Compare order-insensitively: Pi-hole is free to return the same set in a
        # different order, and treating that as a mismatch would produce a
        # permanent false failure — the exact "instrument that can only say no"
        # shape this rule exists to prevent.
        matched = (readback is not None
                   and sorted(map(str, readback)) == sorted(map(str, saved)))
        resolves = verify_upstream_resolves()
        if not (matched and resolves):
            # Do NOT clear `applied` / `saved_upstreams` here. Leaving them intact
            # is what lets the next reconcile cycle retry; clearing them on an
            # UNPROVEN restore is precisely what would turn a transient failure
            # into a permanent silent one, because nothing would ever revisit it.
            log.error("restore NOT confirmed: readback=%s (expected %s, match=%s), "
                      "resolve-probe=%s. Leaving state applied so the next cycle "
                      "retries — Pi-hole may still be pointed at the tunnel "
                      "resolver and DNS may be broken for its clients.",
                      readback, saved, matched, resolves)
            return False
        log.info("restored pre-VPN upstreams %s (readback matched, resolving)", saved)
    else:
        # Applied, tunnel now down, but no baseline to go back to. Say so loudly:
        # Pi-hole is left pointing at a resolver that was only reachable THROUGH
        # the tunnel, so DNS is likely broken for every client it serves. Silence
        # here would leave an outage with no explanation in the log.
        log.error("tunnel down and fix was applied, but NO saved upstreams exist — "
                  "cannot restore. Pi-hole is still pointed at the tunnel resolver "
                  "and DNS is probably broken for its clients. Set upstreams "
                  "manually, then supply a genuine pre-VPN value.")
    state.update({"applied": False, "saved_upstreams": None, "tunnel_iface": None})
    if not _save_state(state):
        log.error("restore completed but state did NOT persist — the next cycle "
                  "may treat the tunnel as still applied")
    return True


# --------------------------------------------------------------------------- #
# MagicDNS conflict detection  (ADR 0002 amendment -- see docs/architecture/0002)
#
# THE PROBLEM. With Tailscale installed from apt and `accept-dns=true`, Tailscale
# takes DNS over in `directManager` mode and rewrites /etc/resolv.conf to point
# EXCLUSIVELY at its own resolver (100.100.100.100) -- it writes NO fallback entry.
# A VPN killswitch that blocks that address therefore does not merely disable
# MagicDNS: it removes every resolver the host has. Measured live 2026-09-01 on
# the daily driver -- total DNS outage until `accept-dns=false` was set.
#
# WHY THE TRIGGER IS OBSERVED STATE, NOT THE VENDOR AND NOT THE PACKAGING.
#   * Vendor-neutral by construction, matching detect_tunnel()'s existing stance:
#     any killswitch that blocks the resolver produces the same observation.
#   * The snap/apt asymmetry falls out FOR FREE. Under a snap install the DNS
#     takeover cannot succeed (strict confinement blocks the /etc/resolv.conf
#     write), so resolv.conf is never exclusively Tailscale's, so this can never
#     fire. That is a no-op BY CONSTRUCTION rather than a packaging special-case
#     that could rot. `tailscale_packaging()` exists to REPORT which case we are
#     in -- it must never be used to DECIDE.
#
# ⛔ NEVER identify the daemon by systemd unit name. On snap the unit is
# `snap.tailscale.tailscaled.service`, so `systemctl is-active tailscaled` returns
# "inactive" FOR A RUNNING DAEMON. core/netfilter_drift.py documents this exact
# trap; its answer is the pattern used here -- prove liveness by reading something
# only a live daemon can answer, never a name proxy.
# --------------------------------------------------------------------------- #

_ALERTMGR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alert_manager")
TS_MAGIC_V4 = "100.100.100.100"
TS_MAGIC_V6 = "fd7a:115c:a1e0::53"
TS_MAGIC_RESOLVERS = frozenset((TS_MAGIC_V4, TS_MAGIC_V6))
RESOLV_CONF_PATH = "/etc/resolv.conf"


def tailscale_cli():
    """Path to the tailscale CLI, or None. PATH-resolved so BOTH packagings work."""
    return shutil.which("tailscale")


def tailscale_packaging():
    """'snap' | 'apt' | 'absent' | 'unknown'. For REPORTING ONLY -- never to decide."""
    exe = tailscale_cli()
    if not exe:
        return "absent"
    try:
        real = os.path.realpath(exe)
    except Exception:  # noqa: BLE001
        return "unknown"
    if real.startswith("/snap/") or os.path.isdir("/var/snap/tailscale"):
        return "snap"
    if real.startswith("/usr/"):
        return "apt"
    return "unknown"


def _resolv_nameservers(path=RESOLV_CONF_PATH):
    """Nameservers from resolv.conf, or None if UNREADABLE.

    None is deliberately distinct from []: an unreadable file must not read as
    "no nameservers" and thereby as "not exclusively Tailscale", which would
    silently suppress the guard. Fail closed, never to a legal-looking value.
    """
    try:
        found = []
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        found.append(parts[1])
        return found
    except Exception:  # noqa: BLE001
        return None


def resolv_is_exclusively_tailscale(path=RESOLV_CONF_PATH):
    """True / False / None(undetermined). True only if EVERY nameserver is Tailscale's."""
    servers = _resolv_nameservers(path)
    if servers is None:
        return None
    if not servers:
        return False
    return all(s in TS_MAGIC_RESOLVERS for s in servers)


def dns_query_answers(server, name="example.com", timeout=2.0):
    """Real UDP DNS query. True=answered, False=no answer, None=could not attempt.

    A FUNCTIONAL query, not a port check: "something is bound" and "it answers"
    are different claims, and only the second one is the thing that matters.
    """
    sock = None
    try:
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        for label in name.split("."):
            query += bytes([len(label)]) + label.encode()
        query += b"\x00" + struct.pack("!HH", 1, 1)
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (server, 53))
        data, _ = sock.recvfrom(512)
        return len(data) >= 12 and data[:2] == query[:2]
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    except Exception:  # noqa: BLE001
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass


def magicdns_conflict(fallback_addr="127.0.0.1", query=None, resolv_path=RESOLV_CONF_PATH):
    """Is Tailscale's resolver the ONLY resolver AND not answering?

    `conflict` is True / False / None(undetermined). `query` is injectable so
    every branch can be FORCED by a test rather than merely being reachable.

    ⛔ POSITIVE CONTROL. Never returns True on "Tailscale does not answer" alone.
    If the fallback resolver is ALSO unreachable then DNS is broken for some other
    reason, falling back would fix nothing, and claiming this conflict would be a
    wrong diagnosis. A probe that can only produce one answer measures nothing.
    """
    q = query or dns_query_answers
    result = {"conflict": None, "reason": "", "packaging": tailscale_packaging(),
              "exclusive": None, "ts_answers": None, "fallback_answers": None}

    exclusive = resolv_is_exclusively_tailscale(resolv_path)
    result["exclusive"] = exclusive
    if exclusive is None:
        result["reason"] = "resolv.conf unreadable -- failing closed, no action"
        return result
    if not exclusive:
        result["conflict"] = False
        result["reason"] = ("resolv.conf is not exclusively Tailscale's resolver, so a "
                            "blocked Tailscale resolver cannot remove all DNS "
                            "(this is always the case on a snap install)")
        return result

    ts_answers = q(TS_MAGIC_V4)
    result["ts_answers"] = ts_answers
    if ts_answers is None:
        result["reason"] = "could not probe Tailscale's resolver -- failing closed, no action"
        return result
    if ts_answers:
        result["conflict"] = False
        result["reason"] = "Tailscale's resolver answers; no conflict"
        return result

    fallback_answers = q(fallback_addr)
    result["fallback_answers"] = fallback_answers
    if fallback_answers is None:
        result["reason"] = "could not probe the fallback resolver -- failing closed, no action"
        return result
    if not fallback_answers:
        result["reason"] = ("POSITIVE CONTROL FAILED: the fallback resolver is also "
                            "unreachable, so this is not the MagicDNS conflict and "
                            "falling back would fix nothing. No action")
        return result

    result["conflict"] = True
    result["reason"] = ("Tailscale's resolver is the ONLY resolver and does not answer "
                        "while the fallback does -- all DNS is broken and falling back "
                        "will restore it")
    return result


def evaluate_magicdns(fallback_addr="127.0.0.1", act=True):
    """Probe, RECORD, and ask the privileged helper to act.

    THIS SERVICE CANNOT ACT ITSELF and must not try: it runs as nemesis-vpndns
    with NoNewPrivileges=yes and an EMPTY CapabilityBoundingSet, while
    `tailscale set` needs root. The privileged half lives behind nemesis-fwd's
    one-op allowlist (`magicdns_switch`), which RE-MEASURES the conflict there
    and refuses if its own verdict disagrees. What we send is a request, never a
    verdict -- so a compromised guard cannot toggle DNS at will.

    `act=False` makes this detection-only, for tests and dry runs.
    """
    verdict = magicdns_conflict(fallback_addr=fallback_addr)
    verdict["action"] = None

    if verdict["conflict"] is True:
        _record(E_MAGICDNS_CONFLICT, {k: str(v)[:200] for k, v in verdict.items()})
        log.warning("MagicDNS conflict: %s", verdict["reason"])
        if act:
            verdict["action"] = _magicdns_ask_helper(False)
    elif verdict["conflict"] is None:
        _record(E_MAGICDNS_UNDETERMINED, {k: str(v)[:200] for k, v in verdict.items()})
        log.warning("MagicDNS probe undetermined: %s", verdict["reason"])
    elif act:
        # No conflict. Ask to restore ONLY if the helper itself disabled it --
        # the helper enforces that; we do not track it here, deliberately, so
        # there is ONE source of truth for "was this ours".
        verdict["action"] = _magicdns_ask_helper(True, quiet=True)
    return verdict


def _magicdns_ask_helper(enable, quiet=False):
    """Send the request. NEVER raises into the reconcile cycle."""
    try:
        sys.path.insert(0, _ALERTMGR) if _ALERTMGR not in sys.path else None
        import fw_client  # noqa: PLC0415
        res = fw_client.magicdns_switch(enable)
        if res.get("ok"):
            log.info("magicdns_switch enable=%s applied and verified", enable)
        elif not quiet:
            log.warning("magicdns_switch enable=%s refused/failed: %s",
                        enable, str(res.get("reason"))[:200])
        return res
    except Exception as exc:  # noqa: BLE001
        # Helper down, socket missing, permission denied -- all non-fatal here.
        # Detection still recorded above; the operator can act by hand.
        if not quiet:
            log.warning("magicdns_switch could not reach nemesis-fwd: %s",
                        str(exc)[:160])
        return {"ok": False, "reason": "helper unreachable: %s" % str(exc)[:120]}


def reconcile(ph=None, force=None):
    """
    One reconcile cycle. Handles all three transitions symmetrically:
      * connect    : state not-applied + tunnel up   -> apply_fix
      * disconnect : state applied     + tunnel down -> restore
      * cold start : state applied     + tunnel up   -> apply_fix re-verifies
                     state applied     + tunnel down -> restore (stale state)
    `force` of 'apply'/'restore' overrides detection (used by the CLI/live-test).
    """
    ph = ph or Pihole()
    state = _load_state()
    tunnel = detect_tunnel()

    # ⛔ THE MAGICDNS GUARD RUNS EVERY CYCLE, BOTH DIRECTIONS, AND UNCONDITIONALLY.
    #
    # It is placed HERE -- above the force/apply/restore branches -- deliberately, so
    # there is exactly ONE call site that every path passes through. Putting it inside
    # the tunnel-up branch would make the RESTORE direction unreachable (accept-dns
    # would never come back on when the tunnel dropped), and putting it after the
    # returns would make it dead code again.
    #
    # ⚠ IT WAS DEAD CODE ON ITS FIRST DEPLOY (2026-09-01): evaluate_magicdns() was
    # written, tested by 82 checks, deployed, and NEVER CALLED -- so the first live
    # test produced a real DNS outage the guard did not even attempt to prevent. The
    # identical defect had been fixed in this repo ONE DAY EARLIER (66ba78e,
    # "wire drift_watch into the diagnostics watcher -- it had no caller").
    # test_tailscale_packaging_independence.py now asserts THIS CALL SITE by AST.
    # Do not move or conditionalise it without updating that test.
    #
    # Never allowed to break the Pi-hole reconcile it shares a cycle with: MagicDNS
    # being unavailable is a degradation, upstream DNS failing is an outage.
    try:
        magicdns = evaluate_magicdns()
    except Exception:  # noqa: BLE001
        log.exception("magicdns evaluation errored; Pi-hole reconcile continues")
        magicdns = {"conflict": None, "reason": "evaluation raised", "action": None}

    if force == "apply":
        tunnel = tunnel if tunnel["up"] else {"up": True, "iface": _force_iface(), "kind": "forced"}
        return {"action": "apply", "tunnel": tunnel, "magicdns": magicdns,
                "ok": apply_fix(ph, tunnel, state)}
    if force == "restore":
        return {"action": "restore", "tunnel": tunnel, "magicdns": magicdns,
                "ok": restore(ph, state)}

    if tunnel["up"]:
        return {"action": "apply", "tunnel": tunnel, "magicdns": magicdns,
                "ok": apply_fix(ph, tunnel, state)}
    return {"action": "restore", "tunnel": tunnel, "magicdns": magicdns,
            "ok": restore(ph, state)}


def _force_iface():
    """Best-effort tunnel iface when forcing apply (live-test convenience)."""
    for iface in _default_route_ifaces() + _policy_default_route_ifaces():
        if _iface_kind(iface) in TUNNEL_KINDS:
            return iface
    # any tunnel-type iface present at all
    links = _run_json(["ip", "-d", "-j", "link", "show"]) or []
    for l in links:
        name = l.get("ifname")
        if name and _iface_kind(name) in TUNNEL_KINDS:
            return name
    return None


# --------------------------------------------------------------------------- #
# Daemon loop
# --------------------------------------------------------------------------- #

def _notify_connectivity(res):
    """Report this cycle to the shared episode notifier — ONLY when a real probe ran.

    WHY THIS IS GATED ON `action == "apply"` AND NOT ON `res["ok"]`.
    `reconcile()` returns ok=True from the restore path too, and `restore()`
    early-returns True whenever nothing was applied (`vpn_dns_guard.py`'s
    `if not state.get("applied"): return True`). So on the common
    no-tunnel-configured cycle, `ok` is True having measured NOTHING. Feeding that
    to the notifier as a passing observation would be an instrument reporting
    success it never established — and worse, it would CLOSE a real episode that
    the diagnostics watcher had legitimately opened.

    `verify_upstream_resolves()` only runs inside `apply_fix()`, i.e. on the
    apply path, so that is the only cycle where `ok` reflects an actual
    resolution probe. Every other cycle reports nothing at all, which is the
    honest answer: this guard has no connectivity signal when no tunnel is up.
    Diagnostics covers that case; this one is deliberately silent rather than
    falsely reassuring.

    VERDICT IS `DEGRADED`, NOT `LOCAL_FAIL`, ON PURPOSE. This guard probes DNS
    resolution through a tunnel resolver. When that fails it genuinely cannot
    tell a local misconfiguration from the VPN provider's own resolver being
    down — so it must not claim the local-vs-upstream discrimination that the
    diagnostics watcher actually performs (four independent probe layers). Naming
    a verdict it did not determine would make the severity split meaningless.
    DEGRADED maps to MEDIUM, keeping it dashboard-visible without auto-ticketing
    on a determination that was never made.

    Never raises — reporting must not kill the guard loop.
    """
    try:
        if res.get("action") != "apply":
            return
        import nemesis_connectivity_notify as conn_notify
        ok = bool(res.get("ok"))
        conn_notify.observe(
            source="vpn_dns_guard",
            ok=ok,
            verdict=None if ok else "DEGRADED",
            # Fixed string — reaches the DB and email, so no addresses (Rule 8).
            detail=None if ok else "vpn dns upstream did not resolve",
        )
    except Exception:  # noqa: BLE001
        log.exception("connectivity notify failed (guard loop continues)")


def main_loop():
    log.info("vpn_dns_guard starting (interval=%ss, debounce=%ss)",
             CHECK_INTERVAL_SECONDS, DEBOUNCE_SECONDS)
    ph = Pihole()
    last_up = None
    stable_since = 0.0
    while True:
        try:
            up = detect_tunnel()["up"]
            now = time.time()
            if up != last_up:
                last_up = up
                stable_since = now  # state changed; start debounce timer
            elif now - stable_since >= DEBOUNCE_SECONDS:
                # State has been stable long enough — safe to reconcile.
                res = reconcile(ph)
                if not res["ok"]:
                    # `reason` carries the DETAIL (which teardown did not take,
                    # which self-test failed). It was being discarded here, so
                    # the one line an operator would find said only "abort".
                    log.warning("reconcile reported failure: %s -- %s",
                                res.get("action"), res.get("reason"))
                    # A REFUSAL and a FAILURE are different events: refusing to
                    # touch routing is correct behaviour that happens to mean
                    # Fork B is not working, while a failure means it tried and
                    # the routing state is not what was intended.
                    _record(E_RECONCILE_REFUSED if res.get("action") == "abort"
                            else E_RECONCILE_FAILED,
                            {"action": res.get("action"),
                             "reason": str(res.get("reason"))[:300],
                             "topology": res.get("topology")})
                _notify_connectivity(res)
        except Exception as exc:  # noqa: BLE001
            log.exception("reconcile cycle errored")
            _record(E_RECONCILE_CYCLE_ERROR,
                    {"error": "%s: %s" % (type(exc).__name__, exc)})
        time.sleep(CHECK_INTERVAL_SECONDS)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _print(obj):
    print(json.dumps(obj, indent=2, default=str))


def main(argv):
    arg = argv[1] if len(argv) > 1 else ""
    if arg == "--detect":
        _print(detect_tunnel())
    elif arg == "--status":
        # Rule 13. This block used to build `dns = {"error": str(e)}` on failure and
        # then read `dns.get("upstreams")` out of it — so an exception rendered as
        # `"pihole_upstreams": null`, IDENTICAL to a healthy Pi-hole that simply has
        # no upstreams set, and the "error" key it had just built was never printed.
        # That cost real time on 2026-08-07: a run without the service's
        # EnvironmentFile (so an empty PIHOLE_PASSWORD) showed nulls and was read as
        # a live production auth failure. It was not — the daemon authenticates fine.
        # The failure must be visible, and it must be distinguishable from an
        # empty-but-healthy answer.
        ph = Pihole()
        dns, pihole_error = {}, None
        try:
            dns = ph.get_dns()
        except Exception as e:  # noqa: BLE001
            pihole_error = "%s: %s" % (type(e).__name__, e)
        _print({
            "tunnel": detect_tunnel(),
            "state": _load_state(),
            # Report the CONFIG this process actually resolved, not what a service
            # would get. Reading --status from a shell without /etc/nemesis.env
            # loaded is the single most likely reason it fails, and these two fields
            # say so immediately instead of leaving it to be inferred from a null.
            # The password is reported as a boolean ONLY — never its value (Rule 8).
            "pihole_target": PIHOLE_IP,
            "pihole_password_configured": bool(PIHOLE_PASSWORD),
            "pihole_query_ok": pihole_error is None,
            "pihole_error": pihole_error,
            "pihole_upstreams": dns.get("upstreams"),
            "pihole_interface": dns.get("interface"),
            "pihole_listeningMode": dns.get("listeningMode"),
            "resolves_now": verify_upstream_resolves(),
        })
        # Non-zero exit when Pi-hole could not be queried, matching the
        # --egress-iface precedent above: a caller that scripts this must be able
        # to tell "reported successfully" from "could not measure".
        return 1 if pihole_error else 0
    elif arg == "--apply":
        _print(reconcile(force="apply"))
    elif arg == "--restore":
        _print(reconcile(force="restore"))
    elif arg == "--once":
        _print(reconcile())
    elif arg == "--egress-iface":
        # For ADR-0009 Fork B Piece 2: install.sh asks which interface to
        # masquerade out of. Prints the name and exits 0, or prints nothing and
        # exits 1 when no non-tunnel default egress exists (redirect-gateway VPN).
        # The non-zero exit is the contract — callers must treat it as "do not
        # install a NAT rule", never as "pick something".
        iface = masquerade_egress_iface()
        if not iface:
            print("", end="")
            return 1
        print(iface)
        return 0
    else:
        main_loop()
    return 0


if __name__ == "__main__":
    # Assert the privilege boundary against the kernel before doing any work.
    # Inert until the migrated unit sets NEMESIS_EXPECT_USER (see nemesis_privsep).
    # This service lives in core/, so reach alert_manager/ for the shared module.
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "..", "alert_manager"))
    import nemesis_privsep
    nemesis_privsep.attest_from_env("vpn-dns-guard")
    # Propagate main()'s return as the exit status: --egress-iface's non-zero
    # exit is a contract ("no safe egress found — do not install NAT"), and it
    # is worthless if the shell always sees 0.
    sys.exit(main(sys.argv))
