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
import socket
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

LOG_PATH = os.environ.get("VPN_DNS_GUARD_LOG", os.path.join(_HERE, "vpn_dns_guard.log"))
# State persists across restarts so we can restore the pre-VPN upstreams even if
# the service (or the whole box) was restarted while the tunnel was up.
STATE_PATH = os.environ.get(
    "VPN_DNS_GUARD_STATE",
    os.path.join(_ROOT, "alert_manager", "vpn_dns_guard.state.json"),
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
# Small shell helpers
# --------------------------------------------------------------------------- #

def _run(cmd, timeout=6):
    """Run a command, return (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:  # noqa: BLE001
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

def _iface_kind(iface):
    """Return the kernel link kind for an iface (e.g. 'tun', 'wireguard'), or ''."""
    data = _run_json(["ip", "-d", "-j", "link", "show", iface])
    if data:
        try:
            info = data[0].get("linkinfo", {}) or {}
            kind = info.get("info_kind", "")
            if kind:
                return kind
        except Exception:  # noqa: BLE001
            pass
    # Fallback for iproute2 builds that omit linkinfo for tun/tap devices: the
    # presence of tun_flags in sysfs is a definitive "this is a tun/tap device".
    if os.path.exists(f"/sys/class/net/{iface}/tun_flags"):
        return "tun"
    return ""


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
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return {"applied": False, "saved_upstreams": None, "tunnel_iface": None}


def _save_state(state):
    try:
        tmp = STATE_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, STATE_PATH)
    except Exception:  # noqa: BLE001
        log.exception("could not persist state")


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
    else:
        # First time: remember the pre-VPN upstreams so we can restore them later.
        state["saved_upstreams"] = current

    tun_dns = discover_tunnel_dns(tunnel["iface"])
    if not tun_dns:
        # No tunnel-reachable resolver found. Re-verify with the existing public
        # upstreams (they may already egress via the tunnel); if they fail there is
        # no Pi-hole-config-only remedy and we leave config untouched.
        log.warning("no tunnel-reachable DNS discovered on %s; leaving upstreams=%s",
                    tunnel["iface"], current)
        ok = verify_upstream_resolves()
        if ok:
            state.update({"applied": True, "tunnel_iface": tunnel["iface"]})
            _save_state(state)
        return ok

    ph.set_upstreams(tun_dns)
    if verify_upstream_resolves():
        state.update({"applied": True, "tunnel_iface": tunnel["iface"]})
        _save_state(state)
        log.info("fix applied: upstreams now %s (verified resolving)", tun_dns)
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
        log.info("restored pre-VPN upstreams %s", saved)
    state.update({"applied": False, "saved_upstreams": None, "tunnel_iface": None})
    _save_state(state)
    return True


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

    if force == "apply":
        tunnel = tunnel if tunnel["up"] else {"up": True, "iface": _force_iface(), "kind": "forced"}
        return {"action": "apply", "tunnel": tunnel, "ok": apply_fix(ph, tunnel, state)}
    if force == "restore":
        return {"action": "restore", "tunnel": tunnel, "ok": restore(ph, state)}

    if tunnel["up"]:
        return {"action": "apply", "tunnel": tunnel, "ok": apply_fix(ph, tunnel, state)}
    return {"action": "restore", "tunnel": tunnel, "ok": restore(ph, state)}


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
                    log.warning("reconcile reported failure: %s", res["action"])
        except Exception:  # noqa: BLE001
            log.exception("reconcile cycle errored")
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
        ph = Pihole()
        try:
            dns = ph.get_dns()
        except Exception as e:  # noqa: BLE001
            dns = {"error": str(e)}
        _print({
            "tunnel": detect_tunnel(),
            "state": _load_state(),
            "pihole_upstreams": dns.get("upstreams"),
            "pihole_interface": dns.get("interface"),
            "pihole_listeningMode": dns.get("listeningMode"),
            "resolves_now": verify_upstream_resolves(),
        })
    elif arg == "--apply":
        _print(reconcile(force="apply"))
    elif arg == "--restore":
        _print(reconcile(force="restore"))
    elif arg == "--once":
        _print(reconcile())
    else:
        main_loop()


if __name__ == "__main__":
    # Assert the privilege boundary against the kernel before doing any work.
    # Inert until the migrated unit sets NEMESIS_EXPECT_USER (see nemesis_privsep).
    # This service lives in core/, so reach alert_manager/ for the shared module.
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "..", "alert_manager"))
    import nemesis_privsep
    nemesis_privsep.attest_from_env("vpn-dns-guard")
    main(sys.argv)
