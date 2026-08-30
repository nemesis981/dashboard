"""
Diagnostics connectivity watcher — probe library (Pass 1).

OBSERVE-ONLY. Probes routing / DNS / raw-egress / upstream-API, classifies the
"is-it-me-or-them" question, then splits its output per Rule 8 (spec §4):

  RAW detail (real IPs: routing tables, resolved/tunnel/public addresses) -> a
      flat log OUTSIDE the repo (watcher_log_dir). Never the DB, never committed.
  SANITIZED verdicts ONLY (booleans + verdict enum + latency + a controlled-
      vocabulary note) -> the diagnostics_* DB tables. No addresses ever.

Makes NO system changes (engine-aware, ADR 0005 — any future remediation routes
through the firewall engine, never from here). This file holds NO loop: the
standalone service (Pass 3) and the nemesis-diag runner call run_once(). It is
hand-runnable: `python3 -m modules.diagnostics.watcher [--verbose]`.
"""

import os
import re
import shutil
import socket
import logging
import subprocess
from datetime import datetime, timedelta

from modules.diagnostics import module as diag

log = logging.getLogger("nemesis.diagnostics.watcher")

# ── structured error codes (alert_manager/nemesis_errors.py) ─────────────────
# Registration deferred to first use, same reasoning as every other retrofit
# site. Shares diag._conn() (the "diagnostics" namespace) rather than opening
# its own connection.
_ERR_CODES = {
    "E-DIAG-001": ("diagnostics_connectivity_samples retention DELETE failed "
                   "(malformed samples_max setting); the table grows unbounded "
                   "until it becomes a disk problem",
                   "MEDIUM", "silent-retention-skip"),
}
_recorder = None


def _errors_record(code, context):
    """Record one structured error occurrence. Never raises into the caller."""
    global _recorder
    try:
        if _recorder is None:
            import nemesis_errors
            _recorder = nemesis_errors.make_recorder(
                "diagnostics", diag._conn, _ERR_CODES, logger=log)
        return _recorder(code, context=context)
    except Exception:
        return None


NET_TIMEOUT = 5            # seconds per network probe (mirrors vpn-watch.sh NETTO)
LOG_BASENAME = "connectivity.log"
_CURL_W = "http_code=%{http_code} time=%{time_total}"
_CURL_RE = re.compile(r"http_code=(\d+)\s+time=([\d.]+)")

# Controlled-vocabulary notes — fixed strings, NEVER interpolate an address into
# these (they reach the DB). Addresses live only in the flat log.
_NOTE_NO_ROUTE = "no default route"
_NOTE_DNS_FAIL = "dns resolution failed"
_NOTE_EGRESS_FAIL = "raw egress blocked"
_NOTE_IPV6_FAIL = "ipv6 keytest failed"
_NOTE_IPV4_FAIL = "ipv4 keytest failed"
#: IPv6 is not provisioned on this link at all, so its keytest failing is the
#: expected result rather than a fault. Distinct from _NOTE_IPV6_FAIL: one says
#: "a thing that should work does not", the other says "this link is IPv4-only".
_NOTE_IPV6_ABSENT = "ipv6 not provisioned on this link"
#: We could not determine whether IPv6 is provisioned. NOT the same as either of
#: the two above — see `ipv6_expectation`.
_NOTE_IPV6_UNKNOWN = "ipv6 provisioning undetermined"
#: A VPN tunnel is up and is blocking IPv6 egress. Consumer VPNs commonly disable
#: or block IPv6 outright as leak protection, so a failing keytest is the EXPECTED
#: result while tunnelled rather than a fault. Same distinction _NOTE_IPV6_ABSENT
#: already draws for an IPv4-only link — "a thing that should work does not" vs
#: "this is the normal condition here" — applied to a fourth case.
_NOTE_IPV6_VPN_BLOCKED = "ipv6 blocked by vpn"
#: The raw-egress probe cannot leave a tunnelled host whose VPN killswitch blocks
#: every non-tunnel egress. Named separately so it is visible, not swallowed.
_NOTE_EGRESS_VPN_BLOCKED = "raw egress blocked by vpn"


# ── Is IPv6 even expected here? ───────────────────────────────────────────────
#
# THE BUG THIS CLOSES (found 2026-08-22). `classify()` returned DEGRADED whenever
# the IPv6 keytest failed, and `_notify` treats anything other than ALL_OK as a
# failing observation. On an IPv4-only link — most home and small-office
# connections — `curl -6` fails on EVERY cycle, forever. After FAILURE_DEBOUNCE
# an episode opens at MEDIUM and never closes, and there was no setting anywhere
# to suppress it. A monitor that reports a permanent fault for a condition that is
# not a fault trains its operator to ignore it, which costs more coverage than the
# check was ever worth.
#
# "IPv6 down" is only a fault where IPv6 is actually provisioned. So measure that
# instead of assuming it.
IPV6_EXPECTED     = "expected"          # a global address exists; a failure is real
IPV6_NOT_PROVISIONED = "not_provisioned"  # IPv4-only link; failure is the norm
IPV6_UNKNOWN      = "unknown"           # could not tell — never guess either way


def ipv6_expectation(runner=None) -> str:
    """Three-valued: is IPv6 provisioned on this host?

    Presence of a GLOBAL-scope IPv6 address is the test. Link-local (`fe80::`)
    addresses exist on virtually every interface whether or not the network
    carries IPv6, so counting them would make every link look IPv6-capable and
    reinstate the exact false positive this exists to remove — `scope global` is
    what distinguishes provisioned from merely present.

    Returns IPV6_UNKNOWN — never a boolean — when the probe itself fails. A failed
    read must not resolve to either real answer: guessing "not provisioned" would
    silently suppress a genuine IPv6 outage, and guessing "expected" would restore
    the permanent false positive. Unknown is a third thing and is reported as one.
    """
    # Resolved at call time, not as a default argument: this function is defined
    # above `_run` (it belongs with the note vocabulary it feeds), and a default
    # of `_run` would be evaluated at def time and raise NameError at import.
    runner = runner or _run
    rc, out = runner(["ip", "-6", "-o", "addr", "show", "scope", "global"])
    if rc == 127:
        return IPV6_UNKNOWN                      # no `ip` binary — cannot tell
    if rc != 0:
        return IPV6_UNKNOWN                      # probe failed; not evidence of absence
    # rc == 0 with empty output is a REAL measurement: the command succeeded and
    # found no global IPv6 address. This is the one place empty means something,
    # and it means it only because the return code proved the instrument ran.
    return IPV6_EXPECTED if out.strip() else IPV6_NOT_PROVISIONED


def _selftest_ipv6_expectation() -> None:
    """Prove this can return all three answers before trusting any of them.

    Runs at import, in the production path. Without it, a probe that always said
    NOT_PROVISIONED would silently disable IPv6 fault reporting everywhere and
    look exactly like a working one.
    """
    cases = [
        (lambda cmd: (0, "eth0 inet6 2001:db8::1/64 scope global"), IPV6_EXPECTED,
         "a global address means IPv6 is provisioned"),
        (lambda cmd: (0, ""), IPV6_NOT_PROVISIONED,
         "rc=0 with no output is a real 'IPv4-only' measurement"),
        (lambda cmd: (1, "Cannot open netlink"), IPV6_UNKNOWN,
         "a failed probe is not evidence of absence"),
        (lambda cmd: (127, "<command not found>"), IPV6_UNKNOWN,
         "a missing `ip` binary is not evidence of absence"),
        (lambda cmd: (124, "<timeout>"), IPV6_UNKNOWN,
         "a timeout is not evidence of absence"),
    ]
    for runner, expected, why in cases:
        got = ipv6_expectation(runner=runner)
        if got != expected:
            raise AssertionError(
                "ipv6_expectation self-test failed (%s): got %r, expected %r"
                % (why, got, expected))
    # A link-local-only host must NOT read as provisioned — the specific mistake
    # that would silently re-open the false positive.
    got = ipv6_expectation(lambda cmd: (0, ""))
    if got != IPV6_NOT_PROVISIONED:
        raise AssertionError("ipv6_expectation self-test: link-local-only host "
                             "must read as not provisioned")


_selftest_ipv6_expectation()


# ── command runner (per-probe isolation: one failing probe never kills the run)─
def _run(cmd, timeout=NET_TIMEOUT):
    """Run a command, return (rc, combined_output). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return 124, "<timeout>"
    except FileNotFoundError:
        return 127, "<command not found>"
    except Exception as e:  # noqa: BLE001 — observe-only, never propagate
        return 1, f"<error: {e}>"


def _curl(host_or_ip, *extra):
    """curl an https endpoint for its HTTP code + time. Returns (ok, code, secs, raw)."""
    cmd = ["curl", "-sS", "-o", "/dev/null", "-w", _CURL_W,
           "--max-time", str(NET_TIMEOUT), *extra, f"https://{host_or_ip}"]
    rc, out = _run(cmd)
    m = _CURL_RE.search(out)
    code = m.group(1) if m else "000"
    secs = float(m.group(2)) if m else None
    ok = (rc == 0 and code != "000")
    return ok, code, secs, out


# ── VPN provider probes (plugins) ─────────────────────────────────────────────
# Each probe detects ONE VPN client. CONTRACT: return None if the client is not
# installed (skip-if-absent — never crash on a box that lacks it); otherwise a
# dict {provider, connected, server, protocol, raw}. `server`/`raw` may carry
# IPs/hostnames, so they go to the FLAT LOG ONLY. The DB sampler records just the
# aggregated `vpn_connected` boolean — provider-agnostic and address-free (Rule 8).
# Add your own provider: write one of these + append it to _VPN_PROBES below.
# Beginner guide: docs/modules/diagnostics/CUSTOM_VPN_PROBE.md
def _probe_pia():
    """Private Internet Access — `piactl get connectionstate`."""
    exe = shutil.which("piactl")
    if not exe:
        return None
    _rc, state = _run([exe, "get", "connectionstate"])
    _r2, region = _run([exe, "get", "region"])
    return {"provider": "PIA", "connected": state.strip() == "Connected",
            "server": region.strip() or None, "protocol": None,
            "raw": f"connectionstate: {state}\nregion: {region}"}


def _probe_mullvad():
    """Mullvad — `mullvad status`."""
    exe = shutil.which("mullvad")
    if not exe:
        return None
    _rc, out = _run([exe, "status"])
    first = (out.splitlines() or [""])[0].strip().lower()
    low = out.lower()
    m = re.search(r"[Cc]onnected to ([^\s,]+)", out)
    proto = "WireGuard" if "wireguard" in low else ("OpenVPN" if "openvpn" in low else None)
    return {"provider": "Mullvad", "connected": first.startswith("connected"),
            "server": m.group(1) if m else None, "protocol": proto, "raw": out}


def _probe_protonvpn():
    """ProtonVPN — `protonvpn-cli status`."""
    exe = shutil.which("protonvpn-cli")
    if not exe:
        return None
    _rc, out = _run([exe, "status"])
    low = out.lower()
    connected = ("connected" in low) and ("no active" not in low) and ("disconnected" not in low)
    srv = re.search(r"[Ss]erver:\s*(\S+)", out)
    prt = re.search(r"[Pp]rotocol:\s*(\S+)", out)
    return {"provider": "ProtonVPN", "connected": connected,
            "server": srv.group(1) if srv else None,
            "protocol": prt.group(1) if prt else None, "raw": out}


def _probe_wireguard():
    """WireGuard — `wg show` (an interface present = a tunnel is up)."""
    exe = shutil.which("wg")
    if not exe:
        return None
    _rc, out = _run([exe, "show"])
    ep = re.search(r"endpoint:\s*(\S+)", out)
    return {"provider": "WireGuard", "connected": "interface:" in out,
            "server": ep.group(1) if ep else None, "protocol": "WireGuard", "raw": out}


def _probe_tailscale():
    """Tailscale — `tailscale status`."""
    exe = shutil.which("tailscale")
    if not exe:
        return None
    _rc, out = _run([exe, "status"])
    low = out.lower()
    connected = bool(out.strip()) and "stopped" not in low and "logged out" not in low
    parts = (out.splitlines() or [""])[0].split()
    return {"provider": "Tailscale", "connected": connected,
            "server": parts[1] if len(parts) > 1 else None,
            "protocol": "WireGuard", "raw": out}


# Register every built-in probe here. Custom probes append to this list (see guide).
_VPN_PROBES = [_probe_pia, _probe_mullvad, _probe_protonvpn, _probe_wireguard, _probe_tailscale]


def _probe_vpn(raw_lines) -> bool:
    """Run every VPN provider probe (each skips cleanly if its client is absent).
    Flat log gets the full per-provider detail (provider/state/server/proto + raw
    output); the DB gets ONLY the returned aggregated boolean. True if any detected
    provider reports connected, else False (incl. no client installed)."""
    connected_any = False
    detected = False
    for probe in _VPN_PROBES:
        try:
            res = probe()
        except Exception:   # a single probe must never kill the cycle (observe-only)
            log.exception("watcher: VPN probe %s failed", getattr(probe, "__name__", "?"))
            res = None
        if not res:
            continue
        detected = True
        raw_lines.append(
            f"  [vpn.{res.get('provider', '?')}] connected={res.get('connected')} "
            f"server={res.get('server')} protocol={res.get('protocol')}"
        )
        for line in (res.get("raw") or "").splitlines():
            raw_lines.append(f"      {line}")
        if res.get("connected"):
            connected_any = True
    if not detected:
        raw_lines.append("  [vpn] no supported VPN client detected")
    return connected_any


# ── config ─────────────────────────────────────────────────────────────────--
def _load_cfg() -> dict:
    g = diag._get_setting
    return {
        "verbose":        g("watcher_verbose", "0"),
        "verbose_until":  g("watcher_verbose_until", ""),
        "log_dir":        g("watcher_log_dir", "/var/log/nemesis/diagnostics"),
        "log_max_mb":     g("watcher_log_max_mb", "50"),
        "log_retain_days": g("watcher_log_retain_days", "14"),
        "samples_max":    g("watcher_samples_max", "2880"),
        "egress_ip":      g("watcher_egress_ip", "1.1.1.1"),
        "api_host":       g("watcher_api_host", "api.anthropic.com"),
    }


def _verbose_now(cfg: dict) -> bool:
    """Verbose iff the flag is set AND (no time-box OR not yet expired). When the
    time-box has passed, auto-revert the flag to quiet (spec §7) and return False.
    """
    if cfg["verbose"] != "1":
        return False
    until = (cfg["verbose_until"] or "").strip()
    if not until:
        return True
    try:
        if datetime.now() < datetime.fromisoformat(until):
            return True
        diag._set_setting("watcher_verbose", "0")   # auto-revert to quiet
        log.info("watcher: verbose time-box expired — reverted to quiet")
        return False
    except ValueError:
        return True


# ── probes (raw text -> flat log; ok booleans -> DB) ──────────────────────────
def _probe(cfg: dict):
    """Run all probes. Returns (flags, latency_ms, note, raw_lines).

    flags: dict of routing_ok/dns_ok/egress_ok/api_ok (bool). raw_lines carries
    the address-bearing detail for the flat log; the caller keeps it OUT of the DB.
    """
    raw = []
    api_host, egress_ip = cfg["api_host"], cfg["egress_ip"]

    def blk(label, rc, out):
        raw.append(f"  [{label}] (rc={rc})")
        for line in (out or "<no output>").splitlines() or ["<no output>"]:
            raw.append(f"      {line}")

    # 1. VPN provider probes (plugins; each skips if its client is absent).
    #    Raw per-provider detail -> flat log; only the aggregated boolean -> DB.
    vpn_connected = _probe_vpn(raw)

    # 2. Tunnel interface present?
    rc, out = _run(["ip", "-o", "link", "show"])
    tun = ""
    for line in out.splitlines():
        m = re.search(r"^\d+:\s+(tun\d+|wg\d+)", line)
        if m:
            tun = m.group(1)
            break
    raw.append(f"  [tunnel.iface] {tun or 'NONE'}")

    # 3. Routing — default route is the routing_ok signal; rest is detail
    rc_def, out_def = _run(["ip", "route", "show", "default"])
    routing_ok = (rc_def == 0 and bool(out_def.strip()))
    blk("route.default", rc_def, out_def)
    blk("ip.rule", *_run(["ip", "rule", "show"]))
    blk(f"route.get.egress({egress_ip})", *_run(["ip", "route", "get", egress_ip]))

    # 4. DNS — resolve the API host (getent mirrors the shell probe)
    rc_dns, out_dns = _run(["getent", "ahostsv4", api_host])
    dns_ok = (rc_dns == 0 and bool(out_dns.strip()))
    api_ip = out_dns.split()[0] if (dns_ok and out_dns.split()) else ""
    blk(f"dns.resolve({api_host})", rc_dns, out_dns)
    if api_ip:
        blk(f"route.get.api({api_ip})", *_run(["ip", "route", "get", api_ip]))
    # ADR 0005 decisive test: source-based client refusal (dig optional)
    if shutil.which("dig"):
        blk("dns.refusal(@127.0.0.1)", *_run(["dig", "+short", "+time=2", "@127.0.0.1", api_host]))
        blk("dns.refusal(@127.0.0.1 -b 127.0.0.1)",
            *_run(["dig", "+short", "+time=2", "-b", "127.0.0.1", "@127.0.0.1", api_host]))

    # 5. Raw egress BY IP (no DNS in path)
    egress_ok, e_code, _e_secs, e_raw = _curl(egress_ip)
    raw.append(f"  [egress.byip({egress_ip})] ok={egress_ok} {e_raw}")

    # 6. KEYTEST — the real upstream dependency, default/-4/-6
    api_ok, a_code, a_secs, a_raw = _curl(api_host)
    v4_ok, _c4, _s4, r4 = _curl(api_host, "-4")
    v6_ok, _c6, _s6, r6 = _curl(api_host, "-6")
    raw.append(f"  [KEYTEST.default({api_host})] ok={api_ok} {a_raw}")
    raw.append(f"  [KEYTEST.ipv4] ok={v4_ok} {r4}")
    raw.append(f"  [KEYTEST.ipv6] ok={v6_ok} {r6}")

    # Is IPv6 even provisioned here? Measured, not assumed — an IPv4-only link
    # otherwise reports DEGRADED on every cycle forever (see ipv6_expectation).
    v6_expect = ipv6_expectation()
    raw.append(f"  [ipv6.expectation] {v6_expect}")

    latency_ms = round(a_secs * 1000, 1) if a_secs is not None else None
    flags = {"routing_ok": routing_ok, "dns_ok": dns_ok,
             "egress_ok": egress_ok, "api_ok": api_ok}
    note = _note(flags, v4_ok, v6_ok, v6_expect, vpn_connected)
    return flags, latency_ms, note, raw, (v4_ok, v6_ok, v6_expect), vpn_connected


def _note(flags, v4_ok, v6_ok, v6_expect=IPV6_EXPECTED,
          vpn_connected=False) -> str:
    if not flags["routing_ok"]:
        return _NOTE_NO_ROUTE
    if not flags["dns_ok"]:
        return _NOTE_DNS_FAIL
    if not flags["egress_ok"]:
        # A killswitch blocks the raw-egress probe by design. Name that condition
        # rather than reporting it as a fault — same treatment as the IPv6 notes.
        return _NOTE_EGRESS_VPN_BLOCKED if vpn_connected else _NOTE_EGRESS_FAIL
    # IPv4 is reported ahead of IPv6 now. On an IPv4-only link an IPv6 failure is
    # expected and uninformative, so letting it win the note would bury a real
    # IPv4 fault behind a permanent one — which is how the old ordering behaved
    # on every IPv4-only box.
    if flags["api_ok"] and not v4_ok:
        return _NOTE_IPV4_FAIL
    if flags["api_ok"] and not v6_ok:
        # Checked BEFORE provisioning state: the address stays on the interface
        # while the tunnel blocks egress, so `ipv6_expectation()` still reports
        # EXPECTED and cannot distinguish this case on its own.
        if vpn_connected:
            return _NOTE_IPV6_VPN_BLOCKED  # expected while tunnelled
        if v6_expect == IPV6_NOT_PROVISIONED:
            return _NOTE_IPV6_ABSENT      # not a fault; stated, not hidden
        if v6_expect == IPV6_UNKNOWN:
            return _NOTE_IPV6_UNKNOWN     # undetermined; stated, not guessed
        return _NOTE_IPV6_FAIL            # provisioned and failing — a real fault
    return ""


def classify(flags: dict, v4_ok: bool, v6_ok: bool,
             v6_expect: str = IPV6_EXPECTED,
             vpn_connected: bool = False) -> str:
    """The is-it-me-or-them verdict (spec §6).

    `v6_expect` decides whether a failed IPv6 keytest counts against the verdict
    at all. Only a link that actually has IPv6 provisioned can have IPv6 "down";
    on an IPv4-only link the failure is the expected result and must not produce
    a DEGRADED verdict on every cycle forever (see `ipv6_expectation`).

    `vpn_connected` does the same job for a VPN tunnel (added 2026-08-30). A
    leak-blocking VPN disables IPv6 egress and blocks the raw-egress probe BY
    DESIGN, so both fail on every cycle for as long as the tunnel is up — the
    identical permanent-episode shape the IPv4-only link produced. It is a
    separate input from `v6_expect` because `ipv6_expectation()` cannot see it:
    that measures whether a global IPv6 ADDRESS exists, and the address stays
    while the tunnel blocks the traffic.

    Both flags default to the strict answer, so a caller that forgets either gets
    the old, noisier verdict rather than a silently more permissive one.
    """
    local_ok = flags["routing_ok"] and flags["dns_ok"] and flags["egress_ok"]
    egress_blocked_by_vpn = False
    if not local_ok:
        # A tunnelled host frequently cannot send the raw-egress probe at all.
        # That DEGRADES rather than escalating to LOCAL_FAIL — but only when
        # routing and DNS are both healthy, so a genuine local fault under a VPN
        # still reports as one. Measured 2026-08-30: a single `egress_ok=0`
        # sample escalated a whole episode to LOCAL_FAIL while routing, DNS and
        # the API were all green.
        if (vpn_connected and flags["routing_ok"] and flags["dns_ok"]
                and not flags["egress_ok"]):
            egress_blocked_by_vpn = True
        else:
            return "LOCAL_FAIL"      # it's us
    if not flags["api_ok"]:
        return "UPSTREAM_FAIL"       # local green, upstream dead — it's them
    # api_ok from here on: the upstream is reachable by SOME address family.
    if not v4_ok:
        return "DEGRADED"            # IPv4 down is always a real degradation
    if egress_blocked_by_vpn:
        return "DEGRADED"            # visible, but not blamed on the host
    if v6_ok:
        return "ALL_OK"
    # IPv6 keytest failed. Whether that is a degradation depends on whether this
    # link has IPv6 at all.
    if vpn_connected:
        return "ALL_OK"              # tunnel blocks IPv6 by design; note says so
    if v6_expect == IPV6_EXPECTED:
        return "DEGRADED"
    # NOT_PROVISIONED -> genuinely fine. UNKNOWN -> we could not establish that a
    # fault exists, and reporting one we cannot substantiate is what produced the
    # permanent-MEDIUM episode. The condition is carried in the NOTE either way,
    # so it is visible rather than swallowed.
    return "ALL_OK"


# ── flat-file writer (raw; rotation + age prune; OUTSIDE the repo) ────────────
def _write_log(cfg: dict, verbose: bool, ts: datetime, summary: str, raw_lines):
    log_dir = cfg["log_dir"]
    try:
        os.makedirs(log_dir, exist_ok=True)
    except PermissionError:
        log.warning("watcher: cannot create log dir %s (permission) — skipping flat log", log_dir)
        return
    except Exception:
        log.exception("watcher: log dir setup failed for %s", log_dir)
        return

    path = os.path.join(log_dir, LOG_BASENAME)
    _rotate_if_needed(path, cfg)
    _prune_old(log_dir, cfg)
    try:
        with open(path, "a") as f:
            if verbose:
                f.write(f"\n===== {ts.isoformat()} =====\n")
                f.write("\n".join(raw_lines) + "\n")
            f.write(summary + "\n")    # quiet mode: just the one summary line
    except Exception:
        log.exception("watcher: flat-log write failed at %s", path)


def _rotate_if_needed(path: str, cfg: dict):
    """Rotate the flat log once it exceeds the configured size.

    The destination name is RESERVED with O_EXCL before the rename, rather than
    handed straight to os.rename. Two callers can reach this at once — the
    diagnostics-watcher daemon loop and a manual `run_once` hand-run both call
    _write_log — and the name carries only one-second granularity. os.rename
    silently REPLACES an existing destination on POSIX, so two rotations in the
    same second destroyed one of the two rotated logs outright.

    O_EXCL makes the name claim atomic: whoever loses gets FileExistsError and
    takes the next suffix, so no rotation is ever discarded. The rename then
    replaces the caller's own empty placeholder, which is safe by construction.
    """
    try:
        max_bytes = int(cfg["log_max_mb"]) * 1024 * 1024
        if not (os.path.exists(path) and os.path.getsize(path) >= max_bytes):
            return
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        directory = os.path.dirname(path)
        for attempt in range(100):
            suffix = "" if attempt == 0 else f".{attempt}"
            dest = os.path.join(directory, f"connectivity-{stamp}{suffix}.log")
            try:
                fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o640)
            except FileExistsError:
                continue          # someone else took this name; try the next
            os.close(fd)
            os.rename(path, dest)
            return
        log.warning("watcher: could not reserve a rotation name for %s after "
                    "100 attempts — leaving the log unrotated", path)
    except Exception:
        log.exception("watcher: rotation check failed for %s", path)


def _prune_old(log_dir: str, cfg: dict):
    try:
        cutoff = datetime.now() - timedelta(days=int(cfg["log_retain_days"]))
        for name in os.listdir(log_dir):
            if not (name.startswith("connectivity-") and name.endswith(".log")):
                continue
            fp = os.path.join(log_dir, name)
            if datetime.fromtimestamp(os.path.getmtime(fp)) < cutoff:
                os.remove(fp)
    except Exception:
        log.exception("watcher: prune failed in %s", log_dir)


# ── sanitized DB sampler (verdicts ONLY — guaranteed address-free) ────────────
def _record(flags, verdict, latency_ms, note, vpn_connected, actor, samples_max):
    def b(x):  # bool -> 0/1, preserve None
        return None if x is None else (1 if x else 0)

    conn = diag._conn()
    try:
        ts = datetime.now().timestamp()
        conn.execute(
            "INSERT INTO diagnostics_connectivity_samples"
            "(ts, routing_ok, dns_ok, egress_ok, api_ok, verdict, latency_ms, vpn_connected, actor, note)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (ts, b(flags["routing_ok"]), b(flags["dns_ok"]), b(flags["egress_ok"]),
             b(flags["api_ok"]), verdict, latency_ms, b(vpn_connected), actor, note),
        )
        count = conn.execute(
            "SELECT COUNT(*) FROM diagnostics_connectivity_samples").fetchone()[0]
        conn.execute(
            "INSERT INTO diagnostics_status"
            "(id, updated_at, verdict, routing_ok, dns_ok, egress_ok, api_ok,"
            " latency_ms, vpn_connected, sample_count, actor, note) VALUES (1,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(id) DO UPDATE SET updated_at=excluded.updated_at,"
            " verdict=excluded.verdict, routing_ok=excluded.routing_ok,"
            " dns_ok=excluded.dns_ok, egress_ok=excluded.egress_ok,"
            " api_ok=excluded.api_ok, latency_ms=excluded.latency_ms,"
            " vpn_connected=excluded.vpn_connected,"
            " sample_count=excluded.sample_count, actor=excluded.actor, note=excluded.note",
            (ts, verdict, b(flags["routing_ok"]), b(flags["dns_ok"]), b(flags["egress_ok"]),
             b(flags["api_ok"]), latency_ms, b(vpn_connected), count, actor, note),
        )
        # Retention: row-count cap (oldest dropped). Flat-file age prune is separate.
        try:
            cap = max(1, int(samples_max))
            conn.execute(
                "DELETE FROM diagnostics_connectivity_samples WHERE id NOT IN "
                "(SELECT id FROM diagnostics_connectivity_samples ORDER BY ts DESC, id DESC LIMIT ?)",
                (cap,),
            )
        except (TypeError, ValueError) as exc:
            # E-DIAG-001 — retention never runs; the table grows unbounded
            # until it becomes a disk problem. best_effort: still inside the
            # record()/commit() path, must not abort the sample write itself.
            _errors_record("E-DIAG-001", {"fn": "_record", "samples_max": samples_max,
                                          "error": f"{type(exc).__name__}: {exc}"})
        conn.commit()
    finally:
        conn.close()


# ── entrypoint ────────────────────────────────────────────────────────────────
def run_once(actor: str = "watcher-service", verbose=None) -> dict:
    """One probe cycle. Writes the flat log + the sanitized DB sample/status.
    Returns the sanitized verdict dict. Never raises (observe-only)."""
    cfg = _load_cfg()
    if verbose is None:
        verbose = _verbose_now(cfg)

    ts = datetime.now()
    flags, latency_ms, note, raw_lines, (v4_ok, v6_ok, v6_expect), vpn_connected = _probe(cfg)
    verdict = classify(flags, v4_ok, v6_ok, v6_expect, vpn_connected)

    summary = (f"{ts.isoformat()} verdict={verdict} "
               f"routing={int(bool(flags['routing_ok']))} dns={int(bool(flags['dns_ok']))} "
               f"egress={int(bool(flags['egress_ok']))} api={int(bool(flags['api_ok']))} "
               f"vpn={int(bool(vpn_connected))} "
               f"lat={latency_ms if latency_ms is not None else '-'}ms"
               + (f" note={note}" if note else ""))

    _write_log(cfg, verbose, ts, summary, raw_lines)
    try:
        _record(flags, verdict, latency_ms, note, vpn_connected, actor, cfg["samples_max"])
    except Exception:
        log.exception("watcher: DB record failed")

    return {"verdict": verdict, "latency_ms": latency_ms, "note": note,
            "vpn_connected": bool(vpn_connected), **flags}


if __name__ == "__main__":
    import sys
    # Hand-run convenience: register the repo's shared alerts.db if the loader hasn't.
    import modules
    try:
        modules.get_shared_db_path()
    except RuntimeError:
        here = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.dirname(os.path.dirname(here))
        _legacy = os.path.join(repo_root, "alert_manager", "alerts.db")
        try:
            sys.path.insert(0, os.path.join(repo_root, "alert_manager"))
            import nemesis_paths
            modules.set_shared_db_path(nemesis_paths.db_path(_legacy))
        except Exception:
            modules.set_shared_db_path(_legacy)
    diag._init_db()
    result = run_once(actor="hand-run", verbose=("--verbose" in sys.argv))
    print(result)
