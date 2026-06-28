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

    # 1. VPN state (optional plugin — skip cleanly if piactl absent)
    piactl = shutil.which("piactl")
    if piactl:
        for k in ("connectionstate", "vpnip", "pubip"):
            rc, out = _run([piactl, "get", k])
            raw.append(f"  [pia.{k}] (rc={rc}) {out}")
    else:
        raw.append("  [pia] piactl not present — VPN probe skipped")

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

    latency_ms = round(a_secs * 1000, 1) if a_secs is not None else None
    flags = {"routing_ok": routing_ok, "dns_ok": dns_ok,
             "egress_ok": egress_ok, "api_ok": api_ok}
    note = _note(flags, v4_ok, v6_ok)
    return flags, latency_ms, note, raw, (v4_ok, v6_ok)


def _note(flags, v4_ok, v6_ok) -> str:
    if not flags["routing_ok"]:
        return _NOTE_NO_ROUTE
    if not flags["dns_ok"]:
        return _NOTE_DNS_FAIL
    if not flags["egress_ok"]:
        return _NOTE_EGRESS_FAIL
    if flags["api_ok"] and not v6_ok:
        return _NOTE_IPV6_FAIL
    if flags["api_ok"] and not v4_ok:
        return _NOTE_IPV4_FAIL
    return ""


def classify(flags: dict, v4_ok: bool, v6_ok: bool) -> str:
    """The is-it-me-or-them verdict (spec §6)."""
    local_ok = flags["routing_ok"] and flags["dns_ok"] and flags["egress_ok"]
    if not local_ok:
        return "LOCAL_FAIL"          # it's us
    if flags["api_ok"] and v4_ok and v6_ok:
        return "ALL_OK"
    if flags["api_ok"]:
        return "DEGRADED"            # reachable overall, one variant down
    return "UPSTREAM_FAIL"           # local green, upstream dead — it's them


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
    try:
        max_bytes = int(cfg["log_max_mb"]) * 1024 * 1024
        if os.path.exists(path) and os.path.getsize(path) >= max_bytes:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            os.rename(path, os.path.join(os.path.dirname(path), f"connectivity-{stamp}.log"))
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
def _record(flags, verdict, latency_ms, note, actor, samples_max):
    def b(x):  # bool -> 0/1, preserve None
        return None if x is None else (1 if x else 0)

    conn = diag._conn()
    try:
        ts = datetime.now().timestamp()
        conn.execute(
            "INSERT INTO diagnostics_connectivity_samples"
            "(ts, routing_ok, dns_ok, egress_ok, api_ok, verdict, latency_ms, actor, note)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (ts, b(flags["routing_ok"]), b(flags["dns_ok"]), b(flags["egress_ok"]),
             b(flags["api_ok"]), verdict, latency_ms, actor, note),
        )
        count = conn.execute(
            "SELECT COUNT(*) FROM diagnostics_connectivity_samples").fetchone()[0]
        conn.execute(
            "INSERT INTO diagnostics_status"
            "(id, updated_at, verdict, routing_ok, dns_ok, egress_ok, api_ok,"
            " latency_ms, sample_count, actor, note) VALUES (1,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(id) DO UPDATE SET updated_at=excluded.updated_at,"
            " verdict=excluded.verdict, routing_ok=excluded.routing_ok,"
            " dns_ok=excluded.dns_ok, egress_ok=excluded.egress_ok,"
            " api_ok=excluded.api_ok, latency_ms=excluded.latency_ms,"
            " sample_count=excluded.sample_count, actor=excluded.actor, note=excluded.note",
            (ts, verdict, b(flags["routing_ok"]), b(flags["dns_ok"]), b(flags["egress_ok"]),
             b(flags["api_ok"]), latency_ms, count, actor, note),
        )
        # Retention: row-count cap (oldest dropped). Flat-file age prune is separate.
        try:
            cap = max(1, int(samples_max))
            conn.execute(
                "DELETE FROM diagnostics_connectivity_samples WHERE id NOT IN "
                "(SELECT id FROM diagnostics_connectivity_samples ORDER BY ts DESC, id DESC LIMIT ?)",
                (cap,),
            )
        except (TypeError, ValueError):
            pass
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
    flags, latency_ms, note, raw_lines, (v4_ok, v6_ok) = _probe(cfg)
    verdict = classify(flags, v4_ok, v6_ok)

    summary = (f"{ts.isoformat()} verdict={verdict} "
               f"routing={int(bool(flags['routing_ok']))} dns={int(bool(flags['dns_ok']))} "
               f"egress={int(bool(flags['egress_ok']))} api={int(bool(flags['api_ok']))} "
               f"lat={latency_ms if latency_ms is not None else '-'}ms"
               + (f" note={note}" if note else ""))

    _write_log(cfg, verbose, ts, summary, raw_lines)
    try:
        _record(flags, verdict, latency_ms, note, actor, cfg["samples_max"])
    except Exception:
        log.exception("watcher: DB record failed")

    return {"verdict": verdict, "latency_ms": latency_ms, "note": note, **flags}


if __name__ == "__main__":
    import sys
    # Hand-run convenience: register the repo's shared alerts.db if the loader hasn't.
    import modules
    try:
        modules.get_shared_db_path()
    except RuntimeError:
        here = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.dirname(os.path.dirname(here))
        modules.set_shared_db_path(os.path.join(repo_root, "alert_manager", "alerts.db"))
    diag._init_db()
    result = run_once(actor="hand-run", verbose=("--verbose" in sys.argv))
    print(result)
