#!/usr/bin/env python3
"""Nemesis Unified Agent — security endpoint agent for Windows, macOS, and Linux.

Run directly: python agent.py
Starts polling hardware/security data and posting to Nemesis on port 5001.
Listens for commands on localhost:5002.
"""
import ipaddress
import json
import logging
import platform
import signal
import socket
import sys
import time
import threading
import traceback
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

import psutil
import requests

import config
import keyprotect
from modules import hardware, security, scanner

_HERE = __import__("os").path.dirname(__import__("os").path.abspath(__file__))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(__import__("os").path.join(_HERE, "nemesis_agent.log")),
    ],
)
log = logging.getLogger("nemesis_agent")

_running = True
_conf = {}
_platform_name = platform.system()  # 'Windows' | 'Darwin' | 'Linux'
_platform_mod = None
_suricata_mod = None
_agent_start_time = time.time()
_scan_on_reconnect_done = False

# Heartbeat cadence. poll_interval is a live conf key (re-read each cycle); default 300s.
# FLOOR clamps a mis-set/tiny value so it can never hammer the server.
POLL_INTERVAL_DEFAULT = 300
POLL_INTERVAL_FLOOR = 15

# Startup ramp: the first few inter-beat gaps are short so a fresh start/reconnect gets
# quick data (and seeds the future tuning baseline), then it settles to poll_interval.
# Re-armed on EVERY process start (remote workers change networks often). Simple +
# best-effort; full adaptive logic is deferred to the connection-tuning work.
RAMP_START = 30   # seconds — first ramp gap
RAMP_BEATS = 4    # number of ramping beats (geometric doubling) before settling

# Attempts allowed at the startup device-secret prompt before the agent gives up
# and exits WITHOUT starting the poll loop.
MAX_UNLOCK_ATTEMPTS = 3


def _unlock_key_material():
    """Unlock the signing key if it is protected. True if the agent may proceed.

    Runs BEFORE enrollment, because enroll() signs — a locked key would break
    enrollment itself — and because ensure_enrolled() can block for a long time
    waiting on owner approval, which is no place to discover a password is
    needed.

    Deployed tier-4 devices are NEVER prompted: LegacyBackend.is_unlocked()
    returns True because an unencrypted key genuinely needs no secret. The gate
    asks the backend whether it can sign, rather than inspecting a tier name.

    Returns False (rather than raising) so main() can exit quietly on a cancel;
    every failure path leaves the poll loop unstarted.
    """
    import enrollment
    import keyprotect

    backend = enrollment.get_backend()
    if backend is None or not backend.is_provisioned():
        return True         # nothing provisioned yet; enrollment provisions it
    if backend.is_unlocked():
        return True         # tier 4, or already unlocked in this process

    import secret_prompt
    for attempt in range(1, MAX_UNLOCK_ATTEMPTS + 1):
        try:
            secret = secret_prompt.prompt_secret_auto(
                kind=backend.secret_kind(), mode=secret_prompt.UNLOCK)
        except secret_prompt.NoPromptAvailable as e:
            log.error("device secret required but there is no way to ask: %s", e)
            return False
        if secret is None:
            log.error("device secret entry cancelled — agent will not report")
            return False
        try:
            backend.unlock(secret)
            enrollment.set_backend(backend)
            log.info("device key unlocked (tier=%s)", backend.tier_id)
            return True
        except keyprotect.WrongSecret:
            log.warning("incorrect device secret (attempt %d/%d)",
                        attempt, MAX_UNLOCK_ATTEMPTS)
        except keyprotect.KeyProtectError as e:
            # Corrupt/locked-out/unavailable are not retryable by typing again.
            log.error("cannot unlock device key: %s", e)
            return False
    log.error("device key not unlocked after %d attempts — agent will not report",
              MAX_UNLOCK_ATTEMPTS)
    return False


def _resolve_poll_interval(conf):
    """Heartbeat interval (seconds) from conf, floor-clamped and robust to non-numeric
    values. Re-read every cycle so a conf edit takes effect on the next heartbeat."""
    try:
        v = int(conf.get("poll_interval", POLL_INTERVAL_DEFAULT))
    except (TypeError, ValueError):
        v = POLL_INTERVAL_DEFAULT
    return max(POLL_INTERVAL_FLOOR, v)


def _ramp_interval(beat_index, poll_interval):
    """Sleep (seconds) to wait AFTER heartbeat number `beat_index` (0-based). During the
    startup ramp the gap doubles from RAMP_START (30,60,120,240) then settles to
    poll_interval. Never below POLL_INTERVAL_FLOOR, and never SLOWER than poll_interval
    (so a user who set a fast steady cadence isn't slowed by the ramp). Separable +
    best-effort — the deferred adaptive tuning replaces this later."""
    if beat_index >= RAMP_BEATS:
        return poll_interval
    ramp = RAMP_START * (2 ** beat_index)
    return max(POLL_INTERVAL_FLOOR, min(ramp, poll_interval))


def _load_platform_module():
    global _platform_mod
    if _platform_name == "Windows":
        from platforms import windows as pm
    elif _platform_name == "Darwin":
        from platforms import mac as pm
    else:
        from platforms import linux as pm
    _platform_mod = pm
    log.info("Loaded platform module for %s", _platform_name)


def _detect_connection_type(conf):
    """Compare local IP against nemesis_subnet to determine local vs vpn_remote."""
    try:
        subnet_str = conf.get("nemesis_subnet") or ""
        if not subnet_str:
            return "vpn_remote"   # no local subnet configured -> treat as remote
        subnet = ipaddress.ip_network(subnet_str, strict=False)
        hostname = socket.gethostname()
        local_ips = [addr.address for iface_addrs in psutil.net_if_addrs().values()
                     for addr in iface_addrs if addr.family == socket.AF_INET]
        for ip in local_ips:
            if ipaddress.ip_address(ip) in subnet:
                return "local"
    except Exception as e:
        log.debug("connection type detection error: %s", e)
    return "vpn_remote"


def _detect_link_type(conf):
    """WiFi vs ethernet of the PHYSICAL link to the Nemesis server (via the platform
    module; never the Tailscale tunnel). 'unknown' on any failure."""
    try:
        if _platform_mod and hasattr(_platform_mod, "get_link_type"):
            return _platform_mod.get_link_type(conf.get("nemesis_ip"))
    except Exception as e:
        log.debug("link type detection error: %s", e)
    return "unknown"


def _collect_payload(conf):
    device_id   = conf.get("device_id", "unknown")
    device_name = conf.get("device_name", socket.gethostname())
    device_type = _platform_name.lower().replace("darwin", "mac")
    conn_type   = _detect_connection_type(conf)
    link_type   = _detect_link_type(conf)

    # Hardware
    raw_hw = {}
    if _platform_mod:
        try:
            raw_hw = _platform_mod.get_hardware_metrics()
        except Exception as e:
            log.warning("hardware collection error: %s", e)
    hw = hardware.normalize(raw_hw)

    # Security
    sec = {}
    try:
        sec = security.collect(_platform_name)
    except Exception as e:
        log.warning("security collection error: %s", e)

    # Suricata alerts
    suri_alerts = []
    suri_running = False
    suri_profile = None
    if _suricata_mod and _suricata_mod.is_running():
        suri_running = True
        suri_profile = _suricata_mod.get_current_profile()
        suri_alerts  = _suricata_mod.drain_alerts()
        # Auto-switch profile if connection type changed
        expected_profile = _expected_suricata_profile(conn_type, conf)
        if expected_profile != suri_profile:
            rules_dir = __import__("os").path.join(_HERE, "suricata_rules")
            _suricata_mod.switch_profile(expected_profile, rules_dir)
            suri_profile = expected_profile

    # Agent health
    uptime = int(time.time() - _agent_start_time)
    proc = psutil.Process()
    agent_health = {
        "agent_cpu_pct":      round(proc.cpu_percent(interval=0.1), 2),
        "agent_ram_mb":       round(proc.memory_info().rss / (1024 ** 2), 1),
        "agent_uptime_seconds": uptime,
        "suricata_running":   suri_running,
        "suricata_profile":   suri_profile,
        "last_scan_at":       conf.get("last_scan_at") or None,
        "last_scan_result":   _get_last_scan_result(),
        # Key-protection tier, so uneven protection across the fleet is visible
        # rather than silent -- the same argument ADR 0004 (b) makes for engine
        # and ruleset versions. hw_monitor reads agent_health with specific
        # .get() calls, so an unknown key is ignored: the agent can report this
        # today and the dashboard display follows as an approved follow-on.
        "key_protection_tier": _key_protection_tier(),
    }

    return {
        "source":          "nemesis_agent",
        "device_id":       device_id,
        "device_name":     device_name,
        "device_type":     device_type,
        "connection_type": conn_type,
        "link_type":       link_type,
        "timestamp":       datetime.now().isoformat(timespec="seconds"),
        "hardware":        hw,
        "security":        sec,
        "agent_health":    agent_health,
        "suricata_alerts": suri_alerts,
        "scan_result":     None,
    }


def _migrate_key_material():
    """Offer to protect an unencrypted signing key. NEVER blocks startup.

    Operator decision 2026-08-03 — migrate-or-continue. Every currently-enrolled
    device is tier 4, so refusing to start without a password would brick agents
    for users who have no idea one is now required. Declining therefore keeps the
    agent running on the unencrypted key and reports `key_protection_tier: none`,
    which is the honest answer: the fleet view shows exactly which devices are
    still unprotected rather than the product quietly pretending otherwise.

    Every failure path leaves the existing key untouched and usable — the
    migration deletes the plaintext copy only after proving the protected one
    works (see keyprotect/migrate.py).
    """
    import enrollment
    import secret_prompt

    keys_dir = config.keys_dir()
    try:
        if not keyprotect.needs_migration(keys_dir):
            return
    except Exception as e:
        log.debug("could not evaluate key migration: %s", e)
        return

    log.warning("this device's signing key is stored UNENCRYPTED on disk; "
                "offering to protect it")
    try:
        secret = secret_prompt.prompt_secret_auto(
            kind=keyprotect.SECRET_PASSWORD, mode=secret_prompt.CREATE)
    except secret_prompt.NoPromptAvailable as e:
        log.warning("cannot ask for a device password here (%s) — continuing with "
                    "an UNENCRYPTED key", e)
        return
    if secret is None:
        log.warning("device key protection DECLINED — continuing with an "
                    "UNENCRYPTED key; this device will report tier 'none'")
        return

    try:
        backend, _pub = keyprotect.migrate_legacy(secret, keys_dir)
    except keyprotect.KeyProtectError as e:
        log.error("key protection FAILED (%s) — the existing key is untouched, "
                  "continuing", e)
        return

    enrollment.set_backend(backend)
    # The conf pointer now names a file that no longer exists. An actively-false
    # value is worse than an absent one, so clear it rather than leave it.
    try:
        conf = config.load()
        if conf.get("private_key_path"):
            conf["private_key_path"] = ""
            config.save(conf)
    except Exception as e:
        log.debug("could not clear private_key_path: %s", e)
    log.info("device key is now protected (tier=%s)", backend.tier_id)


def _key_protection_tier():
    """Reported tier, or 'unknown' if it cannot be determined.

    'unknown' is deliberately NOT 'none'. A failed read must not masquerade as
    a real measurement -- reporting 'none' here would tell the dashboard this
    device has an unprotected key, which may be false, and would be acted on.
    """
    try:
        return keyprotect.tier_of(config.keys_dir())
    except Exception as e:
        log.debug("could not determine key protection tier: %s", e)
        return "unknown"


def _get_last_scan_result():
    for job in reversed(list(scanner._jobs.values())):
        return job.get("status", "never")
    return "never"


def _expected_suricata_profile(conn_type, conf):
    profile_pref = conf.get("suricata_profile", "auto")
    if profile_pref == "auto":
        return "office" if conn_type == "local" else "roaming"
    return profile_pref


def _sign_heartbeat(device_id, body: bytes):
    """(signed_at, signature) for a heartbeat body, or (None, None) if unavailable.

    Reuses the enrollment keypair — the same key the server already stored and
    already verifies on /enroll and /api/agent/uninstall. No new key material and
    no re-enrollment.

    The signature covers "<device_id>|<signed_at>|<sha256(body)>", where the
    digest is over the EXACT BYTES POSTED. That binds the payload to the
    signature, so a captured signature cannot be replayed over different metrics
    — which matters because the server evaluates scan triggers from this body.

    Best-effort by design: if the key is missing or signing fails, the heartbeat
    is sent UNSIGNED rather than dropped. A server in observe mode accepts and
    logs it; a server in enforce mode rejects it. Losing telemetry outright would
    be a worse failure than an unsigned beat during rollout, and the server —
    not the agent — is where that policy belongs.
    """
    try:
        import hashlib
        from enrollment import _sign
        signed_at = datetime.now().isoformat(timespec="seconds")
        digest = hashlib.sha256(body).hexdigest()
        return signed_at, _sign(f"{device_id}|{signed_at}|{digest}")
    except Exception as e:
        # A locked or missing key is NOT a transient signing glitch, and must not
        # fall into the best-effort unsigned path below. The server runs in
        # observe mode, so it ACCEPTS unsigned heartbeats — swallowing this would
        # silently downgrade the device from authenticated to unauthenticated
        # while it kept reporting and looking healthy. The startup gate should
        # make this unreachable; if it happens anyway, something is wrong enough
        # that continuing is the wrong answer.
        import keyprotect
        if isinstance(e, keyprotect.KeyProtectError):
            raise
        log.warning("could not sign heartbeat (sending unsigned): %s", e)
        return None, None


#: Set once, at startup, by _arm_task_channel(). None means tasks are refused —
#: no anchor pinned, or the verifier failed its own self-test. Deliberately not a
#: bool: the pinned key IS the capability, so there is nothing to get out of sync.
_task_anchor = None


def _arm_task_channel(device_id):
    """Decide, once, whether this device may execute server-sent tasks.

    Refusing costs nothing: no agent executes remote tasks today, so an agent that
    declines them behaves exactly as the whole fleet already does. That is why
    there is no observe mode on this direction — unlike heartbeat auth, failing
    closed here drops nothing.
    """
    global _task_anchor
    try:
        import enrollment
        import tasks as task_mod
        anchor = enrollment.pinned_server_key()
        if anchor is None:
            log.warning("no pinned server key — server-sent tasks will be REFUSED")
            return
        # Prove the verifier can tell good from bad before trusting it with real
        # tasks. A verifier that always accepts, or always rejects, is invisible
        # in production; both look like "the server isn't sending anything".
        task_mod.self_test(anchor, device_id)
        _task_anchor = anchor
        log.info("task channel armed (server key pinned, verifier self-test passed)")
    except Exception as exc:
        log.error("task channel DISABLED: %s", exc)


def _handle_response_tasks(response, device_id):
    """Verify and run any tasks carried by the heartbeat response.

    Execution routes into the SAME `_CommandHandler._dispatch` the loopback
    listener already uses, rather than a second implementation — the new surface
    here is the transport, not the actions.

    Wrapped whole: a malformed response, or a task that misbehaves, must never
    break the heartbeat loop. Telemetry is this loop's primary job.
    """
    if _task_anchor is None:
        return
    try:
        body = response.json()
    except Exception:
        return                      # not JSON, or an older server — nothing to do
    if not isinstance(body, dict):
        return
    envelopes = body.get("tasks") or []
    if not envelopes:
        return

    import tasks as task_mod
    for env in envelopes:
        try:
            verified = task_mod.verify_task(env, device_id, _task_anchor)
        except task_mod.TaskRejected as exc:
            # Refusals are expected traffic, not errors — a replayed or expired
            # task is the protection working. Logged with its typed reason so a
            # rejection is never mistaken for "nothing arrived".
            log.warning("task refused (%s): %s", getattr(exc, "reason", "?"), exc)
            continue
        # CLAIM before executing — one atomic operation, not a check followed by
        # a record. Two concurrent deliveries of the same task cannot both win the
        # claim however they interleave, and a crash after claiming means
        # redelivery is skipped rather than run twice. At-least-once delivery with
        # idempotent execution is the honest contract for a poll channel.
        if not task_mod.claim_task(verified["task_id"], verified["expires_at"]):
            log.warning("task refused (replayed): %s already claimed",
                        verified["task_id"])
            continue
        try:
            result = _CommandHandler._dispatch(None, verified["action"],
                                               verified.get("params") or {})
            log.info("task %s (%s) executed: %s",
                     verified["task_id"][:8], verified["action"], result)
        except Exception as exc:
            log.error("task %s (%s) failed: %s",
                      verified["task_id"][:8], verified["action"], exc)


def _post_payload(conf, payload):
    url = f"http://{conf['nemesis_ip']}:{conf['nemesis_port']}/hw_data"
    try:
        # Serialise ONCE and post the exact bytes we signed. Letting requests
        # re-serialise via json= would sign one byte-sequence and transmit
        # another, and the digest would never match.
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        device_id = payload.get("device_id", "")
        signed_at, signature = _sign_heartbeat(device_id, body)
        headers = {"Content-Type": "application/json"}
        if signed_at and signature:
            headers["X-Nemesis-Device"] = device_id
            headers["X-Nemesis-Signed-At"] = signed_at
            headers["X-Nemesis-Signature"] = signature
        r = requests.post(url, data=body, headers=headers, timeout=10)
        if r.status_code == 200:
            log.info("Posted payload to %s (device=%s conn=%s)",
                     url, payload.get("device_id"), payload.get("connection_type"))
            _handle_response_tasks(r, payload.get("device_id", ""))
        else:
            log.warning("Nemesis returned %d: %s", r.status_code, r.text[:200])
    except requests.exceptions.ConnectionError:
        log.warning("Cannot reach Nemesis at %s (will retry)", url)
    except Exception as e:
        log.error("POST failed: %s", e)


def _poll_loop():
    global _conf, _scan_on_reconnect_done
    # Startup ramp re-arms on every process start: beat counter resets to 0 here, so a
    # restart (or a new machine/network) gets fast fresh beats before settling.
    beat = 0
    log.info("heartbeat ramp armed: %s -> steady poll_interval (RAMP_BEATS=%d)",
             ",".join(str(RAMP_START * (2 ** i)) for i in range(RAMP_BEATS)), RAMP_BEATS)
    while _running:
        try:
            _conf = config.load()
            payload = _collect_payload(_conf)
            _post_payload(_conf, payload)

            # On-reconnect scan
            if (not _scan_on_reconnect_done and
                    _conf.get("scan_on_reconnect", "true").lower() == "true"):
                last = _conf.get("last_scan_at", "")
                if not last or _older_than_24h(last):
                    log.info("scan_on_reconnect: triggering auto-scan")
                    scanner.trigger_scan("/")
                    _scan_on_reconnect_done = True
        except keyprotect.KeyProtectError as e:
            # Ordered BEFORE the broad except deliberately. Nothing in this loop
            # can re-acquire an unusable key, so retrying would only spin -- and
            # the alternative the old code took, swallowing it, meant heartbeats
            # kept flowing unsigned. Stop, and say why.
            log.critical("signing key became unusable (%s) — stopping agent", e)
            _shutdown()
            return
        except Exception as e:
            log.exception("poll_loop error: %s", e)

        steady = _resolve_poll_interval(_conf)
        interval = _ramp_interval(beat, steady)
        beat += 1
        _interruptible_sleep(interval)


def _older_than_24h(iso_str):
    try:
        ts = datetime.fromisoformat(iso_str)
        return (datetime.now() - ts).total_seconds() > 86400
    except Exception:
        return True


def _interruptible_sleep(seconds):
    for _ in range(int(seconds)):
        if not _running:
            break
        time.sleep(1)


# ── Command listener on localhost:5002 ───────────────────────────────────────

class _CommandHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length))
        except Exception:
            self._respond(400, {"error": "bad request"})
            return

        action = body.get("action", "")
        resp   = self._dispatch(action, body)
        self._respond(200, resp)

    def _dispatch(self, action, body):
        if action == "ping":
            return {"ok": True,
                    "device_id":   _conf.get("device_id"),
                    "device_name": _conf.get("device_name", socket.gethostname())}

        if action == "scan":
            scan_id = scanner.trigger_scan(body.get("path", "/"),
                                           body.get("scan_id"))
            return {"ok": True, "scan_id": scan_id}

        if action == "scan_status":
            job = scanner.get_status(body.get("scan_id", ""))
            return {"ok": True, "job": job}

        if action == "restart":
            log.info("Restart command received — exiting")
            threading.Thread(target=_shutdown, daemon=True).start()
            return {"ok": True}

        if action == "notify":
            _send_notification(body.get("title", "Nemesis"),
                               body.get("message", ""),
                               body.get("severity", "info"),
                               body.get("suggested_action", ""))
            return {"ok": True}

        if action == "update_rules":
            _update_suricata_rules(body.get("rules_url"))
            return {"ok": True}

        return {"error": f"unknown action: {action}"}

    def _respond(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)


def _send_notification(title, message, severity, suggested_action):
    full_msg = message
    if suggested_action:
        full_msg += f"\n\nSuggested action: {suggested_action}"
    timeout = 30 if severity == "critical" else 10

    try:
        if _platform_name == "Linux":
            urgency = "critical" if severity == "critical" else (
                "normal" if severity == "warning" else "low")
            __import__("subprocess").run(
                ["notify-send", "-u", urgency, "-t", str(timeout * 1000), title, full_msg],
                check=False, timeout=5,
            )
        else:
            from plyer import notification
            notification.notify(title=title, message=full_msg, timeout=timeout)
    except Exception as e:
        log.warning("notification failed: %s", e)


def _update_suricata_rules(rules_url):
    if not rules_url:
        return
    try:
        r = requests.get(rules_url, timeout=30)
        rules_dir = __import__("os").path.join(_HERE, "suricata_rules")
        __import__("os").makedirs(rules_dir, exist_ok=True)
        profile = _expected_suricata_profile(_detect_connection_type(_conf), _conf)
        dest = __import__("os").path.join(rules_dir, f"{profile}.rules")
        with open(dest, "wb") as f:
            f.write(r.content)
        log.info("Updated rules for profile=%s from %s", profile, rules_url)
    except Exception as e:
        log.error("update_rules failed: %s", e)


def _start_command_listener():
    def _serve():
        server = HTTPServer(("127.0.0.1", 5002), _CommandHandler)
        log.info("Command listener on localhost:5002")
        server.serve_forever()
    t = threading.Thread(target=_serve, daemon=True, name="cmd-listener")
    t.start()


def _shutdown(*_):
    global _running
    _running = False
    if _suricata_mod:
        _suricata_mod.stop()
    # L1 fail-safe: if DNS enforcement was active, revert it on shutdown so the box is
    # never left with enforced DNS when the agent stops. No-op if never enforced.
    try:
        import dns_enforce
        dns_enforce.restore()
    except Exception:
        pass
    # L2 fail-safe: stop the divert loop + close the WinDivert handle so the filter is
    # removed and traffic flows normally when the agent stops. No-op if never started.
    try:
        import l2_windivert
        l2_windivert.stop()
    except Exception:
        pass
    sys.exit(0)


def main():
    global _conf, _suricata_mod

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    log.info("Nemesis Agent starting (platform=%s)", _platform_name)

    _conf = config.load()

    # Device-secret gate. Placed above enrollment because enroll() SIGNS, so a
    # locked key would break enrollment itself, and because ensure_enrolled()
    # can block for a long time awaiting owner approval. Returns False on
    # cancel/failure, and every such path exits WITHOUT starting the poll loop --
    # the agent must never fall through to sending unsigned heartbeats.
    if not _unlock_key_material():
        log.error("Device key unavailable — agent will not report. Exiting.")
        return

    # Tier 4 -> tier 3. Placed after the unlock gate so both key-state
    # transitions happen in one place, and before enrollment because enroll()
    # signs — better to be on the final backend by then than to switch mid-flight.
    _migrate_key_material()

    # Owner-gated enrollment: block until the owner approves this device in the
    # Nemesis dashboard before starting the /hw_data telemetry loop. Backward-
    # compatible — an already-approved (or grandfathered) device passes straight
    # through. The keypair signature on /enroll is the agent's auth.
    try:
        import enrollment
        approved_id = enrollment.ensure_enrolled(_conf)
    except Exception:
        log.exception("enrollment failed")
        approved_id = None
    if not approved_id:
        log.error("Device not approved — agent will not report. Exiting.")
        return
    _conf = config.load()

    # Decide once whether server-sent tasks may run (ADR 0004 Stage 1). After
    # enrollment, so approved_id is the device identity tasks are bound to.
    _arm_task_channel(approved_id)

    _load_platform_module()

    # Optionally start local Suricata IDS
    if _conf.get("suricata_enabled", "false").lower() == "true":
        try:
            from modules import suricata_local
            _suricata_mod = suricata_local
            profile = _expected_suricata_profile(_detect_connection_type(_conf), _conf)
            rules_dir = __import__("os").path.join(_HERE, "suricata_rules")
            __import__("os").makedirs(rules_dir, exist_ok=True)
            suricata_local.start(profile, rules_dir)
        except Exception as e:
            log.warning("Suricata IDS init failed: %s", e)

    _start_command_listener()

    # L1 (DNS plumbing, default OFF): apply a configured DNS target only if explicitly
    # enabled (dns_enforce_enabled=true + dns_enforce_target set) — otherwise a no-op.
    # FAIL-OPEN: any failure restores the original DNS. NOT yet pointed at the tunnel
    # Pi-hole (ADR 0005 blocker). Restored on shutdown by _shutdown().
    try:
        import dns_enforce
        dns_enforce.enforce_if_configured(_conf)
    except Exception:
        log.exception("dns enforce (L1) init failed — continuing")

    # Feature 6 (observation-only): build + measure the local IP-reputation cache
    # once at startup. Best-effort — NEVER enforces, blocks, or touches traffic, and
    # any failure is swallowed so the poll loop / telemetry is unaffected.
    if _conf.get("reputation_cache_enabled", "true").lower() == "true":
        try:
            import reputation_cache
            reputation_cache.run(_conf)
        except Exception:
            log.exception("reputation cache (observational) init failed — continuing")

    # L2 (WinDivert enforcement, default OFF): reputation-gated blocking on TCP
    # handshake-initiation, BIDIRECTIONAL (outbound SYN + outbound SYN-ACK -> blocks
    # outbound-to-bad-IP and inbound-from-bad-IP), fed by the Feature-6 cache. Fail-open
    # on handle-open failure; a stall-watchdog force-closes the handle on a hang; any
    # exception closes the handle (traffic restored). Runs in daemon threads -- never
    # blocks the poll loop.
    if _conf.get("l2_enforce_enabled", "false").lower() == "true":
        try:
            import l2_windivert
            l2_windivert.start_background(_conf)
        except Exception:
            log.exception("L2 WinDivert init failed — continuing (fail-open)")

    # Block in poll loop
    _poll_loop()


if __name__ == "__main__":
    if "--lhm-probe" in sys.argv:
        # Diagnostic (Windows/Method B): exercise the in-process LibreHardwareMonitor
        # sensor binding and print the stage-by-stage result, then exit WITHOUT
        # starting the agent. Validates the frozen bundle; also a field-debug tool.
        from platforms import lhm_inproc
        print(json.dumps(lhm_inproc.probe(), indent=2, default=str))
        lhm_inproc.close()
    else:
        main()
