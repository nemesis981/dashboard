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


def _collect_payload(conf):
    device_id   = conf.get("device_id", "unknown")
    device_name = conf.get("device_name", socket.gethostname())
    device_type = _platform_name.lower().replace("darwin", "mac")
    conn_type   = _detect_connection_type(conf)

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
    }

    return {
        "source":          "nemesis_agent",
        "device_id":       device_id,
        "device_name":     device_name,
        "device_type":     device_type,
        "connection_type": conn_type,
        "timestamp":       datetime.now().isoformat(timespec="seconds"),
        "hardware":        hw,
        "security":        sec,
        "agent_health":    agent_health,
        "suricata_alerts": suri_alerts,
        "scan_result":     None,
    }


def _get_last_scan_result():
    for job in reversed(list(scanner._jobs.values())):
        return job.get("status", "never")
    return "never"


def _expected_suricata_profile(conn_type, conf):
    profile_pref = conf.get("suricata_profile", "auto")
    if profile_pref == "auto":
        return "office" if conn_type == "local" else "roaming"
    return profile_pref


def _post_payload(conf, payload):
    url = f"http://{conf['nemesis_ip']}:{conf['nemesis_port']}/hw_data"
    try:
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code == 200:
            log.info("Posted payload to %s (device=%s conn=%s)",
                     url, payload.get("device_id"), payload.get("connection_type"))
        else:
            log.warning("Nemesis returned %d: %s", r.status_code, r.text[:200])
    except requests.exceptions.ConnectionError:
        log.warning("Cannot reach Nemesis at %s (will retry)", url)
    except Exception as e:
        log.error("POST failed: %s", e)


def _poll_loop():
    global _conf, _scan_on_reconnect_done
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
        except Exception as e:
            log.exception("poll_loop error: %s", e)

        interval = int(_conf.get("poll_interval", 300))
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
    sys.exit(0)


def main():
    global _conf, _suricata_mod

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    log.info("Nemesis Agent starting (platform=%s)", _platform_name)

    _conf = config.load()

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

    # Block in poll loop
    _poll_loop()


if __name__ == "__main__":
    main()
