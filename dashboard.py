from flask import Flask, jsonify, request
import requests
import subprocess
import sqlite3
import json
import html
import os
import re
import sys
import time
import logging
from datetime import datetime, timedelta

log = logging.getLogger(__name__)

_suricata_cache = {"ts": 0.0, "lines": []}
_SURICATA_CACHE_TTL = 5.0

_alert_24h_cache = {"ts": 0.0, "data": None}
_ALERT_24H_CACHE_TTL = 60.0
_alert_counts_cache = {"ts": 0.0, "data": None, "date": None}
_ALERT_COUNTS_CACHE_TTL = 60.0
_svc_cache = {"ts": 0.0, "data": None}
_SVC_CACHE_TTL = 30.0
_vpn_cache = {"ts": 0.0, "data": None}
_VPN_CACHE_TTL = 30.0

HEALTH_SERVICES = [
    "pihole-FTL", "clamav-daemon", "suricata",
    "dashboard", "device-scanner",
    "alert-watcher", "hw-monitor", "watchdog",
]

WATCHDOG_LOG_PATH = "/home/paul/alert_manager/watchdog.log"
# "HW alert sent: KEY (breach message)"  — breach present
_HW_ALERT_SENT_RE   = re.compile(r"HW alert sent: (\S+) \((.+)\)")
# "HW alert email failed: KEY (...)"     — no breach, key only
_HW_ALERT_FAILED_RE = re.compile(r"HW alert email failed: (\S+)")
_SVC_ALERT_RE = re.compile(r"(?:Sent|Failed to send) alert email for (\S+)")

sys.path.insert(0, "/home/paul/alert_manager")
from ip_enrichment import enrich_ip
from firewall import parse_alert, ufw_delete, ufw_deny_append
import hw_monitor
import modules_loader

hw_monitor.init_db()

app = Flask(__name__)

PIHOLE_IP = "192.168.4.69:8080"
PIHOLE_PASSWORD = os.environ.get("PIHOLE_PASSWORD", "")
DB_PATH = "/home/paul/alert_manager/alerts.db"
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")
MODULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules")

modules_loader.init(app, DB_PATH, MODULES_DIR)

pihole_session = {"sid": None}

def get_pihole_token():
    try:
        if pihole_session["sid"]:
            headers = {"sid": pihole_session["sid"]}
            test = requests.get(f"http://{PIHOLE_IP}/api/auth", headers=headers, timeout=3)
            if test.json().get("session", {}).get("valid"):
                return pihole_session["sid"]
        r = requests.post(f"http://{PIHOLE_IP}/api/auth", json={"password": PIHOLE_PASSWORD}, timeout=3)
        sid = r.json().get("session", {}).get("sid")
        pihole_session["sid"] = sid
        return sid
    except Exception as e:
        log.exception("get_pihole_token failed: %s", e)
        return None

def get_pihole_stats():
    try:
        token = get_pihole_token()
        if not token:
            return None
        headers = {"sid": token}
        response = requests.get(f"http://{PIHOLE_IP}/api/stats/summary", headers=headers, timeout=3)
        return response.json()
    except Exception as e:
        log.exception("get_pihole_stats failed: %s", e)
        return None

def get_clamav_status():
    try:
        result = subprocess.run(
            ["sudo", "systemctl", "status", "clamav-daemon"],
            capture_output=True, text=True
        )
        return "Running" if "active (running)" in result.stdout else "Stopped"
    except Exception as e:
        log.exception("get_clamav_status failed: %s", e)
        return "Unknown"

def get_system_status():
    try:
        cpu = subprocess.run(["top", "-bn1"], capture_output=True, text=True)
        memory = subprocess.run(["free", "-h"], capture_output=True, text=True)
        disk = subprocess.run(["df", "-h", "/"], capture_output=True, text=True)
        return {
            "cpu": cpu.stdout.split("\n")[2],
            "memory": memory.stdout.split("\n")[1],
            "disk": disk.stdout.split("\n")[1]
        }
    except Exception as e:
        log.exception("get_system_status failed: %s", e)
        return {"cpu": "Unknown", "memory": "Unknown", "disk": "Unknown"}

def get_suricata_alerts():
    now = time.monotonic()
    if now - _suricata_cache["ts"] < _SURICATA_CACHE_TTL:
        return _suricata_cache["lines"]
    try:
        result = subprocess.run(
            ["sudo", "tail", "-n", "100", "/var/log/suricata/fast.log"],
            capture_output=True, text=True
        )
        lines = [l for l in result.stdout.strip().split("\n") if l]
        _suricata_cache["lines"] = lines
        _suricata_cache["ts"] = now
        return lines
    except Exception as e:
        log.exception("get_suricata_alerts failed: %s", e)
        return []

def get_db_alert(rule_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM alerts WHERE rule_id = ?", (rule_id,))
        result = c.fetchone()
        conn.close()
        return result
    except Exception as e:
        log.exception("get_db_alert failed for rule_id=%s: %s", rule_id, e)
        return None

def get_alert_counts():
    """Count today's Suricata fast.log P1/P2/P3 alerts.

    Reads a deep tail of fast.log and filters by the today date prefix.
    The previous version only sampled the last 100 lines, so a burst of P3 noise
    would push P1/P2 entries off the window and report counts as 0.
    """
    try:
        today = datetime.now().strftime("%m/%d/%Y")
        now_mono = time.monotonic()
        cached = _alert_counts_cache.get("data")
        if (cached
                and _alert_counts_cache.get("date") == today
                and now_mono - _alert_counts_cache["ts"] < _ALERT_COUNTS_CACHE_TTL):
            return cached
        result = subprocess.run(
            ["sudo", "tail", "-n", "200000", "/var/log/suricata/fast.log"],
            capture_output=True, text=True, timeout=30,
        )
        prefix = today + "-"
        p1 = p2 = p3 = 0
        for line in result.stdout.splitlines():
            if not line.startswith(prefix):
                continue
            if "Priority: 1" in line:
                p1 += 1
            elif "Priority: 2" in line:
                p2 += 1
            elif "Priority: 3" in line:
                p3 += 1
        data = {"total": p1 + p2 + p3, "p1": p1, "p2": p2, "p3": p3}
        _alert_counts_cache["data"] = data
        _alert_counts_cache["ts"] = now_mono
        _alert_counts_cache["date"] = today
        log.info("get_alert_counts: today=%s p1=%d p2=%d p3=%d total=%d",
                 today, p1, p2, p3, data["total"])
        return data
    except Exception as e:
        log.exception("get_alert_counts failed: %s", e)
        return {"total": 0, "p1": 0, "p2": 0, "p3": 0}

def get_active_alerts():
    try:
        alerts = get_suricata_alerts()
        today = datetime.now().strftime("%m/%d/%Y")
        active = []
        seen_rules = set()
        for alert in reversed(alerts):
            if today not in alert:
                continue
            if "Priority: 1" not in alert and "Priority: 2" not in alert:
                continue
            parsed = parse_alert(alert)
            if not parsed or parsed["rule_id"] in seen_rules:
                continue
            seen_rules.add(parsed["rule_id"])
            db_alert = get_db_alert(parsed["rule_id"])
            if db_alert and db_alert[7] == "ignore":
                continue
            active.append(parsed)
        return active[:10]
    except Exception as e:
        log.exception("get_active_alerts failed: %s", e)
        return []

def get_review_queue():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT rule_id, rule_name, classification, times_seen, last_seen, src_ip
            FROM alerts
            WHERE risk_level = 'HIGH' AND action = 'pending'
            ORDER BY last_seen DESC
            LIMIT 20
        """)
        rows = c.fetchall()
        conn.close()
        return [
            {
                "rule_id": r[0] or "",
                "rule_name": r[1] or "",
                "classification": r[2] or "",
                "times_seen": r[3] or 1,
                "last_seen": r[4] or "",
                "src_ip": r[5] or "",
            }
            for r in rows
        ]
    except Exception as e:
        log.exception("get_review_queue failed: %s", e)
        return []

def get_device_name(mac, ip):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT friendly_name, device_type, trusted FROM devices WHERE mac = ?", (mac.lower(),))
        result = c.fetchone()
        conn.close()
        if result:
            return result
        return (ip, "Unknown", 0)
    except Exception as e:
        log.exception("get_device_name failed for mac=%s ip=%s: %s", mac, ip, e)
        return (ip, "Unknown", 0)

def get_network_devices():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT mac, ip, friendly_name, device_type, trusted FROM devices ORDER BY ip")
        db_devices = c.fetchall()
        conn.close()
        devices = []
        for d in db_devices:
            devices.append({
                "ip": d[1],
                "mac": d[0],
                "vendor": d[3],
                "friendly_name": d[2],
                "device_type": d[3],
                "trusted": d[4],
                "offline": False
            })
        return sorted(devices, key=lambda x: x["ip"])
    except Exception as e:
        return []

def _ensure_audit_log_table():
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TIMESTAMP NOT NULL,
                rule_id TEXT,
                ip TEXT,
                action TEXT NOT NULL,
                user TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts)")
        conn.commit()
    finally:
        conn.close()


def _audit(action, rule_id=None, ip=None):
    """Record a state-changing decision. `user` is derived from request.remote_addr."""
    try:
        _ensure_audit_log_table()
        try:
            user = request.remote_addr or "unknown"
        except RuntimeError:
            user = "system"
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        try:
            c = conn.cursor()
            c.execute(
                "INSERT INTO audit_log (ts, rule_id, ip, action, user) VALUES (?, ?, ?, ?, ?)",
                (datetime.now().isoformat(), rule_id, ip, action, user),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        log.exception("audit log insert failed (action=%s rule_id=%s ip=%s): %s",
                      action, rule_id, ip, e)


def _ensure_quarantines_table():
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS quarantines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP NOT NULL,
                status TEXT NOT NULL DEFAULT 'active'
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_quarantines_active ON quarantines(status, expires_at)")
        conn.commit()
    finally:
        conn.close()


def get_active_quarantines():
    _ensure_quarantines_table()
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            SELECT q.id, q.ip, q.rule_id, q.expires_at, q.created_at,
                   a.rule_name, a.priority, a.risk_level
            FROM quarantines q
            LEFT JOIN alerts a ON q.rule_id = a.rule_id
            WHERE q.status = 'active'
            ORDER BY q.created_at DESC
        """)
        rows = c.fetchall()
        # enrichment is in a separate table; query individually to keep the join simple
        enrich = {}
        if rows:
            ips = list({r[1] for r in rows})
            placeholders = ",".join("?" * len(ips))
            c.execute(
                f"SELECT ip, country, city, threat_level FROM ip_enrichment WHERE ip IN ({placeholders})",
                ips,
            )
            for ip, country, city, threat in c.fetchall():
                enrich[ip] = {"country": country, "city": city, "threat_level": threat}
    finally:
        conn.close()
    out = []
    now = datetime.now()
    for q_id, ip, rule_id, expires_at, created_at, rule_name, priority, risk_level in rows:
        try:
            exp_dt = datetime.fromisoformat(expires_at)
            minutes_remaining = max(0, int((exp_dt - now).total_seconds() / 60))
        except ValueError:
            minutes_remaining = 0
        e = enrich.get(ip, {})
        out.append({
            "id": q_id,
            "ip": ip,
            "rule_id": rule_id,
            "rule_name": rule_name or "",
            "priority": priority,
            "risk_level": risk_level or e.get("threat_level") or "",
            "country": e.get("country"),
            "city": e.get("city"),
            "expires_at": expires_at,
            "created_at": created_at,
            "minutes_remaining": minutes_remaining,
        })
    return out


def render_quarantine_banner_html(quarantines):
    if not quarantines:
        return ""
    rows = []
    for q in quarantines:
        loc_parts = [p for p in (q.get("city"), q.get("country")) if p]
        loc = f" ({html.escape(', '.join(loc_parts))})" if loc_parts else ""
        rows.append(f"""<div class="q-row">
            <div class="q-info">
                <strong style="color:#ff4444">{html.escape(q['ip'])}</strong>{loc}
                &mdash; rule {html.escape(str(q['rule_id']))} {html.escape(q['rule_name'][:60])}
                <br><span style="color:#aaa;font-size:0.85em">Expires in {q['minutes_remaining']} min</span>
            </div>
            <div class="q-actions">
                <button class="btn btn-block" onclick="confirmQuarantine({q['id']})">✓ Confirm</button>
                <button class="btn btn-ignore" onclick="liftQuarantine({q['id']}, {json.dumps(q['ip'])})">↻ Lift</button>
            </div>
        </div>""")
    return "".join(rows)


def render_alerts_html(active_alerts):
    if not active_alerts:
        return ("<tr><td colspan=5 style='color:#00ff88'>"
                "<span class='tier-text'"
                " data-beginner='✓ All clear — no threats need your attention right now'"
                " data-intermediate='✓ No active P1/P2 alerts requiring attention'"
                " data-pro='✓ No active P1/P2'"
                ">✓ No active P1/P2 alerts requiring attention</span></td></tr>")
    parts = []
    for alert in active_alerts:
        priority = alert["priority"]
        color = "#ff4444" if priority == 1 else "#ffaa00"
        label = "P1 CRITICAL" if priority == 1 else "P2 HIGH"
        rule_name = alert["rule_name"][:50] if alert["rule_name"] else "Unknown"
        timestamp = alert.get("timestamp", "") or "—"
        onclick = html.escape(f"viewAlert({json.dumps(str(alert['rule_id']))}, {json.dumps(alert['raw'])})")
        parts.append(f"""<tr>
            <td><span style="color:{color}">{label}</span></td>
            <td style="font-size:0.8em;white-space:nowrap;color:#aaa">{html.escape(timestamp)}</td>
            <td style="font-size:0.8em">{html.escape(rule_name)}</td>
            <td style="font-size:0.8em">{html.escape(alert["src_ip"])}</td>
            <td><button onclick="{onclick}"
                style="background:#00d4ff;color:#1a1a2e;border:none;padding:3px 8px;cursor:pointer;border-radius:3px">
                View</button></td>
        </tr>""")
    return "".join(parts)

def render_review_queue_html(items):
    if not items:
        return ("<tr><td colspan=6 style='color:#00ff88;padding:10px'>"
                "<span class='tier-text'"
                " data-beginner='✓ Nothing suspicious needs your review right now'"
                " data-intermediate='✓ Review queue is clear — no HIGH risk alerts pending'"
                " data-pro='✓ Queue empty'"
                ">✓ Review queue is clear — no HIGH risk alerts pending</span></td></tr>")
    parts = []
    for item in items:
        ts = item["last_seen"][:16].replace("T", " ") if item["last_seen"] else "—"
        rule_name = item["rule_name"][:50] if item["rule_name"] else "Unknown"
        classification = item["classification"][:35] if item["classification"] else "—"
        src_ip = item["src_ip"] or "—"
        onclick = html.escape(f"viewAlert({json.dumps(str(item['rule_id']))}, {json.dumps('')})")
        parts.append(f"""<tr>
            <td style="font-size:0.8em;white-space:nowrap;color:#aaa">{html.escape(ts)}</td>
            <td style="font-size:0.8em">{html.escape(rule_name)}</td>
            <td style="font-size:0.8em">{html.escape(src_ip)}</td>
            <td style="font-size:0.8em;color:#aaa">{html.escape(classification)}</td>
            <td style="font-size:0.8em;text-align:center">{html.escape(str(item['times_seen']))}</td>
            <td><button onclick="{onclick}"
                style="background:#ff8800;color:#1a1a2e;border:none;padding:3px 8px;cursor:pointer;border-radius:3px;font-weight:bold">
                View</button></td>
        </tr>""")
    return "".join(parts)

def render_devices_html(devices):
    parts = []
    for d in devices:
        trusted = d.get("trusted", 0)
        offline = d.get("offline", False)
        trust_icon = "✅" if trusted else "❓"
        status_color = "#888" if offline else "#eee"
        status = " (offline)" if offline else ""
        onclick = html.escape(f"editDevice({json.dumps(d['mac'])}, {json.dumps(d['friendly_name'])}, {json.dumps(d['device_type'])})")
        parts.append(f"""<tr style="color:{status_color}">
            <td>{html.escape(d["ip"])}{status}</td>
            <td>
                <span id="name-{d["mac"].replace(":","")}">{html.escape(d["friendly_name"])}</span>
                <button onclick="{onclick}"
                    style="background:none;border:1px solid #00d4ff;color:#00d4ff;padding:2px 6px;cursor:pointer;border-radius:3px;margin-left:5px;font-size:0.75em">
                    ✏️</button>
            </td>
            <td style="font-size:0.8em">{html.escape(d["device_type"])}</td>
            <td style="font-size:0.8em">{html.escape(d["mac"])}</td>
            <td>{trust_icon}</td>
        </tr>""")
    return "".join(parts)

def get_pihole_summary():
    stats = get_pihole_stats()
    if not stats:
        return {"total": "N/A", "blocked": "N/A", "percent": "N/A"}
    q = stats.get("queries", {})
    percent = q.get("percent_blocked", "N/A")
    if isinstance(percent, (int, float)):
        percent = f"{round(percent, 1):g}"
    return {
        "total": q.get("total", "N/A"),
        "blocked": q.get("blocked", "N/A"),
        "percent": percent,
    }

@app.route("/api/stats")
def api_stats():
    quarantines = get_active_quarantines()
    try:
        hw_live = hw_monitor.get_live_metrics()
    except Exception as e:
        log.exception("hw_monitor.get_live_metrics failed: %s", e)
        hw_live = None
    alerts_24h = get_24h_alert_stats()
    svc_status = get_services_status()
    health = compute_health_score(hw_live, alerts_24h, svc_status)
    review_queue = get_review_queue()
    vpn = get_vpn_status()
    vpn_status_str = vpn.get("status", "Disconnected")
    try:
        hw_alerts = hw_monitor.get_hw_alerts()
    except Exception:
        hw_alerts = []
    return jsonify({
        "now": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "pihole": get_pihole_summary(),
        "alert_counts": get_alert_counts(),
        "alerts_html": render_alerts_html(get_active_alerts()),
        "devices_html": render_devices_html(get_network_devices()),
        "quarantines": quarantines,
        "quarantine_banner_html": render_quarantine_banner_html(quarantines),
        "hw": hw_live,
        "hw_alerts": hw_alerts,
        "alert_24h": {"total": alerts_24h["total"], "color": alert_color(alerts_24h["total"])},
        "health": {"score": health["score"], "color": health["color"]},
        "review_queue_count": len(review_queue),
        "review_queue_html": render_review_queue_html(review_queue),
        "vpn": {
            "provider": vpn.get("provider"),
            "status": vpn_status_str,
            "vpn_ip": vpn.get("vpn_ip"),
        },
        "module_cards_html": "".join(
            h for _, h in modules_loader.get_module_cards()
        ),
    })


def get_24h_alert_stats():
    """Count hardware/system alerts emitted by the watchdog in the last 24h.

    Sources: thermal/fan threshold breaches ("HW alert sent: <key>" or
    "HW alert email failed: <key>") and service-down escalations
    ("Sent alert email for <svc>" or "Failed to send alert email for <svc>").
    Suricata network alerts are intentionally excluded — those are surfaced
    by the AI Firewall section's get_alert_counts().
    """
    now = time.monotonic()
    cached = _alert_24h_cache["data"]
    if cached and now - _alert_24h_cache["ts"] < _ALERT_24H_CACHE_TTL:
        return cached
    cutoff = datetime.now() - timedelta(days=1)
    thermal_fan = service_down = 0
    # breakdown[key] = {"count": N, "occurrences": [{"ts": str, "breach": str|None}, ...]}
    breakdown = {}
    try:
        with open(WATCHDOG_LOG_PATH) as f:
            for line in f:
                try:
                    ts = datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    continue
                if ts < cutoff:
                    continue
                ts_str = line[:19]

                m = _HW_ALERT_SENT_RE.search(line)
                if m:
                    thermal_fan += 1
                    key = f"thermal/fan: {m.group(1)}"
                    occ = {"ts": ts_str, "breach": m.group(2)}
                    entry = breakdown.setdefault(key, {"count": 0, "occurrences": []})
                    entry["count"] += 1
                    entry["occurrences"].append(occ)
                    continue

                m = _HW_ALERT_FAILED_RE.search(line)
                if m:
                    thermal_fan += 1
                    key = f"thermal/fan: {m.group(1)}"
                    occ = {"ts": ts_str, "breach": None}
                    entry = breakdown.setdefault(key, {"count": 0, "occurrences": []})
                    entry["count"] += 1
                    entry["occurrences"].append(occ)
                    continue

                m = _SVC_ALERT_RE.search(line)
                if m:
                    service_down += 1
                    key = f"service down: {m.group(1)}"
                    occ = {"ts": ts_str, "breach": None}
                    entry = breakdown.setdefault(key, {"count": 0, "occurrences": []})
                    entry["count"] += 1
                    entry["occurrences"].append(occ)
    except FileNotFoundError:
        log.warning("get_24h_alert_stats: %s not found", WATCHDOG_LOG_PATH)
    except Exception as e:
        log.exception("get_24h_alert_stats failed: %s", e)

    # Most recent first; cap at 50 occurrences per key to limit JSON size
    for entry in breakdown.values():
        entry["occurrences"] = list(reversed(entry["occurrences"]))[:50]

    bd_list = sorted(
        ({"type": k, "count": v["count"], "occurrences": v["occurrences"]}
         for k, v in breakdown.items()),
        key=lambda x: -x["count"],
    )
    data = {
        "total": thermal_fan + service_down,
        "thermal_fan": thermal_fan,
        "service_down": service_down,
        "breakdown": bd_list,
    }
    _alert_24h_cache["data"] = data
    _alert_24h_cache["ts"] = now
    return data


def alert_color(total):
    if total == 0:
        return "green"
    if total <= 5:
        return "yellow"
    return "red"


def get_services_status():
    now = time.monotonic()
    cached = _svc_cache["data"]
    if cached and now - _svc_cache["ts"] < _SVC_CACHE_TTL:
        return cached
    results = []
    for svc in HEALTH_SERVICES:
        try:
            r = subprocess.run(
                ["systemctl", "is-active", "--quiet", svc],
                timeout=5,
            )
            results.append({"name": svc, "active": r.returncode == 0})
        except Exception:
            results.append({"name": svc, "active": False})
    data = {
        "active": sum(1 for r in results if r["active"]),
        "total": len(results),
        "services": results,
    }
    _svc_cache["data"] = data
    _svc_cache["ts"] = now
    return data


_TUNNEL_IFACES = ["tun0", "tun1", "wg0", "wg1", "nordlynx", "proton0"]

def get_vpn_status():
    now = time.monotonic()
    if _vpn_cache["data"] and now - _vpn_cache["ts"] < _VPN_CACHE_TTL:
        return _vpn_cache["data"]

    result = {"provider": None, "status": "Disconnected", "vpn_ip": None, "protocol": None, "server_location": None}

    def _cache(r):
        _vpn_cache["data"] = r
        _vpn_cache["ts"] = time.monotonic()
        return r

    # PIA VPN
    try:
        r = subprocess.run(["piactl", "get", "connectionstate"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            state = r.stdout.strip()
            result["provider"] = "PIA VPN"
            result["status"] = state.capitalize() if state else "Unknown"
            if state.lower() == "connected":
                for flag, cmd in [("vpn_ip", ["piactl", "get", "vpnip"]),
                                   ("server_location", ["piactl", "get", "region"]),
                                   ("protocol", ["piactl", "get", "protocol"])]:
                    try:
                        cr = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                        if cr.returncode == 0:
                            result[flag] = cr.stdout.strip()
                    except Exception:
                        pass
            return _cache(result)
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass

    # Mullvad
    try:
        r = subprocess.run(["mullvad", "status"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            out = r.stdout.strip()
            result["provider"] = "Mullvad"
            if "Connected" in out:
                result["status"] = "Connected"
                for line in out.splitlines():
                    if "Tunnel type:" in line:
                        result["protocol"] = line.split(":", 1)[1].strip()
                    elif "Location:" in line:
                        result["server_location"] = line.split(":", 1)[1].strip()
                    elif "IP:" in line:
                        result["vpn_ip"] = line.split(":", 1)[1].strip()
            elif "Connecting" in out:
                result["status"] = "Connecting"
            return _cache(result)
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass

    # ProtonVPN
    try:
        r = subprocess.run(["protonvpn-cli", "status"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            out = r.stdout.strip()
            result["provider"] = "ProtonVPN"
            if "Connected" in out:
                result["status"] = "Connected"
                for line in out.splitlines():
                    if "IP:" in line:
                        result["vpn_ip"] = line.split(":", 1)[1].strip()
                    elif "Server:" in line:
                        result["server_location"] = line.split(":", 1)[1].strip()
                    elif "Protocol:" in line:
                        result["protocol"] = line.split(":", 1)[1].strip()
            return _cache(result)
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass

    # Fallback: check tunnel interfaces via `ip addr show`
    try:
        ip_r = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True, timeout=5)
        if ip_r.returncode == 0:
            for iface in _TUNNEL_IFACES:
                if re.search(rf'^\d+: {re.escape(iface)}:', ip_r.stdout, re.MULTILINE):
                    vpn_ip = None
                    for line in ip_r.stdout.splitlines():
                        if f" {iface} " in line or f" {iface}:" in line:
                            pass
                        if "inet " in line:
                            m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                            if m:
                                vpn_ip = m.group(1)
                    if iface == "nordlynx":
                        provider, proto = "NordVPN", "WireGuard"
                    elif iface.startswith("wg"):
                        provider, proto = "WireGuard VPN", "WireGuard"
                    elif iface == "proton0":
                        provider, proto = "ProtonVPN", "WireGuard"
                    else:
                        provider, proto = "Unknown Provider", "OpenVPN"
                    result.update({"provider": provider, "status": "Connected",
                                   "vpn_ip": vpn_ip, "protocol": proto,
                                   "server_location": f"via {iface}"})
                    return _cache(result)
    except Exception:
        pass

    return _cache(result)


def get_vpn_split_tunnel_apps():
    try:
        r = subprocess.run(["piactl", "get", "splittunnelapps"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return [a for a in r.stdout.strip().splitlines() if a.strip()]
    except Exception:
        pass
    return []


def _temp_score(temp, threshold, healthy_max):
    """100 when temp <= healthy_max, 0 when temp >= threshold, linear between."""
    if temp is None:
        return 100.0
    if temp <= healthy_max:
        return 100.0
    if temp >= threshold:
        return 0.0
    return 100.0 * (threshold - temp) / (threshold - healthy_max)


def _fan_score(sample, fan_status=None):
    """100% when all ever-active fans spin > 200 RPM; 100% if none are tracked.

    fan_status: {unique_key: {"ever_active": bool, ...}} from get_fan_status().
    When provided, fans whose unique_key has ever_active=False are excluded so
    empty motherboard headers at 0 RPM don't penalise the health score.
    Fans missing from fan_status default to included (safe fallback for old
    historical samples that don't carry a unique_key field).
    """
    fans = sample.get("fans", [])
    if not fans:
        return 100.0
    if fan_status:
        relevant = [f for f in fans
                    if fan_status.get(f.get("unique_key"), {}).get("ever_active", True)]
    else:
        relevant = fans
    if not relevant:
        return 100.0
    spinning = sum(1 for f in relevant if f.get("rpm") and f["rpm"] > 200)
    return 100.0 * spinning / len(relevant)


def _alert_score(total):
    if total == 0:
        return 100.0
    if total <= 5:
        # 1 -> 90, 5 -> 50
        return 100.0 - (total / 5.0) * 50.0
    if total <= 20:
        # 6 -> ~47, 20 -> 0
        return max(0.0, 50.0 - ((total - 5) / 15.0) * 50.0)
    return 0.0


def _score_color(score):
    if score >= 80:
        return "green"
    if score >= 50:
        return "yellow"
    return "red"


def compute_health_score(hw_live, alerts_24h, svc_status):
    hw = hw_live or {}
    cpu_t = hw.get("cpu_temp")
    gpu_t = hw.get("gpu_temp")
    cpu_score = _temp_score(cpu_t, 85, 70)
    gpu_score = _temp_score(gpu_t, 85, 75)
    fan_status = hw.get("fan_status", {})
    fans_list = hw.get("fans", [])
    fan_score = _fan_score(hw, fan_status)
    svc_active = svc_status.get("active", 0)
    svc_total = max(1, svc_status.get("total", 1))
    svc_score = 100.0 * svc_active / svc_total
    alert_total = alerts_24h.get("total", 0)
    alrt_score = _alert_score(alert_total)
    relevant_fans = [f for f in fans_list
                     if fan_status.get(f.get("unique_key"), {}).get("ever_active", True)]
    spinning = sum(1 for f in relevant_fans if f.get("rpm") and f["rpm"] > 200)
    fan_detail = (f"{spinning}/{len(relevant_fans)} tracked fans above 200 RPM"
                  if relevant_fans else "no fans tracked")

    components = [
        {"name": "CPU temperature", "weight": 25, "score": round(cpu_score, 1),
         "detail": f"{cpu_t if cpu_t is not None else '—'}°C / threshold 85°C (healthy ≤70°C)"},
        {"name": "GPU temperature", "weight": 25, "score": round(gpu_score, 1),
         "detail": f"{gpu_t if gpu_t is not None else '—'}°C / threshold 85°C (healthy ≤75°C)"},
        {"name": "Fan speeds", "weight": 20, "score": round(fan_score, 1),
         "detail": fan_detail},
        {"name": "Services running", "weight": 20, "score": round(svc_score, 1),
         "detail": f"{svc_active}/{svc_status.get('total', 0)} monitored services active"},
        {"name": "System alerts (24h)", "weight": 10, "score": round(alrt_score, 1),
         "detail": f"{alert_total} thermal/fan/service alerts in last 24h"},
    ]
    for c in components:
        c["contribution"] = round(c["score"] * c["weight"] / 100.0, 1)
    total = sum(c["contribution"] for c in components)
    return {
        "score": round(total, 1),
        "color": _score_color(total),
        "components": components,
        "services": svc_status.get("services", []),
    }


def compute_health_sparkline(samples, fan_status=None):
    """Per-sample simplified score (CPU 40, GPU 40, fans 20) for the trend line."""
    out = []
    for s in samples:
        cpu = _temp_score(s.get("cpu_temp"), 85, 70)
        gpu = _temp_score(s.get("gpu_temp"), 85, 75)
        fans = _fan_score(s, fan_status)
        out.append(round(cpu * 0.4 + gpu * 0.4 + fans * 0.2, 1))
    return out


@app.route("/api/alert-breakdown-24h")
def api_alert_breakdown_24h():
    return jsonify(get_24h_alert_stats())


@app.route("/api/health-score")
def api_health_score():
    try:
        hw_live = hw_monitor.get_live_metrics()
    except Exception:
        hw_live = {}
    return jsonify(compute_health_score(hw_live, get_24h_alert_stats(), get_services_status()))


@app.route("/api/hw-metrics")
def api_hw_metrics():
    try:
        samples = hw_monitor.get_recent_samples(288)
        fan_status = hw_monitor.get_fan_status()
        return jsonify({
            "live": hw_monitor.get_live_metrics(),
            "samples": samples,
            "health_sparkline": {
                "labels": [s.get("timestamp") for s in samples],
                "scores": compute_health_sparkline(samples, fan_status),
            },
        })
    except Exception as e:
        log.exception("api_hw_metrics failed: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/vpn-status")
def api_vpn_status():
    vpn = get_vpn_status()
    split_tunnel = []
    if vpn.get("provider") and "pia" in vpn["provider"].lower():
        split_tunnel = get_vpn_split_tunnel_apps()
    return jsonify({**vpn, "split_tunnel_apps": split_tunnel})


@app.route("/api/vpn/<action>")
def api_vpn_action(action):
    if action not in ("connect", "disconnect"):
        return jsonify({"error": "invalid action"}), 400
    vpn = get_vpn_status()
    provider = (vpn.get("provider") or "").lower()
    try:
        if "pia" in provider:
            cmd = ["piactl", action]
        elif "mullvad" in provider:
            cmd = ["mullvad", action]
        elif "proton" in provider:
            cmd = ["protonvpn-cli", "c" if action == "connect" else "disconnect"]
        else:
            return jsonify({"error": "No supported VPN CLI detected"}), 400
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        _vpn_cache["ts"] = 0.0
        _vpn_cache["data"] = None
        if r.returncode == 0:
            return jsonify({"success": True, "output": r.stdout.strip()})
        return jsonify({"error": r.stderr.strip() or "Command failed"})
    except FileNotFoundError:
        return jsonify({"error": "VPN CLI not found"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/review-queue")
def api_review_queue():
    items = get_review_queue()
    return jsonify({"count": len(items), "html": render_review_queue_html(items)})


@app.route("/api/quarantines")
def api_quarantines():
    return jsonify({"quarantines": get_active_quarantines()})


@app.route("/api/quarantine/<int:q_id>/confirm")
def api_quarantine_confirm(q_id):
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        c = conn.cursor()
        c.execute("SELECT ip, rule_id, status FROM quarantines WHERE id = ?", (q_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "quarantine not found"}), 404
        ip, rule_id, status = row
        if status != "active":
            conn.close()
            return jsonify({"error": f"quarantine status is {status}, cannot confirm"}), 409
        c.execute("UPDATE alerts SET action='block' WHERE rule_id=?", (rule_id,))
        c.execute("UPDATE quarantines SET status='confirmed' WHERE id=?", (q_id,))
        conn.commit()
        conn.close()
        _audit(action="confirm", rule_id=rule_id, ip=ip)
        return jsonify({"success": True, "ip": ip, "rule_id": rule_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/quarantine/<int:q_id>/lift")
def api_quarantine_lift(q_id):
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        c = conn.cursor()
        c.execute("SELECT ip, rule_id, status FROM quarantines WHERE id = ?", (q_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "quarantine not found"}), 404
        ip, rule_id, status = row
        if status != "active":
            conn.close()
            return jsonify({"error": f"quarantine status is {status}, cannot lift"}), 409
        ufw_ok = ufw_delete(ip)
        c.execute("UPDATE alerts SET action='pending' WHERE rule_id=?", (rule_id,))
        c.execute("UPDATE quarantines SET status='lifted' WHERE id=?", (q_id,))
        conn.commit()
        conn.close()
        _audit(action="lift", rule_id=rule_id, ip=ip)
        return jsonify({"success": True, "ip": ip, "rule_id": rule_id, "ufw_ok": ufw_ok})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/update-device", methods=["POST"])
def update_device():
    try:
        data = request.json
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""UPDATE devices SET friendly_name=?, device_type=?, notes=?, trusted=? 
                     WHERE mac=?""",
                  (data["friendly_name"], data["device_type"], 
                   data.get("notes", ""), data.get("trusted", 1), data["mac"]))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/analyze/<rule_id>")
def analyze_alert(rule_id):
    try:
        raw_alert = request.args.get("raw", "")
        parsed = parse_alert(raw_alert) if raw_alert else None
        src_ip = parsed["src_ip"] if parsed else ""
        enrichment = None
        if src_ip:
            try:
                enrichment = enrich_ip(src_ip)
            except Exception:
                enrichment = None
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM alerts WHERE rule_id = ?", (rule_id,))
        existing = c.fetchone()
        if existing and existing[4]:
            # Fall back to DB-stored src_ip when raw alert had no parseable IP
            if not src_ip and len(existing) > 11 and existing[11]:
                src_ip = existing[11]
                if enrichment is None:
                    try:
                        enrichment = enrich_ip(src_ip)
                    except Exception:
                        enrichment = None
            conn.close()
            return jsonify({
                "explanation": existing[4],
                "risk_level": existing[5],
                "action": existing[7],
                "recommended_action": "See previous decision",
                "reason": "Retrieved from local database",
                "cached": True,
                "src_ip": src_ip,
                "enrichment": enrichment
            })
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=500,
            messages=[{
                "role": "user",
                "content": f"""You are Nemesis, an AI security assistant for a home network firewall.
Analyze this Suricata alert and respond in JSON only, no markdown:

Alert: {raw_alert}

{{
    "explanation": "Plain English explanation for home user",
    "risk_level": "LOW/MEDIUM/HIGH",
    "is_threat": true/false,
    "recommended_action": "Block/Ignore/Monitor",
    "reason": "Brief reason"
}}"""
            }]
        )
        response_text = message.content[0].text
        try:
            analysis = json.loads(response_text)
        except Exception as e:
            log.warning("analyze_alert: failed to parse Claude response as JSON: %s", e)
            analysis = {
                "explanation": response_text,
                "risk_level": "UNKNOWN",
                "is_threat": False,
                "recommended_action": "Monitor",
                "reason": "Could not parse response"
            }
        now = datetime.now().isoformat()
        new_action = "ignore" if analysis.get("risk_level") == "LOW" else "pending"
        if existing:
            c.execute("UPDATE alerts SET explanation=?, risk_level=? WHERE rule_id=?",
                     (analysis["explanation"], analysis["risk_level"], rule_id))
        else:
            c.execute("""INSERT INTO alerts
                (rule_id, rule_name, classification, priority, explanation, risk_level, action, times_seen, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)""",
                (rule_id, raw_alert[:50], "", 1, analysis["explanation"], analysis["risk_level"], new_action, now, now))
        conn.commit()
        conn.close()
        return jsonify({**analysis, "cached": False, "src_ip": src_ip, "enrichment": enrichment})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/report/<rule_id>")
def report_abuse(rule_id):
    try:
        ip = request.args.get("ip", "").strip()
        if not ip:
            return jsonify({"error": "IP required"}), 400
        if not ABUSEIPDB_KEY:
            return jsonify({"error": "ABUSEIPDB_KEY not configured"}), 500
        categories = request.args.get("categories", "14,15")
        comment = request.args.get(
            "comment",
            f"Reported from Nemesis Firewall - Suricata rule {rule_id}"
        )
        resp = requests.post(
            "https://api.abuseipdb.com/api/v2/report",
            data={"ip": ip, "categories": categories, "comment": comment},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=10,
        )
        try:
            payload = resp.json()
        except ValueError:
            payload = {}
        if resp.status_code >= 400:
            errors = payload.get("errors") or [{"detail": "Unknown error"}]
            detail = errors[0].get("detail") if isinstance(errors, list) and errors else str(errors)
            return jsonify({"error": detail, "status": resp.status_code}), resp.status_code
        data = payload.get("data", {})
        return jsonify({
            "success": True,
            "ip": ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/test-enrichment/<ip>")
def test_enrichment(ip):
    try:
        return jsonify(enrich_ip(ip))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/action/<rule_id>/<action>")
def set_action(rule_id, action):
    try:
        src_ip = request.args.get("ip", "")
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE alerts SET action=? WHERE rule_id=?", (action, rule_id))
        if c.rowcount == 0:
            now = datetime.now().isoformat()
            c.execute("""INSERT INTO alerts
                (rule_id, rule_name, classification, priority, explanation, risk_level, action, times_seen, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)""",
                (rule_id, "", "", 1, "", "UNKNOWN", action, now, now))
        if action == "block" and src_ip:
            ufw_deny_append(src_ip)
        conn.commit()
        conn.close()
        _audit(action=action, rule_id=rule_id, ip=(src_ip or None))
        return jsonify({"success": True, "action": action})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/settings")
def settings_page():
    # Build module rows dynamically from discovered manifests
    manifests = modules_loader.get_all_manifests()
    module_rows_html = ""
    for name, m in sorted(manifests.items(), key=lambda kv: kv[1].get("display_name", kv[0])):
        enabled = modules_loader.is_enabled(name)
        display_name = html.escape(m.get("display_name", name))
        description = html.escape(m.get("description", ""))
        category = html.escape(m.get("category", ""))
        confirm_required = "true" if m.get("confirmation_required") else "false"
        confirm_msg = html.escape(m.get("confirmation_message", ""), quote=True)
        toggle_checked = "checked" if enabled else ""
        toggle_color = "#00ff88" if enabled else "#444"
        status_label = "Enabled" if enabled else "Disabled"
        status_color = "#00ff88" if enabled else "#666"
        module_rows_html += f"""
        <div class="module-row" id="mod-row-{name}">
            <div class="module-info">
                <div class="module-name">{display_name}
                    <span class="module-cat">{category}</span>
                </div>
                <div class="module-desc">{description}</div>
                <div class="module-status" id="mod-status-{name}" style="color:{status_color}">{status_label}</div>
            </div>
            <label class="toggle-switch" title="{'Enable' if not enabled else 'Disable'} {display_name}">
                <input type="checkbox" id="mod-toggle-{name}" {toggle_checked}
                    onchange="handleModuleToggle('{name}', this.checked, {confirm_required}, '{confirm_msg}')">
                <span class="toggle-slider"></span>
            </label>
        </div>"""

    if not module_rows_html:
        module_rows_html = '<p style="color:#555;font-style:italic">No modules found in modules/ directory.</p>'

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Nemesis — Settings</title>
    <script src="/static/tier.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; background: #1a1a2e; color: #eee;
               padding: 24px; max-width: 700px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; margin-bottom: 4px; }}
        h2 {{ color: #00d4ff; font-size: 1.05em; margin: 28px 0 8px 0;
             border-bottom: 1px solid #1e2d4e; padding-bottom: 6px; }}
        .back {{ color: #00d4ff; text-decoration: none; font-size: 0.9em; }}
        .back:hover {{ text-decoration: underline; }}
        .settings-section {{ margin-bottom: 32px; }}
        .tier-option {{ display: flex; align-items: flex-start; gap: 12px;
                       padding: 12px 14px; border-radius: 6px; cursor: pointer;
                       border: 1px solid transparent; margin-bottom: 8px;
                       transition: background 0.15s, border-color 0.15s; }}
        .tier-option:hover {{ background: rgba(0,212,255,0.06); }}
        .tier-option.selected {{ background: rgba(0,212,255,0.1);
                                border-color: rgba(0,212,255,0.4); }}
        .tier-option input[type=radio] {{ margin-top: 3px; flex-shrink: 0;
                                          accent-color: #00d4ff; width: 16px; height: 16px; }}
        .tier-label {{ flex: 1; }}
        .tier-label strong {{ color: #eee; font-size: 1em; }}
        .tier-label em {{ color: #888; font-size: 0.85em; margin-left: 6px; }}
        .tier-label p {{ color: #aaa; font-size: 0.85em; margin: 4px 0 0 0; line-height: 1.5; }}
        .save-note {{ color: #00ff88; font-size: 0.82em; margin-top: 6px; display: none; }}
        .settings-intro {{ color: #aaa; font-size: 0.9em; margin: 0 0 18px 0; line-height: 1.6; }}
        /* Module rows */
        .module-row {{ display: flex; align-items: center; gap: 14px;
                       padding: 14px 0; border-bottom: 1px solid #1e2d4e; }}
        .module-row:last-child {{ border-bottom: none; }}
        .module-info {{ flex: 1; }}
        .module-name {{ font-weight: bold; color: #eee; margin-bottom: 3px; }}
        .module-cat {{ display: inline-block; font-size: 0.72em; color: #00d4ff;
                       background: rgba(0,212,255,0.1); padding: 1px 7px;
                       border-radius: 10px; margin-left: 8px; font-weight: normal;
                       vertical-align: middle; }}
        .module-desc {{ color: #aaa; font-size: 0.84em; line-height: 1.5; margin-bottom: 4px; }}
        .module-status {{ font-size: 0.78em; font-weight: bold; }}
        /* Toggle switch */
        .toggle-switch {{ position: relative; display: inline-block;
                          width: 48px; height: 26px; flex-shrink: 0; }}
        .toggle-switch input {{ opacity: 0; width: 0; height: 0; }}
        .toggle-slider {{ position: absolute; cursor: pointer; inset: 0;
                          background: #333; border-radius: 26px;
                          transition: background 0.2s; }}
        .toggle-slider:before {{ content: ""; position: absolute;
                                  width: 20px; height: 20px; left: 3px; bottom: 3px;
                                  background: #888; border-radius: 50%;
                                  transition: transform 0.2s, background 0.2s; }}
        input:checked + .toggle-slider {{ background: rgba(0,212,255,0.25); }}
        input:checked + .toggle-slider:before {{ transform: translateX(22px); background: #00d4ff; }}
        /* Confirmation modal */
        .confirm-overlay {{ display: none; position: fixed; inset: 0;
                             background: rgba(0,0,0,0.85); z-index: 100; }}
        .confirm-box {{ background: #16213e; border: 1px solid #ffaa00;
                         border-radius: 10px; padding: 24px; max-width: 500px;
                         margin: 100px auto; }}
        .confirm-box h3 {{ color: #ffaa00; margin-top: 0; }}
        .confirm-box p {{ color: #ccc; font-size: 0.9em; line-height: 1.6; }}
        .confirm-check {{ display: flex; align-items: flex-start; gap: 10px;
                           margin: 16px 0; cursor: pointer; }}
        .confirm-check input {{ flex-shrink: 0; margin-top: 3px;
                                  accent-color: #ffaa00; width: 16px; height: 16px; }}
        .confirm-check span {{ color: #eee; font-size: 0.9em; }}
        .confirm-actions {{ display: flex; gap: 10px; margin-top: 16px; }}
        .btn-confirm {{ padding: 9px 20px; background: #ffaa00; color: #1a1a2e;
                         border: none; border-radius: 5px; cursor: pointer;
                         font-weight: bold; opacity: 0.4; }}
        .btn-confirm.ready {{ opacity: 1; cursor: pointer; }}
        .btn-cancel {{ padding: 9px 20px; background: #333; color: #eee;
                        border: none; border-radius: 5px; cursor: pointer; }}
    </style>
</head>
<body>
    <h1>⚙️ Settings</h1>
    <p><a class="back" href="/">← Back to Dashboard</a></p>

    <div class="settings-section">
        <h2>Explanation Detail Level</h2>
        <p class="settings-intro">
            Controls how labels, descriptions, and explanatory text are displayed across
            the dashboard. Your preference is saved per browser and takes effect immediately.
        </p>

        <div class="tier-option" id="optBeginner" onclick="chooseTier('beginner')">
            <input type="radio" name="tier" id="radioBeginner" value="beginner">
            <div class="tier-label">
                <strong>Beginner</strong>
                <p>Full plain-English explanations with context. Best for users new to
                   network security — explains what each alert means, whether to worry,
                   and what to do. Nothing is assumed.</p>
            </div>
        </div>

        <div class="tier-option" id="optIntermediate" onclick="chooseTier('intermediate')">
            <input type="radio" name="tier" id="radioIntermediate" value="intermediate">
            <div class="tier-label">
                <strong>Intermediate</strong> <em>(default)</em>
                <p>Balanced detail — clear labels with enough context to act, without
                   over-explaining fundamentals. Good for users comfortable with the
                   basics of networking and security.</p>
            </div>
        </div>

        <div class="tier-option" id="optPro" onclick="chooseTier('pro')">
            <input type="radio" name="tier" id="radioPro" value="pro">
            <div class="tier-label">
                <strong>Pro</strong>
                <p>Concise technical language for experienced users. Abbreviations,
                   protocol names, and security terminology used without explanation.
                   Maximum signal, minimum prose.</p>
            </div>
        </div>

        <p class="save-note" id="saveNote">✓ Saved — takes effect immediately on all pages</p>
    </div>

    <div class="settings-section">
        <h2>Modules</h2>
        <p class="settings-intro">
            Optional features that can be enabled or disabled independently.
            Disabled modules are not loaded at all — they have zero runtime cost.
            Changes take effect immediately.
        </p>
        <div id="moduleList">
        {module_rows_html}
        </div>
        <p id="moduleMsg" style="display:none;font-size:0.85em;margin-top:10px"></p>
    </div>

    <!-- Confirmation modal for dangerous toggles -->
    <div class="confirm-overlay" id="confirmOverlay">
        <div class="confirm-box">
            <h3>⚠️ Important — read before enabling</h3>
            <p id="confirmMsg"></p>
            <label class="confirm-check">
                <input type="checkbox" id="confirmCheck" onchange="confirmCheckChanged()">
                <span>I understand the implications and have already taken the required steps.</span>
            </label>
            <div class="confirm-actions">
                <button class="btn-confirm" id="btnConfirmEnable" disabled onclick="doConfirmEnable()">
                    Enable anyway
                </button>
                <button class="btn-cancel" onclick="cancelConfirm()">Cancel</button>
            </div>
        </div>
    </div>

    <script>
        // --- Tier selector ---
        function chooseTier(tier) {{
            setTier(tier);
            document.getElementById('radioBeginner').checked    = (tier === 'beginner');
            document.getElementById('radioIntermediate').checked = (tier === 'intermediate');
            document.getElementById('radioPro').checked         = (tier === 'pro');
            ['Beginner','Intermediate','Pro'].forEach(function(t) {{
                document.getElementById('opt' + t).classList.toggle(
                    'selected', t.toLowerCase() === tier);
            }});
            var note = document.getElementById('saveNote');
            note.style.display = 'block';
            clearTimeout(note._t);
            note._t = setTimeout(function() {{ note.style.display = 'none'; }}, 3000);
        }}
        (function() {{
            var t = getTier();
            document.getElementById('radio' + t.charAt(0).toUpperCase() + t.slice(1)).checked = true;
            document.getElementById('opt'   + t.charAt(0).toUpperCase() + t.slice(1))
                .classList.add('selected');
        }})();

        // --- Module toggles ---
        var _pendingModule = null;

        function handleModuleToggle(name, wantEnabled, confirmRequired, confirmMsg) {{
            if (wantEnabled && confirmRequired) {{
                // Show confirmation modal; revert toggle visually until confirmed
                document.getElementById('mod-toggle-' + name).checked = false;
                _pendingModule = name;
                document.getElementById('confirmMsg').textContent = confirmMsg;
                document.getElementById('confirmCheck').checked = false;
                document.getElementById('btnConfirmEnable').disabled = true;
                document.getElementById('btnConfirmEnable').classList.remove('ready');
                document.getElementById('confirmOverlay').style.display = 'block';
            }} else {{
                setModuleEnabled(name, wantEnabled);
            }}
        }}

        function confirmCheckChanged() {{
            var ready = document.getElementById('confirmCheck').checked;
            document.getElementById('btnConfirmEnable').disabled = !ready;
            document.getElementById('btnConfirmEnable').classList.toggle('ready', ready);
        }}

        function doConfirmEnable() {{
            document.getElementById('confirmOverlay').style.display = 'none';
            if (_pendingModule) {{
                document.getElementById('mod-toggle-' + _pendingModule).checked = true;
                setModuleEnabled(_pendingModule, true);
                _pendingModule = null;
            }}
        }}

        function cancelConfirm() {{
            document.getElementById('confirmOverlay').style.display = 'none';
            _pendingModule = null;
        }}

        function setModuleEnabled(name, enabled) {{
            var url = '/api/modules/' + name + '/' + (enabled ? 'enable' : 'disable');
            var statusEl = document.getElementById('mod-status-' + name);
            statusEl.style.color = '#ffaa00';
            statusEl.textContent = enabled ? 'Enabling…' : 'Disabling…';

            fetch(url, {{method: 'POST'}})
                .then(function(r) {{ return r.json(); }})
                .then(function(d) {{
                    if (d.error) {{
                        statusEl.style.color = '#ff4444';
                        statusEl.textContent = 'Error: ' + d.error;
                        document.getElementById('mod-toggle-' + name).checked = !enabled;
                    }} else {{
                        statusEl.style.color = enabled ? '#00ff88' : '#666';
                        statusEl.textContent = enabled ? 'Enabled' : 'Disabled';
                    }}
                }})
                .catch(function(e) {{
                    statusEl.style.color = '#ff4444';
                    statusEl.textContent = 'Request failed';
                    document.getElementById('mod-toggle-' + name).checked = !enabled;
                }});
        }}
    </script>
</body>
</html>"""


@app.route("/firewall-db")
def firewall_db():
    # Tiered tooltip descriptions for known Suricata rule IDs.
    # Each entry: (beginner, intermediate, pro)
    RULE_TIPS = {
        # Device Retrieving External IP Address family
        "2054140": (
            "A device on your network checked what its public internet address is — like asking 'what is my IP?' Very common and almost always harmless. Browsers, apps, and smart devices do this regularly.",
            "ET INFO: device queried an external IP-echo service (ipify, ifconfig.me, etc.). Routine behavior on home networks; fires on IoT, browsers, and apps needing WAN IP awareness.",
            "ET INFO Device Retrieving External IP. HTTP/DNS to IP-echo service. Expected on NAT'd LAN; low signal."
        ),
        "2054168": (
            "A device checked its own public internet address using a slightly different method than the most common pattern. Still routine and harmless.",
            "ET INFO external IP retrieval via alternate endpoint. Same class as 2054140; different URL/method signature.",
            "ET INFO Device Retrieving External IP. Alt-endpoint variant of 2054140."
        ),
        "2054169": (
            "Another variant of the 'device checking its public IP' pattern. Normal background behaviour.",
            "ET INFO external IP retrieval, third endpoint variant. Same risk profile as 2054140/2054168.",
            "ET INFO Device Retrieving External IP. Endpoint variant #3."
        ),
        "2025331": (
            "A device asked an external service for its public IP address — routine and expected.",
            "ET INFO external IP lookup via a specific service endpoint. Low risk, routine on home networks.",
            "ET INFO Device Retrieving External IP. Service-specific signature."
        ),
        "2039594": (
            "A device checked its public IP address using yet another external service. Completely routine.",
            "ET INFO external IP retrieval, additional service variant. Same class and risk as other 205xxxx rules.",
            "ET INFO Device Retrieving External IP. Additional service variant."
        ),
        "2026718": (
            "A device on your network looked up its own public IP address. Normal behaviour.",
            "ET INFO external IP lookup. One occurrence; same low-risk class as other IP-retrieval rules.",
            "ET INFO Device Retrieving External IP. Single occurrence."
        ),
        # Potentially Bad Traffic — identified apps
        "2027758": (
            "Wondershare software (PDF editor, video tools, etc.) on your network sent data back to Wondershare's servers — likely telemetry or licence checks. Not malicious, but it does track usage.",
            "ET POLICY Wondershare software telemetry/licensing traffic. 'Potentially Bad Traffic' reflects privacy concern, not active threat.",
            "ET POLICY Wondershare telemetry/licensing C2. Privacy flag; not malicious."
        ),
        "2028651": (
            "Steam (Valve's PC gaming platform) is communicating with its servers. Completely normal when the Steam app or a Steam game is running.",
            "ET POLICY Steam gaming client protocol detected. 'Corporate Privacy Violation' is Suricata's DPI classification for recognisable platform traffic, not an actual threat.",
            "ET POLICY Steam client traffic. Corporate privacy classification (DPI); expected. Not a threat."
        ),
        "2027867": (
            "An Amazon Fire TV or Echo device is talking to Amazon's servers — normal operation for streaming and smart-home devices. The 'dewrain' label refers to the traffic pattern Amazon uses.",
            "ET POLICY dewrain — Amazon Fire TV/Echo traffic to AWS. Pattern matches Amazon streaming device cloud communication.",
            "ET dewrain. Fire TV/Echo → AWS traffic. Amazon streaming infra pattern. Not a threat."
        ),
        # Potentially Bad Traffic — generic patterns
        "2029340": (
            "Suricata spotted a traffic pattern it considers potentially suspicious, but assessed it as low risk. Likely an app communicating in an unusual but harmless way.",
            "ET POLICY Potentially Bad Traffic. LOW risk; specific trigger context is in the raw alert. Review source/destination if unexpected.",
            "ET POLICY Potentially Bad Traffic. LOW. Check raw alert for signature context."
        ),
        "2027757": (
            "A network traffic pattern that Suricata flags as potentially suspicious, though it was rated low risk. Probably routine application traffic.",
            "ET POLICY Potentially Bad Traffic, low frequency. LOW risk classification; check raw alert for specific trigger.",
            "ET POLICY Potentially Bad Traffic. LOW. 3 occurrences."
        ),
        "2037042": (
            "Another low-risk 'potentially bad traffic' pattern. Usually means an app doing something slightly unusual but not actually harmful.",
            "ET POLICY Potentially Bad Traffic. LOW risk; infrequent. Examine raw alert for source application context.",
            "ET POLICY Potentially Bad Traffic. LOW. Infrequent."
        ),
        "2027863": (
            "A traffic pattern Suricata flagged as potentially suspicious but rated low risk. Very rare — only seen twice.",
            "ET POLICY Potentially Bad Traffic. LOW risk; 2 occurrences. Check raw alert for specific context.",
            "ET POLICY Potentially Bad Traffic. LOW. 2 hits."
        ),
        # ICMP / Misc Attack
        "2400016": (
            "An ICMP 'ping' was detected — this is how computers check if another device is reachable, like knocking on a door. On a home network this is almost always harmless.",
            "GPL ICMP_INFO PING *NIX — ICMP echo request. 'Misc Attack' is a legacy Snort/GPL classification; ICMP pings are routine on home LANs. Worth reviewing src/dst if unexpected.",
            "GPL ICMP_INFO PING *NIX. Legacy Misc Attack class. ICMP echo; routine on home LAN. Verify src/dst."
        ),
        "2400038": (
            "Another ICMP ping alert — a device checked if another device was reachable. The difference from the other ping alert is the format of the ping, not the risk level.",
            "GPL ICMP_INFO PING BSDtype — BSD-format ICMP echo variant. Same classification and risk as 2400016; distinguishes OS-specific ICMP payload format.",
            "GPL ICMP_INFO PING BSDtype. BSD-format ICMP echo variant of 2400016. Same risk profile."
        ),
    }
    GENERIC_TIP = (
        "This Suricata rule fired for traffic that matched a known pattern. The AI rated it LOW risk — click 'View' on the main dashboard alert list to see the full AI analysis.",
        "Suricata signature match; LOW risk per AI analysis. See the dashboard alert view for explanation and raw alert context.",
        "Suricata sig match. LOW risk. See alert view for raw context."
    )

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM alerts ORDER BY last_seen DESC")
        alerts = c.fetchall()
        conn.close()
        rows = ""
        for a in alerts:
            aid = int(a[0])
            rule_id_raw = str(a[1] or "")
            rule_id = html.escape(rule_id_raw)
            rule_name = html.escape((a[3] or a[2] or "")[:50])
            risk_level = html.escape(str(a[6] or ""))
            action_val = html.escape(str(a[7] or ""))
            times_seen = html.escape(str(a[8] or ""))
            last_seen = html.escape(str(a[10] or ""))

            # Row styling by action status
            if action_val == "pending":
                row_style = "background:rgba(255,170,0,0.08);border-left:3px solid #ffaa00;"
                action_color = "color:#ffaa00;font-weight:bold"
            elif action_val == "ignore":
                row_style = "opacity:0.55;"
                action_color = "color:#555"
            elif action_val == "block":
                row_style = "background:rgba(255,68,68,0.08);border-left:3px solid #ff4444;"
                action_color = "color:#ff4444;font-weight:bold"
            elif action_val == "monitor":
                row_style = "background:rgba(0,212,255,0.05);border-left:3px solid #00d4ff;"
                action_color = "color:#00d4ff"
            else:
                row_style = ""
                action_color = ""

            tip_b, tip_m, tip_p = RULE_TIPS.get(rule_id_raw, GENERIC_TIP)
            tip_b = html.escape(tip_b, quote=True)
            tip_m = html.escape(tip_m, quote=True)
            tip_p = html.escape(tip_p, quote=True)

            rows += f"""<tr style="{row_style}">
                <td style="color:#888">{rule_id}</td>
                <td class="rule-name-cell" data-tip-beginner="{tip_b}" data-tip-intermediate="{tip_m}" data-tip-pro="{tip_p}" style="cursor:help" title="{tip_m}">{rule_name}</td>
                <td style="color:{'#00ff88' if a[6]=='LOW' else '#ffaa00' if a[6]=='MEDIUM' else '#ff4444'}">{risk_level}</td>
                <td style="{action_color}">{action_val}</td>
                <td style="color:#aaa;text-align:right">{times_seen}</td>
                <td style="color:#aaa">{last_seen}</td>
                <td>
                    <select onchange="changeAction({aid}, this.value)">
                        <option {"selected" if a[7]=="pending" else ""}>pending</option>
                        <option {"selected" if a[7]=="ignore" else ""}>ignore</option>
                        <option {"selected" if a[7]=="block" else ""}>block</option>
                        <option {"selected" if a[7]=="monitor" else ""}>monitor</option>
                    </select>
                </td>
            </tr>"""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Nemesis - Alert Database</title>
    <script src="/static/tier.js"></script>
    <style>
        body {{ font-family: Arial; background: #1a1a2e; color: #eee; padding: 20px; }}
        h1 {{ color: #00d4ff; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #16213e; color: #00d4ff; padding: 10px; text-align: left; }}
        td {{ padding: 8px; border-bottom: 1px solid #222; font-size: 0.85em; }}
        tr:hover td {{ background: rgba(255,255,255,0.03); }}
        select {{ background: #16213e; color: #eee; border: 1px solid #333; padding: 3px; border-radius:3px; }}
        a {{ color: #00d4ff; }}
    </style>
    <script>
        function changeAction(id, action) {{
            fetch("/api/db-action/" + id + "/" + action)
                .then(r => r.json()).then(d => console.log(d));
        }}

        // Apply tier-appropriate tooltip text to rule name cells.
        // Called on load and whenever the tier changes.
        function applyTierTooltips() {{
            var tier = getTier();
            var attr = "data-tip-" + tier;
            document.querySelectorAll(".rule-name-cell[" + attr + "]").forEach(function(el) {{
                el.title = el.getAttribute(attr) || el.getAttribute("data-tip-intermediate") || "";
            }});
        }}
        window.onTierChange = applyTierTooltips;
        window.addEventListener("storage", function(e) {{
            if (e.key === "explanationTier") applyTierTooltips();
        }});
        document.addEventListener("DOMContentLoaded", applyTierTooltips);
    </script>
</head>
<body>
    <h1>🛡️ Nemesis - Alert Database</h1>
    <p><a href="javascript:window.close()" style="color:#888">✕ Close this tab</a></p>
    <p style="background:#0d1117;border-left:3px solid #00d4ff;padding:10px 14px;font-size:0.85em;color:#aaa;border-radius:0 4px 4px 0;margin-bottom:16px">
        ℹ️ <strong style="color:#00d4ff">This database shows P1/P2 alerts that required review or action.</strong>
        Routine informational (P3) traffic — DNS lookups, ET POLICY notices, protocol scans — is not individually logged here,
        but is counted in the dashboard's Total and can be inspected in Suricata's fast.log directly.
    </p>
    <table>
        <tr><th>Rule ID</th><th>Rule Name</th><th>Risk</th><th>Action</th><th>Times Seen</th><th>Last Seen</th><th>Change</th></tr>
        {rows}
    </table>
</body>
</html>"""
    except Exception as e:
        return str(e)

@app.route("/api/db-action/<int:alert_id>/<action>")
def db_action(alert_id, action):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT rule_id, src_ip FROM alerts WHERE id=?", (alert_id,))
        row = c.fetchone()
        rule_id = row[0] if row else None
        src_ip = row[1] if row else None
        c.execute("UPDATE alerts SET action=? WHERE id=?", (action, alert_id))
        conn.commit()
        conn.close()
        _audit(action=action, rule_id=rule_id, ip=src_ip)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/modules")
def api_modules():
    """List all discovered modules with their enabled state and runtime status."""
    manifests = modules_loader.get_all_manifests()
    result = []
    for name, m in manifests.items():
        result.append({
            "name": name,
            "display_name": m.get("display_name", name),
            "description": m.get("description", ""),
            "category": m.get("category", ""),
            "enabled": modules_loader.is_enabled(name),
            "status": modules_loader.module_status(name),
            "confirmation_required": m.get("confirmation_required", False),
            "confirmation_message": m.get("confirmation_message", ""),
        })
    return jsonify({"modules": result})


@app.route("/api/modules/<name>/enable", methods=["POST"])
def api_module_enable(name):
    try:
        modules_loader.set_enabled(name, True)
        return jsonify({"success": True, "status": modules_loader.module_status(name)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/modules/<name>/disable", methods=["POST"])
def api_module_disable(name):
    try:
        modules_loader.set_enabled(name, False)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/")
def dashboard():
    clamav_status = get_clamav_status()
    system_status = get_system_status()
    alert_counts = get_alert_counts()
    initial_total = alert_counts["total"]
    pihole = get_pihole_summary()
    total = pihole["total"]
    blocked = pihole["blocked"]
    percent = pihole["percent"]
    try:
        hw_live = hw_monitor.get_live_metrics()
    except Exception:
        hw_live = {}
    hw_cpu = hw_live.get("cpu_temp")
    hw_ambient = hw_live.get("ambient_temp")
    hw_nvme = hw_live.get("nvme_temp")
    hw_gpu = hw_live.get("gpu_temp")
    hw_fans = hw_live.get("fans", [])
    hw_gpu_fan = hw_live.get("gpu_fan_percent")
    hw_cpu_pct = hw_live.get("cpu_percent")
    hw_ram_pct = hw_live.get("ram_percent")
    hw_ram_used_gb = hw_live.get("ram_used_gb")
    hw_ram_total_gb = hw_live.get("ram_total_gb")
    hw_ram_free_gb = (
        round(hw_ram_total_gb - hw_ram_used_gb, 1)
        if hw_ram_total_gb is not None and hw_ram_used_gb is not None
        else None
    )
    hw_fans_js = json.dumps(hw_fans)
    hw_cpu_pct_js = "null" if hw_cpu_pct is None else str(hw_cpu_pct)
    fan_status_js = json.dumps(hw_live.get("fan_status", {}))
    try:
        hw_alerts_init = hw_monitor.get_hw_alerts()
    except Exception:
        hw_alerts_init = []
    hw_alerts_js = json.dumps(hw_alerts_init)
    def _fmt(v, suffix=""):
        return "—" if v is None else f"{v}{suffix}"

    try:
        alerts_24h_init = get_24h_alert_stats()
        svc_status_init = get_services_status()
        health_init = compute_health_score(hw_live, alerts_24h_init, svc_status_init)
    except Exception:
        alerts_24h_init = {"total": 0}
        health_init = {"score": 0.0, "color": "red"}
    color_map = {"green": "#00ff88", "yellow": "#ffaa00", "red": "#ff4444"}
    alert_24h_total = alerts_24h_init.get("total", 0)
    alert_24h_color = color_map[alert_color(alert_24h_total)]
    health_score = health_init["score"]
    health_color = color_map[health_init["color"]]

    vpn = get_vpn_status()
    vpn_status_str = vpn.get("status", "Disconnected")
    vpn_provider = vpn.get("provider") or "VPN"
    _vpn_color_map = {"connected": "#00ff88", "connecting": "#ffaa00", "reconnecting": "#ffaa00"}
    vpn_color = _vpn_color_map.get(vpn_status_str.lower(), "#ff4444")
    vpn_label = f"{vpn_provider} — {vpn_status_str}" if vpn.get("provider") else f"VPN — {vpn_status_str}"

    alerts_html = render_alerts_html(get_active_alerts())
    devices_html = render_devices_html(get_network_devices())
    review_queue = get_review_queue()
    review_queue_html = render_review_queue_html(review_queue)
    review_queue_count = len(review_queue)
    quarantines = get_active_quarantines()
    quarantine_banner_html = render_quarantine_banner_html(quarantines)
    quarantine_banner_display = "block" if quarantines else "none"

    module_cards_html = "".join(
        card_html for _, card_html in modules_loader.get_module_cards()
    )

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Nemesis Firewall</title>
    <style>
        body {{ font-family: Arial; background: #1a1a2e; color: #eee; padding: 20px; margin: 0; }}
        h1 {{ color: #00d4ff; margin-bottom: 5px; }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }}
        .card {{ background: #16213e; padding: 15px; border-radius: 10px; border: 1px solid #00d4ff; }}
        .card h2 {{ color: #00d4ff; margin-top: 0; font-size: 1em; }}
        .stat {{ font-size: 1.8em; color: #00ff88; }}
        .full-width {{ grid-column: span 2; }}
        .running {{ color: #00ff88; }}
        .stopped {{ color: #ff4444; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ text-align: left; padding: 5px; border-bottom: 1px solid #00d4ff; font-size: 0.85em; color: #00d4ff; }}
        td {{ padding: 5px; border-bottom: 1px solid #222; font-size: 0.85em; }}
        .counter-box {{ display: inline-block; background: #0d1117; border-radius: 8px; padding: 10px 15px; margin: 5px; text-align: center; }}
        .counter-num {{ font-size: 1.8em; font-weight: bold; }}
        .p1 {{ color: #ff4444; }}
        .p2 {{ color: #ffaa00; }}
        .p3 {{ color: #aaaaaa; }}
        .total {{ color: #00d4ff; }}
        .modal {{ display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.8); z-index:1000; }}
        .modal-content {{ background:#16213e; border:1px solid #00d4ff; border-radius:10px; padding:20px; max-width:600px; margin:80px auto; }}
        .modal h3 {{ color:#00d4ff; }}
        .btn {{ padding:8px 16px; border:none; border-radius:5px; cursor:pointer; margin:5px; font-weight:bold; }}
        .btn-block {{ background:#ff4444; color:white; }}
        .btn-ignore {{ background:#aaaaaa; color:#1a1a2e; }}
        .btn-monitor {{ background:#ffaa00; color:#1a1a2e; }}
        .btn-close {{ background:#333; color:#eee; }}
        .btn-save {{ background:#00ff88; color:#1a1a2e; }}
        .btn-report {{ background:#8800ff; color:white; }}
        input, select {{ background:#0d1117; color:#eee; border:1px solid #00d4ff; padding:5px; border-radius:3px; width:100%; margin:3px 0; }}
        a {{ color: #00d4ff; }}
        .enrichment-card {{ background:#0d1117; border:1px solid #333; border-radius:6px; padding:10px; margin:10px 0; }}
        .enrichment-card h4 {{ color:#00d4ff; margin:0 0 8px 0; font-size:0.95em; }}
        .enrichment-card p {{ margin:4px 0; font-size:0.9em; }}
        .flag {{ font-size:1.3em; vertical-align:middle; }}
        .warn-tor {{ color:#ff4444; font-weight:bold; }}
        .warn-vpn {{ color:#ffaa00; font-weight:bold; }}
        .quarantine-banner {{ background:#2a0d0d; border:2px solid #ff4444; border-radius:10px; padding:15px; margin-bottom:15px; }}
        .quarantine-banner h2 {{ color:#ff4444; margin-top:0; }}
        .q-row {{ display:flex; justify-content:space-between; align-items:center; padding:8px; border-bottom:1px solid #4a1010; flex-wrap:wrap; gap:8px; }}
        .q-row:last-child {{ border-bottom:none; }}
        .q-info {{ flex:1; min-width:200px; }}
        .q-actions {{ display:flex; gap:5px; }}
        .devices-table td {{ border-bottom: 1px solid #1e3a5f; }}
        .hw-card:hover {{ background:#1a2950; }}
        .hw-grid {{ display:grid; grid-template-columns: repeat(4, 1fr); gap:10px; margin-top:8px; }}
        .hw-stat {{ background:#0d1117; border-radius:6px; padding:8px 10px; text-align:center; }}
        .hw-label {{ color:#aaa; font-size:0.75em; text-transform:uppercase; letter-spacing:0.05em; }}
        .hw-value {{ color:#00ff88; font-size:1.4em; font-weight:bold; margin-top:2px; }}
        .hw-clickable {{ cursor:pointer; transition:background 0.15s; }}
        .hw-clickable:hover {{ background:#1a2950; outline:1px solid #00d4ff; }}
        .breakdown-table {{ width:100%; border-collapse:collapse; margin-top:10px; }}
        .breakdown-table th, .breakdown-table td {{ padding:6px 10px; border-bottom:1px solid #2a3a5a; text-align:left; font-size:0.85em; }}
        .breakdown-table th {{ color:#00d4ff; background:#0d1117; }}
        .health-bar {{ height:8px; background:#0d1117; border-radius:4px; overflow:hidden; }}
        .health-bar-fill {{ height:100%; background:#00ff88; }}
        .hw-modal-content {{ background:#16213e; border:1px solid #00d4ff; border-radius:10px; padding:20px; max-width:900px; width:90%; max-height:90vh; overflow-y:auto; margin:40px auto; position:relative; }}
        .hw-close-x {{ position:sticky; top:0; float:right; background:#16213e; color:#00d4ff; border:1px solid #00d4ff; border-radius:50%; width:32px; height:32px; font-size:1.1em; line-height:1; cursor:pointer; z-index:10; }}
        .hw-close-x:hover {{ background:#ff4444; color:#fff; border-color:#ff4444; }}
        .chart-box {{ background:#0d1117; border-radius:6px; padding:10px; margin-bottom:12px; }}
        .chart-box h4 {{ color:#00d4ff; margin:0 0 6px 0; font-size:0.9em; }}
        .fan-section {{ margin-top:10px; border-top:1px solid #1e2d4e; padding-top:6px; }}
        .fan-summary {{ display:flex; align-items:center; cursor:pointer; padding:6px 4px; border-radius:4px; user-select:none; gap:8px; border:1px solid transparent; }}
        .fan-summary:hover {{ background:rgba(0,212,255,0.06); }}
        .fan-summary.fan-alert {{ background:rgba(255,68,68,0.12); border-color:rgba(255,68,68,0.5); }}
        .fan-summary.fan-alert:hover {{ background:rgba(255,68,68,0.18); }}
        .fan-toggle {{ color:#00d4ff; font-size:0.75em; display:inline-block; width:10px; flex-shrink:0; }}
        .fan-dot {{ width:9px; height:9px; border-radius:50%; display:inline-block; flex-shrink:0; }}
        .fan-summary-text {{ color:#ccc; font-size:0.85em; }}
        .fan-detail-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(110px,1fr)); gap:8px; margin-top:8px; }}
        .fan-tile {{ background:#0d1117; border-radius:6px; padding:8px 6px; text-align:center; }}
        .fan-tile-lbl {{ color:#aaa; font-size:0.65em; text-transform:uppercase; letter-spacing:0.04em; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
        .fan-tile-rpm {{ font-size:1.15em; font-weight:bold; margin-top:3px; }}
        .fan-rpm-active {{ color:#00ff88; }}
        .fan-rpm-idle {{ color:#777; }}
        .fan-rpm-concern {{ color:#ff4444; }}
        .hw-alerts-section {{ margin-top:10px; border-top:1px solid #1e2d4e; padding-top:8px; }}
        .hw-alerts-header {{ color:#aaa; font-size:0.75em; text-transform:uppercase; letter-spacing:0.06em; margin-bottom:6px; }}
        .hw-alert-row {{ display:flex; align-items:center; gap:10px; padding:7px 10px; border-radius:5px; cursor:pointer; background:rgba(255,68,68,0.08); border:1px solid rgba(255,68,68,0.3); margin-bottom:4px; }}
        .hw-alert-row:hover {{ background:rgba(255,68,68,0.16); border-color:rgba(255,68,68,0.5); }}
        .hw-alert-icon {{ font-size:1.1em; flex-shrink:0; }}
        .hw-alert-body {{ flex:1; min-width:0; }}
        .hw-alert-msg {{ color:#ff9999; font-size:0.85em; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
        .hw-alert-meta {{ color:#999; font-size:0.72em; margin-top:2px; }}
        .hw-alert-sev-CRITICAL {{ color:#ff4444; font-weight:bold; font-size:0.72em; flex-shrink:0; }}
        .hw-alert-sev-HIGH {{ color:#ff8800; font-weight:bold; font-size:0.72em; flex-shrink:0; }}
        .hw-alert-sev-MEDIUM {{ color:#ffcc00; font-weight:bold; font-size:0.72em; flex-shrink:0; }}
        .hw-alert-empty {{ color:#888; font-size:0.82em; padding:5px 2px; }}
        .hw-alert-detail-modal {{ background:#16213e; border:1px solid #ff4444; border-radius:10px; padding:20px; max-width:600px; width:90%; max-height:85vh; overflow-y:auto; margin:60px auto; position:relative; }}
        .hw-alert-detail-modal h3 {{ color:#ff6666; margin-top:0; }}
        .hw-alert-detail-field {{ margin-bottom:12px; }}
        .hw-alert-detail-label {{ color:#aaa; font-size:0.75em; text-transform:uppercase; letter-spacing:0.05em; }}
        .hw-alert-detail-value {{ color:#ddd; font-size:0.9em; margin-top:3px; white-space:pre-wrap; }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <script src="/static/tier.js"></script>
</head>
<body>
    <h1>🛡️ Nemesis Firewall <a href="/settings" target="_blank" rel="noopener" style="float:right;font-size:0.45em;color:#888;text-decoration:none;font-weight:normal;margin-top:8px" title="Settings">⚙️ Settings</a></h1>
    <p style="color:#aaa;margin-top:0">Last updated: <span id="lastUpdated">{now}</span> | Stats refresh every 60s, tables every 5 min</p>

    <div class="quarantine-banner" id="quarantineBanner" style="display:{quarantine_banner_display}">
        <h2>🚨 Auto-Quarantined IPs</h2>
        <div id="quarantineList">{quarantine_banner_html}</div>
    </div>

    <div class="grid">
        <div class="card">
            <h2><span class="tier-text" data-beginner="Pi-hole — DNS Ad &amp; Tracker Blocker" data-intermediate="Pi-hole DNS Protection" data-pro="Pi-hole DNS">Pi-hole DNS Protection</span></h2>
            <p><span class="tier-text" data-beginner="DNS Queries Today (all devices):" data-intermediate="Queries Today:" data-pro="Queries:">Queries Today:</span> <span class="stat" id="phTotal">{total}</span></p>
            <p><span class="tier-text" data-beginner="Blocked (ads, trackers, malware domains):" data-intermediate="Blocked:" data-pro="Blocked:">Blocked:</span> <span class="stat" id="phBlocked">{blocked}</span></p>
            <p><span class="tier-text" data-beginner="Block Rate (higher = more protection):" data-intermediate="Percent Blocked:" data-pro="Block %:">Percent Blocked:</span> <span class="stat" id="phPercent">{percent}%</span></p>
        </div>

        <div class="card">
            <h2><span class="tier-text" data-beginner="Security Services Status" data-intermediate="System Status" data-pro="Services">System Status</span></h2>
            <p><span class="tier-text" data-beginner="ClamAV Antivirus:" data-intermediate="ClamAV:" data-pro="ClamAV:">ClamAV:</span> <span class="{"running" if clamav_status == "Running" else "stopped"}">{clamav_status}</span></p>
            <p><span class="tier-text" data-beginner="VPN (encrypts your traffic):" data-intermediate="VPN:" data-pro="VPN:">VPN:</span> <span id="vpnStatusText" onclick="openVpnModal()"
                style="color:{vpn_color};cursor:pointer;text-decoration:underline dotted"
                title="Click for details">{html.escape(vpn_label)}</span></p>
            <p style="font-size:0.8em">CPU: {system_status.get("cpu", "N/A")}</p>
            <p style="font-size:0.8em">Memory: {system_status.get("memory", "N/A")}</p>
            <p style="font-size:0.8em">Disk: {system_status.get("disk", "N/A")}</p>
        </div>

        <div class="card full-width hw-card" onclick="openHwModal()" style="cursor:pointer">
            <h2>🌡️ <span class="tier-text" data-beginner="Hardware Health &amp; Temperatures" data-intermediate="Hardware Stats" data-pro="Hardware">Hardware Stats</span>
                <span style="float:right;font-size:0.75em;color:#aaa"><span class="tier-text" data-beginner="click for 24-hour history graphs ▸" data-intermediate="click for 24h graphs ▸" data-pro="24h ▸">click for 24h graphs ▸</span></span>
            </h2>
            <div class="hw-grid">
                <div class="hw-stat">
                    <div class="hw-label"><span class="tier-text" data-beginner="CPU Temperature" data-intermediate="CPU Temp" data-pro="CPU °C">CPU Temp</span></div>
                    <div class="hw-value" id="hwCpuTemp">{_fmt(hw_cpu, "°C")}</div>
                </div>
                <div class="hw-stat">
                    <div class="hw-label"><span class="tier-text" data-beginner="GPU Temperature" data-intermediate="GPU Temp" data-pro="GPU °C">GPU Temp</span></div>
                    <div class="hw-value" id="hwGpuTemp">{_fmt(hw_gpu, "°C")}</div>
                </div>
                <div class="hw-stat">
                    <div class="hw-label"><span class="tier-text" data-beginner="Case / Ambient Temp" data-intermediate="Ambient" data-pro="Ambient °C">Ambient</span></div>
                    <div class="hw-value" id="hwAmbient">{_fmt(hw_ambient, "°C")}</div>
                </div>
                <div class="hw-stat">
                    <div class="hw-label"><span class="tier-text" data-beginner="SSD Temperature (NVMe)" data-intermediate="NVMe" data-pro="NVMe °C">NVMe</span></div>
                    <div class="hw-value" id="hwNvme">{_fmt(hw_nvme, "°C")}</div>
                </div>
                <div class="hw-stat">
                    <div class="hw-label"><span class="tier-text" data-beginner="CPU Usage" data-intermediate="CPU Load" data-pro="CPU %">CPU Load</span></div>
                    <div class="hw-value" id="hwCpuPct">{_fmt(hw_cpu_pct, "%")}</div>
                </div>
                <div class="hw-stat">
                    <div class="hw-label"><span class="tier-text" data-beginner="RAM / Memory Used" data-intermediate="RAM Used" data-pro="RAM %">RAM Used</span></div>
                    <div class="hw-value" id="hwRamPct">{_fmt(hw_ram_pct, "%")}</div>
                    <div class="hw-label" id="hwRamFree" style="margin-top:3px;font-size:0.85em">{_fmt(hw_ram_free_gb, " GB free") if hw_ram_free_gb is not None else ""}</div>
                </div>
                <div class="hw-stat">
                    <div class="hw-label"><span class="tier-text" data-beginner="GPU Fan Speed" data-intermediate="GPU Fan" data-pro="GPU Fan %">GPU Fan</span></div>
                    <div class="hw-value" id="hwGpuFan">{_fmt(hw_gpu_fan, "%")}</div>
                </div>
                <div class="hw-stat hw-clickable" onclick="event.stopPropagation(); openAlertBreakdownModal()">
                    <div class="hw-label"><span class="tier-text" data-beginner="System Alerts (last 24h)" data-intermediate="24h System Alerts" data-pro="24h Alerts">24h System Alerts</span></div>
                    <div class="hw-value" id="hwAlert24h" style="color:{alert_24h_color}">{alert_24h_total}</div>
                </div>
                <div class="hw-stat hw-clickable" onclick="event.stopPropagation(); openHealthModal()">
                    <div class="hw-label"><span class="tier-text" data-beginner="Overall System Health" data-intermediate="System Health" data-pro="Health">System Health</span></div>
                    <div class="hw-value" id="hwHealthScore" style="color:{health_color}">{health_score}%</div>
                </div>
            </div>
            <div class="fan-section" onclick="event.stopPropagation()">
                <div class="fan-summary" id="fanSummaryRow" onclick="toggleFanSection()">
                    <span class="fan-toggle" id="fanToggleIcon">▶</span>
                    <span class="fan-dot" id="fanStatusDot" style="background:#444"></span>
                    <span class="fan-summary-text" id="fanSummaryText">Fans: loading…</span>
                </div>
                <div id="fanDetailGrid" class="fan-detail-grid" style="display:none"></div>
            </div>
            <div class="hw-alerts-section" onclick="event.stopPropagation()">
                <div class="hw-alerts-header"><span class="tier-text"
                    data-beginner="Hardware Problems"
                    data-intermediate="Hardware Alerts"
                    data-pro="HW Alerts">Hardware Alerts</span></div>
                <div id="hwAlertsList"></div>
            </div>
        </div>

        <div class="card full-width">
            <h2>🔥 <span class="tier-text" data-beginner="AI Firewall — Security Events Detected Today" data-intermediate="AI Firewall — Today's Activity" data-pro="AI Firewall">AI Firewall — Today's Activity</span>
                <span style="float:right;font-size:0.8em">
                    <label style="color:#aaa;cursor:pointer;margin-right:15px" title="Show informational Priority-3 alerts (DNS lookups, ET POLICY notices, etc.)">
                        <input type="checkbox" id="showP3Toggle" onchange="toggleP3()" style="width:auto;margin-right:5px;vertical-align:middle">
                        <span class="tier-text"
                              data-beginner="Show background/informational traffic (P3)"
                              data-intermediate="Show P3 (info)"
                              data-pro="P3">Show P3 (info)</span>
                    </label>
                    <a href="/firewall-db" target="_blank" rel="noopener" style="color:#00d4ff;text-decoration:none">📋 Alert Database</a>
                </span>
            </h2>
            <div>
                <div class="counter-box"><div class="counter-num total" id="cntTotal">{initial_total}</div>
                    <div><span class="tier-text" data-beginner="All Alerts Today" data-intermediate="Total" data-pro="Total">Total</span></div>
                    <div style="color:#888;font-size:0.65em;margin-top:2px"><span class="tier-text" data-beginner="includes routine traffic" data-intermediate="incl. P3 info" data-pro="P1+P2+P3">incl. P3 info</span></div>
                </div>
                <div class="counter-box"><div class="counter-num p1" id="cntP1">{alert_counts["p1"]}</div>
                    <div><span class="tier-text" data-beginner="Critical Threats" data-intermediate="Critical P1" data-pro="P1">Critical P1</span></div>
                </div>
                <div class="counter-box"><div class="counter-num p2" id="cntP2">{alert_counts["p2"]}</div>
                    <div><span class="tier-text" data-beginner="High Risk" data-intermediate="High P2" data-pro="P2">High P2</span></div>
                </div>
                <div class="counter-box" id="p3Box" style="display:none"><div class="counter-num p3" id="cntP3">{alert_counts["p3"]}</div>
                    <div><span class="tier-text" data-beginner="Background Traffic" data-intermediate="Info P3" data-pro="P3">Info P3</span></div>
                </div>
                <div class="counter-box"><div class="counter-num" id="cntReviewQueue" style="color:#ff8800">{review_queue_count}</div>
                    <div style="color:#ff8800"><span class="tier-text" data-beginner="Needs Your Review" data-intermediate="Review Queue" data-pro="Queue">Review Queue</span></div>
                </div>
            </div>
            <div id="p3Note" style="display:none;color:#aaa;font-size:0.85em;margin-top:8px;padding:10px;background:#0d1117;border-radius:4px;border-left:3px solid #00d4ff">
                <span class="tier-text"
                    data-beginner="ℹ️ These are not threats. P3 alerts are routine background traffic your firewall notices but automatically ignores — things like DNS queries (when your devices look up website names), software checking for updates, or standard protocol handshakes. Your network is safe. Nothing here needs action; these events are filtered out of all security checks and email alerts."
                    data-intermediate="ℹ️ P3 alerts are informational only — not an issue. These are typically DNS queries, ET POLICY notices, common protocol scans, or device chatter that Suricata flags by convention. They do not represent threats and do not require any action. The watchdog, AI analysis, and auto-quarantine pipelines all ignore P3."
                    data-pro="P3: informational. ET POLICY, DNS queries, protocol-scan signatures. Not actionable; excluded from watchdog, AI analysis, and quarantine pipelines.">ℹ️ P3 alerts are informational only — not an issue. These are typically DNS queries, ET POLICY notices, common protocol scans, or device chatter that Suricata flags by convention. They do not represent threats and do not require any action. The watchdog, AI analysis, and auto-quarantine pipelines all ignore P3.</span>
            </div>
            <div style="margin-top:15px;background:#1a0d00;border:1px solid #ff8800;border-radius:8px;padding:12px">
                <h3 style="color:#ff8800;margin:0 0 10px 0;font-size:1em"><span class="tier-text"
                    data-beginner="🔎 Suspicious Activity — Needs Your Decision"
                    data-intermediate="🔎 Review Queue — HIGH Risk Pending"
                    data-pro="🔎 Review Queue (HIGH, unresolved)">🔎 Review Queue — HIGH Risk Pending</span></h3>
                <table>
                    <thead><tr>
                        <th style="color:#ff8800">Time</th>
                        <th style="color:#ff8800">Rule</th>
                        <th style="color:#ff8800">Source IP</th>
                        <th style="color:#ff8800">Classification</th>
                        <th style="color:#ff8800;text-align:center">Seen</th>
                        <th style="color:#ff8800">Action</th>
                    </tr></thead>
                    <tbody id="reviewQueueRows">
                    {review_queue_html}
                    </tbody>
                </table>
            </div>
            <h3 style="color:#ffaa00;margin-top:15px"><span class="tier-text"
                data-beginner="⚠️ Active Threats — These Need Your Attention"
                data-intermediate="⚠️ Alerts Requiring Attention"
                data-pro="⚠️ Active P1/P2">⚠️ Alerts Requiring Attention</span></h3>
            <table>
                <thead><tr><th>Priority</th><th>Time</th><th>Alert</th><th>Source IP</th><th>Action</th></tr></thead>
                <tbody id="alertsRows">
                {alerts_html}
                </tbody>
            </table>
        </div>

        <div class="card full-width">
            <h2>🖥️ <span class="tier-text" data-beginner="Devices on Your Network" data-intermediate="Network Devices" data-pro="Devices">Network Devices</span>
                <span style="float:right;font-size:0.8em;color:#aaa"><span class="tier-text" data-beginner="✅ You trust this device &nbsp; ❓ Not yet verified" data-intermediate="✅ Trusted &nbsp; ❓ Unverified" data-pro="✅ Trusted ❓ Unknown">✅ Trusted &nbsp; ❓ Unverified</span></span>
            </h2>
            <table class="devices-table">
                <thead><tr><th>IP</th><th>Friendly Name</th><th>Type</th><th>MAC</th><th>Trust</th></tr></thead>
                <tbody id="devicesRows">
                {devices_html}
                </tbody>
            </table>
        </div>

        <div id="moduleCardsContainer" style="display:contents">
        {module_cards_html}
        </div>
    </div>

    <!-- Alert Modal -->
    <div class="modal" id="alertModal">
        <div class="modal-content">
            <h3>🔍 Nemesis AI Analysis</h3>
            <div id="modalContent">Analyzing...</div>
            <div style="margin-top:15px">
                <button class="btn btn-block" onclick="takeAction('block')" id="btnBlock">🚫 Block IP</button>
                <button class="btn btn-ignore" onclick="takeAction('ignore')" id="btnIgnore">✓ Ignore Rule</button>
                <button class="btn btn-monitor" onclick="takeAction('monitor')" id="btnMonitor">👁 Monitor</button>
                <button class="btn btn-report" id="btnReport" onclick="reportAbuse()" style="display:none">🚨 Report to AbuseIPDB</button>
                <button class="btn btn-close" onclick="closeModal()">✕ Close</button>
            </div>
        </div>
    </div>

    <!-- Hardware Stats Modal -->
    <div class="modal" id="hwModal">
        <div class="hw-modal-content">
            <button class="hw-close-x" onclick="closeHwModal()" title="Close (Esc)">✕</button>
            <h3 style="color:#00d4ff;margin-top:0">🌡️ <span class="tier-text" data-beginner="Hardware History — last 24 hours" data-intermediate="Hardware — last 24 hours" data-pro="Hardware 24h">Hardware — last 24 hours</span></h3>
            <div id="hwModalStatus" style="color:#aaa;font-size:0.85em">Loading…</div>
            <div class="chart-box"><h4><span class="tier-text" data-beginner="Temperatures — how hot each component is running (°C)" data-intermediate="Temperatures (°C)" data-pro="Temps °C">Temperatures (°C)</span></h4><canvas id="chartTemp" height="120"></canvas></div>
            <div class="chart-box"><h4><span class="tier-text" data-beginner="Fan Speeds — higher RPM = better cooling" data-intermediate="Fan Speeds (RPM)" data-pro="Fans RPM">Fan Speeds (RPM)</span></h4><canvas id="chartFans" height="120"></canvas></div>
            <div class="chart-box"><h4><span class="tier-text" data-beginner="CPU &amp; RAM Usage (%)" data-intermediate="CPU &amp; RAM (%)" data-pro="CPU/RAM %">CPU &amp; RAM (%)</span></h4><canvas id="chartUsage" height="120"></canvas></div>
            <div class="chart-box"><h4><span class="tier-text" data-beginner="Disk &amp; Network activity (MB per 5 minutes)" data-intermediate="Disk &amp; Network (MB / 5 min)" data-pro="Disk/Net MB/5m">Disk &amp; Network (MB / 5 min)</span></h4><canvas id="chartIo" height="120"></canvas></div>
            <div class="chart-box"><h4><span class="tier-text" data-beginner="System Health Score over time (100% = fully healthy)" data-intermediate="System Health Score (24h)" data-pro="Health % 24h">System Health Score (24h)</span></h4><canvas id="chartHealth" height="120"></canvas></div>
            <div style="text-align:right">
                <button class="btn btn-close" onclick="closeHwModal()">✕ Close</button>
            </div>
        </div>
    </div>

    <!-- 24h Alert Breakdown Modal -->
    <div class="modal" id="alertBreakdownModal">
        <div class="hw-modal-content">
            <button class="hw-close-x" onclick="closeAlertBreakdownModal()" title="Close (Esc)">✕</button>
            <h3 style="color:#00d4ff;margin-top:0"><span class="tier-text" data-beginner="🛠️ What triggered alerts in the last 24 hours?" data-intermediate="🛠️ 24h System Alert Breakdown" data-pro="🛠️ 24h Alerts">🛠️ 24h System Alert Breakdown</span></h3>
            <div id="alertBreakdownBody" style="color:#aaa;font-size:0.9em">Loading…</div>
            <div style="text-align:right;margin-top:10px">
                <button class="btn btn-close" onclick="closeAlertBreakdownModal()">✕ Close</button>
            </div>
        </div>
    </div>

    <!-- Health Score Breakdown Modal -->
    <div class="modal" id="healthModal">
        <div class="hw-modal-content">
            <button class="hw-close-x" onclick="closeHealthModal()" title="Close (Esc)">✕</button>
            <h3 style="color:#00d4ff;margin-top:0"><span class="tier-text" data-beginner="💚 How healthy is your system right now?" data-intermediate="💚 System Health Score" data-pro="💚 Health Score">💚 System Health Score</span></h3>
            <div id="healthModalBody" style="color:#aaa;font-size:0.9em">Loading…</div>
            <div style="text-align:right;margin-top:10px">
                <button class="btn btn-close" onclick="closeHealthModal()">✕ Close</button>
            </div>
        </div>
    </div>

    <!-- Hardware Alert Detail Modal -->
    <div class="modal" id="hwAlertDetailModal" onclick="if(event.target.id==='hwAlertDetailModal')closeHwAlertDetailModal()">
        <div class="hw-alert-detail-modal">
            <button class="hw-close-x" onclick="closeHwAlertDetailModal()" title="Close (Esc)">✕</button>
            <h3 id="hwAlertDetailTitle">Hardware Alert</h3>
            <div id="hwAlertDetailBody"></div>
            <div style="text-align:right;margin-top:12px">
                <button class="btn btn-close" onclick="closeHwAlertDetailModal()">✕ Close</button>
            </div>
        </div>
    </div>

    <!-- VPN Status Modal -->
    <div class="modal" id="vpnModal" onclick="if(event.target.id==='vpnModal')closeVpnModal()">
        <div class="modal-content">
            <h3>🔒 VPN Status</h3>
            <div id="vpnModalContent" style="min-height:80px">Loading…</div>
            <div style="margin-top:15px" id="vpnModalActions">
                <button class="btn btn-monitor" onclick="vpnAction('connect')">🔄 Reconnect</button>
                <button class="btn btn-ignore" onclick="vpnAction('disconnect')">⏹ Disconnect</button>
                <button class="btn btn-close" onclick="closeVpnModal()">✕ Close</button>
            </div>
        </div>
    </div>

    <!-- Device Edit Modal -->
    <div class="modal" id="deviceModal">
        <div class="modal-content">
            <h3>✏️ Edit Device</h3>
            <input type="hidden" id="editMac">
            <label>Friendly Name</label>
            <input type="text" id="editName">
            <label>Device Type</label>
            <select id="editType">
                <option>Router</option>
                <option>Switch</option>
                <option>Desktop</option>
                <option>Laptop</option>
                <option>Phone</option>
                <option>Tablet</option>
                <option>Smart Home</option>
                <option>Entertainment</option>
                <option>Security Camera</option>
                <option>Printer</option>
                <option>Unknown</option>
            </select>
            <label>Notes</label>
            <input type="text" id="editNotes">
            <label>
                <input type="checkbox" id="editTrusted" style="width:auto"> Trusted Device
            </label>
            <div style="margin-top:15px">
                <button class="btn btn-save" onclick="saveDevice()">💾 Save</button>
                <button class="btn btn-close" onclick="closeDeviceModal()">✕ Cancel</button>
            </div>
        </div>
    </div>

    <script>
        var currentRuleId = "";
        var currentSrcIp = "";

        function escapeHtml(s) {{
            if (s === null || s === undefined) return "";
            return String(s).replace(/[&<>"']/g, function(c) {{
                return {{"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;"}}[c];
            }});
        }}

        function countryFlag(cc) {{
            if (!cc || cc.length !== 2) return "";
            return cc.toUpperCase().replace(/./g, function(c) {{
                return String.fromCodePoint(127397 + c.charCodeAt(0));
            }});
        }}

        function threatColor(level) {{
            if (level === "CRITICAL") return "#ff0000";
            if (level === "HIGH") return "#ff4444";
            if (level === "MEDIUM") return "#ffaa00";
            return "#00ff88";
        }}

        function renderEnrichment(enr) {{
            if (!enr) return "";
            var flag = countryFlag(enr.country);
            var loc = [enr.city, enr.country].filter(Boolean).map(escapeHtml).join(", ") || "Unknown location";
            var isp = escapeHtml(enr.isp || enr.org || "Unknown ISP");
            var level = enr.threat_level || "LOW";
            var color = threatColor(level);
            var score = (enr.abuse_confidence_score == null) ? "n/a" : enr.abuse_confidence_score;
            var reports = (enr.total_reports == null) ? 0 : enr.total_reports;
            var lastRep = enr.last_reported ? escapeHtml(enr.last_reported) : "never";
            var warnings = "";
            if (enr.is_tor) warnings += '<p class="warn-tor">⚠ TOR exit node</p>';
            if (enr.is_vpn) warnings += '<p class="warn-vpn">⚠ VPN / Proxy / Hosting</p>';
            return `
                <div class="enrichment-card">
                    <h4>🌍 IP Intelligence — ${{escapeHtml(enr.ip)}}</h4>
                    <p><span class="flag">${{flag}}</span> <strong>${{loc}}</strong></p>
                    <p><strong>ISP:</strong> ${{isp}}</p>
                    <p><strong>Threat Level:</strong> <span style="color:${{color}};font-weight:bold">${{escapeHtml(level)}}</span></p>
                    <p><strong>Abuse Score:</strong> ${{escapeHtml(score)}}/100 &nbsp; <strong>Reports:</strong> ${{escapeHtml(reports)}} &nbsp; <strong>Last:</strong> ${{lastRep}}</p>
                    ${{warnings}}
                </div>
            `;
        }}

        function viewAlert(ruleId, rawAlert) {{
            currentRuleId = ruleId;
            currentSrcIp = "";
            document.getElementById("btnReport").style.display = "none";
            document.getElementById("alertModal").style.display = "block";
            document.getElementById("modalContent").innerHTML =
                "<p>🤖 " + tierText(
                    "Nemesis AI is checking this alert — this takes a few seconds…",
                    "Nemesis AI analyzing...",
                    "Analyzing…"
                ) + "</p>";
            fetch("/api/analyze/" + ruleId + "?raw=" + encodeURIComponent(rawAlert))
                .then(r => r.json())
                .then(data => {{
                    currentSrcIp = data.src_ip || "";
                    var cached = data.cached
                        ? " <span style='color:#aaa'>(" + tierText("from cache", "cached", "cached") + ")</span>"
                        : " <span style='color:#00ff88'>(" + tierText("freshly analyzed by AI", "AI analyzed", "AI") + ")</span>";
                    var riskColor = data.risk_level === "HIGH" ? "#ff4444" : data.risk_level === "MEDIUM" ? "#ffaa00" : "#00ff88";
                    var riskLabel = tierText(
                        {{HIGH:"HIGH — Investigate this now", MEDIUM:"MEDIUM — Worth reviewing", LOW:"LOW — Likely safe"}}[data.risk_level] || data.risk_level,
                        data.risk_level || "UNKNOWN",
                        data.risk_level || "?"
                    );
                    document.getElementById("modalContent").innerHTML = `
                        <p><strong>${{tierText("Threat Level","Risk Level","Risk")}}:</strong> <span style="color:${{riskColor}}">${{escapeHtml(riskLabel)}}</span>${{cached}}</p>
                        <p><strong>${{tierText("What is this?","Explanation","Detail")}}:</strong> ${{escapeHtml(data.explanation || "No explanation available")}}</p>
                        <p><strong>${{tierText("What should I do?","Recommended Action","Action")}}:</strong> ${{escapeHtml(data.recommended_action || "Monitor")}}</p>
                        <p><strong>${{tierText("Why?","Reason","Reason")}}:</strong> ${{escapeHtml(data.reason || "")}}</p>
                        ${{renderEnrichment(data.enrichment)}}
                    `;
                    if (data.enrichment && data.enrichment.abuse_confidence_score !== null && currentSrcIp) {{
                        document.getElementById("btnReport").style.display = "inline-block";
                    }}
                }})
                .catch(e => {{
                    document.getElementById("modalContent").innerHTML = "<p style=\'color:#ff4444\'>Error: " + escapeHtml(e) + "</p>";
                }});
        }}

        function takeAction(action) {{
            var url = "/api/action/" + currentRuleId + "/" + action;
            if (action === "block" && currentSrcIp) url += "?ip=" + encodeURIComponent(currentSrcIp);
            fetch(url).then(r => r.json()).then(data => {{
                closeModal();
                location.reload();
            }});
        }}

        function reportAbuse() {{
            if (!currentSrcIp) {{ alert("No source IP to report"); return; }}
            if (!confirm("Report " + currentSrcIp + " to AbuseIPDB?")) return;
            fetch("/api/report/" + currentRuleId + "?ip=" + encodeURIComponent(currentSrcIp))
                .then(r => r.json())
                .then(d => {{
                    if (d.success) {{
                        alert("Reported to AbuseIPDB. Current confidence score: " + (d.abuse_confidence_score == null ? "unknown" : d.abuse_confidence_score));
                    }} else {{
                        alert("Report failed: " + (d.error || "unknown error"));
                    }}
                }})
                .catch(e => alert("Error: " + e));
        }}

        function closeModal() {{
            document.getElementById("alertModal").style.display = "none";
            document.getElementById("btnReport").style.display = "none";
        }}

        function editDevice(mac, name, type) {{
            document.getElementById("editMac").value = mac;
            document.getElementById("editName").value = name;
            document.getElementById("editType").value = type;
            document.getElementById("deviceModal").style.display = "block";
        }}

        function saveDevice() {{
            var data = {{
                mac: document.getElementById("editMac").value,
                friendly_name: document.getElementById("editName").value,
                device_type: document.getElementById("editType").value,
                notes: document.getElementById("editNotes").value,
                trusted: document.getElementById("editTrusted").checked ? 1 : 0
            }};
            fetch("/api/update-device", {{
                method: "POST",
                headers: {{"Content-Type": "application/json"}},
                body: JSON.stringify(data)
            }}).then(r => r.json()).then(d => {{
                closeDeviceModal();
                location.reload();
            }});
        }}

        function closeDeviceModal() {{
            document.getElementById("deviceModal").style.display = "none";
        }}

        var hwCharts = {{}};

        function isP3Shown() {{
            var el = document.getElementById("showP3Toggle");
            return !!(el && el.checked);
        }}

        function applyP3Visibility(show) {{
            document.getElementById("p3Box").style.display = show ? "" : "none";
            document.getElementById("p3Note").style.display = show ? "" : "none";
        }}

        function toggleP3() {{
            var show = isP3Shown();
            try {{ localStorage.setItem("showP3", show ? "1" : "0"); }} catch (e) {{}}
            applyP3Visibility(show);
        }}

        (function initP3Toggle() {{
            var stored = null;
            try {{ stored = localStorage.getItem("showP3"); }} catch (e) {{}}
            var show = stored === "1";
            document.getElementById("showP3Toggle").checked = show;
            applyP3Visibility(show);
        }})();

        function fmtHw(v, suffix) {{
            return (v === null || v === undefined) ? "—" : v + suffix;
        }}

        // ── Fan section ───────────────────────────────────────────────────────
        function toggleFanSection() {{
            var grid = document.getElementById("fanDetailGrid");
            setFanSectionExpanded(grid.style.display === "none");
        }}
        function setFanSectionExpanded(expanded) {{
            var grid = document.getElementById("fanDetailGrid");
            var icon = document.getElementById("fanToggleIcon");
            grid.style.display = expanded ? "grid" : "none";
            icon.textContent = expanded ? "▼" : "▶";
            try {{ localStorage.setItem("fansExpanded", expanded ? "1" : "0"); }} catch(e) {{}}
        }}
        function renderFanSection(fans, cpuPct, fanStatus) {{
            fans = fans || [];
            fanStatus = fanStatus || {{}};
            var highLoad = cpuPct !== null && cpuPct !== undefined && cpuPct >= 40;
            var nActive = 0, nIdle = 0, nConcern = 0, nHidden = 0;
            var tiles = [];
            fans.forEach(function(f) {{
                var ukey = f.unique_key;
                // Fans with no status entry default to visible (safe fallback)
                var status = ukey ? (fanStatus[ukey] || {{}}) : {{}};
                var everActive = "ever_active" in status ? status.ever_active : true;
                var rpm = f.rpm;
                // Never-active fan at 0: hide entirely — presumed-empty header
                if (!everActive && (rpm === null || rpm === undefined || rpm <= 0)) {{
                    nHidden++;
                    return;
                }}
                var lbl = escapeHtml(String(f.label || "Fan"));
                var rpmText, cls;
                if (rpm === null || rpm === undefined) {{
                    rpmText = "—"; cls = "fan-rpm-idle"; nIdle++;
                }} else if (rpm > 200) {{
                    rpmText = rpm + " RPM"; cls = "fan-rpm-active"; nActive++;
                }} else if (rpm <= 50 && highLoad) {{
                    // Ever-active fan stopped under load — real concern
                    rpmText = rpm + " RPM"; cls = "fan-rpm-concern"; nConcern++;
                }} else {{
                    rpmText = rpm === 0 ? "0 RPM (idle)" : rpm + " RPM";
                    cls = "fan-rpm-idle"; nIdle++;
                }}
                tiles.push('<div class="fan-tile"><div class="fan-tile-lbl" title="' + lbl + '">' + lbl +
                           '</div><div class="fan-tile-rpm ' + cls + '">' + rpmText + '</div></div>');
            }});
            var grid = document.getElementById("fanDetailGrid");
            if (grid) grid.innerHTML = tiles.join("");

            var visibleCount = nActive + nIdle + nConcern;
            var hiddenNote = nHidden > 0
                ? ' <span style="color:#666;font-size:0.9em">(' + nHidden + ' unused header' + (nHidden > 1 ? 's' : '') + ' not shown)</span>'
                : '';
            var el = document.getElementById("fanSummaryText");
            var summaryRow = document.getElementById("fanSummaryRow");

            if (nConcern > 0) {{
                // Alert state: row background turns red, text changes to urgent message
                if (summaryRow) summaryRow.classList.add("fan-alert");
                if (el) el.innerHTML =
                    '<span style="color:#ff4444;font-weight:bold">&#9888; ' + nConcern +
                    ' fan' + (nConcern > 1 ? 's' : '') + ' stopped under load</span>' +
                    ' <span style="color:#ff9999">— click to expand</span>' + hiddenNote;
            }} else {{
                // Normal state
                if (summaryRow) summaryRow.classList.remove("fan-alert");
                var parts = [];
                if (nActive > 0) parts.push('<span style="color:#00ff88;font-weight:bold">' + nActive + ' active</span>');
                if (nIdle   > 0) parts.push('<span style="color:#777">' + nIdle + ' idle</span>');
                if (el) el.innerHTML = 'Fans (' + visibleCount + '):&ensp;' +
                    (parts.length ? parts.join('&ensp;') : '<span style="color:#aaa">none configured</span>') +
                    hiddenNote;
            }}

            var dot = document.getElementById("fanStatusDot");
            if (dot) dot.style.background = nConcern > 0 ? "#ff4444"
                : nActive > 0 ? "#00ff88"
                : visibleCount > 0 ? "#ffaa00" : "#555";
        }}
        (function initFanSection() {{
            var stored = null;
            try {{ stored = localStorage.getItem("fansExpanded"); }} catch(e) {{}}
            setFanSectionExpanded(stored === "1");
            renderFanSection({hw_fans_js}, {hw_cpu_pct_js}, {fan_status_js});
        }})();

        // ── Hardware Alerts ───────────────────────────────────────────────
        var _hwAlertIcons = {{
            "cpu_temp": "🌡️", "ambient_temp": "🌡️", "nvme_temp": "💾",
            "gpu_temp": "🎮", "cpu_sustained_load": "⚡"
        }};
        function _hwAlertIcon(key) {{
            if (key.startsWith("fan_stopped/")) return "🌀";
            return _hwAlertIcons[key] || "⚠️";
        }}
        function _fmtTs(ts) {{
            if (!ts) return "—";
            var d = new Date(ts * 1000);
            return d.toLocaleString();
        }}

        var _currentHwAlerts = [];
        function renderHwAlerts(alerts) {{
            _currentHwAlerts = alerts || [];
            var el = document.getElementById("hwAlertsList");
            if (!el) return;
            if (!_currentHwAlerts.length) {{
                el.innerHTML = '<div class="hw-alert-empty">' + tierText(
                    '✓ All hardware operating normally — no problems detected',
                    '✓ No active hardware alerts',
                    '✓ No active HW alerts'
                ) + '</div>';
                return;
            }}
            el.innerHTML = _currentHwAlerts.map(function(a, i) {{
                var icon = _hwAlertIcon(a.alert_key);
                var sevClass = "hw-alert-sev-" + (a.severity || "HIGH");
                var since = _fmtTs(a.first_triggered_ts);
                return '<div class="hw-alert-row" onclick="openHwAlertDetailModal(' + i + ')">' +
                    '<span class="hw-alert-icon">' + icon + '</span>' +
                    '<span class="' + sevClass + '">' + (a.severity || "") + '</span>' +
                    '<span class="hw-alert-body">' +
                        '<div class="hw-alert-msg">' + (a.breach || "") + '</div>' +
                        '<div class="hw-alert-meta">Since ' + since + '</div>' +
                    '</span>' +
                    '<span style="color:#888;font-size:0.8em">▸</span>' +
                '</div>';
            }}).join("");
        }}

        function openHwAlertDetailModal(idx) {{
            var a = _currentHwAlerts[idx];
            if (!a) return;
            var icon = _hwAlertIcon(a.alert_key);
            document.getElementById("hwAlertDetailTitle").textContent =
                icon + " " + (a.severity || "Alert") + " — Hardware Alert";
            document.getElementById("hwAlertDetailBody").innerHTML =
                '<div class="hw-alert-detail-field">' +
                    '<div class="hw-alert-detail-label">Condition</div>' +
                    '<div class="hw-alert-detail-value">' + (a.breach || "—") + '</div>' +
                '</div>' +
                '<div class="hw-alert-detail-field">' +
                    '<div class="hw-alert-detail-label">Recommendation</div>' +
                    '<div class="hw-alert-detail-value">' + (a.recommendation || "—") + '</div>' +
                '</div>' +
                '<div class="hw-alert-detail-field">' +
                    '<div class="hw-alert-detail-label">First triggered</div>' +
                    '<div class="hw-alert-detail-value">' + _fmtTs(a.first_triggered_ts) + '</div>' +
                '</div>' +
                '<div class="hw-alert-detail-field">' +
                    '<div class="hw-alert-detail-label">Last confirmed</div>' +
                    '<div class="hw-alert-detail-value">' + _fmtTs(a.last_triggered_ts) + '</div>' +
                '</div>' +
                '<div class="hw-alert-detail-field">' +
                    '<div class="hw-alert-detail-label">Alert key</div>' +
                    '<div class="hw-alert-detail-value" style="color:#999;font-size:0.85em">' +
                        (a.alert_key || "—") +
                    '</div>' +
                '</div>';
            document.getElementById("hwAlertDetailModal").style.display = "block";
        }}

        function closeHwAlertDetailModal() {{
            document.getElementById("hwAlertDetailModal").style.display = "none";
        }}

        renderHwAlerts({hw_alerts_js});

        function applyHwLive(hw) {{
            if (!hw) return;
            document.getElementById("hwCpuTemp").textContent = fmtHw(hw.cpu_temp, "°C");
            document.getElementById("hwGpuTemp").textContent = fmtHw(hw.gpu_temp, "°C");
            document.getElementById("hwAmbient").textContent = fmtHw(hw.ambient_temp, "°C");
            document.getElementById("hwNvme").textContent = fmtHw(hw.nvme_temp, "°C");
            document.getElementById("hwCpuPct").textContent = fmtHw(hw.cpu_percent, "%");
            document.getElementById("hwRamPct").textContent = fmtHw(hw.ram_percent, "%");
            var ramFreeEl = document.getElementById("hwRamFree");
            if (ramFreeEl) {{
                var freeGb = (hw.ram_total_gb != null && hw.ram_used_gb != null)
                    ? Math.round((hw.ram_total_gb - hw.ram_used_gb) * 10) / 10
                    : null;
                ramFreeEl.textContent = freeGb != null ? freeGb + " GB free" : "";
            }}
            document.getElementById("hwGpuFan").textContent = fmtHw(hw.gpu_fan_percent, "%");
            renderFanSection(hw.fans, hw.cpu_percent, hw.fan_status);
        }}

        function openHwModal() {{
            document.getElementById("hwModal").style.display = "block";
            document.getElementById("hwModalStatus").textContent = "Loading…";
            fetch("/api/hw-metrics", {{cache: "no-store"}})
                .then(r => r.json())
                .then(d => {{
                    if (d.error) {{
                        document.getElementById("hwModalStatus").textContent = "Error: " + d.error;
                        return;
                    }}
                    applyHwLive(d.live);
                    renderHwCharts(d.samples || [], (d.health_sparkline || {{}}).scores || []);
                    var n = (d.samples || []).length;
                    document.getElementById("hwModalStatus").textContent =
                        n ? n + " samples (5 min each, oldest → newest)"
                          : "No samples yet — the monitor records one every 5 minutes.";
                }})
                .catch(e => {{
                    document.getElementById("hwModalStatus").textContent = "Error: " + e;
                }});
        }}

        function closeHwModal() {{
            document.getElementById("hwModal").style.display = "none";
        }}

        function colorForCount(n) {{
            if (n === 0) return "#00ff88";
            if (n <= 5) return "#ffaa00";
            return "#ff4444";
        }}

        function colorForScore(s) {{
            if (s >= 80) return "#00ff88";
            if (s >= 50) return "#ffaa00";
            return "#ff4444";
        }}

        function openAlertBreakdownModal() {{
            document.getElementById("alertBreakdownModal").style.display = "block";
            document.getElementById("alertBreakdownBody").innerHTML = "Loading…";
            fetch("/api/alert-breakdown-24h", {{cache: "no-store"}})
                .then(r => r.json())
                .then(d => {{
                    window._breakdown24h = d.breakdown || [];
                    var rows = window._breakdown24h.map(function(b, idx) {{
                        return '<tr class="hw-clickable" style="cursor:pointer" onclick="open24hAlertDetail(' + idx + ')">' +
                               '<td>' + escapeHtml(b.type) + '</td>' +
                               '<td style="text-align:right">' + b.count + '</td>' +
                               '<td style="color:#00d4ff;font-size:0.8em;padding-left:6px">▸</td>' +
                               '</tr>';
                    }}).join("");
                    if (!rows) rows = `<tr><td colspan=3 style="color:#00ff88">${{tierText(
                        "✓ No hardware or service alerts in the last 24 hours — everything is running normally",
                        "No system alerts in the last 24 hours.",
                        "No alerts (24h)"
                    )}}</td></tr>`;
                    var ct = d.thermal_fan || 0, cs = d.service_down || 0;
                    var intro = tierText(
                        "These are hardware and service alerts from the background watchdog — things like overheating, fan failures, or a security service going down. Click any row for full detail. Network intrusion alerts are shown separately in the AI Firewall section below.",
                        "Thermal, fan-failure, and service-down alerts from the watchdog. Click a row for detail. Suricata network alerts appear in the AI Firewall section.",
                        "Watchdog alerts (thermal/fan/service). Click row for detail. Network alerts → AI Firewall."
                    );
                    document.getElementById("alertBreakdownBody").innerHTML = `
                        <p style="color:#aaa;font-size:0.85em;margin:0 0 10px 0">${{intro}}</p>
                        <div style="display:flex;gap:20px;margin:10px 0">
                            <div><span style="color:#aaa">${{tierText("Total alerts:","Total:","Total:")}}</span> <strong style="color:${{colorForCount(d.total || 0)}};font-size:1.2em">${{d.total || 0}}</strong></div>
                            <div><span style="color:#aaa">${{tierText("Overheating / fan:","Thermal/Fan:","Thermal:")}}</span> <strong style="color:${{colorForCount(ct)}}">${{ct}}</strong></div>
                            <div><span style="color:#aaa">${{tierText("Service went down:","Service down:","Svc down:")}}</span> <strong style="color:${{colorForCount(cs)}}">${{cs}}</strong></div>
                        </div>
                        <table class="breakdown-table">
                            <thead><tr><th>${{tierText("What triggered it","Alert type","Type")}}</th><th style="text-align:right">${{tierText("How many times","Count","#")}}</th><th></th></tr></thead>
                            <tbody>${{rows}}</tbody>
                        </table>
                    `;
                }})
                .catch(e => {{
                    document.getElementById("alertBreakdownBody").innerHTML = `<p style="color:#ff4444">Error: ${{escapeHtml(e)}}</p>`;
                }});
        }}

        function closeAlertBreakdownModal() {{
            document.getElementById("alertBreakdownModal").style.display = "none";
        }}

        function _hw24hRec(alertType) {{
            var k = alertType.replace(/^thermal[/]fan: /, "");
            var recs = {{
                "cpu_temp":          "Check CPU fan and case airflow. Consider reducing load until temps recover.",
                "ambient_temp":      "Check room ventilation, dust filters, and chassis fan operation.",
                "nvme_temp":         "Verify NVMe heatsink contact and ambient airflow over the M.2 slot.",
                "gpu_temp":          "Check GPU fan and case airflow. Reduce GPU load (gaming, compute, ML) until temps recover.",
                "cpu_sustained_load":"Investigate runaway processes with `top` / `ps auxf`. May indicate stuck job or attack.",
                "cpu_fan_failure":   "Inspect the CPU fan immediately. Risk of thermal damage if not addressed."
            }};
            if (recs[k]) return recs[k];
            if (k.indexOf("fan_stopped") === 0) return "Inspect the fan. A stopped fan under sustained load will raise temperatures.";
            if (alertType.indexOf("service down:") === 0)
                return "Check service status with `systemctl status " + escapeHtml(k) + "`. Restart if needed and investigate root cause.";
            return "";
        }}

        function open24hAlertDetail(idx) {{
            var b = (window._breakdown24h || [])[idx];
            if (!b) return;
            var rec  = _hw24hRec(b.type);
            var icon = b.type.indexOf("service") === 0 ? "🔧" : "🌡️";
            document.getElementById("hwAlertDetailTitle").textContent = icon + " " + b.type;

            var occs = (b.occurrences || []).map(function(o) {{
                return '<div style="padding:4px 0;border-bottom:1px solid #1e2d4e;font-size:0.88em">' +
                       '<span style="color:#00d4ff">' + escapeHtml(o.ts) + '</span>' +
                       (o.breach ? ' &mdash; <span style="color:#ddd">' + escapeHtml(o.breach) + '</span>'
                                 : ' <span style="color:#555">(email delivery failed — breach detail not logged)</span>') +
                       '</div>';
            }}).join("") || '<div style="color:#555;font-size:0.88em">No occurrence detail captured in log</div>';

            document.getElementById("hwAlertDetailBody").innerHTML =
                '<div class="hw-alert-detail-field">' +
                    '<div class="hw-alert-detail-label">Alert key</div>' +
                    '<div class="hw-alert-detail-value">' + escapeHtml(b.type) +
                        ' <span style="color:#888;font-size:0.85em">(' + b.count +
                        ' occurrence' + (b.count !== 1 ? 's' : '') + ' in last 24h)</span></div>' +
                '</div>' +
                (rec ?
                    '<div class="hw-alert-detail-field">' +
                        '<div class="hw-alert-detail-label">Recommendation</div>' +
                        '<div class="hw-alert-detail-value">' + escapeHtml(rec) + '</div>' +
                    '</div>'
                : '') +
                '<div class="hw-alert-detail-field">' +
                    '<div class="hw-alert-detail-label">' +
                        (b.count > 1 ? 'Occurrences (most recent first)' : 'Occurrence') +
                    '</div>' +
                    '<div class="hw-alert-detail-value">' + occs + '</div>' +
                '</div>';

            document.getElementById("hwAlertDetailModal").style.display = "block";
        }}

        function openHealthModal() {{
            document.getElementById("healthModal").style.display = "block";
            document.getElementById("healthModalBody").innerHTML = "Loading…";
            fetch("/api/health-score", {{cache: "no-store"}})
                .then(r => r.json())
                .then(d => {{
                    var totalColor = colorForScore(d.score);
                    var rows = (d.components || []).map(c => {{
                        var barColor = colorForScore(c.score);
                        return `<tr>
                            <td><strong>${{escapeHtml(c.name)}}</strong><br><span style="color:#aaa;font-size:0.85em">${{escapeHtml(c.detail)}}</span></td>
                            <td style="width:100px"><div class="health-bar"><div class="health-bar-fill" style="width:${{c.score}}%;background:${{barColor}}"></div></div><div style="text-align:right;color:#aaa;font-size:0.8em">${{c.score}}%</div></td>
                            <td style="text-align:right;width:60px" title="${{tierText('How much this factor contributes to the total score','Weight','Weight')}}">${{c.weight}}%</td>
                            <td style="text-align:right;width:80px;color:${{barColor}};font-weight:bold">${{c.contribution}}</td>
                        </tr>`;
                    }}).join("");
                    var svcList = (d.services || []).map(s =>
                        `<span style="color:${{s.active ? '#00ff88' : '#ff4444'}};margin-right:12px">${{s.active ? '●' : '○'}} ${{escapeHtml(s.name)}}</span>`
                    ).join("");
                    var overallLabel = tierText("Overall Health Score", "Overall", "Score");
                    var noAlerts = `<tr><td colspan=2 style="color:#00ff88">${{tierText("✓ No system alerts in the last 24 hours — all clear","No system alerts in the last 24 hours.","No alerts (24h)")}}</td></tr>`;
                    document.getElementById("healthModalBody").innerHTML = `
                        <div style="margin:10px 0">
                            <div style="font-size:0.85em;color:#aaa">${{overallLabel}}</div>
                            <div style="font-size:2.5em;font-weight:bold;color:${{totalColor}}">${{d.score}}%</div>
                        </div>
                        <table class="breakdown-table">
                            <thead><tr>
                                <th>${{tierText("Factor","Component","Component")}}</th>
                                <th style="text-align:right">${{tierText("Health","Score","Score")}}</th>
                                <th style="text-align:right">${{tierText("Importance","Weight","Wt")}}</th>
                                <th style="text-align:right">${{tierText("Points","Points","Pts")}}</th>
                            </tr></thead>
                            <tbody>${{rows}}</tbody>
                        </table>
                        <div style="margin-top:15px">
                            <div style="color:#aaa;font-size:0.85em;margin-bottom:4px">${{tierText("Security services running","Services","Services")}}</div>
                            ${{svcList}}
                        </div>
                    `;
                }})
                .catch(e => {{
                    document.getElementById("healthModalBody").innerHTML = `<p style="color:#ff4444">Error: ${{escapeHtml(e)}}</p>`;
                }});
        }}

        function closeHealthModal() {{
            document.getElementById("healthModal").style.display = "none";
        }}

        function vpnStatusColor(status) {{
            if (!status) return "#ff4444";
            var s = status.toLowerCase();
            if (s === "connected") return "#00ff88";
            if (s === "connecting" || s === "reconnecting") return "#ffaa00";
            return "#ff4444";
        }}

        function openVpnModal() {{
            document.getElementById("vpnModal").style.display = "block";
            document.getElementById("vpnModalContent").innerHTML = "Loading…";
            document.getElementById("vpnModalActions").style.display = "block";
            fetch("/api/vpn-status", {{cache: "no-store"}})
                .then(r => r.json())
                .then(d => {{
                    var color = vpnStatusColor(d.status);
                    var html = `
                        <p><strong>${{tierText("VPN Service:","Provider:","Provider:")}}</strong> ${{escapeHtml(d.provider || "Unknown")}}</p>
                        <p><strong>${{tierText("Connection Status:","Status:","Status:")}}</strong> <span style="color:${{color}};font-weight:bold">${{escapeHtml(d.status || "Unknown")}}</span></p>
                        <p><strong>${{tierText("Your VPN IP Address:","VPN IP:","VPN IP:")}}</strong> ${{escapeHtml(d.vpn_ip || "—")}}</p>
                        <p><strong>${{tierText("Connected Server:","Server / Location:","Server:")}}</strong> ${{escapeHtml(d.server_location || "—")}}</p>
                        <p><strong>${{tierText("Encryption Protocol:","Protocol:","Protocol:")}}</strong> ${{escapeHtml(d.protocol || "—")}}</p>
                    `;
                    if (d.split_tunnel_apps && d.split_tunnel_apps.length) {{
                        html += `<p style="margin-bottom:2px"><strong>${{tierText("Apps bypassing VPN (split tunnel):","Split Tunnel Apps:","Split tunnel:")}}</strong></p><ul style="font-size:0.85em;color:#aaa;margin:4px 0 0 18px">`;
                        d.split_tunnel_apps.forEach(function(app) {{ html += `<li>${{escapeHtml(app)}}</li>`; }});
                        html += `</ul>`;
                    }} else if (d.provider && d.provider.toLowerCase().includes("pia")) {{
                        html += `<p style="color:#aaa;font-size:0.85em">${{tierText("Split tunnel: no apps are bypassing the VPN","Split tunnel: none configured","Split tunnel: none")}}</p>`;
                    }}
                    document.getElementById("vpnModalContent").innerHTML = html;
                    // Hide action buttons if no supported CLI
                    if (!d.provider) {{
                        document.getElementById("vpnModalActions").style.display = "none";
                    }}
                }})
                .catch(function(e) {{
                    document.getElementById("vpnModalContent").innerHTML = `<p style="color:#ff4444">Error: ${{escapeHtml(String(e))}}</p>`;
                }});
        }}

        function closeVpnModal() {{
            document.getElementById("vpnModal").style.display = "none";
        }}

        function vpnAction(action) {{
            var btn = event.target;
            btn.disabled = true;
            btn.textContent = action === "connect" ? "Connecting…" : "Disconnecting…";
            fetch("/api/vpn/" + action, {{cache: "no-store"}})
                .then(r => r.json())
                .then(function(d) {{
                    if (d.error) {{
                        alert("VPN error: " + d.error);
                        btn.disabled = false;
                        btn.textContent = action === "connect" ? "🔄 Reconnect" : "⏹ Disconnect";
                    }} else {{
                        setTimeout(openVpnModal, 2500);
                    }}
                }})
                .catch(function(e) {{
                    alert("Error: " + e);
                    btn.disabled = false;
                }});
        }}

        document.addEventListener("keydown", function(e) {{
            if (e.key !== "Escape") return;
            if (document.getElementById("hwModal").style.display === "block") closeHwModal();
            if (document.getElementById("alertBreakdownModal").style.display === "block") closeAlertBreakdownModal();
            if (document.getElementById("healthModal").style.display === "block") closeHealthModal();
            if (document.getElementById("vpnModal").style.display === "block") closeVpnModal();
            if (document.getElementById("hwAlertDetailModal").style.display === "block") closeHwAlertDetailModal();
        }});
        document.getElementById("hwModal").addEventListener("click", function(e) {{
            if (e.target.id === "hwModal") closeHwModal();
        }});
        document.getElementById("alertBreakdownModal").addEventListener("click", function(e) {{
            if (e.target.id === "alertBreakdownModal") closeAlertBreakdownModal();
        }});
        document.getElementById("healthModal").addEventListener("click", function(e) {{
            if (e.target.id === "healthModal") closeHealthModal();
        }});

        function shortTs(ts) {{
            if (!ts) return "";
            var t = ts.replace("T", " ");
            return t.length > 16 ? t.slice(5, 16) : t;
        }}

        function makeChart(canvasId, labels, datasets, yLabel) {{
            var ctx = document.getElementById(canvasId).getContext("2d");
            if (hwCharts[canvasId]) hwCharts[canvasId].destroy();
            hwCharts[canvasId] = new Chart(ctx, {{
                type: "line",
                data: {{labels: labels, datasets: datasets}},
                options: {{
                    responsive: true,
                    interaction: {{mode: "index", intersect: false}},
                    plugins: {{
                        legend: {{labels: {{color: "#ccc", boxWidth: 12}}}},
                        tooltip: {{enabled: true}}
                    }},
                    scales: {{
                        x: {{ticks: {{color: "#888", maxTicksLimit: 8, autoSkip: true}},
                             grid: {{color: "#222"}}}},
                        y: {{ticks: {{color: "#888"}},
                             grid: {{color: "#222"}},
                             title: {{display: !!yLabel, text: yLabel || "", color: "#888"}}}}
                    }},
                    elements: {{point: {{radius: 0}}, line: {{tension: 0.25, borderWidth: 1.5}}}}
                }}
            }});
        }}

        function pick(samples, key) {{ return samples.map(s => s[key]); }}

        function renderHwCharts(samples, healthScores) {{
            var labels = samples.map(s => shortTs(s.timestamp));
            makeChart("chartTemp", labels, [
                {{label: "CPU",     data: pick(samples, "cpu_temp"),     borderColor: "#ff4444", backgroundColor: "rgba(255,68,68,0.1)"}},
                {{label: "GPU",     data: pick(samples, "gpu_temp"),     borderColor: "#00ff88", backgroundColor: "rgba(0,255,136,0.1)"}},
                {{label: "Ambient", data: pick(samples, "ambient_temp"), borderColor: "#ffaa00", backgroundColor: "rgba(255,170,0,0.1)"}},
                {{label: "NVMe",    data: pick(samples, "nvme_temp"),    borderColor: "#00d4ff", backgroundColor: "rgba(0,212,255,0.1)"}}
            ], "°C");
            // Fan chart: use array position as the primary key so duplicate
            // human-readable labels (e.g. 8× "Chassis Motherboard Fan") each
            // get their own line.  Append " #N" suffix to distinguish repeats.
            var _fanCount = 0;
            samples.forEach(function(s) {{ _fanCount = Math.max(_fanCount, (s.fans || []).length); }});
            var _fanLabels = [];
            for (var _si = 0; _si < samples.length; _si++) {{
                if (samples[_si].fans && samples[_si].fans.length > 0) {{
                    var _seen = {{}};
                    samples[_si].fans.forEach(function(f, fi) {{
                        var base = String(f.label || ("Fan " + (fi + 1)));
                        var lbl = base, n = 1;
                        while (_seen[lbl]) {{ lbl = base + " #" + (++n); }}
                        _seen[lbl] = true;
                        _fanLabels[fi] = lbl;
                    }});
                    break;
                }}
            }}
            for (var _fi = _fanLabels.length; _fi < _fanCount; _fi++) {{
                _fanLabels[_fi] = "Fan " + (_fi + 1);
            }}
            var fanPalette = ["#00ff88","#00d4ff","#8800ff","#ffaa00","#ff4444","#ff00ff","#ffffff","#88ffcc","#ffbb44","#aa88ff"];
            makeChart("chartFans", labels, _fanLabels.map(function(lbl, fi) {{
                var posIdx = fi;
                return {{
                    label: lbl,
                    data: samples.map(function(s) {{
                        var fa = s.fans || [];
                        return posIdx < fa.length ? fa[posIdx].rpm : null;
                    }}),
                    borderColor: fanPalette[fi % fanPalette.length]
                }};
            }}), "RPM");
            makeChart("chartUsage", labels, [
                {{label: "CPU %",      data: pick(samples, "cpu_percent"), borderColor: "#ff4444"}},
                {{label: "RAM (GB)",   data: pick(samples, "ram_used_gb"), borderColor: "#00ff88", yAxisID: "y"}}
            ], "%");
            makeChart("chartIo", labels, [
                {{label: "Disk Read",  data: pick(samples, "disk_read_mb"),  borderColor: "#00d4ff"}},
                {{label: "Disk Write", data: pick(samples, "disk_write_mb"), borderColor: "#8800ff"}},
                {{label: "Net In",     data: pick(samples, "net_in_mb"),     borderColor: "#00ff88"}},
                {{label: "Net Out",    data: pick(samples, "net_out_mb"),    borderColor: "#ffaa00"}}
            ], "MB");
            makeChart("chartHealth", labels, [
                {{label: "Health", data: healthScores || [],
                  borderColor: "#00d4ff",
                  backgroundColor: "rgba(0,212,255,0.15)",
                  fill: true}}
            ], "%");
        }}

        var refreshTick = 0;
        function refreshDashboard() {{
            fetch("/api/stats", {{cache: "no-store"}})
                .then(r => r.json())
                .then(d => {{
                    document.getElementById("lastUpdated").textContent = d.now;
                    document.getElementById("phTotal").textContent = d.pihole.total;
                    document.getElementById("phBlocked").textContent = d.pihole.blocked;
                    document.getElementById("phPercent").textContent = d.pihole.percent + "%";
                    document.getElementById("cntTotal").textContent = d.alert_counts.total;
                    document.getElementById("cntP1").textContent = d.alert_counts.p1;
                    document.getElementById("cntP2").textContent = d.alert_counts.p2;
                    document.getElementById("cntP3").textContent = d.alert_counts.p3;
                    applyP3Visibility(isP3Shown());
                    var banner = document.getElementById("quarantineBanner");
                    var list = document.getElementById("quarantineList");
                    if (d.quarantines && d.quarantines.length) {{
                        banner.style.display = "block";
                        list.innerHTML = d.quarantine_banner_html;
                    }} else {{
                        banner.style.display = "none";
                        list.innerHTML = "";
                    }}
                    if (d.hw) applyHwLive(d.hw);
                    if (d.hw_alerts !== undefined) renderHwAlerts(d.hw_alerts);
                    if (d.alert_24h) {{
                        var ael = document.getElementById("hwAlert24h");
                        ael.textContent = d.alert_24h.total;
                        ael.style.color = colorForCount(d.alert_24h.total);
                    }}
                    if (d.health) {{
                        var hel = document.getElementById("hwHealthScore");
                        hel.textContent = d.health.score + "%";
                        hel.style.color = colorForScore(d.health.score);
                    }}
                    if (d.review_queue_count !== undefined) {{
                        document.getElementById("cntReviewQueue").textContent = d.review_queue_count;
                    }}
                    if (d.vpn) {{
                        var vpnEl = document.getElementById("vpnStatusText");
                        var vpnLabel = d.vpn.provider
                            ? d.vpn.provider + " — " + d.vpn.status
                            : "VPN — " + d.vpn.status;
                        vpnEl.textContent = vpnLabel;
                        vpnEl.style.color = vpnStatusColor(d.vpn.status);
                    }}
                    refreshTick++;
                    if (refreshTick % 5 === 0) {{
                        document.getElementById("alertsRows").innerHTML = d.alerts_html;
                        document.getElementById("devicesRows").innerHTML = d.devices_html;
                        document.getElementById("reviewQueueRows").innerHTML = d.review_queue_html;
                        if (d.module_cards_html !== undefined) {{
                            document.getElementById("moduleCardsContainer").innerHTML = d.module_cards_html;
                        }}
                        applyTierText();
                    }}
                }})
                .catch(e => console.error("refresh failed", e));
        }}
        setInterval(refreshDashboard, 60000);

        // Re-apply tier-dependent JS content when the user changes tier from /settings
        // (localStorage storage events fire across tabs).
        window.onTierChange = function() {{
            applyTierText();
            updateActionButtonLabels();
        }};
        window.addEventListener("storage", function(e) {{
            if (e.key === "explanationTier") {{
                applyTierText();
                updateActionButtonLabels();
            }}
        }});

        function updateActionButtonLabels() {{
            var b = document.getElementById("btnBlock");
            var ig = document.getElementById("btnIgnore");
            var mo = document.getElementById("btnMonitor");
            if (b)  b.textContent  = tierText("🚫 Block this IP address", "🚫 Block IP", "🚫 Block");
            if (ig) ig.textContent = tierText("✓ Ignore — stop alerting on this rule", "✓ Ignore Rule", "✓ Ignore");
            if (mo) mo.textContent = tierText("👁 Keep watching (monitor only)", "👁 Monitor", "👁 Monitor");
        }}
        updateActionButtonLabels();

        function confirmQuarantine(id) {{
            if (!confirm("Confirm this block permanently? The ufw rule will be kept and the alert marked 'block'.")) return;
            fetch("/api/quarantine/" + id + "/confirm")
                .then(r => r.json())
                .then(d => {{
                    if (d.success) {{ refreshDashboard(); }}
                    else {{ alert("Confirm failed: " + (d.error || "unknown")); }}
                }})
                .catch(e => alert("Error: " + e));
        }}

        function liftQuarantine(id, ip) {{
            if (!confirm("Lift this quarantine for " + ip + "? The ufw rule will be removed.")) return;
            fetch("/api/quarantine/" + id + "/lift")
                .then(r => r.json())
                .then(d => {{
                    if (d.success) {{ refreshDashboard(); }}
                    else {{ alert("Lift failed: " + (d.error || "unknown")); }}
                }})
                .catch(e => alert("Error: " + e));
        }}
    </script>
</body>
</html>"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)