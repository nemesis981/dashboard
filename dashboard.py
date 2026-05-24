from flask import Flask, jsonify, request
import requests
import subprocess
import sqlite3
import json
import html
import os
import sys
from datetime import datetime

sys.path.insert(0, "/home/paul/alert_manager")
from ip_enrichment import enrich_ip

app = Flask(__name__)

PIHOLE_IP = "192.168.4.69"
PIHOLE_PASSWORD = os.environ.get("PIHOLE_PASSWORD", "")
DB_PATH = "/home/paul/alert_manager/alerts.db"
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")

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
    except:
        return None

def get_pihole_stats():
    try:
        token = get_pihole_token()
        if not token:
            return None
        headers = {"sid": token}
        response = requests.get(f"http://{PIHOLE_IP}/api/stats/summary", headers=headers, timeout=3)
        return response.json()
    except:
        return None

def get_clamav_status():
    try:
        result = subprocess.run(
            ["sudo", "systemctl", "status", "clamav-daemon"],
            capture_output=True, text=True
        )
        return "Running" if "active (running)" in result.stdout else "Stopped"
    except:
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
    except:
        return {"cpu": "Unknown", "memory": "Unknown", "disk": "Unknown"}

def get_suricata_alerts():
    try:
        result = subprocess.run(
            ["sudo", "tail", "-n", "100", "/var/log/suricata/fast.log"],
            capture_output=True, text=True
        )
        lines = result.stdout.strip().split("\n")
        return [l for l in lines if l]
    except:
        return []

def parse_alert(alert_line):
    try:
        timestamp = ""
        ts_token = alert_line.split(" ", 1)[0] if alert_line else ""
        if "/" in ts_token and "-" in ts_token:
            try:
                dt = datetime.strptime(ts_token, "%m/%d/%Y-%H:%M:%S.%f")
                timestamp = dt.strftime("%H:%M:%S")
            except ValueError:
                timestamp = ""
        priority = 3
        if "Priority: 1" in alert_line:
            priority = 1
        elif "Priority: 2" in alert_line:
            priority = 2
        rule_id = ""
        rule_name = ""
        classification = ""
        src_ip = ""
        dst_ip = ""
        protocol = ""
        if "[**] [" in alert_line:
            rule_part = alert_line.split("[**] [")[1].split("]")[0]
            rule_id = rule_part.split(":")[1] if ":" in rule_part else rule_part
        if "[**]" in alert_line:
            parts = alert_line.split("[**]")
            if len(parts) > 2:
                rule_name = parts[2].strip()
        if "[Classification:" in alert_line:
            classification = alert_line.split("[Classification:")[1].split("]")[0].strip()
        if "{" in alert_line and "}" in alert_line:
            protocol = alert_line.split("{")[1].split("}")[0]
        if "->" in alert_line and "} " in alert_line:
            flow = alert_line.split("} ")[1]
            if "->" in flow:
                parts = flow.split("->")
                src_ip = parts[0].strip().split(":")[0]
                dst_ip = parts[1].strip().split(":")[0]
        return {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "classification": classification,
            "priority": priority,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "raw": alert_line
        }
    except:
        return None

def get_db_alert(rule_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM alerts WHERE rule_id = ?", (rule_id,))
        result = c.fetchone()
        conn.close()
        return result
    except:
        return None

def get_alert_counts():
    try:
        alerts = get_suricata_alerts()
        today = datetime.now().strftime("%m/%d/%Y")
        p1 = sum(1 for a in alerts if "Priority: 1" in a and today in a)
        p2 = sum(1 for a in alerts if "Priority: 2" in a and today in a)
        p3 = sum(1 for a in alerts if "Priority: 3" in a and today in a)
        return {"total": p1+p2+p3, "p1": p1, "p2": p2, "p3": p3}
    except:
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
    except:
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
    except:
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
        return "<tr><td colspan=5 style='color:#00ff88'>✓ No active P1/P2 alerts requiring attention</td></tr>"
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
    return jsonify({
        "now": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "pihole": get_pihole_summary(),
        "alert_counts": get_alert_counts(),
        "alerts_html": render_alerts_html(get_active_alerts()),
        "devices_html": render_devices_html(get_network_devices()),
        "quarantines": quarantines,
        "quarantine_banner_html": render_quarantine_banner_html(quarantines),
    })


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
        ufw_rc = subprocess.run(
            ["sudo", "ufw", "delete", "deny", "from", ip],
            capture_output=True, text=True, timeout=10,
        ).returncode
        c.execute("UPDATE alerts SET action='pending' WHERE rule_id=?", (rule_id,))
        c.execute("UPDATE quarantines SET status='lifted' WHERE id=?", (q_id,))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "ip": ip, "rule_id": rule_id, "ufw_rc": ufw_rc})
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
        except:
            analysis = {
                "explanation": response_text,
                "risk_level": "UNKNOWN",
                "is_threat": False,
                "recommended_action": "Monitor",
                "reason": "Could not parse response"
            }
        now = datetime.now().isoformat()
        if existing:
            c.execute("UPDATE alerts SET explanation=?, risk_level=? WHERE rule_id=?",
                     (analysis["explanation"], analysis["risk_level"], rule_id))
        else:
            c.execute("""INSERT INTO alerts 
                (rule_id, rule_name, classification, priority, explanation, risk_level, action, times_seen, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, "pending", 1, ?, ?)""",
                (rule_id, raw_alert[:50], "", 1, analysis["explanation"], analysis["risk_level"], now, now))
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
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE alerts SET action=? WHERE rule_id=?", (action, rule_id))
        if c.rowcount == 0:
            now = datetime.now().isoformat()
            c.execute("""INSERT INTO alerts 
                (rule_id, rule_name, classification, priority, explanation, risk_level, action, times_seen, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)""",
                (rule_id, "", "", 1, "", "UNKNOWN", action, now, now))
        if action == "block":
            src_ip = request.args.get("ip", "")
            if src_ip:
                subprocess.run(["sudo", "ufw", "deny", "from", src_ip], capture_output=True)
        conn.commit()
        conn.close()
        return jsonify({"success": True, "action": action})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/firewall-db")
def firewall_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM alerts ORDER BY last_seen DESC")
        alerts = c.fetchall()
        conn.close()
        rows = ""
        for a in alerts:
            rows += f"""<tr>
                <td>{a[1]}</td>
                <td>{a[2][:40] if a[2] else ""}</td>
                <td>{a[5] or ""}</td>
                <td>{a[7]}</td>
                <td>{a[8]}</td>
                <td>{a[10] or ""}</td>
                <td>
                    <select onchange="changeAction({a[0]}, this.value)">
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
    <style>
        body {{ font-family: Arial; background: #1a1a2e; color: #eee; padding: 20px; }}
        h1 {{ color: #00d4ff; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #16213e; color: #00d4ff; padding: 10px; text-align: left; }}
        td {{ padding: 8px; border-bottom: 1px solid #333; font-size: 0.85em; }}
        select {{ background: #16213e; color: #eee; border: 1px solid #00d4ff; padding: 3px; }}
        a {{ color: #00d4ff; }}
    </style>
    <script>
        function changeAction(id, action) {{
            fetch("/api/db-action/" + id + "/" + action)
                .then(r => r.json()).then(d => console.log(d));
        }}
    </script>
</head>
<body>
    <h1>🛡️ Nemesis - Alert Database</h1>
    <p><a href="/">← Back to Dashboard</a></p>
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
        c.execute("UPDATE alerts SET action=? WHERE id=?", (action, alert_id))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/")
def dashboard():
    clamav_status = get_clamav_status()
    system_status = get_system_status()
    alert_counts = get_alert_counts()
    pihole = get_pihole_summary()
    total = pihole["total"]
    blocked = pihole["blocked"]
    percent = pihole["percent"]

    alerts_html = render_alerts_html(get_active_alerts())
    devices_html = render_devices_html(get_network_devices())
    quarantines = get_active_quarantines()
    quarantine_banner_html = render_quarantine_banner_html(quarantines)
    quarantine_banner_display = "block" if quarantines else "none"

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
    </style>
</head>
<body>
    <h1>🛡️ Nemesis Firewall</h1>
    <p style="color:#888;margin-top:0">Last updated: <span id="lastUpdated">{now}</span> | Stats refresh every 60s, tables every 5 min</p>

    <div class="quarantine-banner" id="quarantineBanner" style="display:{quarantine_banner_display}">
        <h2>🚨 Auto-Quarantined IPs</h2>
        <div id="quarantineList">{quarantine_banner_html}</div>
    </div>

    <div class="grid">
        <div class="card">
            <h2>Pi-hole DNS Protection</h2>
            <p>Queries Today: <span class="stat" id="phTotal">{total}</span></p>
            <p>Blocked: <span class="stat" id="phBlocked">{blocked}</span></p>
            <p>Percent Blocked: <span class="stat" id="phPercent">{percent}%</span></p>
        </div>

        <div class="card">
            <h2>System Status</h2>
            <p>ClamAV: <span class="{"running" if clamav_status == "Running" else "stopped"}">{clamav_status}</span></p>
            <p style="font-size:0.8em">CPU: {system_status.get("cpu", "N/A")}</p>
            <p style="font-size:0.8em">Memory: {system_status.get("memory", "N/A")}</p>
            <p style="font-size:0.8em">Disk: {system_status.get("disk", "N/A")}</p>
        </div>

        <div class="card full-width">
            <h2>🔥 AI Firewall — Today's Activity
                <a href="/firewall-db" style="float:right;color:#00d4ff;font-size:0.85em;text-decoration:none">📋 Alert Database</a>
            </h2>
            <div>
                <div class="counter-box"><div class="counter-num total" id="cntTotal">{alert_counts["total"]}</div><div>Total</div></div>
                <div class="counter-box"><div class="counter-num p1" id="cntP1">{alert_counts["p1"]}</div><div>Critical P1</div></div>
                <div class="counter-box"><div class="counter-num p2" id="cntP2">{alert_counts["p2"]}</div><div>High P2</div></div>
                <div class="counter-box"><div class="counter-num p3" id="cntP3">{alert_counts["p3"]}</div><div>Info P3</div></div>
            </div>
            <h3 style="color:#ffaa00;margin-top:15px">⚠️ Alerts Requiring Attention</h3>
            <table>
                <thead><tr><th>Priority</th><th>Time</th><th>Alert</th><th>Source IP</th><th>Action</th></tr></thead>
                <tbody id="alertsRows">
                {alerts_html}
                </tbody>
            </table>
        </div>

        <div class="card full-width">
            <h2>🖥️ Network Devices
                <span style="float:right;font-size:0.8em;color:#888">✅ Trusted &nbsp; ❓ Unverified</span>
            </h2>
            <table>
                <thead><tr><th>IP</th><th>Friendly Name</th><th>Type</th><th>MAC</th><th>Trust</th></tr></thead>
                <tbody id="devicesRows">
                {devices_html}
                </tbody>
            </table>
        </div>
    </div>

    <!-- Alert Modal -->
    <div class="modal" id="alertModal">
        <div class="modal-content">
            <h3>🔍 Nemesis AI Analysis</h3>
            <div id="modalContent">Analyzing...</div>
            <div style="margin-top:15px">
                <button class="btn btn-block" onclick="takeAction('block')">🚫 Block IP</button>
                <button class="btn btn-ignore" onclick="takeAction('ignore')">✓ Ignore Rule</button>
                <button class="btn btn-monitor" onclick="takeAction('monitor')">👁 Monitor</button>
                <button class="btn btn-report" id="btnReport" onclick="reportAbuse()" style="display:none">🚨 Report to AbuseIPDB</button>
                <button class="btn btn-close" onclick="closeModal()">✕ Close</button>
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
            document.getElementById("modalContent").innerHTML = "<p>🤖 Nemesis AI analyzing...</p>";
            fetch("/api/analyze/" + ruleId + "?raw=" + encodeURIComponent(rawAlert))
                .then(r => r.json())
                .then(data => {{
                    currentSrcIp = data.src_ip || "";
                    var cached = data.cached ? " <span style=\'color:#888\'>(cached)</span>" : " <span style=\'color:#00ff88\'>(AI analyzed)</span>";
                    var riskColor = data.risk_level === "HIGH" ? "#ff4444" : data.risk_level === "MEDIUM" ? "#ffaa00" : "#00ff88";
                    document.getElementById("modalContent").innerHTML = `
                        <p><strong>Risk Level:</strong> <span style="color:${{riskColor}}">${{escapeHtml(data.risk_level || "UNKNOWN")}}</span>${{cached}}</p>
                        <p><strong>Explanation:</strong> ${{escapeHtml(data.explanation || "No explanation available")}}</p>
                        <p><strong>Recommended Action:</strong> ${{escapeHtml(data.recommended_action || "Monitor")}}</p>
                        <p><strong>Reason:</strong> ${{escapeHtml(data.reason || "")}}</p>
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
                    var banner = document.getElementById("quarantineBanner");
                    var list = document.getElementById("quarantineList");
                    if (d.quarantines && d.quarantines.length) {{
                        banner.style.display = "block";
                        list.innerHTML = d.quarantine_banner_html;
                    }} else {{
                        banner.style.display = "none";
                        list.innerHTML = "";
                    }}
                    refreshTick++;
                    if (refreshTick % 5 === 0) {{
                        document.getElementById("alertsRows").innerHTML = d.alerts_html;
                        document.getElementById("devicesRows").innerHTML = d.devices_html;
                    }}
                }})
                .catch(e => console.error("refresh failed", e));
        }}
        setInterval(refreshDashboard, 60000);

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