"""Check: Pi-hole DNS health — service state and query stats."""

import subprocess
import os
import json

META = {
    "id": "pihole_health",
    "name": "Pi-hole DNS Health",
    "icon": "🕳️",
    "descriptions": {
        "beginner": "Checks whether Pi-hole (your DNS ad and tracker blocker) is running correctly and shows how many queries it has processed today.",
        "intermediate": "Pi-hole FTL service status, DNS query count, block rate, and gravity list size via the Pi-hole API.",
        "pro": "systemctl is-active pihole-FTL + Pi-hole v6 /api/stats/summary via session token from PIHOLE_PASSWORD env.",
    },
}

PIHOLE_IP = os.environ.get("PIHOLE_IP", "127.0.0.1:8080")


def run() -> dict:
    sections = []
    status = "ok"

    # Service check
    try:
        r = subprocess.run(
            ["systemctl", "is-active", "pihole-FTL"],
            capture_output=True, text=True, timeout=5,
        )
        state = r.stdout.strip() or "unknown"
        sections.append(f"pihole-FTL service: {state}")
        if state != "active":
            status = "warn"
    except Exception as e:
        sections.append(f"pihole-FTL service: error ({e})")
        status = "warn"

    # Try Pi-hole v6 API
    try:
        import urllib.request
        import urllib.parse

        pwd = os.environ.get("PIHOLE_PASSWORD", "")
        if pwd:
            # Authenticate
            auth_data = json.dumps({"password": pwd}).encode()
            auth_req = urllib.request.Request(
                f"http://{PIHOLE_IP}/api/auth",
                data=auth_data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(auth_req, timeout=5) as resp:
                auth_json = json.loads(resp.read().decode())
            sid = auth_json.get("session", {}).get("sid", "")
            if sid:
                stats_req = urllib.request.Request(
                    f"http://{PIHOLE_IP}/api/stats/summary",
                    headers={"sid": sid},
                )
                with urllib.request.urlopen(stats_req, timeout=5) as resp:
                    stats = json.loads(resp.read().decode())
                queries = stats.get("queries", {})
                total   = queries.get("total", "?")
                blocked = queries.get("blocked", "?")
                pct     = queries.get("percent_blocked", "?")
                gravity = stats.get("gravity", {}).get("domains_being_blocked", "?")
                sections.append(
                    f"DNS queries today:  {total}\n"
                    f"Blocked today:      {blocked} ({pct}%)\n"
                    f"Gravity list size:  {gravity} domains"
                )
            else:
                sections.append("Pi-hole API: authentication failed (no session ID)")
                status = "warn"
        else:
            sections.append("Pi-hole API: PIHOLE_PASSWORD not set — skipping stats query")
    except Exception as e:
        sections.append(f"Pi-hole API: unavailable ({e})")
        if status == "ok":
            status = "warn"

    return {
        "id": META["id"],
        "name": META["name"],
        "icon": META["icon"],
        "status": status,
        "summary": "Pi-hole stats retrieved" if status == "ok" else "Pi-hole check incomplete",
        "output": "\n".join(sections),
    }


if __name__ == "__main__":
    import json as _json
    print(_json.dumps(run(), indent=2))
