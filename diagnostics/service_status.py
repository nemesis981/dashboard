"""Check: systemd service status for all Nemesis components."""

import subprocess

META = {
    "id": "service_status",
    "name": "Service Status",
    "icon": "🔧",
    "descriptions": {
        "beginner": "Checks whether all the background programs that keep your firewall running are active and healthy.",
        "intermediate": "Checks systemd active/inactive state for Suricata, Pi-hole, and all Nemesis services.",
        "pro": "systemctl is-active for Suricata, pihole-FTL, nemesis-dashboard/watchdog/hw-monitor/alert-watcher.",
    },
}

SERVICES = [
    ("suricata",               "Suricata IDS"),
    ("pihole-FTL",             "Pi-hole DNS"),
    ("nemesis-dashboard",      "Dashboard"),
    ("nemesis-watchdog",       "Watchdog"),
    ("nemesis-hw-monitor",     "HW Monitor"),
    ("nemesis-alert-watcher",  "Alert Watcher"),
]


def run() -> dict:
    lines = []
    any_bad = False
    for svc, label in SERVICES:
        try:
            r = subprocess.run(
                ["systemctl", "is-active", svc],
                capture_output=True, text=True, timeout=5,
            )
            state = r.stdout.strip() or "unknown"
        except Exception as e:
            state = f"error ({e})"
        ok = state == "active"
        if not ok:
            any_bad = True
        mark = "✓" if ok else "✗"
        lines.append(f"{mark} {label:25s} ({svc}): {state}")

    return {
        "id": META["id"],
        "name": META["name"],
        "icon": META["icon"],
        "status": "warn" if any_bad else "ok",
        "summary": "All services active" if not any_bad else "One or more services not running",
        "output": "\n".join(lines),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))
