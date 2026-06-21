"""Check: tail recent lines from key Nemesis log files."""

import subprocess
import os

META = {
    "id": "log_tails",
    "name": "Recent Log Entries",
    "icon": "📋",
    "descriptions": {
        "beginner": "Shows the most recent activity logs from the watchdog, hardware monitor, and alert systems — useful for seeing what the firewall has been doing lately.",
        "intermediate": "Last 30 lines from watchdog.log, hw_monitor.log, and alert_watcher.log.",
        "pro": "tail -n 30 on watchdog.log, hw_monitor.log, alert_watcher.log — raw output, redacted.",
    },
}

_LOG_BASE = "/home/paul/alert_manager"
LOG_FILES = [
    (os.path.join(_LOG_BASE, "watchdog.log"),      "Watchdog"),
    (os.path.join(_LOG_BASE, "hw_monitor.log"),    "HW Monitor"),
    (os.path.join(_LOG_BASE, "alert_watcher.log"), "Alert Watcher"),
]


def run() -> dict:
    sections = []
    any_error = False
    for path, label in LOG_FILES:
        try:
            r = subprocess.run(
                ["tail", "-n", "30", path],
                capture_output=True, text=True, timeout=10,
            )
            content = r.stdout if r.stdout else "(empty)"
        except Exception as e:
            content = f"(error: {e})"
            any_error = True
        sections.append(f"=== {label} — {path} (last 30 lines) ===\n{content.rstrip()}")

    return {
        "id": META["id"],
        "name": META["name"],
        "icon": META["icon"],
        "status": "warn" if any_error else "info",
        "summary": "Log tails retrieved" + (" (some errors)" if any_error else ""),
        "output": "\n\n".join(sections),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))
