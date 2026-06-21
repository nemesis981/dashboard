"""Check: Suricata IDS health — today's alert counts and recent log errors."""

import subprocess
from datetime import datetime

META = {
    "id": "suricata_health",
    "name": "Suricata IDS Health",
    "icon": "🔍",
    "descriptions": {
        "beginner": "Checks that your intrusion detection system is running and shows how many network alerts it has generated today.",
        "intermediate": "Today's fast.log alert counts (P1/P2/P3) and last 20 lines of suricata.log for errors.",
        "pro": "Parses /var/log/suricata/fast.log for today's date prefix, counts by priority; tails suricata.log for ERR/WARN.",
    },
}


def run() -> dict:
    sections = []
    status = "ok"

    today = datetime.now().strftime("%m/%d/%Y")
    prefix = today + "-"

    # Count today's alerts
    try:
        r = subprocess.run(
            ["sudo", "tail", "-n", "200000", "/var/log/suricata/fast.log"],
            capture_output=True, text=True, timeout=30,
        )
        p1 = p2 = p3 = 0
        for line in r.stdout.splitlines():
            if not line.startswith(prefix):
                continue
            if "Priority: 1" in line:
                p1 += 1
            elif "Priority: 2" in line:
                p2 += 1
            elif "Priority: 3" in line:
                p3 += 1
        sections.append(
            f"Today's fast.log alert counts ({today}):\n"
            f"  P1 (Critical): {p1}\n"
            f"  P2 (High):     {p2}\n"
            f"  P3 (Info):     {p3}\n"
            f"  Total:         {p1 + p2 + p3}"
        )
    except Exception as e:
        sections.append(f"fast.log: error reading ({e})")
        status = "warn"

    # Tail suricata.log for errors
    try:
        r = subprocess.run(
            ["sudo", "tail", "-n", "50", "/var/log/suricata/suricata.log"],
            capture_output=True, text=True, timeout=10,
        )
        log_lines = r.stdout.splitlines() if r.stdout else []
        errors = [l for l in log_lines if " Error " in l or " Fatal " in l or " Error]" in l]
        if errors:
            status = "warn"
            sections.append(
                f"Recent errors in suricata.log ({len(errors)} found):\n"
                + "\n".join(errors[-10:])
            )
        else:
            sections.append(f"suricata.log: no errors in last 50 lines")
        sections.append(
            "suricata.log tail (last 20 lines):\n"
            + "\n".join(log_lines[-20:])
        )
    except Exception as e:
        sections.append(f"suricata.log: error reading ({e})")

    return {
        "id": META["id"],
        "name": META["name"],
        "icon": META["icon"],
        "status": status,
        "summary": f"Today: {p1} P1, {p2} P2, {p3} P3" if "p1" in dir() else "Counts unavailable",
        "output": "\n\n".join(sections),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))
