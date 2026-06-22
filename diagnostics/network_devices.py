"""Check: network device inventory from the device database."""

import sqlite3

META = {
    "id": "network_devices",
    "name": "Network Devices",
    "icon": "📡",
    "descriptions": {
        "beginner": "Lists all the devices that have been seen on your network, including whether they are trusted or unknown.",
        "intermediate": "Device inventory from the devices table: IP, MAC, type, trusted flag, and last-seen timestamp.",
        "pro": "alerts.db devices table — all rows, sorted by IP, with trust status.",
    },
}

DB_PATH = "/home/paul/dashboard/alert_manager/alerts.db"


def run() -> dict:
    sections = []
    status = "ok"

    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT ip, mac, friendly_name, device_type, trusted FROM devices ORDER BY ip"
        ).fetchall()
        conn.close()

        total = len(rows)
        trusted = sum(1 for r in rows if r["trusted"])
        untrusted = total - trusted
        sections.append(
            f"Total devices: {total}  |  Trusted: {trusted}  |  Unknown/untrusted: {untrusted}"
        )

        if untrusted > 0:
            status = "warn"

        lines = [f"{'IP':16s}  {'MAC':17s}  {'Type':14s}  {'Trust':7s}  Name"]
        lines.append("-" * 75)
        for r in rows:
            trust = "trusted" if r["trusted"] else "unknown"
            lines.append(
                f"{r['ip']:16s}  {r['mac']:17s}  {(r['device_type'] or ''):14s}  "
                f"{trust:7s}  {r['friendly_name'] or ''}"
            )
        sections.append("\n".join(lines))
    except Exception as e:
        sections.append(f"Error reading device database: {e}")
        status = "error"

    return {
        "id": META["id"],
        "name": META["name"],
        "icon": META["icon"],
        "status": status,
        "summary": f"{total if 'total' in dir() else '?'} devices ({trusted if 'trusted' in dir() else '?'} trusted)",
        "output": "\n\n".join(sections),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))
