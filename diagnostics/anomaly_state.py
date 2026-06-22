"""Check: anomaly detection module configuration and runtime state."""

import sqlite3
import os

META = {
    "id": "anomaly_state",
    "name": "Anomaly Detection State",
    "icon": "🧠",
    "descriptions": {
        "beginner": "Shows the current configuration and status of the AI-powered anomaly detection module, including rate limits and reporting thresholds.",
        "intermediate": "Dumps the anomaly_state key-value store and counts from anomaly_incidents and anomaly_abuseipdb_dedup.",
        "pro": "anomaly_state kv table, incident/baseline/recurrence counts, AI cache size, dedup queue.",
    },
}

DB_PATH = "/home/paul/dashboard/alert_manager/alerts.db"


def run() -> dict:
    sections = []
    status = "info"

    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.row_factory = sqlite3.Row

        # Module enabled?
        en_row = conn.execute(
            "SELECT value FROM anomaly_state WHERE key='enabled'"
        ).fetchone()
        enabled = (en_row["value"] if en_row else "0") == "1"
        sections.append(f"Module enabled: {'yes' if enabled else 'no'}")

        if not enabled:
            conn.close()
            return {
                "id": META["id"],
                "name": META["name"],
                "icon": META["icon"],
                "status": "info",
                "summary": "Anomaly detection module is disabled",
                "output": sections[0],
            }

        # All state keys
        rows = conn.execute("SELECT key, value FROM anomaly_state ORDER BY key").fetchall()
        kv = "\n".join(f"  {r['key']:35s} = {r['value']}" for r in rows)
        sections.append(f"Configuration (anomaly_state):\n{kv}")

        # Table sizes
        for table in ("anomaly_baseline", "anomaly_incidents",
                      "anomaly_recurrence", "anomaly_ai_cache",
                      "anomaly_abuseipdb_dedup"):
            try:
                n = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                sections.append(f"{table}: {n} rows")
            except Exception:
                sections.append(f"{table}: (not found)")

        # Recent incidents
        rows = conn.execute(
            """SELECT domain, incident_type, score, created_at, abuseipdb_reported
               FROM anomaly_incidents ORDER BY created_at DESC LIMIT 5"""
        ).fetchall()
        if rows:
            recent = "\n".join(
                f"  [{r['created_at'][:16]}] {r['domain'][:40]} "
                f"type={r['incident_type']} score={r['score']:.0f}"
                f"{' [reported]' if r['abuseipdb_reported'] else ''}"
                for r in rows
            )
            sections.append(f"5 most recent incidents:\n{recent}")

        conn.close()
    except Exception as e:
        sections.append(f"Error reading anomaly DB: {e}")
        status = "warn"

    return {
        "id": META["id"],
        "name": META["name"],
        "icon": META["icon"],
        "status": status,
        "summary": "Anomaly detection state retrieved",
        "output": "\n\n".join(sections),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))
