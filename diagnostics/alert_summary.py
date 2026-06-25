"""Check: recent alert database summary — counts and newest entries."""

import sqlite3
import os

META = {
    "id": "alert_summary",
    "name": "Alert Database Summary",
    "icon": "🚨",
    "descriptions": {
        "beginner": "Shows a summary of network security alerts that have been logged, including how many are still waiting for your review.",
        "intermediate": "Counts from the alerts table by action/risk_level, plus the 5 most recently seen rule entries.",
        "pro": "SQLite alerts table: counts by (action, risk_level), 5 most recent by last_seen desc.",
    },
}

# Derived from this file's location (repo_root/alert_manager/alerts.db) — no
# hardcoded home dir. (ADR 0001, Stage 1.)
DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "alert_manager", "alerts.db",
)


def run() -> dict:
    sections = []
    status = "ok"

    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.row_factory = sqlite3.Row

        # Overall counts
        total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        sections.append(f"Total alert rules in database: {total}")

        # By action
        rows = conn.execute(
            "SELECT action, COUNT(*) as n FROM alerts GROUP BY action ORDER BY n DESC"
        ).fetchall()
        if rows:
            by_action = "\n".join(f"  {r['action']:10s}: {r['n']}" for r in rows)
            sections.append(f"By action:\n{by_action}")

        # By risk_level
        rows = conn.execute(
            "SELECT risk_level, COUNT(*) as n FROM alerts GROUP BY risk_level ORDER BY n DESC"
        ).fetchall()
        if rows:
            by_risk = "\n".join(f"  {(r['risk_level'] or 'None'):10s}: {r['n']}" for r in rows)
            sections.append(f"By risk level:\n{by_risk}")

        # Pending review count
        pending = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE action='pending'"
        ).fetchone()[0]
        if pending > 0:
            status = "warn"
            sections.append(f"⚠ {pending} rule(s) pending review (action='pending')")

        # Most recent 5
        rows = conn.execute(
            """SELECT rule_id, rule_name, risk_level, action, last_seen
               FROM alerts ORDER BY last_seen DESC LIMIT 5"""
        ).fetchall()
        if rows:
            recent = "\n".join(
                f"  [{r['last_seen']}] {r['rule_name'][:50]} "
                f"(id:{r['rule_id']}) — {r['risk_level']}/{r['action']}"
                for r in rows
            )
            sections.append(f"5 most recently seen:\n{recent}")

        conn.close()
    except Exception as e:
        sections.append(f"Error reading alert database: {e}")
        status = "error"

    return {
        "id": META["id"],
        "name": META["name"],
        "icon": META["icon"],
        "status": status,
        "summary": f"{total if 'total' in dir() else '?'} rules in DB" + (f", {pending} pending" if "pending" in dir() and pending else ""),
        "output": "\n\n".join(sections),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))
