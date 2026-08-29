"""Check: anomaly detection module configuration and runtime state."""

import sqlite3
import os
from datetime import datetime


def _fmt_ts(value):
    """Render `anomaly_incidents.created_at` (REAL epoch) as a readable stamp.

    Matches the module's own convention (`modules/anomaly_detection/module.py`
    formats the same column with `datetime.fromtimestamp(...).strftime(...)`).
    Falls back to `str(value)` rather than raising: this is a DIAGNOSTIC, and a
    single odd timestamp must not take out the whole section — which is precisely
    the failure being fixed here, where one bad expression hid 158 incidents and
    left the check permanently amber.
    """
    try:
        return datetime.fromtimestamp(float(value)).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError, OSError, OverflowError):
        return str(value)[:16]

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

# Derived from this file's location (repo_root/alert_manager/alerts.db) — no
# hardcoded home dir. (ADR 0001, Stage 1.)
def _resolve_db():
    """Shared DB location. Prefers the canonical resolver so this follows the
    /var/lib/nemesis relocation; falls back to the historic tree-relative path
    when run by hand outside an install."""
    _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _legacy = os.path.join(_root, "alert_manager", "alerts.db")
    try:
        import sys
        sys.path.insert(0, os.path.join(_root, "alert_manager"))
        import nemesis_paths
        return nemesis_paths.db_path(_legacy)
    except Exception:
        return _legacy


DB_PATH = _resolve_db()


def run() -> dict:
    sections = []
    status = "info"

    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.row_factory = sqlite3.Row

        # Module enabled?
        #
        # FIXED 2026-08-23. This read used to be:
        #
        #     SELECT value FROM anomaly_state WHERE key='enabled'
        #     enabled = (en_row["value"] if en_row else "0") == "1"
        #
        # `anomaly_state` has NEVER held an `enabled` key -- it holds
        # `baseline_built`, `eve_inode` and `eve_offset`, and the module's only
        # writer never creates one. So the row was always absent, the failed read
        # always defaulted to "0", and this check reported "Anomaly detection
        # module is disabled" UNCONDITIONALLY -- including on this box, where the
        # module is enabled and running. An operator asking "is anomaly detection
        # on?" was told no while it was on.
        #
        # Two defects, one line: the wrong source of truth, and a failed read
        # resolving to a value that means something. Enablement lives in the core
        # `modules_enabled` table (read-any under ADR 0001), which is what
        # `modules/diagnostics/module.py::_module_enabled` already uses.
        #
        # The absent-row case is now its own third state rather than being folded
        # into "disabled": a module that has never been recorded either way is not
        # the same as one deliberately switched off, and reporting them alike is
        # what made this bug invisible for as long as it lasted.
        en_row = conn.execute(
            "SELECT enabled FROM modules_enabled WHERE module_name='anomaly_detection'"
        ).fetchone()
        if en_row is None:
            enabled, enabled_label = None, "unknown (no row in modules_enabled)"
        else:
            enabled = bool(en_row["enabled"])
            enabled_label = "yes" if enabled else "no"
        sections.append(f"Module enabled: {enabled_label}")

        if enabled is None:
            # Not measurable. Deliberately NOT reported as disabled -- see above.
            conn.close()
            return {
                "id": META["id"],
                "name": META["name"],
                "icon": META["icon"],
                "status": "warn",
                "summary": "Cannot determine whether anomaly detection is enabled",
                "output": sections[0] + (
                    "\n\nNo row for 'anomaly_detection' exists in modules_enabled, "
                    "so this check cannot tell whether the module is on. That is "
                    "not the same as it being off, and is not reported as such."),
            }

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
        # `anomaly_ai_cache` was REMOVED from this list when the table was
        # dropped (2026-08-29, operator-approved: 0 rows, no writers, no other
        # readers). The lookup below is wrapped in try/except and would have
        # degraded to "(not found)" rather than crashing — which is precisely why
        # it had to be removed deliberately: left in place it would have printed
        # a permanent, meaningless "(not found)" line that reads like a fault in
        # a diagnostic whose whole job is telling faults from normal states.
        for table in ("anomaly_baseline", "anomaly_incidents",
                      "anomaly_recurrence",
                      "anomaly_abuseipdb_dedup"):
            try:
                n = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                sections.append(f"{table}: {n} rows")
            except Exception:
                sections.append(f"{table}: (not found)")

        # Recent incidents
        #
        # ⚠ THIS SECTION HAD NEVER RENDERED ONCE. Fixed 2026-08-29 — TWO bugs,
        # and fixing only the first would have left it just as broken:
        #
        #   1. It selected a `domain` column that does not exist. The real column
        #      is `offending_target` (it holds exactly what the old name implied —
        #      "a2z.com", "amazonaws.com" — and is what the module's own indexes
        #      key on). The SELECT raised `no such column: domain` every run.
        #   2. `created_at` is REAL (a float epoch, e.g. 1787531804.11421), and
        #      the formatter sliced it as a string (`[:16]`). That raises
        #      `TypeError: 'float' object is not subscriptable` — so even with the
        #      column name corrected, this still threw.
        #
        # Why it stayed hidden: the broad `except` below appended "Error reading
        # anomaly DB: …" and set status=warn, so the check went AMBER FOREVER for
        # a reason unrelated to anomaly health — while 158 real incidents stayed
        # invisible. An always-amber check trains its reader to stop looking, and
        # an empty incidents section reads as "nothing to report" rather than
        # "this never ran". That is worse than an obviously broken diagnostic.
        rows = conn.execute(
            """SELECT offending_target, incident_type, score, created_at,
                      abuseipdb_reported
               FROM anomaly_incidents ORDER BY created_at DESC LIMIT 5"""
        ).fetchall()
        if rows:
            recent = "\n".join(
                f"  [{_fmt_ts(r['created_at'])}] {str(r['offending_target'])[:40]} "
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
