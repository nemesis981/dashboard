#!/usr/bin/env python3
"""
Removes ONLY the synthetic test incident injected by test_anomaly_sim.py.
Safe to run multiple times (idempotent).
"""
import os, sys, sqlite3

TEST_DOMAIN = "c2-beacon-test.ru"
# Derived from this file's location (repo_root/alert_manager/alerts.db) — no
# hardcoded home dir. (ADR 0001, Stage 1.)
DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "alert_manager", "alerts.db",
)

def main():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # Show what we're about to delete
    incidents = conn.execute(
        "SELECT id, score, incident_type, status FROM anomaly_incidents "
        "WHERE offending_target=?", (TEST_DOMAIN,)
    ).fetchall()
    recurrences = conn.execute(
        "SELECT id, recurrence_count FROM anomaly_recurrence "
        "WHERE offending_target=?", (TEST_DOMAIN,)
    ).fetchall()

    if not incidents and not recurrences:
        print(f"Nothing to clean up for '{TEST_DOMAIN}' — already gone.")
        conn.close()
        return

    print(f"Removing test data for '{TEST_DOMAIN}':")
    for r in incidents:
        print(f"  anomaly_incidents  id={r['id']}  score={r['score']}  "
              f"type={r['incident_type']}  status={r['status']}")
    for r in recurrences:
        print(f"  anomaly_recurrence id={r['id']}  recurrence_count={r['recurrence_count']}")

    conn.execute("DELETE FROM anomaly_incidents  WHERE offending_target=?", (TEST_DOMAIN,))
    conn.execute("DELETE FROM anomaly_recurrence WHERE offending_target=?", (TEST_DOMAIN,))
    conn.commit()
    conn.close()
    print("Done — test data removed.")

if __name__ == "__main__":
    main()
