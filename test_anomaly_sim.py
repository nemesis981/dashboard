#!/usr/bin/env python3
"""
Phase 1 anomaly detection simulation test.

Injects a realistic multi-device "coordinated new destination" incident by
calling the real scoring and incident-creation functions, not a raw SQL insert.

Scenario:
  Three real devices (Chris's Laptop, Fire TV Cube, Angie PC) each contact
  the same never-seen-before domain within a 28-second window, triggering:
    +12  new-destination signal (obs_count < MIN_BASELINE_OBS)
    +16  multi-device spread (3 devices × 8pts, capped at 24)
    +10  tight time clustering (spread ≤ 30 s)
    +25  recurrence boost (5 prior appearances seeded below, min(5×5,30)=25)
    ─────
    = 63  HIGH  →  CISA button visible

Cleanup after UI validation:
    python3 /home/paul/dashboard/test_anomaly_cleanup.py
"""

import sys, os, time, json
sys.path.insert(0, "/home/paul/dashboard")

from datetime import datetime

# Pull the real internal functions directly from the module
from modules.anomaly_detection.module import (
    _init_db, _conn, _evaluate, _create_or_update_incident,
    _load_device_names, _hour_of_week,
    DB_PATH, SCORE_FLOOR, SCORE_MEDIUM, SCORE_HIGH, SCORE_CRITICAL,
    MIN_BASELINE_OBS,
)

TEST_DOMAIN = "c2-beacon-test.ru"   # synthetic; grep-able for cleanup

# Real devices from the devices table
DEVICE_IPS = [
    "192.168.4.23",   # Chris's Laptop  — first contact
    "192.168.4.25",   # Fire TV Cube    — second
    "192.168.4.22",   # Angie PC        — third
]

RECURRENCE_SEED_COUNT = 5          # prior appearances to pre-seed
RECURRENCE_SEED_DAYS_AGO = 1      # last seen 1 day ago (well within 30-day window)
RECURRENCE_FIRST_SEEN_DAYS_AGO = 15


def _severity(score):
    if score >= SCORE_CRITICAL: return "CRITICAL", "#ff4444"
    if score >= SCORE_HIGH:     return "HIGH",     "#ff8800"
    if score >= SCORE_MEDIUM:   return "MEDIUM",   "#ffcc00"
    return "LOW", "#aaa"


def main():
    print("=" * 58)
    print("  Anomaly Detection Phase 1 — Simulation Test")
    print("=" * 58)

    # 1. Ensure DB tables exist (idempotent)
    print("\n[1] Initialising DB tables …")
    _init_db()
    print("    OK")

    now = time.time()
    how = _hour_of_week(datetime.fromtimestamp(now))

    # 2. Build tight-spread client timestamps (28 s spread → triggers ≤30s bonus)
    t0 = now - 45   # start 45 s ago so all timestamps are in the past
    fake_clients = {
        DEVICE_IPS[0]: [t0,       t0 +  5],   # Chris's Laptop:  2 queries
        DEVICE_IPS[1]: [t0 + 12,  t0 + 18],   # Fire TV Cube:    2 queries
        DEVICE_IPS[2]: [t0 + 24,  t0 + 28],   # Angie PC:        2 queries
    }
    data = {
        "clients": fake_clients,
        "count":   sum(len(v) for v in fake_clients.values()),   # 6 total
    }
    print(f"\n[2] Simulated event data:")
    print(f"    Domain     : {TEST_DOMAIN}")
    print(f"    Total queries: {data['count']} across {len(fake_clients)} devices")
    all_ts = sorted(ts for lst in fake_clients.values() for ts in lst)
    print(f"    Time spread: {all_ts[-1] - all_ts[0]:.1f} s")

    # 3. Seed recurrence record — simulates 5 prior incidents for this domain
    conn = _conn()
    already = conn.execute(
        "SELECT id, recurrence_count FROM anomaly_recurrence WHERE offending_target=?",
        (TEST_DOMAIN,)
    ).fetchone()

    if already:
        print(f"\n[3] Recurrence record already exists "
              f"(count={already['recurrence_count']}) — skipping seed")
    else:
        first_seen = now - RECURRENCE_FIRST_SEEN_DAYS_AGO * 86400
        last_seen  = now - RECURRENCE_SEED_DAYS_AGO * 86400
        conn.execute("""
            INSERT INTO anomaly_recurrence
                (offending_target, first_seen, last_seen,
                 recurrence_count, max_score, incident_ids)
            VALUES (?, ?, ?, ?, 45.0, '[]')
        """, (TEST_DOMAIN, first_seen, last_seen, RECURRENCE_SEED_COUNT))
        conn.commit()
        print(f"\n[3] Seeded recurrence record:")
        print(f"    Prior appearances : {RECURRENCE_SEED_COUNT}")
        print(f"    First seen        : {RECURRENCE_FIRST_SEEN_DAYS_AGO} days ago")
        print(f"    Last seen         : {RECURRENCE_SEED_DAYS_AGO} day ago")
        print(f"    Expected boost    : +{min(RECURRENCE_SEED_COUNT * 5, 30)} pts")

    # 4. Run real scoring (no baseline entry exists for this domain → is_new=True)
    print(f"\n[4] Calling _evaluate() (real scoring logic) …")
    signals = _evaluate(conn, TEST_DOMAIN, data, how, now)

    print(f"\n    Signal breakdown:")
    print(f"      new_destination   : {signals['new_destination']}")
    print(f"      volume_spike      : {signals['volume_spike']}")
    print(f"      device_count      : {signals['device_count']}")
    print(f"      time_spread_s     : {signals['time_spread_s']}")
    print(f"      recurrence_count  : {signals['recurrence_count']}")
    print(f"      recurrence_boost  : +{signals['recurrence_boost']}")
    print(f"      incident_type     : {signals['incident_type']}")
    print(f"      baseline_obs      : {signals['baseline_obs']}  (< {MIN_BASELINE_OBS} → new)")
    print(f"\n    Raw score         : {signals['score']}")

    label, color = _severity(signals['score'])
    print(f"    Severity          : {label}")

    if signals['score'] < SCORE_HIGH:
        print(f"\n  ⚠  Score {signals['score']} < SCORE_HIGH ({SCORE_HIGH})")
        print("     CISA button will NOT appear. Check recurrence seed or device count.")
    else:
        print(f"\n  ✅  Score {signals['score']} >= SCORE_HIGH ({SCORE_HIGH}) — CISA button WILL show")

    # 5. Call real incident-creation function
    print(f"\n[5] Calling _create_or_update_incident() …")
    device_names = _load_device_names()
    _create_or_update_incident(conn, TEST_DOMAIN, data, signals, device_names, now)
    conn.commit()

    # 6. Fetch and display the result
    inc = conn.execute(
        "SELECT id, score, incident_type, device_count, devices_json, created_at "
        "FROM anomaly_incidents "
        "WHERE offending_target=? AND status='open' "
        "ORDER BY id DESC LIMIT 1",
        (TEST_DOMAIN,)
    ).fetchone()
    conn.close()

    if not inc:
        print("    ERROR: incident not found after insert!")
        sys.exit(1)

    print(f"    Inserted incident id : {inc['id']}")
    print(f"    Score / severity     : {inc['score']} ({label})")
    print(f"    Type                 : {inc['incident_type']}")
    print(f"    Device count         : {inc['device_count']}")

    devs = json.loads(inc["devices_json"])
    print(f"\n    Propagation order:")
    for i, d in enumerate(devs, 1):
        ts_str = datetime.fromtimestamp(d["first_seen_ts"]).strftime("%H:%M:%S")
        print(f"      {i}. {d['name']} ({d['ip']})  first={ts_str}  queries={d['query_count']}")

    print()
    print("=" * 58)
    print("  Test incident is LIVE in the database.")
    print("  → Reload the dashboard and verify:")
    print("    • Incident row visible in Anomaly Detection card")
    print("    • Score badge shows HIGH in orange")
    print("    • 'Details' expand shows propagation table (3 devices)")
    print("    • Signal list shows: 🌐 New destination, 🔄 3 devices, 🔁 Recurrence")
    print("    • CISA button visible (score ≥ 60)")
    print("    • '✓' dismiss button works")
    print()
    print("  When done, run cleanup:")
    print("    python3 /home/paul/dashboard/test_anomaly_cleanup.py")
    print("=" * 58)


if __name__ == "__main__":
    main()
