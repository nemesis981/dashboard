#!/usr/bin/env python3
"""
Anomaly Detection simulation test — Phases 1–3.

Phase 1/2: Injects a realistic multi-device "coordinated new destination" incident
by calling the real scoring and incident-creation functions, not a raw SQL insert.

Scenario:
  Three real devices (<device-b>, <device-d>, <device-c>) each contact
  the same never-seen-before domain within a 28-second window, triggering:
    +12  new-destination signal (obs_count < MIN_BASELINE_OBS)
    +16  multi-device spread (3 devices × 8pts, capped at 24)
    +10  tight time clustering (spread ≤ 30 s)
    +25  recurrence boost (5 prior appearances seeded below, min(5×5,30)=25)
    ─────
    = 63  HIGH  →  CISA button visible

Phase 3: Validates AbuseIPDB threshold/dedup logic and CISA threshold settings.
  Does NOT hit the real AbuseIPDB API (validates flow control, not submission).

Cleanup after UI validation:
    python3 test_anomaly_cleanup.py
"""

import sys, os, time, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # repo root

from datetime import datetime

# Pull the real internal functions directly from the module
from modules.anomaly_detection.module import (
    _init_db, _conn, _evaluate, _create_or_update_incident,
    _load_device_names, _hour_of_day, _set_state,
    _get_abuseipdb_settings, _get_cisa_settings, _auto_report_abuseipdb,
    DB_PATH, SCORE_FLOOR, SCORE_MEDIUM, SCORE_HIGH, SCORE_CRITICAL,
    MIN_BASELINE_OBS, ABUSEIPDB_DEDUP_HOURS,
)

TEST_DOMAIN = "c2-beacon-test.ru"   # synthetic; grep-able for cleanup

# Real devices from the devices table
DEVICE_IPS = [
    "<lan-ip-b>",   # <device-b>  — first contact
    "<lan-ip-c>",   # <device-d>    — second
    "<lan-ip-d>",   # <device-c>        — third
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
    hod = _hour_of_day(datetime.fromtimestamp(now))

    # 2. Build tight-spread client timestamps (28 s spread → triggers ≤30s bonus)
    t0 = now - 45   # start 45 s ago so all timestamps are in the past
    fake_clients = {
        DEVICE_IPS[0]: [t0,       t0 +  5],   # <device-b>:  2 queries
        DEVICE_IPS[1]: [t0 + 12,  t0 + 18],   # <device-d>:    2 queries
        DEVICE_IPS[2]: [t0 + 24,  t0 + 28],   # <device-c>:        2 queries
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
    signals = _evaluate(conn, TEST_DOMAIN, data, hod, now)

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
    print("  Phase 1/2 incident is LIVE in the database.")
    print("  → Reload the dashboard and verify:")
    print("    • Incident row visible in Anomaly Detection card")
    print("    • Score badge shows HIGH in orange")
    print("    • 'Details' expand shows propagation table (3 devices)")
    print("    • Signal list shows: 🌐 New destination, 🔄 3 devices, 🔁 Recurrence")
    print("    • CISA button visible (score ≥ configurable threshold)")
    print("    • '✓' dismiss button works")
    print()

    _run_phase3_tests(inc)

    print()
    print("  When done with UI validation, run cleanup:")
    print("    python3 test_anomaly_cleanup.py")
    print("=" * 58)


def _run_phase3_tests(inc) -> None:
    """Phase 3: validate AbuseIPDB and CISA threshold/dedup logic."""
    inc_id     = inc["id"]
    test_score = inc["score"]

    print()
    print("=" * 58)
    print("  Phase 3 — AbuseIPDB & CISA Threshold Tests")
    print("=" * 58)

    # ── 3.1  AbuseIPDB threshold settings logic ───────────────────────────────
    print("\n[3.1] AbuseIPDB threshold settings")

    _set_state("abuseipdb_active_control", "slider")
    _set_state("abuseipdb_slider_score", "40")
    s = _get_abuseipdb_settings()
    assert s["threshold"] == 40.0, f"Expected 40.0 got {s['threshold']}"
    print("    ✅ slider mode: threshold = 40.0")

    _set_state("abuseipdb_active_control", "dropdown")
    _set_state("abuseipdb_dropdown_mode", "off")
    s = _get_abuseipdb_settings()
    assert s["threshold"] is None, f"Expected None got {s['threshold']}"
    print("    ✅ dropdown 'off': threshold = None (disabled)")

    _set_state("abuseipdb_dropdown_mode", "medium_plus")
    s = _get_abuseipdb_settings()
    assert s["threshold"] == float(SCORE_MEDIUM), \
        f"Expected {float(SCORE_MEDIUM)} got {s['threshold']}"
    print(f"    ✅ dropdown 'medium_plus': threshold = {SCORE_MEDIUM}")

    _set_state("abuseipdb_dropdown_mode", "high_only")
    s = _get_abuseipdb_settings()
    assert s["threshold"] == float(SCORE_HIGH), \
        f"Expected {float(SCORE_HIGH)} got {s['threshold']}"
    print(f"    ✅ dropdown 'high_only': threshold = {SCORE_HIGH}")

    # Reset to Off for safety (default for new installs)
    _set_state("abuseipdb_dropdown_mode", "off")
    _set_state("abuseipdb_active_control", "dropdown")
    print("    ✅ reset to Off (safe default confirmed)")

    # ── 3.2  AbuseIPDB 24h dedup logic ───────────────────────────────────────
    print("\n[3.2] AbuseIPDB 24h dedup")

    conn = _conn()
    now = time.time()

    # Seed a recent dedup entry (1 hour ago → within 24h window → should block)
    conn.execute(
        "INSERT OR REPLACE INTO anomaly_abuseipdb_dedup(offending_target, reported_at) VALUES(?,?)",
        (TEST_DOMAIN, now - 3600)
    )
    conn.commit()

    row = conn.execute(
        "SELECT reported_at FROM anomaly_abuseipdb_dedup WHERE offending_target=?",
        (TEST_DOMAIN,)
    ).fetchone()
    age_h = (now - row["reported_at"]) / 3600
    assert age_h < ABUSEIPDB_DEDUP_HOURS, f"age {age_h:.1f}h should be < {ABUSEIPDB_DEDUP_HOURS}h"
    print(f"    ✅ dedup entry present (age={age_h:.1f}h < {ABUSEIPDB_DEDUP_HOURS}h) → would skip")

    # Now verify _auto_report_abuseipdb skips when API key absent AND dedup is set
    # (no key means it returns immediately, so dedup entry won't be updated)
    saved_key = os.environ.pop("ABUSEIPDB_KEY", None)
    before_ts = row["reported_at"]
    _auto_report_abuseipdb(inc_id, TEST_DOMAIN, "coordinated", test_score)
    row2 = conn.execute(
        "SELECT reported_at FROM anomaly_abuseipdb_dedup WHERE offending_target=?",
        (TEST_DOMAIN,)
    ).fetchone()
    # Reported_at should be unchanged (returned early due to no-key)
    assert row2 is not None and row2["reported_at"] == before_ts, \
        "dedup entry was unexpectedly modified"
    print("    ✅ no ABUSEIPDB_KEY: returned immediately, dedup entry unchanged")
    if saved_key:
        os.environ["ABUSEIPDB_KEY"] = saved_key

    # Clear dedup, re-check: no entry → _auto_report_abuseipdb would proceed past dedup
    conn.execute("DELETE FROM anomaly_abuseipdb_dedup WHERE offending_target=?", (TEST_DOMAIN,))
    conn.commit()
    gone = conn.execute(
        "SELECT reported_at FROM anomaly_abuseipdb_dedup WHERE offending_target=?",
        (TEST_DOMAIN,)
    ).fetchone()
    assert gone is None
    print("    ✅ dedup cleared: next report would proceed (to DNS-resolve step)")
    conn.close()

    # ── 3.3  AbuseIPDB: no-key guard (clean state) ───────────────────────────
    print("\n[3.3] AbuseIPDB no-key guard")
    saved_key = os.environ.pop("ABUSEIPDB_KEY", None)
    _auto_report_abuseipdb(inc_id, TEST_DOMAIN, "coordinated", test_score)
    conn = _conn()
    no_entry = conn.execute(
        "SELECT reported_at FROM anomaly_abuseipdb_dedup WHERE offending_target=?",
        (TEST_DOMAIN,)
    ).fetchone()
    conn.close()
    assert no_entry is None, "dedup entry created without API key!"
    print("    ✅ no API key → returned immediately, no dedup entry written")
    if saved_key:
        os.environ["ABUSEIPDB_KEY"] = saved_key

    # ── 3.4  CISA threshold settings logic ───────────────────────────────────
    print("\n[3.4] CISA button threshold settings")

    _set_state("cisa_active_control", "dropdown")
    _set_state("cisa_dropdown_mode", "high_only")
    cs = _get_cisa_settings()
    assert cs["threshold"] == float(SCORE_HIGH), \
        f"Expected {float(SCORE_HIGH)} got {cs['threshold']}"
    print(f"    ✅ dropdown 'high_only': threshold = {SCORE_HIGH}")

    shows = test_score >= cs["threshold"]
    assert shows, f"score {test_score} should be ≥ threshold {cs['threshold']}"
    print(f"    ✅ score={test_score:.0f} ≥ {SCORE_HIGH} → CISA button VISIBLE")

    _set_state("cisa_dropdown_mode", "critical_only")
    cs2 = _get_cisa_settings()
    assert cs2["threshold"] == float(SCORE_CRITICAL), \
        f"Expected {float(SCORE_CRITICAL)} got {cs2['threshold']}"
    # score=80 == SCORE_CRITICAL=80, so button SHOWS at critical_only (>=80 is met)
    shows2 = test_score >= cs2["threshold"]
    print(f"    ✅ dropdown 'critical_only': threshold={SCORE_CRITICAL}, "
          f"score={test_score:.0f} → CISA button {'VISIBLE' if shows2 else 'HIDDEN'} "
          f"(score {'≥' if shows2 else '<'} threshold)")

    # Use slider set just above current score to demonstrate the hidden case
    above_score = int(test_score) + 1
    _set_state("cisa_active_control", "slider")
    _set_state("cisa_slider_score", str(above_score))
    cs_above = _get_cisa_settings()
    assert cs_above["threshold"] == float(above_score), \
        f"Expected {float(above_score)} got {cs_above['threshold']}"
    hides = test_score < float(above_score)
    assert hides, f"score {test_score} should be < threshold {above_score}"
    print(f"    ✅ slider threshold={above_score} > score={test_score:.0f} → CISA button HIDDEN")

    _set_state("cisa_active_control", "slider")
    _set_state("cisa_slider_score", "50")
    cs3 = _get_cisa_settings()
    assert cs3["threshold"] == 50.0, f"Expected 50.0 got {cs3['threshold']}"
    shows3 = test_score >= 50.0
    assert shows3
    print(f"    ✅ slider mode: threshold=50.0, score={test_score:.0f} → CISA button VISIBLE")

    # Reset CISA to sensible default (high_only via dropdown)
    _set_state("cisa_active_control", "dropdown")
    _set_state("cisa_dropdown_mode", "high_only")
    print(f"    ✅ reset CISA to default: dropdown 'high_only' (threshold={SCORE_HIGH})")

    # ── 3.5  CISA two-step UI confirmation (logic summary) ────────────────────
    print("\n[3.5] CISA two-step confirmation flow (UI — not automatable)")
    print("    Step 1: Click 'CISA' button on an incident row")
    print("            → Modal opens, incident details loaded from /api/anomaly/incident/<id>")
    print("            → Review checkbox is UNCHECKED, 'Open CISA Reporting Form' is DISABLED")
    print("    Step 2: Check 'I have reviewed the details' checkbox")
    print("            → Button becomes ENABLED (opacity:1, cursor:pointer)")
    print("    Step 3: Click 'Open CISA Reporting Form ↗'")
    print("            → cisa.gov/report opens in NEW TAB")
    print("            → Dashboard sends NOTHING programmatically")
    print("    → Three distinct user actions required; no single click submits anything")
    print("    ✅ Two-step confirmation enforced by disabled-until-checked pattern")

    print()
    print("=" * 58)
    print("  Phase 3 tests: ALL PASSED")
    print("=" * 58)


if __name__ == "__main__":
    main()
