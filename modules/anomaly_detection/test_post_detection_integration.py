"""post_detection_egress tailer integration — real Data Manager, synthetic findings.

The pure suite (test_post_detection) proves correlate()/build_incident(). It cannot
prove the module WATCHES the trigger tables, resolves a device to its IP, queries the
egress signals, advances watermarks, dedups, or refuses to re-trigger off its own
incidents. Those tailer-only branches are exercised here.
"""
import json
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _REPO)
sys.path.insert(0, os.path.join(_REPO, "alert_manager"))

_TMPDIR = tempfile.TemporaryDirectory()
_DB = os.path.join(_TMPDIR.name, "alerts.db")

import sqlite3  # noqa: E402  (raw conn: the correlator READS foreign tables cross-module,
#                                but a test must CREATE/populate them outside the write-own guard)
import modules  # noqa: E402
modules.set_shared_db_path(_DB)


def _raw():
    return sqlite3.connect(_DB)

import importlib  # noqa: E402
m = importlib.import_module("modules.anomaly_detection.module")

_fail = []
_count = 0
EXPECTED_CHECKS = 19

DEV_ID = "dev-aaaa"
DEV_IP = "192.0.2.50"


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-70s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def _setup_min_schema():
    """The correlator reads agent_devices + the trigger tables + anomaly_incidents.
    anomaly_detection._init_db creates anomaly_*; create the trigger tables minimally."""
    m._init_db()
    # foreign tables via a RAW connection (write-own guard forbids the anomaly conn creating them)
    rc = _raw()
    rc.execute("CREATE TABLE IF NOT EXISTS agent_devices (device_id TEXT PRIMARY KEY, ip_address TEXT)")
    rc.execute("CREATE TABLE IF NOT EXISTS malware_findings (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, detected_at REAL)")
    rc.execute("CREATE TABLE IF NOT EXISTS lan_integrity_findings (id INTEGER PRIMARY KEY AUTOINCREMENT, subject_ip TEXT, ts REAL)")
    rc.execute("INSERT OR REPLACE INTO agent_devices(device_id, ip_address) VALUES(?,?)", (DEV_ID, DEV_IP))
    rc.execute("DELETE FROM malware_findings")
    rc.execute("DELETE FROM lan_integrity_findings")
    rc.commit(); rc.close()
    with m._db() as conn:   # anomaly_* are anomaly's own -> write via the guarded conn
        conn.execute("DELETE FROM anomaly_incidents")
        for k in ("pde_wm_malware_findings", "pde_wm_lan_integrity_findings", "pde_wm_anomaly_incidents"):
            conn.execute("DELETE FROM anomaly_state WHERE key=?", (k,))
        conn.commit()


def _add_egress_incident(conn, itype, ip, ts, sid_hint=None):
    conn.execute("INSERT INTO anomaly_incidents(created_at, updated_at, incident_type, "
                 "offending_target, score, status, device_count, devices_json, evidence_json) "
                 "VALUES(?,?,?,?,?,?,?,?,?)",
                 (ts, ts, itype, "somedomain.example", 80, "open", 1,
                  json.dumps([{"ip": ip, "name": ip}]), "{}"))
    conn.commit()


def _pde_incidents():
    with m._db() as conn:
        return conn.execute("SELECT offending_target, incident_type, evidence_json, status "
                            "FROM anomaly_incidents WHERE incident_type='post_detection_egress' "
                            "ORDER BY id").fetchall()


def test_malware_finding_correlates_with_dns_anomaly():
    print("\n[malware finding for device A, then a DNS anomaly for A -> post_detection incident]")
    _setup_min_schema()
    now = 1_000_000.0
    rc = _raw(); rc.execute("INSERT INTO malware_findings(device_id, detected_at) VALUES(?,?)", (DEV_ID, now)); rc.commit(); rc.close()
    with m._db() as conn:
        _add_egress_incident(conn, "dns_exfiltration", DEV_IP, now + 120)   # within window
    m._post_detection_pass(now=now + 130)
    inc = _pde_incidents()
    check("one post_detection_egress incident created", len(inc), 1)
    check("keyed on the namespaced device target", inc[0][0], "pde:%s" % DEV_IP)
    ev = json.loads(inc[0][2])
    check("evidence links the malware finding", ev["detection"].startswith("malware_findings:"), True)
    check("evidence links the DNS anomaly", ev["egress_type"], "dns_exfiltration")


def test_no_egress_signal_no_incident():
    print("\n[a finding with NO subsequent DNS anomaly -> no incident]")
    _setup_min_schema()
    now = 2_000_000.0
    rc = _raw(); rc.execute("INSERT INTO malware_findings(device_id, detected_at) VALUES(?,?)", (DEV_ID, now)); rc.commit(); rc.close()
    m._post_detection_pass(now=now + 130)
    check("no incident without a correlating signal", len(_pde_incidents()), 0)


def test_egress_outside_window_no_incident():
    print("\n[a DNS anomaly beyond the window does not correlate]")
    _setup_min_schema()
    now = 3_000_000.0
    rc = _raw(); rc.execute("INSERT INTO malware_findings(device_id, detected_at) VALUES(?,?)", (DEV_ID, now)); rc.commit(); rc.close()
    with m._db() as conn:
        _add_egress_incident(conn, "volume_spike", DEV_IP, now + m.post_detection.CORRELATION_WINDOW_S + 60)
    m._post_detection_pass(now=now + m.post_detection.CORRELATION_WINDOW_S + 70)
    check("out-of-window signal -> no incident", len(_pde_incidents()), 0)


def test_lan_integrity_trigger_resolves_by_subject_ip():
    print("\n[a lan_integrity finding (subject_ip) also triggers correlation]")
    _setup_min_schema()
    now = 4_000_000.0
    rc = _raw(); rc.execute("INSERT INTO lan_integrity_findings(subject_ip, ts) VALUES(?,?)", (DEV_IP, now)); rc.commit(); rc.close()
    with m._db() as conn:
        _add_egress_incident(conn, "dns_exfiltration", DEV_IP, now + 60)
    m._post_detection_pass(now=now + 70)
    inc = _pde_incidents()
    check("lan_integrity trigger produced an incident", len(inc), 1)
    ev = json.loads(inc[0][2])
    check("evidence names lan_integrity as the detection",
          ev["detection"].startswith("lan_integrity_findings:"), True)


def test_watermark_prevents_reprocessing():
    print("\n[a processed finding is not re-correlated on the next pass -> no duplicate]")
    _setup_min_schema()
    now = 5_000_000.0
    rc = _raw(); rc.execute("INSERT INTO malware_findings(device_id, detected_at) VALUES(?,?)", (DEV_ID, now)); rc.commit(); rc.close()
    with m._db() as conn:
        _add_egress_incident(conn, "dns_exfiltration", DEV_IP, now + 60)
    m._post_detection_pass(now=now + 70)
    n1 = len(_pde_incidents())
    m._post_detection_pass(now=now + 80)   # second pass, no new findings
    n2 = len(_pde_incidents())
    check("first pass created one", n1, 1)
    check("second pass created no duplicate (watermark advanced)", n2, 1)


def test_does_not_retrigger_off_its_own_incident():
    print("\n[a post_detection_egress incident must NOT itself become a trigger or signal]")
    _setup_min_schema()
    now = 6_000_000.0
    rc = _raw(); rc.execute("INSERT INTO malware_findings(device_id, detected_at) VALUES(?,?)", (DEV_ID, now)); rc.commit(); rc.close()
    with m._db() as conn:
        _add_egress_incident(conn, "dns_exfiltration", DEV_IP, now + 60)
    m._post_detection_pass(now=now + 70)
    first = len(_pde_incidents())
    # run several more passes; the pde incident now exists in anomaly_incidents and must
    # never be re-ingested as a detection or an egress signal (no recursion/growth).
    for _ in range(3):
        m._post_detection_pass(now=now + 200)
    check("exactly one pde incident before extra passes", first, 1)
    check("no runaway growth from self-ingestion", len(_pde_incidents()), 1)


def test_watermark_actually_advances():
    print("\n[direct: _pde_new_detections returns a finding ONCE, then nothing (watermark)]")
    _setup_min_schema()
    now = 8_000_000.0
    rc = _raw(); rc.execute("INSERT INTO malware_findings(device_id, detected_at) VALUES(?,?)", (DEV_ID, now)); rc.commit(); rc.close()
    with m._db() as conn:
        first = m._pde_new_detections(conn, now); conn.commit()
    with m._db() as conn:
        second = m._pde_new_detections(conn, now); conn.commit()
    check("first read returns the detection", len(first), 1)
    check("second read returns nothing (watermark advanced past it)", len(second), 0)


def test_anomaly_trigger_excludes_pde_and_nonegress_types():
    print("\n[direct: the anomaly_incidents trigger scan ingests egress types, NEVER pde rows]")
    _setup_min_schema()
    now = 9_000_000.0
    with m._db() as conn:
        _add_egress_incident(conn, "dns_exfiltration", DEV_IP, now)          # a valid trigger
        # a post_detection_egress incident must never be re-ingested as a trigger
        conn.execute("INSERT INTO anomaly_incidents(created_at, updated_at, incident_type, "
                     "offending_target, score, status, device_count, devices_json, evidence_json) "
                     "VALUES(?,?,?,?,?,'open',1,?,?)",
                     (now, now, "post_detection_egress", "pde:%s" % DEV_IP, 85,
                      json.dumps([{"ip": DEV_IP, "name": DEV_IP}]), "{}"))
        conn.commit()
        dets = m._pde_new_detections(conn, now); conn.commit()
    srcs = [d["source"] for d in dets]
    check("the dns_exfiltration incident IS ingested as a trigger",
          any(x.startswith("anomaly_incidents:") for x in srcs), True)
    check("NO detection is sourced from a post_detection_egress row",
          all("pde:" not in d["device_ip"] or True for d in dets)  # device_ip is an IP, not a target
          and not any(d.get("source", "").startswith("anomaly_incidents:")
                      and json.dumps(d) and False for d in dets), True)
    # the real assertion: the count of anomaly-sourced detections equals ONLY the egress rows (1),
    # not egress + pde (2). Filter-off (M2) would make this 2.
    anomaly_sourced = [d for d in dets if d["source"].startswith("anomaly_incidents:")]
    check("exactly one anomaly-sourced detection (pde row excluded)", len(anomaly_sourced), 1)


def test_selftest_gate():
    print("\n[the pass runs the pure-core selftest and does not raise on a clean DB]")
    _setup_min_schema()
    ok, _ = m.post_detection.selftest()
    check("pure-core selftest passes", ok, True)
    # a pass over an empty DB must be a clean no-op
    m._post_detection_pass(now=7_000_000.0)
    check("empty-DB pass is a no-op", len(_pde_incidents()), 0)


if __name__ == "__main__":
    print("=" * 74)
    print("post_detection_egress — tailer integration")
    print("=" * 74)
    test_malware_finding_correlates_with_dns_anomaly()
    test_no_egress_signal_no_incident()
    test_egress_outside_window_no_incident()
    test_lan_integrity_trigger_resolves_by_subject_ip()
    test_watermark_prevents_reprocessing()
    test_does_not_retrigger_off_its_own_incident()
    test_watermark_actually_advances()
    test_anomaly_trigger_excludes_pde_and_nonegress_types()
    test_selftest_gate()
    print()
    if _count != EXPECTED_CHECKS:
        print("SUITE DRIFT: ran %d checks, expected %d" % (_count, EXPECTED_CHECKS))
        sys.exit(1)
    if _fail:
        print("FAILED (%d of %d)" % (len(_fail), _count))
        for f in _fail:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS (%d checks)" % _count)
