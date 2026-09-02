#!/usr/bin/env python3
"""ADR 0012 FLEET-auto — the auto-admit audit trail (enrollment_auto_audit).

Run: python3 core_module/hw_monitor/test_fleet_auto_audit.py

BEHAVIOURAL, not just structural. It drives the REAL `_create_enrollment()`
against a temp DB with a real RSA keypair and a real signature, because the
thing being verified is "does an unattended admission actually leave a trail",
and only a real admission can answer that.

THE CONTROL THAT MATTERS: the same enrollment with FINDINGS must be withheld
and must write NO audit row. Without it, a test that only ever exercises the
happy path cannot distinguish "the row is written on auto-admit" from "a row is
written on every enrollment" — and those differ exactly where it counts.

Also asserts the Data Manager grant DIRECTLY, per the standing instruction in
data_manager.py: a missing grant name is a silent WOULD-DENY that leaves the
enrollment succeeding and only the audit row missing — i.e. the precise
condition this table exists to eliminate, arriving quietly.
"""
import base64
import json
import os
import sys
import sqlite3
import tempfile
import time

sys.path.insert(0, "/opt/nemesis/core_module/hw_monitor")
sys.path.insert(0, "/opt/nemesis/alert_manager")
sys.path.insert(0, "/opt/nemesis")

EXPECTED_CHECKS = 29
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 46:
        g, w = g[:43] + "...", w[:43] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def _keypair():
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def sign(msg):
        return base64.b64encode(
            key.sign(msg.encode(), padding.PKCS1v15(), hashes.SHA256())).decode()
    return pem, sign


def _payload(pem, sign, name, token, findings):
    signed_at = str(int(time.time()))
    scan = {"scan_status": "findings" if findings else "clean",
            "clamav_findings": 2 if findings else 0,
            "yara_findings": 0,
            "scan_timestamp": signed_at}
    return {
        "public_key": pem,
        "device_name": name,
        "os": "Windows",
        "os_version": "11",
        "signed_at": signed_at,
        "signature": sign("%s|%s|%s" % (name, "Windows", signed_at)),
        "hardware_summary": "test data 2026-09-02 fleet-auto audit suite",
        "enrollment_token": token,
        "pre_enrollment_scan": json.dumps(scan),
        "hardware_fingerprint": json.dumps(
            {"stable_id": "stable-" + name, "signals_used": ["cpu_id"],
             "signal_hashes": {"cpu_id": "deadbeef"}, "confidence": "high",
             "schema_version": 1, "is_virtual": False}),
    }


def main():
    import database as DB
    import hw_monitor as HW
    import data_manager as DM

    # ── the Data Manager grant, asserted directly ───────────────────────────
    print("the grant exists (a missing name is a SILENT would-deny)")
    check("hw_monitor may write enrollment_auto_audit",
          DM.allowed("hw_monitor", "enrollment_auto_audit"), True)
    check("CONTROL the grant is exact-match, not a prefix",
          DM.allowed("hw_monitor", "enrollment_auto_audit_X"), False)
    check("CONTROL a table it must NOT have is still refused",
          DM.allowed("hw_monitor", "users"), False)
    check("CONTROL a known-granted sibling still passes",
          DM.allowed("hw_monitor", "agent_devices"), True)

    # ── schema ──────────────────────────────────────────────────────────────
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "t.db")
    DB.DB_PATH = db
    DB.init_enrollment_tokens_table()
    HW.DB_PATH = db
    for attr in ("_DB_PATH", "DB_FILE"):
        if hasattr(HW, attr):
            setattr(HW, attr, db)
    con = sqlite3.connect(db)
    cols = [r[1] for r in con.execute("PRAGMA table_info(enrollment_auto_audit)")]
    print("\nthe table exists with the columns the writer relies on")
    check("CONTROL the table was created at all", bool(cols), True)
    for need in ("device_id", "source_ip", "token_prefix", "token_id",
                 "mode", "network_posture", "scan_verified", "has_findings"):
        check("column %s" % need, need in cols, True)

    # hw_monitor's own tables, on a raw connection (same shape the other
    # behavioural suites use).
    HW._init_db() if hasattr(HW, "_init_db") else None
    con.execute("""CREATE TABLE IF NOT EXISTS agent_devices (
        device_id TEXT PRIMARY KEY, device_name TEXT, device_type TEXT, ip_address TEXT,
        connection_type TEXT, agent_last_seen TIMESTAMP, enrollment_status TEXT DEFAULT 'approved',
        public_key TEXT, enrolled_by TEXT, enrolled_at TEXT, os TEXT, os_version TEXT,
        hardware_summary TEXT, pre_enrollment_scan TEXT, enrollment_has_findings INTEGER DEFAULT 0,
        hw_stable_id TEXT, hw_signals_used TEXT, hw_signal_hashes TEXT, hw_fp_confidence TEXT,
        hw_fp_schema_version INTEGER, hw_fp_locked_at REAL, hw_is_virtual INTEGER DEFAULT 0,
        remote_enabled INTEGER DEFAULT 0, remote_enabled_at TEXT, remote_enabled_by TEXT)""")
    con.commit()

    TOKEN = "tok-fleetauto-abcdef123456"
    con.execute("INSERT INTO enrollment_tokens (token, created_by, created_at, expires_at,"
                " max_uses, uses, auto_approve, revoked) VALUES (?,?,?,?,?,?,?,?)",
                (TOKEN, "tester", time.time(), time.time() + 3600, 5, 0, 1, 0))
    con.commit()
    con.close()

    pem, sign = _keypair()
    SRC_IP = "192.88.99.7"      # reads as public, goes nowhere (test_quarantine convention)

    # ── the admission that SHOULD be audited ────────────────────────────────
    print("\na CLEAN auto-admit is recorded")
    did_clean, status_clean = HW._create_enrollment(
        _payload(pem, sign, "clean-box", TOKEN, findings=False), SRC_IP)
    check("the clean device enrolled", bool(did_clean), True)
    check("it was AUTO-APPROVED (the precondition for auditing it)",
          status_clean, "approved")

    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM enrollment_auto_audit").fetchall()
    check("exactly one audit row was written", len(rows), 1)
    r = dict(rows[0]) if rows else {}
    check("it names the device that was admitted", r.get("device_id"), did_clean)
    check("source_ip is the SERVER-observed address, not client-claimed",
          r.get("source_ip"), SRC_IP)
    check("mode records HOW it got in", r.get("mode"), "fleet-auto")
    check("network_posture records WHAT it got", r.get("network_posture"), "trusted")
    check("scan evidence is recorded (this is what made it safe)",
          (r.get("scan_verified"), r.get("has_findings")), (1, 0))
    check("the granting token is referenced", bool(r.get("token_id")), True)
    # Rule 8 -- the whole point of storing a prefix.
    check("token PREFIX only", r.get("token_prefix"), TOKEN[:8])
    check("THE PROPERTY: the full token is NOT stored",
          TOKEN in json.dumps({k: str(v) for k, v in r.items()}), False)

    # ── THE CONTROL: an admission that must NOT be audited ──────────────────
    # Without this, "a row is written on auto-admit" is indistinguishable from
    # "a row is written on every enrollment".
    print("\nCONTROL — a WITHHELD enrollment writes no row")
    did_f, status_f = HW._create_enrollment(
        _payload(pem, sign, "findings-box", TOKEN, findings=True), SRC_IP)
    check("the findings device still enrolled", bool(did_f), True)
    check("CONTROL it was NOT auto-approved (held for review)",
          status_f == "approved", False)
    n = con.execute("SELECT COUNT(*) FROM enrollment_auto_audit").fetchone()[0]
    check("THE PROPERTY: still exactly one audit row, not two", n, 1)
    check("CONTROL the withheld device is absent from the trail",
          con.execute("SELECT COUNT(*) FROM enrollment_auto_audit WHERE device_id=?",
                      (did_f,)).fetchone()[0], 0)
    # ...and it really did reach agent_devices, so the absence above is a
    # deliberate non-audit rather than an enrollment that never happened.
    check("CONTROL the withheld device DID enrol (absence is not a no-op)",
          con.execute("SELECT COUNT(*) FROM agent_devices WHERE device_id=?",
                      (did_f,)).fetchone()[0], 1)
    con.close()

    import shutil
    shutil.rmtree(tmp, ignore_errors=True)

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [l for l, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d "
              "-- a check was skipped, not merely failed" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
