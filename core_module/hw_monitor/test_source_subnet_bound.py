#!/usr/bin/env python3
"""ADR 0012 FLEET-auto — the source_subnet WHERE-FROM bound.

Run: python3 core_module/hw_monitor/test_source_subnet_bound.py

Behavioural, against the real `_create_enrollment()`.

Four properties, each with a control that can distinguish it from an adjacent
almost-right behaviour:

  1. IN-subnet auto-approves        (control: proves the bound is not simply
                                     refusing everything)
  2. OUT-of-subnet is WITHHELD      (the bound does something)
  3. A refused attempt COSTS THE TOKEN NOTHING -- `uses` must not move.
     This is the one worth the most: checking the bound AFTER the claim would
     still refuse correctly and still LOOK right, while handing anyone who can
     reach /enroll a way to exhaust a legitimate token from outside its subnet.
  4. FAILS CLOSED on an unparseable bound -- "cannot determine" is never
     "permitted".

Plus: a NULL bound must stay unbounded, because every pre-existing token has
one and narrowing them retroactively would silently break working installers.
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

EXPECTED_CHECKS = 15
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
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


def _payload(pem, sign, name, token):
    at = str(int(time.time()))
    return {"public_key": pem, "device_name": name, "os": "Windows", "os_version": "11",
            "signed_at": at, "signature": sign("%s|%s|%s" % (name, "Windows", at)),
            "hardware_summary": "test data 2026-09-02 source_subnet bound suite",
            "enrollment_token": token,
            "pre_enrollment_scan": json.dumps(
                {"scan_status": "clean", "clamav_findings": 0, "yara_findings": 0,
                 "scan_timestamp": at})}


def main():
    import database as DB
    import hw_monitor as HW

    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "t.db")
    DB.DB_PATH = db
    DB.init_enrollment_tokens_table()
    HW.DB_PATH = db
    con = sqlite3.connect(db)
    cols = [r[1] for r in con.execute("PRAGMA table_info(enrollment_tokens)")]
    print("schema")
    check("source_subnet column exists", "source_subnet" in cols, True)
    check("CONTROL the table was really read (other columns present)",
          "auto_approve" in cols and "max_uses" in cols, True)

    con.execute("""CREATE TABLE IF NOT EXISTS agent_devices (
        device_id TEXT PRIMARY KEY, device_name TEXT, device_type TEXT, ip_address TEXT,
        connection_type TEXT, agent_last_seen TIMESTAMP, enrollment_status TEXT DEFAULT 'approved',
        public_key TEXT, enrolled_by TEXT, enrolled_at TEXT, os TEXT, os_version TEXT,
        hardware_summary TEXT, pre_enrollment_scan TEXT, enrollment_has_findings INTEGER DEFAULT 0,
        hw_stable_id TEXT, hw_signals_used TEXT, hw_signal_hashes TEXT, hw_fp_confidence TEXT,
        hw_fp_schema_version INTEGER, hw_fp_locked_at REAL, hw_is_virtual INTEGER DEFAULT 0,
        remote_enabled INTEGER DEFAULT 0, remote_enabled_at TEXT, remote_enabled_by TEXT)""")

    def mktoken(name, subnet):
        con.execute("INSERT INTO enrollment_tokens (token, created_by, created_at, expires_at,"
                    " max_uses, uses, auto_approve, revoked, source_subnet)"
                    " VALUES (?,?,?,?,?,?,?,?,?)",
                    (name, "tester", time.time(), time.time() + 3600, 5, 0, 1, 0, subnet))
        con.commit()
        return name

    T_BOUND  = mktoken("tok-bound-1",   "192.88.99.0/24")
    T_NULL   = mktoken("tok-unbound-1", None)
    T_BROKEN = mktoken("tok-broken-1",  "not-a-subnet/99")
    con.close()

    pem, sign = _keypair()
    IN_SUBNET  = "192.88.99.7"     # inside 192.88.99.0/24
    OUT_SUBNET = "198.51.100.7"    # outside it

    def uses(tok):
        c = sqlite3.connect(db)
        n = c.execute("SELECT uses FROM enrollment_tokens WHERE token=?", (tok,)).fetchone()[0]
        c.close()
        return n

    print("\n1. inside the bound -> auto-approved")
    _, st_in = HW._create_enrollment(_payload(pem, sign, "in-box", T_BOUND), IN_SUBNET)
    check("THE PROPERTY: an in-subnet device auto-approves", st_in, "approved")
    check("CONTROL the claim consumed a use", uses(T_BOUND), 1)

    print("\n2. outside the bound -> withheld")
    _, st_out = HW._create_enrollment(_payload(pem, sign, "out-box", T_BOUND), OUT_SUBNET)
    check("THE PROPERTY: an out-of-subnet device is NOT auto-approved",
          st_out == "approved", False)
    check("CONTROL it still enrolled (the bound withholds trust, not enrollment)",
          st_out is not None, True)

    print("\n3. a refused attempt must COST THE TOKEN NOTHING")
    # If the bound were checked after the claim it would still refuse, and still
    # look correct here -- but `uses` would have moved, and repeating this from
    # outside the subnet would exhaust a legitimate token.
    check("THE PROPERTY: uses did NOT move on the refusal", uses(T_BOUND), 1)
    for i in range(4):
        HW._create_enrollment(_payload(pem, sign, "out-%d" % i, T_BOUND), OUT_SUBNET)
    check("THE PROPERTY: 4 more refusals still cost nothing", uses(T_BOUND), 1)
    check("CONTROL the token is therefore still usable from inside",
          HW._create_enrollment(_payload(pem, sign, "in-2", T_BOUND), IN_SUBNET)[1],
          "approved")

    print("\n4. a NULL bound stays UNBOUNDED (every pre-existing token has one)")
    _, st_null = HW._create_enrollment(_payload(pem, sign, "null-box", T_NULL), OUT_SUBNET)
    check("THE PROPERTY: NULL means unbounded, not 'deny'", st_null, "approved")
    # The discriminating control: the SAME source address that was refused under
    # a bound is approved without one. So the variable is the bound, not the
    # address, the network, or anything about the payload.
    check("CONTROL same address, bounded vs unbounded -> refused vs approved",
          (st_out == "approved", st_null == "approved"), (False, True))

    print("\n5. an unparseable bound FAILS CLOSED")
    _, st_bad = HW._create_enrollment(_payload(pem, sign, "bad-box", T_BROKEN), IN_SUBNET)
    check("THE PROPERTY: unparseable bound withholds rather than allows",
          st_bad == "approved", False)
    check("CONTROL it did not consume a use either", uses(T_BROKEN), 0)
    check("CONTROL the device still enrolled", st_bad is not None, True)

    print("\n6. the audit row records the bound that was in force")
    c = sqlite3.connect(db)
    c.row_factory = sqlite3.Row
    n_audit = c.execute("SELECT COUNT(*) FROM enrollment_auto_audit").fetchone()[0]
    # 3 auto-admits happened: in-box, in-2, null-box. The refusals must not appear.
    check("THE PROPERTY: only the auto-admits are audited", n_audit, 3)
    c.close()

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
