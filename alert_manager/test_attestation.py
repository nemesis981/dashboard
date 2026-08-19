#!/usr/bin/env python3
"""Tier 1 attestation — server-half tests.

Run: python3 /opt/nemesis/alert_manager/test_attestation.py

The load-bearing test here is the ROUND TRIP: the server builds and signs a
manifest envelope, and the AGENT's own `tasks.verify_task` accepts it. Each half
being internally consistent proves nothing about whether they interoperate —
that is exactly the gap a "must match exactly" duplicated contract leaves open.
"""

import datetime
import os
import sqlite3
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from alert_manager import attestation                        # noqa: E402

EXPECTED_CHECKS = 21
_state = {"ran": 0, "failed": 0}


def check(label, got, want):
    _state["ran"] += 1
    ok = got == want
    if not ok:
        _state["failed"] += 1
    print("  %-58s %s  (got=%r want=%r)"
          % (label, "PASS" if ok else "FAIL", got, want))


def make_db():
    """agent_devices with the attestation columns as shipped."""
    path = os.path.join(tempfile.mkdtemp(prefix="attest_srv_"), "t.db")
    c = sqlite3.connect(path)
    c.executescript("""
        CREATE TABLE agent_devices (
            device_id TEXT PRIMARY KEY,
            uninstalled_at TEXT,
            attestation_state TEXT NOT NULL DEFAULT 'absent',
            attestation_detail TEXT,
            attestation_at TEXT,
            attestation_version TEXT
        );
    """)
    c.commit()
    return c


def main():
    print("-- normalise_state: nothing unrecognised may become ATTESTED --")
    for label, val in [
            ("missing key", None),
            ("not a dict", "attested"),
            ("empty dict", {}),
            ("misspelled state", {"state": "atttested"}),
            ("future/unknown state", {"state": "partially_attested"}),
            ("explicit null state", {"state": None}),
    ]:
        s, _ = attestation.normalise_state(val)
        check("%-22s -> ABSENT" % label, s, attestation.ABSENT)

    s, d = attestation.normalise_state({"state": "attested", "detail": "42 files match"})
    check("exact 'attested' -> ATTESTED", s, attestation.ATTESTED)
    check("detail preserved", d, "42 files match")
    s, _ = attestation.normalise_state({"state": "failed", "detail": "x"})
    check("'failed' preserved as FAILED", s, attestation.FAILED)

    print("\n-- is_healthy: positive match only --")
    check("attested is healthy", attestation.is_healthy("attested"), True)
    check("failed is NOT healthy", attestation.is_healthy("failed"), False)
    check("absent is NOT healthy", attestation.is_healthy("absent"), False)
    # The point of a positive match: a state invented later must not pass.
    check("unknown future state is NOT healthy",
          attestation.is_healthy("attested_v2"), False)
    check("None is NOT healthy", attestation.is_healthy(None), False)

    print("\n-- persistence + schema default --")
    conn = make_db()
    conn.execute("INSERT INTO agent_devices (device_id) VALUES ('dev1')")
    row = conn.execute("SELECT attestation_state FROM agent_devices "
                       "WHERE device_id='dev1'").fetchone()
    check("device that never reported defaults to ABSENT", row[0], "absent")

    attestation.record_attestation(conn, "dev1",
                                   {"attestation": {"state": "attested",
                                                    "detail": "ok",
                                                    "agent_version": "1.2.3"}})
    row = conn.execute("SELECT attestation_state, attestation_version FROM "
                       "agent_devices WHERE device_id='dev1'").fetchone()
    check("attested state persisted", row[0], "attested")
    check("agent_version persisted", row[1], "1.2.3")

    # An agent that stops reporting must not leave a stale 'attested' behind
    # when it sends a heartbeat with no attestation at all.
    attestation.record_attestation(conn, "dev1", {})
    row = conn.execute("SELECT attestation_state FROM agent_devices "
                       "WHERE device_id='dev1'").fetchone()
    check("heartbeat with no attestation downgrades to ABSENT", row[0], "absent")

    print("\n-- ROUND TRIP: server signs, AGENT verifies --")
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    import base64, hashlib
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    sys.path.insert(0, os.path.join(ROOT, "nemesis_agent"))
    import tasks as agent_tasks

    def fake_sign(env):
        digest = hashlib.sha256(
            agent_tasks._canonical_bytes(env)).hexdigest().encode()
        return base64.b64encode(
            key.sign(digest, padding.PKCS1v15(), hashes.SHA256())).decode()

    env = attestation.build_manifest_envelope(
        "dev1", "1.2.3", agent_root=os.path.join(ROOT, "nemesis_agent"),
        sign=fake_sign)
    verified = agent_tasks.verify_task(env, "dev1", key.public_key())
    check("agent ACCEPTS the server-signed manifest envelope",
          verified["action"], attestation.ACTION)
    check("envelope carries a non-empty manifest",
          len(env["params"]["manifest"]["files"]) > 0, True)

    # Device binding must actually bind.
    try:
        agent_tasks.verify_task(env, "someone_else", key.public_key())
        bound = False
    except Exception:
        bound = True
    check("envelope is device-bound (other device REJECTS)", bound, True)

    print("\n%d/%d checks (ran=%d failed=%d)"
          % (_state["ran"] - _state["failed"], EXPECTED_CHECKS,
             _state["ran"], _state["failed"]))
    if _state["ran"] != EXPECTED_CHECKS:
        print("!! declared %d but ran %d — count guard failed"
              % (EXPECTED_CHECKS, _state["ran"]))
        return 1
    return 1 if _state["failed"] else 0




def test_tier2_challenge_round_trip():
    """Full Tier 2 issue->respond->ingest against the REAL functions + real crypto,
    incl. the default now=None path (a missing import would crash here) and a
    tampering control. Requires the private module on path; skips clearly if absent."""
    import os, sys, sqlite3, tempfile
    AGENT="/opt/nemesis/nemesis_agent"; PRIV=os.path.expanduser("~/work/nemesis-internal/attestation-tier2")
    for pth in (PRIV, "/opt/nemesis", AGENT):
        if pth not in sys.path: sys.path.insert(0, pth)
    import attestation as att
    if not att.tier2_available():
        print("  SKIP tier2 round trip (private module not on path) — NOT a pass")
        return
    _cwd=os.getcwd(); os.chdir(AGENT)
    try:
        import tier2_agent, tasks, enrollment, attest
        from modules import scanner
        c=sqlite3.connect(":memory:")
        c.execute("CREATE TABLE agent_devices (device_id TEXT PRIMARY KEY, attestation_state TEXT, tier2_state TEXT, tier2_detail TEXT, tier2_at TEXT)")
        c.execute("INSERT INTO agent_devices VALUES ('d','attested','absent',NULL,NULL)")
        c.execute("CREATE TABLE agent_attestation_challenges (device_id TEXT PRIMARY KEY, nonce TEXT, code_digests TEXT, code_python TEXT, issued_at REAL, expires_at REAL)")
        ch=att.build_and_store_challenge(c,"d",agent_root=AGENT)   # default now=None
        assert ch and ch["nonce"], "issue failed"
        resp=tier2_agent.respond_to_challenge(ch["nonce"], ch["covered"])
        att.ingest_challenge_response(c,"d",resp)
        row=c.execute("SELECT attestation_state,tier2_state FROM agent_devices WHERE device_id='d'").fetchone()
        assert row[0]=="attested", "attestation_state must be untouched (observe-only)"
        assert row[1] in ("absent","attested","failed"), "tier2_state recorded"
        assert c.execute("SELECT 1 FROM agent_attestation_challenges WHERE device_id='d'").fetchone() is None, "challenge cleared"
        # tamper control
        att.build_and_store_challenge(c,"d",agent_root=AGENT)
        n2=c.execute("SELECT nonce FROM agent_attestation_challenges WHERE device_id='d'").fetchone()[0]
        _o=tasks.verify_task; tasks.verify_task=lambda *a,**k:{"ok":True}
        try:
            att.ingest_challenge_response(c,"d",tier2_agent.respond_to_challenge(n2,list(att.TIER2_COVERED)))
        finally: tasks.verify_task=_o
        assert c.execute("SELECT tier2_state FROM agent_devices WHERE device_id='d'").fetchone()[0]=="failed", "tamper must be FAILED"
        print("  PASS  tier2 challenge round trip (issue->respond->ingest, tamper->failed)")
    finally:
        os.chdir(_cwd)

if __name__ == "__main__":
    test_tier2_challenge_round_trip()
    sys.exit(main())
