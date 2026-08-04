#!/usr/bin/env python3
"""Tier 1 attestation — END-TO-END, both halves, real functions only.

Run: python3 /opt/nemesis/alert_manager/test_attestation_e2e.py

The point of this suite is MOVEMENT. A device must be observed going
absent -> attested -> failed using the real server signing path, the real agent
verification path, and the real server recording path. A state machine that
cannot be shown changing has not been shown to measure anything, which is the
failure mode both halves were written to avoid.

Nothing here reimplements the logic under test.
"""

import base64
import hashlib
import os
import shutil
import sqlite3
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "nemesis_agent"))

from alert_manager import attestation                        # noqa: E402
import attest                                                # noqa: E402
import tasks as agent_tasks                                  # noqa: E402

from cryptography.hazmat.primitives import hashes            # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa, padding  # noqa: E402

EXPECTED_CHECKS = 22
_state = {"ran": 0, "failed": 0}


def check(label, got, want):
    _state["ran"] += 1
    ok = got == want
    if not ok:
        _state["failed"] += 1
    print("  %-58s %s  (got=%r want=%r)"
          % (label, "PASS" if ok else "FAIL", got, want))


def make_tree():
    root = tempfile.mkdtemp(prefix="e2e_agent_")
    os.makedirs(os.path.join(root, "modules"))
    for d, n, c in ((root, "agent.py", "print('a')\n"),
                    (root, "config.py", "X=1\n"),
                    (os.path.join(root, "modules"), "security.py", "def scan(): pass\n")):
        with open(os.path.join(d, n), "w", encoding="utf-8") as fh:
            fh.write(c)
    return root


def make_db():
    path = os.path.join(tempfile.mkdtemp(prefix="e2e_db_"), "t.db")
    c = sqlite3.connect(path)
    c.executescript("""
        CREATE TABLE agent_devices (
            device_id TEXT PRIMARY KEY, uninstalled_at TEXT,
            attestation_state TEXT NOT NULL DEFAULT 'absent',
            attestation_detail TEXT, attestation_at TEXT,
            attestation_version TEXT);
    """)
    c.execute("INSERT INTO agent_devices (device_id) VALUES ('dev1')")
    c.commit()
    return c


def stored(conn):
    return conn.execute("SELECT attestation_state FROM agent_devices "
                        "WHERE device_id='dev1'").fetchone()[0]


def heartbeat(root):
    """Exactly what the agent puts in agent_health['attestation']."""
    return {"attestation": attest.evaluate(root, agent_version=attest.AGENT_VERSION)}


def main():
    tree = make_tree()
    conn = make_db()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def sign(env):
        digest = hashlib.sha256(agent_tasks._canonical_bytes(env)).hexdigest().encode()
        return base64.b64encode(
            key.sign(digest, padding.PKCS1v15(), hashes.SHA256())).decode()

    try:
        # ── STATE 1: ABSENT — no manifest has ever arrived ───────────────────
        print("-- state 1: before any manifest --")
        check("schema default before any report", stored(conn), "absent")
        hb = heartbeat(tree)
        check("agent self-reports ABSENT", hb["attestation"]["state"], "absent")
        check("server records ABSENT",
              attestation.record_attestation(conn, "dev1", hb), "absent")
        check("not healthy", attestation.is_healthy(stored(conn)), False)

        # ── deliver a manifest through the REAL signed path ──────────────────
        print("\n-- server signs, agent verifies and installs --")
        env = attestation.build_manifest_envelope(
            "dev1", attest.AGENT_VERSION, agent_root=tree, sign=sign)
        verified = agent_tasks.verify_task(env, "dev1", key.public_key())
        check("agent verifies the envelope", verified["action"],
              agent_tasks.ATTEST_ACTION)
        n = attest.install_manifest(verified["params"]["manifest"], root=tree)
        check("manifest installed, covering the tree", n, 3)

        # ── STATE 2: ATTESTED ────────────────────────────────────────────────
        print("\n-- state 2: manifest matches the tree --")
        hb = heartbeat(tree)
        check("agent self-reports ATTESTED", hb["attestation"]["state"], "attested")
        check("server records ATTESTED",
              attestation.record_attestation(conn, "dev1", hb), "attested")
        check("healthy", attestation.is_healthy(stored(conn)), True)

        # ── STATE 3: FAILED — tamper with a file ─────────────────────────────
        print("\n-- state 3: a file is modified after attestation --")
        with open(os.path.join(tree, "modules", "security.py"), "w",
                  encoding="utf-8") as fh:
            fh.write("def scan(): return {'ok': True}   # neutered\n")
        hb = heartbeat(tree)
        check("agent self-reports FAILED", hb["attestation"]["state"], "failed")
        check("server records FAILED",
              attestation.record_attestation(conn, "dev1", hb), "failed")
        check("NOT healthy after tampering",
              attestation.is_healthy(stored(conn)), False)

        # ── the security property, tested behaviourally ──────────────────────
        # A manifest install reachable from the UNAUTHENTICATED loopback
        # dispatcher would let any local process define what "intact" means.
        # `_dispatch` signals an unknown action by RETURNING {"error": ...}.
        print("\n-- security: manifest install is NOT reachable from _dispatch --")
        import agent as agent_mod
        res = agent_mod._CommandHandler._dispatch(
            None, agent_tasks.ATTEST_ACTION, {"manifest": {"files": {"x": "y"}}})
        check("dispatcher REFUSES attest_manifest",
              bool(isinstance(res, dict) and res.get("error")), True)

        # An empty manifest matches an empty tree — a check that cannot fail.
        try:
            attest.install_manifest({"files": {}}, root=tree)
            refused = False
        except ValueError:
            refused = True
        check("empty manifest REFUSED", refused, True)

        # ── server dispatch wiring ───────────────────────────────────────────
        # This section exists because these exact functions were silently lost
        # in a partial commit on 2026-08-04 and NOTHING NOTICED: the schema and
        # the recording survived, so every suite still passed while the system
        # was inert — no manifest was ever queued or delivered, and every device
        # would have sat at 'absent' forever looking like a correct result.
        #
        # A missing DELIVERY case fails loudly on its own (the envelope arrives
        # with empty params and `install_manifest` refuses it), so the silent
        # failure mode is specifically "nothing ever queues". That is what is
        # covered here.
        print("\n-- server dispatch wiring (guards against silent inertness) --")
        for p in ("/opt/nemesis", "/opt/nemesis/alert_manager",
                  "/opt/nemesis/core_module/hw_monitor"):
            if p not in sys.path:
                sys.path.insert(0, p)
        import hw_monitor

        check("enqueue_manifest exists",
              callable(getattr(hw_monitor, "enqueue_manifest", None)), True)
        check("ensure_manifest_queued exists",
              callable(getattr(hw_monitor, "ensure_manifest_queued", None)), True)

        import inspect
        check("delivery path handles attest_manifest",
              "attest_manifest" in inspect.getsource(hw_monitor._tasks_for_response),
              True)

        # Behavioural dedup test against a synthetic DB.
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT UNIQUE,
                device_id TEXT, action TEXT, params_json TEXT,
                status TEXT DEFAULT 'pending', created_at TEXT,
                dispatched_at TEXT, expires_at TEXT,
                dispatch_count INTEGER DEFAULT 0, origin_queued_at TEXT,
                actor TEXT, result_ok INTEGER, result_detail TEXT,
                reported_at TEXT);
        """)
        conn.execute("UPDATE agent_devices SET attestation_state='absent' "
                     "WHERE device_id='dev1'")
        # `enqueue_task` closes the connection it is handed. Passing the shared
        # test conn directly made the SECOND call return None because the DB was
        # closed — a PASS produced by the exception path, not by dedup logic.
        # Caught 2026-08-04; the proxy makes the check measure what it claims to.
        class _NoClose:
            def __init__(self, c):
                self._c = c

            def __getattr__(self, n):
                return getattr(self._c, n)

            def close(self):
                pass

        real_connect = hw_monitor._db_connect
        hw_monitor._db_connect = lambda *a, **k: _NoClose(conn)
        try:
            first = hw_monitor.ensure_manifest_queued(conn, "dev1")
            check("unattested device gets a manifest queued", bool(first), True)
            queued = conn.execute(
                "SELECT COUNT(*) FROM scan_tasks WHERE action='attest_manifest'"
            ).fetchone()[0]
            check("exactly one task row exists", queued, 1)
            again = hw_monitor.ensure_manifest_queued(conn, "dev1")
            check("second beat does NOT duplicate while one is in flight",
                  again, None)
            check("still exactly one task row after second beat",
                  conn.execute("SELECT COUNT(*) FROM scan_tasks "
                               "WHERE action='attest_manifest'").fetchone()[0], 1)
            conn.execute("UPDATE agent_devices SET attestation_state='attested' "
                         "WHERE device_id='dev1'")
            conn.execute("UPDATE scan_tasks SET status='completed'")
            check("attested device queues nothing",
                  hw_monitor.ensure_manifest_queued(conn, "dev1"), None)
        finally:
            hw_monitor._db_connect = real_connect

        print("\nOBSERVED TRANSITION: absent -> attested -> failed")
        print("\n%d/%d checks (ran=%d failed=%d)"
              % (_state["ran"] - _state["failed"], EXPECTED_CHECKS,
                 _state["ran"], _state["failed"]))
        if _state["ran"] != EXPECTED_CHECKS:
            print("!! declared %d but ran %d — count guard failed"
                  % (EXPECTED_CHECKS, _state["ran"]))
            return 1
        return 1 if _state["failed"] else 0
    finally:
        shutil.rmtree(tree, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
