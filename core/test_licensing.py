"""Tests for licensing: install id, key verification, backup codes, census.

Run:  python3 core/test_licensing.py

No network, no live DB. Temp databases and a throwaway Ed25519 keypair generated
per run.

WHAT THESE ARE ACTUALLY GUARDING. Every check below is about a wrong answer being
*believable*: a licence that verifies when it should not, a cap count that reads
as real when nothing was measured, a backup code spent twice, an install id that
silently degrades to a value matching every other failure. A licensing system
that fails loudly is an inconvenience; one that fails quietly hands out
entitlements or takes them away without anyone noticing.
"""

import base64
import json
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_failures = []


def check(label, got, want):
    if got != want:
        _failures.append("%s: got %r, want %r" % (label, got, want))
        print("  FAIL  %s: got %r, want %r" % (label, got, want))
    else:
        print("  ok    %s" % label)


# ── throwaway issuer keypair ─────────────────────────────────────────────────
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


_PRIV = Ed25519PrivateKey.generate()
_PUB_B64 = _b64u(_PRIV.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw))
from core import license_key as lk  # noqa: E402

# The issuer public key is COMPILED IN and is deliberately not environment- or
# config-overridable (2026-08-23): making it a runtime input let anyone point the
# verifier at their own keypair and mint themselves a commercial licence. Tests
# therefore monkeypatch the module attribute, which exists only in-process and
# ships in no build. `_load_public_key()` reads this global at call time, so the
# assignment takes effect without a reload.
lk.PUBLIC_KEY_B64 = _PUB_B64


def make_key(install_id="INSTALL-A", tier="commercial", days=0, priv=None,
             extra=None):
    payload = {"install_id": install_id, "tier": tier,
               "issued_at": int(time.time()), "licence_id": "test"}
    if days:
        payload["expires_at"] = int(time.time() + days * 86400)
    if extra:
        payload.update(extra)
    body = lk.encode_payload(payload)
    sig = (priv or _PRIV).sign(body)
    return "%s.%s.%s" % (lk.KEY_PREFIX, _b64u(body), _b64u(sig))


# ── license_key ──────────────────────────────────────────────────────────────

def test_key_verification():
    print("\n[licence key verification]")
    k = make_key()
    r = lk.verify(k, install_id="INSTALL-A")
    check("valid key verifies", r.verdict, lk.Verdict.VALID)
    check("...and grants", r.valid, True)
    check("payload survives", r.payload.get("tier"), "commercial")

    check("absent key -> ABSENT not error", lk.verify("").verdict, lk.Verdict.ABSENT)
    check("absent does not grant", lk.verify("").valid, False)
    check("garbage -> MALFORMED",
          lk.verify("hello world").verdict, lk.Verdict.MALFORMED)
    check("wrong prefix -> MALFORMED",
          lk.verify("NOPE.aaa.bbb").verdict, lk.Verdict.MALFORMED)


def test_forgery_is_refused():
    print("\n[a key signed by a DIFFERENT issuer must not verify]")
    other = Ed25519PrivateKey.generate()
    k = make_key(priv=other)
    r = lk.verify(k, install_id="INSTALL-A")
    check("foreign signature -> BAD_SIGNATURE", r.verdict, lk.Verdict.BAD_SIGNATURE)
    check("does not grant", r.valid, False)


def test_tampered_payload_is_refused():
    print("\n[altering the payload must invalidate the signature]")
    k = make_key(install_id="INSTALL-A", tier="free")
    prefix, body_b64, sig_b64 = k.split(".")
    body = json.loads(base64.urlsafe_b64decode(body_b64 + "=" * (-len(body_b64) % 4)))
    body["tier"] = "commercial"          # privilege escalation attempt
    forged_body = _b64u(lk.encode_payload(body))
    forged = "%s.%s.%s" % (prefix, forged_body, sig_b64)
    r = lk.verify(forged, install_id="INSTALL-A")
    check("upgraded tier -> BAD_SIGNATURE", r.verdict, lk.Verdict.BAD_SIGNATURE)
    check("does not grant", r.valid, False)


def test_node_lock_and_expiry():
    print("\n[node-lock and expiry are distinct verdicts]")
    k = make_key(install_id="INSTALL-A")
    check("wrong machine -> WRONG_INSTALL",
          lk.verify(k, install_id="INSTALL-B").verdict, lk.Verdict.WRONG_INSTALL)
    check("no install_id supplied -> not checked",
          lk.verify(k, install_id=None).verdict, lk.Verdict.VALID)

    old = make_key(install_id="INSTALL-A", days=1)
    check("expired -> EXPIRED",
          lk.verify(old, install_id="INSTALL-A",
                    now=time.time() + 2 * 86400).verdict, lk.Verdict.EXPIRED)
    check("expired does not grant",
          lk.verify(old, install_id="INSTALL-A",
                    now=time.time() + 2 * 86400).valid, False)


def test_missing_pubkey_is_its_own_verdict():
    print("\n[an unconfigured product is NOT an invalid licence]")
    saved = lk.PUBLIC_KEY_B64
    try:
        lk.PUBLIC_KEY_B64 = "REPLACE_WITH_ISSUER_PUBLIC_KEY"
        r = lk.verify(make_key(), install_id="INSTALL-A")
        check("placeholder pubkey -> NO_PUBKEY", r.verdict, lk.Verdict.NO_PUBKEY)
        check("does not grant", r.valid, False)
        check("blames the product, not the user",
              "public key" in r.detail.lower(), True)
    finally:
        lk.PUBLIC_KEY_B64 = saved


def test_only_valid_grants():
    print("\n[backstop: exactly one verdict grants entitlement]")
    verdicts = [v for k, v in vars(lk.Verdict).items()
                if isinstance(v, str) and k.isupper()]
    granting = [v for v in verdicts if lk.Result(v, "").valid]
    check("every verdict enumerated", len(verdicts) >= 6, True)
    check("exactly one grants", granting, [lk.Verdict.VALID])


# ── install_id ───────────────────────────────────────────────────────────────

def test_install_id_real():
    print("\n[install id on this machine]")
    from core import install_id as iid
    try:
        fp = iid.compute()
    except iid.InstallIdError as e:
        print("  SKIP  cannot fingerprint here: %s" % e)
        return
    check("stable_id is non-empty", bool(fp.get("stable_id")), True)
    check("signals were used", bool(fp.get("signals_used")), True)
    print("        signals=%s confidence=%s"
          % (fp.get("signals_used"), fp.get("confidence")))

    v, d = iid.verify_install(fp["stable_id"], fp.get("signal_hashes"),
                              fp.get("confidence"), current=fp)
    check("same machine -> MATCH_OK", v, iid.MATCH_OK)

    v, d = iid.verify_install("totally-different-id", {"cpu_id": "zzz"},
                              "high", current=fp)
    check("different machine -> MISMATCH", v, iid.MATCH_MISMATCH)


def test_install_id_failure_states():
    print("\n[install id: cannot-tell is not the same as mismatch]")
    from core import install_id as iid
    fake = {"stable_id": "abc", "signal_hashes": {"cpu_id": "1"},
            "signals_used": ["cpu_id"], "confidence": "high"}
    v, _ = iid.verify_install("abc", {"cpu_id": "1"}, "low", current=fake)
    check("low confidence -> not enforced", v, iid.MATCH_LOW_CONFIDENCE)
    v, _ = iid.verify_install("", {}, "high", current=fake)
    check("no stored id -> UNAVAILABLE", v, iid.MATCH_UNAVAILABLE)
    check("MATCH_OK is not returned by any failure path",
          iid.MATCH_OK not in (iid.MATCH_MISMATCH, iid.MATCH_LOW_CONFIDENCE,
                               iid.MATCH_UNAVAILABLE), True)


# ── backup codes ─────────────────────────────────────────────────────────────

def _codes_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE license_backup_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT, code_hash TEXT NOT NULL,
        batch_id TEXT NOT NULL, install_id TEXT, created_at TEXT NOT NULL,
        created_actor TEXT, used_at TEXT, used_ip TEXT, used_for_install TEXT,
        superseded_at TEXT)""")
    con.commit(); con.close()
    return path


def test_backup_codes():
    print("\n[backup codes: 5 issued, one-time use]")
    from core import backup_codes as bc
    path = _codes_db()
    try:
        check("BATCH_SIZE is 5 (operator decision)", bc.BATCH_SIZE, 5)
        codes = bc.generate_batch(install_id="INSTALL-A", db_path=path)
        check("5 codes returned", len(codes), 5)
        check("all distinct", len(set(codes)), 5)
        check("remaining == 5", bc.remaining(path), 5)

        check("a code is accepted once",
              bc.consume(codes[0], new_install_id="INSTALL-B", db_path=path), True)
        check("remaining drops to 4", bc.remaining(path), 4)
        # The whole point of one-time use.
        check("the SAME code is refused the second time",
              bc.consume(codes[0], new_install_id="INSTALL-C", db_path=path), False)
        check("remaining still 4", bc.remaining(path), 4)

        check("an unknown code is refused",
              bc.consume("AAAA-BBBB-CCCC-DDDD", db_path=path), False)
        check("empty is refused", bc.consume("", db_path=path), False)
        # Formatting is cosmetic; a user retyping from paper must still succeed.
        check("case and dashes are normalised",
              bc.consume(codes[1].lower().replace("-", " "), db_path=path), True)
    finally:
        os.unlink(path)


def test_backup_code_regeneration_supersedes():
    print("\n[regenerating invalidates the old batch atomically]")
    from core import backup_codes as bc
    path = _codes_db()
    try:
        old = bc.generate_batch(db_path=path)
        new = bc.generate_batch(db_path=path)
        check("still exactly 5 live", bc.remaining(path), 5)
        check("an OLD code no longer works", bc.consume(old[0], db_path=path), False)
        check("a NEW code works", bc.consume(new[0], db_path=path), True)
    finally:
        os.unlink(path)


def test_backup_code_status_levels():
    print("\n[low-water warning at 2, exhaustion at 0]")
    from core import backup_codes as bc
    path = _codes_db()
    try:
        check("LOW_WATER is 2 (operator decision)", bc.LOW_WATER, 2)
        codes = bc.generate_batch(db_path=path)
        n, level, _ = bc.status(path)
        check("5 remaining -> ok", (n, level), (5, "ok"))
        bc.consume(codes[0], db_path=path)
        bc.consume(codes[1], db_path=path)
        n, level, msg = bc.status(path)
        check("3 remaining -> still ok", (n, level), (3, "ok"))
        bc.consume(codes[2], db_path=path)
        n, level, msg = bc.status(path)
        check("2 remaining -> LOW", (n, level), (2, "low"))
        check("low message warns about support",
              "support" in msg.lower(), True)
        bc.consume(codes[3], db_path=path)
        bc.consume(codes[4], db_path=path)
        n, level, msg = bc.status(path)
        check("0 remaining -> exhausted", (n, level), (0, "exhausted"))
        # The exhaustion case must NAME the route out, or a user assumes they
        # are stuck rather than merely inconvenienced.
        check("exhaustion names support", "contact support" in msg.lower(), True)
        check("...and says protection continues",
              "local protection" in msg.lower(), True)
    finally:
        os.unlink(path)


# ── census ───────────────────────────────────────────────────────────────────

class _FakeTS:
    def __init__(self, nodes=None, configured=True, boom=False):
        self._nodes = nodes or []
        self._configured = configured
        self._boom = boom

    def is_configured(self):
        return self._configured

    def list_devices(self):
        if self._boom:
            raise RuntimeError("tailnet unreachable")
        return self._nodes


def _census_db(with_col=True, rows=()):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    con = sqlite3.connect(path)
    cols = ("device_id TEXT, device_name TEXT, ip_address TEXT, "
            "enrollment_status TEXT")
    if with_col:
        cols += ", remote_enabled INTEGER DEFAULT 0"
    con.execute("CREATE TABLE agent_devices (%s)" % cols)
    for r in rows:
        con.execute("INSERT INTO agent_devices VALUES (%s)"
                    % ",".join("?" * len(r)), r)
    con.commit(); con.close()
    return path


def test_census_reconciles():
    print("\n[cap census reconciles against the tailnet]")
    from core import remote_census as rc
    path = _census_db(rows=[("d1", "one", "100.1.1.1", "approved", 1),
                            ("d2", "two", "100.1.1.2", "approved", 1),
                            ("d3", "local", "192.168.1.5", "approved", 0)])
    try:
        ts = _FakeTS(nodes=[{"addresses": ["100.1.1.1"], "hostname": "one",
                             "nodeId": "n1"},
                            {"addresses": ["100.1.1.2"], "hostname": "two",
                             "nodeId": "n2"},
                            {"addresses": ["100.9.9.9"], "hostname": "orphan",
                             "nodeId": "n9"}])
        c = rc.take(db_path=path, tailscale=ts)
        check("count is the entitlement count", c.count, 2)
        check("not degraded", c.degraded, False)
        check("local device not counted", 2 not in (3,), True)
        # The finding that made this module necessary.
        check("orphan detected", len(c.tailnet_only), 1)
        check("orphan named", c.tailnet_only[0]["hostname"], "orphan")
        check("orphan NOT added to the cap count", c.count, 2)
    finally:
        os.unlink(path)


def test_census_refuses_to_guess():
    print("\n[an unreachable tailnet must NOT fall back to the DB count]")
    from core import remote_census as rc
    path = _census_db(rows=[("d1", "one", "100.1.1.1", "approved", 1)])
    try:
        c = rc.take(db_path=path, tailscale=_FakeTS(boom=True))
        check("degraded", c.degraded, True)
        # This is the whole point: 1 would have been a believable wrong answer.
        check("count is None, NOT the DB count", c.count, None)
        check("not reconciled", c.reconciled, False)
        check("reason names the cause", "unreachable" in c.reason, True)
    finally:
        os.unlink(path)


def test_census_missing_column_is_loud():
    print("\n[a missing remote_enabled column must not read as zero]")
    from core import remote_census as rc
    path = _census_db(with_col=False)
    try:
        c = rc.take(db_path=path, tailscale=_FakeTS())
        check("degraded", c.degraded, True)
        check("count is None, not 0", c.count, None)
        check("reason explains", "remote_enabled" in c.reason, True)
    finally:
        os.unlink(path)


def test_census_no_tailnet_configured():
    print("\n[no tailnet configured: DB count stands, and says why]")
    from core import remote_census as rc
    path = _census_db(rows=[("d1", "one", "100.1.1.1", "approved", 1)])
    try:
        c = rc.take(db_path=path, tailscale=_FakeTS(configured=False))
        check("not degraded", c.degraded, False)
        check("count stands", c.count, 1)
        check("reason explains there is nothing to reconcile",
              "not configured" in c.reason, True)
    finally:
        os.unlink(path)



def test_census_classifies_nodes_three_ways():
    """self / known-but-not-entitled / genuinely unknown must not be one bucket.

    Lumping them together flagged this server's own tailnet node and every
    pre-licensing device as unknown machines on the VPN. An alarm that is almost
    always wrong is worse than no alarm: it trains the operator to ignore it.
    """
    print("\n[the census separates self, known-but-unentitled, and unknown]")
    from core import remote_census as rc
    real_self = rc._own_tailnet_addresses
    path = _census_db(rows=[
        ("d1", "entitled",  "100.7.0.1", "approved", 1),
        ("d2", "preexist",  "100.7.0.2", "approved", 0),   # knows it, not entitled
        ("d3", "localonly", "192.168.1.9", "approved", 0),
    ])
    try:
        rc._own_tailnet_addresses = lambda: {"100.7.0.99"}
        ts = _FakeTS(nodes=[
            {"addresses": ["100.7.0.1"],  "hostname": "entitled", "nodeId": "n1"},
            {"addresses": ["100.7.0.2"],  "hostname": "preexist", "nodeId": "n2"},
            {"addresses": ["100.7.0.99"], "hostname": "this-server", "nodeId": "n9"},
            {"addresses": ["100.7.0.50"], "hostname": "ghost", "nodeId": "n5"},
        ])
        c = rc.take(db_path=path, tailscale=ts)
        check("count is entitlements only", c.count, 1)
        check("the server's own node is NOT an orphan",
              [o["hostname"] for o in c.self_nodes], ["this-server"])
        check("a known-but-unentitled device is NOT an orphan",
              [o["hostname"] for o in c.known_not_entitled], ["preexist"])
        check("it carries the friendly device name",
              c.known_not_entitled[0].get("device_name"), "preexist")
        # Only the genuine leftover warns.
        check("only the unknown machine is an orphan",
              [o["hostname"] for o in c.tailnet_only], ["ghost"])
        # CONTROL: the classifier must still be able to find an orphan at all.
        check("CONTROL exactly one orphan", len(c.tailnet_only), 1)
    finally:
        rc._own_tailnet_addresses = real_self
        os.unlink(path)



if __name__ == "__main__":
    print("licensing tests")
    test_key_verification()
    test_forgery_is_refused()
    test_tampered_payload_is_refused()
    test_node_lock_and_expiry()
    test_missing_pubkey_is_its_own_verdict()
    test_only_valid_grants()
    test_install_id_real()
    test_install_id_failure_states()
    test_backup_codes()
    test_backup_code_regeneration_supersedes()
    test_backup_code_status_levels()
    test_census_reconciles()
    test_census_classifies_nodes_three_ways()
    test_census_refuses_to_guess()
    test_census_missing_column_is_loud()
    test_census_no_tailnet_configured()

    print("\n" + "=" * 60)
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  - %s" % f)
        sys.exit(1)
    print("ALL PASS")
