"""Tests for Track C consent grant/revoke and Requirement 0 clause 7's purge.

The revocation tests are the point of this file. Clause 7 is a compliance claim
— "revoking erases what was collected" — and a claim like that has to be proven
against real rows, with controls that can genuinely fail, not asserted.

Every purge test therefore seeds TWO devices and checks the OTHER one is
untouched. A purge that deletes everything would satisfy a single-device test
perfectly.

Run:  python3 test_conn_consent.py
"""
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

RESULTS = []
DEV = "device-under-test"
OTHER = "other-device-must-survive"


def check(n, name, ok, detail=""):
    RESULTS.append((n, name, bool(ok)))
    print("  [%s] %2d. %-58s %s" % ("PASS" if ok else "FAIL", n, name, detail))
    return bool(ok)


def fresh_db():
    """A real schema, built by the canonical init, not hand-rolled here."""
    import database
    tmpd = tempfile.mkdtemp(prefix="consent-")
    dbp = os.path.join(tmpd, "t.db")
    orig = database.DB_PATH
    database.DB_PATH = dbp
    try:
        database.init_conn_events_tables()
    finally:
        database.DB_PATH = orig
    return sqlite3.connect(dbp)


def seed_events(conn, device_id, n=3):
    for i in range(n):
        conn.execute(
            "INSERT INTO conn_events (device_id, conn_id, event, consent_version,"
            " proto, laddr, lport, raddr, rport, ts_open_wall, ts_open_mono,"
            " received_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (device_id, "c-%d" % i, "open", 1, "tcp", "198.51.100.5", 1000 + i,
             "203.0.113.%d" % (10 + i), 443, "2026-08-08T00:00:0%d" % i,
             1000.0 + i, "2026-08-08T00:00:0%d" % i))


def counts(conn, device_id):
    q = lambda t: conn.execute(
        "SELECT COUNT(*) FROM %s WHERE device_id=?" % t, (device_id,)).fetchone()[0]
    return (q("conn_events"), q("conn_seen_destinations"), q("conn_seen_dest_addrs"))


def main():
    import conn_consent as cc
    import conn_seen
    import data_manager as dm

    print("TRACK C — CONSENT GRANT / REVOKE + CLAUSE 7 PURGE")
    print("=" * 78)

    # ── grants, asserted DIRECTLY (the silent WOULD-DENY trap) ───────────────
    need = ("conn_consent", "conn_events", "conn_seen_destinations",
            "conn_seen_dest_addrs")
    check(1, "grant: all four tables writable by the conn_consent namespace",
          all(dm.allowed("conn_consent", t) for t in need),
          "%d/4" % sum(dm.allowed("conn_consent", t) for t in need))
    check(2, "CONTROL: grant is EXACT, not a `conn_` prefix",
          not dm.allowed("conn_consent", "conn_anything_future"))
    check(3, "CONTROL: dashboard did NOT silently gain telemetry-delete rights",
          not any(dm.allowed("dashboard", t) for t in need))
    check(4, "namespace defaults to ENFORCE",
          dm.namespace_mode("conn_consent") == dm.MODE_ENFORCE)

    # ── the version constant must match the agent's ──────────────────────────
    import importlib.util
    ap = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "..", "nemesis_agent", "consent.py")
    spec = importlib.util.spec_from_file_location("agent_consent", ap)
    ac = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ac)
    check(5, "CURRENT_CONSENT_VERSION matches agent DISCLOSURE_VERSION",
          cc.CURRENT_CONSENT_VERSION == ac.DISCLOSURE_VERSION,
          "server=%s agent=%s" % (cc.CURRENT_CONSENT_VERSION,
                                  ac.DISCLOSURE_VERSION))

    # ── grant ────────────────────────────────────────────────────────────────
    conn = fresh_db()
    res = cc.grant(DEV, granted_by="operator", conn=conn)
    st = cc.status(DEV, conn=conn)
    check(6, "grant records consent and opens the gate",
          st["consented"] and st["consent_version"] == 1
          and st["consent_basis"] == "individual", str(res)[:56])

    check(7, "status of an unknown device is explicit, not a fake grant",
          cc.status("never-seen", conn=conn)["consented"] is False)

    # ── employer basis is REFUSED, not silently coerced ──────────────────────
    refused = False
    try:
        cc.grant("emp-device", basis="employer", conn=conn)
    except cc.EmployerBasisNotAvailable:
        refused = True
    check(8, "employer basis RAISES its own type (gated on legal review)",
          refused and cc.status("emp-device", conn=conn)["consented"] is False,
          "and no row was written")

    bad = False
    try:
        cc.grant("x", basis="nonsense", conn=conn)
    except cc.ConsentError:
        bad = True
    check(9, "unknown basis refused", bad)

    for badid in (None, "", "   ", 42):
        try:
            cc.grant(badid, conn=conn)
            check(10, "device_id validated", False, "accepted %r" % (badid,))
            break
        except cc.ConsentError:
            pass
    else:
        check(10, "device_id validated (None/empty/blank/non-str refused)", True)

    # ── the ingest gate actually opens ───────────────────────────────────────
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "..", "core_module", "hw_monitor"))
    import hw_monitor as hm
    v = hm._server_consent_version(conn, DEV)
    check(11, "hw_monitor's ingest gate now returns a version (gate OPEN)",
          v == 1, "version=%r" % v)
    check(12, "CONTROL: gate still CLOSED for an unconsented device",
          hm._server_consent_version(conn, "never-seen") is None)

    # ── clause 7: revoke purges BOTH stores, and ONLY this device ────────────
    cc.grant(OTHER, conn=conn)
    seed_events(conn, DEV, 3)
    seed_events(conn, OTHER, 2)
    conn_seen.record_destinations(conn, DEV, [
        ("203.0.113.10", "example-a.invalid", True),
        ("203.0.113.11", None, True)], "2026-08-08T00:00:00")
    conn_seen.record_destinations(conn, OTHER, [
        ("203.0.113.50", "example-b.invalid", True)], "2026-08-08T00:00:00")
    conn.commit()

    before_dev = counts(conn, DEV)
    before_other = counts(conn, OTHER)
    check(13, "seeded: both devices have events AND seen-set rows",
          all(x > 0 for x in before_dev) and all(x > 0 for x in before_other),
          "dev=%s other=%s" % (before_dev, before_other))

    out = cc.revoke(DEV, actor="operator", conn=conn)
    after_dev = counts(conn, DEV)
    after_other = counts(conn, OTHER)

    check(14, "revoke PURGES conn_events for the device",
          after_dev[0] == 0 and out["purged_events"] == before_dev[0],
          "%d -> 0" % before_dev[0])
    check(15, "revoke PURGES the seen-set too (summary is not exempt)",
          after_dev[1] == 0 and after_dev[2] == 0,
          "dests %d->0, addrs %d->0" % (before_dev[1], before_dev[2]))
    check(16, "CONTROL: the OTHER device is untouched",
          after_other == before_other, "%s == %s" % (after_other, before_other))
    check(17, "revoke marks revoked_at and closes the gate",
          cc.status(DEV, conn=conn)["revoked_at"] is not None
          and hm._server_consent_version(conn, DEV) is None)

    check(18, "revoking a device with no record RAISES (not silent success)",
          _raises(lambda: cc.revoke("never-consented", conn=conn), cc.ConsentError))

    # ── re-grant does NOT resurrect purged data ──────────────────────────────
    cc.grant(DEV, conn=conn)
    st2 = cc.status(DEV, conn=conn)
    check(19, "re-grant clears revoked_at and reopens the gate",
          st2["consented"] and st2["revoked_at"] is None
          and hm._server_consent_version(conn, DEV) == 1)
    check(20, "re-grant does NOT resurrect purged data",
          counts(conn, DEV) == (0, 0, 0), str(counts(conn, DEV)))

    # ── atomicity: a failed purge must roll the revocation back ──────────────
    conn2 = fresh_db()
    cc.grant(DEV, conn=conn2)
    seed_events(conn2, DEV, 2)
    conn_seen.record_destinations(conn2, DEV, [
        ("203.0.113.10", "a.invalid", True)], "2026-08-08T00:00:00")
    conn2.commit()
    real_purge = conn_seen.purge_device
    conn_seen.purge_device = lambda c, d: (_ for _ in ()).throw(
        RuntimeError("simulated purge failure"))
    try:
        blew_up = _raises(lambda: cc.revoke(DEV, conn=conn2), cc.ConsentError)
    finally:
        conn_seen.purge_device = real_purge
    # caller-owned conn: this module does not roll back a connection it does not
    # own, so the caller must. That contract is what the next check pins.
    conn2.rollback()
    st3 = cc.status(DEV, conn=conn2)
    ev = conn2.execute("SELECT COUNT(*) FROM conn_events WHERE device_id=?",
                       (DEV,)).fetchone()[0]
    check(21, "failed purge RAISES rather than reporting a completed erasure",
          blew_up)
    check(22, "after rollback: NOT recorded as revoked, and data intact",
          st3["revoked_at"] is None and st3["consented"] and ev == 2,
          "revoked_at=%r events=%d" % (st3["revoked_at"], ev))

    # ── MUTATION: prove the isolation control is real ────────────────────────
    print()
    print("  MUTATION GATES")
    conn3 = fresh_db()
    cc.grant(DEV, conn=conn3); cc.grant(OTHER, conn=conn3)
    seed_events(conn3, DEV, 2); seed_events(conn3, OTHER, 2)
    conn3.commit()
    # purge everything, ignoring device scope — gate 16 must notice.
    # A PROXY connection, not a monkeypatch: sqlite3.Connection is an immutable
    # type and cannot have `execute` reassigned. The proxy is arguably the better
    # mutation anyway — it exercises the real code path with one statement
    # swapped, rather than altering the driver underneath it.
    class UnscopedProxy:
        def __init__(self, real): self._r = real
        def execute(self, sql, *a):
            if "DELETE FROM conn_events WHERE device_id=?" in sql:
                return self._r.execute("DELETE FROM conn_events")
            return self._r.execute(sql, *a)
        def __getattr__(self, n): return getattr(self._r, n)

    try:
        cc.revoke(DEV, conn=UnscopedProxy(conn3))
    except Exception:
        pass
    other_left = conn3.execute("SELECT COUNT(*) FROM conn_events WHERE device_id=?",
                               (OTHER,)).fetchone()[0]
    check(23, "MUTATION: an unscoped purge is CAUGHT (other device wiped)",
          other_left == 0, "proves gate 16 is not vacuous")

    print()
    passed = sum(1 for _n, _t, ok in RESULTS if ok)
    failed = [(n, t) for n, t, ok in RESULTS if not ok]
    print("=" * 78)
    print("RESULT: %d/%d checks passed" % (passed, len(RESULTS)))
    for n, t in failed:
        print("  FAILED %2d. %s" % (n, t))
    print("=" * 78)
    return 0 if not failed else 1


def _raises(fn, exc):
    try:
        fn()
        return False
    except exc:
        return True


if __name__ == "__main__":
    raise SystemExit(main())
