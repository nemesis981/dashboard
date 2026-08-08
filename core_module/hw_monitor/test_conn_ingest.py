"""Track C step 3 — server ingest, and Requirement 0 clause 5 enforced server-side.

Run: python3 core_module/hw_monitor/test_conn_ingest.py

The plan's acceptance for Requirement 0 is "zero server-side rows — verified by
test, not by inspection", so the decisive assertions here read the TABLE back
rather than trusting the returned counts. Counts are what the code says it did;
rows are what it did.

Every rejection case is paired with an accept case that must store rows — a suite
that only proved "nothing was stored" would pass against an ingest function that
is simply broken.
"""
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "alert_manager"))
sys.path.insert(0, _HERE)

import database                       # noqa: E402
from nemesis_agent import conn_events as ce   # noqa: E402
import hw_monitor as hm               # noqa: E402

passed = failed = 0
_tmp = tempfile.mkdtemp(prefix="conn-ingest-")
DB = os.path.join(_tmp, "alerts.db")
database.DB_PATH = DB
database.init_conn_events_tables()

# Point the module under test at the temp DB. Raw sqlite3 here is the TEST
# harness standing in for the Data Manager connection, not production code.
hm._db_connect = lambda: sqlite3.connect(DB, timeout=5.0)


def check(name, cond, detail=""):
    global passed, failed
    ok = bool(cond)
    print(("  [PASS] " if ok else "  [FAIL] ") + name + ("" if ok or not detail else "  (%s)" % detail))
    if ok:
        passed += 1
    else:
        failed += 1


def db():
    return sqlite3.connect(DB)


def rowcount():
    return db().execute("SELECT COUNT(*) FROM conn_events").fetchone()[0]


def wipe():
    c = db()
    c.execute("DELETE FROM conn_events")
    c.execute("DELETE FROM conn_consent")
    c.commit()
    c.close()


def grant(device_id="dev-1", version=1, revoked=None):
    c = db()
    c.execute("INSERT OR REPLACE INTO conn_consent (device_id, consent_version, granted_at,"
              " granted_by, recorded_at, revoked_at) VALUES (?,?,?,?,?,?)",
              (device_id, version, "2026-08-07T12:00:00", "device-user",
               datetime.now().isoformat(timespec="seconds"), revoked))
    c.commit()
    c.close()


def ev(**over):
    rec = {
        "schema_version": ce.SCHEMA_VERSION, "event": "open", "conn_id": "c-1",
        "device_id": "dev-1", "consent_version": 1, "proto": "tcp",
        "laddr": "192.0.2.10", "lport": 51000, "raddr": "198.51.100.20", "rport": 443,
        "ts_open_wall": "2026-08-07T12:00:00-0500", "ts_open_mono": 1000.0,
        "ts_close_wall": None, "ts_close_mono": None, "pid": 42,
        "proc_name": "curl", "proc_path": "/usr/bin/curl",
        "proc_signed": "unknown", "bytes_sent": None, "bytes_recv": None,
        "resolved_name": None, "resolved_name_source": ce.NAME_SRC_UNAVAILABLE,
    }
    rec.update(over)
    return rec


def payload(events, device_id="dev-1"):
    return {"device_id": device_id, "security": {ce.PAYLOAD_KEY: events}}


# ---------------------------------------------------- THE ACCEPTANCE CRITERION
print("Requirement 0 clause 5 — no server-side consent => ZERO rows")
wipe()
c = hm.ingest_connection_events(payload([ev(), ev(conn_id="c-2")]))
check("counts report rejection", c["rejected_no_consent"] == 2 and c["stored"] == 0)
check("*** ZERO ROWS IN THE TABLE (read back, not trusted) ***", rowcount() == 0,
      "rows=%d" % rowcount())

print("the paired control — WITH consent, rows are actually stored")
wipe()
grant()
c = hm.ingest_connection_events(payload([ev(), ev(conn_id="c-2")]))
check("counts report storage", c["stored"] == 2 and c["rejected_no_consent"] == 0)
check("*** ROWS PRESENT (so the zero above measured something) ***", rowcount() == 2,
      "rows=%d" % rowcount())
r = db().execute("SELECT proc_signed, bytes_sent, bytes_recv FROM conn_events LIMIT 1").fetchone()
check("proc_signed stored as 'unknown', not coerced", r[0] == "unknown")
check("bytes stored as NULL, not 0 (the distinction survives the DB)",
      r[1] is None and r[2] is None)

# ------------------------------------------------------------- revoked consent
print("revoked consent is not consent")
wipe()
grant(revoked="2026-08-07T13:00:00")
c = hm.ingest_connection_events(payload([ev()]))
check("revoked => rejected", c["rejected_no_consent"] == 1)
check("  and zero rows", rowcount() == 0)

# ------------------------------------------------------------ version mismatch
print("consent_version must match what the SERVER recorded")
wipe()
grant(version=2)
c = hm.ingest_connection_events(payload([ev(consent_version=1)]))
check("agent claiming an older version => rejected", c["rejected_consent_mismatch"] == 1)
check("  and zero rows", rowcount() == 0)
wipe()
grant(version=1)
c = hm.ingest_connection_events(payload([ev(consent_version=99)]))
check("agent claiming a version ahead of the server => rejected",
      c["rejected_consent_mismatch"] == 1)
check("  and zero rows", rowcount() == 0)

# ------------------------------------------------------------ record validation
print("invalid records are dropped individually, valid ones still land")
wipe()
grant()
c = hm.ingest_connection_events(payload([ev(), ev(conn_id="c-bad", rport=99999), ev(conn_id="c-3")]))
check("one invalid rejected", c["rejected_invalid"] == 1)
check("  the two valid ones stored", c["stored"] == 2 and rowcount() == 2)
check("  and the bad one is absent by conn_id",
      db().execute("SELECT COUNT(*) FROM conn_events WHERE conn_id='c-bad'").fetchone()[0] == 0)

print("a record cannot claim to be from another device")
wipe()
grant()
c = hm.ingest_connection_events(payload([ev(device_id="dev-OTHER")]))
check("device_id mismatch rejected", c["rejected_invalid"] == 1 and rowcount() == 0)

# --------------------------------------------------------------- malformed block
print("malformed / absent telemetry never breaks the heartbeat")
wipe()
grant()
c = hm.ingest_connection_events(payload("not-a-list"))
check("non-list events block rejected wholesale", c["rejected_invalid"] == 1 and rowcount() == 0)
c = hm.ingest_connection_events({"device_id": "dev-1", "security": {}})
check("no events key => zeros, no error", c["received"] == 0 and c["stored"] == 0)
c = hm.ingest_connection_events({"security": {ce.PAYLOAD_KEY: [ev()]}})
check("payload with no device_id => rejected, zero rows",
      c["rejected_no_consent"] == 1 and rowcount() == 0)

# ------------------------------------------------------------------- the reaper
print("retention is enforced by a real reaper, not by intention")
wipe()
grant()
hm.ingest_connection_events(payload([ev()]))
old = (datetime.now() - timedelta(days=40)).isoformat(timespec="seconds")
c2 = db()
c2.execute("INSERT INTO conn_events (device_id, conn_id, event, consent_version, proto,"
           " laddr, lport, raddr, rport, ts_open_wall, ts_open_mono, received_at)"
           " VALUES ('dev-1','c-old','open',1,'tcp','192.0.2.10',5,'198.51.100.20',443,"
           "'2026-07-01T00:00:00-0500',1.0,?)", (old,))
c2.commit(); c2.close()
check("setup: 2 rows, one of them 40 days old", rowcount() == 2)
deleted = hm.reap_conn_events()
check("reaper deleted exactly the old one", deleted == 1, "deleted=%r" % deleted)
check("  recent row SURVIVES (control: not a delete-everything)", rowcount() == 1)
check("  and it is the recent one",
      db().execute("SELECT conn_id FROM conn_events").fetchone()[0] == "c-1")

print("a hostile retention setting cannot disable or weaponise retention")
s = db(); s.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL,"
                    " updated_at TEXT, updated_by TEXT)")
s.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('conn_event_retention_days','0')")
s.commit(); s.close()
wipe(); grant(); hm.ingest_connection_events(payload([ev()]))
deleted = hm.reap_conn_events()
check("retention_days=0 clamped to >=1, so today's row is NOT deleted",
      deleted == 0 and rowcount() == 1, "deleted=%r rows=%d" % (deleted, rowcount()))

print("schema v2: the resolved name survives the round trip to storage")
wipe(); grant()
hm.ingest_connection_events(payload([ev(resolved_name="example.test",
                                        resolved_name_source=ce.NAME_SRC_DNS_EVENT)]))
r = db().execute("SELECT resolved_name, resolved_name_source FROM conn_events").fetchone()
check("name stored", r[0] == "example.test")
check("provenance stored alongside it", r[1] == ce.NAME_SRC_DNS_EVENT)
wipe(); grant()
hm.ingest_connection_events(payload([ev()]))
r = db().execute("SELECT resolved_name, resolved_name_source FROM conn_events").fetchone()
check("absent name stored as NULL, not empty string", r[0] is None)
check("  with 'unavailable' provenance preserved (null is not informative alone)",
      r[1] == ce.NAME_SRC_UNAVAILABLE)

# ── Track C step 5: ingest populates the seen-set, and ONLY from stored events ──
# The seen-set is derived from consented telemetry, so every gate protecting
# conn_events has to protect it too. A rejection path that stored no event but
# still recorded the destination would leak exactly what Requirement 0 exists to
# prevent — and it would leak it into the table nothing ever reaps by device.

def seen_dests(device="dev-1"):
    return db().execute(
        "SELECT dest_key, key_kind, first_seen, conn_count FROM "
        "conn_seen_destinations WHERE device_id=? ORDER BY dest_key",
        (device,)).fetchall()


def wipe_seen():
    c = db()
    c.execute("DELETE FROM conn_seen_dest_addrs")
    c.execute("DELETE FROM conn_seen_destinations")
    c.commit()
    c.close()


print("ingest populates the seen-set from stored events")
wipe(); wipe_seen(); grant()
c = hm.ingest_connection_events(payload([ev(raddr="198.51.100.7")]))
d = seen_dests()
check("a stored event created a seen-set entry", len(d) == 1, str(d))
check("  keyed on the address when no name was observed",
      d and d[0][0] == "198.51.100.7" and d[0][1] == "addr")
check("  and the ingest counts report it", c.get("seen_new") == 1, str(c))

print("the seen-set learns NOTHING from rejected events")
for label, setup, evs in (
        ("no consent", lambda: None, [ev(raddr="198.51.100.20")]),
        ("revoked consent", lambda: grant(revoked="2026-08-07T13:00:00"),
         [ev(raddr="198.51.100.21")]),
        ("consent_version mismatch", lambda: grant(version=2),
         [ev(raddr="198.51.100.22", consent_version=1)]),
        ("invalid record", lambda: grant(),
         [ev(raddr="198.51.100.23", rport=99999)]),
):
    wipe(); wipe_seen(); setup()
    res = hm.ingest_connection_events(payload(evs))
    check("%s: nothing stored" % label, rowcount() == 0, str(res))
    check("  and the seen-set is EMPTY", len(seen_dests()) == 0, str(seen_dests()))

# CONTROL. Every check above is satisfied by an ingest function that is simply
# broken and stores nothing at all, so the accept case is re-run last: the same
# harness, the same table, one valid consented event, and it MUST land.
wipe(); wipe_seen(); grant()
hm.ingest_connection_events(payload([ev(raddr="198.51.100.30")]))
check("CONTROL: a valid consented event still populates the seen-set",
      len(seen_dests()) == 1, str(seen_dests()))

print("the merge path survives the real ingest path, not just unit tests")
wipe(); wipe_seen(); grant()
hm.ingest_connection_events(payload([ev(conn_id="m-1", raddr="198.51.100.40")]))
first = seen_dests()[0][2]
hm.ingest_connection_events(payload([
    ev(conn_id="m-2", raddr="198.51.100.40", resolved_name="edge.example.test",
       resolved_name_source=ce.NAME_SRC_DNS_EVENT)]))
d = seen_dests()
check("address entry merged into the named one", len(d) == 1, str(d))
check("  first_seen carried across the merge", d[0][2] == first)
check("  keyed on the name now", d[0][0] == "edge.example.test")

print("close events refresh the seen-set without double-counting connections")
wipe(); wipe_seen(); grant()
hm.ingest_connection_events(payload([ev(conn_id="x-1", raddr="198.51.100.50")]))
hm.ingest_connection_events(payload([
    ev(conn_id="x-1", raddr="198.51.100.50", event=ce.EVENT_CLOSE,
       ts_close_wall="2026-08-07T12:00:05", ts_close_mono=5.0)]))
check("one connection counted once despite two lifecycle events",
      seen_dests()[0][3] == 1, str(seen_dests()))

print("the seen-set reaper runs on its own window, not the event window")
wipe(); wipe_seen(); grant()
s = db()
s.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('conn_seen_retention_days','365')")
s.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('conn_event_retention_days','30')")
s.commit(); s.close()
hm.ingest_connection_events(payload([ev(raddr="198.51.100.60")]))
old = (datetime.now() - timedelta(days=100)).isoformat(timespec="seconds")
s = db(); s.execute("UPDATE conn_seen_destinations SET first_seen=?, last_seen=?", (old, old))
s.execute("UPDATE conn_seen_dest_addrs SET first_seen=?, last_seen=?", (old, old))
s.commit(); s.close()
# 100 days old: past the 30-day EVENT window, well inside the 365-day SEEN
# window. It must survive — this is the whole point of decoupling the two.
n = hm.reap_conn_seen()
check("an entry older than the EVENT window survives the seen window",
      n == 0 and len(seen_dests()) == 1, "reaped=%r rows=%s" % (n, seen_dests()))
# CONTROL: the same reaper must actually delete when the entry IS stale.
s = db()
s.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('conn_seen_retention_days','30')")
s.commit(); s.close()
n = hm.reap_conn_seen()
check("CONTROL: shortening the seen window does delete it",
      n > 0 and len(seen_dests()) == 0, "reaped=%r rows=%s" % (n, seen_dests()))

import shutil                                    # noqa: E402
shutil.rmtree(_tmp, ignore_errors=True)
print()
print("%d/%d passed" % (passed, passed + failed))
sys.exit(1 if failed else 0)
