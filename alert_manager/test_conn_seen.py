"""Track C step 5 — seen-set tests, weighted towards the merge path.

Run: python3 alert_manager/test_conn_seen.py

The merge is the part that fails SILENTLY. A seen-set that never stores anything
is obvious within a day; a seen-set that resets a destination's history every
time a name appears looks exactly like a working detector having a busy week. So
the tests here are not "does it insert a row" — they check that history SURVIVES
the events that could destroy it, and each one is paired with a case that must
come out the other way, so a check that can only pass is visible as such.
"""
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)
sys.path.insert(0, _HERE)

import conn_seen as cs                   # noqa: E402
import data_manager                      # noqa: E402
import database                          # noqa: E402

passed = failed = 0
_tmp = tempfile.mkdtemp(prefix="conn-seen-")
DB = os.path.join(_tmp, "alerts.db")
database.DB_PATH = DB


def check(name, cond, detail=""):
    global passed, failed
    ok = bool(cond)
    print(("  [PASS] " if ok else "  [FAIL] ") + name +
          ("" if ok or not detail else "   (%s)" % detail))
    if ok:
        passed += 1
    else:
        failed += 1


def db():
    return sqlite3.connect(DB, timeout=5.0)


def fresh():
    """A clean seen-set. Returns an open connection the caller must close."""
    c = db()
    c.execute("DELETE FROM conn_seen_dest_addrs")
    c.execute("DELETE FROM conn_seen_destinations")
    c.commit()
    return c


def day(n):
    """A fixed ISO timestamp n days after a fixed epoch.

    Fixed rather than relative to now(): a retention test written against
    datetime.now() passes or fails depending on when it runs, which is the same
    class of untrustworthy instrument this suite exists to catch.
    """
    return (datetime(2026, 1, 1, 12, 0, 0) + timedelta(days=n)).isoformat(
        timespec="seconds")


def dests(c, device="dev-1"):
    return c.execute(
        "SELECT dest_key, key_kind, first_seen, last_seen, conn_count "
        "FROM conn_seen_destinations WHERE device_id=? ORDER BY dest_key",
        (device,)).fetchall()


def rec(c, obs, device="dev-1", now=None):
    return cs.record_destinations(c, device, obs, now or day(0))


database.init_conn_events_tables()

# ═══════════════════════════════════════════════════ schema + migration
print("\nschema and the consent_basis migration")
cols = {r[1] for r in db().execute("PRAGMA table_info(conn_consent)").fetchall()}
check("conn_consent has consent_basis", "consent_basis" in cols)
check("granted_by still present (migration did not replace it)", "granted_by" in cols)

c = db()
c.execute("INSERT INTO conn_consent (device_id, consent_version, recorded_at) "
          "VALUES ('dev-legacy', 1, ?)", (day(0),))
c.commit()
basis = c.execute("SELECT consent_basis FROM conn_consent WHERE device_id='dev-legacy'"
                  ).fetchone()[0]
# The decisive one: a row that predates the column must read as UNKNOWN, not as
# a manufactured claim that someone consented individually.
check("a row with no basis reads back as NULL, not a default", basis is None,
      "got %r" % (basis,))
c.close()

database.init_conn_events_tables()      # idempotency: running it twice must not throw
cols2 = {r[1] for r in db().execute("PRAGMA table_info(conn_consent)").fetchall()}
check("migration is idempotent (second init adds nothing)", cols2 == cols)

tables = {r[0] for r in db().execute(
    "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
check("conn_seen_destinations created", "conn_seen_destinations" in tables)
check("conn_seen_dest_addrs created", "conn_seen_dest_addrs" in tables)

# ═══════════════════════════════════════════════════ Data Manager grant
print("\nData Manager grant (the failure that hides in production)")
check("hw_monitor may write conn_seen_destinations",
      data_manager.allowed("hw_monitor", "conn_seen_destinations"))
check("hw_monitor may write conn_seen_dest_addrs",
      data_manager.allowed("hw_monitor", "conn_seen_dest_addrs"))
# CONTROL: the grant is exact-match, so a neighbouring name must be REFUSED. If
# this passed, the grant would be a prefix and would silently pre-authorise
# every future conn_seen_* table.
check("a same-stem table is NOT pre-authorised (grant is exact)",
      not data_manager.allowed("hw_monitor", "conn_seen_destinations_archive"))
check("an unrelated module is refused",
      not data_manager.allowed("dhcp", "conn_seen_destinations"))

# ═══════════════════════════════════════════════════ basic membership
print("\nbasic membership, both directions")
c = fresh()
r = cs.lookup(c, "dev-1", "203.0.113.10")
check("an unseen destination is unseen", r["known"] is False and r["basis"] == "unseen")
rec(c, [("203.0.113.10", None, True)])
r = cs.lookup(c, "dev-1", "203.0.113.10")
check("after recording, it is known", r["known"] is True)
check("basis is the address (no name was observed)", r["basis"] == "addr")
check("conn_count counted the open", r["conn_count"] == 1)
# CONTROL: a DIFFERENT address must still be unseen — otherwise "known" is just
# a function that returns True.
check("a different address is still unseen",
      cs.lookup(c, "dev-1", "203.0.113.11")["known"] is False)
# CONTROL: another device must not inherit this device's history.
check("another device does not see it (scope is per-device)",
      cs.lookup(c, "dev-2", "203.0.113.10")["known"] is False)
c.close()

# ═══════════════════════════════════════════════════ THE MERGE, forward
print("\nMERGE: address first, name later — history must survive")
c = fresh()
rec(c, [("203.0.113.20", None, True)], now=day(0))           # day 0: bare IP
before = dests(c)
check("bare address created one address-keyed entry",
      len(before) == 1 and before[0][1] == cs.KIND_ADDR, str(before))

rec(c, [("203.0.113.20", "cdn.example.com", True)], now=day(5))   # day 5: named
after = dests(c)
check("after the merge there is exactly ONE entry, not two", len(after) == 1,
      str(after))
check("the surviving entry is name-keyed",
      after and after[0][0] == "cdn.example.com" and after[0][1] == cs.KIND_NAME)
# THE decisive assertion of the whole suite.
check("first_seen was CARRIED ACROSS from day 0 (history not reset)",
      after and after[0][2] == day(0), "got %r, wanted %r" % (after[0][2], day(0)))
check("conn_count was carried across too (1 + 1)", after and after[0][4] == 2)
check("merged_count records that a merge happened",
      c.execute("SELECT merged_count FROM conn_seen_destinations").fetchone()[0] == 1)

# The follow-on that the whole two-table design exists for: a LATER name-less
# connection to the same address must resolve to the merged entry. If the addr
# mapping had not been repointed, this would mint a fresh entry with
# first_seen=day(9) and the destination would read as novel again.
rec(c, [("203.0.113.20", None, True)], now=day(9))
after2 = dests(c)
check("a later name-less connection did NOT create a rival entry",
      len(after2) == 1, str(after2))
check("first_seen is STILL day 0 after the name-less follow-up",
      after2[0][2] == day(0), "got %r" % (after2[0][2],))
r = cs.lookup(c, "dev-1", "203.0.113.20")
check("lookup by bare address finds the named destination",
      r["known"] and r["key_kind"] == cs.KIND_NAME and r["first_seen"] == day(0))
check("only one address row exists for it",
      c.execute("SELECT COUNT(*) FROM conn_seen_dest_addrs").fetchone()[0] == 1)
# These two exist because of a mutation test. With the merge's address-repoint
# REMOVED, the two first_seen checks above still passed — the follow-up write
# landed on a dangling row, affected nothing, and "history unchanged" was
# satisfied by nothing having happened at all. Both assertions below fail under
# that mutation, because both require the write to have actually landed.
check("the day-9 connection was actually COUNTED (write landed, not a no-op)",
      after2[0][4] == 3, "conn_count=%r, wanted 3" % (after2[0][4],))
check("no address row dangles (every addr points at a live destination)",
      c.execute("SELECT COUNT(*) FROM conn_seen_dest_addrs a WHERE NOT EXISTS "
                "(SELECT 1 FROM conn_seen_destinations d WHERE d.id=a.dest_id)"
                ).fetchone()[0] == 0)
c.close()

# ═══════════════════════════════════════════════════ THE MERGE, reverse
print("\nMERGE: one name, many addresses (the CDN direction)")
c = fresh()
for i, ip in enumerate(("203.0.113.30", "203.0.113.31", "203.0.113.32")):
    rec(c, [(ip, "cdn.example.com", True)], now=day(i))
d = dests(c)
check("three CDN edges collapsed into ONE destination entry", len(d) == 1, str(d))
check("first_seen is the earliest of the three", d[0][2] == day(0))
check("all three addresses map to it",
      c.execute("SELECT COUNT(*) FROM conn_seen_dest_addrs").fetchone()[0] == 3)
check("each edge is individually known by address",
      all(cs.lookup(c, "dev-1", ip)["known"]
          for ip in ("203.0.113.30", "203.0.113.31", "203.0.113.32")))
# CONTROL: an edge we have NOT seen must still be novel, even under a known name.
r = cs.lookup(c, "dev-1", "203.0.113.99", "cdn.example.com")
check("an unseen address under a KNOWN name: name known, address not",
      r["name_known"] is True and r["addr_known"] is False and r["basis"] == "name")
c.close()

# ═══════════════════════════════════════════════════ shared hosting
print("\nshared infrastructure: two names on one address must NOT merge")
c = fresh()
rec(c, [("203.0.113.40", "first.example.com", True)], now=day(0))
rec(c, [("203.0.113.40", "second.example.net", True)], now=day(1))
d = dests(c)
check("both named destinations survive as separate entries", len(d) == 2, str(d))
check("neither inherited the other's first_seen",
      {row[2] for row in d} == {day(0), day(1)}, str(d))
check("the address rebound to the most recent name",
      c.execute("SELECT dest_key FROM conn_seen_destinations d JOIN "
                "conn_seen_dest_addrs a ON a.dest_id=d.id").fetchone()[0]
      == "second.example.net")
c.close()

# ═══════════════════════════════════════════════════ normalisation
print("\nnormalisation (an unnormalised key resets history just as quietly)")
c = fresh()
rec(c, [("203.0.113.50", "Example.COM.", True)], now=day(0))
rec(c, [("203.0.113.51", "example.com", True)], now=day(1))
check("case and trailing dot collapse to one entry", len(dests(c)) == 1, str(dests(c)))
c.close()

c = fresh()
rec(c, [("::1", None, True)], now=day(0))
rec(c, [("0:0:0:0:0:0:0:1", None, True)], now=day(1))
check("two spellings of one IPv6 address collapse to one entry",
      len(dests(c)) == 1, str(dests(c)))
# CONTROL: genuinely different addresses must NOT collapse.
rec(c, [("::2", None, True)], now=day(2))
check("a genuinely different IPv6 address stays separate", len(dests(c)) == 2)
c.close()

# ═══════════════════════════════════════════════════ counting
print("\ncounting: opens are connections, closes are not")
c = fresh()
rec(c, [("203.0.113.60", None, True)], now=day(0))
rec(c, [("203.0.113.60", None, False)], now=day(3))
d = dests(c)
check("close did not increment conn_count", d[0][4] == 1, str(d))
check("close DID refresh last_seen", d[0][3] == day(3), str(d))
c.close()

# ═══════════════════════════════════════════════════ retention arithmetic
print("\nretention window arithmetic")
check("the seen window is used when it is the longer one",
      cs.effective_retention_days(365, 30) == 365)
# THE FLOOR. A seen-set shorter than the event window is incoherent.
check("a seen window SHORTER than the event window is floored to it",
      cs.effective_retention_days(10, 30) == 30)
check("the ceiling caps a hostile value",
      cs.effective_retention_days(999999, 30) == cs.RETENTION_CEILING_DAYS)
check("a negative falls back to the default", cs.effective_retention_days(-5, 30) == 365)
check("a non-integer falls back to the default",
      cs.effective_retention_days("forever", 30) == 365)
# bool is an int subclass and has bitten this codebase before.
check("True is not accepted as a day count", cs.effective_retention_days(True, 30) == 365)

# ═══════════════════════════════════════════════════ the reaper
print("\nreaper: aged by INACTIVITY, never by age")
c = fresh()
# Old and untouched: must go.
rec(c, [("203.0.113.70", None, True)], now=day(0))
# Old first_seen but STILL ACTIVE: must survive. This is the control that
# separates last_seen aging from first_seen aging — a reaper written against
# first_seen passes every other check in this file and fails only here.
rec(c, [("203.0.113.71", None, True)], now=day(0))
rec(c, [("203.0.113.71", None, True)], now=day(400))
res = cs.reap(c, 365, 30, day(401))
check("the stale destination was deleted", res["destinations"] == 1, str(res))
survivors = [r[0] for r in dests(c)]
check("the long-lived but ACTIVE destination survived",
      survivors == ["203.0.113.71"], str(survivors))
check("its first_seen is older than the window (so age alone did not save it)",
      dests(c)[0][2] == day(0))
check("the deleted destination's address row went too",
      c.execute("SELECT COUNT(*) FROM conn_seen_dest_addrs").fetchone()[0] == 1)
check("the reaper reports the window it actually applied", res["days"] == 365)
c.close()

print("\nreaper: orphan sweep")
c = fresh()
rec(c, [("203.0.113.80", "orphan.example.com", True)], now=day(0))
c.execute("DELETE FROM conn_seen_destinations")          # simulate a torn state
c.commit()
res = cs.reap(c, 365, 30, day(1))
check("an address row whose destination vanished is swept",
      res["orphans"] == 1 and
      c.execute("SELECT COUNT(*) FROM conn_seen_dest_addrs").fetchone()[0] == 0,
      str(res))
c.close()

# ═══════════════════════════════════════════════════ revocation purge
print("\nrevocation purge (Requirement 0 clause 7)")
c = fresh()
rec(c, [("203.0.113.90", "keep.example.com", True)], device="dev-keep")
rec(c, [("203.0.113.91", "gone.example.com", True)], device="dev-gone")
res = cs.purge_device(c, "dev-gone")
check("the revoking device's entries were deleted", res["destinations"] == 1, str(res))
check("its address rows went too", res["addrs"] == 1, str(res))
check("purged device has nothing left",
      cs.lookup(c, "dev-gone", "203.0.113.91")["known"] is False)
# CONTROL: a purge that deleted everything would also pass the check above.
check("the OTHER device was untouched",
      cs.lookup(c, "dev-keep", "203.0.113.90")["known"] is True)
c.close()

# ═══════════════════════════════════════════════════ failure posture
print("\nfailure posture: a broken read must not look like an answer")
c = fresh()
c.execute("DROP TABLE conn_seen_dest_addrs")
c.commit()
try:
    r = cs.lookup(c, "dev-1", "203.0.113.10")
    check("a failed lookup RAISES rather than returning 'unseen'", False,
          "returned %r" % (r,))
except cs.ConnSeenError:
    check("a failed lookup RAISES rather than returning 'unseen'", True)
try:
    cs.reap(c, 365, 30, day(1))
    check("a failed reap RAISES rather than reporting 0 deleted", False)
except cs.ConnSeenError:
    check("a failed reap RAISES rather than reporting 0 deleted", True)
c.close()

# record_destinations is the exception — it must NOT raise, because losing the
# seen-set update must never cost the events that produced it.
c = db()
counts = cs.record_destinations(c, "dev-1", [("203.0.113.10", None, True)], day(0))
check("record_destinations survives a broken table and COUNTS the error",
      counts["errors"] == 1 and counts["created"] == 0, str(counts))
c.close()
database.init_conn_events_tables()       # rebuild what the failure test dropped

# ═══════════════════════════════════════════════════ malformed input
print("\nmalformed observations")
c = fresh()
counts = rec(c, [(None, None, True), ("", None, True), ("   ", None, True)])
check("unusable addresses are skipped, not stored", counts["skipped"] == 3, str(counts))
check("nothing was created from them", len(dests(c)) == 0)
# A name that is textually an address must not collide with the real address
# entry — the reason key_kind is in the unique index.
rec(c, [("203.0.113.10", "203.0.113.10", True)])
rec(c, [("198.51.100.5", None, True)])
d = dests(c)
check("a name that looks like an address is stored as a NAME",
      any(x[0] == "203.0.113.10" and x[1] == cs.KIND_NAME for x in d), str(d))
c.close()

# ═══════════════════════════════════════════════════ concurrency
print("\nconcurrent writers (hw_monitor's agent listener is threaded)")
import threading                                    # noqa: E402

c = fresh()
c.execute("PRAGMA journal_mode=WAL")
c.close()
errors = []


def hammer(i):
    conn = sqlite3.connect(DB, timeout=15.0)
    try:
        for _ in range(20):
            r = cs.record_destinations(
                conn, "dev-race",
                [("203.0.113.200", "race.example.com", True)], day(0))
            if r["errors"]:
                errors.append(("record", i, r))
            conn.commit()
    except Exception as e:                           # noqa: BLE001
        errors.append(("raise", i, repr(e)))
    finally:
        conn.close()


threads = [threading.Thread(target=hammer, args=(i,)) for i in range(6)]
for t in threads:
    t.start()
for t in threads:
    t.join()

c = db()
n_dest = c.execute("SELECT COUNT(*) FROM conn_seen_destinations WHERE device_id='dev-race'"
                   ).fetchone()[0]
n_addr = c.execute("SELECT COUNT(*) FROM conn_seen_dest_addrs WHERE device_id='dev-race'"
                   ).fetchone()[0]
total = c.execute("SELECT conn_count FROM conn_seen_destinations WHERE device_id='dev-race'"
                  ).fetchone()
check("6 concurrent writers produced exactly ONE destination", n_dest == 1,
      "got %d" % n_dest)
check("  and exactly ONE address row", n_addr == 1, "got %d" % n_addr)
check("  with no errors or exceptions", not errors, str(errors[:3]))
# CONTROL: the writes must actually have landed — a run where every thread
# silently failed would satisfy all three checks above.
check("CONTROL: all 120 observations were counted",
      total and total[0] == 120, "conn_count=%r, wanted 120" % (total and total[0],))
c.close()

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
