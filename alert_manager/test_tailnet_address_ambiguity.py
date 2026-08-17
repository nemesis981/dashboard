"""Tests for the tailnet-address attribution guard in dashboard.py.

Run:  python3 alert_manager/test_tailnet_address_ambiguity.py

WHAT THIS GUARDS. A tailnet address is a LEASE, not an identity. Found against
the live production tailnet 2026-08-17: one node had THREE agent_devices rows
pointing at its address -- two stale June enrollments plus one device that had
reported that morning. Revoking either stale row would have removed the tailnet
node currently serving the ACTIVE device.

The failure is silent and only shows up later as "my laptop stopped working",
which is why it gets a test rather than a comment.

HOW IT AVOIDS TESTING A COPY. The SQL is not retyped here -- it is PARSED OUT OF
dashboard.py at test time and executed against a temp database. A test that
retyped the query would keep passing after the shipped query was changed or
broken, which is the exact class of useless instrument this repo keeps finding.
"""

import os
import re
import sqlite3
import sys
import tempfile

DASH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "dashboard.py")

_failures = []


def check(label, got, want):
    if got != want:
        _failures.append("%s: got %r, want %r" % (label, got, want))
        print("  FAIL  %s: got %r, want %r" % (label, got, want))
    else:
        print("  ok    %s" % label)


def extract_claimants_sql(src):
    """Pull the SELECT out of _tailnet_address_claimants as shipped."""
    body = src[src.index("def _tailnet_address_claimants"):]
    body = body[:body.index("\ndef ", 1)]
    parts = re.findall(r'"([^"]*)"', body)
    sql = "".join(p for p in parts if
                  any(t in p for t in ("SELECT", "FROM", "WHERE", "AND", "NOT IN")))
    return sql, body


SRC = open(DASH).read()
SQL, BODY = extract_claimants_sql(SRC)


def make_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE agent_devices (device_id TEXT PRIMARY KEY, "
                "device_name TEXT, ip_address TEXT, enrollment_status TEXT, "
                "agent_last_seen TEXT)")
    return con, path


def claimants(con, device_id, address):
    return con.execute(SQL, (address, device_id)).fetchall()


def test_sql_extracted():
    print("\n[the shipped SQL was actually found]")
    check("SELECT present", "SELECT" in SQL, True)
    check("filters on ip_address", "ip_address = ?" in SQL, True)
    check("excludes self", "device_id <> ?" in SQL, True)
    check("excludes surrendered claims",
          all(s in SQL for s in ("revoked", "uninstalled", "rejected")), True)


def test_the_live_production_shape():
    print("\n[the real household-device collision case: 3 rows, 1 address]")
    con, path = make_db()
    con.executemany(
        "INSERT INTO agent_devices VALUES (?,?,?,?,?)",
        [("0c21c124561c", "Windows Device", "100.40.0.1", "approved", "2026-06-29"),
         ("8628443b1d32", "Windows Device", "100.40.0.1", "approved", "2026-06-29"),
         ("ece4736c4377", "trip-laptop",    "100.40.0.1", "approved", "2026-08-17")])
    con.commit()

    # Revoking a STALE row must be refused, because the node currently serves
    # trip-laptop. This is the eviction the guard exists to prevent.
    got = claimants(con, "0c21c124561c", "100.40.0.1")
    check("stale row sees 2 other claimants", len(got), 2)
    check("trip-laptop is among them",
          any(r[0] == "ece4736c4377" for r in got), True)

    got = claimants(con, "ece4736c4377", "100.40.0.1")
    check("active row also refused (cannot attribute either way)", len(got), 2)
    con.close(); os.unlink(path)


def test_unique_address_proceeds():
    print("\n[a genuinely unique address is NOT blocked]")
    con, path = make_db()
    con.executemany(
        "INSERT INTO agent_devices VALUES (?,?,?,?,?)",
        [("aaa", "solo",  "100.10.0.1", "approved", "2026-08-01"),
         ("bbb", "other", "100.10.0.2", "approved", "2026-08-01")])
    con.commit()
    check("no claimants -> removal proceeds", claimants(con, "aaa", "100.10.0.1"), [])
    con.close(); os.unlink(path)


def test_surrendered_claims_are_ignored():
    print("\n[revoked/uninstalled/rejected rows do not block]")
    con, path = make_db()
    con.executemany(
        "INSERT INTO agent_devices VALUES (?,?,?,?,?)",
        [("live", "current",  "100.20.0.1", "approved",    "2026-08-01"),
         ("old1", "previous", "100.20.0.1", "revoked",     "2026-07-01"),
         ("old2", "previous", "100.20.0.1", "uninstalled", "2026-07-01"),
         ("old3", "previous", "100.20.0.1", "rejected",    "2026-07-01")])
    con.commit()
    # Without this exclusion, every re-enrolled device would be permanently
    # unrevokable -- the guard would block on its own history.
    check("re-enrolled device is still revocable",
          claimants(con, "live", "100.20.0.1"), [])
    con.close(); os.unlink(path)


def test_guard_runs_before_the_api_call():
    """Ordering is the whole point: checking after the DELETE is worthless."""
    print("\n[the guard is called BEFORE remove_device_by_address]")
    body = SRC[SRC.index("def _revoke_tailnet_access"):]
    body = body[:body.index("\ndef ", 1)] if "\ndef " in body[1:] else body
    has_guard = "_tailnet_address_claimants" in body
    check("guard is called in the revoke helper", has_guard, True)
    if has_guard:
        check("guard precedes the removal call",
              body.index("_tailnet_address_claimants")
              < body.index("remove_device_by_address"), True)
        check("ambiguous path returns confirmed=False",
              '"confirmed": False' in body, True)


def test_dm_conn_rows_are_read_positionally():
    """_dm_conn() resets row_factory=None, so its rows are TUPLES.

    Subscripting one by column name raises TypeError. That shipped once and made
    every revoke return HTTP 500 (2026-08-17). It is a whole defect class rather
    than a typo -- every other _dm_conn() caller in this file has the same trap --
    so it gets a regression check rather than a comment.
    """
    print("\n[_dm_conn rows are read positionally, not by name]")
    body = SRC[SRC.index("def api_agent_revoke"):]
    body = body[:body.index("\n@app.route")] if "\n@app.route" in body else body

    # Strip comment lines before matching. The fix's own comment QUOTES the bad
    # pattern (`_row["ip_address"]`) as the thing not to do, and the first version
    # of this check flagged that prose as a defect -- a false positive that would
    # have been "fixed" by deleting the explanation. Match code, not commentary.
    code = "\n".join(l for l in body.splitlines()
                     if not l.lstrip().startswith("#"))

    bad = re.findall(r'_row\s*\[\s*[\'"]', code)
    check("no name-subscripting of a _dm_conn row in api_agent_revoke", bad, [])
    check("CONTROL the route body was actually located",
          "SELECT ip_address" in code, True)
    # CONTROL: the stripper must not have eaten the code along with the comments.
    check("CONTROL positional access is present in the code",
          bool(re.search(r'_row\s*\[\s*\d', code)), True)
    # CONTROL: prove the matcher can still fire, on a known-bad synthetic line.
    check("CONTROL the matcher detects a real violation",
          bool(re.findall(r'_row\s*\[\s*[\'"]', '_row["ip_address"]')), True)

    # And the same check on the helper, which also queries via _dm_conn().
    hbody = SRC[SRC.index("def _tailnet_address_claimants"):]
    hbody = hbody[:hbody.index("\ndef ", 1)]
    hcode = "\n".join(l for l in hbody.splitlines()
                      if not l.lstrip().startswith("#"))
    check("no name-subscripting in _tailnet_address_claimants",
          re.findall(r'\br\s*\[\s*[\'"]', hcode), [])


def test_route_logs_its_own_500():
    """A 500 that logs nothing is diagnosable only by reading code."""
    print("\n[api_agent_revoke logs exceptions]")
    body = SRC[SRC.index("def api_agent_revoke"):]
    body = body[:body.index("\n@app.route")] if "\n@app.route" in body else body
    check("except branch logs", "log.exception" in body, True)
    check("...and still returns 500 to the caller", "500" in body, True)


def test_unreadable_db_fails_toward_refusing():
    print("\n[a failed claimant check must not read as 'no collisions']")
    # The except branch returns a non-empty sentinel list, so the caller refuses.
    check("except branch returns a sentinel, not []",
          "<check failed>" in BODY, True)
    check("...and it is returned, not swallowed",
          BODY.count("return [(") >= 1, True)


if __name__ == "__main__":
    print("tailnet address-attribution guard tests")
    test_sql_extracted()
    test_the_live_production_shape()
    test_unique_address_proceeds()
    test_surrendered_claims_are_ignored()
    test_guard_runs_before_the_api_call()
    test_dm_conn_rows_are_read_positionally()
    test_route_logs_its_own_500()
    test_unreadable_db_fails_toward_refusing()

    print("\n" + "=" * 60)
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  - %s" % f)
        sys.exit(1)
    print("ALL PASS")
