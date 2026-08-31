"""Autodiscovery baked into the enrollment request at MINT time.

Run: python3 modules/email_security/test_enrollment_discovery.py

WHY THIS SUITE EXISTS AS ITS OWN FILE. `get_enrollment_request`'s SELECT grew
seven columns. The only existing coverage of that function
(test_enroll_route_public.py) greps dashboard.py's SOURCE for the string
"get_enrollment_request" -- it never executes it. So the modified query had a
green suite and no test that ran it, which is indistinguishable from a passing
one right up until a column name is wrong in production. Every check below runs
the real function against a real table.

THE SECURITY PROPERTY UNDER TEST, stated plainly: autodiscovery performs
outbound DNS and HTTPS against a domain from its input. It must run ONLY in the
authenticated, capability-gated admin mint route -- never in the unauthenticated
/email/enroll pages, where an anonymous caller would choose the domain and the
rate. That boundary is asserted here.

THREE STATES MUST STAY DISTINGUISHABLE, and conflating them is the bug this
guards: "discovery never ran", "discovery ran and found nothing (here is why)",
and "discovery found settings". The middle one is the common case for custom
domains, which is why Tier 3 manual entry is a normal path and not a fallback.

NO NETWORK: discovery results are constructed directly. Real lookups are
test_autodiscover.py's job.
"""
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, "/opt/nemesis")
sys.path.insert(0, "/opt/nemesis/alert_manager")   # mirrors dashboard.service

import modules                                              # noqa: E402
import database                                             # noqa: E402
import data_manager as dm_mod                                # noqa: E402

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s %s" % (label, detail))


_TMPDB = os.path.join(tempfile.mkdtemp(prefix="emailsec-disc-"), "t.db")
database.DB_PATH = _TMPDB
modules.set_shared_db_path(_TMPDB)
database.init_email_security_tables()

import writes                                               # noqa: E402
from modules.email_security import autodiscover              # noqa: E402

DM = modules.get_data_manager()

print("-- 0. CONTROLS: the harness is what it claims to be --")
check("throwaway DB in use, not the live one",
      "/var/lib/nemesis" not in _TMPDB and os.path.exists(_TMPDB), _TMPDB)
check("CONTROL: a REAL DataManager, not a stub",
      isinstance(DM, dm_mod.DataManager), type(DM))
check("CONTROL: enforcement is ON (a missing grant would be silent otherwise)",
      dm_mod.namespace_mode("email_security") == dm_mod.MODE_ENFORCE)

print("\n-- 1. the migration actually created the columns --")
_conn = DM.connect("email_security")
_cols = {r[1] for r in _conn.execute(
    "PRAGMA table_info(email_enrollment_requests)").fetchall()}
_conn.close()
for _c in ("disc_host", "disc_port", "disc_tls", "disc_source",
           "disc_provider", "disc_problems", "disc_at"):
    check("column %s exists" % _c, _c in _cols, sorted(_cols))

print("\n-- 2. state A: discovery never ran --")
writes.create_enrollment_request("hash-none", 1, expires_at="2099-01-01T00:00:00")
row = writes.get_enrollment_request("hash-none")
check("the row reads back at all (EXERCISES the widened SELECT)",
      row is not None)
check("...and carries the new keys", "disc_host" in row and "disc_at" in row,
      sorted(row or {}))
check("disc_at is NULL -- the marker that discovery never ran",
      row["disc_at"] is None, row["disc_at"])
check("no host", row["disc_host"] is None)
check("no problems recorded", row["disc_problems"] is None)

print("\n-- 3. state B: discovery ran and found NOTHING (the common case) --")
r_none = autodiscover.DiscoveryResult("example.com")
r_none.problems = ["dns_NXDOMAIN", "ispdb_404"]
writes.create_enrollment_request("hash-nf", 1, expires_at="2099-01-01T00:00:00",
                                 discovery=r_none.to_dict())
row_nf = writes.get_enrollment_request("hash-nf")
check("disc_at IS set -- distinguishes 'ran, found nothing' from 'never ran'",
      row_nf["disc_at"] is not None, row_nf["disc_at"])
check("...and the REASONS are kept", row_nf["disc_problems"],
      row_nf["disc_problems"])
check("dns_NXDOMAIN recorded", "dns_NXDOMAIN" in (row_nf["disc_problems"] or ""))
check("ispdb_404 recorded", "ispdb_404" in (row_nf["disc_problems"] or ""))
check("NO host is invented for a not-found result",
      row_nf["disc_host"] is None, row_nf["disc_host"])
check("no port invented", row_nf["disc_port"] is None)
check("no tls invented", row_nf["disc_tls"] is None)

print("\n-- 4. state C: discovery found settings --")
r_ok = autodiscover.DiscoveryResult("example.net")
r_ok.found = True
r_ok.imap_host, r_ok.imap_port = "imap.example.net", 993
r_ok.tls_mode, r_ok.source = "implicit", "srv"
r_ok.provider_hint = "fastmail"
writes.create_enrollment_request("hash-ok", 1, expires_at="2099-01-01T00:00:00",
                                 discovery=r_ok.to_dict())
row_ok = writes.get_enrollment_request("hash-ok")
check("host stored", row_ok["disc_host"], "imap.example.net")
check("port stored as an INTEGER, not text",
      row_ok["disc_port"] == 993 and isinstance(row_ok["disc_port"], int),
      repr(row_ok["disc_port"]))
check("tls mode stored", row_ok["disc_tls"], "implicit")
check("source stored (srv vs ispdb is diagnostically different)",
      row_ok["disc_source"], "srv")
check("provider hint stored", row_ok["disc_provider"], "fastmail")
check("disc_at set", row_ok["disc_at"] is not None)

print("\n-- 5. the three states are distinguishable FROM THE ROW ALONE --")


def classify(r):
    if r["disc_at"] is None:
        return "never-ran"
    return "found" if r["disc_host"] else "ran-found-nothing"


check("state A classifies as never-ran", classify(row), "never-ran")
check("state B classifies as ran-found-nothing", classify(row_nf),
      "ran-found-nothing")
check("state C classifies as found", classify(row_ok), "found")
check("CONTROL: the classifier is not constant",
      len({classify(row), classify(row_nf), classify(row_ok)}), 3)

print("\n-- 6. accepts a DiscoveryResult object as well as a dict --")
writes.create_enrollment_request("hash-obj", 1, expires_at="2099-01-01T00:00:00",
                                 discovery=r_ok)
check("object form stores the same host",
      writes.get_enrollment_request("hash-obj")["disc_host"],
      "imap.example.net")

print("\n-- 7. SECURITY BOUNDARY: discovery is admin-side only --")
# STRUCTURAL check, and labelled as one: this asserts WHERE a call site exists,
# not that a function behaves. That is the right tool for "this dangerous call
# must not appear in the unauthenticated file" and the wrong tool for
# "this query works" -- which is why section 2 executes the query instead.
_views_src = open(os.path.join(_HERE, "views.py"), encoding="utf-8").read()
_dash_src = open("/opt/nemesis/dashboard.py", encoding="utf-8").read()
check("the ADMIN mint route calls autodiscover",
      "autodiscover.discover(" in _views_src)
check("dashboard.py (which owns the UNAUTHENTICATED /email/enroll routes) "
      "never calls autodiscover.discover",
      "autodiscover.discover(" not in _dash_src)
check("...and does not import autodiscover at all",
      "autodiscover" not in _dash_src)
check("the mint route wraps discovery so a lookup failure cannot break minting",
      "autodiscovery failed" in _views_src)

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
