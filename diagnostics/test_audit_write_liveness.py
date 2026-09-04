#!/usr/bin/env python3
"""audit_write_liveness — proves an audit_log write COMMITS, not merely returns.

The gap this closes is narrow and worth stating precisely. A write that THROWS is
already covered: nemesis_fwd.audit() catches and raises ERR_AUDIT_WRITE_FAILED
(NEM-FWD-0001) with a degraded_ingest consumer. What nothing covered is a write that
SUCCEEDS AND LANDS NOWHERE — an uncommitted transaction, or a connection open on a
different database than the one readers use.

That gap became load-bearing on 2026-09-03. Before b2b9d56, audit_log gained ~17,280
rows/day; after it, ~0 by design. Volume was the de facto liveness signal, and removing
it means a broken write path and a healthy quiet one now look identical.

⛔ THE FRESH-CONNECTION READ IS THE WHOLE TEST. Reading back on the SAME connection that
wrote succeeds for an uncommitted transaction, which is precisely the failure being
probed. A same-connection round-trip is an instrument that cannot fail.

Run: python3 diagnostics/test_audit_write_liveness.py
"""
import os
import sqlite3
import sys
import tempfile

ROOT = os.environ.get("NEMESIS_ROOT", "/opt/nemesis")
sys.path.insert(0, os.path.join(ROOT, "diagnostics"))
sys.path.insert(0, os.path.join(ROOT, "alert_manager"))

import audit_write_liveness as A                                   # noqa: E402
import canary as C                                                 # noqa: E402

EXPECTED_CHECKS = 29
_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


def _mkdb(with_table=True):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    if with_table:
        c = sqlite3.connect(path)
        c.execute("CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                  "ts TEXT, request_id TEXT, ip TEXT, action TEXT, user TEXT)")
        c.commit(); c.close()
    return path


print("\n1. the round trip, on a real database")
db = _mkdb()
r = A.probe(db)
check("probe reports ok on a healthy db", r["ok"] is True, repr(r))
check("  ...and returns the row id it wrote (Rule 11 marker for the worklog)",
      isinstance(r.get("row_id"), int) and r["row_id"] > 0, repr(r))
check("  ...and names the db it actually wrote to", r.get("db_path") == db, repr(r))

con = sqlite3.connect(db); con.row_factory = sqlite3.Row
row = con.execute("SELECT * FROM audit_log WHERE id=?", (r["row_id"],)).fetchone()
check("the row is visible to an INDEPENDENT reader", row is not None)
check("  ...marked with an RFC 5737 address, not a real one",
      row is not None and row["ip"].startswith("203.0.113."), repr(row and row["ip"]))
check("  ...RFC 5737 is used because audit_log has NO free-text column (Rule 11 exception)",
      "ip" in row.keys() and not any(
          k in row.keys() for k in ("notes", "description", "message")))
check("  ...action is self-identifying", "canary" in (row["action"] or "").lower(),
      repr(row and row["action"]))
con.close()

print("\n2. ⛔ the failure it exists to catch: write succeeds, does not commit")
db2 = _mkdb()
r2 = A.probe(db2, _commit=False)
check("a NON-COMMITTED write is reported as a FAILURE", r2["ok"] is False, repr(r2))
check("  ...with a reason naming the read-back, not a generic error",
      "read" in (r2.get("detail") or "").lower()
      or "commit" in (r2.get("detail") or "").lower(), repr(r2))
con = sqlite3.connect(db2)
n = con.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
con.close()
check("  ...and the row genuinely is not there (the premise of the test)", n == 0, str(n))

print("\n3. failure modes are reported, never silently 'ok'")
missing = A.probe(os.path.join(tempfile.gettempdir(), "definitely-absent-xyz.db"))
check("an absent/unwritable db is NOT ok", missing["ok"] is False, repr(missing))
notable = _mkdb(with_table=False)
r3 = A.probe(notable)
check("a db with no audit_log table is NOT ok", r3["ok"] is False, repr(r3))
check("  ...and says so specifically", "audit_log" in (r3.get("detail") or ""), repr(r3))

print("\n4. one row per day, not one per invocation")
db4 = _mkdb()
first = A.probe(db4)
second = A.probe(db4)
con = sqlite3.connect(db4)
total = con.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
con.close()
check("two probes on the same day write ONE row", total == 1, str(total))
check("  ...and the second still reports ok (verifies the existing row)",
      second["ok"] is True, repr(second))
check("  ...reusing the same row id", second["row_id"] == first["row_id"],
      "%r vs %r" % (first.get("row_id"), second.get("row_id")))
check("  ...and says it reused rather than wrote", second.get("reused") is True, repr(second))

print("\n5. the canary harness contract")
cases = A.CASES
kinds = {k for _l, k, _t in cases}
check("the case list has a known-BAD case", C.BAD in kinds, repr(kinds))
check("  ...and a known-GOOD case", C.GOOD in kinds, repr(kinds))
# run_cases returns (ok, detail) -- the house convention, same as
# test_clock_and_timestamp_sanity.py:58. Asserting `not res` on a tuple is always
# false and would have "failed" a healthy canary.
ok, detail = A._canary()
check("the canary passes against real behaviour", ok is True, repr(detail))

print("\n6. run() shape, and that it fails closed")
# ⛔ run() -> _produce() -> probe() with NO path, which resolves to the PRODUCTION
# database. On 2026-09-04 this test wrote three canary rows into live alerts.db
# (ids 32719-32721) before that was noticed -- one of them carrying 10.0.0.7 from a
# mutation run, which is not even the RFC 5737 marker. A test must never resolve a
# real path by default. Pinned to a temp db for the duration of this section.
_dbrun = _mkdb()
_saved_resolve = A.resolve_db_path
A.resolve_db_path = lambda env=None: _dbrun
try:
    out = A.run()
finally:
    A.resolve_db_path = _saved_resolve
    try: os.unlink(_dbrun)
    except OSError: pass
check("run() returns a dict", isinstance(out, dict))
check("  ...with a legal diagnostics status",
      out.get("status") in C.LEGAL_STATUS, repr(out.get("status")))
check("  ...and an id matching META", A.META["id"] == "audit_write_liveness")
check("META carries all three explanation tiers",
      set(A.META["descriptions"]) >= {"beginner", "intermediate", "pro"},
      repr(list(A.META.get("descriptions", {}))))

print("\n7. it targets the SAME db the production writer uses")
check("DB_PATH resolves from NEMESIS_DB_PATH when set",
      A.resolve_db_path({"NEMESIS_DB_PATH": "/tmp/x.db"}) == "/tmp/x.db")
check("  ...and falls back to the canonical /var/lib path, never a __file__-relative guess",
      A.resolve_db_path({}) == "/var/lib/nemesis/alerts.db")

print("\n8. it is REGISTERED -- built-and-tested is not the same as wired")
# This module was committed complete, with 26 passing checks, and sat unregistered:
# absent from diagnostics/__init__.py, so nothing ever ran it. Every check above
# passed the whole time. The sweep below is what closes that class of gap -- it asks
# the package, not this module, so a FUTURE diagnostic cannot ship unwired either.
#
# It imports and inspects real objects rather than grepping source: a text search for
# "META" would match this very comment, and the prose documenting a pattern is exactly
# what makes a text-search check pass falsely.
import importlib
import pkgutil

# ROOT itself (not just ROOT/diagnostics) must be importable to reach the PACKAGE.
# Deliberately not relying on cwd: run from /opt/nemesis the import would be rescued
# silently, and the check would pass for a reason that does not hold under systemd.
sys.path.insert(0, ROOT)
import diagnostics as _pkg

_registered = {m.META["id"] for m in _pkg.CHECKS}
check("this check is registered in CHECKS", "audit_write_liveness" in _registered,
      "registered: %s" % (sorted(_registered),))   # str: check() concatenates detail
# NOT an `is A` identity test: this file imports the module top-level while the package
# imports it as diagnostics.audit_write_liveness, so they are two distinct objects loaded
# from ONE source file. Identity would compare import paths and fail on working code.
_mapped = _pkg._CHECK_MAP.get("audit_write_liveness")
check("  ...and run_check() resolves it to the same source file",
      _mapped is not None
      and os.path.realpath(getattr(_mapped, "__file__", "")) ==
          os.path.realpath(getattr(A, "__file__", "")),
      "mapped=%r" % (getattr(_mapped, "__file__", None),))

_unwired = []
for _mi in pkgutil.iter_modules([os.path.join(ROOT, "diagnostics")]):
    if _mi.name.startswith("test_") or _mi.name in ("canary", "redact"):
        continue
    try:
        _m = importlib.import_module("diagnostics.%s" % _mi.name)
    except Exception:                                              # noqa: BLE001
        continue
    _meta = getattr(_m, "META", None)
    if isinstance(_meta, dict) and _meta.get("id") and callable(getattr(_m, "run", None)):
        if _meta["id"] not in _registered:
            _unwired.append(_meta["id"])
check("NO diagnostic defines META+run() while absent from CHECKS", not _unwired,
      "unwired: %s" % sorted(_unwired))

for p in (db, db2, db4, notable):
    try: os.unlink(p)
    except OSError: pass

print("\n%d passed, %d failed" % (_pass, _fail))
if _pass + _fail != EXPECTED_CHECKS:
    print("EXPECTED_CHECKS MISMATCH: declared %d, ran %d" % (EXPECTED_CHECKS, _pass + _fail))
    sys.exit(1)
sys.exit(1 if _fail else 0)
