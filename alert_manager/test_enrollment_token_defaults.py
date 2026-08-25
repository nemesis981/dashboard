#!/usr/bin/env python3
"""enrollment_tokens: auto-approve must FAIL CLOSED when nobody says otherwise.

Auto-approve is opt-in by ADR 0012, and the live path honours that — dashboard.py
computes 0 unless an explicit truthy flag arrives from the form. The column DEFAULT was
still 1 until 2026-08-25, so the schema and the policy disagreed. Nothing exploited it,
because the single writer always supplies the value; the defect was that the fallback on
a security decision pointed the wrong way, and would have granted auto-approval to every
device using a token created by any future INSERT that merely omitted the column.

Two things are pinned here, and the second matters more than the first:
  1. the DDL default is 0 — checked by EXECUTING the shipped CREATE, not by reading it;
  2. the one live writer still names the column explicitly — because if that ever stops
     being true, the default becomes load-bearing on an existing install, where it is
     STILL 1 (SQLite cannot ALTER a column default, so the fix reaches new installs only).

Run: python3 alert_manager/test_enrollment_token_defaults.py
"""
import io
import os
import re
import sqlite3
import sys

ROOT = os.environ.get("NEMESIS_ROOT", "/opt/nemesis")

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


src = io.open(os.path.join(ROOT, "alert_manager", "database.py"), encoding="utf-8").read()
m = re.search(r"CREATE TABLE IF NOT EXISTS enrollment_tokens.*?\)\s*\"\"\"", src, re.S)

print("== THE SHIPPED DDL, EXECUTED (not pattern-matched) ==")
check("the enrollment_tokens CREATE was found in database.py", m is not None)
ddl = m.group(0).rstrip('"').rstrip() if m else ""
conn = sqlite3.connect(":memory:")
try:
    conn.execute(ddl)
    ok = True
except Exception as exc:                                          # noqa: BLE001
    ok = False
    print("      DDL failed to execute: %r" % (exc,))
check("it executes as real SQL", ok)

cols = {r[1]: r[4] for r in conn.execute("PRAGMA table_info(enrollment_tokens)")}
check("auto_approve exists", "auto_approve" in cols)
check("...and its DEFAULT is 0, not 1", str(cols.get("auto_approve")) == "0",
      repr(cols.get("auto_approve")))

print("\n== AN INSERT THAT OMITS THE COLUMN MUST NOT GRANT AUTO-APPROVAL ==")
conn.execute("INSERT INTO enrollment_tokens (token, created_by, created_at, expires_at) "
             "VALUES (?,?,?,?)", ("tok", "someone", 1.0, 2.0))
got = list(conn.execute("SELECT auto_approve FROM enrollment_tokens"))[0][0]
check("an omitting INSERT yields 0 (manual approval required)", got == 0, repr(got))
# Control: the column is genuinely settable, so the 0 above is the DEFAULT doing its job
# rather than the column being incapable of holding 1.
conn.execute("INSERT INTO enrollment_tokens (token, created_by, created_at, expires_at, "
             "auto_approve) VALUES (?,?,?,?,1)", ("tok2", "someone", 1.0, 2.0))
got2 = [r[0] for r in conn.execute("SELECT auto_approve FROM enrollment_tokens ORDER BY id")]
check("CONTROL: an explicit 1 is still stored (so the default is what produced the 0)",
      got2 == [0, 1], repr(got2))

print("\n== THE LIVE WRITER STILL NAMES THE COLUMN EXPLICITLY ==")
dash = io.open(os.path.join(ROOT, "dashboard.py"), encoding="utf-8").read()
inserts = re.findall(r"INSERT INTO enrollment_tokens(.{0,400})", dash, re.S)
check("exactly one INSERT INTO enrollment_tokens exists", len(inserts) == 1, str(len(inserts)))
check("...and it names auto_approve in its column list",
      bool(inserts) and "auto_approve" in inserts[0],
      (inserts[0][:120] if inserts else ""))

print("\n== WHY THIS IS PINNED: existing installs still carry DEFAULT 1 ==")
# Not a hypothetical. Prove SQLite cannot retrofit the default, so the comment in
# database.py is describing a real constraint rather than an assumption.
c2 = sqlite3.connect(":memory:")
c2.execute("CREATE TABLE t (a INTEGER DEFAULT 1)")
try:
    c2.execute("ALTER TABLE t ALTER COLUMN a SET DEFAULT 0")
    altered = True
except Exception:                                                 # noqa: BLE001
    altered = False
check("SQLite genuinely cannot ALTER a column default", not altered)
check("  ...so the fix reaches NEW installs only, as the DDL comment states",
      "NEW INSTALLS ONLY" in src)

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)
