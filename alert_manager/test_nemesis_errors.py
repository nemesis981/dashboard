#!/usr/bin/env python3
"""Checks for the structured error-code system (alert_manager/nemesis_errors.py).

Run: python3 alert_manager/test_nemesis_errors.py

WHAT THIS SUITE IS WEIGHTED AGAINST
-----------------------------------
Every failure mode this design has looks like success from the outside:

  * a cause bound only to a code, never to a class, still RETURNS causes — it
    just never shares knowledge between the 51+ sites with the same mechanism.
    Nothing errors; the system merely stays expensive forever while appearing to
    learn. So the class level is tested from BOTH sides.
  * archival that writes a corrupt file and then deletes the live rows loses data
    silently. So the verify-before-modify ordering is tested by CORRUPTING the
    archive and asserting the live table survives.
  * `prune_snapshots` deleting rows instead of nulling text would orphan
    `error_occurrences.snapshot_id` and only show up much later. So the row's
    survival is asserted explicitly, not just the text's absence.

Runs entirely against a throwaway database. Never touches the live DB.
"""

import gzip
import json
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nemesis_errors as ne          # noqa: E402
import nemesis_severity              # noqa: E402

EXPECTED_CHECKS = 73

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f"  ({detail})" if (not cond and detail) else ""))
    if cond:
        passed += 1
    else:
        failed += 1
    return cond


def fresh():
    db = os.path.join(tempfile.mkdtemp(prefix="err-test-"), "t.db")
    conn = sqlite3.connect(db)
    ne.init_error_tables(conn)
    return conn, db


# ── schema ───────────────────────────────────────────────────────────────────
print("\n[schema] four tables, idempotent init")
conn, _ = fresh()
tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
for t in ("error_codes", "error_occurrences", "error_ledger_causes", "error_code_snapshots"):
    check(f"table {t} exists", t in tables)
ne.init_error_tables(conn)
check("init is idempotent (re-run does not raise)", True)
cols = {r[1] for r in conn.execute("PRAGMA table_info(error_occurrences)")}
check("occurrences carry the actor seam (NULL today, per multi-user rule)", "actor" in cols)
check("occurrences link to a snapshot", "snapshot_id" in cols)
check("occurrences link to a resolved cause", "resolved_cause_id" in cols)
check("codes carry a nullable class", "class" in {r[1] for r in conn.execute("PRAGMA table_info(error_codes)")})


# ── severity reuses the canonical ladder ─────────────────────────────────────
print("\n[severity] reuses nemesis_severity, never a second enum")
ne.register_error_code(conn, "E-T-001", "test", "d", "high")
sev = conn.execute("SELECT severity FROM error_codes WHERE code='E-T-001'").fetchone()[0]
check("severity is normalised to the canonical spelling", sev == "HIGH", sev)
check("stored severity is ON the canonical ladder", sev in nemesis_severity.CANONICAL)
for bad in ("banana", "", None, "SEV1", "urgent"):
    try:
        ne.register_error_code(conn, f"E-BAD-{bad}", "test", "d", bad)
        check(f"REJECTS off-ladder severity {bad!r}", False, "accepted it")
    except ne.ErrorSystemError:
        check(f"REJECTS off-ladder severity {bad!r}", True)
# CONTROL: a valid severity must still be accepted, or the checks above would
# pass on an implementation that rejects everything.
ne.register_error_code(conn, "E-T-002", "test", "d", "critical")
check("CONTROL a valid severity is still accepted",
      conn.execute("SELECT 1 FROM error_codes WHERE code='E-T-002'").fetchone() is not None)


# ── registration semantics ───────────────────────────────────────────────────
print("\n[register] idempotent, and a code's meaning cannot change under it")
ne.register_error_code(conn, "E-T-001", "test", "REWRITTEN", "low")
row = conn.execute("SELECT description, severity FROM error_codes WHERE code='E-T-001'").fetchone()
check("re-registration does NOT rewrite an existing code", row[0] == "d" and row[1] == "HIGH",
      str(row))
check("re-registration does not duplicate the row",
      conn.execute("SELECT COUNT(*) FROM error_codes WHERE code='E-T-001'").fetchone()[0] == 1)
for bad in ("", "   ", None):
    try:
        ne.register_error_code(conn, bad, "test", "d", "LOW")
        check(f"REJECTS empty code {bad!r}", False)
    except ne.ErrorSystemError:
        check(f"REJECTS empty code {bad!r}", True)


# ── recording ────────────────────────────────────────────────────────────────
print("\n[record] an unregistered code is refused, not silently accepted")
try:
    ne.record_error(conn, "E-NEVER-REGISTERED")
    check("REFUSES an unregistered code", False, "it was accepted")
except ne.ErrorSystemError:
    check("REFUSES an unregistered code", True)
oid = ne.record_error(conn, "E-T-001", context={"device": "abc"})
check("records a registered code", isinstance(oid, int) and oid > 0)
ctx = conn.execute("SELECT context FROM error_occurrences WHERE id=?", (oid,)).fetchone()[0]
check("dict context is serialised to JSON", json.loads(ctx)["device"] == "abc")
ts = conn.execute("SELECT ts FROM error_occurrences WHERE id=?", (oid,)).fetchone()[0]
check("ts is canonical (offset-aware, from nemesis_timestamp)",
      "T" in ts and ("+" in ts[10:] or "-" in ts[11:]), ts)
check("actor is NULL today (seam present, unwired)",
      conn.execute("SELECT actor FROM error_occurrences WHERE id=?", (oid,)).fetchone()[0] is None)


# ── the class axis — the part most likely to be mis-simplified ───────────────
print("\n[class] causes attach at exactly one level; reads span both")
conn2, _ = fresh()
ne.register_error_code(conn2, "E-A-001", "a", "site A", "MEDIUM",
                       error_class="db-read-empty-default")
ne.register_error_code(conn2, "E-B-001", "b", "site B", "LOW",
                       error_class="db-read-empty-default")
ne.add_cause(conn2, "the DB was locked", error_class="db-read-empty-default")
ne.add_cause(conn2, "this site's own quirk", code="E-A-001")

a = ne.resolve_causes(conn2, "E-A-001")
b = ne.resolve_causes(conn2, "E-B-001")
check("code-level cause is returned for its own code", any(c["level"] == "code" for c in a))
check("class-level cause is returned for that code too", any(c["level"] == "class" for c in a))
check("EXACT-CODE ranks ABOVE class-level", a[0]["level"] == ne.LEVEL_CODE,
      str([c["level"] for c in a]))
# THE POINT OF THE CLASS LEVEL: a DIFFERENT site inherits the shared cause
# without anyone re-entering it. Without this, 51+ sites each relearn it.
check("a DIFFERENT code in the same class inherits the shared cause",
      any(c["cause_description"] == "the DB was locked" for c in b))
check("  ...and does NOT inherit the other site's code-level cause",
      not any(c["cause_description"] == "this site's own quirk" for c in b))
# CONTROL: a code with NO class gets only its own causes — proves the class
# lookup is doing work rather than returning everything.
ne.register_error_code(conn2, "E-C-001", "c", "classless", "LOW")
check("CONTROL a classless code inherits nothing", ne.resolve_causes(conn2, "E-C-001") == [])
check("CONTROL an unknown code returns nothing", ne.resolve_causes(conn2, "E-NOPE") == [])

print("\n[class] exactly one of code/class — both or neither is refused")
for kwargs, label in (({}, "neither"),
                      ({"code": "E-A-001", "error_class": "db-read-empty-default"}, "both")):
    try:
        ne.add_cause(conn2, "x", **kwargs)
        check(f"REFUSES a cause with {label}", False, "accepted it")
    except ne.ErrorSystemError:
        check(f"REFUSES a cause with {label}", True)
try:
    ne.add_cause(conn2, "x", code="E-A-001", status="maybe")
    check("REFUSES an unknown status", False)
except ne.ErrorSystemError:
    check("REFUSES an unknown status", True)

# The declined class, pinned so it is not silently re-added as VOCABULARY.
# (An earlier version of this check grepped the source for the string and failed
# on the docstring that DOCUMENTS the decline — it tested the prose, not the
# code. What actually matters is that the module ships no built-in class list at
# all: classes are caller-supplied, per the design's "do not pre-populate beyond
# three classes" principle. A built-in list is the only way one could be
# silently re-added.)
_module_consts = {n for n in dir(ne) if n.isupper()}
check("module ships NO built-in class vocabulary (classes are caller-supplied)",
      not any("CLASS" in n and n not in ("LEVEL_CLASS",) for n in _module_consts),
      str(sorted(_module_consts)))
check("  ...so invisible-side-effect cannot be re-added by editing a constant",
      "invisible-side-effect" not in {getattr(ne, n) for n in _module_consts
                                      if isinstance(getattr(ne, n), str)})


# ── snapshots — source only, supersede without deleting ─────────────────────
print("\n[snapshots] superseded text is nulled; the ROW survives for the FK")
conn3, _ = fresh()
s1 = ne.capture_snapshot(conn3, "/x/y.py", "fn", 1, 9, "old source", "abc123")
ne.register_error_code(conn3, "E-S-001", "s", "d", "LOW")
occ = ne.record_error(conn3, "E-S-001", snapshot_id=s1)
s2 = ne.capture_snapshot(conn3, "/x/y.py", "fn", 1, 12, "new source", "def456")
old = conn3.execute("SELECT id, source_text, git_commit_hash FROM error_code_snapshots "
                    "WHERE id=?", (s1,)).fetchone()
check("superseded ROW still exists (FK stays resolvable)", old is not None)
check("superseded source_text is NULLed", old[1] is None)
check("superseded git_commit_hash SURVIVES (which commit was investigated)",
      old[2] == "abc123")
check("the occurrence's snapshot_id still resolves",
      conn3.execute("SELECT COUNT(*) FROM error_code_snapshots WHERE id=("
                    "SELECT snapshot_id FROM error_occurrences WHERE id=?)",
                    (occ,)).fetchone()[0] == 1)
check("CONTROL the NEW snapshot keeps its text",
      conn3.execute("SELECT source_text FROM error_code_snapshots WHERE id=?",
                    (s2,)).fetchone()[0] == "new source")
# A different (file, function) pair must be untouched by the supersede.
s3 = ne.capture_snapshot(conn3, "/x/other.py", "fn", 1, 3, "other source")
ne.capture_snapshot(conn3, "/x/y.py", "fn", 1, 12, "newest")
check("CONTROL a DIFFERENT file/function pair is not pruned",
      conn3.execute("SELECT source_text FROM error_code_snapshots WHERE id=?",
                    (s3,)).fetchone()[0] == "other source")


# ── archival — ordering is the correctness property ─────────────────────────
print("\n[archival] write -> verify -> ONLY THEN modify")
conn4, _ = fresh()
arch = tempfile.mkdtemp(prefix="err-arch-")
ne.register_error_code(conn4, "E-R-001", "r", "d", "LOW")
old_ts = "2020-01-01T00:00:00-05:00"
for i in range(5):
    conn4.execute("INSERT INTO error_occurrences (code, ts, context, actor) "
                  "VALUES ('E-R-001', ?, ?, NULL)", (old_ts, f"ctx{i}"))
conn4.execute("INSERT INTO error_occurrences (code, ts, context, actor) "
              "VALUES ('E-R-001', ?, 'human', 'someone')", (old_ts,))
recent = ne.record_error(conn4, "E-R-001", context="recent")
conn4.commit()

res = ne.archive_and_coalesce_occurrences(conn4, arch, dry_run=True)
check("dry run reports what it WOULD archive", res["archived"] == 5, str(res))
check("dry run changes nothing",
      conn4.execute("SELECT COUNT(*) FROM error_occurrences").fetchone()[0] == 7)

res = ne.archive_and_coalesce_occurrences(conn4, arch)
check("archived the aged, unattributed rows", res["archived"] == 5, str(res))
check("coalesced into (code, hour) buckets", res["coalesced"] == 1, str(res))
check("archive file exists", os.path.exists(res["archive_ref"]))
with gzip.open(res["archive_ref"], "rt") as fh:
    lines = [json.loads(l) for l in fh if l.strip()]
check("archive holds every archived row", len(lines) == 5, str(len(lines)))
check("HUMAN-ATTRIBUTED row was NOT archived, at any age",
      conn4.execute("SELECT COUNT(*) FROM error_occurrences WHERE actor IS NOT NULL"
                    ).fetchone()[0] == 1)
check("recent row untouched",
      conn4.execute("SELECT COUNT(*) FROM error_occurrences WHERE id=?",
                    (recent,)).fetchone()[0] == 1)
summary = conn4.execute("SELECT context FROM error_occurrences WHERE context LIKE "
                        "'%coalesced%'").fetchone()
check("summary row carries the archive_ref (nothing is unrecoverable)",
      summary and json.loads(summary[0])["archive_ref"] == res["archive_ref"])

# THE ORDERING TEST: corrupt the archive and assert the live table survives.
conn5, _ = fresh()
ne.register_error_code(conn5, "E-R-002", "r", "d", "LOW")
for i in range(3):
    conn5.execute("INSERT INTO error_occurrences (code, ts, context, actor) "
                  "VALUES ('E-R-002', ?, ?, NULL)", (old_ts, f"c{i}"))
conn5.commit()
before = conn5.execute("SELECT COUNT(*) FROM error_occurrences").fetchone()[0]
_real_open = gzip.open
def _truncating_open(path, mode="rb", *a, **k):
    """Simulate a truncated/partial archive on the READ-BACK only."""
    fh = _real_open(path, mode, *a, **k)
    if "r" in mode:
        class _Short:
            def __enter__(self): return iter([])          # reads back as empty
            def __exit__(self, *e): fh.close(); return False
        return _Short()
    return fh
gzip.open = _truncating_open
try:
    ne.archive_and_coalesce_occurrences(conn5, arch)
    check("CORRUPT archive raises rather than proceeding", False, "it proceeded")
except ne.ErrorSystemError:
    check("CORRUPT archive raises rather than proceeding", True)
finally:
    gzip.open = _real_open
check("LIVE TABLE SURVIVES a failed archive verify",
      conn5.execute("SELECT COUNT(*) FROM error_occurrences").fetchone()[0] == before,
      f"was {before}")

res = ne.archive_and_coalesce_occurrences(conn4, arch)
check("archival with nothing to do is a clean no-op", res["archived"] == 0, str(res))


# ── make_recorder() — the shared retrofit helper ─────────────────────────────
# Weighted against the ways a never-raising helper fails INVISIBLY: it swallows
# everything by contract, so "it didn't raise" proves nothing at all. Every check
# below asserts on OBSERVABLE STATE (rows written, factory call counts) rather
# than on the absence of an exception.
print("\n--- make_recorder ---")

rec_db = os.path.join(tempfile.mkdtemp(prefix="err-rec-"), "recorder.db")
_opened = {"n": 0}


def _rec_conn():
    _opened["n"] += 1
    return sqlite3.connect(rec_db)


CODES = {"E-TEST-001": ("first probe code", "MEDIUM", "db-read-empty-default"),
         "E-TEST-002": ("second probe code", "LOW", None)}


class _CapturingLog:
    def __init__(self):
        self.msgs = []

    def warning(self, msg, *a):
        self.msgs.append(msg % a if a else msg)


lg = _CapturingLog()
rec = ne.make_recorder("probe", _rec_conn, CODES, logger=lg)

# Tables must NOT exist before first use — registration is deferred, and if it
# were happening at construction time this assertion is what would catch it.
_c = sqlite3.connect(rec_db)
_pre = _c.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
_c.close()
check("make_recorder does NOT touch the DB at construction", _pre == 0, f"{_pre} tables")

oid1 = rec("E-TEST-001", context={"probe": 1})
check("first call registers and records", isinstance(oid1, int) and oid1 > 0, repr(oid1))

_c = sqlite3.connect(rec_db)
check("both declared codes registered on first use",
      _c.execute("SELECT COUNT(*) FROM error_codes").fetchone()[0] == 2)
check("occurrence row actually written",
      _c.execute("SELECT COUNT(*) FROM error_occurrences").fetchone()[0] == 1)
check("error_class persisted for the code that declared one",
      _c.execute("SELECT class FROM error_codes WHERE code='E-TEST-001'"
                 ).fetchone()[0] == "db-read-empty-default")
_c.close()

oid2 = rec("E-TEST-002")
check("second call records without re-registering", isinstance(oid2, int) and oid2 > oid1)

# Registration must be idempotent-by-flag, not re-run per call.
_c = sqlite3.connect(rec_db)
check("still exactly 2 codes after a second record (no duplicate registration)",
      _c.execute("SELECT COUNT(*) FROM error_codes").fetchone()[0] == 2)
check("connection is opened per call and closed (factory called once per record)",
      _opened["n"] == 2, f"opened {_opened['n']}")
_c.close()

# An undeclared code must not silently write nothing with no trace.
_before = _opened["n"]
und = rec("E-NOT-DECLARED-999")
check("undeclared code returns None", und is None, repr(und))
check("undeclared code warns rather than failing silently",
      any("not declared" in m for m in lg.msgs), str(lg.msgs))
check("undeclared code does not even open a connection", _opened["n"] == _before)

# NEGATIVE CONTROL for the whole harness: if the recorder could only ever return
# None, every check above would still pass. Prove a real id came back and that
# the two ids differ, so the instrument is demonstrably able to distinguish.
check("NEGATIVE CONTROL: recorder returns distinct real ids, not a constant None",
      oid1 is not None and oid2 is not None and oid1 != oid2, f"{oid1} {oid2}")


def _broken_conn():
    raise sqlite3.OperationalError("unable to open database file")


rec_bad = ne.make_recorder("probe", _broken_conn, CODES, logger=lg)
check("unopenable DB returns None instead of raising", rec_bad("E-TEST-001") is None)
check("unopenable DB is logged", any("could not open" in m for m in lg.msgs))


# Registration that keeps failing must give up rather than retry forever on the
# already-failing path.
class _RegFailConn:
    """Opens fine, but every write fails — the 'DB is read-only' shape."""

    def execute(self, *a, **k):
        raise sqlite3.OperationalError("attempt to write a readonly database")

    def close(self):
        pass


_regfail = {"n": 0}


def _regfail_conn():
    _regfail["n"] += 1
    return _RegFailConn()


rec_ro = ne.make_recorder("probe", _regfail_conn, CODES, logger=lg)
for _ in range(6):
    rec_ro("E-TEST-001")
check("registration gives up after the cap instead of retrying every call",
      _regfail["n"] == ne._Recorder._MAX_REG_FAILURES, f"opened {_regfail['n']}")
check("giving up is logged, not silent",
      any("giving up" in m for m in lg.msgs), str(lg.msgs))


print("\n" + "=" * 62)
total = passed + failed
print(f"Total: {passed} passed, {failed} failed ({total} checks)")
if total != EXPECTED_CHECKS:
    print(f"GUARD FAILED: expected {EXPECTED_CHECKS} checks, ran {total}.")
    sys.exit(1)
print("RESULT: all checks passed" if not failed else "RESULT: FAILED")
sys.exit(0 if failed == 0 else 1)
