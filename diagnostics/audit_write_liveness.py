"""Proves an `audit_log` write COMMITS — not merely that it returned without raising.

WHY THIS EXISTS, AND WHY IT DIDN'T BEFORE 2026-09-04
    A write that THROWS was already covered: `nemesis_fwd.audit()` catches and signals
    `ERR_AUDIT_WRITE_FAILED` (NEM-FWD-0001), consumed by `degraded_ingest`. Nothing
    covered a write that SUCCEEDS AND LANDS NOWHERE — an uncommitted transaction, or a
    connection open on a different database than readers use.

    That gap only became load-bearing on 2026-09-03. Before `b2b9d56`, `audit_log` gained
    ~17,280 rows/day (98.3% of the table) from a no-op consistency sweep; after it, ~0 by
    design. **Volume was the de facto liveness signal, and removing it made a broken write
    path and a healthy quiet one look identical.** Fixing the noise created the blind spot;
    this closes it.

⛔ THE FRESH-CONNECTION READ-BACK IS THE ENTIRE POINT.
    Reading the row back on the SAME connection that wrote it succeeds even when nothing
    was committed — which is exactly the failure being probed. A same-connection round
    trip is an instrument that cannot fail. Every read-back here opens a NEW connection.

⚠ RULE 11 EXCEPTION TABLE. `audit_log`'s columns are all structured — `ts`, `request_id`,
    `ip`, `action`, `user` — with no free-text field, so the standard "test data <date>"
    label cannot be carried in-band and the `LIKE '%test data%'` sweep will never find a
    canary row. Per CLAUDE.md's documented `audit_log` exception the marker is an RFC 5737
    address (`203.0.113.0/24`, non-routable and expendable) plus the row id recorded in the
    result, which the caller records in that session's worklog.

BUDGET: one row per day. A canary that writes per invocation would re-create the noise
    problem that made this check necessary.
"""
import datetime
import os
import sqlite3

try:
    import canary as _canary_harness
except ImportError:                                              # pragma: no cover
    import diagnostics.canary as _canary_harness                 # type: ignore

#: RFC 5737 TEST-NET-3. Non-routable and expendable — the established convention for
#: marking synthetic rows in this table. NOT valid for exercising is_private-branching
#: code (Python classifies all TEST-NET blocks as private); this is a labelling use only.
CANARY_IP = "203.0.113.7"

#: Self-identifying in the one column that can carry it.
CANARY_ACTION = "diag_audit_canary"

CANARY_USER = "diagnostics"

#: ADR 0001: never a `__file__`-relative DB path. Separate processes must resolve the
#: SAME shared database, and a relative guess is how a check ends up proving a property
#: of a file nothing else reads.
DEFAULT_DB_PATH = "/var/lib/nemesis/alerts.db"

META = {
    "id": "audit_write_liveness",
    "name": "Audit Trail Write Check",
    "icon": "📝",
    "descriptions": {
        "beginner": "Checks that the security audit trail is still recording. Writes one "
                    "harmless test entry a day and confirms it is really saved.",
        "intermediate": "Writes a marked row to audit_log and reads it back on a separate "
                        "connection, proving the write committed rather than merely "
                        "returning. Catches a silently-failing write that logs nothing.",
        "pro": "Round-trips audit_log through a fresh connection. Targets the "
               "succeeds-but-does-not-commit case; throwing writes are already covered by "
               "NEM-FWD-0001. One row/day, marked with RFC 5737 per the Rule 11 "
               "audit_log exception.",
    },
}


def resolve_db_path(env=None):
    """The database the PRODUCTION writer uses, resolved the way it resolves it.

    Reads `NEMESIS_DB_PATH` (what nemesis-fwd.service sets) and falls back to the
    canonical path. Checking a different database than the real writer would make every
    result here a property of the wrong file.
    """
    env = os.environ if env is None else env
    return (env.get("NEMESIS_DB_PATH") or "").strip() or DEFAULT_DB_PATH


def _today(now=None):
    return (now or datetime.datetime.now()).strftime("%Y-%m-%d")


def _fail(detail, db_path=None):
    return {"ok": False, "detail": detail, "row_id": None, "db_path": db_path,
            "reused": False}


def probe(db_path=None, now=None, _commit=True):
    """Write (or reuse today's) canary row and prove it is readable independently.

    Returns {"ok", "detail", "row_id", "db_path", "reused"}. Never raises: a diagnostic
    that throws takes down the page it was meant to inform.

    `_commit=False` is NOT a test-only flag — it is how the known-bad canary case is
    produced. `canary.run_cases` refuses a case list with no case that must fail, so this
    seam is what lets the check prove it can distinguish at all.
    """
    db_path = db_path or resolve_db_path()
    if not os.path.exists(db_path):
        return _fail("database not present at %s" % db_path, db_path)

    day = _today(now)
    try:
        conn = sqlite3.connect(db_path, timeout=5.0)
    except Exception as exc:                                     # noqa: BLE001
        return _fail("cannot open %s (%r)" % (db_path, exc), db_path)

    try:
        try:
            existing = conn.execute(
                "SELECT id FROM audit_log WHERE action=? AND ip=? AND ts LIKE ? "
                "ORDER BY id DESC LIMIT 1",
                (CANARY_ACTION, CANARY_IP, day + "%")).fetchone()
        except sqlite3.Error as exc:
            return _fail("audit_log not queryable (%r) -- table missing or unreadable"
                         % (exc,), db_path)

        if existing:
            # Budget already spent today. Still PROVE it is readable independently
            # rather than trusting this connection's view of it.
            rid = existing[0]
            if _readback(db_path, rid) is None:
                return _fail("today's canary row id=%s is not visible to a fresh "
                             "connection -- audit_log reads are not durable" % rid,
                             db_path)
            return {"ok": True, "detail": "verified today's existing canary row",
                    "row_id": rid, "db_path": db_path, "reused": True}

        ts = _now_iso(now)
        cur = conn.execute(
            "INSERT INTO audit_log(ts, request_id, ip, action, user) VALUES (?,?,?,?,?)",
            (ts, "audit-write-liveness", CANARY_IP, CANARY_ACTION, CANARY_USER))
        rid = cur.lastrowid
        if _commit:
            conn.commit()
    except Exception as exc:                                     # noqa: BLE001
        return _fail("write failed: %r" % (exc,), db_path)
    finally:
        try:
            conn.close()
        except Exception:                                        # noqa: BLE001
            pass

    # ⛔ FRESH connection. Same-connection read succeeds uncommitted.
    if _readback(db_path, rid) is None:
        return _fail("write returned success but the row is NOT readable on a fresh "
                     "connection -- it did not commit", db_path)
    return {"ok": True, "detail": "wrote and independently read back row id=%s" % rid,
            "row_id": rid, "db_path": db_path, "reused": False}


def _readback(db_path, row_id):
    """Read one row on a NEW connection. None means it is not durably there."""
    try:
        c = sqlite3.connect(db_path, timeout=5.0)
    except Exception:                                            # noqa: BLE001
        return None
    try:
        return c.execute("SELECT id FROM audit_log WHERE id=?", (row_id,)).fetchone()
    except Exception:                                            # noqa: BLE001
        return None
    finally:
        try:
            c.close()
        except Exception:                                        # noqa: BLE001
            pass


def _now_iso(now=None):
    try:
        import nemesis_timestamp
        return nemesis_timestamp.now()
    except Exception:                                            # noqa: BLE001
        return (now or datetime.datetime.now()).astimezone().isoformat()


# ── canary: the instrument must prove it can distinguish ─────────────────────
def _tmpdb(with_table=True):
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".canary.db",
                                dir=_canary_harness.scratch_dir())
    os.close(fd)
    if with_table:
        c = sqlite3.connect(path)
        c.execute("CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                  "ts TEXT, request_id TEXT, ip TEXT, action TEXT, user TEXT)")
        c.commit(); c.close()
    return path


def _case_healthy():
    p = _tmpdb()
    try:
        return None if probe(p)["ok"] else "healthy db reported as broken"
    finally:
        try: os.unlink(p)
        except OSError: pass


def _case_uncommitted():
    p = _tmpdb()
    try:
        return None if probe(p, _commit=False)["ok"] else "uncommitted write detected"
    finally:
        try: os.unlink(p)
        except OSError: pass


CASES = [
    _canary_harness.good("a committed write reports nothing", _case_healthy),
    _canary_harness.bad("an UNCOMMITTED write IS reported", _case_uncommitted),
]


def _canary():
    return _canary_harness.run_cases(CASES)


def _produce(detail):
    r = probe()
    if r["ok"]:
        return {
            "status": "ok",
            "summary": "Audit trail is recording (row id=%s%s)." % (
                r["row_id"], ", reused today's" if r["reused"] else ""),
            "sections": [{"title": "Audit write round-trip",
                          "body": "%s\nDatabase: %s" % (r["detail"], r["db_path"])}],
        }
    return {
        "status": "error",
        "summary": "Audit trail write could not be verified: %s" % r["detail"],
        "sections": [{"title": "Audit write round-trip",
                      "body": "%s\nDatabase: %s" % (r["detail"], r["db_path"])}],
    }


def run() -> dict:
    return _canary_harness.guard(META, _canary, _produce, subject="the audit trail")
