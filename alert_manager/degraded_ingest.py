#!/usr/bin/env python3
"""Ingest the degraded journal into `audit_log` — the half ADR 0019 designed but
never built.

WHY THIS EXISTS
---------------
`nemesis_fw_watch._audit_row()` is a deliberate no-op, and its docstring explains
why: an earlier version opened `alerts.db` as root-with-CAP_NET_ADMIN-and-nothing-
else, which created root-owned WAL sidecars and LOCKED THE DASHBOARD OUT OF ITS
OWN DATABASE (measured on the VM 2026-08-01, not theorised). A privileged
component has no business holding a handle to the unprivileged dashboard's
database.

That docstring then says the audit requirement is not dropped, it MOVES: "The
dashboard ingests degraded.jsonl and writes the row itself, as the user that owns
the database." **That move was never built.** Audited 2026-08-05: `degraded.jsonl`
had two writers (`nemesis_fwd`, `nemesis_fw_watch`) and zero readers, so a real
`NEM-FWW-0001 modified outside Nemesis` event from 2026-08-01 reached the journal
and an email but never the audit trail. This module is the missing reader.

WHAT IT IS NOT
--------------
Not a module (`modules/<name>/`). It writes `audit_log`, an unprefixed CORE table
that `dashboard` already holds a documented shared-writer grant on; a module would
own tables by prefix and could not write it without a new grant that would be
wrong on its face. It lives beside `firewall.py` / `fw_client.py` /
`nemesis_fw_watch.py` for the same reason those do.

IDEMPOTENCY IS THE LOAD-BEARING PROPERTY
----------------------------------------
Every insert is guarded by a duplicate check on the natural key
(ts, action, request_id, ip). That is what makes the stored offset an
OPTIMISATION rather than a correctness dependency: a lost, stale, or unreadable
offset costs a re-scan, never a duplicated audit row and never a skipped event.
Given the choice between silently losing a security event and writing it twice,
this module is built so that neither is the outcome.

FAILURE SEMANTICS
-----------------
Standing practice in this repo: a failed read must surface as an explicit failure
state, never as a default value that happens to be a legal answer. So:
  * an unreadable journal RAISES — it never reports "0 events ingested", which is
    exactly what a healthy quiet system also reports.
  * an unreadable offset RAISES — it never falls back to 0, which would look like
    a legitimate first run.
  * `database.get_setting()` is deliberately NOT used for the offset. It swallows
    every exception and returns the default, which is correct for a config knob
    whose consumers clamp it, and wrong for state where "missing" and "unreadable"
    must be told apart.
"""
import json
import logging
import os
import sqlite3
from datetime import datetime

import nemesis_timestamp  # canonical audit_log.ts — see canonical_ts() below

log = logging.getLogger("nemesis.degraded_ingest")

DEGRADED_LOG = os.environ.get("NEMESIS_DEGRADED_LOG",
                              "/var/lib/nemesis/degraded.jsonl")

#: Offset key in the core `settings` table. Deliberately NOT added to
#: CORE_SETTING_DEFAULTS: that map drives the settings UI and validation, and this
#: is internal state, not a knob anyone should be offered.
OFFSET_KEY = "degraded_ingest_offset"

#: The watcher's tamper code, mirrored from nemesis_fw_watch.ERR_TAMPERED. Kept as
#: a literal rather than imported: importing that module pulls in its netlink
#: machinery and its module-level paths, which a dashboard-side reader has no
#: business loading just to compare a string.
ERR_TAMPERED = "NEM-FWW-0001"

#: The helper's lost-audit-record code (nemesis_fwd.ERR_AUDIT_WRITE_FAILED).
ERR_AUDIT_WRITE_FAILED = "NEM-FWD-0001"


class IngestError(Exception):
    """A step could not be completed. Never raised for 'nothing new to do'."""


def read_offset(conn):
    """Stored byte offset, or 0 if none has ever been written.

    Raises IngestError if the table cannot be read at all. The distinction
    matters: 'no offset yet' is a normal first run, 'cannot read' is not, and
    collapsing them would silently re-ingest the whole journal.
    """
    try:
        row = conn.execute("SELECT value FROM settings WHERE key=?",
                           (OFFSET_KEY,)).fetchone()
    except Exception as exc:
        raise IngestError("could not read the ingest offset: %s" % exc) from exc
    if not row or row[0] is None:
        return 0
    try:
        return max(0, int(row[0]))
    except (TypeError, ValueError):
        # A corrupt stored value is not a reason to re-ingest from zero silently.
        raise IngestError("stored ingest offset is not an integer: %r" % (row[0],))


def write_offset(conn, offset):
    """Persist the offset. Best-effort BY DESIGN — see the idempotency note in the
    module docstring. Failure is logged, not raised: the rows are already written
    and correct, and the duplicate guard makes a re-scan harmless.

    THE TIMESTAMP IS LOCAL, AND THAT IS LOAD-BEARING, NOT COSMETIC.
    This wrote `datetime('now')` until 2026-08-05 — SQLite's UTC — while every
    other timestamp in this database is local (`audit_log.ts`, `alerts.last_seen`,
    `database.set_setting`). Measured: the stored stamp read 19:03:56 while the
    machine clock said 14:04:50, a five-hour skew on a row that had just been
    written.

    Nothing broke, because nothing read it yet. The moment something did — the
    ADR 0019 status panel, which derives sweep health from exactly this column —
    it would have compared a UTC stamp against a local `now` and reported a
    sweep running every 60 seconds as FIVE HOURS STALE. Permanently degraded, on
    a healthy system: a health indicator that can only ever return one answer,
    which is the failure class this panel exists to detect.

    Stamped in Python rather than SQL so it matches `datetime.now().isoformat()`
    used elsewhere, instead of relying on SQLite's `'localtime'` modifier, which
    silently depends on the server process's TZ.
    """
    try:
        conn.execute(
            "INSERT INTO settings (key, value, updated_at, updated_by) "
            "VALUES (?,?,?,?) ON CONFLICT(key) DO UPDATE SET "
            "value=excluded.value, updated_at=excluded.updated_at, "
            "updated_by=excluded.updated_by",
            (OFFSET_KEY, str(int(offset)),
             datetime.now().isoformat(timespec="seconds"), "degraded_ingest"))
        conn.commit()
        return True
    except Exception:
        log.warning("degraded_ingest: could not persist offset %d — the next run "
                    "will re-scan, which the duplicate guard makes safe", offset)
        return False


def map_record(rec):
    """Map one degraded record to audit_log columns, or None if unmappable.

    Two shapes, because the two writers mean different things:

    NEM-FWD-0001 — a privileged firewall action SUCCEEDED but its audit write was
    lost. The context carries everything the original row would have held, so this
    RECONSTRUCTS that row rather than recording "an audit write failed". Recovering
    the lost record is the entire point; a row saying the record was lost would be
    a worse version of the file we already have.

    NEM-FWW-* — a watcher alert about the enforcement table. Reproduces exactly the
    action/detail pair the no-op `_audit_row()` would have written, so the audit
    trail reads as originally designed rather than as an artefact of this module.
    """
    if not isinstance(rec, dict):
        return None
    code = rec.get("code") or ""
    ts = rec.get("ts") or ""
    if not ts:
        return None
    ctx = rec.get("context") or {}
    if not isinstance(ctx, dict):
        ctx = {}
    message = rec.get("message") or ""

    if code == ERR_AUDIT_WRITE_FAILED:
        action = ctx.get("audit_action")
        if not action:
            return None          # cannot reconstruct without the original action
        return {"ts": ts, "action": action, "ip": ctx.get("target_ip"),
                "user": ctx.get("actor"), "request_id": ctx.get("request_id")}

    if code.startswith("NEM-FWW"):
        return {"ts": ts,
                "action": "fw_table_tampered" if code == ERR_TAMPERED
                          else "fw_enforcement_alert",
                "ip": None,
                "user": "nemesis-fw-watch",
                "request_id": ("%s %s" % (code, message)).strip()}

    return None


def canonical_ts(row_ts):
    """The journal's timestamp in canonical form, or VERBATIM if unparseable.

    The journal records an event's ORIGINAL time, which is why this path stamps
    the record's own timestamp rather than `now()` like the other three audit_log
    writers — an ingested row is a historical reconstruction, not a new event.
    Canonicalising it only changes the FORMAT (separator + explicit offset), never
    the instant: `nemesis_timestamp.normalize` reads a naive value as local and
    attaches the offset that applied on that date.

    Unparseable input is kept EXACTLY as it arrived (`default=row_ts`) rather than
    dropped or replaced. A timestamp we cannot read is still evidence; substituting
    a parseable-looking one would be the failure this repo keeps cataloguing — a
    legal-looking value standing in for a real measurement.
    """
    return nemesis_timestamp.normalize(row_ts, default=row_ts)


def _already_present(conn, row):
    """Duplicate check on the natural key. IFNULL so NULL columns compare equal —
    `NULL = NULL` is NULL in SQL, so a plain `=` would never match a row with a
    NULL ip and every re-scan would duplicate watcher events.

    MATCHES BOTH THE RAW AND THE CANONICAL ts, and that is load-bearing. Rows
    ingested before 2026-08-06 carry the journal's raw timestamp; rows ingested
    after carry the canonical form of the same instant. Comparing only the
    canonical form would fail to recognise a pre-existing row and re-insert every
    historical event the day the offset is ever reset — idempotency was PROVEN in
    production against the raw form, and this keeps that guarantee across the
    format change instead of quietly narrowing it.
    """
    raw = row["ts"]
    canon = canonical_ts(raw)
    cur = conn.execute(
        "SELECT 1 FROM audit_log WHERE ts IN (?, ?) AND action=? "
        "AND IFNULL(request_id,'')=IFNULL(?,'') AND IFNULL(ip,'')=IFNULL(?,'') "
        "LIMIT 1",
        (raw, canon, row["action"], row["request_id"], row["ip"]))
    return cur.fetchone() is not None


def ingest_once(conn_factory, path=None, offset_conn_factory=None):
    """Read new records from the degraded journal into audit_log.

    `conn_factory` is a zero-arg callable returning a DB connection — injected so
    tests run against a throwaway database rather than reaching into the live one.
    It must be the DATA-MANAGER-GUARDED connection: `audit_log` is a real
    namespaced table that `dashboard` holds a documented shared-writer grant on,
    and the write belongs under the guard.

    `offset_conn_factory` is a SEPARATE, RAW connection, and the separation is
    deliberate rather than an accident of plumbing. `settings` is granted to no
    namespace at all — core writes it on plain connections from `database.py`
    (`init_settings_table`, `get_setting`, `set_setting`), which is the
    established pattern for an unprefixed core table with no module owner.
    Pushing the offset write through the guard instead produces a permanent
    ungranted-write warning on every run and a hard failure the day dashboard's
    namespace moves to enforce — the exact defect shape `scan_tasks` had (found
    and fixed 2026-08-05, and not worth re-creating the same day). Measured, not
    assumed: routed through the guard, the offset write was DENIED under enforce
    and the ingest fell back to re-scanning the whole journal every run.

    Defaults to `conn_factory` so a test can pass one raw factory for both.

    Returns a dict: ingested / duplicate / malformed / unmappable / offset /
    rescanned. Never a bare count: a caller must be able to tell "nothing new"
    from "everything was already there" from "the file was garbage".
    """
    path = path or DEGRADED_LOG
    offset_conn_factory = offset_conn_factory or conn_factory

    if not os.path.exists(path):
        # A journal that has never been written is a legitimate state — the
        # writers create it on first degraded event, not at boot.
        return {"ingested": 0, "duplicate": 0, "malformed": 0, "unmappable": 0,
                "offset": 0, "rescanned": False, "absent": True}

    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise IngestError("could not stat the degraded journal: %s" % exc) from exc

    # Both opened INSIDE the try. Opening either one outside it leaks that
    # connection if the other factory raises — the finally below never runs for a
    # failure that happens before the try is entered.
    conn = off_conn = None
    try:
        off_conn = offset_conn_factory()
        conn = conn_factory()
        offset = read_offset(off_conn)

        rescanned = False
        if offset > size:
            # Truncated or rotated under us. Re-scan from the start rather than
            # trusting an offset into a file that no longer has that shape. Safe
            # only because of the duplicate guard — say so out loud, because a
            # silent reset would be indistinguishable from normal operation.
            log.warning("degraded_ingest: journal shrank (offset=%d size=%d) — "
                        "re-scanning from the start; the duplicate guard makes "
                        "this safe", offset, size)
            offset, rescanned = 0, True

        try:
            with open(path, "rb") as fh:
                fh.seek(offset)
                data = fh.read()
        except OSError as exc:
            raise IngestError("could not read the degraded journal: %s" % exc) from exc

        # Only consume COMPLETE lines. A writer appending concurrently can leave a
        # partial record at EOF; consuming it would both corrupt this run and
        # advance the offset past a record that was never whole.
        consumed = data.rfind(b"\n") + 1
        block = data[:consumed]

        counts = {"ingested": 0, "duplicate": 0, "malformed": 0, "unmappable": 0}
        for raw in block.splitlines():
            if not raw.strip():
                continue
            try:
                rec = json.loads(raw.decode("utf-8", "replace"))
            except ValueError:
                counts["malformed"] += 1
                log.warning("degraded_ingest: skipping malformed line: %.120r", raw)
                continue
            row = map_record(rec)
            if row is None:
                counts["unmappable"] += 1
                log.warning("degraded_ingest: no audit mapping for record: %.160r",
                            rec)
                continue
            if _already_present(conn, row):
                counts["duplicate"] += 1
                continue
            conn.execute(
                "INSERT INTO audit_log(ts, request_id, ip, action, user) "
                "VALUES (?,?,?,?,?)",
                (canonical_ts(row["ts"]), row["request_id"], row["ip"],
                 row["action"], row["user"]))
            counts["ingested"] += 1

        conn.commit()
        new_offset = offset + consumed
        write_offset(off_conn, new_offset)

        if counts["ingested"] or counts["malformed"] or counts["unmappable"]:
            log.info("degraded_ingest: ingested=%d duplicate=%d malformed=%d "
                     "unmappable=%d offset=%d", counts["ingested"],
                     counts["duplicate"], counts["malformed"],
                     counts["unmappable"], new_offset)

        counts.update({"offset": new_offset, "rescanned": rescanned,
                       "absent": False})
        return counts
    finally:
        for c in (conn, off_conn):
            if c is None:
                continue
            try:
                c.close()
            except Exception:
                pass
