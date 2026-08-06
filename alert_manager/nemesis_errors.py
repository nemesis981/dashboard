"""Structured error codes — tier-1 of the error-code system.

ONE place where a failure gets a durable identity, so that the second
investigation of a recurring failure is cheaper than the first.

WHY THIS EXISTS. Free-text log lines cannot be counted, correlated, or attached
to a confirmed cause. A structured code assigned AT THE FAILURE SITE can. The
2026-07-29 audit's recommendation was exactly that — "codes belong at the point a
check fails", not guessed later from a log string — and this module is that
recommendation made callable.

    register_error_code()  declare a code once (catalog)
    record_error()         one row per time it actually fires
    resolve_causes()       what is already known about why it fires
    capture_snapshot()     the SOURCE that was executing, never runtime state

── WHERE THIS LIVES, AND WHY IT IS CORE ─────────────────────────────────────
Core, not a module, and the storage is core-owned (ADR 0001's unprefixed-core
rule, with `error_*` reserved to core). Three reasons, in order of weight:

1. **Every module must be able to write it.** ADR 0001 is write-own/read-any, so
   module-owned storage would make every `record_error()` from another module a
   forbidden cross-module write. Core-owned with one write path is the only shape
   that does not require breaking the isolation rule in order to use it.
2. **Grants must not multiply.** Writes go through ONE core-namespaced call, so
   no per-module Data Manager grant is ever needed. The alternative — listing the
   error tables in every module's grant — is precisely the drift that left
   `scan_tasks` missing from `hw_monitor`'s namespace for five days (derived
   2026-07-28, table added 2026-08-03, nothing re-ran the derivation).
3. **Modules load AFTER core and can fail DURING load.** An error facility that
   lives in a module is unavailable at exactly the moment it is most needed.

`audit_log` is the existing precedent: a cross-cutting core table with several
writers and no single owner.

── SEVERITY REUSES THE EXISTING LADDER ──────────────────────────────────────
`error_codes.severity` stores a value from `nemesis_severity.CANONICAL`, via that
module's own `normalize()`. It does NOT define a second enum. Two canonical
severities would recreate the exact fragmentation `nemesis_severity.py` was built
to end (it retired two hand-duplicated `_sev_order` dicts).

── THE CLASS AXIS — the part most likely to be mis-simplified ────────────────
A `class` is a shared failure MECHANISM (e.g. `db-read-empty-default`), and a
cause may attach to a CODE or to a CLASS — exactly one, never both.

**Class means cause-sharing, NOT shape-similarity.** The test is: "would a cause
confirmed at one member plausibly explain another?" `db-read-empty-default` and
`detector-collapse` look nearly identical in code shape and are correctly two
classes, because "the DB was locked" never explains "clamscan is not installed".

Without the class level the design's core property silently never materialises:
51+ measured sites share one failure shape, and with causes bound to exactly one
code each site would relearn "the DB was locked" independently. It would never
look broken — it would just pay full price forever while appearing to learn.

**Severity stays per-CODE, never per-class**, so sites with the same mechanism but
very different consequences remain distinguishable.

`invisible-side-effect` was DECLINED as a class (2026-08-05): it groups by
consequence rather than cause, and its live membership eroded to ~1. Do not
re-add it without new evidence.

── THE 51 IS A FLOOR, NOT A COUNT ───────────────────────────────────────────
Provably. The AST filter that produced it required the handler's ONLY statement to
be a `return`, so `watchdog._fetch_fan_status()` — one of the pilot's own
confirmed instances, which assigns `rows = []` — is not in it. Neither are
log-then-return handlers. Quote it as "51+", never as a total.
"""

import gzip
import json
import os
import sqlite3
import time

import nemesis_severity
import nemesis_timestamp

#: Cause rows are attached at exactly one level.
LEVEL_CODE = "code"
LEVEL_CLASS = "class"

#: Cause status vocabulary. Deliberately two values: a cause is either confirmed
#: or ruled out. "Unknown" is the absence of a row, not a third state — an
#: explicit "unknown" row would be indistinguishable from an unexamined one.
STATUS_CONFIRMED = "confirmed"
STATUS_RULED_OUT = "ruled_out"
STATUSES = (STATUS_CONFIRMED, STATUS_RULED_OUT)

#: Occurrence archival cutoff. Same default as the Data Manager's op-log archival
#: (OP_LOG_ARCHIVE_DAYS = 7) — deliberately NOT a second, separately-invented
#: number. No evidence yet that error occurrences need a different window, and
#: inventing one without evidence is the ungrounded-decision shape this design's
#: own "do not pre-populate beyond three classes" principle argues against.
ARCHIVE_DAYS = 7


class ErrorSystemError(RuntimeError):
    """Raised when the error system itself cannot do its job.

    Deliberately loud. A facility whose whole purpose is making failures
    visible must not fail quietly — a swallowed exception here would mean
    failures stop being recorded and nothing says so.
    """


# ── Schema ───────────────────────────────────────────────────────────────────
# CANONICAL DDL. Per the standing rule, every table's CREATE lives in exactly one
# place; there is no second copy anywhere. Schema changes go here, guarded.
_DDL = (
    """
    CREATE TABLE IF NOT EXISTS error_codes (
        code             TEXT PRIMARY KEY,
        module           TEXT NOT NULL,
        class            TEXT,
        description      TEXT NOT NULL,
        severity         TEXT NOT NULL,
        first_defined_ts TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS error_code_snapshots (
        id               INTEGER PRIMARY KEY,
        function_name    TEXT,
        file_path        TEXT NOT NULL,
        line_start       INTEGER,
        line_end         INTEGER,
        source_text      TEXT,
        git_commit_hash  TEXT,
        captured_ts      TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS error_ledger_causes (
        id                INTEGER PRIMARY KEY,
        code              TEXT,
        class             TEXT,
        cause_description TEXT NOT NULL,
        status            TEXT NOT NULL,
        occurrence_count  INTEGER NOT NULL DEFAULT 0,
        check_ref         TEXT,
        last_confirmed_ts TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS error_occurrences (
        id                INTEGER PRIMARY KEY,
        code              TEXT NOT NULL,
        ts                TEXT NOT NULL,
        context           TEXT,
        snapshot_id       INTEGER,
        resolved_cause_id INTEGER,
        actor             TEXT,
        -- Set on rows produced BY coalescing, so they are never re-archived.
        -- Without this the summary row inherits its bucket's hour as `ts`, which
        -- is by definition older than the cutoff, so every subsequent run
        -- re-archives its own summaries recursively — burying each previous
        -- archive_ref one level deeper. Caught by the test suite, 2026-08-06.
        is_summary        INTEGER NOT NULL DEFAULT 0
    )
    """,
    # Occurrence reads are always "this code, recent first" or "this code, in
    # this window" (the archival cutoff). Without it, archival degrades to a
    # full scan on the table specifically expected to grow.
    "CREATE INDEX IF NOT EXISTS idx_error_occ_code_ts ON error_occurrences(code, ts)",
    "CREATE INDEX IF NOT EXISTS idx_error_causes_code  ON error_ledger_causes(code)",
    "CREATE INDEX IF NOT EXISTS idx_error_causes_class ON error_ledger_causes(class)",
    "CREATE INDEX IF NOT EXISTS idx_error_snap_pair    ON error_code_snapshots(file_path, function_name)",
)


def init_error_tables(conn):
    """Create the four tables and their indexes. Idempotent.

    Uses CREATE TABLE IF NOT EXISTS rather than a PRAGMA-guarded ALTER because
    these are new tables with no deployed predecessor. When a COLUMN is later
    added, that migration goes here as a guarded `PRAGMA table_info` +
    `ALTER TABLE ADD COLUMN` alongside an updated CREATE — the pattern the rest
    of this codebase already uses.
    """
    for stmt in _DDL:
        conn.execute(stmt)
    conn.commit()


# ── Writing ──────────────────────────────────────────────────────────────────

def register_error_code(conn, code, module, description, severity,
                        error_class=None):
    """Declare a code in the catalog. Idempotent on `code`.

    `severity` is normalised through `nemesis_severity` and REJECTED if it is not
    on that ladder — never silently coerced to a default. A code registered with
    a severity nobody defined would sort unpredictably against every other code,
    and a wrong severity is worse than a refused registration.
    """
    if not code or not str(code).strip():
        raise ErrorSystemError("error code must be a non-empty string")
    sev = nemesis_severity.normalize(severity)
    if sev is None:
        raise ErrorSystemError(
            f"severity {severity!r} is not on the canonical ladder "
            f"{nemesis_severity.CANONICAL} — refusing to invent a second enum")

    code = str(code).strip()
    existing = conn.execute(
        "SELECT severity, class FROM error_codes WHERE code=?", (code,)).fetchone()
    if existing:
        # Re-registration is a no-op, not an update: a code's meaning must not
        # change under occurrences already recorded against it.
        return code

    conn.execute(
        "INSERT INTO error_codes (code, module, class, description, severity, "
        "first_defined_ts) VALUES (?,?,?,?,?,?)",
        (code, module, (error_class or None), description, sev,
         nemesis_timestamp.now()))
    conn.commit()
    return code


def record_error(conn, code, context=None, snapshot_id=None, actor=None):
    """Record ONE occurrence of an already-registered code.

    Refuses an unregistered code. That refusal is the point: an occurrence with
    no catalog entry has no severity, no module and no class, so it cannot be
    ranked, routed or matched to a cause — it would be a free-text log line
    wearing a code's clothes, which is the exact thing this system replaces.

    `actor` is the multi-user attribution seam. It is NULL today, like every
    other actor column here, and is wired later through the same mechanism the
    Data Manager already stamps — see ADR 0006. The column exists now so the
    retrofit is not a schema change across every write site.
    """
    row = conn.execute("SELECT 1 FROM error_codes WHERE code=?", (code,)).fetchone()
    if not row:
        raise ErrorSystemError(
            f"error code {code!r} is not registered — call register_error_code() "
            f"at the failure site first")

    if context is not None and not isinstance(context, str):
        context = json.dumps(context, sort_keys=True, default=str)

    cur = conn.execute(
        "INSERT INTO error_occurrences (code, ts, context, snapshot_id, "
        "resolved_cause_id, actor) VALUES (?,?,?,?,NULL,?)",
        (code, nemesis_timestamp.now(), context, snapshot_id, actor))
    conn.commit()
    return cur.lastrowid


def record_error_best_effort(conn, code, context=None, snapshot_id=None,
                             actor=None, logger=None):
    """`record_error()` that NEVER raises. For use INSIDE an exception handler.

    WHY THIS EXISTS AS A SEPARATE FUNCTION, and why the plain one stays loud:

    Most of these call sites are failures of a DB read — which means the very
    database we would write the error record into may be the thing that just
    failed. If recording then raised, it would REPLACE the original exception
    with a different one, and the operator would be handed the error system's
    failure instead of the actual fault. That is strictly worse than not
    recording at all.

    So: `record_error()` stays loud, because an unregistered code is a
    programming error that should surface during development. This variant is
    for production call sites already inside `except:`, where masking the
    original failure is the greater harm.

    Returns the occurrence id, or None if it could not record. **None means
    "not recorded" — it is never confused with a real id**, and the caller is
    free to ignore it, which is the normal case.
    """
    try:
        return record_error(conn, code, context=context,
                            snapshot_id=snapshot_id, actor=actor)
    except Exception as exc:                      # noqa: BLE001 - deliberate
        # Log, never re-raise. A warning here is the honest signal that error
        # RECORDING degraded, distinct from the failure being recorded.
        if logger is not None:
            try:
                logger.warning("error-code recording failed for %s: %s", code, exc)
            except Exception:
                pass
        return None


def add_cause(conn, cause_description, code=None, error_class=None,
              status=STATUS_CONFIRMED, check_ref=None):
    """Add a ledger cause at EXACTLY ONE level — code or class, never both.

    Both-or-neither is rejected rather than resolved by precedence. A cause
    attached at both levels would be counted twice by `resolve_causes()` and
    would make the exact-code-beats-class ranking meaningless.
    """
    has_code, has_class = bool(code), bool(error_class)
    if has_code == has_class:
        raise ErrorSystemError(
            "a cause attaches to exactly one of code= or error_class= "
            f"(got code={code!r}, class={error_class!r})")
    if status not in STATUSES:
        raise ErrorSystemError(f"status must be one of {STATUSES}, got {status!r}")

    cur = conn.execute(
        "INSERT INTO error_ledger_causes (code, class, cause_description, status, "
        "occurrence_count, check_ref, last_confirmed_ts) VALUES (?,?,?,?,0,?,?)",
        (code, error_class, cause_description, status, check_ref,
         nemesis_timestamp.now() if status == STATUS_CONFIRMED else None))
    conn.commit()
    return cur.lastrowid


# ── Reading ──────────────────────────────────────────────────────────────────

def resolve_causes(conn, code):
    """Known causes for `code`, EXACT-CODE RANKED ABOVE CLASS-LEVEL.

    Queries both levels deliberately. Class-level causes are what let knowledge
    cross a site boundary — without them, 51+ sites sharing one failure shape
    would each relearn the same cause independently and the system would appear
    to work while never getting cheaper.

    Returns a list of dicts with `level` set to 'code' or 'class', code-level
    first. The caller can therefore prefer the specific over the general without
    re-deriving which is which.
    """
    row = conn.execute("SELECT class FROM error_codes WHERE code=?", (code,)).fetchone()
    if not row:
        return []
    cls = row[0]

    out = []
    for r in conn.execute(
            "SELECT id, cause_description, status, occurrence_count, check_ref, "
            "last_confirmed_ts FROM error_ledger_causes WHERE code=? "
            "ORDER BY status='confirmed' DESC, occurrence_count DESC", (code,)):
        out.append(dict(zip(("id", "cause_description", "status", "occurrence_count",
                             "check_ref", "last_confirmed_ts"), r), level=LEVEL_CODE))
    if cls:
        for r in conn.execute(
                "SELECT id, cause_description, status, occurrence_count, check_ref, "
                "last_confirmed_ts FROM error_ledger_causes WHERE class=? "
                "ORDER BY status='confirmed' DESC, occurrence_count DESC", (cls,)):
            out.append(dict(zip(("id", "cause_description", "status", "occurrence_count",
                                 "check_ref", "last_confirmed_ts"), r), level=LEVEL_CLASS))
    return out


# ── Snapshots — SOURCE ONLY ──────────────────────────────────────────────────

def capture_snapshot(conn, file_path, function_name=None, line_start=None,
                     line_end=None, source_text=None, git_commit_hash=None):
    """Store the SOURCE that was executing. Never runtime state.

    ⚠ SOURCE ONLY, and this is a security boundary rather than a style choice.
    No local-variable dump, no argument values, no in-memory object state. A
    variable dump would make this table a new leak surface on day one — it would
    capture whatever happened to be in scope at a failure, which on this codebase
    includes credentials, tokens and network identifiers. Source text is already
    in the repo and leaks nothing that `git` does not.

    Supersedes any prior snapshot for the same (file_path, function_name): the
    OLD ROW SURVIVES with its source_text nulled. See prune_snapshots().
    """
    prune_snapshots(conn, file_path, function_name)
    cur = conn.execute(
        "INSERT INTO error_code_snapshots (function_name, file_path, line_start, "
        "line_end, source_text, git_commit_hash, captured_ts) VALUES (?,?,?,?,?,?,?)",
        (function_name, file_path, line_start, line_end, source_text,
         git_commit_hash, nemesis_timestamp.now()))
    conn.commit()
    return cur.lastrowid


def prune_snapshots(conn, file_path, function_name=None):
    """NULL the source_text of superseded snapshots for one (file, function).

    THE ROW IS NOT DELETED, and that is the whole design. `error_occurrences.
    snapshot_id` points into this table, so deleting would either orphan those
    references or force rewriting every historical occurrence — the
    verify-before-touching cost this codebase refuses to pay casually.

    Losing superseded source text is a deliberate, acceptable loss: tier-2 only
    ever needs the CURRENT source to reason about a CURRENT failure. What must
    survive is the historical fact that occurrence N was investigated against
    commit X — preserved by the row (and its git_commit_hash) remaining
    resolvable, independent of the text.
    """
    conn.execute(
        "UPDATE error_code_snapshots SET source_text=NULL "
        "WHERE file_path=? AND IFNULL(function_name,'')=IFNULL(?,'') "
        "AND source_text IS NOT NULL",
        (file_path, function_name))
    conn.commit()


# ── Occurrence archival ──────────────────────────────────────────────────────

def archive_and_coalesce_occurrences(conn, archive_dir, cutoff_days=None,
                                     dry_run=False):
    """Archive aged occurrences, then coalesce them to one row per (code, hour).

    ORDERING IS THE CORRECTNESS PROPERTY, and it mirrors
    `DataManager.archive_and_coalesce_op_log()` deliberately:
        write -> atomic rename -> re-open -> verify field by field
        -> ONLY THEN modify the live table
    Any failure at any step leaves the live table exactly as it was and keeps the
    archive for inspection. Nothing is destroyed: every archived row is
    recoverable via the summary row's context, which carries the archive ref.

    NOTE ON REUSE, stated because the scoping doc expected otherwise: this
    follows the op-log method's SEQUENCE but is not a parameterisation of it.
    That method's body is `dm_operation_log`-shaped (its columns, its
    (module,table,operation,hour) bucket, its summary format). Genuinely
    parameterising it would mean refactoring a hardened, security-relevant Data
    Manager method in the same change that introduces this subsystem — two
    variables at once, against a method the whole system depends on. Extracting
    the shared sequence into one helper is worth doing LATER, as its own change.

    Rows with a non-NULL actor are NEVER archived, at any age — human-attributed
    records keep per-row fidelity permanently, same rule as the op log.
    """
    days = ARCHIVE_DAYS if cutoff_days is None else int(cutoff_days)
    cutoff_ts = nemesis_timestamp.normalize(
        time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - days * 86400)))

    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM error_occurrences WHERE ts < ? AND actor IS NULL "
        "AND is_summary = 0 ORDER BY id", (cutoff_ts,)).fetchall()
    if not rows:
        return {"status": "ok", "archived": 0, "coalesced": 0, "archive_ref": None}
    if dry_run:
        return {"status": "dry-run", "archived": len(rows), "coalesced": 0,
                "archive_ref": None}

    os.makedirs(archive_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S")
    final = os.path.join(archive_dir, f"error_occurrences-{stamp}.jsonl.gz")
    tmp = final + ".tmp"

    payload = [dict(r) for r in rows]
    with gzip.open(tmp, "wt", encoding="utf-8") as fh:
        for rec in payload:
            fh.write(json.dumps(rec, sort_keys=True, default=str) + "\n")
    os.replace(tmp, final)                      # atomic

    # RE-OPEN AND VERIFY FIELD BY FIELD. Writing then trusting the write is the
    # failure this ordering exists to prevent — a truncated or partially-flushed
    # archive would otherwise be followed by deleting the only remaining copy.
    with gzip.open(final, "rt", encoding="utf-8") as fh:
        read_back = [json.loads(line) for line in fh if line.strip()]
    if len(read_back) != len(payload):
        raise ErrorSystemError(
            f"archive verify FAILED: wrote {len(payload)} rows, read back "
            f"{len(read_back)} — live table left untouched, archive kept at {final}")
    for a, b in zip(payload, read_back):
        if {k: str(v) for k, v in a.items()} != {k: str(v) for k, v in b.items()}:
            raise ErrorSystemError(
                f"archive verify FAILED on row id={a.get('id')} — live table "
                f"left untouched, archive kept at {final}")

    # Only now is it safe to modify the live table.
    buckets = {}
    for r in payload:
        buckets.setdefault((r["code"], str(r["ts"])[:13]), []).append(r)
    ids = [r["id"] for r in payload]
    conn.execute(
        f"DELETE FROM error_occurrences WHERE id IN ({','.join('?' * len(ids))})", ids)
    for (code, hour), group in sorted(buckets.items()):
        conn.execute(
            "INSERT INTO error_occurrences (code, ts, context, snapshot_id, "
            "resolved_cause_id, actor, is_summary) VALUES (?,?,?,NULL,NULL,NULL,1)",
            (code, hour + ":00:00",
             json.dumps({"coalesced": len(group), "archive_ref": final,
                         "bucket": "code+hour"}, sort_keys=True)))
    conn.commit()
    return {"status": "ok", "archived": len(payload), "coalesced": len(buckets),
            "archive_ref": final}
