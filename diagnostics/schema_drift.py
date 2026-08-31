"""Check: database schema drift — does the live DB match what the code declares?

THE BUG CLASS THIS EXISTS FOR
    A fresh install crashed because the `devices` table had no `CREATE` anywhere
    in the repo. Every existing box worked, because the table had been created by
    hand long ago and simply persisted; nothing failed until someone installed
    from scratch. CLAUDE.md's database rule ("no table without a CREATE in the
    repo") is the response, and this check is what enforces it continuously
    rather than at the next fresh install.

    The second half is the mirror image: a guarded migration that never ran. The
    canonical `CREATE` gains a column, the `ALTER TABLE ADD COLUMN` beside it is
    missed or fails silently, and the live table is one column short. Code written
    against the new schema then fails on a box that looks perfectly healthy.

WHAT IT COMPARES
    live tables  (PRAGMA / sqlite_master)   vs   CREATE TABLE statements in the repo
    live columns (PRAGMA table_info)        vs   the columns those CREATEs declare

WHY THE PARSER RESOLVES CONSTANTS
    A literal grep for the DDL keyword followed by a name produces a FALSE
    POSITIVE on this very repo: `data_manager.py` creates its operation log from
    an f-string whose table name is a module-level constant, not a literal.
    Reporting that table as undeclared would be a check that cries wolf on its
    first run, and an operator told to ignore the first finding will ignore the
    real one underneath it. So simple `NAME = "literal"` assignments are resolved
    before matching.

    NOTE FOR ANYONE EDITING THIS FILE: it scans the whole repo INCLUDING its own
    source, so writing the DDL keyword followed by a `{placeholder}` anywhere
    here -- even in prose like this paragraph -- makes the scanner match its own
    documentation and report a phantom unresolved table on every production run.
    That happened twice while this was being written. Describe the pattern; do
    not spell it.

    This is deliberately NOT a general SQL parser. It handles literal names and
    single-constant interpolation, and anything it cannot resolve is reported as
    UNRESOLVED rather than counted as either present or absent — an unparsed
    statement is not evidence that a table is undeclared.

Read-only: opens the database read-only and reads files. Runs no DDL, ever.
"""

import os
import re
import sqlite3
import sys

try:                                    # normal package import
    from . import canary as _canary_harness
except ImportError:                     # loaded by file path (tests, direct run)
    # The checks are documented as independently runnable, and the test suites
    # load them via spec_from_file_location -- neither has package context, so a
    # bare relative import fails. Falling back keeps all three entry points
    # working: `import diagnostics`, `python3 -m diagnostics.<id>`, and a direct
    # path load.
    import os as _os, sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    import canary as _canary_harness

META = {
    "id": "schema_drift",
    "name": "Database Schema Drift",
    "icon": "🗂️",
    "descriptions": {
        "beginner": "Checks that the database on this machine matches what the "
                    "software expects. Finds tables that would be missing on a "
                    "fresh install, and columns an update should have added but "
                    "did not.",
        "intermediate": "Compares live sqlite_master/table_info against every "
                        "CREATE TABLE declared in the repo. Reports tables with "
                        "no CREATE (fresh-install crash risk) and declared "
                        "columns absent from the live table (missed migration).",
        "pro": "Two-way schema diff: live tables vs repo CREATE TABLE (constants "
               "resolved), and declared columns vs PRAGMA table_info. Read-only; "
               "unparseable DDL is reported UNRESOLVED, never counted as absent.",
    },
}

# ── Shared per-section status vocabulary (the vpn_status.py convention) ───────
# A failed probe and a genuine absence must not render identically -- that is the
# distinction the batch3 audit was written about.
_OK = "ok"
_DRIFT = "drift"
_PROBE_FAILED = "probe-failed"

_TAGS = {_OK: "OK", _DRIFT: "DRIFT", _PROBE_FAILED: "PROBE-FAILED"}


def _section(label, state, detail=""):
    """One labeled line, tagged with its measured state.

    An unrecognised state raises rather than rendering as OK — a check that
    cannot report failure is not a check.
    """
    return f"[{_TAGS[state]}] {label}" + (f": {detail}" if detail else "")


def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resolve_db():
    """(path, problem). `problem` is None only when the CANONICAL resolver ran.

    ⛔ THE SILENT FALLBACK THIS REPLACES COULD AUDIT THE WRONG DATABASE, and
    the failure was invisible in the output. `except: return legacy` handed
    back `alert_manager/alerts.db` — the pre-2026-07-27 location. Measured on
    this box 2026-08-31: that path still exists as a **0-byte file**, SQLite
    opens a 0-byte file as a perfectly valid EMPTY database, and the live DB
    has 99 tables. So a failed `nemesis_paths` import produced a confident
    verdict that every declared table was missing, computed against a database
    nobody meant to read, with nothing in the output naming which file it was.

    Returning the problem instead of swallowing it lets the caller refuse to
    produce a verdict at all — "assert the source identity, not just the
    value", which is exactly the class of bug this whole check exists to find
    in other people's code.
    """
    root = _repo_root()
    legacy = os.path.join(root, "alert_manager", "alerts.db")
    try:
        sys.path.insert(0, os.path.join(root, "alert_manager"))
        import nemesis_paths
        return nemesis_paths.db_path(legacy), None
    except Exception as exc:                                 # noqa: BLE001
        return legacy, "%s: %s" % (type(exc).__name__, exc)


# ── DDL extraction ───────────────────────────────────────────────────────────

#: `CREATE TABLE [IF NOT EXISTS] name (` — name may be quoted, or an f-string
#: placeholder like {OP_LOG_TABLE}.
_CREATE_RE = re.compile(
    r"""CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?
        (?P<name>\{[A-Za-z_][A-Za-z0-9_]*\}|["'`]?[A-Za-z_][A-Za-z0-9_]*["'`]?)""",
    re.IGNORECASE | re.VERBOSE)

#: Module-level `NAME = "literal"` — how a table name reaches an f-string CREATE.
_CONST_RE = re.compile(
    r"""^\s*([A-Z_][A-Z0-9_]*)\s*=\s*["']([A-Za-z_][A-Za-z0-9_]*)["']""",
    re.MULTILINE)

_SKIP_DIRS = {".git", "__pycache__", "node_modules", "venv", ".venv"}
_SCAN_EXT = (".py", ".sql", ".sh")


def _iter_source_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(_SCAN_EXT):
                yield os.path.join(dirpath, fn)


def declared_tables(root=None):
    """Every table the repo declares a CREATE for.

    Returns (names, unresolved) — `unresolved` holds placeholder names whose
    constant could not be resolved. They are reported separately and never
    counted as absent: an unparsed statement is not evidence of a missing table.
    """
    root = root or _repo_root()
    names, unresolved = set(), set()
    for path in _iter_source_files(root):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        if "CREATE" not in text.upper():
            continue
        consts = dict(_CONST_RE.findall(text))
        for m in _CREATE_RE.finditer(text):
            raw = m.group("name").strip("\"'`")
            if raw.startswith("{") and raw.endswith("}"):
                key = raw[1:-1]
                if key in consts:
                    names.add(consts[key].lower())
                else:
                    unresolved.add(raw)
            else:
                names.add(raw.lower())
    return names, unresolved


def declared_columns(table, root=None):
    """Columns the repo's CREATE for `table` declares, or None if not found.

    None (not an empty set) because "no CREATE found" and "a CREATE declaring no
    columns" are different facts, and an empty set would make a missing
    declaration look like a table that legitimately has none.
    """
    root = root or _repo_root()
    want = table.lower()
    for path in _iter_source_files(root):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        consts = dict(_CONST_RE.findall(text))
        for m in _CREATE_RE.finditer(text):
            raw = m.group("name").strip("\"'`")
            if raw.startswith("{") and raw.endswith("}"):
                raw = consts.get(raw[1:-1], "")
            if raw.lower() != want:
                continue
            body = _balanced_paren_body(text, m.end())
            if body is None:
                continue
            cols = _column_names(body)
            if cols:
                return cols
    return None


def _balanced_paren_body(text, start):
    """The (...) immediately following `start`, respecting nesting."""
    i = text.find("(", start)
    if i < 0:
        return None
    depth, j = 0, i
    while j < len(text):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return text[i + 1:j]
        j += 1
    return None


#: Constraint keywords that begin a table-level clause rather than a column.
_NOT_A_COLUMN = {"primary", "foreign", "unique", "check", "constraint", "key"}


#: SQL line comment: `--` to end of line.
_SQL_COMMENT_RE = re.compile(r"--[^\n]*")
#: SQL block comment.
_SQL_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def _strip_sql_comments(body):
    """Remove SQL comments from a CREATE body before parsing columns.

    NOT cosmetic. This repo comments its DDL heavily and inline, e.g.

        username  TEXT NOT NULL UNIQUE,   -- login ID, stable, lowercase
        display_name TEXT NOT NULL,       -- shown in UI, can change

    Splitting that on commas without stripping comments is wrong in BOTH
    directions at once: it invents columns named `stable`, `lowercase` and `can`
    out of English prose, AND it loses `display_name` and `password_hash`,
    because everything after the first inline comment on a line ends up inside
    the wrong fragment. The first run of this check reported seven tables as
    drifted entirely on that basis -- every one a false positive, while real
    drift would have been buried among them.
    """
    body = _SQL_BLOCK_COMMENT_RE.sub(" ", body)
    return _SQL_COMMENT_RE.sub("", body)


def _column_names(body):
    """Column names from a CREATE TABLE body, skipping table-level constraints."""
    body = _strip_sql_comments(body)
    cols, depth, current = [], 0, []
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            cols.append("".join(current))
            current = []
        else:
            current.append(ch)
    cols.append("".join(current))
    out = []
    for frag in cols:
        frag = frag.strip()
        if not frag:
            continue
        first = frag.split()[0].strip("\"'`,")
        if first.lower() in _NOT_A_COLUMN:
            continue
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", first):
            continue
        out.append(first.lower())
    return out


# ── Live schema ──────────────────────────────────────────────────────────────

def live_schema(db_path):
    """{table: [columns]} from the live DB. Opened READ-ONLY.

    Raises on failure rather than returning {} — an empty schema is a legal
    answer (a brand-new database) and would be indistinguishable from a failed
    read, which is the exact defect this module reports on other people's code.
    """
    uri = "file:%s?mode=ro" % db_path
    conn = sqlite3.connect(uri, uri=True, timeout=5.0)
    try:
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'")]
        return {t: [r[1].lower() for r in conn.execute(
            'PRAGMA table_info("%s")' % t.replace('"', '""'))] for t in tables}
    finally:
        conn.close()


def compare(live, declared, unresolved=(), column_lookup=None):
    """Pure comparison. Returns {orphans, column_drift, unresolved, checked}.

    Separated from all I/O so the canary below can run it against fixtures and
    prove it distinguishes cases.
    """
    orphans = sorted(t for t in live if t.lower() not in declared)
    drift = {}
    if column_lookup is not None:
        for table, live_cols in sorted(live.items()):
            if table.lower() not in declared:
                continue                      # already an orphan; not column drift
            want = column_lookup(table)
            if not want:
                continue                      # unparseable body — not evidence
            missing = [c for c in want if c not in live_cols]
            if missing:
                drift[table] = missing
    return {"orphans": orphans, "column_drift": drift,
            "unresolved": sorted(unresolved), "checked": len(live)}


# ── Canary — proves the comparison can return more than one answer ───────────
#
# Runs on EVERY invocation, in the production path, before the check vouches for
# anything real. The reference shape is scripts/nemesis-fw-neverblock's CANARIES.
# Without it, a comparison that always reported "clean" would look identical to a
# genuinely clean database, and the AI and the operator would both trust it.

def _canary():
    """Returns (ok, detail). Never raises."""
    try:
        # Known-GOOD: live matches declared exactly -> nothing reported.
        good = compare({"alpha": ["id", "name"]}, {"alpha"},
                       column_lookup=lambda t: ["id", "name"])
        if good["orphans"] or good["column_drift"]:
            return False, ("a matching schema reported drift (%s / %s)"
                           % (good["orphans"], good["column_drift"]))

        # Known-BAD 1: a live table the repo never declares -> orphan.
        bad1 = compare({"ghost": ["id"]}, set(), column_lookup=lambda t: [])
        if bad1["orphans"] != ["ghost"]:
            return False, "an undeclared table was not reported as an orphan"

        # Known-BAD 2: declared column absent from the live table -> drift.
        bad2 = compare({"alpha": ["id"]}, {"alpha"},
                       column_lookup=lambda t: ["id", "added_later"])
        if bad2["column_drift"] != {"alpha": ["added_later"]}:
            return False, ("a missing declared column was not reported (%s)"
                           % bad2["column_drift"])

        # An orphan must NOT also be reported as column drift — one fault, one line.
        both = compare({"ghost": ["id"]}, set(),
                       column_lookup=lambda t: ["id", "nope"])
        if both["column_drift"]:
            return False, "an orphan table was double-reported as column drift"

        # SQL comments must be stripped before columns are parsed. This defect
        # was REAL, not hypothetical: the first version of this check reported
        # seven tables as drifted, every one a false positive built out of
        # English words in inline DDL comments -- while simultaneously LOSING the
        # real columns that followed those comments.
        commented = ("\n  id INTEGER PRIMARY KEY,\n"
                     "  username TEXT NOT NULL,   -- login ID, stable, lowercase\n"
                     "  display_name TEXT NOT NULL,  -- shown in UI, can change\n")
        cols = _column_names(commented)
        if cols != ["id", "username", "display_name"]:
            return False, ("DDL comments are not being stripped before column "
                           "parsing -- prose becomes phantom columns and real "
                           "columns after a comment are lost (got %s)" % cols)

        # The constant resolver must actually resolve, or dm_operation_log-shaped
        # tables produce a false positive on every run.
        import tempfile
        # The DDL keyword is assembled at runtime, never written literally in this
        # file. This module scans the whole repo for CREATE statements -- INCLUDING
        # its own source -- so a literal fixture here would be picked up as a real
        # declaration and reported as an unresolved table on every production run.
        # It was, on the first run: `{SOME_UNKNOWN_NAME}` appeared in the live
        # output, sourced from this very canary.
        _ct = "CREATE" + " TABLE"
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "m.py"), "w") as fh:
                fh.write('OP_LOG_TABLE = "resolved_via_constant"\n'
                         'q = f"%s IF NOT EXISTS {OP_LOG_TABLE} (id INTEGER)"\n'
                         'q2 = "%s plain_literal (id INTEGER)"\n' % (_ct, _ct))
            names, unres = declared_tables(d)
            if "resolved_via_constant" not in names:
                return False, ("an f-string CREATE with a resolvable constant was "
                               "not resolved -- this produces a false positive on "
                               "the real dm_operation_log")
            if "plain_literal" not in names:
                return False, "a plain literal CREATE was not detected"
            # ...and an UNRESOLVABLE one is reported, not silently dropped.
            with open(os.path.join(d, "n.py"), "w") as fh:
                fh.write('q = f"%s {AN_UNRESOLVABLE_NAME} (id INTEGER)"\n' % _ct)
            _n2, unres2 = declared_tables(d)
            if "{AN_UNRESOLVABLE_NAME}" not in unres2:
                return False, ("an unresolvable table name was not reported as "
                               "UNRESOLVED -- it would be silently ignored")
        return True, "known-good and 5 known-bad cases behaved correctly"
    except Exception as e:                                   # noqa: BLE001
        return False, "canary itself failed: %s: %s" % (type(e).__name__, e)


def run() -> dict:
    """Entry point. The harness runs the canary and suppresses the verdict
    entirely if it fails — a schema verdict from an unverified comparator reads
    as a clean bill of health, which is worse than no verdict. See
    diagnostics/canary.py."""
    return _canary_harness.guard(META, _canary, _produce, subject="schema")


def _produce(detail):
    sections = []
    status = _OK
    summary = "Schema matches the code"
    sections.append(_section("canary self-test", _OK, detail))

    db_path, resolve_problem = _resolve_db()
    if resolve_problem:
        # REFUSE, do not fall back. A verdict computed against an unverified
        # database is worse than no verdict: it looks authoritative and the
        # reader has no way to tell which file produced it. Same reasoning the
        # canary harness above applies to a failed self-test.
        return {
            "id": META["id"], "name": META["name"], "icon": META["icon"],
            "status": "error",
            "summary": "Could not determine which database to check",
            "output": "\n".join(sections + [
                _section("database location", _PROBE_FAILED,
                         "the canonical path resolver is unavailable (%s), so "
                         "this check cannot confirm WHICH database it would "
                         "read. Refusing rather than falling back to the "
                         "pre-relocation path, which on some installs still "
                         "exists as an empty file and would report every table "
                         "as missing." % resolve_problem)]),
        }

    try:
        live = live_schema(db_path)
    except Exception as e:                                   # noqa: BLE001
        # Rule 8: name the file, not its absolute path -- this output can reach an
        # external support address.
        return {
            "id": META["id"], "name": META["name"], "icon": META["icon"],
            "status": "error",
            "summary": "Could not read the database schema",
            "output": "\n".join(sections + [
                _section("live schema", _PROBE_FAILED,
                         "%s reading %s" % (type(e).__name__,
                                            os.path.basename(db_path)))]),
        }

    declared, unresolved = declared_tables()
    result = compare(live, declared, unresolved,
                     column_lookup=lambda t: declared_columns(t) or [])

    sections.append(_section(
        "tables examined", _OK,
        # THE PATH IS NAMED DELIBERATELY. Both the live and the pre-relocation
        # database are called `alerts.db`, so a basename cannot tell a reader
        # which one produced this verdict -- and reading the wrong one was a
        # real defect here (see _resolve_db). Neither path is user-specific, so
        # naming it in full carries nothing Rule 8 excludes.
        "%d live, %d declared in the repo (read from %s)"
        % (result["checked"], len(declared), db_path)))

    if result["orphans"]:
        status = _DRIFT
        sections.append(_section(
            "tables with NO CREATE in the repo", _DRIFT,
            "%d — a fresh install would not have these:\n    %s"
            % (len(result["orphans"]), "\n    ".join(result["orphans"]))))
    else:
        sections.append(_section("every live table has a CREATE", _OK))

    if result["column_drift"]:
        status = _DRIFT
        lines = ["%s: missing %s" % (t, ", ".join(c))
                 for t, c in sorted(result["column_drift"].items())]
        sections.append(_section(
            "declared columns absent from the live table", _DRIFT,
            "%d table(s) — a migration did not run:\n    %s"
            % (len(lines), "\n    ".join(lines))))
    else:
        sections.append(_section("no missing declared columns", _OK))

    if result["unresolved"]:
        # Reported, never counted either way.
        sections.append(_section(
            "CREATE statements whose table name could not be resolved",
            _PROBE_FAILED,
            "%d — NOT counted as present or absent:\n    %s"
            % (len(result["unresolved"]), "\n    ".join(result["unresolved"]))))

    if status == _DRIFT:
        n = len(result["orphans"]) + len(result["column_drift"])
        summary = "%d schema issue(s) found" % n

    return {
        "id": META["id"], "name": META["name"], "icon": META["icon"],
        # Only ok/warn/error/info are recognised by the page; anything else
        # renders as a grey "Not run", i.e. a finding that looks like an unrun check.
        "status": "warn" if status == _DRIFT else "ok",
        "summary": summary,
        "output": "\n".join(sections),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))
