#!/usr/bin/env python3
"""Window-liveness check for `hw_anomaly_snapshots.top_processes` retention.

⛔ WHAT THIS TESTS AND WHY IT IS NOT A TEST OF THE ARCHIVER.

From 2026-08-03 to 2026-09-05 `archive_old_top_processes()` was correct, verified
round-trip, and NEVER CALLED -- it had zero callers, no timer, no unit. Every
code-level test of the archiver passed throughout, because the archiver was never
the broken part. 64.0 MB of live data sat past its own declared 14-day window and
nothing anywhere noticed, because nothing anywhere asserted the WINDOW held.

So this file deliberately asks ONE question OF THE DATA -- "is any live blob older
than its cutoff?" -- and knows nothing about how archival works. That independence
is the whole point: it fails if the archiver breaks, if the timer is removed, if
the unit is masked, or if someone ships a correct function and forgets to schedule
it. A test written against the mechanism cannot do that.

Run:  python3 core_module/hw_monitor/test_retention_window.py
"""
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta

sys.path.insert(0, "/opt/nemesis/alert_manager")
sys.path.insert(0, "/opt/nemesis/core_module/hw_monitor")

import hw_monitor                                                    # noqa: E402

EXPECTED_CHECKS = 17
LIVE_DB = os.environ.get("NEMESIS_DB_PATH", "/var/lib/nemesis/alerts.db")

_results = []


def check(label, got, want):
    """Unconditional assertion. Never guarded by an `if` -- a run with fewer
    checks than EXPECTED_CHECKS is itself a failure (see CLAUDE.md: a test whose
    assertion count changes under failure cannot be compared between runs)."""
    ok = (got == want)
    _results.append((ok, label, got, want))
    return ok


# ---------------------------------------------------------------- fixtures ---
SCHEMA = """
CREATE TABLE hw_anomaly_snapshots (
    id                INTEGER PRIMARY KEY,
    captured_at       TEXT,
    top_processes     TEXT,
    top_processes_ref TEXT
)
"""


def _mkdb(rows):
    """Synthetic DB. `rows` = [(days_ago, blob, ref), ...]."""
    fd, path = tempfile.mkstemp(suffix=".db", prefix="nemtest_retention_")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.execute(SCHEMA)
    for days_ago, blob, ref in rows:
        ts = (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S")
        conn.execute(
            "INSERT INTO hw_anomaly_snapshots (captured_at, top_processes, "
            "top_processes_ref) VALUES (?,?,?)", (ts, blob, ref))
    conn.commit()
    return conn, path


def _status(conn, **kw):
    return hw_monitor.top_processes_retention_status(conn=conn, **kw)


def main():
    blob = "x" * 2000
    tmpfiles = []

    # ---- KNOWN-BAD: three 30-day-old rows still holding blobs ---------------
    bad, p = _mkdb([(30, blob, None), (40, blob, None), (50, blob, None)])
    tmpfiles.append(p)
    s_bad = _status(bad)
    check("known-bad: ok is False", s_bad["ok"], False)
    check("known-bad: counts all 3 violating rows", s_bad["violating_rows"], 3)
    check("known-bad: sums their bytes", s_bad["violating_bytes"], 6000)
    check("known-bad: oldest_violation is the 50-day row",
          s_bad["oldest_violation"][:10],
          (datetime.now() - timedelta(days=50)).strftime("%Y-%m-%d"))
    check("known-bad: reports the window it used", s_bad["cutoff_days"],
          hw_monitor.TOP_PROC_ARCHIVE_DAYS)

    # ---- KNOWN-GOOD: rows inside the window --------------------------------
    good, p = _mkdb([(1, blob, None), (5, blob, None)])
    tmpfiles.append(p)
    s_good = _status(good)
    check("known-good: ok is True", s_good["ok"], True)
    check("known-good: zero violating rows", s_good["violating_rows"], 0)
    check("known-good: oldest_violation is None", s_good["oldest_violation"], None)

    # ---- CONTROL: the instrument produces DIFFERENT answers -----------------
    # Without this, every check above is consistent with a function that can only
    # ever return one verdict. (CLAUDE.md: prove the premise against a
    # known-different input.)
    check("CONTROL: known-bad and known-good disagree",
          s_bad["ok"] != s_good["ok"], True)

    # ---- ARCHIVED rows must NOT count as violations ------------------------
    arch, p = _mkdb([(90, None, "hw_anomaly_top_processes_2026-08-03.jsonl.gz"),
                     (95, "", "hw_anomaly_top_processes_2026-08-03.jsonl.gz")])
    tmpfiles.append(p)
    check("archived rows (NULL/empty blob) are not violations",
          _status(arch)["ok"], True)

    # ---- EMPTY table is clean, and says so explicitly ----------------------
    empty, p = _mkdb([])
    tmpfiles.append(p)
    check("empty table is clean, not an error", _status(empty)["violating_rows"], 0)

    # ---- BOUNDARY ----------------------------------------------------------
    edge, p = _mkdb([(hw_monitor.TOP_PROC_ARCHIVE_DAYS - 1, blob, None)])
    tmpfiles.append(p)
    check("a row just inside the window is clean", _status(edge)["ok"], True)
    edge2, p = _mkdb([(hw_monitor.TOP_PROC_ARCHIVE_DAYS + 1, blob, None)])
    tmpfiles.append(p)
    check("a row just outside the window violates", _status(edge2)["ok"], False)

    # ---- the cutoff_days PARAMETER is actually used ------------------------
    # Same data, wider window -> clean. Proves the argument reaches the query
    # rather than the constant being hardcoded into the SQL.
    check("widening cutoff_days clears the same violation",
          _status(bad, cutoff_days=365)["ok"], True)

    # ---- must NOT inherit the archiver's own predicate ---------------------
    # archive_old_top_processes() filters on `top_processes_ref IS NULL`. If this
    # check copied that, a row holding BOTH a blob and a ref -- which should never
    # exist, and would mean the archiver half-completed -- would be invisible to
    # the very check meant to catch archival going wrong.
    both, p = _mkdb([(60, blob, "some_archive.jsonl.gz")])
    tmpfiles.append(p)
    check("a row with BOTH blob and ref past the window is still reported",
          _status(both)["violating_rows"], 1)

    # ---- fail closed on an unreadable table --------------------------------
    broken, p = _mkdb([])
    tmpfiles.append(p)
    broken.execute("DROP TABLE hw_anomaly_snapshots")
    broken.commit()
    raised = False
    try:
        _status(broken)
    except Exception:                                             # noqa: BLE001
        raised = True
    check("an unreadable table RAISES, never returns a clean-looking default",
          raised, True)

    for c in (bad, good, arch, empty, edge, edge2, both, broken):
        c.close()
    for p in tmpfiles:
        try:
            os.unlink(p)
        except OSError:
            pass

    # ---- LIVE DB -----------------------------------------------------------
    # The check this file exists for. Expected to FAIL until the archiver is
    # actually scheduled and has run.
    live = sqlite3.connect("file:%s?mode=ro" % LIVE_DB, uri=True)
    try:
        s_live = _status(live)
    finally:
        live.close()
    check("LIVE: no top_processes blob is past its retention window",
          s_live["ok"], True)

    # ---------------------------------------------------------------- report --
    print("=" * 72)
    for ok, label, got, want in _results:
        print("  %s  %s" % ("PASS" if ok else "FAIL", label))
        if not ok:
            print("        got=%r want=%r" % (got, want))
    passed = sum(1 for r in _results if r[0])
    total = len(_results)
    print("-" * 72)
    print("  %d/%d passed  (expected %d checks)" % (passed, total, EXPECTED_CHECKS))
    print("  LIVE state: %d rows / %.1f MB past the %d-day window; oldest %s"
          % (s_live["violating_rows"], s_live["violating_bytes"] / 1e6,
             s_live["cutoff_days"], s_live["oldest_violation"]))
    print("=" * 72)

    if total != EXPECTED_CHECKS:
        print("  ⛔ CHECK COUNT DRIFT: ran %d, expected %d" % (total, EXPECTED_CHECKS))
        return 2
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
