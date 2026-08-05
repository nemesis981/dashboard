#!/usr/bin/env python3
"""`degraded_ingest_health()` — ADR 0019 Phase 2 state derivation.

Run: python3 alert_manager/test_ingest_health.py

WHY FOUR STATES AND NOT A BOOLEAN
---------------------------------
The degraded-journal ingest logs only when it FINDS something, so a healthy idle
sweep and a dead poller thread are indistinguishable in the journal. Proven on
2026-08-05: liveness had to be established from /proc/<pid>/task/*/comm because
nothing else could answer it. This panel exists to answer it — which means it
must never report health it did not measure.

So `unknown` is split in two, deliberately:
  * unknown-no-sweep    — nothing has ever run (fresh install, or a restart less
                          than one interval ago). Expected, not a fault.
  * unknown-unreadable  — the heartbeat exists but cannot be read or parsed.
                          A real fault, and it must not hide inside the first.

WHAT THIS SUITE IS WEIGHTED TOWARD
----------------------------------
Every state must be REACHABLE and DISTINGUISHABLE. A suite that only checked
"healthy when fresh" would pass an implementation that returned healthy
unconditionally — which is the precise failure this panel is built to catch, so
proving it cannot happen is the whole job.

The staleness threshold is also pinned against a NON-DEFAULT interval, because
reading it from config is what stops a changed poll interval from silently
turning a healthy system degraded.
"""
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

EXPECTED_CHECKS = 21

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 42:
        g, w = g[:39] + "...", w[:39] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def load_health_fn():
    """AST-extract the one function under test.

    Importing dashboard.py wholesale runs module-level init against the live
    database and loads every module. Extracting keeps this hermetic while still
    testing the REAL source rather than a reimplementation that would drift.
    """
    import ast
    src = open(os.path.join(REPO, "dashboard.py")).read()
    tree = ast.parse(src)
    ns = {"sqlite3": sqlite3, "datetime": datetime, "DB_PATH": ":memory:"}
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id.startswith("INGEST_")
                for t in node.targets):
            exec(compile(ast.Module(body=[node], type_ignores=[]), "d", "exec"), ns)
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "DEGRADED_INGEST_INTERVAL"
                for t in node.targets):
            ns["DEGRADED_INGEST_INTERVAL"] = 60
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "degraded_ingest_health":
            exec(compile(ast.Module(body=[node], type_ignores=[]), "d", "exec"), ns)
            return ns["degraded_ingest_health"], ns
    raise AssertionError("degraded_ingest_health not found in dashboard.py — the "
                         "feature is ABSENT, not merely failing")


def make_db(stamp=None, with_settings=True, events=0):
    path = os.path.join(tempfile.mkdtemp(prefix="ih-"), "t.db")
    c = sqlite3.connect(path)
    c.executescript("""
        CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL,
            updated_at TEXT, updated_by TEXT);
        CREATE TABLE audit_log (id INTEGER PRIMARY KEY, ts TIMESTAMP NOT NULL,
            rule_id TEXT, ip TEXT, action TEXT NOT NULL, user TEXT,
            request_id TEXT);
    """)
    if with_settings and stamp is not None:
        c.execute("INSERT INTO settings (key,value,updated_at,updated_by) "
                  "VALUES ('degraded_ingest_offset','962',?,'degraded_ingest')",
                  (stamp,))
    for i in range(events):
        c.execute("INSERT INTO audit_log (ts,action,user) VALUES (?,?,?)",
                  ("2026-08-01T17:54:28", "fw_table_tampered", "nemesis-fw-watch"))
    c.commit(); c.close()
    return path


def main():
    health, ns = load_health_fn()
    H = ns["INGEST_HEALTHY"]; D = ns["INGEST_DEGRADED"]
    UN = ns["INGEST_UNKNOWN_NO_SWEEP"]; UU = ns["INGEST_UNKNOWN_UNREADABLE"]
    now = datetime(2026, 8, 5, 14, 0, 0)

    def fac(path):
        return lambda: sqlite3.connect(path)

    # ── all four states are reachable and distinct ───────────────────────────
    print("\nevery state is reachable — none is unreachable dead code")
    fresh = make_db((now - timedelta(seconds=30)).isoformat())
    check("a recent sweep is healthy", health(fac(fresh), now)["state"], H)

    stale = make_db((now - timedelta(seconds=600)).isoformat())
    check("a stale sweep is degraded", health(fac(stale), now)["state"], D)

    never = make_db(None, with_settings=False)
    check("no settings row at all is unknown-no-sweep",
          health(fac(never), now)["state"], UN)

    junk = make_db("not-a-timestamp")
    check("an unparseable stamp is unknown-unreadable",
          health(fac(junk), now)["state"], UU)

    # The two unknowns must NOT collapse into each other — that is the whole
    # reason there are two.
    check("CONTROL the two unknown states are distinct values", UN == UU, False)

    # A DB that cannot be opened must not read as healthy.
    def exploding():
        raise sqlite3.OperationalError("unable to open database file")
    check("an unopenable database is unknown-unreadable, not healthy",
          health(exploding, now)["state"], UU)

    # ── a FUTURE timestamp must not read as healthy ─────────────────────────
    # Found by the panel reading its own live input on 2026-08-05: the pre-fix
    # UTC stamp gave age = -17957s and `age <= threshold` accepted it, so the
    # most broken possible input produced the most confident possible answer.
    print("\na sweep stamped in the future is unreadable, not healthy")
    future = make_db((now + timedelta(hours=5)).isoformat())
    check("a far-future stamp is unknown-unreadable",
          health(fac(future), now)["state"], UU)
    # CONTROL: small negative skew is ordinary clock jitter and must NOT trip it,
    # or every machine with a slightly fast clock reports a fault.
    jitter = make_db((now + timedelta(seconds=2)).isoformat())
    check("CONTROL 2s of clock jitter is still healthy",
          health(fac(jitter), now)["state"], H)

    # ── the threshold is exactly 2x the interval, read from config ───────────
    print("\nthe staleness threshold tracks the configured interval")
    at_edge = make_db((now - timedelta(seconds=120)).isoformat())
    check("exactly 2x the interval is still healthy",
          health(fac(at_edge), now)["state"], H)
    just_over = make_db((now - timedelta(seconds=121)).isoformat())
    check("one second past 2x is degraded",
          health(fac(just_over), now)["state"], D)

    # NON-DEFAULT interval: the same 121s-old sweep must be HEALTHY at a 300s
    # interval. Without this, a hardcoded 60 would pass every check above.
    check("CONTROL the same age is healthy under a larger interval",
          health(fac(just_over), now, interval=300)["state"], H)
    check("  and the reported threshold follows the interval",
          health(fac(just_over), now, interval=300)["threshold_seconds"], 600)

    # ── the payload is complete and honest ──────────────────────────────────
    print("\nthe returned payload never leaves a field silently absent")
    r = health(fac(fresh), now)
    for key in ("state", "last_sweep", "age_seconds", "threshold_seconds",
                "interval_seconds", "events", "detail"):
        check("payload carries %r" % key, key in r, True)
    check("age is computed, not None, on a real sweep", r["age_seconds"], 30)

    # events is supplementary — None when unreadable, never a misleading 0.
    counted = make_db((now - timedelta(seconds=10)).isoformat(), events=3)
    check("enforcement events are counted", health(fac(counted), now)["events"], 3)

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [lbl for lbl, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d "
              "-- a check was skipped, not merely failed" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
