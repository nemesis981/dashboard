"""Tests for the Tier 2 gate state-publication interface.

THE GRANT ASSERTIONS ARE THE POINT OF THIS FILE, not an afterthought. A missing
Data Manager grant is invisible to an ordinary behavioural test: build the tables
on a plain sqlite3 connection and every assertion passes, while production logs
one `WOULD DENY` and silently drops the write. For THIS table pair the resulting
failure is unusually quiet AND unusually bad — the banner keeps rendering the
last successfully-written state, so a gate that went into bypass still displays
as inspecting. A dropped write here produces a FALSE REASSURANCE.

So both names are asserted against `allowed()` DIRECTLY, with a control proving
the grant is exact rather than a prefix, and the whole thing is mutation-checked.

Run:  python3 test_tier2_gate_state.py
"""
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

RESULTS = []


def check(n, name, ok, detail=""):
    RESULTS.append((n, name, bool(ok)))
    print("  [%s] %2d. %-58s %s" % ("PASS" if ok else "FAIL", n, name, detail))
    return bool(ok)


def main():
    import data_manager as dm
    import tier2_gate_state as tg

    print("TIER 2 GATE STATE — PUBLICATION INTERFACE")
    print("=" * 78)

    # ── grants: asserted DIRECTLY against allowed() ──────────────────────────
    check(1, "grant: tier2_gate may write tier2_gate_state",
          dm.allowed("tier2_gate", "tier2_gate_state"))
    check(2, "grant: tier2_gate may write tier2_gate_events",
          dm.allowed("tier2_gate", "tier2_gate_events"))

    # CONTROL — the grant must be EXACT, not a prefix. If someone "simplifies"
    # the explicit list into a `tier2_` prefix, this is what notices.
    check(3, "CONTROL: grant is EXACT, not a `tier2_` prefix",
          not dm.allowed("tier2_gate", "tier2_gate_secrets")
          and not dm.allowed("tier2_gate", "tier2_anything"),
          "tier2_gate_secrets denied")

    # CONTROL — fail-closed on an unrelated table, and the audit log is never
    # module-writable by anyone.
    check(4, "CONTROL: unrelated + audit-log tables are denied",
          not dm.allowed("tier2_gate", "alerts")
          and not dm.allowed("tier2_gate", dm.OP_LOG_TABLE))

    # CONTROL — another namespace must NOT be able to write these tables.
    check(5, "CONTROL: hw_monitor cannot write the gate tables",
          not dm.allowed("hw_monitor", "tier2_gate_state")
          and not dm.allowed("hw_monitor", "tier2_gate_events"))

    check(6, "namespace defaults to ENFORCE (authored list, no WARN grace)",
          dm.namespace_mode("tier2_gate") == dm.MODE_ENFORCE,
          dm.namespace_mode("tier2_gate"))

    # ── DDL is canonical and idempotent ──────────────────────────────────────
    import database
    tmpd = tempfile.mkdtemp(prefix="tier2gs-")
    dbp = os.path.join(tmpd, "t.db")
    orig = database.DB_PATH
    database.DB_PATH = dbp
    try:
        database.init_tier2_gate_tables()
        database.init_tier2_gate_tables()          # idempotent
        c = sqlite3.connect(dbp)
        names = {r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        check(7, "DDL creates both tables and is idempotent",
              {"tier2_gate_state", "tier2_gate_events"} <= names)
        ok = c.execute("PRAGMA integrity_check").fetchone()[0]
        check(8, "PRAGMA integrity_check ok", ok == "ok", ok)
        # single-row constraint is enforced by the schema, not by convention
        c.execute("INSERT INTO tier2_gate_state (id,state,inspecting,degraded,"
                  "since,heartbeat_at) VALUES (1,'armed',1,0,'x','y')")
        dup = False
        try:
            c.execute("INSERT INTO tier2_gate_state (id,state,inspecting,"
                      "degraded,since,heartbeat_at) VALUES (2,'armed',1,0,'x','y')")
        except sqlite3.IntegrityError:
            dup = True
        check(9, "state table is structurally single-row (CHECK id=1)", dup)
        c.close()
    finally:
        database.DB_PATH = orig

    # ── staleness: the core reader property ──────────────────────────────────
    NOW = 1_700_000_000.0

    def fake_row(state="armed", inspecting=1, degraded=0, hb_offset=0.0,
                 episodes=0):
        """Drive read_state() off a synthetic row without a live DB."""
        hb = tg._now_iso(lambda: NOW - hb_offset)
        return (state, inspecting, degraded, episodes, None, hb, hb)

    class FakeConn:
        def __init__(self, row): self.row = row
        def execute(self, *a, **k):
            class C:
                def __init__(s, r): s.r = r
                def fetchone(s): return s.r
            return C(self.row)

    real_get_db = tg._get_db
    try:
        tg._get_db = lambda: FakeConn(fake_row(hb_offset=5))
        fresh = tg.read_state(max_age_s=120, clock=lambda: NOW)
        check(10, "fresh heartbeat -> real state, inspecting True",
              fresh["state"] == "armed" and fresh["inspecting"] is True
              and fresh["stale"] is False, "age=%.0fs" % fresh["age_s"])

        tg._get_db = lambda: FakeConn(fake_row(hb_offset=600))
        stale = tg.read_state(max_age_s=120, clock=lambda: NOW)
        check(11, "STALE heartbeat -> state is STALE, not the stored state",
              stale["state"] == tg.STALE and stale["last_known_state"] == "armed",
              "state=%s last_known=%s" % (stale["state"],
                                          stale["last_known_state"]))
        check(12, "STALE forces inspecting=False (no false reassurance)",
              stale["inspecting"] is False and stale["degraded"] is True)

        # a corrupt timestamp must read STALE, never as a fresh heartbeat
        tg._get_db = lambda: FakeConn(("armed", 1, 0, 0, None, "x", "not-a-date"))
        corrupt = tg.read_state(max_age_s=120, clock=lambda: NOW)
        check(13, "unparseable heartbeat -> STALE (never treated as now)",
              corrupt["state"] == tg.STALE and corrupt["inspecting"] is False)

        tg._get_db = lambda: FakeConn(None)
        unpub = tg.read_state(clock=lambda: NOW)
        check(14, "no row -> UNPUBLISHED, distinct from STALE and from armed",
              unpub["state"] == tg.UNPUBLISHED and unpub["inspecting"] is False)

        # read error must RAISE, not degrade to UNPUBLISHED
        class BadConn:
            def execute(self, *a, **k): raise sqlite3.Error("disk I/O error")
        tg._get_db = lambda: BadConn()
        raised = False
        try:
            tg.read_state(clock=lambda: NOW)
        except RuntimeError:
            raised = True
        check(15, "DB read error RAISES (not reported as 'Tier 2 is off')", raised)
    finally:
        tg._get_db = real_get_db

    # ── banner mapping ───────────────────────────────────────────────────────
    b_armed = tg.banner({"state": "armed", "age_s": 1, "stale": False,
                         "episodes_in_window": 0, "reason": None})
    check(16, "banner: armed -> no banner", b_armed is None)

    b_stale = tg.banner({"state": tg.STALE, "age_s": 900, "stale": True,
                         "episodes_in_window": 0, "reason": None})
    check(17, "banner: STALE -> CRITICAL and says state is UNKNOWN",
          b_stale and b_stale["level"] == "critical"
          and "UNKNOWN" in b_stale["title"])

    b_lock = tg.banner({"state": "locked_out", "age_s": 1, "stale": False,
                        "episodes_in_window": 3, "reason": "flap bound"})
    check(18, "banner: locked_out -> CRITICAL, says manual action + uninspected",
          b_lock and b_lock["level"] == "critical"
          and "manual" in b_lock["title"].lower()
          and "UNINSPECTED" in b_lock["body"])

    b_bypass = tg.banner({"state": "bypass_pending", "age_s": 1, "stale": False,
                          "episodes_in_window": 1, "reason": "probe timeout"})
    check(19, "banner: bypass_pending -> CRITICAL, distinct from locked_out",
          b_bypass and b_bypass["level"] == "critical"
          and b_bypass["title"] != b_lock["title"])

    b_soak = tg.banner({"state": "soaking", "age_s": 1, "stale": False,
                        "episodes_in_window": 1, "reason": None})
    check(20, "banner: soaking -> info, not critical (recovering, not broken)",
          b_soak and b_soak["level"] == "info")

    # ── MUTATION: prove gates 1-3 are real ───────────────────────────────────
    print()
    print("  MUTATION GATES")
    orig_ns = dm.NAMESPACES["tier2_gate"]
    try:
        dm.NAMESPACES["tier2_gate"] = {"tables": ("tier2_gate_state",)}
        check(21, "MUTATION: dropping the events grant is CAUGHT",
              not dm.allowed("tier2_gate", "tier2_gate_events"))
        dm.NAMESPACES["tier2_gate"] = {"prefixes": ("tier2_",)}
        check(22, "MUTATION: relaxing to a `tier2_` prefix is CAUGHT",
              dm.allowed("tier2_gate", "tier2_gate_secrets"),
              "prefix grant would wrongly permit an unlisted table")
    finally:
        dm.NAMESPACES["tier2_gate"] = orig_ns
    check(23, "namespace restored after mutation",
          dm.allowed("tier2_gate", "tier2_gate_events")
          and not dm.allowed("tier2_gate", "tier2_gate_secrets"))

    print()
    passed = sum(1 for _n, _t, ok in RESULTS if ok)
    failed = [(n, t) for n, t, ok in RESULTS if not ok]
    print("=" * 78)
    print("RESULT: %d/%d checks passed" % (passed, len(RESULTS)))
    for n, t in failed:
        print("  FAILED %2d. %s" % (n, t))
    print("=" * 78)
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
