"""Validation for mem_appliance — the appliance half of the RAM budget work.

Run:  python3 alert_manager/test_mem_appliance.py

Two properties carry the weight here, and both are about clamd:

  1. clamd is BUDGETED (it is the dominant consumer; headroom maths that ignored
     it would be meaningless), and
  2. clamd is EXEMPT FROM RECOVERY ACTION (it is the largest consumer by design,
     so any size-ranked recovery picks it first every time — and throttling or
     killing it disarms malware scanning, which would let an attacker who can
     induce memory pressure make the appliance stand its own AV down).

Getting either half alone is a defect: budgeted-but-not-exempt builds the attack,
exempt-but-not-budgeted makes the headroom numbers fiction. So they are tested as
a pair, and the "still reports a verdict" case is tested separately, because the
lazy way to implement an exemption is to filter it out of the results entirely —
which would hide the biggest consumer from the view built to watch memory.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alert_manager import mem_appliance as ma  # noqa: E402

_failures = []


def check(label, got, want):
    if got != want:
        _failures.append("%s: got %r, want %r" % (label, got, want))
        print("  FAIL  %s: got %r, want %r" % (label, got, want))
    else:
        print("  ok    %s" % label)


# ── the clamd pairing ────────────────────────────────────────────────────────

def test_clamd_is_budgeted_and_exempt():
    print("\n[clamd: budgeted AND recovery-exempt — both halves required]")
    check("budgeted", "clamav-daemon" in ma.APPLIANCE_BUDGETS, True)
    check("recovery-exempt", "clamav-daemon" in ma.RECOVERY_EXEMPT, True)
    # CONTROL: the exemption is narrow, not a blanket that would spare everything.
    check("suricata is NOT exempt", "suricata" in ma.RECOVERY_EXEMPT, False)
    check("dashboard is NOT exempt", "dashboard" in ma.RECOVERY_EXEMPT, False)
    check("exactly one exemption", len(ma.RECOVERY_EXEMPT), 1)


def test_exempt_component_still_reports_a_verdict():
    """The lazy implementation — filtering it out — would hide it entirely."""
    print("\n[an exempt component is annotated, NOT filtered from the results]")
    procmem, membudget = ma.load_memory_modules()
    sample = {"state": "ok", "uss_state": "measured", "total_ram_mb": 8192.0,
              "components": {
                  "clamav-daemon": {"rss_mb": 5000.0, "uss_mb": 4800.0,
                                    "uss_complete": True, "pids": [1],
                                    "proc_count": 1},
                  "dashboard": {"rss_mb": 900.0, "uss_mb": 880.0,
                                "uss_complete": True, "pids": [2],
                                "proc_count": 1}}}
    v = membudget.evaluate(sample, ma.APPLIANCE_BUDGETS)
    for name, c in v["components"].items():
        c["recovery_exempt"] = name in ma.RECOVERY_EXEMPT
    v["actionable_breaches"] = [n for n in v["breaches"] if n not in ma.RECOVERY_EXEMPT]
    v["exempt_breaches"] = [n for n in v["breaches"] if n in ma.RECOVERY_EXEMPT]

    check("clamd still present in components", "clamav-daemon" in v["components"], True)
    check("clamd's breach IS reported", "clamav-daemon" in v["breaches"], True)
    check("...but is not actionable", v["actionable_breaches"], ["dashboard"])
    check("...and is visible as an exempt breach", v["exempt_breaches"],
          ["clamav-daemon"])
    check("clamd flagged exempt",
          v["components"]["clamav-daemon"]["recovery_exempt"], True)
    check("dashboard flagged not exempt",
          v["components"]["dashboard"]["recovery_exempt"], False)


# ── the classifier ───────────────────────────────────────────────────────────

def test_unit_resolution_from_cgroup(tmpdir=None):
    print("\n[systemd unit resolution, and never inventing one]")
    import tempfile
    root = tempfile.mkdtemp()

    def _mk(pid, text):
        d = os.path.join(root, str(pid))
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "cgroup"), "w").write(text)

    _mk(101, "0::/system.slice/dashboard.service\n")                  # v2
    _mk(102, "1:name=systemd:/system.slice/hw-monitor.service\n")     # v1
    _mk(103, "0::/system.slice/getty@tty1.service\n")                 # templated
    _mk(104, "0::/user.slice/user-1000.slice/session-2.scope\n")      # not a unit

    check("cgroup v2", ma.unit_for_pid(101, proc_root=root), "dashboard")
    check("cgroup v1", ma.unit_for_pid(102, proc_root=root), "hw-monitor")
    check("template instance collapses to its base",
          ma.unit_for_pid(103, proc_root=root), "getty")
    check("a scope is not a unit -> None", ma.unit_for_pid(104, proc_root=root), None)
    check("missing pid -> None, never invented",
          ma.unit_for_pid(999999, proc_root=root), None)


def test_fallback_is_marked_as_less_reliable():
    print("\n[name-attributed components are prefixed so they cannot pass as units]")
    import tempfile
    root = tempfile.mkdtemp()
    c = ma.classify_process({"pid": 424242, "name": "weird"}, proc_root=root)
    check("prefixed", c, "proc:weird")
    check("does not look like a unit", c.endswith(".service"), False)
    check("no name and no unit -> unclassified",
          ma.classify_process({"pid": 424242}, proc_root=root), "unclassified")


# ── budget-table coherence across re-baselining ──────────────────────────────

def test_table_is_coherent_at_every_plausible_baseline():
    print("\n[the table stays satisfiable at 4 / 8 / 16 GB]")
    _, membudget = ma.load_memory_modules()
    for gb in (4, 8, 16, 32):
        v = membudget.validate_budgets(ma.APPLIANCE_BUDGETS, gb * 1024.0)
        check("coherent at %d GB" % gb, v["ok"], True)
        if not v["ok"]:
            print("        %s" % "; ".join(v["problems"]))


def test_every_budget_records_its_basis():
    """A number with no recorded observation is a guess that will never be revisited."""
    print("\n[every budget entry names the measurement it came from]")
    missing = [k for k, v in ma.APPLIANCE_BUDGETS.items() if not v.get("basis")]
    check("all entries carry a basis", missing, [])


# ── the loading design claim ─────────────────────────────────────────────────

def test_generic_modules_load_without_polluting_sys_path():
    print("\n[loading the generic modules does not put nemesis_agent on sys.path]")
    before = list(sys.path)
    procmem, membudget = ma.load_memory_modules()
    added = [p for p in sys.path if p not in before]
    check("nothing added to sys.path", added, [])
    check("procmem really loaded", hasattr(procmem, "sample_processes"), True)
    check("membudget really loaded", hasattr(membudget, "evaluate"), True)
    # CONTROL: prove we loaded the real modules, not stubs that happen to exist.
    check("procmem exposes its states", procmem.STATE_UNAVAILABLE, "unavailable")


def test_self_test_passes_here():
    print("\n[the adapter's own premise-proof passes on this host]")
    st = ma.self_test()
    for f in st["findings"]:
        print("        finding: %s" % f)
    check("self_test ok", st["ok"], True)


# ── rung availability ────────────────────────────────────────────────────────

def test_availability_matches_the_audit():
    print("\n[availability reflects what was actually audited, not assumed]")
    am = ma.availability_map()
    check("suricata: alert+restart only", sorted(am["suricata"]),
          ["alert", "restart"])
    check("dashboard: alert only (operator decision)", sorted(am["dashboard"]),
          ["alert"])
    check("hw-monitor has a real throttle", "throttle" in am["hw-monitor"], True)
    check("device-scanner throttle honestly absent",
          "throttle" in am["device-scanner"], False)


def test_every_absent_rung_states_why():
    """An absent rung with no reason is indistinguishable from an oversight."""
    print("\n[every absent rung carries a reason]")
    problems = []
    for comp, entry in ma.RUNG_AVAILABILITY.items():
        for rung in ("throttle", "abort", "restart", "alert"):
            if rung not in entry["available"] and not entry["why_absent"].get(rung):
                problems.append("%s/%s" % (comp, rung))
    check("no unexplained absences", problems, [])
    check("CONTROL a reason is actually retrievable",
          bool(ma.why_rung_absent("suricata", "throttle")), True)
    check("CONTROL an available rung has no reason",
          ma.why_rung_absent("hw-monitor", "throttle"), None)


def test_alert_is_available_everywhere():
    """Nothing may be invisible: every component can at least be alerted on."""
    print("\n[every component keeps ALERT — nothing becomes silent]")
    missing = [c for c, e in ma.RUNG_AVAILABILITY.items()
               if "alert" not in e["available"]]
    check("alert present for all", missing, [])


def test_availability_covers_every_budgeted_component():
    print("\n[every budgeted component has an availability entry]")
    missing = sorted(set(ma.APPLIANCE_BUDGETS) - set(ma.RUNG_AVAILABILITY))
    check("no budgeted component left undeclared", missing, [])


def test_ladder_consumes_the_map_end_to_end():
    print("\n[the ladder actually honours the appliance's availability map]")
    import importlib.util, os as _os
    root = _os.path.dirname(_os.path.dirname(_os.path.abspath(ma.__file__)))
    spec = importlib.util.spec_from_file_location(
        "ml_t", _os.path.join(root, "nemesis_agent", "memladder.py"))
    ml = importlib.util.module_from_spec(spec); spec.loader.exec_module(ml)

    def V(name):
        return {"state": "ok", "components": {name: {
            "verdict": "breach", "observed_mb": 900.0, "budget_mb": 100.0,
            "basis": "uss", "detail": "t"}}}

    st, acts = ml.new_state(), []
    for _ in range(20):
        st, a = ml.decide(V("suricata"), st, ml.DEFAULT_POLICY,
                          available=ma.availability_map())
        acts.extend(a)
    climbed = [x["rung"] for x in acts if x["kind"] == "escalate"]
    check("suricata skips throttle and abort", climbed, ["alert", "restart"])
    check("the skip is recorded",
          [x for x in acts if x["rung"] == "restart"][0]["skipped_rungs"],
          ["throttle", "abort"])


def test_throttle_executor_end_to_end():
    """The ladder's THROTTLE rung EXECUTES: a real escalation publishes intent a
    throttle-aware service would read, respects RUNG_AVAILABILITY (clamd never
    throttled), refreshes while breaching, and clears on recovery."""
    print("\n[throttle executor: real escalation -> publish -> refresh -> clear]")
    import os, tempfile                                       # noqa: PLC0415
    import database, data_manager, throttle                   # noqa: PLC0415
    ladder = ma.load_ladder()
    tmp = tempfile.mkdtemp(prefix="nem-execT-")
    database.DB_PATH = os.path.join(tmp, "alerts.db")
    database.init_throttle_tables()
    dm = data_manager.DataManager(database.DB_PATH)
    AVAIL, EXEMPT = ma.availability_map(), ma.RECOVERY_EXEMPT

    def breach(names):
        return {"state": "ok", "components": {n: {"verdict": "breach",
                "observed_mb": 900, "budget_mb": 500, "basis": "pct_of_total"}
                for n in names}}
    def okv(names):
        return {"state": "ok", "components": {n: {"verdict": "ok",
                "observed_mb": 100, "budget_mb": 500, "basis": "pct_of_total"}
                for n in names}}
    def factor(comp, now):
        return throttle.ThrottleHandle(comp, dm, now_fn=lambda: now).current_factor()

    state, T = ladder.new_state(), 100000.0
    for i in range(1, 5):                        # 4 breaches -> THROTTLE
        state, _ = ladder.decide(breach(["hw-monitor", "clamav-daemon"]),
                                 state, exempt=EXEMPT, available=AVAIL)
        ma.execute_ladder_throttle(state, dm, ladder=ladder, now=T + i * 300)
    check("hw-monitor throttled -> reads 4x", factor("hw-monitor", T + 1300), 4.0)
    check("clamd exempt+unavailable -> never throttled",
          factor("clamav-daemon", T + 1300), throttle.NORMAL)

    for i in range(6):                           # recover_after -> drops below THROTTLE
        state, _ = ladder.decide(okv(["hw-monitor"]), state, exempt=EXEMPT, available=AVAIL)
        ma.execute_ladder_throttle(state, dm, ladder=ladder, now=T + (6 + i) * 300)
    check("recovery clears intent -> back to normal", factor("hw-monitor", T + 9000),
          throttle.NORMAL)

    # CONTROL: a throttle-UNAVAILABLE component forced to rung THROTTLE is NOT published.
    forced = {"components": {"clamav-daemon": {"rung": ladder.RUNG_THROTTLE,
              "breach_streak": 9, "ok_streak": 0}}}
    ma.execute_ladder_throttle(forced, dm, ladder=ladder, now=T + 9500)
    check("availability defense: forced clamd THROTTLE not published",
          factor("clamav-daemon", T + 9600), throttle.NORMAL)


def test_throttle_status_three_way():
    """UNTHROTTLED (excluded by design) must be DISTINCT from UNAVAILABLE (not wired
    yet) and from THROTTLEABLE — a reader must never mistake one for another."""
    print("\n[throttle status: throttleable / unthrottled / unavailable are distinct]")
    # structural exclusions -> UNTHROTTLED
    for c in ("clamav-daemon", "suricata", "dashboard"):
        check("%s is UNTHROTTLED (by design)" % c, ma.throttle_status(c), ma.THROTTLE_UNTHROTTLED)
    # REQUIRED DETECTORS -> UNTHROTTLED (2026-08-22). Both previously read
    # differently and were changed deliberately, so the expectations here move
    # with them rather than being loosened:
    #   * malware-canary was UNAVAILABLE ("loop has no interval knob yet"). It has
    #     had one all along -- `canary_poll_seconds`, now bounded 5..300s -- so the
    #     old note would have led someone to WIRE throttle into a required
    #     detector.
    #   * diagnostics-watcher was THROTTLEABLE and genuinely registered. The
    #     throttle multiplied its bounded 900s interval by up to MAX_FACTOR=8,
    #     giving a 7,200s gap -- past the ceiling whose own rationale is that an
    #     outage must not fall entirely between two samples.
    # A ceiling another subsystem may stretch is not a ceiling.
    for c in ("diagnostics-watcher", "malware-canary"):
        check("%s is UNTHROTTLED (required detector, bounded cadence)" % c,
              ma.throttle_status(c), ma.THROTTLE_UNTHROTTLED)
    # not-wired-yet -> UNAVAILABLE (the generic case), NOT unthrottled. Kept as a
    # CONTROL: it proves UNAVAILABLE still exists and did not collapse into
    # UNTHROTTLED when the two entries above moved.
    for c in ("device-scanner",):
        check("%s is UNAVAILABLE (pending a knob), not unthrottled" % c,
              ma.throttle_status(c), ma.THROTTLE_UNAVAILABLE)
    # real interval -> THROTTLEABLE
    for c in ("hw-monitor", "watchdog", "alert-watcher"):
        check("%s is THROTTLEABLE" % c, ma.throttle_status(c), ma.THROTTLE_THROTTLEABLE)
    # the three statuses are genuinely different strings
    check("the three statuses are distinct",
          len({ma.THROTTLE_THROTTLEABLE, ma.THROTTLE_UNTHROTTLED, ma.THROTTLE_UNAVAILABLE}), 3)


def test_throttle_status_consistency_and_guard():
    """The UNTHROTTLED set must not contradict RUNG_AVAILABILITY, and the
    registration guard must refuse exactly the structural exclusions."""
    print("\n[throttle status: consistency + register guard]")
    # no UNTHROTTLED component may ALSO be marked throttle-available (contradiction)
    for c in ma.THROTTLE_UNTHROTTLED_COMPONENTS:
        entry = ma.RUNG_AVAILABILITY.get(c, {"available": frozenset()})
        check("%s is not simultaneously throttle-available" % c,
              "throttle" in entry["available"], False)
    # the components that DO register (throttleable) are disjoint from UNTHROTTLED
    throttleable = {c for c in ma.RUNG_AVAILABILITY
                    if "throttle" in ma.RUNG_AVAILABILITY[c]["available"]}
    check("registering(throttleable) set is disjoint from UNTHROTTLED",
          bool(throttleable & ma.THROTTLE_UNTHROTTLED_COMPONENTS), False)
    # the guard: UNTHROTTLED components raise; throttleable pass
    import mem_appliance as _ma
    raised = False
    try:
        _ma.assert_throttle_registerable("clamav-daemon")
    except ValueError:
        raised = True
    check("guard REFUSES an UNTHROTTLED component (loud, not silent)", raised, True)
    ok = True
    try:
        _ma.assert_throttle_registerable("hw-monitor")
    except ValueError:
        ok = False
    check("guard PASSES a throttleable component", ok, True)
    # CONTROL: a not-yet-wired component is allowed to register later (not refused)
    passed = True
    try:
        _ma.assert_throttle_registerable("device-scanner")
    except ValueError:
        passed = False
    check("CONTROL: UNAVAILABLE (pending) is NOT refused by the guard", passed, True)


def test_throttle_status_report_and_log_line():
    """Directly exercise throttle_status_report() and log_throttle_status() on the
    DEFAULT now=None path — the exact call /api/throttle-status makes, and the path
    a missing `import time` crashed on (the earlier tests only covered the static
    throttle_status()/throttle_status_map(), never these DB-backed surfaces)."""
    print("\n[throttle status surface: report + log line, default now=None]")
    import os, sqlite3, tempfile, io, logging                # noqa: PLC0415
    import database, data_manager, throttle                  # noqa: PLC0415
    tmp = tempfile.mkdtemp(prefix="nem-tsr-")
    database.DB_PATH = os.path.join(tmp, "alerts.db")
    database.init_throttle_tables()
    dm = data_manager.DataManager(database.DB_PATH)
    throttle.publish_throttle("hw-monitor", 4.0, 600, "pressure", dm)   # live intent
    throttle.register_throttle_aware("watchdog", dm)
    conn = sqlite3.connect(database.DB_PATH)

    # DEFAULT now=None — this is what crashed before `import time`.
    rep = ma.throttle_status_report(conn)                    # no `now=` -> time.time()
    check("report returns without crashing on default now", isinstance(rep, dict), True)
    check("report distinguishes UNTHROTTLED from unavailable",
          (rep["clamav-daemon"]["status"], rep["device-scanner"]["status"]),
          (ma.THROTTLE_UNTHROTTLED, ma.THROTTLE_UNAVAILABLE))
    check("report shows the live throttle on hw-monitor", rep["hw-monitor"]["throttled"], True)

    # log_throttle_status also defaults now=None -> same path
    buf = io.StringIO(); h = logging.StreamHandler(buf); h.setLevel(logging.INFO)
    ma.log.addHandler(h); ma.log.setLevel(logging.INFO)
    try:
        rep2 = ma.log_throttle_status(conn)                 # no `now=`
    finally:
        ma.log.removeHandler(h)
    check("log_throttle_status returns without crashing on default now",
          isinstance(rep2, dict), True)
    check("log line names UNTHROTTLED-by-design",
          "UNTHROTTLED-by-design" in buf.getvalue(), True)

    # graceful: missing throttle tables -> static-only, still default now=None, no crash
    c2 = sqlite3.connect(":memory:")
    rep3 = ma.throttle_status_report(c2)                     # no `now=`, no tables
    check("static-only when tables absent (no crash on default now)",
          rep3["clamav-daemon"]["status"], ma.THROTTLE_UNTHROTTLED)
    conn.close()


def test_run_ladder_cycle_persists_and_accumulates():
    """The production loop: run_ladder_cycle persists state across cycles and
    accumulates + resolves shadow records — the promotion clock the ABORT/RESTART
    gates depend on. Without a committed test this loop could silently stop driving."""
    print("\n[run_ladder_cycle: state persists, shadow records accumulate + resolve]")
    import os, sqlite3, tempfile                             # noqa: PLC0415
    import database, data_manager                            # noqa: PLC0415
    tmp = tempfile.mkdtemp(prefix="nem-runladder-")
    database.DB_PATH = os.path.join(tmp, "a.db")
    database.init_memory_recovery_tables(); database.init_throttle_tables()
    dm = data_manager.DataManager(database.DB_PATH)
    conn = sqlite3.connect(database.DB_PATH)

    _orig = ma.sample_and_evaluate
    ma.sample_and_evaluate = lambda repo_root=None: {"state": "ok", "components":
        {"hw-monitor": {"verdict": "breach", "observed_mb": 900, "budget_mb": 100}}}
    try:
        for _ in range(8):                    # abort_after=8 -> a SHADOW rung
            ma.run_ladder_cycle(dm, conn)
        seq = conn.execute("SELECT sample_seq FROM mem_ladder_state WHERE id=1").fetchone()[0]
        check("state persisted across cycles (seq=8)", seq, 8)
        rows = conn.execute("SELECT rung FROM mem_shadow_records").fetchall()
        check("a SHADOW record accumulated (abort)", any(r[0] == "abort" for r in rows), True)
        state, _ = ma._load_ladder_state(conn, ma.load_ladder())
        check("streak survives reload (clock not reset)",
              state["components"]["hw-monitor"]["breach_streak"] >= 8, True)
        for _ in range(7):                    # accrue follow-ups -> resolve
            ma.run_ladder_cycle(dm, conn)
        outcome = conn.execute("SELECT outcome FROM mem_shadow_records WHERE rung='abort' "
                               "ORDER BY id LIMIT 1").fetchone()[0]
        check("shadow record RESOLVES over cycles (clock advances)", outcome, "correct")
    finally:
        ma.sample_and_evaluate = _orig
        conn.close()


if __name__ == "__main__":
    print("mem_appliance — appliance half of the RAM budget work")
    test_clamd_is_budgeted_and_exempt()
    test_exempt_component_still_reports_a_verdict()
    test_unit_resolution_from_cgroup()
    test_fallback_is_marked_as_less_reliable()
    test_table_is_coherent_at_every_plausible_baseline()
    test_every_budget_records_its_basis()
    test_generic_modules_load_without_polluting_sys_path()
    test_availability_matches_the_audit()
    test_every_absent_rung_states_why()
    test_alert_is_available_everywhere()
    test_availability_covers_every_budgeted_component()
    test_ladder_consumes_the_map_end_to_end()
    test_self_test_passes_here()
    test_throttle_executor_end_to_end()
    test_throttle_status_three_way()
    test_throttle_status_consistency_and_guard()
    test_throttle_status_report_and_log_line()
    test_run_ladder_cycle_persists_and_accumulates()

    print("\n" + "=" * 64)
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  - %s" % f)
        sys.exit(1)
    print("ALL PASS")
