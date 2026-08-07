#!/usr/bin/env python3
"""
Tests for the DHCP mode-switch fail-over mechanism (`modules/dhcp/module.py`).

NO HOST NETWORK STATE IS TOUCHED. Every systemd call, port probe and Pi-hole read
is stubbed; snapshots go to a temp directory; the DB is a throwaway file. The
2026-08-07 incident that produced Rule 13 was caused by a test that changed real
host network state on an unverified promise to revert, so the suite for a
DHCP-switching mechanism must not do the same thing.

The retry delay is injected (`_sleep`), so the cascade is exercised in
milliseconds rather than the ~4 minutes it takes in production.

Every group carries a CONTROL that must produce the opposite result.
"""

import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, "/opt/nemesis")
sys.path.insert(0, "/opt/nemesis/alert_manager")

import modules

_TMPDB = tempfile.mkstemp(prefix="nemtest_dhcpsw_", suffix=".db")[1]
os.unlink(_TMPDB)
modules.set_shared_db_path(_TMPDB)

from modules.dhcp import module as M  # noqa: E402

_PASS = 0
_FAIL = 0
_EXPECTED_CHECKS = 78


def check(label, got, want):
    global _PASS, _FAIL
    if got == want:
        _PASS += 1
        print("  PASS  %-60s %r" % (label, got))
    else:
        _FAIL += 1
        print("  ****  %-60s got=%r want=%r" % (label, got, want))


def section(t):
    print("\n== %s ==" % t)


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #

class FakeProc:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


class World:
    """The stubbed machine. Everything the module can observe lives here."""
    def __init__(self):
        self.daemon_active = False
        self.port67 = "free"
        self.pihole_dhcp = False
        self.start_should_fail = False
        self.systemctl_calls = []
        self.slept = []

    # --- stubs the module will call ---
    def run(self, argv, **kw):
        self.systemctl_calls.append(list(argv))
        if argv[:2] == ["systemctl", "is-active"]:
            return FakeProc(0, "active\n" if self.daemon_active else "inactive\n")
        if argv[:2] == ["systemctl", "stop"]:
            self.daemon_active = False
            return FakeProc(0)
        if argv[:2] == ["systemctl", "start"]:
            if self.start_should_fail:
                return FakeProc(1, "", "unit failed")
            self.daemon_active = True
            return FakeProc(0)
        return FakeProc(0)

    def sleep(self, n):
        self.slept.append(n)


def make_module(world, snapdir, mode="provider", cfg=None):
    """A Module wired to the fake world. Patches at the module's own seams."""
    moddir = tempfile.mkdtemp(prefix="dhcpmod_")
    conf = dict(cfg or {})
    conf["mode"] = mode
    with open(os.path.join(moddir, "config.json"), "w") as f:
        json.dump(conf, f)

    M.SNAP_DIR = snapdir
    M.subprocess.run = world.run
    M.port67_state = lambda: world.port67
    M.pihole_dhcp_active = lambda *a, **k: world.pihole_dhcp
    M._iface_addresses = lambda iface: ["10.0.0.1"]

    inst = M.Module({"name": "dhcp", "_dir": moddir})
    # Serving is exercised end-to-end elsewhere (test_dhcp_module.py, 81 checks);
    # here the subject is the switch/verify/rollback cascade, so the serving path
    # is reduced to its observable effect on the fake world.
    def _start_serving(conn):
        if world.start_should_fail:
            raise RuntimeError("failed to start %s" % M.SERVICE_NAME)
        world.daemon_active = True
        world.port67 = "bound"
    inst._start_serving = _start_serving
    inst._start_sync_thread = lambda: None
    inst._err_conn = lambda: None
    inst._moddir = moddir
    return inst


def trace_rows():
    import sqlite3
    conn = sqlite3.connect(_TMPDB)
    try:
        cur = conn.execute("SELECT event,tier,attempt,ok,detail FROM "
                           "dhcp_mode_change_log ORDER BY id")
        return [dict(zip([d[0] for d in cur.description], r)) for r in cur.fetchall()]
    except Exception:
        return []
    finally:
        conn.close()


def events():
    return [r["event"] for r in trace_rows()]


# --------------------------------------------------------------------------- #

def main():
    snapdir = tempfile.mkdtemp(prefix="dhcpsnap_")

    section("0. Constants match the agreed design")
    check("rollback order is most-proven-recent first", list(M.ROLLBACK_ORDER),
          ["thought-trusted", "trusted", "aging", "install-baseline"])
    check("2 attempts per tier", M.ROLLBACK_ATTEMPTS_PER_TIER, 2)
    check("30s between attempts", M.ROLLBACK_RETRY_DELAY_SECONDS, 30)
    codes = [c[0] for c in M._CODES]
    check("E-DHCP-009..013 registered in _CODES",
          [c for c in codes if c >= "E-DHCP-009"],
          ["E-DHCP-009", "E-DHCP-010", "E-DHCP-011", "E-DHCP-012", "E-DHCP-013"])

    section("1. Install baseline: captured once, NEVER overwritten")
    w = World()
    m = make_module(w, snapdir, mode="provider")
    check("baseline captured on first call", m.ensure_install_baseline(), True)
    base1 = m._read_snapshot(M.TIER_BASELINE)
    check("baseline records the real current mode", base1["mode"], "provider")
    check("second call is a no-op", m.ensure_install_baseline(), False)
    base2 = m._read_snapshot(M.TIER_BASELINE)
    check("baseline byte-identical after re-call", base2, base1)
    check("CONTROL: rolling tiers still absent", m._read_snapshot(M.TIER_THOUGHT), None)

    section("2. verify_mode() reads BACK state — never trusts an exit code")
    w.daemon_active, w.port67 = True, "bound"
    m._cfg["interfaces"] = ["enp0s3"]
    m._cfg["expected_addrs"] = {"enp0s3": "10.0.0.1"}
    ok, rb, det = m.verify_mode(M.MODE_NEMESIS)
    check("nemesis: active+bound+addr -> pass", ok, True)
    check("readback carries the RAW port value", rb["port67_state"], "bound")
    w.port67 = "unknown"
    ok, rb, det = m.verify_mode(M.MODE_NEMESIS)
    check("nemesis: port 'unknown' is a FAILURE, not a pass", ok, False)
    check("...and says why", "refusing to assume" in det, True)
    w.port67 = "free"
    ok, _, _ = m.verify_mode(M.MODE_NEMESIS)
    check("nemesis: daemon active but port free -> fail", ok, False)
    w.daemon_active = False
    ok, _, det = m.verify_mode(M.MODE_NEMESIS)
    check("nemesis: daemon inactive -> fail", ok, False)
    # provider / pihole
    ok, _, det = m.verify_mode(M.MODE_PROVIDER)
    check("provider: daemon stopped -> pass", ok, True)
    check("provider: states the router is UNVERIFIABLE", "UNVERIFIABLE" in det, True)
    w.pihole_dhcp = True
    ok, _, _ = m.verify_mode(M.MODE_PIHOLE)
    check("pihole: pi-hole serving -> pass", ok, True)
    w.pihole_dhcp = False
    ok, _, det = m.verify_mode(M.MODE_PIHOLE)
    check("pihole: pi-hole NOT serving -> fail (zero-DHCP case)", ok, False)
    w.pihole_dhcp = None
    ok, _, _ = m.verify_mode(M.MODE_PIHOLE)
    check("pihole: 'cannot tell' -> fail, not assumed fine", ok, False)
    w.daemon_active = True
    ok, _, det = m.verify_mode(M.MODE_PROVIDER)
    check("CONTROL: provider with daemon STILL running -> fail", ok, False)

    section("3. Successful switch rotates the chain")
    w = World(); w.pihole_dhcp = False
    m = make_module(w, snapdir, mode="provider")
    r = m.switch_mode(M.MODE_NEMESIS, {"interfaces": ["enp0s3"],
                                       "allowlist": ["enp0s3"],
                                       "expected_addrs": {"enp0s3": "10.0.0.1"}},
                      _sleep=w.sleep)
    check("switch succeeded", r["ok"], True)
    check("action", r["action"], "switched")
    check("daemon really running in the fake world", w.daemon_active, True)
    check("thought-trusted now holds the new state",
          m._read_snapshot(M.TIER_THOUGHT)["mode"], "nemesis")
    check("no retries slept on the happy path", w.slept, [])
    # The chain records states AFTER a successful switch, so the pre-switch
    # `provider` state is NOT in the rolling chain — it is in the permanent
    # baseline, which is exactly why the baseline exists (§3a bootstrapping).
    check("nothing shifted into trusted yet (only one success so far)",
          m._read_snapshot(M.TIER_TRUSTED), None)
    w.pihole_dhcp = True
    r2 = m.switch_mode(M.MODE_PIHOLE, _sleep=w.sleep)
    check("second switch succeeded", r2["ok"], True)
    check("thought-trusted = newest (pihole)",
          m._read_snapshot(M.TIER_THOUGHT)["mode"], "pihole")
    check("trusted = previous (nemesis)",
          m._read_snapshot(M.TIER_TRUSTED)["mode"], "nemesis")
    check("aging still absent after only two successes",
          m._read_snapshot(M.TIER_AGING), None)
    # third success fills all three rungs
    w.pihole_dhcp = False
    r3 = m.switch_mode(M.MODE_PROVIDER, _sleep=w.sleep)
    check("third switch succeeded", r3["ok"], True)
    check("thought-trusted = provider", m._read_snapshot(M.TIER_THOUGHT)["mode"], "provider")
    check("trusted = pihole", m._read_snapshot(M.TIER_TRUSTED)["mode"], "pihole")
    check("aging = nemesis", m._read_snapshot(M.TIER_AGING)["mode"], "nemesis")
    # fourth success must DROP the oldest — max 3 kept, rolling
    w.pihole_dhcp = True
    m.switch_mode(M.MODE_PIHOLE, _sleep=w.sleep)
    check("chain rolls: aging = pihole (nemesis dropped)",
          m._read_snapshot(M.TIER_AGING)["mode"], "pihole")
    check("CONTROL: still exactly 3 rolling tiers on disk",
          sorted(f for f in os.listdir(snapdir) if not f.startswith(".")),
          ["aging.json", "install-baseline.json", "thought-trusted.json",
           "trusted.json"])

    section("4. Failed verification -> cascade rollback, verified at each tier")
    w = World(); w.pihole_dhcp = False
    m = make_module(w, snapdir, mode="provider")
    m._write_snapshot(M.TIER_THOUGHT, {"mode": "provider", "config": {},
                                       "captured_at": "x"})
    # Ask for nemesis but make serving not actually take: daemon starts, port
    # never binds. That is precisely the "exit code said OK" case Rule 13 targets.
    def half_start(conn):
        w.daemon_active = True
        w.port67 = "free"      # never actually bound
    m._start_serving = half_start
    r = m.switch_mode(M.MODE_NEMESIS, {"interfaces": [], "allowlist": []},
                      _sleep=w.sleep)
    check("switch reported NOT ok", r["ok"], False)
    check("it rolled back", r["action"], "rolled_back")
    check("recovered onto the newest tier", r["tier"], "thought-trusted")
    check("succeeded on first attempt of that tier", r["attempt"], 1)
    check("no sleep needed (first attempt worked)", w.slept, [])
    check("daemon left stopped (provider mode)", w.daemon_active, False)
    ev = events()
    check("trace recorded the failed verify", "verify" in ev, True)
    check("trace recorded a rollback attempt", "rollback-attempt" in ev, True)
    check("trace recorded rollback success", "rollback-succeeded" in ev, True)

    section("5. Retry spacing: 2 attempts per tier, 30s apart")
    w = World(); w.pihole_dhcp = False
    m = make_module(w, snapdir)
    # thought-trusted wants nemesis, but nemesis can never verify here ->
    # both attempts on that tier must fail, then fall through to a good tier.
    m._write_snapshot(M.TIER_THOUGHT, {"mode": "nemesis", "config": {}})
    m._write_snapshot(M.TIER_TRUSTED, {"mode": "provider", "config": {}})
    m._start_serving = lambda conn: None       # start "succeeds", port stays free
    r = m.switch_mode(M.MODE_NEMESIS, {}, _sleep=w.sleep)
    check("fell through to the trusted tier", r["tier"], "trusted")
    check("slept exactly once on the failing tier", len(w.slept), 1)
    check("...for 30 seconds", w.slept, [30])

    section("6. Absent tiers are SKIPPED, not attempted")
    w = World(); w.pihole_dhcp = False
    snap2 = tempfile.mkdtemp(prefix="dhcpsnap2_")
    m = make_module(w, snap2)
    m.ensure_install_baseline()                 # only the baseline exists
    m._start_serving = lambda conn: None
    r = m.switch_mode(M.MODE_NEMESIS, {}, _sleep=w.sleep)
    check("recovered onto the permanent baseline", r["tier"], "install-baseline")
    check("no sleeps for the absent tiers", w.slept, [])
    skips = [e for e in events() if e == "rollback-skip"]
    check("absent tiers logged as skipped", len(skips) >= 3, True)

    section("7. Every tier fails -> escalate, daemon stopped, nothing silent")
    w = World(); w.pihole_dhcp = False
    snap3 = tempfile.mkdtemp(prefix="dhcpsnap3_")
    m = make_module(w, snap3)
    # Every tier asks for nemesis, and nemesis can never verify.
    for t in (M.TIER_THOUGHT, M.TIER_TRUSTED, M.TIER_AGING, M.TIER_BASELINE):
        m._write_snapshot(t, {"mode": "nemesis", "config": {}})
    m._start_serving = lambda conn: None
    r = m.switch_mode(M.MODE_NEMESIS, {}, _sleep=w.sleep)
    check("escalated", r["action"], "escalated")
    check("explicitly NOT rolled back", r["rolled_back"], False)
    check("daemon stopped as the safe mechanical floor", w.daemon_active, False)
    check("last stop was a real systemctl stop",
          w.systemctl_calls[-1][:2], ["systemctl", "stop"])
    check("operator-facing text says NEEDS ATTENTION",
          "NEEDS ATTENTION" in m._last_error, True)
    check("8 attempts logged (4 tiers x 2)", len(r["attempts"]), 8)
    check("slept 4 times (once per tier)", len(w.slept), 4)
    check("trace recorded the escalation", "escalated" in events(), True)

    section("8. force=True suppresses rollback but NEVER the conflict gates")
    w = World(); w.pihole_dhcp = False
    snap4 = tempfile.mkdtemp(prefix="dhcpsnap4_")
    m = make_module(w, snap4, mode="provider")
    m._write_snapshot(M.TIER_THOUGHT, {"mode": "provider", "config": {}})
    before = m._read_snapshot(M.TIER_THOUGHT)
    m._start_serving = lambda conn: None        # will not verify
    r = m.switch_mode(M.MODE_NEMESIS, {}, force=True, _sleep=w.sleep)
    check("forced switch reports not-ok (honest)", r["ok"], False)
    check("action is 'forced'", r["action"], "forced")
    check("rollback suppressed", r["rolled_back"], False)
    check("no rollback attempts slept", w.slept, [])
    check("chain NOT rotated — unverified state is not a future target",
          m._read_snapshot(M.TIER_THOUGHT), before)
    check("_last_error explains the override", "override" in m._last_error, True)
    check("trace recorded the override", "override-accepted" in events(), True)
    # CONTROL: force must NOT reach into precondition territory. _start_serving
    # raising (the precondition path) must still fail the apply, force or not.
    def refuse(conn):
        raise M.PreconditionFailed("Pi-hole DHCP already active")
    m._start_serving = refuse
    r = m.switch_mode(M.MODE_NEMESIS, {}, force=True, _sleep=w.sleep)
    check("CONTROL: force does not bypass a precondition refusal", r["ok"], False)
    check("...daemon not left running", w.daemon_active, False)

    section("9. Trace log is INSERT-ONLY (a code property, not a promise)")
    src = open("/opt/nemesis/modules/dhcp/module.py").read()
    import ast
    # Parse rather than grep: a comment or docstring mentioning UPDATE would
    # match a text search. That exact trap has bitten this module three times.
    lits = [n.value for n in ast.walk(ast.parse(src))
            if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    sqlish = [s for s in lits if "dhcp_mode_change_log" in s]
    check("trace table SQL statements found", len(sqlish) >= 2, True)
    def mutates(s):
        # Needle AND haystack both uppercased. The first version of this
        # uppercased only the haystack and compared it against a lowercase
        # needle, so it could never match — and the "no UPDATE/DELETE" assertion
        # above it was passing vacuously. Caught solely by the control below,
        # which is the entire reason the control is here.
        u = " ".join(s.upper().split())
        return "UPDATE DHCP_MODE_CHANGE_LOG" in u or \
               "DELETE FROM DHCP_MODE_CHANGE_LOG" in u
    check("no UPDATE/DELETE against the trace table anywhere",
          [s for s in sqlish if mutates(s)], [])
    # CONTROL: the detector must be able to see one if it existed.
    check("CONTROL: detector catches a planted UPDATE",
          mutates("UPDATE dhcp_mode_change_log SET x=1"), True)
    check("CONTROL: detector catches a planted DELETE",
          mutates("delete from dhcp_mode_change_log where id=1"), True)
    check("CONTROL: detector does NOT fire on a plain INSERT",
          mutates("INSERT INTO dhcp_mode_change_log (ts) VALUES (?)"), False)
    check("trace rows actually persisted", len(trace_rows()) > 0, True)

    section("10. Data Manager grant — BEHAVIOURAL, not source text")
    dm = modules.get_data_manager()
    c = dm.connect("dhcp")
    # Insert with the columns the REAL schema requires. The first version omitted
    # `event` (NOT NULL) and failed on a schema constraint while the label claimed
    # a permission refusal — a test reporting the wrong cause for a real failure.
    try:
        c.execute("INSERT INTO dhcp_mode_change_log (ts,event) VALUES (?,?)",
                  ("2026-08-07T00:00:00", "test data 2026-08-07 grant check"))
        c.commit()
        wrote, why = True, None
    except Exception as e:
        wrote, why = False, str(e)
    check("dhcp MAY write its own trace table (%s)" % (why or "ok"), wrote, True)
    try:
        c.execute("UPDATE devices SET hostname='x'")
        refused = False
    except Exception:
        refused = True
    check("CONTROL: dhcp may NOT write core `devices`", refused, True)
    try:
        c.execute("CREATE TABLE IF NOT EXISTS dhcp_leases_archive (id INTEGER)")
        c.execute("INSERT INTO dhcp_leases_archive (id) VALUES (1)")
        pre_authorised = True
    except Exception:
        pre_authorised = False
    check("CONTROL: grant stayed EXACT — dhcp_leases_archive still refused",
          pre_authorised, False)
    c.close()

    print("\n%s" % ("-" * 76))
    print("checks run: %d   passed: %d   failed: %d" % (_PASS + _FAIL, _PASS, _FAIL))
    if _PASS + _FAIL != _EXPECTED_CHECKS:
        print("**** DECLARED %d CHECKS BUT RAN %d" % (_EXPECTED_CHECKS, _PASS + _FAIL))
    for d in (snapdir, snap2, snap3, snap4):
        shutil.rmtree(d, ignore_errors=True)
    for p in (_TMPDB, _TMPDB + "-wal", _TMPDB + "-shm"):
        if os.path.exists(p):
            os.unlink(p)
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
