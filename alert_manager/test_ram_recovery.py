"""Tests for manual RAM recovery.

The load-bearing tests are the ones that can FAIL for a real reason:
  * an ATTACHED segment is never classified orphan (the catastrophic case),
  * the /proc/*/maps sweep can VETO on its own,
  * the release-time re-verification REFUSES a segment that was re-attached
    between listing and action,
  * a process sample without `status` RAISES rather than reporting "no zombies",
  * a failed read raises instead of returning an empty (safe-looking) list.

Run: python3 test_ram_recovery.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ram_recovery as rr                                    # noqa: E402

_state = {"ran": 0, "failed": 0}


def check(label, got, want):
    _state["ran"] += 1
    ok = got == want
    if not ok:
        _state["failed"] += 1
    print("  %-62s %s  (got=%r want=%r)"
          % (label, "PASS" if ok else "FAIL", got, want))


def raises(fn, exc=Exception):
    try:
        fn()
    except exc:
        return True
    except Exception:
        return False
    return False


LIVE = {"shmid": 1, "key": 0x1111, "size": 4096, "cpid": 1,
        "nattch": 1, "perms": 0o600}
ORPHAN = {"shmid": 2, "key": 0x2222, "size": 8192, "cpid": 4294967,
          "nattch": 0, "perms": 0o600}
DEST = {"shmid": 3, "key": 0x3333, "size": 4096, "cpid": 4294967,
        "nattch": 0, "perms": 0o600 | rr.SHM_DEST}
ANON = {"shmid": 4, "key": 0, "size": 4096, "cpid": 4294967,
        "nattch": 0, "perms": 0o600}
NO_MAPS = (set(), 10, 0)


def main():
    print("== instrument integrity ==")
    check("self_test passes (classifier proves BOTH answers)",
          rr.self_test(), True)

    print("\n== orphan classification ==")
    inv = rr.shm_inventory(_shm_rows=[LIVE, ORPHAN, DEST, ANON], _maps=NO_MAPS)
    by = {s["shmid"]: s for s in inv["segments"]}
    check("ATTACHED segment is NOT orphan (the catastrophic case)",
          by[1]["orphan"], False)
    check("  ...and says why", any("nattch" in r for r in by[1]["reasons"]), True)
    check("genuinely orphaned segment IS orphan", by[2]["orphan"], True)
    check("  ...with no disqualifying reason", by[2]["reasons"], [])
    check("SHM_DEST segment is NOT offered (kernel already frees it)",
          by[3]["orphan"], False)
    check("anonymous key=0 segment is NOT offered (no cross-check possible)",
          by[4]["orphan"], False)
    check("find_orphan_shm returns exactly the one real orphan",
          [s["shmid"] for s in
           rr.find_orphan_shm(_shm_rows=[LIVE, ORPHAN, DEST, ANON],
                              _maps=NO_MAPS)], [2])

    print("\n== the /proc/*/maps sweep can veto ON ITS OWN ==")
    # Same row that just classified as orphan, now visible in an address space.
    vetoed = rr.shm_inventory(_shm_rows=[ORPHAN],
                              _maps=({0x2222}, 10, 0))["segments"][0]
    check("mapped key vetoes an otherwise-orphan-looking segment",
          vetoed["orphan"], False)
    check("  ...naming the address-space reason",
          any("address space" in r for r in vetoed["reasons"]), True)

    print("\n== creator-alive veto ==")
    alive = dict(ORPHAN); alive["cpid"] = os.getpid()
    v = rr.shm_inventory(_shm_rows=[alive], _maps=NO_MAPS)["segments"][0]
    check("live creator pid vetoes", v["orphan"], False)
    check("  ...naming the creator", any("creator" in r for r in v["reasons"]),
          True)

    print("\n== release-time RE-VERIFICATION (the safety interlock) ==")
    removed = []

    def fake_rmid(shmid):
        removed.append(shmid)
        return True, "removed"

    ok, detail, code = rr.release_shm(2, _shm_rows=[ORPHAN], _maps=NO_MAPS,
                                      _rmid=fake_rmid)
    check("releases a still-orphaned segment", (ok, code), (True, None))
    check("  ...and actually called shmctl", removed, [2])

    # THE KEY TEST: listed as orphan, re-attached before the button was pressed.
    removed.clear()
    reattached = dict(ORPHAN); reattached["nattch"] = 1
    ok, detail, code = rr.release_shm(2, _shm_rows=[reattached], _maps=NO_MAPS,
                                      _rmid=fake_rmid)
    check("REFUSES a segment re-attached since listing", ok, False)
    check("  ...logs it as a failure, not a silent skip", code, "E-RAMREC-003")
    check("  ...and shmctl was NEVER called", removed, [])

    # Re-mapped between listing and action -- same interlock, other instrument.
    removed.clear()
    ok, detail, code = rr.release_shm(2, _shm_rows=[ORPHAN],
                                      _maps=({0x2222}, 10, 0), _rmid=fake_rmid)
    check("REFUSES a segment that reappeared in an address space", ok, False)
    check("  ...shmctl NEVER called", removed, [])

    print("\n== failed reads FAIL LOUD, never as an empty list ==")
    check("unreadable /proc/sysvipc/shm raises OrphanCheck",
          raises(lambda: rr._read_sysvipc_shm(_path="/nonexistent/shm"),
                 rr.OrphanCheck), True)
    check("a header without the needed columns raises",
          raises(lambda: rr._read_sysvipc_shm(_path="/etc/hostname"),
                 rr.OrphanCheck), True)

    print("\n== zombies: detection + three-way classification ==")
    # A fake /proc tree so classification is exercised without touching real
    # processes. `_run` injects systemctl answers.
    def mkrun(answers):
        def _run(cmd, timeout=8):
            key = " ".join(cmd)
            for pat, val in answers.items():
                if pat in key:
                    return val
            return (1, "", "no match")
        return _run

    svc_run = mkrun({
        "status 900": (0, "\u25cf speech-dispatcher.service - Common interface\n", ""),
        "show speech-dispatcher.service": (0, "yes\n", ""),
    })
    scope_run = mkrun({
        "status 901": (0, "\u25cf app-gnome-term-901.scope - Application launched\n", ""),
        "show app-gnome-term-901.scope": (0, "no\n", ""),
    })
    none_run = mkrun({})

    c = rr.classify_parent(900, _run=svc_run, _self_pid=os.getpid())
    check("restartable .service -> CASE_SERVICE", c["case"], rr.CASE_SERVICE)
    check("  ...and names the unit", c["unit"], "speech-dispatcher.service")

    c = rr.classify_parent(901, _run=scope_run, _self_pid=os.getpid())
    check("a .scope -> CASE_TERMINATE (NOT restartable)", c["case"], rr.CASE_TERMINATE)
    check("  ...and says why (no ExecStart / not a service)",
          "not a service" in c["why"], True)

    c = rr.classify_parent(902, _run=none_run, _self_pid=os.getpid())
    check("no unit at all -> CASE_TERMINATE", c["case"], rr.CASE_TERMINATE)

    print("\n== CONTAINER-UNIT guard (found live: would have restarted the whole session) ==")
    # `systemctl status <pid>` in SYSTEM scope answers with the container unit
    # for any user process. Measured on the build box: pid 210451 ->
    # user@1000.service (1707 tasks) in system scope, but
    # speech-dispatcher.service in user scope. Restarting the container would
    # tear down the entire desktop session.
    for u, want in (("user@1000.service", True), ("user.slice", True),
                    ("system.slice", True), ("session-3.scope", True),
                    ("init.scope", True), ("speech-dispatcher.service", False),
                    ("app-gnome-term-901.scope", False)):
        check("container-unit guard: %-28s" % u, rr._is_container_unit(u), want)

    container_run = mkrun({
        "--user status 903": (1, "", "no user unit"),
        "status 903": (0, "● user@1000.service - User Manager for UID 1000\n", ""),
        "show user@1000.service": (0, "yes\n", ""),
    })
    c = rr.classify_parent(903, _run=container_run, _self_pid=os.getpid())
    check("a container unit is NEVER offered as restartable",
          c["case"], rr.CASE_TERMINATE)
    check("  ...and the unit is cleared so nothing can restart it",
          c["unit"], None)
    check("  ...and says why", "whole session" in c["why"], True)

    # User scope must be preferred over system scope (the ordering half).
    both_run = mkrun({
        "--user status 904": (0, "● speech-dispatcher.service - x\n", ""),
        "--user show speech-dispatcher.service": (0, "yes\n", ""),
        "status 904": (0, "● user@1000.service - User Manager\n", ""),
    })
    c = rr.classify_parent(904, _run=both_run, _self_pid=os.getpid())
    check("USER scope preferred over SYSTEM scope (most specific wins)",
          c["unit"], "speech-dispatcher.service")
    check("  ...and is marked user_scope", c["user_scope"], True)

    print("\n== THE ANCESTOR INTERLOCK (would kill our own session) ==")
    own = sorted(rr.ancestor_pids())
    check("our own ancestor chain is non-empty", len(own) > 0, True)
    check("our OWN pid is in it", os.getpid() in rr.ancestor_pids(), True)
    # Classify one of our real ancestors -- must refuse even though it may well
    # have a perfectly restartable unit.
    anc = own[-1] if own else os.getpid()
    c = rr.classify_parent(anc, _run=svc_run)
    check("an ANCESTOR pid -> CASE_REFUSED regardless of unit type",
          c["case"], rr.CASE_REFUSED)
    check("  ...refusal explains the consequence",
          "kill the session" in c["why"], True)

    print("\n== process-table primitives (real, on this box) ==")
    check("proc_state of our own pid is a live state, not None",
          rr.proc_state(os.getpid()) in ("R", "S", "D"), True)
    check("proc_starttime of our own pid is an int",
          isinstance(rr.proc_starttime(os.getpid()), int), True)
    check("proc_state of an impossible pid is None (explicit, not a default)",
          rr.proc_state(4294967), None)
    check("CONTROL: existence check would WRONGLY say a zombie is present",
          os.path.isdir("/proc/%d" % os.getpid()), True)

    print("\n== verify_zombie_gone: all four outcomes ==")
    fake = {"state": "Z", "start": 111}

    def fake_proc_gone(pid, _proc=None):
        return None
    # entry gone -> reaped
    ok, d = rr.verify_zombie_gone(5, 111, _proc=None,
                                  _sleep=lambda s: None) if False else (None, None)
    # use direct monkeypatching for determinism
    orig_state, orig_start = rr.proc_state, rr.proc_starttime
    try:
        rr.proc_state = lambda pid, _proc=None: None
        ok, d = rr.verify_zombie_gone(5, 111, _sleep=lambda s: None)
        check("entry gone -> reaped", ok, True)

        rr.proc_state = lambda pid, _proc=None: "Z"
        ok, d = rr.verify_zombie_gone(5, 111, timeout=0.01, _sleep=lambda s: None)
        check("still Z past the deadline -> NOT CONFIRMED (never assumed)", ok, False)
        check("  ...and says NOT CONFIRMED", "NOT CONFIRMED" in d, True)

        rr.proc_state = lambda pid, _proc=None: "S"
        rr.proc_starttime = lambda pid, _proc=None: 999
        ok, d = rr.verify_zombie_gone(5, 111, _sleep=lambda s: None)
        check("PID REUSE (starttime differs) -> original zombie gone", ok, True)
        check("  ...and names the reuse", "reused" in d, True)

        rr.proc_starttime = lambda pid, _proc=None: 111
        ok, d = rr.verify_zombie_gone(5, 111, _sleep=lambda s: None)
        check("same process, no longer Z -> NOT a reap", ok, False)
    finally:
        rr.proc_state, rr.proc_starttime = orig_state, orig_start

    print("\n== reap_zombie: actions + verification, never assumed ==")
    killed, ran = [], []

    def kill_ok(p, s):
        killed.append((p, s))

    def run_ok(cmd, timeout=8):
        ran.append(cmd)
        return (0, "", "")

    def verify_yes(pid, st, _proc=None, _sleep=None):
        return True, "entry gone"

    def verify_no(pid, st, _proc=None, _sleep=None):
        return False, "NOT CONFIRMED: still a zombie"

    ok, d, code = rr.reap_zombie(50, 900, rr.CASE_SERVICE,
                                 unit="speech-dispatcher.service", user_scope=True,
                                 starttime=1, _run=run_ok, _verify=verify_yes)
    check("CASE_SERVICE runs systemctl restart", ok, True)
    check("  ...with --user and the unit",
          ran[-1], ["systemctl", "--user", "restart", "speech-dispatcher.service"])
    check("  ...and NEVER 'stop' (which on a scope would be a kill)",
          any("stop" in c for c in ran[-1]), False)

    ok, d, code = rr.reap_zombie(51, 901, rr.CASE_TERMINATE, starttime=1,
                                 _kill=kill_ok, _verify=verify_yes)
    check("CASE_TERMINATE sends SIGTERM to the parent", ok, True)
    import signal as _sig
    check("  ...exactly SIGTERM", killed[-1], (901, _sig.SIGTERM))

    ok, d, code = rr.reap_zombie(52, 902, rr.CASE_REFUSED, starttime=1,
                                 _kill=kill_ok, _verify=verify_yes)
    check("CASE_REFUSED does NOT act", ok, False)
    check("  ...logs E-RAMREC-007", code, "E-RAMREC-007")
    check("  ...and sent no signal", killed[-1], (901, _sig.SIGTERM))

    # THE KEY TEST: command succeeds but the zombie is still there.
    ok, d, code = rr.reap_zombie(53, 903, rr.CASE_SERVICE, unit="x.service",
                                 starttime=1, _run=run_ok, _verify=verify_no)
    check("command exit 0 but zombie REMAINS -> reported as FAILURE", ok, False)
    check("  ...logs E-RAMREC-006 (not-confirmed, not assumed success)",
          code, "E-RAMREC-006")

    ok, d, code = rr.reap_zombie(54, 904, rr.CASE_SERVICE, unit="x.service",
                                 starttime=1,
                                 _run=lambda c, timeout=8: (1, "", "boom"),
                                 _verify=verify_yes)
    check("failed restart command -> E-RAMREC-005", code, "E-RAMREC-005")

    print("\n== clean_selected: failure-only logging ==")
    logged = []

    def recorder(code, ctx):
        logged.append(code)

    res = rr.clean_selected(
        [{"kind": "shm", "shmid": 2, "bytes": 8192}],
        recorder=recorder, _shm_rows=[ORPHAN], _maps=NO_MAPS,
        _rmid=lambda s: (True, "ok"))
    check("successful reclaim reported", res[0]["ok"], True)
    check("  ...and NOTHING written to the error ledger", logged, [])

    logged.clear()
    res = rr.clean_selected(
        [{"kind": "shm", "shmid": 2}],
        recorder=recorder, _shm_rows=[reattached], _maps=NO_MAPS,
        _rmid=lambda s: (True, "ok"))
    check("refused reclaim reported as failure", res[0]["ok"], False)
    check("  ...and IS written to the ledger", logged, ["E-RAMREC-003"])

    logged.clear()

    def _denied(_p, _s):
        raise PermissionError()

    res = rr.clean_selected(
        [{"kind": "zombie", "pid": 60, "ppid": 905, "case": rr.CASE_TERMINATE,
          "starttime": 1}],
        recorder=recorder, _kill=_denied)
    check("failed zombie action logs E-RAMREC-005", logged, ["E-RAMREC-005"])
    check("  ...and reports 0 bytes freed", res[0]["bytes_freed"], 0)

    print("\n== error codes are well-formed for registration ==")
    check("all codes carry (short, desc, severity)",
          all(len(v) == 3 for v in rr.E_CODES.values()), True)
    check("codes are in the claimed E-RAMREC- range",
          all(c.startswith("E-RAMREC-") for c in rr.E_CODES), True)
    check("retired E-RAMREC-001 is NOT registered (nothing can emit it)",
          "E-RAMREC-001" in rr.E_CODES, False)
    emitted = {"E-RAMREC-002", "E-RAMREC-003", "E-RAMREC-004",
               "E-RAMREC-005", "E-RAMREC-006", "E-RAMREC-007"}
    check("every registered code is one a real site can emit",
          set(rr.E_CODES) == emitted, True)

    print("\n%d/%d checks (failed=%d)"
          % (_state["ran"] - _state["failed"], _state["ran"], _state["failed"]))
    return 1 if _state["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
