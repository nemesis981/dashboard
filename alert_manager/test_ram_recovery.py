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

import io
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ram_recovery as rr                                    # noqa: E402


def _w(path, text):
    """Write a fake /proc file."""
    with io.open(path, "w", encoding="utf-8") as fh:
        fh.write(text)

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

    def cg(unit, uid=None):
        base = "/user.slice/user-%d.slice/user@%d.service/app.slice/" % (uid, uid) \
            if uid is not None else "/system.slice/"
        return {"unit": unit, "user_uid": uid,
                "path": base + (unit or "")}

    def canstart(val):
        """Fake systemctl answering CanStart; rc=1 means 'could not read'."""
        return (lambda cmd: (0, val + "\n", "")) if val is not None \
            else (lambda cmd: (1, "", "no bus"))

    # _self_pid=1 throughout: init is never in our ancestor chain, so interlock
    # 1 CANNOT fire and each result below is genuinely interlock 2 / unit-type
    # logic doing the work. Without this the tests would pass for the wrong
    # reason -- exactly the "instrument that can only produce one answer" trap.
    def cls(unit, uid=None, cs="yes"):
        return rr.classify_parent(900, _cgroup=cg(unit, uid), _self_pid=1,
                                  _run=canstart(cs))

    c = cls("cups.service")
    check("system .service, CanStart=yes -> CASE_SERVICE", c["case"], rr.CASE_SERVICE)
    check("  ...and names the unit", c["unit"], "cups.service")

    c = cls("speech-dispatcher.service", uid=1000)
    check("USER .service, CanStart=yes -> CASE_SERVICE", c["case"], rr.CASE_SERVICE)
    check("  ...and carries the owning uid (which manager to talk to)",
          c["user_uid"], 1000)
    check("  ...and is marked user_scope", c["user_scope"], True)

    c = cls("app-gnome-term-901.scope")
    check("SYSTEM-scope .scope -> CASE_TERMINATE (no live user to protect)",
          c["case"], rr.CASE_TERMINATE)
    check("  ...and says why (no ExecStart / not a service)",
          "not a service" in c["why"], True)

    c = cls(None)
    check("no unit at all, system scope -> CASE_TERMINATE", c["case"], rr.CASE_TERMINATE)

    c = rr.classify_parent(900, _cgroup=None, _self_pid=1)
    check("UNREADABLE cgroup -> CASE_REFUSED (unknown is not 'no unit')",
          c["case"], rr.CASE_REFUSED)
    check("  ...and says the ownership is UNKNOWN", "UNKNOWN" in c["why"], True)

    c = cls("weird.service", cs=None)
    check("CanStart unreadable -> still proposed, but canstart=None",
          (c["case"], c["canstart"]), (rr.CASE_SERVICE, None))
    check("  ...and the listing admits it is unconfirmed",
          "could not be read" in c["why"], True)

    c = cls("nostart.service", cs="no")
    check("system .service CanStart=no -> CASE_TERMINATE", c["case"], rr.CASE_TERMINATE)

    print("\n== INTERLOCK 2: live interactive sessions (root has no EPERM) ==")
    # THE REGRESSION THIS EXISTS FOR. Measured 2026-08-20: ptyxis (141640) is an
    # ancestor of an operator shell but NOT of `dashboard` (707418) or
    # `nemesis-fwd` (702432). Interlock 1 therefore does not fire inside either
    # service. While the dashboard was unprivileged, EPERM hid that. Root has no
    # EPERM -- so without interlock 2 this exact case becomes a SUCCESSFUL kill
    # of the operator's terminal.
    c = cls("app-gnome-xdg-terminal-exec-141640.scope", uid=1000)
    check("live-session .scope -> CASE_REFUSED, NOT terminate",
          c["case"], rr.CASE_REFUSED)
    check("  ...refusal names the human consequence",
          "out from under that user" in c["why"], True)
    check("  ...and interlock 1 provably did NOT fire (self_pid=1)",
          "ancestor" in c["why"], False)

    c = cls("nostart.service", uid=1000, cs="no")
    check("live-session unrestartable .service -> CASE_REFUSED too",
          c["case"], rr.CASE_REFUSED)

    print("\n== CONTAINER-UNIT guard (found live: would have restarted the whole session) ==")
    for u, want in (("user@1000.service", True), ("user.slice", True),
                    ("system.slice", True), ("session-3.scope", True),
                    ("init.scope", True), ("speech-dispatcher.service", False),
                    ("app-gnome-term-901.scope", False)):
        check("container-unit guard: %-28s" % u, rr._is_container_unit(u), want)

    c = cls("user@1000.service", uid=1000)
    check("a container unit is NEVER offered as restartable",
          c["case"], rr.CASE_REFUSED)
    check("  ...and the unit is cleared so nothing can restart it",
          c["unit"], None)
    check("  ...and says why", "whole session" in c["why"], True)

    print("\n== cgroup resolution (the replaced instrument) ==")
    check("cgroup unescaping turns \\x2d back into '-'",
          rr._cg_unescape("app-gnome-xdg\\x2dterminal\\x2dexec-1.scope"),
          "app-gnome-xdg-terminal-exec-1.scope")
    own = rr.proc_cgroup_unit(os.getpid())
    check("our own cgroup resolves to a real unit", bool(own and own["unit"]), True)
    check("an impossible pid resolves to None (explicit, not a default)",
          rr.proc_cgroup_unit(4294967), None)
    check("proc_ppid of our own pid matches os.getppid()",
          rr.proc_ppid(os.getpid()), os.getppid())
    check("proc_ppid of an impossible pid is None",
          rr.proc_ppid(4294967), None)

    print("\n== THE ANCESTOR INTERLOCK (interlock 1, still required) ==")
    own_chain = sorted(rr.ancestor_pids())
    check("our own ancestor chain is non-empty", len(own_chain) > 0, True)
    check("our OWN pid is in it", os.getpid() in rr.ancestor_pids(), True)
    anc = own_chain[-1] if own_chain else os.getpid()
    c = rr.classify_parent(anc, _run=canstart("yes"))
    check("an ANCESTOR pid -> CASE_REFUSED regardless of unit type",
          c["case"], rr.CASE_REFUSED)
    check("  ...refusal explains the consequence",
          "kill the session" in c["why"], True)

    print("\n== _systemctl routes to the RIGHT manager, or fails explicitly ==")
    seen = []
    rr._systemctl(["show", "x.service"], None, _run=lambda c: seen.append(c) or (0, "", ""))
    check("system scope: no --user flag", "--user" in seen[-1], False)
    rr._systemctl(["show", "x.service"], 1000, _run=lambda c: seen.append(c) or (0, "", ""))
    check("user scope: --user flag present", seen[-1][:2], ["systemctl", "--user"])

    _euid = os.geteuid
    try:
        # An account that is neither root nor the target must NOT silently
        # answer from the wrong manager -- that silent wrong answer, made by
        # nemesis-dash (uid 973) against uid 1000's units, is the original bug.
        os.geteuid = lambda: 973
        rc, out, err = rr._systemctl(["show", "x.service"], 1000)
        check("uid 973 asking about uid 1000's manager -> explicit failure",
              rc != 0, True)
        check("  ...and says it cannot reach it (not an empty answer)",
              "cannot reach" in err, True)
        rc, out, err = rr._systemctl(["show", "x.service"], 424242)
        check("a uid with no /run/user/<uid> -> explicit failure", rc != 0, True)
        check("  ...naming the missing runtime dir", "no running user manager" in err, True)
    finally:
        os.geteuid = _euid

    check("_unit_property returns None (unknown) when the read fails",
          rr._unit_property("x.service", "CanStart", None,
                            _run=lambda c: (1, "", "boom")), None)

    print("\n== the classifier proves its own premise on every call ==")
    check("zombie_self_test passes (all three answers reachable)",
          rr.zombie_self_test(), True)

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
                                 unit="speech-dispatcher.service", user_uid=1000,
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

    # A FAKE /proc, deliberately. This previously used pid 60 against the real
    # /proc -- which on this box is the live kernel thread `migration/7`, so the
    # test's outcome depended on what happened to occupy a low pid. It passed,
    # but not for the reason it claimed.
    fake = tempfile.mkdtemp(prefix="nem-proc-")
    zpid, zppid = 60, 905
    os.makedirs(os.path.join(fake, str(zpid)))
    os.makedirs(os.path.join(fake, str(zppid)))
    # field 3 = state, field 22 (rest[19]) = starttime
    rest = ["Z"] + ["0"] * 18 + ["12345"]
    _w(os.path.join(fake, str(zpid), "stat"),
       "%d (zomb) %s\n" % (zpid, " ".join(rest)))
    _w(os.path.join(fake, str(zpid), "status"), "Name:\tzomb\nPPid:\t%d\n" % zppid)
    _w(os.path.join(fake, str(zpid), "comm"), "zomb\n")
    _w(os.path.join(fake, str(zppid), "comm"), "someparent\n")
    # system-scope .scope -> CASE_TERMINATE, so SIGTERM is genuinely attempted
    _w(os.path.join(fake, str(zppid), "cgroup"),
       "0::/system.slice/stray-905.scope\n")

    res = rr.clean_selected(
        [{"kind": "zombie", "pid": zpid}],
        recorder=recorder, _kill=_denied, _proc=fake)
    check("failed zombie action logs E-RAMREC-005", logged, ["E-RAMREC-005"])
    check("  ...and it really was the SIGTERM path (EPERM), not a refusal",
          "not permitted" in res[0]["detail"], True)
    check("  ...and reports 0 bytes freed", res[0]["bytes_freed"], 0)

    print("\n== reap_zombie_verified: caller vouches for NOTHING ==")
    # The interlock that bounds this op: a caller naming a LIVE pid must not be
    # able to get root to signal that process's parent.
    _w(os.path.join(fake, str(zpid), "stat"),
       "%d (zomb) %s\n" % (zpid, " ".join(["S"] + rest[1:])))
    ok, detail, code, info = rr.reap_zombie_verified(zpid, _proc=fake,
                                                     _kill=_denied)
    check("a pid that is NOT a zombie is refused outright", ok, False)
    check("  ...and says so explicitly", "not a zombie" in detail, True)
    _w(os.path.join(fake, str(zpid), "stat"),
       "%d (zomb) %s\n" % (zpid, " ".join(rest)))

    ok, detail, code, info = rr.reap_zombie_verified(4294967, _proc=fake)
    check("an absent pid is 'nothing to reap', not a failure", ok, True)

    check("bad pid types are rejected",
          rr.reap_zombie_verified("60", _proc=fake)[0], False)

    # live-session .scope -> refused with 008, and NOTHING is signalled
    _w(os.path.join(fake, str(zppid), "cgroup"),
       "0::/user.slice/user-1000.slice/user@1000.service/app.slice/"
       "app-gnome-term-905.scope\n")
    signalled = []
    ok, detail, code, info = rr.reap_zombie_verified(
        zpid, _proc=fake, _kill=lambda p, s: signalled.append(p))
    check("live-session parent -> refused with E-RAMREC-008", code, "E-RAMREC-008")
    check("  ...and NO signal was sent at all", signalled, [])

    # a restartable user service, with CanStart unreadable -> FAIL CLOSED
    _w(os.path.join(fake, str(zppid), "cgroup"),
       "0::/user.slice/user-1000.slice/user@1000.service/app.slice/"
       "thing.service\n")
    ok, detail, code, info = rr.reap_zombie_verified(
        zpid, _proc=fake, _run=lambda cmd: (1, "", "no bus"),
        _kill=lambda p, s: signalled.append(p))
    check("CanStart unreadable -> REFUSED (fail closed, not assumed yes)",
          ok, False)
    check("  ...and still no signal sent", signalled, [])
    shutil.rmtree(fake, ignore_errors=True)

    print("\n== REGENERATION: a reap that is immediately undone ==")
    # The pure matcher first -- both answers, on fixtures.
    A = (1, "sd_espeak-ng-mb", "speech-dispatcher.service", "speech-dispatch")
    def match(cand, unit="speech-dispatcher.service", pcomm="speech-dispatch",
              args=A):
        return rr._is_equivalent_zombie(cand, *args, cand_parent_unit=unit,
                                        cand_parent_comm=pcomm)
    check("same comm + same parent UNIT -> equivalent",
          match({"pid": 2, "ppid": 20, "comm": "sd_espeak-ng-mb"}), True)
    check("  ...even though the parent pid is different (restart gives a new one)",
          match({"pid": 2, "ppid": 999, "comm": "sd_espeak-ng-mb"}), True)
    check("a DIFFERENT child comm -> not equivalent",
          match({"pid": 2, "ppid": 20, "comm": "other"}), False)
    check("a different parent unit -> not equivalent",
          match({"pid": 2, "ppid": 20, "comm": "sd_espeak-ng-mb"},
                unit="cups.service"), False)
    check("the pid we just reaped is never its own regeneration",
          match({"pid": 1, "ppid": 20, "comm": "sd_espeak-ng-mb"}), False)
    check("no unit -> falls back to parent COMM",
          rr._is_equivalent_zombie({"pid": 2, "ppid": 20, "comm": "child"},
                                   1, "child", None, "theparent",
                                   cand_parent_unit=None,
                                   cand_parent_comm="theparent"), True)
    check("  ...and refuses to match on comm when neither anchor is known",
          rr._is_equivalent_zombie({"pid": 2, "ppid": 20, "comm": "child"},
                                   1, "child", None, None,
                                   cand_parent_unit=None,
                                   cand_parent_comm=None), False)

    # Now the scan, against a fake /proc holding a REAL regeneration.
    f2 = tempfile.mkdtemp(prefix="nem-regen-")
    UNIT = ("0::/user.slice/user-1000.slice/user@1000.service/app.slice/"
            "speech-dispatcher.service\n")
    st = ["Z"] + ["0"] * 18 + ["999"]
    for zp, pp in ((60, 905), (61, 906)):
        os.makedirs(os.path.join(f2, str(zp)))
        os.makedirs(os.path.join(f2, str(pp)))
        _w(os.path.join(f2, str(zp), "stat"), "%d (z) %s\n" % (zp, " ".join(st)))
        _w(os.path.join(f2, str(zp), "status"), "PPid:\t%d\n" % pp)
        _w(os.path.join(f2, str(zp), "comm"), "sd_espeak-ng-mb\n")
        _w(os.path.join(f2, str(pp), "comm"), "speech-dispatch\n")
        _w(os.path.join(f2, str(pp), "cgroup"), UNIT)

    state, detail, m = rr.detect_regeneration(
        60, "sd_espeak-ng-mb", "speech-dispatcher.service", "speech-dispatch",
        timeout=0, _proc=f2)
    check("an equivalent zombie under the same unit -> 'regenerated'",
          state, "regenerated")
    check("  ...and names the pid it came back as", m["pid"], 61)
    check("  ...and says clearing it again will not help",
          "will not help" in detail, True)

    shutil.rmtree(os.path.join(f2, "61"))
    state, detail, m = rr.detect_regeneration(
        60, "sd_espeak-ng-mb", "speech-dispatcher.service", "speech-dispatch",
        timeout=0, _proc=f2)
    check("with no equivalent zombie -> 'clear' (the SAME code path)",
          state, "clear")

    state, detail, m = rr.detect_regeneration(
        60, "x", "u.service", "p", timeout=0, _proc="/nonexistent-proc-xyz")
    check("an unreadable /proc -> 'unknown', NOT 'clear'", state, "unknown")
    check("  ...so 'could not check' can never read as 'it did not come back'",
          state == "clear", False)

    print("\n== reap_zombie_verified reports the recurrence, end to end ==")
    os.makedirs(os.path.join(f2, "61"))
    _w(os.path.join(f2, "61", "stat"), "61 (z) %s\n" % " ".join(st))
    _w(os.path.join(f2, "61", "status"), "PPid:\t906\n")
    _w(os.path.join(f2, "61", "comm"), "sd_espeak-ng-mb\n")
    ok, detail, code, info = rr.reap_zombie_verified(
        60, _proc=f2, _run=lambda cmd: (0, "yes\n", ""),
        _verify=lambda pid, s0, _proc=None, _sleep=None: (True, "entry gone"),
        _regen_timeout=0)
    check("the reap itself still reports SUCCESS (it did work)", ok, True)
    check("  ...but is flagged as regenerated", info["regeneration"], "regenerated")
    check("  ...records E-RAMREC-009", code, "E-RAMREC-009")
    check("  ...and the detail says the zombie came back",
          "CAME BACK" in detail, True)

    shutil.rmtree(os.path.join(f2, "61"))
    ok, detail, code, info = rr.reap_zombie_verified(
        60, _proc=f2, _run=lambda cmd: (0, "yes\n", ""),
        _verify=lambda pid, s0, _proc=None, _sleep=None: (True, "entry gone"),
        _regen_timeout=0)
    check("a clean reap is NOT flagged", info["regeneration"], "clear")
    check("  ...and records no code", code, None)
    shutil.rmtree(f2, ignore_errors=True)

    print("\n== error codes are well-formed for registration ==")
    check("all codes carry (short, desc, severity)",
          all(len(v) == 3 for v in rr.E_CODES.values()), True)
    check("codes are in the claimed E-RAMREC- range",
          all(c.startswith("E-RAMREC-") for c in rr.E_CODES), True)
    check("retired E-RAMREC-001 is NOT registered (nothing can emit it)",
          "E-RAMREC-001" in rr.E_CODES, False)
    # Derived from the SOURCE, not a hand-maintained set. A hardcoded list here
    # is a second source of truth that goes stale the moment a code is added --
    # and a stale list fails in the direction that looks like a real defect.
    _src = io.open(rr.__file__, encoding="utf-8").read()
    emitted = {c for c in rr.E_CODES if ('"%s"' % c) in _src}
    check("every registered code is one a real site can emit",
          set(rr.E_CODES) == emitted, True)

    print("\n%d/%d checks (failed=%d)"
          % (_state["ran"] - _state["failed"], _state["ran"], _state["failed"]))
    return 1 if _state["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
