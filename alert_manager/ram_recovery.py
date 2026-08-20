"""Manual RAM recovery — the CONVENIENCE half of the memory work.

This is deliberately NOT the memory-injection ladder. The ladder
(`mem_appliance` / `memladder`) is automated, evidence-gated, scoped to the four
wired Nemesis services, and keeps its harsher rungs in shadow until promotion
evidence clears. THIS module is the opposite by design: a direct, immediate,
user-triggered reclaim of things that are already dead, invoked because a human
asked for it in the moment. It bypasses the ladder's gating on purpose. It also
never touches a live application's memory — "reclaim what is orphaned", not
"kill what is big".

WHAT IT DOES AND DOES NOT RECOVER (measured 2026-08-19, not assumed)
--------------------------------------------------------------------
* **Zombies recover essentially NO RAM.** A zombie has already released its
  memory maps -- `/proc/<pid>/status` carries no `VmRSS` line at all, and psutil
  reports `memory_info().rss == 0`. What remains is a process-table entry. This
  is worth reaping as hygiene (PID slots; a zombie means a parent that is not
  reaping), but the UI must never present it as freed memory.
* **Orphaned SysV shared memory is the ONLY category here that returns real
  RAM**, and only after a crash -- on a healthy box there is usually none.

DELIBERATELY EXCLUDED FROM v1, with reasons (so neither is silently re-added)
----------------------------------------------------------------------------
* **Semaphores.** The kernel exposes NO holder information for SysV semaphores:
  there is no `nattch` equivalent, `ipcs -s -p` is empty, `/proc/sysvipc/sem`
  carries only key/perms/uid/otime/ctime, and semaphores are not file
  descriptors so `/proc/<pid>/fd` cannot help either. The only available
  heuristic -- "last-op PID is dead" -- produced a REAL false positive on the
  build box: a semaphore whose creator had exited but which was created in the
  same second as, and belongs to, a still-running application's cluster.
  Unprovable means excluded; a checkbox defaulted checked must not be able to
  break a live app.
* **Leak-pattern processes.** Nothing in this codebase measures memory GROWTH.
  `membudget.evaluate()` is stateless -- a point-in-time `value > budget_mb` --
  and memladder's `breach_streak` counts consecutive samples over a threshold,
  not a slope. A process holding a large steady cache is therefore
  indistinguishable from one leaking at the same magnitude. Reporting "leaking"
  off that data would be an instrument that can only produce one answer.
  Budget-breach information is surfaced READ-ONLY, with no reclaim action.

REUSE
-----
Per-process data comes from `procmem.sample_processes()` (which now reports
`status`); budget state from `membudget.evaluate()`; logging from
`nemesis_errors`. The only genuinely new machinery here is orphan detection and
the reclaim actions themselves.
"""

import ctypes
import errno
import os
import signal
import subprocess
import time

__all__ = [
    "E_CODES", "register_codes",
    "find_zombies", "find_orphan_shm", "shm_inventory",
    "reap_zombie", "release_shm", "clean_selected",
    "classify_parent", "ancestor_pids", "verify_zombie_gone",
    "proc_state", "proc_starttime",
    "CASE_SERVICE", "CASE_TERMINATE", "CASE_REFUSED",
    "SHM_DEST", "OrphanCheck",
]

# ── zombie parent classification (three-way, not two) ────────────────────────
# Measured 2026-08-19; the two-way "systemd-managed or not" split does NOT hold.
# Both real zombie parents on the build box are systemd-managed, but only one is
# restartable:
#   speech-dispatcher -> speech-dispatcher.service  (service, CanStart=yes)
#   ptyxis            -> app-gnome-...-141640.scope (SCOPE,   CanStart=no)
# A .scope is a cgroup systemd ADOPTED for a process it did not launch: it has
# no ExecStart, so it cannot be started. Proven on a disposable scope rather
# than inferred -- `systemctl restart` returns:
#     "Job type restart is not applicable for unit <name>.scope"
# The trap this closes: keying on unit PRESENCE says "systemd-managed" for BOTH,
# and the natural fallback for a failed restart is `systemctl stop`, which for a
# scope is a KILL wearing a systemd command's clothes.
CASE_SERVICE = "restartable_service"   # .service with CanStart=yes -> restart
CASE_TERMINATE = "terminate_only"      # scope / no unit            -> SIGTERM
CASE_REFUSED = "refused_ancestor"      # would kill our own session -> no action

# ── error codes ──────────────────────────────────────────────────────────────
# FAILURE-ONLY by decision (operator, 2026-08-19). The error ledger exists for
# "a fault an operator would want to know happened"; a successful user-initiated
# cleanup is not a fault, and recording successes would dilute a ledger meant
# for defects. Successful reclaims are returned to the caller for ordinary
# audit/UI display instead.
#
# Range claim: E-RAMREC-001..099 belongs to alert_manager/ram_recovery. The
# 2026-08-08 classification batches show E-HWMON-, E-MALWARE-, E-ANOMALY-,
# E-DHCP-, E-TICKETS- and E-CONSENT- already claimed; E-RAMREC- is new.
#
# 001 is RETIRED, deliberately left unassigned. It covered "SIGCHLD to the
# parent failed" from the first design; that whole approach was dropped once
# measurement showed SIGCHLD is inert against a persistent zombie (a parent that
# leaves one has SIGCHLD at SIG_DFL, which means ignore). Nothing can emit 001
# any more, and a code registered in the catalog that no site can ever raise is
# a false entry -- it looks like coverage while being unreachable. Not reused
# for something else either: a recycled code makes historical occurrences
# ambiguous.
E_CODES = {
    "E-RAMREC-002": (
        "Orphaned shm release failed",
        "shmctl(IPC_RMID) on a segment that passed every orphan check failed. "
        "The segment remains and its memory is not reclaimed.",
        "medium"),
    "E-RAMREC-003": (
        "Orphan re-verification refused a release",
        "A segment listed as orphaned no longer satisfied every orphan "
        "condition at the moment of release, so it was NOT removed. This is "
        "the safety interlock doing its job -- it means something re-attached "
        "between listing and action.",
        "medium"),
    "E-RAMREC-004": (
        "Orphan detection could not read its inputs",
        "/proc/sysvipc/shm or the /proc/*/maps sweep could not be read, so "
        "orphan status is UNKNOWN. Nothing is offered for cleanup, rather "
        "than defaulting to an empty (safe-looking) candidate list.",
        "medium"),
    "E-RAMREC-005": (
        "Zombie parent restart/terminate failed",
        "The restart or terminate command for a zombie's parent did not "
        "succeed. The zombie remains.",
        "low"),
    "E-RAMREC-006": (
        "Zombie removal NOT CONFIRMED after a successful command",
        "The restart/terminate command reported success but the zombie was "
        "still in the process table when re-checked. This is the difference "
        "between a command exiting 0 and the outcome actually happening -- "
        "the command's exit status is not evidence.",
        "medium"),
    "E-RAMREC-007": (
        "Refused to act on a parent that is one of our own ancestors",
        "Terminating this process would kill the session Nemesis itself is "
        "running under. Refused by the ancestor interlock.",
        "medium"),
}

MODULE_NAME = "alert_manager/ram_recovery"

#: SHM_DEST -- the segment is already marked for destruction and the kernel
#: frees it when the last attach drops. Removing it ourselves is redundant at
#: best; it must never be offered as a candidate.
SHM_DEST = 0o1000

_SYSVIPC_SHM = "/proc/sysvipc/shm"
_PROC = "/proc"


class OrphanCheck(Exception):
    """Raised when orphan status cannot be DETERMINED.

    Deliberately distinct from "there are no orphans": a failed read must never
    degrade into an empty candidate list, because an empty list is a legal,
    reassuring-looking answer that is indistinguishable from a real one.
    """


def register_codes(conn, nemesis_errors):
    """Register this module's codes. `record_error` refuses unregistered codes,
    so this must run before any failure can be logged."""
    for code, (desc_short, desc, severity) in E_CODES.items():
        nemesis_errors.register_error_code(
            conn, code, MODULE_NAME, "%s -- %s" % (desc_short, desc), severity)


# ── process-table primitives (the REAL verification, not an existence check) ─
def proc_state(pid, _proc=None):
    """Field 3 of /proc/<pid>/stat -- 'Z' for a zombie. Returns None if the
    entry is gone.

    WHY NOT os.path.exists(): a zombie STILL HAS a /proc entry (measured:
    /proc/141657 exists with state=Z). An existence check therefore reports
    "still there" forever and can never observe a successful reap -- an
    instrument that can only produce one answer.

    Parsed from the LAST ')' rather than by splitting the whole line, because
    field 2 is the comm in parentheses and may itself contain spaces or ')'.
    """
    try:
        with open(os.path.join(_proc or _PROC, str(pid), "stat"), "r") as fh:
            data = fh.read()
    except (OSError, ValueError):
        return None
    rp = data.rfind(")")
    if rp < 0:
        return None
    rest = data[rp + 2:].split()
    return rest[0] if rest else None


def proc_starttime(pid, _proc=None):
    """Field 22 of /proc/<pid>/stat -- start time in clock ticks since boot.

    The PID-REUSE guard. After a parent is restarted or terminated its PID (and
    the zombie's) can be recycled; without this, a brand-new process occupying
    the same PID reads as "the zombie is gone" or "the zombie is still here"
    depending on its state, both wrong. Stable for the life of a process and
    distinct for a new one.
    """
    try:
        with open(os.path.join(_proc or _PROC, str(pid), "stat"), "r") as fh:
            data = fh.read()
    except (OSError, ValueError):
        return None
    rp = data.rfind(")")
    if rp < 0:
        return None
    rest = data[rp + 2:].split()
    # rest[0] is field 3, so field 22 is rest[19]
    try:
        return int(rest[19])
    except (IndexError, ValueError):
        return None


def ancestor_pids(pid=None, _proc=None):
    """Our own PPid chain, as a set.

    The interlock behind CASE_REFUSED. Measured on the build box: the zombie
    parent `ptyxis` (141640) is a direct ancestor of the running session --
        bash -> claude -> bash -> ptyxis-agent -> ptyxis
    so "terminate the zombie's parent" would kill the terminal Nemesis is
    running in. Cheap to check, catastrophic to skip; the same asymmetric
    safety as the shm re-verification.
    """
    proc = _proc or _PROC
    out, cur, guard = set(), pid or os.getpid(), 0
    while cur and cur > 1 and guard < 64:
        out.add(cur)
        try:
            with open(os.path.join(proc, str(cur), "status"), "r") as fh:
                nxt = None
                for line in fh:
                    if line.startswith("PPid:"):
                        nxt = int(line.split()[1])
                        break
        except (OSError, ValueError):
            break
        cur = nxt
        guard += 1
    return out


def _systemctl_unit_for(pid, user_scope, _run=None):
    """Resolve pid -> unit name in the given systemd scope, or None."""
    run = _run or _run_cmd
    cmd = ["systemctl"] + (["--user"] if user_scope else []) + \
          ["status", str(pid), "--no-pager", "-n", "0"]
    rc, out, _err = run(cmd)
    for line in (out or "").splitlines():
        stripped = line.strip().lstrip("●").strip()
        if not stripped:
            continue
        token = stripped.split()[0]
        if "." in token and any(token.endswith(s) for s in
                                (".service", ".scope", ".slice", ".socket")):
            return token
        break
    return None


def _unit_property(unit, prop, user_scope, _run=None):
    run = _run or _run_cmd
    cmd = ["systemctl"] + (["--user"] if user_scope else []) + \
          ["show", unit, "-p", prop, "--value"]
    rc, out, _err = run(cmd)
    return (out or "").strip() if rc == 0 else None


def _run_cmd(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except Exception as exc:                                 # noqa: BLE001
        return 1, "", str(exc)


#: Units that CONTAIN large numbers of unrelated processes. Restarting one to
#: clear a single zombie would take down far more than the zombie's parent --
#: `user@1000.service` alone held 1707 tasks on the build box. These are never
#: an actionable answer, in either systemd scope.
_CONTAINER_UNIT_PREFIXES = ("user@", "user-runtime-dir@", "session-",
                            "init.scope", "system.slice", "user.slice")


def _is_container_unit(unit):
    if not unit:
        return False
    if unit.endswith(".slice"):
        return True
    return any(unit.startswith(p) for p in _CONTAINER_UNIT_PREFIXES)


def classify_parent(ppid, _proc=None, _run=None, _self_pid=None):
    """Three-way classification of a zombie's parent.

    Returns {case, unit, user_scope, why}. The ancestor interlock is checked
    FIRST and overrides everything: a restartable unit that happens to be our
    own ancestor is still refused.
    """
    mine = ancestor_pids(_self_pid, _proc=_proc)
    if ppid in mine:
        return {"case": CASE_REFUSED, "unit": None, "user_scope": None,
                "why": "pid %d is an ancestor of the Nemesis process; acting "
                       "on it would kill the session Nemesis is running in"
                       % ppid}

    # USER scope FIRST, deliberately. `systemctl status <pid>` in SYSTEM scope
    # answers with the CONTAINER unit for any user process -- measured: pid
    # 210451 resolves to `user@1000.service` (the User Manager, 1707 tasks)
    # in system scope but to the correct `speech-dispatcher.service` in user
    # scope. Restarting the container would tear down the operator's entire
    # desktop session -- far worse than the single-app termination this
    # feature is meant to avoid. Most specific answer wins.
    for user_scope in (True, False):
        unit = _systemctl_unit_for(ppid, user_scope, _run=_run)
        if not unit:
            continue
        if _is_container_unit(unit):
            # Ordering alone is not enough: if user-scope resolution fails for
            # any reason we would fall back to system scope and get exactly the
            # container unit again. This refuses it outright.
            return {"case": CASE_TERMINATE, "unit": None,
                    "user_scope": user_scope,
                    "why": "resolved only to the container unit %s, which owns "
                           "the whole session and must never be restarted for "
                           "one zombie" % unit}
        if not unit.endswith(".service"):
            return {"case": CASE_TERMINATE, "unit": unit,
                    "user_scope": user_scope,
                    "why": "unit %s is a %s, not a service -- it has no "
                           "ExecStart and cannot be restarted (systemd: 'Job "
                           "type restart is not applicable')"
                           % (unit, unit.rsplit(".", 1)[-1])}
        can = _unit_property(unit, "CanStart", user_scope, _run=_run)
        if can == "yes":
            return {"case": CASE_SERVICE, "unit": unit,
                    "user_scope": user_scope,
                    "why": "restartable service unit"}
        return {"case": CASE_TERMINATE, "unit": unit, "user_scope": user_scope,
                "why": "unit %s reports CanStart=%r -- not restartable"
                       % (unit, can)}

    return {"case": CASE_TERMINATE, "unit": None, "user_scope": None,
            "why": "no systemd unit owns this process"}


def verify_zombie_gone(pid, starttime0, timeout=8.0, _proc=None, _sleep=None):
    """Did the zombie ACTUALLY leave the process table?

    Never infers success from a command's exit status -- proven necessary:
    `systemctl --user restart` returned 0 while the outcome still had to be
    observed separately. Three distinguishable outcomes, plus an explicit
    not-confirmed on timeout (never a default "probably worked").
    """
    sleep = _sleep or time.sleep
    deadline = time.time() + timeout
    while True:
        st = proc_state(pid, _proc=_proc)
        if st is None:
            return True, "process-table entry for pid %d is gone" % pid
        if st != "Z":
            now = proc_starttime(pid, _proc=_proc)
            if starttime0 is not None and now is not None and now != starttime0:
                return True, ("pid %d was reused by a different process "
                              "(starttime %s != %s); the original zombie is "
                              "gone" % (pid, now, starttime0))
            return False, ("pid %d is no longer a zombie but is still the same "
                           "process (state=%s) -- not a reap" % (pid, st))
        if time.time() >= deadline:
            return False, ("NOT CONFIRMED: pid %d is still a zombie after %.0fs"
                           % (pid, timeout))
        sleep(0.5)


# ── zombies ──────────────────────────────────────────────────────────────────
def find_zombies(sample, _proc=None, _run=None):
    """Zombie rows from an EXISTING `procmem.sample_processes()` result.

    Pure: takes the sample, adds no sampling of its own. Returns [] only when
    the sample is usable and genuinely contains no zombies; an unusable sample
    raises rather than reporting a clean box.
    """
    if not isinstance(sample, dict):
        raise OrphanCheck("process sample is not a dict")
    if sample.get("state") == "unavailable":
        raise OrphanCheck("process sample unavailable: %s"
                          % sample.get("reason", "unknown"))
    procs = sample.get("processes")
    if not isinstance(procs, list):
        raise OrphanCheck("process sample carries no process list")

    seen_status = any(p.get("status") is not None for p in procs)
    if procs and not seen_status:
        # Every row missing `status` means the sampler predates the status
        # attribute (or the platform does not supply it). "No zombies found"
        # would be a non-measurement wearing a result's clothes.
        raise OrphanCheck(
            "process sample carries no `status` field -- cannot distinguish a "
            "zombie from a live 0-RSS process")

    out = []
    for p in procs:
        if (p.get("status") or "").lower() != "zombie":
            continue
        pid, ppid = p.get("pid"), p.get("ppid")
        cls = classify_parent(ppid, _proc=_proc, _run=_run) if ppid else {
            "case": CASE_TERMINATE, "unit": None, "user_scope": None,
            "why": "no parent recorded"}
        out.append({
            "kind": "zombie",
            "pid": pid,
            "ppid": ppid,
            "name": p.get("name"),
            "parent_name": _comm(ppid, _proc=_proc),
            # Captured AT LIST TIME so the post-action check can detect PID
            # reuse. Without it a recycled PID reads as a result.
            "starttime": proc_starttime(pid, _proc=_proc),
            "case": cls["case"],
            "unit": cls["unit"],
            "user_scope": cls["user_scope"],
            "why": cls["why"],
            "actionable": cls["case"] != CASE_REFUSED,
            # Stated explicitly so the UI cannot imply otherwise: a zombie has
            # already released its maps.
            "reclaimable_bytes": 0,
            "detail": "already dead; clearing it frees a process-table slot, "
                      "not memory",
        })
    return out


def _comm(pid, _proc=None):
    try:
        with open(os.path.join(_proc or _PROC, str(pid), "comm"), "r") as fh:
            return fh.read().strip()
    except OSError:
        return None


def reap_zombie(zpid, ppid, case, unit=None, user_scope=False, starttime=None,
                _kill=None, _run=None, _proc=None, _sleep=None, _verify=None):
    """Clear a zombie by acting on its PARENT, then VERIFY it actually left.

    SIGCHLD is deliberately NOT used. Measured 2026-08-19 with a differential on
    a real fixture: a parent with default SIGCHLD disposition (SIG_DFL, which
    for SIGCHLD means IGNORE) leaves a persistent zombie AND ignores the signal
    -- zombie still `Z` after SIGCHLD. The same fixture's zombie disappeared
    within 1s of the parent being terminated. A persistent zombie therefore
    almost by definition implies a parent that will ignore SIGCHLD, which is why
    that path was dropped in favour of restart/terminate.

    Returns (ok, detail, code).
    """
    verify = _verify or verify_zombie_gone
    kill = _kill or os.kill

    if case == CASE_REFUSED:
        return (False,
                "REFUSED: parent pid %s is an ancestor of the Nemesis process; "
                "acting on it would kill the session Nemesis runs in" % ppid,
                "E-RAMREC-007")

    if not ppid or ppid <= 1:
        return False, "no actionable parent (ppid=%r)" % (ppid,), "E-RAMREC-005"

    # Re-check the ancestor interlock at ACTION time, not just at list time --
    # same reasoning as the shm re-verification: the listing is a proposal, and
    # process trees change while a popup sits open.
    if ppid in ancestor_pids(_proc=_proc):
        return (False,
                "REFUSED at action time: parent pid %d became an ancestor of "
                "the Nemesis process" % ppid,
                "E-RAMREC-007")

    if case == CASE_SERVICE and unit:
        cmd = ["systemctl"] + (["--user"] if user_scope else []) + \
              ["restart", unit]
        rc, _out, err = (_run or _run_cmd)(cmd)
        if rc != 0:
            return (False, "restart of %s failed: %s" % (unit, (err or "").strip()[:180]),
                    "E-RAMREC-005")
        action = "restarted unit %s" % unit
    else:
        try:
            kill(ppid, signal.SIGTERM)
        except ProcessLookupError:
            # Parent already gone -- init inherits and reaps. Still verified below.
            action = "parent pid %d had already exited" % ppid
        except PermissionError:
            return (False, "not permitted to terminate parent pid %d" % ppid,
                    "E-RAMREC-005")
        except OSError as exc:
            return (False, "terminating parent pid %d failed: %s" % (ppid, exc),
                    "E-RAMREC-005")
        else:
            action = "terminated parent pid %d (SIGTERM)" % ppid

    # THE POINT: a command exiting 0 is not evidence. Proven necessary --
    # `systemctl --user restart` returned 0 and the outcome still had to be
    # observed separately against the process table.
    ok, detail = verify(zpid, starttime, _proc=_proc, _sleep=_sleep)
    if ok:
        return True, "%s; verified: %s" % (action, detail), None
    return False, "%s; but %s" % (action, detail), "E-RAMREC-006"


# ── shared memory ────────────────────────────────────────────────────────────
def _read_sysvipc_shm(_path=None):
    """Parse /proc/sysvipc/shm -- a stable, header-labelled kernel interface.

    Preferred over scraping `ipcs` output: fixed columns, no locale/format
    drift, and no subprocess. Columns are read BY NAME from the header rather
    than by fixed index, so a kernel that adds a column does not silently shift
    the meaning of the values.
    """
    path = _path or _SYSVIPC_SHM
    try:
        with open(path, "r") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        raise OrphanCheck("cannot read %s: %s" % (path, exc)) from exc
    if not lines:
        raise OrphanCheck("%s is empty (not even a header)" % path)

    header = lines[0].split()
    need = ("shmid", "key", "size", "cpid", "nattch", "perms")
    missing = [c for c in need if c not in header]
    if missing:
        raise OrphanCheck("%s header lacks %s" % (path, ", ".join(missing)))
    idx = {name: i for i, name in enumerate(header)}

    rows = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < len(header):
            continue
        try:
            rows.append({
                "shmid": int(parts[idx["shmid"]]),
                "key": int(parts[idx["key"]]),
                "size": int(parts[idx["size"]]),
                "cpid": int(parts[idx["cpid"]]),
                "nattch": int(parts[idx["nattch"]]),
                # octal in this file; the SHM_DEST bit lives here
                "perms": int(parts[idx["perms"]], 8),
            })
        except (ValueError, KeyError):
            continue
    return rows


def _sysv_keys_in_maps(_proc=None):
    """Every SysV shm key currently mapped by ANY process, from /proc/*/maps.

    This is the SECOND, INDEPENDENT instrument. `nattch` is the kernel's own
    attach counter; this is the set of segments actually present in live
    address spaces. Requiring both to agree is what makes the orphan check
    trustworthy rather than a single-source assertion -- and it is exactly the
    cross-check that semaphores cannot offer, which is why they are excluded.

    Returns (keys, scanned, unreadable). Unreadable /proc entries are COUNTED,
    never silently ignored, so the caller can refuse to act on a partial view.
    """
    proc = _proc or _PROC
    keys = set()
    scanned = unreadable = 0
    try:
        entries = os.listdir(proc)
    except OSError as exc:
        raise OrphanCheck("cannot list %s: %s" % (proc, exc)) from exc

    for name in entries:
        if not name.isdigit():
            continue
        maps = os.path.join(proc, name, "maps")
        try:
            with open(maps, "r") as fh:
                data = fh.read()
            scanned += 1
        except FileNotFoundError:
            # Process exited mid-walk. Genuinely gone, so it holds nothing.
            continue
        except OSError:
            # Permission denied on another user's process. This one COULD be
            # holding a segment we cannot see, so it is counted, not ignored.
            unreadable += 1
            continue
        for chunk in data.split("/SYSV")[1:]:
            hexkey = ""
            for ch in chunk:
                if ch in "0123456789abcdefABCDEF":
                    hexkey += ch
                else:
                    break
            if hexkey:
                try:
                    keys.add(int(hexkey, 16))
                except ValueError:
                    pass
    return keys, scanned, unreadable


def _pid_alive(pid, _proc=None):
    if not pid or pid <= 0:
        return False
    return os.path.isdir(os.path.join(_proc or _PROC, str(pid)))


def shm_inventory(_shm_rows=None, _maps=None, _proc=None):
    """Full shm inventory with an orphan verdict + REASON for every segment.

    Every segment is returned, not just the orphans, so the caller can show
    what was considered and why it was rejected. A verdict with no reason is
    how a wrong verdict hides.
    """
    rows = _shm_rows if _shm_rows is not None else _read_sysvipc_shm()
    if _maps is not None:
        mapped_keys, scanned, unreadable = _maps
    else:
        mapped_keys, scanned, unreadable = _sysv_keys_in_maps(_proc=_proc)

    out = []
    for r in rows:
        reasons = []
        if r["nattch"] != 0:
            reasons.append("attached (nattch=%d)" % r["nattch"])
        if r["key"] != 0 and r["key"] in mapped_keys:
            reasons.append("present in a live process address space")
        if r["perms"] & SHM_DEST:
            reasons.append("already marked SHM_DEST; the kernel frees it on "
                           "last detach")
        if _pid_alive(r["cpid"], _proc=_proc):
            reasons.append("creator pid %d still alive" % r["cpid"])
        # A private (key==0) segment cannot be matched against /proc/*/maps by
        # key, so the maps cross-check cannot vouch for it. nattch==0 alone is
        # a single-source claim, and this module does not act on those.
        if r["key"] == 0 and r["nattch"] == 0:
            reasons.append("anonymous segment (key=0): the /proc/*/maps "
                           "cross-check cannot confirm it, and nattch alone "
                           "is a single source")
        # NOTE on `unreadable`: it is reported but deliberately does NOT block.
        # An unreadable /proc entry cannot hide an attachment that `nattch`
        # has not already counted -- the kernel increments shm_nattch on every
        # shmat() and decrements it on shmdt()/exit, so a segment present in
        # ANY address space necessarily has nattch > 0. The maps sweep is
        # therefore a confirming VETO, never a required proof of absence: it
        # can only ever make this check MORE conservative (spotting a mapping
        # the counter somehow missed), never less. Blocking on `unreadable`
        # instead would make the feature permanently inert in production, where
        # the dashboard runs as the unprivileged `nemesis-dash` and most of
        # /proc belongs to other users -- an always-empty candidate list that
        # looks like a clean box. Verified on the build box: 98 of 566 /proc
        # entries unreadable as a normal user.

        out.append({
            "kind": "shm",
            "shmid": r["shmid"],
            "key": r["key"],
            "bytes": r["size"],
            "creator_pid": r["cpid"],
            "nattch": r["nattch"],
            "orphan": not reasons,
            "reasons": reasons,
        })
    return {"segments": out, "maps_scanned": scanned,
            "maps_unreadable": unreadable}


def find_orphan_shm(_shm_rows=None, _maps=None, _proc=None):
    """Only the segments that satisfy EVERY orphan condition."""
    inv = shm_inventory(_shm_rows=_shm_rows, _maps=_maps, _proc=_proc)
    return [s for s in inv["segments"] if s["orphan"]]


def _shmctl_rmid(shmid):
    """shmctl(shmid, IPC_RMID, NULL) via libc. Returns (ok, detail)."""
    IPC_RMID = 0
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
    except OSError as exc:
        return False, "cannot load libc: %s" % exc
    ctypes.set_errno(0)
    libc.shmctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    libc.shmctl.restype = ctypes.c_int
    rc = libc.shmctl(ctypes.c_int(shmid), ctypes.c_int(IPC_RMID), None)
    if rc != 0:
        err = ctypes.get_errno()
        return False, "shmctl(IPC_RMID) failed: %s (errno %d)" % (
            errno.errorcode.get(err, "?"), err)
    return True, "segment removed"


def release_shm(shmid, _shm_rows=None, _maps=None, _proc=None, _rmid=None):
    """Release ONE orphaned segment, RE-VERIFYING orphan status first.

    The re-check is the whole safety interlock and is not optional. The popup
    may sit open for minutes between listing and the user pressing the button,
    and a segment can be re-attached in that window -- so the listing is a
    proposal, never a licence to act. A segment that no longer qualifies is
    REFUSED, not removed, and the refusal is a logged failure (E-RAMREC-003)
    rather than a silent skip.

    Returns (ok, detail, code) -- `code` is the error code to record, or None.
    """
    try:
        current = find_orphan_shm(_shm_rows=_shm_rows, _maps=_maps, _proc=_proc)
    except OrphanCheck as exc:
        return False, "re-verification could not run: %s" % exc, "E-RAMREC-004"

    match = next((s for s in current if s["shmid"] == shmid), None)
    if match is None:
        return (False,
                "REFUSED: shmid %d no longer satisfies every orphan condition "
                "at release time" % shmid,
                "E-RAMREC-003")

    ok, detail = (_rmid or _shmctl_rmid)(shmid)
    if not ok:
        return False, detail, "E-RAMREC-002"
    return True, "released %d bytes (shmid %d)" % (match["bytes"], shmid), None


# ── orchestration ────────────────────────────────────────────────────────────
def clean_selected(selections, *, sample=None, recorder=None,
                   _proc=None, _rmid=None, _kill=None, _run=None, _sleep=None,
                   _shm_rows=None, _maps=None):
    """Act on the user's checked selections.

    `selections` is [{"kind": "zombie", "ppid": N} | {"kind": "shm",
    "shmid": N}]. `recorder(code, context)` records a FAILURE ONLY -- successes
    are returned for display, never written to the error ledger.
    """
    results = []
    for sel in selections or []:
        kind = sel.get("kind")
        if kind == "zombie":
            ppid = sel.get("ppid")
            ok, detail, code = reap_zombie(
                sel.get("pid"), ppid, sel.get("case", CASE_TERMINATE),
                unit=sel.get("unit"), user_scope=bool(sel.get("user_scope")),
                starttime=sel.get("starttime"),
                _kill=_kill, _run=_run, _proc=_proc, _sleep=_sleep)
            results.append({"kind": "zombie", "ppid": ppid, "pid": sel.get("pid"),
                            "case": sel.get("case"), "unit": sel.get("unit"),
                            "ok": ok, "detail": detail, "bytes_freed": 0})
        elif kind == "shm":
            shmid = sel.get("shmid")
            ok, detail, code = release_shm(
                shmid, _shm_rows=_shm_rows, _maps=_maps, _proc=_proc,
                _rmid=_rmid)
            results.append({"kind": "shm", "shmid": shmid, "ok": ok,
                            "detail": detail,
                            "bytes_freed": sel.get("bytes", 0) if ok else 0})
        else:
            results.append({"kind": kind, "ok": False,
                            "detail": "unknown selection kind %r" % kind})
            code = None

        if code and recorder is not None:
            try:
                recorder(code, {"selection": sel,
                                "detail": results[-1]["detail"]})
            except Exception:
                # Logging a failure must never turn into a second failure that
                # sinks the whole cleanup run.
                pass
    return results


def self_test():
    """Prove the orphan classifier can produce BOTH answers before it is
    trusted -- a known-orphan and a known-live fixture, checked on every call.
    A classifier that can only ever say 'orphan' would look identical to a
    working one right up until it deleted something live.
    """
    live = [{"shmid": 1, "key": 0x1111, "size": 4096, "cpid": 1,
             "nattch": 1, "perms": 0o600}]
    orphan = [{"shmid": 2, "key": 0x2222, "size": 8192, "cpid": 999999,
               "nattch": 0, "perms": 0o600}]
    maps_none = (set(), 10, 0)

    live_v = shm_inventory(_shm_rows=live, _maps=maps_none)["segments"][0]
    orph_v = shm_inventory(_shm_rows=orphan, _maps=maps_none)["segments"][0]
    if live_v["orphan"]:
        raise OrphanCheck("self-test: an ATTACHED segment classified as orphan")
    if not orph_v["orphan"]:
        raise OrphanCheck("self-test: a genuinely orphaned segment was missed")

    # and the maps cross-check alone must be able to veto
    vetoed = shm_inventory(_shm_rows=orphan,
                           _maps=({0x2222}, 10, 0))["segments"][0]
    if vetoed["orphan"]:
        raise OrphanCheck("self-test: /proc/*/maps veto did not apply")
    return True
