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
import pwd
import re
import signal
import subprocess
import time

__all__ = [
    "E_CODES", "register_codes",
    "find_zombies", "find_orphan_shm", "shm_inventory",
    "reap_zombie", "release_shm", "clean_selected",
    "classify_parent", "ancestor_pids", "verify_zombie_gone",
    "proc_state", "proc_starttime", "proc_ppid", "proc_cgroup_unit",
    "reap_zombie_verified", "zombie_self_test", "detect_regeneration",
    "REAP_KIND_CODE", "REAP_CODE_KIND",
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
    # 008 exists because the 007 interlock STOPS WORKING once classification
    # moves to root (2026-08-20). 007 asks "is this parent an ancestor of MY
    # process?" -- a question whose answer depends entirely on who is asking.
    # Measured on the build box: ptyxis (141640) IS an ancestor of an operator
    # shell, so 007 fires there; it is NOT an ancestor of `dashboard` (707418)
    # or `nemesis-fwd` (702432), so 007 does not fire in the helper at all.
    # While the dashboard was unprivileged that gap was masked by EPERM. Root
    # has no EPERM, so porting 007 alone would have turned a harmless failure
    # into a successful kill of the operator's terminal.
    # In the ledger DESPITE the reap succeeding, which is a deliberate
    # exception to the failures-only rule rather than a drift from it. The
    # ledger exists for "a fault an operator would want to know happened", and
    # a parent that regenerates its zombie on every restart IS one -- it is
    # just not OUR fault. Recording it is the difference between "you cleaned
    # this 40 times" and "this parent is broken"; without it the recurrence is
    # invisible in history and each reap looks like an isolated success.
    "E-RAMREC-009": (
        "Zombie reappeared immediately after a successful reap",
        "The reap worked and the original zombie is gone, but an equivalent "
        "zombie (same child process name, same parent unit) appeared right "
        "after. The parent is producing zombies faster than clearing them "
        "helps, so the action treats the symptom and the cause is upstream.",
        "low"),
    "E-RAMREC-008": (
        "Refused to terminate a process in a live interactive session",
        "The zombie's parent belongs to a logged-in user's systemd session "
        "and cannot be restarted (it is a .scope, or reports CanStart=no). "
        "Terminating it would close a running desktop application out from "
        "under the person using it, and a zombie reap frees no memory -- so "
        "the interlock refuses rather than acting.",
        "medium"),
}

#: The zombie op crosses a process boundary, so the failure REASON has to
#: survive the trip. nemesis_fwd raises Denied(kind); the dashboard maps that
#: kind back to the ledger code. Defined here -- the one module both sides
#: already import -- so there is a single definition rather than two that drift.
#:
#: Deliberately NOT message-text matching on the receiving side: prose gets
#: reworded, and a caller keying on it would start mis-filing codes silently.
REAP_KIND_CODE = {
    "reap_refused_ancestor": "E-RAMREC-007",
    "reap_refused_session":  "E-RAMREC-008",
    "reap_unconfirmed":      "E-RAMREC-006",
    "reap_failed":           "E-RAMREC-005",
}
REAP_CODE_KIND = {v: k for k, v in REAP_KIND_CODE.items()}

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


# ── unit resolution: the CGROUP, not `systemctl status <pid>` ────────────────
# REPLACED 2026-08-20. The previous resolver shelled out to
# `systemctl [--user] status <pid>` and parsed the header line. It returned a
# DIFFERENT ANSWER DEPENDING ON WHICH ACCOUNT RAN IT, which is the whole reason
# the zombie feature failed in production:
#
#     as the desktop user:  speech-dispatcher.service   <- correct
#     as nemesis-dash:      user@<uid>.service          <- the container unit
#
# `systemctl --user` needs $XDG_RUNTIME_DIR and a session bus. `nemesis-dash`
# is a nologin system account with no /run/user/973, so the --user probe could
# never work there; it fell back to SYSTEM scope, which answers with the
# container unit for ANY user process. The container blocklist then correctly
# refused that, leaving unit=None -> SIGTERM -> EPERM. Every layer behaved as
# written; the input was wrong.
#
# /proc/<pid>/cgroup has none of those properties. World-readable, no bus, no
# runtime dir, no privilege, and it is the same data systemd itself uses to
# answer this question. Verified against every relevant case on the build box,
# each producing a DISTINGUISHABLE answer rather than one uniform one:
#     ptyxis 141640       -> app-gnome-xdg-terminal-exec-141640.scope  uid 1000
#     speech-disp 210451  -> speech-dispatcher.service                 uid 1000
#     dashboard 707418    -> dashboard.service                         uid None
#     user@1000 manager   -> init.scope                                uid 1000
#     pid 999999          -> None (explicit failure, not a default)
_CG_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")
_UNIT_SUFFIXES = (".service", ".scope", ".socket", ".mount", ".slice")


def _cg_unescape(name):
    """systemd escapes unit names inside cgroup paths (`\\x2d` for `-`)."""
    return _CG_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), name)


def proc_cgroup_unit(pid, _proc=None):
    """Resolve pid -> {unit, user_uid, path} from /proc/<pid>/cgroup.

    Returns None if the cgroup cannot be read AT ALL -- an explicit "I do not
    know", never an empty-but-legal-looking answer. Callers must treat None as
    a refusal to act, not as "no unit owns this".

    `user_uid` is the owning login uid when the process sits under a
    `user@<uid>.service` manager, else None for a system-scope process. That
    single field is what tells a caller whether acting on this process would
    reach into a live human session.
    """
    try:
        with open(os.path.join(_proc or _PROC, str(pid), "cgroup"), "r") as fh:
            data = fh.read()
    except OSError:
        return None

    # cgroup v2 is the `0::<path>` line. v1 controller lines are ignored: they
    # do not carry the unit for a systemd-managed process on this box.
    path = None
    for line in data.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == "0" and parts[1] == "":
            path = parts[2]
            break
    if path is None:
        return None

    unit, user_uid = None, None
    for comp in path.split("/"):
        if not comp:
            continue
        name = _cg_unescape(comp)
        if name.startswith("user@") and name.endswith(".service"):
            try:
                user_uid = int(name[len("user@"):-len(".service")])
            except ValueError:
                pass
        # LAST unit-like component wins: the leaf is the actual owning unit,
        # everything above it is the slice/manager hierarchy.
        if any(name.endswith(suf) for suf in _UNIT_SUFFIXES):
            unit = name
    return {"unit": unit, "user_uid": user_uid, "path": path}


def proc_ppid(pid, _proc=None):
    """Parent pid from /proc/<pid>/status. None if unreadable.

    Read SERVER-SIDE so the parent is never a caller-supplied claim: the helper
    must decide for itself whose parent it is about to act on.
    """
    try:
        with open(os.path.join(_proc or _PROC, str(pid), "status"), "r") as fh:
            for line in fh:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except (OSError, ValueError):
        return None
    return None


def _run_cmd(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except Exception as exc:                                 # noqa: BLE001
        return 1, "", str(exc)


def _run_cmd_as(cmd, uid, env, timeout=8):
    """Run `cmd` as `uid` (None = unchanged) with `env` overlaid.

    ⚠ `preexec_fn` runs between fork and exec and is only async-signal-safe in a
    SINGLE-THREADED parent. That holds today: nemesis_fwd.serve() is a plain
    accept loop with no threading, and the dashboard never reaches this branch
    (it is not root). If either ever becomes threaded, this must move to
    `subprocess.run(..., user=, group=, extra_groups=)` (Python 3.9+), which
    does the same work inside CPython's own safe child setup.
    """
    def _drop():
        os.setgroups([])
        os.setgid(pwd.getpwuid(uid).pw_gid)
        os.setuid(uid)

    full = dict(os.environ)
    full.update(env or {})
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=full, preexec_fn=_drop if uid is not None else None)
        return r.returncode, r.stdout, r.stderr
    except Exception as exc:                                 # noqa: BLE001
        return 1, "", str(exc)


def _systemctl(args, user_uid=None, _run=None):
    """`systemctl` in the right manager for `user_uid`.

    user_uid None  -> the system manager.
    user_uid set   -> that login's `--user` manager.

    WHEN WE ARE ROOT we do NOT talk to the user manager as root. We DROP TO
    THAT UID first and run as them. Two reasons, both deliberate:
      * it is the identity that legitimately owns the unit, so no polkit or
        cross-uid bus-policy question arises at all; and
      * it bounds the blast radius -- a bug in an argument we build can only
        ever reach one unprivileged user's own session, never the system
        manager.
    Any account that is neither root nor the target returns an explicit
    failure rather than silently answering from the wrong manager -- that
    silent wrong answer is precisely the bug this replaced.
    """
    cmd = ["systemctl"] + (["--user"] if user_uid is not None else []) + list(args)
    if _run is not None:
        return _run(cmd)
    if user_uid is None:
        return _run_cmd(cmd)

    runtime_dir = "/run/user/%d" % user_uid
    if not os.path.isdir(runtime_dir):
        return 1, "", ("uid %d has no %s -- no running user manager"
                       % (user_uid, runtime_dir))
    env = {"XDG_RUNTIME_DIR": runtime_dir,
           "DBUS_SESSION_BUS_ADDRESS": "unix:path=%s/bus" % runtime_dir}
    euid = os.geteuid()
    if euid == user_uid:
        return _run_cmd_as(cmd, None, env)
    if euid != 0:
        return 1, "", ("uid %d cannot reach uid %d's systemd manager"
                       % (euid, user_uid))
    return _run_cmd_as(cmd, user_uid, env)


def _unit_property(unit, prop, user_uid=None, _run=None):
    """One unit property, or None if it could not be READ.

    None means "unknown", never "no". Callers that are about to ACT must treat
    unknown as a refusal (see reap_zombie_verified), because a property that
    failed to load is indistinguishable from a real answer to anything that
    defaults it.
    """
    rc, out, _err = _systemctl(["show", unit, "-p", prop, "--value"],
                               user_uid, _run=_run)
    return (out or "").strip() if rc == 0 else None


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


def classify_parent(ppid, _proc=None, _run=None, _self_pid=None, _cgroup=None):
    """Three-way classification of a zombie's parent.

    Returns {case, unit, user_uid, user_scope, canstart, why}. Two interlocks
    run before anything can be classified as actionable, and both override a
    perfectly restartable-looking unit.
    """
    # ── interlock 1: our own ancestors ──
    # Cheap, and still correct as far as it goes -- but see interlock 2 for why
    # it is NOT sufficient on its own once this runs as root.
    mine = ancestor_pids(_self_pid, _proc=_proc)
    if ppid in mine:
        return {"case": CASE_REFUSED, "unit": None, "user_uid": None,
                "user_scope": None, "canstart": None,
                "why": "pid %d is an ancestor of the Nemesis process; acting "
                       "on it would kill the session Nemesis is running in"
                       % ppid}

    info = _cgroup if _cgroup is not None else proc_cgroup_unit(ppid, _proc=_proc)
    if info is None:
        # A failed read is NOT "no unit owns this process". Refuse.
        return {"case": CASE_REFUSED, "unit": None, "user_uid": None,
                "user_scope": None, "canstart": None,
                "why": "cannot read the cgroup of pid %d, so what owns it is "
                       "UNKNOWN -- refusing rather than guessing" % ppid}

    unit, user_uid = info.get("unit"), info.get("user_uid")
    in_session = user_uid is not None

    def not_restartable(why, keep_unit=None):
        """The parent cannot be RESTARTED. Terminate it, or refuse outright.

        ── interlock 2: live interactive sessions (added 2026-08-20) ──
        The ancestor interlock above asks "is this an ancestor of MY process?",
        and that answer depends on who is asking. Measured on the build box:
        ptyxis (141640) is an ancestor of an operator shell -- so the check
        fires there -- but NOT of `dashboard` (707418) or `nemesis-fwd`
        (702432), so it does not fire in either service. While the dashboard
        was unprivileged that gap was hidden by EPERM: the kill was refused by
        the kernel, and the failure was read as the interlock working. Root has
        no EPERM. Porting interlock 1 alone into the helper would therefore have
        converted a harmless failure into a SUCCESSFUL kill of the operator's
        terminal.

        So the real question is not "is it my ancestor" but "does a human have
        this on screen right now". A process under a `user@<uid>.service`
        manager belongs to a live login session; terminating it closes a
        running application out from under whoever is using it, with no
        systemd restart to bring it back. Weighed against a reap that frees
        NO memory at all (only a process-table slot), that trade is never
        worth making -- so it is refused, not attempted.

        A system-scope parent has no such user, and SIGTERM stays available.
        """
        if in_session:
            return {"case": CASE_REFUSED, "unit": keep_unit,
                    "user_uid": user_uid, "user_scope": True, "canstart": None,
                    "why": "%s, and it belongs to the live session of uid %d "
                           "-- terminating it would close a running "
                           "application out from under that user, to free no "
                           "memory" % (why, user_uid)}
        return {"case": CASE_TERMINATE, "unit": keep_unit, "user_uid": None,
                "user_scope": False, "canstart": None, "why": why}

    if not unit:
        return not_restartable("no systemd unit owns pid %d" % ppid)

    if _is_container_unit(unit):
        # unit is CLEARED so nothing downstream can restart the container.
        return not_restartable(
            "pid %d resolved only to the container unit %s, which owns the "
            "whole session and must never be restarted for one zombie"
            % (ppid, unit))

    if not unit.endswith(".service"):
        return not_restartable(
            "unit %s is a %s, not a service -- it has no ExecStart and cannot "
            "be restarted (systemd: 'Job type restart is not applicable')"
            % (unit, unit.rsplit(".", 1)[-1]), keep_unit=unit)

    canstart = _unit_property(unit, "CanStart", user_uid, _run=_run)
    if canstart == "yes":
        return {"case": CASE_SERVICE, "unit": unit, "user_uid": user_uid,
                "user_scope": in_session, "canstart": "yes",
                "why": "restartable service unit"}
    if canstart is None:
        # UNKNOWN, not "no". Listing runs in the dashboard, which cannot reach
        # a user manager -- so it may legitimately not know. The listing is a
        # PROPOSAL and says so; reap_zombie_verified re-derives this on the
        # privileged side and fails closed if it still cannot confirm.
        return {"case": CASE_SERVICE, "unit": unit, "user_uid": user_uid,
                "user_scope": in_session, "canstart": None,
                "why": "unit %s looks restartable, but CanStart could not be "
                       "read from here -- to be confirmed before any action"
                       % unit}
    return not_restartable(
        "unit %s reports CanStart=%r" % (unit, canstart), keep_unit=unit)


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
            "user_scope": cls.get("user_scope"),
            "user_uid": cls.get("user_uid"),
            # Carried so the UI can be honest that the listing is a PROPOSAL:
            # None means the restartability of the unit is not yet confirmed
            # and the privileged side will decide.
            "canstart": cls.get("canstart"),
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


def reap_zombie(zpid, ppid, case, unit=None, user_uid=None, starttime=None,
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
        rc, _out, err = _systemctl(["restart", unit], user_uid, _run=_run)
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


def zombie_self_test(_proc=None):
    """Prove the zombie classifier can produce ALL THREE answers before it is
    trusted to authorise an action -- the same premise-check `self_test` does
    for the orphan classifier, and required for the same reason: a classifier
    stuck on one answer looks identical to a working one until it acts.

    Runs on FIXTURES, not live processes, so it is deterministic and cannot be
    made to pass by the state of the box.
    """
    def fixed(cg, canstart="yes"):
        return classify_parent(
            424242, _cgroup=cg, _self_pid=1,
            _run=lambda cmd: (0, canstart + "\n", ""))

    sysd = fixed({"unit": "cups.service", "user_uid": None, "path": "/system.slice/cups.service"})
    if sysd["case"] != CASE_SERVICE:
        raise OrphanCheck("zombie self-test: a restartable system service did "
                          "not classify as %s (got %s)" % (CASE_SERVICE, sysd["case"]))

    orphan_proc = fixed({"unit": None, "user_uid": None, "path": "/"})
    if orphan_proc["case"] != CASE_TERMINATE:
        raise OrphanCheck("zombie self-test: an unowned system process did not "
                          "classify as %s (got %s)"
                          % (CASE_TERMINATE, orphan_proc["case"]))

    # The one that matters: a desktop .scope must be REFUSED, not terminated.
    scope = fixed({"unit": "app-gnome-term-1.scope", "user_uid": 1000,
                   "path": "/user.slice/user-1000.slice/user@1000.service/"
                           "app.slice/app-gnome-term-1.scope"})
    if scope["case"] != CASE_REFUSED:
        raise OrphanCheck("zombie self-test: a live-session .scope classified "
                          "as %s -- it MUST be %s" % (scope["case"], CASE_REFUSED))

    # The REGENERATION MATCHER must be able to say both things. One that can
    # only ever answer "no" silently restores the unqualified success this was
    # built to remove, and looks identical to a working one from the outside.
    same = {"pid": 2, "ppid": 20, "comm": "sd_espeak-ng-mb"}
    args = (1, "sd_espeak-ng-mb", "speech-dispatcher.service", "speech-dispatch")
    if not _is_equivalent_zombie(same, *args,
                                 cand_parent_unit="speech-dispatcher.service",
                                 cand_parent_comm="speech-dispatch"):
        raise OrphanCheck("zombie self-test: the regeneration matcher failed "
                          "to recognise an equivalent zombie")
    if _is_equivalent_zombie({"pid": 3, "ppid": 30, "comm": "something-else"},
                             *args, cand_parent_unit="speech-dispatcher.service",
                             cand_parent_comm="speech-dispatch"):
        raise OrphanCheck("zombie self-test: the regeneration matcher matched "
                          "a DIFFERENT child process")
    if _is_equivalent_zombie({"pid": 1, "ppid": 20, "comm": "sd_espeak-ng-mb"},
                             *args, cand_parent_unit="speech-dispatcher.service",
                             cand_parent_comm="speech-dispatch"):
        raise OrphanCheck("zombie self-test: the matcher matched the very pid "
                          "that was just reaped")

    # And an unreadable cgroup must refuse, never fall through to terminate.
    unknown = classify_parent(424242, _cgroup=None, _self_pid=1,
                              _proc="/nonexistent-proc")
    if unknown["case"] != CASE_REFUSED:
        raise OrphanCheck("zombie self-test: an UNREADABLE cgroup classified "
                          "as %s -- unknown must refuse" % unknown["case"])
    return True


def _scan_zombies(_proc=None):
    """Every zombie currently in the process table: [{pid, ppid, comm}].

    Raises OrphanCheck if /proc itself cannot be listed -- an unreadable /proc
    must never degrade into "no zombies", which is a legal-looking answer that
    is indistinguishable from a real one.
    """
    proc = _proc or _PROC
    try:
        entries = os.listdir(proc)
    except OSError as exc:
        raise OrphanCheck("cannot list %s: %s" % (proc, exc))

    out = []
    for name in entries:
        if not name.isdigit():
            continue
        pid = int(name)
        if proc_state(pid, _proc=proc) != "Z":
            continue
        out.append({"pid": pid, "ppid": proc_ppid(pid, _proc=proc),
                    "comm": _comm(pid, _proc=proc)})
    return out


def _is_equivalent_zombie(cand, reaped_pid, child_comm, parent_unit,
                          parent_comm, cand_parent_unit, cand_parent_comm):
    """Is `cand` the same zombie in all but identity? PURE -- no I/O.

    Split out from the scan specifically so it can be self-tested on fixtures:
    a matcher that can only ever answer "no" would silently restore the exact
    unqualified-success behaviour this whole check exists to remove, and would
    look identical to a working one.

    "Equivalent" is same child process name AND same parent. Parent identity is
    the UNIT where there is one -- a restart gives the parent a new pid, so
    matching on pid would never fire for the case this is most needed for. With
    no unit (a terminated system process) the parent's comm is the best
    available anchor, and is labelled as weaker in the caller's message.
    """
    if cand.get("pid") == reaped_pid:
        return False                      # the one we just reaped
    if not child_comm or cand.get("comm") != child_comm:
        return False
    if parent_unit:
        return cand_parent_unit == parent_unit
    if parent_comm:
        return cand_parent_comm == parent_comm
    return False


def detect_regeneration(reaped_pid, child_comm, parent_unit, parent_comm,
                        timeout=3.0, _proc=None, _sleep=None):
    """Did an EQUIVALENT zombie reappear after a successful reap?

    WHY THIS EXISTS (measured in production 2026-08-20). Reaping the
    speech-dispatcher zombie restarts the unit; the fresh instance probes its
    output modules at startup, one of them dies, and it is not reaped -- so a
    NEW zombie exists within the same second. Observed three times, one per
    restart: 210451->210471, 878435->878448, 878877->878890. Every reap
    genuinely succeeded and the list looked unchanged, which reads as a broken
    feature when the feature is working exactly as designed.

    Reporting an unqualified success there is a true statement that leaves the
    operator with a false belief. This makes the recurrence visible instead.

    Returns (state, detail, match) with state one of:
        "regenerated" -- an equivalent zombie is back
        "clear"       -- none appeared within the window
        "unknown"     -- /proc could not be read, so NEITHER can be claimed
    """
    sleep = _sleep or time.sleep
    deadline = time.time() + max(0.0, timeout)

    while True:
        try:
            zombies = _scan_zombies(_proc=_proc)
        except OrphanCheck as exc:
            return ("unknown",
                    "could not check whether the zombie came back: %s" % exc,
                    None)

        for cand in zombies:
            cppid = cand.get("ppid")
            cinfo = proc_cgroup_unit(cppid, _proc=_proc) if cppid else None
            if _is_equivalent_zombie(
                    cand, reaped_pid, child_comm, parent_unit, parent_comm,
                    (cinfo or {}).get("unit"), _comm(cppid, _proc=_proc)):
                anchor = ("parent unit %s" % parent_unit if parent_unit
                          else "parent name %r (no unit -- a weaker match)"
                               % parent_comm)
                return ("regenerated",
                        "the zombie CAME BACK: %s reappeared as pid %s under "
                        "the same %s. The reap worked, but this parent "
                        "recreates the zombie, so clearing it again will not "
                        "help -- the cause is in the parent."
                        % (child_comm, cand.get("pid"), anchor),
                        cand)

        if time.time() >= deadline:
            return ("clear",
                    "checked for %.0fs afterwards and no equivalent zombie "
                    "came back" % max(0.0, timeout),
                    None)
        sleep(0.25)


def reap_zombie_verified(pid, _proc=None, _run=None, _kill=None, _sleep=None,
                         _verify=None, _regen_timeout=3.0):
    """Clear a zombie, RE-DERIVING every fact from the pid alone.

    THE PRIVILEGED ENTRY POINT. The caller sends one integer and vouches for
    nothing -- no parent, no case, no unit, no starttime. Same contract as
    `release_shm`, and for the same reason: the unprivileged dashboard is
    modelled as potentially compromised, so any fact it asserted would be a
    fact an attacker simply asserts differently.

    What that buys, concretely: THE HELPER ONLY EVER ACTS ON THE PARENT OF A
    PROCESS IT HAS ITSELF CONFIRMED IS A ZOMBIE. Without the state check below,
    a caller could name any live pid and have root SIGTERM its parent -- an
    arbitrary-process-kill primitive handed to the least trusted side of the
    boundary. That check, not the credential, is what bounds this op.

    Returns (ok, detail, code, info).
    """
    info = {"pid": pid}

    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
        return False, "pid must be an integer greater than 1", "E-RAMREC-005", info

    # ── the interlock: it must ACTUALLY be a zombie, right now ──
    state = proc_state(pid, _proc=_proc)
    if state is None:
        return (True, "pid %d is no longer in the process table; nothing to "
                      "reap" % pid, None, info)
    if state != "Z":
        return (False,
                "REFUSED: pid %d is not a zombie (state=%s). Only a confirmed "
                "zombie's parent may be acted on." % (pid, state),
                "E-RAMREC-005", info)

    # Captured HERE, not accepted from the caller: it is the PID-reuse guard
    # the post-action check depends on, so a caller-supplied value could
    # manufacture a "successfully reaped" verdict for a reap that never
    # happened.
    starttime = proc_starttime(pid, _proc=_proc)
    ppid = proc_ppid(pid, _proc=_proc)
    info.update({"ppid": ppid, "starttime": starttime,
                 "name": _comm(pid, _proc=_proc),
                 "parent_name": _comm(ppid, _proc=_proc) if ppid else None})

    if not ppid or ppid <= 1:
        return (False, "zombie %d has no actionable parent (ppid=%r); init "
                       "will reap it" % (pid, ppid), "E-RAMREC-005", info)

    cls = classify_parent(ppid, _proc=_proc, _run=_run)
    info.update({"case": cls["case"], "unit": cls["unit"],
                 "user_uid": cls.get("user_uid"),
                 "user_scope": cls.get("user_scope"),
                 "why": cls["why"]})

    if cls["case"] == CASE_REFUSED:
        # Which interlock refused decides which code is recorded -- 007 is the
        # ancestor check, 008 the live-session one. Distinguishable on purpose:
        # they fail for different reasons and one of them only exists because
        # the other stops working under root.
        code = "E-RAMREC-007" if "ancestor" in cls["why"] else "E-RAMREC-008"
        return False, "REFUSED: %s" % cls["why"], code, info

    if cls["case"] == CASE_SERVICE and cls.get("canstart") != "yes":
        # FAIL CLOSED. `canstart is None` means the property could not be read,
        # which is not permission to restart -- see _unit_property.
        return (False,
                "REFUSED: cannot confirm %s is restartable (CanStart=%r); "
                "refusing to act on an unverified unit"
                % (cls["unit"], cls.get("canstart")), "E-RAMREC-005", info)

    ok, detail, code = reap_zombie(
        pid, ppid, cls["case"], unit=cls["unit"], user_uid=cls.get("user_uid"),
        starttime=starttime, _kill=_kill, _run=_run, _proc=_proc,
        _sleep=_sleep, _verify=_verify)
    if not ok:
        return ok, detail, code, info

    # ── did it just come straight back? ──
    # A reap that succeeds and is immediately undone is still a success, and
    # saying only that leaves the operator believing something untrue. The
    # qualifier is attached HERE rather than left to the UI so every caller of
    # this function gets it, including any future non-UI one.
    state, regen_detail, match = detect_regeneration(
        pid, info.get("name"), cls["unit"], info.get("parent_name"),
        timeout=_regen_timeout, _proc=_proc, _sleep=_sleep)
    info["regeneration"] = state
    if match:
        info["regenerated_pid"] = match.get("pid")
    if state == "regenerated":
        # ok stays True: the reap DID work. The code records the recurrence,
        # which is a real defect in the parent even though our action succeeded.
        return True, "%s -- BUT %s" % (detail, regen_detail), "E-RAMREC-009", info
    return True, "%s; %s" % (detail, regen_detail), code, info


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
            # ONE code path, and it starts from the pid alone. Everything the
            # caller may have put in `sel` about the parent, case or unit is
            # deliberately IGNORED and re-derived -- see reap_zombie_verified.
            ok, detail, code, info = reap_zombie_verified(
                sel.get("pid"), _kill=_kill, _run=_run, _proc=_proc,
                _sleep=_sleep)
            results.append({"kind": "zombie", "pid": sel.get("pid"),
                            "ppid": info.get("ppid"), "case": info.get("case"),
                            "unit": info.get("unit"),
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
