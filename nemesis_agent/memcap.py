"""Memory-inspection capability — can this agent read ANOTHER process's memory?

This is the acquisition-layer capability the memory-injection detector (step 4)
needs, scoped and reported HONESTLY here (step 3a) BEFORE the detector exists —
"leave the socket, don't wire the house". Nothing here reads memory for
detection; it answers exactly one question, truthfully: does this process
actually have the privilege to read a foreign process's address space, right now?

WHY A FUNCTIONAL TEST, NOT A CapEff BIT-READ
--------------------------------------------
The tempting shortcut is to read CAP_SYS_PTRACE out of /proc/self/status CapEff
and report that. It is the exact shape of instrument this codebase keeps finding
broken: a bit that is SET does not prove a read will succeed (Yama ptrace_scope,
an LSM, a seccomp filter, a mount option can all still refuse it), and a bit that
is CLEAR does not prove a read will fail (a root agent has the privilege with the
bit unset in some presentations). So the bit is CORROBORATING evidence only; the
authoritative test is to actually attempt a cross-privilege read and see what the
kernel does.

THREE STATES, FAIL-CLOSED (same discipline as attest/key_protection tiers)
--------------------------------------------------------------------------
    available    — a real cross-privilege read SUCCEEDED. The detector can run.
    unavailable  — a real cross-privilege read was DENIED (EPERM/EACCES) on a
                   valid foreign target. Confident negative.
    undetermined — could not be measured (no suitable foreign target, the target
                   raced away, /proc unreadable, non-Linux). NOT a pass and NOT a
                   confident fail — the honest third state. `undetermined` is
                   NEVER collapsed into `available`.

The distinction between `unavailable` and `undetermined` is load-bearing: a
default value that "means something" (here, silently reporting unavailable when
the truth is unmeasured, or worse available) is exactly the failure mode the
project's verification-code rule exists to prevent. A denial is measured; an
absence of measurement says so.

WHY process_vm_readv AND NOT /proc/<pid>/mem  (VM-verified 2026-08-22)
---------------------------------------------------------------------
The first cut acquired through `/proc/<pid>/mem`. That CANNOT work for the agent
as designed, and the VM proved it: CAP_SYS_PTRACE satisfies `ptrace_may_access`,
but it does NOT bypass ordinary file permissions — that is CAP_DAC_OVERRIDE. And
the two /proc files are not equally permissive:

    /proc/<pid>/maps   mode 0444   world-readable; only ptrace_may_access gates it
    /proc/<pid>/mem    mode 0600   owned by the target's user

So a non-root agent holding CAP_SYS_PTRACE reads a root process's `maps` fine and
then gets EACCES merely OPENING its `mem` — a plain DAC denial, before any
privilege check is reached. The maps read succeeding is exactly what made the
broken design look plausible.

`process_vm_readv(2)` is gated ONLY by `ptrace_may_access` and touches no file, so
CAP_SYS_PTRACE alone is sufficient — verified live, non-root, reading pid 1. The
alternative "fix", granting CAP_DAC_OVERRIDE, would work and would also hand the
agent read access to every file on the box; that trades away the bounded blast
radius this step exists to keep. The primitive changed instead of the grant.

PLATFORM
--------
Linux only in 3a: acquisition is `process_vm_readv` gated by CAP_SYS_PTRACE, and a
plain systemd service can be granted it (AmbientCapabilities=CAP_SYS_PTRACE, an
opt-in drop-in — see deploy_memscan_linux.sh) with no process-model change. The
Windows path (SeDebugPrivilege in a SYSTEM service, behind the two-process split)
is step 3b/3c and reports `undetermined` here until then.
"""

from __future__ import annotations

import ctypes
import os
import sys

AVAILABLE = "available"
UNAVAILABLE = "unavailable"
UNDETERMINED = "undetermined"

#: CAP_SYS_PTRACE is bit 19. Used only as corroborating evidence in the report,
#: never as the authoritative verdict (see the module docstring).
CAP_SYS_PTRACE_BIT = 19

#: How many distinct foreign targets to try before giving up as `undetermined`.
#: A single target can race away between reading its maps and its memory; a confident
#: `unavailable` needs an actual permission denial, not a transient miss.
_MAX_TARGETS = 8


#: Bound lazily; None means the syscall is unavailable on this box (very old
#: kernel, or a libc without the wrapper). That is `undetermined`, never a denial.
_pvr = None
_pvr_loaded = False


class _IoVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


def _process_vm_readv():
    """Bind process_vm_readv(2), or return None if it is not available.

    An unavailable syscall is an absence of measurement, not a denial — the caller
    maps it to `undetermined`, per this module's fail-closed rule.
    """
    global _pvr, _pvr_loaded
    if _pvr_loaded:
        return _pvr
    _pvr_loaded = True
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        fn = libc.process_vm_readv
        fn.restype = ctypes.c_ssize_t
        fn.argtypes = [ctypes.c_int,
                       ctypes.POINTER(_IoVec), ctypes.c_ulong,
                       ctypes.POINTER(_IoVec), ctypes.c_ulong,
                       ctypes.c_ulong]
        _pvr = fn
    except (OSError, AttributeError):
        _pvr = None
    return _pvr


def _is_linux() -> bool:
    return sys.platform.startswith("linux")


def _capeff() -> int | None:
    """Effective capability bitmask from the kernel, or None if unreadable.

    Mirrors alert_manager/nemesis_privsep.py's reader rather than importing it —
    that module lives in the server tree and asserts the OPPOSITE boundary
    (empty caps); duplicating this two-line read keeps the agent free of a
    cross-tree dependency, the same reasoning nemesis_privsep gives for not
    importing the agent.
    """
    try:
        with open("/proc/self/status", "r") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    return int(line.split(":", 1)[1].strip(), 16)
    except (OSError, ValueError):
        return None
    return None


def has_cap_sys_ptrace() -> bool | None:
    """True/False if CAP_SYS_PTRACE is in the effective set, or None if unreadable.
    CORROBORATING ONLY — see the module docstring on why this is not the verdict."""
    caps = _capeff()
    if caps is None:
        return None
    return bool(caps & (1 << CAP_SYS_PTRACE_BIT))


#: How many readable mappings of one target to try before giving up on it. A
#: region flagged readable in maps can still EFAULT (guard pages, [vvar]); trying
#: a few keeps a single odd mapping from turning a real answer into `undetermined`.
_MAX_REGIONS = 16


def _readable_regions(pid: int, limit: int = _MAX_REGIONS):
    """Yield (start, size) for up to `limit` readable mappings of `pid`.

    ⚠ Does NOT swallow a permission denial. Reading a foreign process's
    /proc/<pid>/maps is gated by ptrace_may_access (confirmed live 2026-08-21: a
    cross-uid maps read returns EPERM without the capability; 2026-08-22: the same
    read SUCCEEDS once CAP_SYS_PTRACE is granted). So a PermissionError HERE is a
    measured 'no capability' signal and must reach the caller as a denial, not be
    lost as 'no region found' — that lost signal was the first cut's bug.
    PermissionError therefore PROPAGATES; only a genuinely regionless or
    unparseable target yields nothing.

    NOTE maps is mode 0444 and merely ptrace-gated, whereas /proc/<pid>/mem is
    0600 and DAC-gated — the asymmetry that broke the original acquisition path.
    See the module docstring.
    """
    n = 0
    with open("/proc/%d/maps" % pid, "r") as fh:      # PermissionError propagates
        for line in fh:                               # a mid-read EPERM propagates too
            # e.g. "5583a1c00000-5583a1c21000 rw-p 00000000 00:00 0  [heap]"
            fields = line.split()
            if len(fields) < 2 or fields[1][:1] != "r":
                continue
            try:
                lo, hi = fields[0].split("-", 1)
                lo, hi = int(lo, 16), int(hi, 16)
            except ValueError:
                continue
            if lo > 0 and hi > lo:
                yield lo, hi - lo
                n += 1
                if n >= limit:
                    return


def _try_read_foreign_byte(pid: int):
    """Attempt to read ONE byte of `pid`'s memory via process_vm_readv. Returns:
        True   — read succeeded (we have the privilege for this target)
        False  — access was DENIED by permission (EPERM/EACCES) at EITHER step
                 (the maps read or the syscall): a confident, measured negative
        None   — could not test this target (raced away, no readable region, the
                 syscall is unavailable, other error)

    The three-way return is the whole point: a permission denial is a MEASUREMENT
    (privilege absent); anything else is an absence of measurement, and must not be
    reported as either a pass or a confident fail.

    Acquisition is process_vm_readv, NOT /proc/<pid>/mem: the latter is a 0600
    file, so opening it needs CAP_DAC_OVERRIDE rather than the CAP_SYS_PTRACE this
    step grants, and a non-root agent is refused at the DAC layer before any
    privilege check runs (VM-verified 2026-08-22 — see the module docstring).
    """
    import errno
    fn = _process_vm_readv()
    if fn is None:
        return None                                   # syscall absent — unmeasured

    try:
        regions = list(_readable_regions(pid))
    except PermissionError:
        return False                                  # EPERM/EACCES — measured denial
    except OSError as exc:
        # EPERM/EACCES can also arrive as a bare OSError on some kernels; a denial.
        # Everything else (ENOENT raced-away, ...) is untestable.
        if exc.errno in (errno.EPERM, errno.EACCES):
            return False
        return None
    if not regions:
        return None                                   # kernel thread / no mappings

    buf = (ctypes.c_char * 1)()
    local = _IoVec(ctypes.cast(buf, ctypes.c_void_p), 1)
    for start, _size in regions:
        remote = _IoVec(ctypes.c_void_p(start), 1)
        ctypes.set_errno(0)
        got = fn(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
        if got == 1:
            return True
        err = ctypes.get_errno()
        if err in (errno.EPERM, errno.EACCES):
            return False                              # measured denial
        if err == errno.ESRCH:
            return None                               # raced away mid-probe
        # EFAULT/EIO/partial: this mapping is not readable at that address —
        # try the next one rather than calling the target untestable.
    return None


def _iter_targets(my_uid: int):
    """Yield candidate discriminator pids — targets whose memory can be read ONLY
    with CAP_SYS_PTRACE (or root's inherent copy of it), never via same-uid Yama
    permission.

    pid 1 (init/systemd) FIRST and unconditionally: it is always present, always a
    REAL process with a readable address space, and is NEVER a descendant of the
    agent — so reading it requires the capability regardless of the agent's own
    uid (root reads it via its inherent cap; a non-root agent needs the grant).
    That makes it the one universal, churn-immune discriminator. The first cut
    chased newest-pid targets and got `undetermined` because they raced away on a
    high-churn box; pid 1 does not race away.

    Then, as insurance if pid 1 is ever untestable, DIFFERENT-uid pids: reading
    those also always requires the capability (a uid mismatch fails
    ptrace_may_access without it), independent of the box's ptrace_scope. Kernel
    threads (empty maps) simply return `None` and are skipped by the caller.
    """
    my_pid = os.getpid()
    if 1 != my_pid:
        yield 1
    try:
        entries = sorted(int(e) for e in os.listdir("/proc") if e.isdigit())
    except OSError:
        return
    for pid in entries:
        if pid in (1, my_pid):
            continue
        try:
            st = os.stat("/proc/%d" % pid)
        except OSError:
            continue
        if st.st_uid != my_uid:
            yield pid


def probe() -> dict:
    """Answer 'can this agent read a foreign process's memory?' — honestly.

    Never raises. Returns a state dict suitable for the heartbeat, with the
    authoritative functional verdict plus corroborating evidence (euid, the
    CAP_SYS_PTRACE bit) so a reader can see WHY, and can never mistake the
    corroborating bit for the verdict.
    """
    if not _is_linux():
        return {"state": UNDETERMINED,
                "detail": "non-Linux platform; Windows SeDebugPrivilege path is "
                          "step 3b/3c",
                "method": "platform-gate",
                "euid": None, "capeff_has_ptrace": None}

    euid = os.geteuid()
    cap_bit = has_cap_sys_ptrace()

    tested = 0
    saw_denial = False
    for pid in _iter_targets(euid):
        result = _try_read_foreign_byte(pid)
        if result is True:
            return {"state": AVAILABLE,
                    "detail": "read a foreign process's memory (pid %d) — the "
                              "detector can acquire target memory" % pid,
                    "method": "functional process_vm_readv cross-uid read",
                    "euid": euid, "capeff_has_ptrace": cap_bit}
        if result is False:
            saw_denial = True
        tested += 1
        if tested >= _MAX_TARGETS:
            break

    if saw_denial:
        return {"state": UNAVAILABLE,
                "detail": "cross-privilege memory read DENIED (EPERM) — grant "
                          "CAP_SYS_PTRACE (see deploy_memscan_linux.sh) or run the "
                          "detector in a privileged component",
                "method": "functional process_vm_readv cross-uid read",
                "euid": euid, "capeff_has_ptrace": cap_bit}

    return {"state": UNDETERMINED,
            "detail": ("no foreign process could be tested (%d tried) — capability "
                       "could not be measured, NOT assumed present" % tested),
            "method": "functional process_vm_readv cross-uid read",
            "euid": euid, "capeff_has_ptrace": cap_bit}


def _read_own_byte_impl():
    """Read one byte of OUR OWN memory through the SAME reader used for foreign
    targets — a process may always read itself, so this proves that exact read path
    works independent of any privilege. Returns True (read ok) / False (denied,
    impossible for self) / None (no region, impossible for self)."""
    return _try_read_foreign_byte(os.getpid())


def self_test() -> dict:
    """Premise proof: the probe's instrument must be able to produce BOTH answers.

    Runs the two controls that a broken probe would fail:
      * reading OUR OWN memory MUST succeed — proves the read path actually works,
        so an `unavailable`/`undetermined` verdict reflects the kernel's decision
        and not a bug in our own reader (which would deny everything).
      * reading a NON-EXISTENT pid MUST NOT succeed — proves the reader does not
        rubber-stamp success, so an `available` verdict reflects a real read.
    Non-Linux is a clean skip (the functional path does not apply there yet).
    """
    if not _is_linux():
        return {"ok": True, "findings": [], "skipped": "non-Linux"}
    findings = []

    own = _read_own_byte_impl()
    if own is not True:
        findings.append("could not read our OWN memory (%r) — the reader itself is "
                        "broken, so no verdict from it can be trusted" % (own,))

    bogus_pid = 2 ** 30                       # far above any real pid
    bogus = _try_read_foreign_byte(bogus_pid)
    if bogus is True:
        findings.append("reported a successful read of a non-existent pid — the "
                        "reader rubber-stamps success")

    return {"ok": not findings, "findings": findings}


if __name__ == "__main__":                                # pragma: no cover
    import json
    # --json emits ONE machine-readable object (self-test + probe) for the deploy
    # canary to parse. The self-test travels WITH the verdict deliberately: a
    # verdict from a reader that cannot prove its own premise is not evidence, so
    # the canary can refuse both a bad state AND a broken instrument.
    if "--json" in sys.argv:
        st = self_test()
        print(json.dumps({"self_test": st, "probe": probe()}))
    else:
        st = self_test()
        print("self-test:", "PASS" if st["ok"] else "FAIL")
        for f in st["findings"]:
            print("  -", f)
        print(json.dumps(probe(), indent=2))
