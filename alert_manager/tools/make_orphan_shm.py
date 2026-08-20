#!/usr/bin/env python3
"""Deliberate leak generator — creates REAL orphaned SysV shared memory, and a
real zombie, so the manual RAM-recovery feature can be tested end to end.

TEST TOOL. Never invoked by production code. Intended for a disposable VM.

Why this exists: the orphan path only fires after a crash, so a healthy box
offers nothing to test against. Every earlier verification of this feature was
"no orphans found", which is indistinguishable from a detector that can never
find one. This makes the positive case real.

Modes
-----
  orphan   Create a segment, attach, detach, then EXIT without removing it.
           Result: nattch==0, creator pid dead, key non-zero, not SHM_DEST --
           a genuine orphan that MUST be detected.

  live     Create a segment, attach, and HOLD it until killed. This is the
           NEGATIVE CONTROL: nattch>0 and the key is visible in this process's
           /proc/<pid>/maps, so it MUST NEVER be offered as a candidate.
           Prints its own pid and shmid, then sleeps.

  zombie   Fork a child that exits immediately while the parent does NOT wait,
           leaving a real zombie. The parent holds until killed.

  both     `orphan` then a backgrounded `live`, for a single run that produces
           one cleanable and one untouchable segment at once.

Usage:  python3 make_orphan_shm.py orphan|live|zombie|both [--size-mb N]
"""

import ctypes
import os
import signal
import sys
import time

IPC_CREAT = 0o1000
IPC_RMID = 0

_libc = ctypes.CDLL("libc.so.6", use_errno=True)
_libc.shmget.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_int]
_libc.shmget.restype = ctypes.c_int
_libc.shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
_libc.shmat.restype = ctypes.c_void_p
_libc.shmdt.argtypes = [ctypes.c_void_p]
_libc.shmdt.restype = ctypes.c_int
_libc.shmctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
_libc.shmctl.restype = ctypes.c_int


def _fail(what):
    err = ctypes.get_errno()
    raise OSError(err, "%s failed: errno=%d" % (what, err))


def create_and_attach(size_bytes, key):
    """shmget + shmat. Returns (shmid, addr). Raises loudly on failure -- a
    test fixture that silently produced nothing would make the detector look
    correct while it was never actually exercised."""
    ctypes.set_errno(0)
    shmid = _libc.shmget(ctypes.c_int(key), ctypes.c_size_t(size_bytes),
                         IPC_CREAT | 0o600)
    if shmid < 0:
        _fail("shmget")
    ctypes.set_errno(0)
    addr = _libc.shmat(ctypes.c_int(shmid), None, 0)
    if addr == ctypes.c_void_p(-1).value or addr is None:
        _fail("shmat")
    # Touch the memory so it is genuinely resident, not just reserved.
    ctypes.memset(ctypes.c_void_p(addr), 0xAB, min(size_bytes, 1 << 20))
    return shmid, addr


def mode_orphan(size_bytes):
    key = 0x4E454D00 + (os.getpid() & 0xFF)
    shmid, addr = create_and_attach(size_bytes, key)
    print("ORPHAN shmid=%d key=0x%x size=%d creator_pid=%d"
          % (shmid, key, size_bytes, os.getpid()), flush=True)
    # Detach but DO NOT shmctl(IPC_RMID) -- this is the leak.
    if _libc.shmdt(ctypes.c_void_p(addr)) != 0:
        _fail("shmdt")
    print("detached without IPC_RMID; exiting -> segment is now orphaned",
          flush=True)
    # Exiting here is what makes the creator pid dead.


def mode_live(size_bytes):
    key = 0x4E454D80 + (os.getpid() & 0x7F)
    shmid, _addr = create_and_attach(size_bytes, key)
    print("LIVE shmid=%d key=0x%x size=%d holder_pid=%d"
          % (shmid, key, size_bytes, os.getpid()), flush=True)
    print("holding attached; MUST NOT be offered as a cleanup candidate",
          flush=True)

    def _bye(_sig, _frm):
        _libc.shmctl(ctypes.c_int(shmid), ctypes.c_int(IPC_RMID), None)
        print("live holder removed its own segment on exit", flush=True)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _bye)
    signal.signal(signal.SIGINT, _bye)
    while True:
        time.sleep(3600)


def mode_zombie():
    pid = os.fork()
    if pid == 0:
        os._exit(0)          # child dies immediately
    print("ZOMBIE child_pid=%d parent_pid=%d" % (pid, os.getpid()), flush=True)
    print("parent deliberately not calling wait(); child is now a zombie",
          flush=True)

    def _bye(_sig, _frm):
        sys.exit(0)

    signal.signal(signal.SIGTERM, _bye)
    signal.signal(signal.SIGINT, _bye)
    # NOTE: default SIGCHLD disposition means the zombie persists. When
    # ram_recovery sends SIGCHLD here, Python's default handler does not reap,
    # so this fixture demonstrates the honest case: SIGCHLD is a nudge that a
    # parent may ignore. Use `--reap-on-sigchld` to model a well-behaved parent.
    if "--reap-on-sigchld" in sys.argv:
        def _reap(_sig, _frm):
            try:
                while os.waitpid(-1, os.WNOHANG)[0]:
                    pass
            except ChildProcessError:
                pass
            print("parent reaped on SIGCHLD", flush=True)
        signal.signal(signal.SIGCHLD, _reap)
    while True:
        time.sleep(3600)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    mode = args[0] if args else "orphan"
    size_mb = 8
    if "--size-mb" in sys.argv:
        size_mb = int(sys.argv[sys.argv.index("--size-mb") + 1])
    size_bytes = size_mb * 1024 * 1024

    if mode == "orphan":
        mode_orphan(size_bytes)
    elif mode == "live":
        mode_live(size_bytes)
    elif mode == "zombie":
        mode_zombie()
    elif mode == "both":
        mode_orphan(size_bytes)
        if os.fork() == 0:
            mode_live(size_bytes)
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
