# Roadmap stub — manual RAM recovery, Windows platform gap

**Status:** parked (what + why; capture-only, do NOT build from this stub without its
own scoping pass). Written 2026-08-19 alongside the Linux implementation
(`alert_manager/ram_recovery.py`, `368b828`), for whoever picks up the Windows side of
this feature next.

## What

The manual RAM recovery feature shipped Linux-only. Its two reclaim categories —
orphaned SysV shared memory and zombie processes — are **not just unimplemented on
Windows, they don't have the same shape there.** This is not a porting task; it needs
its own design.

- **Orphaned SysV shared memory has no Windows equivalent.** SysV IPC (`shmget`/
  `shmat`/`shmctl`, `/proc/sysvipc/shm`) is a Linux/POSIX kernel facility. Windows has
  its own shared-memory primitive (named file mappings via `CreateFileMapping`), with
  a **different lifetime model**: a named mapping is reference-counted by handle, and
  Windows itself frees the backing memory once the last handle closes — there is no
  kernel-level "orphaned segment sitting around after every handle is gone" state the
  way a detached-but-not-`IPC_RMID`'d SysV segment can persist indefinitely. **The
  orphan-shm category most likely does not exist as a problem on Windows at all** —
  not "harder to detect," but possibly nothing to detect. That needs confirming before
  any Windows work starts, not assumed either way.
- **Zombie processes have no Windows equivalent.** A POSIX zombie is a process-table
  entry surviving because its parent hasn't called `wait()`. Windows has no equivalent
  process-table state — a process either exists or it's gone. The **nearest analogue is
  a handle leak**: a process holding open handles (to files, other processes, kernel
  objects) that never get closed, preventing full cleanup of whatever those handles
  reference. This is a **different diagnostic** with a different detection mechanism
  (handle enumeration via `Get-Process`/`NtQuerySystemInformation`-style APIs, not a
  process-state field) and a different remediation shape (closing/releasing handles,
  not restarting or terminating a parent) — not a drop-in replacement for the zombie
  logic.

## Why this is captured now, not discovered later

Window 3 found both gaps while reviewing the Linux implementation for portability, in
the same session that feature shipped. Capturing it here — rather than letting it
surface as a surprise when someone starts a naive Windows port — is what CLAUDE.md's
Rule 7 capture discipline exists for: a good finding written down with its reasoning,
returned to later, rather than chased mid-task or lost.

## What this stub does NOT decide

- Whether a Windows RAM-recovery feature is worth building at all, given the orphan-shm
  category may not exist as a real problem there. That is a scoping question for
  whoever picks this up, not answered here.
- If a handle-leak diagnostic for Windows is wanted, its design is independent of this
  feature's Linux shape — it needs its own detection strategy, its own safety
  interlocks (the Linux version's ancestor-interlock and container-unit guard are both
  systemd-specific and have no direct Windows analogue either), and its own honest
  accounting of what it can and cannot verify. Nothing here specifies that design.
- Whether the Linux module's dual-instrument verification pattern (kernel counter +
  independent live sweep, both must agree) has a meaningful Windows equivalent, or
  whether Windows offers a single trustworthy source that makes the cross-check
  unnecessary. Unknown until someone measures it, the same way the Linux orphan
  detection was measured rather than assumed (see `ram_recovery.py`'s own module
  docstring for that precedent).

## Reasoning / shape

Capture-only, per the request. No implementation plan — the point of this stub is that
the next person scoping Windows RAM recovery starts from "these two categories don't
transfer as-is, here's why" instead of rediscovering it from scratch or, worse, shipping
a Windows port that assumes SysV-shaped orphans and zombie-shaped process states exist
where they don't.
