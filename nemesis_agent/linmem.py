"""linmem - Linux memory ACQUISITION primitives (step 4b). PUBLIC, mirrors winmem.py.

The Linux counterpart to `winmem.py`. Same job, same vocabulary, same bounds: enumerate
what is mapped in a process and read bounded slices of it. It decides nothing about what
any of that MEANS -- the injection heuristics are the detector's novelty and live in the
private module (operator decision D2). The split is source-visibility only, never a
feature gate.

WHY THIS EXISTS SEPARATELY FROM memcap.py
------------------------------------------
`memcap.py` (step 3a) answers ONE question -- can this agent read a foreign process at
all -- and its region walk is deliberately private and minimal: it yields only
(start, size), because a capability probe needs somewhere to read, not a description of
the address space. The detector needs the opposite: permissions and BACKING for every
mapping. Discovered while planning step 4: Windows had that via `winmem.iter_regions`
and Linux had nothing public at all, so the two arms could not feed one classifier.

WHAT /proc/<pid>/maps GIVES US, AND WHY THAT IS THE WHOLE POINT
---------------------------------------------------------------
    5caedbfa9000-5caedc09b000 r--p 00000000 103:02 89129455  /usr/lib/.../head
    ^ range                   ^perms       ^offset ^dev ^ino ^ pathname (may be absent)

The `x` bit and the PRESENCE OR ABSENCE of a pathname are exactly the two facts the
detector turns on: an executable mapping with no backing file is the shape both a JIT
and an injected payload take, and telling those apart is step 4's actual problem. A
bracketed pseudo-path (`[heap]`, `[stack]`, `[vdso]`) is NOT a file: it is recorded
separately so a classifier cannot mistake it for a file-backed mapping.

READS
-----
Reuses `process_vm_readv` -- the primitive 3a proved, and specifically NOT
`/proc/<pid>/mem`, which is a 0600 file whose DAC check CAP_SYS_PTRACE does not bypass
(VM-verified 2026-08-22; see memcap.py's header for the full account).

BOUNDS
------
Identical discipline to winmem: a region map is attacker-influenced data and a target
with pathologically many mappings must not become a memory-pressure lever against a
privileged reader. Caps are enforced HERE, never assumed of callers.
"""

from __future__ import annotations

import errno
import os
import sys

#: Per-target outcomes. Deliberately the SAME vocabulary as winmem, so one classifier
#: and one heartbeat field mean one thing on both platforms. `PROTECTED` exists on
#: Linux too: a target can be unreadable for a known, permanent reason (a hardened LSM
#: policy, a different user without the capability) as distinct from unmeasurable.
READABLE = "readable"
PROTECTED = "protected"
UNAVAILABLE = "unavailable"
UNDETERMINED = "undetermined"

#: Mirrors winmem.MAX_REGIONS / MAX_READ_BYTES.
MAX_REGIONS = 4096
MAX_READ_BYTES = 1 << 20

#: Kernel pseudo-mappings. Bracketed names are NOT files; a classifier must be able to
#: tell "anonymous", "file-backed" and "kernel pseudo-mapping" apart.
_PSEUDO_PREFIX = "["


class LinMemUnsupported(RuntimeError):
    """A Linux-only primitive was called off Linux."""


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def _require_linux(what: str):
    if not is_linux():
        raise LinMemUnsupported("%s is Linux-only" % what)


# ── pure: parsing one maps line ──────────────────────────────────────────────

def parse_maps_line(line: str):
    """Parse one /proc/<pid>/maps line into region facts, or None if unparseable.

    PURE and total: never raises, whatever the kernel or a fuzzer hands it. Returns raw
    facts only -- no judgement about which mappings are interesting.
    """
    parts = line.split(None, 5)
    if len(parts) < 5:
        return None
    rng, perms = parts[0], parts[1]
    try:
        lo_s, hi_s = rng.split("-", 1)
        lo, hi = int(lo_s, 16), int(hi_s, 16)
    except ValueError:
        return None
    if hi < lo or len(perms) < 4:
        return None
    path = parts[5].strip() if len(parts) > 5 else ""
    pseudo = path.startswith(_PSEUDO_PREFIX)
    return {
        "base": lo,
        "size": hi - lo,
        "perms": perms[:4],
        "readable": perms[0] == "r",
        "writable": perms[1] == "w",
        "executable": perms[2] == "x",
        "private": perms[3] == "p",
        "offset": parts[2],
        "dev": parts[3],
        "inode": parts[4],
        "path": path,
        # THE load-bearing distinction for step 4. Three states, not two: a bracketed
        # kernel pseudo-mapping is neither an anonymous allocation nor a real file, and
        # collapsing it into either would mislead the classifier.
        "backing": ("pseudo" if pseudo else ("file" if path else "anonymous")),
    }


def is_region_readable(region: dict) -> bool:
    """Mechanically readable? A readable mapping that is not a kernel pseudo-mapping.
    A judgement about INTEREST is not made here."""
    return bool(region.get("readable")) and region.get("backing") != "pseudo"


# ── Linux-only: enumerate and read ───────────────────────────────────────────

def open_target(pid: int):
    """Establish whether `pid`'s address space can be enumerated.

    Linux has no handle to hold, so this returns (pid, None) on success and mirrors
    winmem's states on failure:
        (pid,  None)           the maps file opened
        (None, PROTECTED)      EPERM/EACCES -- a measured refusal with a known cause
                               (no capability for a cross-privilege target, or an LSM)
        (None, UNDETERMINED)   the target is gone, or something unclassifiable
        (None, UNAVAILABLE)    another definite refusal
    """
    _require_linux("open_target")
    try:
        with open("/proc/%d/maps" % pid, "r"):
            return pid, None
    except PermissionError:
        return None, PROTECTED
    except FileNotFoundError:
        return None, UNDETERMINED
    except OSError as exc:
        if exc.errno in (errno.EPERM, errno.EACCES):
            return None, PROTECTED
        if exc.errno == errno.ESRCH:
            return None, UNDETERMINED
        return None, UNAVAILABLE


def iter_regions(pid: int, max_regions: int = MAX_REGIONS):
    """Yield region facts for `pid`, bounded by `max_regions` and MAX_REGIONS.

    A PermissionError PROPAGATES rather than ending the walk quietly: a denial part-way
    through is a measured refusal, and swallowing it would hand the caller a SHORT map
    that looks complete. That exact swallowing was 3a's first bug.
    """
    _require_linux("iter_regions")
    cap = min(int(max_regions), MAX_REGIONS)
    seen = 0
    with open("/proc/%d/maps" % pid, "r") as fh:
        for line in fh:
            if seen >= cap:
                return
            region = parse_maps_line(line)
            if region is None:
                continue
            yield region
            seen += 1


def read_bytes(pid: int, base: int, size: int, cap: int = MAX_READ_BYTES):
    """Read up to min(size, cap, MAX_READ_BYTES) bytes from `pid` at `base`.

    Returns bytes, or None when the read did not happen. None is an explicit "no data",
    never an empty-bytes stand-in a caller might read as a successful read of nothing.
    """
    _require_linux("read_bytes")
    import ctypes
    try:
        import memcap
    except Exception:                                        # noqa: BLE001
        return None
    fn = memcap._process_vm_readv()
    if fn is None:
        return None
    want = max(0, min(int(size), int(cap), MAX_READ_BYTES))
    if want == 0:
        return None
    buf = (ctypes.c_char * want)()
    local = memcap._IoVec(ctypes.cast(buf, ctypes.c_void_p), want)
    remote = memcap._IoVec(ctypes.c_void_p(base), want)
    ctypes.set_errno(0)
    got = fn(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
    if got <= 0:
        return None
    return bytes(buf[:got])


def close(handle):
    """Present for symmetry with winmem.close, so a caller can be platform-agnostic.
    Linux holds no handle, so this is a genuine no-op rather than a stub that pretends."""
    return None
