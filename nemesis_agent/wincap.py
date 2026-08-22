"""wincap - can this agent read ANOTHER process's memory, on Windows? (step 3c)

The Windows half of the acquisition-layer capability `memcap.py` answers on Linux, and
it answers with the SAME three-state, fail-closed contract so the heartbeat's
`memscan_capability` field means one thing on both platforms:

    available    - a real cross-process read SUCCEEDED
    unavailable  - a real cross-process read was DENIED on a valid target
    undetermined - it could not be measured. NOT a pass, NOT a confident fail.

WHY A FUNCTIONAL TEST, NOT A PRIVILEGE-BIT READ
-----------------------------------------------
The tempting shortcut is to report "SeDebugPrivilege is enabled" and stop. 3a proved
exactly how that lies: on Linux the agent held CAP_SYS_PTRACE, the bit read TRUE, and
the read still failed EACCES because `/proc/<pid>/mem` is DAC-gated and the capability
does not bypass file permissions. A held privilege is not a demonstrated capability.
So the privilege state here is CORROBORATING evidence only; the verdict comes from
actually reading another process and seeing what the kernel does.

MEASURED ON THIS PLATFORM (VM, 2026-08-22, as the real LocalSystem service)
---------------------------------------------------------------------------
SeDebugPrivilege was present AND already enabled; a normal target read cleanly; a
PROTECTED (PPL) target refused OpenProcess with ERROR_ACCESS_DENIED. The PPL ceiling
is a platform limitation, not a defect, and `probe()` deliberately does NOT let a
protected target drag the verdict down: being unable to read Defender says nothing
about whether the agent can inspect ordinary processes. Per-target honesty is
`winmem`'s PROTECTED state; this module reports the CAPABILITY.
"""

from __future__ import annotations

import sys

AVAILABLE = "available"
UNAVAILABLE = "unavailable"
UNDETERMINED = "undetermined"

#: How many candidate targets to try before giving up as `undetermined`. A single
#: target can exit between the open and the read; a confident verdict needs a real
#: outcome, not a transient miss.
_MAX_TARGETS = 8


def _is_windows() -> bool:
    return sys.platform == "win32"


def debug_privilege_state() -> dict:
    """The SeDebugPrivilege enable attempt. CORROBORATING ONLY -- never the verdict."""
    try:
        import winmem
        return winmem.ensure_debug_privilege()
    except Exception as exc:                                 # noqa: BLE001
        return {"privilege": "SeDebugPrivilege", "adjust_called": False,
                "enabled": False, "not_held": False,
                "error": "%s: %s" % (type(exc).__name__, exc)}


def _own_sid():
    """This process's user SID, or None if it cannot be read."""
    import os
    try:
        import privchannel
        return privchannel.sid_of_pid(os.getpid())
    except Exception:                                        # noqa: BLE001
        return None


def _iter_targets():
    """Yield candidate foreign pids, most-likely-readable first.

    Deliberately NOT our own process: reading ourselves proves the reader works (that
    is `self_test`'s job) but proves nothing about cross-process privilege.
    """
    import subprocess
    names = ("explorer", "spoolsv", "svchost", "winlogon")
    seen = []
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "Get-Process %s -ErrorAction SilentlyContinue | "
             "Select-Object -ExpandProperty Id" % ",".join(names)],
            text=True, stderr=subprocess.DEVNULL, timeout=20)
        for line in out.split():
            try:
                pid = int(line)
            except ValueError:
                continue
            if pid and pid not in seen:
                seen.append(pid)
                yield pid
    except Exception:                                        # noqa: BLE001
        return


def _try_read_foreign(pid: int):
    """Attempt one real cross-process read. Returns True / False / None.

        True   - read succeeded (we have the capability for this target)
        False  - a MEASURED denial on a target we were allowed to consider
        None   - untestable (protected target, raced away, no readable region)

    A PROTECTED target returns None, not False: it is a definite refusal for THIS
    target but says nothing about the capability in general, and letting it read as a
    confident capability-negative would be wrong in the other direction.
    """
    try:
        import winmem
    except Exception:                                        # noqa: BLE001
        return None
    handle, state = winmem.open_target(pid)
    if handle is None:
        if state == winmem.PROTECTED:
            return None
        return False if state == winmem.UNAVAILABLE else None

    # CROSS-PRIVILEGE ONLY. Reading a process owned by our OWN user needs no special
    # privilege at all, so it cannot demonstrate the capability the detector needs.
    # MEASURED 2026-08-22: a NON-elevated user with SeDebugPrivilege not_held=True
    # still read explorer.exe (its own process) and this probe reported `available` --
    # an overstatement of exactly the kind memcap already guards against on Linux by
    # targeting pid 1 and different-uid processes only. Same rule, ported.
    try:
        import privchannel
        target_sid = privchannel.sid_of_pid(pid)
    except Exception:                                        # noqa: BLE001
        target_sid = None
    mine = _own_sid()
    if target_sid is not None and mine is not None and \
            target_sid.upper() == mine.upper():
        winmem.close(handle)
        return None            # same-user target: not a discriminator, untestable
    if target_sid is None or mine is None:
        winmem.close(handle)
        return None            # ownership unverified -> cannot claim cross-privilege

    try:
        for region in winmem.iter_regions(handle, max_regions=256):
            if not winmem.is_region_readable(region):
                continue
            data = winmem.read_bytes(handle, region["base"], 16, cap=16)
            if data:
                return True
        return None                    # opened, but nothing readable -- untestable
    finally:
        winmem.close(handle)


def probe() -> dict:
    """Answer 'can this agent read a foreign process's memory?' -- honestly.

    Never raises. Mirrors `memcap.probe()`'s return shape so the heartbeat field is
    platform-uniform.
    """
    if not _is_windows():
        return {"state": UNDETERMINED,
                "detail": "non-Windows platform; the Linux path is memcap.probe()",
                "method": "platform-gate", "sedebug": None}

    priv = debug_privilege_state()
    tested = 0
    saw_denial = False
    for pid in _iter_targets():
        result = _try_read_foreign(pid)
        if result is True:
            return {"state": AVAILABLE,
                    "detail": "read a DIFFERENT user's process memory (pid %d) - the "
                              "detector can acquire target memory" % pid,
                    "method": "functional ReadProcessMemory cross-process read",
                    "sedebug": priv}
        if result is False:
            saw_denial = True
        tested += 1
        if tested >= _MAX_TARGETS:
            break

    if saw_denial:
        return {"state": UNAVAILABLE,
                "detail": "cross-process memory read DENIED - the privileged service "
                          "cannot acquire target memory",
                "method": "functional ReadProcessMemory cross-process read",
                "sedebug": priv}
    return {"state": UNDETERMINED,
            "detail": "no cross-user process could be tested (%d tried) - capability "
                      "could not be measured, NOT assumed present. Same-user targets "
                      "do not count: reading them needs no privilege." % tested,
            "method": "functional ReadProcessMemory cross-process read",
            "sedebug": priv}


def _read_own_byte():
    """Read our OWN memory through the SAME path used for foreign targets."""
    import os
    try:
        import winmem
    except Exception:                                        # noqa: BLE001
        return None
    handle, _state = winmem.open_target(os.getpid())
    if handle is None:
        return None
    try:
        for region in winmem.iter_regions(handle, max_regions=256):
            if winmem.is_region_readable(region):
                if winmem.read_bytes(handle, region["base"], 16, cap=16):
                    return True
        return None
    finally:
        winmem.close(handle)


def self_test() -> dict:
    """Premise proof: the instrument must be able to produce BOTH answers.

    Same two controls as `memcap.self_test`, for the same reason -- a reader that can
    only ever say one thing is not evidence:
      * reading OUR OWN memory MUST succeed, so a negative verdict reflects the OS's
        decision rather than a bug in our own reader
      * a NON-EXISTENT pid MUST NOT read, so a positive verdict is not a rubber stamp
    """
    if not _is_windows():
        return {"ok": True, "findings": [], "skipped": "non-Windows"}
    findings = []

    if _read_own_byte() is not True:
        findings.append("could not read our OWN memory - the reader itself is broken, "
                        "so no verdict from it can be trusted")

    if _try_read_foreign(0x7FFFFFFE) is True:
        findings.append("reported a successful read of a non-existent pid - the "
                        "reader rubber-stamps success")

    return {"ok": not findings, "findings": findings}


if __name__ == "__main__":                                   # pragma: no cover
    import json
    if "--json" in sys.argv:
        print(json.dumps({"self_test": self_test(), "probe": probe()}))
    else:
        st = self_test()
        print("self-test:", "PASS" if st["ok"] else "FAIL")
        for f in st["findings"]:
            print("  -", f)
        print(json.dumps(probe(), indent=2))
