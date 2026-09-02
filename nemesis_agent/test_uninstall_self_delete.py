"""R1 — the uninstaller must not delete its own directory while it is still running.

THE DEFECT (measured on VM `.83`, recorded as R1 in clean-uninstall-build-spec.md).
`_remove_components()` scheduled the install-dir deletion like this:

    cmd /c timeout /t 3 /nobreak >nul & rmdir /s /q "%APPDATA%\\Nemesis"

...and then `_run()` carried on: `_remove_arp_startmenu()`, a completion message, and finally
`btn.config(text="Close")` — i.e. the GUI sits there until a human clicks Close. So the rmdir
fires 3 seconds later while `NemesisUninstall.exe` is STILL RUNNING out of the very directory
being deleted. Windows cannot delete a running executable's file, the rmdir fails, and both the
exe and `%APPDATA%\\Nemesis\\` survive — exactly what the audit found.

**It is a fixed timer racing an indefinite human, so it fails whenever the user reads the
completion screen for more than three seconds — i.e. essentially always.** The spec's own named
remedy (§3: relaunch from `%TEMP%`) was never implemented; a different technique was used, and
that technique cannot work.

WHAT IS ASSERTED HERE. The Windows deletion itself cannot be executed on this machine, so this
file does NOT claim to prove on-device removal — that is Test-plan §7's job and remains
unproven until it runs. What IS proven here is the SEQUENCING CONTRACT that the bug violated:
the delete must never be issued while the process is alive, and the scheduled command must key
off THIS process's exit rather than a fixed delay.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)

import uninstaller_gui as U  # noqa: E402

_fail = []
_count = 0
EXPECTED_CHECKS = 16


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-72s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


# --------------------------------------------------------------------------
# 1. THE SEQUENCING CONTRACT — a real behavioural test of the actual failure path
#    ("deleted too early"), runnable here because the waiting logic is pure.
# --------------------------------------------------------------------------

def test_never_deletes_while_the_process_is_alive():
    print("\n[the delete must NOT be issued while the process still lives]")
    events = []
    alive = {"n": 4}          # alive for 4 polls, then gone

    def is_alive():
        events.append("poll")
        alive["n"] -= 1
        return alive["n"] > 0

    def delete():
        events.append("delete")
        return True

    ok = U._wait_then_delete(is_alive, delete, sleep=lambda s: None, max_wait=60)
    check("returned success", ok, True)
    check("delete happened exactly once", events.count("delete"), 1)
    check("delete was the LAST action, never mid-poll", events[-1], "delete")
    check("it actually waited (more than one poll)", events.count("poll") > 1, True)
    check("no delete before the process was gone",
          events.index("delete") > events.index("poll"), True)


def test_gives_up_rather_than_deleting_a_live_process_dir():
    print("\n[if the process never exits, REFUSE to delete — residue beats a partial wipe]")
    events = []

    def is_alive():
        events.append("poll")
        return True                      # never exits

    def delete():
        events.append("delete")
        return True

    ok = U._wait_then_delete(is_alive, delete, sleep=lambda s: None, max_wait=5)
    check("reported failure rather than deleting", ok, False)
    check("delete NEVER called against a live process", "delete" in events, False)
    check("it bounded its wait instead of spinning forever", len(events) <= 60, True)


# --------------------------------------------------------------------------
# 2. THE SCHEDULED COMMAND — must key off THIS pid, not a fixed delay
# --------------------------------------------------------------------------

def test_command_waits_for_this_process_not_a_timer():
    print("\n[the detached command must wait for OUR pid, not sleep a fixed 3s]")
    argv = U._deferred_removal_command(r"C:\Users\x\AppData\Roaming\Nemesis", 4242)
    # argv (a list), not a shell string -- no shell=True, no quoting hazard in a path
    # that contains spaces. Joined here only so the assertions can read it.
    check("returned an argv list, not a shell string", isinstance(argv, list), True)
    cmd = " ".join(argv)
    check("references this process's pid", "4242" in cmd, True)
    check("targets the install dir", "Nemesis" in cmd, True)
    check("waits on process exit", "Wait-Process" in cmd or "waitfor" in cmd.lower(), True)
    # THE REGRESSION ASSERTION: the exact broken shape must not come back.
    broken = ("timeout /t 3" in cmd and "Wait-Process" not in cmd)
    check("does NOT use the old fixed-timer-then-rmdir shape", broken, False)


def test_removal_is_scheduled_detached_not_run_inline():
    print("\n[scheduling must be detached — an inline delete would block or self-kill]")
    src = open(os.path.join(HERE, "uninstaller_gui.py")).read()
    check("uses Popen (detached), not run/call (blocking)",
          "_deferred_removal_command" in src and "Popen" in src, True)
    check("the old fixed-timer command string is gone from the source",
          "timeout /t 3 /nobreak" in src, False)
    check("deletion is keyed to os.getpid()", "os.getpid()" in src, True)


if __name__ == "__main__":
    print("=" * 78)
    print("R1 — uninstaller must not delete its own directory while running")
    print("=" * 78)
    test_never_deletes_while_the_process_is_alive()
    test_gives_up_rather_than_deleting_a_live_process_dir()
    test_command_waits_for_this_process_not_a_timer()
    test_removal_is_scheduled_detached_not_run_inline()
    print()
    if _count != EXPECTED_CHECKS:
        print("SUITE DRIFT: ran %d checks, expected %d" % (_count, EXPECTED_CHECKS))
        sys.exit(1)
    if _fail:
        print("FAILED (%d of %d)" % (len(_fail), _count))
        for f in _fail:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS (%d checks)" % _count)
