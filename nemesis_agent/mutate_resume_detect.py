#!/usr/bin/env python3
"""Re-run the resume-hook mutation suite. Anyone can verify; nobody need take it on trust.

⛔ WHY THIS FILE EXISTS. `8722521`'s commit message claimed "mutation-proven, 5/5
caught". Two other windows then had to either believe that sentence or redo the
work from scratch, and both correctly declined to record it as confirmed --
Window 2 downgraded it to "commit-message-sourced, not jointly confirmed". A
mutation result that lives only in a commit message is an ASSERTION, not
evidence. This turns it back into something reproducible in one command.

    python3 nemesis_agent/mutate_resume_detect.py

Exit 0 iff every mutant is caught. Exit 1 otherwise -- so this is a GATE, not a
report, and can be run by a window that did not write the code.

⛔ IT NEVER TOUCHES THE SHARED CHECKOUT. Every mutation is applied to a private
copy under a temp dir; `/opt/nemesis` is read but never written. That matters in
a tree three windows commit from -- a mutation left behind by a crashed run would
be an uncommitted edit to a tracked file, which this repo's own rules identify as
the least-protected state anything can be in.

⛔ THE BASELINE IS CHECKED FIRST, AND THAT IS NOT CEREMONY. If the copied tree
does not pass CLEAN, every "mutant caught" result below is meaningless -- the
suite would be failing for its own reasons and every mutation would look caught.
That is the standing "a control needs its own precondition checked" rule; a
uniform failure reads as a real result about the code rather than a broken
harness, which is exactly how it slips past.
"""
import os
import shutil
import subprocess
import sys
import tempfile

SRC = os.path.dirname(os.path.abspath(__file__))
TEST = "test_resume_detect.py"
TARGET = "agent.py"

#: (id, description, original, replacement). Each MUST break something real.
MUTANTS = [
    ("M1", "resume detected but never acted on",
     '            request_early_beat("resume")',
     '            pass  # MUTANT'),
    ("M2", "slice cap removed -- one wait spans the suspend",
     '        wait_for = max(0.0, min(wait_for, RESUME_CHECK_SLICE_S))',
     '        wait_for = max(0.0, wait_for)  # MUTANT'),
    ("M3", "threshold does nothing -- every wait is a resume",
     '    return (wall_after - wall_before) - intended > RESUME_JUMP_TOLERANCE_S',
     '    return True  # MUTANT'),
    ("M4", "backwards clock step misread as a resume",
     '    return (wall_after - wall_before) - intended > RESUME_JUMP_TOLERANCE_S',
     '    return abs((wall_after - wall_before) - intended) > RESUME_JUMP_TOLERANCE_S  # MUTANT'),
    ("M5", "rate limiter bypassed -- returns instead of requesting",
     '            request_early_beat("resume")',
     '            return  # MUTANT'),
    # M6 targets the RELATIONSHIP between two tunables rather than either alone.
    # With a slice below the floor the resume beat is delayed by the floor
    # remainder, which is precisely the latency claim written into the docs.
    ("M6", "slice tuned BELOW the floor -- the ~60s latency claim breaks",
     'RESUME_CHECK_SLICE_S = 60.0',
     'RESUME_CHECK_SLICE_S = 10.0  # MUTANT'),
]


def run(cwd):
    p = subprocess.run([sys.executable, "-B", TEST], cwd=cwd,
                       capture_output=True, text=True, timeout=180)
    return p.returncode, p.stdout


def main():
    tmp = tempfile.mkdtemp(prefix="mut-resume-")
    work = os.path.join(tmp, "nemesis_agent")
    shutil.copytree(SRC, work, ignore=shutil.ignore_patterns("__pycache__"))
    target = os.path.join(work, TARGET)
    pristine = open(target).read()

    try:
        rc, out = run(work)
        if rc != 0:
            print("⛔ BASELINE FAILS IN THE COPY -- every result below would be "
                  "meaningless. Aborting without running any mutation.")
            print(out[-2000:])
            return 1
        print("baseline: %s" % [l for l in out.splitlines()
                                if l.startswith("checks:")][0])
        print()

        escaped = 0
        for mid, desc, old, new in MUTANTS:
            if pristine.count(old) < 1:
                print("  %s  ⛔ ANCHOR NOT FOUND -- the code moved; this mutation "
                      "tested NOTHING. (%s)" % (mid, desc))
                escaped += 1
                continue
            open(target, "w").write(pristine.replace(old, new))
            rc, out = run(work)
            if rc == 0:
                print("  %s  ❌ ESCAPED -- %s" % (mid, desc))
                escaped += 1
            else:
                fails = [l.strip() for l in out.splitlines() if "[FAIL]" in l]
                print("  %s  ✅ caught (%d assertion%s) -- %s"
                      % (mid, len(fails), "" if len(fails) == 1 else "s", desc))
            open(target, "w").write(pristine)

        print()
        if escaped:
            print("RESULT: %d of %d mutants ESCAPED -- the suite does not prove "
                  "what it claims." % (escaped, len(MUTANTS)))
            return 1
        print("RESULT: all %d mutants caught." % len(MUTANTS))
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
