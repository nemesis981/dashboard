#!/usr/bin/env python3
"""Every repeating timer that hits an authenticated endpoint must be nemPoll-marked.

THE BUG THIS EXISTS TO PREVENT (found live 2026-09-04)
    static/throttle-status.js ran `setInterval(load, 30000)` unwrapped. /api/throttle-status
    is an ordinary authenticated endpoint and is NOT in dashboard.py's _IDLE_LOCK_ALLOWED,
    so every 30s it stamped `last_activity` against a 15-minute idle timeout. That card
    renders on the main dashboard, so the walk-away idle lock could never fire there --
    while the whole mechanism still looked fully implemented.

    static/nemesis-activity.js's own header names this exact failure. One file was marked,
    another was not, and nothing compared them. That is what this test does.

⛔ HOW IT AVOIDS BEING SATISFIED BY PROSE.
    .js sources have comments stripped before scanning; .py sources are parsed with `ast`
    and only STRING LITERALS are scanned, so a Python comment or docstring mentioning
    setInterval is structurally invisible. The word appears in explanatory comments in at
    least three files here -- a raw text scan would count them as call sites.

Run: python3 alert_manager/test_poll_marking.py
"""
import ast
import glob
import os
import re
import sys

ROOT = os.environ.get("NEMESIS_ROOT", "/opt/nemesis")

#: Timers that legitimately do NOT mark themselves, with the reason each is safe.
#: An entry here is a deliberate, reviewed exception -- not a way to silence the test.
EXEMPT = {
    ("static/nemesis-idle-lock.js", "refreshHealth"):
        "re-renders /account/unlock, which IS in _IDLE_LOCK_ALLOWED and deliberately "
        "does not stamp last_activity -- so it cannot extend a locked session",
    ("static/nemesis-idle-lock.js", "tick"):
        "pure client-side countdown; issues no fetch at all",
}

EXPECTED_SITES = 11
EXPECTED_CHECKS = 8
_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + str(detail)) if detail else ""))


def strip_js_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)//.*$", "", text)


def first_arg(src, open_idx):
    """setInterval's first argument, brace/paren balanced."""
    i = src.index("(", open_idx)
    depth = 0
    out = []
    while i < len(src):
        c = src[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                break
        elif c == "," and depth == 1:
            return "".join(out)[1:].strip()
        out.append(c)
        i += 1
    return "".join(out)[1:].strip()


def sites_in_js(text):
    text = strip_js_comments(text)
    return [first_arg(text, m.start()) for m in re.finditer(r"setInterval\s*\(", text)]


def sites_in_py(path):
    """Only STRING LITERALS -- a comment mentioning setInterval is invisible to ast."""
    found = []
    tree = ast.parse(open(path, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.extend(sites_in_js(node.value))
    return found


print("1. the scanner can distinguish (known-good / known-bad)")
check("finds an unwrapped timer", sites_in_js("setInterval(load, 30000);") == ["load"])
check("finds a wrapped timer",
      "nemPoll" in (sites_in_js("setInterval(nemPoll(load), 30000);") or [""])[0])
check("  ...and IGNORES setInterval named only in a comment",
      sites_in_js("// setInterval(ghost, 1000) is described here\nvar x = 1;") == [])
check("  ...handles a nested-paren first argument",
      sites_in_js("setInterval((window.nemPoll || function(f){return f;})(load), 30);")
      == ["(window.nemPoll || function(f){return f;})(load)"])

print("\n2. survey every JS source in the tree")
os.chdir(ROOT)
found = []
for f in sorted(glob.glob("static/*.js")):
    for a in sites_in_js(open(f, encoding="utf-8").read()):
        found.append((f, a))
for f in ["dashboard.py"] + sorted(glob.glob("modules/*/module.py")):
    if os.path.exists(f):
        for a in sites_in_py(f):
            found.append((f, a))

print("     %d timer call sites found" % len(found))
check("site count matches the reviewed total", len(found) == EXPECTED_SITES,
      "found %d, expected %d -- a NEW timer was added; mark it or exempt it with a reason"
      % (len(found), EXPECTED_SITES))

print("\n3. every timer is marked, or is a documented exception")
unmarked = [(f, a) for (f, a) in found
            if "nemPoll" not in a and (f, a.strip()) not in EXEMPT]
check("no unmarked, unexempted timer", not unmarked,
      "unmarked: %s" % sorted(unmarked))

print("\n4. the exemptions are real, not stale")
stale = [k for k in EXEMPT if k not in [(f, a.strip()) for (f, a) in found]]
check("every exemption still corresponds to a real call site", not stale,
      "stale exemptions: %s" % sorted(stale))

print("\n5. mutation: an unwrapped timer must be caught")
_mutated = found + [("static/fake.js", "load")]
_mut_unmarked = [(f, a) for (f, a) in _mutated
                 if "nemPoll" not in a and (f, a.strip()) not in EXEMPT]
check("a newly-added unwrapped timer is detected", bool(_mut_unmarked), _mut_unmarked)

print("\n%d passed, %d failed" % (_pass, _fail))
if _pass + _fail != EXPECTED_CHECKS:
    print("EXPECTED_CHECKS MISMATCH: declared %d, ran %d" % (EXPECTED_CHECKS, _pass + _fail))
    sys.exit(1)
sys.exit(1 if _fail else 0)
