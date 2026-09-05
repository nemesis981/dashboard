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
EXPECTED_CHECKS = 15
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

#: Every source root that can render page JS. `core/*.py` was added 2026-09-05:
#: the Learning Center landed there and the scan had never looked at it. Nothing
#: in core/ polls yet, so that gap was latent rather than live -- which is
#: precisely why it needed closing before it became live, and why section 8
#: below now detects a blind spot instead of relying on someone remembering to
#: widen this list.
SCANNED_PY = (["dashboard.py"]
              + sorted(glob.glob("modules/*/module.py"))
              + sorted(glob.glob("core/*.py")))
SCANNED_JS = sorted(glob.glob("static/*.js"))
found = []
for f in SCANNED_JS:
    for a in sites_in_js(open(f, encoding="utf-8").read()):
        found.append((f, a))
for f in SCANNED_PY:
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

print("\n6. nemPoll must EXIST on every page that relies on it")
# ⛔ THE OTHER HALF OF THIS FILE'S INVARIANT, and the half that was missing.
# Sections 1-5 prove every timer is WRAPPED. They cannot see whether
# window.nemPoll exists on the page hosting it. Each wrapped timer is written
# `(window.nemPoll || fallback)(fn)`, so on a page that never loads
# static/nemesis-activity.js the wrapper silently degrades to the unwrapped
# fallback -- and a correctly-marked timer is then indistinguishable from an
# unmarked one, while this test still reported PASS.
#
# FOUND LIVE 2026-09-05. static/nemesis-activity.js was missing from
# settings_page, diagnostics_page and firewall_db -- three of the six pages that
# render the idle-lock overlay. nemesis-activity.js also installs the
# window.fetch patch that adds X-Nemesis-Poll, so on those pages EVERY request
# read as human activity and the walk-away idle lock could never fire
# server-side. The operator saw the lock overlay (client-side, and its own header
# says "Nothing here may be relied on for security"), refreshed, and was let
# straight back in against a session the server had never locked. Zero
# session_idle_locked audit rows were written on the day it was observed.
#
# MATCHES THE SCRIPT TAG, NOT THE FILENAME. dashboard.py mentions both files in
# comments and docstrings -- api_session_touch's docstring names
# nemesis-idle-lock.js and would otherwise register as an overlay-bearing page.
# A tag is code; a mention is prose. Same discipline as this file's .py scanning.
IDLE_TAG = 'src="/static/nemesis-idle-lock.js"'
ACT_TAG = 'src="/static/nemesis-activity.js"'

EXPECTED_OVERLAY_PAGES = 6


def _page_markup(fn_node, src_lines):
    """Concatenated STRING LITERALS of a function, minus its docstring.

    Docstrings are excluded explicitly: they are string literals too, so
    including them would let prose satisfy a check about markup.
    """
    body = list(fn_node.body)
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        body = body[1:]                       # drop the docstring
    parts = []
    for stmt in body:
        for n in ast.walk(stmt):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                parts.append(n.value)
    return "\n".join(parts)


_dash = os.path.join(ROOT, "dashboard.py")
_tree = ast.parse(open(_dash, encoding="utf-8").read())
_lines = open(_dash, encoding="utf-8").read().split("\n")

overlay_pages, missing_act, wrong_order = [], [], []
for _node in ast.walk(_tree):
    if not isinstance(_node, ast.FunctionDef):
        continue
    markup = _page_markup(_node, _lines)
    if IDLE_TAG not in markup:
        continue
    overlay_pages.append(_node.name)
    if ACT_TAG not in markup:
        missing_act.append(_node.name)
    elif markup.index(ACT_TAG) > markup.index(IDLE_TAG):
        # It wraps window.fetch, so anything loaded ahead of it can capture the
        # unwrapped original -- the working pages carry a comment saying exactly
        # this, and order is therefore part of the contract, not a preference.
        wrong_order.append(_node.name)

print("     overlay-bearing pages: %s" % ", ".join(sorted(overlay_pages)))
check("found the expected number of overlay pages",
      len(overlay_pages) == EXPECTED_OVERLAY_PAGES,
      "found %d (%s), expected %d -- a page was added or removed; this count is "
      "what stops the scan passing vacuously"
      % (len(overlay_pages), sorted(overlay_pages), EXPECTED_OVERLAY_PAGES))
check("every overlay page loads nemesis-activity.js", not missing_act,
      "MISSING on: %s -- window.nemPoll is undefined there, so every wrapped "
      "timer silently falls back to unmarked and the idle lock cannot fire"
      % sorted(missing_act))
check("...and loads it BEFORE nemesis-idle-lock.js", not wrong_order,
      "out of order on: %s" % sorted(wrong_order))

print("\n7. mutation: a page that drops nemesis-activity.js must be caught")
_mut = "<script " + IDLE_TAG + "></script>"          # overlay, no activity.js
check("a page with the overlay and no nemPoll is detected",
      ACT_TAG not in _mut and IDLE_TAG in _mut, _mut)
_mut_ok = "<script " + ACT_TAG + "></script><script " + IDLE_TAG + "></script>"
check("CONTROL: a correctly-ordered page is NOT flagged",
      ACT_TAG in _mut_ok and _mut_ok.index(ACT_TAG) < _mut_ok.index(IDLE_TAG))

print("\n8. THE SCAN MUST DETECT ITS OWN BLIND SPOTS")
# ⛔ WHY THIS EXISTS. Sections 2-3 can only police files they look at, so a timer
# in an unscanned directory is invisible to them AND to their mutation test --
# the suite stays green and proves nothing about that file. That is the same
# shape as the bug this whole file was written for ("one file was marked,
# another was not, and nothing compared them"), lifted to the scan's own scope.
#
# FOUND LIVE 2026-09-05: the Learning Center shipped into core/, which this scan
# had never covered. Nothing there polled, so it was latent -- but the next timer
# added in core/ would have been unmarked, undetected and green. Widening the
# list fixes today; this check fixes the class, because it fails the moment a
# timer appears anywhere the list does not reach, instead of waiting for someone
# to notice.
_SKIP_DIRS = ("__pycache__", ".git", "node_modules", "venv", "layerd-model",
              "nemesis_agent")     # the agent is not a browser surface
unscanned = []
for root, dirs, files in os.walk("."):
    dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
    for fn in files:
        rel = os.path.relpath(os.path.join(root, fn), ".")
        if os.path.basename(rel).startswith("test_"):
            continue
        if rel in SCANNED_PY or rel in SCANNED_JS:
            continue
        try:
            if fn.endswith(".js"):
                sites = sites_in_js(open(rel, encoding="utf-8").read())
            elif fn.endswith(".py"):
                sites = sites_in_py(rel)
            else:
                continue
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        if sites:
            unscanned.append((rel, sites))

check("no timer call site lives outside the scanned set", not unscanned,
      "UNSCANNED timer(s): %s -- add the file's directory to SCANNED_PY/SCANNED_JS, "
      "then mark or exempt the timer" % sorted(unscanned))
check("  (control: the detector can see a site at all)",
      bool(sites_in_js("setInterval(ghost, 1000);")), True)

print("\n%d passed, %d failed" % (_pass, _fail))
if _pass + _fail != EXPECTED_CHECKS:
    print("EXPECTED_CHECKS MISMATCH: declared %d, ran %d" % (EXPECTED_CHECKS, _pass + _fail))
    sys.exit(1)
sys.exit(1 if _fail else 0)
