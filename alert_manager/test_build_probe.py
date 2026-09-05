#!/usr/bin/env python3
"""The stale-page signal: authenticated, idle-lock-exempt, and never auto-reloading.

Run: python3 alert_manager/test_build_probe.py   (exit 0 = all pass)

WHAT THIS PROTECTS (2026-09-05). The idle-lock bypass was fixed and deployed
(be72fdb), then reproduced anyway: a tab loaded ~5h earlier was still running
pre-fix markup and nothing said so. This feature makes that visible.

⛔ THE PROPERTY MOST WORTH GUARDING IS THE ONE THAT LOOKS LIKE A DETAIL.
`/api/build` MUST be in _IDLE_LOCK_ALLOWED. The probe polls it on a timer, and any
poll to an ordinary authenticated endpoint stamps `last_activity` — so without the
exemption this feature would keep every session alive forever and defeat the
walk-away lock it exists to surface. The feature would become its own cause. It
must equally NOT be in _AUTH_EXEMPT: the running build helps match a host to a
known vulnerability and is not for unauthenticated callers.

Both directions are asserted, because each is silently wrong in a different way:
a missing idle-lock exemption breaks security while looking like it works, and an
added auth exemption leaks while looking like it works.

ASSERTS ON PARSED STRUCTURE, NOT TEXT. dashboard.py is read with `ast`, and the
JS has its comments stripped first — both files document the very rules being
checked, so a text search would match the prose explaining them. That trap has
three logged instances in this repo.
"""
import ast
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASH = os.path.join(REPO, "dashboard.py")
JS = os.path.join(REPO, "static", "nemesis-version.js")

EXPECTED_CHECKS = 17
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 40:
        g, w = g[:37] + "...", w[:37] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def strip_js_comments(t):
    t = re.sub(r"/\*.*?\*/", "", t, flags=re.S)
    return re.sub(r"(?m)//.*$", "", t)


def fn_node(tree, name):
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return n
    return None


def main():
    src = open(DASH, encoding="utf-8").read()
    tree = ast.parse(src)

    print("1. the endpoint's two memberships — each wrong in a different silent way")
    m = re.search(r"_IDLE_LOCK_ALLOWED = \{(.*?)\}", src, re.S)
    idle = set(re.findall(r'"([^"]+)"', m.group(1))) if m else set()
    check("api_build IS idle-lock-exempt (else it defeats the lock)",
          "api_build" in idle, True)
    ma = re.search(r"_AUTH_EXEMPT\s*=\s*\{(.*?)\n\s*\}", src, re.S)
    auth = set(re.findall(r'"([^"]+)"', ma.group(1))) if ma else set()
    check("api_build is NOT auth-exempt (else it leaks the build publicly)",
          "api_build" in auth, False)
    check("  (control: the _AUTH_EXEMPT set was actually parsed)", len(auth) > 5, True)
    check("  (control: the _IDLE_LOCK_ALLOWED set was actually parsed)",
          "account_unlock" in idle, True)

    print("\n2. the route itself")
    n = fn_node(tree, "api_build")
    decs = [ast.unparse(d) for d in n.decorator_list] if n else []
    check("api_build exists", n is not None, True)
    check("  ...is @login_required", any("login_required" in d for d in decs), True)
    check("  ...is routed at /api/build",
          any("/api/build" in d for d in decs), True)
    # It must return a bare identifier and nothing else -- no version string, no
    # host, no path -- so it cannot become a fingerprinting surface. Read the
    # jsonify() call's actual keys, not every string constant in the function:
    # the docstring is a constant too, and a crude filter over all of them was
    # the first version of this check and failed for that reason.
    keys = set()
    for c in ast.walk(n):
        if (isinstance(c, ast.Call) and getattr(c.func, "id", "") == "jsonify"):
            for a in c.args:
                if isinstance(a, ast.Dict):
                    keys |= {k.value for k in a.keys if isinstance(k, ast.Constant)}
    check("  ...returns exactly one field, 'build'", keys, {"build"})

    print("\n3. the injector is a hook, and every guard is present as CODE")
    h = fn_node(tree, "_inject_build_probe")
    check("_inject_build_probe exists", h is not None, True)
    check("  ...registered as after_request",
          any("after_request" in ast.unparse(d) for d in h.decorator_list), True)
    attrs = {a.attr for a in ast.walk(h) if isinstance(a, ast.Attribute)}
    hconsts = {c.value for c in ast.walk(h) if isinstance(c, ast.Constant)}
    check("  guards on status_code", "status_code" in attrs, True)
    check("  guards on direct_passthrough (never touch a streamed response)",
          "direct_passthrough" in attrs, True)
    check("  guards on authentication", "is_authenticated" in attrs, True)
    check("  guards on text/html", "text/html" in hconsts, True)
    check("  idempotent — skips a response already carrying the script",
          "nemesis-version.js" in hconsts, True)

    print("\n4. the client never reloads without a human saying so")
    js = strip_js_comments(open(JS, encoding="utf-8").read())
    reloads = [mm.start() for mm in re.finditer(r"location\.reload\(", js)]
    check("exactly one location.reload() in the file", len(reloads), 1)
    # Heuristic, stated as one: the single reload must sit inside a click
    # listener. A timer-driven reload is the failure being excluded -- it would
    # discard unsaved work without asking.
    check("  ...and it is inside a click handler, not a timer",
          bool(reloads) and "addEventListener('click'" in js[max(0, reloads[0] - 120):reloads[0]],
          True)

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    bad = [l for l, ok in _results if not ok]
    if bad:
        print("FAILED:")
        for b in bad:
            print("  - " + b)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(main())
