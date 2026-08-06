#!/usr/bin/env python3
"""The shared alert-analysis modal — one renderer, complete on every host page.

Run: python3 alert_manager/test_alert_modal_shared.py

WHY THIS SUITE EXISTS
---------------------
`/firewall-db`'s Analyze control used to be a LINK to `/?alert=<id>`. It
navigated that tab to the main dashboard, so closing the modal left the operator
looking at a second copy of the dashboard in a tab that was meant to be showing
the alert database — the "duplicate dashboard" report of 2026-08-06.

The fix was to open the modal in place, which means the modal has to exist on
more than one page. The comment that used to justify the link named the real
risk: two renderers for one result WILL drift. So the modal became THREE shared
emitters — `_alert_modal_css()`, `_alert_modal_html()`, `_alert_modal_js()` —
included by both pages, the same pattern ai_engine's chat widget already uses.

THE BUG THIS SUITE IS REALLY GUARDING
-------------------------------------
When the modal was first wired into `/firewall-db`, the markup and JS went over
but the CSS did not. Every structural check still passed: markup present, ids
unique, JS parsed, functions defined exactly once. But `.modal` is what carries
`display:none`, so the page would have rendered the entire modal — heading,
buttons, chat host — expanded in the document flow on load.

A component whose styles live in one page's template is only half-shared, and
the missing half fails VISIBLY while every automated check reports success. So
this suite checks the three parts against each other: every class the markup
uses, and every class the JS emits, must have a rule in the CSS emitter.
"""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DASH = os.path.join(REPO, "dashboard.py")

EXPECTED_CHECKS = 26

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


src = open(DASH).read()


def emitter_body(name):
    """Return what the emitter ACTUALLY emits, by AST-extracting and calling it.

    NOT a regex over the source text. That was the first implementation and it
    was wrong in a way worth recording: the source spells escapeHtml's quote key
    as `\\\\"` inside a non-raw Python string, which Python evaluates to `\\"`.
    Reading the raw source hands the checker a doubled backslash that the real
    page never contains, and `node --check` then rejects JS that is perfectly
    valid in the browser. The render harness said ALL PARSE while this said FAIL
    — two instruments disagreeing, and the one reading real output was right.

    Executing the function is what makes this test the same string the browser
    receives. These three emitters are pure (no args, no globals, they return a
    literal), so exec'ing them in an empty namespace is safe and total.

    Fails loudly rather than returning "" — an empty body would make every
    downstream containment check trivially pass, which is the exact
    instrument-that-can-only-say-yes shape this repo keeps finding.
    """
    import ast
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            ns = {}
            exec(compile(ast.Module([node], []), "<emitter>", "exec"), ns)
            body = ns[name]()
            if not body.strip():
                sys.exit("FATAL: %s() returned an empty body" % name)
            return body
    sys.exit("FATAL: could not extract %s() from dashboard.py" % name)


print("\n1. The three emitters exist and are non-empty")
css = emitter_body("_alert_modal_css")
html_ = emitter_body("_alert_modal_html")
js = emitter_body("_alert_modal_js")
check("css emitter non-empty", bool(css.strip()), True)
check("html emitter non-empty", bool(html_.strip()), True)
check("js emitter non-empty", bool(js.strip()), True)

print("\n2. Both host pages include all three")
# Counted on the SOURCE rather than a render: this must hold for every page that
# hosts the modal, and a render only proves the two that happen to be exercised.
for fn in ("_alert_modal_css()", "_alert_modal_html()", "_alert_modal_js()"):
    check("%s referenced twice (both pages)" % fn, src.count("{" + fn + "}"), 2)

print("\n3. The modal does not carry a second renderer's worth of ids")
# One hardcoded id per page is the whole single-instance contract; a second copy
# is a duplicate-id collision where getElementById() silently returns the first.
check("one alertModal id in the emitter", html_.count('id="alertModal"'), 1)
check("one modalContent id", html_.count('id="modalContent"'), 1)
check("one _alertChatHost id", html_.count('id="_alertChatHost"'), 1)

print("\n4. CSS covers every class the markup uses")
markup_classes = set()
for group in re.findall(r'class="([^"]+)"', html_):
    markup_classes.update(group.split())
# tier-text is styled by static/tier.js's own consumers, not by this component.
markup_classes.discard("tier-text")
missing = sorted(c for c in markup_classes if (".%s {" % c) not in css)
check("markup classes with no CSS rule", missing, [])

print("\n5. CSS covers every class the JS emits at runtime")
js_classes = set()
for pat in (r'class=[\\]*"([a-zA-Z0-9 _-]+)', r"class='([a-zA-Z0-9 _-]+)"):
    for g in re.findall(pat, js):
        js_classes.update(g.split())
js_classes.discard("tier-text")
missing_js = sorted(c for c in js_classes if (".%s {" % c) not in css)
check("JS-emitted classes with no CSS rule", missing_js, [])

print("\n6. The rule that actually hides the modal")
# Named on its own because losing it is silent in every other check and loud on
# screen: the modal renders fully expanded in the document flow.
check(".modal carries display:none",
      bool(re.search(r"\.modal \{[^}]*display:none", css)), True)

print("\n7. .btn-save did NOT travel with the component")
# It belongs to the device-edit modal, which is main-page-only. Only what this
# component renders should ship with it.
check(".btn-save absent from the shared CSS", ".btn-save" in css, False)

print("\n8. /firewall-db no longer NAVIGATES to the main dashboard")
fw = re.search(r"def firewall_db\(\).*?(?=\n@app\.route)", src, re.S)
if not fw:
    sys.exit("FATAL: could not isolate firewall_db() from dashboard.py")
fwsrc = fw.group(0)
check("no href=/?alert= links remain", 'href="/?alert=' in fwsrc, False)
check("Analyze calls viewAlert in place", "viewAlert(" in fwsrc, True)
check("Analyze suppresses navigation", "return false" in fwsrc, True)

print("\n9. The emitter returns RAW js (the main page nests it in an open block)")
check("no <script> tag inside the js emitter", "<script" in js, False)
check("no closing script tag either", "</script>" in js, False)

print("\n10. Emitted JS parses (node --check)")


def node_check(text):
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(text)
        p = f.name
    try:
        r = subprocess.run(["node", "--check", p], capture_output=True,
                           text=True, timeout=60)
        return r.returncode == 0, (r.stderr or "").strip()
    finally:
        os.unlink(p)


if not subprocess.run(["which", "node"], capture_output=True).returncode == 0:
    sys.exit("FATAL: node unavailable — refusing to report a pass for a check "
             "that did not run")
# Prove the checker can say NO before trusting it when it says YES.
bad_ok, _ = node_check("var a = ; function {{{")
good_ok, _ = node_check("var a=1;")
check("node --check rejects known-bad", bad_ok, False)
check("node --check accepts known-good", good_ok, True)
ok, err = node_check(js)
if not ok:
    print("      node error:", err[:300])
check("shared modal JS parses", ok, True)

print("\n11. Functions the host pages call are actually defined here")
for fn in ("viewAlert", "closeModal", "takeAction", "unblockIp", "reportAbuse"):
    check("%s defined once" % fn, js.count("function %s(" % fn), 1)

passed = sum(1 for _, ok in _results if ok)
total = len(_results)
print("\n%d/%d checks passed (ran=%d expected=%d)"
      % (passed, total, total, EXPECTED_CHECKS))
if total != EXPECTED_CHECKS:
    print("ERROR: ran %d checks, expected %d — a check was added or skipped "
          "without updating EXPECTED_CHECKS" % (total, EXPECTED_CHECKS))
    sys.exit(2)
sys.exit(0 if passed == total else 1)
