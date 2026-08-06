#!/usr/bin/env python3
"""Per-expertise-tier AI explanations — the fallback contract and the emitted JS.

Run: python3 alert_manager/test_tiered_explanations.py

WHAT THIS PINS, AND WHY EACH HALF EXISTS
----------------------------------------
The dashboard has had a three-tier explanation system (static/tier.js:
beginner | intermediate | pro) since long before AI alert analysis existed, but
`/api/analyze/<rule_id>` never participated: its prompt asked for one "Plain
English explanation for home user" unconditionally, so a `pro` reader and a
`beginner` reader got identical consumer prose. 2026-08-06 changed the prompt to
return all three variants in the SINGLE existing call and stores them in three
new `alerts` columns.

1. `_tiered_explanations()` NEVER RETURNS A BLANK TIER. Three real inputs arrive
   without all three variants — a pre-2026-08-06 row with only the flat
   `explanation`, a partial reply, and the parse-failure branch that synthesises
   an `analysis` from raw text. An empty explanation renders as "nothing to say
   about this alert", which is a LEGAL-LOOKING answer nothing downstream can
   distinguish from a real one. That is the same failure family as this route's
   three 2026-08-05 defects (a truthy `priority`, an empty prompt, an `UNKNOWN`
   risk), so it gets the same treatment: fall back, never blank.

2. THE ALL-IDENTICAL WARNING MUST FIRE ONLY WHEN EARNED. A model that returns
   three identical variants has ignored the instruction while producing a reply
   that passes every structural check. But the fallback paths produce identical
   variants BY DESIGN, so a naive check would warn constantly and train the
   reader to ignore it. Both directions are tested — the warning firing when it
   should, AND staying silent when the identity is legitimate. A warning that
   cannot stay silent is not a signal.

3. THE EMITTED JS ACTUALLY PARSES. `py_compile` cannot see inside a Python
   f-string that builds a <script> block — this repo's #1 recurring bug. The
   explanation now ships as a `.tier-text` span with three `data-*` attributes
   built by string concatenation, which is precisely the shape that breaks. So
   the rendered page's JS is extracted and run through `node --check`, and the
   check SELF-TESTS first against known-bad JS so a silently-broken checker
   cannot report a pass. (Standing practice: verification code must prove its
   own premise.)
"""
import ast
import json
import os
import re
import shutil
import subprocess
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

EXPECTED_CHECKS = 32

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


# ── Extract _tiered_explanations from dashboard.py without importing it ──────
# Importing dashboard.py wholesale runs module-level init against the live
# database, loads every module, and reads /var/lib/nemesis/.flask_secret (mode
# 0600, owned by nemesis-dash) -- so it cannot even be imported as the operator
# account. AST extraction tests the REAL source rather than a reimplementation
# that would drift and prove nothing. Same as test_analyze_alert_body.py.
def load_tiered_explanations():
    src = open(os.path.join(REPO, "dashboard.py")).read()
    tree = ast.parse(src)

    captured = {}

    class _Log:
        """Stand-in for dashboard's module logger, recording warning calls.

        Not a silent no-op: check 2's whole point is whether the warning fires,
        so a stub that swallowed it would make both directions of that test pass
        for the wrong reason.
        """
        def warning(self, *a, **k):
            captured.setdefault("warnings", []).append(a)

    ns = {"log": _Log()}
    wanted = {"_EXPLANATION_TIERS", "_tiered_explanations"}
    found = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id in wanted:
                    exec(compile(ast.Module([node], []), "<x>", "exec"), ns)
                    found.add(t.id)
        elif isinstance(node, ast.FunctionDef) and node.name in wanted:
            exec(compile(ast.Module([node], []), "<x>", "exec"), ns)
            found.add(node.name)
    missing = wanted - found
    if missing:
        sys.exit("FATAL: could not extract %s from dashboard.py" % sorted(missing))
    return ns["_tiered_explanations"], ns["_EXPLANATION_TIERS"], captured


tiered, TIERS, captured = load_tiered_explanations()

print("\n1. Tier vocabulary")
check("three tiers, in tier.js order", TIERS, ("beginner", "intermediate", "pro"))

print("\n2. Full three-variant reply — each tier gets its OWN text")
full = {
    "explanation": "flat",
    "explanation_beginner": "B text",
    "explanation_intermediate": "M text",
    "explanation_pro": "P text",
}
b, m, p = tiered(full, "r1")
check("beginner", b, "B text")
check("intermediate", m, "M text")
check("pro", p, "P text")
check("no warning when all three differ", captured.get("warnings"), None)

print("\n3. Legacy row — flat explanation only, all three fall back")
captured.clear()
b, m, p = tiered({"explanation": "only this"}, "r2")
check("beginner falls back", b, "only this")
check("intermediate falls back", m, "only this")
check("pro falls back", p, "only this")
check("NO warning — identical here is BY DESIGN", captured.get("warnings"), None)

print("\n4. Partial reply — missing variants fall back, present ones survive")
captured.clear()
b, m, p = tiered({
    "explanation": "flat",
    "explanation_pro": "P only",
}, "r3")
check("beginner -> flat (no intermediate supplied)", b, "flat")
check("intermediate -> flat", m, "flat")
check("pro survives", p, "P only")
check("no warning on a partial reply", captured.get("warnings"), None)

print("\n5. Intermediate is preferred over flat as the fallback source")
# tier.js's own DEFAULT is intermediate, so it is the closest thing to a
# tier-neutral answer -- a fallback to `flat` when a real intermediate exists
# would silently prefer the older, less specific text.
b, m, p = tiered({
    "explanation": "flat",
    "explanation_intermediate": "M text",
}, "r4")
check("beginner -> intermediate, not flat", b, "M text")
check("pro -> intermediate, not flat", p, "M text")

print("\n6. Parse-failure shape — raw text only, still never blank")
captured.clear()
b, m, p = tiered({
    "explanation": "raw unparseable model output",
    "risk_level": None,
}, "r5")
check("beginner non-blank", bool(b.strip()), True)
check("pro non-blank", bool(p.strip()), True)
check("all three equal the raw text", (b, m, p),
      ("raw unparseable model output",) * 3)

print("\n7. Empty everything — degrades to empty, does NOT raise")
# A blank result is bad, but raising here would turn a cosmetic problem into a
# 500 on the whole analyze route. The route's own 422 guard upstream is what
# prevents an empty body reaching the model in the first place.
b, m, p = tiered({}, "r6")
check("returns three values, no exception", (b, m, p), ("", "", ""))

print("\n8. All-identical warning FIRES when the model ignored the instruction")
captured.clear()
b, m, p = tiered({
    "explanation_beginner": "same",
    "explanation_intermediate": "same",
    "explanation_pro": "same",
}, "r7")
check("warning fired", len(captured.get("warnings", [])), 1)
check("values still returned (warn, don't fail)", (b, m, p), ("same",) * 3)

print("\n9. Whitespace-only variants are treated as ABSENT, not as content")
# A model emitting "   " would otherwise satisfy a truthiness check and render
# as a blank explanation -- the exact legal-looking-but-empty shape guarded
# against above.
captured.clear()
b, m, p = tiered({
    "explanation": "real text",
    "explanation_beginner": "   ",
    "explanation_pro": "\n\t",
}, "r8")
check("whitespace beginner -> fallback", b, "real text")
check("whitespace pro -> fallback", p, "real text")

# ── The emitted JS ───────────────────────────────────────────────────────────
print("\n10. Emitted dashboard JS parses (node --check)")


def node_check(js_text, label):
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(js_text)
        path = f.name
    try:
        r = subprocess.run(["node", "--check", path],
                           capture_output=True, text=True, timeout=60)
        return r.returncode == 0, (r.stderr or "").strip()
    finally:
        os.unlink(path)


if not shutil.which("node"):
    sys.exit("FATAL: node not available — cannot verify emitted JS. "
             "Refusing to report a pass for a check that did not run.")

# SELF-TEST FIRST. A checker that returns True unconditionally would pass every
# real case below and prove nothing -- so prove it can say NO before trusting it
# when it says YES.
ok_good, _ = node_check("var a = 1; function f(){ return a; }", "known-good")
ok_bad, _ = node_check("var a = ; function {{{", "known-bad")
check("node --check accepts known-GOOD js", ok_good, True)
check("node --check rejects known-BAD js", ok_bad, False)

# Extract the alert-modal JS region from the rendered f-string source. Rendering
# the whole page needs the Flask app; this instead pulls the concatenation block
# that was actually changed and wraps it in a function so it is parseable alone.
src = open(os.path.join(REPO, "dashboard.py")).read()
start = src.find("var explFallback = data.explanation")
end = src.find("if (window.applyTierText) applyTierText();")
if start < 0 or end < 0:
    sys.exit("FATAL: could not locate the emitted explanation-block JS in "
             "dashboard.py — the extraction anchors have moved. Refusing to "
             "report a pass for a region that was not found.")
region = src[start:end]
# The page is built by a Python f-string, so literal JS braces are doubled.
# Undo that to recover the JS as the browser receives it.
region_js = region.replace("{{", "{").replace("}}", "}")
ok_region, err = node_check(
    "function _t(){ var data={}, escapeHtml=String, tierText=function(){};\n"
    + region_js + "\n return explHtml; }", "explanation block")
if not ok_region:
    print("      node error:", err[:300])
check("changed explanation-block JS parses", ok_region, True)

print("\n11. The data-* attribute contract matches tier.js")
# tier.js's applyTierText() reads getAttribute('data-' + tier) for exactly these
# three names on elements with class 'tier-text'. A typo in either half fails
# silently -- the element simply never updates -- so both halves are pinned.
check("emits class='tier-text'", "class='tier-text'" in region, True)
for t in TIERS:
    check("emits data-%s" % t, ("data-%s='" % t) in region, True)

tierjs = open(os.path.join(REPO, "static", "tier.js")).read()
check("tier.js still selects .tier-text", ".tier-text" in tierjs, True)
check("tier.js still reads data-<tier>", "'data-' + tier" in tierjs, True)

# ── Summary ──────────────────────────────────────────────────────────────────
passed = sum(1 for _, ok in _results if ok)
total = len(_results)
print("\n%d/%d checks passed (ran=%d expected=%d)"
      % (passed, total, total, EXPECTED_CHECKS))
if total != EXPECTED_CHECKS:
    # A silently-skipped check is invisible without this. It has caught its own
    # author more than once.
    print("ERROR: ran %d checks, expected %d — a check was added or skipped "
          "without updating EXPECTED_CHECKS" % (total, EXPECTED_CHECKS))
    sys.exit(2)
sys.exit(0 if passed == total else 1)
