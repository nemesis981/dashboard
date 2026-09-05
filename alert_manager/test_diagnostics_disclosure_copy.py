#!/usr/bin/env python3
"""The Diagnostics page's privacy disclosure copy must describe what the code
actually does.

Run: python3 alert_manager/test_diagnostics_disclosure_copy.py  (exit 0 = pass)

WHY THIS EXISTS. On 2026-09-05 every tier of this page's disclosure copy was
false. 109191d widened diagnostics/redact.py for the Submit-to-Support path;
run_check() shared that function, so the display path silently inherited it and
started redacting the owner's own IPs, MACs and device names. The copy was never
updated, so the page said "Scope is secrets only. Network identifiers are not
redacted in general." while redacting 205 identifiers out of Network Devices
alone.

That is the SECOND time this page's copy and its behaviour disagreed. The first
was the reverse: the master plan's 2.1 recorded that Submit-to-Support mailed
device PII out "while the UI tells the user API keys and passwords are
automatically hidden". Fixing that produced the mirror image. A claim in this
copy is a claim about redact.py, and nothing checked it either time.

APPROACH: the copy is read out of dashboard.py's AST, taking only the CONSTANT
segments of diagnostics_page()'s f-string. Deliberately not a grep over the
file: a text search matches the comment describing a string as readily as the
string, and this repo has three logged instances of exactly that producing a
confident wrong answer. Constant-extraction cannot see a comment at all.

It also cannot be satisfied by prose elsewhere in dashboard.py, which a grep
could be.
"""
import ast
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

EXPECTED_CHECKS = 19

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 46:
        g, w = g[:43] + "...", w[:43] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def page_literal_text():
    """The constant (non-interpolated) text of diagnostics_page()'s f-string.

    Returns "" only if the function genuinely has no string constants, which
    would itself be a failure — the caller asserts a non-trivial length so an
    extraction that quietly found nothing cannot read as "no false claims
    present".
    """
    src = open(os.path.join(REPO, "dashboard.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "diagnostics_page":
            parts = []
            for n in ast.walk(node):
                if isinstance(n, ast.JoinedStr):
                    for v in n.values:
                        if isinstance(v, ast.Constant) and isinstance(v.value, str):
                            parts.append(v.value)
                elif isinstance(n, ast.Constant) and isinstance(n.value, str):
                    parts.append(n.value)
            return "\n".join(parts)
    sys.exit("FATAL: diagnostics_page() not found in dashboard.py")


# Claims that were true before 109191d and false after it. Each is quoted
# verbatim from the copy as it shipped, so a revert reintroduces the exact
# string and this test goes red.
FALSE_CLAIMS = [
    "Scope is secrets only. Network identifiers are not redacted in general.",
    "no PII or network-identifier handling",
    "replaces all secret values ≥8 chars with [REDACTED] before JSON "
    "response is serialized",
    "Sensitive values (API keys, passwords) are automatically redacted "
    "server-side before display or submission",
    "are redacted server-side before output reaches your browser or a "
    "support email",
]

# The distinction the copy now has to carry: display shows identifiers, export
# strips them.
REQUIRED = [
    "SCOPE_DISPLAY",
    "SCOPE_EXPORT",
    "_SECRET_NAME_PATTERN",
    "on screen they are shown in full",
    "Credentials only on screen",
    "stay visible here",
]


def main():
    text = page_literal_text()

    # LIVENESS CONTROL. Every "claim is absent" check below would pass against
    # an empty extraction, which is the classic vacuous-negative shape.
    print("control: the extraction actually produced the page copy")
    check("extracted a non-trivial amount of page text", len(text) > 20000, True)
    check("...and it is the diagnostics page (marker string present)",
          "Automatic redaction:" in text, True)
    check("...and the tier attributes survived extraction",
          text.count("data-beginner=") >= 3, True)

    print("\nclaims that became false when redact() was widened are gone")
    for claim in FALSE_CLAIMS:
        check("  absent: %s" % claim[:52], claim in text, False)

    print("\ncopy states the display/export split")
    for needle in REQUIRED:
        check("  present: %s" % needle[:52], needle in text, True)

    # ── #1 recurring bug: JS/HTML strings inside a Python f-string ──────────
    print("\ntier attributes are safe inside the f-string")
    attrs = re.findall(r'data-(?:beginner|intermediate|pro)="([^"]*)"', text)
    check("all tier attributes parse with balanced quotes", len(attrs) >= 9, True)
    check("no raw apostrophe in any tier attribute",
          any("'" in a for a in attrs), False)
    check("no stray brace in any tier attribute",
          any("{" in a or "}" in a for a in attrs), False)

    # Every tier-text block must carry all three tiers. A block missing one
    # silently falls back to another tier's wording, which is exactly how a
    # false claim survives a rewrite that "updated all the tiers". The page has
    # many such blocks (each check card has its own), so the invariant is that
    # the three counts are EQUAL -- not that there are three of them.
    counts = {t: len(re.findall(r'data-%s="' % t, text))
              for t in ("beginner", "intermediate", "pro")}
    check("all three tiers appear equally often (no block missing one)",
          len(set(counts.values())), 1)
    check("...across a plausible number of blocks (not a degenerate match)",
          counts["pro"] >= 3, True)

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [l for l, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d "
              "-- a check was skipped, not merely failed" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
