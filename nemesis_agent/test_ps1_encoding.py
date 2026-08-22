#!/usr/bin/env python3
"""Every shipped .ps1 in the repo must decode correctly under Windows PowerShell 5.1.

Run: python3 /opt/nemesis/nemesis_agent/test_ps1_encoding.py

WHY THIS EXISTS (VM-verified 2026-08-22)
----------------------------------------
Windows PowerShell 5.1 reads a .ps1 with NO byte-order mark using the machine's ANSI
codepage, not UTF-8. A UTF-8 em dash (E2 80 94) therefore arrives as three CP1252
characters ending in U+201D -- and PowerShell treats U+201D as a REAL double-quote
delimiter. So a single em dash inside a quoted string closes that string early and
everything after it parses as code.

This is not theoretical. `deploy_privservice_windows.ps1` shipped with em dashes and
would NOT PARSE AT ALL on a stock Windows 11 box:

    line 73: Missing closing '}' in statement block or type definition.
    line 97: Missing argument in parameter list.

The script never ran a single statement -- no service, no canary, nothing -- and the
failure looked like a syntax bug in code that is perfectly valid UTF-8 on Linux.

THE RULE: pure ASCII, or a UTF-8 BOM. Either one makes the decode unambiguous.
ASCII is preferred here because a BOM is easy to lose (editors, git filters, copy
through a pipeline) and its absence fails silently in exactly this way.

NOTE ON MEASUREMENT: counting mojibake characters is NOT a sound test -- a smart
quote inside a `#` comment is harmless. Only position matters, and only PowerShell can
judge that. This test therefore enforces invariants that ARE decidable here, and the
real syntax gate belongs in the Windows VM acceptance.

WHY A PARSE CHECK IS NECESSARY BUT NOT SUFFICIENT (learned 2026-08-22)
----------------------------------------------------------------------
The first version of this file checked encoding only. It passed `uninstall_windows.ps1`
while that file carried a five-line ENCODING banner inserted OUTSIDE its `<# #>` block
with no `#` prefix -- lines that are not comments at all.

Worse, the Windows-side PARSE check passed it too, with **zero parse errors**, because
those lines are perfectly valid PowerShell *syntax*:

    line 3   Generic      ENCODING:          <- parsed as a COMMAND NAME
    line 3   Identifier   this
    line 3   Identifier   file  ...          <- parsed as its ARGUMENTS

PowerShell would have parsed the file happily and then failed at RUNTIME with "the term
'ENCODING:' is not recognized". So:

  * an ASCII/BOM check catches the FINDING-3 class (an em dash closing a string early)
  * a parse-error check catches syntax breakage
  * NEITHER catches valid-syntax/wrong-semantics, which is this class

The decidable invariant for THIS class is our own convention: the ENCODING banner must
be commented. That is checked below on any platform. The authoritative check --
PowerShell tokenising those lines as `Comment` -- runs on the VM (tools/ps1_token_check.ps1).
"""

import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
#: Repo root, so the rule covers EVERY shipped .ps1, not just the agent's. The bug
#: is a property of how Windows decodes the file, so it applies anywhere a .ps1 is
#: shipped -- scoping this to one directory would leave the same trap open in
#: modules/.
REPO = os.path.dirname(HERE)

#: Files known to violate the rule, with the reason they are not fixed here.
#: An entry is a DEBT MARKER, not a pass: the test still reports it loudly.
#: Files known to violate the rule, with the reason they are not fixed here.
#: An entry is a DEBT MARKER, not a pass: the test still reports it loudly, and a
#: file that becomes clean while still listed FAILS the suite, so an exemption can
#: never outlive the bug it excused.
#:
#: EMPTY as of 2026-08-22: install_windows.ps1 and uninstall_windows.ps1 were both
#: converted to pure ASCII (encoding-only, no logic changes) and are now enforced by
#: the same rule as every other shipped script.
KNOWN_VIOLATIONS = {}

_failures = []
_debt = []


def check(label, got, want):
    ok = got == want
    if not ok:
        _failures.append("%s: got %r, want %r" % (label, got, want))
    print("  %-58s %s%s" % (label, "PASS" if ok else "FAIL",
                            "" if ok else "  (got=%r want=%r)" % (got, want)))


def classify(path):
    data = open(path, "rb").read()
    if data[:3] == b"\xef\xbb\xbf":
        return "bom", None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        return "undecodable", str(exc)
    bad = sorted({c for c in text if ord(c) > 127})
    if not bad:
        return "ascii", None
    return "risky", "".join(bad)


def test_every_ps1_is_ascii_or_bom():
    print("\n[every shipped .ps1 is pure ASCII or carries a UTF-8 BOM]")
    files = sorted(glob.glob(os.path.join(REPO, "**", "*.ps1"), recursive=True))
    check("found .ps1 files to check", len(files) > 0, True)
    for path in files:
        name = os.path.relpath(path, REPO)
        kind, detail = classify(path)
        if kind in ("ascii", "bom"):
            print("  %-58s %s" % (name, kind.upper()))
            if name in KNOWN_VIOLATIONS:
                _failures.append("%s is now clean -- remove its KNOWN_VIOLATIONS "
                                 "entry so the exemption cannot outlive the bug"
                                 % name)
                print("  %-58s STALE EXEMPTION" % name)
            continue
        if name in KNOWN_VIOLATIONS:
            _debt.append((name, detail, KNOWN_VIOLATIONS[name]))
            print("  %-58s KNOWN DEBT (non-ASCII %r)" % (name, detail))
        else:
            check("%s is ASCII or BOM (non-ASCII %r)" % (name, detail), False, True)


#: The marker line every ENCODING banner starts with. Checked structurally below.
_BANNER_MARKER = "ENCODING: this file MUST stay pure ASCII"

#: Files that legitimately contain the marker as DATA rather than as a banner -- i.e.
#: the checkers themselves, which must name the string they look for. Narrow by
#: design: a shipped installer has no reason to be here, and an entry that stops
#: containing the marker at all FAILS below, so this cannot quietly rot.
_MARKER_AS_DATA = {
    "nemesis_agent/tools/ps1_token_check.ps1":
        "the Windows-side token checker; it must name the marker it searches for",
}


def _banner_is_commented(text):
    """Is every line of the ENCODING banner actually a comment?

    Decidable without PowerShell: a line is commented if it starts with `#`, or if it
    lies between a `<#` and its matching `#>`. Returns (ok, first_bad_line_no_or_None).
    """
    depth = 0
    in_banner = False
    for n, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        opens, closes = line.count("<#"), line.count("#>")
        started_inside = depth > 0
        depth += opens - closes
        if _BANNER_MARKER in raw:
            in_banner = True
        if not in_banner:
            continue
        if not raw.strip():
            in_banner = False              # blank line ends the banner
            continue
        commented = raw.lstrip().startswith("#") or started_inside or depth > 0
        if not commented:
            return False, n
    return True, None


def test_encoding_banner_is_actually_commented():
    """REGRESSION (Window 2, 2026-08-22). The banner was inserted BEFORE
    `uninstall_windows.ps1`'s opening `<#`, un-prefixed -- five bareword lines that are
    not comments. Both the encoding check AND the Windows parse check passed it, the
    latter with zero parse errors, because `ENCODING: this file MUST ...` is valid
    PowerShell syntax: a command name plus arguments. It would have failed at runtime.

    This asserts the property those two checks were blind to."""
    print("\n[the ENCODING banner is inside a comment on every line]")
    for path in sorted(glob.glob(os.path.join(REPO, "**", "*.ps1"), recursive=True)):
        name = os.path.relpath(path, REPO)
        text = open(path, encoding="utf-8", errors="replace").read()
        if _BANNER_MARKER not in text:
            if name in _MARKER_AS_DATA:
                _failures.append("%s is exempted as holding the marker as data, but no "
                                 "longer contains it -- drop the stale exemption" % name)
                print("  %-58s STALE EXEMPTION" % name)
            continue
        if name in _MARKER_AS_DATA:
            print("  %-58s marker-as-data (%s)" % (name, _MARKER_AS_DATA[name]))
            continue
        ok, bad = _banner_is_commented(text)
        check("%s: banner fully commented" % name, ok, True)
        if not ok:
            print("        first un-commented banner line: %d" % bad)


def test_the_banner_check_would_catch_the_real_regression():
    """CONTROL: rebuild the exact defect and confirm the check fails on it. Without
    this, a checker that always returns True would look identical to a passing repo."""
    print("\n[CONTROL: the banner check catches the real 2026-08-22 defect]")
    broken = ("#Requires -RunAsAdministrator\n"
              "\n"
              "    " + _BANNER_MARKER + " (no em dashes).\n"
              "    Windows PowerShell 5.1 reads a BOM-less .ps1 as the ANSI codepage.\n"
              "<#\n    real doc block\n#>\n")
    ok, bad = _banner_is_commented(broken)
    check("the un-prefixed, outside-the-block banner FAILS", ok, False)
    check("and it names the first offending line", bad, 3)

    fixed_hash = ("#Requires -RunAsAdministrator\n"
                  "# " + _BANNER_MARKER + " (no em dashes).\n"
                  "# Windows PowerShell 5.1 reads a BOM-less .ps1 as the ANSI codepage.\n")
    check("CONTROL: a '#'-prefixed banner passes", _banner_is_commented(fixed_hash)[0],
          True)

    fixed_block = ("<#\n"
                   "    " + _BANNER_MARKER + " (no em dashes).\n"
                   "    Windows PowerShell 5.1 reads it as the ANSI codepage.\n"
                   "#>\n")
    check("CONTROL: a banner INSIDE a <# #> block also passes",
          _banner_is_commented(fixed_block)[0], True)


def test_the_rule_would_catch_a_regression():
    """CONTROL: the classifier must actually distinguish the two cases, not just
    return 'ascii' for everything."""
    print("\n[CONTROL: the classifier discriminates]")
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        clean = os.path.join(d, "clean.ps1")
        open(clean, "w", encoding="ascii").write('Write-Host "plain ascii"\n')
        check("pure ASCII classifies as ascii", classify(clean)[0], "ascii")

        dirty = os.path.join(d, "dirty.ps1")
        open(dirty, "w", encoding="utf-8").write('Write-Host "an em dash — here"\n')
        check("an em dash classifies as risky", classify(dirty)[0], "risky")

        bommed = os.path.join(d, "bom.ps1")
        open(bommed, "w", encoding="utf-8-sig").write('Write-Host "em dash — ok"\n')
        check("the same content WITH a BOM is accepted", classify(bommed)[0], "bom")


if __name__ == "__main__":
    print("shipped .ps1 encoding — Windows PowerShell 5.1 decode safety")
    test_every_ps1_is_ascii_or_bom()
    test_encoding_banner_is_actually_commented()
    test_the_banner_check_would_catch_the_real_regression()
    test_the_rule_would_catch_a_regression()

    if _debt:
        print("\nKNOWN DEBT (reported every run, deliberately not silenced):")
        for name, chars, why in _debt:
            print("  - %s  (non-ASCII %r)\n      %s" % (name, chars, why))

    print()
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS" + (" (with %d known-debt file(s) reported above)" % len(_debt)
                        if _debt else ""))
