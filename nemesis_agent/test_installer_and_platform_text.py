#!/usr/bin/env python3
"""Three defects found by the first real Linux agent enrollment, 2026-09-04.

All three shipped because each fails in a way that still LOOKS successful:

  1. `install_linux.sh`'s enrollment heredoc is UNQUOTED, so bash command-substitutes
     backticks that appear in PYTHON COMMENTS inside it. Observed live: it printed
     `syntax error near unexpected token '('` and `first_connect: command not found`
     and then **exited 0**. Harmless only because the affected lines are comments —
     a future edit putting a real `$(...)` in code would silently corrupt the Python.
     The same file already has the safe pattern twice (lines 259, 279): quoted
     delimiter, values passed as positional args. The enrollment heredoc is the lone
     divergent sibling, which is the defect signature this repo already names.

  2. The unencrypted-key warning names a WINDOWS mechanism ("Task-Scheduler startup
     never prompts") and is emitted unconditionally. On the Linux agent — verified
     live in this session — a Linux operator is told to fix it via a mechanism that
     does not exist on their platform.

  3. `install.sh`'s subnet fallback hardcodes /24 from the first three octets. On a site
     whose LAN is wider than a /24 the derived enrollment allow is too narrow, and any
     client outside it is silently refused. The same file condemns exactly
     this shape ~1800 lines later: "a failed read became a permissive default … the
     shape this codebase treats as a defect class".

Run: python3 nemesis_agent/test_installer_and_platform_text.py
"""
import os
import re
import sys

ROOT = os.environ.get("NEMESIS_ROOT", "/opt/nemesis")

EXPECTED_CHECKS = 11
_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


def _heredocs(text):
    """Yield (delimiter, quoted?, body) for every heredoc in a shell script."""
    out = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = re.search(r"<<-?\s*('([A-Za-z_]+)'|\"([A-Za-z_]+)\"|([A-Za-z_]+))\s*$",
                      lines[i])
        if m:
            quoted = bool(m.group(2) or m.group(3))
            delim = m.group(2) or m.group(3) or m.group(4)
            body, j = [], i + 1
            while j < len(lines) and lines[j].strip() != delim:
                body.append(lines[j]); j += 1
            out.append((delim, quoted, "\n".join(body), i + 1))
            i = j
        i += 1
    return out


# ── 1. install_linux.sh heredoc quoting ──────────────────────────────────────
print("\n1. no unquoted heredoc may contain shell-expandable text")
il = open(os.path.join(ROOT, "nemesis_agent", "install_linux.sh")).read()
hds = _heredocs(il)
check("found heredocs to inspect (liveness -- a parser that finds none proves nothing)",
      len(hds) >= 4, "found %d" % len(hds))

offenders = [(d, ln) for d, q, b, ln in hds
             if not q and ("`" in b or "$(" in b)]
check("NO unquoted heredoc contains a backtick or $( ", not offenders, repr(offenders))

enroll = [(d, q, ln) for d, q, b, ln in hds if "import config, enrollment" in b]
check("the enrollment heredoc was located", len(enroll) == 1, repr(enroll))
check("  ...and its delimiter is QUOTED",
      len(enroll) == 1 and enroll[0][1] is True, repr(enroll))

# The house pattern it must match: siblings pass values as positional args.
check("siblings still use the quoted+positional pattern (guard against 'fixing' them wrong)",
      il.count("<<'PYEOF'") >= 2, str(il.count("<<'PYEOF'")))

# ── 2. platform-specific text ────────────────────────────────────────────────
print("\n2. the unencrypted-key warning must not name a Windows mechanism on Linux")
ag = open(os.path.join(ROOT, "nemesis_agent", "agent.py")).read()
warn_idx = ag.find("stored UNENCRYPTED on disk")
check("the warning site was located", warn_idx > 0)
window = ag[max(0, warn_idx - 1200):warn_idx + 600]
# ⛔ Must match a real CONDITIONAL, not any mention of a platform API. The first
# version of this check searched the window for "platform.system()" -- and passed
# against a mutant, because the explanatory COMMENT above the fix contains that
# string. A test satisfied by its own prose measures nothing. Strip comments first,
# then require an actual `if <expr> == "Windows"` branch.
_code = "\n".join(l.split("#", 1)[0] for l in window.splitlines())
check("Task-Scheduler wording sits behind a real platform CONDITIONAL",
      ("Task-Scheduler" not in _code)
      or re.search(r'if\s+[A-Za-z_.()]*(platform|system)[A-Za-z_.()]*\s*==\s*["\']Windows["\']',
                   _code, re.I) is not None,
      "Task-Scheduler text present with no platform conditional in CODE")

# ── 3. install.sh subnet fallback ────────────────────────────────────────────
print("\n3. subnet derivation must not invent a /24")
ish = open(os.path.join(ROOT, "install.sh")).read()
check("no hardcoded '.0/24' fallback remains",
      not re.search(r"grep -oP '\^\\d\+\\\.\\d\+\\\.\\d\+'\)\.0/24", ish)
      and ".0/24\"" not in ish,
      "hardcoded /24 fallback still present")
check("  ...the correct interface-derived path is still there",
      "ip_interface(" in ish and "').network" in ish)
# Parse the actual `if [[ -z "$DETECTED_SUBNET" ]]` block rather than a fuzzy
# character window -- the first version of this check used `.{0,400}` and failed
# against a correct fix simply because the explanatory comment was longer than the
# window. A regex whose verdict depends on comment length is not measuring the code.
_lines = ish.splitlines()
_blk = []
for _i, _l in enumerate(_lines):
    if 'if [[ -z "$DETECTED_SUBNET" ]]' in _l:
        _j = _i + 1
        while _j < len(_lines) and _lines[_j].strip() != "fi":
            _blk.append(_lines[_j]); _j += 1
        break
_blktxt = "\n".join(_blk)
check("  ...and the empty-subnet branch was located (liveness)", bool(_blk),
      "block not found")
check("  ...and that branch FAILS LOUD rather than guessing",
      bool(re.search(r"^\s*(die |exit 1)", _blktxt, re.M)),
      repr(_blktxt[:120]))

print("\n%d passed, %d failed" % (_pass, _fail))
if _pass + _fail != EXPECTED_CHECKS:
    print("EXPECTED_CHECKS MISMATCH: declared %d, ran %d" % (EXPECTED_CHECKS, _pass + _fail))
    sys.exit(1)
sys.exit(1 if _fail else 0)
