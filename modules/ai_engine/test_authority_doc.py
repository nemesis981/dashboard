#!/usr/bin/env python3
"""ARCHITECTURE.md's authority ladder must match the code it describes.

Run:  python3 modules/ai_engine/test_authority_doc.py   (exit 0 = pass)

WHY THIS EXISTS. Until 2026-08-21 ARCHITECTURE.md documented the approval model
as "Teaching Mode / Automated Mode" with `LOW=click OK, MEDIUM=confirm,
HIGH=type YES` — a vocabulary that appears nowhere in the tree, describing an
execution path that does not exist. It sat there, authoritative-looking, while
the code shipped an entirely different design (the L0–L4 ladder).

That is the SECOND-SOURCE-OF-TRUTH failure this repo already knows by name: the
same session found the Settings page hardcoding "Claude Sonnet 4.6" while the
engine calls `claude-sonnet-5`. A doc that restates constants desyncs by default
— the only question is when someone notices.

So the doc is not merely rewritten; the parts of it that restate code are PINNED
here. Every level name, number and per-class ceiling in the table is parsed out
of ARCHITECTURE.md and compared against `modules/ai_engine/module.py`. If either
side moves without the other, this fails.

CONTROLS. The parser is proved to actually find rows before any comparison is
trusted — a regex that silently matched nothing would otherwise "pass" every
assertion by comparing two empty sets.
"""
import os
import re
import sys

sys.path.insert(0, "/opt/nemesis")

ROOT = "/opt/nemesis"
ARCH = os.path.join(ROOT, "ARCHITECTURE.md")
MOD = os.path.join(ROOT, "modules", "ai_engine", "module.py")

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + detail) if detail else ""))


arch = open(ARCH).read()
code = open(MOD).read()

# ── parse the code side ─────────────────────────────────────────────────────
code_levels = dict(
    (m.group(1), int(m.group(2)))
    for m in re.finditer(r"^(L[0-4]_[A-Z_]+)\s*=\s*([0-4])\s*$", code, re.M))

_ceil_block = re.search(r"ACTION_CLASS_CEILINGS\s*=\s*\{(.*?)\}", code, re.S)
code_ceilings = dict(
    (m.group(1), m.group(2))
    for m in re.finditer(r'"([a-z_]+)":\s*(L[0-4]_[A-Z_]+)', _ceil_block.group(1) if _ceil_block else ""))

# ── parse the doc side ──────────────────────────────────────────────────────
doc_levels = dict(
    (m.group(2), int(m.group(1)))
    for m in re.finditer(r"^\|\s*([0-4])\s*\|\s*`(L[0-4]_[A-Z_]+)`\s*\|", arch, re.M))
doc_classes = set(re.findall(r"`([a-z_]{6,})`", arch))


def main():
    print("\n-- PREMISE: both parsers actually found something --")
    check("code defines 5 levels", len(code_levels) == 5, repr(code_levels))
    check("code defines action-class ceilings", len(code_ceilings) >= 4, repr(code_ceilings))
    check("doc table yielded level rows", len(doc_levels) >= 5, repr(doc_levels))

    print("\n-- the documented ladder matches the code exactly --")
    check("same level NAMES", set(doc_levels) == set(code_levels),
          "doc=%r code=%r" % (sorted(doc_levels), sorted(code_levels)))
    for name, num in sorted(code_levels.items()):
        check("%s documented as %d" % (name, num), doc_levels.get(name) == num,
              "doc says %r" % (doc_levels.get(name),))

    print("\n-- every action class in code is named in the doc --")
    for cls in sorted(code_ceilings):
        check("%s appears in ARCHITECTURE.md" % cls, cls in doc_classes)

    print("\n-- each class's documented ceiling matches the code --")
    for cls, lvl in sorted(code_ceilings.items()):
        # the doc names the ceiling in prose near the class; require the level's
        # short form (e.g. "L3") to appear in the same sentence as the class
        sent = next((s for s in re.split(r"(?<=[.;])\s", arch) if "`%s`" % cls in s), "")
        want = lvl.split("_")[0]                       # L0..L4
        check("%s documented at %s" % (cls, want), want in sent,
              "sentence=%r" % sent[:160])

    print("\n-- the retired vocabulary is gone from ARCHITECTURE.md --")
    # Allowed ONLY inside the paragraph that explicitly retires it.
    stray = [ln for ln in arch.splitlines()
             if re.search(r"LOW=click|MEDIUM=confirm|HIGH=type YES", ln)
             and "supersedes" not in ln and "appears nowhere" not in ln]
    check("no live LOW/MEDIUM/HIGH approval claim remains", not stray, repr(stray))
    check("the architecture diagram no longer labels ai_engine with the old modes",
          "Teaching / Automated mode" not in arch)

    print("\n-- the doc states the ladder's current inert state --")
    check("it says the ladder is inert / has no production writer",
          "INERT" in arch or "no production writer" in arch)

    print("\n%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
