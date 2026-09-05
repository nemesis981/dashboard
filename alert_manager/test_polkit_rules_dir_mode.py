#!/usr/bin/env python3
"""install.sh must not widen /etc/polkit-1/rules.d from the mode polkitd ships.

Run: python3 alert_manager/test_polkit_rules_dir_mode.py   (exit 0 = all pass)

THE INVARIANT
    `install -d` CHMODS a directory that already exists, so it must never be
    applied unconditionally to a packaged path. polkitd ships
    /etc/polkit-1/rules.d as 0750 root:polkitd; a wider mode there would make
    every polkit rule on the system world-readable. The installer must create
    that directory only when it is genuinely absent, and at the packaged mode.

⛔ THE SNIPPET UNDER TEST IS EXTRACTED FROM install.sh, NOT REIMPLEMENTED.
    A copy of the logic here would drift from the installer and then prove
    something about this file instead of about the shipped code. The block is
    read out of install.sh and re-pointed at a temp directory.

⛔ COMMENTS ARE STRIPPED BEFORE ANY SOURCE MATCHING.
    The fix's own comment quotes `install -d -m 0755` while explaining why it is
    wrong -- so a raw grep for the defect matches the documentation of the
    defect and reports a bug that is not there. This repo has three logged
    instances of exactly that. Writing a good comment is what creates the false
    match, which is why stripping is not optional here.
"""
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = os.environ.get("NEMESIS_ROOT", "/opt/nemesis")
INSTALL_SH = os.path.join(ROOT, "install.sh")

EXPECTED_CHECKS = 11
_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + str(detail)) if detail else ""))


def strip_sh_comments(text):
    """Drop full-line and trailing `#` comments.

    Deliberately conservative: a `#` inside a quoted string would also be cut.
    That is acceptable here because the result is used ONLY for absence
    assertions -- over-stripping can cause a false PASS on a string that happens
    to contain `#`, never a false FAIL, and the guard-present assertion below is
    matched against the same stripped text so the two cannot disagree.
    """
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("#"):
            continue
        out.append(re.sub(r"\s+#.*$", "", line))
    return "\n".join(out)


def mode_of(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def extract_block(src):
    """The polkit rules-dir creation block, re-pointed at $TESTDIR."""
    m = re.search(r"(if \[\[ ! -d /etc/polkit-1/rules\.d \]\]; then.*?\n        fi\n)",
                  src, re.S)
    if not m:
        return None
    block = m.group(1)
    # Run as the invoking user, not root: -o/-g would need privilege we do not
    # have and are not what this test is about. Mode is the whole question.
    block = block.replace("/etc/polkit-1/rules.d", '"$TESTDIR"')
    block = re.sub(r"\s-o root -g polkitd", "", block)
    block = re.sub(r"\s-o root -g root", "", block)
    return block


def run_sh(script, testdir):
    return subprocess.run(["bash", "-c", script], env={**os.environ, "TESTDIR": testdir},
                          capture_output=True, text=True)


src = open(INSTALL_SH, encoding="utf-8").read()
stripped = strip_sh_comments(src)

_MARKER = "applied unconditionally to a packaged path"

print("1. the source guards the packaged directory")
check("no unguarded `install -d -m 0755 /etc/polkit-1/rules.d`",
      "install -d -m 0755 /etc/polkit-1/rules.d" not in stripped)
check("  ...and the rationale is documented next to the guard",
      _MARKER in src,
      "the explanation was removed -- a future edit will not know why the guard exists")
# CONTROL for the stripper itself, keyed on a phrase that exists ONLY inside the
# fix's comment. An earlier version asserted `"install -d -m 0755" not in
# stripped`, which FAILED -- and correctly so: install.sh uses that exact command
# legitimately for four other directories ($dropin, /etc/apparmor.d/local,
# $UNIT_BACKUP_DIR), none of which ship with a tighter mode. The assertion was
# too broad, not the code. Keyed narrowly now so it proves the stripper works
# without entangling unrelated call sites.
check("  (control: the stripper removes that comment text)",
      _MARKER not in stripped,
      "marker survived stripping -- the comment stripper is not working")
check("the existence guard is present", "if [[ ! -d /etc/polkit-1/rules.d ]]; then" in stripped)
check("the created mode is 0750, not 0755", "install -d -m 0750" in stripped)

print("\n2. the block extracts from install.sh (not reimplemented here)")
block = extract_block(src)
check("block found in install.sh", block is not None,
      "the installer was restructured -- this test is stale, not the code")
if block is None:
    print("\n%d passed, %d failed" % (_pass, _fail))
    sys.exit(1)

tmp = tempfile.mkdtemp(prefix="nemesis-polkit-test-")
try:
    target = os.path.join(tmp, "rules.d")

    print("\n3. KNOWN-BAD control: the OLD command really does widen an existing dir")
    os.mkdir(target, 0o750)
    os.chmod(target, 0o750)
    run_sh('install -d -m 0755 "$TESTDIR"', target)
    widened = mode_of(target)
    check("old form chmods 0750 -> 0755 (the bug is real, and stat can see it)",
          widened == 0o755, "got %o" % widened)

    print("\n4. the NEW block leaves an existing directory alone")
    os.chmod(target, 0o750)
    r = run_sh(block, target)
    check("exit 0", r.returncode == 0, r.stderr.strip()[:120])
    after = mode_of(target)
    check("existing 0750 directory is NOT chmodded", after == 0o750, "got %o" % after)

    print("\n5. the NEW block creates a missing directory at 0750")
    shutil.rmtree(target)
    r = run_sh(block, target)
    check("directory created", os.path.isdir(target), r.stderr.strip()[:120])
    created = mode_of(target)
    check("created 0750, not the umask default", created == 0o750, "got %o" % created)
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print("\n%d passed, %d failed" % (_pass, _fail))
if _pass + _fail != EXPECTED_CHECKS:
    print("EXPECTED_CHECKS MISMATCH: declared %d, ran %d" % (EXPECTED_CHECKS, _pass + _fail))
    sys.exit(1)
sys.exit(1 if _fail else 0)
