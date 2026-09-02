"""R2 — every install-side action MUST have an `install-manifest.json` entry.

THE INVARIANT (clean-uninstall-build-spec.md §1 / R2):

    ANYTHING the product installs -- scheduled task, registry key, service, file, driver,
    Defender exclusion, firewall rule, shortcut -- MUST be recorded in install-manifest.json,
    or uninstall will not remove it. Out-of-band creation = guaranteed residue.

R2 was filed as a guardrail confirmed by a NON-bug (`NemesisOvernightLog`, a dev artifact that
correctly survived). This file turns the guardrail into an executable check, and writing it
immediately found a REAL gap: the installer creates a Start Menu folder with two shortcuts,
while the uninstaller removed it via a SEPARATELY HARDCODED path constant rather than from the
manifest. Two independent definitions of one path: identical today, silently divergent the
moment either is edited -- and a divergence orphans the folder with no error anywhere.

DIRECTION MATTERS, SO BOTH ARE ASSERTED:
  forward  -- an install action with no manifest key  -> residue on uninstall
  backward -- a manifest key with no install action   -> a phantom entry that makes the
              manifest look more complete than it is, which is worse than an obvious hole
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import installer_gui as I  # noqa: E402

_fail = []
_count = 0
EXPECTED_CHECKS = 14

INSTALLER_SRC = open(os.path.join(HERE, "installer_gui.py"), encoding="utf-8").read()
UNINSTALLER_SRC = open(os.path.join(HERE, "uninstaller_gui.py"), encoding="utf-8").read()

# Explicit inventory: an install ACTION marker -> the manifest key that must cover it.
# Adding an install action means adding a row here, which is the point: the check cannot
# be satisfied by silence.
ACTIONS = {
    "schtasks":         ("scheduled_tasks",      r"schtasks"),
    "defender":         ("defender_exclusion",   r"Add-MpPreference"),
    "arp registry":     ("registry",             r"winreg\.CreateKey"),
    "tailscale":        ("tailscale",            r"tailscale"),
    "lhm bundle":       ("librehardwaremonitor", r"\blhm\b"),
    "clamav bundle":    ("clamav",               r"clamav"),
    "pawnio":           ("pawnio",               r"pawnio"),
    "start menu":       ("start_menu",           r"Start Menu"),
}


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-72s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def manifest_keys():
    m = I._build_manifest("C:\\x", ts_pre_existing=False, ts_now=True,
                          lhm=True, clam=True, pawnio_installed=True)
    return set((m.get("components") or {}).keys())


def test_detector_can_tell_present_from_absent():
    print("\n[positive control: the scanner must distinguish present from absent]")
    # A marker that IS in the installer, and one that certainly is not. Without this,
    # "no violations found" could equally mean "the regexes match nothing".
    check("detects a marker that is genuinely present",
          bool(re.search(r"schtasks", INSTALLER_SRC, re.I)), True)
    check("does NOT detect an invented marker",
          bool(re.search(r"ZzNotARealInstallAction", INSTALLER_SRC, re.I)), False)


def test_every_install_action_has_a_manifest_key():
    print("\n[FORWARD: an install action with no manifest key = residue on uninstall]")
    keys = manifest_keys()
    for label, (key, pattern) in sorted(ACTIONS.items()):
        performed = bool(re.search(pattern, INSTALLER_SRC, re.I))
        # only assert coverage for actions the installer actually performs
        check("%-14s performed -> manifest key %r" % (label, key),
              (not performed) or (key in keys), True)


def test_no_phantom_manifest_keys():
    print("\n[BACKWARD: a manifest key with no install action is a false assurance]")
    keys = manifest_keys()
    covered = {k for (k, _p) in ACTIONS.values()}
    check("every manifest key maps to a known install action",
          sorted(keys - covered), [])


def test_start_menu_is_removed_FROM_THE_MANIFEST_not_a_second_constant():
    print("\n[the Start Menu path must have ONE definition, not two that can drift]")
    # BEHAVIOURAL, not a source grep: give it a manifest whose path differs from the
    # module constant and confirm the manifest value is what gets targeted. The earlier
    # `"start_menu" in UNINSTALLER_SRC` form passed against code that ignored the
    # manifest, because the word appears in a comment.
    import uninstaller_gui as UN
    custom = {"components": {"start_menu": {"path": r"D:\Custom\Menu\Nemesis"}}}
    check("uninstaller targets the MANIFEST path, not its own constant",
          UN._start_menu_path(custom), r"D:\Custom\Menu\Nemesis")
    check("falls back to the constant when the manifest predates start_menu",
          UN._start_menu_path({"components": {}}), UN.START_MENU)
    check("manifest records a start_menu path",
          bool((I._build_manifest("C:\\x", False, True).get("components") or {})
               .get("start_menu", {}).get("path")), True)


if __name__ == "__main__":
    print("=" * 78)
    print("R2 — manifest coverage: every install action must be recorded")
    print("=" * 78)
    test_detector_can_tell_present_from_absent()
    test_every_install_action_has_a_manifest_key()
    test_no_phantom_manifest_keys()
    test_start_menu_is_removed_FROM_THE_MANIFEST_not_a_second_constant()
    print()
    if _count != EXPECTED_CHECKS:
        print("SUITE DRIFT: ran %d checks, expected %d" % (_count, EXPECTED_CHECKS))
        sys.exit(1)
    if _fail:
        print("FAILED (%d of %d)" % (len(_fail), _count))
        for f in _fail:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS (%d checks)" % _count)
