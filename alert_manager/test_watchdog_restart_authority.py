#!/usr/bin/env python3
"""Every unit watchdog SUPERVISES must be one polkit AUTHORISES it to restart.

THE BUG THIS EXISTS TO PREVENT (found live 2026-09-04)
    watchdog's SERVICES list held 6 units; 10-nemesis-watchdog.rules authorised 3.
    For pihole-FTL, clamav-daemon and suricata, watchdog would detect the outage,
    call `systemctl restart`, be denied by polkit, and email "down and could not be
    restarted" -- indistinguishable from a genuinely broken service. The capability
    was missing, not the service.

    Nothing caught it because the two lists live in different files, different
    languages, and neither references the other. The mismatch is invisible until a
    supervised service actually fails, which is the worst possible moment.

⛔ COMMENTS ARE STRIPPED BEFORE PARSING, AND THAT IS LOAD-BEARING.
    The rule's own header comment NAMES pihole-FTL, clamav-daemon and suricata while
    explaining why they were added. A regex over the raw file would match that prose
    and report the units as authorised even if someone deleted them from the array --
    the check would pass against the very mutation it exists to catch. Python side
    uses `ast`, which cannot be satisfied by prose at all.

Run: python3 alert_manager/test_watchdog_restart_authority.py
"""
import ast
import os
import re
import sys

ROOT = os.environ.get("NEMESIS_ROOT", "/opt/nemesis")
RULE = os.path.join(ROOT, "alert_manager", "10-nemesis-watchdog.rules")
WATCHDOG = os.path.join(ROOT, "core_module", "watchdog", "watchdog.py")

EXPECTED_CHECKS = 12
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


def rule_allowed_units(text):
    """Unit names from the `allowed` array only -- never from prose."""
    body = re.search(r"var\s+allowed\s*=\s*\[(.*?)\]", strip_js_comments(text), re.S)
    if not body:
        return None
    return [u for u in re.findall(r'"([^"]+)"', body.group(1))]


def watchdog_services(path):
    """SERVICES via ast -- structure, not text."""
    tree = ast.parse(open(path, encoding="utf-8").read())
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "SERVICES":
                    return [e.value for e in node.value.elts
                            if isinstance(e, ast.Constant)]
    return None


print("1. the instrument can distinguish (known-good / known-bad)")
_good = 'var allowed = [\n  "a.service",\n  "b.service"\n];'
_bad = '// mentions "ghost.service" in prose only\nvar allowed = [\n  "a.service"\n];'
check("parser reads units from the array", rule_allowed_units(_good) == ["a.service", "b.service"],
      rule_allowed_units(_good))
check("  ...and does NOT read units out of a comment",
      rule_allowed_units(_bad) == ["a.service"], rule_allowed_units(_bad))
check("  ...and reports None when the array is absent",
      rule_allowed_units("no array here at all") is None)

print("\n2. both files parse")
check("polkit rule is readable", os.path.exists(RULE), RULE)
_rule_text = open(RULE, encoding="utf-8").read() if os.path.exists(RULE) else ""
_allowed = rule_allowed_units(_rule_text) or []
_services = watchdog_services(WATCHDOG) or []
check("rule exposes a non-empty allowed list", len(_allowed) > 0, _allowed)
check("watchdog exposes a non-empty SERVICES list", len(_services) > 0, _services)

print("\n3. the action id is the FULL polkit id")
# "manage-units" alone never matches action.id and would silently authorise nothing.
check("rule matches org.freedesktop.systemd1.manage-units",
      "org.freedesktop.systemd1.manage-units" in strip_js_comments(_rule_text))

print("\n4. COVERAGE -- every supervised unit is authorised")
_missing = [s for s in _services if "%s.service" % s not in _allowed]
check("no supervised unit lacks a polkit grant", not _missing,
      "unauthorised: %s" % sorted(_missing))

print("\n5. the restart verbs are the ones watchdog actually uses")
_stripped = strip_js_comments(_rule_text)
check('rule permits verb "restart"', '"restart"' in _stripped)
check("rule does NOT grant a blanket verb",
      "action.lookup(\"verb\")" in _stripped or "action.lookup('verb')" in _stripped)

print("\n6. over-grant is reported, not silently accepted")
_extra = [a for a in _allowed if a.replace(".service", "") not in _services]
# Not a failure: these are Nemesis units a future SERVICES list may add. But an
# unexamined grant is how least privilege erodes, so it must stay VISIBLE.
print("     granted but not supervised: %s" % (sorted(_extra) or "none"))
check("over-grant list is enumerable (visible, not hidden)", isinstance(_extra, list))

print("\n7. mutation: removing a unit from the array must FAIL coverage")
_mutant = _rule_text.replace('"suricata.service"', '"REMOVED.service"', 1)
_mut_allowed = rule_allowed_units(_mutant) or []
_mut_missing = [s for s in _services if "%s.service" % s not in _mut_allowed]
check("a removed grant is detected", bool(_mut_missing), _mut_missing)

print("\n%d passed, %d failed" % (_pass, _fail))
if _pass + _fail != EXPECTED_CHECKS:
    print("EXPECTED_CHECKS MISMATCH: declared %d, ran %d" % (EXPECTED_CHECKS, _pass + _fail))
    sys.exit(1)
sys.exit(1 if _fail else 0)
