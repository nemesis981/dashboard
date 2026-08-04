#!/usr/bin/env python3
"""Tests for parse_alert()'s field extraction, especially rule_name.

Filed 2026-08-04 as FIX-NOW: parse_alert() split a Suricata fast.log line on
"[**]" and took parts[2] as the rule name. parts[2] is the
Classification/Priority block; the rule name is in parts[1], after the
"[gid:sid:rev]" prefix. Every alerts row and every alert email carried
classification text under "Rule:", and the actual rule name was discarded.

Why it stayed invisible, and why these tests assert on VALUES rather than
merely on truthiness: the wrong value was plausible text of about the right
length, truncated to 50 chars on insert. Nothing errored, nothing was empty,
and `classification` was correct in its own column — so a reader saw a
populated field with no reason to doubt it. A test that only checked
`rule_name` was non-empty would have passed against the bug.

Run: python3 alert_manager/test_parse_alert.py
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from firewall import parse_alert  # noqa: E402

FAILURES = []
CHECKS = [0]


def check(name, got, want):
    CHECKS[0] += 1
    if got == want:
        print(f"  [PASS] {name}")
    else:
        print(f"  [FAIL] {name}\n         got : {got!r}\n         want: {want!r}")
        FAILURES.append(name)


def check_true(name, cond, detail=""):
    CHECKS[0] += 1
    if cond:
        print(f"  [PASS] {name}")
    else:
        print(f"  [FAIL] {name} {detail}")
        FAILURES.append(name)


# The line from the bug report, verbatim.
REAL = ("02/01/2026-10:15:32.123456  [**] [1:2001219:20] ET SCAN Potential SSH Scan "
        "[**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} "
        "192.168.1.5:54321 -> 203.0.113.10:22")


def test_rule_name_is_the_rule_not_the_classification():
    p = parse_alert(REAL)
    check("rule_name is the rule message", p["rule_name"], "ET SCAN Potential SSH Scan")
    # The regression itself: the old code produced the Classification block.
    check_true("rule_name is NOT the classification block",
               "Classification" not in p["rule_name"] and "Priority" not in p["rule_name"],
               f"-> {p['rule_name']!r}")
    check_true("rule_name carries no leading [gid:sid:rev]",
               not p["rule_name"].startswith("["), f"-> {p['rule_name']!r}")


def test_other_fields_unaffected():
    """The fix touches one branch; everything else must be untouched."""
    p = parse_alert(REAL)
    check("rule_id", p["rule_id"], "2001219")
    check("classification", p["classification"], "Attempted Information Leak")
    check("priority", p["priority"], 2)
    check("src_ip", p["src_ip"], "192.168.1.5")
    check("dst_ip", p["dst_ip"], "203.0.113.10")
    check("protocol", p["protocol"], "TCP")
    check("timestamp", p["timestamp"], "10:15:32")


def test_rule_name_and_classification_are_distinct():
    """The email prints both. Before the fix they were effectively the same
    text, so the 'Rule:' line carried no information."""
    p = parse_alert(REAL)
    check_true("rule_name != classification",
               p["rule_name"] != p["classification"],
               f"-> both {p['rule_name']!r}")


def test_message_containing_brackets_is_preserved():
    """Only the FIRST bracket group (the sid block) is stripped — a rule
    message may legitimately contain brackets and they belong to the name."""
    line = ("02/01/2026-10:15:32.123456  [**] [1:2010935:3] ET POLICY [Suspicious] "
            "curl UA [**] [Classification: Misc activity] [Priority: 3] {TCP} "
            "10.0.0.1:1 -> 10.0.0.2:2")
    p = parse_alert(line)
    check("bracketed message preserved", p["rule_name"], "ET POLICY [Suspicious] curl UA")


def test_priority_one_and_three():
    p1 = parse_alert(REAL.replace("Priority: 2", "Priority: 1"))
    check("priority 1", p1["priority"], 1)
    p3 = parse_alert(REAL.replace("[Priority: 2] ", ""))
    check("priority defaults to 3 when absent", p3["priority"], 3)


def test_malformed_lines_do_not_raise():
    for label, line in (
        ("empty", ""),
        ("no markers", "just some text"),
        ("marker only", "[**]"),
        ("sid block but no message", "ts [**] [1:1:1] [**] [Classification: x]"),
    ):
        try:
            p = parse_alert(line)
            check_true(f"malformed ({label}) returns dict or None",
                       p is None or isinstance(p, dict))
        except Exception as exc:      # noqa: BLE001
            check_true(f"malformed ({label}) does not raise", False, f"raised {exc!r}")


def main():
    print("parse_alert() — rule_name extraction\n")
    for fn in (test_rule_name_is_the_rule_not_the_classification,
               test_other_fields_unaffected,
               test_rule_name_and_classification_are_distinct,
               test_message_containing_brackets_is_preserved,
               test_priority_one_and_three,
               test_malformed_lines_do_not_raise):
        print(f"{fn.__name__}:")
        fn()
        print()
    total = CHECKS[0]
    print("=" * 60)
    if FAILURES:
        print(f"{total - len(FAILURES)}/{total} checks passed — FAILED: {', '.join(FAILURES)}")
        return 1
    print(f"{total}/{total} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
