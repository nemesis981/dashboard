#!/usr/bin/env python3
"""Hostname matching must survive Windows' 15-character DHCP truncation.

Run: python3 alert_manager/test_hostname_truncation_safety.py  (exit 0 = all pass)

THE OBSERVATION (gateway test zone, 2026-08-06, with a control)
    A Windows client sent `Nemesis-SW-CLEA` -- exactly 15 characters, the NetBIOS
    limit, visibly cut mid-word. CONTROL: a Linux client on the SAME segment, the
    same DHCP server and the same lease file sent a 20-character name intact. So
    the truncation is Windows sending a short name in DHCP option 12, not the
    server, the lease file or the wire format.

⛔ WHY THIS IS A GUARD AND NOT A FIX.
    Nothing is broken today: hostname is matched in exactly ONE place, by
    SUBSTRING, against hints of 4-6 characters, all of which survive the cut. The
    PUNCHLIST entry is explicit that the full name is NOT recoverable and that the
    exact semantics are NOT yet verified -- only one Windows client has ever been
    observed, and whether this is a fixed 15-char cap or that host's real NetBIOS
    name simply being short is unknown. So building a prefix-matcher now would be
    building on unverified semantics, which is precisely what that entry says not
    to do.

    What CAN be done without depending on those semantics is make the future
    failure loud. The hazard is entirely in what gets added next: a longer hint,
    an equality comparison, or a join on hostname would silently fail FOR WINDOWS
    DEVICES ONLY while every other platform matched -- reading as "this feature is
    flaky" rather than "Windows names are cut at 15". These checks fail the day
    someone introduces that, instead of the bug surfacing months later as a
    platform correlation nobody spots from one failing case.
"""
import ast
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import nemesis_device_category as cat  # noqa: E402

#: The measured cut. Named once so a future correction has one place to land.
NETBIOS_LIMIT = 15

EXPECTED_CHECKS = 8
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def main():
    print("1. every hostname hint survives a 15-character cut")
    for hint in cat._IOS_HOSTNAME_HINTS:
        check("  %-8s is <= %d chars" % (repr(hint), NETBIOS_LIMIT),
              len(hint) <= NETBIOS_LIMIT, True)

    print("\n2. hostname is matched by SUBSTRING, never by equality")
    # Structural, via AST: a text search would match the comment that explains
    # this very rule, which is the trap this repo keeps logging. `==` against the
    # hostname variable is the shape that breaks silently on Windows.
    src = open(os.path.join(HERE, "nemesis_device_category.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    eq_on_hostname = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and any(
                isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
            if "hostname" in names:
                eq_on_hostname.append(node.lineno)
    check("no ==/!= comparison involving `hostname`", eq_on_hostname, [])

    print("\n3. a truncated Windows hostname still classifies correctly")
    # The real observed value, cut at exactly the limit.
    truncated = "Nemesis-SW-CLEA"
    check("  the fixture really is at the limit", len(truncated), NETBIOS_LIMIT)
    # An iOS hint embedded in a name that a cut would NOT reach still matches...
    got, _ = cat.classify({"hostname": "iphone-of-someone"})
    check("  'iphone-...' classifies as iOS", got, cat.IOS)
    # ...and the same name after truncation still matches, because the hint sits
    # inside the surviving prefix. This is the property the hints depend on.
    got2, _ = cat.classify({"hostname": "iphone-of-someone"[:NETBIOS_LIMIT]})
    check("  ...and still does after a 15-char cut", got2, cat.IOS)

    print("\n4. CONTROL: a hint that could NOT survive would be caught")
    # Proves check 1 can fail. Without this it passes for any list of short
    # strings, including an empty one, and proves nothing about the rule.
    too_long = "iphone-generation"        # 17 chars
    check("a >15-char hint is detected as unsafe",
          len(too_long) <= NETBIOS_LIMIT, False)

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [l for l, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
