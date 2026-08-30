"""Gateway Mode step 1 -- forwarding persistence. Pure tests, no root, no sysctl.

The load-bearing cases are the two HALF-STATES. Forwarding that is live but not
persisted works until the box reboots; forwarding that is persisted but not applied
never works at all while every config check passes. Both are silent, they have
completely different fixes, and a verifier that accepts either half is the shape of a
check that looks like coverage and is not.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gateway_mode as G

_fail = []
_count = 0
EXPECTED_CHECKS = 38


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-66s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def test_ordering_refusal():
    print("\n[enabling forwarding before the FORWARD gate exists must be REFUSED]")
    a, steps, reason = G.plan_enable(False)
    check("refused", a, G.REFUSE)
    check("no steps planned", steps, [])
    check("reason names the hazard", "open forwarding path" in reason, True)
    # CONTROL: the same call with the gate ready proceeds -- so the refusal is
    # attributable to the gate flag and not to the planner being broken.
    check("CONTROL: with the gate ready it proceeds", G.plan_enable(True)[0], G.ENABLE)


def test_step_order():
    print("\n[step order is load-bearing in both directions]")
    _, steps, _ = G.plan_enable(True)
    check("enable WRITES before applying", steps[0][0], "write")
    check("...then applies", steps[1][1][0], "sysctl")
    check("...to the documented path", steps[0][1], G.SYSCTL_DROPIN)

    _, steps, _ = G.plan_disable()
    # Applying before removal would re-assert 1 from the file about to be deleted,
    # leaving live=1 with no persistence -- the worst of both states.
    check("disable REMOVES before applying", steps[0][0], "remove")
    check("...then applies", steps[1][1][0], "sysctl")
    check("...then forces the live value to 0", steps[2][1][-1], "net.ipv4.ip_forward=0")


def test_dropin_parsing_is_comment_aware():
    print("\n[the drop-in mentions the key in its OWN comment -- substring tests lie]")
    check("the shipped drop-in reads as enabled",
          G.dropin_says_enabled(G.DROPIN_CONTENT), True)
    check("a fully commented-out assignment is NOT enabled",
          G.dropin_says_enabled("# net.ipv4.ip_forward = 1"), False)
    check("an explicit 0 is not enabled",
          G.dropin_says_enabled("net.ipv4.ip_forward = 0"), False)
    check("a trailing comment does not defeat parsing",
          G.dropin_says_enabled("net.ipv4.ip_forward = 1  # on"), True)
    check("whitespace variations parse",
          G.dropin_says_enabled("  net.ipv4.ip_forward=1  "), True)
    check("a DIFFERENT key set to 1 is not our key",
          G.dropin_says_enabled("net.ipv6.conf.all.forwarding = 1"), False)
    check("empty -> not enabled", G.dropin_says_enabled(""), False)
    check("None -> not enabled", G.dropin_says_enabled(None), False)


def test_live_value_parsing():
    print("\n[an unreadable live value must not read as 'off']")
    check("bare value", G.parse_live_forwarding("1"), 1)
    check("sysctl -n style with whitespace", G.parse_live_forwarding("  0\n"), 0)
    check("key = value form", G.parse_live_forwarding("net.ipv4.ip_forward = 1"), 1)
    check("unreadable -> None, NOT 0", G.parse_live_forwarding("permission denied"), None)
    check("empty -> None", G.parse_live_forwarding(""), None)
    check("None -> None", G.parse_live_forwarding(None), None)


def test_both_halves_required():
    print("\n[THE point: both halves must hold, and the report says WHICH failed]")
    ok, d = G.verify_forwarding(G.DROPIN_CONTENT, "1", True)
    check("persisted + live -> ok", ok, True)

    ok, d = G.verify_forwarding("", "1", True)
    check("live but NOT persisted -> not ok", ok, False)
    check("...and says it reverts on reboot", "reverts on reboot" in d, True)

    ok, d = G.verify_forwarding(G.DROPIN_CONTENT, "0", True)
    check("persisted but NOT applied -> not ok", ok, False)
    check("...and says sysctl --system was not run", "never applied" in d, True)

    check("neither -> not ok", G.verify_forwarding("", "0", True)[0], False)
    # ⚠ ASSERT THE REASON, NOT JUST THE VERDICT. An unreadable live value and a
    # written-but-unapplied drop-in BOTH return ok=False, so a boolean-only test
    # cannot distinguish them -- and it did not: a mutation disabling the
    # unreadable-value guard passed this suite until this check was added. The two
    # states send the operator to completely different fixes.
    ok, d = G.verify_forwarding(G.DROPIN_CONTENT, None, True)
    check("unreadable live value -> not ok (never assume)", ok, False)
    check("...and is reported AS unreadable", "could not read" in d, True)
    check("...NOT misreported as 'never applied'", "never applied" in d, False)

    print("\n  [and the disabled direction is checked too, not assumed]")
    check("cleanly disabled -> ok", G.verify_forwarding("", "0", False)[0], True)
    check("stale drop-in left behind -> not ok",
          G.verify_forwarding(G.DROPIN_CONTENT, "0", False)[0], False)
    check("still live when it should be off -> not ok",
          G.verify_forwarding("", "1", False)[0], False)


def test_selftest():
    print("\n[the instrument proves it produces every answer it claims]")
    ok, detail = G.selftest()
    check("selftest passes", ok, True)
    check("counts its canaries", "canaries passed" in detail, True)


if __name__ == "__main__":
    print("Gateway Mode step 1 -- forwarding persistence")
    test_ordering_refusal()
    test_step_order()
    test_dropin_parsing_is_comment_aware()
    test_live_value_parsing()
    test_both_halves_required()
    test_selftest()
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
