"""Drift detection for netfilter mode + tailnet anti-spoof. Pure tests, no root.

The load-bearing cases are the ones a naive check would pass: an anti-spoof rule that
is PRESENT but sits below the conntrack accept (and is therefore useless), and an
unreadable input treated as healthy. Both failures are silent in production, and both
are what this file exists to keep caught.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netfilter_drift as D

_fail = []
_count = 0
EXPECTED_CHECKS = 39


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-66s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def test_netfilter_mode():
    print("\n[netfilter mode: nodivert is the only healthy answer]")
    check("nodivert (1) -> ok", D.check_netfilter_mode('{"NetfilterMode": 1}')[0], D.OK)
    check("on (2) -> DRIFTED", D.check_netfilter_mode('{"NetfilterMode": 2}')[0], D.DRIFTED)
    check("off (0) -> DRIFTED", D.check_netfilter_mode('{"NetfilterMode": 0}')[0], D.DRIFTED)
    s, d = D.check_netfilter_mode('{"NetfilterMode": 2}')
    check("...and explains the consequence", "unreachable" in d, True)


def test_mode_fails_closed():
    print("\n[an unread value must never round down to healthy]")
    for label, txt in (("empty", ""), ("None", None), ("not json", "not json"),
                       ("json without the key", '{"Other": 1}'),
                       ("key of wrong type", '{"NetfilterMode": "1"}'),
                       ("a bare list", "[]")):
        check("%-22s -> UNDETERMINED" % label, D.check_netfilter_mode(txt)[0], D.UNDETERMINED)
    check("parse returns None, not a default", D.parse_netfilter_mode(""), None)


def test_antispoof_presence():
    print("\n[the anti-spoof DROP: presence]")
    check("correct ruleset -> ok", D.check_antispoof(D._GOOD_RULES)[0], D.OK)
    check("rule missing -> DRIFTED", D.check_antispoof(D._BAD_MISSING)[0], D.DRIFTED)
    s, d = D.check_antispoof(D._BAD_MISSING)
    check("...and names what depends on it", "ADR 0011" in d, True)
    only_comment = "-A ufw-before-input -i lo -j ACCEPT\n# NEMESIS-TAILNET-ANTISPOOF\n"
    s, d = D.check_antispoof(only_comment)
    check("comment survives but rule gone -> DRIFTED", s, D.DRIFTED)
    check("...and says only the explanation survived", "only the explanation" in d, True)


def test_antispoof_position():
    print("\n[POSITION is part of the property -- presence alone is not enough]")
    s, d = D.check_antispoof(D._BAD_BELOW)
    check("rule BELOW the conntrack accept -> DRIFTED", s, D.DRIFTED)
    check("...and explains why that is useless", "existing flow" in d, True)
    # CONTROL: the identical rule ABOVE the accept is healthy, so the verdict is
    # attributable to POSITION and not to some other difference in the fixture.
    check("CONTROL: same rule above the accept -> ok",
          D.check_antispoof(D._GOOD_RULES)[0], D.OK)
    no_ct = "-A ufw-before-input -s 100.64.0.0/10 ! -i tailscale0 -j DROP\n"
    check("no conntrack accept present at all -> ok (nothing to sit below)",
          D.check_antispoof(no_ct)[0], D.OK)


def test_antispoof_tolerances():
    print("\n[tolerant where install.sh is, strict where it matters]")
    renamed = D._GOOD_RULES.replace("tailscale0", "ts9")
    check("a renamed tunnel device still matches (install.sh name-matches too)",
          D.check_antispoof(renamed)[0], D.OK)
    spaced = D._GOOD_RULES.replace("-s 100.64.0.0/10", "-s  100.64.0.0/10")
    check("extra whitespace tolerated", D.check_antispoof(spaced)[0], D.OK)
    wrong_net = D._GOOD_RULES.replace("100.64.0.0/10", "10.0.0.0/8")
    check("a DIFFERENT source network does NOT count as the guard",
          D.check_antispoof(wrong_net)[0], D.DRIFTED)
    accept = D._GOOD_RULES.replace("-j DROP", "-j ACCEPT")
    check("the rule turned into an ACCEPT does not count",
          D.check_antispoof(accept)[0], D.DRIFTED)


def test_antispoof_fails_closed():
    print("\n[an unread rules file is not a healthy rules file]")
    check("empty -> UNDETERMINED", D.check_antispoof("")[0], D.UNDETERMINED)
    check("None -> UNDETERMINED", D.check_antispoof(None)[0], D.UNDETERMINED)
    check("whitespace only -> UNDETERMINED", D.check_antispoof("   \n ")[0], D.UNDETERMINED)


def test_overall_never_rounds_down():
    print("\n[worst-of: an unknown never becomes healthy, a failure never hides]")
    check("drifted beats ok", D.overall([D.OK, D.DRIFTED]), D.DRIFTED)
    check("undetermined beats ok", D.overall([D.OK, D.UNDETERMINED]), D.UNDETERMINED)
    check("drifted beats undetermined",
          D.overall([D.UNDETERMINED, D.DRIFTED]), D.DRIFTED)
    check("all ok -> ok", D.overall([D.OK, D.OK]), D.OK)


def test_no_systemctl_proxy():
    print("\n[the snap false-negative: no is-active proxy anywhere in this module]")
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "netfilter_drift.py")).read()
    check("module never calls systemctl", "systemctl" in src.split('"""', 2)[2], False)
    check("...and says why, in the docstring", "not-found" in src, True)


def test_unread_reason_is_reported():
    print("\n[an unreadable prefs read must name its REAL cause, not blame the daemon]")
    st, detail = D.check_netfilter_mode("", "no tailscaled socket found (tried: /a, /b)")
    check("still undetermined", st, D.UNDETERMINED)
    check("the caller's reason reaches the detail", "no tailscaled socket found" in detail, True)
    # The 2026-08-31 regression in one assertion: the old text asserted a daemon fault
    # for every failure, including a missing CLI binary. It must no longer do that
    # unless the caller actually said so.
    check("does NOT invent a daemon fault", "did not answer" in detail, False)
    check("an absent reason is admitted, not guessed",
          "cause not recorded" in D.check_netfilter_mode("")[1], True)


def test_selftest():
    print("\n[known-good AND known-bad, in the production path]")
    ok, detail = D.selftest()
    check("selftest passes", ok, True)
    check("counts its canaries", "canaries passed" in detail, True)


if __name__ == "__main__":
    print("netfilter / anti-spoof drift detection")
    test_netfilter_mode()
    test_mode_fails_closed()
    test_antispoof_presence()
    test_antispoof_position()
    test_antispoof_tolerances()
    test_antispoof_fails_closed()
    test_overall_never_rounds_down()
    test_no_systemctl_proxy()
    test_unread_reason_is_reported()
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
