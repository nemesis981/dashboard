#!/usr/bin/env python3
"""The one "is this address safe to send to a third party" predicate.

Run: python3 alert_manager/test_ip_scope.py

WHY THIS EXISTS. `enrich_ip()` gated its external lookups (AbuseIPDB, ipinfo) on
`is_private or is_loopback or is_link_local`. Python reports **is_private=False for
CGNAT 100.64.0.0/10** -- the Tailscale range -- so a tailnet peer address sailed
past a guard whose own docstring called it "public-only" and was transmitted to two
external services. Same predicate, same gap, in three places.

⚠ AND `is_global` ALONE IS NOT THE FIX. Python 3.14 reports is_global=True for
MULTICAST (224.0.0.1, 239.1.1.1 -- asserted below). One of the three call sites
already excluded multicast and reserved; a naive is_global swap would have
REGRESSED it into reporting multicast addresses to AbuseIPDB. The predicate here is
globally-routable UNICAST, promoted from core/forkb_policy_route._is_public_probe()
-- which already had this right, with the CGNAT trap written up, after being caught
by test_forkb_resolution_topology.py.

The known-good half of the canary set is load-bearing in its own right: this repo
tests with 192.88.99.x as "reads as public but routes nowhere" (the TEST_IP_PUBLIC
convention). If this predicate refused it, a dozen suites would start passing for
the wrong reason.
"""
import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ip_scope                                   # noqa: E402

_fail = []
_count = 0
EXPECTED_CHECKS = 47

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-70s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def main():
    print("\n[THE BUG: CGNAT is not private, and that is the whole point]")
    check("CONTROL stdlib really does call CGNAT non-private (the trap)",
          ipaddress.ip_address("100.64.1.1").is_private, False)
    check("100.64.1.1 (tailnet) is NOT public", ip_scope.is_public_ip("100.64.1.1"), False)
    check("100.101.102.103 (tailnet) is NOT public",
          ip_scope.is_public_ip("100.101.102.103"), False)
    check("the CGNAT edges are covered -- 100.64.0.0",
          ip_scope.is_public_ip("100.64.0.0"), False)
    check("...and 100.127.255.255", ip_scope.is_public_ip("100.127.255.255"), False)
    check("CONTROL just outside CGNAT is still public -- 100.63.255.255",
          ip_scope.is_public_ip("100.63.255.255"), True)
    check("CONTROL ...and 100.128.0.0", ip_scope.is_public_ip("100.128.0.0"), True)

    print("\n[⚠ is_global ALONE would regress the multicast/reserved site]")
    check("CONTROL stdlib calls multicast is_global (why the extra exclusions exist)",
          ipaddress.ip_address("224.0.0.1").is_global, True)
    check("...and admin-scoped multicast too",
          ipaddress.ip_address("239.1.1.1").is_global, True)
    check("224.0.0.1 is NOT public here", ip_scope.is_public_ip("224.0.0.1"), False)
    check("239.1.1.1 is NOT public here", ip_scope.is_public_ip("239.1.1.1"), False)

    print("\n[the repo's TEST_IP_PUBLIC convention must survive]")
    check("192.88.99.7 reads as public (test_quarantine convention)",
          ip_scope.is_public_ip("192.88.99.7"), True)
    check("192.88.99.1 likewise", ip_scope.is_public_ip("192.88.99.1"), True)

    print("\n[genuinely routable addresses still pass -- this is not a blanket refusal]")
    for a in ("8.8.8.8", "1.1.1.1", "93.184.216.34"):
        check("%s is public" % a, ip_scope.is_public_ip(a), True)
    check("2001:4860:4860::8888 (public v6) is public",
          ip_scope.is_public_ip("2001:4860:4860::8888"), True)

    print("\n[everything that must never reach an external service]")
    for a, why in (("10.0.0.1", "RFC1918"), ("192.168.1.5", "RFC1918"),
                   ("172.16.0.1", "RFC1918"), ("127.0.0.1", "loopback"),
                   ("169.254.1.1", "link-local"), ("0.0.0.0", "unspecified"),
                   ("255.255.255.255", "broadcast"), ("240.0.0.1", "reserved"),
                   ("192.0.2.5", "RFC5737 doc"), ("198.51.100.7", "RFC5737 doc"),
                   ("203.0.113.9", "RFC5737 doc"), ("198.18.0.1", "benchmark")):
        check("%s (%s) refused" % (a, why), ip_scope.is_public_ip(a), False)
    check("fd7a:115c:a1e0::53 (tailnet v6 ULA) refused",
          ip_scope.is_public_ip("fd7a:115c:a1e0::53"), False)
    check("fe80::1 (v6 link-local) refused", ip_scope.is_public_ip("fe80::1"), False)
    check("::1 (v6 loopback) refused", ip_scope.is_public_ip("::1"), False)

    print("\n[garbage in -- refuse, never raise into a caller's request path]")
    check("a hostname is not an address", ip_scope.is_public_ip("example.com"), False)
    check("empty string", ip_scope.is_public_ip(""), False)
    check("None", ip_scope.is_public_ip(None), False)
    check("a number", ip_scope.is_public_ip(12345), False)
    check("surrounding whitespace is tolerated",
          ip_scope.is_public_ip("  8.8.8.8  "), True)

    print("\n[the predicate proves its own premise, and fails CLOSED]")
    ok, detail = ip_scope.selftest()
    check("selftest passes against the running stdlib", ok, True)
    check("...and says so", detail, "")
    check("CONTROL the module trusted itself at import", ip_scope._TRUSTED, True)
    saved = ip_scope._TRUSTED
    try:
        ip_scope._TRUSTED = False
        check("THE PROPERTY: an untrusted classifier refuses a PUBLIC address",
              ip_scope.is_public_ip("8.8.8.8"), False)
        check("...and still refuses a private one", ip_scope.is_public_ip("10.0.0.1"), False)
    finally:
        ip_scope._TRUSTED = saved
    check("CONTROL trust restored", ip_scope.is_public_ip("8.8.8.8"), True)

    print("\n[the call sites delegate -- no second copy left behind]")
    enr = open(os.path.join(REPO, "alert_manager", "ip_enrichment.py")).read()
    anom = open(os.path.join(REPO, "modules", "anomaly_detection", "module.py")).read()
    check("ip_enrichment delegates to the shared predicate",
          "ip_scope.is_public_ip" in enr or "is_public_ip(" in enr, True)
    check("THE PROPERTY: ip_enrichment has no is_private-based gate left",
          "is_private or ip_obj.is_loopback" in enr
          or "obj.is_private or obj.is_loopback" in enr, False)
    check("anomaly_detection delegates to the shared predicate",
          "is_public_ip(" in anom, True)
    check("THE PROPERTY: anomaly_detection has no is_private-based gate left",
          "obj.is_private or obj.is_loopback" in anom, False)

    passed = _count - len(_fail)
    print("\n%d/%d checks passed" % (passed, _count))
    if _fail:
        print("FAILED:")
        for f in _fail:
            print("  - " + f)
    if _count != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d -- a check was skipped, "
              "not merely failed" % (_count, EXPECTED_CHECKS))
        return 2
    return 1 if _fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
