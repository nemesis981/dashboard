"""Connectivity verdict must be VPN-aware. Pure core: no DB, no network, no curl.

WHY THIS EXISTS (measured on production, 2026-08-30). A leak-blocking VPN disables
IPv6 egress and blocks the raw-egress probe BY DESIGN. `classify()` did not take the
VPN into account, so for as long as the tunnel was up it returned DEGRADED on every
cycle — and one blocked raw-egress sample escalated a whole episode to LOCAL_FAIL —
while `routing_ok`, `dns_ok` and `api_ok` were all 1 on every single sample. That
raised a MEDIUM `action=investigate` alert pair for a correctly functioning VPN, which
is why PIA was switched off and left off.

This is the SAME failure shape the 2026-08-22 IPv4-only-link fix closed, on a fourth
input. `ipv6_expectation()` structurally cannot cover it: it measures whether a global
IPv6 ADDRESS exists, and the address stays on the interface while the tunnel blocks the
traffic.

THE NEGATIVES ARE THE LOAD-BEARING HALF. A fix that simply stopped reporting IPv6
failures would pass a naive "VPN up -> ALL_OK" test while destroying the check. So every
permissive case below is paired with a case proving the same input STILL reports a fault
when the VPN is down, and that a genuine local fault still reports LOCAL_FAIL even while
tunnelled.

TOTAL IS ASSERTED, so a run with less coverage reports as a failure rather than as a
smaller suite.
"""
import os
import sys

# Repo root derived from __file__, never from the cwd: running from the repo root
# silently rescues imports that would fail inside the service, so a cwd-dependent
# test can pass while the thing it tests is broken.
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from modules.diagnostics import watcher as w

_fail = []
_count = 0

EXPECTED_CHECKS = 36


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-70s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def flags(routing=1, dns=1, egress=1, api=1):
    return {"routing_ok": bool(routing), "dns_ok": bool(dns),
            "egress_ok": bool(egress), "api_ok": bool(api)}


# ── 1. VPN UP: the exact production state must NOT report a fault ────────────
def test_vpn_up_ipv6_blocked_is_not_a_fault():
    """Samples 85189/85190/85191/85193 as recorded live: everything green but v6."""
    f = flags()
    check("vpn up, ipv6 blocked -> ALL_OK (not DEGRADED)",
          w.classify(f, True, False, w.IPV6_EXPECTED, True), "ALL_OK")
    check("vpn up, ipv6 blocked -> note names the vpn",
          w._note(f, True, False, w.IPV6_EXPECTED, True), w._NOTE_IPV6_VPN_BLOCKED)
    check("vpn up, ipv6 blocked -> note is NOT the fault vocabulary",
          w._note(f, True, False, w.IPV6_EXPECTED, True) == w._NOTE_IPV6_FAIL, False)
    # The condition is reported, never silently swallowed.
    check("vpn up, ipv6 blocked -> note is non-empty (visible, not hidden)",
          bool(w._note(f, True, False, w.IPV6_EXPECTED, True)), True)


# ── 2. VPN DOWN: the identical input MUST still report the fault ─────────────
def test_vpn_down_ipv6_fault_still_fires():
    """Same flags, same v6 failure, VPN off -> unchanged strict behaviour."""
    f = flags()
    check("vpn DOWN, ipv6 provisioned+failing -> DEGRADED",
          w.classify(f, True, False, w.IPV6_EXPECTED, False), "DEGRADED")
    check("vpn DOWN, ipv6 provisioned+failing -> real-fault note",
          w._note(f, True, False, w.IPV6_EXPECTED, False), w._NOTE_IPV6_FAIL)
    # Default argument must be the STRICT answer, not the permissive one.
    check("vpn arg omitted -> strict verdict (old behaviour preserved)",
          w.classify(f, True, False, w.IPV6_EXPECTED), "DEGRADED")
    check("vpn arg omitted -> strict note",
          w._note(f, True, False, w.IPV6_EXPECTED), w._NOTE_IPV6_FAIL)


# ── 3. THE PARAMETER MUST ACTUALLY CHANGE THE OUTCOME ────────────────────────
def test_vpn_flag_is_load_bearing():
    """A fix that ignored the new flag would pass every single-value test above."""
    f = flags()
    up = w.classify(f, True, False, w.IPV6_EXPECTED, True)
    down = w.classify(f, True, False, w.IPV6_EXPECTED, False)
    check("verdict DIFFERS on vpn flag alone (identical other inputs)", up != down, True)
    n_up = w._note(f, True, False, w.IPV6_EXPECTED, True)
    n_down = w._note(f, True, False, w.IPV6_EXPECTED, False)
    check("note DIFFERS on vpn flag alone", n_up != n_down, True)


# ── 4. raw-egress: degrade while tunnelled, never escalate to LOCAL_FAIL ─────
def test_egress_blocked_degrades_not_escalates():
    """Sample 85192 as recorded live: egress_ok=0, routing/dns/api all 1."""
    f = flags(egress=0)
    check("vpn up, egress-only blocked -> DEGRADED (not LOCAL_FAIL)",
          w.classify(f, True, True, w.IPV6_EXPECTED, True), "DEGRADED")
    check("vpn up, egress-only blocked -> NOT ALL_OK (still visible)",
          w.classify(f, True, True, w.IPV6_EXPECTED, True) == "ALL_OK", False)
    check("vpn up, egress blocked -> note names the vpn",
          w._note(f, True, True, w.IPV6_EXPECTED, True), w._NOTE_EGRESS_VPN_BLOCKED)
    check("vpn DOWN, egress blocked -> LOCAL_FAIL (unchanged)",
          w.classify(f, True, True, w.IPV6_EXPECTED, False), "LOCAL_FAIL")
    check("vpn DOWN, egress blocked -> original note",
          w._note(f, True, True, w.IPV6_EXPECTED, False), w._NOTE_EGRESS_FAIL)
    check("egress verdict DIFFERS on vpn flag alone",
          w.classify(f, True, True, w.IPV6_EXPECTED, True)
          != w.classify(f, True, True, w.IPV6_EXPECTED, False), True)
    # Both blocked at once — the full production shape.
    check("vpn up, egress AND ipv6 blocked -> DEGRADED (egress still surfaces)",
          w.classify(flags(egress=0), True, False, w.IPV6_EXPECTED, True), "DEGRADED")


# ── 5. A REAL local fault under a VPN must STILL be LOCAL_FAIL ───────────────
def test_vpn_does_not_mask_genuine_local_faults():
    """The over-permissive failure mode: a VPN must not become a blanket excuse."""
    check("vpn up, no default route -> LOCAL_FAIL",
          w.classify(flags(routing=0), True, True, w.IPV6_EXPECTED, True), "LOCAL_FAIL")
    check("vpn up, dns dead -> LOCAL_FAIL",
          w.classify(flags(dns=0), True, True, w.IPV6_EXPECTED, True), "LOCAL_FAIL")
    check("vpn up, routing AND egress dead -> LOCAL_FAIL",
          w.classify(flags(routing=0, egress=0), True, True, w.IPV6_EXPECTED, True),
          "LOCAL_FAIL")
    check("vpn up, dns AND egress dead -> LOCAL_FAIL",
          w.classify(flags(dns=0, egress=0), True, True, w.IPV6_EXPECTED, True),
          "LOCAL_FAIL")
    check("vpn up, no route -> note is the route fault, not a vpn excuse",
          w._note(flags(routing=0), True, True, w.IPV6_EXPECTED, True), w._NOTE_NO_ROUTE)
    check("vpn up, dns dead -> note is the dns fault",
          w._note(flags(dns=0), True, True, w.IPV6_EXPECTED, True), w._NOTE_DNS_FAIL)
    check("vpn up, upstream dead -> UPSTREAM_FAIL (not masked)",
          w.classify(flags(api=0), True, True, w.IPV6_EXPECTED, True), "UPSTREAM_FAIL")
    check("vpn up, IPv4 keytest failing -> DEGRADED (a real degradation)",
          w.classify(flags(), False, True, w.IPV6_EXPECTED, True), "DEGRADED")
    check("vpn up, ipv4 failing -> ipv4 note, not a vpn note",
          w._note(flags(), False, True, w.IPV6_EXPECTED, True), w._NOTE_IPV4_FAIL)


# ── 6. the pre-existing IPv4-only-link behaviour is untouched ────────────────
def test_prior_ipv6_expectation_cases_unchanged():
    f = flags()
    check("ipv4-only link, vpn down -> ALL_OK (2026-08-22 fix intact)",
          w.classify(f, True, False, w.IPV6_NOT_PROVISIONED, False), "ALL_OK")
    check("ipv4-only link -> absent note",
          w._note(f, True, False, w.IPV6_NOT_PROVISIONED, False), w._NOTE_IPV6_ABSENT)
    check("ipv6 undetermined, vpn down -> ALL_OK",
          w.classify(f, True, False, w.IPV6_UNKNOWN, False), "ALL_OK")
    check("ipv6 undetermined -> unknown note",
          w._note(f, True, False, w.IPV6_UNKNOWN, False), w._NOTE_IPV6_UNKNOWN)
    check("healthy everything, vpn down -> ALL_OK",
          w.classify(f, True, True, w.IPV6_EXPECTED, False), "ALL_OK")
    check("healthy everything, vpn up -> ALL_OK",
          w.classify(f, True, True, w.IPV6_EXPECTED, True), "ALL_OK")
    check("healthy everything -> empty note",
          w._note(f, True, True, w.IPV6_EXPECTED, False), "")
    # VPN must win over provisioning state, since expectation cannot see the tunnel.
    check("vpn up beats NOT_PROVISIONED for the note",
          w._note(f, True, False, w.IPV6_NOT_PROVISIONED, True), w._NOTE_IPV6_VPN_BLOCKED)


# ── 7. note vocabulary stays controlled (these strings reach the DB) ─────────
def test_notes_are_address_free_controlled_vocabulary():
    for name in ("_NOTE_IPV6_VPN_BLOCKED", "_NOTE_EGRESS_VPN_BLOCKED"):
        val = getattr(w, name)
        check("%s is a fixed lowercase string" % name,
              isinstance(val, str) and val == val.lower() and val.strip() == val, True)


if __name__ == "__main__":
    test_vpn_up_ipv6_blocked_is_not_a_fault()
    test_vpn_down_ipv6_fault_still_fires()
    test_vpn_flag_is_load_bearing()
    test_egress_blocked_degrades_not_escalates()
    test_vpn_does_not_mask_genuine_local_faults()
    test_prior_ipv6_expectation_cases_unchanged()
    test_notes_are_address_free_controlled_vocabulary()
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
