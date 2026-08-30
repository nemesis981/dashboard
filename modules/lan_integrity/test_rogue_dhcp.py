"""Rogue-DHCP pure core. No DB, no Flask, no eve.json.

The load-bearing cases here are the REFUSALS, not the detections. A rogue-DHCP
detector on a healthy network produces no findings for days, so "it found
nothing" is indistinguishable from "it is broken" unless the negatives are
pinned explicitly: a client message must not count as a server claim, an empty
expectation must not read as clean, and a missing server address must not read
as clean.

TOTAL IS ASSERTED. Two assertions in this file used to be reachable only on the
success path elsewhere in the codebase, and a run with LESS coverage then
reported as a smaller suite rather than a failing one. Every check below is
unconditional, and the expected count is asserted at the end so drift reports
itself instead of vanishing.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rogue_dhcp as rd

_fail = []
_count = 0

EXPECTED_CHECKS = 46


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-64s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


PINNED = "192.0.2.1"          # RFC 5737 TEST-NET-1 throughout -- routes nowhere
ROGUE_SRV = "192.0.2.66"


def _ev(src, mtype, **dhcp):
    d = {"dhcp_type": mtype}
    d.update(dhcp)
    return {"event_type": "dhcp", "src_ip": src, "dhcp": d}


# ── parse_event: only a SERVER speaking is a claim of authority ──────────────
def test_only_server_messages_parse():
    print("\n[only server-originated messages are claims of authority]")
    for t in ("offer", "ack", "nak"):
        check("%-8s parses as a server message" % t,
              rd.parse_event(_ev(ROGUE_SRV, t)) is not None, True)
    for t in ("discover", "request", "release", "decline", "inform"):
        check("%-8s is NOT a server message" % t,
              rd.parse_event(_ev(ROGUE_SRV, t)), None)
    check("case-insensitive on message type",
          rd.parse_event(_ev(ROGUE_SRV, "OFFER")) is not None, True)


def test_non_dhcp_records_rejected():
    print("\n[records that are not DHCP must not enter the pipeline at all]")
    check("wrong event_type -> None",
          rd.parse_event({"event_type": "dns", "src_ip": ROGUE_SRV,
                          "dhcp": {"dhcp_type": "offer"}}), None)
    check("missing dhcp object -> None",
          rd.parse_event({"event_type": "dhcp", "src_ip": ROGUE_SRV}), None)
    check("dhcp not a dict -> None",
          rd.parse_event({"event_type": "dhcp", "dhcp": "offer"}), None)
    check("not a dict at all -> None", rd.parse_event("offer"), None)
    check("None -> None", rd.parse_event(None), None)


# ── the REFUSALS: none of these may read as CLEAN ────────────────────────────
def test_empty_expectation_fails_closed():
    print("\n[an unpinned network has no such thing as an unexpected server]")
    obs = rd.parse_event(_ev(ROGUE_SRV, "offer"))
    check("empty set -> UNKNOWN, not CLEAN",
          rd.classify(obs, set())["verdict"], rd.UNKNOWN)
    check("None -> UNKNOWN, not CLEAN",
          rd.classify(obs, None)["verdict"], rd.UNKNOWN)
    check("set of empty strings -> UNKNOWN, not CLEAN",
          rd.classify(obs, {"", None})["verdict"], rd.UNKNOWN)
    check("reason names the missing pin",
          "pinned" in rd.classify(obs, set())["reason"], True)


def test_missing_server_address_fails_closed():
    print("\n[an event we cannot attribute is not evidence of health]")
    obs = rd.parse_event(_ev("", "offer"))
    check("blank src_ip -> UNKNOWN", rd.classify(obs, {PINNED})["verdict"], rd.UNKNOWN)
    check("garbage observation -> UNKNOWN",
          rd.classify("nonsense", {PINNED})["verdict"], rd.UNKNOWN)
    check("None observation -> UNKNOWN",
          rd.classify(None, {PINNED})["verdict"], rd.UNKNOWN)


# ── the detections ───────────────────────────────────────────────────────────
def test_pinned_server_is_clean():
    print("\n[the real server answering is the overwhelmingly common case]")
    obs = rd.parse_event(_ev(PINNED, "offer"))
    v = rd.classify(obs, {PINNED})
    check("pinned server -> CLEAN", v["verdict"], rd.CLEAN)
    check("clean carries info severity", v["severity"], rd.SEV_INFO)
    check("still clean with several pinned servers",
          rd.classify(obs, {PINNED, "192.0.2.9"})["verdict"], rd.CLEAN)


def test_unexpected_server_is_rogue():
    print("\n[an unpinned server answering DHCP is the finding]")
    obs = rd.parse_event(_ev(ROGUE_SRV, "offer"))
    v = rd.classify(obs, {PINNED})
    check("unpinned server -> ROGUE", v["verdict"], rd.ROGUE)
    check("HIGH when the advertisement is unknown", v["severity"], rd.SEV_HIGH)
    check("reason says WHY the payload is unknown",
          "extended" in v["reason"], True)


def test_extended_payload_escalates():
    print("\n[extended logging distinguishes 'answered' from 'tried to be your gateway']")
    obs = rd.parse_event(_ev(ROGUE_SRV, "offer",
                             routers=["192.0.2.66"], dns_servers=["192.0.2.66"]))
    v = rd.classify(obs, {PINNED}, expected_routers={"192.0.2.1"},
                    expected_dns={"192.0.2.1"})
    check("hijacking gateway+DNS -> CRITICAL", v["severity"], rd.SEV_CRITICAL)
    check("reason names the advertised gateway", "gateway=192.0.2.66" in v["reason"], True)
    check("reason names the advertised DNS", "dns=192.0.2.66" in v["reason"], True)

    benign = rd.parse_event(_ev(ROGUE_SRV, "offer",
                                routers=["192.0.2.1"], dns_servers=["192.0.2.1"]))
    v2 = rd.classify(benign, {PINNED}, expected_routers={"192.0.2.1"},
                     expected_dns={"192.0.2.1"})
    check("unpinned server is STILL rogue even advertising expected values",
          v2["verdict"], rd.ROGUE)
    check("...but only HIGH, not CRITICAL", v2["severity"], rd.SEV_HIGH)


def test_self_advertisement_needs_no_config():
    """The branch that was UNREACHABLE in production until 2026-08-30.

    The tailer supplies no expected_routers/expected_dns -- it has none to supply
    -- so an escalation that REQUIRED them could never fire outside a test that
    passed them in by hand. A server naming itself is self-evident from the packet.
    """
    print("\n[a rogue naming ITSELF as gateway/DNS escalates with nothing configured]")
    g = rd.parse_event(_ev(ROGUE_SRV, "offer", routers=[ROGUE_SRV]))
    v = rd.classify(g, {PINNED})                      # no expected_* passed, as in production
    check("self-advertised gateway -> CRITICAL", v["severity"], rd.SEV_CRITICAL)
    check("reason marks it as itself", "(itself)" in v["reason"], True)

    d = rd.parse_event(_ev(ROGUE_SRV, "offer", dns_servers=[ROGUE_SRV]))
    check("self-advertised DNS -> CRITICAL",
          rd.classify(d, {PINNED})["severity"], rd.SEV_CRITICAL)

    both = rd.parse_event(_ev(ROGUE_SRV, "offer",
                              routers=[ROGUE_SRV], dns_servers=[ROGUE_SRV]))
    v3 = rd.classify(both, {PINNED})
    check("both self-advertised -> CRITICAL", v3["severity"], rd.SEV_CRITICAL)
    check("both are named in the reason",
          v3["reason"].count("(itself)"), 2)


def test_missing_config_does_not_manufacture_a_finding():
    print("\n[an unconfigured expectation means 'not configured', never 'nothing allowed']")
    third = rd.parse_event(_ev(ROGUE_SRV, "offer", routers=["192.0.2.7"]))
    v = rd.classify(third, {PINNED})                  # no expected_routers configured
    check("third-party advertisement alone does NOT escalate", v["severity"], rd.SEV_HIGH)
    check("still a rogue finding, just not critical", v["verdict"], rd.ROGUE)
    v2 = rd.classify(third, {PINNED}, expected_routers={"192.0.2.1"})
    check("...but WITH an expectation configured it does", v2["severity"], rd.SEV_CRITICAL)


def test_payload_known_flag():
    print("\n[absent extended data must not read as 'advertised nothing']")
    plain = rd.parse_event(_ev(ROGUE_SRV, "offer"))
    check("no extended fields -> payload_known False", plain["payload_known"], False)
    check("routers is None, not []", plain["routers"], None)
    ext = rd.parse_event(_ev(ROGUE_SRV, "offer", routers=[]))
    check("an EMPTY advertised list is still 'known'", ext["payload_known"], True)
    check("empty list preserved as []", ext["routers"], [])


def test_selftest_canaries():
    print("\n[the instrument proves it can produce BOTH answers]")
    ok, detail = rd.selftest()
    check("selftest passes", ok, True)
    check("selftest reports a count", "canaries passed" in detail, True)


if __name__ == "__main__":
    print("lan_integrity -- rogue DHCP pure core")
    test_only_server_messages_parse()
    test_non_dhcp_records_rejected()
    test_empty_expectation_fails_closed()
    test_missing_server_address_fails_closed()
    test_pinned_server_is_clean()
    test_unexpected_server_is_rogue()
    test_extended_payload_escalates()
    test_self_advertisement_needs_no_config()
    test_missing_config_does_not_manufacture_a_finding()
    test_payload_known_flag()
    test_selftest_canaries()
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
