"""Rogue-DHCP detection — PURE core. No DB, no Flask, no filesystem.

WHAT THIS DETECTS, AND WHAT IT CANNOT
    A DHCP server on the LAN that is not the one this network is supposed to
    have. An attacker who answers DHCP faster than the real server hands the
    victim a gateway and a resolver of the attacker's choosing — an on-path
    position obtained with no credentials and no access to the real router.

    It does NOT detect a rogue server that never answers while we are watching.
    Detection here is PASSIVE and OPPORTUNISTIC: it sees a server only when that
    server speaks. That is a real limit and `observed_total` exists so the
    dashboard can say "nothing seen yet" instead of implying "nothing there".

WHY THIS WORKS FROM ANY LAN POSITION, UNLIKE ARP SPOOFING
    DHCP OFFER/ACK are broadcast (or relayed) rather than unicast between two
    third parties, so the appliance does not need to be the gateway, and does not
    need a mirror port, to see them. This is the entire reason rogue-DHCP
    detection was separable from the parked ARP-spoofing work, which does have a
    vantage-point dependency.

ONLY SERVER-ORIGINATED MESSAGES ARE CLAIMS OF AUTHORITY
    A client sending DISCOVER or REQUEST is asking, not asserting. Treating a
    client message as evidence of a server would make every DHCP client on the
    network look like a DHCP server. `SERVER_MESSAGE_TYPES` is that boundary.

⚠ `extended: yes` IS A COVERAGE CHANGE, NOT ONLY A SEVERITY ONE — MEASURED
    This was initially documented (wrongly) as a severity upgrade only. Measured
    2026-08-30 by running Suricata offline against a crafted pcap holding one
    OFFER and one ACK:

        extended: no   ->  1 event  (the ACK only; the OFFER is DROPPED)
        extended: yes  ->  2 events (OFFER and ACK, with routers/dns_servers)

    Suricata's non-extended mode logs "just enough to map a MAC to an IP", and in
    practice that means the ACK. **The OFFER never reaches the log at all.**

    Why that matters to THIS detector: a rogue server's defining act is racing the
    real server with an OFFER. If the victim accepts the rogue, a rogue ACK
    follows and we would see it either way. But a rogue that OFFERS AND LOSES THE
    RACE produces an OFFER and no ACK — invisible without extended logging. The
    flip therefore moves this detector from "sees rogue servers that WON" to "sees
    rogue servers that are TRYING", which is the early warning.

    Detection still functions without it, on ACKs alone, and server identity still
    comes from the eve record's top-level `src_ip`. `payload_known` still says
    which case a finding was built from. But do NOT describe the un-flipped state
    as full coverage with thinner evidence — it is NARROWER COVERAGE.
"""

# DHCP message types that only a SERVER sends. A client's DISCOVER/REQUEST/
# RELEASE/DECLINE/INFORM asserts nothing about who serves the network.
SERVER_MESSAGE_TYPES = frozenset({"offer", "ack", "nak"})

# Verdicts. UNKNOWN is a first-class outcome, never folded into CLEAN: an event
# we could not evaluate is not evidence of a healthy network, and the standing
# practice in this repo is that a failed derivation surfaces as an explicit state
# rather than as a default that happens to be a legal answer.
CLEAN, ROGUE, UNKNOWN = "clean", "rogue", "unknown"

# Severity bands for a ROGUE verdict.
SEV_INFO, SEV_HIGH, SEV_CRITICAL = "info", "high", "critical"


def parse_event(rec):
    """Normalise one eve.json record into a server-authority observation.

    Returns a dict, or None when the record is not a server-originated DHCP
    message. None means "not relevant", NOT "clean" — callers must not count it.
    """
    if not isinstance(rec, dict):
        return None
    if rec.get("event_type") != "dhcp":
        return None
    dhcp = rec.get("dhcp")
    if not isinstance(dhcp, dict):
        return None

    mtype = str(dhcp.get("dhcp_type", "")).lower()
    if mtype not in SERVER_MESSAGE_TYPES:
        return None

    # `routers` / `dns_servers` appear only under `extended: yes`. Their ABSENCE
    # is recorded as unknown-payload rather than as an empty advertisement --
    # an empty list would read as "advertised nothing", which is a different and
    # much stronger claim than "we were not told".
    routers = dhcp.get("routers")
    dns_servers = dhcp.get("dns_servers")
    payload_known = isinstance(routers, list) or isinstance(dns_servers, list)

    return {
        "server_ip": (rec.get("src_ip") or "").strip(),
        "message_type": mtype,
        "client_mac": (dhcp.get("client_mac") or "").strip().lower() or None,
        "assigned_ip": (dhcp.get("assigned_ip") or "").strip() or None,
        "routers": list(routers) if isinstance(routers, list) else None,
        "dns_servers": list(dns_servers) if isinstance(dns_servers, list) else None,
        "payload_known": payload_known,
        "timestamp": rec.get("timestamp") or None,
        "iface": rec.get("in_iface") or None,
    }


def classify(obs, expected_servers, expected_routers=None, expected_dns=None):
    """Verdict for one observation against the pinned expectation.

    `expected_servers` is the set of addresses permitted to answer DHCP. An
    EMPTY expected set yields UNKNOWN, never CLEAN: with nothing pinned there is
    no such thing as an unexpected server, and reporting that as clean would be
    an instrument that can only ever say "fine" -- the exact shape this codebase
    keeps catching. Fail closed and say so instead.
    """
    if not isinstance(obs, dict):
        return {"verdict": UNKNOWN, "severity": SEV_INFO,
                "reason": "unparseable observation"}

    server = obs.get("server_ip") or ""
    if not server:
        return {"verdict": UNKNOWN, "severity": SEV_INFO,
                "reason": "server address absent from event"}

    expected = frozenset(x for x in (expected_servers or ()) if x)
    if not expected:
        return {"verdict": UNKNOWN, "severity": SEV_INFO,
                "reason": "no expected DHCP server pinned yet"}

    if server in expected:
        return {"verdict": CLEAN, "severity": SEV_INFO,
                "reason": "server is pinned as expected"}

    # Unexpected server. Severity depends on what it actually tried to hand out,
    # which is only knowable under extended logging.
    #
    # ⚠ THE SELF-ADVERTISEMENT CHECK NEEDS NO CONFIGURED EXPECTATION, and that is
    # why it is first. A rogue server naming ITSELF as the gateway or the resolver
    # is the on-path attack in its literal form -- it is self-evident from the
    # packet, with nothing to compare against. Requiring `expected_routers` /
    # `expected_dns` to be populated before this could escalate made the branch
    # UNREACHABLE in production, since the tailer has no such configuration to
    # supply. Found by the integration test, not by reading this function: the
    # pure-core suite passed because it passed those sets in by hand, which
    # production never does.
    hijack = []
    if obs.get("payload_known"):
        advertised_routers = tuple(obs.get("routers") or ())
        advertised_dns = tuple(obs.get("dns_servers") or ())
        if server in advertised_routers:
            hijack.append("gateway=%s (itself)" % server)
        if server in advertised_dns:
            hijack.append("dns=%s (itself)" % server)

        # Secondary: an unexpected server pointing at some THIRD address that is
        # not in a configured expectation. Only meaningful when an expectation
        # exists -- an empty set here means "not configured", not "nothing is
        # allowed", and must not manufacture a finding out of missing config.
        exp_r = frozenset(x for x in (expected_routers or ()) if x)
        exp_d = frozenset(x for x in (expected_dns or ()) if x)
        for adv in advertised_routers:
            if exp_r and adv not in exp_r and adv != server:
                hijack.append("gateway=%s" % adv)
        for adv in advertised_dns:
            if exp_d and adv not in exp_d and adv != server:
                hijack.append("dns=%s" % adv)

    if hijack:
        return {"verdict": ROGUE, "severity": SEV_CRITICAL,
                "reason": "unexpected DHCP server advertising " + ", ".join(sorted(hijack))}
    if obs.get("payload_known"):
        return {"verdict": ROGUE, "severity": SEV_HIGH,
                "reason": "unexpected DHCP server answered (advertised values match expectation)"}
    return {"verdict": ROGUE, "severity": SEV_HIGH,
            "reason": "unexpected DHCP server answered "
                      "(advertised gateway/DNS unknown -- Suricata extended DHCP logging is off)"}


# ── Self-test: prove the instrument can produce BOTH answers ──────────────────
#
# Standing practice in this repo (`scripts/nemesis-fw-neverblock`'s CANARIES):
# a verification step must prove its own premise against a known-different input
# before anything trusts what it reports. A rogue-DHCP detector on a quiet
# network emits nothing for days, and "no findings" is exactly what a detector
# broken at import time also produces. These canaries run in the PRODUCTION path,
# not only under the test suite, and a failure fails the module closed.

_CANARY_EXPECTED_SERVER = "192.0.2.1"      # RFC 5737 TEST-NET-1, goes nowhere
_CANARY_ROGUE_SERVER    = "192.0.2.66"

_CANARIES = (
    # (label, raw eve record, expected verdict)
    ("legitimate OFFER from the pinned server", {
        "event_type": "dhcp", "src_ip": _CANARY_EXPECTED_SERVER,
        "dhcp": {"dhcp_type": "offer", "client_mac": "00:00:5e:00:53:01",
                 "assigned_ip": "192.0.2.50"}}, CLEAN),
    ("OFFER from an unpinned server", {
        "event_type": "dhcp", "src_ip": _CANARY_ROGUE_SERVER,
        "dhcp": {"dhcp_type": "offer", "client_mac": "00:00:5e:00:53:01",
                 "assigned_ip": "192.0.2.50"}}, ROGUE),
    ("ACK from an unpinned server", {
        "event_type": "dhcp", "src_ip": _CANARY_ROGUE_SERVER,
        "dhcp": {"dhcp_type": "ack", "client_mac": "00:00:5e:00:53:01"}}, ROGUE),
    # The self-advertisement case carries its own canary because it is the one
    # that matters most and the one that was unreachable in production once.
    ("OFFER from an unpinned server naming ITSELF as gateway", {
        "event_type": "dhcp", "src_ip": _CANARY_ROGUE_SERVER,
        "dhcp": {"dhcp_type": "offer", "routers": [_CANARY_ROGUE_SERVER]}}, ROGUE),
)


def selftest():
    """(ok, detail). Proves classify() can return BOTH clean and rogue, and that
    client-originated traffic is not mistaken for a server claim."""
    for label, rec, want in _CANARIES:
        obs = parse_event(rec)
        if obs is None:
            return False, "canary %r did not parse as a server message" % label
        got = classify(obs, {_CANARY_EXPECTED_SERVER})["verdict"]
        if got != want:
            return False, "canary %r: expected %s, got %s" % (label, want, got)

    # A client DISCOVER must NOT register as a server claim. Without this the
    # detector would flag every DHCP client on the network as a rogue server.
    if parse_event({"event_type": "dhcp", "src_ip": _CANARY_ROGUE_SERVER,
                    "dhcp": {"dhcp_type": "discover"}}) is not None:
        return False, "canary: client DISCOVER was treated as a server message"

    # And it must escalate WITHOUT any configured expectation -- the exact
    # condition production runs under.
    self_adv = parse_event(_CANARIES[3][1])
    if classify(self_adv, {_CANARY_EXPECTED_SERVER})["severity"] != SEV_CRITICAL:
        return False, "canary: self-advertised gateway did not escalate to critical"

    # An empty expectation must fail closed, not read as clean.
    obs = parse_event(_CANARIES[0][1])
    if classify(obs, set())["verdict"] != UNKNOWN:
        return False, "canary: empty expected-server set did not fail closed"

    return True, "%d canaries passed" % (len(_CANARIES) + 2)
