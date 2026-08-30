"""ARP-spoofing detection — PURE core. No DB, no Flask, no filesystem.

WHAT THIS DETECTS
    A device claiming an IP address that belongs to another device. That is how
    an attacker puts itself between a victim and the gateway without touching the
    gateway or knowing any credential: it simply asserts, repeatedly, that the
    gateway's IP is at the attacker's MAC.

⚠ THE VISIBILITY CEILING — READ THIS BEFORE TRUSTING A NEGATIVE RESULT
    Measured on this appliance, not assumed: of 24,707 sampled Suricata flow
    events, 90.6% involved the appliance itself and only 0.73% (181 flows, 25
    distinct pairs) were LAN-peer to LAN-peer, essentially all broadcast. On a
    SWITCHED LAN a non-gateway appliance does not see unicast traffic between two
    other hosts. Applied to ARP specifically:

      VISIBLE    ARP requests            -- broadcast by definition.
      VISIBLE    Gratuitous ARP          -- broadcast; the loudest spoofing form,
                                            and the one most tools actually use.
      VISIBLE    Anything addressed to,
                 or claimed about, THIS appliance.
      INVISIBLE  A unicast ARP REPLY sent from attacker straight to victim,
                 where neither is this appliance. Nothing reaches us. We cannot
                 see it, and no amount of parsing changes that.

    So a quiet result means "no spoofing that we could see", NEVER "no spoofing".
    That distinction is carried in every signal as `confidence`, and in
    `signals.get_coverage()`, precisely so Tier 2 correlation cannot silently
    treat our silence as evidence of health. **Closing this gap needs the gateway
    position or agent-side reporting -- it is a deployment-topology limit, not a
    detection-quality one, and no threshold tuning will move it.**

TWO SOURCES, DIFFERENT TRUST
    * `suricata_arp` -- wire observations from eve.json (`event_type: arp`).
      Schema VERIFIED 2026-08-30 by running Suricata offline against a crafted
      ARP pcap rather than by reading documentation: addresses live INSIDE the
      `arp` object (`arp.src_ip` / `arp.src_mac`), not at the top level, and a
      gratuitous ARP appears as `opcode: reply` with `src_ip == dest_ip`.
    * `kernel_arp_cache` -- /proc/net/arp, this host's OWN resolutions. Available
      with no config change, but SELF-REFERENTIAL: an attacker poisoning this
      appliance corrupts the very table used to detect them. Useful for detecting
      an attack ON us; useless for one between two third parties.
"""

# One MAC legitimately holding a couple of addresses is ordinary (an interface
# with an alias, a router). Holding many is the signature of an impersonator.
MULTI_CLAIM_THRESHOLD = 4

# A binding that changes once is a DHCP lease turning over or a NIC swap. One
# that oscillates is two hosts fighting over the same address, which is what an
# active spoofing session looks like from the outside.
FLAP_CHANGES = 3
FLAP_WINDOW_SECONDS = 300

# Signal kinds. Stable strings -- Tier 2 correlation keys on these.
BINDING_CHANGE = "arp_binding_change"
GATEWAY_TAKEOVER = "arp_gateway_takeover"
MAC_MULTI_CLAIM = "arp_mac_multi_claim"
BINDING_FLAP = "arp_binding_flap"

SEV_INFO, SEV_HIGH, SEV_CRITICAL = "info", "high", "critical"

# Confidence reflects the CEILING above, not scoring certainty.
#   observed -- seen directly on the wire in a form that is broadcast, so our
#               view of this event class is complete.
#   partial  -- derived from this host's own cache, or from a form we may only
#               see some instances of. Absence proves nothing.
CONF_OBSERVED, CONF_PARTIAL = "observed", "partial"

_NULL_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


def _norm_mac(m):
    m = (m or "").strip().lower()
    return m if m and m not in _NULL_MACS else None


def parse_eve_event(rec):
    """Normalise one eve.json `arp` record into an observation, or None.

    None means "not a usable ARP claim", NOT "nothing wrong". Only the SENDER
    fields assert a binding: `src_ip` is at `src_mac` is the claim being made.
    The target fields of a request are a QUESTION ("who has X"), and recording
    them as a binding would invent one out of an unanswered query.
    """
    if not isinstance(rec, dict) or rec.get("event_type") != "arp":
        return None
    arp = rec.get("arp")
    if not isinstance(arp, dict):
        return None
    src_ip = (arp.get("src_ip") or "").strip()
    src_mac = _norm_mac(arp.get("src_mac"))
    if not src_ip or not src_mac:
        return None
    opcode = str(arp.get("opcode", "")).lower()
    dest_ip = (arp.get("dest_ip") or "").strip()
    # Gratuitous: an unsolicited reply announcing yourself. src_ip == dest_ip.
    # VERIFIED against real Suricata output, not inferred from the RFC.
    gratuitous = bool(opcode == "reply" and dest_ip and dest_ip == src_ip)
    return {
        "ip": src_ip,
        "mac": src_mac,
        "opcode": opcode or None,
        "gratuitous": gratuitous,
        "source": "suricata_arp",
        # A request or a gratuitous reply is broadcast, so our view of that class
        # is complete. A directed reply we happened to see is not evidence that we
        # see all of them.
        "confidence": CONF_OBSERVED if (opcode == "request" or gratuitous) else CONF_PARTIAL,
        "ts": rec.get("timestamp"),
    }


def parse_proc_arp(text):
    """Observations from /proc/net/arp text. ALWAYS `partial` confidence.

    This is the appliance's own resolution cache: it reflects what WE asked
    about, and an attacker poisoning us edits exactly this. It is a genuine
    signal for an attack on this host and no signal at all for one between two
    third parties.
    """
    out = []
    for line in (text or "").splitlines()[1:]:      # skip the header row
        parts = line.split()
        if len(parts) < 4:
            continue
        ip_addr, flags, mac = parts[0], parts[2], _norm_mac(parts[3])
        # flags 0x0 == INCOMPLETE: the kernel asked and got no answer. Recording
        # it would manufacture a binding from a failed lookup.
        if flags == "0x0" or not mac:
            continue
        out.append({"ip": ip_addr, "mac": mac, "opcode": None, "gratuitous": False,
                    "source": "kernel_arp_cache", "confidence": CONF_PARTIAL, "ts": None})
    return out


def classify(obs, prior, gateways=(), now=0.0):
    """Verdict for one observation against the stored prior binding for that IP.

    `prior` is the stored row for this IP (dict) or None if unseen. Returns None
    when there is nothing to report -- callers MUST NOT read None as "clean";
    it means "no anomaly in this observation", which for a first sighting is
    simply an absence of history rather than a statement about health.
    """
    if not isinstance(obs, dict) or not obs.get("ip") or not obs.get("mac"):
        return None
    if prior is None:
        return None                       # first sighting: learn, never alert
    prev_mac = prior.get("mac")
    if not prev_mac or prev_mac == obs["mac"]:
        return None

    is_gateway = obs["ip"] in set(g for g in (gateways or ()) if g)

    # Flapping is checked FIRST because it is strictly more alarming than the
    # single change that would otherwise be reported: a binding that keeps moving
    # is two hosts actively contesting one address.
    changes = int(prior.get("change_count", 0) or 0) + 1
    last_change = float(prior.get("last_change_ts", 0) or 0)
    flapping = (changes >= FLAP_CHANGES and last_change
                and (now - last_change) <= FLAP_WINDOW_SECONDS)

    if is_gateway:
        signal, severity = GATEWAY_TAKEOVER, SEV_CRITICAL
        reason = ("the gateway address %s moved from %s to %s -- this is the "
                  "on-path position an attacker wants" % (obs["ip"], prev_mac, obs["mac"]))
    elif flapping:
        signal, severity = BINDING_FLAP, SEV_CRITICAL
        reason = ("%s has changed hardware address %d times, most recently %s -> %s, "
                  "within %ds -- consistent with an active spoofing contest"
                  % (obs["ip"], changes, prev_mac, obs["mac"], FLAP_WINDOW_SECONDS))
    else:
        signal, severity = BINDING_CHANGE, SEV_HIGH
        reason = ("%s moved from %s to %s" % (obs["ip"], prev_mac, obs["mac"]))

    return {
        "signal": signal,
        "severity": severity,
        "confidence": obs.get("confidence", CONF_PARTIAL),
        "reason": reason,
        "subject_ip": obs["ip"],
        "subject_mac": obs["mac"],
        "previous_mac": prev_mac,
        "gratuitous": bool(obs.get("gratuitous")),
        "source": obs.get("source"),
        "change_count": changes,
    }


def classify_multi_claim(mac, claimed_ips):
    """One MAC asserting many distinct IPs. Evaluated across bindings, not per event."""
    ips = sorted(set(i for i in (claimed_ips or ()) if i))
    if len(ips) < MULTI_CLAIM_THRESHOLD:
        return None
    return {
        "signal": MAC_MULTI_CLAIM,
        "severity": SEV_HIGH,
        "confidence": CONF_PARTIAL,   # we may only have seen a subset of its claims
        "reason": "%s currently claims %d addresses (%s)" % (mac, len(ips), ", ".join(ips[:6])),
        "subject_ip": None,
        "subject_mac": mac,
        "previous_mac": None,
        "gratuitous": False,
        "source": "derived",
        "change_count": 0,
    }


# ── Self-test: prove the instrument produces every answer it claims ───────────
_GW = "192.0.2.1"          # RFC 5737 TEST-NET-1 throughout
_MAC_A = "00:00:5e:00:53:01"
_MAC_B = "00:00:5e:00:53:66"


def selftest():
    """(ok, detail). Runs in the PRODUCTION path -- an ARP detector on a healthy
    network is silent, and silence is also what a broken one produces."""
    req = parse_eve_event({"event_type": "arp", "arp": {
        "opcode": "request", "src_ip": _GW, "src_mac": _MAC_A,
        "dest_ip": "192.0.2.50", "dest_mac": "00:00:00:00:00:00"}})
    if req is None or req["confidence"] != CONF_OBSERVED:
        return False, "canary: a broadcast ARP request did not parse as fully observed"

    grat = parse_eve_event({"event_type": "arp", "arp": {
        "opcode": "reply", "src_ip": _GW, "src_mac": _MAC_B,
        "dest_ip": _GW, "dest_mac": "ff:ff:ff:ff:ff:ff"}})
    if grat is None or not grat["gratuitous"]:
        return False, "canary: gratuitous ARP (src_ip == dest_ip) was not recognised"

    # A first sighting must NOT alert, or every new device is an attack.
    if classify(grat, None, gateways=[_GW]) is not None:
        return False, "canary: a first sighting produced an alert"

    # The same MAC re-asserting itself must NOT alert.
    if classify(grat, {"mac": _MAC_B}, gateways=[_GW]) is not None:
        return False, "canary: an unchanged binding produced an alert"

    # A gateway takeover MUST alert, at critical.
    v = classify(grat, {"mac": _MAC_A}, gateways=[_GW])
    if not v or v["signal"] != GATEWAY_TAKEOVER or v["severity"] != SEV_CRITICAL:
        return False, "canary: a gateway takeover was not raised as critical"

    # The SAME change on a non-gateway address must be high, not critical --
    # proving severity is derived from the gateway set and not hardcoded.
    nv = classify(dict(grat, ip="192.0.2.77"), {"mac": _MAC_A}, gateways=[_GW])
    if not nv or nv["severity"] != SEV_HIGH:
        return False, "canary: severity does not discriminate gateway from ordinary host"

    if classify_multi_claim(_MAC_B, ["192.0.2.%d" % i for i in range(2, 2 + MULTI_CLAIM_THRESHOLD)]) is None:
        return False, "canary: a MAC claiming many addresses was not flagged"
    if classify_multi_claim(_MAC_B, ["192.0.2.2"]) is not None:
        return False, "canary: a MAC claiming one address was flagged"

    # /proc/net/arp: an INCOMPLETE entry must not become a binding.
    rows = parse_proc_arp("IP address  HW type  Flags  HW address  Mask  Device\n"
                          "192.0.2.9   0x1      0x0    00:00:00:00:00:00  *  eth0\n"
                          "192.0.2.10  0x1      0x2    %s  *  eth0\n" % _MAC_A)
    if len(rows) != 1 or rows[0]["ip"] != "192.0.2.10":
        return False, "canary: /proc/net/arp parsing did not drop the INCOMPLETE entry"
    if rows[0]["confidence"] != CONF_PARTIAL:
        return False, "canary: kernel-cache observations must never claim full confidence"

    return True, "10 canaries passed"
