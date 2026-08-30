"""lan_integrity → Tier 2 correlation: the STABLE consumption seam.

WHO THIS IS FOR
    Tier 2 lateral-movement / outbreak correlation
    (`docs/roadmap/lateral-movement-outbreak-detection.md`) consumes ARP anomalies
    as one of five signals. This module is that interface. It exists so Tier 2
    never reads `lan_integrity_*` tables directly: the tables are this module's
    private storage and will change as ARP and IPv6-RA detection grow, while the
    shape below is a contract.

    **`SCHEMA_VERSION` is the compatibility handle.** Additive fields will not bump
    it; a removal or a meaning change will. Assert on it rather than trusting a
    field to exist forever.

⚠ THE MOST IMPORTANT THING A CORRELATION ENGINE MUST NOT DO WITH THIS DATA
    **Do not treat "no signals returned" as evidence that nothing happened.**
    lan_integrity's view of the LAN is structurally incomplete: from a non-gateway
    position on a switched network it cannot see unicast traffic between two other
    hosts. Measured on this appliance, only 0.73% of observed flows were LAN-peer
    to LAN-peer, essentially all broadcast.

    So an empty result is ambiguous between "nothing happened" and "it happened
    where we cannot see". `get_coverage()` exists to disambiguate, and it is not
    optional garnish: **call it, and weight or suppress the ARP dimension of a
    correlation score according to what it reports.** A five-signal score that
    silently treats a dark signal as a passing one is not a lower-confidence
    score, it is a wrong one -- the same failure shape as a green test suite that
    never ran the code.

FIELD CONTRACT (schema_version 1)
    signal        str   stable kind. See arp_watch (arp_*) and rogue_dhcp.
    ts            float unix seconds, when observed.
    severity      str   "info" | "high" | "critical".
    confidence    str   "observed" -- broadcast-class, our view of this class is
                        complete; "partial" -- derived from this host's own cache
                        or a form we may see only some instances of. NOT a
                        probability, and NOT a measure of how sure we are the
                        event is malicious.
    subject_ip    str|None   the address the claim is ABOUT.
    subject_mac   str|None   the hardware address making the claim.
    previous_mac  str|None   what the address was bound to before, if applicable.
    source        str   "suricata_arp" | "kernel_arp_cache" | "suricata_dhcp" | "derived".
    evidence      dict  detector-specific detail. Free-form; do NOT key on it.
    status        str   "open" | "closed" (operator-acknowledged).

CORRELATION KEYS
    Join on `subject_mac` where present, falling back to `subject_ip`. MAC is the
    stabler identity for this signal class specifically -- an ARP anomaly is an
    assertion BY a hardware address ABOUT an IP, and the IP is the thing being
    contested, so keying correlation on IP alone will merge attacker and victim
    into one entity.
"""

SCHEMA_VERSION = 1

_SELECT = (
    "SELECT id, ts, kind, severity, confidence, subject_ip, subject_mac, "
    "       previous_mac, source, reason, detail, status "
    "FROM lan_integrity_findings"
)


def _row_to_signal(r):
    import json
    try:
        evidence = json.loads(r[10]) if r[10] else {}
    except Exception:
        # A detail blob we cannot parse is reported as UNPARSEABLE rather than as
        # an empty dict: {} reads as "no evidence", which is a different claim.
        evidence = {"_unparseable": True}
    if not isinstance(evidence, dict):
        evidence = {"_unparseable": True}
    evidence.setdefault("reason", r[9])
    return {
        "schema_version": SCHEMA_VERSION,
        "id": r[0],
        "signal": r[2],
        "ts": r[1],
        "severity": r[3],
        "confidence": r[4] or "partial",
        "subject_ip": r[5],
        "subject_mac": r[6],
        "previous_mac": r[7],
        "source": r[8],
        "evidence": evidence,
        "status": r[11],
    }


def get_signals(conn, since_ts=0.0, kinds=None, include_closed=False, limit=500):
    """Signals observed at or after `since_ts`, newest first.

    `conn` is supplied by the caller so this reads inside the caller's own
    transaction and connection lifetime -- this module does not open connections
    on someone else's behalf, and must not outlive their scope.
    """
    sql = _SELECT + " WHERE ts >= ?"
    args = [float(since_ts or 0.0)]
    if kinds:
        ks = [k for k in kinds if k]
        if ks:
            sql += " AND kind IN (%s)" % ",".join("?" * len(ks))
            args.extend(ks)
    if not include_closed:
        sql += " AND status = 'open'"
    sql += " ORDER BY ts DESC LIMIT ?"
    args.append(int(limit))
    return [_row_to_signal(r) for r in conn.execute(sql, args)]


def get_coverage(conn):
    """What this module can and cannot see. Call this before scoring on absence.

    Every field is derived from LIVE state, never from a constant: `observable`
    reflects whether a source has actually produced anything, not whether it is
    configured to. A logger that is enabled and silent looks exactly like a quiet
    network, and that is the distinction a correlation engine most needs.
    """
    def state(key, default=""):
        row = conn.execute(
            "SELECT value FROM lan_integrity_state WHERE key=?", (key,)).fetchone()
        return default if row is None else row[0]

    arp_total = int(state("arp_events_total", "0") or 0)
    dhcp_total = int(state("dhcp_events_total", "0") or 0)
    cache_total = int(state("arp_cache_reads_total", "0") or 0)
    selftest_ok = state("selftest_ok", "1") == "1"

    return {
        "schema_version": SCHEMA_VERSION,
        "detector_healthy": selftest_ok,
        "sources": {
            "suricata_arp": {
                "observable": arp_total > 0,
                "observed_count": arp_total,
                "reason": ("wire ARP seen" if arp_total
                           else "no ARP events yet -- Suricata's eve `arp` logger is "
                                "DISABLED BY DEFAULT (`enabled: no`); until it is on, "
                                "the only ARP source is this host's own cache"),
            },
            "kernel_arp_cache": {
                "observable": cache_total > 0,
                "observed_count": cache_total,
                "reason": "this appliance's own /proc/net/arp resolutions",
            },
            "suricata_dhcp": {
                "observable": dhcp_total > 0,
                "observed_count": dhcp_total,
                "reason": ("DHCP server messages seen" if dhcp_total
                           else "no DHCP server messages observed yet; renewals are "
                                "unicast, so silence here is expected on a quiet LAN"),
            },
        },
        # Structural, not fixable by configuration. Stated so a consumer can put it
        # in front of a human rather than discovering it during an incident.
        "blind_spots": [
            "Unicast ARP replies sent directly from one LAN host to another, where "
            "neither is this appliance, are not observable from a non-gateway "
            "position on a switched network. Broadcast ARP requests and gratuitous "
            "ARP ARE observable.",
            "Only 0.73% of observed flows on this appliance were LAN-peer to "
            "LAN-peer (measured 2026-08-30), essentially all broadcast. Any signal "
            "requiring peer-to-peer unicast visibility is unreliable until the "
            "gateway-mode decision is made or agents report their own view.",
            "The kernel ARP cache is self-referential: an attacker poisoning THIS "
            "appliance edits the same table used to detect them.",
        ],
        "interpretation": (
            "An empty get_signals() result is NOT evidence of a healthy LAN. Check "
            "`sources` and `blind_spots` before letting an absent ARP signal raise a "
            "correlation score."
        ),
    }
