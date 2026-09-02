"""Scan-and-spread detection — PURE core. No DB, no Flask, no filesystem.

WHAT THIS DETECTS
    An unmanaged device — a guest phone, an infected IoT box, anything that can
    never run the Nemesis agent — that starts PROBING the rest of the LAN: the
    network signature of one host looking for neighbours to reach or infect. The
    trigger is the device's OWN broadcast-visible behaviour, so no prior detection
    and no agent is required (that is what makes this different from the
    post-detection egress correlator in anomaly_detection, which needs an already-
    flagged, agent-known source).

    Four signals, aggregated per source over a rolling window:
      1. ARP FAN-OUT   — one host ARP-requesting many DISTINCT targets. A scanner
                         MUST ARP for every peer it has not spoken to, and ARP
                         requests are broadcast, so this is the load-bearing signal.
      2. PORT SWEEP    — the already-tuned host-defence SIDs 1000001-1000006 firing
                         for this source (they fire on any LAN device sweeping).
      3. mDNS/SSDP FLOOD — a source flooding multicast service-discovery.
      4. NEW + NOISY   — the source was first seen recently AND fired any of the
                         above. A just-joined device that is instantly probing is
                         the highest-signal pattern; it raises severity, it is never
                         a finding on its own.

⚠ THE VISIBILITY CEILING — READ THIS BEFORE TRUSTING A NEGATIVE RESULT
    On a flat, switched L2 network a non-gateway appliance sees only traffic
    addressed to itself plus broadcast/multicast. Measured on this appliance:
    ~0.1-0.7% of captured flows were true peer-to-peer, essentially all broadcast.
    Applied here:

      VISIBLE    ARP requests, gratuitous ARP, mDNS/SSDP  -- broadcast/multicast.
      VISIBLE    A broad sweep, because it includes the appliance among its targets.
      INVISIBLE  A TARGETED unicast probe A->B where the attacker already knows B's
                 MAC, never broadcasts an ARP for it, and never touches the
                 appliance. Nothing reaches our NIC; no threshold tuning changes it.

    So coverage is inversely proportional to attacker precision: broad, noisy
    scan-and-spread is caught; a narrow, deliberate A->B probe is not. A quiet
    result means "no probing we could see", NEVER "no probing". Closing the gap
    needs Option B (active ARP monitoring) or VLAN-capable hardware — a deployment-
    topology limit, not a detection-quality one. get_coverage() carries this so no
    caller can silently read our silence as health.

ALERT-ONLY, BY DESIGN (2026-09-02). This module detects and records; it does NOT
    auto-isolate. An actor seam is carried on every finding, but wiring containment
    is a separate, deliberate decision (same deferred stance as the canary's
    Layer B'). Do not add auto-quarantine here without that decision.
"""

# ── Tunable thresholds. Conservative to start (minutes not hours, high counts) so
#    a legitimately chatty new device is not a finding. Each is a named constant
#    next to the logic it governs, never a bare number, and every one is exercised
#    by a test in test_behavior.py.
ARP_FANOUT_DISTINCT_IPS = 20        # distinct ARP targets from one source ...
ARP_FANOUT_WINDOW_S = 60            # ... within this many seconds = fan-out.
MDNS_FLOOD_COUNT = 40               # multicast-discovery events from one source ...
MDNS_FLOOD_WINDOW_S = 60            # ... within this window = flood.
NEW_DEVICE_WINDOW_S = 300           # first seen within 5 min = "new" (set by caller).

# The tuned host-defence sweep SIDs (config/suricata/local.rules 1-6). These fire on
# any LAN device sweeping, source-excluding the appliance, and are already verified
# (test_local_rules.py, 24/24). Consumed here rather than re-detected.
SWEEP_SIDS = frozenset({1000001, 1000002, 1000003, 1000004, 1000005, 1000006})

PROBE_SCAN = "lan_probe_scan"       # the finding type (Window 2 naming, c261338).

SIG_ARP_FANOUT = "arp_fanout"
SIG_PORT_SWEEP = "port_sweep"
SIG_MDNS_FLOOD = "mdns_flood"

SEV_INFO, SEV_HIGH, SEV_CRITICAL = "info", "high", "critical"
CONF_OBSERVED, CONF_PARTIAL = "observed", "partial"


def _norm_mac(mac):
    if not mac:
        return None
    m = str(mac).strip().lower()
    return m or None


# ── Parsing: eve.json records -> minimal projections. Kept separate from
#    arp_watch.parse_eve_event ON PURPOSE: that one drops a request's target IP
#    (a "who has X" question is not a binding); here the target IP IS the signal.
def parse_arp_probe(rec):
    """An ARP REQUEST for a real target -> {src_mac, src_ip, target_ip}, else None.

    Only requests count: a scanner ASKS ("who has X"), it does not announce. A null
    or self target (0.0.0.0, ARP probe/announcement) is not a scan target.
    """
    if not isinstance(rec, dict) or rec.get("event_type") != "arp":
        return None
    arp = rec.get("arp")
    if not isinstance(arp, dict):
        return None
    if str(arp.get("opcode", "")).lower() != "request":
        return None
    src_mac = _norm_mac(arp.get("src_mac"))
    target_ip = (arp.get("dest_ip") or "").strip()
    src_ip = (arp.get("src_ip") or "").strip()
    if not src_mac or not target_ip or target_ip in ("0.0.0.0", "::"):
        return None
    return {"src_mac": src_mac, "src_ip": src_ip, "target_ip": target_ip}


def parse_sweep_alert(rec):
    """An alert for one of the tuned sweep SIDs -> {src_ip, sid}, else None."""
    if not isinstance(rec, dict) or rec.get("event_type") != "alert":
        return None
    alert = rec.get("alert")
    if not isinstance(alert, dict):
        return None
    try:
        sid = int(alert.get("signature_id"))
    except (TypeError, ValueError):
        return None
    if sid not in SWEEP_SIDS:
        return None
    src_ip = (rec.get("src_ip") or "").strip()
    if not src_ip:
        return None
    return {"src_ip": src_ip, "sid": sid}


# ── Rolling per-source state. State is a plain dict owned by the caller, so this
#    core stays pure and the module can persist/restore it however it likes.
def record_probe(state, probe, now):
    """Record one ARP probe into per-source rolling state. Prunes as it goes."""
    src = probe.get("src_mac")
    tip = probe.get("target_ip")
    if not src or not tip:
        return
    bucket = state.setdefault(src, {})
    bucket[tip] = now
    _prune(bucket, now, ARP_FANOUT_WINDOW_S)


def _prune(bucket, now, window):
    cutoff = now - window
    for k in [k for k, ts in bucket.items() if ts < cutoff]:
        del bucket[k]


def fanout_count(state, src, now):
    """Distinct in-window ARP targets for a source. 0 for an unknown source."""
    bucket = state.get(src)
    if not bucket:
        return 0
    _prune(bucket, now, ARP_FANOUT_WINDOW_S)
    return len(bucket)


def is_arp_fanout(state, src, now):
    return fanout_count(state, src, now) >= ARP_FANOUT_DISTINCT_IPS


def record_mdns(state, src, now):
    if not src:
        return
    lst = state.setdefault(src, [])
    lst.append(now)
    cutoff = now - MDNS_FLOOD_WINDOW_S
    lst[:] = [t for t in lst if t >= cutoff]


def is_mdns_flood(state, src, now):
    lst = state.get(src)
    if not lst:
        return False
    cutoff = now - MDNS_FLOOD_WINDOW_S
    return sum(1 for t in lst if t >= cutoff) >= MDNS_FLOOD_COUNT


# ── Classification. Points model, deliberately simple and explainable:
#    each fired signal +1; a NEW device that fired any signal +1.
#    1 -> info (investigate), 2 -> high, 3+ -> critical (isolate-worthy).
def classify(summary):
    """Verdict dict for one source's current signal summary, or None.

    `summary`: {src, fanout, sweep, mdns_flood, is_new, source?}. A NEW device that
    fired nothing is NOT a finding — newness only ever raises an existing signal.
    """
    fired = []
    if summary.get("fanout"):
        fired.append(SIG_ARP_FANOUT)
    if summary.get("sweep"):
        fired.append(SIG_PORT_SWEEP)
    if summary.get("mdns_flood"):
        fired.append(SIG_MDNS_FLOOD)
    if not fired:
        return None

    is_new = bool(summary.get("is_new"))
    score = len(fired) + (1 if is_new else 0)

    if score >= 3:
        severity = SEV_CRITICAL
    elif score == 2:
        severity = SEV_HIGH
    else:
        severity = SEV_INFO

    parts = []
    if SIG_ARP_FANOUT in fired:
        parts.append("ARP fan-out to many distinct LAN addresses")
    if SIG_PORT_SWEEP in fired:
        parts.append("a host-defence port-sweep alert")
    if SIG_MDNS_FLOOD in fired:
        parts.append("multicast-discovery flooding")
    reason = "%s exhibited %s" % (summary.get("src", "a device"), "; ".join(parts))
    if is_new:
        reason += " -- and is a NEW device, first seen only recently, with no normal warm-up"

    return {
        "signal": PROBE_SCAN,
        "severity": severity,
        "score": score,
        "signals": fired,
        "confidence": CONF_OBSERVED,   # the broadcast signals themselves are fully seen ...
        "coverage_note": get_coverage()["note"],  # ... but the extent may exceed what we see
        "reason": reason,
        "src": summary.get("src"),
        "is_new": is_new,
        # Actor/source seam. "passive" today; Option B sets "active_monitoring" when a
        # finding used interception-derived visibility. Never renames the detector.
        "source": summary.get("source", "passive"),
        "actor": summary.get("actor"),
    }


def get_coverage():
    """The honesty contract. What this detector can and cannot see, so no caller
    treats a quiet result as proof of a clean network."""
    return {
        "broadcast_visible": True,
        "targeted_unicast_visible": False,
        "note": ("Broadcast-visible probing (ARP fan-out, mDNS/SSDP flood) and broad "
                 "sweeps that include this appliance are seen. A targeted unicast probe "
                 "A->B on a switched L2 network, where the attacker knows B's MAC and "
                 "never touches this appliance, is NOT seen. Coverage is inversely "
                 "proportional to attacker precision; closing the gap needs active ARP "
                 "monitoring or VLAN hardware, not threshold tuning."),
    }


# ── Self-test: prove the instrument produces BOTH answers, in the production path.
#    A scan-and-spread detector on a quiet LAN is silent, and so is a broken one.
def selftest():
    """(ok, detail). Runs on start and each cycle -- known-scan MUST fire,
    known-quiet MUST NOT, so a detector that can only ever say one thing is caught
    before it vouches for anything real."""
    # Known-bad: a source fanning out past the threshold must classify.
    st = {}
    src = "00:00:5e:00:53:aa"      # RFC 5737 / RFC 7042 documentation MAC space
    for i in range(ARP_FANOUT_DISTINCT_IPS):
        record_probe(st, {"src_mac": src, "target_ip": "198.51.100.%d" % i}, now=0.0)
    if not is_arp_fanout(st, src, now=0.0):
        return False, "canary: a source over the fan-out threshold did not register"
    v = classify({"src": src, "fanout": True, "sweep": False, "mdns_flood": False,
                  "is_new": True})
    if v is None or v["severity"] != SEV_HIGH:
        return False, "canary: new-device fan-out did not classify as high"

    # Known-good: no signals -> no finding, and a new-but-quiet device -> no finding.
    if classify({"src": src, "fanout": False, "sweep": False, "mdns_flood": False,
                 "is_new": True}) is not None:
        return False, "canary: a quiet new device was reported as a finding"

    # Known-good: one under threshold does not trip fan-out.
    st2 = {}
    for i in range(ARP_FANOUT_DISTINCT_IPS - 1):
        record_probe(st2, {"src_mac": src, "target_ip": "203.0.113.%d" % i}, now=0.0)
    if is_arp_fanout(st2, src, now=0.0):
        return False, "canary: fan-out fired one target under the threshold"

    return True, "ok"
