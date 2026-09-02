"""Post-detection egress correlation — PURE core. No DB, no Flask, no filesystem.

STAGE 1 of post_detection_egress. The question: a managed device A was just flagged
by a finding (malware, LAN-integrity, an anomaly incident) -- is A now REACHING OUT?
The elevating signal is TIMING: A's DNS/behaviour changing shortly AFTER the detection
is more alarming than the same behaviour in isolation.

⚠ WHAT "EGRESS" MEANS HERE, HONESTLY. On a flat switched L2 network a non-gateway
appliance cannot see a device's direct internet egress -- that traffic goes
device->router, never touching the appliance (measured 2026-09-02). What the appliance
DOES see is the device's DNS queries, because it is the resolver. So the correlated
"egress" signal is DNS-intent (dns_exfiltration / volume_spike), NOT raw flow. This
detector adds CORRELATION and TIMING over signals other detectors already produce; it
is not new sensor visibility. build_incident()'s confidence_note carries this so the
incident cannot be misread as "watched the device exfiltrate".

Stage 2 (separate) adds lan_behavior_findings (discovery/scan) as a second reach-out
signal, reusing that module rather than re-tailing eve.json.
"""

# The correlation window: how long after a detection a behaviour change still counts as
# related. A compromised device typically begins beaconing/lateral movement within
# minutes, so 10 minutes is long enough to catch the change and short enough that
# unrelated later activity is not spuriously tied to the finding. Named constant,
# adjustable if real data suggests otherwise -- same discipline as lan_behavior's
# thresholds.
CORRELATION_WINDOW_S = 600

# The types that count as a "reach-out" signal, correlated against a detection.
#   DNS-intent (anomaly_detection's own DNS analysis): dns_exfiltration, volume_spike.
#   DISCOVERY (stage 2, reused from lan_behavior_monitor): lan_probe_scan -- the device,
#     after being flagged, is now actively scanning the LAN. Host/file detection PLUS
#     active discovery is the strongest post-detection shape.
# EGRESS_SIGNAL_TYPES stays the DNS-only subset used to scan anomaly_incidents (so a
# post_detection_egress row can never be a signal); REACH_OUT_TYPES is the full set
# correlate() accepts, including the discovery signal that lives in lan_behavior_findings.
EGRESS_SIGNAL_TYPES = frozenset({"dns_exfiltration", "volume_spike"})
DISCOVERY_SIGNAL_TYPES = frozenset({"lan_probe_scan"})
REACH_OUT_TYPES = EGRESS_SIGNAL_TYPES | DISCOVERY_SIGNAL_TYPES

POST_DETECTION_TYPE = "post_detection_egress"

SEV_HIGH = "high"


def correlate(detection, egress_signals, window=CORRELATION_WINDOW_S):
    """Return the egress signal that correlates with a detection, or None.

    `detection`     : {"device_ip", "ts", "source"}   source e.g. "malware_findings:12"
    `egress_signals`: [{"id", "type", "ips", "ts", "source"}, ...]
    A signal correlates iff: it is an egress type; it covers the detection's device;
    it occurred AT OR AFTER the detection and within `window`; and it is not the
    detection itself (same source -- an anomaly incident must not correlate with
    itself). When several qualify, the EARLIEST post-detection one is returned.
    """
    dev = detection.get("device_ip")
    dts = detection.get("ts")
    dsrc = detection.get("source")
    if not dev or dts is None:
        return None
    best = None
    for s in egress_signals:
        if s.get("type") not in REACH_OUT_TYPES:
            continue
        if s.get("source") == dsrc:          # no self-correlation
            continue
        if dev not in (s.get("ips") or ()):
            continue
        sts = s.get("ts")
        if sts is None or sts < dts or sts > dts + window:
            continue
        if best is None or sts < best.get("ts"):
            best = s
    return best


def build_incident(detection, signal, now):
    """Assemble the post_detection_egress incident payload from a correlation.

    offending_target is NAMESPACED ("pde:<device>") so it cannot collide with a
    domain or bare-IP target used by other incident types under the shared
    one-open-per-target index.
    """
    dev = detection["device_ip"]
    return {
        "incident_type": POST_DETECTION_TYPE,
        "offending_target": "pde:%s" % dev,
        "device_ip": dev,
        "score": _score(detection, signal),
        "severity": SEV_HIGH,
        "evidence": {
            "detection": detection.get("source"),
            "detection_ts": detection.get("ts"),
            "egress_signal": signal.get("source"),
            "egress_type": signal.get("type"),
            "egress_ts": signal.get("ts"),
            "window_s": CORRELATION_WINDOW_S,
        },
        "reason": ("device %s was flagged (%s) and then showed %s within %d minutes "
                   "-- a behaviour change AFTER a detection, which is more significant "
                   "than either signal alone"
                   % (dev, detection.get("source"), signal.get("type"),
                      CORRELATION_WINDOW_S // 60)),
        # Visibility honesty, carried onto the incident. This is DNS-intent seen by the
        # resolver, not observed raw egress -- see the module docstring's ceiling note.
        "confidence_note": ("correlated via DNS-intent (this appliance is the resolver); "
                            "raw device egress is not visible on a flat L2 network, so "
                            "this reflects reach-out INTENT, not confirmed exfiltration"),
        "actor": "detector:post_detection_egress",
        "now": now,
    }


def _score(detection, signal):
    """A post-detection correlation is inherently high-signal: two independent
    detectors agreeing on one device within a short window. Base high; active
    discovery (lan_probe_scan) is the strongest reach-out, dns_exfiltration next."""
    base = 70
    t = signal.get("type")
    if t == "lan_probe_scan":
        base += 20   # host/file detection + active LAN scanning
    elif t == "dns_exfiltration":
        base += 15
    return base


def selftest():
    """(ok, detail). Prove the correlator produces BOTH answers -- a real correlation
    matches, a non-correlation does not -- so an instrument that can only ever say one
    thing is caught before it vouches for anything real."""
    det = {"device_ip": "198.51.100.7", "ts": 1000.0, "source": "malware_findings:1"}
    good = {"id": 1, "type": "dns_exfiltration", "ips": {"198.51.100.7"},
            "ts": 1120.0, "source": "anomaly_incidents:1"}
    if correlate(det, [good]) is None:
        return False, "canary: a valid post-detection correlation did not match"
    # wrong device must NOT match
    bad = {"id": 2, "type": "dns_exfiltration", "ips": {"203.0.113.9"},
           "ts": 1120.0, "source": "anomaly_incidents:2"}
    if correlate(det, [bad]) is not None:
        return False, "canary: correlated a signal for a different device"
    # pre-detection signal must NOT match (direction)
    early = {"id": 3, "type": "dns_exfiltration", "ips": {"198.51.100.7"},
             "ts": 500.0, "source": "anomaly_incidents:3"}
    if correlate(det, [early]) is not None:
        return False, "canary: correlated a signal that preceded the detection"
    return True, "ok"
