"""Tests for post_detection.py — the PURE post-detection egress correlator.

Stage 1 of post_detection_egress: correlate a detection event (a new finding about
device A) with A's subsequent DNS-anomaly behaviour within a bounded window. The
timing is the signal: behaviour changing RIGHT AFTER a detection is what elevates it.

WHAT IS AND IS NOT PROVEN HERE. This proves the correlation logic: window bounds,
direction (egress must follow detection), device match, egress-type gating, and the
no-self-correlation rule. It does NOT prove raw internet-egress visibility — the
appliance cannot see a device's direct egress on flat L2, so the correlated signal is
DNS-intent (the appliance is the resolver), stated in build_incident's confidence.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import post_detection as P  # noqa: E402

_fail = []
_count = 0
EXPECTED_CHECKS = 27

WIN = P.CORRELATION_WINDOW_S
DEV = "192.0.2.50"


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-72s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def _sig(sid, typ, ips, ts, source=None):
    return {"id": sid, "type": typ, "ips": set(ips), "ts": ts,
            "source": source or ("anomaly_incidents:%d" % sid)}


def _det(ts, ip=DEV, source="malware_findings:1"):
    return {"device_ip": ip, "ts": ts, "source": source}


# --------------------------------------------------------------------------
def test_no_signals_is_none():
    print("\n[no egress signals -> no correlation]")
    check("empty signal list", P.correlate(_det(1000.0), [], WIN), None)


def test_valid_correlation():
    print("\n[detection then a DNS anomaly for the same device within the window -> match]")
    det = _det(1000.0)
    sig = _sig(7, "dns_exfiltration", [DEV], 1000.0 + WIN / 2)
    got = P.correlate(det, [sig], WIN)
    check("matched the signal", got is not None and got["id"], 7)


def test_signal_outside_window_is_none():
    print("\n[a DNS anomaly beyond the window is not related]")
    det = _det(1000.0)
    sig = _sig(7, "dns_exfiltration", [DEV], 1000.0 + WIN + 1)
    check("outside window -> None", P.correlate(det, [sig], WIN), None)


def test_signal_before_detection_is_none():
    print("\n[egress must FOLLOW the detection, not precede it]")
    det = _det(1000.0)
    sig = _sig(7, "dns_exfiltration", [DEV], 1000.0 - 1)
    check("pre-detection signal -> None", P.correlate(det, [sig], WIN), None)


def test_wrong_device_is_none():
    print("\n[a DNS anomaly for a DIFFERENT device does not correlate]")
    det = _det(1000.0)
    sig = _sig(7, "dns_exfiltration", ["192.0.2.99"], 1000.0 + 10)
    check("other device -> None", P.correlate(det, [sig], WIN), None)


def test_wrong_signal_type_is_none():
    print("\n[only egress-class incident types count as the reach-out signal]")
    det = _det(1000.0)
    sig = _sig(7, "some_other_type", [DEV], 1000.0 + 10)
    check("non-egress type -> None", P.correlate(det, [sig], WIN), None)
    check("the egress types are exactly dns_exfiltration + volume_spike",
          sorted(P.EGRESS_SIGNAL_TYPES), ["dns_exfiltration", "volume_spike"])


def test_no_self_correlation():
    print("\n[a detection that IS an anomaly incident must not correlate with itself]")
    # detection sourced from anomaly_incidents:7; a signal with the SAME source is itself.
    det = _det(1000.0, source="anomaly_incidents:7")
    same = _sig(7, "dns_exfiltration", [DEV], 1000.0 + 10, source="anomaly_incidents:7")
    check("self-correlation refused", P.correlate(det, [same], WIN), None)
    # but a DIFFERENT anomaly incident for the same device DOES correlate (escalation)
    other = _sig(8, "dns_exfiltration", [DEV], 1000.0 + 10, source="anomaly_incidents:8")
    check("a different incident still correlates", P.correlate(det, [other], WIN)["id"], 8)


def test_earliest_match_wins():
    print("\n[when several signals qualify, the earliest post-detection one is chosen]")
    det = _det(1000.0)
    sigs = [_sig(9, "dns_exfiltration", [DEV], 1000.0 + 300),
            _sig(8, "volume_spike", [DEV], 1000.0 + 60),
            _sig(7, "dns_exfiltration", [DEV], 1000.0 + 200)]
    check("earliest qualifying signal chosen", P.correlate(det, sigs, WIN)["id"], 8)


def test_window_is_a_documented_constant():
    print("\n[the correlation window is a named constant, not a magic number]")
    check("CORRELATION_WINDOW_S is 600s (10 min) by default", P.CORRELATION_WINDOW_S, 600)


def test_build_incident_shape():
    print("\n[build_incident: namespaced target, evidence linking both sides, honest confidence]")
    det = _det(1000.0, source="malware_findings:12")
    sig = _sig(7, "dns_exfiltration", [DEV], 1000.0 + 120)
    inc = P.build_incident(det, sig, now=1000.0 + 130)
    check("incident_type is post_detection_egress", inc["incident_type"], P.POST_DETECTION_TYPE)
    check("offending_target is namespaced (cannot collide with a domain/IP target)",
          inc["offending_target"].startswith("pde:"), True)
    check("target carries the device", DEV in inc["offending_target"], True)
    check("evidence names the detection source", inc["evidence"]["detection"], "malware_findings:12")
    check("evidence names the egress signal", inc["evidence"]["egress_signal"], "anomaly_incidents:7")
    check("evidence records the egress type", inc["evidence"]["egress_type"], "dns_exfiltration")
    check("device ip recorded", inc["device_ip"], DEV)
    check("confidence states DNS-intent, not raw egress",
          "dns" in inc["confidence_note"].lower() and "egress" in inc["confidence_note"].lower(),
          True)
    check("reason mentions the post-detection timing", "after" in inc["reason"].lower(), True)
    check("a score is assigned", inc["score"] > 0, True)


def test_discovery_signal_correlates_stage2():
    print("\n[stage 2: a lan_probe_scan (discovery) after a detection also correlates]")
    det = _det(1000.0, source="malware_findings:5")
    sig = {"id": 3, "type": "lan_probe_scan", "ips": {DEV}, "ts": 1000.0 + 90,
           "source": "lan_behavior_findings:3"}
    got = P.correlate(det, [sig], WIN)
    check("discovery signal correlates", got is not None and got["id"], 3)
    check("lan_probe_scan is a reach-out type", "lan_probe_scan" in P.REACH_OUT_TYPES, True)
    inc = P.build_incident(det, sig, now=1000.0 + 100)
    check("discovery scores highest (host detection + active scanning)", inc["score"], 90)
    check("egress-only set still excludes discovery (anomaly scan can't ingest it)",
          "lan_probe_scan" in P.EGRESS_SIGNAL_TYPES, False)


def test_selftest_proves_both_answers():
    print("\n[selftest: a real correlation matches, a non-correlation does not]")
    ok, detail = P.selftest()
    check("selftest passes", ok, True)
    check("selftest returns detail", isinstance(detail, str), True)


if __name__ == "__main__":
    print("=" * 74)
    print("post_detection.py — post-detection egress correlator (stage 1)")
    print("=" * 74)
    test_no_signals_is_none()
    test_valid_correlation()
    test_signal_outside_window_is_none()
    test_signal_before_detection_is_none()
    test_wrong_device_is_none()
    test_wrong_signal_type_is_none()
    test_no_self_correlation()
    test_earliest_match_wins()
    test_window_is_a_documented_constant()
    test_build_incident_shape()
    test_discovery_signal_correlates_stage2()
    test_selftest_proves_both_answers()
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
