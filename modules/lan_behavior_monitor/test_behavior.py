"""Tests for behavior.py — the PURE scan-and-spread core.

Test-first, mutation-proven. Every check exercises a real classification path; the
mutation matrix at the bottom of the build log proves each signal and threshold is
load-bearing (disable it, a check goes red).

WHAT IS AND IS NOT PROVEN HERE. These tests prove the DETECTION LOGIC over parsed
events: fan-out windowing, the four signals, scoring, severity, and the honest
coverage statement. They do NOT prove on-wire capture — that ceiling (targeted
unicast A->B is invisible on a flat L2 network) is a topology fact stated in the
module docstring and get_coverage(), not something a unit test can move.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import behavior as B  # noqa: E402

_fail = []
_count = 0
EXPECTED_CHECKS = 38


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-70s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


# --------------------------------------------------------------------------
# 1. parse_arp_probe — KEEPS the request's target IP (the fan-out signal),
#    unlike arp_watch.parse_eve_event which deliberately drops it.
# --------------------------------------------------------------------------

def _arp(opcode, src_mac, src_ip, dest_ip):
    return {"event_type": "arp", "arp": {
        "opcode": opcode, "src_mac": src_mac, "src_ip": src_ip,
        "dest_ip": dest_ip, "dest_mac": "00:00:00:00:00:00"}}


def test_parse_arp_probe():
    print("\n[parse_arp_probe: a request carries a target IP; a reply/self-query does not]")
    p = B.parse_arp_probe(_arp("request", "aa:bb:cc:dd:ee:01", "192.0.2.50", "192.0.2.77"))
    check("request parses", p is not None, True)
    check("keeps src_mac", p["src_mac"], "aa:bb:cc:dd:ee:01")
    check("keeps the TARGET ip (the fan-out signal)", p["target_ip"], "192.0.2.77")

    # A reply is not a probe (a scanner announces nothing; it asks).
    check("reply is not a probe", B.parse_arp_probe(
        _arp("reply", "aa:bb:cc:dd:ee:01", "192.0.2.50", "192.0.2.50")), None)
    # A request for 0.0.0.0 / empty target is an ARP probe/announcement, not a scan target.
    check("null target dropped", B.parse_arp_probe(
        _arp("request", "aa:bb:cc:dd:ee:01", "192.0.2.50", "0.0.0.0")), None)
    check("non-arp event dropped", B.parse_arp_probe({"event_type": "dns"}), None)


# --------------------------------------------------------------------------
# 2. Fan-out windowing — distinct targets within the window, pruned by age.
# --------------------------------------------------------------------------

def test_fanout_counts_distinct_targets():
    print("\n[fan-out: DISTINCT targets, not raw request count]")
    st = {}
    src = "aa:bb:cc:dd:ee:02"
    # 5 requests, but only 3 distinct targets -> distinct count is 3.
    for tip in ("10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.3", "10.0.0.2"):
        B.record_probe(st, {"src_mac": src, "target_ip": tip}, now=1000.0)
    check("distinct target count", B.fanout_count(st, src, now=1000.0), 3)
    check("unknown source is 0, not error", B.fanout_count(st, "zz:zz", now=1000.0), 0)


def test_fanout_window_prunes_old_targets():
    print("\n[fan-out window: targets older than the window fall out]")
    st = {}
    src = "aa:bb:cc:dd:ee:03"
    B.record_probe(st, {"src_mac": src, "target_ip": "10.0.0.1"}, now=1000.0)
    B.record_probe(st, {"src_mac": src, "target_ip": "10.0.0.2"}, now=1000.0)
    # far in the future: both prior targets are now outside ARP_FANOUT_WINDOW_S.
    future = 1000.0 + B.ARP_FANOUT_WINDOW_S + 1
    B.record_probe(st, {"src_mac": src, "target_ip": "10.0.0.9"}, now=future)
    check("only the in-window target remains", B.fanout_count(st, src, now=future), 1)


def test_fanout_threshold_is_load_bearing():
    print("\n[a source at/over the distinct-IP threshold is flagged; under it is not]")
    st = {}
    src = "aa:bb:cc:dd:ee:04"
    for i in range(B.ARP_FANOUT_DISTINCT_IPS):
        B.record_probe(st, {"src_mac": src, "target_ip": "10.1.%d.%d" % (i // 250, i % 250)},
                       now=2000.0)
    check("count reached the threshold", B.fanout_count(st, src, now=2000.0),
          B.ARP_FANOUT_DISTINCT_IPS)
    check("at threshold -> fan-out signal true",
          B.is_arp_fanout(st, src, now=2000.0), True)

    st2 = {}
    for i in range(B.ARP_FANOUT_DISTINCT_IPS - 1):
        B.record_probe(st2, {"src_mac": src, "target_ip": "10.2.%d.%d" % (i // 250, i % 250)},
                       now=2000.0)
    check("one under threshold -> no signal", B.is_arp_fanout(st2, src, now=2000.0), False)


# --------------------------------------------------------------------------
# 3. mDNS/SSDP flood + sweep-alert parsing
# --------------------------------------------------------------------------

def test_parse_sweep_alert():
    print("\n[sweep alert: only the tuned host-defence SIDs count]")
    ev = {"event_type": "alert", "src_ip": "192.0.2.50",
          "alert": {"signature_id": 1000002, "signature": "SYN sweep"}}
    a = B.parse_sweep_alert(ev)
    check("tuned sweep sid parses", a is not None and a["src_ip"], "192.0.2.50")
    # An unrelated alert sid is not a sweep signal.
    ev2 = {"event_type": "alert", "src_ip": "192.0.2.50",
           "alert": {"signature_id": 2000000, "signature": "something else"}}
    check("non-sweep sid ignored", B.parse_sweep_alert(ev2), None)
    check("dns event is not a sweep alert", B.parse_sweep_alert({"event_type": "dns"}), None)


def test_mdns_flood_rate():
    print("\n[mDNS flood: high multicast-discovery rate from one source]")
    st = {}
    src = "192.0.2.60"
    for _ in range(B.MDNS_FLOOD_COUNT):
        B.record_mdns(st, src, now=3000.0)
    check("at flood rate -> signal", B.is_mdns_flood(st, src, now=3000.0), True)
    st2 = {}
    for _ in range(B.MDNS_FLOOD_COUNT - 1):
        B.record_mdns(st2, src, now=3000.0)
    check("under flood rate -> no signal", B.is_mdns_flood(st2, src, now=3000.0), False)


# --------------------------------------------------------------------------
# 4. classify — the scoring model. Points: each signal +1; a NEW device that
#    fired any signal +1. 1->info(investigate), 2->high, 3+->critical.
# --------------------------------------------------------------------------

def test_classify_no_signals_is_none():
    print("\n[nothing firing -> None, never a finding]")
    check("no signals", B.classify(
        {"src": "x", "fanout": False, "sweep": False, "mdns_flood": False,
         "is_new": False}), None)
    # A NEW device that is doing nothing noisy is NOT a finding on its own.
    check("new but quiet -> None", B.classify(
        {"src": "x", "fanout": False, "sweep": False, "mdns_flood": False,
         "is_new": True}), None)


def test_classify_single_signal_is_investigate():
    print("\n[one signal on an established device -> info/investigate]")
    v = B.classify({"src": "192.0.2.50", "fanout": True, "sweep": False,
                    "mdns_flood": False, "is_new": False})
    check("verdict raised", v is not None, True)
    check("signal type", v["signal"], B.PROBE_SCAN)
    check("severity info", v["severity"], B.SEV_INFO)
    check("score 1", v["score"], 1)
    check("names the fan-out reason", "fan-out" in v["reason"].lower()
          or "distinct" in v["reason"].lower(), True)


def test_classify_new_device_fanning_out_is_high():
    print("\n[the headline pattern: NEW device immediately fanning out -> high]")
    v = B.classify({"src": "192.0.2.50", "fanout": True, "sweep": False,
                    "mdns_flood": False, "is_new": True})
    check("score 2 (fanout + new)", v["score"], 2)
    check("severity high", v["severity"], B.SEV_HIGH)
    check("reason notes the device is new", "new" in v["reason"].lower(), True)


def test_classify_new_fanout_and_sweep_is_critical():
    print("\n[new + fan-out + sweep -> critical, the isolate-worthy case]")
    v = B.classify({"src": "192.0.2.50", "fanout": True, "sweep": True,
                    "mdns_flood": False, "is_new": True})
    check("score 3", v["score"], 3)
    check("severity critical", v["severity"], B.SEV_CRITICAL)


def test_classify_two_signals_established_device_is_high():
    print("\n[two signals even on an established device -> high]")
    v = B.classify({"src": "192.0.2.50", "fanout": True, "sweep": True,
                    "mdns_flood": False, "is_new": False})
    check("score 2", v["score"], 2)
    check("severity high", v["severity"], B.SEV_HIGH)


def test_classify_carries_source_tag_seam():
    print("\n[every verdict carries a source tag seam for Option B (active_monitoring)]")
    v = B.classify({"src": "192.0.2.50", "fanout": True, "sweep": False,
                    "mdns_flood": False, "is_new": False})
    check("default source is passive", v["source"], "passive")
    v2 = B.classify({"src": "192.0.2.50", "fanout": True, "sweep": False,
                     "mdns_flood": False, "is_new": False, "source": "active_monitoring"})
    check("source tag honored when supplied", v2["source"], "active_monitoring")


# --------------------------------------------------------------------------
# 5. Coverage honesty + selftest (production-path canary).
# --------------------------------------------------------------------------

def test_coverage_states_the_unicast_gap():
    print("\n[get_coverage names the targeted-unicast blind spot plainly]")
    cov = B.get_coverage()
    check("declares broadcast-visible signals seen", cov["broadcast_visible"], True)
    check("declares targeted unicast NOT seen", cov["targeted_unicast_visible"], False)
    check("carries a human reason mentioning L2/switched",
          any(w in cov["note"].lower() for w in ("switch", "l2", "unicast")), True)


def test_selftest_proves_both_answers():
    print("\n[selftest: a known scan fires, known-quiet does not — runs in production path]")
    ok, detail = B.selftest()
    check("selftest passes", ok, True)
    check("selftest returns a detail string", isinstance(detail, str), True)


if __name__ == "__main__":
    print("=" * 74)
    print("behavior.py — pure scan-and-spread core")
    print("=" * 74)
    test_parse_arp_probe()
    test_fanout_counts_distinct_targets()
    test_fanout_window_prunes_old_targets()
    test_fanout_threshold_is_load_bearing()
    test_parse_sweep_alert()
    test_mdns_flood_rate()
    test_classify_no_signals_is_none()
    test_classify_single_signal_is_investigate()
    test_classify_new_device_fanning_out_is_high()
    test_classify_new_fanout_and_sweep_is_critical()
    test_classify_two_signals_established_device_is_high()
    test_classify_carries_source_tag_seam()
    test_coverage_states_the_unicast_gap()
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
