"""ARP-spoofing pure core. No DB, no eve.json, no /proc.

The load-bearing cases are the NON-alerts. An ARP detector that flags a spoofer is
easy; one that does not flag every new device joining the network, every DHCP
lease turnover and every NIC replacement is the product problem. Each suppression
below also proves its DERIVATION -- the same input with the suppressing property
removed must alert -- so a case cannot pass because some earlier gate caught it.

Fixtures use the REAL Suricata eve schema, captured 2026-08-30 by running Suricata
offline against a crafted ARP pcap rather than transcribed from documentation:
addresses live inside the `arp` object, and gratuitous ARP is `opcode: reply` with
`src_ip == dest_ip`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import arp_watch as aw

_fail = []
_count = 0
EXPECTED_CHECKS = 49

GW = "192.0.2.1"
HOST = "192.0.2.50"
MAC_A = "00:00:5e:00:53:01"
MAC_B = "00:00:5e:00:53:66"
MAC_C = "00:00:5e:00:53:77"


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-66s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def ev(opcode, src_ip, src_mac, dest_ip="192.0.2.99", dest_mac="00:00:00:00:00:00"):
    return {"event_type": "arp", "timestamp": "2026-08-30T10:00:00-0500",
            "arp": {"hw_type": "ethernet", "proto_type": "ipv4", "opcode": opcode,
                    "src_ip": src_ip, "src_mac": src_mac,
                    "dest_ip": dest_ip, "dest_mac": dest_mac}}


def test_parse_real_schema():
    print("\n[the VERIFIED eve schema -- addresses live inside `arp`, not top level]")
    o = aw.parse_eve_event(ev("request", GW, MAC_A))
    check("request parses", o is not None, True)
    check("ip comes from arp.src_ip", o["ip"], GW)
    check("mac comes from arp.src_mac", o["mac"], MAC_A)
    check("broadcast request is fully observed", o["confidence"], aw.CONF_OBSERVED)
    check("source is tagged", o["source"], "suricata_arp")

    g = aw.parse_eve_event(ev("reply", GW, MAC_B, dest_ip=GW, dest_mac="ff:ff:ff:ff:ff:ff"))
    check("gratuitous recognised (src_ip == dest_ip)", g["gratuitous"], True)
    check("gratuitous is fully observed (broadcast)", g["confidence"], aw.CONF_OBSERVED)

    d = aw.parse_eve_event(ev("reply", HOST, MAC_A, dest_ip=GW, dest_mac=MAC_B))
    check("directed reply is NOT gratuitous", d["gratuitous"], False)
    check("directed reply is only PARTIAL -- we may not see them all",
          d["confidence"], aw.CONF_PARTIAL)


def test_parse_rejections():
    print("\n[only the SENDER fields assert a binding; junk must not become one]")
    check("non-arp event -> None",
          aw.parse_eve_event({"event_type": "dhcp", "arp": {"src_ip": GW, "src_mac": MAC_A}}), None)
    check("missing arp object -> None", aw.parse_eve_event({"event_type": "arp"}), None)
    check("arp not a dict -> None",
          aw.parse_eve_event({"event_type": "arp", "arp": "x"}), None)
    check("absent src_mac -> None", aw.parse_eve_event(ev("request", GW, "")), None)
    check("all-zero src_mac -> None",
          aw.parse_eve_event(ev("request", GW, "00:00:00:00:00:00")), None)
    check("broadcast src_mac -> None",
          aw.parse_eve_event(ev("request", GW, "ff:ff:ff:ff:ff:ff")), None)
    check("absent src_ip -> None", aw.parse_eve_event(ev("request", "", MAC_A)), None)
    check("None -> None", aw.parse_eve_event(None), None)
    check("mac is normalised to lowercase",
          aw.parse_eve_event(ev("request", GW, MAC_A.upper()))["mac"], MAC_A)


def test_first_sighting_never_alerts():
    print("\n[every device on the network is new ONCE -- that is not an attack]")
    o = aw.parse_eve_event(ev("request", GW, MAC_A))
    check("no prior -> no verdict", aw.classify(o, None, gateways=[GW]), None)
    check("prior with same mac -> no verdict",
          aw.classify(o, {"mac": MAC_A}, gateways=[GW]), None)
    check("prior with empty mac -> no verdict (nothing to compare)",
          aw.classify(o, {"mac": None}, gateways=[GW]), None)
    # DERIVATION: a genuine change on the same input DOES alert.
    check("CONTROL: a different prior mac DOES alert",
          aw.classify(o, {"mac": MAC_B}, gateways=[GW]) is not None, True)


def test_gateway_takeover_is_critical():
    print("\n[the gateway moving is the on-path attack -- top severity]")
    o = aw.parse_eve_event(ev("reply", GW, MAC_B, dest_ip=GW, dest_mac="ff:ff:ff:ff:ff:ff"))
    v = aw.classify(o, {"mac": MAC_A}, gateways=[GW])
    check("signal kind", v["signal"], aw.GATEWAY_TAKEOVER)
    check("severity critical", v["severity"], aw.SEV_CRITICAL)
    check("names both addresses", MAC_A in v["reason"] and MAC_B in v["reason"], True)
    check("carries the previous mac for correlation", v["previous_mac"], MAC_A)
    check("subject is the contested IP", v["subject_ip"], GW)
    check("subject_mac is the CLAIMANT, not the victim", v["subject_mac"], MAC_B)


def test_severity_derives_from_gateway_set():
    print("\n[CONTROL: severity is derived, not hardcoded -- same event, ordinary host]")
    o = aw.parse_eve_event(ev("reply", HOST, MAC_B, dest_ip=HOST, dest_mac="ff:ff:ff:ff:ff:ff"))
    v = aw.classify(o, {"mac": MAC_A}, gateways=[GW])
    check("non-gateway change is a binding change", v["signal"], aw.BINDING_CHANGE)
    check("...and HIGH, not critical", v["severity"], aw.SEV_HIGH)
    check("an EMPTY gateway set degrades severity, never suppresses the finding",
          aw.classify(o, {"mac": MAC_A}, gateways=[])["severity"], aw.SEV_HIGH)
    # DERIVATION: the same address IS critical when it is in the gateway set.
    check("CONTROL: same address, listed as gateway -> critical",
          aw.classify(o, {"mac": MAC_A}, gateways=[HOST])["severity"], aw.SEV_CRITICAL)


def test_flapping():
    print("\n[a binding that oscillates is two hosts contesting one address]")
    o = aw.parse_eve_event(ev("reply", HOST, MAC_B, dest_ip=HOST, dest_mac="ff:ff:ff:ff:ff:ff"))
    prior = {"mac": MAC_A, "change_count": aw.FLAP_CHANGES, "last_change_ts": 1000.0}
    v = aw.classify(o, prior, gateways=[GW], now=1000.0 + 10)
    check("rapid repeat changes -> flap", v["signal"], aw.BINDING_FLAP)
    check("flap is critical", v["severity"], aw.SEV_CRITICAL)
    # DERIVATION: identical counts, but the changes are old -> ordinary change.
    old = aw.classify(o, prior, gateways=[GW], now=1000.0 + aw.FLAP_WINDOW_SECONDS + 60)
    check("CONTROL: the same change count OUTSIDE the window is not a flap",
          old["signal"], aw.BINDING_CHANGE)
    check("a single change is never a flap",
          aw.classify(o, {"mac": MAC_A, "change_count": 0, "last_change_ts": 0},
                      gateways=[GW], now=1000.0)["signal"], aw.BINDING_CHANGE)


def test_multi_claim():
    print("\n[one MAC claiming many addresses is an impersonator]")
    many = ["192.0.2.%d" % i for i in range(2, 2 + aw.MULTI_CLAIM_THRESHOLD)]
    v = aw.classify_multi_claim(MAC_C, many)
    check("at threshold -> flagged", v["signal"], aw.MAC_MULTI_CLAIM)
    check("confidence is PARTIAL -- we may have seen only some claims",
          v["confidence"], aw.CONF_PARTIAL)
    check("below threshold -> None",
          aw.classify_multi_claim(MAC_C, many[:-1]), None)
    check("duplicates do not inflate the count",
          aw.classify_multi_claim(MAC_C, [many[0]] * 10), None)
    check("empty -> None", aw.classify_multi_claim(MAC_C, []), None)


def test_proc_arp():
    print("\n[/proc/net/arp: this host's OWN cache, never full confidence]")
    text = ("IP address  HW type  Flags  HW address  Mask  Device\n"
            "192.0.2.9   0x1      0x0    00:00:00:00:00:00  *  eth0\n"
            "192.0.2.10  0x1      0x2    %s  *  eth0\n"
            "192.0.2.11  0x1      0x2    %s  *  eth0\n" % (MAC_A, MAC_B))
    rows = aw.parse_proc_arp(text)
    check("INCOMPLETE (flags 0x0) dropped", len(rows), 2)
    check("a failed lookup never becomes a binding",
          any(r["ip"] == "192.0.2.9" for r in rows), False)
    check("always partial confidence",
          all(r["confidence"] == aw.CONF_PARTIAL for r in rows), True)
    check("source tagged as the kernel cache",
          rows[0]["source"], "kernel_arp_cache")
    check("empty input -> []", aw.parse_proc_arp(""), [])
    check("None -> []", aw.parse_proc_arp(None), [])


def test_selftest():
    print("\n[the instrument proves it produces every answer it claims]")
    ok, detail = aw.selftest()
    check("selftest passes", ok, True)
    check("selftest counts canaries", "canaries passed" in detail, True)


if __name__ == "__main__":
    print("lan_integrity -- ARP spoofing pure core")
    test_parse_real_schema()
    test_parse_rejections()
    test_first_sighting_never_alerts()
    test_gateway_takeover_is_critical()
    test_severity_derives_from_gateway_set()
    test_flapping()
    test_multi_claim()
    test_proc_arp()
    test_selftest()
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
