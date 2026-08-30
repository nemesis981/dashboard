"""ARP detection through the real DB path, plus the Tier 2 signals contract.

Two things the pure suite cannot prove: that the module actually CALLS the
detector and persists bindings, and that `signals.py` -- the interface Tier 2
correlation consumes -- returns what its docstring promises. The second matters
most: a contract nobody tests is a contract that drifts, and the consumer here is
another window building against it concurrently.
"""
import json
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _REPO)
sys.path.insert(0, os.path.join(_REPO, "alert_manager"))

_TMP = tempfile.TemporaryDirectory()
import modules                                    # noqa: E402
modules.set_shared_db_path(os.path.join(_TMP.name, "alerts.db"))

import importlib                                  # noqa: E402
li = importlib.import_module("modules.lan_integrity.module")
sg = importlib.import_module("modules.lan_integrity.signals")
aw = importlib.import_module("modules.lan_integrity.arp_watch")

_fail = []
_count = 0
EXPECTED_CHECKS = 43

GW = "192.0.2.1"
HOST = "192.0.2.50"
MAC_A = "00:00:5e:00:53:01"
MAC_B = "00:00:5e:00:53:66"


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-66s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def obs(ip, mac, source="suricata_arp", conf=aw.CONF_OBSERVED, grat=True):
    return {"ip": ip, "mac": mac, "opcode": "reply", "gratuitous": grat,
            "source": source, "confidence": conf, "ts": None}


def bindings():
    with li._db() as c:
        return {r[0]: {"mac": r[1], "prev": r[2], "changes": r[3]} for r in c.execute(
            "SELECT ip, mac, previous_mac, change_count FROM lan_integrity_arp_bindings")}


def findings():
    with li._db() as c:
        return [(r[0], r[1], r[2], r[3]) for r in c.execute(
            "SELECT kind, severity, subject_ip, confidence FROM lan_integrity_findings "
            "WHERE status='open' ORDER BY id")]


def main():
    li.EVE_LOG = os.path.join(_TMP.name, "eve.json")
    open(li.EVE_LOG, "w").close()
    li._init_db()

    print("\n[CONTROL: the Data Manager granted the new table -- asserted by OUTCOME]")
    with li._db() as c:
        c.execute("INSERT INTO lan_integrity_arp_bindings(ip, mac, first_seen, last_seen) "
                  "VALUES('192.0.2.250','%s',1,1)" % MAC_A)
        c.commit()
    check("a write to lan_integrity_arp_bindings persists",
          "192.0.2.250" in bindings(), True)
    with li._db() as c:
        c.execute("DELETE FROM lan_integrity_arp_bindings WHERE ip='192.0.2.250'")
        c.commit()

    print("\n[first sighting learns the binding and raises nothing]")
    with li._db() as c:
        n = li._arp_cycle(c, [obs(GW, MAC_A), obs(HOST, MAC_A)], now=1000.0)
        c.commit()
    check("no findings on first sighting", n, 0)
    check("both bindings learned", len(bindings()), 2)
    check("binding records the mac", bindings()[GW]["mac"], MAC_A)

    print("\n[an unchanged re-assertion is not an event]")
    with li._db() as c:
        n = li._arp_cycle(c, [obs(GW, MAC_A)], now=1010.0)
        c.commit()
    check("no finding when nothing changed", n, 0)
    check("change_count stays zero", bindings()[GW]["changes"], 0)

    print("\n[the gateway moving to a new MAC is the critical case]")
    # _gateways() reads the real /proc/net/route, which will not contain our
    # RFC 5737 fixtures -- so pin it. Without this the test would silently
    # exercise the non-gateway path while claiming to test the gateway one.
    orig_gw = li._gateways
    li._gateways = lambda *a, **k: {GW}
    try:
        with li._db() as c:
            n = li._arp_cycle(c, [obs(GW, MAC_B)], now=1020.0)
            c.commit()
        check("one finding written", n, 1)
        f = findings()
        check("kind is gateway takeover", f[0][0], aw.GATEWAY_TAKEOVER)
        check("severity critical", f[0][1], "critical")
        check("subject is the gateway address", f[0][2], GW)
        check("confidence recorded from the observation", f[0][3], aw.CONF_OBSERVED)
        check("binding updated to the new mac", bindings()[GW]["mac"], MAC_B)
        check("previous mac retained for correlation", bindings()[GW]["prev"], MAC_A)
        check("change_count advanced", bindings()[GW]["changes"], 1)

        print("\n[dedup is per subject -- a spoofer re-asserting must not write per packet]")
        with li._db() as c:
            n = li._arp_cycle(c, [obs(GW, MAC_A), obs(GW, MAC_B)], now=1030.0)
            c.commit()
        check("no duplicate open finding for the same subject", n, 0)
        check("still exactly one open finding", len(findings()), 1)
    finally:
        li._gateways = orig_gw

    print("\n[CONTROL: an unreadable routing table degrades severity, never suppresses]")
    li._gateways = lambda *a, **k: set()
    try:
        with li._db() as c:
            li._arp_cycle(c, [obs(HOST, MAC_B)], now=1040.0)
            c.commit()
        hostf = [f for f in findings() if f[2] == HOST]
        check("a finding is still raised with no gateway set", len(hostf), 1)
        check("...at HIGH rather than critical", hostf[0][1], "high")
    finally:
        li._gateways = orig_gw

    print("\n[kernel-cache observations must never claim full confidence]")
    with li._db() as c:
        li._arp_cycle(c, [obs("192.0.2.77", MAC_A, source="kernel_arp_cache",
                              conf=aw.CONF_PARTIAL, grat=False)], now=1050.0)
        li._arp_cycle(c, [obs("192.0.2.77", MAC_B, source="kernel_arp_cache",
                              conf=aw.CONF_PARTIAL, grat=False)], now=1060.0)
        c.commit()
    kf = [f for f in findings() if f[2] == "192.0.2.77"]
    check("cache-derived finding is raised", len(kf), 1)
    check("...and marked PARTIAL, so absence proves nothing", kf[0][3], aw.CONF_PARTIAL)

    print("\n[a broken detector must fail closed, not report a clean LAN]")
    # ⚠ STUB THE OBJECT THE CODE ACTUALLY HOLDS. module.py reaches its siblings
    # via a sys.path insert (`import arp_watch`), so `modules.lan_integrity.
    # arp_watch` and `arp_watch` are TWO DISTINCT module objects in sys.modules.
    # Patching the one this test imported left production calling the real
    # selftest, and the fail-closed assertions failed for that reason and not
    # because the behaviour was wrong. Harmless in production -- arp_watch is
    # pure functions and constants, so a duplicate object holds no diverging
    # state -- but fatal to a test that patches the wrong one.
    check("CONTROL: the two import paths really are distinct objects",
          li.arp_watch is aw, False)
    orig = li.arp_watch.selftest
    li.arp_watch.selftest = lambda: (False, "forced")
    try:
        raised = False
        try:
            with li._db() as c:
                li._arp_cycle(c, [obs(GW, MAC_A)], now=1070.0)
        except RuntimeError:
            raised = True
        check("selftest failure raises rather than returning 0 findings", raised, True)
        check("...and is recorded for status()", li._get_state("selftest_ok"), "0")
    finally:
        li.arp_watch.selftest = orig
        li._set_state("selftest_ok", "1")

    # ── the Tier 2 contract ──────────────────────────────────────────────────
    print("\n[signals.py: the contract Tier 2 correlation is built against]")
    # One connection scope for every read below: `_db()` CLOSES on exit, and a
    # connection used after its `with` block raises "Cannot operate on a closed
    # database" -- which is exactly what the first version of this test did.
    with li._db() as c:
        sigs = sg.get_signals(c, since_ts=0.0)
        cov = sg.get_coverage(c)
        filtered = sg.get_signals(c, kinds=[aw.GATEWAY_TAKEOVER])
    check("signals are returned", len(sigs) >= 3, True)
    s0 = sigs[0]
    for field in ("schema_version", "signal", "ts", "severity", "confidence",
                  "subject_ip", "subject_mac", "source", "evidence", "status"):
        check("contract field present: %s" % field, field in s0, True)
    check("schema_version matches the module constant",
          s0["schema_version"], sg.SCHEMA_VERSION)
    check("evidence is a dict, never a raw string", isinstance(s0["evidence"], dict), True)
    check("newest first", sigs[0]["ts"] >= sigs[-1]["ts"], True)
    check("kind filtering works",
          all(x["signal"] == aw.GATEWAY_TAKEOVER for x in filtered), True)
    check("CONTROL: the filter actually matched something (not vacuously true)",
          len(filtered) >= 1, True)

    print("\n[coverage is what stops Tier 2 scoring on a dark signal]")
    check("coverage reports the arp source", "suricata_arp" in cov["sources"], True)
    check("blind spots are enumerated, not implied", len(cov["blind_spots"]) >= 3, True)
    check("detector health is exposed", cov["detector_healthy"], True)
    check("an unobserved source is reported as NOT observable",
          cov["sources"]["suricata_arp"]["observable"], False)


if __name__ == "__main__":
    print("lan_integrity -- ARP integration + Tier 2 signals contract")
    main()
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
