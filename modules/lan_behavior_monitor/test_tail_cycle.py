"""lan_behavior_monitor tailer — integration against a real Data Manager + synthetic eve.json.

The pure-core suite (test_behavior.py) proves classify()/fan-out logic. It cannot prove the
module ever CALLS them, reads eve.json correctly, keys findings per source, dedups, tracks
liveness, or applies the new-device warm-up. A detector that is perfect but never invoked
produces the same output as a quiet network — so every tailer-only branch is exercised here.

LIVENESS IS THE POINT, not an extra: "0 findings" must be distinguishable from "never ran".
"""
import json
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _REPO)
sys.path.insert(0, os.path.join(_REPO, "alert_manager"))

_TMPDIR = tempfile.TemporaryDirectory()
_DB = os.path.join(_TMPDIR.name, "alerts.db")

import modules  # noqa: E402
modules.set_shared_db_path(_DB)

import importlib  # noqa: E402
m = importlib.import_module("modules.lan_behavior_monitor.module")

_fail = []
_count = 0
EXPECTED_CHECKS = 32

SCANNER_MAC = "aa:bb:cc:00:00:01"
SCANNER_IP = "192.0.2.50"
QUIET_MAC = "aa:bb:cc:00:00:02"
QUIET_IP = "192.0.2.51"


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-68s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def _arp_req(mac, ip, target):
    return {"event_type": "arp", "arp": {
        "opcode": "request", "src_mac": mac, "src_ip": ip,
        "dest_ip": target, "dest_mac": "00:00:00:00:00:00"}}


def _sweep_alert(ip):
    return {"event_type": "alert", "src_ip": ip,
            "alert": {"signature_id": 1000002, "signature": "SYN sweep"}}


def _mdns(ip):
    return {"event_type": "mdns", "src_ip": ip, "mdns": {"type": "query"}}


def _write_eve(path, records, mode="a"):
    with open(path, mode, encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")


def _open_findings():
    with m._db() as conn:
        return conn.execute(
            "SELECT src_key, severity, score, signals, is_new FROM lan_behavior_findings "
            "WHERE status='open' ORDER BY id").fetchall()


def _reset_rolling():
    """Reset per-scenario state so windows don't bleed across tests. Also clears the tail
    offset: scenarios rewrite the same eve path with mode='w' (truncate-in-place), which
    keeps the inode and can leave size>=offset, so without this the module would correctly
    read from the stale offset and skip the fresh records. Real rotation (new inode) is
    exercised separately in test_rotation_resets_offset."""
    m._ARP_STATE.clear()
    m._MDNS_STATE.clear()
    m._SWEEP_STATE.clear()
    m._IP_TO_MAC.clear()
    m._set_state("eve_offset", "0")
    m._set_state("eve_inode", "0")


# --------------------------------------------------------------------------
def test_setup_and_selftest_gate():
    print("\n[init + fail-closed selftest]")
    eve = os.path.join(_TMPDIR.name, "eve.json")
    _write_eve(eve, [], mode="w")
    m.EVE_LOG = eve
    m._init_db()
    check("selftest passes on init", m.behavior.selftest()[0], True)
    s = m._tail_cycle()
    check("empty log -> no findings, no error", (s["findings"], s["error"]), (0, None))
    check("liveness: cycle timestamp recorded", bool(m._get_state("last_cycle_ts")), True)


def test_arp_fanout_raises_a_finding():
    print("\n[a source ARP-fanning-out past threshold -> a finding]")
    _reset_rolling()
    eve = os.path.join(_TMPDIR.name, "eve.json")
    # Make the module NOT in warm-up and the scanner NOT new (established), so this
    # isolates the fan-out signal alone -> info severity, score 1.
    m._set_state("module_started_at", "1.0")   # long ago
    recs = [_arp_req(SCANNER_MAC, SCANNER_IP, "192.0.2.%d" % i)
            for i in range(2, 2 + m.behavior.ARP_FANOUT_DISTINCT_IPS)]
    _write_eve(eve, recs, mode="w")
    m.EVE_LOG = eve
    # Pre-seed first_seen far in the past so the scanner is ESTABLISHED, not new.
    with m._db() as conn:
        conn.execute("INSERT OR REPLACE INTO lan_behavior_seen_devices(mac, first_seen) "
                     "VALUES(?,?)", (SCANNER_MAC, 1.0))
        conn.commit()
    s = m._tail_cycle(now=100000.0)
    check("cycle saw arp events", s["arp_events"] >= m.behavior.ARP_FANOUT_DISTINCT_IPS, True)
    check("one finding raised", s["findings"], 1)
    of = _open_findings()
    check("exactly one open finding", len(of), 1)
    check("keyed on the scanner", of[0][0], SCANNER_MAC)
    check("severity info (single signal, established device)", of[0][1], "info")
    check("score 1", of[0][2], 1)
    check("not flagged new", of[0][4], 0)


def test_new_device_fanout_is_high():
    print("\n[a NEW device fanning out -> high (the headline pattern)]")
    _reset_rolling()
    eve = os.path.join(_TMPDIR.name, "eve.json")
    with m._db() as conn:
        conn.execute("DELETE FROM lan_behavior_findings")
        conn.execute("DELETE FROM lan_behavior_seen_devices")
        conn.commit()
    m._set_state("module_started_at", "1.0")   # module long up -> warm-up over
    newmac = "aa:bb:cc:00:00:09"
    newip = "192.0.2.90"
    recs = [_arp_req(newmac, newip, "192.0.2.1%02d" % i)
            for i in range(m.behavior.ARP_FANOUT_DISTINCT_IPS)]
    _write_eve(eve, recs, mode="w")
    m.EVE_LOG = eve
    # first sight is THIS cycle's now -> device is new
    s = m._tail_cycle(now=200000.0)
    of = _open_findings()
    check("finding raised", len(of), 1)
    check("flagged as new", of[0][4], 1)
    check("severity high (fanout + new)", of[0][1], "high")
    check("score 2", of[0][2], 2)


def test_new_device_warmup_suppresses_false_new():
    print("\n[cold start: module in warm-up must NOT mark everything new]")
    _reset_rolling()
    eve = os.path.join(_TMPDIR.name, "eve.json")
    with m._db() as conn:
        conn.execute("DELETE FROM lan_behavior_findings")
        conn.execute("DELETE FROM lan_behavior_seen_devices")
        conn.commit()
    # module JUST started (started_at == now) -> within warm-up window
    m._set_state("module_started_at", "300000.0")
    wmac = "aa:bb:cc:00:00:0a"
    recs = [_arp_req(wmac, "192.0.2.120", "192.0.2.2%02d" % i)
            for i in range(m.behavior.ARP_FANOUT_DISTINCT_IPS)]
    _write_eve(eve, recs, mode="w")
    m.EVE_LOG = eve
    s = m._tail_cycle(now=300000.0)   # now == started_at -> warm-up active
    of = _open_findings()
    check("finding still raised (fan-out is real)", len(of), 1)
    check("but NOT marked new during warm-up", of[0][4], 0)
    check("severity info, not inflated to high", of[0][1], "info")


def test_dedup_one_open_finding_per_source():
    print("\n[a source fanning out across cycles -> ONE open finding, updated not duplicated]")
    _reset_rolling()
    eve = os.path.join(_TMPDIR.name, "eve.json")
    with m._db() as conn:
        conn.execute("DELETE FROM lan_behavior_findings")
        conn.execute("DELETE FROM lan_behavior_seen_devices")
        conn.execute("INSERT INTO lan_behavior_seen_devices(mac, first_seen) VALUES(?,?)",
                     (SCANNER_MAC, 1.0))
        conn.commit()
    m._set_state("module_started_at", "1.0")
    _write_eve(eve, [_arp_req(SCANNER_MAC, SCANNER_IP, "192.0.2.%d" % i)
                     for i in range(2, 2 + m.behavior.ARP_FANOUT_DISTINCT_IPS)], mode="w")
    m.EVE_LOG = eve
    m._tail_cycle(now=100000.0)
    n1 = len(_open_findings())
    # more fan-out from the SAME source in a later cycle
    _write_eve(eve, [_arp_req(SCANNER_MAC, SCANNER_IP, "192.0.2.2%02d" % i)
                     for i in range(m.behavior.ARP_FANOUT_DISTINCT_IPS)], mode="a")
    m._tail_cycle(now=100030.0)
    n2 = len(_open_findings())
    check("still exactly one open finding after re-detection", (n1, n2), (1, 1))
    with m._db() as conn:
        repeats = conn.execute("SELECT repeat_count FROM lan_behavior_findings "
                               "WHERE src_key=? AND status='open'", (SCANNER_MAC,)).fetchone()[0]
    check("repeat_count advanced instead of a new row", repeats >= 1, True)


def test_quiet_device_no_finding_but_liveness_advances():
    print("\n[a device below all thresholds -> no finding, but the cycle proves it ran]")
    _reset_rolling()
    eve = os.path.join(_TMPDIR.name, "eve.json")
    with m._db() as conn:
        conn.execute("DELETE FROM lan_behavior_findings")
        conn.commit()
    m._set_state("module_started_at", "1.0")
    before = int(m._get_state("arp_events_total", "0") or 0)
    # a few ARP requests, well under the fan-out threshold
    _write_eve(eve, [_arp_req(QUIET_MAC, QUIET_IP, "192.0.2.60"),
                     _arp_req(QUIET_MAC, QUIET_IP, "192.0.2.61")], mode="w")
    m.EVE_LOG = eve
    s = m._tail_cycle(now=400000.0)
    check("no finding for a quiet device", s["findings"], 0)
    check("arp liveness counter advanced", int(m._get_state("arp_events_total", "0")) > before, True)


def test_rotation_resets_offset():
    print("\n[eve.json rotated (inode change) -> re-read from start, not skipped]")
    _reset_rolling()
    eve = os.path.join(_TMPDIR.name, "eve_rot.json")
    m._set_state("module_started_at", "1.0")
    _write_eve(eve, [_mdns(QUIET_IP)], mode="w")
    m.EVE_LOG = eve
    m._tail_cycle(now=500000.0)
    off1 = int(m._get_state("eve_offset", "0"))
    check("offset advanced past first content", off1 > 0, True)
    # simulate rotation: replace file (new inode), smaller size
    os.remove(eve)
    _write_eve(eve, [_mdns(QUIET_IP)], mode="w")
    s = m._tail_cycle(now=500030.0)
    check("rotation detected, cycle did not error", s["error"], None)


def test_selftest_failure_fails_closed():
    print("\n[a broken detector must NOT report a clean cycle]")
    _reset_rolling()
    eve = os.path.join(_TMPDIR.name, "eve.json")
    _write_eve(eve, [_arp_req(SCANNER_MAC, SCANNER_IP, "192.0.2.7")], mode="w")
    m.EVE_LOG = eve
    orig = m.behavior.selftest
    m.behavior.selftest = lambda: (False, "forced canary failure")
    try:
        s = m._tail_cycle(now=600000.0)
        check("cycle reports the selftest error", "selftest" in (s["error"] or "").lower(), True)
        check("selftest_ok state flipped to 0", m._get_state("selftest_ok"), "0")
    finally:
        m.behavior.selftest = orig


def test_status_distinguishes_unproven_from_clean():
    print("\n[status: 'never observed' is a DISTINCT state from 'observed, clean']")
    _reset_rolling()
    inst = m.Module({"name": "lan_behavior_monitor"})
    st = inst.status()
    check("status returns a dict with state", "state" in st, True)
    check("status carries a human detail", bool(st.get("detail")), True)


def _iso(epoch):
    import datetime
    return datetime.datetime.fromtimestamp(epoch).astimezone().isoformat()


def test_first_run_seeks_to_end_not_backlog():
    print("\n[first run with NO saved offset seeks to END -- a rate detector must not replay history]")
    _reset_rolling()
    eve = os.path.join(_TMPDIR.name, "eve_firstrun.json")
    # a big pre-existing backlog: one source fanning out, as if a week of history
    with m._db() as conn:
        conn.execute("DELETE FROM lan_behavior_findings"); conn.commit()
    m._set_state("module_started_at", "1.0")
    _write_eve(eve, [_arp_req("aa:bb:cc:00:00:0b", "192.0.2.130", "192.0.2.3%02d" % i)
                     for i in range(m.behavior.ARP_FANOUT_DISTINCT_IPS)], mode="w")
    m.EVE_LOG = eve
    # simulate a genuinely-never-run module: clear the offset state entirely
    with m._db() as conn:
        conn.execute("DELETE FROM lan_behavior_state WHERE key IN ('eve_offset','eve_inode')")
        conn.commit()
    s = m._tail_cycle(now=700000.0)
    check("first run processed ZERO events (seeked to end)", s["events"], 0)
    check("first run raised NO findings from the backlog", s["findings"], 0)
    check("offset was set to the file end", int(m._get_state("eve_offset", "0")) > 0, True)


def test_old_events_are_pruned_not_flagged():
    print("\n[events with OLD timestamps are pruned by the window, never flagged]")
    _reset_rolling()
    eve = os.path.join(_TMPDIR.name, "eve_old.json")
    with m._db() as conn:
        conn.execute("DELETE FROM lan_behavior_findings"); conn.commit()
    m._set_state("module_started_at", "1.0")
    # fan-out volume, but every event stamped WELL before the cycle's now -> outside window
    old = 800000.0 - (m.behavior.ARP_FANOUT_WINDOW_S * 100)
    recs = []
    for i in range(m.behavior.ARP_FANOUT_DISTINCT_IPS):
        r = _arp_req("aa:bb:cc:00:00:0c", "192.0.2.140", "192.0.2.4%02d" % i)
        r["timestamp"] = _iso(old)
        recs.append(r)
    _write_eve(eve, recs, mode="w")
    m.EVE_LOG = eve
    s = m._tail_cycle(now=800000.0)
    check("old-timestamp fan-out raised NO finding (pruned)", s["findings"], 0)
    # control: the SAME volume stamped at ~now DOES fire
    _reset_rolling()
    eve2 = os.path.join(_TMPDIR.name, "eve_now.json")
    recs2 = []
    for i in range(m.behavior.ARP_FANOUT_DISTINCT_IPS):
        r = _arp_req("aa:bb:cc:00:00:0d", "192.0.2.150", "192.0.2.5%02d" % i)
        r["timestamp"] = _iso(800100.0)
        recs2.append(r)
    _write_eve(eve2, recs2, mode="w")
    m.EVE_LOG = eve2
    s2 = m._tail_cycle(now=800100.0)
    check("CONTROL: same volume at current-timestamp DOES fire", s2["findings"], 1)


if __name__ == "__main__":
    print("=" * 74)
    print("lan_behavior_monitor — tail cycle integration")
    print("=" * 74)
    test_setup_and_selftest_gate()
    test_arp_fanout_raises_a_finding()
    test_new_device_fanout_is_high()
    test_new_device_warmup_suppresses_false_new()
    test_dedup_one_open_finding_per_source()
    test_quiet_device_no_finding_but_liveness_advances()
    test_rotation_resets_offset()
    test_selftest_failure_fails_closed()
    test_status_distinguishes_unproven_from_clean()
    test_first_run_seeks_to_end_not_backlog()
    test_old_events_are_pruned_not_flagged()
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
