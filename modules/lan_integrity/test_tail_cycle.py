"""lan_integrity tailer — integration against a real Data Manager and a synthetic eve.json.

The pure-core suite proves `classify()` can tell rogue from legitimate. It cannot
prove the module ever CALLS it, reads the log correctly, or writes a finding — and
a detector that is perfect but never invoked produces exactly the same output as a
healthy network. So every branch that only exists in the tailer is exercised here:
dedup, rotation, the fail-closed paths, and the liveness counters.

THE LIVENESS COUNTERS ARE THE POINT, not an extra. Measured on the build host: 2
DHCP events in 89 MB of eve.json over 7.8 hours. Silence is this detector's normal
state, so "0 findings" must be distinguishable from "never ran" by something other
than trust.
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

import modules                                   # noqa: E402
modules.set_shared_db_path(_DB)

import importlib                                 # noqa: E402
li = importlib.import_module("modules.lan_integrity.module")

_fail = []
_count = 0
EXPECTED_CHECKS = 31

PINNED = "192.0.2.1"
ROGUE_SRV = "192.0.2.66"
OTHER_ROGUE = "192.0.2.99"


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-66s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def _write_eve(path, records, mode="a"):
    with open(path, mode, encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")


def _ev(src, mtype, **dhcp):
    d = {"dhcp_type": mtype}
    d.update(dhcp)
    return {"event_type": "dhcp", "src_ip": src, "timestamp": "2026-08-30T09:00:00-0500",
            "dhcp": d}


def _findings():
    with li._db() as conn:
        return conn.execute(
            "SELECT server_ip, severity, status FROM lan_integrity_findings "
            "ORDER BY id").fetchall()


def _servers():
    with li._db() as conn:
        return {r[0]: {"count": r[1], "pinned": bool(r[2])} for r in conn.execute(
            "SELECT server_ip, observed_count, pinned FROM lan_integrity_dhcp_servers")}


def main():
    eve = os.path.join(_TMPDIR.name, "eve.json")
    li.EVE_LOG = eve
    open(eve, "w").close()
    li._init_db()

    # ── the tables really exist, through the Data Manager's write path ────────
    print("\n[CONTROL: the Data Manager actually granted these writes]")
    # A missing NAMESPACES grant does not raise here -- it logs WOULD DENY and the
    # write silently does not happen. So this is asserted by OUTCOME (a row comes
    # back), never by absence of an exception.
    with li._db() as conn:
        conn.execute("INSERT INTO lan_integrity_state(key,value) VALUES('probe','1')")
        conn.commit()
    check("a write to a granted table is actually persisted",
          li._get_state("probe"), "1")

    # ── unpinned network: fail closed, record candidate, DO NOT alert ─────────
    print("\n[an unpinned network cannot have an 'unexpected' server -- no findings, but a candidate]")
    _write_eve(eve, [_ev(ROGUE_SRV, "offer", assigned_ip="192.0.2.50",
                         client_mac="00:00:5e:00:53:01")])
    s = li._tail_cycle()
    check("cycle reports no error", s["error"], None)
    check("the event was seen", s["events"], 1)
    check("no finding without a pin (fail closed, not false-positive)", s["findings"], 0)
    check("server recorded as a candidate", ROGUE_SRV in _servers(), True)
    check("candidate is NOT pinned", _servers()[ROGUE_SRV]["pinned"], False)
    check("liveness counter advanced", int(li._get_state("dhcp_events_total", "0")), 1)
    check("selftest recorded as passing in the production path",
          li._get_state("selftest_ok"), "1")

    # ── pin the real server; the rogue now becomes a finding ──────────────────
    print("\n[once a server is confirmed, an unexpected one is a finding]")
    _write_eve(eve, [_ev(PINNED, "offer", assigned_ip="192.0.2.51")])
    li._tail_cycle()
    with li._db() as conn:
        conn.execute("UPDATE lan_integrity_dhcp_servers SET pinned=1 WHERE server_ip=?",
                     (PINNED,))
        conn.commit()
    _write_eve(eve, [_ev(ROGUE_SRV, "offer", assigned_ip="192.0.2.52",
                         client_mac="00:00:5e:00:53:02")])
    s = li._tail_cycle()
    check("rogue server produces exactly one finding", s["findings"], 1)
    rows = _findings()
    check("finding names the rogue server", rows[0][0], ROGUE_SRV)
    check("severity HIGH without extended data", rows[0][1], "high")
    check("finding is open", rows[0][2], "open")

    # ── the pinned server must NOT produce a finding ──────────────────────────
    print("\n[CONTROL: the detector is selective, not blanket -- the real server stays clean]")
    _write_eve(eve, [_ev(PINNED, "ack", assigned_ip="192.0.2.53")])
    s = li._tail_cycle()
    check("pinned server produces no finding", s["findings"], 0)
    check("still exactly one finding in total", len(_findings()), 1)

    # ── dedup: a flapping rogue server must not write a row per packet ────────
    print("\n[a rogue server answering every DISCOVER must not write thousands of rows]")
    _write_eve(eve, [_ev(ROGUE_SRV, "offer", assigned_ip="192.0.2.5%d" % i)
                     for i in range(4)])
    s = li._tail_cycle()
    check("repeat offences do not open a second finding", s["findings"], 0)
    check("total findings unchanged", len(_findings()), 1)
    check("but the observation count still climbs", _servers()[ROGUE_SRV]["count"] >= 5, True)

    # ── a DIFFERENT rogue server is a separate finding ────────────────────────
    print("\n[dedup is per-server, not global -- a second attacker must not be swallowed]")
    _write_eve(eve, [_ev(OTHER_ROGUE, "offer", assigned_ip="192.0.2.60")])
    s = li._tail_cycle()
    check("a different rogue server opens its own finding", s["findings"], 1)
    check("two findings total", len(_findings()), 2)

    # ── extended payload escalates through the real path ──────────────────────
    print("\n[extended logging escalates 'answered' to 'tried to be your gateway']")
    with li._db() as conn:
        conn.execute("UPDATE lan_integrity_findings SET status='closed'")
        conn.commit()
    _write_eve(eve, [_ev(ROGUE_SRV, "offer", assigned_ip="192.0.2.61",
                         routers=[ROGUE_SRV], dns_servers=[ROGUE_SRV])])
    li._tail_cycle()
    open_rows = [r for r in _findings() if r[2] == "open"]
    check("a new finding opens after the previous was closed", len(open_rows), 1)
    check("extended data escalates to CRITICAL", open_rows[0][1], "critical")

    # ── client traffic must never register ────────────────────────────────────
    print("\n[client DISCOVER/REQUEST is not a server claim]")
    before = int(li._get_state("dhcp_events_total", "0"))
    _write_eve(eve, [_ev("192.0.2.200", "discover"), _ev("192.0.2.200", "request")])
    s = li._tail_cycle()
    check("client messages yield no observations", s["events"], 0)
    check("liveness counter did NOT move on client traffic",
          int(li._get_state("dhcp_events_total", "0")), before)

    # ── rotation: a new inode restarts from offset 0 ──────────────────────────
    print("\n[log rotation must not skip a rotated file nor replay from a stale offset]")
    old_offset = int(li._get_state("eve_offset", "0"))
    check("CONTROL: an offset had actually accumulated", old_offset > 0, True)
    os.remove(eve)
    _write_eve(eve, [_ev(OTHER_ROGUE, "offer", assigned_ip="192.0.2.70")], mode="w")
    s = li._tail_cycle()
    check("rotated log is read from its start", s["events"], 1)
    check("offset was reset, not carried over",
          int(li._get_state("eve_offset", "0")) < old_offset, True)

    # ── an unreadable log is an ERROR, never a silent 'no events' ─────────────
    print("\n[a failed read must surface as failure, never as a default that looks like a result]")
    li.EVE_LOG = os.path.join(_TMPDIR.name, "does-not-exist.json")
    s = li._tail_cycle()
    check("missing log reports an explicit error", bool(s["error"]), True)
    check("...and does NOT report a clean zero-event cycle", s["events"], 0)
    check("error text names the cause", "unreadable" in s["error"], True)

    # ── a broken detector must fail closed, not report 'nothing found' ────────
    print("\n[if the detector cannot prove itself, it must not vouch for the network]")
    li.EVE_LOG = eve
    orig = li.rogue_dhcp.selftest
    li.rogue_dhcp.selftest = lambda: (False, "forced failure")
    try:
        s = li._tail_cycle()
        check("selftest failure aborts the cycle", bool(s["error"]), True)
        check("...and is recorded so status() can report it",
              li._get_state("selftest_ok"), "0")
    finally:
        li.rogue_dhcp.selftest = orig


if __name__ == "__main__":
    print("lan_integrity -- tailer integration")
    try:
        main()
    finally:
        pass
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
