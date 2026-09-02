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
EXPECTED_CHECKS = 41

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


def _iso(offset_s=0):
    """A real ISO timestamp offset_s seconds from now (negative = in the past).
    The tailer now windows events by their OWN timestamp, so fixed past dates
    would be filtered as stale; events must be dated relative to the run."""
    import datetime
    return (datetime.datetime.now().astimezone()
            + datetime.timedelta(seconds=offset_s)).isoformat()


def _ev(src, mtype, ts=None, **dhcp):
    d = {"dhcp_type": mtype}
    d.update(dhcp)
    return {"event_type": "dhcp", "src_ip": src,
            "timestamp": ts if ts is not None else _iso(),
            "dhcp": d}


def _clear_tail_state():
    """Force the genuine first-run/state-loss condition: drop the persisted tail
    offset+inode so _tail_cycle sees the empty-string sentinel it treats as
    'never run'."""
    with li._db() as conn:
        conn.execute("DELETE FROM lan_integrity_state WHERE key IN "
                     "('eve_offset','eve_inode')")
        conn.commit()


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

    # First-run priming: the tailer now seeks to end on a genuine first run
    # (fresh state) instead of replaying byte 0. The file is empty here, so this
    # records offset 0 and flips the first-run sentinel; every event written
    # below is appended AFTER it and read normally. Without this the first real
    # cycle would (correctly, post-fix) seek past the event it writes. Dedicated
    # first-run-with-history + staleness coverage is in
    # test_first_run_and_staleness().
    _clear_tail_state()
    li._tail_cycle()
    check("first-run priming flips the offset sentinel (not empty)",
          li._get_state("eve_offset", "") != "", True)

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


# IPs used ONLY by the first-run/staleness test, so DB membership checks are not
# contaminated by main()'s shared-state writes (same _TMPDIR DB across the run).
FR_OLD    = "192.0.2.170"   # first-run history OLDER than the lookback (must be skipped)
FR_RECENT = "192.0.2.171"   # first-run history WITHIN the lookback (must be surfaced)
FR_LIVE   = "192.0.2.182"   # a live event after first run (must be read)
ST_OLD    = "192.0.2.190"   # stale-timestamped event in a steady-state bulk read (dropped)
ST_FRESH  = "192.0.2.191"   # current event in the same bulk read (must survive)


def _server_set():
    with li._db() as conn:
        return {r[0] for r in conn.execute(
            "SELECT server_ip FROM lan_integrity_dhcp_servers")}


def _iso_at(epoch):
    import datetime
    return datetime.datetime.fromtimestamp(epoch).astimezone().isoformat()


def test_first_run_and_staleness():
    """The latent-bug coverage, OPTION 2 (bounded lookback, operator decision
    2026-09-02): a genuine first run reads a bounded few-hour window (surfacing an
    already-active threat) but NOT the whole log, then jumps to end; and a
    steady-state bulk read is windowed by the tighter staleness bound.

    First-run assertions FAIL against BOTH prior shapes: the original bug (offset
    0, no bound -> the pre-lookback event would be surfaced) AND option-1
    seek-to-end (-> the recent event would be skipped). That two-sided failure is
    the point -- it pins option 2 specifically, not merely 'not the bug'."""
    eve2 = os.path.join(_TMPDIR.name, "eve-firstrun.json")
    li.EVE_LOG = eve2
    _clear_tail_state()
    now = 2_000_000.0
    recent_ts = _iso_at(now - 600)                              # 10 min ago: inside lookback
    old_ts = _iso_at(now - (li.FIRST_RUN_LOOKBACK_S + 3600))    # older than lookback: skipped

    # ── first run: bounded lookback surfaces the recent threat, skips the old ──
    print("\n[first run reads a BOUNDED lookback: recent history surfaced, older skipped]")
    _write_eve(eve2, [_ev(FR_OLD, "offer", assigned_ip="192.0.2.70",
                          client_mac="00:00:5e:00:53:aa", ts=old_ts),
                      _ev(FR_RECENT, "offer", assigned_ip="192.0.2.71", ts=recent_ts)],
               mode="w")
    size = os.path.getsize(eve2)
    s = li._tail_cycle(now=now)
    check("first run reports no error", s["error"], None)
    check("first run SURFACES the recent event (bounded lookback, not seek-to-end)",
          s["events"], 1)
    check("first run SKIPS the pre-lookback event (bounded, not full replay)",
          FR_OLD in _server_set(), False)
    check("first run recorded the recent event as a server",
          FR_RECENT in _server_set(), True)
    check("first run jumps to END after the bounded read",
          int(li._get_state("eve_offset", "0")), size)

    # ── after first run, offset is at end: a new live event is still read ──────
    print("\n[first run is not permanent blindness: the next live event is read]")
    _write_eve(eve2, [_ev(FR_LIVE, "offer", assigned_ip="192.0.2.72",
                          ts=_iso_at(now + 5))])
    s = li._tail_cycle(now=now + 10)
    check("a live event appended after first run is read", s["events"], 1)

    # ── steady-state staleness: a bulk read (established offset) drops OLD events
    print("\n[steady state: an old event in a bulk read is windowed by the tighter bound]")
    eve3 = os.path.join(_TMPDIR.name, "eve-stale.json")
    li.EVE_LOG = eve3
    now2 = 3_000_000.0
    st_old_ts = _iso_at(now2 - (li.STALE_EVENT_MAX_AGE_S + 600))   # stale for steady state
    st_fresh_ts = _iso_at(now2 - 5)                               # current
    _write_eve(eve3, [_ev(ST_OLD, "offer", assigned_ip="192.0.2.90", ts=st_old_ts),
                      _ev(ST_FRESH, "offer", assigned_ip="192.0.2.91", ts=st_fresh_ts)],
               mode="w")
    # Establish state so this is a steady-state BULK read from 0, NOT first-run
    # (offset "0" is a real persisted value; only "" means first run).
    st = os.stat(eve3)
    li._set_state("eve_offset", "0")
    li._set_state("eve_inode", str(st.st_ino))
    s = li._tail_cycle(now=now2)
    check("only the fresh event survives the steady-state window (events=1)",
          s["events"], 1)
    check("the stale event was NOT recorded as a server", ST_OLD in _server_set(), False)
    check("the fresh event WAS recorded (control: filter is not blanket)",
          ST_FRESH in _server_set(), True)


if __name__ == "__main__":
    print("lan_integrity -- tailer integration")
    try:
        main()
        test_first_run_and_staleness()
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
