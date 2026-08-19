#!/usr/bin/env python3
"""Regression tests for the ADR 0023 device↔agent correlation (agent_device_macs).

Covers the two functions the correlation feature turns on — _persist_lan_macs and
approved_agent_macs — with LIVE sqlite execution, including the two defects the
route-security audit found: a use-after-close on the read, and a failed read that
was SILENTLY swallowed into an empty set (which made the use-after-close invisible
and the whole feature dead-on-arrival). test_nemesis_device_category's coverage is
static/AST and could not see either — these run real queries."""
import io
import logging
import os
import sqlite3
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "alert_manager"))
sys.path.insert(0, _HERE)
import hw_monitor as hw                                      # noqa: E402

_failures = []


def check(cond, label):
    print(("  ok    " if cond else "  FAIL  ") + label)
    if not cond:
        _failures.append(label)


def _seed():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE agent_devices (device_id TEXT PRIMARY KEY, enrollment_status TEXT)")
    c.execute("CREATE TABLE agent_device_macs (device_id TEXT, mac TEXT, last_seen REAL, "
              "PRIMARY KEY(device_id, mac))")
    return c


def test_persist_normalises_and_skips():
    print("\n[_persist_lan_macs: normalise + skip malformed + idempotent]")
    c = _seed()
    c.execute("INSERT INTO agent_devices VALUES ('A','approved')")
    hw._persist_lan_macs(c, "A", ["AA:BB:CC:DD:EE:01", "aa:bb:cc:dd:ee:02",
                                  "tun-junk", "00:00:00:00:00:00", ""])
    rows = [r[0] for r in c.execute(
        "SELECT mac FROM agent_device_macs WHERE device_id='A' ORDER BY mac")]
    check(rows == ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"],
          "lowercased, malformed/zero/empty skipped (%r)" % rows)
    hw._persist_lan_macs(c, "A", ["aa:bb:cc:dd:ee:01"], now=999.0)
    n = c.execute("SELECT COUNT(*) FROM agent_device_macs WHERE device_id='A'").fetchone()[0]
    ls = c.execute("SELECT last_seen FROM agent_device_macs WHERE mac='aa:bb:cc:dd:ee:01'").fetchone()[0]
    check(n == 2 and ls == 999.0, "re-report is idempotent + refreshes last_seen")


def test_approved_only_and_open_conn():
    print("\n[approved_agent_macs: only approved agents, open connection]")
    c = _seed()
    c.execute("INSERT INTO agent_devices VALUES ('A','approved')")
    c.execute("INSERT INTO agent_devices VALUES ('P','pending')")
    hw._persist_lan_macs(c, "A", ["aa:bb:cc:dd:ee:01"])
    hw._persist_lan_macs(c, "P", ["bb:bb:bb:bb:bb:bb"])
    got = hw.approved_agent_macs(c)
    check(got == {"aa:bb:cc:dd:ee:01"},
          "approved agent's MAC returned; pending agent's EXCLUDED (%r)" % got)


def test_failed_read_is_loud_not_silent():
    """The route-security audit's core finding: a failed read (here a closed conn,
    the exact use-after-close symptom) must SURFACE, never default silently to an
    empty set that reads as a real 'no agents' answer."""
    print("\n[approved_agent_macs: a failed read is LOUD, not a silent empty default]")
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    h.setLevel(logging.ERROR)
    hw.log.addHandler(h)
    try:
        c = _seed()
        c.close()                                # simulate the use-after-close
        got = hw.approved_agent_macs(c)          # must not raise, must LOG
    finally:
        hw.log.removeHandler(h)
    check(got == set(), "closed conn -> empty set (fail-safe for the UI)")
    check("approved_agent_macs read FAILED" in buf.getvalue(),
          "closed conn -> ERROR logged (NOT silently swallowed)")


if __name__ == "__main__":
    print("agent_device_macs correlation (ADR 0023) — regression")
    test_persist_normalises_and_skips()
    test_approved_only_and_open_conn()
    test_failed_read_is_loud_not_silent()
    print("\n" + "=" * 60)
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  - %s" % f)
        sys.exit(1)
    print("ALL PASS")
