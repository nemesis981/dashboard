#!/usr/bin/env python3
"""E-LANINT-* codes: recorded from REAL failure paths, with real controls.

Run: python3 modules/lan_integrity/test_lan_integrity_errors.py

WHY A DETECTOR NEEDS THIS MOST. Every failure coded here makes the module see
LESS while continuing to report normally, and an empty result from a blind
detector reads as reassurance. `_read_proc_arp` returning `[]` on OSError was
the sharpest case: `/proc/net/arp` is the only ARP source this module has, so a
permission or mount failure disabled ARP detection permanently and looked
exactly like a quiet network.

REAL FAILURES, NOT MOCKS OF THE MODULE. The two source-reading functions take a
`path` argument, so the failure is induced the way it would really happen -- by
pointing them at something unreadable -- rather than by patching the function
under test. That distinction matters: patching the function proves the test can
patch, not that the handler works.

CONTROLS THROUGHOUT. Every "it records" check has a matching "a healthy call
records nothing", because a recorder that fires unconditionally would pass the
first half and be useless.
"""
import os
import sys
import tempfile

sys.path.insert(0, "/opt/nemesis")
sys.path.insert(0, "/opt/nemesis/alert_manager")

import modules                                               # noqa: E402
import database                                              # noqa: E402
import data_manager as dm_mod                                # noqa: E402

_TMPDB = os.path.join(tempfile.mkdtemp(prefix="lanint-errors-"), "t.db")
database.DB_PATH = _TMPDB
modules.set_shared_db_path(_TMPDB)
database.init_db()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import module as L                                           # noqa: E402
import nemesis_errors                                        # noqa: E402

EXPECTED_CHECKS = 19
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


_conn = modules.get_data_manager().connect("lan_integrity")
nemesis_errors.init_error_tables(_conn)


def occ(code):
    return _conn.execute(
        "SELECT COUNT(*) FROM error_occurrences WHERE code=?",
        (code,)).fetchone()[0]


def main():
    print("\n0. CONTROLS: the harness is real")
    check("throwaway DB, not the live one",
          "/var/lib/nemesis" not in _TMPDB, True)
    check("CONTROL a REAL DataManager",
          isinstance(modules.get_data_manager(), dm_mod.DataManager), True)
    check("CONTROL enforcement is ON",
          dm_mod.namespace_mode("lan_integrity"), dm_mod.MODE_ENFORCE)

    print("\n1. the catalog is sound")
    check("7 codes declared", len(L._ERR_CODES), 7)
    check("all E-LANINT-NNN shaped",
          all(c.startswith("E-LANINT-") for c in L._ERR_CODES), True)
    check("every code has a description and severity",
          all(d and s for d, s, _c in L._ERR_CODES.values()), True)

    print("\n2. the ARP source: the headline failure")
    # REAL failure: point the real function at a path that cannot be read.
    before = occ(L.E_ARP_SOURCE_UNREADABLE)
    got = L._read_proc_arp(path="/proc/definitely-not-here/arp")
    check("returns [] (callers depend on the shape)", got, [])
    check("...and RECORDS that it was blind, not silently empty",
          occ(L.E_ARP_SOURCE_UNREADABLE), before + 1)
    # CONTROL: the real /proc/net/arp exists on this box, so a healthy read
    # must record nothing. Without this the check above would pass even if the
    # recorder fired unconditionally.
    before = occ(L.E_ARP_SOURCE_UNREADABLE)
    if os.path.exists("/proc/net/arp"):
        L._read_proc_arp()
        check("CONTROL a healthy ARP read records nothing",
              occ(L.E_ARP_SOURCE_UNREADABLE), before)
    else:
        check("CONTROL skipped: /proc/net/arp absent on this host", True, True)

    print("\n3. the gateway list: degraded, not blind")
    before_g = occ(L.E_GATEWAY_LIST_UNREADABLE)
    before_a = occ(L.E_ARP_SOURCE_UNREADABLE)
    got = L._gateways(path="/proc/definitely-not-here/route")
    check("returns an empty set", got, set())
    check("...and records the DEGRADED code",
          occ(L.E_GATEWAY_LIST_UNREADABLE), before_g + 1)
    # The two must not be confused: they have different consequences.
    check("...and NOT the ARP-blind code",
          occ(L.E_ARP_SOURCE_UNREADABLE), before_a)
    before_g = occ(L.E_GATEWAY_LIST_UNREADABLE)
    if os.path.exists("/proc/net/route"):
        L._gateways()
        check("CONTROL a healthy route read records nothing",
              occ(L.E_GATEWAY_LIST_UNREADABLE), before_g)
    else:
        check("CONTROL skipped: /proc/net/route absent", True, True)

    print("\n4. recording never raises into the detector")
    # A detector that died because its error recorder failed would be a worse
    # outcome than the failure it was reporting.
    check("an unknown code does not raise",
          L._record("E-LANINT-999", {"x": 1}) is None or True, True)
    check("CONTROL a known code still records afterwards",
          L._record(L.E_CYCLE_FAILED, {"probe": 1}) is not None, True)

    print("\n5. it is DURABLE -- readable back out of the database")
    rows = {r[0] for r in _conn.execute(
        "SELECT DISTINCT code FROM error_occurrences").fetchall()}
    for c in (L.E_ARP_SOURCE_UNREADABLE, L.E_GATEWAY_LIST_UNREADABLE,
              L.E_CYCLE_FAILED):
        check("%s survives in the DB" % c, c in rows, True)

    print("\n6. no PHANTOMS -- every declared code has a call site")
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "module.py"), encoding="utf-8").read()
    const_for = {v: k for k, v in vars(L).items()
                 if isinstance(v, str) and v.startswith("E-LANINT-")}
    phantom = [c for c in L._ERR_CODES
               if src.count(const_for.get(c, "@@")) < 2]   # decl + >=1 use
    check("every code is recorded somewhere", phantom, [])

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [l for l, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
