#!/usr/bin/env python3
"""ARP observation coalescing — write volume AND the detection semantics it must not cost.

Run: python3 modules/lan_integrity/test_arp_coalesce.py

WHY THIS EXISTS. `_arp_cycle` used to issue one SELECT and one UPDATE per raw ARP
observation. Measured live 2026-09-03: ~1.24M UPDATEs in 24h against a 33-row table,
each also inserting a `dm_operation_log` row -- the single largest writer in the
system, for a table whose content changes almost never.

⛔ THE DANGEROUS FIX, AND WHY THIS SUITE IS SHAPED THE WAY IT IS. The obvious
de-duplication -- keep the LAST observation per IP -- silently destroys flap
detection. Within one cycle A -> B -> A collapses to "A", which equals the stored
prior, so `classify()` returns None and a binding actively being contested by two
hosts reports as quiet. BINDING_FLAP is a CRITICAL detector; that would be trading a
real detection for a write count. So every volume assertion below is paired with a
semantic one, and the flap case is asserted by OUTCOME (change_count advanced twice),
not by inspecting the collapse.

The write-count checks assert a COUNT, not a plausible-looking value: the point is
that N observations of an unchanged binding produce exactly ONE statement, and a
count is the only thing that can tell "coalesced" apart from "happened to be quiet".
"""
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
aw = importlib.import_module("modules.lan_integrity.arp_watch")

_fail = []
_count = 0
EXPECTED_CHECKS = 44

GW = "192.0.2.1"
HOST = "192.0.2.50"
OTHER = "192.0.2.77"
MAC_A = "00:00:5e:00:53:01"
MAC_B = "00:00:5e:00:53:66"
MAC_C = "00:00:5e:00:53:99"


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-70s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def obs(ip, mac, source="suricata_arp", conf=aw.CONF_OBSERVED, grat=True):
    return {"ip": ip, "mac": mac, "source": source, "confidence": conf,
            "gratuitous": grat}


class CountingConn:
    """Delegating proxy that records every statement `_arp_cycle` executes.

    Counting is the whole point: the difference between "coalesced to one write"
    and "wrote 50 times" is invisible in the resulting row, which looks identical
    either way. Only the statement count can tell them apart.
    """

    def __init__(self, conn):
        self._conn = conn
        self.statements = []

    def execute(self, sql, params=()):
        self.statements.append(" ".join(sql.split()))
        return self._conn.execute(sql, params)

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def writes(self):
        return [s for s in self.statements
                if s.startswith("INSERT") or s.startswith("UPDATE")]

    def binding_writes(self):
        return [s for s in self.writes() if "lan_integrity_arp_bindings" in s]

    def binding_reads(self):
        return [s for s in self.statements
                if s.startswith("SELECT") and "lan_integrity_arp_bindings" in s]


def bindings():
    with li._db() as c:
        return {r[0]: {"mac": r[1], "prev": r[2], "changes": r[3], "seen": r[4],
                       "count": r[5], "src": r[6]}
                for r in c.execute(
                    "SELECT ip, mac, previous_mac, change_count, last_seen, "
                    "observed_count, last_source FROM lan_integrity_arp_bindings")}


def findings():
    with li._db() as c:
        return c.execute(
            "SELECT kind, subject_ip FROM lan_integrity_findings "
            "WHERE status='open'").fetchall()


def cycle(observations, now):
    """Run one _arp_cycle through the counting proxy. Returns (findings, proxy)."""
    with li._db() as c:
        proxy = CountingConn(c)
        n = li._arp_cycle(proxy, observations, now=now)
        c.commit()
    return n, proxy


def main():
    li.EVE_LOG = os.path.join(_TMP.name, "eve.json")
    open(li.EVE_LOG, "w").close()
    li._init_db()

    # ── the pure collapse function ───────────────────────────────────────────
    print("\n[collapse: pure function, no DB]")
    collapse = li._collapse_arp_observations

    got = collapse([obs(GW, MAC_A)] * 50)
    check("50 identical observations collapse to one entry", len(got[GW]), 1)
    check("...and the raw count is preserved, not discarded",
          got[GW][0]["_raw_count"], 50)

    got = collapse([obs(GW, MAC_A), obs(GW, MAC_B), obs(GW, MAC_A)])
    check("THE PROPERTY: a within-cycle flap keeps every transition", len(got[GW]), 3)
    check("...in arrival order, so classify() sees each move",
          [r["mac"] for r in got[GW]], [MAC_A, MAC_B, MAC_A])
    check("...and nothing is merged across the flap",
          [r["_raw_count"] for r in got[GW]], [1, 1, 1])

    got = collapse([obs(GW, MAC_A), obs(GW, MAC_A), obs(GW, MAC_B),
                    obs(GW, MAC_B), obs(GW, MAC_B)])
    check("runs of identical macs collapse, transitions survive", len(got[GW]), 2)
    check("...counts are attributed to the right run", got[GW][0]["_raw_count"], 2)
    check("...including the trailing run", got[GW][1]["_raw_count"], 3)

    got = collapse([obs(GW, MAC_A), obs(HOST, MAC_B), obs(GW, MAC_A), obs(HOST, MAC_B)])
    check("interleaved IPs are collapsed per-IP, not globally", len(got[GW]), 1)
    check("...both IPs present", sorted(got.keys()), sorted([GW, HOST]))
    check("...interleaving does not fake a transition", got[HOST][0]["_raw_count"], 2)

    check("CONTROL empty input yields nothing", collapse([]), {})
    check("CONTROL an observation with no mac is dropped",
          collapse([{"ip": GW}]), {})
    check("CONTROL an observation with no ip is dropped",
          collapse([{"mac": MAC_A}]), {})
    check("CONTROL a non-dict observation is dropped", collapse(["nope"]), {})

    # ── write volume through the real DB path ────────────────────────────────
    print("\n[first sighting: one INSERT regardless of observation count]")
    n, p = cycle([obs(GW, MAC_A)] * 50, now=1000.0)
    check("no finding on a first sighting", n, 0)
    check("THE COUNT: exactly one binding write for 50 observations",
          len(p.binding_writes()), 1)
    check("...and it is an INSERT", p.binding_writes()[0].startswith("INSERT"), True)
    check("observed_count records all 50, not 1", bindings()[GW]["count"], 50)
    check("the binding learned the mac", bindings()[GW]["mac"], MAC_A)

    print("\n[unchanged re-assertion: one UPDATE for the whole cycle]")
    n, p = cycle([obs(GW, MAC_A)] * 40, now=1010.0)
    check("no finding when nothing changed", n, 0)
    check("THE COUNT: exactly one binding write for 40 unchanged observations",
          len(p.binding_writes()), 1)
    check("...and it is an UPDATE", p.binding_writes()[0].startswith("UPDATE"), True)
    # One prior lookup for the address, plus the multi-claim pass's single
    # table-wide scan (which is per-cycle and independent of observation volume).
    check("THE COUNT: one prior read per distinct IP + one multi-claim scan",
          len(p.binding_reads()), 2)
    check("observed_count accumulated exactly (50+40)", bindings()[GW]["count"], 90)
    check("last_seen still refreshed on the unchanged path",
          bindings()[GW]["seen"], 1010.0)

    print("\n[a real change still writes and still alerts]")
    orig_gw = li._gateways
    li._gateways = lambda *a, **k: {GW}
    try:
        n, p = cycle([obs(GW, MAC_B)] * 10, now=1020.0)
        check("the change raises exactly one finding", n, 1)
        check("THE COUNT: still one binding write", len(p.binding_writes()), 1)
        check("binding moved to the new mac", bindings()[GW]["mac"], MAC_B)
        check("previous_mac retained for correlation", bindings()[GW]["prev"], MAC_A)
        check("change_count advanced by one", bindings()[GW]["changes"], 1)
        check("observed_count accumulated (90+10)", bindings()[GW]["count"], 100)

        # THE regression this suite exists for.
        print("\n[⛔ within-cycle flap: the case naive dedup would erase]")
        n, p = cycle([obs(HOST, MAC_A)] * 5, now=1030.0)          # learn HOST
        check("CONTROL host learned quietly", bindings()[HOST]["changes"], 0)
        li._gateways = lambda *a, **k: set()
        n, p = cycle([obs(HOST, MAC_B)] * 3 + [obs(HOST, MAC_A)] * 3, now=1040.0)
        check("THE PROPERTY: both transitions counted, flap not erased",
              bindings()[HOST]["changes"], 2)
        check("...binding ends on the last observed mac", bindings()[HOST]["mac"], MAC_A)
        check("...previous_mac is the one immediately before it",
              bindings()[HOST]["prev"], MAC_B)
        check("...a finding was raised for the contested address",
              any(f[1] == HOST for f in findings()), True)
        check("THE COUNT: one write even across two transitions",
              len(p.binding_writes()), 1)
        check("observed_count counts every raw observation (5+6)",
              bindings()[HOST]["count"], 11)
    finally:
        li._gateways = orig_gw

    print("\n[three distinct macs in one cycle]")
    n, p = cycle([obs(OTHER, MAC_A), obs(OTHER, MAC_B), obs(OTHER, MAC_C)], now=1050.0)
    check("first sighting then two moves = change_count 2",
          bindings()[OTHER]["changes"], 2)
    check("ends on the final mac", bindings()[OTHER]["mac"], MAC_C)
    check("THE COUNT: one write", len(p.binding_writes()), 1)

    print("\n[many IPs: writes scale with BINDINGS, not observations]")
    many = []
    for i in range(10, 30):
        many.extend([obs("192.0.2.%d" % i, MAC_A)] * 25)     # 20 IPs x 25 obs = 500
    n, p = cycle(many, now=1060.0)
    check("THE COUNT: 500 observations over 20 IPs produce 20 writes",
          len(p.binding_writes()), 20)
    check("...and 21 reads (20 priors + 1 multi-claim scan), not 500",
          len(p.binding_reads()), 21)

    passed = _count - len(_fail)
    print("\n%d/%d checks passed" % (passed, _count))
    if _fail:
        print("FAILED:")
        for f in _fail:
            print("  - " + f)
    if _count != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d -- a check was skipped, "
              "not merely failed" % (_count, EXPECTED_CHECKS))
        return 2
    return 1 if _fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
