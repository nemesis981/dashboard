#!/usr/bin/env python3
"""E-GATEWAY-* and E-FORKB-*: recorded from the REAL code paths.

Run: python3 alert_manager/test_gateway_forkb_codes.py

⚠ EXERCISES THE REAL FUNCTIONS, NOT A REPLAY OF THEIR LOGIC. The first version
of this check re-implemented `op_gateway_switch`'s phase->code decision in the
test and asserted against that -- which proves the copy agrees with itself and
nothing about the shipped code. `gateway_mode.switch` is stubbed to return each
result shape and the real `op_gateway_switch` is called.

WHAT THESE CODES ARE FOR
    Both catalogs are declared at the CALLER, because `core/gateway_mode.py`
    and `core/forkb_policy_route.py` are pure -- they return result dicts and do
    no I/O. Recording inside them would give them a database dependency they
    have deliberately never had.

    E-GATEWAY-003 is the one that matters most: "rolled back and NOT restored
    -- MANUAL RECOVERY NEEDED" is the highest-blast-radius outcome this product
    can produce, and it was reported at log.info and recorded nowhere. It is the
    only CRITICAL in either catalog.

    E-FORKB's recorder REFUSES TO WRITE AS ROOT. This file is both a daemon
    (User=nemesis-vpndns) and a CLI install.sh runs as root, and a root write to
    alerts.db leaves root-owned WAL siblings that lock nemesis-dash out of its
    own database -- the hazard drift_watch.py documents.
"""
import sys
import types

sys.path.insert(0, "/opt/nemesis/alert_manager")
sys.path.insert(0, "/opt/nemesis/core")
sys.path.insert(0, "/opt/nemesis")

import nemesis_fwd as F                                        # noqa: E402
import vpn_dns_guard as V                                      # noqa: E402

EXPECTED_CHECKS = 17
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 40:
        g, w = g[:37] + "...", w[:37] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def switch_returning(result):
    """Call the REAL op_gateway_switch with gateway_mode.switch stubbed."""
    recorded = []
    real_switch = F.gateway_mode.switch
    real_rec = F._errors_record
    F.gateway_mode.switch = lambda *a, **k: result
    F._errors_record = lambda code, ctx: recorded.append((code, ctx))
    try:
        F.op_gateway_switch({"enable": False, "iface": "eth1",
                             "cidr": "192.0.2.0/24"})
    finally:
        F.gateway_mode.switch = real_switch
        F._errors_record = real_rec
    return recorded


def main():
    print("\n1. E-GATEWAY: the phase -> code decision, in the REAL function")
    rec = switch_returning({"ok": False, "phase": "rollback", "restored": False,
                            "reason": "NOT restored -- MANUAL RECOVERY NEEDED"})
    check("unrestored rollback -> E-GATEWAY-003", rec[0][0], "E-GATEWAY-003")
    check("...context carries restored=False", rec[0][1]["restored"], False)

    rec = switch_returning({"ok": False, "phase": "rollback", "restored": True,
                            "reason": "step failed; rolled back"})
    check("a rollback that DID restore is not the manual-recovery code",
          rec[0][0], "E-GATEWAY-002")

    rec = switch_returning({"ok": False, "phase": "verify",
                            "reason": "SNAT chain: COULD NOT BE MEASURED, so ..."})
    check("unmeasured axis -> E-GATEWAY-001 (unverifiable)",
          rec[0][0], "E-GATEWAY-001")

    rec = switch_returning({"ok": False, "phase": "verify",
                            "reason": "ruleset: SNAT chain missing"})
    check("verified-and-wrong -> E-GATEWAY-004 (not the same as unverifiable)",
          rec[0][0], "E-GATEWAY-004")

    rec = switch_returning({"ok": False, "phase": "plan",
                            "reason": "needs iface and cidr"})
    check("any other failure -> E-GATEWAY-002", rec[0][0], "E-GATEWAY-002")

    print("\n2. CONTROL: a SUCCESSFUL switch records nothing")
    # Without this, a recorder that fired unconditionally would pass everything
    # above while filling the ledger with noise on every healthy switch.
    rec = switch_returning({"ok": True, "phase": "done", "reason": "applied"})
    check("success records no code", rec, [])

    print("\n3. E-GATEWAY severities: exactly one CRITICAL, and it is the right one")
    gw = {k: v for k, v in F._ERR_CODES.items() if k.startswith("E-GATEWAY")}
    check("four codes declared", len(gw), 4)
    check("MANUAL RECOVERY is the only CRITICAL",
          [k for k, (_d, s, _c) in gw.items() if s == "CRITICAL"],
          ["E-GATEWAY-003"])
    check("unverifiable and verified-wrong share a class",
          gw["E-GATEWAY-001"][2] == gw["E-GATEWAY-004"][2], True)
    check("...distinct from the failed-switch class",
          gw["E-GATEWAY-001"][2] != gw["E-GATEWAY-002"][2], True)

    print("\n4. E-FORKB: the recorder REFUSES to write as root")
    real_euid = V.os.geteuid
    V.os.geteuid = lambda: 0
    try:
        out = V._record(V.E_MASQ_KIND_UNDETERMINED, {"interfaces": ["wg0"]})
    finally:
        V.os.geteuid = real_euid
    check("as root -> records nothing", out, None)
    # CONTROL: it is refusing because of the euid, not because it is broken.
    # A non-root call must at least REACH the recorder rather than short-circuit.
    reached = {}
    real_rec = V._recorder
    V._recorder = lambda code, context=None: reached.setdefault("code", code)
    try:
        V._record(V.E_MASQ_KIND_UNDETERMINED, {"interfaces": ["wg0"]})
    finally:
        V._recorder = real_rec
    check("CONTROL non-root DOES reach the recorder",
          reached.get("code"), V.E_MASQ_KIND_UNDETERMINED)

    print("\n5. both catalogs are sound and phantom-free")
    check("E-FORKB has 5 codes", len(V._ERR_CODES), 5)
    check("every E-FORKB code has a description and severity",
          all(d and s for d, s, _c in V._ERR_CODES.values()), True)
    vsrc = open("/opt/nemesis/core/vpn_dns_guard.py", encoding="utf-8").read()
    const = {v: k for k, v in vars(V).items()
             if isinstance(v, str) and v.startswith("E-FORKB-")}
    check("no E-FORKB phantoms (every code has a call site)",
          [c for c in V._ERR_CODES if vsrc.count(const.get(c, "@@")) < 2], [])
    fsrc = open("/opt/nemesis/alert_manager/nemesis_fwd.py", encoding="utf-8").read()
    check("no E-GATEWAY phantoms",
          [c for c in gw if fsrc.count('"%s"' % c) < 2], [])

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
