#!/usr/bin/env python3
"""Gateway Mode: an axis that could not be READ must not verify as CLEAN.

Run: python3 core/test_gateway_unmeasured.py

THE BUG THIS PINS, and why the disable direction is where it bit. Every failed
read in `_gw_collect` fell back to a value that happens to BE the pass
condition when disabling:

    unreadable sysctl drop-in -> ""   -> dropin_says_enabled("") is False
                                      -> "forwarding not persisted"  = PASS
    unreadable /etc/nemesis.env -> {} -> configured False
                                      -> "still persisted" never fires = PASS
    nft command failed -> empty stdout -> snat_present False
                                      -> "chain still present" never fires = PASS

So three independent read failures each produced a confident "successfully
disabled" verdict about a box whose real state nobody knew. `verify_state` now
takes `unmeasured` and refuses to pass on any named axis.

⚠ THE CONTROLS CARRY EQUAL WEIGHT. A change that made verification always fail
would satisfy every check in section 2 while breaking the feature outright, so
the healthy enable AND disable paths are both asserted to still pass.
"""
import sys

sys.path.insert(0, "/opt/nemesis")

from core import gateway_mode as G                             # noqa: E402

EXPECTED_CHECKS = 14
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 40:
        g, w = g[:37] + "...", w[:37] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


# A box correctly DISABLED: nothing persisted, forwarding off, no SNAT chain.
DISABLED = dict(enable=False, config_iface=None, config_cidr=None,
                dropin_content="", live_output="0", snat_present=False)

# A box correctly ENABLED.
ENABLED = dict(enable=True, config_iface="eth1", config_cidr="192.0.2.0/24",
               dropin_content="net.ipv4.ip_forward=1", live_output="1",
               snat_present=True)


def main():
    print("\n1. CONTROLS: the healthy verdicts still pass")
    ok, problems = G.verify_state(**DISABLED)
    check("a correctly DISABLED box verifies clean", (ok, problems), (True, []))
    ok, problems = G.verify_state(**ENABLED)
    check("a correctly ENABLED box verifies clean", (ok, problems), (True, []))
    # Without these two, everything below could pass by always failing.

    print("\n2. THE FIX: an unmeasured axis cannot verify clean")
    for axis in ("forwarding drop-in (PermissionError)",
                 "live forwarding (sysctl rc=1)",
                 "SNAT chain (nft rc=1)",
                 "persisted gateway config (nemesis.env unreadable)"):
        ok, problems = G.verify_state(unmeasured=[axis], **DISABLED)
        check("unmeasured %-28s -> refuses" % axis.split(" (")[0], ok, False)

    print("\n3. the refusal explains itself")
    ok, problems = G.verify_state(unmeasured=["SNAT chain (nft rc=1)"], **DISABLED)
    check("the problem names the axis",
          any("SNAT chain" in p for p in problems), True)
    check("...and says it could not be measured",
          any("COULD NOT BE MEASURED" in p for p in problems), True)
    check("...and does not silently pass alongside real problems",
          len(problems) >= 1, True)

    print("\n4. it applies to the ENABLE direction too")
    # The enable path was less exposed (its pass conditions are positive, so a
    # failed read tended to fail closed already) -- but "tended to" is not a
    # guarantee, and the guard must not be direction-specific.
    ok, _ = G.verify_state(unmeasured=["live forwarding (sysctl rc=1)"], **ENABLED)
    check("an unmeasured axis refuses when enabling as well", ok, False)

    print("\n5. real problems are still reported, and ALONGSIDE unmeasured ones")
    # A half-applied disable with one unreadable axis must report BOTH, or the
    # new guard would mask the original verification.
    bad = dict(DISABLED, config_iface="eth1", config_cidr="192.0.2.0/24")
    ok, problems = G.verify_state(unmeasured=["SNAT chain (nft rc=1)"], **bad)
    check("still refuses", ok, False)
    check("...reports the REAL problem (config still persisted)",
          any("still persisted" in p for p in problems), True)
    check("...and the unmeasured axis, both", len(problems) >= 2, True)

    print("\n6. the default keeps every existing caller working")
    # unmeasured is keyword-with-default so the 102 existing gateway_mode
    # checks, and any caller not yet updated, behave exactly as before.
    ok, problems = G.verify_state(False, None, None, "", "0", False)
    check("positional call with no unmeasured arg still passes",
          (ok, problems), (True, []))

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
