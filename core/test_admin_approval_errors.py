#!/usr/bin/env python3
"""E-APPROVAL-* : the bridge from the AAP-/GATE- wire vocabulary.

Run: python3 core/test_admin_approval_errors.py

THE CHECK THAT MATTERS MOST IS COMPLETENESS. The mapping groups 17 domain codes
into 4 rejection buckets. If someone adds a code to `Reason.ALL` or
`GateReason.ALL` upstream and does not classify it, `classify()` falls back to
the CRYPTO bucket with `unmapped=True` -- deliberately the loud direction, since
a new security-relevant refusal quietly filed as routine is how a real signal
goes unnoticed. But a fallback is a safety net, not a plan: the completeness
test below fails the moment a domain code is unclassified, so the net should
never be needed.

THE OTHER PROPERTY: the audit-gap code must stay distinguishable from the
rejection codes. They are different KINDS of event -- four are refusals of
things that never happened, and E-APPROVAL-005 is the missing record of a
privileged action that already DID, spent and unreplayable. Asserted by
error_class, not by convention.

NO DATABASE, NO NETWORK: `classify()` is pure. Recording is exercised by the
dashboard-side wiring, which is covered separately.
"""
import os
import sys

sys.path.insert(0, "/opt/nemesis")

from core import admin_approval_errors as E                   # noqa: E402
from core.admin_approval import Reason                        # noqa: E402
from core.admin_approval_gate import GateReason               # noqa: E402

EXPECTED_CHECKS = 28
_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 44:
        g, w = g[:41] + "...", w[:41] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def main():
    print("\n1. COMPLETENESS: every domain code is classified")
    all_domain = set(Reason.ALL) | set(GateReason.ALL)
    check("the vocabulary is the size we think it is", len(all_domain), 17)
    mapped = E._CRYPTO | E._SCOPE | E._LIFECYCLE | E._RATE
    check("every AAP-/GATE- code appears in exactly one bucket",
          sorted(all_domain - mapped), [])
    check("no bucket contains a code the vocabulary does not define",
          sorted(mapped - all_domain), [])
    # Buckets must be disjoint, or "exactly one" above is not actually true.
    buckets = (E._CRYPTO, E._SCOPE, E._LIFECYCLE, E._RATE)
    overlap = set()
    for i, a in enumerate(buckets):
        for b in buckets[i + 1:]:
            overlap |= (a & b)
    check("the buckets are disjoint", sorted(overlap), [])
    # And every domain code resolves without hitting the unmapped fallback.
    unmapped = [c for c in all_domain if E.classify(aap_code=c)[1]]
    check("NO domain code reaches the unmapped fallback", unmapped, [])

    print("\n2. the classification an operator depends on")
    check("BAD_SIGNATURE -> crypto (attack signal)",
          E.classify(aap_code=Reason.BAD_SIGNATURE)[0], E.E_REJECTED_CRYPTO)
    check("UV_NOT_ASSERTED -> crypto",
          E.classify(aap_code=Reason.UV_NOT_ASSERTED)[0], E.E_REJECTED_CRYPTO)
    check("COUNTER_REGRESSION -> crypto (cloned authenticator)",
          E.classify(aap_code=Reason.COUNTER_REGRESSION)[0], E.E_REJECTED_CRYPTO)
    check("EXPIRED -> lifecycle (routine)",
          E.classify(aap_code=Reason.EXPIRED)[0], E.E_REJECTED_LIFECYCLE)
    check("ALREADY_CONSUMED -> lifecycle",
          E.classify(aap_code=Reason.ALREADY_CONSUMED)[0], E.E_REJECTED_LIFECYCLE)
    check("BINDING_MISMATCH -> scope (operator error)",
          E.classify(aap_code=Reason.BINDING_MISMATCH)[0], E.E_REJECTED_SCOPE)
    check("TARGET_MISMATCH (a GATE code) -> scope",
          E.classify(reason=GateReason.TARGET_MISMATCH)[0], E.E_REJECTED_SCOPE)
    check("RATE_LIMITED -> its own code",
          E.classify(aap_code=Reason.RATE_LIMITED)[0],
          E.E_REJECTED_RATE_LIMITED)
    # THE DISTINCTION THE WHOLE BRIDGE EXISTS FOR.
    check("a forged signature and an expired request are DIFFERENT codes",
          E.classify(aap_code=Reason.BAD_SIGNATURE)[0]
          != E.classify(aap_code=Reason.EXPIRED)[0], True)

    print("\n3. GATE-004 must not mask the inner verdict")
    # GATE-004 means "the inner §7 verification failed, see .verdict". Reading
    # the outer code would file a forged signature as ordinary lifecycle --
    # exactly the conflation this bridge ends.
    check("GATE-004 alone -> lifecycle",
          E.classify(reason=GateReason.APPROVAL_REJECTED)[0],
          E.E_REJECTED_LIFECYCLE)
    check("GATE-004 CARRYING a BAD_SIGNATURE -> crypto, not lifecycle",
          E.classify(reason=GateReason.APPROVAL_REJECTED,
                     aap_code=Reason.BAD_SIGNATURE)[0], E.E_REJECTED_CRYPTO)
    check("...the inner code wins over the outer one",
          E.classify(reason=GateReason.APPROVAL_REJECTED,
                     aap_code=Reason.BAD_SIGNATURE)[0]
          != E.classify(reason=GateReason.APPROVAL_REJECTED)[0], True)

    print("\n4. an UNKNOWN code fails toward the loud answer")
    code, unmapped = E.classify(aap_code="AAP-999")
    check("an unrecognised code is flagged unmapped", unmapped, True)
    check("...and lands in CRYPTO, not lifecycle", code, E.E_REJECTED_CRYPTO)
    check("nothing at all -> still flagged, still loud",
          E.classify(), (E.E_REJECTED_CRYPTO, True))
    # CONTROL: unmapped must not be set for a code that IS mapped, or the flag
    # is meaningless.
    check("CONTROL a mapped code is NOT flagged unmapped",
          E.classify(aap_code=Reason.EXPIRED)[1], False)

    print("\n5. the audit gap is a different KIND of event")
    classes = {c: cls for c, _d, _s, cls in E._CATALOG}
    check("E-APPROVAL-005 has its own error_class",
          classes[E.E_AUDIT_GAP], E._CLASS_AUDIT_GAP)
    check("...distinct from every rejection code's class",
          {classes[c] for c in (E.E_REJECTED_CRYPTO, E.E_REJECTED_SCOPE,
                                E.E_REJECTED_LIFECYCLE,
                                E.E_REJECTED_RATE_LIMITED)},
          {E._CLASS_REJECTED})
    check("...and classify() can NEVER return it "
          "(it is not a refusal)",
          E.E_AUDIT_GAP in {E.classify(aap_code=c)[0] for c in all_domain}
          or E.classify()[0] == E.E_AUDIT_GAP, False)

    print("\n6. severities reflect the operator's urgency")
    sev = {c: s for c, _d, s, _cls in E._CATALOG}
    check("crypto is high", sev[E.E_REJECTED_CRYPTO], "high")
    check("the audit gap is high", sev[E.E_AUDIT_GAP], "high")
    check("lifecycle is low (routine, must not cry wolf)",
          sev[E.E_REJECTED_LIFECYCLE], "low")
    check("scope sits between them", sev[E.E_REJECTED_SCOPE], "medium")

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
