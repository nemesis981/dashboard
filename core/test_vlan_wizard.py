#!/usr/bin/env python3
"""The guided VLAN setup flow: pure question/outcome logic, no UI, no probing.

Run: python3 core/test_vlan_wizard.py   (exit 0 = all pass)

WHY A WIZARD AND NOT A YES/NO TOGGLE. Most people do not know whether their
network hardware supports VLANs, and asking them directly ("is your switch
802.1Q-capable?") filters for the people who did not need to be asked. The flow
asks practical, answerable questions instead and derives the answer.

⛔ THREE OUTCOMES, NOT TWO, AND THE MIDDLE ONE IS THE POINT. A VLAN-capable
switch that is not CONFIGURED still cannot be used -- Nemesis cannot trunk a
switch port from an end-host position. So "capable" and "usable" are different
answers, and collapsing them fails in both directions: fold the middle into
UNAVAILABLE and you tell someone with good hardware they cannot have the
feature; fold it into READY and you enable a mode that silently does nothing.
The middle case is common -- anyone who bought a managed switch and never
configured it.

FAILS CLOSED EVERYWHERE. Unknown, unanswered, and "I am not sure" all resolve
AWAY from READY. The cost of a wrong "no" is a person who has to look something
up; the cost of a wrong "yes" is a mode that appears enabled and enforces
nothing.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import vlan_wizard as W  # noqa: E402

EXPECTED_CHECKS = 40
_count = 0
_fail = []


def check(label, got, want):
    global _count
    _count += 1
    ok = (got == want)
    if not ok:
        _fail.append(label)
    print("  %-64s %s" % (label, "PASS" if ok else "FAIL (got=%r want=%r)" % (got, want)))


def test_questions_are_answerable_by_a_non_expert():
    print("\n[the questions must not require the knowledge they exist to establish]")
    qs = W.QUESTIONS
    check("there are questions at all", len(qs) >= 3, True)
    ids = [q["id"] for q in qs]
    check("question ids are unique", len(set(ids)), len(ids))
    for q in qs:
        check("  %-22s has options" % q["id"], len(q["options"]) >= 2, True)
        check("  %-22s offers an 'unsure' escape" % q["id"],
              any(o["value"] == "unsure" for o in q["options"]), True)
    # The whole point: a person who could answer "do you have VLANs?" does not
    # need this flow. If that phrasing appears, the wizard has become the thing
    # it replaces.
    blob = " ".join(q["text"].lower() for q in qs)
    for jargon in ("vlan", "802.1q", "trunk", "tagged", "subnet"):
        check("  asks nothing about %-8s in the question text" % jargon, jargon in blob, False)


def test_isp_supplied_router_exits_immediately():
    print("\n[early exit: most users are done on question one]")
    out, reason = W.evaluate({"gear_origin": "provider"})
    check("ISP-supplied gear -> unavailable", out, W.OUTCOME_UNAVAILABLE)
    check("  ...with a reason naming the gear, not a shrug", reason, "isp_supplied")
    check("  ...and no further question is asked",
          W.next_question({"gear_origin": "provider"}), None)


def test_no_separate_switch_is_unavailable():
    print("\n[no switch means no layer-2 separation, whatever the router can do]")
    a = {"gear_origin": "own", "separate_switch": "no"}
    out, reason = W.evaluate(a)
    check("no separate switch -> unavailable", out, W.OUTCOME_UNAVAILABLE)
    check("  ...reason is the missing switch", reason, "no_switch")
    check("  ...flow stops there", W.next_question(a), None)


def test_capable_but_unconfigured_is_its_own_outcome():
    print("\n[THE CASE A YES/NO GETS WRONG: good hardware, not set up]")
    a = {"gear_origin": "own", "separate_switch": "yes",
         "managed_ui": "yes", "vlans_configured": "no"}
    out, reason = W.evaluate(a)
    check("capable but not configured -> prerequisites", out, W.OUTCOME_PREREQUISITES)
    check("  ...reason distinguishes it from 'cannot'", reason, "not_configured")
    check("  ...and it is NOT ready", out == W.OUTCOME_READY, False)
    check("  ...and it is NOT unavailable", out == W.OUTCOME_UNAVAILABLE, False)


def test_only_an_explicit_yes_reaches_ready():
    print("\n[fail closed: unsure never becomes yes]")
    base = {"gear_origin": "own", "separate_switch": "yes", "managed_ui": "yes"}
    ready, _ = W.evaluate(dict(base, vlans_configured="yes"))
    check("explicit yes -> ready", ready, W.OUTCOME_READY)
    for v in ("no", "unsure"):
        o, _ = W.evaluate(dict(base, vlans_configured=v))
        check("  vlans_configured=%-6s does NOT reach ready" % v, o == W.OUTCOME_READY, False)
    o, _ = W.evaluate(dict(base, managed_ui="unsure", vlans_configured="yes"))
    check("  unsure about the switch being managed does NOT reach ready",
          o == W.OUTCOME_READY, False)


def test_incomplete_answers_never_resolve():
    print("\n[an unanswered wizard must not decide anything]")
    o, _ = W.evaluate({})
    check("no answers -> undecided", o, W.OUTCOME_UNDECIDED)
    check("  ...and the flow asks its first question",
          W.next_question({})["id"], W.QUESTIONS[0]["id"])
    partial = {"gear_origin": "own", "separate_switch": "yes"}
    o, _ = W.evaluate(partial)
    check("partial answers -> still undecided", o, W.OUTCOME_UNDECIDED)
    check("  ...and it asks the NEXT unanswered question",
          W.next_question(partial)["id"], "managed_ui")
    # An unrecognised value means the question is effectively UNANSWERED, and the
    # assertion says exactly that rather than the weaker "does not reach ready".
    # "Not READY" is satisfied by PREREQUISITES too, so the weak form let a
    # mutation that accepted any non-None value survive: garbage fell through to
    # PREREQUISITES, which is still not READY. Asserting the exact outcome, and
    # that the flow re-asks the question, is what actually pins the behaviour.
    garbage = dict(partial, managed_ui="banana", vlans_configured="yes")
    check("an unrecognised answer leaves the flow UNDECIDED",
          W.evaluate(garbage)[0], W.OUTCOME_UNDECIDED)
    check("  ...with the reason 'incomplete', not a decision",
          W.evaluate(garbage)[1], "incomplete")
    check("  ...and the flow re-asks that same question",
          W.next_question(garbage)["id"], "managed_ui")


def test_outcome_maps_to_the_capability_gate():
    print("\n[the wizard's answer is what vlan_available() consumes]")
    import gateway_mode as G
    check("READY declares capability to the gate",
          G.MODE_GATEWAY_VLAN in G.vlan_available(W.declares_capable(W.OUTCOME_READY)), True)
    for o in (W.OUTCOME_PREREQUISITES, W.OUTCOME_UNAVAILABLE, W.OUTCOME_UNDECIDED):
        check("  %-14s does not" % o,
              G.MODE_GATEWAY_VLAN in G.vlan_available(W.declares_capable(o)), False)


def main():
    test_questions_are_answerable_by_a_non_expert()
    test_isp_supplied_router_exits_immediately()
    test_no_separate_switch_is_unavailable()
    test_capable_but_unconfigured_is_its_own_outcome()
    test_only_an_explicit_yes_reaches_ready()
    test_incomplete_answers_never_resolve()
    test_outcome_maps_to_the_capability_gate()
    print()
    if _count != EXPECTED_CHECKS:
        print("SUITE DRIFT: ran %d checks, expected %d" % (_count, EXPECTED_CHECKS))
        return 1
    if _fail:
        print("FAILED (%d of %d)" % (len(_fail), _count))
        for f in _fail:
            print("  -", f)
        return 1
    print("ALL PASS (%d checks)" % _count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
