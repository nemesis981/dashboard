"""Validation for memladder — the escalation ladder.

Run:  python3 nemesis_agent/test_memladder.py

Escalation is a function of HISTORY, which is exactly why it is worth testing in
a pure form: the cases that matter are "the fourth consecutive breach", "a breach
that cleared on sample three", and "the sampler went blind for two samples". On a
real box those cost hours and induced memory pressure. Here they are lists.

Two properties carry the most weight, because both fail silently:

  * RESTART must be SHADOW. A ladder that quietly executed restarts would look
    identical in every log line to one that recorded them — right up until it
    bounced a production service nobody approved it to touch.
  * Promotion must count only RESOLVED decisions. Counting unresolved ones lets
    volume masquerade as confidence, which is precisely the "guess or fixed
    timeout" that was ruled out.
"""

import ast
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import memladder as ml  # noqa: E402

_failures = []


def check(label, got, want):
    if got != want:
        _failures.append("%s: got %r, want %r" % (label, got, want))
        print("  FAIL  %s: got %r, want %r" % (label, got, want))
    else:
        print("  ok    %s" % label)


def V(verdict, name="svc", observed=500.0, budget=100.0):
    return {"state": "ok", "components": {name: {
        "verdict": verdict, "observed_mb": observed, "budget_mb": budget,
        "basis": "uss", "detail": "test"}}}


def run(verdicts_seq, exempt=frozenset(), policy=None):
    """Feed a sequence of verdicts; return (state, all_actions)."""
    st, acts = ml.new_state(), []
    for v in verdicts_seq:
        st, a = ml.decide(v, st, policy, exempt=exempt)
        acts.extend(a)
    return st, acts


# ── escalation shape ─────────────────────────────────────────────────────────

def test_single_breach_does_not_act():
    print("\n[one breach never acts — memory spikes transiently]")
    st, acts = run([V("breach")])
    check("no actions", acts, [])
    check("streak recorded", st["components"]["svc"]["breach_streak"], 1)
    check("rung still none", st["components"]["svc"]["rung"], ml.RUNG_NONE)


def test_escalation_is_monotonic_and_ordered():
    print("\n[rungs are climbed one at a time, in order, never skipped]")
    st, acts = run([V("breach")] * 20)
    climbed = [a["rung"] for a in acts if a["kind"] == "escalate"]
    check("exact order", climbed,
          [ml.RUNG_ALERT, ml.RUNG_THROTTLE, ml.RUNG_ABORT, ml.RUNG_RESTART])
    check("no rung reached twice", len(climbed), len(set(climbed)))
    check("tops out at restart", st["components"]["svc"]["rung"], ml.RUNG_RESTART)


def test_monotonic_holds_when_the_streak_JUMPS():
    """The rung-skip case a rising streak can never expose.

    Feeding breaches one at a time crosses each threshold in turn, so cur and
    target are never more than one apart and a skip-implementation looks
    identical to a stepping one. The guarantee only bites when state arrives
    with a HIGH streak and a LOW rung — persisted state from an older policy,
    thresholds lowered under a running system, or a restored ladder. Then a
    skipping ladder jumps straight to RESTART on a single decision.
    """
    print("\n[a jump in streak still climbs ONE rung, not straight to the top]")
    st = {"components": {"svc": {"breach_streak": 99, "ok_streak": 0,
                                 "rung": ml.RUNG_NONE}}}
    st2, acts = ml.decide(V("breach"), st, ml.DEFAULT_POLICY)
    check("exactly one action", len(acts), 1)
    check("stepped to ALERT, not RESTART", acts[0]["rung"], ml.RUNG_ALERT)
    check("state agrees", st2["components"]["svc"]["rung"], ml.RUNG_ALERT)
    # and from mid-ladder it still steps by one
    st3 = {"components": {"svc": {"breach_streak": 99, "ok_streak": 0,
                                  "rung": ml.RUNG_ALERT}}}
    _, acts3 = ml.decide(V("breach"), st3, ml.DEFAULT_POLICY)
    check("mid-ladder steps to THROTTLE only", acts3[0]["rung"], ml.RUNG_THROTTLE)


def test_restart_is_shadow_and_lower_rungs_are_live():
    print("\n[RESTART is shadow; alert/throttle/abort are live]")
    _, acts = run([V("breach")] * 20)
    mode = {a["rung"]: a["mode"] for a in acts if a["kind"] == "escalate"}
    check("alert live", mode[ml.RUNG_ALERT], ml.MODE_LIVE)
    check("throttle live", mode[ml.RUNG_THROTTLE], ml.MODE_LIVE)
    check("abort live", mode[ml.RUNG_ABORT], ml.MODE_LIVE)
    check("restart SHADOW", mode[ml.RUNG_RESTART], ml.MODE_SHADOW)


# ── the exemption ────────────────────────────────────────────────────────────

def test_exempt_component_caps_at_alert():
    print("\n[a recovery-exempt component is alerted about and never acted on]")
    st, acts = run([V("breach", name="clamav-daemon")] * 20,
                   exempt={"clamav-daemon"})
    climbed = [a["rung"] for a in acts if a["kind"] == "escalate"]
    check("only ever alert", climbed, [ml.RUNG_ALERT])
    check("never throttled", ml.RUNG_THROTTLE in climbed, False)
    check("never restarted (even in shadow)", ml.RUNG_RESTART in climbed, False)
    check("its breach is still tracked",
          st["components"]["clamav-daemon"]["breach_streak"], 20)


def test_non_exempt_control_does_escalate():
    """CONTROL: a ladder that capped everything would pass the test above."""
    print("\n[CONTROL: a non-exempt component climbs past alert]")
    _, acts = run([V("breach")] * 20, exempt={"something-else"})
    climbed = [a["rung"] for a in acts if a["kind"] == "escalate"]
    check("reaches throttle", ml.RUNG_THROTTLE in climbed, True)
    check("reaches abort", ml.RUNG_ABORT in climbed, True)


# ── the things that must NOT move the ladder ────────────────────────────────

def test_indeterminate_neither_escalates_nor_decays():
    print("\n[INDETERMINATE is not evidence in either direction]")
    st, acts = run([V("breach")] * 3 + [V("indeterminate")] * 5)
    check("no actions from the indeterminate run",
          [a for a in acts if a["kind"] == "escalate"][-1]["rung"], ml.RUNG_ALERT)
    check("breach streak preserved, not decayed",
          st["components"]["svc"]["breach_streak"], 3)
    check("rung held", st["components"]["svc"]["rung"], ml.RUNG_ALERT)


def test_blind_sampler_does_not_walk_an_escalation_back_down():
    print("\n['we could not measure' is not evidence of recovery]")
    st, _ = run([V("breach")] * 5)
    before = dict(st["components"]["svc"])
    st2, acts = ml.decide({"state": "unavailable", "reason": "psutil gone"}, st)
    check("state preserved verbatim", st2["components"]["svc"], before)
    check("reported as a sample failure, not a recovery",
          acts[0]["kind"], "sample_unavailable")
    check("no de-escalation emitted",
          [a for a in acts if a["kind"] == "de-escalate"], [])


def test_recovery_steps_down_one_rung_and_needs_sustained_health():
    print("\n[de-escalation requires sustained health and steps down one rung]")
    pol = ml.DEFAULT_POLICY
    st, _ = run([V("breach")] * 20)
    check("at restart", st["components"]["svc"]["rung"], ml.RUNG_RESTART)
    # not enough healthy samples yet
    for _ in range(pol["recover_after"] - 1):
        st, a = ml.decide(V("ok"), st, pol)
        check_none = [x for x in a if x["kind"] == "de-escalate"]
    check("no early de-escalation", check_none, [])
    st, a = ml.decide(V("ok"), st, pol)
    check("steps down exactly one rung", st["components"]["svc"]["rung"],
          ml.RUNG_ABORT)
    check("de-escalation reported", a[0]["kind"], "de-escalate")


# ── promotion evidence ───────────────────────────────────────────────────────

def test_promotion_refuses_without_resolved_evidence():
    print("\n[promotion counts only RESOLVED decisions]")
    unresolved = [{"component": "x"} for _ in range(500)]
    r = ml.promotion_readiness(unresolved)
    check("not ready on 500 unresolved", r["ready"], False)
    check("none counted as resolved", r["resolved"], 0)
    check("unresolved reported separately", r["unresolved_not_counted"], 500)


def test_superseded_is_not_credited_as_correct():
    print("\n[a breach that vanished is not the ladder's success]")
    recs = [{"outcome": ml.OUTCOME_SUPERSEDED} for _ in range(100)]
    r = ml.promotion_readiness(recs)
    check("not ready", r["ready"], False)
    check("not counted as correct", r["correct"], 0)
    check("visible, not silently dropped", r["superseded_not_counted"], 100)


def test_false_positive_rate_blocks_promotion():
    print("\n[too many unnecessary restarts blocks promotion]")
    recs = ([{"outcome": ml.OUTCOME_CORRECT}] * 30 +
            [{"outcome": ml.OUTCOME_UNNECESSARY}] * 10)   # 25%
    r = ml.promotion_readiness(recs)
    check("not ready", r["ready"], False)
    check("rate computed", round(r["unnecessary_rate"], 2), 0.25)
    check("reason names the ceiling",
          any("exceeds" in x for x in r["reasons"]), True)


def test_clean_record_does_promote():
    """CONTROL: a gate that refused everything would pass all three above."""
    print("\n[CONTROL: sufficient clean evidence DOES reach ready]")
    recs = [{"outcome": ml.OUTCOME_CORRECT}] * 25
    r = ml.promotion_readiness(recs)
    check("ready", r["ready"], True)
    check("no reasons", r["reasons"], [])
    check("rate is zero", r["unnecessary_rate"], 0.0)


# ── structure ────────────────────────────────────────────────────────────────

def test_ladder_is_pure_and_platform_neutral():
    print("\n[the ladder decides; it cannot act, and knows no platform]")
    here = os.path.dirname(os.path.abspath(__file__))
    tree = ast.parse(open(os.path.join(here, "memladder.py")).read())
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            b = getattr(node, "body", None)
            if (b and isinstance(b[0], ast.Expr)
                    and isinstance(b[0].value, ast.Constant)
                    and isinstance(b[0].value.value, str)):
                b.pop(0)
    code = ast.unparse(tree)
    for bad in ("subprocess", "systemctl", "os.kill", "import os", "import time",
                "psutil", "clamd", "open("):
        check("no %r in the ladder" % bad, bad in code, False)
    check("CONTROL body extracted", "def decide" in code, True)


def test_self_test_passes():
    print("\n[the module's own premise-proof passes]")
    st = ml.self_test()
    for f in st["findings"]:
        print("        finding: %s" % f)
    check("self_test ok", st["ok"], True)

def test_unresolved_until_enough_follow_up():
    print("\n[an outcome is not declared before there is evidence for one]")
    pol = ml.DEFAULT_POLICY
    r = ml.shadow_record({"component": "svc", "rung": ml.RUNG_RESTART}, 0)
    for _ in range(pol["resolve_after_samples"] - 1):
        r = ml.observe_follow_up(r, "breach")
    check("still unresolved", ml.classify_outcome(r, pol), None)
    r = ml.observe_follow_up(r, "breach")
    check("CONTROL: resolves once there is enough", ml.classify_outcome(r, pol),
          ml.OUTCOME_CORRECT)


def test_cleared_breach_resolves_unnecessary():
    print("\n[a breach that cleared and stayed clear = a false positive]")
    pol = ml.DEFAULT_POLICY
    r = ml.shadow_record({"component": "svc"}, 0)
    for v in ["breach", "breach"] + ["ok"] * 4:
        r = ml.observe_follow_up(r, v)
    check("unnecessary", ml.classify_outcome(r, pol), ml.OUTCOME_UNNECESSARY)


def test_absent_component_is_superseded_even_amid_breaches():
    print("\n[a vanished component is superseded, never credited as correct]")
    pol = ml.DEFAULT_POLICY
    r = ml.shadow_record({"component": "svc"}, 0)
    for v in ["breach", "breach", None, "breach", "breach", "breach"]:
        r = ml.observe_follow_up(r, v)
    check("superseded", ml.classify_outcome(r, pol), ml.OUTCOME_SUPERSEDED)
    check("not correct", ml.classify_outcome(r, pol) == ml.OUTCOME_CORRECT, False)


def test_only_indeterminate_follow_ups_stay_unresolved():
    print("\n[indeterminate follow-ups resolve nothing — not correct, not clear]")
    pol = ml.DEFAULT_POLICY
    r = ml.shadow_record({"component": "svc"}, 0)
    for _ in range(pol["resolve_after_samples"] + 2):
        r = ml.observe_follow_up(r, "indeterminate")
    check("unresolved", ml.classify_outcome(r, pol), None)


def test_resolve_records_is_pure():
    print("\n[resolution does not mutate the records it is given]")
    r = ml.shadow_record({"component": "svc"}, 0)
    for _ in range(6):
        r = ml.observe_follow_up(r, "breach")
    before = dict(r)
    out = ml.resolve_records([r])
    check("input untouched", r, before)
    check("output resolved", out[0]["outcome"], ml.OUTCOME_CORRECT)


def test_the_promotion_loop_can_actually_close():
    """A gate that can never open is the same trap as one that always opens."""
    print("\n[shadow -> resolved -> ready: the loop closes end to end]")
    pol = ml.DEFAULT_POLICY
    recs = []
    for _ in range(pol["promote_min_resolved"]):
        r = ml.shadow_record({"component": "svc", "rung": ml.RUNG_RESTART}, 0)
        for _ in range(pol["resolve_after_samples"]):
            r = ml.observe_follow_up(r, "breach")
        recs.append(r)
    resolved = ml.resolve_records(recs, pol)
    rd = ml.promotion_readiness(resolved, pol)
    check("all resolved", rd["resolved"], pol["promote_min_resolved"])
    check("ready", rd["ready"], True)
    # CONTROL: the same volume of false positives must NOT open the gate.
    bad = []
    for _ in range(pol["promote_min_resolved"]):
        r = ml.shadow_record({"component": "svc"}, 0)
        for v in ["breach"] + ["ok"] * 5:
            r = ml.observe_follow_up(r, v)
        bad.append(r)
    rd2 = ml.promotion_readiness(ml.resolve_records(bad, pol), pol)
    check("CONTROL false positives do not promote", rd2["ready"], False)


# ── per-component available rungs ────────────────────────────────────────────

def test_missing_rung_is_skipped_and_recorded():
    print("\n[a structurally-absent rung is skipped, and the skip is recorded]")
    # suricata-shaped: alert and restart exist, throttle/abort do not.
    avail = {"svc": {ml.RUNG_ALERT, ml.RUNG_RESTART}}
    st, acts = ml.new_state(), []
    for _ in range(20):
        st, a = ml.decide(V("breach"), st, ml.DEFAULT_POLICY, available=avail)
        acts.extend(a)
    climbed = [a["rung"] for a in acts if a["kind"] == "escalate"]
    check("only existing rungs reached", climbed, [ml.RUNG_ALERT, ml.RUNG_RESTART])
    check("throttle never claimed", ml.RUNG_THROTTLE in climbed, False)
    rec = [a for a in acts if a.get("rung") == ml.RUNG_RESTART][0]
    check("the skip is recorded, not silent",
          rec["skipped_rungs"], [ml.RUNG_THROTTLE, ml.RUNG_ABORT])


def test_skipping_never_accelerates_escalation():
    """The dangerous misreading: 'no gentle option' must not mean 'act sooner'."""
    print("\n[a missing rung makes escalation WAIT, never arrive earlier]")
    pol = ml.DEFAULT_POLICY
    avail = {"svc": {ml.RUNG_ALERT, ml.RUNG_RESTART}}
    st, first_restart_at = ml.new_state(), None
    for i in range(1, 21):
        st, a = ml.decide(V("breach"), st, pol, available=avail)
        if any(x.get("rung") == ml.RUNG_RESTART and x["kind"] == "escalate" for x in a):
            first_restart_at = i
            break
    check("restart waits for its OWN justification threshold",
          first_restart_at, pol["restart_after"])
    check("not reached at the throttle threshold",
          first_restart_at == pol["throttle_after"], False)


def test_alert_only_component_never_climbs():
    print("\n[an alert-only component (dashboard) stops at alert]")
    avail = {"svc": {ml.RUNG_ALERT}}
    st, acts = ml.new_state(), []
    for _ in range(20):
        st, a = ml.decide(V("breach"), st, ml.DEFAULT_POLICY, available=avail)
        acts.extend(a)
    climbed = [a["rung"] for a in acts if a["kind"] == "escalate"]
    check("only alert", climbed, [ml.RUNG_ALERT])
    blocked = [a for a in acts if a["kind"] == "blocked"]
    check("being stuck is reported", len(blocked) >= 1, True)
    check("...and not re-reported every sample", len(blocked) <= 3, True)
    check("blocked names what it was justified for",
          blocked[0]["justified_rung"], ml.RUNG_THROTTLE)


def test_default_availability_is_unchanged_behaviour():
    """CONTROL: omitting `available` must behave exactly as before."""
    print("\n[CONTROL: no availability map = all rungs, previous behaviour]")
    st, acts = ml.new_state(), []
    for _ in range(20):
        st, a = ml.decide(V("breach"), st, ml.DEFAULT_POLICY)
        acts.extend(a)
    climbed = [a["rung"] for a in acts if a["kind"] == "escalate"]
    check("full ladder", climbed,
          [ml.RUNG_ALERT, ml.RUNG_THROTTLE, ml.RUNG_ABORT, ml.RUNG_RESTART])
    check("nothing skipped",
          all(a.get("skipped_rungs") == [] for a in acts if a["kind"] == "escalate"),
          True)


if __name__ == "__main__":
    print("memladder — escalation ladder")

    def _run(fn):
        # A test that RAISES must be recorded and the suite must continue.
        # Aborting on the first exception hides every check after it — which is
        # exactly what happened the first time these mutants were run.
        try:
            fn()
        except Exception as exc:
            _failures.append("%s raised %s: %s"
                             % (fn.__name__, type(exc).__name__, exc))
            print("  FAIL  %s raised %s: %s"
                  % (fn.__name__, type(exc).__name__, exc))

    for _fn in (
        test_single_breach_does_not_act,
        test_escalation_is_monotonic_and_ordered,
        test_monotonic_holds_when_the_streak_JUMPS,
        test_restart_is_shadow_and_lower_rungs_are_live,
        test_exempt_component_caps_at_alert,
        test_non_exempt_control_does_escalate,
        test_indeterminate_neither_escalates_nor_decays,
        test_blind_sampler_does_not_walk_an_escalation_back_down,
        test_recovery_steps_down_one_rung_and_needs_sustained_health,
        test_promotion_refuses_without_resolved_evidence,
        test_superseded_is_not_credited_as_correct,
        test_false_positive_rate_blocks_promotion,
        test_clean_record_does_promote,
        test_ladder_is_pure_and_platform_neutral,
        test_self_test_passes,
        test_unresolved_until_enough_follow_up,
        test_cleared_breach_resolves_unnecessary,
        test_absent_component_is_superseded_even_amid_breaches,
        test_only_indeterminate_follow_ups_stay_unresolved,
        test_resolve_records_is_pure,
        test_the_promotion_loop_can_actually_close,
        test_missing_rung_is_skipped_and_recorded,
        test_skipping_never_accelerates_escalation,
        test_alert_only_component_never_climbs,
        test_default_availability_is_unchanged_behaviour,
    ):
        _run(_fn)




# ── shadow outcome resolution: the loop that turns decisions into evidence ───
    print("\n" + "=" * 64)
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  - %s" % f)
        sys.exit(1)
    print("ALL PASS")
