"""Escalation ladder for RAM budget breaches — generic, pure, decision-only.

Consumes `membudget.evaluate()` verdicts and decides what SHOULD happen. It does
not do it. Execution is the platform adapter's job (systemd on the appliance,
Windows services / launchd on agents), which is what keeps this file free of
`systemctl` and free of anything that could fire while under test.

Purity is what makes a ladder testable at all: escalation is a function of
HISTORY, so the interesting cases are "the fourth consecutive breach" and "a
breach that cleared on sample three". Producing those against a real box means
waiting hours and inducing real memory pressure. Here they are a list of dicts.

────────────────────────────────────────────────────────────────────────────
THE RUNGS (operator decision, 2026-08-18)
────────────────────────────────────────────────────────────────────────────
  ALERT     record it and tell someone. Always the first rung — nothing acts
            before something has been said.
  THROTTLE  slow or pause an IN-FLIGHT operation WITHOUT killing it. The
            component keeps its state and its work; it just proceeds slower or
            waits. This is the first rung with teeth and it is deliberately the
            gentlest one that can actually relieve pressure.
  ABORT     cancel the in-flight operation. Separate and harder than throttle,
            for when throttling is not sufficient. Work is lost; the process is
            not.
  RESTART   SHADOW ONLY. Decided, recorded, and NEVER executed — see below.

Escalation is strictly monotonic: a rung is only ever reached by passing through
the one below it. Skipping is not a shortcut, it is how a gentle mechanism
becomes an abrupt one without anyone deciding to make it so.

────────────────────────────────────────────────────────────────────────────
WHY RESTART IS SHADOW, AND WHAT WOULD END THAT
────────────────────────────────────────────────────────────────────────────
Unattended restart is not enabled and this module cannot enable it. It records
what it WOULD have restarted, and promotion happens only on accumulated evidence
of correct decisions — explicitly NOT on a timer, and not on a count of
decisions alone.

That distinction is the whole point, so it is enforced structurally:
`promotion_readiness()` counts only RESOLVED shadow records — ones where what
actually happened next is known. An unresolved decision is not evidence of
anything; a hundred unresolved decisions are not evidence a hundred times over.

A shadow record resolves when the following samples say what the breach did:
  * `correct`    - the breach persisted or worsened. A restart would have been
                   addressing something real.
  * `unnecessary`- the breach cleared on its own. A restart would have been a
                   needless service interruption, i.e. a false positive.
  * `superseded` - the component went away or was restarted by something else
                   (crash, OOM killer, operator). Says nothing either way, and
                   is deliberately NOT counted as correct — inferring success
                   from "the problem disappeared" is exactly how a mechanism
                   gets credit for someone else's fix.

`unnecessary` is the one that matters. A ladder promoted on a record full of
false positives would restart healthy services under transient load — and a
service restart that was not needed is indistinguishable, from the outside, from
the fault it claims to be fixing.
"""

from __future__ import annotations

__all__ = [
    "RUNG_NONE", "RUNG_ALERT", "RUNG_THROTTLE", "RUNG_ABORT", "RUNG_RESTART",
    "RUNGS", "MODE_LIVE", "MODE_SHADOW",
    "DEFAULT_POLICY", "decide", "new_state", "promotion_readiness",
    "OUTCOME_CORRECT", "OUTCOME_UNNECESSARY", "OUTCOME_SUPERSEDED",
    "shadow_record", "observe_follow_up", "classify_outcome", "resolve_records",
    "self_test",
]

RUNG_NONE = "none"
RUNG_ALERT = "alert"
RUNG_THROTTLE = "throttle"
RUNG_ABORT = "abort"
RUNG_RESTART = "restart"

#: Ordered. Index is the rung's height; escalation may only ever step +1.
RUNGS = [RUNG_NONE, RUNG_ALERT, RUNG_THROTTLE, RUNG_ABORT, RUNG_RESTART]

MODE_LIVE = "live"
MODE_SHADOW = "shadow"

OUTCOME_CORRECT = "correct"
OUTCOME_UNNECESSARY = "unnecessary"
OUTCOME_SUPERSEDED = "superseded"

DEFAULT_POLICY = {
    # Consecutive breaching samples required to REACH each rung. At the
    # appliance's 300 s cadence these are ~10 min / ~20 min / ~40 min / ~60 min.
    # A single sample never acts: memory spikes transiently, and a ladder that
    # reacted to one sample would be a load-triggered outage generator.
    "alert_after": 2,
    "throttle_after": 4,
    "abort_after": 8,
    "restart_after": 12,
    # Consecutive healthy samples required to step DOWN one rung. Higher than
    # the escalation thresholds on purpose: coming down fast after a throttle
    # takes effect would oscillate, throttling and un-throttling forever.
    "recover_after": 6,
    # Which rungs may actually execute. ALERT and THROTTLE are live (each has a
    # proven executor). ABORT and RESTART are BOTH shadow: neither has a proven
    # executor, and each must earn promotion to live on its OWN resolved shadow
    # evidence — `promotion_readiness(records, rung=...)`, PER RUNG — before it
    # could act. A harsher rung with no evidence must never fire on the strength
    # of a different rung's history. Flip a rung here, in one place, once its own
    # shadow evidence clears the bar.
    "modes": {
        RUNG_ALERT: MODE_LIVE,
        RUNG_THROTTLE: MODE_LIVE,
        RUNG_ABORT: MODE_SHADOW,
        RUNG_RESTART: MODE_SHADOW,
    },
    # Promotion gate for the shadow rungs (ABORT and RESTART), applied PER RUNG.
    # Both must hold, and only resolved records count.
    "promote_min_resolved": 20,
    "promote_max_unnecessary_rate": 0.05,
}


def new_state():
    """Fresh ladder state. Plain dicts so callers can persist it as JSON."""
    return {"components": {}}


def _rung_for_streak(streak, policy, exempt):
    """Highest rung justified by `streak`, capped for recovery-exempt components."""
    rung = RUNG_NONE
    if streak >= policy["alert_after"]:
        rung = RUNG_ALERT
    if streak >= policy["throttle_after"]:
        rung = RUNG_THROTTLE
    if streak >= policy["abort_after"]:
        rung = RUNG_ABORT
    if streak >= policy["restart_after"]:
        rung = RUNG_RESTART
    if exempt:
        # A recovery-exempt component may be ALERTED about and nothing more. It
        # is still measured, still breached, still reported — it is simply never
        # acted upon. Capping here rather than filtering earlier is deliberate:
        # the breach stays visible.
        return RUNG_ALERT if RUNGS.index(rung) >= RUNGS.index(RUNG_ALERT) else rung
    return rung


def decide(verdicts, state, policy=None, exempt=frozenset(),
           available=None):
    """(new_state, actions). Pure: no I/O, no clock, no side effects.

    `verdicts` is a `membudget.evaluate()` result. `state` is from `new_state()`
    or a previous call. Returns a NEW state dict rather than mutating, so a
    caller that fails to persist cannot half-apply an escalation.

    `available` maps component -> set of rungs that STRUCTURALLY EXIST for it.
    Omit it and every rung is assumed available (previous behaviour).

    ⚠ SKIPPING AN UNAVAILABLE RUNG MUST NEVER ACCELERATE ESCALATION. If THROTTLE
    does not exist for a component, the ladder does NOT jump to ABORT the moment
    THROTTLE was justified — it waits at the current rung until the streak
    justifies ABORT on its own. Skipping is about which rungs EXIST, never about
    reaching a harsher one sooner. The opposite reading would turn "we have no
    gentle option here" into "so act harshly, earlier", which is precisely
    backwards.
    """
    policy = policy or DEFAULT_POLICY
    comps = (verdicts or {}).get("components") or {}
    prev = (state or {}).get("components") or {}
    out_state, actions = {}, []

    # An unusable sample must not decay streaks toward zero. "We could not
    # measure" is not evidence of recovery, and treating it as such would let a
    # sampler outage silently walk an escalating component back down to none.
    sample_bad = (verdicts or {}).get("state") == "unavailable"
    if sample_bad:
        return ({"components": dict(prev)},
                [{"rung": RUNG_NONE, "component": None, "mode": MODE_LIVE,
                  "kind": "sample_unavailable",
                  "reason": (verdicts or {}).get("reason")}])

    for name, v in comps.items():
        st = dict(prev.get(name) or {"breach_streak": 0, "ok_streak": 0,
                                     "rung": RUNG_NONE})
        verdict = v.get("verdict")

        if verdict == "breach":
            st["breach_streak"] = st.get("breach_streak", 0) + 1
            st["ok_streak"] = 0
        elif verdict == "ok":
            st["ok_streak"] = st.get("ok_streak", 0) + 1
            st["breach_streak"] = 0
        else:
            # indeterminate / unbudgeted: neither escalate nor decay. An
            # INDETERMINATE is an RSS reading over a USS budget — it may or may
            # not be a breach, and acting on "may" is how shared pages get a
            # healthy service throttled.
            out_state[name] = st
            continue

        target = _rung_for_streak(st["breach_streak"], policy, name in exempt)
        cur_i = RUNGS.index(st.get("rung", RUNG_NONE))
        tgt_i = RUNGS.index(target)

        avail = None if available is None else set(
            available.get(name, set(RUNGS)))

        if tgt_i > cur_i:
            # Lowest rung strictly above current that EXISTS for this component,
            # and never above what the streak already justifies.
            candidates = [i for i in range(cur_i + 1, tgt_i + 1)
                          if avail is None or RUNGS[i] in avail]
            if not candidates:
                # Justified to escalate, but no rung exists to escalate to.
                # Reported ONCE per target so a permanently-stuck component does
                # not emit an identical action every sample forever.
                if st.get("blocked_target") != target:
                    st["blocked_target"] = target
                    actions.append({
                        "component": name, "rung": st.get("rung", RUNG_NONE),
                        "mode": MODE_LIVE, "kind": "blocked",
                        "justified_rung": target,
                        "breach_streak": st["breach_streak"],
                        "detail": "no rung available between %s and %s for this "
                                  "component" % (st.get("rung", RUNG_NONE), target),
                    })
                out_state[name] = st
                continue
            new_i = candidates[0]
            skipped = [RUNGS[i] for i in range(cur_i + 1, new_i)]
            st["blocked_target"] = None
            st["rung"] = RUNGS[new_i]
            mode = policy["modes"].get(st["rung"], MODE_LIVE)
            actions.append({
                "component": name, "rung": st["rung"], "mode": mode,
                "kind": "escalate",
                "breach_streak": st["breach_streak"],
                "observed_mb": v.get("observed_mb"),
                "budget_mb": v.get("budget_mb"),
                "basis": v.get("basis"),
                "exempt": name in exempt,
                # Recorded, not silent: a skipped rung is a fact about this
                # component's capabilities and belongs in the audit trail.
                "skipped_rungs": skipped,
                "detail": v.get("detail"),
            })
        elif verdict == "ok" and st["ok_streak"] >= policy["recover_after"] \
                and cur_i > 0:
            st["rung"] = RUNGS[cur_i - 1]
            st["ok_streak"] = 0
            actions.append({"component": name, "rung": st["rung"],
                            "mode": MODE_LIVE, "kind": "de-escalate",
                            "detail": "recovered for %d consecutive samples"
                                      % policy["recover_after"]})
        out_state[name] = st

    # Components that vanished keep no state: a process that is gone has no
    # streak to continue, and resurrecting one later would escalate a fresh
    # process on a dead one's history.
    return {"components": out_state}, actions


def promotion_readiness(records, policy=None, rung=None):
    """Is there enough evidence to promote a SHADOW rung (ABORT or RESTART) to live?

    `records` are shadow decisions each carrying an `outcome`. ONLY RESOLVED
    RECORDS COUNT — an unresolved decision is not evidence, and counting it
    would let volume masquerade as confidence, which is precisely the "fixed
    timeout or a guess" the operator ruled out.

    `rung` scopes the evidence: pass RUNG_ABORT or RUNG_RESTART to gate that rung
    on ITS OWN resolved records only. A harsher rung must not inherit a gentler
    one's history — ABORT and RESTART earn promotion independently. `rung=None`
    (the default) counts every record, preserving the original single-rung call.
    """
    policy = policy or DEFAULT_POLICY
    recs = [r for r in (records or []) if rung is None or r.get("rung") == rung]
    resolved = [r for r in recs if r.get("outcome") in
                (OUTCOME_CORRECT, OUTCOME_UNNECESSARY)]
    superseded = [r for r in recs if r.get("outcome") == OUTCOME_SUPERSEDED]
    unresolved = [r for r in recs if not r.get("outcome")]

    correct = [r for r in resolved if r["outcome"] == OUTCOME_CORRECT]
    unnecessary = [r for r in resolved if r["outcome"] == OUTCOME_UNNECESSARY]
    rate = (len(unnecessary) / len(resolved)) if resolved else None

    reasons = []
    if len(resolved) < policy["promote_min_resolved"]:
        reasons.append("only %d resolved decisions, need %d"
                       % (len(resolved), policy["promote_min_resolved"]))
    if rate is None:
        reasons.append("no resolved decisions to compute a false-positive rate")
    elif rate > policy["promote_max_unnecessary_rate"]:
        reasons.append("unnecessary-%s rate %.1f%% exceeds the %.1f%% ceiling"
                       % (rung or "action", 100 * rate,
                          100 * policy["promote_max_unnecessary_rate"]))

    return {
        "ready": not reasons,
        "reasons": reasons,
        "resolved": len(resolved),
        "correct": len(correct),
        "unnecessary": len(unnecessary),
        "unnecessary_rate": rate,
        # Reported, never counted. Kept visible so nobody concludes the sample is
        # larger than the evidence.
        "superseded_not_counted": len(superseded),
        "unresolved_not_counted": len(unresolved),
    }


# ── turning a shadow decision into evidence ──────────────────────────────────
#
# ⚠ WITHOUT THIS, SHADOW MODE IS A WRITE-ONLY LOG. `promotion_readiness()`
# counts only RESOLVED records, and nothing else in the system sets an outcome —
# so decisions would accumulate forever at "0 resolved" and promotion would be
# blocked by MISSING MACHINERY rather than by missing evidence. Those two look
# identical from the outside, which is exactly the failure this codebase keeps
# finding: a gate that can only ever return one answer.

#: Follow-up samples required before an outcome may be declared. Resolving too
#: early is how a transient dip gets labelled `unnecessary` and a slow leak gets
#: labelled `correct` — both of which corrupt the evidence the promotion gate
#: is supposed to weigh.
DEFAULT_POLICY["resolve_after_samples"] = 6
DEFAULT_POLICY["resolve_clear_samples"] = 4


def shadow_record(action, sample_seq):
    """A shadow decision, awaiting evidence. Pure."""
    return {"component": action.get("component"),
            "rung": action.get("rung"),
            "decided_at": sample_seq,
            "observed_mb": action.get("observed_mb"),
            "budget_mb": action.get("budget_mb"),
            "follow_ups": [],
            "outcome": None}


def observe_follow_up(record, verdict_or_none):
    """Append one post-decision observation. Returns a NEW record. Pure.

    `verdict_or_none` is the component's verdict in a later sample, or None if
    the component was ABSENT from that sample — which is meaningful, not missing
    data: it means the process is gone.
    """
    out = dict(record)
    out["follow_ups"] = list(record.get("follow_ups") or []) + [verdict_or_none]
    return out


def classify_outcome(record, policy=None):
    """Outcome for a shadow record, or None while still unresolved. Pure.

    ⚠ WHAT `correct` HONESTLY MEANS. It means the condition the restart targeted
    was REAL AND SUSTAINED, so acting would have been justified. It does NOT
    mean a restart would have cured it: for a genuine leak a restart is
    palliative and the breach returns. Claiming the stronger thing would let the
    promotion gate accumulate "successes" for decisions that would not have
    fixed anything.
    """
    policy = policy or DEFAULT_POLICY
    if record.get("outcome"):
        return record["outcome"]
    ups = list(record.get("follow_ups") or [])

    # The component disappeared: crashed, OOM-killed, or restarted by someone
    # else. Says nothing about whether OUR decision was right, so it resolves to
    # superseded and is never counted toward promotion.
    if any(u is None for u in ups):
        return OUTCOME_SUPERSEDED

    if len(ups) < policy["resolve_after_samples"]:
        return None                      # not enough evidence yet — stay unresolved

    tail = ups[-policy["resolve_clear_samples"]:]
    if tail and all(u == "ok" for u in tail):
        # It cleared on its own and stayed clear. A restart would have been a
        # needless service interruption.
        return OUTCOME_UNNECESSARY
    if any(u == "breach" for u in ups[-policy["resolve_after_samples"]:]):
        return OUTCOME_CORRECT
    # Only indeterminate/unbudgeted observations: we still do not know.
    return None


def resolve_records(records, policy=None):
    """Apply `classify_outcome` across a list. Returns NEW records. Pure."""
    return [dict(r, outcome=classify_outcome(r, policy)) for r in (records or [])]


def self_test():
    """Canaries: the ladder must reach different rungs for different histories."""
    findings = []
    pol = DEFAULT_POLICY

    def _v(verdict, name="svc"):
        return {"state": "ok", "components": {name: {
            "verdict": verdict, "observed_mb": 500.0, "budget_mb": 100.0,
            "basis": "uss", "detail": "canary"}}}

    # 1. sustained breach climbs, one rung at a time, and reaches throttle
    st, seen = new_state(), []
    for _ in range(pol["throttle_after"] + 2):
        st, acts = decide(_v("breach"), st, pol)
        seen += [a["rung"] for a in acts if a["kind"] == "escalate"]
    if seen[:2] != [RUNG_ALERT, RUNG_THROTTLE]:
        findings.append("escalation order was %r, expected alert then throttle"
                        % (seen[:2],))
    # 2. a single breach must NOT act
    st1, acts1 = decide(_v("breach"), new_state(), pol)
    if acts1:
        findings.append("a single breach produced actions: %r" % (acts1,))
    # 3. restart must be shadow
    if pol["modes"][RUNG_RESTART] != MODE_SHADOW:
        findings.append("RESTART is not shadow — unattended restart is not approved")
    # 4. indeterminate must neither escalate nor decay
    st2, acts2 = decide(_v("indeterminate"), new_state(), pol)
    if acts2:
        findings.append("indeterminate produced actions: %r" % (acts2,))
    # 5. promotion must refuse an empty record
    if promotion_readiness([], pol)["ready"]:
        findings.append("promotion_readiness approved with no evidence")
    return {"ok": not findings, "findings": findings}


if __name__ == "__main__":                                # pragma: no cover
    st = self_test()
    print("self-test:", "PASS" if st["ok"] else "FAIL")
    for f in st["findings"]:
        print("  -", f)
