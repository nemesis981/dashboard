#!/usr/bin/env python3
"""§5 A/B harness — does a MATURED install decide differently from a FRESH one?

DESIGN-L4-full-ai-mode-2026-08-27 §5. Operator-approved 2026-08-27 to be built
ahead of the real run, validated against the existing stub.

═══════════════════════════════════════════════════════════════════════════════
⛔ WHAT THIS PROVES, AND — MORE IMPORTANTLY — WHAT IT DOES NOT
═══════════════════════════════════════════════════════════════════════════════
Two layers, and conflating them would be the whole point missed:

  MECHANISM  (--judge deterministic, the default)
      Context REACHES the decision, is ATTRIBUTABLE to a named entry, is scoped
      correctly, expires correctly, and cannot breach a ceiling. Deterministic,
      offline, repeatable.
      ⚠ It CANNOT show that a matured install decides *better*. The judge here
      follows context by construction, so "B differs" is guaranteed by the
      judge, not discovered. That is circular as evidence about model quality
      and is stated so nobody quotes it as such.

  CLAIM      (--judge model)
      A real `analyze()` on two real installs. THIS is §5. Only this can
      support the customer-facing claim, and it needs Window 1's
      `firewall_failsafe_override` registry entry to exist first.

⭐ A STUB-VALIDATED RUN IS NEVER A §5 RESULT. The harness enforces that itself:
in stub mode it refuses to emit a result document, prints MODE=STUB on every
line of the verdict, and exits 3 (a distinct code, not success) so no caller can
mistake it for a pass. Operator-held caveat, 2026-08-27 — made structural here
rather than left as a promise.

⚠ A AND B RUN AS SEPARATE SUBPROCESSES WITH SEPARATE DATABASES, deliberately.
Same-process A/B would share the module-level DataManager and the shared-db-path
global, so "fresh" could silently inherit "matured" state — a fresh install that
is not fresh, which is exactly the false negative §5's requirement 1 warns about.
Subprocess isolation also means the worker can later be replaced by an SSH call
to a real VM without changing the orchestrator.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CLS = "firewall_failsafe_override"

#: Identical for A and B. Divergence must come from stored context, never from
#: a different question. Keys are stable so results can be diffed across runs.
SCENARIOS = [
    {"id": "S1-narrow-permissive",
     "change_id": "chg-narrow-0001",
     "note": "B has a permissive entry for THIS exact change"},
    {"id": "S2-just-outside",
     "change_id": "chg-narrow-0002",
     "note": "one key away from S1 — the erosion guardrail: B must equal A here"},
    {"id": "S3-restrictive",
     "change_id": "chg-strict-0001",
     "note": "B has a restrictive entry — B must be MORE cautious"},
    {"id": "S4-expired-permissive",
     "change_id": "chg-expired-0001",
     "note": "B's permissive entry has lapsed — B must fall back to A's answer"},
    {"id": "S5-no-context",
     "change_id": "chg-virgin-0001",
     "note": "neither has context — A and B must agree (the null control)"},
]


def _request(change_id, deadline_offset=900):
    return {"schema": "nemesis.failsafe.decision_request/1",
            "change_id": change_id,
            "trigger": "healthcheck_failed",
            "mode": "unattended",
            "checks": [{"id": "1 dashboard-loopback", "verdict": "FAIL"},
                       {"id": "2 ssh-reachable", "verdict": "PASS"},
                       {"id": "3 dns-resolves", "verdict": "UNKNOWN"}],
            "revert_deadline_epoch": time.time() + deadline_offset}


# ─────────────────────────────────────────────────────────────────────────────
# WORKER — one install. Runs in its own process, with its own database.
# ─────────────────────────────────────────────────────────────────────────────

def worker(role, judge, stub):
    import datetime
    db = os.path.join(tempfile.mkdtemp(prefix="l4ab-%s-" % role), "alerts.db")
    sys.path.insert(0, "/opt/nemesis")
    sys.path.insert(0, "/opt/nemesis/alert_manager")
    import modules
    modules.set_shared_db_path(db)
    from modules.ai_engine import module as ai
    from modules.ai_engine import context_store as cs
    from modules.ai_engine import failsafe_decision as fd
    ai._init_db()

    if stub:
        # The SAME stub the unit suite uses. In real mode neither branch runs
        # and the genuine ladder answers — so the only difference between a
        # stub run and a real run is this block.
        ai.ACTION_CLASS_CEILINGS[CLS] = ai.L4_GOVERN
        _orig = ai.effective_ceiling
        ai.effective_ceiling = lambda c: (
            {"level": ai.L4_GOVERN, "earned": ai.L4_GOVERN,
             "hard_ceiling": ai.L4_GOVERN, "reasons": ["stub"]}
            if c == CLS else _orig(c))

    seeded = {}
    if role == "B":
        # ── the MATURED install: entries of both directions ──────────────────
        seeded["S1"] = cs.add_learned(
            CLS, "change", "chg-narrow-0001", cs.PERMISSIVE, cs.SCOPE_TRIGGER,
            "known-good change, health check misreports it")
        seeded["S3"] = cs.add_learned(
            CLS, "change", "chg-strict-0001", cs.RESTRICTIVE, cs.SCOPE_TRIGGER,
            "this class of change has bitten us; never override")
        exp = cs.add_learned(
            CLS, "change", "chg-expired-0001", cs.PERMISSIVE, cs.SCOPE_TRIGGER,
            "temporary allowance from an old incident")
        # Lapse it, so §5 requirement 5 has something real to observe.
        conn = cs._conn()
        conn.execute("UPDATE ai_learned_context SET expires_at=? WHERE id=?",
                     ((datetime.datetime.now()
                       - datetime.timedelta(days=1)).isoformat(timespec="seconds"),
                      exp))
        conn.commit()
        conn.close()
        seeded["S4-expired"] = exp

    out = {"role": role, "judge": judge, "stub": stub, "seeded": seeded,
           "results": []}
    for sc in SCENARIOS:
        analyze = _make_judge(judge)
        res = fd.decide(_request(sc["change_id"]), _analyze=analyze)
        # use_count is what makes a difference ATTRIBUTABLE (§5 requirement 2).
        used = []
        conn = cs._conn()
        for r in conn.execute(
                "SELECT id, use_count, direction, trigger_key FROM "
                "ai_learned_context WHERE use_count > 0").fetchall():
            used.append({"id": r["id"], "use_count": r["use_count"],
                         "direction": r["direction"], "key": r["trigger_key"]})
        conn.close()
        out["results"].append({"scenario": sc["id"],
                               "decision": res.get("decision"),
                               "level": res.get("level_asserted"),
                               "entries_used": used})
    print(json.dumps(out))
    return 0


def _make_judge(kind):
    """The thing that decides. Deterministic by default; the real model on ask."""
    if kind == "model":
        return None                      # fd.decide falls back to ai.analyze
    seen = {}

    def deterministic(prompt, **_kw):
        """Follows the structured context it is given.

        ⚠ CIRCULAR AS EVIDENCE ABOUT MODEL QUALITY, ON PURPOSE. It exists to
        prove the PLUMBING delivers context and that scoping/expiry/ceiling
        behave — not to show a real model reasons better. Reading a
        deterministic-judge run as evidence for the customer-facing claim is
        precisely the misuse this docstring exists to prevent.
        """
        text = str(prompt)
        seen["last"] = text
        # ⭐ THE BASELINE MUST DIFFER BY SCENARIO, or half the requirements
        # cannot be tested. With a uniformly cautious baseline A NEVER
        # overrides, so "B is MORE cautious than A" can only ever compare
        # allow_revert to allow_revert and passes VACUOUSLY. `chg-strict-*`
        # therefore models a change the engine would ordinarily override, so a
        # restrictive entry has something to pull BACK from.
        lenient_baseline = "chg-strict-" in text
        if "restrictive" in text:
            return {"ok": True, "decision": "allow_revert"}
        if "permissive" in text:
            return {"ok": True, "decision": "override",
                    "reasoning": "a permissive entry covers this exact change"}
        if lenient_baseline:
            return {"ok": True, "decision": "override",
                    "reasoning": "no context; the checks look survivable"}
        return {"ok": True, "decision": "allow_revert"}

    return deterministic


# ─────────────────────────────────────────────────────────────────────────────
# ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

def run_side(role, judge, stub):
    cmd = [sys.executable, os.path.abspath(__file__), "--worker", role,
           "--judge", judge] + (["--stub"] if stub else [])
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if p.returncode != 0 or not p.stdout.strip():
        return None, (p.stderr or "")[-800:]
    try:
        return json.loads(p.stdout.strip().splitlines()[-1]), ""
    except json.JSONDecodeError as exc:
        return None, "unparseable worker output: %s" % exc


def evaluate(a, b):
    """The six §5 requirements. Returns [(id, ok, detail)]."""
    da = {r["scenario"]: r["decision"] for r in a["results"]}
    db = {r["scenario"]: r["decision"] for r in b["results"]}
    used_b = {r["scenario"]: r["entries_used"] for r in b["results"]}
    out = []

    differs = [s for s in da if da[s] != db[s]]
    out.append(("R1 A differs from B on >=1 scenario", bool(differs),
                "differing: %s" % (differs or "NONE — mechanism is inert")))

    attributable = bool(used_b.get("S1-narrow-permissive"))
    out.append(("R2 B's difference is attributable to a named entry",
                attributable, "entries used: %s"
                % (used_b.get("S1-narrow-permissive") or "none")))

    # ⚠ MUST compare A TO B, not just inspect B. Asserting only
    # `B == allow_revert` passes when BOTH sides refuse for unrelated reasons —
    # "more cautious" would be reported for a B that is merely EQUALLY cautious.
    # Caught 2026-08-27 when it passed on A=allow_revert B=allow_revert.
    r3 = (da.get("S3-restrictive") == "override"
          and db.get("S3-restrictive") == "allow_revert")
    out.append(("R3 restrictive: B is MORE cautious than A",
                r3, "A=%s B=%s%s" % (da.get("S3-restrictive"),
                                     db.get("S3-restrictive"),
                                     "" if r3 else
                                     "  <- needs A=override,B=allow_revert to mean anything")))

    inside = da.get("S1-narrow-permissive") != db.get("S1-narrow-permissive")
    outside = da.get("S2-just-outside") == db.get("S2-just-outside")
    out.append(("R4 permissive: differs INSIDE scope, identical OUTSIDE",
                inside and outside,
                "inside differs=%s (A=%s B=%s); outside identical=%s (A=%s B=%s)"
                % (inside, da.get("S1-narrow-permissive"),
                   db.get("S1-narrow-permissive"), outside,
                   da.get("S2-just-outside"), db.get("S2-just-outside"))))

    out.append(("R5 an EXPIRED entry yields A's behaviour, not B's",
                da.get("S4-expired-permissive") == db.get("S4-expired-permissive"),
                "A=%s B=%s" % (da.get("S4-expired-permissive"),
                               db.get("S4-expired-permissive"))))

    # R6: no response may assert a level, or override, without the ladder. In
    # stub mode the ladder IS L4, so the meaningful assertion is that nothing
    # asserted anything OTHER than L4 — a breach would show as a non-L4 level.
    levels = {r.get("level") for r in a["results"] + b["results"]} - {None}
    out.append(("R6 neither side exceeded its class ceiling",
                levels <= {"L4"}, "levels asserted: %s" % (levels or "none")))

    # The null control. If this fails, divergence elsewhere is not attributable
    # to context at all and every other row above is suspect.
    out.append(("CONTROL no-context scenario agrees on both sides",
                da.get("S5-no-context") == db.get("S5-no-context"),
                "A=%s B=%s" % (da.get("S5-no-context"), db.get("S5-no-context"))))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--worker", choices=["A", "B"])
    ap.add_argument("--judge", choices=["deterministic", "model"],
                    default="deterministic")
    ap.add_argument("--stub", action="store_true",
                    help="stub the action class + ceiling (NOT a §5 result)")
    args = ap.parse_args(argv)

    if args.worker:
        return worker(args.worker, args.judge, args.stub)

    if not args.stub:
        sys.path.insert(0, "/opt/nemesis")
        sys.path.insert(0, "/opt/nemesis/alert_manager")
        import modules
        modules.set_shared_db_path(os.path.join(tempfile.mkdtemp(), "probe.db"))
        from modules.ai_engine import module as ai
        ai._init_db()
        # ⚠ THE PRECONDITION IS AN EFFECTIVE L4, NOT MERE REGISTRATION.
        # The first version of this guard checked `CLS in ACTION_CLASS_CEILINGS`
        # and passed the moment Window 1 landed the entry — while `earned` was
        # still 0, so both sides answered allow_revert for an AUTHORITY reason
        # and the harness printed "§5 FAILED". That is the exact false negative
        # this guard exists to prevent, produced BY the guard checking a proxy
        # for the precondition instead of the precondition. Assert the thing
        # that actually has to be true.
        if CLS not in ai.ACTION_CLASS_CEILINGS:
            print("ABORT: %r is not registered in ACTION_CLASS_CEILINGS.\n"
                  "  That entry is Window 1's (ADR 0019 Amendment 03 §10.3)."
                  % CLS, file=sys.stderr)
            return 2
        try:
            ceil = ai.effective_ceiling(CLS)
        except Exception as exc:                               # noqa: BLE001
            print("ABORT: cannot read the ceiling for %r: %s" % (CLS, exc),
                  file=sys.stderr)
            return 2
        if ceil.get("level") != ai.L4_GOVERN:
            print("ABORT: %r is registered (hard ceiling L%s) but its EFFECTIVE\n"
                  "  level is L%s — %s.\n"
                  "  `decide()` overrides only at L4, so BOTH sides would answer\n"
                  "  allow_revert for an AUTHORITY reason having nothing to do\n"
                  "  with accumulated context. That null result looks exactly\n"
                  "  like §5 requirement 1's failure ('the mechanism is inert')\n"
                  "  and would be reported as one.\n"
                  "  The L4 grant is DESIGN-L4 §2, still held. Re-run with --stub\n"
                  "  to exercise the INSTRUMENT — which is not a §5 result."
                  % (CLS, ceil.get("hard_ceiling"), ceil.get("level"),
                     ", ".join(ceil.get("reasons") or ["no reason given"])),
                  file=sys.stderr)
            return 2

    a, err_a = run_side("A", args.judge, args.stub)
    b, err_b = run_side("B", args.judge, args.stub)
    if a is None or b is None:
        print("ABORT: a side failed to run.\n  A: %s\n  B: %s" % (err_a, err_b),
              file=sys.stderr)
        return 2

    mode = "STUB (instrument check only)" if args.stub else "REAL"
    tag = "MODE=STUB " if args.stub else ""
    print("=" * 74)
    print("§5 A/B — fresh vs matured    judge=%s    mode=%s" % (args.judge, mode))
    print("=" * 74)
    for r in a["results"]:
        s = r["scenario"]
        bb = next(x for x in b["results"] if x["scenario"] == s)
        flag = "  <-- differs" if r["decision"] != bb["decision"] else ""
        print("  %-24s A=%-13s B=%-13s%s" % (s, r["decision"], bb["decision"], flag))

    print("-" * 74)
    rows = evaluate(a, b)
    for name, ok, detail in rows:
        print("  %s[%s] %s" % (tag, "PASS" if ok else "FAIL", name))
        print("        %s" % detail)

    failed = [n for n, ok, _ in rows if not ok]
    print("-" * 74)
    if args.stub:
        print("  MODE=STUB — %d/%d instrument checks passed.\n"
              "  ⛔ THIS IS NOT A §5 RESULT. The action class and ceiling were\n"
              "  stubbed and the judge follows context by construction. It shows\n"
              "  only that the instrument can DISTINGUISH A from B."
              % (len(rows) - len(failed), len(rows)))
        return 3 if failed else 3
    if failed:
        print("  §5 FAILED: %s" % ", ".join(failed))
        return 1
    print("  §5 PASSED — all six requirements plus the null control.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
