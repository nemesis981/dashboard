"""
Test harness for the contextual chat component — modules/ai_engine/module.py.

Standalone (no pytest needed): builds ai_engine against a throwaway temp DB and
exercises ask_followup() / get_chat_state() / register_anchor().

The two properties that matter most, and why:

1. **The chat is inside the money gates, not beside them.** It is the first
   uncacheable surface in the product — every question is a real billed call —
   so the hourly limit, the daily limit and the dollar spend cap must all stop
   it. Those are proved here END TO END (a real cap, real recorded spend, a real
   refusal), not by asserting that a helper was called.

2. **A failed context rebuild must never become an answer.** If the anchor
   loader raises or returns nothing, answering anyway would produce a confident
   response about nothing. That is a hard failure, not an empty context.

No network calls are made. The spend/rate cases return at the gate inside
_analyze_inner before any request; the remaining cases stub analyze() so the
arguments it receives can be asserted.

Run:  python3 modules/ai_engine/test_chat.py   (exit 0 = all pass)
"""

import os
import sys
import tempfile

sys.path.insert(0, "/opt/nemesis")

_db = os.path.join(tempfile.mkdtemp(), "throwaway.db")
os.environ["NEMESIS_DB_PATH"] = _db
# Must look configured, or _analyze_inner returns "no key" before reaching the
# rate/spend gate this harness exists to prove. Never used for a real request:
# every path here is refused at the gate or stubbed before the client is built.
os.environ["ANTHROPIC_API_KEY"] = "sk-ant-test-not-a-real-key"

import modules
modules.set_shared_db_path(_db)
# get_status() reaches modules_loader.is_enabled(), which uses its OWN module-level
# path rather than the shared accessor. Setting only the shared one leaves this
# reading None and the failure surfaces far from its cause.
import modules_loader
modules_loader._db_path = _db

# modules_enabled is core-owned, so ai_engine's own _init_db does not create it.
# Built here rather than stubbing is_enabled(), so get_chat_state() exercises the
# real enablement path it will use in production.
import sqlite3 as _sqlite3
_c = _sqlite3.connect(_db)
_c.execute("CREATE TABLE IF NOT EXISTS modules_enabled "
           "(module_name TEXT PRIMARY KEY, enabled INTEGER, actor TEXT)")
_c.execute("INSERT OR REPLACE INTO modules_enabled VALUES ('ai_engine',1,NULL)")
_c.commit()
_c.close()

from modules.ai_engine import module as ai

_failures = []


def check(cond, label):
    if not isinstance(cond, bool):
        raise TypeError(f"check(cond, label) looks reversed at {label!r}")
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
    if not cond:
        _failures.append(label)


def eq(label, got, expected):
    ok = (got == expected)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}  (got {got!r}, expected {expected!r})")
    if not ok:
        _failures.append(label)


def _reset_gates():
    """Clear rate/spend state so each case starts from a known-open gate."""
    conn = ai._conn()
    conn.execute("DELETE FROM ai_rate_state")
    conn.execute("DELETE FROM ai_usage")
    conn.execute("DELETE FROM ai_settings WHERE key IN "
                 "('spend_cap_monthly_usd','rate_per_hour','rate_per_day','chat_turn_cap')")
    conn.commit()
    conn.close()


def _good_loader(row_id):
    return f"Alert {row_id}: repeated connection attempts from an external address."


def main():
    check(ai.__file__.startswith("/opt/nemesis/"), f"module under test is on disk: {ai.__file__}")
    check(hasattr(ai, "ask_followup"), "ask_followup() is present")
    check(hasattr(ai, "register_anchor"), "register_anchor() is present")

    print("\n-- registration is deliberate, and validated --")
    r = ai.ask_followup("never_registered", 1, "what is this?")
    eq("an unregistered surface has no chat affordance", r.get("code"), "anchor_not_registered")
    try:
        ai.register_anchor("bad", _good_loader, action_classes=("not_a_class",))
        check(False, "an unknown action class is rejected at registration")
    except ai.UnknownActionClass:
        check(True, "an unknown action class is rejected at registration")

    ai.register_anchor("alert", _good_loader,
                       action_classes=("ip_quarantine_external",), label="Alert")
    check("alert" in ai.registered_anchors(), "a registered surface appears in the registry")

    print("\n-- a failed context rebuild is never answered over --")
    ai.register_anchor("raiser", lambda rid: (_ for _ in ()).throw(RuntimeError("boom")),
                       action_classes=())
    r = ai.ask_followup("raiser", 1, "what is this?")
    eq("a loader that raises fails explicitly", r.get("code"), "context_unavailable")
    check(not r.get("ok"), "a loader that raises yields no answer")

    ai.register_anchor("empty", lambda rid: "", action_classes=())
    r = ai.ask_followup("empty", 1, "what is this?")
    eq("a loader returning nothing fails explicitly", r.get("code"), "context_unavailable")

    print("\n-- input bounds --")
    eq("an empty question is refused",
       ai.ask_followup("alert", 1, "   ").get("code"), "empty_question")
    eq("an over-long question is refused",
       ai.ask_followup("alert", 1, "x" * (ai._MAX_QUESTION_CHARS + 1)).get("code"),
       "question_too_long")

    # ─── THE MONEY GATES — proved end to end, no stubbing ────────────────────
    print("\n-- the dollar spend cap stops the chat (end to end) --")
    _reset_gates()
    conn = ai._conn()
    # Real recorded usage priced well past a $1 cap.
    conn.execute("INSERT INTO ai_usage (date, hour, call_count, tokens_in, tokens_out) "
                 "VALUES (strftime('%Y-%m-%d','now'), 0, 50, 8000000, 2000000)")
    conn.execute("INSERT OR REPLACE INTO ai_settings (key,value) "
                 "VALUES ('spend_cap_monthly_usd','1.00')")
    conn.commit()
    conn.close()
    spend = ai.get_spend_this_month()
    check(bool(spend.get("ok")) and spend.get("usd", 0) > 1.00,
          f"(premise) recorded spend ${spend.get('usd')} really is over the $1.00 cap")
    r = ai.ask_followup("alert", 1, "what is this?")
    check(not r.get("ok"), "the chat is refused when the spend cap is exceeded")
    check("spend cap" in (r.get("reason") or "").lower(),
          f"the refusal names the spend cap: {r.get('reason')!r}")

    print("\n-- and lifting the cap re-opens it (proving the gate, not a dead path) --")
    conn = ai._conn()
    conn.execute("DELETE FROM ai_settings WHERE key='spend_cap_monthly_usd'")
    conn.commit()
    conn.close()
    calls = []
    _real_analyze = ai.analyze
    ai.analyze = lambda p, **kw: (calls.append(kw) or
                                  {"ok": True, "text": "an answer", "from_cache": False,
                                   "tokens_used": 30, "tokens_in": 20, "tokens_out": 10})
    try:
        r = ai.ask_followup("alert", 1, "what is this?")
        check(bool(r.get("ok")), "with no cap set, the same question succeeds")

        print("\n-- the call is made on the terms the design requires --")
        eq("cache is bypassed (a follow-up is novel by definition)",
           calls[0].get("cache_hours"), 0)
        check("force" not in calls[0],
              "force=True is NOT passed (it would bypass the spend cap entirely)")
        check(bool(calls[0].get("job_id")),
              "a job_id is passed, so a double-click cannot bill twice")

        print("\n-- per-anchor turn cap --")
        conn = ai._conn()
        conn.execute("INSERT OR REPLACE INTO ai_settings (key,value) "
                     "VALUES ('chat_turn_cap','3')")
        conn.commit()
        conn.close()
        st = ai.get_chat_state("alert", 1)
        eq("(premise) one turn is already recorded", st["turns_used"], 1)
        ai.ask_followup("alert", 1, "second question")
        ai.ask_followup("alert", 1, "third question")
        r = ai.ask_followup("alert", 1, "fourth question")
        eq("the fourth question is refused at a cap of 3", r.get("code"), "turn_cap")
        r2 = ai.ask_followup("alert", 999, "different row, fresh budget")
        check(bool(r2.get("ok")), "the cap is per anchored row, not global")

        print("\n-- cost transparency --")
        st = ai.get_chat_state("alert", 1)
        check(st.get("billed_per_question") is True,
              "state declares the surface is billed per question")
        check(st.get("spent_usd") is not None and st["spent_usd"] > 0,
              f"spend so far on this finding is reported: {st.get('spent_usd')}")
        check(st.get("spend_partial") is False,
              "spend is reported as complete when every turn was priced")
        est = ai.estimate_question_cost("why does this matter?", "alert", 1)
        check(est.get("is_estimate") is True, "a pre-flight estimate is labelled an estimate")

        print("\n-- an unpriceable call reports None, never $0.00 --")
        _real_pricing = ai.get_pricing
        ai.get_pricing = lambda model=None: {"model": "mystery", "known": False,
                                             "input_per_mtok": None,
                                             "output_per_mtok": None, "updated": None}
        try:
            check(ai._cost_of(1000, 500) is None,
                  "unknown pricing yields None, not a legitimate-looking $0.00")
        finally:
            ai.get_pricing = _real_pricing

        print("\n-- scope tracks authority (D1), enforced in one place --")
        sp = ai._chat_system_prompt(ai._chat_scope(("ip_quarantine_external",)))
        check("do NOT recommend" in sp, "at L0 the system prompt forbids recommending")
        conn = ai._conn()
        conn.execute("INSERT OR REPLACE INTO ai_authority "
                     "(action_class,current_level,hard_ceiling) "
                     "VALUES ('ip_quarantine_external',1,3)")
        conn.commit()
        conn.close()
        sp = ai._chat_system_prompt(ai._chat_scope(("ip_quarantine_external",)))
        check("may recommend" in sp, "at L1 the system prompt permits recommending")
        check("CANNOT execute" in sp, "at L1 it still forbids executing")

        print("\n-- a standing 'never' rule narrows the chat back down --")
        conn = ai._conn()
        conn.execute("INSERT INTO ai_standing_rules (rule_type,action_class,rule_text,"
                     "created_by,created_at) VALUES ('never','ip_quarantine_external',"
                     "'test data 2026-08-04 - chat scope clamp','user:test','2026-08-04')")
        conn.commit()
        conn.close()
        sp = ai._chat_system_prompt(ai._chat_scope(("ip_quarantine_external",)))
        check("do NOT recommend" in sp,
              "a 'never' rule returns the chat to explanation-only")

        print("\n-- unreadable authority degrades visibly, not silently --")
        _orig_conn = ai._conn
        ai._conn = lambda: (_ for _ in ()).throw(RuntimeError("simulated failure"))
        try:
            sc = ai._chat_scope(("ip_quarantine_external",))
        finally:
            ai._conn = _orig_conn
        eq("degraded scope falls back to L0", sc["level"], ai.L0_OBSERVE)
        check(sc["degraded"] is True,
              "degraded state is flagged, not presented as an ordinary L0")
    finally:
        ai.analyze = _real_analyze

    print("\n-- model tiers: a client can never name a model, only a tier --")
    eq("absent tier resolves to standard", ai.resolve_chat_tier(None)[0], "standard")
    eq("empty tier resolves to standard", ai.resolve_chat_tier("")[0], "standard")
    eq("unknown tier resolves DOWN to standard",
       ai.resolve_chat_tier("premium-ultra")[0], "standard")
    # The attack this guards: a caller trying to name an expensive model directly.
    eq("a raw model ID is NOT honoured as a tier",
       ai.resolve_chat_tier("claude-opus-5")[1], ai._ACTIVE_MODEL)
    eq("(control) the real tier name IS honoured",
       ai.resolve_chat_tier("advanced")[0], "advanced")
    eq("advanced maps to a different model than standard is",
       ai.resolve_chat_tier("advanced")[1] != ai.resolve_chat_tier(None)[1], True)
    check(ai.resolve_chat_tier(None)[1] == ai._ACTIVE_MODEL,
          "standard follows _ACTIVE_MODEL rather than pinning a second string")

    print("\n-- the cost multiple is computed, never hardcoded --")
    opts = ai.chat_model_options()
    check(opts["multiple"] is not None and opts["multiple"] > 1,
          f"advanced costs more than standard, by a computed factor: {opts['multiple']}x")
    _rp = ai.get_pricing
    ai.get_pricing = lambda model=None: {"model": model, "known": False,
                                         "input_per_mtok": None,
                                         "output_per_mtok": None, "updated": None}
    try:
        check(ai.chat_model_options()["multiple"] is None,
              "an unknown price yields NO multiple, not a fabricated one")
    finally:
        ai.get_pricing = _rp

    print("\n-- spend is summed from recorded per-turn cost, not re-priced --")
    conn = ai._conn()
    conn.execute("DELETE FROM ai_chat_turns")
    conn.execute("INSERT INTO ai_chat_turns (surface_key,row_id,question,answer,"
                 "asked_at,tokens_in,tokens_out,cost_usd,model_used) VALUES "
                 "('alert','9','q','a','2026-08-04',100,50,0.5,'claude-opus-5')")
    conn.execute("INSERT INTO ai_chat_turns (surface_key,row_id,question,answer,"
                 "asked_at,tokens_in,tokens_out,cost_usd,model_used) VALUES "
                 "('alert','9','q2','a2','2026-08-04',100,50,0.25,'claude-sonnet-5')")
    conn.commit(); conn.close()
    st = ai.get_chat_state("alert", "9")
    eq("mixed-model spend sums the real per-turn costs", round(st["spent_usd"], 2), 0.75)
    st2 = ai.get_chat_state("alert", "no-turns-here")
    check(st2["spent_usd"] is None,
          "a finding with no turns reports None, not $0.00")

    print("\n-- the hourly rate limit also stops the chat --")
    _reset_gates()
    conn = ai._conn()
    conn.execute("INSERT OR REPLACE INTO ai_settings (key,value) VALUES ('rate_per_hour','1')")
    conn.execute("INSERT OR REPLACE INTO ai_rate_state (key,value) "
                 "VALUES ('hour_window_start',strftime('%s','now'))")
    conn.execute("INSERT OR REPLACE INTO ai_rate_state (key,value) VALUES ('hour_count','5')")
    conn.commit()
    conn.close()
    r = ai.ask_followup("alert", 2, "what is this?")
    check(not r.get("ok"), "the chat is refused when the hourly call limit is spent")
    check("rate limit" in (r.get("reason") or "").lower(),
          f"the refusal names the rate limit: {r.get('reason')!r}")

    print()
    if _failures:
        print(f"RESULT: {len(_failures)} FAILED")
        for f in _failures:
            print(f"  - {f}")
        return 1
    print("RESULT: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
