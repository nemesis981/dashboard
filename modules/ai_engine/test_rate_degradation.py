#!/usr/bin/env python3
"""A call-count ceiling degrades the model; a MONEY ceiling still refuses.

Run:  python3 modules/ai_engine/test_rate_degradation.py   (exit 0 = pass)

WHAT THIS GUARDS. Hitting `rate_per_hour`/`rate_per_day` used to stop AI
interpretation dead — and a rate limit binds on the busiest day, exactly when
findings most need explaining. Those ceilings now fall back to a cheaper model
instead of refusing.

THE PROPERTY THAT MAKES THAT SAFE, and the one most likely to be broken by a
later "simplification":

  * a THROUGHPUT ceiling (calls/hour, calls/day) may degrade, but only inside a
    bounded band — past `ceiling * rate_degrade_multiplier` it refuses, or the
    ceiling would not be a ceiling at all; and
  * a MONEY ceiling (`spend_cap_monthly_usd`) is NEVER degradable. A cap the
    engine can route around by picking a cheaper model is not a cap. This suite
    fails if anyone makes money limits degrade "for consistency".

CONTROLS EVERYWHERE. Each state is paired with proof the harness can produce a
different one: the under-ceiling case proves it can run full-quality, the
disabled-multiplier case proves degradation can be switched off, and every
"no call was made" assertion is paired with a case where a call IS made — a
harness wired to never call would otherwise pass all the refusal assertions.

NO NETWORK. The SDK is stubbed; nothing here contacts Anthropic or spends money.
"""
import os
import sys
import tempfile
import time
import types

sys.path.insert(0, "/opt/nemesis")

_db = os.path.join(tempfile.mkdtemp(prefix="ai-degrade-"), "throwaway.db")
os.environ["NEMESIS_DB_PATH"] = _db
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-not-real")

import modules                                          # noqa: E402
modules.set_shared_db_path(_db)
import sys as _s_npfa
_s_npfa.path.insert(0, '/opt/nemesis/alert_manager')
import prompt_fields as _pf                    # noqa: E402  (NPFA/1)

# `get_status()` asks modules_loader whether ai_engine is enabled, and the loader
# gets its DB path from `init(app, db_path, modules_dir)` — which needs a Flask
# app this harness has no reason to build. Point it at the throwaway DB directly
# and create its table. Harness plumbing only: nothing under test reads these.
import modules_loader                                    # noqa: E402
modules_loader._db_path = _db
modules_loader._init_db()
# Row written directly: `set_enabled()` validates the name against modules the
# loader has DISCOVERED, which needs a filesystem scan this harness does not do.
# get_status() short-circuits to "disabled" without this row.
import sqlite3 as _sq3                                   # noqa: E402
_c = _sq3.connect(_db)
_c.execute("INSERT OR REPLACE INTO modules_enabled (module_name, enabled) VALUES ('ai_engine', 1)")
_c.commit()
_c.close()

from modules.ai_engine import module as ai               # noqa: E402

passed = failed = 0
SENT = []


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + detail) if detail else ""))


# ── stub SDK ────────────────────────────────────────────────────────────────
class _B:
    type = "text"

    def __init__(self, t):
        self.text = t


class _U:
    input_tokens = 10
    output_tokens = 5


class _M:
    stop_reason = "end_turn"

    def __init__(self):
        self.content = [_B("answer")]
        self.usage = _U()


class _Messages:
    def create(self, **kw):
        SENT.append(kw)
        return _M()


class _Client:
    def __init__(self, **_kw):
        self.messages = _Messages()


_fake = types.ModuleType("anthropic")
_fake.Anthropic = _Client
sys.modules["anthropic"] = _fake
ai._increment_usage = lambda conn, tokens_in, tokens_out, **kw: None
ai._record_call_success = lambda: None


def set_counts(hour_count, day_count):
    """Put the sliding-window counters into a known state."""
    conn = ai._conn()
    now = time.time()
    ai._set_rate_state(conn, "hour_window_start", now)
    ai._set_rate_state(conn, "hour_count", hour_count)
    ai._set_rate_state(conn, "day_window_start", now)
    ai._set_rate_state(conn, "day_count", day_count)
    conn.commit()
    conn.close()


def limit():
    conn = ai._conn()
    try:
        return ai._check_rate_limit(conn)
    finally:
        conn.close()


def call(prompt="hello", cache_key=None):
    SENT.clear()
    # NPFA/1 (ADR 0025): this suite exercises rate limiting and degradation, not the
    # allowlist. The prompt is wrapped in the proof type so the boundary
    # passes and the guard under test is the one actually measured.
    return ai._analyze_inner(_pf.BuiltPrompt(prompt), None, 200, cache_key, 0, False)


def sent0(field):
    """The captured wire field, or None if no call was made.

    Indexing SENT[0] directly makes an unexpected "no call" abort the whole run
    with an IndexError, so the remaining checks never report. A failed check
    should cost one line, not the rest of the suite.
    """
    return SENT[0].get(field) if SENT else None


def main():
    ai._set_setting("rate_per_hour", "10")
    ai._set_setting("rate_per_day", "100")
    ai._set_setting("rate_degrade_multiplier", "2")
    ai._set_setting("spend_cap_monthly_usd", "")

    print("\n-- CONTROL: under the ceiling, nothing is limited or degraded --")
    set_counts(3, 3)
    lim, reason, kind = limit()
    check("not limited under the ceiling", lim is False and kind == "")
    r = call()
    check("a real call is made", len(SENT) == 1)
    check("the full-quality model is used", sent0("model") == ai._ACTIVE_MODEL,
          "model=%r" % (sent0("model"),))
    check("result is not flagged degraded", r.get("degraded") is False)
    check("model_used reports the active model", r.get("model_used") == ai._ACTIVE_MODEL)

    print("\n-- at the HOURLY ceiling: degrade, do not stop --")
    set_counts(10, 3)
    lim, reason, kind = limit()
    check("limited with kind 'degrade'", lim is True and kind == "degrade",
          "kind=%r reason=%r" % (kind, reason))
    r = call()
    check("the call STILL HAPPENS", len(SENT) == 1, "sent=%d" % len(SENT))
    check("it used the cheap model", sent0("model") == ai._DEGRADED_MODEL,
          "model=%r" % (sent0("model"),))
    check("the result says so (degraded=True)", r.get("degraded") is True)
    check("model_used names the cheap model", r.get("model_used") == ai._DEGRADED_MODEL)
    check("the answer is still returned", r.get("ok") is True and r.get("text"))

    print("\n-- at the DAILY ceiling: same treatment --")
    set_counts(0, 100)
    lim, reason, kind = limit()
    check("daily ceiling degrades too", kind == "degrade", "kind=%r" % kind)
    call()
    check("daily-degraded call uses the cheap model",
          SENT and sent0("model") == ai._DEGRADED_MODEL)

    print("\n-- past ceiling x multiplier: HARD stop, no call --")
    set_counts(20, 3)
    lim, reason, kind = limit()
    check("kind is 'hard' beyond the band", kind == "hard", "kind=%r" % kind)
    r = call()
    check("NO request is made", len(SENT) == 0, "sent=%r" % SENT)
    check("caller is told it was refused", r.get("ok") is False)
    check("the reason names the rate limit", "rate limit" in (r.get("reason") or "").lower())

    print("\n-- multiplier=1 disables degradation (escape hatch) --")
    ai._set_setting("rate_degrade_multiplier", "1")
    set_counts(10, 3)
    lim, reason, kind = limit()
    check("at the ceiling with multiplier=1 it is 'hard'", kind == "hard", "kind=%r" % kind)
    r = call()
    check("and no call is made", len(SENT) == 0)
    ai._set_setting("rate_degrade_multiplier", "2")

    print("\n-- THE SAFETY PROPERTY: money ceilings are NEVER degradable --")
    set_counts(0, 0)                       # throughput deliberately clear
    ai._set_setting("spend_cap_monthly_usd", "5.00")
    _orig_spend = ai.get_spend
    ai.get_spend = lambda window_days=None: {"ok": True, "usd": 9.99, "window_days": 30}
    try:
        lim, reason, kind = limit()
        check("spend cap reports 'hard', never 'degrade'", kind == "hard",
              "kind=%r reason=%r" % (kind, reason))
        r = call()
        check("NO request is made when over the money cap", len(SENT) == 0, "sent=%r" % SENT)
        check("the reason names the spend cap", "spend cap" in (r.get("reason") or "").lower(),
              repr(r.get("reason")))

        print("\n-- and an UNREADABLE spend with a cap set still refuses --")
        ai.get_spend = lambda window_days=None: {"ok": False, "window_days": 30}
        lim, reason, kind = limit()
        check("unreadable spend + cap set is 'hard'", kind == "hard", "kind=%r" % kind)
        check("NOT degraded", kind != "degrade")
    finally:
        ai.get_spend = _orig_spend
        ai._set_setting("spend_cap_monthly_usd", "")

    print("\n-- CONTROL: with the cap cleared, calls work again --")
    set_counts(0, 0)
    r = call()
    check("a normal call succeeds after the cap is cleared",
          r.get("ok") is True and len(SENT) == 1)

    print("\n-- a degraded answer must not pollute the full-quality cache key --")
    set_counts(10, 3)                       # degrade band
    call(cache_key="probe_key")
    conn = ai._conn()
    keys = [r[0] for r in conn.execute("SELECT cache_key FROM ai_cache")]
    conn.close()
    check("nothing was stored under the bare full-quality key",
          "probe_key" not in keys, "keys=%r" % keys)
    check("it was namespaced to the degraded model",
          any(k.endswith("@" + ai._DEGRADED_MODEL) for k in keys), "keys=%r" % keys)

    print("\n-- get_status reports DEGRADED as its own state --")
    set_counts(10, 3)
    st = ai.get_status()
    check("status detail says degraded, not merely rate limited",
          "degrad" in (st.get("detail") or "").lower(), repr(st.get("detail")))
    set_counts(20, 3)
    st = ai.get_status()
    check("past the band it reports rate limited",
          "rate limited" in (st.get("detail") or "").lower(), repr(st.get("detail")))
    set_counts(0, 0)
    st = ai.get_status()
    check("CONTROL: clear counters report Ready",
          (st.get("detail") or "") == "Ready", repr(st.get("detail")))

    print("\n%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
