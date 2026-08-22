#!/usr/bin/env python3
"""Per-feature spend attribution and the hard spend ceiling.

Run: python3 modules/ai_engine/test_spend_metering.py   (exit 0 = all pass)

WHAT THIS GUARDS. Until 2026-08-21 `ai_usage` bucketed on UNIQUE(date, hour) with
no model, cost, surface or actor, and spend was RE-DERIVED by pricing every token
at the ACTIVE model's rate. That was already wrong: chat can select opus and the
rate-degrade path selects haiku, so three models were being priced as one. A
ceiling enforced against that figure is a ceiling against a fiction, which is why
attribution had to land before the ceiling could be trusted.

THE PROPERTY THE CEILING RESTS ON: a figure built from RECORDED prices, with any
part of it that is merely ESTIMATED counted separately and reported. A number that
silently mixes receipts and guesses is the thing this replaces.

CONTROLS THROUGHOUT. Every "is blocked" assertion is paired with a case that is
allowed (a ceiling wired to block everything would pass every refusal check), the
migration is proved to PRESERVE history rather than merely to run, and the stop
state is proved to CLEAR as well as to set -- a latch that never releases reports
a healthy engine as broken forever.

NO NETWORK. The SDK is stubbed; nothing here contacts Anthropic or spends money.
"""
import os
import sqlite3
import sys
import tempfile
import types

sys.path.insert(0, "/opt/nemesis")

_db = os.path.join(tempfile.mkdtemp(prefix="ai-spend-"), "throwaway.db")
os.environ["NEMESIS_DB_PATH"] = _db
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-not-real")

import modules                                          # noqa: E402
modules.set_shared_db_path(_db)
import modules_loader                                    # noqa: E402
modules_loader._db_path = _db
modules_loader._init_db()
_c = sqlite3.connect(_db)
_c.execute("INSERT OR REPLACE INTO modules_enabled (module_name, enabled) "
           "VALUES ('ai_engine', 1)")
_c.commit(); _c.close()

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
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


# ── stub SDK ────────────────────────────────────────────────────────────────
class _B:
    type = "text"

    def __init__(self, t):
        self.text = t


class _U:
    input_tokens = 1000
    output_tokens = 500


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
ai._record_call_success = lambda: None


def rows():
    conn = ai._conn()
    try:
        return conn.execute(
            "SELECT surface, model, cost_usd, tokens_in, tokens_out, actor "
            "FROM ai_usage ORDER BY id").fetchall()
    finally:
        conn.close()


def wipe():
    conn = ai._conn()
    conn.execute("DELETE FROM ai_usage")
    conn.commit()
    conn.close()


def call(job_id=None, cache_key=None, surface=None, model=None):
    SENT.clear()
    return ai.analyze("prompt", job_id=job_id, cache_key=cache_key,
                      cache_hours=0, surface=surface, model=model)


def main():
    ai._set_setting("rate_per_hour", "10000")
    ai._set_setting("rate_per_day", "10000")
    ai._set_setting("spend_cap_usd", "")
    ai._set_setting("spend_cap_monthly_usd", "")

    print("\n-- MIGRATION: an old-shape table is rebuilt WITHOUT losing history --")
    conn = ai._conn()
    conn.executescript("""
        DROP TABLE IF EXISTS ai_usage;
        CREATE TABLE ai_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT NOT NULL,
            hour INTEGER NOT NULL, call_count INTEGER NOT NULL DEFAULT 0,
            tokens_in INTEGER NOT NULL DEFAULT 0,
            tokens_out INTEGER NOT NULL DEFAULT 0, UNIQUE(date, hour));
        INSERT INTO ai_usage(date,hour,call_count,tokens_in,tokens_out)
        VALUES ('2026-08-01',9,3,300,150),('2026-08-01',10,2,200,100);
    """)
    conn.commit()
    before = conn.execute("SELECT COUNT(*), SUM(tokens_in) FROM ai_usage").fetchone()
    ai._migrate_ai_usage(conn)
    after = conn.execute("SELECT COUNT(*), SUM(tokens_in) FROM ai_usage").fetchone()
    cols = {r[1] for r in conn.execute("PRAGMA table_info(ai_usage)")}
    legacy = conn.execute("SELECT COUNT(*) FROM ai_usage "
                          "WHERE surface='legacy_rollup'").fetchone()[0]
    conn.close()
    check("history preserved exactly (rows and tokens)", before == after,
          (before, after))
    check("attribution columns exist afterwards",
          {"model", "cost_usd", "surface", "actor"} <= cols, sorted(cols))
    check("pre-attribution rows are MARKED, not silently blended", legacy == 2, legacy)
    conn = ai._conn(); ai._migrate_ai_usage(conn)
    again = conn.execute("SELECT COUNT(*) FROM ai_usage").fetchone()[0]
    conn.close()
    check("migration is idempotent", again == after[0])

    print("\n-- every call records WHAT WAS BILLED, not an assumed price --")
    wipe()
    call(job_id="alert_1234")
    r = rows()
    check("exactly one row per call", len(r) == 1, r)
    check("the model actually used is recorded", r[0][1] == ai._ACTIVE_MODEL, r[0])
    expect = ai._cost_of(1000, 500, ai._ACTIVE_MODEL)
    check("cost is recorded, and matches the rate table",
          abs((r[0][2] or 0) - expect) < 1e-9, (r[0][2], expect))
    check("tokens are recorded", (r[0][3], r[0][4]) == (1000, 500), r[0])

    print("\n-- SURFACE attribution: which feature spent it --")
    wipe()
    call(job_id="alert_1")
    call(job_id="chat:alert:9:1:standard")
    call(job_id="malware_verdict_abc")
    call(cache_key="cq:example.com")
    call(job_id="something_unknown")
    got = sorted(x[0] for x in rows())
    check("alert / chat / malware / community are each attributed",
          got == sorted(["alert_verdict", "chat", "malware_verdict",
                         "community_queue", "unattributed"]), got)
    check("an unrecognised job is 'unattributed', NOT null",
          "unattributed" in got and None not in got, got)
    wipe()
    call(job_id="alert_1", surface="explicit_override")
    check("an explicit surface= overrides the derived one",
          rows()[0][0] == "explicit_override", rows()[0])

    print("\n-- the per-feature breakdown answers 'what costs money' --")
    wipe()
    for _ in range(3):
        call(job_id="alert_x")
    call(job_id="chat:a:1:1:standard")
    by = dict((s, (n, usd)) for s, n, usd in ai.get_spend_by_surface())
    check("alert_verdict counted 3 calls", by.get("alert_verdict", (0,))[0] == 3, by)
    check("chat counted 1 call", by.get("chat", (0,))[0] == 1, by)
    check("its dollars are non-zero", by.get("alert_verdict", (0, 0))[1] > 0, by)

    print("\n-- ESTIMATED spend is counted SEPARATELY from recorded spend --")
    wipe()
    conn = ai._conn()
    conn.execute("INSERT INTO ai_usage(date,hour,call_count,tokens_in,tokens_out,"
                 "surface) VALUES (date('now'),1,1,1000,500,'legacy_rollup')")
    conn.commit(); conn.close()
    call(job_id="alert_1")
    sp = ai.get_spend()
    check("the unpriced legacy row is reported as such",
          sp.get("unpriced_rows") == 1, sp)
    check("recorded and estimated are reported apart",
          sp.get("recorded_usd", 0) > 0 and sp.get("estimated_usd", 0) > 0, sp)
    check("the total is their sum",
          abs(sp["usd"] - (sp["recorded_usd"] + sp["estimated_usd"])) < 1e-6, sp)

    print("\n-- the rolling WINDOW is what a weekly ceiling needs --")
    wipe()
    conn = ai._conn()
    conn.execute("INSERT INTO ai_usage(date,hour,ts,call_count,tokens_in,tokens_out,"
                 "model,cost_usd,surface) VALUES "
                 "(date('now','-20 day'),1,datetime('now','-20 day'),1,10,10,"
                 "'claude-sonnet-5',5.0,'alert_verdict')")
    conn.commit(); conn.close()
    ai._set_setting("spend_cap_window_days", "7")
    check("a 20-day-old charge is OUTSIDE a 7-day window",
          (ai.get_spend().get("usd") or 0) == 0, ai.get_spend())
    ai._set_setting("spend_cap_window_days", "30")
    check("CONTROL: the same charge is INSIDE a 30-day window",
          (ai.get_spend().get("usd") or 0) >= 5.0, ai.get_spend())

    print("\n-- THE CEILING: hard stop, and it is REPORTABLE --")
    ai._set_setting("spend_cap_usd", "1.00")          # already $5 spent above
    lim, reason, kind = (lambda c: (lambda t: t)(ai._check_rate_limit(c)))(ai._conn())
    check("over the ceiling reports 'hard' (never degrade)", kind == "hard",
          (kind, reason))
    check("the reason names the ceiling and the window",
          "spend cap" in reason and "30d" in reason, reason)
    SENT.clear()
    r = call(job_id="alert_1")
    check("NO request is made once stopped", len(SENT) == 0, SENT)
    check("the caller is told it was refused", r.get("ok") is False, r)
    stop = ai.get_spend_stop()
    check("the stop is RECORDED as state, not just refused", stop.get("stopped") is True, stop)
    check("it records when", bool(stop.get("since")), stop)
    check("it records the spend at the moment of stopping",
          (stop.get("usd_at_stop") or 0) > 0, stop)
    st = ai.get_status()
    check("status reports spend_capped as its OWN state",
          st.get("state") == "spend_capped", st)
    check("the detail explains it is a ceiling, not a rate limit",
          "ceiling" in (st.get("detail") or "").lower(), st)

    print("\n-- and it RELEASES: a latch that never clears is its own bug --")
    ai._set_setting("spend_cap_usd", "1000.00")
    SENT.clear()
    r = call(job_id="alert_1")
    check("raising the ceiling lets calls through again",
          r.get("ok") is True and len(SENT) == 1, (r.get("reason"), SENT))
    check("and the reported stop clears", ai.get_spend_stop().get("stopped") is False,
          ai.get_spend_stop())
    ai._set_setting("spend_cap_usd", "")
    ai._set_setting("spend_stop_active", "1")        # simulate a stale latch
    check("REMOVING the ceiling reports not-stopped even with a stale flag",
          ai.get_spend_stop().get("stopped") is False, ai.get_spend_stop())
    check("...and status does not claim a $0.00 ceiling",
          "ceiling" not in (ai.get_status().get("detail") or "").lower(),
          ai.get_status())

    print("\n-- unreadable spend + a ceiling set still FAILS CLOSED --")
    ai._set_setting("spend_cap_usd", "5.00")
    _orig = ai.get_spend
    ai.get_spend = lambda window_days=None: {"ok": False, "window_days": 30}
    try:
        conn = ai._conn()
        lim, reason, kind = ai._check_rate_limit(conn)
        conn.close()
        check("cannot read spend + ceiling set -> refuse (fail closed)",
              lim is True and kind == "hard", (lim, kind, reason))
    finally:
        ai.get_spend = _orig
    ai._set_setting("spend_cap_usd", "")

    print("\n-- settings validation refuses garbage instead of removing protection --")
    ai._set_setting("spend_cap_usd", "7.50")
    check("a valid ceiling reads back", ai._spend_cap_usd() == 7.50, ai._spend_cap_usd())
    ai._set_setting("spend_cap_usd", "not-a-number")
    check("an unparseable stored ceiling means NO cap, never a cap of zero",
          ai._spend_cap_usd() is None, ai._spend_cap_usd())
    ai._set_setting("spend_cap_usd", "")
    ai._set_setting("spend_cap_monthly_usd", "3.25")
    check("the OLD setting name is still honoured (upgrades keep their cap)",
          ai._spend_cap_usd() == 3.25, ai._spend_cap_usd())
    ai._set_setting("spend_cap_usd", "9.99")
    check("the new name WINS when both are set", ai._spend_cap_usd() == 9.99)
    ai._set_setting("spend_cap_window_days", "abc")
    check("an unparseable window falls back to the default, not to zero",
          ai._spend_window_days() == ai._SPEND_WINDOW_DAYS_DEFAULT,
          ai._spend_window_days())

    
    print("\n== DATED MODEL IDS MUST STILL PRICE (the recorded/estimated boundary) ==")
    # `_MODEL_RATES` is keyed by rolling alias. The lookup was exact-string, so a
    # dated snapshot ID returned known=False and its cost slid from the RECORDED
    # bucket into the ESTIMATED one -- silently, and precisely in the figure the
    # spend ceiling is enforced against.
    _alias = ai.get_pricing("claude-haiku-4-5")
    _dated = ai.get_pricing("claude-haiku-4-5-20251001")
    check("the rolling alias is priced", _alias["known"] is True, _alias)
    check("the DATED id is priced too", _dated["known"] is True, _dated)
    check("and prices identically to its alias",
          (_dated["input_per_mtok"], _dated["output_per_mtok"])
          == (_alias["input_per_mtok"], _alias["output_per_mtok"]), (_dated, _alias))
    check("a dated sonnet id also resolves",
          ai.get_pricing("claude-sonnet-5-20250930")["known"] is True)
    # CONTROLS: normalisation must not invent prices for models we genuinely
    # do not know, and must not mangle ordinary ids.
    _unknown = ai.get_pricing("claude-nonexistent-9")
    check("CONTROL: a genuinely unknown model stays unknown",
          _unknown["known"] is False, _unknown)
    _unknown_dated = ai.get_pricing("claude-nonexistent-9-20260101")
    check("CONTROL: an unknown model with a date stays unknown too",
          _unknown_dated["known"] is False, _unknown_dated)
    check("CONTROL: a non-dated numeric suffix is NOT treated as a date",
          ai._pricing_alias("claude-opus-5") == "claude-opus-5")
    check("CONTROL: the alias helper strips only an 8-digit trailing date",
          ai._pricing_alias("claude-haiku-4-5-20251001") == "claude-haiku-4-5")
    # `_cost_of` returns None for an unpriced model, and `None > 0` RAISES.
    # A check that explodes instead of failing takes the whole suite down with
    # it and reports nothing at all -- so compare defensively and let the check
    # register a clean FAIL.
    _dated_cost = ai._cost_of(1_000_000, 0, "claude-haiku-4-5-20251001")
    check("cost is computed (not None, not zero) for a dated id",
          isinstance(_dated_cost, (int, float)) and _dated_cost > 0, _dated_cost)

    print("\n%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
