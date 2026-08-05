"""
AI Engine Module — centralised Anthropic Claude integration.

Public API (importable from any module):
    is_enabled()        → bool
    get_status()        → dict
    analyze(prompt, ...) → dict
    get_usage_stats()   → dict
    get_pricing()       → dict
    get_settings()      → dict

DB: shared alerts.db (ai_* tables), reached via the Stage-1 module accessor.
    The old per-module ai_engine.db was retired in ADR 0001 Stage 6.
"""

import os
import re
import json
import time
import logging
import threading
import urllib.request
from datetime import datetime, timedelta

from modules import NemesisModule, get_data_manager

log = logging.getLogger("nemesis.ai_engine")

# ADR 0001 Stage 6: the legacy per-module ai_engine.db has been retired (data migrated to
# the shared alerts.db ai_* tables at the Stage 3 cutover) — no per-module DB path remains.

# Defaults — overridden by ai_settings table
_RATE_HOUR_DEFAULT = 10
_RATE_DAY_DEFAULT  = 50


# ─────────────────────────────────────────────────────────────────────────────
# DB
# ─────────────────────────────────────────────────────────────────────────────

def _conn():
    # ADR 0006: route ai_engine DB access through the Data Manager (write-own access
    # control + operation logging). Drop-in for the old shared accessor — the
    # connection's row_factory is applied by connect(). ai_engine writes only ai_*
    # tables, so every write passes the namespace check. Single switch point.
    return get_data_manager().connect("ai_engine")


def _init_db() -> None:
    conn = _conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS ai_cache (
            cache_key    TEXT PRIMARY KEY,
            response_text TEXT NOT NULL,
            generated_at  REAL NOT NULL,
            expires_at    REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ai_usage (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            date       TEXT    NOT NULL,
            hour       INTEGER NOT NULL,
            call_count INTEGER NOT NULL DEFAULT 0,
            tokens_in  INTEGER NOT NULL DEFAULT 0,
            tokens_out INTEGER NOT NULL DEFAULT 0,
            UNIQUE(date, hour)
        );
        CREATE INDEX IF NOT EXISTS idx_aiu_date ON ai_usage(date);

        CREATE TABLE IF NOT EXISTS ai_settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ai_rate_state (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        -- Graduated authority (L0-L4). current_level is EARNED via the promotion
        -- mechanism; hard_ceiling is the code-level maximum for the class and is
        -- never raised by anything at runtime.
        --
        -- NOTE ON THE NAME: the scoping doc's schema sketch called this column
        -- "floor" while its own comment described a ceiling. It is a CEILING — the
        -- maximum authority this class may ever reach. Named unambiguously here
        -- because a column named "floor" holding a maximum is how a later change
        -- writes MAX() where MIN() belongs and silently inverts the safety property.
        CREATE TABLE IF NOT EXISTS ai_authority (
            action_class     TEXT PRIMARY KEY,
            current_level    INTEGER NOT NULL DEFAULT 0,
            hard_ceiling     INTEGER NOT NULL,
            last_promoted_at TEXT,
            last_demoted_at  TEXT,
            policy_ref       TEXT
        );

        -- Every L1 proposal is a labelled datapoint: the human's approve/reject is
        -- what the promotion mechanism measures. Also the audit record for anything
        -- executed at L2+.
        CREATE TABLE IF NOT EXISTS ai_proposals (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            action_class    TEXT NOT NULL,
            surface_key     TEXT NOT NULL,
            row_id          TEXT    NOT NULL,   -- TEXT for the same reason as ai_chat_turns.row_id
            proposed_action TEXT NOT NULL,
            reasoning       TEXT NOT NULL,
            model_used      TEXT NOT NULL,
            created_at      TEXT NOT NULL,
            human_response  TEXT,
            responded_at    TEXT,
            responded_by    TEXT,
            executed        INTEGER NOT NULL DEFAULT 0,
            executed_at     TEXT,
            undone          INTEGER NOT NULL DEFAULT 0,
            undone_at       TEXT,
            undone_by       TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_aip_class ON ai_proposals(action_class);

        -- User-defined standing rules. These NARROW behaviour only — see
        -- effective_ceiling(). No rule type raises the ceiling, so a rule worded to
        -- widen authority cannot do so. active=0 is a soft delete (the standing
        -- no-automatic-permanent-deletion principle).
        CREATE TABLE IF NOT EXISTS ai_standing_rules (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_type    TEXT NOT NULL,
            action_class TEXT,
            rule_text    TEXT NOT NULL,
            created_by   TEXT NOT NULL,
            created_at   TEXT NOT NULL,
            active       INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_aisr_active ON ai_standing_rules(active, action_class);

        -- Contextual chat: one row per question asked against an anchored finding.
        -- Carries the per-turn token split and cost because this is the first
        -- surface where the user spends money one question at a time, and the
        -- product's answer to that is to show them, not to hide it behind a
        -- monthly total. Also backs the per-anchor turn cap.
        CREATE TABLE IF NOT EXISTS ai_chat_turns (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            surface_key TEXT    NOT NULL,
            row_id      TEXT    NOT NULL,   -- TEXT: alerts anchor on rule_id, which is not numeric
            question    TEXT    NOT NULL,
            answer      TEXT,
            asked_by    TEXT,
            asked_at    TEXT    NOT NULL,
            tokens_in   INTEGER NOT NULL DEFAULT 0,
            tokens_out  INTEGER NOT NULL DEFAULT 0,
            cost_usd    REAL,
            model_used  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_act_anchor ON ai_chat_turns(surface_key, row_id);
    """)
    conn.commit()
    conn.close()


# Initialise at import time so any module can import and call before Module.start().
_init_db()


# ─────────────────────────────────────────────────────────────────────────────
# Graduated authority — the ceiling clamp
#
# effective_ceiling() is the single place that decides how much authority an
# action class has RIGHT NOW. Three terms, combined with min():
#
#   earned      — ai_authority.current_level, moved by the promotion mechanism
#   hard        — the code-level maximum for that class (never raised at runtime)
#   rule_clamp  — user standing rules, which NARROW ONLY
#
# The safety property the whole design rests on: a standing rule cannot widen
# authority no matter how it is worded, because there is no rule type that
# raises its term and min() cannot exceed any input. This is structural, not a
# matter of the model interpreting an instruction conservatively.
# ─────────────────────────────────────────────────────────────────────────────

L0_OBSERVE          = 0
L1_RECOMMEND        = 1
L2_ACT_REVERSIBLE   = 2
L3_ACT_DISRUPTIVE   = 3
L4_GOVERN           = 4

# Hard ceilings per action class. A class absent from this map has no ceiling
# defined and is therefore not a known action class — see effective_ceiling().
#
# malware_file_quarantine is pinned at L1 because the product has NO restore
# path for a quarantined file (_quarantine_file() moves + chmod 000s it and
# nothing reverses either step). This is a missing-capability ceiling, not a
# threshold choice: it cannot be raised by any amount of track record until a
# restore function exists.
ACTION_CLASS_CEILINGS = {
    "ip_quarantine_external":  L3_ACT_DISRUPTIVE,
    "ip_block_permanent":      L2_ACT_REVERSIBLE,
    "ip_action_internal":      L1_RECOMMEND,
    "malware_file_quarantine": L1_RECOMMEND,
}


class UnknownActionClass(Exception):
    """Raised for an action class with no defined ceiling.

    Deliberately an exception rather than a returned level: every integer 0-4 is
    a legal answer, so returning one here would be indistinguishable from a real
    measurement of a real class.
    """


class AuthorityUnavailable(Exception):
    """Raised when authority state cannot be read.

    Fails closed AND loud. Returning L0 instead would be a default that means
    something, which the caller cannot tell apart from a genuine "this class is
    only allowed to observe" result.
    """


def _combine_ceiling(earned: int, hard: int, rule_clamp: int) -> int:
    """Pure combination of the three ceiling terms. Narrowing only, by construction."""
    return min(earned, hard, rule_clamp)


# Self-test: proves _combine_ceiling can return more than one answer and that no
# input widens the result. Runs at import, in the production path — a clamp that
# could only ever return one value would otherwise look exactly like a working one.
def _selftest_combine() -> None:
    cases = [
        # (earned, hard, rule_clamp, expected, what it proves)
        (4, 4, 4, 4, "no constraint anywhere leaves the level alone"),
        (4, 4, 0, 0, "a 'never' rule clamps a fully-promoted class to L0"),
        (4, 4, 1, 1, "an 'ask_before' rule forces L1 despite full promotion"),
        (0, 4, 4, 0, "an unearned class stays L0 even with no rules"),
        (4, 1, 4, 1, "the hard ceiling holds against a fully-promoted class"),
        (2, 3, 4, 2, "the lowest term wins when they disagree"),
    ]
    for earned, hard, clamp, expected, why in cases:
        got = _combine_ceiling(earned, hard, clamp)
        if got != expected:
            raise AssertionError(
                f"authority clamp self-test failed ({why}): "
                f"_combine_ceiling({earned}, {hard}, {clamp}) = {got}, expected {expected}"
            )
    # A widening attempt must be inert: no term above the others may raise the result.
    if _combine_ceiling(1, 4, 4) != 1:
        raise AssertionError("authority clamp self-test failed: a high term widened the result")


_selftest_combine()


def _standing_rule_clamp(conn, action_class: str) -> tuple:
    """Most restrictive clamp from active standing rules on this class.

    Returns (clamp_level, matched_rule_types). Rules with a NULL action_class are
    NOT included: they have no structured class for this gate to match against and
    are advisory (system-prompt) only. Callers that surface rules to the user must
    say so, or a user believes a rule is enforced when it is not.
    """
    rows = conn.execute(
        "SELECT rule_type FROM ai_standing_rules "
        "WHERE active=1 AND action_class=?",
        (action_class,),
    ).fetchall()

    types = {(r["rule_type"] or "").strip().lower() for r in rows}

    clamp = L4_GOVERN            # no constraint
    if "ask_before" in types:
        clamp = min(clamp, L1_RECOMMEND)
    if "never" in types:
        clamp = L0_OBSERVE
    # 'always' deliberately absent: it cannot raise the clamp. An 'always' rule
    # specifies HOW an already-earned L2+ action behaves, never WHETHER a lower
    # class acts autonomously — auto-approving an L1 proposal would corrupt the
    # agreement-rate signal the promotion mechanism measures to decide on L2.
    return clamp, sorted(types)


def effective_ceiling(action_class: str) -> dict:
    """How much authority this action class has right now, and why.

    Returns {level, earned, hard_ceiling, rule_clamp, rule_types, reasons}.
    Raises UnknownActionClass / AuthorityUnavailable — never a fallback level.

    'reasons' names which term(s) actually bound the result, so a refusal can be
    stated to the user ("your standing rule against this is active") rather than
    the AI silently declining to mention an action.
    """
    hard = ACTION_CLASS_CEILINGS.get(action_class)
    if hard is None:
        raise UnknownActionClass(
            f"no hard ceiling defined for action class {action_class!r}; "
            f"known classes: {sorted(ACTION_CLASS_CEILINGS)}"
        )

    try:
        conn = _conn()
        try:
            row = conn.execute(
                "SELECT current_level FROM ai_authority WHERE action_class=?",
                (action_class,),
            ).fetchone()
            # No row means this class has never been promoted — a real, meaningful
            # L0, not a failed read. The read itself succeeded.
            earned = int(row["current_level"]) if row else L0_OBSERVE
            clamp, rule_types = _standing_rule_clamp(conn, action_class)
        finally:
            conn.close()
    except Exception as exc:
        raise AuthorityUnavailable(
            f"cannot read authority state for {action_class!r}: {exc}"
        ) from exc

    level = _combine_ceiling(earned, hard, clamp)

    reasons = []
    if level == clamp and clamp < min(earned, hard):
        reasons.append("standing_rule")
    if level == hard and hard < min(earned, clamp):
        reasons.append("hard_ceiling")
    if level == earned and earned < min(hard, clamp):
        reasons.append("not_yet_earned")
    if not reasons:
        reasons.append("unconstrained" if level == L4_GOVERN else "tied")

    return {
        "level":        level,
        "earned":       earned,
        "hard_ceiling": hard,
        "rule_clamp":   clamp,
        "rule_types":   rule_types,
        "reasons":      reasons,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Contextual chat — follow-up questions anchored to a surfaced finding
#
# A chat turn is (surface_key, row_id, question). The CLIENT NEVER SENDS
# CONTEXT: the server rebuilds it from the row via the anchor's registered
# loader. A client able to supply arbitrary context would be a generic chatbot
# wearing an anchor's clothing, which is the thing this design rules out.
#
# Cost, stated plainly because it is the single biggest spend change here:
# every cached call in this product keys on something stable, because the SAME
# question recurs. A follow-up is a novel question by definition, so
# cache_hours=0 and EVERY QUESTION IS A REAL BILLED CALL. Three controls apply,
# all pre-existing:
#   - the hourly/daily call limits and the dollar spend cap, inherited free by
#     going through analyze() (_check_rate_limit runs inside _analyze_inner);
#   - a per-anchor turn cap, so one confusing alert cannot become an unbounded
#     conversation;
#   - job_id in-flight dedup, so a double-click cannot bill twice.
#
# NEVER pass force=True from this path. force=True bypasses rate limiting
# entirely — including the spend cap — and would turn the one surface where the
# user spends interactively into the one surface with no ceiling.
# ─────────────────────────────────────────────────────────────────────────────

_TURN_CAP_DEFAULT      = 6      # follow-ups per anchored row
_HISTORY_TURNS         = 3      # prior Q&A pairs replayed for continuity
_MAX_QUESTION_CHARS    = 4000   # bounds a paste-back; see Path 2 in the scoping doc
_CHAT_MAX_TOKENS       = 700

_ANCHORS: dict = {}


def register_anchor(surface_key: str, loader, action_classes=(), label: str = "") -> None:
    """Register a surface that may carry a chat affordance.

    `loader(row_id)` must return the same facts that produced the original
    analysis, plus that analysis — it is the function that already builds the
    prompt inside each caller today. Returning a falsy value is treated as a
    FAILURE, not as "this row has no context": answering confidently about
    nothing is the failure mode this refuses to have.

    `action_classes` names the action classes this surface can lead to. They
    determine what the chat is permitted to SAY, via effective_ceiling(). A
    surface that never leads to an action registers none and stays explanatory.

    A surface that has not registered has no chat affordance at all — adding one
    is a deliberate registration, never a side effect of the component existing.
    """
    if not surface_key or not callable(loader):
        raise ValueError("register_anchor needs a surface_key and a callable loader")
    for ac in action_classes:
        if ac not in ACTION_CLASS_CEILINGS:
            raise UnknownActionClass(
                f"anchor {surface_key!r} names unknown action class {ac!r}"
            )
    _ANCHORS[surface_key] = {
        "loader":         loader,
        "action_classes": tuple(action_classes),
        "label":          label or surface_key,
    }


def registered_anchors() -> list:
    return sorted(_ANCHORS)


def _chat_scope(action_classes) -> dict:
    """What the chat may say, derived from each action class's earned authority.

    Degrades to explanation-only if authority cannot be read — and SAYS SO via
    `degraded`. Restricting to L0 is safe (it is the floor, so a failed read can
    only ever under-grant), but it must never present as an ordinary L0, or an
    unreadable authority table would look identical to a healthy new install.
    """
    per_class, degraded, reason = {}, False, ""
    for ac in action_classes:
        try:
            per_class[ac] = effective_ceiling(ac)["level"]
        except AuthorityUnavailable as exc:
            per_class[ac] = L0_OBSERVE
            degraded, reason = True, str(exc)
        except UnknownActionClass:
            per_class[ac] = L0_OBSERVE
            degraded, reason = True, f"unknown action class {ac!r}"

    top = max(per_class.values()) if per_class else L0_OBSERVE
    return {"level": top, "per_class": per_class,
            "degraded": degraded, "degraded_reason": reason}


def _chat_system_prompt(scope: dict) -> str:
    """The ONE place chat scope is enforced.

    Written once, here, rather than per surface: the scope boundary is a safety
    property, and a property enforced in six places is enforced in none.
    """
    base = (
        "You are the security assistant built into a Nemesis firewall appliance. "
        "You are explaining a specific finding to the person who owns this network, "
        "who may have no IT background. Be concrete and plain-spoken. "
        "Answer only from the finding data provided — if something is not in it, "
        "say you cannot tell from the available data rather than guessing.\n\n"
    )
    if scope["level"] <= L0_OBSERVE:
        rules = (
            "SCOPE: You explain what this finding means and why it matters. "
            "You do NOT recommend network changes, and you do NOT offer to take "
            "any action. If asked what to do, explain the trade-offs of the "
            "options that exist and say the decision is theirs to make."
        )
    elif scope["level"] == L1_RECOMMEND:
        rules = (
            "SCOPE: You may recommend a specific action and explain your reasoning. "
            "You CANNOT execute anything — every recommendation is a proposal the "
            "person must approve. Never imply an action has been or will be taken "
            "automatically."
        )
    else:
        allowed = [c for c, lvl in scope["per_class"].items() if lvl >= L2_ACT_REVERSIBLE]
        rules = (
            "SCOPE: You may recommend an action and offer to carry it out, but only "
            f"for: {', '.join(sorted(allowed)) or 'none'}. Anything else is a "
            "recommendation only. Every action you offer is carried out through the "
            "system's own gated action path after explicit confirmation — never "
            "state that something is already done."
        )
    if scope["degraded"]:
        rules += ("\nNOTE: authority state could not be read, so you are restricted "
                  "to explanation regardless of configuration.")
    return base + rules


def _turn_count(conn, surface_key: str, row_id) -> int:
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM ai_chat_turns WHERE surface_key=? AND row_id=?",
        (surface_key, str(row_id)),
    ).fetchone()
    return int(row["n"]) if row else 0


def _turn_cap() -> int:
    raw = (_get_setting("chat_turn_cap", str(_TURN_CAP_DEFAULT)) or "").strip()
    try:
        val = int(raw)
        return val if val > 0 else _TURN_CAP_DEFAULT
    except (TypeError, ValueError):
        log.warning("ai_engine: chat_turn_cap=%r is not an integer — using %d",
                    raw, _TURN_CAP_DEFAULT)
        return _TURN_CAP_DEFAULT


def _cost_of(tokens_in: int, tokens_out: int, model: str | None = None):
    """Dollar cost of one call, or None when the model's rates are unknown.

    None, never 0.0. A zero-dollar cost is a legitimate-looking measurement and
    is exactly wrong for a call that really did bill something.
    """
    p = get_pricing(model)
    if not p.get("known") or p.get("input_per_mtok") is None:
        return None
    return round(tokens_in * p["input_per_mtok"] / 1_000_000
                 + tokens_out * p["output_per_mtok"] / 1_000_000, 6)


def estimate_question_cost(question: str, surface_key: str = "", row_id="") -> dict:
    """Pre-flight cost ESTIMATE for a question, for display before it is asked.

    Explicitly an estimate: real token counts are only known after the call.
    Returns `{estimate_usd, is_estimate: True, known, updated, model}`;
    `estimate_usd` is None when the model's rates are unknown, never 0.0.
    """
    q = (question or "").strip()
    # ~4 chars/token is the standard rough ratio; context and history dominate a
    # follow-up prompt, so they are included rather than pricing the question alone.
    ctx_chars = 0
    if surface_key in _ANCHORS and row_id:
        try:
            conn = _conn()
            try:
                rows = conn.execute(
                    "SELECT question, answer FROM ai_chat_turns "
                    "WHERE surface_key=? AND row_id=? ORDER BY id DESC LIMIT ?",
                    (surface_key, str(row_id), _HISTORY_TURNS),
                ).fetchall()
            finally:
                conn.close()
            ctx_chars = sum(len(r["question"] or "") + len(r["answer"] or "") for r in rows)
        except Exception:
            ctx_chars = 0   # estimate only; a failed read here cannot mislead a gate
    est_in  = int((len(q) + ctx_chars + 1500) / 4)   # +1500 ≈ system prompt + finding
    est_out = int(_CHAT_MAX_TOKENS * 0.6)
    p = get_pricing()
    return {
        "estimate_usd": _cost_of(est_in, est_out),
        "is_estimate":  True,
        "known":        bool(p.get("known")),
        "updated":      p.get("updated"),
        "model":        p.get("model"),
        "est_tokens_in":  est_in,
        "est_tokens_out": est_out,
    }


def get_chat_state(surface_key: str, row_id) -> dict:
    """Everything the UI needs to render the chat affordance honestly.

    Includes what has already been spent on this anchor. The user is billed per
    question here, so the running total belongs next to the input box, not
    buried in a monthly settings figure.
    """
    anchor = _ANCHORS.get(surface_key)
    if not anchor:
        return {"ok": False, "code": "anchor_not_registered",
                "reason": f"no chat affordance registered for {surface_key!r}"}

    status = get_status()
    conn = _conn()
    try:
        used = _turn_count(conn, surface_key, row_id)
        # SUM the per-turn cost_usd rather than re-pricing aggregate tokens at
        # one model's rates: with tier selection a conversation can mix models,
        # and re-pricing Opus turns at Sonnet rates would UNDER-report real spend
        # on the one surface where the user is watching the number.
        row = conn.execute(
            "SELECT COALESCE(SUM(cost_usd),0) AS spent, "
            "SUM(CASE WHEN cost_usd IS NULL THEN 1 ELSE 0 END) AS unpriced, "
            "COUNT(*) AS n "
            "FROM ai_chat_turns WHERE surface_key=? AND row_id=?",
            (surface_key, str(row_id)),
        ).fetchone()
    finally:
        conn.close()

    cap    = _turn_cap()
    # None (not 0.0) when nothing has been asked yet -- "no spend recorded"
    # and "$0.0000 spent" are different facts.
    spent  = (float(row["spent"]) if row and int(row["n"] or 0) else None)
    scope  = _chat_scope(anchor["action_classes"])
    return {
        "ok":              True,
        "available":       status.get("state") == "active",
        "unavailable_why": "" if status.get("state") == "active" else status.get("detail", ""),
        "turns_used":      used,
        "turn_cap":        cap,
        "turns_left":      max(0, cap - used),
        "spent_usd":       spent,
        # True when some turn could not be priced — the UI must show the total as
        # incomplete rather than quietly under-reporting it.
        "spend_partial":   bool(row and row["unpriced"]),
        "scope":           scope,
        "billed_per_question": True,
        "label":           anchor["label"],
        "models":          chat_model_options(),
    }


def ask_followup(surface_key: str, row_id, question: str,
                 actor: str | None = None, tier: str | None = None) -> dict:
    """Ask one follow-up question about an anchored finding.

    Returns {"ok": True, "answer", "cost_usd", "tokens_in/out", "turns_left", "scope"}
    or {"ok": False, "code", "reason"} — `code` is machine-readable so the UI can
    distinguish "you are out of turns" from "the AI is rate limited" from "this
    finding's context could not be rebuilt", which need different messages.
    """
    anchor = _ANCHORS.get(surface_key)
    if not anchor:
        return {"ok": False, "code": "anchor_not_registered",
                "reason": f"no chat affordance registered for {surface_key!r}"}

    q = (question or "").strip()
    if not q:
        return {"ok": False, "code": "empty_question", "reason": "no question asked"}
    if len(q) > _MAX_QUESTION_CHARS:
        return {"ok": False, "code": "question_too_long",
                "reason": (f"question is {len(q)} characters; the limit is "
                           f"{_MAX_QUESTION_CHARS}. Trim it or paste less output.")}

    conn = _conn()
    try:
        used = _turn_count(conn, surface_key, row_id)
        cap  = _turn_cap()
        if used >= cap:
            return {"ok": False, "code": "turn_cap",
                    "reason": (f"this finding has used all {cap} follow-up questions. "
                               f"The cap exists because each question is a billed call.")}
        history = conn.execute(
            "SELECT question, answer FROM ai_chat_turns "
            "WHERE surface_key=? AND row_id=? AND answer IS NOT NULL "
            "ORDER BY id DESC LIMIT ?",
            (surface_key, str(row_id), _HISTORY_TURNS),
        ).fetchall()
    finally:
        conn.close()

    # Context is rebuilt SERVER-SIDE from the row. A loader that fails, or that
    # returns nothing, is a hard failure — not an empty context we answer over.
    try:
        context = anchor["loader"](row_id)
    except Exception as exc:
        log.exception("ai_engine: anchor loader failed for %s/%s", surface_key, row_id)
        return {"ok": False, "code": "context_unavailable",
                "reason": f"could not rebuild this finding's context: {exc}"}
    if not context:
        return {"ok": False, "code": "context_unavailable",
                "reason": ("this finding's context could not be rebuilt, so there is "
                           "nothing reliable to answer from")}

    scope  = _chat_scope(anchor["action_classes"])
    system = _chat_system_prompt(scope)

    parts = [f"FINDING ({anchor['label']}):", str(context).strip()]
    if history:
        parts.append("\nEARLIER IN THIS CONVERSATION:")
        for h in reversed(history):
            parts.append(f"Q: {h['question']}\nA: {h['answer']}")
    parts.append(f"\nQUESTION: {q}")
    prompt = "\n".join(parts)

    # cache_hours=0: a follow-up is novel by definition, so a cache lookup could
    # only ever return another question's answer. force is deliberately NOT set.
    # Unrecognised tiers resolve DOWN -- a malformed request cannot spend more.
    tier_name, tier_model = resolve_chat_tier(tier)
    res = analyze(
        prompt,
        system_prompt=system,
        max_tokens=_CHAT_MAX_TOKENS,
        cache_hours=0,
        job_id=f"chat:{surface_key}:{row_id}:{used + 1}:{tier_name}",
        model=tier_model,
        effort=_CHAT_EFFORT,
    )
    if not res.get("ok"):
        return {"ok": False, "code": "call_failed",
                "reason": res.get("reason", "the AI call did not complete")}

    t_in  = int(res.get("tokens_in")  or 0)
    t_out = int(res.get("tokens_out") or 0)
    cost  = _cost_of(t_in, t_out, tier_model)

    try:
        conn = _conn()
        try:
            conn.execute(
                "INSERT INTO ai_chat_turns (surface_key, row_id, question, answer, "
                "asked_by, asked_at, tokens_in, tokens_out, cost_usd, model_used) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (surface_key, str(row_id), q, res.get("text"), actor,
                 datetime.now().isoformat(timespec="seconds"),
                 t_in, t_out, cost, tier_model),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        # The call already billed. Losing the record would silently under-report
        # spend and hand back a turn the user actually used, so say so.
        log.exception("ai_engine: failed to record chat turn for %s/%s",
                      surface_key, row_id)
        return {"ok": True, "answer": res.get("text"), "cost_usd": cost,
                "tokens_in": t_in, "tokens_out": t_out,
                "turns_left": max(0, cap - used - 1), "scope": scope,
                "tier": tier_name, "model": tier_model, "record_failed": True}

    return {"ok": True, "answer": res.get("text"), "cost_usd": cost,
            "tokens_in": t_in, "tokens_out": t_out,
            "turns_left": max(0, cap - used - 1), "scope": scope,
            "tier": tier_name, "model": tier_model, "record_failed": False}


# ─────────────────────────────────────────────────────────────────────────────
# Anthropic incident / cost-protection layer
# ─────────────────────────────────────────────────────────────────────────────

_POLL_INTERVAL = 240   # seconds between status.claude.com polls
_OWN_FAIL_THR  = 3     # consecutive own-call service errors to flag incident
_SERVICE_CODES = {500, 502, 503, 529}

_incident_lock  = threading.Lock()
_incident: dict = {
    "active":           False,
    "severity":         "",        # "minor" | "major" | "critical"
    "name":             "",
    "update":           "",
    "source":           "",        # "poll" | "own_calls"
    "since":            0.0,
    "failure_count":    0,
    "last_poll":        0.0,
    "poll_indicator":   "none",
    "poll_description": "",
    "poll_error":       "",
}

_in_flight_lock = threading.Lock()
_in_flight: set = set()

_poll_stop: threading.Event = threading.Event()


def _poll_anthropic_status() -> None:
    """Fetch Anthropic status page and update _incident. Never raises."""
    try:
        req = urllib.request.Request(
            "https://status.claude.com/api/v2/summary.json",
            headers={"User-Agent": "Nemesis-Firewall/1.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        indicator   = data.get("status", {}).get("indicator", "none")
        description = data.get("status", {}).get("description", "")
        incidents   = data.get("incidents", [])
        inc_name    = incidents[0].get("name", "")  if incidents else ""
        inc_update  = ""
        if incidents:
            upds       = incidents[0].get("incident_updates", [])
            inc_update = upds[0].get("body", "") if upds else ""

        now = time.time()
        with _incident_lock:
            _incident["last_poll"]        = now
            _incident["poll_indicator"]   = indicator
            _incident["poll_description"] = description
            _incident["poll_error"]       = ""
            if indicator != "none":
                _incident["active"]    = True
                _incident["severity"]  = indicator
                _incident["name"]      = inc_name or "Service Disruption"
                _incident["update"]    = inc_update
                _incident["source"]    = "poll"
                if not _incident["since"]:
                    _incident["since"] = now
            else:
                # Status page clear — clear unless held by the simulate hook (testing)
                if _incident.get("source") != "simulate":
                    _incident["active"]        = False
                    _incident["severity"]      = ""
                    _incident["name"]          = ""
                    _incident["update"]        = ""
                    _incident["source"]        = ""
                    _incident["since"]         = 0.0
                    _incident["failure_count"] = 0

        log.info("ai_engine: status poll: indicator=%s (%s)", indicator, description)
    except Exception as exc:
        with _incident_lock:
            _incident["last_poll"]  = time.time()
            _incident["poll_error"] = str(exc)
        log.warning("ai_engine: status poll failed: %s", exc)


def _poll_loop(stop_evt: threading.Event) -> None:
    """Background polling thread: wakes every _POLL_INTERVAL seconds."""
    while not stop_evt.wait(timeout=_POLL_INTERVAL):
        try:
            _poll_anthropic_status()
        except Exception:
            log.exception("ai_engine: status poll loop error")
        try:
            # Reuses this thread rather than starting a second one: the drift
            # check is daily and self-rate-limits on _DRIFT_LAST_RUN_KEY, so
            # calling it on every 240s tick costs one settings read.
            run_pricing_drift_check()
        except Exception:
            log.exception("ai_engine: pricing drift check error")


def _record_call_failure(code: int) -> None:
    """Called when analyze() gets a service error response. Flags incident after threshold."""
    with _incident_lock:
        _incident["failure_count"] += 1
        if _incident["failure_count"] >= _OWN_FAIL_THR and not _incident["active"]:
            _incident["active"]   = True
            _incident["severity"] = "major"
            _incident["name"]     = f"Repeated API errors (HTTP {code})"
            _incident["update"]   = (
                f"Own calls failed {_incident['failure_count']} times with HTTP {code}. "
                "Status page may lag — check status.claude.com."
            )
            _incident["source"]   = "own_calls"
            _incident["since"]    = time.time()
            log.warning(
                "ai_engine: incident flagged — %d consecutive HTTP %d errors",
                _incident["failure_count"], code,
            )


def _record_call_success() -> None:
    """Called when analyze() succeeds. Clears own-calls incidents."""
    with _incident_lock:
        _incident["failure_count"] = 0
        if _incident["active"] and _incident["source"] == "own_calls":
            _incident["active"]   = False
            _incident["severity"] = ""
            _incident["name"]     = ""
            _incident["update"]   = ""
            _incident["source"]   = ""
            _incident["since"]    = 0.0
            log.info("ai_engine: own-calls incident cleared — calls succeeding again")


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get_setting(key: str, default: str = "") -> str:
    try:
        conn = _conn()
        row = conn.execute("SELECT value FROM ai_settings WHERE key=?", (key,)).fetchone()
        conn.close()
        return row[0] if row else default
    except Exception:
        return default


def _set_setting(key: str, value: str) -> None:
    try:
        conn = _conn()
        conn.execute("INSERT OR REPLACE INTO ai_settings(key, value) VALUES(?,?)", (key, value))
        conn.commit()
    except Exception:
        log.exception("ai_engine: _set_setting failed for %s", key)
        raise
    finally:
        conn.close()


def get_settings() -> dict:
    """Public read-only view of the AI settings the dashboard header needs.

    Reads from the shared DB through the module's own accessor so core code
    (dashboard.py) no longer reaches into the module's DB file directly
    (ADR 0001 Stage 3). Rate values are returned as their stored strings, matching
    the dashboard's prior inline read.
    """
    return {
        "rate_per_hour":       _get_setting("rate_per_hour", str(_RATE_HOUR_DEFAULT)),
        "rate_per_day":        _get_setting("rate_per_day",  str(_RATE_DAY_DEFAULT)),
        "ai_upsell_dismissed": _get_setting("ai_upsell_dismissed", "0") == "1",
    }


def _get_rate_state(conn, key: str, default: str = "0") -> str:
    row = conn.execute("SELECT value FROM ai_rate_state WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def _set_rate_state(conn, key: str, value) -> None:
    conn.execute("INSERT OR REPLACE INTO ai_rate_state(key, value) VALUES(?,?)", (key, str(value)))


def _api_key() -> str:
    return os.environ.get("ANTHROPIC_API_KEY", "")


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiting (sliding window)
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Pricing change-detection (detect and notify — never auto-write)
# ─────────────────────────────────────────────────────────────────────────────

#: Where Anthropic publishes prices. Served as MARKDOWN, so this is table-row
#: extraction rather than DOM scraping — materially more stable than a typical
#: scrape, though still not a contract.
_PRICING_DOC_URL = "https://platform.claude.com/docs/en/pricing.md"

#: Maps the human model names in the doc to our rate-table keys. A name that is
#: not in here is an UNRECOGNISED model, which fails the gate — see
#: _validate_parsed_rates.
_DOC_NAME_TO_ID = {
    "claude opus 5":     "claude-opus-5",
    "claude opus 4.8":   "claude-opus-4-8",
    "claude sonnet 5":   "claude-sonnet-5",
    "claude sonnet 4.6": "claude-sonnet-4-6",
    "claude haiku 4.5":  "claude-haiku-4-5",
    "claude fable 5":    "claude-fable-5",
}

#: Order-of-magnitude sanity bounds, per MTok. Deliberately wide: the job is to
#: catch a units change or a mis-parsed cell, not to second-guess Anthropic's
#: pricing decisions.
_RATE_PLAUSIBLE_MIN = 0.01
_RATE_PLAUSIBLE_MAX = 500.0


def _pricing_check_enabled() -> bool:
    """Whether to fetch the pricing doc at all. OFF unless explicitly enabled.

    This is an outbound request from a firewall appliance to a third Anthropic
    host (alongside api.anthropic.com and status.claude.com). That is a
    deliberate decision for an operator to make, not a default to inherit.
    """
    return (_get_setting("pricing_check_enabled", "0") or "0").strip() == "1"


def _parse_pricing_doc(text: str) -> dict:
    """Extract ``{model_id: {"input": float, "output": float}}`` from the doc.

    Pure — no network, no DB — so the parser and the gate below can be tested
    against adversarial input without touching anything.

    Returns only rows whose model name is recognised. An empty result is a
    PARSE FAILURE for the caller to treat as a failed fetch, never as "no
    models are priced".
    """
    out: dict = {}
    if not isinstance(text, str):
        return out
    for line in text.splitlines():
        if line.count("|") < 3:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3:
            continue
        name = cells[0].lower().strip()
        model_id = _DOC_NAME_TO_ID.get(name)
        if not model_id:
            continue
        nums = []
        for cell in cells[1:3]:
            m = re.search(r"\$?\s*([0-9]+(?:\.[0-9]+)?)", cell)
            nums.append(float(m.group(1)) if m else None)
        if nums[0] is None or nums[1] is None:
            continue
        out[model_id] = {"input": nums[0], "output": nums[1]}
    return out


def _validate_parsed_rates(parsed: dict) -> tuple:
    """THE GATE. Returns ``(ok, reason)``; a False makes the whole fetch fail.

    A format change that parses to NOTHING is easy to notice. A format change
    that parses to the WRONG NUMBERS is not — it produces a confident,
    plausible, wrong price with no error anywhere. These checks are what stand
    between that and the product. Every one of them must hold:

      * both rates strictly POSITIVE — this is what makes a $0.00 rate
        structurally impossible to accept, rather than merely unlikely;
      * output > input — true of every Claude model, and the cheapest possible
        tripwire for a swapped column;
      * both within an order-of-magnitude band — catches a units change;
      * the model is RECOGNISED — an unknown name means the table reshaped, so
        no row from it is trustworthy, including the ones that did parse.

    Rejection is not partial. If any row fails, the fetch failed.
    """
    if not parsed:
        return False, "no recognised model rows parsed"
    for model_id, r in parsed.items():
        if model_id not in _MODEL_RATES:
            return False, f"unrecognised model {model_id!r} — table shape changed"
        i, o = r.get("input"), r.get("output")
        if not isinstance(i, (int, float)) or not isinstance(o, (int, float)):
            return False, f"{model_id}: non-numeric rate"
        if i <= 0 or o <= 0:
            return False, f"{model_id}: non-positive rate ({i}/{o})"
        if o <= i:
            return False, f"{model_id}: output {o} <= input {i} — columns look swapped"
        for label, v in (("input", i), ("output", o)):
            if not (_RATE_PLAUSIBLE_MIN <= v <= _RATE_PLAUSIBLE_MAX):
                return False, f"{model_id}: {label} {v} outside plausible band"
    return True, ""


def _fetch_pricing_doc() -> str:
    """Fetch the published pricing doc. Same shape as _poll_anthropic_status."""
    req = urllib.request.Request(
        _PRICING_DOC_URL, headers={"User-Agent": "Nemesis-Firewall/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8", "replace")


#: How often the drift check runs when enabled. Daily, not hourly: published
#: prices change rarely, and the check exists to notice a change within a
#: reasonable window, not to catch it the same minute.
_PRICING_CHECK_INTERVAL_S = 24 * 3600

#: ai_settings keys holding drift state. Kept in ai_settings rather than a new
#: table because there is exactly one row's worth of state, and ADR 0001 keeps
#: this module writing only ai_* names either way.
_DRIFT_STATE_KEY = "pricing_drift_state"       # JSON: last check result
_DRIFT_NOTIFIED_KEY = "pricing_drift_notified" # signature already emailed
_DRIFT_LAST_RUN_KEY = "pricing_drift_last_run" # epoch of last completed check


def _esc(v) -> str:
    """Minimal HTML escape for banner text. Module-level on purpose: the older
    `_e` helper is nested inside get_incident_banner_html and is not visible
    here — a mistake py_compile cannot catch, since it would only surface as a
    NameError on the rare path where drift actually exists."""
    return (str(v).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _drift_signature(divergences) -> str:
    """Stable identity for a set of divergences, so the same drift is not
    re-notified on every daily run. Changes when the published numbers change."""
    parts = [f"{d['model']}:{d['published']['input']}/{d['published']['output']}"
             for d in sorted(divergences, key=lambda d: d["model"])]
    return "|".join(parts)


def get_pricing_drift_state() -> dict:
    """Last recorded drift result, or an empty state. Never raises."""
    try:
        raw = _get_setting(_DRIFT_STATE_KEY, "")
        return json.loads(raw) if raw else {}
    except Exception:
        return {}


def get_pricing_drift_banner_html() -> str:
    """Dashboard banner when published pricing differs from ours, else ''.

    Mirrors get_incident_banner_html: this module already surfaces
    "something changed on Anthropic's side" as a banner, and drift is the same
    shape of news. A log line is not a notification — nobody reads the journal
    to discover a price change.

    States what changed and that NOTHING has been altered automatically, because
    the whole design of check_pricing_drift is detect-and-notify; a banner that
    implied the rates had been updated would misrepresent it.
    """
    st = get_pricing_drift_state()
    divs = st.get("divergences") or []
    if not divs:
        return ""
    rows = "".join(
        f"<li><b>{_esc(d['model'])}</b>: published "
        f"${d['published']['input']}/${d['published']['output']} per MTok, "
        f"this server is using ${d['ours']['input']}/${d['ours']['output']}</li>"
        for d in divs)
    return (
        '<div style="background:#3a2d00;border:1px solid #ffaa00;color:#ffd479;'
        'padding:10px 14px;border-radius:6px;margin:8px 0;font-size:0.86em">'
        '<b>&#9888; Anthropic&#39;s published pricing differs from this '
        'server&#39;s rates.</b>'
        f'<ul style="margin:6px 0 6px 18px;padding:0">{rows}</ul>'
        '<span style="color:#bba">Nothing has been changed automatically. '
        'Update the rate table (and its confirmed date) if these are correct. '
        f'Checked {_esc(st.get("checked_at", "?"))}.</span></div>')


def _notify_pricing_drift(result) -> None:
    """Email on NEWLY-detected drift. Never raises into the caller.

    Deduplicated on the divergence signature: the check runs daily and drift
    persists until someone acts on it, so notifying every run would train the
    operator to ignore it. A CHANGED set of numbers is new news and notifies
    again.
    """
    divs = result.get("divergences") or []
    if not divs:
        return
    sig = _drift_signature(divs)
    if _get_setting(_DRIFT_NOTIFIED_KEY, "") == sig:
        return
    try:
        import sys as _sys
        _sys.path.insert(0, "/opt/nemesis/alert_manager")
        from email_utils import send_email
        body = ["Anthropic's published pricing differs from the rates this "
                "Nemesis server uses for cost estimates.", ""]
        for d in divs:
            body.append(
                f"  {d['model']}: published "
                f"${d['published']['input']}/${d['published']['output']} per MTok; "
                f"this server uses ${d['ours']['input']}/${d['ours']['output']}")
        body += ["",
                 "NOTHING HAS BEEN CHANGED AUTOMATICALLY. Pricing is a maintained",
                 "constant here by design -- a scraped value that parsed wrongly",
                 "would silently become what the product charges against.",
                 "",
                 "If these figures are correct, update _MODEL_RATES and bump",
                 "_PRICING_DEFAULTS_CONFIRMED in the same change.",
                 f"", f"Checked at {result.get('checked_at', '?')}."]
        send_email("[Nemesis] Anthropic pricing has changed", "\n".join(body))
        _set_setting(_DRIFT_NOTIFIED_KEY, sig)
        log.info("ai_engine: pricing drift notification sent (%d model(s))", len(divs))
    except Exception:
        # A failed send must not lose the finding -- the banner still shows it.
        log.exception("ai_engine: pricing drift notification failed")


def run_pricing_drift_check(force=False, fetch=None) -> dict:
    """Scheduled entry point: check, persist, and notify. Never raises.

    Returns the check result, plus `skipped` when it did not run. Gated on the
    operator having enabled checking -- an outbound request from a firewall
    appliance is a deliberate decision, not a default (see
    _pricing_check_enabled).
    """
    if not force and not _pricing_check_enabled():
        return {"ok": False, "skipped": "disabled"}
    if not force:
        try:
            last = float(_get_setting(_DRIFT_LAST_RUN_KEY, "0") or 0)
        except (TypeError, ValueError):
            last = 0.0
        if time.time() - last < _PRICING_CHECK_INTERVAL_S:
            return {"ok": False, "skipped": "interval"}
    result = check_pricing_drift(fetch=fetch)
    try:
        _set_setting(_DRIFT_LAST_RUN_KEY, str(time.time()))
        if result.get("ok"):
            # Persist ONLY a successful check. A failed fetch must not erase a
            # standing drift finding -- that would look like the drift resolved.
            _set_setting(_DRIFT_STATE_KEY, json.dumps({
                "divergences": result.get("divergences") or [],
                "checked_at": result.get("checked_at"),
            }))
            _notify_pricing_drift(result)
    except Exception:
        log.exception("ai_engine: persisting drift state failed")
    return result


def check_pricing_drift(fetch=None) -> dict:
    """Compare published rates against ours and REPORT. Writes no rate, ever.

    Returns ``{ok, divergences, checked_at, reason}``. `divergences` lists
    models whose published rate differs from `_MODEL_RATES`; it is the operator
    who decides whether to accept them, by updating the table (and its
    confirmed date) or the env overrides.

    THE POINT OF NOT AUTO-WRITING: a parse that silently produces wrong numbers
    is undetectable from inside. If it could write, that wrong number becomes
    what the product charges against and every downstream display inherits it.
    Because it can only notify, the worst a bad parse can do is fail to tell
    anyone — which the `ok: False` result makes visible in its own right.

    `fetch` is injectable so the parse and gate can be exercised without
    network access.
    """
    now = datetime.now().isoformat(timespec="seconds")
    fetcher = fetch or _fetch_pricing_doc
    try:
        text = fetcher()
    except Exception as exc:
        log.warning("ai_engine: pricing doc fetch failed: %s", exc)
        return {"ok": False, "reason": f"fetch failed: {str(exc)[:160]}",
                "divergences": [], "checked_at": now}

    parsed = _parse_pricing_doc(text)
    ok, why = _validate_parsed_rates(parsed)
    if not ok:
        # A rejected parse is a FAILED FETCH, not data. Never partially applied.
        log.warning("ai_engine: pricing doc rejected by validation: %s", why)
        return {"ok": False, "reason": why, "divergences": [], "checked_at": now}

    divergences = []
    for model_id, pub in sorted(parsed.items()):
        ours = _MODEL_RATES.get(model_id) or {}
        if pub["input"] != ours.get("input") or pub["output"] != ours.get("output"):
            divergences.append({
                "model": model_id,
                "ours": {"input": ours.get("input"), "output": ours.get("output")},
                "published": {"input": pub["input"], "output": pub["output"]},
            })
    if divergences:
        log.warning("ai_engine: published pricing differs from the maintained "
                    "table for %d model(s): %s — operator confirmation required, "
                    "nothing has been changed",
                    len(divergences), ", ".join(d["model"] for d in divergences))
    return {"ok": True, "reason": "", "divergences": divergences,
            "checked_at": now, "models_checked": len(parsed)}


def get_spend_this_month() -> dict:
    """Actual spend for the current calendar month, in dollars.

    Computed from the RECORDED tokens (`ai_usage.tokens_in`/`tokens_out`, stamped
    from `msg.usage` on every real call) priced at the active model's rates —
    not from a per-call assumption. The old 350-in/150-out guess understated
    real spend by ~13x, so a cap enforced against it would have been a cap
    against a fiction.

    Cache hits cost nothing and correctly contribute nothing: `analyze()` skips
    `_increment_usage` on a cache hit, so those tokens were never recorded.

    Returns `{"ok": True, "usd": float, "month": "YYYY-MM"}`, or
    `{"ok": False, "error": ...}` with NO figure. A caller must not read a
    missing spend as zero — see `_check_rate_limit`, which fails closed on it.
    """
    pricing = get_pricing()
    month = datetime.now().strftime("%Y-%m")
    try:
        conn = _conn()
        row = conn.execute(
            "SELECT COALESCE(SUM(tokens_in),0), COALESCE(SUM(tokens_out),0) "
            "FROM ai_usage WHERE substr(date,1,7)=?", (month,)).fetchone()
        conn.close()
        usd = (int(row[0]) * pricing["input_per_mtok"] / 1_000_000
               + int(row[1]) * pricing["output_per_mtok"] / 1_000_000)
        return {"ok": True, "usd": round(usd, 6), "month": month,
                "tokens": {"in": int(row[0]), "out": int(row[1])}}
    except Exception as exc:
        log.exception("ai_engine: get_spend_this_month failed")
        return {"ok": False, "error": str(exc)[:200], "month": month}


def _spend_cap_usd() -> float | None:
    """Configured monthly cap in dollars, or None when unset/unusable.

    Unset and unparseable both mean "no cap": a garbage value must not be read
    as a cap of 0, which would block every call and look like a bug in the
    engine rather than a typo in a setting.
    """
    raw = (_get_setting("spend_cap_monthly_usd", "") or "").strip()
    if not raw:
        return None
    try:
        val = float(raw)
    except (ValueError, TypeError):
        log.warning("ai_engine: spend_cap_monthly_usd=%r is not a number — "
                    "treating as no cap", raw)
        return None
    return val if val > 0 else None


def _check_rate_limit(conn) -> tuple:
    """Return (is_limited: bool, reason: str)."""
    rate_h = int(_get_setting("rate_per_hour", str(_RATE_HOUR_DEFAULT)))
    rate_d = int(_get_setting("rate_per_day",  str(_RATE_DAY_DEFAULT)))
    now = time.time()

    h_start = float(_get_rate_state(conn, "hour_window_start", "0"))
    h_count = int(_get_rate_state(conn, "hour_count", "0"))
    if now - h_start > 3600 or h_start == 0:
        h_count = 0

    if h_count >= rate_h:
        if h_start == 0 or now - h_start > 3600:
            reset_str = "immediately on reset"
        else:
            mins_left = max(1, int((3600 - (now - h_start)) / 60) + 1)
            reset_str = f"resets in ~{mins_left}m"
        return True, f"{h_count}/{rate_h} per hour ({reset_str})"

    d_start = float(_get_rate_state(conn, "day_window_start", "0"))
    d_count = int(_get_rate_state(conn, "day_count", "0"))
    if now - d_start > 86400 or d_start == 0:
        d_count = 0

    if d_count >= rate_d:
        if d_start == 0 or now - d_start > 86400:
            reset_str = "immediately on reset"
        else:
            hrs_left = max(1, int((86400 - (now - d_start)) / 3600) + 1)
            reset_str = f"resets in ~{hrs_left}h"
        return True, f"{d_count}/{rate_d} per day ({reset_str})"

    # Dollar cap. Checked last so the cheaper call-count checks short-circuit
    # first, and so its reason is the one surfaced when it is the binding limit.
    #
    # Call count is a poor proxy for spend and is getting worse: per-model rates
    # differ ~10x, and any surface where the user controls prompt size makes ten
    # calls anywhere from cents to dollars. This is the control a user actually
    # means by "don't spend more than $X".
    cap = _spend_cap_usd()
    if cap is not None:
        spend = get_spend_this_month()
        if not spend.get("ok"):
            # FAIL CLOSED, but only because a cap was explicitly requested.
            # The point of a cap is protecting money: if we cannot tell whether
            # the user is over it, allowing unlimited spend defeats it entirely.
            # Blocking is recoverable — the reason is visible and the cap can be
            # raised or cleared; an unnoticed overspend is not. When NO cap is
            # set, this branch never runs, so a broken read cannot block a user
            # who never asked for the protection.
            return True, ("monthly spend cannot be read, and a spend cap is set "
                          "— refusing rather than risk exceeding it")
        usd = spend.get("usd") or 0.0
        if usd >= cap:
            return True, (f"monthly spend cap reached: ${usd:.2f} of ${cap:.2f} "
                          f"for {spend.get('month')}")

    return False, ""


def _increment_rate(conn) -> None:
    now = time.time()
    for win_key, cnt_key, span in (
        ("hour_window_start", "hour_count", 3600),
        ("day_window_start", "day_count", 86400),
    ):
        start = float(_get_rate_state(conn, win_key, "0"))
        if now - start > span:
            # Window expired (or first call): open a fresh window. This roll runs at most
            # once per window; a rare boundary collision can drop a single count, which the
            # read side tolerates (_check_rate_limit treats an expired window as count 0).
            _set_rate_state(conn, win_key, now)
            _set_rate_state(conn, cnt_key, "1")
        else:
            # DATA MANAGER v1 — atomic in-window increment, now routed through the Data
            # Manager guarded connection (access control + audit log). Kept inline rather
            # than folded into increment_counter(): this write shares analyze()'s conn with
            # _increment_usage() and the window-reset _set_rate_state() writes above, all
            # committed as ONE transaction. increment_counter() opens its own self-committing
            # connection, which would split that transaction and desync the hour/day counters
            # on rollback. The atomic ON CONFLICT statement itself is unchanged.
            # In-window increment in ONE statement (mirrors _increment_usage's
            # INSERT … ON CONFLICT DO UPDATE). Concurrent calls can no longer read the same
            # count and write back the same +1, so increments are never lost.
            conn.execute(
                "INSERT INTO ai_rate_state(key, value) VALUES(?, '1') "
                "ON CONFLICT(key) DO UPDATE SET "
                "value = CAST(CAST(ai_rate_state.value AS INTEGER) + 1 AS TEXT)",
                (cnt_key,),
            )


def _increment_usage(conn, tokens_in: int, tokens_out: int) -> None:
    now = datetime.now()
    conn.execute(
        """INSERT INTO ai_usage(date, hour, call_count, tokens_in, tokens_out)
           VALUES(?, ?, 1, ?, ?)
           ON CONFLICT(date, hour) DO UPDATE SET
               call_count = call_count + 1,
               tokens_in  = tokens_in  + excluded.tokens_in,
               tokens_out = tokens_out + excluded.tokens_out""",
        (now.strftime("%Y-%m-%d"), now.hour, tokens_in, tokens_out)
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def is_enabled() -> bool:
    """True when an API key is configured."""
    return bool(_api_key())


def get_status() -> dict:
    """Return state: 'active'|'disabled'|'no_key', plus enabled/has_key/key_valid fields."""
    import modules_loader  # lazy import to avoid circular reference at module load time
    enabled = modules_loader.is_enabled("ai_engine")
    key = _api_key()
    has_key = bool(key)
    if not enabled:
        return {"state": "disabled", "enabled": False, "has_key": has_key,
                "key_valid": False, "detail": "AI Engine module is disabled"}
    if not has_key:
        return {"state": "no_key", "enabled": True, "has_key": False,
                "key_valid": False, "detail": "ANTHROPIC_API_KEY not configured"}
    try:
        conn = _conn()
        limited, reason = _check_rate_limit(conn)
        conn.close()
        detail = f"Rate limited: {reason}" if limited else "Ready"
        return {"state": "active", "enabled": True, "has_key": True,
                "key_valid": True, "detail": detail}
    except Exception as exc:
        return {"state": "active", "enabled": True, "has_key": True,
                "key_valid": True, "detail": str(exc)}


# Date the SHIPPED default rates below were last confirmed against Anthropic's
# published pricing. Bump this in the same commit as any change to the defaults —
# a stale date is worse than none, because it vouches for figures nobody checked.
_PRICING_DEFAULTS_CONFIRMED = "2026-08-04"

#: The model analyze() actually calls. Single source of truth — _analyze_inner
#: reads this rather than repeating the string, so the rate table and the
#: request can never disagree about which model is in use.
# Bumped 2026-08-04 (operator decision) from the previous-generation
# claude-sonnet-4-6, the string CLAUDE.md had flagged as suspected-stale.
# BLAST RADIUS -- this is every AI call site, not just the chat: alert analysis,
# anomaly incidents (auto + manual), community-queue batch, and malware Layer C.
# Pricing display is unchanged (_MODEL_RATES lists both at $3/$15). Note that
# get_pricing()'s ANTHROPIC_*_PRICE_PER_MTOK overrides are scoped to whatever
# _ACTIVE_MODEL is, so an operator override now applies to Sonnet 5.
_ACTIVE_MODEL = "claude-sonnet-5"

#: Reference price point for the user's own comparison: what Anthropic's
#: cheapest consumer subscription costs per month. MAINTAINED CONSTANT WITH A
#: DATE, for the same reason the rate table has one — this price can change,
#: and a bare number with no provenance eventually becomes a confident lie.
#: Bump `confirmed` in the same commit as any change to `usd`.
#:
#: THIS IS A COMPARISON, NOT AN ALTERNATIVE. Nemesis authenticates with an
#: `sk-ant-api03-` API key — pay-per-token, billed separately. A consumer
#: subscription issues `sk-ant-oat01-` OAuth tokens intended for interactive
#: and CLI use, not for embedding in an always-on backend service. The two are
#: different products with different billing and different intended use, so the
#: UI states the numbers and lets the operator draw their own conclusion. It
#: must never imply the subscription is a drop-in substitute for this workload.
_SUBSCRIPTION_COMPARISON = {
    "usd": 20.00,
    "label": "Claude Pro",
    "confirmed": "2026-08-04",
}

#: Per-MTok rates by model. A MAINTAINED CONSTANT: there is no pricing API
#: (Models API returns capabilities, not prices — verified 2026-08-04), so this
#: table is only as good as the last person who checked it. `_PRICING_DEFAULTS_
#: CONFIRMED` above dates the whole table.
#:
#: WHY A TABLE AND NOT ONE PAIR. Input and output are priced ~5x apart, and
#: models differ ~10x from each other. Model selection (roadmap item 3) prices
#: whatever model the user picks; without this dimension every model would be
#: costed at the active model's rates — silently wrong, plausible-looking, and
#: invisible to every existing check.
#:
#: SONNET 5 IS DELIBERATELY LISTED AT ITS STANDARD RATE, not the $2/$10
#: introductory rate running to 2026-08-31. Estimates for it therefore run
#: HIGH until then. That is the safe direction — the alternative is a figure
#: that silently becomes an under-estimate the day the intro period ends, and
#: an over-estimate a user notices is better than an under-estimate they do not.
_MODEL_RATES = {
    "claude-opus-5":     {"input": 5.00,  "output": 25.00},
    "claude-opus-4-8":   {"input": 5.00,  "output": 25.00},
    "claude-sonnet-5":   {"input": 3.00,  "output": 15.00},
    "claude-sonnet-4-6": {"input": 3.00,  "output": 15.00},
    "claude-haiku-4-5":  {"input": 1.00,  "output": 5.00},
    "claude-fable-5":    {"input": 10.00, "output": 50.00},
}


def get_pricing(model: str | None = None) -> dict:
    """Per-MTok rates for `model`, plus the date they were last confirmed.

    `model` defaults to the engine's active model, so every existing caller
    keeps its current behaviour unchanged.

    Returns `{model, input_per_mtok, output_per_mtok, updated, known}`.

    AN UNKNOWN MODEL RETURNS `known: False` AND `None` RATES — never another
    model's numbers. That is the whole point of this function taking a model at
    all: pricing model X at model Y's rates is plausible, confident and wrong,
    and nothing downstream could detect it. A caller that gets None must say
    "pricing unknown for this model", not substitute a neighbour or a zero.

    THERE IS NO PRICING API (verified 2026-08-04 — the Models API returns
    capabilities, not prices), so `updated` is the only trust signal these
    figures carry. See `_MODEL_RATES` for the table and its caveats.

    The environment overrides (ANTHROPIC_INPUT_PRICE_PER_MTOK /
    _OUTPUT_ / _PRICING_UPDATED) apply ONLY to the active model. They predate
    this table and were configured for the one model the engine calls; letting
    them silently reprice every other model would be a worse bug than the one
    this function exists to prevent. Their date rules are unchanged:

    1. The shipped date vouches for SHIPPED figures only — an operator-supplied
       rate reads as `updated: None` unless they supply a date too.
    2. A malformed date yields None rather than falling back to the shipped
       date, so a typo surfaces instead of being papered over.
    """
    target = model or _ACTIVE_MODEL
    rates = _MODEL_RATES.get(target)

    raw_in   = (os.environ.get("ANTHROPIC_INPUT_PRICE_PER_MTOK")  or "").strip()
    raw_out  = (os.environ.get("ANTHROPIC_OUTPUT_PRICE_PER_MTOK") or "").strip()
    raw_date = (os.environ.get("ANTHROPIC_PRICING_UPDATED")       or "").strip()
    # Overrides are scoped to the active model — see the docstring.
    is_active    = (target == _ACTIVE_MODEL)
    operator_set = is_active and bool(raw_in or raw_out)

    if rates is None and not operator_set:
        # Nothing known and nothing supplied: say so explicitly.
        return {"model": target, "input_per_mtok": None, "output_per_mtok": None,
                "updated": None, "known": False}

    base_in  = rates["input"]  if rates else None
    base_out = rates["output"] if rates else None

    inp, out = base_in, base_out
    if is_active:
        if raw_in:
            try:
                inp = float(raw_in)
            except (ValueError, TypeError):
                inp = base_in
        if raw_out:
            try:
                out = float(raw_out)
            except (ValueError, TypeError):
                out = base_out

    if is_active and raw_date:
        updated = raw_date if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw_date) else None
    elif operator_set:
        updated = None          # their rates, our date would be a lie
    else:
        updated = _PRICING_DEFAULTS_CONFIRMED

    return {"model": target, "input_per_mtok": inp, "output_per_mtok": out,
            "updated": updated, "known": inp is not None and out is not None}


def get_monthly_cost(today: str | None = None) -> dict:
    """Average monthly token spend for THIS install.

    PER-INSTALL BY CONSTRUCTION, not by attribution. `ai_usage` lives in this
    appliance's own database and records only calls this appliance made, so the
    figure is already scoped to one install with nothing to divide. An anomaly
    incident covering twelve devices is one install's spend either way — there
    is deliberately no per-device split here, because at this scope the question
    does not arise.

    A future multi-appliance / MSP rollup (one client, several servers) would be
    a SEPARATE aggregation layer over several installs' figures — it does not
    change this function, which stays the per-install primitive that layer would
    sum. Do not add a tenant dimension here to anticipate it.

    FAILS CLOSED ON THIN HISTORY. Only calendar months the install observed in
    full are averaged:

      * the month must have STARTED on or after the first recorded usage —
        an install that came up on the 7th never saw the 1st through 6th, so
        that month is a partial sample dressed as a full one; and
      * the month must have fully ELAPSED — the current month is still
        accumulating and would drag the average down every time it is read.

    With no qualifying month this returns `sufficient: False` and `None` for
    both averages — never 0, and never a figure extrapolated from a part-month.
    A dollar amount is a legitimate-looking answer, so it is only ever returned
    when it is a measurement. `days_observed` is reported alongside so the UI
    can say how much longer it needs rather than just refusing.

    `today` is injectable so the month-boundary logic is testable without
    waiting for the calendar.
    """
    pricing = get_pricing()
    try:
        ref = (datetime.strptime(today, "%Y-%m-%d").date() if today
               else datetime.now().date())
        conn = _conn()
        row = conn.execute("SELECT MIN(date), MAX(date) FROM ai_usage").fetchone()
        earliest_s = row[0] if row else None
        if not earliest_s:
            conn.close()
            return {"ok": True, "sufficient": False, "reason": "no usage recorded",
                    "days_observed": 0, "months_counted": 0,
                    "average_tokens": None, "average_cost": None, "pricing": pricing}
        earliest = datetime.strptime(earliest_s, "%Y-%m-%d").date()

        # Enumerate fully-observed, fully-elapsed calendar months.
        months = []
        y, m = earliest.year, earliest.month
        if earliest.day != 1:          # partial first month — skip to the next
            y, m = (y + 1, 1) if m == 12 else (y, m + 1)
        while (y, m) < (ref.year, ref.month):   # strictly before the current month
            months.append(f"{y:04d}-{m:02d}")
            y, m = (y + 1, 1) if m == 12 else (y, m + 1)

        if not months:
            conn.close()
            return {"ok": True, "sufficient": False,
                    "reason": "no complete calendar month observed yet",
                    "days_observed": (ref - earliest).days, "months_counted": 0,
                    "average_tokens": None, "average_cost": None, "pricing": pricing}

        marks = ",".join("?" * len(months))
        agg = conn.execute(
            f"SELECT COALESCE(SUM(tokens_in),0), COALESCE(SUM(tokens_out),0), "
            f"COALESCE(SUM(call_count),0) FROM ai_usage "
            f"WHERE substr(date,1,7) IN ({marks})", months).fetchone()
        conn.close()

        n = len(months)
        avg_in, avg_out = agg[0] / n, agg[1] / n
        avg_cost = round(avg_in * pricing["input_per_mtok"] / 1_000_000
                         + avg_out * pricing["output_per_mtok"] / 1_000_000, 6)
        # Comparison against the consumer-subscription price point. Attached
        # ONLY on this branch — the insufficient-history path returns no
        # average, and comparing against a figure we deliberately refused to
        # compute would be worse than not comparing at all.
        sub = _SUBSCRIPTION_COMPARISON
        comparison = {
            "threshold_usd": sub["usd"],
            "label": sub["label"],
            "confirmed": sub["confirmed"],
            "exceeds": avg_cost > sub["usd"],
            "caveat": (f"{sub['label']} is a different product with different "
                       f"billing and intended use — not a substitute for API "
                       f"access, which is what this server uses."),
        }
        return {
            "ok": True, "sufficient": True,
            "days_observed": (ref - earliest).days,
            "months_counted": n,
            "months": months,
            "average_tokens": {"in": round(avg_in, 1), "out": round(avg_out, 1)},
            "average_calls": round(agg[2] / n, 1),
            "average_cost": avg_cost,
            "comparison": comparison,
            "pricing": pricing,
        }
    except Exception as exc:
        log.exception("ai_engine: get_monthly_cost failed")
        # Same posture as get_usage_stats: no fabricated numbers on a failed read.
        return {"ok": False, "error": str(exc)[:200], "pricing": pricing}


def _price_age_label(pricing: dict) -> str:
    """`(rates as of YYYY-MM-DD)`, or an explicit unknown. Never blank.

    A cost figure with no provenance reads as authoritative, so every surface
    that prints one prints this next to it.
    """
    upd = (pricing or {}).get("updated")
    return f"(rates as of {upd})" if upd else "(pricing date unknown)"


def get_upsell_prompt_html(tokens_in: int = 350, tokens_out: int = 150) -> str:
    """Returns a compact 3-tier AI-suggest prompt, or '' if AI is active or dismissed.
    Call at render time — reads live state from DB each call."""
    if _get_setting("ai_upsell_dismissed", "0") == "1":
        return ""
    status = get_status()
    if status["state"] == "active":
        return ""
    pricing = get_pricing()
    cost = (tokens_in * pricing["input_per_mtok"] / 1_000_000 +
            tokens_out * pricing["output_per_mtok"] / 1_000_000)
    if cost < 0.001:
        cost_str = "<$0.001"
    elif cost < 0.10:
        cost_str = f"~${cost:.3f}"
    else:
        cost_str = f"~${cost:.2f}"
    return (
        '<div class="ai-upsell-prompt" '
        'style="display:flex;align-items:center;gap:8px;'
        'background:rgba(0,212,255,0.04);border:1px solid #00d4ff22;border-radius:6px;'
        'padding:6px 10px;margin:6px 0;font-size:0.81em;line-height:1.4">'
        '<span style="color:#00d4ff;flex-shrink:0">&#128161;</span>'
        '<span class="tier-text" style="color:#888;flex:1" '
        f'data-beginner="This was checked by the built-in engines &#8212; that part&#39;s working. '
        f'AI could explain this result in plain English and help you prioritize it. '
        f'Turn it on in Settings (about {cost_str} for this)." '
        f'data-intermediate="Local analysis complete. AI verdict adds context + '
        f'prioritization for this item &#8212; est. {cost_str}. Enable in Settings." '
        f'data-pro="AI second-opinion available ({cost_str}). Enable in Settings.">'
        f'Local analysis complete. AI verdict adds context &#8212; est. {cost_str}. '
        f'Enable in Settings.</span>'
        # The estimate is priced off a maintained constant, not a live feed, so it
        # carries the date those rates were last confirmed — same rule as every
        # other cost surface. `updated` is None when nobody has vouched for the
        # rates, and that is stated rather than hidden.
        f'<span style="color:#556;font-size:0.85em;white-space:nowrap;flex-shrink:0" '
        f'title="Estimate uses maintained per-MTok rates, not a live price feed">'
        f'{_price_age_label(pricing)}</span>'
        '<button onclick="_aiUpsellDismissOnce(this)" title="Dismiss" '
        'style="background:none;border:none;color:#444;cursor:pointer;padding:0 3px;'
        'line-height:1;font-size:1.1em;flex-shrink:0">&#215;</button>'
        '<a href="#" onclick="_aiUpsellDismissPermanent(event)" '
        'style="color:#555;font-size:0.85em;white-space:nowrap;flex-shrink:0;'
        'text-decoration:underline">don&#39;t&nbsp;remind&nbsp;me</a>'
        '</div>'
    )


def get_upsell_js() -> str:
    """Guarded <script> block defining _aiUpsellDismissOnce + _aiUpsellDismissPermanent.
    Include once per page (guard prevents double-definition across multiple cards)."""
    return (
        '<script>'
        '(function(){'
        'if(window._aiUpsellJsLoaded)return;'
        'window._aiUpsellJsLoaded=true;'
        'window._aiUpsellDismissOnce=function(btn){'
        'var p=btn.closest(".ai-upsell-prompt");'
        'if(p)p.style.display="none";'
        '};'
        'window._aiUpsellDismissPermanent=function(e){'
        'e.preventDefault();'
        'var els=document.querySelectorAll(".ai-upsell-prompt");'
        'els.forEach(function(el){el.style.display="none";});'
        'fetch("/api/ai/upsell_dismiss",{method:"POST"})'
        '.then(function(r){return r.json();})'
        '.then(function(d){if(!d.ok)els.forEach(function(el){el.style.display="";});});'
        '};'
        '})();'
        '</script>'
    )


# ─────────────────────────────────────────────────────────────────────────────
# Incident public API
# ─────────────────────────────────────────────────────────────────────────────

def get_incident_state() -> dict:
    """Return a shallow copy of the current Anthropic incident state."""
    with _incident_lock:
        return dict(_incident)


def is_auto_blocked() -> bool:
    """True when an Anthropic incident is active — auto AI calls should defer."""
    with _incident_lock:
        return _incident["active"]


def get_incident_banner_html() -> str:
    """Dismissible incident banner HTML, or '' when no incident is active."""
    state = get_incident_state()
    if not state["active"]:
        return ""
    sev  = state["severity"]
    name = state["name"]
    upd  = state["update"]

    if sev in ("major", "critical"):
        border = "#ff4444"
        bg     = "rgba(255,68,68,0.08)"
        icon   = "&#128308;"
    else:
        border = "#ffaa00"
        bg     = "rgba(255,170,0,0.08)"
        icon   = "&#9888;"

    def _e(s: str) -> str:
        return (s.replace("&", "&amp;").replace("<", "&lt;")
                 .replace(">", "&gt;").replace('"', "&quot;"))

    name_e = _e(name)
    upd_e  = _e(upd[:240]) + ("&#8230;" if len(upd) > 240 else "")
    sev_e  = _e(sev)

    upd_row = (
        f'<div style="font-size:0.82em;color:#bbb;margin-top:4px">{upd_e}</div>'
        if upd_e else ""
    )
    return (
        f'<div id="nemesisIncidentBanner" data-incident="{name_e}"'
        f' style="border-left:4px solid {border};background:{bg};'
        f'padding:10px 16px;margin-bottom:14px;border-radius:0 6px 6px 0;position:relative">'
        f'<button onclick="(function(b){{'
        f'var p=b.closest(&#39;[data-incident]&#39;);'
        f'sessionStorage.setItem(&#39;nemesisBannerDismissed&#39;,p.dataset.incident);'
        f'p.style.display=&#39;none&#39;'
        f'}})(this)"'
        f' style="position:absolute;top:8px;right:12px;background:none;border:none;'
        f'color:#888;font-size:1.1em;cursor:pointer" title="Dismiss for this session">'
        f'&#10005;</button>'
        f'<span style="color:{border};font-weight:bold">{icon} </span>'
        f'<span class="tier-text"'
        f' data-beginner="{name_e} &#8212; AI may be unavailable right now.'
        f' This is Anthropic&#39;s service, not your setup."'
        f' data-intermediate="Anthropic incident: {name_e}"'
        f' data-pro="{sev_e}: {name_e}">{name_e}</span>'
        f'{upd_row}'
        f'<div style="font-size:0.80em;margin-top:5px;color:#aaa">'
        f'AI calls will likely fail and may still be billed. &#160;'
        f'<a href="https://status.claude.com" target="_blank" rel="noopener"'
        f' style="color:{border}">status.claude.com &#8599;</a></div>'
        f'</div>'
    )


# ─────────────────────────────────────────────────────────────────────────────
# Chat model tiers
#
# The client sends a TIER, never a model ID. An authenticated user choosing to
# spend more is the feature; letting a request name an arbitrary model string is
# not. Anything unrecognised -- absent, misspelled, or hostile -- resolves DOWN
# to standard. Same fail-safe direction as the authority clamp: the cheap,
# expected outcome is what you get when the input cannot be trusted.
#
# Standard deliberately FOLLOWS _ACTIVE_MODEL rather than pinning its own string.
# A second hardcoded model name is exactly the staleness this codebase already
# had once (claude-sonnet-4-6 outliving its generation); one source of truth
# means bumping the default moves the chat with it.
#
# NOT gated by the graduated-authority system. Section 10 of the scoping doc
# establishes a model FLOOR per authority level -- a weak model taking an
# autonomous action is the risk. Raising can never violate a floor, and
# effective_ceiling() does not read the model at all, so a better model cannot
# grant any action the clamp forbids. Raising is a pure cost/quality choice.
# ─────────────────────────────────────────────────────────────────────────────

CHAT_TIER_STANDARD = "standard"
CHAT_TIER_ADVANCED = "advanced"
_CHAT_ADVANCED_MODEL = "claude-opus-5"

#: Reasoning effort for chat follow-ups. One named constant so this is a
#: one-line tuning decision rather than a value buried in a call.
#:
#: "medium", not "low", is a deliberate trade. The complaint this fixes is
#: latency -- every chat question was running at the API default of "high"
#: (see _analyze_inner) -- but these answers are security judgements a user
#: acts on, so the cheapest tier is the wrong floor. "medium" is the
#: documented cost/quality balance and is supported by BOTH chat tiers.
#:
#: Adaptive thinking is deliberately left ON (i.e. `thinking` stays unset).
#: Disabling it on the 5-series has two documented failure modes: tool calls
#: emitted as plain text, and <thinking> tags leaking into the visible answer.
#: Lowering effort is the supported way to cut spend; disabling thinking is not.
_CHAT_EFFORT = "medium"

#: Models known to accept `output_config.effort`. This is an ALLOWLIST because
#: sending `effort` to a model that does not support it is a hard 400 -- it
#: errors on Sonnet 4.5 and Haiku 4.5. An unknown or non-capable model omits the
#: field and runs at the API default instead of failing the whole call: slower,
#: never broken. Both chat tiers are here by construction (resolve_chat_tier can
#: only return _ACTIVE_MODEL or _CHAT_ADVANCED_MODEL).
#:
#: Note the levels differ by model even within this set -- `xhigh` exists on
#: Opus 4.7+ / Sonnet 5 but not on Sonnet 4.6 / Opus 4.6, which cap at `max`
#: with no `xhigh`. _CHAT_EFFORT is "medium", which every model here accepts;
#: raising it to `xhigh` would need this list narrowed in the same edit.
_EFFORT_CAPABLE_MODELS = frozenset({
    "claude-opus-5",
    "claude-opus-4-8",
    "claude-sonnet-5",
    "claude-sonnet-4-6",
    "claude-fable-5",
})

# Representative follow-up shape, used ONLY to compute the cost multiple between
# tiers. The ratio is what is displayed, and it is stable across any plausible
# mix because both tiers are priced on the same token counts.
_CHAT_COST_SAMPLE = (2000, 420)


def resolve_chat_tier(tier: str | None) -> tuple:
    """(tier_name, model_id) for a client-supplied tier. Never raises; defaults down."""
    if (tier or "").strip().lower() == CHAT_TIER_ADVANCED:
        return CHAT_TIER_ADVANCED, _CHAT_ADVANCED_MODEL
    return CHAT_TIER_STANDARD, _ACTIVE_MODEL


def chat_model_options() -> dict:
    """Tier metadata for the UI, including a COMPUTED cost multiple.

    The multiple is derived from get_pricing() for both models on identical
    token counts -- never hardcoded. If either model's rates are unknown the
    multiple is None and the UI must say the increase cannot be quantified
    rather than showing a fabricated number. Same discipline as never rendering
    an unknown cost as $0.00: a plausible-looking figure nobody measured is
    worse than an honest gap, and this one is the basis of a spending decision.
    """
    t_in, t_out = _CHAT_COST_SAMPLE
    std_model = _ACTIVE_MODEL
    adv_model = _CHAT_ADVANCED_MODEL
    std_cost = _cost_of(t_in, t_out, std_model)
    adv_cost = _cost_of(t_in, t_out, adv_model)

    multiple = None
    if std_cost and adv_cost and std_cost > 0:
        multiple = round(adv_cost / std_cost, 1)

    std_p = get_pricing(std_model)
    adv_p = get_pricing(adv_model)
    return {
        "current_default": CHAT_TIER_STANDARD,
        "multiple":        multiple,
        "tiers": [
            {"tier": CHAT_TIER_STANDARD, "label": "Standard", "model": std_model,
             "known": bool(std_p.get("known")), "updated": std_p.get("updated"),
             "input_per_mtok": std_p.get("input_per_mtok"),
             "output_per_mtok": std_p.get("output_per_mtok"),
             "sample_cost_usd": std_cost},
            {"tier": CHAT_TIER_ADVANCED, "label": "Advanced", "model": adv_model,
             "known": bool(adv_p.get("known")), "updated": adv_p.get("updated"),
             "input_per_mtok": adv_p.get("input_per_mtok"),
             "output_per_mtok": adv_p.get("output_per_mtok"),
             "sample_cost_usd": adv_cost},
        ],
    }


def get_chat_widget_html() -> str:
    """DEPRECATED no-op, retained as a fail-safe. Returns "" -- never markup.

    The widget is now injected exactly once per page by get_chat_js(); see
    _chat_widget_markup() for why. This function stays (rather than being
    deleted) precisely BECAUSE the surfaces that used to call it wrap the import
    in try/except: a missing name would be swallowed and look identical to
    "feature off", while an empty string is inert and cannot resurrect the
    duplicate-id collision. A caller that still embeds this renders nothing
    extra and keeps working, because the JS supplies the node either way.
    """
    return ""


def _chat_widget_markup() -> str:
    """Markup for the contextual chat affordance. ONE instance per page, ever.

    Shared rather than hand-rolled per surface for one specific reason: the cost
    line. The product requirement is that no user is ever unaware there is a
    cost, and four separately-written UIs are four chances to drop or weaken
    that line.
    The server-side gates are shared already; this makes the disclosure shared too.

    PRIVATE, and injected only from get_chat_js(). It carries a hardcoded
    id="nemChatSection", so embedding it from more than one place on a page is a
    duplicate-id collision: getElementById() silently returns whichever copy is
    first in the DOM, and the surface that "opened" a different copy becomes a
    no-op with no error anywhere. That is exactly what shipped in 5330220 --
    three copies on `/`, and the alert chat box toggling a node nested inside
    anomaly_detection's display:none overlay. Single-instancing is therefore
    structural here, not a convention each surface has to remember.

    Plain string, not an f-string -- it is embedded into JS via json.dumps(), so
    it must not carry brace-escaping of its own.
    """
    return (
        '<div id="nemChatSection" style="display:none;margin-top:18px;'
        'border-top:1px solid #333;padding-top:14px">'
        '<div style="display:flex;justify-content:space-between;align-items:center;'
        'margin-bottom:8px">'
        '<strong style="color:#00d4ff;font-size:0.95em">Ask about this finding</strong>'
        '<span id="nemChatTurnsLeft" style="font-size:0.78em;color:#888"></span>'
        '</div>'
        # Always-on, non-dismissible cost notice.
        '<div style="background:#1a1f36;border:1px solid #2a3f5f;border-radius:4px;'
        'padding:7px 10px;margin-bottom:9px;font-size:0.78em;color:#9fb3d1">'
        '<span style="color:#ffc107">&#9432;</span> '
        '<span id="nemChatCostText">Each question is a live AI request that costs money.</span>'
        '</div>'
        # Tier control. Raising is a button, not a dropdown selection: a passive
        # select fires on change and would elevate spend without an explicit act.
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:9px;'
        'font-size:0.78em;flex-wrap:wrap">'
        '<span style="color:#888">Model:</span>'
        '<span id="nemChatTierLabel" style="color:#00d4ff;font-weight:bold">Standard</span>'
        '<button id="nemChatRaiseBtn" onclick="nemChatRaise()" '
        'style="background:transparent;color:#ffc107;border:1px solid #ffc10744;'
        'padding:2px 9px;border-radius:3px;cursor:pointer;font-size:0.95em">'
        'Use a more capable model\u2026</button>'
        '<button id="nemChatLowerBtn" onclick="nemChatLower()" '
        'style="display:none;background:transparent;color:#9fb3d1;'
        'border:1px solid #2a3f5f;padding:2px 9px;border-radius:3px;'
        'cursor:pointer;font-size:0.95em">Back to Standard</button>'
        # Persistent, always rendered while elevated -- not a toast that fades.
        '<span id="nemChatLowerHint" style="display:none;color:#8a9bb5">'
        'You can switch back to Standard at any time.</span>'
        '</div>'
        '<div id="nemChatLog" style="max-height:230px;overflow-y:auto;'
        'margin-bottom:9px;font-size:0.85em"></div>'
        '<textarea id="nemChatInput" rows="2" '
        'placeholder="e.g. why does this matter for my network?" '
        'style="width:100%;background:#0d1117;border:1px solid #333;color:#eee;'
        'padding:8px;border-radius:4px;font-size:0.85em;resize:vertical;'
        'box-sizing:border-box"></textarea>'
        '<div style="margin-top:6px;display:flex;gap:8px;align-items:center">'
        '<button id="nemChatAskBtn" onclick="nemChatAsk()" '
        'style="background:#00d4ff;color:#1a1a2e;border:none;padding:5px 14px;'
        'cursor:pointer;border-radius:3px;font-weight:bold">Ask</button>'
        '<span id="nemChatStatus" style="font-size:0.8em;color:#ccc"></span>'
        '</div></div>'
    )


def get_chat_js() -> str:
    """Guarded <script> for the shared chat widget. Include once per page.

    Exposes nemChatInit(surface,rowId) and nemChatClose(). All AI- and
    user-supplied text is written with textContent, never innerHTML: the answer
    is model-generated and could contain markup.
    """
    return (
        '<script>'
        '(function(){'
        'if(window._nemChatJsLoaded)return;'
        'window._nemChatJsLoaded=true;'
        'var S=null,R=null;'
        'function el(i){return document.getElementById(i);}'
        # The single widget instance is created HERE, not embedded by each
        # surface -- see _chat_widget_markup() for the collision this prevents.
        # json.dumps() because the markup is full of double quotes; a raw splice
        # would terminate the JS string literal mid-attribute.
        # Idempotent by construction: it returns early if the node already
        # exists, so a second get_chat_js() on the page (the guard above already
        # prevents that) still could not produce a duplicate.
        'function ensureWidget(){'
        'if(el("nemChatSection"))return true;'
        # document.body is null when this script runs in <head> or above <body>
        # (dashboard.py includes it well before the markup it attaches to), so
        # report failure rather than throwing -- the DOMContentLoaded hook and
        # the lazy calls in Init/Attach below each retry.
        'if(!document.body)return false;'
        'var d=document.createElement("div");'
        'd.innerHTML=' + json.dumps(_chat_widget_markup()) + ';'
        'var n=d.firstElementChild;if(!n)return false;'
        'document.body.appendChild(n);'
        'return true;'
        '}'
        'if(!ensureWidget()){'
        'document.addEventListener("DOMContentLoaded",ensureWidget);}'
        'function money(v){return (v===null||v===undefined)?null:"$"+Number(v).toFixed(4);}'
        'function meta(st){'
        'el("nemChatTurnsLeft").textContent=st.turns_left+" of "+st.turn_cap+" questions left";'
        'var sp=money(st.spent_usd);'
        'var t="Each question is a live AI request that costs money.";'
        'if(sp!==null){t+=" Spent on this finding so far: "+sp;'
        'if(st.spend_partial)t+=" (at least \\u2014 some calls could not be priced)";}'
        'else if(st.spend_partial){t+=" Cost of earlier questions could not be determined.";}'
        'el("nemChatCostText").textContent=t;'
        'el("nemChatAskBtn").disabled=(st.turns_left<=0);'
        '}'
        'function refresh(){'
        'return fetch("/api/ai/chat/state?surface="+encodeURIComponent(S)'
        '+"&row_id="+encodeURIComponent(R)).then(function(r){return r.json();});'
        '}'
        'window.nemChatInit=function(surface,rowId){'
        'S=surface;R=rowId;'
        'ensureWidget();'
        'var sec=el("nemChatSection");if(!sec)return;'
        'el("nemChatLog").innerHTML="";el("nemChatInput").value="";'
        'el("nemChatStatus").textContent="";sec.style.display="none";'
        'refresh().then(function(st){'
        'if(!st.ok||!st.available)return;'
        'sec.style.display="block";OPTS=st.models||null;meta(st);tierUI();'
        '}).catch(function(){});'
        '};'
        # Relocate the single widget into whichever container is open. Surfaces
        # that expand rows in place (malware findings, queue items) can have
        # several open at once; moving one widget keeps a single DOM instance and
        # a single cost display, rather than N copies to keep consistent.
        'var TIER="standard",OPTS=null;''function tierUI(){''var adv=(TIER==="advanced");''el("nemChatTierLabel").textContent=adv?"Advanced":"Standard";''el("nemChatTierLabel").style.color=adv?"#ffc107":"#00d4ff";''el("nemChatRaiseBtn").style.display=adv?"none":"";''el("nemChatLowerBtn").style.display=adv?"":"none";''el("nemChatLowerHint").style.display=adv?"":"none";''}''window.nemChatRaise=function(){''var m=(OPTS&&OPTS.multiple)?OPTS.multiple:null;''var cost=(m===null)''?"The exact cost increase CANNOT be calculated right now, because pricing for one of the models is unknown. It will be more expensive per question."'':("Each question will cost about "+m+"x more than Standard.");''var msg="Switch to the Advanced model?\n\n"+cost''+"\n\nThis applies to new questions in this conversation only. "''+"Your spend cap and rate limits still apply.\n\n"''+"You can switch back to Standard at any time.";''if(!window.confirm(msg))return;''TIER="advanced";tierUI();''};''window.nemChatLower=function(){TIER="standard";tierUI();};''window.nemChatAttach=function(container,surface,rowId){'
        'ensureWidget();'
        'var sec=el("nemChatSection");'
        'if(!sec||!container)return;'
        'if(sec.parentNode!==container)container.appendChild(sec);'
        'window.nemChatInit(surface,rowId);'
        '};'
        'window.nemChatClose=function(){'
        'var sec=el("nemChatSection");'
        'if(sec){'
        'sec.style.display="none";'
        # Park the single instance back on <body> on close. Surfaces re-render
        # their own containers (module cards refresh on poll, modals rebuild
        # innerHTML), and a widget left parked inside one would be destroyed
        # with it -- silently, because every caller goes through nemChatAttach
        # and would simply find nothing. Parking makes the node outlive every
        # container that borrows it; ensureWidget() is the backstop if it gets
        # destroyed anyway.
        'if(document.body&&sec.parentNode!==document.body)'
        'document.body.appendChild(sec);'
        '}'
        'if(el("nemChatLog"))el("nemChatLog").innerHTML="";'
        'if(el("nemChatInput"))el("nemChatInput").value="";'
        'S=null;R=null;'
        '};'
        'window.nemChatAsk=function(){'
        'var inp=el("nemChatInput");var q=(inp.value||"").trim();if(!q)return;'
        'var btn=el("nemChatAskBtn");var stx=el("nemChatStatus");'
        'btn.disabled=true;stx.textContent="asking\\u2026";'
        'fetch("/api/ai/chat/ask",{method:"POST",'
        'headers:{"Content-Type":"application/json"},'
        'body:JSON.stringify({surface:S,row_id:R,question:q,tier:TIER})})'
        '.then(function(r){return r.json();})'
        '.then(function(d){'
        # Distinct reasons must stay distinct: "out of questions", "spend cap
        # reached" and "rate limited" need different responses from the user.
        'if(!d.ok){stx.textContent=d.reason||"could not ask that question";'
        'btn.disabled=false;return;}'
        'inp.value="";stx.textContent="";'
        'var log=el("nemChatLog");'
        'var w=document.createElement("div");'
        'w.style.cssText="margin-bottom:10px;border-bottom:1px solid #222;padding-bottom:8px";'
        'var qe=document.createElement("div");'
        'qe.style.cssText="color:#00d4ff;margin-bottom:3px";qe.textContent="You: "+q;'
        'var ae=document.createElement("div");'
        'ae.style.cssText="color:#ddd;white-space:pre-wrap";ae.textContent=d.answer;'
        'var ce=document.createElement("div");'
        'ce.style.cssText="color:#777;font-size:0.75em;margin-top:4px";'
        'var m=money(d.cost_usd);'
        'var lbl=(d.tier==="advanced")?" (Advanced)":"";''ce.textContent=((m===null)?"cost unavailable for this model":"this question cost "+m)+lbl;'
        'w.appendChild(qe);w.appendChild(ae);w.appendChild(ce);'
        'log.appendChild(w);log.scrollTop=log.scrollHeight;'
        'if(d.record_failed){stx.textContent="answered, but this question could not be '
        'added to the spend record shown above";}'
        'refresh().then(function(st){if(st.ok)meta(st);}).catch(function(){});'
        'btn.disabled=false;'
        '}).catch(function(e){stx.textContent="error: "+e;btn.disabled=false;});'
        '};'
        '})();'
        '</script>'
    )


def get_incident_js() -> str:
    """Guarded <script> block: in-flight lock + incident confirm + banner dismiss init.
    Include once per page (after tier.js). Guard prevents double-definition."""
    return (
        '<script>'
        '(function(){'
        'if(window._aiIncidentJsLoaded)return;'
        'window._aiIncidentJsLoaded=true;'
        # Incident state (populated by stats poll)
        'window._nemesisIncidentState={};'
        # In-flight tracking set
        'window._aiInFlightSet=new Set();'
        'window._aiInFlightStart=function(key,btn){'
        'window._aiInFlightSet.add(key);'
        'if(btn)btn.disabled=true;'
        '};'
        'window._aiInFlightEnd=function(key,btn){'
        'window._aiInFlightSet.delete(key);'
        'if(btn)btn.disabled=false;'
        '};'
        'window._aiIsInFlight=function(key){'
        'return window._aiInFlightSet.has(key);'
        '};'
        # Incident confirm: gate user-triggered calls when incident active
        'window._aiIncidentConfirm=function(callFn){'
        'var s=window._nemesisIncidentState||{};'
        'if(!s.active){callFn();return;}'
        'var n=s.name||"Service Issue";'
        'var msg=typeof tierText==="function"'
        '?tierText('
        '"Anthropic is reporting a service issue ("+n+"). AI calls will likely fail'
        ' and may still be billed. Try anyway?",'
        '"Anthropic incident: "+n+". AI may fail or bill without response. Try?",'
        '"Incident active ("+n+"). Proceed?"'
        ')'
        ':"Anthropic incident: "+n+". Proceed?";'
        'if(confirm(msg))callFn();'
        '};'
        # Banner dismiss: hide on load if this incident was already dismissed this session
        '(function(){'
        'function _initDismiss(){'
        'var b=document.getElementById("nemesisIncidentBanner");'
        'if(b&&sessionStorage.getItem("nemesisBannerDismissed")===b.dataset.incident)'
        'b.style.display="none";'
        '}'
        'if(document.readyState==="loading")'
        'document.addEventListener("DOMContentLoaded",_initDismiss);'
        'else _initDismiss();'
        '})();'
        '})();'
        '</script>'
    )


def get_usage_stats() -> dict:
    """Call counts, real token totals, and real cost per period.

    COST IS COMPUTED FROM THE RECORDED TOKENS, not from an assumed call size.
    Until 2026-08-04 this returned a single `cost_per_call` built from a
    hardcoded 350-in/150-out guess and the client multiplied it by the call
    count — while `ai_usage` had held the true per-call `tokens_in`/`tokens_out`
    all along (`_increment_usage`, stamped from `msg.usage` on every real call).
    The displayed dollar figure was therefore call-count (real) x per-call cost
    (invented). Measured against one 5000-in/2000-out call it understated spend
    by ~13x.

    NO BLENDED PER-CALL FIGURE IS RETURNED, deliberately. Input and output are
    priced ~5x apart on every current model, so one number per call cannot be
    right except by coincidence — and exposing one is what invited the
    multiply-by-count pattern that caused the bug. Callers get per-period totals
    already summed, or the raw token counts to sum themselves.

    A CACHE HIT IS A REAL CALL WITH ZERO TOKENS. `analyze()` returns
    `tokens_used: 0` and skips `_increment_usage` on a cache hit, so a window
    can legitimately hold calls whose cost is $0. That is a genuine measurement
    and must stay distinguishable from "no calls at all" — hence counts and
    tokens are both returned rather than cost alone.

    FAILS CLOSED. On any read failure this returns `{"ok": False}` and NO
    numbers. The previous version returned zeroed counts plus an
    assumption-derived cost, which is indistinguishable from a real reading of
    "no usage yet" — a default that means something, which is the failure mode
    this codebase keeps finding.
    """
    pricing = get_pricing()

    def _cost(tokens_in: int, tokens_out: int) -> float:
        return round(tokens_in * pricing["input_per_mtok"] / 1_000_000
                     + tokens_out * pricing["output_per_mtok"] / 1_000_000, 6)

    try:
        conn = _conn()
        now = datetime.now()
        today       = now.strftime("%Y-%m-%d")
        week_start  = (now - timedelta(days=7)).strftime("%Y-%m-%d")
        month_start = (now - timedelta(days=30)).strftime("%Y-%m-%d")

        def _window(sql, param):
            # COALESCE, not `or 0` on the Python side: SUM() over no rows returns
            # NULL, and the distinction between "no rows" and "rows summing to
            # zero" is carried by call_count, not by coercing NULL here.
            r = conn.execute(sql, (param,)).fetchone()
            return (int(r[0] or 0), int(r[1] or 0), int(r[2] or 0))

        cols = "SUM(call_count), SUM(tokens_in), SUM(tokens_out)"
        t_calls, t_in, t_out = _window(
            f"SELECT {cols} FROM ai_usage WHERE date=?", today)
        w_calls, w_in, w_out = _window(
            f"SELECT {cols} FROM ai_usage WHERE date>=?", week_start)
        m_calls, m_in, m_out = _window(
            f"SELECT {cols} FROM ai_usage WHERE date>=?", month_start)

        hourly_rows = conn.execute(
            "SELECT hour, call_count, tokens_in, tokens_out FROM ai_usage "
            "WHERE date=? ORDER BY hour", (today,)
        ).fetchall()
        conn.close()

        return {
            "ok":      True,
            "today":   t_calls,
            "week":    w_calls,
            "month":   m_calls,
            "hourly":  {r["hour"]: r["call_count"] for r in hourly_rows},
            "pricing": pricing,
            "tokens": {
                "today": {"in": t_in, "out": t_out},
                "week":  {"in": w_in, "out": w_out},
                "month": {"in": m_in, "out": m_out},
                "hourly": {r["hour"]: {"in": r["tokens_in"], "out": r["tokens_out"]}
                           for r in hourly_rows},
            },
            # Per-install monthly average rides the existing payload rather than
            # a new endpoint — no new route, no new auth surface.
            "monthly": get_monthly_cost(),
            "cost": {
                "today": _cost(t_in, t_out),
                "week":  _cost(w_in, w_out),
                "month": _cost(m_in, m_out),
                "hourly": {r["hour"]: _cost(r["tokens_in"], r["tokens_out"])
                           for r in hourly_rows},
            },
        }
    except Exception as exc:
        log.exception("ai_engine: get_usage_stats failed")
        # Pricing is safe to return (it is read from env, not the DB) and the UI
        # needs it to render the rate footnote. Everything measured is omitted.
        return {"ok": False, "error": str(exc)[:200], "pricing": pricing}


def analyze(
    prompt: str,
    system_prompt: str | None = None,
    max_tokens: int = 1000,
    cache_key: str | None = None,
    cache_hours: float = 24,
    force: bool = False,
    job_id: str | None = None,
    model: str | None = None,
    effort: str | None = None,
) -> dict:
    """
    Single entry point for all Anthropic API calls.

    Returns {"ok": True, "text": str, "from_cache": bool, "tokens_used": int}
         or {"ok": False, "reason": str}.

    force=True bypasses rate limiting (for manual/override calls).
    cache_hours=0 skips cache lookup (always calls API).
    job_id — if provided, deduplicates concurrent calls for the same job.
    effort — optional reasoning-effort hint ("low"|"medium"|"high"|...). Default
        None means "send no output_config", which is NOT the same as sending
        "high": it leaves the choice to the API. Every existing caller therefore
        keeps its current behaviour byte-for-byte. Only sent for models on
        _EFFORT_CAPABLE_MODELS -- see that constant for why it is an allowlist.
    """
    # In-flight dedup
    if job_id:
        with _in_flight_lock:
            if job_id in _in_flight:
                return {"ok": False, "reason": "duplicate call — already in flight"}
            _in_flight.add(job_id)

    try:
        return _analyze_inner(prompt, system_prompt, max_tokens, cache_key,
                              cache_hours, force, model, effort)
    finally:
        if job_id:
            with _in_flight_lock:
                _in_flight.discard(job_id)


def _analyze_inner(
    prompt: str,
    system_prompt: str | None,
    max_tokens: int,
    cache_key: str | None,
    cache_hours: float,
    force: bool,
    model: str | None = None,
    effort: str | None = None,
) -> dict:
    # A non-default model gets its own cache namespace. Without this a cached
    # answer from one model would be served for a request that explicitly asked
    # for another -- silently, and looking exactly like a normal cache hit.
    target_model = model or _ACTIVE_MODEL
    if cache_key and target_model != _ACTIVE_MODEL:
        cache_key = f"{cache_key}@{target_model}"
    key = _api_key()
    if not key:
        return {"ok": False, "reason": "ANTHROPIC_API_KEY not configured"}

    now = time.time()

    # Cache lookup
    if cache_key and cache_hours > 0 and not force:
        try:
            conn = _conn()
            row = conn.execute(
                "SELECT response_text, generated_at FROM ai_cache WHERE cache_key=?",
                (cache_key,)
            ).fetchone()
            conn.close()
            if row and row["generated_at"] + cache_hours * 3600 > now:
                # Same keys as the live-call return, so a caller reading the
                # split never KeyErrors on a cache hit. Zero here is a real
                # measurement: a cache hit genuinely bills nothing.
                return {"ok": True, "text": row["response_text"],
                        "from_cache": True, "tokens_used": 0,
                        "tokens_in": 0, "tokens_out": 0}
        except Exception:
            log.exception("ai_engine: cache lookup failed for %s", cache_key)

    # Rate limit check (skipped when force=True)
    if not force:
        try:
            conn = _conn()
            limited, reason = _check_rate_limit(conn)
            conn.close()
            if limited:
                return {"ok": False, "reason": f"Rate limit: {reason}"}
        except Exception:
            log.exception("ai_engine: rate limit check failed")

    # API call with capped retry (max 1 retry)
    try:
        import anthropic
    except ImportError:
        return {"ok": False, "reason": "anthropic package not installed — run pip install anthropic"}

    client = anthropic.Anthropic(api_key=key)
    messages = [{"role": "user", "content": prompt}]
    kwargs: dict = dict(model=target_model, max_tokens=max_tokens, messages=messages)
    if system_prompt:
        kwargs["system"] = system_prompt

    # Reasoning effort. Omitted entirely unless a caller asked for one -- an
    # absent output_config lets the API pick (currently "high"), which is what
    # every non-chat surface has always run at and is left untouched here.
    #
    # Gated on the model, not just on `effort` being set: `effort` is a hard 400
    # on models that do not support it (Sonnet 4.5, Haiku 4.5). Failing that way
    # would take out the whole call, so a non-capable model drops the hint and
    # runs at the default -- slower, never broken -- and says so in the log
    # rather than dropping it silently.
    if effort:
        if target_model in _EFFORT_CAPABLE_MODELS:
            kwargs["output_config"] = {"effort": effort}
        else:
            log.warning(
                "ai_engine: model %s is not on the effort allowlist; sending no "
                "output_config (request runs at the API default effort)",
                target_model,
            )

    text = tokens_in = tokens_out = None
    last_exc = None

    for attempt in range(2):
        try:
            msg        = client.messages.create(**kwargs)

            # A declined request returns HTTP 200 with stop_reason='refusal' and
            # empty-or-partial content, not an exception. Checked BEFORE reading
            # content so a refusal surfaces as a stated reason rather than an
            # unexplained empty answer.
            if getattr(msg, "stop_reason", None) == "refusal":
                detail = getattr(msg, "stop_details", None)
                cat = getattr(detail, "category", None) if detail else None
                raise RuntimeError(
                    "the model declined this request"
                    + (" (%s)" % cat if cat else ""))

            # Select the TEXT block by type — do NOT index content[0].
            #
            # content is a list of typed blocks (ThinkingBlock, TextBlock, ...),
            # and which one comes first depends on the model. On claude-opus-5
            # thinking is ON BY DEFAULT — omitting the `thinking` parameter runs
            # adaptive thinking, unlike opus-4-8/4-7 where omitting it meant no
            # thinking. So content[0] became a ThinkingBlock, which has
            # `.thinking` and no `.text`, and every AI surface in the product
            # broke on the same AttributeError while the API call itself
            # returned 200. Selecting by type is version-proof; indexing is not.
            text = next((b.text for b in msg.content
                         if getattr(b, "type", None) == "text"), "").strip()
            if not text:
                raise RuntimeError(
                    "response carried no text block (blocks: %s)"
                    % ", ".join(getattr(b, "type", "?") for b in msg.content))

            tokens_in  = getattr(msg.usage, "input_tokens",  0)
            tokens_out = getattr(msg.usage, "output_tokens", 0)
            _record_call_success()
            last_exc   = None
            break
        except Exception as exc:
            last_exc    = exc
            status_code = getattr(exc, "status_code", None)
            is_timeout  = (
                type(exc).__name__ in ("APITimeoutError", "APIConnectionError")
                or "timeout" in str(exc).lower()
                or "connection" in str(exc).lower()
            )
            is_service  = status_code in _SERVICE_CODES
            is_rate     = status_code == 429

            if attempt == 0:
                if is_rate:
                    retry_after = 30.0
                    try:
                        rh = getattr(getattr(exc, "response", None), "headers", {}) or {}
                        v  = float(rh.get("retry-after") or rh.get("Retry-After") or 0)
                        if v > 0:
                            retry_after = min(v, 60.0)
                    except Exception:
                        pass
                    log.warning("ai_engine: 429 rate-limited, waiting %.0fs before retry",
                                retry_after)
                    time.sleep(retry_after)
                elif is_service or is_timeout:
                    log.warning("ai_engine: HTTP %s on attempt 1, retrying in 2s",
                                status_code or "timeout")
                    time.sleep(2.0)
                else:
                    break  # auth error or similar — don't retry
            else:
                if is_service or is_timeout:
                    _record_call_failure(status_code or 0)
                break

    if last_exc is not None:
        log.error("ai_engine: API call failed: %s", last_exc)
        status_code = getattr(last_exc, "status_code", None)
        result: dict = {"ok": False, "reason": str(last_exc)}
        if status_code:
            result["http_status"] = status_code
        return result

    # Persist cache + usage + rate counters
    try:
        conn = _conn()
        if cache_key:
            expires = now + cache_hours * 3600 if cache_hours > 0 else now
            conn.execute(
                "INSERT OR REPLACE INTO ai_cache(cache_key, response_text, generated_at, expires_at)"
                " VALUES(?,?,?,?)",
                (cache_key, text, now, expires)
            )
        _increment_usage(conn, tokens_in, tokens_out)
        _increment_rate(conn)
        conn.commit()
        conn.close()
    except Exception:
        log.exception("ai_engine: failed to persist usage/cache for %s", cache_key)

    # tokens_in/tokens_out are returned ALONGSIDE the existing tokens_used sum,
    # not instead of it — every current caller keeps working untouched. The split
    # is needed because input and output are priced ~5x apart, so a per-call cost
    # derived from the sum alone cannot be right except by coincidence. The chat
    # surface shows the user what each question actually cost, which needs both.
    return {"ok": True, "text": text, "from_cache": False,
            "tokens_used": (tokens_in or 0) + (tokens_out or 0),
            "tokens_in": tokens_in or 0, "tokens_out": tokens_out or 0}


# ─────────────────────────────────────────────────────────────────────────────
# Flask route handlers
# ─────────────────────────────────────────────────────────────────────────────

def _route_status():
    from flask import jsonify
    return jsonify(get_status())


def _route_usage():
    from flask import jsonify
    return jsonify(get_usage_stats())


def _route_settings():
    from flask import request, jsonify
    if request.method == "GET":
        return jsonify({
            "rate_per_hour":       int(_get_setting("rate_per_hour", str(_RATE_HOUR_DEFAULT))),
            "rate_per_day":        int(_get_setting("rate_per_day",  str(_RATE_DAY_DEFAULT))),
            "ai_upsell_dismissed": _get_setting("ai_upsell_dismissed", "0") == "1",
            # "" means no cap. Returned as the stored string rather than a float
            # so the UI can distinguish "unset" from "0" without guessing.
            "spend_cap_monthly_usd": _get_setting("spend_cap_monthly_usd", ""),
        })
    data = request.get_json(silent=True) or {}

    # Validate the spend cap BEFORE writing anything. Two reasons, and the
    # second is the one that matters:
    #
    #  1. The POST carries several keys; applying some and then rejecting one
    #     leaves the settings half-saved.
    #  2. `_spend_cap_usd()` treats an unparseable stored value as "no cap"
    #     (deliberately — a cap of 0 would block every call and read as an
    #     engine bug rather than a typo). That is right at READ time, but it
    #     means a typo accepted here would SILENTLY REMOVE the user's spending
    #     protection while the save looked successful. So garbage is refused at
    #     the point of entry, and an existing cap is left exactly as it was.
    cap_write = None
    if "spend_cap_monthly_usd" in data:
        raw = ("" if data["spend_cap_monthly_usd"] is None
               else str(data["spend_cap_monthly_usd"]).strip())
        if raw == "":
            cap_write = ""            # explicit clear — "no cap"
        else:
            try:
                val = float(raw)
            except (ValueError, TypeError):
                return jsonify({"ok": False, "error":
                                "Spend cap must be a number, or empty for no cap. "
                                "Existing cap left unchanged."}), 400
            if val <= 0:
                return jsonify({"ok": False, "error":
                                "Spend cap must be greater than 0, or empty for "
                                "no cap. Existing cap left unchanged."}), 400
            cap_write = f"{val:.2f}"

    try:
        if cap_write is not None:
            _set_setting("spend_cap_monthly_usd", cap_write)
        if "rate_per_hour" in data:
            _set_setting("rate_per_hour", str(max(0, int(data["rate_per_hour"]))))
        if "rate_per_day" in data:
            _set_setting("rate_per_day",  str(max(0, int(data["rate_per_day"]))))
        if "ai_upsell_dismissed" in data:
            _set_setting("ai_upsell_dismissed", "1" if data["ai_upsell_dismissed"] else "0")
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


def _route_incident():
    """GET /api/ai/incident — current Anthropic incident state JSON."""
    from flask import jsonify
    return jsonify(get_incident_state())


def _route_incident_simulate():
    """POST /api/ai/incident/simulate — force incident state for testing."""
    from flask import request, jsonify
    data = request.get_json(silent=True) or {}
    active = data.get("active", False)
    with _incident_lock:
        _incident["active"]        = bool(active)
        _incident["severity"]      = data.get("severity", "major") if active else ""
        _incident["name"]          = data.get("name", "Test Incident") if active else ""
        _incident["update"]        = data.get("update", "Simulated for testing.") if active else ""
        _incident["source"]        = "simulate" if active else ""
        _incident["since"]         = time.time() if active else 0.0
        _incident["failure_count"] = 0
    return jsonify({"ok": True, "active": bool(active)})


def _route_upsell_dismiss():
    from flask import jsonify
    _set_setting("ai_upsell_dismissed", "1")
    return jsonify({"ok": True})


def _route_upsell_restore():
    from flask import jsonify
    _set_setting("ai_upsell_dismissed", "0")
    return jsonify({"ok": True})


# ─────────────────────────────────────────────────────────────────────────────
# Module class
# ─────────────────────────────────────────────────────────────────────────────

class Module(NemesisModule):

    def start(self) -> None:
        global _poll_stop
        _init_db()
        _poll_stop.clear()
        # Fire initial poll immediately (non-blocking daemon thread)
        threading.Thread(target=_poll_anthropic_status, daemon=True,
                         name="ai-status-init").start()
        # Recurring poll loop
        threading.Thread(target=_poll_loop, args=(_poll_stop,), daemon=True,
                         name="ai-status-poll").start()
        log.info("ai_engine: started (key %s, status poll started)",
                 "configured" if is_enabled() else "not configured")

    def stop(self) -> None:
        _poll_stop.set()
        log.info("ai_engine: stopped")

    def status(self) -> dict:
        return get_status()

    def get_dashboard_card(self):
        return None  # badge is injected into the h1 by dashboard.py

    def get_routes(self):
        return [
            ("/api/ai/status",             _route_status,            {"methods": ["GET"]}),
            ("/api/ai/usage",              _route_usage,             {"methods": ["GET"]}),
            ("/api/ai/settings",           _route_settings,          {"methods": ["GET", "POST"]}),
            ("/api/ai/upsell_dismiss",     _route_upsell_dismiss,    {"methods": ["POST"]}),
            ("/api/ai/upsell_restore",     _route_upsell_restore,    {"methods": ["POST"]}),
            ("/api/ai/incident",           _route_incident,          {"methods": ["GET"]}),
            ("/api/ai/incident/simulate",  _route_incident_simulate, {"methods": ["POST"]}),
        ]
