"""L4 accumulating context — the structured store. DESIGN-L4 §4.

WHAT THIS IS FOR
    A mature install is the one with the most accumulated learning, so the
    earlier flat-document sketch was LONGEST exactly when decisions mattered
    most: token cost rising linearly while relevance fell. This retrieves only
    what applies.

═══════════════════════════════════════════════════════════════════════════════
⚠ CONTEXT SHAPES JUDGMENT, NEVER AUTHORITY (§4.6)
═══════════════════════════════════════════════════════════════════════════════
    The LADDER decides *what class of action is permitted*  -> authority.
    This STORE informs *which choice within that class*     -> judgment.

`effective_ceiling()` MUST NEVER read either table. No stored row can authorise
a class the ladder forbids; the strongest possible learned entry cannot make an
L1-ceilinged class executable. `test_context_store.py` mutation-tests this: a
change making learned context influence a ceiling turns the suite RED. Without
that this paragraph is a comment — and comments have contradicted their own code
more than once in this project.

⭐ RETRIEVAL IS DETERMINISTIC CATEGORICAL MATCHING, NOT SEMANTIC SEARCH (§4.2)
    Stated as a DECISION, not an omission. Semantic similarity retrieves
    precedents that *read* alike; a superficially similar but materially
    different precedent, applied confidently, is worse than no precedent — and
    its failure mode is invisible, because retrieved text always looks plausible
    beside the decision it is shaping. That is the same shape as every instrument
    failure this project has hit: a plausible answer from something that did not
    measure the right thing.

    Categorical matching also has a property semantic search cannot offer: it is
    EXPLAINABLE. For any decision we can say exactly which rows applied and why,
    column by column. "It seemed similar" cannot support a review surface, a
    post-incident analysis, or an operator asking why a precedent was used.

    If semantic search is ever revisited it ships only after a MEASURED
    false-match rate against a labelled set, and it SUPPLEMENTS this — never
    replaces it.

⚠ RETRIEVAL FILTERS CONTEXT, IT NEVER PRUNES THE RECORD (§4.4)
    Nothing here deletes. Expiry and revocation are columns. An expired
    permissive entry stops INFLUENCING decisions and stays FULLY READABLE in the
    review surface and in audit, forever. "No longer applied" and "no longer
    recorded" are different states; collapsing them would make the system's own
    history unauditable exactly where it matters.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

MODULE_NAME = "ai_engine"

RESTRICTIVE = "restrictive"
PERMISSIVE = "permissive"
SCOPE_TRIGGER = "trigger"
SCOPE_CATEGORY = "category"

#: §6: operator-approved default for permissive entries. Restrictive never
#: expires — the asymmetry IS the erosion guardrail (§4.3).
PERMISSIVE_TTL_DAYS = 180

#: Bounded retrieval. Exceeding it is REPORTED, never silently trimmed (§4.4).
MAX_CONTEXT_ROWS = 25


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _conn():
    from modules import get_data_manager                        # noqa: PLC0415
    return get_data_manager().connect(MODULE_NAME)


class ContextWriteRejected(ValueError):
    """A write violating the §4.3 asymmetry or a required field."""


def add_learned(action_class, trigger_type, trigger_key, direction, scope,
                admin_reasoning, *, source_event_id=None, actor=None,
                ttl_days=PERMISSIVE_TTL_DAYS, now=None):
    """Record one calibration entry. Append-only.

    ⚠ The DATABASE also enforces the §4.3 asymmetry via CHECK constraints. These
    Python checks exist to produce a READABLE error, not to be the guarantee —
    the guarantee is in the schema, where no write path can bypass it, including
    one written later by someone who has not read §4.3. Both are tested.

    `expires_at` is set automatically for permissive entries and left NULL for
    restrictive ones. A permissive entry that never expires is a category grant
    wearing a narrow label: it accumulates the same way, only slower.
    """
    if direction not in (RESTRICTIVE, PERMISSIVE):
        raise ContextWriteRejected("direction must be %r or %r, got %r"
                                   % (RESTRICTIVE, PERMISSIVE, direction))
    if scope not in (SCOPE_TRIGGER, SCOPE_CATEGORY):
        raise ContextWriteRejected("scope must be %r or %r, got %r"
                                   % (SCOPE_TRIGGER, SCOPE_CATEGORY, scope))
    if direction == PERMISSIVE and scope == SCOPE_CATEGORY:
        raise ContextWriteRejected(
            "a PERMISSIVE entry may not have CATEGORY scope. Fifty "
            "individually-reasonable permissive overrides compose into a system "
            "markedly less cautious than the one approved, with no single wrong "
            "decision behind it. A blanket permissive policy belongs in a "
            "standing rule -- visible and first-class -- not inferred from a "
            "pile of overrides. (DESIGN-L4 §4.3)")
    if not (admin_reasoning or "").strip():
        raise ContextWriteRejected(
            "admin_reasoning is required and must be non-empty: it is the "
            "artefact a human reads in the review surface, not decoration")

    ts = now or _now()
    expires = None
    if direction == PERMISSIVE:
        expires = (datetime.fromisoformat(ts)
                   + timedelta(days=int(ttl_days))).isoformat(timespec="seconds")

    conn = _conn()
    try:
        cur = conn.execute(
            "INSERT INTO ai_learned_context(created_at, action_class, "
            "trigger_type, trigger_key, direction, scope, admin_reasoning, "
            "source_event_id, expires_at, actor) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (ts, action_class, trigger_type, trigger_key, direction, scope,
             admin_reasoning, source_event_id, expires, actor))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def revoke_learned(entry_id, revoked_by, now=None):
    """SOFT delete. Returns rows affected.

    ⚠ There is deliberately NO delete_learned(). §4.4 requires the record be
    permanent; a hard delete would make "no longer applied" indistinguishable
    from "never happened".
    """
    conn = _conn()
    try:
        cur = conn.execute(
            "UPDATE ai_learned_context SET revoked_at=?, revoked_by=? "
            "WHERE id=? AND revoked_at IS NULL",
            (now or _now(), revoked_by, int(entry_id)))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def retrieve(action_class, trigger_type, trigger_key, *, category=None,
             tier=None, trace_id=None, limit=MAX_CONTEXT_ROWS, now=None):
    """Context for ONE decision. Returns a dict; NEVER raises on zero matches.

    Zero matches is a VALID, SAFE outcome — baseline guidance only. It must
    never error and must never be filled in by loosening the match (§4.4).

    The returned dict always carries `truncated`, `matched_total` and
    `returned_count`. A bounded retrieval that presents as complete is the
    "never `head -n` a set you draw a conclusion from" rule applied to the AI's
    own inputs — so the caller cannot mistake a partial context for the whole.
    """
    ts = now or _now()
    conn = _conn()
    try:
        # Baseline: vendor guidance for this class, optionally tier-scoped.
        base_rows = conn.execute(
            "SELECT id, guidance, version FROM ai_policy_baseline "
            "WHERE action_class=? AND trigger_type=? "
            "  AND (trigger_key=? OR trigger_key=?) "
            "  AND (tier IS NULL OR tier=?) ORDER BY id",
            (action_class, trigger_type, trigger_key,
             category or trigger_key, tier)).fetchall()

        # Learned: EXACT action_class (never crossed), narrow key OR a
        # category-scoped row, live only. Specificity first so a narrow entry
        # outranks a category one.
        sql = ("SELECT id, direction, scope, trigger_key, admin_reasoning, "
               "       created_at, expires_at, "
               "       CASE WHEN scope='trigger' THEN 1 ELSE 0 END AS specificity "
               "FROM ai_learned_context "
               "WHERE action_class=? AND trigger_type=? "
               "  AND (trigger_key=? OR (scope='category' AND trigger_key=?)) "
               "  AND revoked_at IS NULL "
               "  AND suspended_at IS NULL "     # §4.7: awaiting human review
               "  AND (expires_at IS NULL OR expires_at > ?) "
               "ORDER BY specificity DESC, created_at DESC")
        params = (action_class, trigger_type, trigger_key,
                  category or trigger_key, ts)
        all_matched = conn.execute(sql, params).fetchall()
        matched_total = len(all_matched)
        rows = all_matched[:int(limit)]
        truncated = matched_total > len(rows)

        learned = [{"id": r["id"], "direction": r["direction"],
                    "scope": r["scope"], "trigger_key": r["trigger_key"],
                    "admin_reasoning": r["admin_reasoning"],
                    "created_at": r["created_at"],
                    "expires_at": r["expires_at"]} for r in rows]
        baseline = [{"id": r["id"], "guidance": r["guidance"],
                     "version": r["version"]} for r in base_rows]

        # Retrieval is itself recorded, and use_count updated — so "why did it
        # decide that?" is answerable after the fact, and the review surface can
        # show which entries actually influence anything.
        conn.execute(
            "INSERT INTO ai_context_retrieval(retrieved_at, trace_id, "
            "action_class, trigger_type, trigger_key, learned_ids, "
            "baseline_ids, matched_total, returned_count, truncated) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (ts, trace_id, action_class, trigger_type, trigger_key,
             json.dumps([e["id"] for e in learned]),
             json.dumps([b["id"] for b in baseline]),
             matched_total, len(learned), 1 if truncated else 0))
        for e in learned:
            conn.execute(
                "UPDATE ai_learned_context SET use_count = use_count + 1, "
                "last_used_at=? WHERE id=?", (ts, e["id"]))
        conn.commit()
    finally:
        conn.close()

    return {"action_class": action_class, "baseline": baseline,
            "learned": learned, "matched_total": matched_total,
            "returned_count": len(learned), "truncated": truncated}


#: trigger_type -> the NPFA/1 field kind that can carry its key. Anything not
#: listed falls to IDENTIFIER, whose validator will reject a value it cannot
#: represent rather than mangling it.
_KEY_KIND = {
    "ip": "address",
    "domain": "domain",
    "host": "device_name",
    "path": "basename",
}


def context_parts(ctx, *, key_kind=None):
    """Turn a `retrieve()` result into NPFA/1 field parts (ADR 0025).

    ⭐ RETURNS PARTS; IT NEVER CALLS `prompt_fields.build()`.
    The set of `build()` callers is deliberately closed (five machine-generated
    builders, asserted by `test_prompt_allowlist.py`). Returning parts lets any
    of them splice learned context into a prompt they already own, WITHOUT
    adding a sixth caller and without this module having to know the shape of
    the decision request it is enriching. That shape belongs to whoever owns the
    decision — for the failsafe path, Window 1 (Amendment 03 §10.3).

    ⚠ `admin_reasoning` IS DELIBERATELY NOT INCLUDED, and never will be.
    Operator decision, 2026-08-27. NPFA/1 has no field kind that can carry
    free-form prose — LITERAL is explicitly "never runtime data" — and widening
    the one `free_text_reason` exemption to automated calls would turn a marked
    path into a general hatch. The STRUCTURE is what reaches the decision; the
    PROSE stays in the review surface (§4.5), where §4.5 says a human reads it.
    This is also the more consistent position: §4.2's whole argument for
    categorical matching over semantic search is that the match is structured
    and explainable, so the structure is the thing worth transmitting. A side
    effect worth naming: an admin's verbatim words never leave the box.

    ⚠ IT RAISES RATHER THAN DEGRADING. A `path`-keyed entry cannot be expressed
    as one NPFA/1 field (IDENTIFIER forbids `/`, BASENAME rejects separators).
    Quietly emitting the basename would hand the model a LESS SPECIFIC key that
    looks exact — two different paths sharing a basename become indistinguishable
    — which is the failed-read-as-default shape this codebase forbids. The
    caller passes an explicit `key_kind` or fixes the entry; it is never guessed.
    """
    parts = []
    parts.append("Accumulated policy context for this decision "
                 "(structured; operator reasoning is NOT included):")
    parts.append(("Action class", "identifier", ctx["action_class"]))

    # §4.4 applied to the AI's own input: a bounded context that presents as
    # complete is the "never head -n a set you draw a conclusion from" failure,
    # relocated into the prompt. If it was trimmed, the prompt SAYS so.
    if ctx.get("truncated"):
        parts.append("NOTE: this context was truncated; more entries matched "
                     "than are shown.")
        parts.append(("Entries matched", "number", int(ctx["matched_total"])))
        parts.append(("Entries shown", "number", int(ctx["returned_count"])))

    for e in ctx.get("learned", []):
        kind = key_kind or _KEY_KIND.get(e.get("trigger_type") or "", "identifier")
        parts.append(("Entry direction", "enum", e["direction"],
                      {"allowed": {RESTRICTIVE, PERMISSIVE}}))
        parts.append(("Entry scope", "enum", e["scope"],
                      {"allowed": {SCOPE_TRIGGER, SCOPE_CATEGORY}}))
        parts.append(("Applies to", kind, e["trigger_key"]))

    for b in ctx.get("baseline", []):
        # Vendor guidance is authored in the shipped baseline, not typed by a
        # user -- but it still arrives at runtime from a table, so it is a
        # LABEL (bounded, not scrubbed), never a LITERAL.
        parts.append(("Baseline guidance", "label", b["guidance"]))

    return parts


def review_rows(action_class=None, include_inactive=True, now=None):
    """The §4.5 review surface: "what your AI has learned".

    Shows revoked and expired entries by default — that is the point. An entry
    that has never influenced anything is clutter; one influencing decisions
    daily deserves scrutiny. Both are invisible without `use_count`.
    """
    ts = now or _now()
    conn = _conn()
    try:
        sql = ("SELECT id, created_at, action_class, trigger_type, trigger_key, "
               "direction, scope, admin_reasoning, expires_at, revoked_at, "
               "revoked_by, use_count, last_used_at, actor, suspended_at, "
               "suspended_by_version, suspension_resolved_at, "
               "suspension_resolution FROM ai_learned_context")
        params = []
        if action_class:
            sql += " WHERE action_class=?"
            params.append(action_class)
        sql += " ORDER BY id DESC"
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()

    for r in rows:
        r["suspended"] = r["suspended_at"] is not None
        r["active"] = (r["revoked_at"] is None
                       and r["suspended_at"] is None
                       and (r["expires_at"] is None or r["expires_at"] > ts))
    if not include_inactive:
        rows = [r for r in rows if r["active"]]
    return rows


def install_baseline(version, rows, *, now=None, actor=None):
    """Install a vendor baseline WHOLESALE, then suspend conflicting rows (§4.7).

    Order matters and is not arbitrary:
      1. `ai_policy_baseline` is REPLACED ENTIRELY by the new version. Local
         edits to it are impossible by construction, so there is nothing to
         clobber — which is exactly why wholesale replacement is safe here and
         would not be for `ai_learned_context`.
      2. `ai_learned_context` is NEVER touched by the update itself.
      3. Conflicts are detected NOW, at update time, and the affected learned
         rows are SUSPENDED — because discovering a conflict mid-decision means
         discovering it under time pressure, on someone else's schedule.

    Returns {"version", "installed", "suspended": [ids]}.
    """
    ts = now or _now()
    conn = _conn()
    try:
        conn.execute("DELETE FROM ai_policy_baseline")
        for r in rows:
            conn.execute(
                "INSERT INTO ai_policy_baseline(version, action_class, "
                "trigger_type, trigger_key, guidance, installed_at, tier) "
                "VALUES(?,?,?,?,?,?,?)",
                (version, r["action_class"], r["trigger_type"],
                 r["trigger_key"], r["guidance"], ts, r.get("tier")))
        conn.commit()
    finally:
        conn.close()

    suspended = []
    for c in baseline_conflicts(now=ts):
        if _suspend(c["learned_id"], version, ts):
            suspended.append(c["learned_id"])
    return {"version": version, "installed": len(rows), "suspended": suspended}


def _suspend(entry_id, version, ts):
    conn = _conn()
    try:
        cur = conn.execute(
            "UPDATE ai_learned_context SET suspended_at=?, suspended_by_version=? "
            "WHERE id=? AND suspended_at IS NULL", (ts, version, int(entry_id)))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def resolve_suspension(entry_id, resolution, resolved_by, now=None):
    """A human decides a suspended row's fate. `resolution` is 'kept' or 'revoked'.

    'kept' returns it to influence; 'revoked' retires it permanently (still
    readable — see revoke_learned). There is deliberately no automatic
    resolution: §4.7's whole point is that neither side silently wins.
    """
    if resolution not in ("kept", "revoked"):
        raise ContextWriteRejected("resolution must be 'kept' or 'revoked', got %r"
                                   % (resolution,))
    ts = now or _now()
    conn = _conn()
    try:
        cur = conn.execute(
            "UPDATE ai_learned_context SET suspended_at=NULL, "
            "suspension_resolved_at=?, suspension_resolution=? "
            "WHERE id=? AND suspended_at IS NOT NULL",
            (ts, resolution, int(entry_id)))
        conn.commit()
        n = cur.rowcount
    finally:
        conn.close()
    if n and resolution == "revoked":
        revoke_learned(entry_id, resolved_by, now=ts)
    return n


def baseline_conflicts(now=None):
    """Live learned rows a NEW baseline may contradict (§4.7).

    ⚠ THIS IS A DELIBERATE OVER-FLAG, AND SAYING SO IS THE HONEST FORM.
    `guidance` is free text, so there is no deterministic test for "contradicts".
    What is testable is COVERAGE: the new baseline now speaks to this exact
    (action_class, trigger_type, trigger_key). Flagging that for review is the
    safe direction, because a vendor baseline is sometimes issued PRECISELY
    BECAUSE the previous guidance was wrong. A precise-looking conflict test
    built on text similarity would be the semantic-matching mistake §4.2 already
    rejects, relocated.

    ⭐ ONLY PERMISSIVE ROWS ARE FLAGGED, and that asymmetry is the point.
    A restrictive learned row is strictly MORE cautious than any baseline;
    suspending it on a vendor update would LOOSEN the system in response to a
    security update, which is backwards. Same shape as §4.3: the direction of a
    change decides how much scrutiny it earns.
    """
    ts = now or _now()
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT lc.id AS learned_id, lc.action_class, lc.trigger_type, "
            "       lc.trigger_key, lc.direction, lc.admin_reasoning, "
            "       pb.id AS baseline_id, pb.guidance, pb.version "
            "FROM ai_learned_context lc "
            "JOIN ai_policy_baseline pb "
            "  ON pb.action_class = lc.action_class "
            " AND pb.trigger_type = lc.trigger_type "
            " AND pb.trigger_key  = lc.trigger_key "
            "WHERE lc.revoked_at IS NULL "
            "  AND (lc.expires_at IS NULL OR lc.expires_at > ?) "
            "  AND lc.direction = 'permissive'",
            (ts,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
