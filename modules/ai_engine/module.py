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
import uuid
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

#: How far past a call-count ceiling the engine keeps answering on a CHEAPER
#: model before it refuses outright. 2 means: up to the ceiling, full quality;
#: from the ceiling to twice it, degraded; beyond that, refuse.
#:
#: WHY DEGRADE AT ALL. Hitting the ceiling used to stop interpretation dead, and
#: a rate limit is likeliest to bind on the busiest day — exactly when the
#: findings most need explaining. A cheaper answer beats no answer, provided the
#: drop is VISIBLE (every degraded result carries `degraded: True` and the model
#: it actually used).
#:
#: WHY IT IS STILL BOUNDED. "Never stop, just get cheaper" is not a ceiling at
#: all; spend would then be limited only by inbound traffic. Set this to 1 to
#: disable degradation entirely and restore hard-stop-at-ceiling behaviour.
_RATE_DEGRADE_MULTIPLIER_DEFAULT = 2

#: The model a degraded call falls back to. Cheapest in `_MODEL_RATES`
#: ($1/$5 per MTok vs Sonnet's $3/$15). Deliberately NOT in
#: `_EFFORT_CAPABLE_MODELS`, which the call path already handles by omitting
#: `output_config` rather than failing the request.
_DEGRADED_MODEL = "claude-haiku-4-5"


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

        -- PER-CALL rows, not an hourly rollup. The old shape bucketed on
        -- UNIQUE(date, hour) with no model/cost/surface/actor, so spend could not
        -- be attributed to a FEATURE and had to be re-derived by pricing every
        -- token at the ACTIVE model's rate. That was already wrong once chat
        -- could select opus and the rate-degrade path could select haiku: three
        -- models, one assumed price. A spend CAP enforced against that figure is
        -- a cap against a fiction, which is why this had to change before the cap
        -- could be trusted.
        --
        -- The UNIQUE(date, hour) constraint is what forced a rebuild rather than
        -- a column add: it structurally permits only one row per hour.
        CREATE TABLE IF NOT EXISTS ai_usage (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            date       TEXT    NOT NULL,
            hour       INTEGER NOT NULL,
            ts         TEXT,
            call_count INTEGER NOT NULL DEFAULT 0,
            tokens_in  INTEGER NOT NULL DEFAULT 0,
            tokens_out INTEGER NOT NULL DEFAULT 0,
            model      TEXT,
            cost_usd   REAL,
            surface    TEXT,
            actor      TEXT
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

    conn.execute("""
        CREATE TABLE IF NOT EXISTS ai_authority_override (
            action_class TEXT PRIMARY KEY,
            level        INTEGER NOT NULL,
            granted_by   TEXT NOT NULL,
            granted_at   TEXT NOT NULL,
            reason       TEXT
        )
    """)
    # APPEND-ONLY history of changes to the table above. That table is
    # INSERT OR REPLACE keyed by action_class, so it holds only the CURRENT
    # grant -- raising L2 to L4 and back leaves no trace that L4 was ever held,
    # and a cleared grant leaves nothing at all. For the ladder that governs
    # UNATTENDED action, "what authority did this system hold on Tuesday" has to
    # be answerable after the fact.
    #
    # ⚠ WHY THIS EXISTS ALONGSIDE THE DASHBOARD'S audit_log ROW, NOT INSTEAD OF
    # IT. `audit_log` is a CORE unprefixed table and -- verified against the tree
    # -- no module under modules/ writes it; only dashboard.py, manage.py,
    # nemesis_fwd.py and degraded_ingest.py do. ADR 0001 is write-own / read-any,
    # so ai_engine must not write it. The dashboard routes write the central
    # trail; THIS table is the module-side guarantee that holds when the caller
    # is not the dashboard -- a script, a migration, or a future service calling
    # set_authority_override() directly still leaves a record. Neither alone
    # covers both cases, which is why both exist.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ai_authority_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ts           TEXT NOT NULL,
            action_class TEXT NOT NULL,
            event        TEXT NOT NULL,
            level        INTEGER,
            prior_level  INTEGER,
            actor        TEXT NOT NULL,
            reason       TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_auth_events_class "
                 "ON ai_authority_events(action_class, id)")
    # Requirement 1: one row per DECISION POINT, not per API call. Includes the
    # decisions where nothing happened -- an absent row would be a default value
    # that reads as "nothing to report", and the single most useful question
    # during a trial week is "did it look at this and pass, or never see it?"
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ai_decision_log (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            trace_id         TEXT NOT NULL,
            ts               TEXT NOT NULL,
            stage            TEXT NOT NULL,
            surface          TEXT NOT NULL,
            subject_key      TEXT NOT NULL,
            decision         TEXT NOT NULL,
            reason_code      TEXT NOT NULL,
            reason_detail    TEXT,
            action_class     TEXT,
            level_needed     INTEGER,
            level_granted    INTEGER,
            authority_source TEXT,
            authority_by     TEXT,
            model            TEXT,
            tokens_in        INTEGER,
            tokens_out       INTEGER,
            cost_usd         REAL,
            latency_ms       INTEGER,
            proposal_id      INTEGER,
            ticket_number    TEXT,
            actor            TEXT
        )
    """)

    # ── L4 accumulating context (DESIGN-L4-full-ai-mode-2026-08-27 §4) ────────
    # executescript, not execute: three related statements, same pattern the top
    # of this function already uses. `execute` takes exactly one.
    conn.executescript("""
        -- ── L4 accumulating context (DESIGN-L4-full-ai-mode-2026-08-27 §4) ──
        --
        -- TWO TABLES, DELIBERATELY SEPARATE. The separation is what makes §4.4's
        -- "vendor baseline and learned context are never merged" a STRUCTURAL
        -- property rather than a convention someone has to remember.
        --
        -- Vendor-authored. Replaced WHOLESALE on update (new `version`), never
        -- written by the AI or the admin -- so a baseline update has nothing to
        -- clobber, by construction rather than by merge logic.
        CREATE TABLE IF NOT EXISTS ai_policy_baseline (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            version      TEXT NOT NULL,
            action_class TEXT NOT NULL,
            trigger_type TEXT NOT NULL,
            trigger_key  TEXT NOT NULL,
            guidance     TEXT NOT NULL,
            installed_at TEXT NOT NULL,
            -- Per install TIER (§6): commercial/SMB ships more cautious than
            -- home. NULL means "applies to every tier".
            tier         TEXT
        );

        -- This install's accumulated calibration. APPEND-ONLY.
        --
        -- ⚠ NOTHING IS EVER DELETED FROM THIS TABLE. Expiry and revocation are
        -- COLUMNS, not removals (§4.4). "No longer applied" and "no longer
        -- recorded" are different states, and collapsing them would make the
        -- system's own history unauditable exactly where it matters most.
        CREATE TABLE IF NOT EXISTS ai_learned_context (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at      TEXT NOT NULL,
            -- REQUIRED. Retrieval never crosses action classes (§4.2).
            action_class    TEXT NOT NULL,
            trigger_type    TEXT NOT NULL,
            trigger_key     TEXT NOT NULL,
            direction       TEXT NOT NULL,
            scope           TEXT NOT NULL,
            -- Verbatim, required, non-empty. This is the artefact a human reads.
            admin_reasoning TEXT NOT NULL,
            source_event_id INTEGER,
            -- §4.7 SUSPENDED PENDING REVIEW. A THIRD state, deliberately not
            -- reusing revoked_at: revocation is the DISCARD path, and §4.7 says
            -- a baseline conflict must NOT discard customer calibration. A
            -- suspended row stops influencing decisions and waits for a human.
            suspended_at        TEXT,
            suspended_by_version TEXT,
            suspension_resolved_at TEXT,
            suspension_resolution  TEXT,
            -- NULL for restrictive (persists); set for permissive (§4.3).
            expires_at      TEXT,
            revoked_at      TEXT,
            revoked_by      TEXT,
            use_count       INTEGER NOT NULL DEFAULT 0,
            last_used_at    TEXT,
            actor           TEXT,

            -- ⭐ THE PAWL IS IN THE SCHEMA, WHERE IT CANNOT BE FORGOTTEN (§4.3).
            --
            -- Erosion is ASYMMETRIC: fifty individually-reasonable permissive
            -- overrides compose into a system markedly less cautious than the one
            -- approved, with no single wrong decision behind it. A restrictive
            -- entry may generalise to a category; a permissive one may NEVER --
            -- it binds to this address, this signature, this process, and nothing
            -- wider. Enforced by the DATABASE so no write path can bypass it,
            -- including one written later by someone who has not read §4.3.
            CHECK (direction IN ('restrictive', 'permissive')),
            CHECK (scope IN ('trigger', 'category')),
            CHECK (NOT (direction = 'permissive' AND scope = 'category')),
            -- A permissive entry that never expires is a category grant wearing a
            -- narrow label: it accumulates the same way, just slower.
            CHECK (direction = 'restrictive' OR expires_at IS NOT NULL),
            CHECK (length(trim(admin_reasoning)) > 0)
        );

        -- ⚠ RETRIEVAL IS ITSELF RECORDED (§4.4). Without this, "why did it decide
        -- that?" is unanswerable after the fact, and `use_count` would be a number
        -- nobody could audit. Also carries the TRUNCATION flag: a bounded
        -- retrieval that presents as complete is the "never head -n a set you draw
        -- a conclusion from" rule applied to the AI's own inputs.
        CREATE TABLE IF NOT EXISTS ai_context_retrieval (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            retrieved_at   TEXT NOT NULL,
            trace_id       TEXT,
            action_class   TEXT NOT NULL,
            trigger_type   TEXT NOT NULL,
            trigger_key    TEXT NOT NULL,
            -- Which learned rows were fed in, as a JSON id list. Empty is a
            -- VALID, SAFE outcome (baseline only) -- never an error, never
            -- filled in with a loosened match.
            learned_ids    TEXT NOT NULL,
            baseline_ids   TEXT NOT NULL,
            matched_total  INTEGER NOT NULL,
            returned_count INTEGER NOT NULL,
            truncated      INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS ix_adl_trace "
                 "ON ai_decision_log(trace_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_adl_ts ON ai_decision_log(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_adl_subject "
                 "ON ai_decision_log(surface, subject_key)")
    conn.commit()
    # Runs AFTER the CREATEs so a fresh install already has the new shape and the
    # migration is a no-op; an existing install gets rebuilt exactly once.
    _migrate_ai_usage(conn)
    conn.close()


def _migrate_ai_usage(conn) -> None:
    """Rebuild a pre-2026-08-21 `ai_usage` into the per-call shape. Idempotent.

    SQLite cannot drop a UNIQUE constraint in place, so the table is rebuilt.
    History is PRESERVED rather than discarded: each old hourly bucket becomes one
    row marked `surface='legacy_rollup'` with model/cost NULL, so it is obvious
    which rows predate attribution. Dropping the history instead would silently
    reset every spend window to zero -- the one thing a cap must never do by
    accident.
    """
    cols = {r[1] for r in conn.execute("PRAGMA table_info(ai_usage)")}
    if not cols or {"model", "cost_usd", "surface", "actor"} <= cols:
        return                      # fresh install, or already migrated
    log.warning("ai_engine: migrating ai_usage to per-call attribution")
    conn.executescript("""
        CREATE TABLE ai_usage_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL, hour INTEGER NOT NULL, ts TEXT,
            call_count INTEGER NOT NULL DEFAULT 0,
            tokens_in INTEGER NOT NULL DEFAULT 0,
            tokens_out INTEGER NOT NULL DEFAULT 0,
            model TEXT, cost_usd REAL, surface TEXT, actor TEXT
        );
        INSERT INTO ai_usage_new
            (date, hour, ts, call_count, tokens_in, tokens_out, surface)
        SELECT date, hour, NULL, call_count, tokens_in, tokens_out, 'legacy_rollup'
        FROM ai_usage;
        DROP TABLE ai_usage;
        ALTER TABLE ai_usage_new RENAME TO ai_usage;
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_usage_date ON ai_usage(date)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_usage_surface ON ai_usage(surface)")
    conn.commit()


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
    # Setting an alert's DISPOSITION (e.g. auto-ignoring a low-risk alert) is an
    # action, and it was the one the engine had been taking with no authority
    # check at all: `/api/analyze/<rule_id>` wrote `alerts.action='ignore'`
    # directly, while chat about that same alert was pinned to "you may not even
    # recommend". Two surfaces, one object, opposite permission models -- the
    # incoherence this class exists to close.
    #
    # Ceiling L2 (reversible), not higher: a disposition can be changed back, so
    # it never warrants disruptive authority. At L0 the alert simply stays
    # `pending` and a human decides; at L1 the engine may PROPOSE a disposition
    # (recorded in ai_proposals for approval); only at L2 may it set one itself.
    "alert_disposition":       L2_ACT_REVERSIBLE,
    # ADR 0019 Amendment 03 §10.3 — the AI declining ONE scheduled revert of a
    # firewall change it believes is correct. Consumed by
    # `failsafe_decision.decide()`; until this entry existed every request
    # resolved to allow_revert, which was the correct behaviour rather than a gap.
    #
    # L4 is the ceiling because this action is DEFINED as L4-only: below it the
    # class is simply not executable, and the failsafe independently refuses any
    # assertion that is not exactly L4. A lower hard ceiling here would not make
    # the design safer, it would make the capability unreachable while leaving
    # every other part of it in place — a mechanism that looks armed and cannot
    # fire.
    #
    # This is NOT the ladder granting the AI L4. `effective_ceiling()` is still
    # min(earned, hard, standing rule): the class is now PERMITTED to reach L4,
    # and reaching it still requires earned authority at L4 and no standing rule
    # narrowing it. Registering a ceiling opens a door; it does not walk through.
    "firewall_failsafe_override": L4_GOVERN,
}


#: WHY A CEILING IS WHERE IT IS -- and therefore whether a human may raise it.
#:
#: `ACTION_CLASS_CEILINGS` mixes two genuinely different things, and the comment
#: above already says so for malware_file_quarantine ("a missing-capability
#: ceiling, not a threshold choice"). Until now that distinction lived only in
#: prose, which was fine while nothing could override a ceiling. The master-
#: password override makes it load-bearing:
#:
#:   THRESHOLD  -- a judgment about how much authority is appropriate. Someone
#:                 in charge may decide to trust the engine earlier than its
#:                 track record warrants. That is their call to make.
#:   CAPABILITY -- the code cannot do the thing safely. Raising this would not
#:                 grant authority, it would grant a lie: the action still
#:                 cannot be taken back. No password creates a missing reversal.
#:
#: The original worked example here was file restore -- "no password creates a
#: file-restore path". That example EXPIRED on 2026-08-30, when the restore path
#: and its undo handler were built and `malware_file_quarantine` became a
#: threshold. Kept in the record because it is the clearest illustration of the
#: distinction, and because it demonstrates the intended lifecycle: a capability
#: ceiling is a statement of fact about the code, so it is expected to be
#: RETIRED when the code changes, not defended. No entry in this map is
#: currently "capability"; that is the correct state, not an oversight.
#:
#: Only THRESHOLD ceilings are overridable. This is the same principle as the
#: undo-handler gate in `execute_proposal` -- authentication establishes WHO you
#: are, never what the code is capable of.
CEILING_KIND = {
    "ip_quarantine_external":  "threshold",
    "ip_block_permanent":      "threshold",
    "ip_action_internal":      "threshold",
    # WAS "capability", pinned by a MISSING RESTORE PATH. Both conditions the
    # old comment named -- "a restore function and an undo handler" -- were met
    # on 2026-08-30: `malware_detection._restore_file()` and the
    # `_undo_file_quarantine` handler it registers. The label is therefore now
    # THRESHOLD, because "capability" would assert the code cannot reverse this,
    # which is false, and a false entry here is worse than a missing one --
    # `ceiling_kind()` treats missing as restrictive, but a wrong "capability"
    # silently makes a real capability unreachable.
    #
    # ⚠ THIS CHANGED THE LABEL, NOT THE LEVEL. `ACTION_CLASS_CEILINGS` keeps
    # this class at L1_RECOMMEND deliberately. Flipping the kind makes the
    # ceiling OVERRIDABLE by someone in charge; it does not grant authority, and
    # nothing acts differently until a human raises it on purpose.
    #
    # ⚠ AND THE REVERSAL IS CONDITIONAL, which no other threshold class here is.
    # `_restore_file()` refuses when the original path has been re-occupied,
    # when its parent directory is gone, or when the row predates mode capture.
    # Every other reversible class in this map can always be taken back; this
    # one usually can. That is the specific fact to weigh before raising the
    # hard ceiling, and it is why raising it was deliberately left as its own
    # decision rather than folded into this correction.
    "malware_file_quarantine": "threshold",
    "alert_disposition":       "threshold",
    # THRESHOLD, and the reasoning matters because at L4 the label looks vacuous.
    #
    # It is a threshold in the exact sense this map means: a judgment about how
    # much authority is appropriate, not a limit on what the code can do. The
    # code CAN take this action and CAN undo it — the revert timer is still
    # armed, the change is still reversible, and §10.6 bounds the override to a
    # single event. Labelling it "capability" would assert the code cannot do it
    # safely, which is simply false, and false entries here are worse than
    # missing ones because `ceiling_kind()` treats missing as restrictive.
    #
    # Being overridable is vacuous at L4 anyway: the ceiling is already the top
    # of the ladder and min() cannot exceed any input, so there is nothing a
    # master password could raise it to. The honest label costs nothing and the
    # dishonest one would mislead the next reader.
    "firewall_failsafe_override": "threshold",
}


#: Classes whose action is carried out OUTSIDE `execute_proposal`.
#:
#: `automation_readiness` and the warning text both model one execution path --
#: propose, approve, execute_proposal -- and that model is correct for every class
#: that uses it. `firewall_failsafe_override` does not: the engine returns a
#: decision and a separate privileged component acts on it, so the undo-handler
#: gate in execute_proposal is never reached.
#:
#: ⚠ WITHOUT THIS SET THE READINESS MODEL IS WRONG IN THE DANGEROUS DIRECTION.
#: It reported will_act=False and the warning said the engine "will REFUSE to act
#: on it even at this level" -- for a class that DOES act. An operator granting L4
#: and reading that could reasonably conclude nothing can happen, which is the
#: exact inversion of the mistake automation_readiness was built to prevent
#: (someone believing automation is live when it is inert). Found by Window 3's
#: §5 A/B run, 2026-08-27.
#:
#: MEMBERSHIP IS NOT AN EXEMPTION FROM REVERSIBILITY. These classes must still be
#: reversible; they simply prove it somewhere other than an undo handler. For
#: firewall_failsafe_override the change stays provisional -- `nemesis-fw-apply
#: revert-now`, the standalone revert endpoint, and the console command all undo
#: it -- and its safety gate is disclosure-as-precondition, not undo registration.
#:
#: ⛔ DO NOT "FIX" THIS BY REGISTERING AN UNDO HANDLER. Registering one would make
#: the class eligible for execute_proposal, which has NO disclosure precondition --
#: creating a second route to an override that bypasses the guarantee the whole
#: mechanism rests on. The handler would also need a privileged revert path the
#: engine deliberately does not have (the dashboard runs as nemesis-dash with zero
#: sudo, and the one privileged revert is token-scoped and single-use by design).
EXTERNALLY_EXECUTED = {"firewall_failsafe_override"}


def ceiling_kind(action_class: str) -> str:
    """'threshold' | 'capability'. Unknown classes are treated as CAPABILITY.

    Defaulting to the RESTRICTIVE answer on purpose: a class someone forgot to
    classify must not silently become overridable. A missing entry is a gap in
    our knowledge, and a gap in knowledge is not permission.
    """
    return CEILING_KIND.get(action_class, "capability")


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

    # A manual override raises `earned` and, for THRESHOLD classes only, the hard
    # ceiling too. It never touches `clamp` (the user's own standing rule -- you
    # edit the rule, you do not out-authenticate yourself) and never touches the
    # spend cap, which is enforced separately and deliberately stays absolute:
    # a flood limit a password can lift is not a flood limit.
    override = _authority_override(action_class)
    ov_level = override["level"] if override else None
    effective_hard = hard
    if ov_level is not None:
        earned = max(earned, ov_level)
        if ceiling_kind(action_class) == "threshold":
            effective_hard = max(hard, ov_level)

    level = _combine_ceiling(earned, effective_hard, clamp)

    reasons = []
    if ov_level is not None:
        reasons.append("manual_override")
        if ceiling_kind(action_class) == "capability" and ov_level > hard:
            # The override was accepted but CANNOT lift this class. Say so, or
            # the UI shows a raised toggle and the engine quietly does nothing.
            reasons.append("capability_ceiling_not_overridable")
    hard = effective_hard
    if level == clamp and clamp < min(earned, hard):
        reasons.append("standing_rule")
    if level == hard and hard < min(earned, clamp):
        reasons.append("hard_ceiling")
    if level == earned and earned < min(hard, clamp):
        reasons.append("not_yet_earned")
    if not reasons:
        reasons.append("unconstrained" if level == L4_GOVERN else "tied")

    return {
        "level":            level,
        "earned":           earned,
        "hard_ceiling":     hard,
        "rule_clamp":       clamp,
        "rule_types":       rule_types,
        "reasons":          reasons,
        # PROVENANCE. Requirement-1 logging needs to distinguish "the ladder
        # promoted this" from "someone typed the master password at 2am"; a
        # level with no origin recorded cannot be audited after the fact.
        "authority_source": "override" if ov_level is not None else "earned",
        "override_by":      (override or {}).get("granted_by"),
        "override_at":      (override or {}).get("granted_at"),
        "ceiling_kind":     ceiling_kind(action_class),
        "undo_available":   undo_handler_for(action_class) is not None,
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


def _diagnostics_capability_note() -> str:
    """The appliance's own diagnostic checks, enumerated AT RUNTIME.

    Deliberately dynamic rather than a list written into the prompt. A hardcoded
    list goes stale silently and in the worse direction: a check added later would
    never be mentioned, and one renamed or removed would have the assistant sending
    a non-technical user to a button that is not there -- which reads as
    authoritative and is worse than saying nothing. Enumerating means a new check
    is picked up with no prompt edit, which is the whole point.

    Returns "" on ANY failure. That is a real answer here, not a default dressed up
    as one: the caller's wording already covers the generic case ("prefer this
    appliance's own diagnostics where they fit"), so an empty note degrades to
    generic-but-true guidance instead of naming tools that may not exist. Reading
    the beginner description deliberately -- this text exists to help someone with
    no IT background, and the pro variant would defeat that.
    """
    try:
        import diagnostics as _diag
        lines = []
        for chk in getattr(_diag, "CHECKS", []):
            meta = getattr(chk, "META", None) or {}
            cid, name = meta.get("id"), meta.get("name")
            if not cid or not name:
                continue
            desc = meta.get("descriptions")
            blurb = desc.get("beginner", "") if isinstance(desc, dict) else ""
            blurb = " ".join(str(blurb).split())
            lines.append(f"- {name} ({cid})" + (f": {blurb}" if blurb else ""))
        if not lines:
            return ""
        return (
            "\n\nDIAGNOSTIC CHECKS BUILT INTO THIS APPLIANCE. The person can run any "
            "of these from the Diagnostics page without installing anything, and each "
            "is read-only. Point them at one by name when it would answer their "
            "question, and say what in the output to look at:\n" + "\n".join(lines)
        )
    except Exception:
        log.debug("chat: diagnostics capability note unavailable", exc_info=True)
        return ""


def _chat_system_prompt(scope: dict) -> str:
    """The ONE place chat scope is enforced.

    Written once, here, rather than per surface: the scope boundary is a safety
    property, and a property enforced in six places is enforced in none.
    """
    base = (
        "You are the security assistant built into a Nemesis firewall appliance. "
        "You are explaining a specific finding to the person who owns this network, "
        "who may have no IT background. Be concrete, plain-spoken and reassuring: "
        "most findings are routine, and someone asking about one deserves a clear "
        "answer rather than a hedge.\n\n"
        # Two standards, not one. The single old rule ("answer only from the finding
        # data") was written against hallucination and did stop it -- but it also
        # stopped the assistant bringing the general knowledge that makes it useful,
        # so it answered "I cannot tell from this alert" to questions that were not
        # about the alert's contents at all. Splitting the standards keeps the
        # anti-hallucination guarantee exactly where it belongs (claims about THIS
        # network) without gagging the part a non-expert actually needs.
        "Two kinds of statement, held to different standards:\n"
        "- FACTS ABOUT THIS NETWORK (what this alert saw, which host, how often, "
        "what action was taken) come only from the finding data below. If a detail "
        "is not there, say so plainly and name what you would need — never guess "
        "or infer it.\n"
        "- GENERAL SECURITY KNOWLEDGE RELEVANT TO INVESTIGATING OR UNDERSTANDING "
        "THIS FINDING (what this class of signature usually means, how someone "
        "would check it, what a given tool would show) is yours to bring, and you "
        "are expected to use it. \"I cannot tell from the data\" applies to the "
        "first kind, not the second. Keep it to what bears on this finding — you "
        "are not a general security tutor.\n\n"
        "HELPING THEM INVESTIGATE. When they ask how to check something, help them: "
        "name the read-only commands or checks that would answer the question, say "
        "what output to look for, and explain how to read it. Prefer this "
        "appliance's own diagnostics where they fit — already installed, already "
        "safe to run.\n\n"
        # The restriction that makes the loosening above safe. Read-only is the
        # boundary the whole change rests on, so it is stated as a hard rule rather
        # than left implied by "investigate".
        "ONLY EVER SUGGEST COMMANDS THAT READ STATE. Never suggest a command that "
        "changes configuration, kills a process, modifies firewall rules, or "
        "deletes anything. If the answer requires a change, describe what needs to "
        "change and let them decide how.\n\n"
    )
    if scope["level"] <= L0_OBSERVE:
        rules = (
            "SCOPE: You explain what this finding means, why it matters, and how to "
            "investigate it. You do NOT recommend changes to the network or firewall, "
            "and you do NOT offer to take any action yourself. Read-only "
            "investigation is not a change — suggesting a diagnostic command or "
            "check that the person runs and interprets is expected of you, and is "
            "not the same as recommending a configuration change. If asked what to "
            "DO about the finding, explain the trade-offs of the options that exist "
            "and say the decision is theirs to make."
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
    # Appended AFTER the scope rules, and at every level: read-only investigation is
    # deliberately not gated on action authority, so a degraded or L0 scope still
    # gets the check list. Empty string when it cannot be enumerated -- see
    # _diagnostics_capability_note().
    return base + rules + _diagnostics_capability_note()


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
        # ── THE ONE NPFA/1 EXEMPTION (see prompt_fields.py and ADR 0025) ──
        # A follow-up question is text a human deliberately typed -- often pasted
        # command output, which is what the 4000-char limit exists for. No
        # allowlist can express "whatever the operator decided to type", so
        # forcing one here would DELETE this feature rather than tighten it.
        #
        # This is consented disclosure, not silent disclosure: the operator is
        # composing a message in a chat widget with a visible cost estimate. The
        # pseudonymization chokepoint still scrubs addresses and known device
        # names from it. The residual -- an UNKNOWN name inside text the operator
        # chose to send -- is disclosed in the product privacy notice.
        #
        # This must remain the ONLY caller passing this argument. ADR 0025 §6
        # is the conformance list; a test asserts the count.
        free_text_reason="operator-authored follow-up question (chat surface)",
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
        import notify as _notify
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
        # LOW: pricing drift is a "look at this when convenient" notice -- nothing
        # is charged differently and nothing has changed automatically, which the
        # body says explicitly. It is exactly the class the digest exists for.
        #
        # The family key is the drift signature, so repeated detections of the SAME
        # drift collapse to one digest line. Note this is belt-and-braces: the
        # `_DRIFT_NOTIFIED_KEY` guard below already suppresses a repeat of an
        # identical signature, so in practice the family rarely bundles. Set anyway
        # because the two guards protect different things -- that one stops the
        # notice recurring at all, this one groups it if the guard is ever relaxed.
        _notify.notify("LOW", "[Nemesis] Anthropic pricing has changed",
                       "\n".join(body), family_key="ai-pricing-drift:%s" % sig,
                       actor="system:ai_engine")
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


#: Default rolling window for the spend ceiling, in days. 30 preserves the old
#: month-ish behaviour for anyone who never changes it; a trial can set 7.
_SPEND_WINDOW_DAYS_DEFAULT = 30


def get_spend_this_month() -> dict:
    """Calendar-month spend. Kept for existing callers; now RECORDED-cost based.

    Superseded by `get_spend(window_days)`, which is what the ceiling enforces --
    a rolling window expresses "no more than $X per week" naturally, where a
    calendar month cannot. This is retained because callers exist, but it no
    longer re-prices every token at the active model's rate: that produced a
    plausible wrong number once more than one model was in play.
    """
    month = datetime.now().strftime("%Y-%m")
    pricing = get_pricing()
    try:
        conn = _conn()
        row = conn.execute(
            "SELECT COALESCE(SUM(cost_usd),0), "
            "       COALESCE(SUM(CASE WHEN cost_usd IS NULL THEN tokens_in  ELSE 0 END),0), "
            "       COALESCE(SUM(CASE WHEN cost_usd IS NULL THEN tokens_out ELSE 0 END),0), "
            "       SUM(CASE WHEN cost_usd IS NULL THEN 1 ELSE 0 END) "
            "FROM ai_usage WHERE substr(COALESCE(ts, date),1,7)=?", (month,)).fetchone()
        conn.close()
        priced = float(row[0] or 0.0)
        est = (int(row[1]) * pricing["input_per_mtok"] / 1_000_000
               + int(row[2]) * pricing["output_per_mtok"] / 1_000_000)
        return {"ok": True, "usd": round(priced + est, 6), "month": month,
                "recorded_usd": round(priced, 6),
                "estimated_usd": round(est, 6),
                "unpriced_rows": int(row[3] or 0)}
    except Exception as exc:                                 # noqa: BLE001
        log.exception("ai_engine: get_spend_this_month failed")
        return {"ok": False, "error": str(exc)[:200], "month": month}


def get_spend_stop() -> dict:
    """Is the engine currently STOPPED on the spend ceiling, and since when.

    Exists so the halt is REPORTABLE rather than merely enforced. An engine that
    silently stops answering is indistinguishable from a broken one; this is what
    lets a badge, an API or a report say "stopped on 2026-08-21 at $10.03 of
    $10.00" instead of leaving the operator to guess.
    """
    cap = _spend_cap_usd()
    active = (_get_setting("spend_stop_active", "0") or "0") == "1"
    # NO CEILING MEANS NOT STOPPED, whatever the stored flag says. The flag is a
    # latch set at the moment of crossing, and removing the ceiling entirely used
    # to leave it set forever -- the engine then reported "Stopped: spend ceiling
    # of $0.00" while happily answering, which is both false and unfixable from
    # the UI. Derived state wins over a stale latch.
    if cap is None:
        active = False
    out = {"stopped": active, "cap_usd": cap,
           "window_days": _spend_window_days()}
    if active:
        out["since"] = _get_setting("spend_stop_at", "") or None
        try:
            out["usd_at_stop"] = float(_get_setting("spend_stop_usd", "0") or 0)
        except (TypeError, ValueError):
            out["usd_at_stop"] = None
    return out


def clear_spend_stop(actor: str | None = None) -> None:
    """Manually clear the stopped flag (e.g. after raising the ceiling).

    The flag also clears itself on the next call once spend is back under the
    ceiling; this is for an operator who wants the reported state corrected
    immediately rather than at the next attempt.
    """
    _set_setting("spend_stop_active", "0")
    log.warning("ai_engine: spend stop cleared by %s", actor or "unknown")


def _spend_cap_usd() -> float | None:
    """The configured spend ceiling in dollars, or None when unset/unusable.

    TWO SETTINGS, ONE MEANING, resolved oldest-last:
      `spend_cap_usd`          -- the ceiling (the setting users see)
      `spend_cap_monthly_usd`  -- the previous name, still honoured so an existing
                                  install does not silently lose its cap on upgrade

    Unset AND unparseable both mean "no cap". A garbage value must never be read
    as a cap of ZERO, which would block every call and read as a broken engine
    rather than a typo in a setting.
    """
    for key in ("spend_cap_usd", "spend_cap_monthly_usd"):
        raw = (_get_setting(key, "") or "").strip()
        if not raw:
            continue
        try:
            val = float(raw)
        except (ValueError, TypeError):
            log.warning("ai_engine: %s=%r is not a number - treating as no cap",
                        key, raw)
            return None
        return val if val > 0 else None
    return None


def _spend_window_days() -> int:
    """Rolling window the ceiling is measured over. Always >= 1."""
    raw = (_get_setting("spend_cap_window_days",
                        str(_SPEND_WINDOW_DAYS_DEFAULT)) or "").strip()
    try:
        return max(1, int(float(raw)))
    except (ValueError, TypeError):
        return _SPEND_WINDOW_DAYS_DEFAULT


def get_spend(window_days: int | None = None) -> dict:
    """Recorded spend over a ROLLING window, in dollars.

    Sums the `cost_usd` RECORDED on each call -- the price of the model that was
    actually billed. It no longer re-prices tokens at the active model's rate,
    which was wrong the moment chat could pick opus and the degrade path could
    pick haiku.

    ROWS WITH NO RECORDED PRICE ARE COUNTED SEPARATELY AND SAID OUT LOUD.
    Legacy rollup rows (pre-attribution) and any call whose model had no known
    rate carry cost_usd NULL. Their tokens are still priced, at the active rate,
    as the best available estimate -- but `unpriced_rows` reports how many, so a
    figure resting on estimates is never mistaken for a figure resting on
    receipts. Silently folding them in at an assumed price is exactly the fiction
    this rewrite exists to remove.

    Returns ok=False with NO figure on failure; a caller must not read a missing
    spend as zero (see `_check_rate_limit`, which fails closed on it).
    """
    days = window_days or _spend_window_days()
    since_date = (datetime.now() - timedelta(days=days)).isoformat()[:10]
    pricing = get_pricing()
    try:
        conn = _conn()
        # ts is NULL on migrated legacy rows, so the window is matched on `date`
        # too -- otherwise upgrading would drop all history out of the window and
        # reset the cap to zero, which is the dangerous direction.
        row = conn.execute(
            "SELECT COALESCE(SUM(cost_usd),0), "
            "       COALESCE(SUM(CASE WHEN cost_usd IS NULL THEN tokens_in  ELSE 0 END),0), "
            "       COALESCE(SUM(CASE WHEN cost_usd IS NULL THEN tokens_out ELSE 0 END),0), "
            "       SUM(CASE WHEN cost_usd IS NULL THEN 1 ELSE 0 END), "
            "       COUNT(*) "
            "FROM ai_usage WHERE COALESCE(ts, date) >= ?",
            (since_date,)).fetchone()
        conn.close()
        priced = float(row[0] or 0.0)
        est = (int(row[1]) * pricing["input_per_mtok"] / 1_000_000
               + int(row[2]) * pricing["output_per_mtok"] / 1_000_000)
        return {"ok": True, "usd": round(priced + est, 6),
                "recorded_usd": round(priced, 6),
                "estimated_usd": round(est, 6),
                "unpriced_rows": int(row[3] or 0), "rows": int(row[4] or 0),
                "window_days": days, "since": since_date}
    except Exception as exc:                                 # noqa: BLE001
        log.exception("ai_engine: get_spend failed")
        return {"ok": False, "error": str(exc)[:200], "window_days": days}


def get_spend_by_surface(window_days: int | None = None) -> list:
    """[(surface, calls, usd)] over the window, dearest first.

    The whole point of the attribution columns: "what is costing money" is a
    question the product could not answer at all before.
    """
    days = window_days or _spend_window_days()
    since_date = (datetime.now() - timedelta(days=days)).isoformat()[:10]
    try:
        conn = _conn()
        rows = conn.execute(
            "SELECT COALESCE(surface,'unattributed'), COUNT(*), "
            "       COALESCE(SUM(cost_usd),0) "
            "FROM ai_usage WHERE COALESCE(ts, date) >= ? "
            "GROUP BY 1 ORDER BY 3 DESC", (since_date,)).fetchall()
        conn.close()
        return [(r[0], int(r[1]), round(float(r[2] or 0.0), 6)) for r in rows]
    except Exception:                                        # noqa: BLE001
        log.exception("ai_engine: get_spend_by_surface failed")
        return []


#: Device-name cache for the pseudonymization chokepoint. A fleet's names change
#: on the order of days; re-reading two tables on every AI call would be pure
#: overhead. Short enough that a rename is picked up within the same session.
# NPFA/1: the allowlist lives in alert_manager/ (same path situation as
# nemesis_pseudonymize -- see the chokepoint below for why the insert is needed).
def _load_prompt_fields():
    import sys as _s, os as _o
    _a = _o.path.join(
        _o.path.dirname(_o.path.dirname(_o.path.dirname(_o.path.abspath(__file__)))),
        "alert_manager")
    if _a not in _s.path:
        _s.path.insert(0, _a)
    import prompt_fields as _pf
    return _pf


_prompt_fields = _load_prompt_fields()


_NAMES_TTL_S = 300.0
_names_cache: tuple = (0.0, ())
_names_lock = threading.Lock()


def _known_device_names() -> tuple:
    """Every device/host name this deployment knows, for pseudonymization.

    RAISES on failure -- deliberately, and the caller (the chokepoint) turns that
    into a BLOCKED call. Returning an empty tuple instead would be the classic
    failed-read-as-legal-value: "no names to scrub" and "the name lookup broke"
    would become indistinguishable, and the second one silently puts real
    customer device names on the wire while the product claims they are
    pseudonymized. An outage is recoverable; that claim being false is not.
    """
    global _names_cache
    now = time.time()
    with _names_lock:
        stamp, cached = _names_cache
        if cached and (now - stamp) < _NAMES_TTL_S:
            return cached

    names = set()
    conn = _conn()
    try:
        for table, cols in (("devices", ("friendly_name", "hostname")),
                            ("agent_devices", ("device_name",))):
            have = {r[1] for r in conn.execute("PRAGMA table_info(%s)" % table)}
            wanted = [c for c in cols if c in have]
            if not wanted:
                # The table exists but not the column: schema drift, not an
                # empty fleet. Skip THIS source rather than failing the whole
                # call -- the other source still yields real coverage.
                continue
            rows = conn.execute(
                "SELECT %s FROM %s" % (", ".join(wanted), table)).fetchall()
            for row in rows:
                for value in row:
                    if value:
                        names.add(str(value))
    finally:
        try:
            conn.close()
        except Exception:                                        # noqa: BLE001
            pass

    result = tuple(sorted(names))
    with _names_lock:
        _names_cache = (now, result)
    return result


def _check_rate_limit(conn) -> tuple:
    """Return (is_limited: bool, reason: str, kind: str).

    `kind` is the whole point of this function's shape, so read it before
    changing anything here:

      ""        not limited.
      "degrade" the CALL-COUNT ceiling is reached but the hard ceiling is not.
                The caller should still answer, on a cheaper model. Interpretation
                continues; quality drops, visibly.
      "hard"    refuse. Either the call count is past the hard ceiling, or a
                MONEY limit was hit.

    WHY THROUGHPUT AND MONEY DEGRADE DIFFERENTLY. `rate_per_hour`/`rate_per_day`
    bound how CHATTY the engine is; `spend_cap_monthly_usd` bounds what it may
    COST. Falling back to a cheaper model is a real answer to the first and no
    answer at all to the second — a cap the engine can route around is not a cap.
    So money limits are never degradable, and that asymmetry is deliberate.

    THE DEGRADED BAND IS BOUNDED. Degradation is allowed between the ceiling and
    `ceiling * rate_degrade_multiplier`, then it becomes "hard". Without that
    upper bound "degrade instead of stopping" would remove the ceiling
    altogether and spend would be limited only by traffic — the opposite of what
    a rate limit is for. Setting the multiplier to 1 disables degradation and
    restores the previous hard-stop-at-ceiling behaviour exactly.

    ⚠ THREE-TUPLE, and callers unpack it positionally. All three call sites
    (`get_status`, `_analyze_inner`, and anomaly_detection's
    `_is_currently_rate_limited`) were updated together. `limited` stays True for
    BOTH "degrade" and "hard" so any caller that only looks at the flag keeps its
    conservative reading.
    """
    rate_h = int(_get_setting("rate_per_hour", str(_RATE_HOUR_DEFAULT)))
    rate_d = int(_get_setting("rate_per_day",  str(_RATE_DAY_DEFAULT)))
    try:
        mult = float(_get_setting("rate_degrade_multiplier",
                                  str(_RATE_DEGRADE_MULTIPLIER_DEFAULT)))
    except (TypeError, ValueError):
        mult = _RATE_DEGRADE_MULTIPLIER_DEFAULT
    if mult < 1:
        mult = 1.0
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
        _kind = "hard" if h_count >= rate_h * mult else "degrade"
        return True, f"{h_count}/{rate_h} per hour ({reset_str})", _kind

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
        _kind = "hard" if d_count >= rate_d * mult else "degrade"
        return True, f"{d_count}/{rate_d} per day ({reset_str})", _kind

    # Dollar cap. Checked last so the cheaper call-count checks short-circuit
    # first, and so its reason is the one surfaced when it is the binding limit.
    #
    # Call count is a poor proxy for spend and is getting worse: per-model rates
    # differ ~10x, and any surface where the user controls prompt size makes ten
    # calls anywhere from cents to dollars. This is the control a user actually
    # means by "don't spend more than $X".
    cap = _spend_cap_usd()
    if cap is not None:
        spend = get_spend()
        if not spend.get("ok"):
            # FAIL CLOSED, but only because a cap was explicitly requested.
            # The point of a cap is protecting money: if we cannot tell whether
            # the user is over it, allowing unlimited spend defeats it entirely.
            # Blocking is recoverable — the reason is visible and the cap can be
            # raised or cleared; an unnoticed overspend is not. When NO cap is
            # set, this branch never runs, so a broken read cannot block a user
            # who never asked for the protection.
            return True, ("monthly spend cannot be read, and a spend cap is set "
                          "— refusing rather than risk exceeding it"), "hard"
        usd = spend.get("usd") or 0.0
        if usd >= cap:
            # RECORD THE STOP so it is reportable, not just refused. A cap that
            # halts the engine silently is indistinguishable from an engine that
            # is broken -- the operator needs to be able to see WHY it went quiet,
            # and when. Written once per crossing (the value only changes when the
            # spend does), and cleared by `clear_spend_stop()` when the cap is
            # raised or the window rolls past it.
            try:
                _set_setting("spend_stop_active", "1")
                _set_setting("spend_stop_at", datetime.now().isoformat(timespec="seconds"))
                _set_setting("spend_stop_usd", "%.6f" % usd)
                _set_setting("spend_stop_cap", "%.6f" % cap)
            except Exception:                                # noqa: BLE001
                log.exception("ai_engine: could not record the spend-stop state")
            return True, (f"spend cap reached: ${usd:.2f} of ${cap:.2f} "
                          f"over the last {spend.get('window_days')}d"), "hard"
        if (_get_setting("spend_stop_active", "0") or "0") == "1":
            # Back under the ceiling (cap raised, or the rolling window moved on).
            # Clearing it here means the reported state follows reality instead of
            # latching on forever after one crossing.
            try:
                _set_setting("spend_stop_active", "0")
                log.warning("ai_engine: spend ceiling no longer exceeded "
                            "($%.2f of $%.2f) - resuming", usd, cap)
            except Exception:                                # noqa: BLE001
                pass

    return False, "", ""


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


#: Maps a job_id/cache_key prefix onto the FEATURE that spent the money. Derived
#: rather than demanded from callers so attribution works for every existing call
#: site immediately; `analyze(surface=...)` overrides it when a caller knows better.
_SURFACE_PREFIXES = (
    ("chat:", "chat"),
    ("alert_", "alert_verdict"),
    ("malware_verdict_", "malware_verdict"),
    ("cq:", "community_queue"),
)


def _derive_surface(job_id, cache_key):
    """Best-effort feature name for a call, or 'unattributed'.

    'unattributed' is deliberately a REAL value rather than NULL: a NULL would be
    indistinguishable from a legacy row, and the whole point of this column is
    being able to say which feature spent what. A growing 'unattributed' total is
    a visible prompt to add a prefix here, not a silent gap.
    """
    for key in (job_id or "", cache_key or ""):
        for prefix, name in _SURFACE_PREFIXES:
            if key.startswith(prefix):
                return name
    return "unattributed"


def _current_actor():
    """Whoever the Data Manager says is acting, or None. Never raises."""
    try:
        from modules import get_data_manager
        return get_data_manager().current_actor()
    except Exception:                                        # noqa: BLE001
        return None


def _increment_usage(conn, tokens_in: int, tokens_out: int, model=None,
                     cost_usd=None, surface=None, actor=None) -> None:
    """Record ONE call. Per-row, not an hourly rollup -- see the schema comment.

    `cost_usd` is RECORDED, not re-derived later, because the model that was
    actually billed is knowable now and unknowable afterwards. A NULL here means
    the price could not be determined (unknown model), which `_spend_since`
    reports as a distinct, visible condition rather than treating as zero.
    """
    now = datetime.now()
    conn.execute(
        """INSERT INTO ai_usage(date, hour, ts, call_count, tokens_in, tokens_out,
                                model, cost_usd, surface, actor)
           VALUES(?, ?, ?, 1, ?, ?, ?, ?, ?, ?)""",
        (now.strftime("%Y-%m-%d"), now.hour, now.isoformat(timespec="seconds"),
         tokens_in, tokens_out, model, cost_usd, surface, actor)
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
        limited, reason, kind = _check_rate_limit(conn)
        conn.close()
        # "Degraded" is a THIRD state and is reported as one. Calling it plain
        # "Rate limited" would tell the operator interpretation had stopped when
        # it is still running, just cheaper — and the badge is the one place they
        # look to find that out.
        # SPEND-STOPPED is its own state, ahead of the generic rate wording.
        # "Rate limited" implies "wait and it resumes"; a spend ceiling does not
        # resume until the window rolls or the ceiling is raised, and telling the
        # operator the wrong one sends them to the wrong fix.
        stop = get_spend_stop()
        if stop.get("stopped"):
            detail = ("Stopped: spend ceiling of $%.2f reached over %sd"
                      % (stop.get("cap_usd") or 0.0, stop.get("window_days")))
            state = "spend_capped"
        elif limited and kind == "degrade":
            detail = f"Degraded (cheaper model): {reason}"
            state = "active"
        elif limited:
            detail = f"Rate limited: {reason}"
            state = "active"
        else:
            detail = "Ready"
            state = "active"
        return {"state": state, "enabled": True, "has_key": True,
                "key_valid": True, "detail": detail,
                "spend_stop": stop}
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


#: Anthropic model IDs come in two forms: the rolling alias (`claude-haiku-4-5`)
#: and the dated snapshot (`claude-haiku-4-5-20251001`). `_MODEL_RATES` is keyed
#: by alias, and the lookup was exact-string — so a dated ID priced at NOTHING
#: and the call's cost silently moved from the RECORDED bucket into the ESTIMATED
#: one. That distinction is the entire basis of the spend ceiling: a cap enforced
#: against a figure that has quietly become a guess is a cap against a fiction.
#: Nothing passes a dated ID today; the degrade path is where one would plausibly
#: get pinned later, and the failure would be invisible at the moment it started.
_DATED_MODEL_RE = re.compile(r"^(.*?)-(\d{8})$")


def _pricing_alias(model_id: str) -> str:
    """Strip a trailing -YYYYMMDD snapshot suffix to get the rolling alias.

    Returns the input unchanged when it is not a dated ID, so a genuinely unknown
    model stays unknown and still reports `known: False` rather than being
    coerced into some neighbouring model's price.
    """
    m = _DATED_MODEL_RE.match(model_id or "")
    return m.group(1) if m else (model_id or "")


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
    rates = _MODEL_RATES.get(target) or _MODEL_RATES.get(_pricing_alias(target))

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
        # The header doubles as the DRAG HANDLE once unpinned, hence the id.
        # Unpin/Pin-back are two buttons rather than one toggle: a single button
        # whose meaning depends on state has to be read before it can be used,
        # and only one of these is ever visible at a time anyway.
        '<div id="nemChatHeader" style="display:flex;'
        'justify-content:space-between;align-items:center;'
        'margin-bottom:8px;gap:8px">'
        '<strong style="color:#00d4ff;font-size:0.95em">Ask about this finding</strong>'
        '<span style="display:flex;align-items:center;gap:8px">'
        '<span id="nemChatTurnsLeft" style="font-size:0.78em;color:#888"></span>'
        '<button id="nemChatUnpinBtn" onclick="nemChatUnpin()" '
        'title="Detach into a movable, resizable panel" '
        'style="background:transparent;color:#9fb3d1;border:1px solid #2a3f5f;'
        'padding:2px 8px;border-radius:3px;cursor:pointer;font-size:0.75em">'
        '&#9744; Unpin</button>'
        '<button id="nemChatRepinBtn" onclick="nemChatRepin()" '
        'title="Put the panel back inline" '
        'style="display:none;background:transparent;color:#9fb3d1;'
        'border:1px solid #2a3f5f;padding:2px 8px;border-radius:3px;'
        'cursor:pointer;font-size:0.75em">&#9635; Pin back</button>'
        '</span>'
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
        # Enter submits, Shift+Enter inserts a newline -- standard chat-input
        # behaviour. Bound HERE, inside the one branch that actually creates the
        # node, so it attaches exactly once no matter how often ensureWidget()
        # is called (it early-returns above when the node already exists).
        #
        # Gated on the Ask button's OWN disabled state rather than re-deriving
        # the conditions: that flag already covers both "out of turns"
        # (meta() sets it from turns_left) and "a request is in flight"
        # (nemChatAsk disables it on entry). So Enter can never spend a turn the
        # button itself would have refused, and cannot double-submit.
        #
        # isComposing is checked so Enter that is committing an IME candidate
        # (CJK input) does not fire a question mid-word.
        'var _inp=el("nemChatInput");'
        'if(_inp){_inp.addEventListener("keydown",function(e){'
        'if(e.key==="Enter"&&!e.shiftKey&&!e.isComposing){'
        'e.preventDefault();'
        'var b=el("nemChatAskBtn");'
        'if(b&&!b.disabled&&window.nemChatAsk)window.nemChatAsk();'
        '}});}'
        # ── Drag, resize-persist and viewport-clamp ──────────────────────────
        # Bound HERE for the same reason the Enter handler above is: this is the
        # single branch that creates the node, so these attach exactly once no
        # matter how often ensureWidget() is called.
        #
        # Pointer events, not mouse events: one code path covers mouse, touch and
        # pen. setPointerCapture keeps the drag alive when the cursor outruns the
        # header -- without it a fast drag drops the panel mid-motion.
        #
        # FLOAT is a `var` declared further down and is therefore UNDEFINED at the
        # moment ensureWidget() first runs. That is safe and deliberate: only the
        # handler BODIES read it, and they run on user interaction long after the
        # IIFE has finished. `!FLOAT` on undefined is also correctly falsy, so a
        # drag before the first unpin is ignored rather than throwing.
        'var _hdr=el("nemChatHeader");'
        'if(_hdr&&window.PointerEvent){'
        '_hdr.addEventListener("pointerdown",function(e){'
        'if(!FLOAT)return;'
        # Let the header's own buttons work: a pointerdown on Pin back must not
        # start a drag, or the button never receives its click.
        'if(e.target&&e.target.closest&&e.target.closest("button"))return;'
        'var sec=el("nemChatSection");if(!sec)return;'
        'var r=sec.getBoundingClientRect();'
        'var dx=e.clientX-r.left,dy=e.clientY-r.top;'
        'function mv(ev){sec.style.left=(ev.clientX-dx)+"px";'
        'sec.style.top=(ev.clientY-dy)+"px";}'
        'function up(){'
        '_hdr.removeEventListener("pointermove",mv);'
        '_hdr.removeEventListener("pointerup",up);'
        '_hdr.removeEventListener("pointercancel",up);'
        'fclamp(sec);'
        'var st=fstate();st.left=parseInt(sec.style.left,10);'
        'st.top=parseInt(sec.style.top,10);fsave(st);}'
        'try{_hdr.setPointerCapture(e.pointerId);}catch(err){}'
        '_hdr.addEventListener("pointermove",mv);'
        '_hdr.addEventListener("pointerup",up);'
        # pointercancel fires when the browser steals the gesture (scroll,
        # context menu). Without it the move handler would stay bound and the
        # panel would follow the cursor with no button held.
        '_hdr.addEventListener("pointercancel",up);'
        'e.preventDefault();'
        '});}'
        # CSS `resize:both` does NOT fire the window resize event, so a
        # ResizeObserver is the only way to notice the user dragging the corner.
        # Guarded rather than assumed present -- an older browser simply loses
        # size persistence and log re-sizing, not the feature.
        'var _sec0=el("nemChatSection");'
        'if(_sec0&&window.ResizeObserver){'
        'new ResizeObserver(function(){'
        'var s=el("nemChatSection");if(!s||!FLOAT)return;'
        'fsizelog(s);var st=fstate();st.w=s.offsetWidth;st.h=s.offsetHeight;fsave(st);'
        '}).observe(_sec0);}'
        'window.addEventListener("resize",function(){'
        'var s=el("nemChatSection");if(s&&FLOAT){fclamp(s);fsizelog(s);}});'
        'return true;'
        '}'
        'if(!ensureWidget()){'
        'document.addEventListener("DOMContentLoaded",ensureWidget);}'
        'function money(v){return (v===null||v===undefined)?null:"$"+Number(v).toFixed(4);}'
        # ── copy-to-clipboard ────────────────────────────────────────────────
        # The answer often contains a command the operator needs to RUN, and
        # drag-selecting inside a short scrolling box is the interaction this
        # product least wants to require. So every answer, and every fenced
        # block inside it, gets an explicit copy button.
        #
        # execCommand IS the load-bearing path here, not a legacy fallback: the
        # dashboard is served over plain HTTP on a LAN address, which is not a
        # secure context, so `navigator.clipboard` is UNDEFINED in Chrome. A
        # clipboard-API-only button would look identical to a working one and do
        # nothing. Try the modern API when it exists (HTTPS / localhost), fall
        # back otherwise, and ALWAYS report the outcome on the button so a
        # failure cannot pass for success.
        'function copyDone(btn,prev,ok){'
        'btn.textContent=ok?"Copied":"Copy failed";'
        'btn.style.color=ok?"#00ff88":"#ff6666";'
        'setTimeout(function(){btn.textContent=prev;btn.style.color="#00d4ff";},1400);'
        '}'
        'function copyFallback(t,btn,prev){'
        'var ok=false;'
        'try{'
        'var ta=document.createElement("textarea");'
        'ta.value=t;ta.setAttribute("readonly","");'
        'ta.style.cssText="position:fixed;top:0;left:-9999px;opacity:0";'
        'document.body.appendChild(ta);'
        'ta.select();ta.setSelectionRange(0,String(t).length);'
        'ok=document.execCommand("copy");'
        'document.body.removeChild(ta);'
        '}catch(e){ok=false;}'
        'copyDone(btn,prev,ok);'
        '}'
        'function copyText(t,btn){'
        'var prev=btn.textContent;'
        'if(navigator.clipboard&&navigator.clipboard.writeText){'
        'navigator.clipboard.writeText(t).then(function(){copyDone(btn,prev,true);})'
        '.catch(function(){copyFallback(t,btn,prev);});'
        '}else{copyFallback(t,btn,prev);}'
        '}'
        # txt is a parameter, so each button closes over its OWN text -- do not
        # refactor this to read a loop variable, which would make every button
        # copy the last block.
        'function copyBtn(txt,label){'
        'var b=document.createElement("button");'
        'b.type="button";b.textContent=label||"Copy";'
        'b.style.cssText="background:transparent;border:1px solid #2a3f5f;color:#00d4ff;'
        'padding:1px 8px;border-radius:3px;cursor:pointer;font-size:0.95em;flex-shrink:0";'
        'b.onclick=function(){copyText(txt,b);};'
        'return b;'
        '}'
        # Split the answer on ``` fences: prose stays flowing text, each fenced
        # block becomes its own monospace box with a copy button. Model output is
        # still written with textContent ONLY -- never innerHTML -- so this adds
        # structure without letting model-generated markup render.
        'function renderAnswer(host,text){'
        'var parts=String(text).split("```");'
        'for(var i=0;i<parts.length;i++){'
        'var seg=parts[i];'
        'if(!seg.replace(/\\s/g,""))continue;'
        'if(i%2===1){'
        'var body=seg.replace(/^[a-zA-Z0-9_.+-]*\\r?\\n/,"");'
        'if(!body.replace(/\\s/g,""))continue;'
        'var box=document.createElement("div");'
        'box.style.cssText="margin:6px 0;border:1px solid #2a3f5f;border-radius:4px;background:#0d1117";'
        'var hd=document.createElement("div");'
        'hd.style.cssText="display:flex;justify-content:flex-end;padding:3px 5px;border-bottom:1px solid #1c2942";'
        'hd.appendChild(copyBtn(body,"Copy"));'
        'var pre=document.createElement("pre");'
        'pre.style.cssText="margin:0;padding:7px 9px;overflow-x:auto;white-space:pre;'
        'font-family:monospace;font-size:0.92em;color:#9fe8c0";'
        'pre.textContent=body;'
        'box.appendChild(hd);box.appendChild(pre);host.appendChild(box);'
        '}else{'
        'var p=document.createElement("div");'
        'p.style.cssText="color:#ddd;white-space:pre-wrap";'
        'p.textContent=seg;host.appendChild(p);'
        '}'
        '}'
        '}'
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
        # ⚠ NAMING: this `TIER` is the MODEL tier — "standard" | "advanced",
        # which Anthropic model a chat question is billed against. It is NOT the
        # EXPLANATION tier ("beginner" | "intermediate" | "pro") that
        # static/tier.js stores in localStorage under `explanationTier` and that
        # every user-facing string in the dashboard is written against, including
        # the per-tier AI alert explanations added 2026-08-06
        # (dashboard.py `_EXPLANATION_TIERS`).
        #
        # Two unrelated axes, one identifier apart, in code that sits side by
        # side: a chat surface can be on the ADVANCED model while its reader is
        # on the BEGINNER explanation tier, and neither constrains the other.
        # Named here rather than renamed because `TIER` is closed over by
        # tierUI()/nemChatRaise()/nemChatLower() in this same concatenated string
        # — a rename is a mechanical change to string-built JS with no compiler
        # to catch a miss, which is a poor trade for a comment's worth of clarity.
        #
        # ── UNPIN: float the SAME node, in the SAME document ─────────────────
        #
        # PUNCHLIST backlog (2026-08-05): "unpin the chat widget into a separate,
        # user-resizable popup window" -- the fixed-size embedded area feels
        # cramped. Scoped 2026-08-06 as three options; this is Option 2.
        #
        # WHY NOT A REAL window.open() POPUP. `appendChild` cannot move a node
        # between documents, so the relocation mechanism below would not merely
        # need extending -- it would not apply at all. Worse, every control in
        # this widget is an inline `onclick="nemChatAsk()"`, which resolves
        # against the POPUP's globals, where nemChatAsk/TIER/OPTS do not exist.
        # Each button would silently become a no-op: the exact failure shape the
        # single-instance design was introduced to fix (5330220), arriving from a
        # new direction. And `ensureWidget()` -- the backstop for a destroyed
        # node -- would fire in the opener and mint a SECOND widget while the
        # first lived in the popup, recreating the duplicate-instance state.
        #
        # So this floats the existing node instead: position:fixed on <body>,
        # CSS `resize:both`, header as a drag handle. The single-instance
        # invariant, every handler, the shared cost display and ensureWidget()
        # are all untouched, because nothing crosses a document boundary. It
        # cannot leave the tab -- the accepted trade, and a narrow one, since the
        # chat is anchored to a finding that is being viewed on this page.
        'var FLOAT=false,HOST=null,FKEY="nemChatFloat";'
        # Geometry persists so the panel reopens where it was left. A corrupt or
        # unreadable value returns {} and every read below falls back to a
        # default, rather than throwing and taking the widget down with it.
        'function fstate(){try{return JSON.parse(localStorage.getItem(FKEY)||"{}")||{};}catch(e){return {};}}'
        'function fsave(o){try{localStorage.setItem(FKEY,JSON.stringify(o));}catch(e){}}'
        # Keep the panel reachable. Without this a panel left near the right edge
        # of a wide monitor is stranded off-screen on a laptop -- present in the
        # DOM, impossible to drag back, and indistinguishable from "the unpin
        # button did nothing".
        'function fclamp(sec){'
        'var l=parseInt(sec.style.left,10),t=parseInt(sec.style.top,10);'
        'if(isNaN(l))l=0;if(isNaN(t))t=0;'
        'var maxL=Math.max(0,window.innerWidth-sec.offsetWidth);'
        'var maxT=Math.max(0,window.innerHeight-sec.offsetHeight);'
        'sec.style.left=Math.min(Math.max(0,l),maxL)+"px";'
        'sec.style.top=Math.min(Math.max(0,t),maxT)+"px";'
        '}'
        # The log has a fixed 230px cap inline, so a taller panel would grow its
        # chrome and leave the transcript the same size -- resizing would look
        # broken. A RATIO rather than measured arithmetic: subtracting measured
        # chrome height is exact until any control wraps, and then it is silently
        # wrong. This is always sane at every size, which matters more here than
        # pixel fidelity.
        'function fsizelog(sec){var lg=el("nemChatLog");if(!lg)return;'
        'lg.style.maxHeight=FLOAT?(Math.max(80,Math.round(sec.clientHeight*0.45))+"px"):"230px";}'
        'function fbtns(){'
        'var u=el("nemChatUnpinBtn"),p=el("nemChatRepinBtn"),h=el("nemChatHeader");'
        'if(u)u.style.display=FLOAT?"none":"";'
        'if(p)p.style.display=FLOAT?"":"none";'
        'if(h)h.style.cursor=FLOAT?"move":"default";'
        '}'
        # z-index 1500 sits above .modal/.db-modal (1000) so the panel is usable
        # over an open alert modal -- the main reason to unpin at all -- and below
        # the toast (2000), which must never be covered.
        #
        # `display` is deliberately NOT set here: nemChatInit owns it (none while
        # loading, block once available), and writing it from this path would
        # race that and show an empty panel.
        'function fapply(sec){var st=fstate();'
        'sec.style.position="fixed";sec.style.zIndex="1500";'
        'sec.style.width=(st.w||420)+"px";sec.style.height=(st.h||460)+"px";'
        'sec.style.left=(st.left!=null?st.left:Math.max(0,window.innerWidth-460))+"px";'
        'sec.style.top=(st.top!=null?st.top:80)+"px";'
        'sec.style.resize="both";sec.style.overflow="auto";'
        'sec.style.background="#16213e";sec.style.border="1px solid #2a3f5f";'
        'sec.style.borderRadius="6px";sec.style.boxShadow="0 8px 28px rgba(0,0,0,0.55)";'
        'sec.style.padding="12px";sec.style.boxSizing="border-box";'
        'sec.style.minWidth="300px";sec.style.minHeight="260px";'
        'sec.style.marginTop="0";sec.style.borderTop="1px solid #2a3f5f";'
        'fclamp(sec);fsizelog(sec);}'
        # Restore the three inline values from the original markup explicitly
        # rather than blanking them: they are part of how the widget looks INLINE,
        # so clearing them all would repin into a subtly different widget.
        'function fclear(sec){'
        '["position","left","top","width","height","zIndex","resize","overflow",'
        '"background","border","borderRadius","boxShadow","padding","boxSizing",'
        '"minWidth","minHeight"].forEach(function(p){sec.style[p]="";});'
        'sec.style.marginTop="18px";sec.style.borderTop="1px solid #333";'
        'sec.style.paddingTop="14px";fsizelog(sec);}'
        'window.nemChatUnpin=function(){var sec=el("nemChatSection");if(!sec)return;'
        'FLOAT=true;'
        # Park on <body> before floating. position:fixed inside an ancestor with
        # a transform/filter resolves against THAT ancestor, not the viewport --
        # so a panel left inside a module card could land somewhere unexpected.
        # <body> is also the widget's existing safe home on close.
        'if(document.body&&sec.parentNode!==document.body)document.body.appendChild(sec);'
        'fapply(sec);fbtns();var st=fstate();st.on=true;fsave(st);};'
        'window.nemChatRepin=function(){var sec=el("nemChatSection");if(!sec)return;'
        'FLOAT=false;fclear(sec);fbtns();'
        # Back into the container it was last attached to -- but only if that node
        # is still in the document. Surfaces rebuild their own containers, so a
        # remembered HOST can be detached, and appending into it would move the
        # only widget somewhere invisible. Falling back to <body> is the same
        # parking rule nemChatClose already relies on.
        'if(HOST&&document.body&&document.body.contains(HOST))HOST.appendChild(sec);'
        'else if(document.body)document.body.appendChild(sec);'
        'var st=fstate();st.on=false;fsave(st);};'
        # Re-float on load if the panel was left unpinned. Deliberately NOT done
        # inside ensureWidget(): that runs at line-1 of this IIFE, BEFORE the
        # window.nemChatUnpin assignment above has executed, so calling it from
        # there would throw on `undefined is not a function`.
        #
        # The `else fbtns()` branch is not cosmetic -- without it a pinned widget
        # never initialises its buttons, and Unpin would render hidden.
        'function frestore(){var sec=el("nemChatSection");if(!sec)return;'
        'if(fstate().on&&window.nemChatUnpin)window.nemChatUnpin();else fbtns();}'
        # ensureWidget registered its own DOMContentLoaded listener earlier in
        # this IIFE, so on a still-loading document it runs FIRST and the node
        # exists by the time frestore is called. Listener order is registration
        # order, and that ordering is what makes this correct.
        'if(document.readyState==="loading"){'
        'document.addEventListener("DOMContentLoaded",frestore);}else{frestore();}'
        # Relocate the single widget into whichever container is open. Surfaces
        # that expand rows in place (malware findings, queue items) can have
        # several open at once; moving one widget keeps a single DOM instance and
        # a single cost display, rather than N copies to keep consistent.
        'var TIER="standard",OPTS=null;''function tierUI(){''var adv=(TIER==="advanced");''el("nemChatTierLabel").textContent=adv?"Advanced":"Standard";''el("nemChatTierLabel").style.color=adv?"#ffc107":"#00d4ff";''el("nemChatRaiseBtn").style.display=adv?"none":"";''el("nemChatLowerBtn").style.display=adv?"":"none";''el("nemChatLowerHint").style.display=adv?"":"none";''}''window.nemChatRaise=function(){''var m=(OPTS&&OPTS.multiple)?OPTS.multiple:null;''var cost=(m===null)''?"The exact cost increase CANNOT be calculated right now, because pricing for one of the models is unknown. It will be more expensive per question."'':("Each question will cost about "+m+"x more than Standard.");''var msg="Switch to the Advanced model?\\n\\n"+cost''+"\\n\\nThis applies to new questions in this conversation only. "''+"Your spend cap and rate limits still apply.\\n\\n"''+"You can switch back to Standard at any time.";''if(!window.confirm(msg))return;''TIER="advanced";tierUI();''};''window.nemChatLower=function(){TIER="standard";tierUI();};''window.nemChatAttach=function(container,surface,rowId){'
        'ensureWidget();'
        'var sec=el("nemChatSection");'
        'if(!sec||!container)return;'
        # Remembered even while floating, so Pin back has somewhere to return to.
        'HOST=container;'
        # WHILE FLOATING THE PANEL DOES NOT MOVE. Appending it into the container
        # would yank a panel the user deliberately positioned back inline the
        # moment they opened another finding -- which reads as the unpin having
        # been silently undone. It stays put and simply re-points at the new
        # surface, which is the whole value of an unpinned panel.
        # fapply() re-runs because a container may have been rebuilt underneath it.
        'if(FLOAT){'
        'if(document.body&&sec.parentNode!==document.body)document.body.appendChild(sec);'
        'fapply(sec);'
        '}else if(sec.parentNode!==container)container.appendChild(sec);'
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
        'renderAnswer(ae,d.answer);'
        # Cost row doubles as the per-answer action row: the log auto-scrolls to
        # the bottom on each new answer, so a control here is in view without
        # scrolling, and it costs no extra height in a 230px-max box.
        'var ce=document.createElement("div");'
        'ce.style.cssText="display:flex;align-items:center;gap:8px;color:#777;'
        'font-size:0.75em;margin-top:5px";'
        'var m=money(d.cost_usd);'
        'var lbl=(d.tier==="advanced")?" (Advanced)":"";'
        'var cost=document.createElement("span");'
        'cost.style.cssText="flex:1";'
        'cost.textContent=((m===null)?"cost unavailable for this model":"this question cost "+m)+lbl;'
        'ce.appendChild(cost);'
        'ce.appendChild(copyBtn(d.answer,"Copy answer"));'
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
    surface: str | None = None,
    free_text_reason: str | None = None,
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
                              cache_hours, force, model, effort,
                              job_id=job_id, surface=surface,
                              free_text_reason=free_text_reason)
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
    job_id: str | None = None,
    surface: str | None = None,
    free_text_reason: str | None = None,
) -> dict:
    # ── NPFA/1 ENFORCEMENT BOUNDARY ──────────────────────────────────────────
    # A machine-generated prompt must arrive as a `BuiltPrompt` -- assembled only
    # from declared, type-validated fields (see prompt_fields.py and ADR 0025).
    # A plain `str` is refused.
    #
    # WHY THE TYPE AND NOT AN INSPECTION: you cannot look at a finished string
    # and tell which parts were runtime data. The type carries that proof from
    # where the knowledge exists (assembly) to where it is needed (the wire).
    # Any str operation on a BuiltPrompt returns a plain str, so tampering
    # downgrades it and lands here -- which is asserted directly in the tests.
    #
    # THE SINGLE EXEMPTION is `free_text_reason`: the follow-up chat, where a
    # human deliberately composes a message (often pasted output) and no
    # allowlist can express "whatever the operator typed". It is a marked path,
    # not a general hatch -- the reason string is required, recorded, and the
    # chokepoint below still scrubs addresses and known device names from it.
    if not isinstance(prompt, _prompt_fields.BuiltPrompt):
        if not free_text_reason:
            log.error("ai_engine: REFUSED an unstructured prompt (surface=%r). "
                      "Machine-generated prompts must be built via "
                      "prompt_fields.build(); free text requires an explicit "
                      "free_text_reason.", surface)
            return {"ok": False,
                    "reason": "prompt was not built from declared fields "
                              "(NPFA/1) and no free_text_reason was given"}
        log.info("ai_engine: free-text prompt admitted (surface=%r, reason=%r)",
                 surface, free_text_reason)

    # A non-default model gets its own cache namespace. Without this a cached
    # answer from one model would be served for a request that explicitly asked
    # for another -- silently, and looking exactly like a normal cache hit.
    target_model = model or _ACTIVE_MODEL
    # Kept un-namespaced so a later degrade can re-derive the key for the model
    # it actually ends up using, instead of appending a second @suffix.
    orig_cache_key = cache_key
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
    #
    # DEGRADE RATHER THAN STOP. A call-count ceiling now downgrades the model
    # instead of refusing (see `_check_rate_limit` for why money limits do not
    # get the same treatment). The rate limit is likeliest to bind on the
    # busiest day, which is exactly when the findings most need explaining.
    #
    # The swap is recorded, not hidden: the returned dict carries
    # `degraded: True` and the model actually used, and `get_status()` reports a
    # distinct "Degraded" state. A cheaper answer presented as a normal one
    # would be the same defect this repo keeps finding — a lesser result wearing
    # a full result's costume.
    degraded = False
    if not force:
        try:
            conn = _conn()
            limited, reason, kind = _check_rate_limit(conn)
            conn.close()
            if limited and kind == "degrade" and target_model != _DEGRADED_MODEL:
                degraded = True
                target_model = _DEGRADED_MODEL
                # Re-namespace the cache WRITE so a cheap answer is never stored
                # under the full-quality key and served later as if it were one.
                # The earlier cache LOOKUP used the original key on purpose: a
                # full-quality cached answer is strictly better and should win.
                if orig_cache_key:
                    cache_key = f"{orig_cache_key}@{target_model}"
                log.warning("ai_engine: rate ceiling reached (%s) — degrading to "
                            "%s rather than refusing", reason, target_model)
            elif limited:
                return {"ok": False, "reason": f"Rate limit: {reason}"}
        except Exception:
            log.exception("ai_engine: rate limit check failed")

    # API call with capped retry (max 1 retry)
    try:
        import anthropic
    except ImportError:
        return {"ok": False, "reason": "anthropic package not installed — run pip install anthropic"}

    client = anthropic.Anthropic(api_key=key)

    # ── PSEUDONYMIZATION, ENFORCED HERE AND NOWHERE ELSE ────────────────────
    #
    # Every billed call in the product funnels through this function, so this is
    # the only place the guarantee can actually be made. It used to live in ONE
    # caller (dashboard's alert path) while three others -- anomaly, community
    # queue and malware Layer C -- called straight past it: anomaly was sending
    # real device names and real LAN IPs to the vendor on every automatic
    # incident analysis. That is the same argument `_chat_system_prompt` already
    # makes about scope: "a property enforced in six places is enforced in none."
    #
    # ⚠ SCOPE OF THE GUARANTEE, STATED HONESTLY (updated 2026-08-23): addresses
    # -- IPv4/IPv6 and MACs -- AND known device names are both replaced now. The
    # name half closed the gap this comment used to describe as still open.
    #
    # Names cannot be pattern-detected the way an address can, so they are read
    # from the devices tables here and passed in. Two consequences worth knowing:
    #   * a name that is NOT in those tables is not scrubbed, because nothing
    #     knows it is a name. Free-text an operator typed into a note is the
    #     realistic case.
    #   * generic names ("router", "printer") are deliberately left alone -- see
    #     `_GENERIC_NAMES`. They identify nobody, and tokenizing every occurrence
    #     of the word "router" would wreck the model's reasoning for no gain.
    # Both are honest limits of the mechanism, not gaps being glossed over.
    #
    # ONE MAPPING ACROSS BOTH FIELDS. `pseudonymize()` assigns tokens from "A"
    # per call with no way to seed it, so scrubbing `prompt` and `system` in two
    # passes would mint two different host-A's and `resolve()` would map one of
    # them back to the wrong address. They are therefore scrubbed as a single
    # string and split apart again.
    #
    # FAIL CLOSED. A scrubber that raises must BLOCK the call, never fall
    # through to sending the raw text: a silent pass-through is precisely the
    # "failed read presented as a legal answer" shape this repo keeps finding,
    # and here the cost of it is customer data on the wire.
    #
    # The CACHE is deliberately untouched by any of this. Scrubbing happens on
    # the way to the wire and is reversed on the way back, so `ai_cache` stores
    # exactly what it stored before, and a cache hit -- which never reaches the
    # network -- needs no scrubbing at all.
    _SEP = "\n\x00--nemesis-system-boundary--\x00\n"
    try:
        # `nemesis_pseudonymize` lives in alert_manager/, which is NOT on this
        # module's import path — the one other place in this file that needs an
        # alert_manager import inserts the path locally too (see the
        # pricing-drift notifier). Resolved from __file__ rather than hardcoded
        # so it survives a relocation: module.py -> ai_engine -> modules -> root.
        #
        # ⚠ This is load-bearing for AVAILABILITY, not just tidiness. The block
        # below fails CLOSED, so if this import cannot resolve, every AI call in
        # the product returns "pseudonymization failed" — a total outage of the
        # feature, wearing the costume of a safety measure. Measured during
        # development: without this insert the import raises ImportError on
        # every call. `test_pseudonymize_chokepoint.py` asserts the import
        # resolves from a bare interpreter for exactly this reason.
        import sys as _sys
        _amgr = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "alert_manager")
        if _amgr not in _sys.path:
            _sys.path.insert(0, _amgr)
        import nemesis_pseudonymize as _pseudo
        _names = _known_device_names()
        if _SEP in prompt or (system_prompt and _SEP in system_prompt):
            raise ValueError("input contains the internal boundary sentinel")
        if system_prompt:
            _joined, _addr_map = _pseudo.pseudonymize(system_prompt + _SEP + prompt,
                                                      names=_names)
            _wire_system, _, _wire_prompt = _joined.partition(_SEP)
            if not _wire_prompt and prompt:
                raise ValueError("boundary sentinel did not survive pseudonymization")
        else:
            _wire_prompt, _addr_map = _pseudo.pseudonymize(prompt, names=_names)
            _wire_system = None
    except Exception as exc:                                    # noqa: BLE001
        log.exception("ai_engine: pseudonymization failed — call BLOCKED")
        return {"ok": False,
                "reason": "pseudonymization failed, so the request was not sent "
                          "(%s)" % exc}

    messages = [{"role": "user", "content": _wire_prompt}]
    kwargs: dict = dict(model=target_model, max_tokens=max_tokens, messages=messages)
    if _wire_system:
        kwargs["system"] = _wire_system

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

            # Reverse the pseudonymization before ANYTHING else sees the reply —
            # callers, the cache and the returned dict all get real addresses,
            # so this whole mechanism is invisible above this function. An
            # UNKNOWN token is deliberately left standing by resolve(): if the
            # model referred to a host that was never in its input, the operator
            # should see that it did.
            #
            # Note the caller that already scrubs (dashboard's alert path) still
            # composes correctly: its text arrives here already tokenized, so
            # this pass finds no addresses, `_addr_map` is empty, and resolve()
            # is a no-op. Its own resolve() then does the real work as before.
            text = _pseudo.resolve(text, _addr_map)

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
        # Price it with the model ACTUALLY used (which may be the degraded one),
        # attribute it to a feature, and stamp the acting user. All four are
        # knowable here and unknowable afterwards.
        _increment_usage(conn, tokens_in, tokens_out,
                         model=target_model,
                         cost_usd=_cost_of(tokens_in, tokens_out, target_model),
                         surface=surface or _derive_surface(job_id, cache_key),
                         actor=_current_actor())
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
    # `degraded` and `model_used` travel with every result so a caller (or a
    # reader of a stored verdict) can tell a full-quality answer from a
    # rate-degraded one. Without them the downgrade would be silent, which is
    # the failure this feature exists to avoid rather than introduce.
    return {"ok": True, "text": text, "from_cache": False,
            "tokens_used": (tokens_in or 0) + (tokens_out or 0),
            "tokens_in": tokens_in or 0, "tokens_out": tokens_out or 0,
            "degraded": degraded, "model_used": target_model}


# ─────────────────────────────────────────────────────────────────────────────
# The master password, the manual authority override, and loud demotion
#
# The toggle is settable at any time, but RAISING it past what the ladder has
# earned requires a second credential -- distinct from the dashboard login --
# held by whoever is actually in charge. The gate is authentication, not track
# record.
#
# WHAT A PASSWORD CANNOT DO, no matter who holds it:
#   * make an irreversible action reversible (`execute_proposal`'s undo gate)
#   * lift a CAPABILITY ceiling (see CEILING_KIND)
#   * lift the spend cap  -- a flood limit a password can raise is not a limit
#   * override the user's OWN standing rule -- edit the rule instead
# It authorizes RISK. It does not change what the code is able to do.
# ─────────────────────────────────────────────────────────────────────────────

def new_trace_id() -> str:
    """Minted at INGEST, before the pre-filter -- never at the first model call.

    If it were minted at the model call, every item the pre-filter dropped would
    be untraceable, and that is precisely the population most worth auditing.
    """
    return uuid.uuid4().hex[:12]


def log_decision(trace_id, stage, surface, subject_key, decision, reason_code,
                 reason_detail=None, action_class=None, level_needed=None,
                 level_granted=None, authority_source=None, authority_by=None,
                 model=None, tokens_in=None, tokens_out=None, cost_usd=None,
                 latency_ms=None, proposal_id=None, ticket_number=None,
                 actor=None) -> int | None:
    """Append one decision-point row. Never raises -- logging must not be able to
    break the thing it is observing -- but a failure to log is logged."""
    try:
        conn = _conn()
        cur = conn.execute(
            "INSERT INTO ai_decision_log(trace_id, ts, stage, surface, subject_key,"
            " decision, reason_code, reason_detail, action_class, level_needed,"
            " level_granted, authority_source, authority_by, model, tokens_in,"
            " tokens_out, cost_usd, latency_ms, proposal_id, ticket_number, actor)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (trace_id, datetime.now().isoformat(timespec="seconds"), stage, surface,
             str(subject_key), decision, reason_code, reason_detail, action_class,
             level_needed, level_granted, authority_source, authority_by, model,
             tokens_in, tokens_out, cost_usd, latency_ms, proposal_id,
             ticket_number, actor or _current_actor()))
        conn.commit()
        rid = cur.lastrowid
        conn.close()
        return rid
    except Exception:                                        # noqa: BLE001
        log.exception("ai_engine: decision-log write failed (%s/%s)", stage, decision)
        return None


def decision_trail(trace_id: str) -> list:
    """Every decision point for one subject, in order -- the reconstruction."""
    try:
        conn = _conn()
        rows = conn.execute("SELECT * FROM ai_decision_log WHERE trace_id=? "
                            "ORDER BY id", (trace_id,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:                                        # noqa: BLE001
        log.exception("ai_engine: decision_trail failed")
        return []


def refusal_ticket_text(action_class: str, subject: str, proposed: str) -> str:
    """What the ticket says when the engine WANTED to act and was refused.

    Requirement 2b: a refusal must be self-documenting. Silently doing nothing is
    indistinguishable from having nothing to say, and that ambiguity is exactly
    what turns a safety gate into a bug report.
    """
    lines = ["Nemesis AI identified an action it judged appropriate and did NOT "
             "take it.", "",
             "Subject:         %s" % subject,
             "Proposed action: %s" % proposed,
             "Action class:    %s" % action_class, ""]
    if undo_handler_for(action_class) is None and action_class not in EXTERNALLY_EXECUTED:
        lines += [
            "WHY IT DID NOT ACT: insufficient reversal support to act on this yet.",
            "",
            "No undo handler is registered for '%s', so Nemesis cannot take this "
            "action back if it turns out to be wrong. It therefore refuses to "
            "take it automatically at any authority level -- including levels "
            "granted with the master password. Authority can authorize risk; it "
            "cannot make an action reversible." % action_class,
            "",
            "This is a product limitation, not a misconfiguration. It resolves "
            "when a reversal path for this action class is implemented.",
        ]
    else:
        lines += ["WHY IT DID NOT ACT: current authority level is below what this "
                  "action requires. Raise it in AI settings, or approve this "
                  "action directly."]
    lines += ["", "Review and act on this manually if appropriate."]
    return "\n".join(lines)


_MASTER_PW_KEY        = "master_password_hash"
_MASTER_PW_FAILS_KEY  = "master_password_fails"
_MASTER_PW_LOCK_KEY   = "master_password_locked_until"
#: Attempts before lockout, and how long. Without this the override endpoint is
#: an unrate-limited oracle against a single credential -- the dashboard login
#: already has tiered lockout for exactly this reason.
_MASTER_PW_MAX_FAILS  = 5
_MASTER_PW_LOCKOUT_S  = 900


def master_password_is_set() -> bool:
    return bool((_get_setting(_MASTER_PW_KEY, "") or "").strip())


def set_master_password(new_pw: str, current_pw: str | None = None) -> dict:
    """Set or rotate the master password. Only ever stores a bcrypt hash.

    Rotation requires the CURRENT password: otherwise anyone with a dashboard
    session could silently replace the second credential and defeat the whole
    point of it being second.
    """
    if not new_pw or len(new_pw) < 12:
        return {"ok": False, "error": "master password must be at least 12 characters"}
    if master_password_is_set():
        ok, err = _verify_master_password(current_pw or "")
        if not ok:
            return {"ok": False, "error": "current master password required: %s" % err}
    try:
        import bcrypt
        _set_setting(_MASTER_PW_KEY,
                     bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode())
        _set_setting(_MASTER_PW_FAILS_KEY, "0")
        _set_setting(_MASTER_PW_LOCK_KEY, "")
        log.warning("ai_engine: master password %s",
                    "rotated" if current_pw else "set for the first time")
        return {"ok": True}
    except Exception as exc:                                 # noqa: BLE001
        log.exception("ai_engine: set_master_password failed")
        return {"ok": False, "error": str(exc)[:200]}


def _verify_master_password(pw: str) -> tuple:
    """(ok, error). Rate-limited; never reveals whether a hash exists via timing.

    A failed read of the stored hash returns an explicit failure, never a pass --
    the one direction this check must never fail in.
    """
    stored = (_get_setting(_MASTER_PW_KEY, "") or "").strip()
    if not stored:
        return False, "no master password has been set"
    locked = (_get_setting(_MASTER_PW_LOCK_KEY, "") or "").strip()
    if locked:
        try:
            if time.time() < float(locked):
                return False, ("locked out for %d more seconds after repeated "
                               "failures" % int(float(locked) - time.time()))
        except (TypeError, ValueError):
            pass                      # unparseable lock => treat as not locked
    try:
        import bcrypt
        if bcrypt.checkpw((pw or "").encode(), stored.encode()):
            _set_setting(_MASTER_PW_FAILS_KEY, "0")
            _set_setting(_MASTER_PW_LOCK_KEY, "")
            return True, ""
    except Exception as exc:                                 # noqa: BLE001
        log.exception("ai_engine: master password check errored")
        return False, "verification failed: %s" % str(exc)[:120]
    try:
        fails = int(_get_setting(_MASTER_PW_FAILS_KEY, "0") or 0) + 1
    except (TypeError, ValueError):
        fails = 1
    _set_setting(_MASTER_PW_FAILS_KEY, str(fails))
    if fails >= _MASTER_PW_MAX_FAILS:
        _set_setting(_MASTER_PW_LOCK_KEY, str(time.time() + _MASTER_PW_LOCKOUT_S))
        log.warning("ai_engine: master password locked out after %d failures", fails)
        return False, "too many failures - locked out for %d minutes" % (
            _MASTER_PW_LOCKOUT_S // 60)
    return False, "incorrect master password (%d of %d attempts used)" % (
        fails, _MASTER_PW_MAX_FAILS)


def _authority_override(action_class: str) -> dict | None:
    try:
        conn = _conn()
        row = conn.execute(
            "SELECT action_class, level, granted_by, granted_at, reason "
            "FROM ai_authority_override WHERE action_class=?",
            (action_class,)).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:                                        # noqa: BLE001
        # A failed read must NOT look like "no override" -- but it also must not
        # invent one. Log loudly and report none, which is the SAFE direction
        # (less authority, never more).
        log.exception("ai_engine: override read failed for %s", action_class)
        return None


def raise_authority(action_class: str, level: int, master_pw: str,
                    granted_by: str, reason: str = "") -> dict:
    """Manually raise a class's authority, gated on the master password.

    Refuses, with a reason the UI can show verbatim, when:
      * the class is unknown
      * the password is wrong / locked out
      * the level is out of range
      * the class has a CAPABILITY ceiling it would exceed
    """
    if action_class not in ACTION_CLASS_CEILINGS:
        raise UnknownActionClass(action_class)
    try:
        level = int(level)
    except (TypeError, ValueError):
        return {"ok": False, "error": "level must be an integer"}
    if not L0_OBSERVE <= level <= L4_GOVERN:
        return {"ok": False, "error": "level must be between %d and %d"
                % (L0_OBSERVE, L4_GOVERN)}
    ok, err = _verify_master_password(master_pw)
    if not ok:
        log.warning("ai_engine: REJECTED authority raise for %s by %s: %s",
                    action_class, granted_by, err)
        return {"ok": False, "error": err, "auth_failed": True}
    hard = ACTION_CLASS_CEILINGS[action_class]
    if ceiling_kind(action_class) == "capability" and level > hard:
        return {"ok": False, "error":
                ("%s is capped at L%d by a MISSING CAPABILITY, not by caution: "
                 "the code has no way to reverse this action. No password can "
                 "raise it until that capability exists." % (action_class, hard))}
    try:
        conn = _conn()
        # ONE TRANSACTION. The grant and its history entry commit together or not
        # at all -- a best-effort event write could leave authority raised with no
        # record of who raised it, which is the single state this table exists to
        # make impossible.
        prior = conn.execute(
            "SELECT level FROM ai_authority_override WHERE action_class=?",
            (action_class,)).fetchone()
        now_iso = datetime.now().isoformat(timespec="seconds")
        conn.execute(
            "INSERT OR REPLACE INTO ai_authority_override"
            "(action_class, level, granted_by, granted_at, reason) VALUES(?,?,?,?,?)",
            (action_class, level, granted_by, now_iso, reason or ""))
        conn.execute(
            "INSERT INTO ai_authority_events"
            "(ts, action_class, event, level, prior_level, actor, reason) "
            "VALUES(?,?,?,?,?,?,?)",
            (now_iso, action_class, "granted", level,
             prior[0] if prior else None, granted_by, reason or ""))
        conn.commit()
        conn.close()
    except Exception as exc:                                 # noqa: BLE001
        log.exception("ai_engine: could not record authority override")
        return {"ok": False, "error": str(exc)[:200]}
    log.warning("ai_engine: AUTHORITY RAISED %s -> L%d by %s (%s)",
                action_class, level, granted_by, reason or "no reason given")
    # Returned in the SAME response as the successful raise: the user must not be
    # able to leave this interaction believing something is automated when it is
    # not. Waiting for a refusal ticket is not good enough -- if the triggering
    # condition never occurs, no ticket ever fires and they stay wrong.
    readiness = automation_readiness([action_class], level=level)
    return {"ok": True, "action_class": action_class, "level": level,
            "warnings": authority_raise_warnings(action_class, level),
            "readiness": readiness,
            "inert": [r for r in readiness if not r["will_act"]]}


def surface_action_classes(surface_key: str) -> tuple:
    """Which action classes a surface can lead to, from its registered anchor.

    Empty tuple for a surface that registered none (explanatory only) AND for an
    unregistered surface -- callers that need to tell those apart should check
    `registered_anchors()`; for readiness purposes both correctly yield "nothing
    here will act", which is the honest answer either way.
    """
    a = _ANCHORS.get(surface_key)
    return tuple(a["action_classes"]) if a else ()


def automation_readiness(action_classes=None, surface_key=None, level=None) -> list:
    """Which of these classes will ACTUALLY act automatically -- and which won't.

    THE PROBLEM THIS EXISTS TO SOLVE. Raising a toggle can succeed completely and
    still leave the class inert, because authority is only one of the conditions
    for acting. A user who sees "override applied" and walks away believes
    automation is live. Nothing contradicts them until the engine declines to act
    on a real event -- which, if the triggering condition never occurs, may be
    never. They can be wrong for the entire trial and never find out.

    So this is computed and shown AT RAISE TIME, in the same interaction, rather
    than discovered later from a refusal ticket.

    Two independent reasons a class stays inert, and they fail very differently:

      * CAPABILITY CEILING -- `raise_authority` already refuses these loudly at
        the moment of the raise, so the user does get told.
      * NO UNDO HANDLER    -- this one is SILENT. The raise succeeds cleanly,
        the toggle reads ACT, and `execute_proposal` refuses every time. This is
        the dangerous case and the reason this function is not optional.

    Pure derivation over `effective_ceiling()` -- no new authority rules. If it
    ever disagrees with what `execute_proposal` does, execute_proposal is right
    and this is the bug.
    """
    if action_classes is None:
        action_classes = surface_action_classes(surface_key) if surface_key else ()
    out = []
    for ac in action_classes:
        try:
            eff = effective_ceiling(ac)
        except (UnknownActionClass, AuthorityUnavailable) as exc:
            # An unreadable authority state is NOT "it will act". Report the
            # failure; never let a failed read present as a capability.
            out.append({"action_class": ac, "will_act": False,
                        "reason": "unknown", "level": None,
                        "detail": "could not determine authority: %s" % str(exc)[:120]})
            continue
        # An externally-executed class never reaches execute_proposal's undo gate,
        # so undo_available describes machinery it does not use. Treating it as
        # available here is not a fiction -- see EXTERNALLY_EXECUTED for what
        # actually guarantees reversal for these classes.
        undo_ok = eff["undo_available"] or ac in EXTERNALLY_EXECUTED
        hard = ACTION_CLASS_CEILINGS[ac]
        requested = eff["level"] if level is None else int(level)
        # `level` is the authority being GRANTED, not a cap on current state.
        # Clamping to the current level (the first cut of this) made a preview
        # report the pre-raise world -- every class "below_acting_level" purely
        # because the raise had not happened yet, which is useless in the one
        # dialog that needs to predict the post-raise world.
        if eff["ceiling_kind"] == "capability":
            eff_level = min(requested, hard)
        else:
            eff_level = requested
        # A standing rule the user set themselves still binds -- the override
        # never lifts it (see raise_authority), so readiness must not pretend
        # otherwise.
        eff_level = min(eff_level, eff["rule_clamp"])
        blocked_by_capability = (eff["ceiling_kind"] == "capability"
                                 and requested > hard)
        if blocked_by_capability:
            out.append({"action_class": ac, "will_act": False,
                        "reason": "capability_ceiling", "level": eff_level,
                        # Generalised 2026-08-30. This used to say "no restore
                        # path available", which described malware_file_quarantine
                        # specifically -- the only capability ceiling that ever
                        # existed. That class is now a threshold, so the ONLY way
                        # to reach this branch is an action class missing from
                        # CEILING_KIND, which `ceiling_kind()` treats as
                        # capability on purpose. Naming file restore here would
                        # now misdescribe every case that can actually reach it.
                        "detail": "this action is capped at L%d by a missing "
                                  "capability in the product, and no password "
                                  "can lift it" % hard})
        elif not undo_ok and eff_level >= L2_ACT_REVERSIBLE:
            out.append({"action_class": ac, "will_act": False,
                        "reason": "no_undo_handler", "level": eff_level,
                        "detail": "no reversal is registered, so Nemesis will "
                                  "refuse to do this automatically even at L%d - "
                                  "it could not be taken back if wrong" % eff_level})
        elif eff_level < L2_ACT_REVERSIBLE:
            out.append({"action_class": ac, "will_act": False,
                        "reason": "below_acting_level", "level": eff_level,
                        "detail": "at L%d Nemesis may %s but not act" %
                                  (eff_level, "propose" if eff_level == L1_RECOMMEND
                                   else "only observe")})
        else:
            out.append({"action_class": ac, "will_act": True,
                        "reason": "ready", "level": eff_level,
                        "detail": "will act automatically at L%d" % eff_level})
    return out


def inert_after_raise(surface_key=None, action_classes=None, level=None) -> list:
    """Just the classes that will NOT act -- what the raise dialog must display."""
    return [r for r in automation_readiness(action_classes=action_classes,
                                            surface_key=surface_key, level=level)
            if not r["will_act"]]


def authority_raise_warnings(action_class: str, level: int) -> list:
    """What the confirmation dialog MUST say before a raise is accepted.

    Two different warnings, deliberately not merged: "earlier than its track
    record warrants" is a risk you can take back, and "cannot be undone" is not.
    Collapsing them into one scary paragraph teaches people to click through.
    """
    out = []
    if action_class in EXTERNALLY_EXECUTED:
        # Accurate warning for this shape, instead of the generic "cannot be
        # undone / the engine will refuse" -- which is false here and would be a
        # false REASSURANCE, not a false alarm.
        out.append("This action is carried out by a component outside the "
                   "engine's propose/approve path, so granting this level makes "
                   "it LIVE rather than merely permitted. It remains reversible: "
                   "the change it declines to revert stays provisional and can be "
                   "undone from the dashboard or the console at any time.")
    elif level >= L2_ACT_REVERSIBLE and undo_handler_for(action_class) is None:
        out.append("THIS ACTION CANNOT BE UNDONE IF IT IS WRONG. No reversal is "
                   "registered for %s, so the engine will REFUSE to act on it "
                   "even at this level -- and if a reversal is added later, "
                   "actions taken under it still could not be taken back "
                   "retroactively." % action_class)
    if ceiling_kind(action_class) == "capability":
        out.append("%s is limited by a missing capability in the product, not by "
                   "caution. Raising this setting will not enable the action."
                   % action_class)
    try:
        conn = _conn()
        row = conn.execute("SELECT current_level FROM ai_authority WHERE action_class=?",
                           (action_class,)).fetchone()
        conn.close()
        earned = int(row["current_level"]) if row else L0_OBSERVE
    except Exception:                                        # noqa: BLE001
        earned = None
    if earned is not None and level > earned:
        out.append("You are granting L%d to a class the system has only earned "
                   "L%d for. You are choosing to trust it earlier than its "
                   "track record warrants." % (level, earned))
    return out


def clear_authority_override(action_class: str, cleared_by: str,
                             reason: str = "") -> dict:
    """Remove a manual override. Requires no password -- LOWERING authority is
    always allowed, by anyone. Only raising needs the second credential."""
    try:
        conn = _conn()
        # Read the level BEFORE deleting: afterwards it is unrecoverable, and
        # "L4 was withdrawn" is a materially different record from "something
        # was withdrawn".
        prior = conn.execute(
            "SELECT level FROM ai_authority_override WHERE action_class=?",
            (action_class,)).fetchone()
        cur = conn.execute("DELETE FROM ai_authority_override WHERE action_class=?",
                           (action_class,))
        n = cur.rowcount
        if n:
            conn.execute(
                "INSERT INTO ai_authority_events"
                "(ts, action_class, event, level, prior_level, actor, reason) "
                "VALUES(?,?,?,?,?,?,?)",
                (datetime.now().isoformat(timespec="seconds"), action_class,
                 "cleared", None, prior[0] if prior else None,
                 cleared_by, reason or ""))
        conn.commit()
        conn.close()
    except Exception as exc:                                 # noqa: BLE001
        log.exception("ai_engine: could not clear override")
        return {"ok": False, "error": str(exc)[:200]}
    if n:
        log.warning("ai_engine: authority override CLEARED for %s by %s (%s)",
                    action_class, cleared_by, reason or "no reason given")
    return {"ok": True, "cleared": bool(n)}


def demote_action_class(action_class: str, reason: str, notifier=None) -> dict:
    """The safety response: drop a class's earned level AND kill any override.

    A standing manual override must NOT survive a demotion. The whole point of
    demotion is that something went wrong; letting a password entered last week
    outvote the safety system that just fired would make demotion decorative.

    LOUD BY CONTRACT, not by convention: this returns `notified` and takes a
    `notifier`, because telling the person in charge "the safety system just
    overrode your standing setting" in a log line nobody reads is the same as
    not telling them.
    """
    if action_class not in ACTION_CLASS_CEILINGS:
        raise UnknownActionClass(action_class)
    had_override = _authority_override(action_class)
    try:
        conn = _conn()
        conn.execute(
            "INSERT INTO ai_authority(action_class, current_level, hard_ceiling, "
            " last_demoted_at) VALUES(?,?,?,?) "
            "ON CONFLICT(action_class) DO UPDATE SET current_level=?, "
            " last_demoted_at=excluded.last_demoted_at",
            (action_class, L0_OBSERVE, ACTION_CLASS_CEILINGS[action_class],
             datetime.now().isoformat(timespec="seconds"), L0_OBSERVE))
        conn.execute("DELETE FROM ai_authority_override WHERE action_class=?",
                     (action_class,))
        conn.commit()
        conn.close()
    except Exception as exc:                                 # noqa: BLE001
        log.exception("ai_engine: demotion failed for %s", action_class)
        return {"ok": False, "error": str(exc)[:200]}
    msg = ("Nemesis SAFETY ACTION: automation for '%s' has been demoted to L0 "
           "(observe only).\n\nReason: %s\n" % (action_class, reason))
    if had_override:
        msg += ("\nYOUR MANUAL OVERRIDE WAS CLEARED. It had been set to L%d by "
                "%s on %s. The master password must be re-entered to restore it "
                "-- deliberately, so that restoring authority after a failure is "
                "a decision someone makes on purpose.\n"
                % (had_override["level"], had_override.get("granted_by") or "unknown",
                   had_override.get("granted_at") or "unknown"))
    log.warning("ai_engine: DEMOTED %s to L0 (%s); override_cleared=%s",
                action_class, reason, bool(had_override))
    notified = False
    if notifier:
        try:
            notifier("[Nemesis] Automation demoted: %s" % action_class, msg)
            notified = True
        except Exception:                                    # noqa: BLE001
            # The demotion STOOD; only the shout failed. Never let a mail error
            # roll back a safety action.
            log.exception("ai_engine: demotion notice failed to send")
    return {"ok": True, "action_class": action_class, "level": L0_OBSERVE,
            "override_cleared": bool(had_override), "notified": notified,
            "message": msg}


# ─────────────────────────────────────────────────────────────────────────────
# Proposals: the L1 approve/reject loop, and the UNDO that L2+ requires
#
# `ai_proposals` shipped as schema with NO reader and NO writer -- including the
# `undone`/`undone_at`/`undone_by` columns, which described a capability nothing
# implemented. That is the gap that made the whole authority ladder undeployable:
# you cannot responsibly grant an engine permission to ACT until the action can be
# taken back, and "we will add undo later" is how a system ships that can only go
# one way.
#
# UNDO IS A REGISTRY, NOT A SWITCH. Reversing an action is domain knowledge --
# un-blocking an IP, re-opening an alert, releasing a quarantined file are three
# different operations owned by three different modules. This layer records intent
# and ordering; the module that knows how to reverse its own action registers a
# handler. A class with NO registered handler CANNOT BE EXECUTED at L2+, which is
# enforced below rather than documented: an irreversible action is exactly the one
# that must not be automated.
# ─────────────────────────────────────────────────────────────────────────────

#: action_class -> callable(proposal_row[, context]) -> (ok: bool, detail: str)
#:
#: A handler MAY require a credential passed through `context`, and that still
#: counts as reversible. The asymmetry is deliberate and matches how the firewall
#: is already built: the ENGINE acts unattended, but an UNDO is initiated by a
#: human, so a credential legitimately exists at that moment. nemesis_fwd's
#: PEER_POLICY makes the unattended peer STRUCTURALLY incapable of lifting a
#: block (ops: block_ip/deny_ip/expire_quarantine only) while the credentialed
#: dashboard peer holds `unblock_ip`. That is not an obstacle to L2 -- it IS the
#: L2 contract: the engine may act, and a person can take it back.
_UNDO_HANDLERS = {}



# ── UPWARD promotion — graduated trust (the writer that was missing 2026-08-22) ──
#: Consecutive HUMAN-approved proposals in a class (with no rejection since the last
#: promotion) that earn one level of authority. Conservative and measurable; a rejection
#: since the last promotion breaks the streak (fail-closed). Named so it is one edit to tune.
PROMOTION_THRESHOLD = 5


def _consecutive_approvals_since_promotion(conn, action_class):
    """How many approvals a class has banked toward its next promotion.

    Counts proposals RESPONDED-TO since the class's last promotion. Returns 0 the moment a
    REJECTION appears in that window -- a single rejection resets the streak. Fail-closed:
    any read trouble yields 0 (no promotion), never a guessed count.
    """
    try:
        row = conn.execute("SELECT last_promoted_at FROM ai_authority WHERE action_class=?",
                           (action_class,)).fetchone()
        since = (row["last_promoted_at"] if row and row["last_promoted_at"] else "")
        rows = conn.execute(
            "SELECT human_response FROM ai_proposals "
            "WHERE action_class=? AND human_response IS NOT NULL "
            "  AND responded_at > ? ORDER BY responded_at ASC",
            (action_class, since)).fetchall()
    except Exception:                                        # noqa: BLE001
        return 0
    # Count approvals since the MOST RECENT rejection (and since last promotion). A
    # rejection RESETS the streak to 0 at that point; approvals after it rebuild it.
    # Returning 0 on the first rejection ever seen (an earlier cut) permanently froze
    # promotion after a single rejection -- caught by the "does reach the ceiling"
    # control 2026-08-22. Fail-closed is "a rejection breaks the current streak", not
    # "a rejection is a lifetime ban".
    n = 0
    for r in rows:
        if r["human_response"] == "rejected":
            n = 0
        elif r["human_response"] == "approved":
            n += 1
    return n


def promote_action_class(action_class: str, reason: str = "") -> dict:
    """Raise a class's EARNED level by one, capped at its hard ceiling. Never above.

    The upward counterpart to demote_action_class. Mirrors these ratified constraints:
      * authorizes RISK, not CAPABILITY -- promotion stops at the hard ceiling, and never
        promotes a capability-ceilinged class past its cap (the code cannot reverse the
        action, so no track record grants it).
      * every change is logged + stamped (last_promoted_at) for audit.
      * fail-closed: unknown class raises; a read/write error returns ok:False and does NOT
        move the level.
    Does NOT touch overrides or standing rules -- earned is its own term.
    """
    if action_class not in ACTION_CLASS_CEILINGS:
        raise UnknownActionClass(action_class)
    hard = ACTION_CLASS_CEILINGS[action_class]
    try:
        conn = _conn()
        try:
            row = conn.execute("SELECT current_level FROM ai_authority WHERE action_class=?",
                               (action_class,)).fetchone()
            earned = int(row["current_level"]) if row else L0_OBSERVE
            if earned >= hard:
                return {"ok": True, "promoted": False, "level": earned,
                        "reason": "already at the hard ceiling L%d" % hard}
            new_level = min(earned + 1, hard)
            conn.execute(
                "INSERT INTO ai_authority(action_class, current_level, hard_ceiling, "
                " last_promoted_at) VALUES(?,?,?,?) "
                "ON CONFLICT(action_class) DO UPDATE SET current_level=?, "
                " last_promoted_at=excluded.last_promoted_at",
                # microsecond resolution: a seconds-resolution stamp + strict '>' loses
                # every approval landing in the same second as the promotion, freezing the
                # streak (caught 2026-08-22). Finer resolution makes ordering unambiguous;
                # production promotions are minutes apart regardless.
                (action_class, new_level, hard,
                 datetime.now().isoformat(), new_level))
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:                                 # noqa: BLE001
        log.exception("ai_engine: promotion failed for %s", action_class)
        return {"ok": False, "error": str(exc)[:200]}
    log.warning("ai_engine: AUTHORITY PROMOTED %s L%d -> L%d (%s)",
                action_class, earned, new_level, reason or "track record")
    return {"ok": True, "promoted": True, "level": new_level, "from": earned}


def _consider_promotion(action_class: str) -> dict | None:
    """Called after an APPROVAL: promote if the class has banked the threshold. None if not."""
    try:
        conn = _conn()
        try:
            streak = _consecutive_approvals_since_promotion(conn, action_class)
        finally:
            conn.close()
    except Exception:                                        # noqa: BLE001
        return None
    if streak >= PROMOTION_THRESHOLD:
        return promote_action_class(
            action_class, reason="%d consecutive approvals" % streak)
    return None


def assert_no_action_class_disables_a_detector():
    """STRUCTURAL GUARD (ratified constraint): no authority a master password or a track
    record can grant may disable a required-detector's coverage. Authority classes act on
    alerts/IPs/files -- never on detector enable-state. This proves that stays true: any
    action class whose name implies disabling/stopping a detector/module/service is a
    violation. Run as a self-test; a future class that breaks it fails LOUDLY here rather
    than silently creating a password-reachable coverage-disable."""
    banned = ("disable", "stop", "unload", "deactivate", "turn_off", "kill")
    bad = [c for c in ACTION_CLASS_CEILINGS
           if any(b in c for b in banned)
           and any(t in c for t in ("detector", "module", "service", "canary",
                                    "scan", "monitor", "watch"))]
    return {"ok": not bad, "violations": bad}

def register_undo_handler(action_class: str, handler) -> None:
    """Declare how to REVERSE one class of action.

    Registering is what makes a class eligible for L2+ execution at all (see
    `execute_proposal`). Modules register their own; nothing here guesses how to
    undo someone else's action.
    """
    _UNDO_HANDLERS[action_class] = handler
    log.info("ai_engine: undo handler registered for %s", action_class)


def undo_handler_for(action_class: str):
    return _UNDO_HANDLERS.get(action_class)


def create_proposal(action_class: str, surface_key: str, row_id, proposed_action: str,
                    reasoning: str, model_used: str | None = None) -> int | None:
    """Record a proposed action awaiting human approval. Returns its id.

    This is what the engine does at L1: it proposes, it does not act. Every row is
    also a labelled datapoint for the promotion mechanism the ladder describes --
    the human's approve/reject is the measurement.
    """
    if action_class not in ACTION_CLASS_CEILINGS:
        raise UnknownActionClass(action_class)
    try:
        conn = _conn()
        cur = conn.execute(
            "INSERT INTO ai_proposals(action_class, surface_key, row_id, "
            " proposed_action, reasoning, model_used, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (action_class, surface_key, str(row_id), proposed_action,
             reasoning or "", model_used or _ACTIVE_MODEL,
             datetime.now().isoformat(timespec="seconds")))
        conn.commit()
        pid = cur.lastrowid
        conn.close()
        return pid
    except Exception:                                        # noqa: BLE001
        log.exception("ai_engine: create_proposal failed")
        return None


def get_proposal(proposal_id: int) -> dict | None:
    try:
        conn = _conn()
        conn.row_factory = __import__("sqlite3").Row
        row = conn.execute("SELECT * FROM ai_proposals WHERE id=?",
                           (proposal_id,)).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:                                        # noqa: BLE001
        log.exception("ai_engine: get_proposal failed")
        return None


def list_proposals(limit: int = 100, pending_only: bool = False) -> list:
    """Proposals, newest first -- the approve/reject queue and its audit trail."""
    try:
        conn = _conn()
        conn.row_factory = __import__("sqlite3").Row
        sql = "SELECT * FROM ai_proposals"
        if pending_only:
            sql += " WHERE human_response IS NULL"
        sql += " ORDER BY id DESC LIMIT ?"
        rows = conn.execute(sql, (int(limit),)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:                                        # noqa: BLE001
        log.exception("ai_engine: list_proposals failed")
        return []


def respond_to_proposal(proposal_id: int, response: str, responded_by: str) -> dict:
    """Record a human approve/reject. Does NOT execute -- that is a separate step.

    Split deliberately: approving is a decision, executing is an effect, and
    collapsing them would make "I approve this in principle" indistinguishable
    from "do it now". The audit trail needs both moments.
    """
    if response not in ("approved", "rejected"):
        return {"ok": False, "error": "response must be 'approved' or 'rejected'"}
    p = get_proposal(proposal_id)
    if not p:
        return {"ok": False, "error": "no such proposal"}
    if p["human_response"]:
        # Not an error to re-read, but the FIRST decision stands. Silently
        # overwriting it would erase the audit trail this table exists to be.
        return {"ok": False, "error": "already %s by %s"
                % (p["human_response"], p["responded_by"] or "unknown")}
    try:
        conn = _conn()
        conn.execute("UPDATE ai_proposals SET human_response=?, responded_at=?, "
                     "responded_by=? WHERE id=?",
                     (response, datetime.now().isoformat(),   # microsecond resolution
                      responded_by, proposal_id))
        conn.commit()
        conn.close()
    except Exception as exc:                                 # noqa: BLE001
        log.exception("ai_engine: respond_to_proposal failed")
        return {"ok": False, "error": str(exc)[:200]}
    # Graduated trust: an approval may earn a promotion; a rejection breaks the streak
    # (handled inside the counter). Done AFTER the response is durably recorded, and never
    # allowed to fail the response itself.
    promoted = None
    if response == "approved":
        try:
            promoted = _consider_promotion(p["action_class"])
        except Exception:                                    # noqa: BLE001
            promoted = None
    return {"ok": True, "id": proposal_id, "response": response,
            "promoted": promoted}


def execute_proposal(proposal_id: int, executor, actor: str | None = None) -> dict:
    """Carry out an APPROVED proposal via `executor(proposal) -> (ok, detail)`.

    THREE REFUSALS, all deliberate:
      * not approved            -> an unapproved action is not an action
      * already executed        -> re-running is not idempotent in the real world
      * NO UNDO HANDLER         -> see below

    The undo requirement is the load-bearing one. An action whose class has no
    registered reversal cannot be executed here at all, no matter how much
    authority the ladder grants, because granting an engine the power to do
    something it cannot take back is the failure mode the whole ladder exists to
    prevent. It fails LOUD rather than executing-and-hoping.
    """
    p = get_proposal(proposal_id)
    if not p:
        return {"ok": False, "error": "no such proposal"}
    if p["human_response"] != "approved":
        return {"ok": False, "error": "proposal is not approved (%s)"
                % (p["human_response"] or "no response yet")}
    if p["executed"]:
        return {"ok": False, "error": "already executed at %s" % p["executed_at"]}
    if undo_handler_for(p["action_class"]) is None:
        return {"ok": False, "error":
                "refusing to execute %s: no undo handler registered for that "
                "action class, so it could not be reversed" % p["action_class"]}
    try:
        ok, detail = executor(p)
    except Exception as exc:                                 # noqa: BLE001
        log.exception("ai_engine: executor raised for proposal %s", proposal_id)
        return {"ok": False, "error": "executor raised: %s" % str(exc)[:200]}
    if not ok:
        return {"ok": False, "error": detail or "executor reported failure"}
    try:
        conn = _conn()
        conn.execute("UPDATE ai_proposals SET executed=1, executed_at=? WHERE id=?",
                     (datetime.now().isoformat(timespec="seconds"), proposal_id))
        conn.commit()
        conn.close()
    except Exception:                                        # noqa: BLE001
        # The effect HAPPENED but the record did not. Loud, because an executed
        # action with no audit row is the state we can least afford to be quiet
        # about -- it is also now un-undoable through this path.
        log.exception("ai_engine: proposal %s EXECUTED but could not be recorded",
                      proposal_id)
        return {"ok": False, "error": "executed but the record failed to write - "
                                      "manual reconciliation required"}
    log.warning("ai_engine: proposal %s executed by %s (%s)",
                proposal_id, actor or "unknown", p["action_class"])
    return {"ok": True, "id": proposal_id, "detail": detail}


def _call_handler(handler, proposal, context):
    """Call a reversal handler, passing `context` only if it accepts one.

    Signature-inspected rather than try/except TypeError: catching TypeError
    would also swallow a genuine TypeError raised INSIDE the handler and
    silently retry it with fewer arguments, turning a real bug into a confusing
    second failure.
    """
    import inspect
    try:
        params = inspect.signature(handler).parameters
        takes_ctx = len(params) >= 2
    except (TypeError, ValueError):
        takes_ctx = False
    return handler(proposal, context) if takes_ctx else handler(proposal)


def undo_proposal(proposal_id: int, undone_by: str, context: dict | None = None) -> dict:
    """Reverse an executed proposal through its registered handler.

    The reversal is attempted FIRST and the row is only marked undone if it
    actually succeeded. Marking first would leave a row claiming an action was
    reversed when it is still in force -- a lie in the one record an operator
    would consult during an incident.
    """
    p = get_proposal(proposal_id)
    if not p:
        return {"ok": False, "error": "no such proposal"}
    if not p["executed"]:
        return {"ok": False, "error": "proposal was never executed"}
    if p["undone"]:
        return {"ok": False, "error": "already undone at %s by %s"
                % (p["undone_at"], p["undone_by"] or "unknown")}
    handler = undo_handler_for(p["action_class"])
    if handler is None:
        return {"ok": False, "error":
                "no undo handler for %s - cannot reverse" % p["action_class"]}
    try:
        ok, detail = _call_handler(handler, p, context or {})
    except Exception as exc:                                 # noqa: BLE001
        log.exception("ai_engine: undo handler raised for proposal %s", proposal_id)
        return {"ok": False, "error": "undo handler raised: %s" % str(exc)[:200]}
    if not ok:
        return {"ok": False, "error": detail or "undo reported failure",
                "still_in_force": True}
    try:
        conn = _conn()
        conn.execute("UPDATE ai_proposals SET undone=1, undone_at=?, undone_by=? "
                     "WHERE id=?",
                     (datetime.now().isoformat(timespec="seconds"), undone_by,
                      proposal_id))
        conn.commit()
        conn.close()
    except Exception:                                        # noqa: BLE001
        log.exception("ai_engine: proposal %s REVERSED but could not be recorded",
                      proposal_id)
        return {"ok": False, "error": "reversed but the record failed to write - "
                                      "manual reconciliation required"}
    log.warning("ai_engine: proposal %s undone by %s", proposal_id, undone_by)
    return {"ok": True, "id": proposal_id, "detail": detail}


# ─────────────────────────────────────────────────────────────────────────────
# Flask route handlers
# ─────────────────────────────────────────────────────────────────────────────

def _route_status():
    from flask import jsonify
    return jsonify(get_status())


def _route_usage():
    from flask import jsonify
    return jsonify(get_usage_stats())


def _route_automation_readiness():
    """GET /api/ai/automation_readiness?surface=alert&level=2

    Lets the toggle UI show, BEFORE and AFTER a raise, exactly which action
    classes will still not act. Read-only, so GET is correct here -- it changes
    nothing (contrast the raise itself, which must be POST).
    """
    from flask import jsonify, request
    surface = (request.args.get("surface") or "").strip() or None
    raw = (request.args.get("level") or "").strip()
    try:
        level = int(raw) if raw else None
    except ValueError:
        return jsonify({"error": "level must be an integer"}), 400
    classes = None
    if not surface:
        c = (request.args.get("action_classes") or "").strip()
        classes = [x for x in c.split(",") if x] or None
    if not surface and not classes:
        return jsonify({"error": "surface or action_classes required"}), 400
    try:
        rows = automation_readiness(action_classes=classes, surface_key=surface,
                                    level=level)
    except UnknownActionClass as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({
        "surface": surface,
        "level": level,
        "readiness": rows,
        "inert": [r for r in rows if not r["will_act"]],
        "all_inert": bool(rows) and all(not r["will_act"] for r in rows),
    })


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
            # The canonical ceiling + the window it is measured over. A rolling
            # window is what lets a user express "no more than $10 this week";
            # a calendar month cannot say that at all.
            "spend_cap_usd": _get_setting("spend_cap_usd", ""),
            "spend_cap_window_days": _spend_window_days(),
            # The STOPPED state, so a UI can show why the engine went quiet
            # rather than leaving the operator to infer it from silence.
            "spend_stop": get_spend_stop(),
            "spend": get_spend(),
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
    # Same validate-before-write discipline as below, for the same reason: a
    # typo accepted here would silently remove the user's spending protection
    # while the save looked successful.
    new_cap_write = None
    if "spend_cap_usd" in data:
        raw = ("" if data["spend_cap_usd"] is None
               else str(data["spend_cap_usd"]).strip())
        if raw == "":
            new_cap_write = ""
        else:
            try:
                val = float(raw)
            except (ValueError, TypeError):
                return jsonify({"ok": False, "error":
                                "Spend ceiling must be a number, or empty for no "
                                "ceiling. Existing ceiling left unchanged."}), 400
            if val <= 0:
                return jsonify({"ok": False, "error":
                                "Spend ceiling must be greater than 0, or empty "
                                "for no ceiling. Existing ceiling left "
                                "unchanged."}), 400
            new_cap_write = f"{val:.2f}"

    window_write = None
    if "spend_cap_window_days" in data:
        try:
            wd = int(float(str(data["spend_cap_window_days"]).strip()))
        except (ValueError, TypeError):
            return jsonify({"ok": False, "error":
                            "Spend window must be a whole number of days. "
                            "Existing window left unchanged."}), 400
        if wd < 1 or wd > 365:
            return jsonify({"ok": False, "error":
                            "Spend window must be between 1 and 365 days. "
                            "Existing window left unchanged."}), 400
        window_write = str(wd)

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
        if new_cap_write is not None:
            _set_setting("spend_cap_usd", new_cap_write)
        if window_write is not None:
            _set_setting("spend_cap_window_days", window_write)
        # Raising the ceiling should un-stick a reported stop immediately rather
        # than leaving a stale "stopped" badge until the next call happens to
        # re-evaluate it.
        if new_cap_write is not None or window_write is not None or cap_write is not None:
            try:
                sp = get_spend()
                cap_now = _spend_cap_usd()
                if sp.get("ok") and (cap_now is None or (sp.get("usd") or 0) < cap_now):
                    clear_spend_stop(actor="settings")
            except Exception:                                # noqa: BLE001
                pass
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
# §4.5 review surface — THE PAGE
#
# ⚠ THIS IS A PLAIN STRING, NOT AN f-STRING, AND THAT IS DELIBERATE.
# The #1 recurring defect in this codebase is a JS string or an English
# contraction inside a rendered f-string causing a SILENT SyntaxError at import.
# The page below interpolates NOTHING: it is a static shell that populates from
# /api/ai/context/learned (the admin-only JSON route above). No braces need
# escaping because there is no f-string, so the entire bug class is absent by
# construction rather than avoided by care.
#
# ⚠ EVERY VALUE IS INSERTED WITH textContent, NEVER innerHTML.
# `admin_reasoning` is the one free-text field in the schema — operator-authored
# prose, stored verbatim, and displayed here. innerHTML would make the review
# surface an XSS sink fed by its own database. textContent cannot execute.
# ─────────────────────────────────────────────────────────────────────────────

_CONTEXT_PAGE = """<!DOCTYPE html>
<html>
<head>
    <title>What Your AI Has Learned — Nemesis</title>
    <link rel="icon" type="image/x-icon" href="/static/favicon.ico">
    <style>
        body { font-family: Arial; background: #1a1a2e; color: #eee;
               padding: 20px; margin: 0; }
        h1 { color: #00d4ff; margin-bottom: 4px; }
        a { color: #00d4ff; }
        .back { color: #bbb; text-decoration: none; font-size: 0.9em; }
        .back:hover { color: #00d4ff; }
        .sub { color: #999; font-size: 0.9em; margin: 0 0 18px 0; max-width: 70em; }
        .card { background: #16213e; padding: 18px; border-radius: 10px;
                border: 1px solid #00d4ff; margin-bottom: 18px; }
        .stats-bar { display: flex; gap: 22px; flex-wrap: wrap; margin-bottom: 16px; }
        .stat-item { color: #ccc; font-size: 0.88em; }
        .stat-item b { color: #00d4ff; font-size: 1.15em; }
        table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
        th { padding: 6px 10px; text-align: left; color: #00d4ff;
             font-size: 0.8em; text-transform: uppercase; letter-spacing: 0.05em;
             border-bottom: 1px solid #1e2d4e; }
        td { padding: 8px 10px; border-bottom: 1px solid #1e2d4e;
             vertical-align: top; }
        tr.inactive td { opacity: 0.55; }
        .why { color: #ddd; font-style: italic; max-width: 34em;
               white-space: pre-wrap; word-break: break-word; }
        .pill { display: inline-block; padding: 2px 8px; border-radius: 10px;
                font-size: 0.78em; font-weight: bold; }
        .restrictive { background: #1e3a2e; color: #7fdba0; }
        .permissive  { background: #3a2e1e; color: #dbb87f; }
        .state { font-size: 0.78em; }
        .st-active    { color: #7fdba0; }
        .st-suspended { color: #ffb454; font-weight: bold; }
        .st-expired   { color: #999; }
        .st-revoked   { color: #ff6b6b; }
        .used { color: #ccc; }
        .used.never { color: #777; }
        button { background: #16213e; color: #00d4ff; border: 1px solid #00d4ff;
                 border-radius: 6px; padding: 4px 10px; cursor: pointer;
                 font-size: 0.8em; }
        button:hover { background: #1e2d4e; }
        button.danger { color: #ff6b6b; border-color: #ff6b6b; }
        button.armed  { background: #4a1e1e; color: #fff; border-color: #ff6b6b; }
        button:disabled { opacity: 0.4; cursor: default; }
        .banner { background: #3a2e1e; border: 1px solid #ffb454; color: #ffd9a0;
                  padding: 12px 16px; border-radius: 8px; margin-bottom: 18px; }
        .empty { color: #888; padding: 18px 4px; }
        .err { color: #ff6b6b; }
    </style>
</head>
<body>
    <a class="back" href="/">&larr; Back to dashboard</a>
    <h1>What Your AI Has Learned</h1>
    <p class="sub">Every calibration entry that shapes your AI&#39;s judgment.
    These change WHICH choice it makes within an action it is already allowed to
    take &mdash; they never grant it authority it does not have. Entries that
    have expired or been revoked stay listed: &ldquo;no longer applied&rdquo; and
    &ldquo;no longer recorded&rdquo; are different things.</p>

    <div id="suspended-banner"></div>

    <div class="card">
        <div class="stats-bar" id="stats"></div>
        <table>
            <thead>
                <tr>
                    <th>Added</th><th>Applies to</th><th>Direction</th>
                    <th>Admin&#39;s reasoning</th><th>Used</th>
                    <th>State</th><th></th>
                </tr>
            </thead>
            <tbody id="rows"></tbody>
        </table>
        <div class="empty" id="empty" style="display:none">
            Nothing learned yet. Entries appear here as you correct the AI&#39;s
            decisions &mdash; this page stays empty on a fresh install, which is
            the honest starting state.
        </div>
    </div>

<script>
function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    // textContent, never innerHTML: admin_reasoning is free text from the DB.
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
}

function stateOf(r) {
    if (r.revoked_at) return ['revoked', 'st-revoked'];
    if (r.suspended) return ['suspended \\u2014 awaiting review', 'st-suspended'];
    if (!r.active) return ['expired', 'st-expired'];
    return ['active', 'st-active'];
}

function post(url, body, done) {
    fetch(url, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body)
    }).then(function(r) { return r.json().then(function(j) {
        done(r.ok && j.ok, j.error || '');
    }); }).catch(function() { done(false, 'request failed'); });
}

function render(data) {
    var tbody = document.getElementById('rows');
    tbody.textContent = '';
    var rows = data.entries || [];
    document.getElementById('empty').style.display = rows.length ? 'none' : '';

    var c = data.counts || {};
    var stats = document.getElementById('stats');
    stats.textContent = '';
    [['Total', c.total], ['Active', c.active],
     ['Awaiting review', c.awaiting_review]].forEach(function(pair) {
        var d = el('div', 'stat-item');
        d.appendChild(el('b', null, pair[1] === undefined ? 0 : pair[1]));
        d.appendChild(document.createTextNode(' ' + pair[0]));
        stats.appendChild(d);
    });

    var banner = document.getElementById('suspended-banner');
    banner.textContent = '';
    if (c.awaiting_review) {
        var b = el('div', 'banner');
        b.textContent = c.awaiting_review + ' entr' +
            (c.awaiting_review === 1 ? 'y is' : 'ies are') +
            ' suspended by a vendor policy update and awaiting your review. ' +
            'They are not influencing decisions until you decide. Keeping one ' +
            'restores it; revoking retires it. Neither happens on its own.';
        banner.appendChild(b);
    }

    rows.forEach(function(r) {
        var st = stateOf(r);
        var tr = el('tr', r.active ? '' : 'inactive');
        tr.appendChild(el('td', null, (r.created_at || '').replace('T', ' ')));

        var applies = el('td');
        applies.appendChild(el('div', null, r.trigger_key));
        applies.appendChild(el('div', 'state',
            r.trigger_type + ' \\u00b7 ' + r.scope + '-scoped'));
        tr.appendChild(applies);

        var dir = el('td');
        dir.appendChild(el('span', 'pill ' + r.direction, r.direction));
        tr.appendChild(dir);

        tr.appendChild(el('td', 'why', r.admin_reasoning));

        var used = el('td', 'used' + (r.use_count ? '' : ' never'));
        used.textContent = r.use_count
            ? (r.use_count + (r.use_count === 1 ? ' time' : ' times'))
            : 'never';
        tr.appendChild(used);

        var state = el('td');
        state.appendChild(el('div', 'state ' + st[1], st[0]));
        if (r.expires_at && !r.revoked_at) {
            state.appendChild(el('div', 'state st-expired',
                'expires ' + r.expires_at.replace('T', ' ')));
        }
        if (r.suspended_by_version) {
            state.appendChild(el('div', 'state',
                'by baseline ' + r.suspended_by_version));
        }
        tr.appendChild(state);

        tr.appendChild(actionCell(r));
        tbody.appendChild(tr);
    });
}

function actionCell(r) {
    var td = el('td');
    if (r.revoked_at) return td;

    if (r.suspended) {
        var keep = el('button', null, 'Keep');
        keep.onclick = function() {
            keep.disabled = true;
            post('/api/ai/context/suspension',
                 {id: r.id, resolution: 'kept'}, after(td));
        };
        var drop = el('button', 'danger', 'Retire');
        drop.onclick = function() {
            drop.disabled = true;
            post('/api/ai/context/suspension',
                 {id: r.id, resolution: 'revoked'}, after(td));
        };
        td.appendChild(keep);
        td.appendChild(document.createTextNode(' '));
        td.appendChild(drop);
        return td;
    }

    // Two-step confirm, deliberately in-page: a window.confirm() blocks every
    // subsequent browser event, and revoking a restrictive entry LOOSENS the
    // system, so it deserves a deliberate second click rather than a reflex.
    var btn = el('button', 'danger', 'Revoke');
    btn.onclick = function() {
        if (btn.className.indexOf('armed') === -1) {
            btn.className = 'danger armed';
            btn.textContent = 'Confirm revoke?';
            setTimeout(function() {
                if (btn.className.indexOf('armed') !== -1) {
                    btn.className = 'danger';
                    btn.textContent = 'Revoke';
                }
            }, 4000);
            return;
        }
        btn.disabled = true;
        post('/api/ai/context/revoke', {id: r.id}, after(td));
    };
    td.appendChild(btn);
    return td;
}

function after(td) {
    return function(ok, err) {
        if (ok) { load(); return; }
        td.appendChild(el('div', 'err', err || 'failed'));
    };
}

function load() {
    fetch('/api/ai/context/learned')
        .then(function(r) { return r.json(); })
        .then(render)
        .catch(function() {
            document.getElementById('empty').style.display = '';
            document.getElementById('empty').textContent =
                'Could not load learned context.';
        });
}
load();
</script>
</body>
</html>"""


def _route_context_page():
    """GET /ai/context — the §4.5 review surface page.

    Admin-only, same as the JSON routes beneath it. The page ships no data of
    its own: it fetches from /api/ai/context/learned, so there is exactly one
    read path to secure and one to audit, not two.
    """
    from flask import Response
    return Response(_CONTEXT_PAGE, mimetype="text/html")


# ─────────────────────────────────────────────────────────────────────────────
# §4.5 review surface — "what your AI has learned"
#
# ⚠ ALL THREE ARE ADMIN ON BOTH VERBS (operator decision, 2026-08-27), and the
# read side being admin is deliberate rather than an oversight. Revoking a
# RESTRICTIVE entry LOOSENS the system — it is the same class of act as granting
# authority, so it sits at the same bar as the grant itself. Splitting view down
# to sub_admin was considered and declined: the page's whole content is the
# reasoning behind security decisions, which is not viewer-grade material.
#
# ⚠ These routes are NOT in `_AUTH_EXEMPT`, and that ABSENCE IS the
# authentication for module routes — inverted from dashboard.py's routes. Adding
# an entry here would BE the vulnerability, not a fix for one.
# ─────────────────────────────────────────────────────────────────────────────

def _route_context_learned():
    """GET /api/ai/context/learned — the review surface (§4.5).

    Returns inactive rows too, by design: an expired or revoked entry that
    vanished from the page would make "no longer applied" indistinguishable
    from "never happened" (§4.4).
    """
    from flask import request, jsonify
    from modules.ai_engine import context_store
    cls = request.args.get("action_class") or None
    rows = context_store.review_rows(cls)
    return jsonify({
        "ok": True,
        "entries": rows,
        "counts": {
            "total": len(rows),
            "active": sum(1 for r in rows if r["active"]),
            "suspended": sum(1 for r in rows if r["suspended"]),
            # Surfaced separately because a suspension is the one state that is
            # WAITING ON A HUMAN. It should read as a queue, not a status.
            "awaiting_review": sum(1 for r in rows if r["suspended"]),
        },
    })


def _route_context_revoke():
    """POST /api/ai/context/revoke — retire one entry. Soft, logged, permanent."""
    from flask import request, jsonify
    from modules.ai_engine import context_store
    if not request.is_json:
        # Explicit, matching the email_security precedent. A form-encoded POST
        # already fails (get_json returns None, so `id` is absent and this 400s)
        # -- but that is an IMPLICIT defence resting on a detail a later edit
        # could remove without noticing. A cross-origin form post is the CSRF
        # vector here; state it as a gate rather than inheriting it as luck.
        return jsonify({"ok": False, "error": "JSON content-type required"}), 415
    data = request.get_json(silent=True) or {}
    entry_id = data.get("id")
    if entry_id is None:
        return jsonify({"ok": False, "error": "id is required"}), 400
    actor = _current_actor() or "unknown"
    try:
        n = context_store.revoke_learned(entry_id, actor)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "id must be an integer"}), 400
    if not n:
        # Explicit: already revoked, or no such row. NOT reported as success —
        # a no-op that returns ok:True is a failed read wearing a result's face.
        return jsonify({"ok": False,
                        "error": "no active entry with that id"}), 404
    return jsonify({"ok": True, "revoked": entry_id})


def _route_context_resolve():
    """POST /api/ai/context/suspension — decide a suspended entry's fate (§4.7).

    `resolution` is 'kept' or 'revoked'. There is deliberately no automatic
    resolution and no default: §4.7's whole point is that neither the vendor
    baseline nor the customer's calibration silently wins.
    """
    from flask import request, jsonify
    from modules.ai_engine import context_store
    if not request.is_json:                       # see _route_context_revoke
        return jsonify({"ok": False, "error": "JSON content-type required"}), 415
    data = request.get_json(silent=True) or {}
    entry_id, resolution = data.get("id"), data.get("resolution")
    if entry_id is None or resolution is None:
        return jsonify({"ok": False,
                        "error": "id and resolution are required"}), 400
    actor = _current_actor() or "unknown"
    try:
        n = context_store.resolve_suspension(entry_id, resolution, actor)
    except context_store.ContextWriteRejected as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "id must be an integer"}), 400
    if not n:
        return jsonify({"ok": False,
                        "error": "no suspended entry with that id"}), 404
    return jsonify({"ok": True, "id": entry_id, "resolution": resolution})


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
            ("/api/ai/automation_readiness", _route_automation_readiness, {"methods": ["GET"]}),
            ("/api/ai/upsell_dismiss",     _route_upsell_dismiss,    {"methods": ["POST"]}),
            ("/api/ai/upsell_restore",     _route_upsell_restore,    {"methods": ["POST"]}),
            ("/api/ai/incident",           _route_incident,          {"methods": ["GET"]}),
            ("/api/ai/incident/simulate",  _route_incident_simulate, {"methods": ["POST"]}),
            # §4.5 review surface. Admin on every verb — see the block above
            # these handlers for why the READ side is admin too.
            ("/ai/context",                _route_context_page,      {"methods": ["GET"]}),
            ("/api/ai/context/learned",    _route_context_learned,   {"methods": ["GET"]}),
            ("/api/ai/context/revoke",     _route_context_revoke,    {"methods": ["POST"]}),
            ("/api/ai/context/suspension", _route_context_resolve,   {"methods": ["POST"]}),
        ]
