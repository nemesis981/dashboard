# Roadmap-vs-state audit — 2026-08-07

> Read-only audit (Rule 1). Classifies every `docs/roadmap/*.md` item against actual
> project state (code, `git log`, ADRs, HANDOFF). Baseline for the Morning Status
> roadmap line (latest date wins). No PII / infra values (Rule 8): commit hashes +
> filenames only. Supersedes `roadmap-state-audit-2026-08-06.md` (kept as history).

**Tally: 8 SHIPPED · 11 PARTIAL · 57 STUB/PARKED — 76 total.**

## Drift since 2026-08-06 baseline

### File-set: none
`ls docs/roadmap/*.md` count is 76, matching the 08-06 baseline exactly.
`git log --diff-filter=A --since=2026-08-06 -- docs/roadmap/` and the `-D` counterpart
are both empty — no additions, no removals. The two previously-uncommitted files flagged
in the 08-06 baseline (`device-coverage-tier-indicator.md`, `ipv6-rogue-router-detection.md`)
remain as they were; `venue-guest-network.md` remains modified/uncommitted, unchanged status,
still nobody's per HANDOFF.

### Shipping: one real upgrade found — `track-c-metadata-tier-build-plan.md` (PARKED → PARTIAL)

The baseline's 8 SHIPPED + 10 PARTIAL files were spot-checked against commit subjects since
2026-08-06; no further reclassification found among them (the DHCP/Tailscale/connectivity-
notifier work landed today maps to ADR/HANDOFF-tracked features with no dedicated roadmap
file, same pattern the 08-06 baseline noted for its own same-period activity).

**Real find, from the PARKED keyword sweep against commit subjects since 08-06:**

- **`track-c-metadata-tier-build-plan.md`** — header still reads *"Approved to build...
  No code written yet"* (unrefreshed), but two of its own steps now have shipped commits
  today, both explicitly labeled in the commit subject:
  - Requirement 0 (consent gate) — `ccf02aa feat(nemesis_agent): add consent.py -- Track C
    Requirement 0, the collection consent gate` (43/43 tests, per HANDOFF).
  - Step 2 (connection-event schema) — `e14e5a4 feat(nemesis_agent): add conn_events.py --
    Track C step 2, connection-event schema` (52/52 tests, per HANDOFF).
  - A further "schema v2" tranche (10 files: `conn_events.py`, `test_conn_events.py`, new
    `conn_collector.py` + `test_conn_collector.py`, new `nemesis_agent/tools/etw_probe.py`,
    new `core_module/hw_monitor/test_conn_ingest.py`, `hw_monitor.py`, `database.py`,
    `data_manager.py`, `dashboard.py`) is sitting in the working tree right now
    (`git status --short`), attributed to Window 1, not yet committed — per HANDOFF §3 this
    is Window 2's next priority pickup.
  **Classified PARTIAL, not SHIPPED** — the plan's own scope is the full metadata tier (6–9
  sessions); two steps landing plus a third in-flight is real progress, not completion. Header
  refresh (drop "No code written yet") owed as a small follow-up, same shape as the
  `agent-rebuild-config-driven.md` gap the 08-06 baseline flagged and left unrefreshed itself.
- No other PARKED item showed a specific (non-generic-word) match against commit subjects
  since 08-06. Broad keyword hits against "tailscale"/"preauth"/"connectivity" landed on 13
  files but all were the same generic-word noise the 08-04/08-06 method notes already predict
  (design docs that happen to mention Tailscale/connectivity in passing, not the specific
  mint-at-download / connectivity-notifier work that shipped today) — checked individually,
  none reclassified.

## SHIPPED (8) — unchanged from 08-06 baseline
See `roadmap-state-audit-2026-08-06.md` for the full evidence table; no changes this pass.

## PARTIAL (11) — 10 unchanged + 1 new
See `roadmap-state-audit-2026-08-06.md` for the 10 unchanged entries' evidence.

| Item | State |
|---|---|
| **track-c-metadata-tier-build-plan** (new this pass) | Requirement 0 (consent gate, `ccf02aa`) + Step 2 (connection-event schema, `e14e5a4`) shipped today, 43/43 + 52/52 tests per HANDOFF. Schema v2 tranche (10 files) held uncommitted in working tree, owed to Window 2 as next pickup. Full plan scope (6–9 sessions) remains far from complete — PARTIAL, not SHIPPED. Header still says "No code written yet," owed a refresh. |

## Method
Same as 2026-08-06: `ls docs/roadmap/*.md` file-count/name diff against the prior baseline,
`git log --diff-filter=A`/`-D` provenance for any new/removed files (none this pass),
`git log 2026-08-06..HEAD -- docs/roadmap/<file>.md` per non-parked item to catch silent
shipping, plus a keyword sweep of PARKED filenames against commit subjects since the baseline
date. Baseline doc for tomorrow's Morning Status: this file (2026-08-07), superseding
2026-08-06.
