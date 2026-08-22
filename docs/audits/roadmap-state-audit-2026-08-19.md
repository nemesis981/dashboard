# Roadmap-vs-state audit — 2026-08-19

> Read-only audit (Rule 1). Classifies every `docs/roadmap/*.md` item against actual
> project state (code, `git log`, ADRs, HANDOFF). Baseline for the Morning Status
> roadmap line (latest date wins). No PII / infra values (Rule 8): commit hashes +
> filenames only. Supersedes `roadmap-state-audit-2026-08-07.md` (kept as history).
>
> **Gap note:** no baseline refresh ran between 2026-08-07 and today — 12 days, ~59
> commits. This pass covers that whole window in one diff rather than the usual
> day-over-day increment.

**Tally: 8 SHIPPED · 11 PARTIAL · 61 STUB/PARKED — 80 total.**

## Drift since 2026-08-07 baseline

### File-set: +4, none removed (76 → 80)

`ls docs/roadmap/*.md` count is 80 vs. the 08-07 baseline's 76. Confirmed via
`git log --diff-filter=A --since=2026-08-07 -- docs/roadmap/` (below) — fully accounts for
the delta, no unexplained files:

| File | Commit | Date | Status header |
|---|---|---|---|
| `malware-layer-b-behavioral-monitoring.md` | `f7dc88f` | 08-18 | parked (capture-only) |
| `dashboard-pass-freshness-review.md` | `6a13149` | 08-08 | queued (read-only check) |
| `v2-completion-checklist.md` | `6a13149` | 08-08 | capture, operator-directed |
| `gateway-mode-scoping.md` | `033a1cb` | 08-08 | scoping doc, no code changed |

`git log --diff-filter=D --since=2026-08-07 -- docs/roadmap/` is empty — no removals.
All 4 new files classify STUB/PARKED (queued/capture/scoping-only, no code) — none add to
SHIPPED or PARTIAL.

### Shipping: no reclassification found this pass

The baseline's 8 SHIPPED + 11 PARTIAL items were spot-checked against `git log --since
2026-08-07` commit subjects (59 commits, listed in the worklog/supplement for this date) and
against direct `git log -- docs/roadmap/<file>.md` history per item. No item crossed a
tally boundary (PARKED→PARTIAL, PARTIAL→SHIPPED) this pass:

- **`track-c-metadata-tier-build-plan.md`** (already PARTIAL as of 08-07) — further Track C
  work landed since (`4a82785` step 5 seen-set, `180514a` schema v2, `faaf9a2` doc
  correction), plus adjacent consent/Tier-2-gate infrastructure (`8a671f2`, `080c90a`,
  `db19c20`). Still **PARTIAL, not SHIPPED** — the plan's full 6–9 session scope remains
  incomplete; no header completion marker.
- **`agent-rebuild-config-driven.md`** (already PARTIAL, "parked → ACTIVE" split as of
  08-06) — the observation-layer foundation it covers kept building this window: `165be15`
  (per-process memory sampler, `procmem.py`) plus, per HANDOFF §1/§3, further uncommitted-
  then-committed work (`membudget.py`, `mem_appliance.py` in `b143c10`) sitting on top of
  it. **Still PARTIAL** — same status, more progress within it; not a tally-boundary
  crossing. Worth flagging for Window 2's own header-refresh backlog, not a drift finding.
- **`windows-agent-memory-injection-rework-prereqs.md`** — superseded stub (see its own
  header), folds into `memory-injection-detection-design.md` which is itself already
  reflected via `agent-rebuild-config-driven.md` above. No independent reclassification.
- **`malware-detection-pipeline.md`** (PARTIAL: "Layer A+B live; Layers C/D scaffold
  only") — `f7dc88f` (08-18) is a Layer B *honesty correction* (struck an overclaim), not
  new capability. Status unchanged.
- No other SHIPPED/PARTIAL item showed matching commit activity since 08-07.
- Spot-checked keyword sweep against the 59 commit subjects (memory/RAM, malware Layer B,
  licensing, HTTP/2, dashboard, diagnostics, nemesis_fwd, DHCP, Track C, tailnet, consent,
  Tier 2 gate) against PARKED filenames not otherwise covered above:
  `enterprise-gap-audit-2026.md`, `single-user-assumptions-audit.md`,
  `dashboard-roles-access-control.md`, `server-side-session-store.md` — no commits against
  any of these files or matching subject-line activity since 08-07. Not exhaustive against
  all 61 PARKED filenames individually (12-day/59-commit gap makes a full per-file sweep
  impractical for a "quick recheck" pass) — the licensing engine, DHCP health work, and
  Track C/consent/Tier-2-gate infrastructure that shipped this window all map to
  ADR/HANDOFF-tracked features with no dedicated roadmap file, the same pattern prior
  baselines noted for their own periods' activity.

## SHIPPED (8) — unchanged from 08-07 baseline
See `roadmap-state-audit-2026-08-06.md` for the full evidence table; no changes this pass.

## PARTIAL (11) — unchanged from 08-07 baseline
See `roadmap-state-audit-2026-08-07.md` for the evidence table. Two items (`track-c-
metadata-tier-build-plan`, `agent-rebuild-config-driven`) show continued in-bucket progress
this pass (see Shipping section above) but neither crosses to SHIPPED.

## Method
Same as prior baselines: `ls docs/roadmap/*.md` file-count/name diff against the prior
baseline, `git log --diff-filter=A`/`-D` provenance for new/removed files, `git log
2026-08-07..HEAD -- docs/roadmap/<file>.md` per non-parked item to catch silent shipping,
plus a keyword sweep of the 59-commit window's subjects against PARKED filenames not
already covered by the direct per-file checks. Baseline doc for tomorrow's Morning Status:
this file (2026-08-19), superseding 2026-08-07.
