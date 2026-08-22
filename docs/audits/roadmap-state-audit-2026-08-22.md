# Roadmap-vs-state audit — 2026-08-22

> Read-only audit (Rule 1), refreshed as an explicit follow-up to the 2026-08-22 Morning
> Status pass (`docs/briefing/2026-08-22.md`), which found live shipping drift the 08-19
> baseline hadn't caught. Classifies every `docs/roadmap/*.md` item against actual project
> state (code, `git log`, ADRs, HANDOFF). Baseline for the Morning Status roadmap line
> (latest date wins). No PII/infra values (Rule 8): commit hashes + filenames only.
> Supersedes `roadmap-state-audit-2026-08-19.md` (kept as history).

**Tally: 10 SHIPPED · 12 PARTIAL · 59 STUB/PARKED — 81 total.**

## Drift since 2026-08-19 baseline

### File-set: +1, none removed (80 → 81)

`ls docs/roadmap/*.md` count is 81 vs. the 08-19 baseline's 80. Confirmed via
`git log --diff-filter=A --since=2026-08-19 -- docs/roadmap/`: exactly one new file,

| File | Commit | Date | Status header |
|---|---|---|---|
| `ram-recovery-windows-platform-gap.md` | `ebfa0bb` | 08-19 | parked (capture-only) |

`git log --diff-filter=D --since=2026-08-19 -- docs/roadmap/` is empty — no removals. The new
file classifies STUB/PARKED (capture-only stub describing a gap in Windows coverage; the
Linux-side manual RAM recovery it documents the gap against shipped same-day in `368b828`,
but the roadmap file itself is specifically about the *un-built* Windows platform work, so
PARKED is the correct classification for the file, not a drift item on its own).

### Shipping: 3 items reclassified — real drift, not header-trusted

This is the substantive finding of this refresh. The 08-19 baseline's own text explicitly
warned that STUB/PARKED headers can go stale relative to shipped code and should not be
trusted at face value; this pass confirmed three concrete instances of exactly that, via
direct `git show --stat` inspection of the commits (not the roadmap files' own prose, which
had not been touched):

- **`malware-layer-b-behavioral-monitoring.md`: PARKED → SHIPPED.** Commits `e81cb41`
  ("feat(zero-day): M2 -- behavioral monitoring pipeline (Falco/Sysmon)") and `c091ed5`
  ("feat(zero-day): gap1 -- M2 behavioral monitor deployment mechanism (Falco)"), both landed
  2026-08-21. Delivers exactly what the stub specified: `core_module/hw_monitor/
  behavioral_ingest.py`, `nemesis_agent/behavioral_agent.py`, the Linux deploy mechanism
  (`nemesis_agent/deploy_behavioral_linux.sh`, 261 lines), and a shipped vendor guide
  (`docs/CUSTOM_FALCO.md`, 129 lines) — full feature, tests, and doc together. Roadmap file's
  own status header updated in this pass to point at this evidence.
- **`malware-local-isolated-sandbox.md`: PARKED → SHIPPED.** Commits `7f499a7` ("feat(zero-day):
  gap2 -- M3 detonation base image + guest observation") and `9f0b769` ("feat(zero-day): M3 --
  local detonation sandbox (disposable-VM isolation)"), both 2026-08-21. Delivers the
  disposable-VM detonation design the stub called for (`modules/malware_detection/sandbox.py`,
  +357 lines; `build_detonation_base_linux.sh`, 178 lines) plus `docs/CUSTOM_DETONATION_SANDBOX.md`
  (102 lines). Roadmap file's own status header updated in this pass.
- **`malware-layer-d-local-ml.md`: PARKED → PARTIAL (not SHIPPED).** Commits `ac53b0c`
  ("feat(zero-day): M4 -- Layer D local ML classifier pipeline (no model shipped)") and
  `719d93f` ("feat(zero-day): gap3 -- M4 model training path (dependency-free, endpoint-side)"),
  both 2026-08-21. Delivers the classifier pipeline and a model-training path
  (`ml_classifier.py`, `ml_features.py`, `ml_model.py`, `ml_train.py`,
  `docs/CUSTOM_LAYERD_MODEL.md`) — but `ac53b0c`'s own commit message states directly "no
  model shipped." Classified **PARTIAL, not SHIPPED**: the pipeline exists but the thing the
  stub is actually about (a trained classifier making real verdicts) does not yet exist.
  Roadmap file's own status header updated in this pass to PARTIAL with this caveat stated
  explicitly.

No other PARKED-filename keyword matches were found against the remaining commits in the
08-19→08-22 window (memory/RAM ladder work, agent GUI/DMZ, QUIC decoder, licensing rebind,
tickets/agent-errors bridge, ai-engine rate-degradation/pseudonymization) — none map to a
PARKED roadmap filename, consistent with the pattern prior baselines noted of shipped work
landing without a dedicated roadmap file.

### Baseline's other non-parked items: no further crossings

`track-c-metadata-tier-build-plan.md` and `agent-rebuild-config-driven.md` (the two items the
08-19 baseline flagged as actively progressing) were spot-checked again against
`git log --since=2026-08-19` — no additional commits touched either roadmap file's subject
area in this window. Both remain **PARTIAL**, unchanged.

## SHIPPED (10)
The 8 items unchanged from the 08-19/08-07/08-06 baselines (see `roadmap-state-audit-2026-08-06.md`
for their evidence table) **plus**:
- `malware-layer-b-behavioral-monitoring.md` (new this pass — see Drift section above)
- `malware-local-isolated-sandbox.md` (new this pass — see Drift section above)

## PARTIAL (12)
The 11 items unchanged from the 08-19/08-07 baselines (see `roadmap-state-audit-2026-08-07.md`
for their evidence table) **plus**:
- `malware-layer-d-local-ml.md` (new this pass — see Drift section above)

## STUB/PARKED (59)
The 61 items from the 08-19 baseline, minus the 3 reclassified above, plus the 1 new file
(`ram-recovery-windows-platform-gap.md`): 61 − 3 + 1 = 59.

## Method
Same as prior baselines: `ls docs/roadmap/*.md` file-count/name diff against the prior
baseline, `git log --diff-filter=A`/`-D` provenance for new/removed files, `git log
2026-08-19..HEAD -- docs/roadmap/<file>.md` per non-parked item to catch silent shipping,
plus a keyword sweep of the post-08-19 commit window's subjects against PARKED filenames.
This pass additionally did what the 08-19 baseline flagged as impractical for a "quick
recheck" (a full per-file sweep) for the specific 08-21 zero-day M1-M4 commit cluster, since
that cluster's own commit subjects ("M2 behavioral," "M3 detonation," "M4 Layer D ML")
directly named the exact PARKED stubs they matched — a targeted, not exhaustive, follow-up.
The remaining ~59 PARKED filenames were not individually re-swept this pass beyond the
keyword scan noted above. Baseline doc for tomorrow's Morning Status: this file (2026-08-22),
superseding `roadmap-state-audit-2026-08-19.md`.
