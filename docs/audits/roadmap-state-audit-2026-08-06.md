# Roadmap-vs-state audit — 2026-08-06

> Read-only audit (Rule 1). Classifies every `docs/roadmap/*.md` item against actual
> project state (code, `git log`, ADRs, HANDOFF). Baseline for the Morning Status
> roadmap line (latest date wins). No PII / infra values (Rule 8): commit hashes +
> filenames only. Supersedes `roadmap-state-audit-2026-08-04.md` (kept as history).
> No audit ran on 2026-08-05, so this covers two build days' drift (08-04 full day +
> 08-05 full day, 90 commits total since the prior baseline).

**Tally: 8 SHIPPED · 10 PARTIAL · 58 STUB/PARKED — 76 total.**

## Drift since 2026-08-04 baseline

### File-set: +3, none removed (73 → 76)
| New file | Added in | Class |
|---|---|---|
| udp-default-deny-scoping.md | `32dcc7d` (2026-08-04) | PARKED — self-declares "scoping doc... Not currently built." |
| device-coverage-tier-indicator.md | uncommitted, working tree | PARKED — self-declares "parked (capture-only)," captured 2026-08-05. Still uncommitted as of this audit; not Window 2's to touch absent a handoff (see HANDOFF §6). |
| ipv6-rogue-router-detection.md | uncommitted, working tree | PARKED — self-declares "parked (capture-only)," captured 2026-08-05. Same uncommitted status as above. |

Traced via `git log --diff-filter=A --since=2026-08-04 -- docs/roadmap/` (one hit,
`udp-default-deny-scoping.md`) plus `git status --short` for the two untracked files
already flagged in HANDOFF §6. `--diff-filter=D` over the same window is empty — no
removals. `ls docs/roadmap/*.md` count (76) matches 73 baseline + 3 new, confirming no
untracked-drift beyond the two files already known and flagged.

### Shipping: one real upgrade found — `agent-rebuild-config-driven.md` (PARKED → PARTIAL)

The baseline's 8 SHIPPED + 9 PARTIAL files were re-checked individually
(`git log --since=2026-08-04 -- docs/roadmap/<file>.md`). Only two had any commit at
all, and both are the header-stale fix the 08-04 baseline itself flagged, applied same
day (`77abe9c docs(roadmap): correct two stale headers flagged by the 08-04 audit`) —
no reclassification, just the header catching up to reality:
`hw-anomaly-snapshots-top-processes-archival.md`, `storage-monitoring-retention-supplement-2026-08-03.md`.

**Real find, from the 56-item PARKED keyword sweep against all 90 commit subjects
since 2026-08-04:** most hits were the same generic-word noise the 08-04 method note
predicted (`agent`, `dashboard`, `scope`, `server`, `scan`, `diagnostics`, `network`,
`device`, `connection`, `settings` are common commit-subject words unrelated to any
specific roadmap item). One hit was substantive:

- **`agent-rebuild-config-driven.md`** — its own header now reads *"Status: parked →
  ACTIVE (2026-08-04) for the observation-layer foundation below"* (commit `ddbfc90`).
  The doc splits its scope explicitly: the full config-driven agent rebuild stays
  parked, but a narrower "observation-layer foundation" (5 items, operator-approved
  standalone) went active 2026-08-04 and — per HANDOFF and direct commit citation —
  **all 5 items now have a shipped commit:**
  1. Agent integrity attestation — `9004bb4`, `12d58fe`, `7b45bfd`, `4133dd9` (Tier 1
     client+server scaffold, dispatcher wiring, self-sustaining queue).
  2. Full process enumeration — `3fe91c3` (observation layer, replaces top-10-by-CPU
     sample).
  3. UDP-visible connection reporting — same commit `3fe91c3` ("UDP attribution").
  4. IPv6 connection-type fix — `41ba66f`, closed `4eb6be2`.
  5. Event-triggered early check-in — `f35ad51` (`request_early_beat`).

  **Classified PARTIAL, not SHIPPED** — the doc's own scope still includes the
  config-driven rebuild described in the rest of the file, which remains
  parked/capture-only per the header's own words, and the header has not been updated
  to mark the 5-item foundation itself complete (no "shipped"/"done" marker found in
  the file — checked directly). This is a live header-vs-reality gap worth flagging
  for a header refresh, same shape as the two already caught in the 08-04 baseline,
  but caught here before it aged into one.
- **`memory-injection-detection-design.md`** — checked directly because of adjacent
  hits (`71f653d` "resolve Tier 3 vs memory-injection ownership question"). Confirmed
  **not reclassified**: the doc's own header explicitly keeps the detection technique
  itself "capture-only" and separates it from the now-active observation-layer
  foundation above (which is `agent-rebuild-config-driven.md`'s scope, not this doc's).
  No tally change.
- **`windows-agent-memory-injection-rework-prereqs.md`** — re-checked, unchanged:
  still self-declared SUPERSEDED (folded into `memory-injection-detection-design.md`
  since 08-03), still PARKED, no new tally effect.
- No other PARKED item showed a specific (non-generic-word) match against the 90
  commit subjects.

## Notable same-period activity NOT reflected further in this tally (by design)
Two build days (08-04 Tier 1 attestation/observation-layer, 08-05 chat-widget rescue +
analyze-alert chain + ADR 0019 Phase 2 + pseudonymization) map mostly to ADR/HANDOFF-
tracked work with no corresponding `docs/roadmap/` item beyond what's captured above:
- ADR 0019 Phase 2 (enforcement-visibility panel) + the local-time timestamp fix it
  depends on.
- Chat-widget rescue arc: three sequential defects (duplicate DOM id, literal-newline
  `SyntaxError`, `sqlite3.Row` gap) plus two features (copyable answers, Enter-to-submit).
- Analyze-alert chain: three sequential defects (off-by-one indices/gate, empty
  deep-linked alert body, fenced-JSON parse failure clobbering `risk_level`).
- Pseudonymization (`f743b9a`) — new module, wired into `analyze_alert()`, plus
  disclosure of a separate un-fixed `enrich_ip()` exposure (AbuseIPDB/ipinfo.io).
- Malware-detection/AI-analysis completeness audit findings (Layer D honesty gap,
  the above exposure) — filed to PUNCHLIST, not roadmap files.

## SHIPPED (8) — unchanged from 08-04 baseline
| Item | Evidence |
|---|---|
| connection-type-awareness | `b3146fe` — link_type WiFi/ethernet, stored in `agent_devices`, shown in dashboard |
| diagnostics-anthropic-status-banner | `b7b7174` — `_poll_anthropic_status()` in `ai_engine/module.py` |
| diagnostics-connectivity-watcher-tool | `53975ea`–`086a659` — watcher service, VPN probes, dashboard card, systemd unit |
| hardware-stable-identifiers | `daf273f` — fingerprint (Win+Linux), TOFU, `agent_devices` migration; Mac deferred |
| malware-yara-rule-autoupdate | `0506aed`/`79a4996`/`5ef9a93` — auto-update mechanism, SSRF-guarded routes, rate limit |
| idle-lock-walk-away-protection | `219c282`/`0e15c22` — enforcement + overlay live in `dashboard.py` |
| hw-anomaly-snapshots-top-processes-archival | `97175ba` — storage/retention piece 4; header now correct (`77abe9c`) |
| storage-monitoring-retention-supplement-2026-08-03 | `f9ad33f`/`4ab95dc`/`1fec8b7`/`58fe763` — items 1+3 live; header now correct (`77abe9c`) |

## PARTIAL (10) — 9 unchanged + 1 new
| Item | State |
|---|---|
| clean-uninstall-build-spec | Phases 1–3 built; e2e VM uninstall lifecycle test still UNRUN |
| installer-unified-v1.0.6 | Delivery + self-onboard live; two before-trip fixes remain |
| malware-detection-pipeline | Layer A+B live; Layers C/D scaffold only |
| latent-bug-fleet-clamav-only | Unchanged; fix is ADR 0004's own unbuilt original Step 4 |
| lateral-movement-outbreak-detection | Design complete, no code; v2 candidate |
| open-source-threat-feeds | Design complete, no backend code |
| sandbox-first-software-testing | Design complete, no code; requires VM Lab |
| sandbox-to-system-migration | Design complete, no code; requires VM Lab + software_inventory |
| data-retention-and-archival-policy | `dm_operation_log` coalescing shipped; broader Tier A retention not built |
| **agent-rebuild-config-driven** (new this pass) | Observation-layer foundation (5 items: attestation, full process enumeration, UDP-visible connections, IPv6 fix, event-triggered check-in) all have shipped commits 08-04/08-05, per header's own "parked → ACTIVE" split. Not SHIPPED: doc's own broader config-driven-rebuild scope stays parked, and header has no completion marker for the 5-item foundation yet — flagged for a header refresh. |

## Method
Same as 2026-08-04: `ls docs/roadmap/*.md` file-count/name diff against the prior
baseline, `git log --diff-filter=A` (and `-D` to confirm no removals) provenance for any
new files, `git log <baseline-date>..HEAD -- docs/roadmap/<file>.md` per non-parked item
to catch silent shipping, plus a keyword sweep of all baseline-PARKED filenames against
every commit subject since the baseline date. Baseline doc for tomorrow's Morning
Status: this file (2026-08-06), superseding 2026-08-04.
