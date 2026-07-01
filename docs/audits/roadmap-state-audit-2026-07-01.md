# Roadmap-vs-state audit — 2026-07-01

> Read-only audit (Rule 1). Classifies every `docs/roadmap/*.md` item against actual
> project state (code, `git log`, ADRs, HANDOFF). Baseline for the Morning Status
> roadmap line (latest date wins). No PII / infra values (Rule 8): commit hashes +
> filenames only. Supersedes `roadmap-state-audit-2026-06-30.md` (kept as history).

**Tally: 4 SHIPPED · 7 PARTIAL · 33 STUB/PARKED — 44 total.**

Verdict: not "no drift" — but no *silent* drift. HANDOFF honestly reflects both moved
items; the only stale artifact was the `installer-unified-v1.0.6.md` status header
(fixed this session). Diffed against the 2026-06-30 baseline (3 / 6 / 34, 43 total).

## Drift since 2026-06-30 baseline

### File-set: +1 (accounted-for)
- One roadmap file added, none removed: `installer-unified-v1.0.6.md`.
- Timeline: the 06-30 baseline was committed 08:19 (`7cd7adf`); the file was added the
  same day at 12:43 (`fd50075`), ~4.5h later — a real post-snapshot addition, not a
  miscount. Nothing added 2026-07-01.

### Shipping: 2 items moved
| Item | Move | Evidence |
|---|---|---|
| hardware-stable-identifiers | PARKED → **SHIPPED** | `daf273f` — `hw_stable_id` / `hw_is_virtual` columns + guarded `PRAGMA`+`ALTER` migration + `_match_fingerprint()` in `alert_manager/hw_monitor.py`; Windows+Linux live & tested. Mac = interface-only (deferred). |
| installer-unified-v1.0.6 | (new file) → **PARTIAL** | `2e27a60` (Phase-1 delivery foundation) + `a21b782` (self-onboard, v1.0.7, proven end-to-end). Roadmap header had gone stale ("NOT built") — corrected this session. |

No other parked theme (community / MSP / diagnostics-AI / malware sub-layers) has any
feat commit since baseline — the remaining 33 parked items are unchanged.

## SHIPPED (4)
| Item | Evidence |
|---|---|
| connection-type-awareness | `b3146fe` — link_type WiFi/ethernet, stored in `agent_devices`, shown in dashboard |
| diagnostics-anthropic-status-banner | `b7b7174` — `_poll_anthropic_status()` in `ai_engine/module.py` |
| diagnostics-connectivity-watcher-tool | `53975ea`–`086a659` — watcher service, VPN probes, dashboard card, systemd unit |
| hardware-stable-identifiers | `daf273f` — fingerprint (Win+Linux), TOFU, `agent_devices` migration; Mac deferred |

## PARTIAL (7)
| Item | State |
|---|---|
| installer-unified-v1.0.6 | `2e27a60` delivery + `a21b782` self-onboard (v1.0.7) live; two before-trip fixes remain (auto_approve default, double-enroll) |
| malware-detection-pipeline | Layer A (ClamAV+YARA) `5262fc7` + Layer B canary `def1b13` live; Layers C/D scaffold only |
| latent-bug-fleet-clamav-only | Documented; fix lives in ADR 0004 (status *Proposed*, not built) |
| lateral-movement-outbreak-detection | Design complete, no code; v2 candidate |
| open-source-threat-feeds | Design complete `9eb617c`, no code; depends on community backend |
| sandbox-first-software-testing | Depends on VM Lab (parked); no code |
| sandbox-to-system-migration | Full capture `9eb617c`; depends on VM Lab + `software_inventory` table; no code |

## STUB/PARKED (33)
All self-declare "parked" / "capture-only" / "do NOT build yet" in their own headers.
Unchanged vs the 2026-06-30 baseline except `hardware-stable-identifiers` (now SHIPPED,
removed from this list).

- Community/enterprise/MSP (13): community-reporter-identity, community-signal-dedup,
  enterprise-gap-audit-2026, msp-central-management, responsive-dashboard-multiuser-ready,
  settings-loaded-vs-enabled-refactor, single-user-assumptions-audit, support-bundle,
  three-snapshot-vendor-package, verified-partner-program, venue-guest-network,
  system-changes-badge, nemesis-test-lab
- Device/agent (8): adaptive-link-aware-agent-clock-sync, agent-auto-load-ownership,
  agent-rebuild-config-driven, device-identification, db-resilience-backup-promotion,
  post-update-module-repair, nemesis-overhead-meter, installer-email-delivery
- Diagnostics-AI design set (8): diagnostic-scan-scope,
  diagnostics-ai-reassurance-escalation-routing, diagnostics-ai-tool-aware-loop,
  diagnostics-classification, diagnostics-standalone-runner, pre-escalation-support-search,
  ai-generated-tutorial-walkthrough, product-thesis-built-in-it-expertise
- Malware sub-layers (4): malware-cloud-sandbox-optional, malware-layer-d-local-ml,
  malware-local-isolated-sandbox, malware-yara-rule-autoupdate

## Method
Diffed the live file set + `git log 7cd7adf..HEAD` + code re-check of non-parked items
against the 2026-06-30 baseline. This file is the new baseline the Morning Status roadmap
line diffs against (latest date wins).

**Caveat (do not header-trust):** `installer-unified-v1.0.6.md` carried a stale
`NOT built` header while its code had shipped (`2e27a60` + `a21b782`) — the same stale-header
pattern the 06-30 baseline flagged on the 3 originally-SHIPPED items. The morning check must
keep diffing reality (file set + code/`git log`) against this baseline, never the `Status:`
header.
