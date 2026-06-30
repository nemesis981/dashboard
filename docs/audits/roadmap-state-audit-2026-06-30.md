# Roadmap-vs-state audit — 2026-06-30

> Read-only audit (Rule 1). Classifies every `docs/roadmap/*.md` item against actual
> project state (code, `git log`, ADRs, HANDOFF). Baseline for the Morning Status
> roadmap line. No PII / infra values (Rule 8): commit hashes + filenames only.

**Tally: 3 SHIPPED · 6 PARTIAL · 34 STUB/PARKED — 43 total.**

Key finding: HANDOFF is honest — everything it calls "captured" genuinely is. No silent
doc-vs-code drift. ~79% of the roadmap is pure capture (by design, Rule 7).

## SHIPPED (3)
| Item | Evidence |
|---|---|
| connection-type-awareness | `b3146fe` — link_type WiFi/ethernet, stored in `agent_devices`, shown in dashboard |
| diagnostics-anthropic-status-banner | `b7b7174` — `_poll_anthropic_status()` in `ai_engine/module.py` |
| diagnostics-connectivity-watcher-tool | `53975ea`–`086a659` — watcher service, VPN probes, dashboard card, systemd unit |

## PARTIAL (6) — the malware arc
| Item | State |
|---|---|
| malware-detection-pipeline | Layer A (ClamAV+YARA) `5262fc7` + Layer B canary `def1b13` live; Layers C/D scaffold only |
| latent-bug-fleet-clamav-only | Documented; fix lives in ADR 0004 (status *Proposed*, not built) |
| lateral-movement-outbreak-detection | Design complete, no code; v2 candidate |
| open-source-threat-feeds | Design complete `9eb617c`, no code; depends on community backend |
| sandbox-first-software-testing | Depends on VM Lab (parked); no code |
| sandbox-to-system-migration | Full capture `9eb617c`; depends on VM Lab + `software_inventory` table; no code |

## STUB/PARKED (34)
All self-declare "parked" / "capture-only" / "do NOT build yet" in their own headers.

- Community/enterprise/MSP (13): community-reporter-identity, community-signal-dedup,
  enterprise-gap-audit-2026, msp-central-management, responsive-dashboard-multiuser-ready,
  settings-loaded-vs-enabled-refactor, single-user-assumptions-audit, support-bundle,
  three-snapshot-vendor-package, verified-partner-program, venue-guest-network,
  system-changes-badge, nemesis-test-lab
- Device/agent (9): adaptive-link-aware-agent-clock-sync, agent-auto-load-ownership,
  agent-rebuild-config-driven, device-identification, hardware-stable-identifiers,
  db-resilience-backup-promotion, post-update-module-repair, nemesis-overhead-meter,
  installer-email-delivery
- Diagnostics-AI design set (8): diagnostic-scan-scope,
  diagnostics-ai-reassurance-escalation-routing, diagnostics-ai-tool-aware-loop,
  diagnostics-classification, diagnostics-standalone-runner, pre-escalation-support-search,
  ai-generated-tutorial-walkthrough, product-thesis-built-in-it-expertise
- Malware sub-layers (4): malware-cloud-sandbox-optional, malware-layer-d-local-ml,
  malware-local-isolated-sandbox, malware-yara-rule-autoupdate

## Method
4 parallel read-only agents, each a batch of ~10 files, classifying against codebase +
`git log` + ADRs + HANDOFF. This file is the **baseline** the Morning Status roadmap line
diffs against each session.

**Caveat (do not header-trust):** the 3 SHIPPED items had carried stale
`Status: parked … do NOT build yet` headers — the docs were never updated when the features
shipped (refreshed to `Status: SHIPPED (<commit>)` in this same change). The morning check
still must NOT rely on the `Status:` header as its source of truth — headers go stale again
the next time something ships — so it diffs reality (file set + code/`git log` for the 9
non-parked items + keyword scan of recent commits) against this baseline instead.
