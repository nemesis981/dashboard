# Roadmap-vs-state audit — 2026-07-02

> Read-only audit (Rule 1). Classifies every `docs/roadmap/*.md` item against actual
> project state (code, `git log`, ADRs, HANDOFF). Baseline for the Morning Status
> roadmap line (latest date wins). No PII / infra values (Rule 8): commit hashes +
> filenames only. Supersedes `roadmap-state-audit-2026-07-01.md` (kept as history).

**Tally: 4 SHIPPED · 8 PARTIAL · 39 STUB/PARKED — 51 total.**

Verdict: no *silent* drift. The 7-file growth since the 07-01 baseline is all
accounted-for (six new parked design captures + one build spec that has since been
built). The only stale artifact was the `clean-uninstall-build-spec.md` status header
("BUILD-READY spec. Not built") — corrected this session to PARTIAL (phases 1–3 built +
de-enroll endpoint deployed live; e2e VM uninstall test still pending).

## Drift since 2026-07-01 baseline

### File-set: +7 (all accounted-for)
Seven roadmap files added, none removed (44 → 51). One graduated to PARTIAL (built),
six are new parked design captures:

| New file | Class | Note |
|---|---|---|
| clean-uninstall-build-spec | **PARTIAL** | Phases 1–3 built (`9321cfe`, `5b03260`, `14ce142`); de-enroll endpoint (:5001) deployed live; e2e VM uninstall test still pending. Header was stale ("Not built") — fixed this session. |
| uninstall-deenroll | PARKED | Originating stub for the above; capture (design item, post-trip). |
| connection-health-subsystem | PARKED | DESIGN of record, not built; staged after current Tailscale work (`e48fd5d`). |
| enrollment-modes-build-spec | PARKED | BUILD-READY design; not yet built; execute-ready post-trip (ADR 0012). |
| interactive-ai-clarification | PARKED | Roadmap capture; future item, post-packaging. |
| server-on-windows-roadmap | PARKED | Capture (what + why; parked); server-on-Windows deployment story. |
| sse-inspection-proxy-build-spec | PARKED | DESIGN CAPTURED, not built. |

### Shipping: 1 item moved
| Item | Move | Evidence |
|---|---|---|
| clean-uninstall-build-spec | (new file) → **PARTIAL** | `9321cfe` (Phase 1 — manifest/ARP/Start-Menu/bundled uninstaller), `5b03260` (Phase 2 — `POST /api/agent/uninstall` on :5001, signed soft-mark de-enroll, deployed live), `14ce142` (Phase 3 — manifest-driven `NemesisUninstall.exe` + consent UX, built + unit-verified). E2e VM uninstall lifecycle test still UNRUN → PARTIAL, not SHIPPED. |

No other parked theme (community / MSP / diagnostics-AI / malware sub-layers) has any
feat commit since baseline — the pre-existing parked items are unchanged.

## SHIPPED (4)
| Item | Evidence |
|---|---|
| connection-type-awareness | `b3146fe` — link_type WiFi/ethernet, stored in `agent_devices`, shown in dashboard |
| diagnostics-anthropic-status-banner | `b7b7174` — `_poll_anthropic_status()` in `ai_engine/module.py` |
| diagnostics-connectivity-watcher-tool | `53975ea`–`086a659` — watcher service, VPN probes, dashboard card, systemd unit |
| hardware-stable-identifiers | `daf273f` — fingerprint (Win+Linux), TOFU, `agent_devices` migration; Mac deferred |

## PARTIAL (8)
| Item | State |
|---|---|
| clean-uninstall-build-spec | Phases 1–3 built (`9321cfe`/`5b03260`/`14ce142`); de-enroll endpoint (:5001) deployed live + migration applied; e2e VM uninstall lifecycle test still UNRUN |
| installer-unified-v1.0.6 | `2e27a60` delivery + `a21b782` self-onboard (v1.0.7) live; two before-trip fixes remain (auto_approve default, double-enroll) |
| malware-detection-pipeline | Layer A (ClamAV+YARA) `5262fc7` + Layer B canary `def1b13` live; Layers C/D scaffold only |
| latent-bug-fleet-clamav-only | Documented; fix lives in ADR 0004 (status *Proposed*, not built) |
| lateral-movement-outbreak-detection | Design complete, no code; v2 candidate |
| open-source-threat-feeds | Design complete `9eb617c`, no code; depends on community backend |
| sandbox-first-software-testing | Depends on VM Lab (parked); no code |
| sandbox-to-system-migration | Full capture `9eb617c`; depends on VM Lab + `software_inventory` table; no code |

## STUB/PARKED (39)
All self-declare "parked" / "capture-only" / "do NOT build yet" in their own headers.
Unchanged vs the 2026-07-01 baseline except the six new parked captures listed above
(`uninstall-deenroll`, `connection-health-subsystem`, `enrollment-modes-build-spec`,
`interactive-ai-clarification`, `server-on-windows-roadmap`,
`sse-inspection-proxy-build-spec`).

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
- New parked captures (6): uninstall-deenroll, connection-health-subsystem,
  enrollment-modes-build-spec, interactive-ai-clarification, server-on-windows-roadmap,
  sse-inspection-proxy-build-spec

## Method
Diffed the live file set + `git log` + code re-check of non-parked items against the
2026-07-01 baseline. This file is the new baseline the Morning Status roadmap line diffs
against (latest date wins).

**Caveat (do not header-trust):** `clean-uninstall-build-spec.md` carried a stale
`Not built` header while its code had shipped (`9321cfe`/`5b03260`/`14ce142`, de-enroll
live) — the same stale-header-on-shipping pattern prior baselines flagged. The morning
check must keep diffing reality (file set + code/`git log`) against this baseline, never
the `Status:` header.
