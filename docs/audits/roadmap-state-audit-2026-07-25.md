# Roadmap-vs-state audit — 2026-07-25

> Read-only audit (Rule 1). Classifies every `docs/roadmap/*.md` item against actual
> project state (code, `git log`, ADRs, HANDOFF). Baseline for the Morning Status
> roadmap line (latest date wins). No PII / infra values (Rule 8): commit hashes +
> filenames only. Supersedes `roadmap-state-audit-2026-07-02.md` (kept as history).

**Tally: 4 SHIPPED · 8 PARTIAL · 47 STUB/PARKED — 59 total.**

Verdict: no *silent* drift, and no shipping movement since the 07-02 baseline. `git log`
confirms only **one** commit has landed since that baseline (`8cdb120`, a docs-only
punchlist entry) — the repo has otherwise been idle for 23 days (operator away, then a
gap past the expected return).

## Drift since 2026-07-02 baseline

### File-set: +8, none removed (51 → 59)
All 8 traced via `git log --diff-filter=A -- docs/roadmap/<file>.md` to commits made
**after** the 07-02 baseline-audit doc (`aedfb01`) was written but **before** that same
night's closeout (`f481717`) — i.e. same-session work the 07-02 baseline doc under-counted,
not drift accrued since:

| New file | Class | Note |
|---|---|---|
| adr-0009-build-scope | scoping doc | `14b066b` — read-only analysis, no code changed |
| adr-0009-l3-fork-b-scope | scoping doc | `5bb5dee` — Fork B (tunnel-routed central Suricata) chosen over Fork A; not built |
| agent-tunnel-environment-awareness | PARKED | `d7e3db2` — capture, post-trip |
| clock-sync-foundation-build2-spec | PARKED | `d1cff9f` — build-2 spec, docs-only |
| dashboard-l2-toggle | PARKED | `b4c7dd1` — capture, not built (next build session) |
| dashboard-roles-access-control | PARKED | `639959e` — capture, post-trip, build not started |
| diagnostics-and-access-master-plan | master plan | `7e28a02` — consolidation doc, buildable direction, no code |
| l2-windivert-stumble-escalation | PARKED | `d085e79` — capture, post-L2 work |

### Shipping: no items moved
- **4 SHIPPED** — unchanged: `connection-type-awareness`, `diagnostics-anthropic-status-banner`,
  `diagnostics-connectivity-watcher-tool`, `hardware-stable-identifiers`.
- **8 PARTIAL** — unchanged, no feat commit since baseline for any of them:
  `clean-uninstall-build-spec`, `installer-unified-v1.0.6`, `malware-detection-pipeline`,
  `latent-bug-fleet-clamav-only`, `lateral-movement-outbreak-detection`,
  `open-source-threat-feeds`, `sandbox-first-software-testing`, `sandbox-to-system-migration`.
  `installer-unified-v1.0.6`'s two pre-trip fixes (auto_approve default, double-enroll) remain open.
- No parked theme (community / MSP / diagnostics-AI / malware sub-layers) has any feat commit
  since baseline — the pre-existing parked items are unchanged.

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

## STUB/PARKED + scoping/master-plan docs (47)
All self-declare "parked" / "capture-only" / "scoping doc" / "do NOT build yet" in their own
headers; none has shipped code.

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
- 07-02 same-session captures (6): uninstall-deenroll, connection-health-subsystem,
  enrollment-modes-build-spec, interactive-ai-clarification, server-on-windows-roadmap,
  sse-inspection-proxy-build-spec
- 07-25 baseline correction — same-session captures the 07-02 doc under-counted (6):
  agent-tunnel-environment-awareness, clock-sync-foundation-build2-spec, dashboard-l2-toggle,
  dashboard-roles-access-control, l2-windivert-stumble-escalation, and one master-plan doc
  (diagnostics-and-access-master-plan)
- Scoping docs, no roadmap status but zero code either (2): adr-0009-build-scope,
  adr-0009-l3-fork-b-scope

## Method
Diffed the live file set + `git log --diff-filter=A` (per new file) + code re-check of
non-parked items against the 2026-07-02 baseline. This file is the new baseline the Morning
Status roadmap line diffs against (latest date wins).

**Caveat (do not header-trust):** ADR 0001's own `Status:` header read "Proposed — revised"
while its core migration (Stages 0–3, all four modules cut over to the shared DB) had shipped
— corrected this session (see `adr-status-audit-2026-07-25.md`). Same stale-header-on-shipping
pattern as the `clean-uninstall-build-spec.md` catch in the 07-02 baseline. Keep diffing
reality (file set + code/`git log`) against this baseline, never a file's `Status:` header.
