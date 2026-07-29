# Roadmap-vs-state audit — 2026-07-28

> Read-only audit (Rule 1). Classifies every `docs/roadmap/*.md` item against actual
> project state (code, `git log`, ADRs, HANDOFF). Baseline for the Morning Status
> roadmap line (latest date wins). No PII / infra values (Rule 8): commit hashes +
> filenames only. Supersedes `roadmap-state-audit-2026-07-26.md` (kept as history).

**Tally: 4 SHIPPED · 8 PARTIAL · 52 STUB/PARKED — 64 total.** Closeout run
(2026-07-28), after a full day of security/infrastructure work.

## Drift since 2026-07-26 baseline

### File-set: +1, none removed (63 → 64)
| New file | Added in | Class |
|---|---|---|
| windows-agent-memory-injection-rework-prereqs.md | `2c2d580` | PARKED — three future Windows-agent requirements tied to the paused memory-injection module (agent rework, small GUI, Windows-Update-triggered re-checks, plus a fleet-wide update rollout detail added same-day in `04a3b88`); explicitly not for action now |

Traced via `git log --diff-filter=A -- docs/roadmap/` since the 07-26 baseline commit
(`bc7e230`) — this is the only addition; no removals or renames.

### Shipping: no items moved
- **4 SHIPPED** — unchanged: `connection-type-awareness`, `diagnostics-anthropic-status-banner`,
  `diagnostics-connectivity-watcher-tool`, `hardware-stable-identifiers`.
- **8 PARTIAL** — unchanged, no feat commit since baseline for any of them:
  `clean-uninstall-build-spec`, `installer-unified-v1.0.6`, `malware-detection-pipeline`,
  `latent-bug-fleet-clamav-only`, `lateral-movement-outbreak-detection`,
  `open-source-threat-feeds`, `sandbox-first-software-testing`, `sandbox-to-system-migration`.
  Verified via `git log bc7e230..HEAD -- docs/roadmap/<file>.md` for each of the 12
  tracked non-parked files — zero commits touched any of them today.

## Notable same-day activity NOT reflected in this tally (by design)
Today (2026-07-28) was a large security/infrastructure day — none of it maps to an
existing `docs/roadmap/` item, so correctly none of it moves the tally:
- CSRF fix (GET→POST) on three quarantine/action routes (`8c8bce9`).
- ufw privilege relocated into `nemesis-fwd`, a three-layer-verified helper process, plus
  its deploy tooling (`3cf0e4d`, `7d4999a`, `401b58d` tiered lockout).
- ADR 0018 — attacker-resistant backup + manifest-based recovery design (`045cedc`) —
  architecture-tier doc, not a roadmap stub.
- Data Manager v1.1 retrofit — explicit table lists, 3-state enforcement, column grants
  (`c10a9d3`).
- core_module layout move for six daemons — additive Commit A (`9ffac56`), the
  `migrate_core_module.sh --verify` three-state fix (`eb5a35b`), dashboard's PYTHONPATH
  step 1 (`04c9e11`), and Commit B for five of six daemons (`85e2baa` hw-monitor;
  `fbce915` device_scanner/watchdog/malware_canary/diagnostics_watcher). `alert_watcher`
  Commit B is held pending two consumer fixes (`test_quarantine.py`, `deploy_nemesis_fwd.sh`).
- `install.sh`'s core_module service-discovery gap, found and fixed same day (`dd95de1`).
- Morning migration-status audit (`bc36219`) and the dashboard hardening-exception codification
  (`bd23f2b`) — audit/infra work, not roadmap features.
- Two private audits (dashboard sensitive-surfaces three-layer-pattern inventory,
  core_module identity/DB landscape) — kept private per Rule 10, not roadmap items.

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
| clean-uninstall-build-spec | Phases 1–3 built; de-enroll endpoint (:5001) deployed live + migration applied; e2e VM uninstall lifecycle test still UNRUN |
| installer-unified-v1.0.6 | Delivery + self-onboard (v1.0.7) live; two before-trip fixes remain (auto_approve default, double-enroll) |
| malware-detection-pipeline | Layer A (ClamAV+YARA) + Layer B canary live; Layers C/D scaffold only |
| latent-bug-fleet-clamav-only | Documented; fix lives in ADR 0004 (status Proposed, not built) |
| lateral-movement-outbreak-detection | Design complete, no code; v2 candidate |
| open-source-threat-feeds | Design complete, no backend code |
| sandbox-first-software-testing | Design complete, no code; requires VM Lab |
| sandbox-to-system-migration | Design complete, no code; requires VM Lab + software_inventory |

## Method
Same as 2026-07-26: `ls docs/roadmap/*.md` file-count/name diff against the prior
baseline, `git log --diff-filter=A` provenance for any new files, `git log
<baseline>..HEAD -- docs/roadmap/<file>.md` per non-parked item to catch silent
shipping. Baseline doc for tomorrow's Morning Status: this file (2026-07-28),
superseding 2026-07-26.
