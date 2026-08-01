# Roadmap-vs-state audit — 2026-08-01

> Read-only audit (Rule 1). Classifies every `docs/roadmap/*.md` item against actual
> project state (code, `git log`, ADRs, HANDOFF). Baseline for the Morning Status
> roadmap line (latest date wins). No PII / infra values (Rule 8): commit hashes +
> filenames only. Supersedes `roadmap-state-audit-2026-07-28.md` (kept as history).

**Tally: 4 SHIPPED · 8 PARTIAL · 53 STUB/PARKED — 65 total.** Morning run (2026-08-01),
after three heavy build days (07-29 through 07-31: core_module rollout, host-defense
hardening, full authentication system).

## Drift since 2026-07-28 baseline

### File-set: +1, none removed (64 → 65)
| New file | Added in | Class |
|---|---|---|
| track-c-metadata-tier-build-plan.md | `cf1c319` (2026-07-30) | PARKED — "Approved to build" per operator decision 2026-07-30, but explicitly "No code written yet"; 0 commits have touched the file or its scope since |

Traced via `git log --diff-filter=A -- docs/roadmap/` since the 07-28 baseline commit
(`f00a1fe`) — this is the only addition; no removals or renames confirmed via the matching
`--diff-filter=D` check (empty).

### Shipping: no items moved
- **4 SHIPPED** — unchanged: `connection-type-awareness`, `diagnostics-anthropic-status-banner`,
  `diagnostics-connectivity-watcher-tool`, `hardware-stable-identifiers`.
- **8 PARTIAL** — unchanged, no feat commit since baseline for any of them:
  `clean-uninstall-build-spec`, `installer-unified-v1.0.6`, `malware-detection-pipeline`,
  `latent-bug-fleet-clamav-only`, `lateral-movement-outbreak-detection`,
  `open-source-threat-feeds`, `sandbox-first-software-testing`, `sandbox-to-system-migration`.
  Verified via `git log f00a1fe..HEAD -- docs/roadmap/<file>.md` for each of the 12
  tracked non-parked files — zero commits touched any of them in the intervening ~100
  commits.

## Notable same-period activity NOT reflected in this tally (by design)
2026-07-29 through 07-31 was three straight heavy build days — none of it maps to an
existing `docs/roadmap/` item (it's ADR/HANDOFF-tracked instead), so correctly none of it
moves the tally:
- core_module layout rollout finished 6/6 daemons; Data Manager v1.1 write-routing
  completed across dashboard.
- Host-defense hardening: malware-canary fixes (bait visibility, atomic plant, dedup/cooldown,
  unreadable-vs-deleted distinction), device-scanner privilege fix, severity-ladder unification.
- ADR 0019 (deterministic nftables enforcement point) — stub through Increment 3 measured PASS;
  `nemesis-fwd` gained `write_env`/`restart_dashboard` ops and fail2ban ban surfacing.
- Cutover A/B: `device-scanner`/`dashboard` moved to unprivileged service accounts; Phase 3
  systemd hardening (Steps 1-2) applied to production.
- Full authentication system built end-to-end: `login_events` centralization,
  `password_changed_at`, 30-day expiry, authenticated change-password route, recovery-code
  system, open-redirect guard on next-URL preservation, root-only guard on
  `core/manage.py` mutating commands.
- First end-to-end VM install test — found and fixed Gaps 1-9 (nemesis-fwd not deployed on
  fresh installs, audit_log missing at startup, among others).
- ADR 0020 (agent model retained, tunnel abstracted not rebuilt); ADR 0009 addendum
  (multi-site deployments are a distinct case).
- Twenty commits from 07-31 remain locally committed, NOT pushed (push gate open pending
  Window 1 verification + operator approval — see `docs/handoff/HANDOFF.md` §1-2).

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
| malware-detection-pipeline | Layer A (ClamAV+YARA) + Layer B canary live, canary hardened this period; Layers C/D scaffold only |
| latent-bug-fleet-clamav-only | Documented; fix lives in ADR 0004 (status Proposed, not built) |
| lateral-movement-outbreak-detection | Design complete, no code; v2 candidate |
| open-source-threat-feeds | Design complete, no backend code |
| sandbox-first-software-testing | Design complete, no code; requires VM Lab |
| sandbox-to-system-migration | Design complete, no code; requires VM Lab + software_inventory |

## Method
Same as 2026-07-28: `ls docs/roadmap/*.md` file-count/name diff against the prior
baseline, `git log --diff-filter=A` (and `-D` to confirm no removals) provenance for any
new files, `git log <baseline>..HEAD -- docs/roadmap/<file>.md` per non-parked item to
catch silent shipping. Baseline doc for tomorrow's Morning Status: this file (2026-08-01),
superseding 2026-07-28.
