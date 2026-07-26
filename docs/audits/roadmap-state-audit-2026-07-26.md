# Roadmap-vs-state audit — 2026-07-26

> Read-only audit (Rule 1). Classifies every `docs/roadmap/*.md` item against actual
> project state (code, `git log`, ADRs, HANDOFF). Baseline for the Morning Status
> roadmap line (latest date wins). No PII / infra values (Rule 8): commit hashes +
> filenames only. Supersedes `roadmap-state-audit-2026-07-25.md` (kept as history).

**Tally: 4 SHIPPED · 8 PARTIAL · 51 STUB/PARKED — 63 total.** Unchanged from this
morning's check; confirmed again at closeout — no further drift since.

## Drift since 2026-07-25 baseline

### File-set: +4, none removed (59 → 63)
All four traced (this morning) via `git log --diff-filter=A` to commits landing **after**
the 07-25 baseline-audit doc itself was committed (`035e29b`) but during the **same 07-25
session** — same-session under-count, not overnight drift:

| New file | Added in | Class |
|---|---|---|
| adr-0009-l3-behavioral-trigger-scope.md | `ebf0aae` | PARKED — Tier 1 trigger-layer cost, no session estimate (TBD) |
| tls-interception-sterilization-scope.md | `1d6d2d2` | PARKED — Tier 2 TLS interception, no session estimate (TBD) |
| network-resource-scaling-advisor.md | `946d7b4` | PARKED — resource-analysis module capture |
| adr-0009-l3-tier3-local-triggers-scope.md | `68c0eb1` | PARKED — Tier 3 client-side late triggers |

**Re-checked at closeout (2026-07-26 EOD):** `ls docs/roadmap/*.md | wc -l` still returns
**63** — no `docs/roadmap/` files were added or removed during today's session, despite a
full day of ADR/roadmap-adjacent work. (Today's new content — ADR 0014/0015/0016, the
Fork-B mirror resolution, the Tier 2 hybrid gate design, the disclosure-audit carve-outs —
landed in `docs/architecture/` and as edits to already-counted roadmap files, not as new
roadmap files.)

### Shipping: no items moved
- **4 SHIPPED** — unchanged: `connection-type-awareness`, `diagnostics-anthropic-status-banner`,
  `diagnostics-connectivity-watcher-tool`, `hardware-stable-identifiers`.
- **8 PARTIAL** — unchanged, no feat commit since baseline for any of them:
  `clean-uninstall-build-spec`, `installer-unified-v1.0.6`, `malware-detection-pipeline`,
  `latent-bug-fleet-clamav-only`, `lateral-movement-outbreak-detection`,
  `open-source-threat-feeds`, `sandbox-first-software-testing`, `sandbox-to-system-migration`.
  None of these 12 files were touched by today's commits (verified via `git log
  035e29b..HEAD -- docs/roadmap/<file>.md` for each, this morning, and reconfirmed no
  further activity touched them since).
- Today's real code/docs work (ADR 0009 Fork-B mirror resolution + Tier 2 hybrid design, the
  private-module disclosure-audit carve-outs, the Group-A history rewrite, CLAUDE.md rule
  additions) has no corresponding `docs/roadmap/` file, so — correctly — none of it moves
  the roadmap tally. Real work landing without moving this tally is expected, not a miss.

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

## Notable same-day activity NOT reflected in this tally (by design)
- ADR 0009 Fork-B mirror-mechanism resolution + Tier 2 hybrid inline/mirror gate design —
  lives in `docs/architecture/`, not `docs/roadmap/`.
- Disclosure-audit private-module carve-out (Tier 2 implementation detail, behavioral-trigger
  risk weights, ADR 0005 tamper-response ladder, device-ID confidence weights) — a
  repo-structure change to existing docs, not a new roadmap item.
- Group-A git-history rewrite — executed and verified; infrastructure/hygiene work, not a
  product feature.
- Three new ADRs (0014 deployment-appliance-model, 0015 guest-self-service-enrollment, 0016
  guest-marketing-capture) — architecture-tier docs, not roadmap stubs; no roadmap file to move.

## Method
Same as 2026-07-25: `ls docs/roadmap/*.md` file-count/name diff against the prior baseline,
`git log --diff-filter=A` provenance for any new files, `git log <baseline>..HEAD --
docs/roadmap/<file>.md` per non-parked item to catch silent shipping. Baseline doc for
tomorrow's Morning Status: this file (2026-07-26), superseding 2026-07-25.
