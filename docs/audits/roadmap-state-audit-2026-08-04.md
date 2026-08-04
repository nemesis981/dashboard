# Roadmap-vs-state audit — 2026-08-04

> Read-only audit (Rule 1). Classifies every `docs/roadmap/*.md` item against actual
> project state (code, `git log`, ADRs, HANDOFF). Baseline for the Morning Status
> roadmap line (latest date wins). No PII / infra values (Rule 8): commit hashes +
> filenames only. Supersedes `roadmap-state-audit-2026-08-03.md` (kept as history).

**Tally: 8 SHIPPED · 9 PARTIAL · 56 STUB/PARKED — 73 total.** Morning run (2026-08-04),
after one heavy build day (08-03: ADR 0004 Stage 1 complete, storage/retention build,
concurrency-race emergency — see HANDOFF §1).

## Drift since 2026-08-03 baseline

### File-set: +5, none removed (68 → 73)
| New file | Added in | Class |
|---|---|---|
| hw-anomaly-snapshots-top-processes-archival.md | `496200e` (2026-08-03) | **SHIPPED — header stale.** Header still reads "Implementation not yet started," but this is exactly storage/retention piece 4 from HANDOFF §1: `97175ba feat(hw-monitor): archive aged top_processes blobs out of hw_anomaly_snapshots (piece 4)` — 18,010 rows moved, 34.4MB→837KB, verified round-trip per HANDOFF. |
| storage-monitoring-retention-supplement-2026-08-03.md | `5e6c860` (2026-08-03) | **SHIPPED — header stale.** Doc's own scope is explicitly "items 1 and 3" (disk-space reporting, backup-drive visibility). Both shipped same day: item 1 = `f9ad33f` (disk capacity into `hw_metrics`) + `4ab95dc`/`1fec8b7` (disk-threshold classifier, hardware-card tile); item 3 = `58fe763` (last-known free space at backup destination, new `backup_media_status` table). |
| data-retention-and-archival-policy.md | `496200e` (2026-08-03) | PARTIAL — header says "not yet started" but is now partly stale: item 1 of its own scope (`dm_operation_log` coalescing/sampling) shipped same day (`3066205`, 26,591 rows→125 summaries). Broader scope (Tier A infinite-retention enforcement, disk-monitoring rollout beyond server-only) not built. Not classified SHIPPED — the doc is a policy covering more ground than what's landed. |
| memory-injection-detection-design.md | `77dafbb` (2026-08-03) | PARKED — header confirms ("Capture-only... Paused — do NOT build"). **Supersedes** `windows-agent-memory-injection-rework-prereqs.md` (one of the 54 baseline-PARKED files) per that stub's own instruction — both files still exist and are both PARKED, so this is a content merge, not a tally change. Noted so the supersession isn't mistaken for new scope later. |
| diagnostics-verdict-transition-log.md | `0e1e479` (2026-08-03) | PARKED — header confirms ("STUB, parked") |

Traced via `git log --diff-filter=A --since=2026-08-03 -- docs/roadmap/` — five additions,
no removals (`--diff-filter=D` empty over the same window). `ls docs/roadmap/*.md` count
(73) matches 68 baseline + 5 new, confirming no untracked drift.

### Shipping: baseline's 6 SHIPPED + 8 PARTIAL — unchanged, no feat commit since 08-03
for any of their 14 roadmap files directly (`git log --since=2026-08-03 -- docs/roadmap/<file>.md`
returned zero commits for all 14, checked individually).

- **`latent-bug-fleet-clamav-only` re-checked as flagged by the 08-03 baseline** (its
  PARTIAL status was pinned to ADR 0004 being unresolved; ADR 0004 Stage 1 is now
  complete). **Still PARTIAL, not reclassified** — this item's specific fix is
  "generalize the distribution channel fleet-wide" + a real scheduler, which HANDOFF
  §1 explicitly identifies as ADR 0004's own original Step 4 (Scheduler/Execution/
  Reporting + `scan_threats`→`malware_findings` migration) — **not** the same as
  "Stage 1 Step 4" that shipped 08-03 (task dispatch/results/rotation). HANDOFF calls
  this out by name as a terminology trap. Confirmed still unbuilt; item does not
  graduate this pass.
- **Broader sweep:** all 54 baseline-PARKED filenames (56 counting the two new PARKED
  entries above) keyword-matched against all 60 commits since 2026-08-03. One
  substantive hit — the `windows-agent-memory-injection-rework-prereqs` supersession
  already covered above. Every other hit was generic-word noise (`agent`, `dashboard`,
  `diagnostics`, `server`, `single`, `test`, `scope`) against unrelated commits — no
  second silent-shipping case found.

## Notable same-period activity NOT reflected further in this tally (by design)
2026-08-03 was another heavy build day — most of it maps to ADR/HANDOFF-tracked work
with no corresponding `docs/roadmap/` item beyond what's captured above:
- ADR 0004 Stage 1 completed (all 4 steps): signing keypair/trust anchor, signed task
  envelopes, atomic-claim task dispatch, task results + rules digest + key rotation.
- Tier 3 key protection: keyprotect module through tier-4→tier-3 legacy migration (5
  steps, 149 checks across five suites).
- Concurrency-race emergency: 38-finding audit, 10 HIGH-severity fixes same day, each
  with a control proving the old code actually failed pre-fix.
- Archive integrity manifest (sha256 + record count at write time).
- Route/security additions: device revoke+re-approve, honest check-in wording,
  deterministic agent transport target.
- Diagnostics/audit findings filed not yet fixed: IPv6-false-DEGRADED, 23.1hr DNS
  outage, PIA VPN/tailnet enrollment breakage — process/audit items, no roadmap file.

## SHIPPED (8)
| Item | Evidence |
|---|---|
| connection-type-awareness | `b3146fe` — link_type WiFi/ethernet, stored in `agent_devices`, shown in dashboard |
| diagnostics-anthropic-status-banner | `b7b7174` — `_poll_anthropic_status()` in `ai_engine/module.py` |
| diagnostics-connectivity-watcher-tool | `53975ea`–`086a659` — watcher service, VPN probes, dashboard card, systemd unit |
| hardware-stable-identifiers | `daf273f` — fingerprint (Win+Linux), TOFU, `agent_devices` migration; Mac deferred |
| malware-yara-rule-autoupdate | `0506aed`/`79a4996`/`5ef9a93` (2026-08-02) — auto-update mechanism, SSRF-guarded routes, rate limit; header stale |
| idle-lock-walk-away-protection | `219c282`/`0e15c22` (2026-08-01) — enforcement + overlay live in `dashboard.py`; header stale |
| hw-anomaly-snapshots-top-processes-archival | `97175ba` (2026-08-03) — storage/retention piece 4, 18,010 rows archived, verified round-trip; header stale, see drift note above |
| storage-monitoring-retention-supplement-2026-08-03 | `f9ad33f`/`4ab95dc`/`1fec8b7`/`58fe763` (2026-08-03) — items 1+3 (disk-space reporting, backup-drive visibility) both live; header stale, see drift note above |

## PARTIAL (9)
| Item | State |
|---|---|
| clean-uninstall-build-spec | Phases 1–3 built; de-enroll endpoint (:5001) deployed live + migration applied; e2e VM uninstall lifecycle test still UNRUN |
| installer-unified-v1.0.6 | Delivery + self-onboard (v1.0.7) live; two before-trip fixes remain (auto_approve default, double-enroll) |
| malware-detection-pipeline | Layer A (ClamAV+YARA) + Layer B canary live, canary hardened further 08-02; Layers C/D scaffold only |
| latent-bug-fleet-clamav-only | Re-checked this pass, not reclassified — see drift note above; fix is ADR 0004's own unbuilt original Step 4, distinct from the shipped Stage 1 |
| lateral-movement-outbreak-detection | Design complete, no code; v2 candidate |
| open-source-threat-feeds | Design complete, no backend code |
| sandbox-first-software-testing | Design complete, no code; requires VM Lab |
| sandbox-to-system-migration | Design complete, no code; requires VM Lab + software_inventory |
| data-retention-and-archival-policy | New this pass — `dm_operation_log` coalescing (item 1 of its scope) shipped `3066205`; Tier A retention enforcement + fleet-wide disk monitoring rollout not built. See drift note above. |

## Method
Same as 2026-08-03: `ls docs/roadmap/*.md` file-count/name diff against the prior
baseline, `git log --diff-filter=A` (and `-D` to confirm no removals) provenance for any
new files, `git log <baseline-date>..HEAD -- docs/roadmap/<file>.md` per non-parked item
to catch silent shipping, plus a keyword sweep of all baseline-PARKED filenames against
every commit subject since the baseline date. Baseline doc for tomorrow's Morning
Status: this file (2026-08-04), superseding 2026-08-03.
