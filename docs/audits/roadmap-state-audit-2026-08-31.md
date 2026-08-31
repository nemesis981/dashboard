# Roadmap-vs-state audit — 2026-08-31

> Read-only audit (Rule 1). Full per-file reconciliation, commissioned directly by the
> operator after Morning Status flagged the 08-24 baseline as too stale for a quick
> incremental diff (78 `feat` commits landed since — Gateway Mode, the admin-approval
> ladder, Fork B's rebuild, DNS-exfiltration/rogue-DHCP detection, a full email-security
> pipeline). Classifies every `docs/roadmap/*.md` item against actual project state (code
> read directly, `git log`, ADRs) — not headers, not commit messages alone. Supersedes
> `roadmap-state-audit-2026-08-24.md` (kept as history). No PII/infra values (Rule 8):
> commit hashes + filenames only.

**Tally: 13 SHIPPED · 14 PARTIAL · 59 STUB/PARKED — 86 total.**

## ⚠ Methodology note — this is the first FULL re-derivation since 2026-08-06

Every baseline from `roadmap-state-audit-2026-08-07.md` through `-2026-08-24.md` was an
**incremental diff** against an inherited-but-never-fully-re-verified base — each pass
explicitly re-checked only the prior pass's *non-parked* items plus a keyword sweep of new
commit subjects against PARKED filenames, and said so plainly ("the remaining ~59 PARKED
filenames were not individually re-swept this pass"). The actual evidence table for most of
the current SHIPPED/PARTIAL set traces back to `roadmap-state-audit-2026-08-06.md` and has
never been independently re-derived since — only carried forward.

That gap is not hypothetical: doing this full re-derivation caught **two files
(`hardware-stable-identifiers.md`, `malware-yara-rule-autoupdate.md`) that have been
correctly SHIPPED since June/August but were never individually re-verified in 51 days of
incremental baselines** — see §3 below. Six parallel investigations did the file-by-file
work; two of their own initial findings were themselves wrong (false negatives from
insufficient grep terms) and were caught by cross-checking the 08-06 source baseline
directly rather than trusting the fresh read uncritically — the same "verify your own
instrument" discipline this project's standing practices already require.

## 1. File-set: +3 since 08-24, none removed (83 → 86)

`ls docs/roadmap/*.md` count is 86 vs. the 08-24 baseline's 83. Confirmed via
`git log --diff-filter=A --since=2026-08-24 -- docs/roadmap/`:

| File | Classification |
|---|---|
| `dns-exfiltration-detection.md` | SHIPPED (see §2) |
| `rogue-dhcp-detection.md` | SHIPPED (see §2) |
| `child-safety-monitoring.md` | PARKED — designed, deliberately shelved post-V2.0 (operator decision 2026-08-25) |

`--diff-filter=D` over the same window is empty — no removals.

## 2. New shipping since 08-24 (genuine drift — real progress, correctly caught)

- **`dns-exfiltration-detection.md`: new file → SHIPPED.** `cc4aef5` adds
  `modules/anomaly_detection/dns_exfil.py` (261 lines) + wires a new
  `anomaly_dns_channels` table exactly per the doc's own spec; findings feed the existing
  incident pipeline via a namespaced `offending_target`. Tests: 41/0 + 21/0 integration,
  mutation-proven.
- **`rogue-dhcp-detection.md`: new file → SHIPPED.** `2ce0866` ships
  `modules/lan_integrity/module.py` (521 lines) + `rogue_dhcp.py` (223 lines) +
  `test_rogue_dhcp.py` (211 lines), full registry-completeness + Data Manager/roles
  grants. `5b15b3c` ships the Suricata half — **confirmed live on the box**:
  `/etc/suricata/suricata.yaml:347` has `extended: yes` under the `dhcp:` block, not
  just staged in a commit.
- **`uninstall-deenroll.md`: PARKED → SHIPPED.** `nemesis_agent/uninstaller_gui.py`
  implements the exact spec'd ordering (de-enroll while tailnet up → leave tailnet →
  remove components), graceful non-silent failure, ADR-0011 signed keypair. Server side
  `core_module/hw_monitor/hw_monitor.py:3942` `_create_uninstall()` is idempotent,
  signature-verified, sets the actor-stamped `enrollment_status='uninstalled'`.
- **`gateway-mode-scoping.md`: PARKED ("scoping doc, no code changed") → PARTIAL.**
  `core/gateway_mode.py` (477 lines) is real: `plan_enable/disable`, `verify_forwarding`,
  `render_capability_table`, `plan_switch`, `switch()`, `selftest()`. Steps 1a–5 all
  landed as separate feat+test pairs, including a switch proven against a **live kernel
  under forced failure** (`a66ba42`). **But `_gw.switch()` — the actual operator-facing
  toggle — has exactly one production caller, and it's the read-only capability-table
  DISPLAY on the settings page (`dashboard.py:10857`), not a route that invokes it.** No
  install-time "what kind of network is this" prompt exists either. Built and
  kernel-tested; nothing in the product lets an operator flip it yet. Header's "no code
  changed" claim is flatly false and needs correcting.
- **`tls-interception-sterilization-scope.md`: PARKED ("scoping doc") → PARTIAL.**
  Top banner still says "no code changed," but **Piece J** (hybrid inline/mirror gate)
  has its own inline "built and validated" note (2026-08-04), and **Piece K**
  (QUIC/HTTP-3) has a real adversarial verifier (`config/nftables/verify-quic-block.py`)
  proving discrimination, not just rule presence. Pieces A–I (the core interception
  mechanism) remain scoping-only — 2 of 11 pieces shipped, not the whole thing.

## 3. Pre-existing misses caught this pass (NOT new drift — errors in the historical record)

- **`idle-lock-walk-away-protection.md` — SHIPPED since 2026-08-01, still uncorrected.**
  The `roadmap-state-audit-2026-08-06.md` baseline already classified this SHIPPED
  (`219c282`/`0e15c22` — enforcement + overlay live in `dashboard.py`) and every
  incremental baseline since has silently carried that forward correctly *in the audit
  doc*. **But the roadmap FILE's own header still reads "Design approved 2026-08-01...
  Implementation not yet started" — a month-old stale header nobody ever went back and
  fixed**, exactly the failure shape CLAUDE.md's standing practice warns about. Verified
  independently this pass: `_IDLE_TIMEOUT_SECONDS`/`_SESSION_MAX_SECONDS` config,
  `_IDLE_LOCK_ALLOWED` allowlist, dedicated re-auth flow (`dashboard.py:3359`),
  `static/nemesis-idle-lock.js` live on the settings page. Not a tally move — a
  file-header-needs-fixing flag.
- **`hardware-stable-identifiers.md` — SHIPPED since 2026-06-30 (`daf273f`), initially
  misread this pass, corrected by direct verification.** The first-pass investigation
  grepped for `hardware_fingerprint`/`TOFU`/`hw_fingerprint` and found nothing, flagging
  it AMBIGUOUS. **Wrong search terms, not missing code.** Direct check confirms
  `nemesis_agent/hwid.py` (11KB, `collect_signals_windows/linux/macos`,
  `match_fingerprint`) and `core_module/hw_monitor/hw_monitor.py:338-451` (the
  `hw_stable_id`/`hw_fp_confidence`/`hw_signal_hashes` columns from the original ADR-0011
  migration) are both live, unchanged since June. **Caught here specifically because this
  audit cross-checked the 08-06 source baseline directly rather than trusting an
  "ambiguous" verdict at face value** — the same "an instrument that answered from the
  wrong place looks identical to one that answered correctly" pattern this project's own
  CLAUDE.md names as a standing failure class.
- **`malware-yara-rule-autoupdate.md` — SHIPPED since 2026-08-02 (`0506aed`/`79a4996`),
  initially misread this pass as PARKED, corrected by direct verification.** First-pass
  investigation reported "no matching commits" and classified PARKED from the file's
  current header text alone. Direct check confirms `modules/malware_detection/module.py`
  still has the full mechanism: `yara_update_source` setting, `_validate_source_url()`
  SSRF guard (https-only, public-address-only), rate limiting via
  `yara_update_last_ts`/`yara_update_last_status`. Same false-negative shape as above.

**Why this matters beyond these two files:** both were caught only because this pass
happened to cross-reference the 08-06 source baseline for an unrelated reconciliation
check. Neither would have been caught by the incremental-diff method this audit chain has
used since 08-07, because that method only re-checks the *previous pass's* non-parked set
— once a file drops out of the "needs re-checking" list by being correctly classified once,
nothing re-verifies it again unless a keyword sweep happens to catch a coincidental commit.
A quiet regression in either file (auto-update mechanism silently removed, hwid collector
silently broken) could sit unnoticed indefinitely under that method. Worth flagging as a
process gap, not just a one-time fix.

## 4. Classification-standard correction (not shipping, not regression — a consistency fix)

The 08-06 baseline classified "fully designed, zero code" items as **PARTIAL**. This
project's own convention elsewhere treats that exact shape as **PARKED** —
`child-safety-monitoring.md` self-describes as "PARKED — designed, awaiting post-V2.0
build phase... not abandoned, not a stub" despite being fully designed. This pass applies
that standard uniformly: **PARTIAL now requires actual shipped code implementing a real
subset of the feature, not merely a complete design.** Five items move down accordingly:

| File | 08-06 classification | This pass |
|---|---|---|
| `latent-bug-fleet-clamav-only.md` | PARTIAL | PARKED — fix is ADR 0004's own unbuilt Step 4; zero code toward it |
| `lateral-movement-outbreak-detection.md` | PARTIAL | PARKED — Tier 1 spec written, build not started (own header agrees) |
| `open-source-threat-feeds.md` | PARTIAL | PARKED — design complete, no backend code |
| `sandbox-first-software-testing.md` | PARTIAL | PARKED — design complete, no code, depends on unbuilt VM Lab |
| `sandbox-to-system-migration.md` | PARTIAL | PARKED — design complete, no code, depends on unbuilt VM Lab + software_inventory |

One item moves the other direction under the same tightened standard:

| File | 08-06 classification | This pass |
|---|---|---|
| `storage-monitoring-retention-supplement-2026-08-03.md` | SHIPPED | PARTIAL — items 1 and 3 are live, the rest is design-only; a real subset shipped, not the whole deliverable |

## 5. Findings surfaced, not resolved — flagged for operator decision

- **`malware-detection-pipeline.md` has no `Status:` header at all**, and is a large V1/V2/V3
  umbrella design doc whose named sub-features (Layer B behavioral monitoring, Layer D
  local ML, the local isolated sandbox) now each have their own independently-tracked
  roadmap file. Kept at its historical **PARTIAL** classification rather than guessed at,
  but flagged: should this doc be marked superseded/retired now that its pieces are
  tracked separately, or does it still own real V2/V3 remainder scope? Needs an explicit
  call, not an inference.
- **`product-thesis-built-in-it-expertise.md` is not a build item.** It's a
  philosophy/business-thesis reference doc other roadmap files cite as design rationale.
  Forced into the SHIPPED/PARTIAL/PARKED schema for tally-arithmetic purposes (counted
  PARKED here, the least-wrong bucket), but this is a category mismatch, not a real
  classification. Recommend either excluding reference docs from the roadmap tally
  entirely going forward, or adding a fourth bucket.

## 6. Security-relevant findings surfaced during this pass (unrelated to bucket movement)

- **`diagnostics-and-access-master-plan.md` §2.1 — Submit-to-Support PII-redaction gap is
  STILL UNFIXED.** This is the doc's own named top-priority "must ship before wider
  release" item. Direct read of `diagnostics/redact.py` in full: only `_KEY_PATTERN`
  (secret *values*) is redacted; no IP/MAC/hostname/email pattern exists. The doc's
  broader §5 access-control foundation shipped (classified PARTIAL overall on that
  balance), but this specific named risk has been open since the doc was written and has
  survived every baseline since. Worth direct attention, not just a classification note.
- **`clean-uninstall-build-spec.md`** (kept PARTIAL, unchanged bucket) — flag on
  `aa8d784` ("Cutover B Phase 0... remove web uninstall") and PUNCHLIST entry `353ce11`
  ("uninstall leaves agent process + state behind") sitting on top of the previously
  verified PARTIAL baseline. Not deep-verified whether this is a regression against the
  tracked baseline or an already-known, separately-tracked gap — flagged for a closer
  look, not reclassified without more evidence.

## 7. Content staleness on already-correctly-classified items (no bucket change, header/content needs a refresh)

- **`dashboard-roles-access-control.md`** (SHIPPED, unchanged) — the doc still frames the
  sub-admin/learning-gate tier as future/unscheduled work, but it has since shipped:
  `aa189ac` (capability-unlock schema), `a425d4b` (quiz loader/validator/grader),
  `a7ed8a7` (unlock lifecycle), `role.js:37` has `sub_admin` wired into `RANK`,
  `core/admin_approval_gate.py` exists. Content refresh owed.
- **`v2-completion-checklist.md`** (PARTIAL, unchanged) — checkboxes for
  `rogue-dhcp-detection.md` and `dns-exfiltration-detection.md` still say "Not yet
  built," despite both shipping this session (§2). The doc is otherwise actively
  maintained (self-corrected 2026-08-30 for the lateral-movement Tier 1 omission); these
  two checkboxes just predate those commits.
- **`data-retention-and-archival-policy.md`** (PARTIAL, unchanged from 08-06's original
  classification) — same shape as idle-lock above: the audit-doc lineage already had
  this right (`dm_operation_log` archive-then-coalesce shipped, `3066205`), but the
  roadmap file's own header still reads "implementation not yet started."

## SHIPPED (13)

| File | Evidence |
|---|---|
| `connection-type-awareness.md` | `b3146fe` — `link_type`/`connection_type` in `agent_devices`, written every heartbeat |
| `dashboard-roles-access-control.md` | `c84dcce`→`a0d971c` — RBAC gate, all 149 endpoints; content stale, see §7 |
| `diagnostics-anthropic-status-banner.md` | `b7b7174` — `_poll_anthropic_status()` |
| `diagnostics-connectivity-watcher-tool.md` | `53975ea`–`086a659` — watcher service live (`systemctl is-active` confirmed) |
| `hw-anomaly-snapshots-top-processes-archival.md` | `97175ba` |
| `malware-layer-b-behavioral-monitoring.md` | `e81cb41`/`c091ed5` — behavioral ingest + Falco deploy |
| `malware-local-isolated-sandbox.md` | `7f499a7`/`9f0b769` — detonation sandbox |
| `hardware-stable-identifiers.md` | `daf273f` — see §3, re-verified this pass after an initial false negative |
| `malware-yara-rule-autoupdate.md` | `0506aed`/`79a4996` — see §3, re-verified this pass after an initial false negative |
| `idle-lock-walk-away-protection.md` | `219c282`/`0e15c22` — see §3, file header stale but code confirmed live |
| `dns-exfiltration-detection.md` | `cc4aef5` — new this pass, see §2 |
| `rogue-dhcp-detection.md` | `2ce0866`/`5b15b3c` — new this pass, see §2 |
| `uninstall-deenroll.md` | new this pass, see §2 |

## PARTIAL (14)

| File | State |
|---|---|
| `adr-0009-l3-fork-b-scope.md` | Piece 2 code real and tested (`core/forkb_policy_route.py`, tonight's rebuild) but **live-confirmed inert**: `ip_forward=0`, no policy-route rule, no production caller. NAT logic lives in `install.sh` outside `firewall.py`'s mandated chokepoint — a real deviation from the doc's own requirement. |
| `agent-rebuild-config-driven.md` | Observation-layer foundation (5 items) all shipped; broader config-driven rebuild stays parked, per the doc's own scope split |
| `clean-uninstall-build-spec.md` | Phases 1–3 built; flag on possible regression, see §6 |
| `data-retention-and-archival-policy.md` | `dm_operation_log` coalescing shipped; broader Tier A retention not built; file header stale, see §7 |
| `diagnostics-and-access-master-plan.md` | §5 access-control shipped and exceeds original scope; §2.1 PII-redaction gap still open — see §6 |
| `gateway-mode-scoping.md` | New this pass — see §2 |
| `installer-unified-v1.0.6.md` | Delivery + self-onboard live; two named before-trip fixes remain unconfirmed either way this pass |
| `malware-detection-pipeline.md` | Historical classification kept; flag for retire/supersede decision, see §5 |
| `malware-layer-d-local-ml.md` | Classifier pipeline shipped; no trained model — doc's own header already says so |
| `memory-injection-detection-design.md` | Observation-layer active; detection technique stays paused, per doc's own split |
| `storage-monitoring-retention-supplement-2026-08-03.md` | Moved down from SHIPPED this pass — see §4 |
| `track-c-metadata-tier-build-plan.md` | "IN PROGRESS" (self-corrected 08-25), no new commits since — unchanged |
| `tls-interception-sterilization-scope.md` | New this pass — see §2 |
| `v2-completion-checklist.md` | Living tracking doc; checkboxes stale, see §7 |

## PARKED (59)

`adaptive-link-aware-agent-clock-sync.md`, `adr-0009-build-scope.md`,
`adr-0009-l3-behavioral-trigger-scope.md`, `adr-0009-l3-tier3-local-triggers-scope.md`,
`agent-auto-load-ownership.md`, `agent-tunnel-environment-awareness.md`,
`ai-generated-tutorial-walkthrough.md`, `automated-abuse-reporting.md`,
`child-safety-monitoring.md`, `clock-sync-foundation-build2-spec.md`,
`community-reporter-identity.md`, `community-signal-dedup.md`,
`connection-health-subsystem.md`, `dashboard-l2-toggle.md`,
`dashboard-pass-freshness-review.md`, `db-resilience-backup-promotion.md`,
`device-coverage-tier-indicator.md`, `device-identification.md`,
`diagnostics-ai-reassurance-escalation-routing.md`, `diagnostics-ai-tool-aware-loop.md`,
`diagnostic-scan-scope.md`, `diagnostics-classification.md`,
`diagnostics-standalone-runner.md`, `diagnostics-verdict-transition-log.md`,
`enrollment-modes-build-spec.md`, `enterprise-gap-audit-2026.md`,
`installer-email-delivery.md`, `interactive-ai-clarification.md`,
`ipv6-rogue-router-detection.md`, `l2-windivert-stumble-escalation.md`,
`latent-bug-fleet-clamav-only.md` *(moved, §4)*,
`lateral-movement-outbreak-detection.md` *(moved, §4)*,
`malware-cloud-sandbox-optional.md`, `msp-central-management.md`,
`nemesis-overhead-meter.md`, `nemesis-test-lab.md`,
`network-resource-scaling-advisor.md`, `open-source-threat-feeds.md` *(moved, §4)*,
`post-update-module-repair.md`, `pre-escalation-support-search.md`,
`product-thesis-built-in-it-expertise.md` *(reference doc, not a build item — §5)*,
`ram-recovery-windows-platform-gap.md`, `removable-media-device-control.md`,
`responsive-dashboard-multiuser-ready.md`, `sandbox-first-software-testing.md` *(moved, §4)*,
`sandbox-to-system-migration.md` *(moved, §4)*, `server-on-windows-roadmap.md`,
`server-side-session-store.md`, `settings-loaded-vs-enabled-refactor.md`,
`single-user-assumptions-audit.md`, `sse-inspection-proxy-build-spec.md`,
`support-bundle.md`, `system-changes-badge.md`, `three-snapshot-vendor-package.md`,
`udp-default-deny-scoping.md`, `venue-guest-network.md`, `verified-partner-program.md`,
`vulnerability-patch-management.md`, `windows-agent-memory-injection-rework-prereqs.md`.

## Method

Six parallel read-only investigations each covered ~14-15 roadmap files: read the file,
treat its self-reported `**Status:**` header as an unverified claim, search the actual
codebase for the specific modules/tables/routes/tests the doc names as its deliverable,
cross-reference `git log`. Findings were then reconciled against `roadmap-state-audit-
2026-08-06.md` — the actual source baseline the incremental chain has carried forward
unverified since — which surfaced and allowed correction of two sub-agent false negatives
(§3). File-set arithmetic (86 = 13 + 14 + 59) is internally consistent and independently
confirmed against `ls docs/roadmap/*.md`.

Roadmap FILE headers were **not edited** in this pass (audit-only, per Rule 1 and the
explicit scope of this request) — §3, §6, and §7 above list every file whose own header
or content is now known to be stale and needs a follow-up edit. Baseline doc for the next
Morning Status: this file (2026-08-31), superseding `roadmap-state-audit-2026-08-24.md`.
