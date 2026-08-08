# Roadmap sequence delta — Paul's post-gate sequence vs. documented state — 2026-08-08

> Read-only comparison (Rule 1). Checks Paul's stated post-gate build sequence against
> `ROADMAP.md`, all 77 files in `docs/roadmap/`, `PUNCHLIST.md`'s open items, 19 ADRs, the
> 2026-08-07 `roadmap-state-audit` baseline, and `HANDOFF.md`'s current carried items. Produced
> as an Artifact first (interactive delta view); this is the durable record of the same findings.
> Changes nothing — findings only.

**Sequence checked:** Data Manager correction (in progress) → error-code rollout (in progress) →
Window 1 to memory injection/recovery → final agent versions including Android → full dashboard
pass → v2 full stop → backend build → v3 scoping.

**Tally: 3 confirmed as-is · 1 conflict · 3 ordering nuances · 1 no-doc gap.**

---

## The one real conflict — read this first

**Step 3, "memory injection/recovery," is explicitly paused in the docs.**

- **Memory injection:** `docs/roadmap/memory-injection-detection-design.md`'s status line reads
  *"Capture-only. Paused — do NOT build the detection technique."* Four prerequisites are on
  record as unresolved: agent integrity attestation (no self-integrity check exists anywhere in
  the product today), a RAM budget model (doesn't exist — only single idle measurements), the
  deferred 2.0 signing decision re-scoped for a higher-risk build, and an unresolved architectural
  tension requiring the agent to split into two processes (session-side UI + a separately
  SYSTEM-privileged service) — noted in the doc itself as "not yet a decision," not settled. Only
  the technique-independent *observation-layer foundation*
  (`docs/roadmap/agent-rebuild-config-driven.md`) is active, and per the 2026-08-07 baseline it is
  PARTIAL, not done.
- **Recovery:** whichever doc this maps to is also parked-not-built.
  `docs/roadmap/db-resilience-backup-promotion.md`: "parked — do NOT build yet." ADR 0018
  (attacker-resistant backup / manifest recovery): "Proposed — no code or data changed."

Nothing here says this work is wrong to pick up next — but the docs currently say "paused" and
list specific open blockers, so treating it as the next scheduled step is a decision that reverses
a documented pause, not a continuation of one. Worth an explicit go-ahead on record rather than
starting from the sequence alone.

---

## The eight steps, one at a time

Verdict is about whether the documented state supports the sequence as stated, not a judgment on
the plan itself.

### 1. Data Manager correction — **Matches**
No dedicated `docs/roadmap/` file — this work is tracked through ADR 0006 and live session
activity, not the roadmap corpus. Confirmed genuinely in-progress by direct evidence, not
inference: this session's own `tier2_gate`/`conn_consent` NAMESPACES grants landed
(`db19c20`, `8a671f2`), and Window 3's `data-manager-single-authority-scoping-2026-08-08.md`
(committed `d910ac7`) is actively scoping the broader grant gap right now.

### 2. Error-code rollout — **Matches**
Same situation — no dedicated roadmap file, tracked live. This session shipped the
`E-CONSENT-*` catalog, whose docstring records the motivating finding directly: empirically
verified that *no namespace at all* could write `error_codes`/`error_occurrences` before today,
scoped explicitly to `conn_consent` only, naming "the broader sweep" as Window 3's separate item —
which then shipped same-day as the core error-ledger exemption (`99f745c`). "In progress" is
accurate on the nose.

### 3. Window 1 → memory injection/recovery — **Conflict**
See above.

### 4. Final agent versions, including Android — **No doc**
No Android/mobile scoping doc exists anywhere in `docs/roadmap/` or `docs/architecture/` — only
passing mentions in `device-identification.md` (MAC-randomization behavior) and `ROADMAP.md`'s own
Phase 8, which is itself badly stale (still references `/home/<user>/dashboard/` and port 8080 —
predates the `/opt/nemesis` migration and the entire module system). Mac/Linux agent completion
status isn't tracked as a discrete milestone anywhere either. Not a conflict — there's just no
scoping to build "final" against yet.

### 5. Full dashboard pass — **Has its own order**
Six docs line up with this (`dashboard-l2-toggle`, `dashboard-roles-access-control`,
`responsive-dashboard-multiuser-ready`, `single-user-assumptions-audit`,
`settings-loaded-vs-enabled-refactor`, `system-changes-badge`) — all parked/queued, none built.
Several are explicitly gated on "Pass-0 migration" completing first, and
`single-user-assumptions-audit.md` states its own position outright: run *after* Pass-0, *before*
the responsive-dashboard build. If "full dashboard pass" means all six together, the docs already
specify an internal order worth following rather than treating as one undifferentiated block.

### 6. v2 full stop — **Not one milestone**
A real framework exists — `docs/roadmap/enterprise-gap-audit-2026.md` plus PUNCHLIST's "v2/v3
captures" section — but it's explicitly "capture-only… record, don't build," and its own items
are described as "project-sized — they graduate to roadmap specs when scheduled." That's six-plus
independent, unscoped efforts (MITRE mapping, basic vuln management, auth/login monitoring,
process-execution monitoring, core lateral-movement, emergency-backup-on-canary), not a single
closeable phase. "Full stop" implies a finish line the docs don't currently define.

### 7. Backend build — **Overlaps step 6**
The docs don't treat this as a phase that follows v2 — they treat it as part of v2.
`enterprise-gap-audit-2026.md` tags MITRE mapping and open-source threat-feed integration directly
as *"[V2 — add to the community backend build]"*, and `open-source-threat-feeds.md` says outright:
"Included in the community backend build, not deferred." Sequencing backend build as its own step
after "v2 full stop" is a real reordering versus how the existing docs group this work — worth
confirming that's the intended split. (Small aside: the backend's own design docs,
`community-reporter-identity.md` and `community-signal-dedup.md`, have no Status: line at all —
the only two files in the corpus missing one.)

### 8. v3 scoping — **Matches**
`msp-central-management.md` is explicitly framed exactly this way: "v3+ / possible separate SKU…
parked — design notes only (do NOT build yet)." `verified-partner-program.md` reads the same,
post-commercial. "Scoping" is the right verb for where these already sit.

---

## What the sequence doesn't mention

Not a criticism of the plan — a checklist so nothing already in flight gets silently dropped when
the sequence starts driving priority.

**Already carried forward in HANDOFF.md, owed regardless:**
- Vestigial-tables removal audit (`alert_notes`, `anomaly_ai_cache`, `anomaly_ai_usage`) — carried
  since 2026-08-06, still Window 2's.
- ADR 0022 write-up (QUIC/nftables) — carried since 2026-08-06, still unwritten. Confirmed this
  session it's unrelated to gateway-mode, so it isn't quietly covered by anything else in the
  sequence.
- The long carried-forward tail: `enrich_ip()` external IP exposure, agent check-in jitter,
  empty-alert-list read-window mismatch, install.sh default-route interface detection,
  host-defence rule naming, Windows DHCP hostname truncation, cache-hit token skew, installer
  token revocation, credential rotation, Concurrency Phase 3, `/api/analyze/<rule_id>`
  GET-that-spends-money.

**Named work with its own roadmap doc, not referenced by name:**
- **track-c-metadata-tier-build-plan.md** — PARTIAL per the 08-07 baseline. Worth flagging
  directly: this is very likely the *same effort* as steps 1–2 under a different name — the
  consent/error-code work landed this session (`conn_consent.py` is literally Requirement 0's real
  caller) is this plan's own scope. Tracking it separately from "Data Manager correction" risks
  double-booking or losing continuity.
- **gateway-mode-scoping.md** — committed 2026-08-08 (`033a1cb`), not mentioned anywhere in the
  sequence.
- **ADR 0019 Increment 4** (cutover to real enforcement authority) — explicitly "has not started,"
  sitting as open architecture work independent of this sequence.
- The Tier 2 TLS-interception mechanism's own build status lives in the private mirror entirely —
  invisible from the public roadmap docs, even though the public-side interface for it
  (`tier2_gate_state.py`) shipped this session.

**Other SHIPPED/PARTIAL items from the 08-07 baseline, unmentioned:**
- **clean-uninstall-build-spec** — Phases 1–3 built; the e2e VM uninstall lifecycle test is still
  unrun.
- **installer-unified-v1.0.6** — delivery + self-onboard live; two before-trip fixes remain.
- **malware-detection-pipeline** — Layers A+B live; C/D still scaffold only.
- **data-retention-and-archival-policy** — `dm_operation_log` coalescing shipped; the broader Tier
  A retention policy isn't built.
- Plus 390 open items in `PUNCHLIST.md` generally — small fixes by design, but the sequence
  doesn't say when (or whether) a punchlist sweep happens between phases.

---

## Coverage note

This pass read every roadmap-doc status line, the 08-07 baseline audit, PUNCHLIST's v2/v3
section, the relevant ADRs, and HANDOFF's current carried list. It did not re-verify every
SHIPPED/PARTIAL classification against live code (relied on the maintained baseline), and
Mac/Linux agent completion specifically has no discrete tracking doc anywhere, so step 4's
"final… versions" couldn't be checked beyond Android. Flagging the limits rather than implying a
fully exhaustive sweep.

## Cross-references

Interactive version (same findings, at-a-glance layout): published as a Claude Artifact,
2026-08-08. `docs/audits/roadmap-state-audit-2026-08-07.md` (the SHIPPED/PARTIAL/PARKED
classification baseline this pass relied on), `docs/audits/data-manager-single-authority-scoping-2026-08-08.md`
(steps 1–2's supporting evidence), `docs/roadmap/gateway-mode-scoping.md`,
`docs/roadmap/memory-injection-detection-design.md`, `docs/roadmap/enterprise-gap-audit-2026.md`.
