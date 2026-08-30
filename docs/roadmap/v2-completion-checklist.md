# Roadmap — v2 completion checklist

**Status:** capture, operator-directed 2026-08-08. **This is a completion gate for v2, not a
someday list.** Folded in from `docs/audits/roadmap-sequence-delta-2026-08-08.md`'s "before v2 is
over" findings, per Paul's direct instruction after reviewing that delta: nothing on this list
gets silently dropped as v2 wraps up. Not a build order and not itself a scoping doc for any one
item — each line points at where the real scope already lives.

## Backend build — resolved, no reordering needed

Confirmed 2026-08-08: the community backend build is documented as **part of v2**, not a separate
phase after it (`docs/roadmap/enterprise-gap-audit-2026.md` tags MITRE mapping and open-source
threat-feed integration directly as *"[V2 — add to the community backend build]"*, and
`open-source-threat-feeds.md`: *"Included in the community backend build, not deferred."*). No
doc changes needed here — recorded so this open question from the delta review doesn't get
re-litigated.

## Checklist correction — 2026-08-30, was always a v2 target

**Lateral-movement Tier 1 (core, owned-fleet correlation) is added to this gate as a correction
to a silent omission, not a new addition.** It was already named a v2 target in three places
before this checklist ever mentioned it: `docs/roadmap/lateral-movement-outbreak-detection.md`'s
own status line, the promoting commit (`eec1a00`, 2026-06-28 — "lateral-movement core promoted to
v2"), and an open `PUNCHLIST.md` entry (line 391). It was simply never carried into this checklist
when the checklist was built 2026-08-08 from the roadmap-sequence-delta audit, and nobody caught
the gap until this session's live-verification pass (2026-08-30). Recorded the same way this
checklist already asks everything else to be recorded — a document whose whole purpose is
catching silent gaps had one of its own; the fix is to say so, not to quietly patch it in as if it
had always been item 10.

## Gate reopening — 2026-08-30, operator-directed (not scope creep)

**DNS-exfiltration detection, rogue-DHCP detection, and lateral-movement Tier 2 (venue/epidemic
spread) are added to this gate, effective 2026-08-30.** All three were previously outside v2 scope
(DNS-exfiltration and rogue-DHCP alongside ARP-spoofing detection; Tier 2 on its own
venue-market-timing park decision); the operator explicitly reopened the gate for these three,
while leaving ARP-spoofing itself parked/v3 (see the tension flagged below). Recorded here as a
deliberate decision, not a silently-expanding scope — the exact failure mode this checklist exists
to prevent, applied to itself: a gate that can be reopened without leaving a record of *why* is no
more trustworthy than one that silently grows.

**Reasoning (operator's, recorded verbatim in substance) — DNS-exfiltration and rogue-DHCP:** both
are cheap enough to justify adding to v2 rather than deferring to v3 — telemetry is already
flowing (Suricata's `eve.json` already carries DNS events, and DHCP extended-logging is a config
flip, not new infrastructure), and DNS-exfiltration detection extends existing `anomaly_detection`
tailer code rather than standing up a new pipeline. **ARP-spoofing detection stays parked/v3** —
unlike the other two, it has a structural dependency on the unmade gateway-mode decision
(`gateway-mode-scoping.md`, already item 1 on this gate below), so reopening it now would just
create a second gate item blocked on the same undecided piece.

**Reasoning — lateral-movement Tier 2:** unlike DNS-exfiltration/rogue-DHCP above, this is a
genuine reopening of an already-parked decision, not a same-day addition alongside an
already-open question — Tier 2 was parked pending Tier 1 shipping and the venue market being
scheduled, a business-timing gate, not a technical one. Reopened specifically because Tier 2 is
the only existing design that detects a compromised IoT/agentless device spreading to or attacking
other LAN devices: Tier 1's trigger requires an already-flagged, agent-monitored source
(canary/YARA/anomaly detection), which an IoT device structurally cannot produce, so Tier 1 alone
leaves IoT-as-pivot invisible even if fully built (confirmed this session, live-code-verified —
grep across `modules/anomaly_detection/`, `alert_manager/`, and `git log --all` for the design's
own vocabulary returns nothing beyond its two doc-only commits). The operator specifically wants
IoT-compromise-spread coverage; Tier 2 is the only design that provides it — that is the entire
reason for reopening it now rather than leaving it behind the venue-market timing that motivated
the original park decision.

**⚠ Open tension with the ARP-spoofing decision above, flagged here, not resolved.** Tier 2's own
signal list names "ARP anomalies — spoofing / unexpected mappings" as one of its five detection
signals (`lateral-movement-outbreak-detection.md`'s Tier 2 section). This same reopening,
immediately above, explicitly keeps ARP-spoofing detection parked/v3 because it depends on the
unmade gateway-mode decision. Reopening Tier 2 pulls ARP-anomaly detection back into gated v2
scope as one of Tier 2's bundled signals, the same day it was deliberately excluded under a
different name. Not resolved here — recorded so it is visible rather than silently contradictory.
Whoever scopes Tier 2's build should either exclude the ARP-anomaly signal specifically pending
the gateway-mode decision, or revisit why ARP was kept parked at all.

Full technical scope: `docs/roadmap/dns-exfiltration-detection.md`,
`docs/roadmap/rogue-dhcp-detection.md` (both new 2026-08-30, capture/build-ready, not yet
built — build order: rogue-DHCP first, DNS-exfiltration second, per the docs' own
cross-references); `docs/roadmap/lateral-movement-outbreak-detection.md` (Tier 1 + Tier 2, both
already existed, neither built).

## The gate — thirteen items, checked off before v2 is called done

- [ ] **rogue-dhcp-detection.md** — Suricata `dhcp: logger: extended: yes` config flip
  (install.sh + live box) plus a small consumer watching for a second DHCP server answering.
  No gateway-mode dependency. Not yet built.
- [ ] **dns-exfiltration-detection.md** — extends the existing `anomaly_detection` DNS tailer.
  Requires fixing two data-destruction points in that tailer first (the `_QTYPES = {"A",
  "AAAA"}` filter and the `_root_domain()` FQDN-collapse, `modules/anomaly_detection/module.py:101`
  and `:1336`) — both discard exactly the signal DNS-exfiltration detection depends on. Core
  false-positive suppression is a new per-client-per-domain baseline, extending the existing
  `anomaly_baseline` table's pattern. Newly-registered-domain checking explicitly deferred to
  the v2 community backend build, not this item. Not yet built.
- [ ] **lateral-movement-outbreak-detection.md — Tier 1 (core, owned-fleet correlation).** Was
  always a v2 target — see "Checklist correction" above, not a new decision. **Spec written
  2026-08-30** (in the roadmap doc) — grounded in verified existing schema (finding tables,
  device/IP identity), but gates on one open question: whether Suricata `eve.json` flow-event
  logging is live on the production box, not verified from the repo. Build not started.
- [ ] **lateral-movement-outbreak-detection.md — Tier 2 (venue/epidemic spread).** Reopened
  2026-08-30 — see "Gate reopening" above. **Signal set scoped against current visibility
  2026-08-30** (in the roadmap doc): 2 of 5 signals are Suricata rule-authoring work only, 2
  share Tier 1's open flow-logging question, and 1 (ARP anomalies) is architecturally the same
  detector as the already-parked ARP-spoofing item — flagged as an unresolved tension, not
  decided. Outbound-only IoT beaconing (C2/botnet, no LAN-neighbor attack) recommended
  **excluded** from this scope, as its own future line item. Still needs a real spec/ADR
  (thresholds, baseline windows, false-positive handling) before code — scoping is the input to
  that, not a substitute for it.

- [ ] **gateway-mode-scoping.md** — scoping only, zero code or ADR exists yet. Full gateway vs.
  bridged-peer opt-in toggle, segmentation enforcement. Not required to *ship* before v2 closes,
  but the decision of whether it's in v2's scope at all needs to be made explicitly, not by
  default omission.
- [ ] **ADR 0019 Increment 4** (cutover to real enforcement authority) — explicitly "has not
  started" per the ADR's own status line. Increments 1–3 are built and proven; this is the
  remaining piece that makes the enforcement point authoritative rather than observe-only.
- [ ] **Tier 2 TLS-interception build status — visibility gap, not a build gap.** The mechanism's
  own progress lives entirely in the private mirror (`~/work/nemesis-internal`); nothing in the
  public roadmap tracks it, even though its public-side interface
  (`alert_manager/tier2_gate_state.py`) shipped this session. Before v2 closes, confirm whether
  this needs a public-side status pointer (architecture/existence only, per Rule 10 — not
  mechanism detail) so it isn't invisible to anyone reading only the public docs.
- [ ] **clean-uninstall-build-spec — e2e VM uninstall lifecycle test.** Phases 1–3 are built; the
  actual end-to-end VM uninstall test has never been run. A spec that's "built" but never
  exercised end-to-end is not the same claim as "works."
- [ ] **malware-detection-pipeline — Layers C/D.** Layer A (ClamAV/YARA/heuristics) and Layer B
  (canary/behavioral) are live. Layer C (AI verdict via ai_engine) and Layer D (local ML
  classifier) remain scaffold only.
- [ ] **data-retention-and-archival-policy — broader Tier A retention.** The `dm_operation_log`
  archive-then-coalesce piece shipped; the wider Tier A retention policy the doc scopes has not
  been built.
- [ ] **Vestigial-tables removal audit** (`alert_notes`, `anomaly_ai_cache`, `anomaly_ai_usage`) —
  carried in HANDOFF.md since 2026-08-06, still Window 2's, not yet started.
- [ ] **ADR 0022 write-up** (QUIC/nftables static-policy block, "Piece K") — carried since
  2026-08-06, still unwritten. Confirmed 2026-08-08 it is unrelated to gateway-mode despite
  surfacing in the same day's PUNCHLIST entries — no other doc silently covers it.
- [ ] **The long-carried PUNCHLIST tail** — `enrich_ip()` external IP exposure, agent check-in
  jitter, empty-alert-list read-window mismatch, install.sh default-route interface detection,
  host-defence rule naming, Windows DHCP hostname truncation, cache-hit token skew, installer
  token revocation, credential rotation, Concurrency Phase 3, `/api/analyze/<rule_id>`
  GET-that-spends-money. Individually small; carried unchanged across multiple HANDOFFs, which is
  itself the signal this list exists to catch.

## How this gate is meant to be used

Not everything above has to *ship* for v2 to close — some items may get an explicit "deferred to
v3, decision recorded" resolution instead of a build. What this checklist prevents is the silent
version: v2 gets called done because the visible feature list is complete, while one of these
sits unfinished and un-decided, discovered later as a gap nobody chose. Each line above needs
either a shipped commit, or an explicit operator decision to defer, before v2 is declared over —
not to disappear from a carried-forward list by attrition.

## Cross-references

`docs/audits/roadmap-sequence-delta-2026-08-08.md` (source of this checklist),
`docs/roadmap/enterprise-gap-audit-2026.md` (v2/v3 item catalog), `docs/roadmap/gateway-mode-scoping.md`,
`docs/architecture/0019-deterministic-enforcement-point.md`,
`docs/roadmap/clean-uninstall-build-spec.md`, `docs/roadmap/malware-detection-pipeline.md`,
`docs/roadmap/data-retention-and-archival-policy.md`,
`docs/roadmap/rogue-dhcp-detection.md`, `docs/roadmap/dns-exfiltration-detection.md` (2026-08-30
gate reopening — see above), `docs/roadmap/lateral-movement-outbreak-detection.md` (Tier 1:
2026-08-30 checklist correction; Tier 2: 2026-08-30 gate reopening — see above),
`docs/handoff/HANDOFF.md` (current carried items — this checklist
doesn't replace HANDOFF's carry-forward tracking, it groups the subset that specifically gates
v2).
