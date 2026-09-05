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

**Last verified against code: 2026-09-05.** This gate is graded on code/git-log, never on a
file's own `Status:` header — the same discipline CLAUDE.md's roadmap-vs-state audit already
applies at the file-classification level, one level down: a file can be correctly classified
while the checkboxes *inside* it rot silently. **2026-09-04 finding: 7 of 13 items were stale,
all in the same direction — overstating remaining work** (5 fully closeable, 1 blocker
resolved, 1 partially closed). Found by Window 1's audit, independently re-verified item by
item before any checkbox changed. A gate whose whole purpose is "nothing gets silently
dropped" can't do that job if it also can't tell you when things are already done — add this
line's date forward every time the gate is re-verified, so staleness here is visible rather
than assumed.

**2026-09-05 correction — lateral-movement Tier 1 AND Tier 2 were both stale, same direction
as 09-04's finding.** `lateral-movement-outbreak-detection.md`'s own `⛔ RESOLVED 2026-09-02`
sections (written the same day these shipped, three days before this gate caught up) declare
the reduced-scope detection form "the PERMANENT shape for non-VLAN installs, not a temporary
compromise. Both tiers are unblocked to build in that form now." Both were then built exactly
to that spec, same day: `modules/anomaly_detection/post_detection.py:41`
(`POST_DETECTION_TYPE = "post_detection_egress"`, full four-stage build in `module.py`,
integration-tested) for Tier 1, and `modules/lan_behavior_monitor/` (`behavior.py:64`
`PROBE_SCAN = "lan_probe_scan"`; `manifest.json` `display_name: "LAN Probe & Scan Detection"`
verbatim-matches the doc's own UI-label spec, `enabled_by_default: true`,
`test_lan_behavior_registry.py` registry-completeness test present) for Tier 2's
currently-buildable signals. This checklist's items 3/4 below were still reading "STILL
BLOCKED... build has not started" — quoting the *pre*-RESOLVED state of a doc that had already
resolved itself. Same failure shape as 09-04's ADR 0019 finding (a doc self-corrects, a
downstream reference keeps citing the pre-correction text) — now confirmed twice on this one
checklist. **The full originally-imagined form (true unicast peer-to-peer correlation) remains
genuinely and permanently blocked on VLAN-capable switching/port-mirroring hardware the
operator doesn't control — that has not changed and is not what's being checked off here.**
What changed is that the doc itself declared the reduced form the complete v2 deliverable, not
a partial one, and the code matching that declaration already exists.

- [x] **rogue-dhcp-detection.md — BUILT AND DEPLOYED, corrected 2026-09-04.** Was marked
  "not yet built"; false. `scripts/enable-suricata-dhcp-extended.sh` is the config flip
  (`dhcp: enabled: yes`, confirmed live in `/etc/suricata/suricata.yaml`, dhcp events present
  in `eve.json` — the flip is applied, not just written). `modules/lan_integrity/rogue_dhcp.py`
  is the consumer (`module.py` imports it, `parse_event`/`classify`, findings emit
  `kind='rogue_dhcp'`); `lan_integrity_dhcp_servers` + `lan_integrity_findings` exist in the
  live DB. `test_rogue_dhcp.py`: 46/46 passing (re-run 2026-09-04). Found by Window 1's audit,
  independently re-verified before checking this off.
- [x] **dns-exfiltration-detection.md — BUILT, corrected 2026-09-04.** Was marked "not yet
  built" with two data-destruction points listed as prerequisites; both were fixed in the same
  build that shipped this (`cc4aef5`). `modules/anomaly_detection/module.py`: a second tailer
  consumer (`_accumulate_channel`, `:679`) runs BEFORE the `_QTYPES`/`_root_domain` filtering
  that the old novelty detector still uses — "sees everything" by construction, not by fixing
  the filter in place. `_exfil_cycle` (`:705`) drives a selftest that raises on failure
  (`:717-719`, not a soft warning) and emits `incident_type: "dns_exfiltration"` (`:783`). The
  doc's own line-number citations were additionally stale (`_QTYPES` moved `:101`→`:107`,
  `_root_domain` moved `:1336`→`:1552`) — both re-verified against current code. Found by
  Window 1's audit, independently re-verified (exact line matches) before checking this off.
- [x] **lateral-movement-outbreak-detection.md — Tier 1 (core, owned-fleet correlation) —
  SHIPPED in its permanent reduced-scope form, corrected 2026-09-05.** Was marked "STILL
  BLOCKED... build has not started" — stale, quoting the doc's own pre-RESOLVED state (see the
  2026-09-05 correction note above). `modules/anomaly_detection/post_detection.py:41`
  (`POST_DETECTION_TYPE = "post_detection_egress"`) plus the four-stage build in `module.py`
  (trigger-table watcher, correlation, dedup, incident creation via the existing
  `_create_or_update_incident` pattern), integration-tested
  (`test_post_detection_integration.py`, `test_post_detection.py`). **The full originally-
  imagined form (true unicast peer-to-peer correlation) remains permanently blocked on
  VLAN-capable switching/port mirroring the operator doesn't control** — that's real and
  unchanged, but the doc itself declares the reduced form the complete v2 deliverable, not a
  partial one, so this checks off.
- [x] **lateral-movement-outbreak-detection.md — Tier 2 (venue/epidemic spread), buildable
  signals — SHIPPED, corrected 2026-09-05.** Was marked unchecked pending a spec/ADR — stale,
  same reason as Tier 1 above: the doc's own `⛔ RESOLVED 2026-09-02` section scoped exactly
  which signals are buildable now and named the build. `modules/lan_behavior_monitor/behavior.py:64`
  (`PROBE_SCAN = "lan_probe_scan"`); `manifest.json`'s `display_name: "LAN Probe & Scan
  Detection"` verbatim-matches the doc's own UI-label spec, `enabled_by_default: true`;
  `test_lan_behavior_registry.py` provides the registry-completeness test this codebase's
  standing practice requires for any module declaring routes. **The ARP-anomaly signal /
  ARP-spoofing tension flagged below is still unresolved** — not all five originally-listed
  Tier 2 signals shipped, only the currently-buildable subset the RESOLVED section scoped; the
  excluded outbound-only-IoT-beaconing line item and the ARP tension are real open threads, not
  closed by this checkbox.

- [ ] **gateway-mode-scoping.md — "zero code exists" corrected 2026-09-04, still open
  otherwise.** `core/gateway_mode.py` is 538 lines (not zero), and `alert_manager` carries
  dozens of gateway-related references (`NEMESIS_GW_LAN_IFACE`, `gateway_switch`) — real code
  exists. The item's actual ask is unaffected: no ADR exists for this topic (the only ADR
  matching `/gateway/` is 0028, email security gateway — a different "gateway," not network
  gateway mode), and the decision of whether this is in v2's scope at all still needs to be
  made explicitly, not inferred from code existing.
- [x] **ADR 0019 Increment 4 — SHIPPED, corrected 2026-09-04.** Was marked "explicitly has
  not started per the ADR's own status line" — that line is itself stale and the ADR has
  since corrected it: `0019-*.md` line 13 now reads "...'has not started,' which stopped being
  true 26 days earlier," and line 135 states "Increment 4 (cutover) landed 2026-08-01." This
  checklist was quoting a status line the ADR itself had already retracted — a pattern worth
  watching for elsewhere (a doc can self-correct and a downstream reference can still cite the
  pre-correction text). Found by Window 1's audit, independently re-verified before checking
  this off.
- [ ] **Tier 2 TLS-interception build status — visibility gap, not a build gap.** The mechanism's
  own progress lives entirely in the private mirror (`~/work/nemesis-internal`); nothing in the
  public roadmap tracks it, even though its public-side interface
  (`alert_manager/tier2_gate_state.py`) shipped this session. Before v2 closes, confirm whether
  this needs a public-side status pointer (architecture/existence only, per Rule 10 — not
  mechanism detail) so it isn't invisible to anyone reading only the public docs.
- [ ] **clean-uninstall-build-spec — e2e VM uninstall lifecycle test.** Phases 1–3 are built; the
  actual end-to-end VM uninstall test has never been run. A spec that's "built" but never
  exercised end-to-end is not the same claim as "works."
- [x] **malware-detection-pipeline — Layers C/D — BUILT, corrected 2026-09-04.** Was marked
  "scaffold only"; false, and the module's own docstring says so — its comments explicitly
  read "no classifier — FALSE since 08-21" and "no entry point — FALSE since 08-21."
  `modules/malware_detection/`: `ml_classifier.py`, `ml_features.py`, `ml_model.py`,
  `ml_train.py` all present, `test_layer_c.py` (291 lines, re-run 2026-09-04) plus
  `test_layer_c_render.py`/`test_ml_train.py`. Found by Window 1's audit, independently
  re-verified (files present, line counts match) before checking this off.
- [ ] **data-retention-and-archival-policy — broader Tier A retention.** The `dm_operation_log`
  archive-then-coalesce piece shipped; the wider Tier A retention policy the doc scopes has not
  been built. **Confirmed still accurate 2026-09-04** — the doc's own status line reads
  "PARTIAL, and item 1 is now LIVE," matching this entry exactly.
- [x] **Vestigial-tables removal audit — CLOSED, nothing to remove, corrected 2026-09-04.**
  `alert_notes`, `anomaly_ai_cache`, `anomaly_ai_usage` do not exist in the live DB
  (`sqlite_master` query returns empty, re-verified) and have no `CREATE` anywhere in the repo
  — either already removed or never created. **Worth one deliberate look, not done here:** why
  there's no `CREATE` for tables this checklist assumed existed, given CLAUDE.md's "no table
  without a CREATE in the repo" rule — closing the checkbox doesn't answer that, it just means
  there's nothing live to clean up. Found by Window 1's audit, independently re-verified
  before checking this off.
- [x] **ADR 0031 write-up — SHIPPED 2026-09-05** (QUIC/nftables static-policy block, "Piece
  K"), by Window 1 (`51481f6`). Was carried since 2026-08-06, unwritten. Confirmed 2026-08-08
  it is unrelated to gateway-mode despite surfacing in the same day's PUNCHLIST entries — no
  other doc silently covers it. `docs/architecture/0031-quic-static-policy-block.md` exists,
  status "Accepted and shipped 2026-08-06," measured against real adversarial traffic (24
  packets, zero false positives) — verified directly before checking this off, not taken on
  the commit message alone.
  **Corrected 2026-09-04 — number collision found live:** this item carried "ADR 0022" since
  2026-08-08, when that number was reserved for exactly this write-up
  (`worklog/2026-08-08-002.md:13`). 2026-08-17's licensing work reused 0022 for
  `0022-source-available-license.md` (`worklog/2026-08-17-001.md:44`) without anyone catching
  that it was already spoken for — the QUIC item silently went numberless while this checklist
  kept citing the now-reassigned number. 0022 **stays** the licensing ADR (it exists, is live,
  and is referenced by `LICENSE`/`README.md`); this item takes **0031** instead — the next free
  number, verified against the full `docs/architecture/` range (0001-0030 in use, with
  pre-existing gaps at 0013/0017 not investigated here — flagged, not reused, pending a
  separate look at why they're empty).
  **Correction to the correction, same day:** the line above originally claimed this was "the
  only live citation" — false, caught by a truncated verification (`head -5` on an unfiltered
  grep cut off the tenth of ten matches). `gateway-mode-scoping.md:13` also stated the stale
  0022 earmark, and worse, framed it as independently confirmed settled fact — now fixed
  there too. Both live citations are corrected as of this entry; the append-only historical
  records (worklogs, supplements, dated audits, briefings) that also mention "ADR 0022" for
  this item are deliberately left untouched — they're dated accounts of what was true when
  written, not live references, and editing them would falsify history rather than correct it.
- [ ] **The long-carried PUNCHLIST tail — exact citations added 2026-09-05, one more item
  closed.** Individually small; carried unchanged across multiple HANDOFFs, which is itself the
  signal this list exists to catch. This entry's own naming had drifted far enough from
  `PUNCHLIST.md`'s current text that a fresh grep by topic name mostly failed — exact line
  citations below so this doesn't happen again.
  - `enrich_ip()` external IP exposure — **CLOSED** (confirmed 2026-09-04): `ca473d5`
    (2026-09-03) gates it through `ip_scope.is_public_ip()`.
  - **Installer token revocation — CLOSED, found stale 2026-09-05.** This item was carried as
    open; `PUNCHLIST.md:5059` records `[FIXED — 2026-08-29, pending commit]` —
    `POST /api/agent/installer/revoke` shipped, admin-gated, mutation-tested. Was already
    closed a week before this checklist's own 09-04 pass and nobody caught it.
  - Agent check-in jitter — open, `PUNCHLIST.md:3294`.
  - Empty-alert-list read-window mismatch — open, `PUNCHLIST.md:~3325` (`get_active_alerts()`
    vs. `get_alert_counts()` reading the log through two different windows).
  - `install.sh` default-route interface detection — open, `PUNCHLIST.md:3429`.
  - Host-defence rule naming — open, `PUNCHLIST.md:3453` (related finding at `:3401`).
  - Windows DHCP hostname truncation — open, `PUNCHLIST.md:3736`.
  - Cache-hit token skew — open, `PUNCHLIST.md:3160`.
  - `/api/analyze/<rule_id>` GET-that-spends-money — open, `PUNCHLIST.md:3110` (distinct from
    the already-`[x]`-resolved PII-redaction finding on the same route at `:3128` — don't
    conflate the two).
  - **Credential rotation — NOT confidently located.** Closest candidate is
    `PUNCHLIST.md:4358` ("`enrollment_tokens` stores installer tokens in PLAINTEXT at rest,"
    found 2026-08-27), but that's a storage-format finding, not literally rotation — flagged
    as uncertain rather than asserted.
  - **"Concurrency Phase 3" — NOT confidently located under that name.** Best candidate is the
    residual race documented at `PUNCHLIST.md:~432` ("`anomaly_incidents` merge is still
    read-JSON→merge-Python→write," labeled "RACE 4 residual" in-file, not "Phase 3") — same
    section as the other three concurrency races this checklist's items above already
    reference as fixed. Flagged as uncertain, not asserted.
  - **Net: 8 of 10 sub-items have exact current citations, 2 fixed/closed, 2 uncertain.** This
    checkbox stays open overall — 8 confirmed-open sub-items remain regardless of the 2
    uncertain ones' resolution.

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
