# ADR status audit — 2026-07-25

> Read-only audit (Rule 1). Cross-checks each ADR's own `Status:` header against `git log` /
> code evidence — don't header-trust, same discipline as the roadmap-vs-state audits. Companion
> to `roadmap-state-audit-2026-07-25.md`. First audit of its kind; no prior baseline to diff
> against, so this doc *is* the baseline going forward.

**Tally (updated same day, post-audit — see note on the ADR 0006 row): 2 fully shipped
(headers were stale, fixed this session) · 1 superseded/shipped · 1 partial
(data-collection only) · 1 design-accepted with execution tracked elsewhere as PARTIAL ·
7 proposed/unbuilt — 12 total.**

## Findings

| ADR | Title | Header status (before this audit) | Actual state |
|---|---|---|---|
| 0001 | Database & module architecture | Proposed — revised | **Stale — fixed this session.** Migration Stages 0–3 shipped: all 4 modules cut over to the shared `alert_manager/alerts.db` — tickets (`6f6b6c3`), community_queue (`290c2db`, "completes module consolidation"), ai_engine (`181c14c`), malware_detection (pre-existing). Stage 4 (dedupe creators + retire 0-byte ghosts) also done — `quarantines`/`hw_alerts`/`scan_jobs` each have one `CREATE TABLE` owner; `dashboard.db` and `malware_detection/malware.db` ghosts are gone. **Stage 5 NOT done** — `dashboard.py:36` still hardcodes `HEALTH_SERVICES` instead of discovering `*.service` units. **Stage 6 NOT done** — `ai_engine.db`/`tickets.db`/`community_queue.db` still on disk, unreferenced but not archived/deleted. Header rewritten in place to reflect per-stage status. |
| 0002 | VPN-aware DNS routing | Superseded (root-cause) | **Confirmed.** `core/vpn_dns_guard.py` exists; `vpn-dns-guard` service is active. No change needed. |
| 0003 | Database resilience & recovery | Proposed | **Confirmed unbuilt.** No code. Matches roadmap PARKED `db-resilience-backup-promotion`. |
| 0004 | Scan task orchestration | Proposed | **Confirmed unbuilt.** File already self-notes "Status remains Proposed." |
| 0005 | DNS/firewall device-auth architecture | Proposed | **Confirmed unbuilt/blocked.** Direction decided, design not specified; HANDOFF (07-02) names the unresolved Pi-hole tunnel-query-refusal blocker (blocks L1 real use). |
| 0006 | Data Manager | Proposed (at audit time) → **v1 SHIPPED — COMPLETE (updated later same day, 2026-07-25)** | **Superseded by same-day build, not just a stale-header fix.** At audit time only the v0 seed existed, matching the header — no fix was needed then. Later the same day, v1 shipped in full: `alert_manager/data_manager.py` (`GuardedConnection`, `next_sequence`/`increment_counter`/`upsert`, `dm_operation_log` audit trail, actor context on every write incl. raw passthrough), all 6 DB-using modules migrated (`dhcp` discovered DB-free, no migration needed), and `modules_loader.py` updated to statically reject raw `sqlite3`/bare `get_db()` at load time (AST-based, verified against all 7 real modules + synthetic violation cases). v2 (schema gatekeeper) is now explicitly **deferred** pending L3 producing real schemas to design against, not merely unstarted. v3 unchanged (not started). ADR 0006 doc and CLAUDE.md's Data Manager section both updated to match. |
| 0007 | Device/user model | Proposed | **Confirmed not started.** Commercial-tier build target, explicitly deferred. |
| 0008 | Impossible travel + concurrent session detection | Proposed — v2 target | **Confirmed PARTIAL — data collection only.** `login_events` table + tiered lockout + concurrent-session seam shipped (`21c8931`, `c521d57`). Detection *logic* itself still v2/unbuilt. Header already accurately scoped this; no fix needed. |
| 0009 | Security inspection proxy | Proposed | **Confirmed unbuilt.** Design captured; Fork B (tunnel-routed central Suricata) chosen over Fork A in the two 0009 scoping docs (`adr-0009-build-scope.md`, `adr-0009-l3-fork-b-scope.md`). No code. |
| 0010 | Agent ping monitor (per-device) | Proposed | **Confirmed unbuilt**, explicitly deferred until after trip-readiness. Distinct from the already-SHIPPED host-wide `diagnostics-connectivity-watcher-tool` — the two are easy to conflate but are not the same feature (0010 is per-device continuous ping from the agent; the shipped item is a host-wide HTTP-curl probe from the Nemesis box). |
| 0011 | Enrollment security model | ACCEPTED — BUILD-READY | **Confirmed, not stale.** Design fully resolved (Q0–Q3); the ADR's own header says "no code changed by this ADR" — execution rides on roadmap item `installer-unified-v1.0.6` (roadmap-state audit: PARTIAL, two pre-trip fixes open). This is the ADR's intended shape, not a gap. |
| 0012 | Enrollment trust modes | BUILD-READY | **Confirmed unbuilt**, execute-ready post-trip. Matches roadmap PARKED `enrollment-modes-build-spec`. |

## Action taken this session
- **ADR 0001** header rewritten in place (`docs/architecture/0001-database-and-module-architecture.md`)
  to reflect verified per-stage status instead of the stale "Proposed — revised." No other ADR
  needed a header fix at audit time — 0006, 0008, and 0011 accurately scoped their partial/
  pending state in their own headers as of the audit.
- **ADR 0006 row updated later the same day** (docs-only follow-up, separate from this morning's
  audit run): v1 shipped in full between the audit and this update. This is a real-time
  amendment to a point-in-time audit doc, not a re-audit — flagged explicitly in the row itself
  so a future reader doesn't mistake it for what the original audit pass found.

## Follow-ups (flagged, not done)
- Consider archiving the three orphaned per-module `.db` files (`tickets.db`, `community_queue.db`,
  `ai_engine.db`) now that Stage 6 of ADR 0001 is the only thing keeping them around — small,
  bounded, PUNCHLIST-shaped.
- ADR 0001 Stage 5 (backup switch + service-discovery) is unscoped work sitting mid-migration;
  worth a deliberate go/no-go rather than leaving it implicitly open indefinitely.

## Method
Read each ADR's `Status:` header, then checked it against `git log --oneline --grep`/
`--diff-filter=A`, direct code grep, and cross-references to the roadmap-vs-state audit
(`roadmap-state-audit-2026-07-25.md`) and HANDOFF.md. No ADR content beyond the Status line
was altered.
