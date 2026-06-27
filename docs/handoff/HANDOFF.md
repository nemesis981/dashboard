# HANDOFF — current state

> Current project state, last updated 2026-06-26 (closeout #2). Overwritten at each nightly
> closeout (latest state wins). Durable history lives in `docs/handoff/supplements/`
> (append-only); raw step log in `docs/handoff/worklog/`.

## Resume point → NEXT OPENER

**Run the commercial-readiness / single-user-assumptions audit**
(`docs/roadmap/single-user-assumptions-audit.md`) — with the **single-version / key-unlock**
model as its north-star. Produce a change-list to make the whole tree uniformly multi-user-ready
+ "key-gate-socketed", work it, finalize in repo — **THEN** continue to the orchestration ADR 0004
(answer its 3 hinge questions) + scheduler/reporting build. Reasoning in
`supplements/2026-06-26-002.md` §7. (Unchanged by this session — Stage 4 was the pending Pass 0
cleanup, now closed; the audit is the next real work.)

## Where things stand

**Pass 0 — ✅ COMPLETE (all stages).** Module consolidation onto the shared `alerts.db` (Stages 2–3)
plus all Stage 4 cleanup are done.

**Pass 0 Stage 4 — ✅ COMPLETE:**
- ✅ Ghost 0-byte DBs removed (`dashboard.db`, `malware_detection/malware.db`).
- ✅ `scan_jobs` → `malware_scan_jobs` rename (`9db6e7a`) — name collision resolved; nullable
  `actor` seam added; verified live.
- ✅ Malware DB-accessor fix (`5fd3a9c`) — uses shared `get_db()`; verified live.
- ✅ **`hw_alerts` duplicate CREATE collapsed (`f19e5c5`)** — deleted hw_monitor's redundant CREATE;
  **watchdog** is sole-writer owner. Safe because hw_monitor only reads via the exception-guarded
  `get_hw_alerts()` and there's no startup ordering. Live table untouched.
- ✅ **`quarantines` duplicate CREATE collapsed to shared init (`fb7e7fc`)** — canonical
  `init_quarantines_table()` added to `alert_manager/database.py`; **both** call sites kept as thin
  wrappers (alert_watcher startup create-before-write; dashboard lazy self-heal before its unguarded
  SELECT). One DDL definition, two callers. Live table untouched. (Not deleted-one-side: the audit
  showed that would reintroduce a missing-table crash.)
- ⏳ The previously-listed "retire `hw_monitor`'s local-clamscan path" is **NOT** a Stage-4 cleanup —
  it's entangled with orchestration and sequenced AFTER ADR 0004 direction is specified (see below).

**Scan/task orchestration — DIRECTION DECIDED (ADR 0004, Proposed):** scheduler module =
authoritative dispatcher; execution modules (malware = full-stack, hardware, future) do the work;
reporting module processes/delivers printable reports; `hw_monitor` → hardware-only. 3 open hinge
questions recorded in the ADR (unified findings table?; how full-stack reaches the fleet?; where the
5 `scan_*` tables migrate?). See `docs/architecture/0004-scan-task-orchestration.md`.

**VPN / DNS — lean shifted, HELD OPEN:** stable since post-reboot; no recurrence while the watcher
has run. Current **lean = a PIA-Linux-client STATE issue** (long-uptime daemon rot, reboot-cleared)
**over** a firewall/routing *mechanism* as root trigger — but **explicitly held open**: ADR 0002's
policy-routing/killswitch mechanism is real and could be *triggered by* client state; the two aren't
exclusive. Read-only watcher (`~/work/vpn-watcher/`, OUTSIDE repo, not committed) stays armed to
**disambiguate on the next failure** (v4-vs-v6 KEYTEST + source-IP/route capture). No new evidence
yet — no new failure. Detail in `supplements/2026-06-26-002.md` §2 + §9.

**Concurrency prerequisite (ADR 0001 Stage-2 gate):** shared `alerts.db` is WAL + `busy_timeout`;
concurrent-write smoke test passed.

**Secrets:** externalized OUT of the repo to `~/work/nemesis-private/local-config.md` (chmod 600)
— referenced by location only, never committed.

**Backups:** Stage-0 rollback snapshot on independent external storage (all `integrity_check=ok`).
Per-sub-task Stage 4 backups also on independent storage (scanjobs, dbaccessor, hwalerts,
quarantines — each verified `integrity_check=ok`).

## Decisions / principles carried (see supplements 1 & 2)
- **Licensing principle (flag for CLAUDE.md promotion):** SINGLE version; a key/license unlocks
  commercial features (multi-user, attribution, device limits) IN PLACE — not a separate fork. The
  key is what "wires the house" the multi-user-ready seams leave socketed.
- **Reporting module UX:** dashboard button, flashes on new report, PER-USER unread state → reports
  page → preview/print.
- **VPN self-diagnostic feature idea:** generalize the watcher to any VPN; AI plain-language
  diagnosis → gated fix suggestion OR auto-generated support ticket. Guardrail: config edits go
  through Teaching/Automated approval gates, NEVER silent auto-apply. Build AFTER the root-cause fix.

## New design captures this session (PARKED — supplement 2 §10; ADR/roadmap-bound, NOT built)
- **Namespace reservations** (`modules/scheduler/`, `modules/reporting/`) as anti-drift markers —
  README "this concern lives here, see ADR 0004." (Scheduling already drifted into 4+ places.)
- **Schema gatekeeper / registry** (ADR-bound): modules DECLARE schema, core creates all tables
  before module logic (prevent-by-contract) + resilience (missing table → bounded retry → structured
  log → graceful module UNLOAD with visible reason). MANDATORY, unbypassable, SOLE DB-access path →
  makes ADR 0001 write-own/read-scoped structurally enforced, not convention.
- **Third-party module TRUST & ISOLATION model** (separate ADR): DB-gatekeeper is
  necessary-not-sufficient (module can bring own DB/file/network/subprocess). Layered: curation/review
  (trust) now + manifest capability declaration (transparency) + process/privilege isolation
  (enforcement) later. Honest caveat: real Python sandboxing is hard — near-term is curation +
  transparency, not technical enforcement.
- **Ownership / consent boundary** (PRINCIPLE, CLAUDE.md-bound): device-action capabilities gated by
  ownership. Owned/agent devices = scan/inventory/log-fetch with consent; venue/unowned = network-
  behavior observation ONLY. Agent presence = consent signal for the low tier; sensitive tier needs
  agent + explicit attributed type-YES authorization (owner/admin) + recorded attribution. (Final
  clause was truncated in capture — confirm at next session.)

## Stage 5 / 6 (later)
- **Stage 5** — single SQLite-safe shared-DB snapshot backup; make deploy/health DISCOVER services
  (picks up `vpn-dns-guard.service`); purge per-module-DB refs in `_backup_candidates()` /
  `install.sh` (`PUNCHLIST.md`).
- **Stage 6** — retire old module `.db` fallbacks after N verified days.
- **Parked quick wins** — `PIHOLE_IP` hardcoded-default fix (Rule 8) + hygiene sweep, settings
  status-fix, header de-dup, kernel-update check (all in `PUNCHLIST.md`).

## Pointers
- Methodology & rules: `CLAUDE.md`
- Architecture: `ARCHITECTURE.md`, `docs/architecture/` (ADR 0001 DB, 0002 DNS, 0003 resilience,
  **0004 scan/task orchestration — Proposed**)
- Operational reference: `docs/reference/operational-notes.md`
- Audits: `docs/audits/` — `malware-detection-state-audit.md`, `scan-task-architecture-audit.md`
- Parked ideas: `docs/roadmap/`
- Small fixes: `PUNCHLIST.md`
- Session logs: `docs/handoff/supplements/` (latest: `2026-06-26-002.md`, §8–§10 = Stage 4 close +
  VPN lean + design captures); worklog `docs/handoff/worklog/2026-06-26-001.md`
- VPN watcher (outside repo, not committed): `~/work/vpn-watcher/vpn-watch.sh`
</content>
</invoke>
