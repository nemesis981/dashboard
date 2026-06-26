# HANDOFF — current state

> Current project state, last updated 2026-06-26 (closeout). Overwritten at each nightly
> closeout (latest state wins). Durable history lives in `docs/handoff/supplements/`
> (append-only); raw step log in `docs/handoff/worklog/`.

## Resume point → TOMORROW'S OPENER

**Run the commercial-readiness / single-user-assumptions audit**
(`docs/roadmap/single-user-assumptions-audit.md`) — now with the **single-version /
key-unlock** model as its north-star. Produce a change-list to make the whole tree
uniformly multi-user-ready + "key-gate-socketed", work it, finalize in repo — **THEN**
continue to the orchestration ADR (answer its 3 hinge questions) + scheduler/reporting
build. Reasoning in `supplements/2026-06-26-002.md` §7.

## Where things stand

**Pass 0 Stage 4 — PARTIALLY DONE:**
- ✅ Ghost 0-byte DBs removed (`dashboard.db`, `malware_detection/malware.db`) — untracked
  deletion, no commit.
- ✅ `scan_jobs` → `malware_scan_jobs` rename (commit `9db6e7a`, pushed) — name collision
  resolved; malware-owned schema now real; nullable `actor` seam added; verified live
  (row persists, status endpoint 200, core `scan_jobs` untouched).
- ✅ Malware DB-accessor fix (commit `5fd3a9c`, pushed) — uses shared `get_db()`; dropped
  `__file__`-relative path; verified live (shared DB, WAL, busy_timeout, row_factory).
- ⏳ PENDING: collapse remaining duplicate `CREATE`s — `quarantines`, `hw_alerts` (each in
  two places). (`scan_jobs` member of that trio now resolved.)
- ⏳ PENDING: retire `hw_monitor`'s local-clamscan path (clamav-only duplicate) — sequenced
  AFTER the orchestration direction (ADR 0004) is specified.

**Scan/task orchestration — DIRECTION DECIDED (ADR 0004, Proposed):** scheduler module =
authoritative dispatcher; execution modules (malware = full-stack, hardware, future) do the
work; reporting module processes/delivers printable reports; `hw_monitor` → hardware-only.
Driven by the scan/task audit's 6 cross-cutting facts. 3 open hinge questions recorded in the
ADR (unified findings table?; how full-stack reaches the fleet?; where the 5 `scan_*` tables
migrate?). See `docs/architecture/0004-scan-task-orchestration.md`.

**VPN / DNS — UNRESOLVED (reframed):** NOT a fixed PIA-client bug. It is **intermittent** —
worked ~1hr with PIA on, then connectivity dropped, Code lost `api.anthropic.com`, re-login
failed fetching the auth key. A read-only watcher is **armed** at
`~/work/vpn-watcher/vpn-watch.sh` (OUTSIDE the repo, not committed) logging every 3s to disk
(routing / `ip rule` / source-IP / DNS / egress + v4/v6-split auth-path tests). **Next failure:
read the log at that timestamp.** Leads: PIA leaves a `blackhole default` in table
`piavpnOnlyrt` even when disconnected; `api.anthropic.com` resolves to IPv6 → outage may be
v6-routing-specific. Detail in `supplements/2026-06-26-002.md` §2.

**Pass 0 (earlier stages) — module consolidation COMPLETE:** all three drift modules read/write
the shared `alerts.db`, each migrated backup-first and verified live (Stage 2 copy → Stage 3
cutover). Old per-module `.db` files retained as frozen fallbacks until Stage 6.

| Module | Stage 2 | Stage 3 | Commit | Notes |
|---|---|---|---|---|
| ai_engine | ✅ | ✅ | `181c14c` | shared `ai_*` |
| tickets | ✅ | ✅ | `6f6b6c3` | shared `tickets` / `tickets_seq` / `tickets_settings`; verified live |
| community_queue | ✅ | ✅ | `290c2db` | shared `community_queue`; verified live |

**Concurrency prerequisite (ADR 0001 Stage-2 gate):** shared `alerts.db` is WAL + `busy_timeout`;
concurrent-write smoke test passed.

**Secrets:** externalized OUT of the repo to `~/work/nemesis-private/local-config.md` (chmod 600)
— referenced by location only, never committed.

**Backups:** Stage-0 rollback snapshot on independent external storage
(`nemesis-stage0-refresh-20260626-090254/`, all `integrity_check=ok`). Per-sub-task Stage 4
backups also on independent storage (`nemesis-stage4-scanjobs-*`, `nemesis-stage4-dbaccessor-*`).

## New decisions / principles this session (see supplement 2)
- **Licensing principle (flag for CLAUDE.md promotion):** SINGLE version; a key/license unlocks
  commercial features (multi-user, attribution, device limits) IN PLACE — not a separate fork.
  The key is what "wires the house" the multi-user-ready seams leave socketed.
- **Reporting module UX:** dashboard button, flashes on new report, PER-USER unread state
  (multi-user-ready from day one) → reports page → preview/print.
- **VPN self-diagnostic feature idea:** generalize the watcher to any VPN; AI plain-language
  diagnosis → gated fix suggestion OR auto-generated complete support ticket. Guardrail: config
  edits go through Teaching/Automated approval gates, NEVER silent auto-apply. Build AFTER the
  PIA root-cause fix.

## Stage 5 / 6 (later)
- **Stage 5** — single SQLite-safe shared-DB snapshot backup; make deploy/health DISCOVER
  services (picks up `vpn-dns-guard.service`); purge per-module-DB refs in `_backup_candidates()`
  / `install.sh` (`PUNCHLIST.md`).
- **Stage 6** — retire old module `.db` fallbacks after N verified days.
- **Parked quick wins** — `PIHOLE_IP` hardcoded-default fix (Rule 8) + hygiene sweep, settings
  status-fix, header de-dup, kernel-update check (all in `PUNCHLIST.md`).

## Pointers
- Methodology & rules: `CLAUDE.md`
- Architecture: `ARCHITECTURE.md`, `docs/architecture/` (ADR 0001 DB, 0002 DNS, 0003 resilience,
  **0004 scan/task orchestration — Proposed**)
- Operational reference: `docs/reference/operational-notes.md`
- Audits: `docs/audits/` — `malware-detection-state-audit.md`, **`scan-task-architecture-audit.md`**
- Parked ideas: `docs/roadmap/` — incl. new: `latent-bug-fleet-clamav-only.md`,
  `diagnostic-scan-scope.md`, `diagnostics-anthropic-status-banner.md`
- Small fixes: `PUNCHLIST.md`
- Session logs: `docs/handoff/supplements/` (latest: `2026-06-26-002.md`);
  worklog `docs/handoff/worklog/2026-06-26-001.md`
- VPN watcher (outside repo, not committed): `~/work/vpn-watcher/vpn-watch.sh`
