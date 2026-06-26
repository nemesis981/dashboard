# HANDOFF — current state

> Current project state, last updated 2026-06-26. Overwritten at each nightly closeout
> (latest state wins). Durable history lives in `docs/handoff/supplements/` (append-only).

## Where things stand

**Pass 0 — restore the single shared `alerts.db`** (per ADR 0001). **Module consolidation is
COMPLETE** — all three drift modules now read/write the shared DB, each migrated backup-first
and verified live (Stage 2 copy → Stage 3 cutover). Old per-module `.db` files are retained
as frozen fallbacks (not deleted until Stage 6).

| Module | Stage 2 (copy) | Stage 3 (cutover) | Commit | Notes |
|---|---|---|---|---|
| ai_engine | ✅ done | ✅ done | `181c14c` | shared `ai_*` |
| tickets | ✅ done | ✅ done | `6f6b6c3` | shared `tickets` / `tickets_seq` / `tickets_settings`; verified live (write landed in shared, old `tickets.db` frozen) |
| community_queue | ✅ done | ✅ done | `290c2db` | shared `community_queue` (no renames); verified live |

**Concurrency prerequisite (ADR 0001 Stage-2 gate):** shared `alerts.db` is WAL +
`busy_timeout`; concurrent-write smoke test passed.

**Secrets:** externalized OUT of the repo to `~/work/nemesis-private/local-config.md`
(chmod 600) — referenced by location only, never committed (see `CLAUDE.md` conventions).

**Backups:** fresh Stage-0 rollback snapshot on independent external storage —
`nemesis-stage0-refresh-20260626-090254/` (alerts.db, tickets.db, ai_engine.db,
community_queue.db; all `integrity_check=ok`; SHA256SUMS). Original
`nemesis-stage0-backup-20260625-171223/` retained.

## Resume point → Pass 0 Stage 4 (cleanup)

1. **Stage 4** — collapse duplicate `CREATE`s (`quarantines`, `hw_alerts`, `scan_jobs` each
   created in two places); retire the ghost 0-byte DBs (`dashboard.db`,
   `malware_detection/malware.db`).
2. **Stage 5** — switch backup to a single SQLite-safe shared-DB snapshot; make deploy/health
   DISCOVER services (picks up `vpn-dns-guard.service`); purge the per-module-DB refs in
   `_backup_candidates()` / `install.sh` (see `PUNCHLIST.md`).
3. **Stage 6** — retire the old module `.db` fallbacks after N verified days.
4. **Single-user-assumptions audit** (read-only) — after migration, before the
   responsive-dashboard build. See `docs/roadmap/single-user-assumptions-audit.md`.
5. **Parked quick wins** — `PIHOLE_IP` hardcoded-default fix (Rule 8) + full hygiene sweep,
   settings status-fix (#1/#3), header de-dup, kernel-update check (all in `PUNCHLIST.md`).

## Pointers
- Methodology & rules: `CLAUDE.md`
- Architecture: `ARCHITECTURE.md`, `docs/architecture/` (ADR 0001 DB, 0002 DNS, 0003 resilience)
- Operational reference: `docs/reference/operational-notes.md`
- Parked ideas: `docs/roadmap/`
- Small fixes: `PUNCHLIST.md`
- Session logs: `docs/handoff/supplements/` (latest: `2026-06-26-001.md`)
