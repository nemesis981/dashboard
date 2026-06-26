# HANDOFF — current state

> **This file is overwritten nightly** with the live-handoff doc the maintainer keeps.
> The content below is a SEED reflecting the known current state at creation time
> (2026-06-26); replace it with the canonical maintained handoff.

## Where things stand

**Active effort: Pass 0 — restore the single shared `alerts.db`** (per ADR 0001).
Modules that carried their own SQLite files are being consolidated into the shared DB,
one module at a time, backup-first and verified at each stage.

| Module | Stage 2 (copy) | Stage 3 (cutover) | Notes |
|---|---|---|---|
| ai_engine | ✅ done | ✅ done (committed) | reads/writes shared `ai_*` |
| tickets | ✅ done | ✅ done (committed `6f6b6c3`) | shared `tickets` / `tickets_seq` / `tickets_settings`; old `tickets.db` retained as fallback |
| community_queue | ⬜ not started | ⬜ not started | next to migrate; currently 2 rows |

**Concurrency prerequisite (ADR 0001 Stage-2 gate):** shared `alerts.db` is WAL +
`busy_timeout`; concurrent-write smoke test passed.

**Backups:** fresh Stage-0 rollback snapshot on independent external storage —
`nemesis-stage0-refresh-20260626-090254/` (alerts.db, tickets.db, ai_engine.db,
community_queue.db; all `integrity_check=ok`; SHA256SUMS). Original
`nemesis-stage0-backup-20260625-171223/` retained.

## Next up
1. **community_queue** — Stage 2 (copy → `community_*`) then Stage 3 (cutover).
2. **Cleanup Stages 4–6** — de-duplicate table creators (`quarantines`, `hw_alerts`,
   `scan_jobs`); retire ghost 0-byte DBs; switch backup to a single SQLite-safe shared-DB
   snapshot + auto-discovered services; retire old module `.db` files after N verified days.
3. **Single-user-assumptions audit** (queued, read-only) — see
   `docs/roadmap/single-user-assumptions-audit.md`.

## Pointers
- Methodology & rules: `CLAUDE.md`
- Architecture: `ARCHITECTURE.md`, `docs/architecture/` (ADR 0001 DB, 0002 DNS, 0003 resilience)
- Parked ideas: `docs/roadmap/`
- Small fixes: `PUNCHLIST.md`
- Session logs: `docs/handoff/supplements/`
