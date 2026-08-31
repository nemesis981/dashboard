# Roadmap — Data retention and archival policy

- **Status:** PARTIAL, and item 1 is now LIVE. The `dm_operation_log`
  archive-then-coalesce mechanism shipped in `3066205`; its FIRST production run and a
  daily timer landed `14132c4` (2026-08-31). That run archived 1,290,742 automated-writer
  rows into 14,648 summary rows (table 1.68M → 405K) with the 350 human-actor rows
  hash-verified untouched — closing the measured unbounded-growth problem this item
  exists for. Rows with a non-NULL actor are never touched/coalesced; archive-then-modify
  ordering verified.
  - **Item 2 (tar.gz-backup reuse) will NOT be built — deliberate divergence, not a gap
    (operator decision 2026-08-31).** The design's premise was "reuse `api_backup_create`'s
    tar.gz path rather than a new export mechanism". In practice the coalescer was built
    with its OWN archive format — self-verifying gzipped JSONL with a manifest and a
    sha256 over the compressed bytes (`write_archive_manifested` / `verify_archive` in
    `data_manager.py`). That format works, is integrity-checked, and per-row-recoverable.
    Rebuilding it to route through the tar.gz backup path would be real effort for no
    functional benefit, so the divergence stands as the accepted design. The "reuse, not
    rebuild" reasoning below is kept for history but is superseded on this point.
  - **Items 3 (Tier A infinite retention) and 4 (server disk-space monitor) remain
    unbuilt** — logged as open scope, not urgent, not blocking. Note on item 3: Tier A
    tables (`audit_log`, `login_events`, `tickets`, `malware_findings`) are already
    effectively infinite by ABSENCE of any retention policy — the work there is a guard so
    a future reaper does not accidentally cap them, not a feature to add now.
  Header found stale by `roadmap-state-audit-2026-08-31.md` — this doc's tally lineage
  had it right since the 2026-08-06 baseline, but this header itself was never corrected.
  Corrected here. Candidate to graduate to a numbered ADR once the remaining scope is
  built and pressure-tested against real code — see
  [0006-data-manager](../architecture/0006-data-manager.md) for the related, already-shipped
  decision this extends.
- **Original design approval, 2026-08-03 (operator).**

## What

A differentiated retention/archival policy for the tables that grow unbounded under
normal operation, built on top of the existing Data Manager (ADR 0006) rather than as a
parallel mechanism:

1. **`dm_operation_log` gets a real policy change, not just a retention cap** —
   coalescing/sampling for automated writers, full fidelity retained for human actors.
2. **Archive format reuses the existing tar.gz backup machinery** (`api_backup_create`,
   `dashboard.py:14887-14947` — `tarfile.open(archive_path, "w:gz")`), not a new export
   mechanism.
3. **Tier A tables get effectively infinite retention**: `audit_log`, `login_events`,
   `tickets`, `malware_findings`. Cost is negligible at these tables' row sizes and
   growth rates; there's no reason to cut them.
4. **Disk-space monitoring ships server-only for now.** A remote-agent version is
   deferred as its own future roadmap item, to be picked up once retention exists to
   absorb the added volume that monitoring a fleet of agents would generate.

## Why

`dm_operation_log` (ADR 0006's operation-logging table, `alert_manager/data_manager.py:45`)
logs every mediated write across all 10 DB-using modules (measured live 2026-08-03:
`ai_engine`, `anomaly_detection`, `community_queue`, `dashboard`, `diagnostics`,
`hw_monitor`, `malware_detection`, `nemesis_fwd`, `tickets`, `watchdog`). Automated
writers (scheduled scans, heartbeats, background pollers) dominate its write volume but
each individual row carries low marginal value once the pattern is established;
human-actor writes are rarer but each one matters for accountability (this is exactly the
actor-attribution seam ADR 0006 already stamps on every write — see CLAUDE.md's Data
Manager section, "actor mechanism is live but currently unwired"). A flat retention cap
would either truncate human-actor history too aggressively or let automated-writer volume
balloon unconstrained — a real policy needs to treat the two differently, not average
across them. Measured live 2026-08-03: `malware_canary_files` alone generated 52,610
logged updates against a table that holds 4 actual rows of state — the clearest single
example of why per-row fidelity on automated writers isn't earning its storage cost. See
[[storage-monitoring-retention-supplement-2026-08-03]] for the full measured baseline
(table sizes, growth rates) this design was checked against.

Building a new export/archive mechanism when the tar.gz backup path
(`api_backup_create`) already does integrity-checked, permission-correct
(`os.chmod(archive_path, 0o600)`) archival to an operator-chosen destination would be
pure duplication — same reasoning as ADR 0006 itself (single mediating layer, not
parallel paths per module).

Tier A tables are the ones an operator or the product itself relies on for
accountability and detection history — cutting their retention to save disk space that
isn't actually under pressure would trade real value for a savings that doesn't matter
at these volumes.

Disk-space monitoring needs real single-machine usage data (from this retention policy
actually running) before it's worth extending to a whole agent fleet — building the
remote-agent version first would mean guessing at the volume/cadence it needs to handle
instead of measuring it.

## Key design choices

- **COALESCE/SAMPLE, not a flat cap, for `dm_operation_log`'s automated-writer rows** —
  the policy differentiates by actor type, not by age or count alone. Human-actor rows
  are never coalesced or sampled, regardless of age.
- **REUSE, not REBUILD, for archive format** — the tar.gz backup machinery
  (`dashboard.py:14947`) is the one archival mechanism; this feature extends its
  candidate-file set (`_backup_candidates()`, `dashboard.py:14435`) rather than adding a
  second path.
- **INFINITE, not CAPPED, for Tier A** (`audit_log`, `login_events`, `tickets`,
  `malware_findings`) — explicitly exempted from whatever cap/coalesce policy the rest of
  this design applies elsewhere.
- **SERVER-ONLY, not FLEET-WIDE, for disk-space monitoring** — v1 scope is the Nemesis
  host itself. Remote-agent disk-space monitoring is out of scope here; captured as its
  own future roadmap item once this retention design is live and has absorbed real
  volume.

## Explicitly out of scope for this item

- **`hw_anomaly_snapshots.top_processes` archival** — split out as its own small,
  independent, immediately-buildable item: see
  [[hw-anomaly-snapshots-top-processes-archival]]. Best standalone value in the whole
  scope discussed; doesn't need to wait on the `dm_operation_log` policy design above.
- **A `malware_findings` audit-trail question** — a separate investigation, independent
  of whether this retention feature gets built at all. Not folded into this design.
  Held privately per Rule 10; not tracked in this public repo.
- **Remote-agent disk-space monitoring** — deferred, see above.

## Reasoning / shape (to flesh out when this graduates to a build spec)

- Exact coalescing/sampling algorithm for `dm_operation_log` automated-writer rows (time
  bucketing? count-based reservoir sampling? last-N-per-actor-per-day?) — not yet
  decided, this doc only approves the *shape* (differentiated by actor type), not the
  mechanism.
- Which fields survive coalescing vs. which are safe to drop/aggregate.
- Where the archive's cadence/trigger lives — tied to the existing `api_backup_schedule`
  cron-driven path (`dashboard.py:14964`) or a separate trigger.
- Server-side disk-space monitoring: what threshold triggers archival vs. a plain
  operator warning; where it surfaces (existing hardware-monitor dashboard card is the
  natural fit — see [[nemesis-overhead-meter]] for the sibling "make invisible resource
  use visible" pattern already captured).
