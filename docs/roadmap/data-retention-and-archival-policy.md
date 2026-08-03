# Roadmap — Data retention and archival policy

- **Status:** Design approved 2026-08-03 (operator). Implementation not yet started.
  Candidate to graduate to a numbered ADR once building starts and the design gets
  pressure-tested against real code — see [0006-data-manager](../architecture/0006-data-manager.md)
  for the related, already-shipped decision this extends.

## What

A differentiated retention/archival policy for the tables that grow unbounded under
normal operation, built on top of the existing Data Manager (ADR 0006) rather than as a
parallel mechanism:

1. **`dm_operation_log` gets a real policy change, not just a retention cap** —
   coalescing/sampling for automated writers, full fidelity retained for human actors.
2. **Archive format reuses the existing tar.gz backup machinery** (`api_backup_create`,
   `dashboard.py:7427-7446` — `tarfile.open(archive_path, "w:gz")`), not a new export
   mechanism.
3. **Tier A tables get effectively infinite retention**: `audit_log`, `login_events`,
   `tickets`, `malware_findings`. Cost is negligible at these tables' row sizes and
   growth rates; there's no reason to cut them.
4. **Disk-space monitoring ships server-only for now.** A remote-agent version is
   deferred as its own future roadmap item, to be picked up once retention exists to
   absorb the added volume that monitoring a fleet of agents would generate.

## Why

`dm_operation_log` (ADR 0006's operation-logging table, `alert_manager/data_manager.py:45`)
logs every mediated write across all 7 DB-using modules. Automated writers (scheduled
scans, heartbeats, background pollers) dominate its write volume but each individual row
carries low marginal value once the pattern is established; human-actor writes are rarer
but each one matters for accountability (this is exactly the actor-attribution seam ADR
0006 already stamps on every write — see CLAUDE.md's Data Manager section, "actor
mechanism is live but currently unwired"). A flat retention cap would either truncate
human-actor history too aggressively or let automated-writer volume balloon
unconstrained — a real policy needs to treat the two differently, not average across
them.

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
  (`dashboard.py:7427-7446`) is the one archival mechanism; this feature extends its
  candidate-file set (`_backup_candidates()`, `dashboard.py:7100`) rather than adding a
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
  cron-driven path (`dashboard.py:7453`) or a separate trigger.
- Server-side disk-space monitoring: what threshold triggers archival vs. a plain
  operator warning; where it surfaces (existing hardware-monitor dashboard card is the
  natural fit — see [[nemesis-overhead-meter]] for the sibling "make invisible resource
  use visible" pattern already captured).
