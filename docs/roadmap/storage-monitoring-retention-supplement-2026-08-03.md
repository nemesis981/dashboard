# Roadmap — Storage monitoring & retention: measured baseline, stub design, items 1 & 3

- **Status:** Items 1 (disk-space reporting) and 3 (backup-drive visibility) SHIPPED
  2026-08-03 — item 1 via `f9ad33f feat(hw-monitor): sample disk capacity into hw_metrics
  (storage/retention piece 1)` + `4ab95dc refactor(diagnostics): single source for the
  low-disk thresholds (piece 2a)` + `1fec8b7 feat(dashboard): surface disk capacity on
  the hardware card (piece 2b)`; item 3 via `58fe763 feat(backup): last-known free space
  at the backup destination (piece 3)`, new `backup_media_status` table. The per-table
  stub/tombstone design and measured baseline below remain design-only, not implemented —
  this doc's own scope was always items 1+3 plus that design work, per the title. Follow-up
  to [[data-retention-and-archival-policy]] and
  [[hw-anomaly-snapshots-top-processes-archival]] — fills three gaps identified in a
  Window 3 review of those two docs: the per-table stub/tombstone design (explicitly
  requested to be folded into the retention design, not left as an afterthought), the
  measured numbers the design was checked against, and items 1 and 3 above, both of which
  were underrepresented or absent from the parent doc. Header was stale until corrected
  2026-08-04 — see
  [roadmap-state-audit-2026-08-04](../audits/roadmap-state-audit-2026-08-04.md).

## Measured baseline (live DB, 2026-08-03)

All numbers below are from direct queries against the live `alerts.db`
(`/var/lib/nemesis/alerts.db`), read-only, no writes performed. This is the evidence base
[[data-retention-and-archival-policy]]'s design decisions were checked against.

| Table | Rows | Rows/day | Storage | MB/day | Projected/yr |
|---|---|---|---|---|---|
| `dm_operation_log` (+2 idx) | 285,418 | ~36,100 | 34.8 MB | 4.41 | 1.61 GB |
| `hw_anomaly_snapshots` | 28,118 | ~1,020 recent | 111.3 MB | 2.65–4.0 | 0.97–1.46 GB |
| `hw_metrics` | 12,820 | 298 | 12.2 MB | 0.28 | 104 MB |
| `login_events` | 71 | 2.0 | 0.02 MB | ~0.001 | 0.2 MB |
| `audit_log` | 133 | 3.7 | 0.016 MB | ~0.001 | 0.16 MB |
| `tickets` | 33 | 0.8 | 0.02 MB | ~0.001 | 0.19 MB |
| `scan_*` (6 tables combined) | 21 | <1 | <0.01 MB | ~0 | negligible |
| `malware_findings` | 0 (see gap below) | bursty | 0 MB | — | — |

Combined current rate: ~7.3–8.7 MB/day → 2.7–3.2 GB/year. Measurement window is 43 days
(2026-06-21 → 2026-08-03) for everything except `dm_operation_log`, which only spans 7.9
days because the Data Manager (ADR 0006) shipped 2026-07-25 — its rate is the
best-measured and least-extrapolated number in this table.

**Headline correction to the original scoping premise:** `hw_metrics` was flagged as
possibly the single biggest volume grower. It isn't — `dm_operation_log` and
`hw_anomaly_snapshots` together are **78% of the live 161MB database**; `hw_metrics` is
third, roughly 15x smaller than the leader. This matters because it redirects where any
implementation effort should go first.

`dm_operation_log` — ADR 0006's own write-audit table — is the fastest-growing thing in
the database, and its own indexes (`idx_dmlog_mod` at 12.9MB) cost more than the table
data itself in one case. Sharpest single data point:
`malware_detection|malware_canary_files|update` shows **52,610 logged updates against a
table that holds 4 rows of live state** — roughly 6,500 log rows/day describing a 4-row
table. This is the concrete evidence for the parent doc's "differentiate by actor type,
not age" design choice.

`hw_anomaly_snapshots` costs ~4KB/row because `top_processes` hits its 2000-byte cap on
every single row (avg length == max length == 2000, no row is ever smaller) — see
[[hw-anomaly-snapshots-top-processes-archival]] for the column-level detail.

**`malware_findings`'s 0-row baseline above should not be read as "this table never had
data."** There is an open, privately-tracked audit-trail question about this table (held
fully private per operator decision, 2026-08-03 — no detail here, generic or specific).
It is independent of whether this retention feature gets built and is not part of this
design.

**Freelist check:** `PRAGMA freelist_count` = 0. The live DB is fully compact — no VACUUM
opportunity exists today; any storage recovered by this design comes from the retention
policy itself, not from reclaiming existing slack space.

## Retention principle — no automatic permanent deletion (operator decision, 2026-08-03)

**If a user ever wants data permanently gone, that must be THEIR explicit action — never
Nemesis silently discarding it to save space.** The default posture favors increasing storage
usage over any risk of accidental data loss.

The line this draws:

- **Archival is fine, and automatic.** Moving data into an archive file and replacing the
  live copy with a reference destroys nothing — everything stays recoverable via
  `archive_ref`. This is what every piece of this design does.
- **Permanent destruction must be user-initiated.** Deleting archive files themselves,
  dropping rows outright, or replacing data with a summary it cannot be reconstructed from,
  must never happen on a schedule or as a side effect of a space-saving job.

**A derived summary is not a copy.** This is the subtle case, and it is what made the original
`hw_metrics` rollup plan non-compliant: min/max/avg *looks* like retention but cannot
reconstruct its inputs. If the original cannot be recovered from what remains, it was deleted,
whatever the mechanism is called.

**Ordering is the guarantee, not a nicety.** Every archival step must write the archive, verify
it independently readable and content-matched, and only then clear the live copy. Reverse that
order, or weaken the verification to "the file exists", and the same code becomes a delete. The
shipped `archive_old_top_processes()` treats this as a correctness requirement — it self-tests
its own verifier before trusting it, and three injected failure modes were confirmed to abort
with live data provably unchanged.

**This is a new policy the product does not yet meet in full.** Pre-existing code already
deletes permanently and automatically, none of it part of this build:
`modules/diagnostics/watcher.py:383-392` (row-count cap dropping oldest samples),
`modules/anomaly_detection/module.py:824-826` (`DELETE FROM anomaly_recurrence` past a cutoff),
and `modules/diagnostics/watcher.py:340-348` (`os.remove()` on rotated logs past
`log_retain_days`). `modules/community_queue/module.py:84` and
`nemesis_agent/reputation_cache.py:59` are unconfirmed and may be legitimate cache clears.
Reconciling these is tracked separately — deliberately NOT folded into this build.

## Per-table stub/tombstone design

Explicit per-table answer to "what stays live and searchable vs. what moves to cold
storage," folded into [[data-retention-and-archival-policy]]'s Tier A/B/C structure
rather than left as a general principle. Working rule: **leave a stub only where a human
would plausibly search for the record later.** Nobody searches for a CPU reading at a
specific timestamp; people search old tickets and old findings.

- **`tickets`** — richest stub. Stays live: `id`, `ticket_number`, `created_at`, `title`,
  `type`, `priority`, `status`, plus a new `archive_ref` column. Moves to cold storage:
  `body`, `resolution_notes`, `relevance_scores`, `ai_analysis_ref`, `hw_snapshot_ref`.
  This is the concrete use case that motivated the stub design: an operator searching
  "printer" still gets a hit on the subject line, sees the ticket number and date, and is
  told which archive file holds the full text.
- **`malware_findings`** — near-full stub. Stays live: `id`, `detected_at`, `device_id`,
  `threat_name`, `file_hash`, `severity`, `status`, `archive_ref`. Moves: `signals`,
  `ai_verdict`, `notes`, `file_path`. `file_hash` staying live is a functional
  requirement, not just a searchability nicety — it's the dedup/recurrence key; archiving
  it out would make a re-detected threat look novel to the detection logic.
- **`audit_log` / `login_events`** — stub is nearly the whole row (no bulk column to
  shed), and at 0.16–0.2 MB/year each, the recommendation is these are not archived on
  storage grounds at all — only under a deliberate compliance-driven rotation policy, if
  one is ever adopted. Matches [[data-retention-and-archival-policy]]'s Tier A "infinite,
  not capped" decision.
- **`hw_metrics`** — no stub, but **archive-then-summarize, never summarize-then-delete**
  (corrected 2026-08-03; see the retention principle below). A day of 288 raw samples is
  first written to a verified archive file, and only then replaced in the live table by a
  daily rollup row (min/max/avg per metric) carrying an `archive_ref`. Preserves long-range
  chart usefulness at ~1/288th the live storage while keeping every raw sample recoverable.
  - **Why the original wording was wrong.** It read "before deleting a day of 288 samples,
    write one daily rollup row" — but a rollup is a *derived summary, not a copy*. Min/max/avg
    cannot reconstruct the samples they came from, so that design permanently destroyed the
    raw data automatically, on a schedule, with no user action and nothing to recover from.
    That is precisely what the retention principle forbids.
  - The correction costs almost nothing: `hw_metrics` grows at ~0.28 MB/day, and the
    `top_processes` archival measured 41–43x gzip compression on comparable text, so retaining
    every raw sample indefinitely is cheap. This is the "favor storage over any risk of loss"
    tradeoff taken deliberately.
- **`hw_anomaly_snapshots`** — partial stub at the column level, not the row level: keep
  the full numeric anomaly row live (`sensor_key`, `captured_at`, `cpu_pct`, `ram_mb`,
  etc. — it's small and feeds baselines), archive only `top_processes`, replaced with an
  `archive_ref`. See [[hw-anomaly-snapshots-top-processes-archival]] — this is that item's
  design, restated here for the stub-pattern inventory.
- **`scan_*`** — stub on `scan_jobs` only (`scan_id`, `device_id`, `started_at`,
  `threats_found`, `archive_ref`); the other five `scan_*` tables cascade to archive with
  their parent job, no independent stub.
- **`dm_operation_log`** — no stub (nothing here is ever individually searched by a
  human); this table's problem is write volume, not aged-record lookup, which is why
  [[data-retention-and-archival-policy]] scopes it as a coalescing/sampling policy
  question rather than a stub/archive question.

`archive_ref` format is not yet decided — needs to resolve to both a file (which tar.gz)
and a location inside it (which record), since the parent doc's archive-format decision
is to reuse the existing tar.gz backup machinery (`dashboard.py:7427-7446`), which is
opaque to search. Open item for the build spec.

## Item 1 — disk-space reporting and low-disk warning

**What exists today:** `hw_monitor`'s sampler collects disk I/O throughput only
(`disk_read_mb`/`disk_write_mb`, deltas of `psutil.disk_io_counters()`,
`core_module/hw_monitor/hw_monitor.py:795-806`) — no capacity column exists in
`hw_metrics` (no free/used/total/percent). `dashboard.py:1873` shells `df -h /` and stores
the raw unparsed second line, rendered verbatim at `dashboard.py:9389` — no parsing, no
threshold, no history. A real threshold check does exist —
`diagnostics/disk_space.py`, warn at 80% / critical at 90% via `df` — but it's stateless,
on-demand, unpersisted, unalerted, wired only into the diagnostics UI, and its
`_SKIP_MOUNTS` (`diagnostics/disk_space.py:28`) explicitly excludes `/run/media/` —
meaning the one existing disk-full check deliberately skips the USB backup drive,
directly bearing on item 3 below.

**Proposed scope:**
- Add capacity columns (`disk_free_gb`, `disk_total_gb`, `disk_percent_used` or
  equivalent) to the existing 300s `hw_metrics` sample — the sampler already runs; at 288
  samples/day the added columns cost single-digit MB/year, negligible against the
  baseline above.
- Surface it on the existing hardware-monitor dashboard card next to RAM, rather than
  building a new card — see [[nemesis-overhead-meter]] for the sibling "make invisible
  resource use visible" pattern this would match.
- **Reuse `diagnostics/disk_space.py`'s existing 80%/90% thresholds rather than inventing
  new ones.** Two different disk-full thresholds in one product is a defect in itself, not
  a design choice to make fresh.
- Route escalation through the diagnostics watcher's existing DEGRADED-verdict path
  (`modules/diagnostics/watcher.py:293-302`) — already the nominated hook for this class
  of signal per [[nemesis-overhead-meter]] — rather than building a new alert/ticket path.
  This directly answers the original scoping question of "does it reuse existing
  alert/ticket machinery or need its own path": reuse, no new path needed.

## Item 3 — backup-drive visibility (USB)

**What exists today:** nothing. No code checks the USB backup drive's free space; no
"last known" cache of any kind exists anywhere in the codebase. It is a CLAUDE.md
operator procedure only (`Backup root: /run/media/<user>/storage/nemesis-state-backups/`,
mount-verified via `mountpoint -q` before every write). Live measurement 2026-08-03: the
drive is well under capacity (single-digit percent used), holding 50 backup sets
totaling 13GB.

**Design constraint — ADR 0018** (proposed, not yet built) specifies the backup medium is
*"mounted only for the brief window needed to write a snapshot, and unmounted the rest of
the time"* — a deliberate security property (an unmounted drive is unreachable to a
compromised host). This rules out a polling design outright.

**Proposed scope:** "last known" means free-space measured during the last successful
mount window, stored with its measurement timestamp, displayed with the age always
visible — e.g. "4.6TB free, as of 6 days ago" — never a bare number that reads as current.
The staleness *is* the signal: a last-known reading that's weeks old means no backup has
run recently, which is itself the finding worth surfacing. Where it fits: the existing
backup card in the dashboard (same surface as `api_backup_size`/`api_backup_create`,
`dashboard.py:7100-7449`) plus a CLI check for the case where the drive is unplugged and
the dashboard has no live path to it at all. No new dashboard card needed — this extends
the one that already exists for the tar.gz backup mechanism.

## Remote-agent disk-space monitoring — recommendation (restated from original scoping)

Server/appliance-only for v1, not fleet-wide. Three reasons: the failure modes are
unrelated (appliance disk-full breaks Nemesis itself; a user's laptop being full is not a
Nemesis failure); it's a scope expansion into endpoint management that deserves its own
decision rather than arriving as a side effect of appliance capacity work; and the volume
math is hostile — `hw_metrics` already has a `device_id` column implying per-device rows,
and at 288 samples/day/device, ten agents would multiply that table elevenfold into a
database that has no retention today. Build appliance-side retention first, prove the
policy works, then revisit agent-side reporting as its own future roadmap item with the
retention machinery already in place to absorb it. Matches
[[data-retention-and-archival-policy]]'s existing "out of scope" note on this point.
