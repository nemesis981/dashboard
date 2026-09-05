# Roadmap — `hw_anomaly_snapshots.top_processes` archival

- **Status:** ⛔ **CODE SHIPPED, POLICY NOT ENFORCED** — corrected 2026-09-05, was an
  unqualified SHIPPED. The mechanism shipped 2026-08-03 (`97175ba feat(hw-monitor):
  archive aged top_processes blobs out of hw_anomaly_snapshots (piece 4)`) and is correct.
  **It has never been scheduled.** `archive_old_top_processes()`
  (`core_module/hw_monitor/hw_monitor.py:1492`) has ZERO callers — no timer, no unit, no
  script; the only references in the tree are its own `def` and a comment. It ran ONCE, by
  hand, on 2026-08-03, and not since.
  **Measured 2026-09-05:** 31,975 rows / 64.0 MB sit past this item's own declared 14-day
  window (`TOP_PROC_ARCHIVE_DAYS`), the oldest live blob dating to 2026-07-20 — 47 days,
  3.4× the window — accruing ~1.7 MB/day. The table is back to 256.0 MB, 42.0% of the
  database. Full audit, the missing-schedule fix scope, and the generalizable
  "scheduled or it doesn't exist" rule:
  [[data-retention-enforcement-and-tier-a-scope-2026-09-05]].
  **On the original numbers:** 18,010 rows archived and the verified round-trip are real
  and still stand. "34.4MB→837KB" is a *column payload* measurement, not a reduction in
  database file size — the freed space stayed with the table as intra-page slack (38% page
  utilisation measured 2026-09-05) and only `VACUUM` returns it to the filesystem. See §5
  of the audit above.
  Header was ALSO stale once before, until corrected 2026-08-04 — see
  [roadmap-state-audit-2026-08-04](../audits/roadmap-state-audit-2026-08-04.md). That
  correction upgraded a stale PARKED to SHIPPED; this one records that SHIPPED was itself
  too strong, because it described the build rather than the policy.

## What

Archive (not delete) the `top_processes` column out of `hw_anomaly_snapshots` rows once
they age past whatever cutoff the retention design settles on, using the same tar.gz
backup machinery the parent doc reuses (`dashboard.py:7427-7446`) — not a bespoke export
path for this one column.

## Why

Measured directly against the live table (2026-08-03, 28,118 rows): `top_processes` is a
hard-capped TEXT column that every row fills to exactly 2,000 bytes (avg length == max
length == 2000 — no row is ever smaller). That one column accounts for 53.6MB of the
table's 111.3MB total — roughly 48% of it — making it the single dominant contributor to
this table's storage by direct measurement, not inference. Full baseline:
[[storage-monitoring-retention-supplement-2026-08-03]].

This lines up with what the UI code already treats as true: the dashboard's own
list-view code strips the column out before rendering because it's "too large" —
`dashboard.py:6954-6956`:
```python
# Strip top_processes from list view (too large); keep for detail popup
...
snap.pop("top_processes", None)
```
The column only gets read back in the single-row detail popup
(`dashboard.py:7036-7051`). Older snapshots' `top_processes` blobs have low ongoing value
once their moment has passed — exactly the shape that benefits from archival rather than
either keeping everything live forever or deleting the diagnostic detail outright.

Because it's a single well-understood column on a single table, with the target archive
mechanism already decided (reuse, not rebuild — see the parent doc), this doesn't need
to wait on the harder `dm_operation_log` coalescing/sampling design to ship.

## Reasoning / shape (to flesh out when this graduates to a build spec)

- Cutoff age/count before a row's `top_processes` is eligible for archival — independent
  decision from whatever cutoff `dm_operation_log`'s policy uses; no reason the two need
  to match.
- Archived rows keep every other `hw_anomaly_snapshots` column live (sensor_key,
  captured_at, cpu_pct, ram_mb, etc. — see `core_module/hw_monitor/hw_monitor.py:175-197`
  for the full schema); only `top_processes` itself moves to the archive, likely replaced
  with a NULL or a pointer to the archive file/offset.
- Whether the detail-popup route (`dashboard.py:7036`) needs a fallback path to read an
  archived value, or whether archived rows simply show "no longer available" in the
  popup — worth deciding explicitly rather than defaulting either way.
