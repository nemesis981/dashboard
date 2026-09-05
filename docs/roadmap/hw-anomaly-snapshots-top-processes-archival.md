# Roadmap — `hw_anomaly_snapshots.top_processes` archival

- **Status:** **SHIPPED AND NOW ENFORCED (this appliance), 2026-09-05** — but see the
  installer caveat below before reading that as "shipped to users". The mechanism shipped
  2026-08-03 (`97175ba`) and was always correct; it simply had **no schedule**.
  `archive_old_top_processes()` (`core_module/hw_monitor/hw_monitor.py:1492`) had ZERO
  callers — no timer, no unit, no script — and ran exactly once, by hand, then not again
  for 33 days. Corrected from an unqualified SHIPPED, which described the build rather
  than the policy.
  **What the gap cost, measured 2026-09-05 before the fix:** 31,975 rows / 64.0 MB past
  this item's own 14-day `TOP_PROC_ARCHIVE_DAYS` window, oldest blob 2026-07-20 — 47 days,
  3.4× the window — accruing ~1.7 MB/day.
  **Closed by `e54df43`**, which ships the unit + timer AND a window-liveness check
  (`top_processes_retention_status()` + `test_retention_window.py`, 17 checks) that asserts
  the window holds independently of how archival works — so a timer later disabled or
  masked fails loudly instead of silently. First scheduled run 2026-09-05 16:53:21:
  31,975 rows / 63,950,000 bytes archived, window went 64.0 MB → **0**, and **zero rows
  were deleted** (62,373 → 62,385 total; refs 18,010 → 49,985, exactly +31,975). Archival
  is a MOVE, and that held under a real 64 MB run.
  **⚠ CAVEAT — `install.sh` deploys no timers at all**, so this is enforced HERE and on no
  other installation. Tracked as the primary open item in
  [[data-retention-enforcement-and-tier-a-scope-2026-09-05]] §6.1, alongside the same gap
  affecting `nemesis-oplog-coalesce`, `nemesis-cert-renew` and `nemesis-fw-guard-boot`.
  **On the original numbers:** 18,010 rows archived and the verified round-trip are real
  and still stand. "34.4MB→837KB" is a *column payload* measurement, not a reduction in
  database file size — the freed space stays with the table as intra-page slack, measured
  at 38% page utilisation before the 2026-09-05 run and **14% after** it, with the file
  itself unchanged at ~610 MB. Only `VACUUM` returns that ~221 MB. See §5 of the audit.
  Header was ALSO stale once before, until corrected 2026-08-04 — see
  [roadmap-state-audit-2026-08-04](../audits/roadmap-state-audit-2026-08-04.md). That
  correction upgraded a stale PARKED to SHIPPED; the 2026-09-05 pass recorded that SHIPPED
  was itself too strong.

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
