# Roadmap — `hw_anomaly_snapshots.top_processes` archival

- **Status:** Design approved 2026-08-03 (operator) — split out from
  [[data-retention-and-archival-policy]] as its own small, independent,
  immediately-buildable item. Called out by the operator as the best standalone value in
  that whole scope. Implementation not yet started.

## What

Archive (not delete) the `top_processes` column out of `hw_anomaly_snapshots` rows once
they age past whatever cutoff the retention design settles on, using the same tar.gz
backup machinery the parent doc reuses (`dashboard.py:7427-7446`) — not a bespoke export
path for this one column.

## Why

`top_processes` is already known to be the outsized column on this table: the dashboard's
own list-view code strips it out before rendering because it's "too large" —
`dashboard.py:6954-6956`:
```python
# Strip top_processes from list view (too large); keep for detail popup
...
snap.pop("top_processes", None)
```
The column only gets read back in the single-row detail popup
(`dashboard.py:7036-7051`). That's a strong, already-encoded-in-the-code signal that this
one column is the dominant contributor to this table's storage growth, and that older
snapshots' `top_processes` blobs have low ongoing value once their moment has passed —
exactly the shape that benefits from archival rather than either keeping everything live
forever or deleting the diagnostic detail outright.

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
