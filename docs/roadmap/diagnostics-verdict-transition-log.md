# Roadmap — retain diagnostics verdict TRANSITIONS beyond the sample cap

- **Status:** STUB, parked. Captured 2026-08-03 from a concrete case where the missing data
  actively limited an investigation. Not designed, not scheduled.

## What

Keep a compact, append-only record of connectivity **verdict changes** — separate from, and
outliving, the `diagnostics_connectivity_samples` rows they are derived from.

Roughly: one row per transition (`from_verdict`, `to_verdict`, `note`, `ts`, and the probe
flags at the moment of change), written only when the verdict actually differs from the
previous sample. Nothing is written while a state persists, which is what makes it cheap.

## Why

`diagnostics_connectivity_samples` is capped at `watcher_samples_max` (default 2,880 rows,
~48h at 60s) by the row-count reaper in `modules/diagnostics/watcher.py`. The cap is correct
— that table is high-frequency telemetry and should not grow without bound. But it means the
**shape of any incident older than about two days is gone**, including when it started.

This is not hypothetical. Both findings filed 2026-08-03 hit the limit directly:

- `diagnostics-ipv6-keytest-false-degraded-2026-08-03.md` — the false-positive `DEGRADED`
  state ran for **at least** 60 hours, but its true start had already aged out. "At least" is
  the strongest claim the data supports, and that is weaker than it needed to be.
- `dns-resolution-outage-23h-2026-08-01.md` — a real 23-hour DNS outage. Its boundaries were
  recoverable only because the investigation happened within the retention window. A day
  later and the onset (the ~50 `UPSTREAM_FAIL` samples that preceded the collapse — the most
  diagnostically interesting part) would have been unrecoverable.

A transition log would have preserved both incidents in full, permanently, for a handful of
rows each.

## Why it is cheap

Transitions are rare relative to samples. Across the current retained window there are only a
handful of distinct verdict changes against 2,880 samples. At that ratio the table grows by a
few rows per day even during unstable periods, and by nothing at all while healthy — which is
most of the time.

It also composes with the retention principle already adopted 2026-08-03
(`data-retention-and-archival-policy.md`): this is *derived* data that survives its source, so
it is a genuine exception worth stating explicitly rather than a violation. The samples still
age out on their existing cap; the transitions are a summary that is not reconstructible from
what remains, and so is retained rather than re-derivable.

## Open questions (not decided)

- Where it lives: a `diagnostics_*` prefixed table (module-owned, ADR 0001) is the obvious
  home, but a flat append-only file alongside the connectivity log is also viable and avoids
  DB growth entirely.
- Whether it should be retained forever or on a much longer cap (a year of transitions is
  still small). Forever is defensible given the volume.
- Whether the dashboard should surface it as an incident timeline, or whether it exists purely
  as forensic material read at investigation time. The former is more useful and more work.
- Whether a sustained non-`ALL_OK` state should additionally raise an alert or ticket. Related
  but separable — see the DNS finding, where 23 hours passed unnoticed. That is arguably the
  more valuable half of the idea and should not be bundled in by default.
