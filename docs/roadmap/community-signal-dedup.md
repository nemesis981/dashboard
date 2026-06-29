# Community Signal Deduplication

The community-backend data model for threat signals: one entry per unique
signal (not per report), with bounded aggregates. Lives downstream of the
[reporter identity layer](community-reporter-identity.md) and the three-pass
sanitization pipeline.

## One Entry Per Unique Signal (not one per report)

Deduplication key: SHA256(signal_type:signal_value)
UNIQUE constraint on signal_hash prevents duplicates

## On Duplicate Report

- times_seen += 1
- last_seen updated
- unique_reporters updated (if new reporter)
- recent_timestamps appended (capped at last 100)
- reporting_regions updated
- confidence_score recomputed

## Timestamp Storage (bounded, not unbounded)

- recent: last 100 individual timestamps
- hourly_counts: last 168 hours (7 days)
- daily_counts: last 90 days
- monthly_counts: last 24 months

Bounded growth regardless of report volume.

## Confidence Score (computed, not stored as fixed value)

Factors: volume (log scale), reporter diversity, geographic
distribution, review tier, recency decay.
Recomputed on each new report. Decays over time without
new sightings (threat-type-specific decay rate).

## Local vs Global times_seen

Local DB: raw context (IPs, devices, full detail — stays local)
Community DB: sanitized aggregates (counts, timestamps, regions)
Display combines both: "47 times on your network,
3,847 times globally by 234 Nemesis installs"

## Natural Signal Collection

Locally-detected signals (Suricata, ClamAV, canary)
use same deduplication model in local DB.
Separate decision: should this be submitted to community feed?
Local dedup is independent of community dedup.

## Database Size at Scale

Deduplication keeps DB lean (grows with unique threats, not reports)
100K unique signals × ~1KB = ~100MB uncompressed
Compressed download (150-200KB/10K entries) remains achievable
The database grows with the threat landscape, not with user count.

## Connections
- [community-reporter-identity.md](community-reporter-identity.md) — identity layer + three-pass
  sanitization that feeds this; "Data schema" in the pre-build lock list.
- [open-source-threat-feeds.md](open-source-threat-feeds.md) — external feeds normalize into this
  same signal schema.
- PUNCHLIST "COMMUNITY BACKEND — PRE-BUILD DESIGN REQUIREMENTS" — this is part of the Phase 2
  (submission pipeline) / data-schema design that must be locked before backend code.
