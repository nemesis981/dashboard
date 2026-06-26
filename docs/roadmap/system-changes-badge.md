# Roadmap stub — System Changes badge

**Status:** parked (build as a module after Pass-0 migration completes).

## What
A watcher that snapshots a curated set of security/networking component versions on load
— kernel, Pi-hole, Suricata, ClamAV, key dependencies, distro release — diffs them
against the last snapshot, and records changes to durable `syschange_*` tables (full
history, not just "latest"). Surface as:
- a **flashing badge** when there are unviewed changes → click for the detail view;
- a permanent **"view changes"** link for the full history.

## Why
An **invisible kernel update** caused day-one debugging pain (suspected cause of early
VPN/DNS headaches): the environment changed underneath us with no visible signal. Making
component changes visible — and durably logged — turns a silent variable into an
observable one, directly supporting the "audit first / one variable at a time" discipline.

## Reasoning / shape
- Build as a standard module (`syschange_*` prefix, owns its tables in shared `alerts.db`).
- Snapshot-on-load + diff; persist every observed change with a timestamp.
- Badge derives from **real state** (unviewed-change count), not a manual flag.
- Curate the watched set deliberately (security/networking-relevant components) to keep
  signal high.
