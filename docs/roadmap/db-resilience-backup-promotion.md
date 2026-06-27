# Roadmap stub — DB resilience via backup-promotion

**Status:** parked (what + why; do NOT build yet). Extends ADR
[0003](../architecture/0003-database-resilience-and-recovery.md). The backup it produces is
also the data layer for [safe-mode diagnostics](diagnostics-standalone-runner.md).

## What
Automated, frequent, **integrity-verified flat-file backup rotation** → on **CONFIRMED**
main-DB failure, **PROMOTE** the most recent verified backup to live DB (don't merge back into
the corrupted original — set the original aside for forensics). System + diagnostics come back
online on the promoted DB, **honest about the point-in-time gap** (writes since the last backup
are lost — tune cadence to make the gap acceptable).

## Why
A single live DB is a single point of failure for the *whole* product, including the tools that
would diagnose its failure. Frequent verified backups plus an automatic promote-on-failure path
turns "DB corrupted → everything down, blind" into "DB corrupted → fail over to last good,
keep running, diagnose from the same backup." The gap is the price; cadence is the dial.

## Key design choices
- **PROMOTE not MERGE** — the promoted backup *becomes* the new main. No attempt to reconcile
  with the corrupted original (merge-hell avoided).
- **VERIFY not TRUST** — backups `integrity_check`'d **before rotation in** and **before
  promotion**. A backup is only a backup once verified restorable.
- **CONFIRM not FLINCH** — failover triggers on **persistent failure + failed integrity
  check**, not a transient lock. Distinguish a momentary `database is locked` from real
  corruption before promoting.
- **ROTATE not SINGLE** — keep **several verified generations**, so if the most recent backup
  is *also* corrupt there's depth to fall back through.

## Reasoning / shape
- The backup is **doubly valuable**: disaster-recovery path **and** the
  [safe-mode](diagnostics-standalone-runner.md) diagnostic context source — so invest in
  cadence and verification accordingly.
- Promotion is automatic on confirmed failure; **mounting a backup read-only for diagnostics
  (safe mode) is NOT promotion** — promotion to live is the heavier, point-of-no-return step.
- Forensics: the corrupted original is preserved, not overwritten, so the failure can be
  studied.
- Capture the strategy now; build alongside the ADR 0003 backup rework, not before.
