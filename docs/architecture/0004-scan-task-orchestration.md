# ADR 0004 — Scan & Task Orchestration

- **Status:** Proposed (direction decided; design NOT yet specified — no code changed)
- **Date:** 2026-06-26
- **Affects:** scan triggering/dispatch, the malware module, hw_monitor, reporting,
  the agent fleet, the `scan_*` / `malware_*` tables
- **Depends on:** [0001-database-and-module-architecture](0001-database-and-module-architecture.md)
  (single shared DB + module prefix ownership) — built AFTER Pass 0 lands.
- **Related:** [0003-database-resilience-and-recovery](0003-database-resilience-and-recovery.md);
  evidence base = `docs/audits/scan-task-architecture-audit.md`

> Paths/IPs sanitized for the public repo. This is a STUB: it captures the decided
> direction and the open questions; it does not design the solution.

---

## North-star / design driver

The product thesis: **affordable self-hosted zero-day / behavioral detection plus
whole-network security — enterprise capability without enterprise pricing.** The
architecture must enable **automated, fleet-wide, FULL-STACK detection**, because that
IS the product. Today full-stack detection exists but is reachable only by a single
manual button on the local host (see evidence #2); that gap is the thing this ADR
must close.

## Context / evidence base

From the scan/task architecture audit (`docs/audits/scan-task-architecture-audit.md`),
six verified cross-cutting facts:

1. **No single scan path** — three local-host scanners, two engine sets, two table
   families.
2. **YARA + heuristics reachable only via one manual button** (`POST /api/malware/scan`).
3. **All automation is clamav-only** — every fleet/condition/scheduled path runs
   ClamAV alone, never YARA/heuristics, never `malware_findings`.
4. **Scheduled scans are DEAD** — `scan_schedules` is write-only; no timer/worker
   drains the queue; dispatch is purely event-driven on agent check-in.
5. **Dispatch is welded into the hw_monitor `/hw_data` handler** — scan triggering +
   dispatch interleaved with hardware ingest + device-state management in one HTTP
   handler in the hw_monitor process.
6. **All five `scan_*` tables are core/unprefixed**; **remote HW monitoring is BUILT
   but remote full-stack scanning is NOT** (agent is clamav-only).

## Decision direction (decided)

A three-role separation, replacing today's hw_monitor-welded dispatch:

- **Scheduler module** — the **authoritative dispatcher** for all scan/task dispatch:
  decides *what* runs, *when*, and against *which target*. Owns the timer/queue that is
  missing today (fact #3/#4). Single place that initiates work.
- **Execution modules** — do the work: **malware = the full-stack engine**
  (ClamAV + YARA + heuristics), hardware, and future engines. They execute; they do
  not schedule.
- **Reporting module** — processes results and delivers **printable reports viewable
  in the dashboard**. Separate from both scheduling and execution.
- **hw_monitor reduced to hardware-only** — scan responsibilities move out of its
  `/hw_data` handler (fact #5), leaving it a pure hardware-telemetry ingester.

## Open hinge questions (for the full ADR to resolve — NOT answered here)

a. **One unified findings table vs two** — reconcile core `scan_jobs`/`scan_threats`
   (clamav-only paths) with `malware_findings` (full-stack), or keep two.
b. **How full-stack reaches the fleet** — ship engine code (YARA rules + pefile/entropy)
   to endpoints, vs. ship suspect files back to the server for central scanning.
c. **Where the five `scan_*` tables migrate** — scheduler-owned `scan_*` prefix, vs.
   fold into `malware_*`, vs. another owner — under ADR 0001 prefix rules.

## Status / next

Proposed. Build only after Pass 0 Stage 4 cleanup completes. Next step is the full
ADR: answer (a)/(b)/(c), specify the module contracts and the migration of the
`scan_*` tables, and the cutover from the hw_monitor-welded dispatch.
