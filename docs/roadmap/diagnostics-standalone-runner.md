# Roadmap stub — diagnostics: nemesis-diag standalone runner (+ safe mode)

**Status:** parked (what + why; do NOT build yet). Core of the diagnostics subsystem's
"works when everything else is down" guarantee. Pairs with
[connectivity watcher](diagnostics-connectivity-watcher-tool.md),
[tool-aware loop](diagnostics-ai-tool-aware-loop.md),
[reassurance + routing](diagnostics-ai-reassurance-escalation-routing.md),
[classification framework](diagnostics-classification.md), and
[DB resilience](db-resilience-backup-promotion.md). Backed by ADR
[0003](../architecture/0003-database-resilience-and-recovery.md).

## What
A **CLI diagnostic tool that runs independently of the dashboard** — no Flask, no live-DB
dependency. **Tiered by what's available** at run time:

- **ALWAYS (deterministic core):** local tools run regardless of dashboard/DB/network state;
  results written to a **flat file + terminal**. Runnable over **SSH when the dashboard is
  down**.
- **WHEN NETWORK AVAILABLE (AI layer):** calls the Anthropic API with context for
  interpretation. The watcher's **"is-it-me-or-them"** check **gates** this — if DNS/egress is
  broken, the AI layer **skips gracefully and says so** rather than hanging.
- **WHEN DASHBOARD HEALTHY (rich layer):** full UI, tiered report rendering, interactive
  session.

Invocation: `nemesis-diag` (normal) · `nemesis-diag --safe-mode` (see Safe Mode below).

## Why
**The tool that diagnoses failures must not depend on the thing that's failing.** Dashboard
down = exactly when you need diagnostics = exactly when on-demand dashboard tools are
unavailable. A diagnostics path that only lives inside Flask is useless in the failure modes
that matter most (TRIP-relevant for the unreachable camper deployment). The deterministic core
degrades to "still runs over SSH and writes a file" no matter what else is broken.

## Safe Mode — `nemesis-diag --safe-mode`
Boots against the **most recent verified backup DB as a READ-ONLY working copy** — **NOT
promoted to live** (promotion is a separate, human-confirmed disaster-recovery decision; see
[DB resilience](db-resilience-backup-promotion.md)). The backup DB is the safe-mode **data
layer**, so AI-aided diagnosis is available *even when the main DB is the failure*. Flow:

1. Detect main DB unavailable.
2. Locate + verify the most recent backup (`integrity_check=ok`).
3. Mount it **read-only** as the diagnostic context source (no writes).
4. Run deterministic tools (local, no writes).
5. If network available → call AI with **backup context + tool results**; else → deterministic
   report only.
6. Write a structured report to a flat file.
7. Display in terminal **with disclosure**: *"running in safe mode from backup dated
   [timestamp] — [N] minutes of data may be missing."*

**Backup cadence matters doubly:** it is both the recovery path *and* the diagnostic context
source. Invest accordingly.

## Reasoning / shape
- The deterministic core is the non-negotiable floor; AI and rich UI are additive tiers that
  light up when their preconditions hold.
- Gate the AI tier on the watcher's connectivity fact (don't guess; measure) — same
  division-of-labor as the rest of the subsystem.
- Tools the runner invokes come from the same catalog the
  [tool-aware loop](diagnostics-ai-tool-aware-loop.md) uses.
- Capture the architecture now; defer the build (CLI entry point, tier detection, safe-mode
  backup mount) until scheduled.
