# Roadmap stub — LATENT BUG: automated/fleet scans are clamav-only

**Status:** parked (current-behavior defect captured — do NOT build the fix here;
resolved by the scan/task orchestration ADR, [0004](../architecture/0004-scan-task-orchestration.md)).

## What
Every **automated, scheduled, condition-triggered, or fleet** scan runs **ClamAV only**
— NOT the full Layer-A stack (ClamAV + YARA + entropy/PE heuristics). The full stack is
reachable **only** via the manual scan trigger on the local host. **Exact code paths and
executor names are kept in the private mirror per Rule 10** — this is a live, unfixed
coverage gap, and precision about exactly which entry points route through which engine
is attacker-relevant detail, not architectural direction.

## Why it matters
**Users believe they are full-scanning and are not.** A scheduled or fleet "scan" looks
like protection but silently skips YARA + heuristics — i.e. exactly the zero-day /
behavioral coverage that is the product's headline. This is a correctness/trust defect,
not just a missing feature: the UI implies depth the execution doesn't deliver, on both
the local host and the fleet.

## Reasoning / shape
- This is the concrete user-facing symptom of the scan/task architecture audit's
  findings — the general facts are already public in
  [ADR 0004](../architecture/0004-scan-task-orchestration.md)'s evidence base;
  executor-level implementation detail is kept private per Rule 10.
- The fix is architectural, not a patch: it depends on unifying the scan path so
  automation routes through the full-stack engine. That is ADR 0004's job (scheduler →
  full-stack execution module → reporting).
- Capture-only here so the defect is not forgotten while the ADR is designed; do NOT
  spot-fix individual executors (would entrench the divergence).
