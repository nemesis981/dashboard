# Roadmap stub — LATENT BUG: automated/fleet scans are clamav-only

**Status:** parked (current-behavior defect captured — do NOT build the fix here;
resolved by the scan/task orchestration ADR, [0004](../architecture/0004-scan-task-orchestration.md)).

## What
Every **automated, scheduled, condition-triggered, or fleet** scan runs **ClamAV only**
— NOT the full Layer-A stack (ClamAV + YARA + entropy/PE heuristics). The full stack
(`scan_file`/`scan_directory` → `malware_findings`) is reachable **only** via the manual
`POST /api/malware/scan` button on the local host. The dashboard's local scan
(`_run_local_clamscan`), hw_monitor's queued-scan executor (`_local_clamscan_thread`),
and the agent's remote scanner (`scanner._run_scan`) are all clamav-only and write
`scan_jobs`/`scan_threats`, never `malware_findings`.

## Why it matters
**Users believe they are full-scanning and are not.** A scheduled or fleet "scan" looks
like protection but silently skips YARA + heuristics — i.e. exactly the zero-day /
behavioral coverage that is the product's headline. This is a correctness/trust defect,
not just a missing feature: the UI implies depth the execution doesn't deliver, on both
the local host and the fleet.

## Reasoning / shape
- This is the concrete user-facing symptom of audit facts #2/#3
  (`docs/audits/scan-task-architecture-audit.md`).
- The fix is architectural, not a patch: it depends on unifying the scan path so
  automation routes through the full-stack engine. That is ADR 0004's job (scheduler →
  full-stack execution module → reporting).
- Capture-only here so the defect is not forgotten while the ADR is designed; do NOT
  spot-fix individual executors (would entrench the divergence).
