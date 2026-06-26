# Roadmap stub — Run-Diagnostic scan scope (pre-run popup)

**Status:** parked (what + why — do NOT build yet). Depends on a unified full-stack
scan path (ADR [0004](../architecture/0004-scan-task-orchestration.md)).

## What
A pre-run popup on "Run Diagnostic" that lets the user choose scope before it runs:
- **Health checks** — always run.
- **Optional "include full malware scan"** — opt-in checkbox.
  - If included, choose **fresh scan** (run a new full-stack scan now) vs **use last
    results** (reuse the most recent scan).
  - A fresh scan runs the **full stack** (ClamAV + YARA + heuristics), not clamav-only.
  - If reusing results, **flag stale scans** (show age; warn if old) so the user knows
    they're looking at cached findings.

## Why
A full malware scan is expensive (time/CPU); health checks are cheap. The user should
**own the cost/depth tradeoff** explicitly rather than have the diagnostic silently
either skip the scan or block on a long one. Surfacing fresh-vs-cached + staleness keeps
the result honest (no pretending a week-old scan is "current").

## Reasoning / shape
- **Depends on the unified scan path** — "full-stack when fresh" only makes sense once
  diagnostics can invoke the full-stack engine (today only the manual button can; see
  `latent-bug-fleet-clamav-only.md`). Build after ADR 0004 lands.
- Staleness flagging pairs with the scan-job timestamps already tracked in
  `malware_scan_jobs` (`started_at`/`finished_at`).
- Capture the UX intent now; defer the popup build until the engine path exists.
