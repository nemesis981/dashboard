# Nemesis — Project Status (print & carry)

**As of 2026-06-26** · verified against repo + live `alerts.db`, not memory.
HEAD `e6fd3fd`. "Done" = verified, not just written.

---

## 1. WHAT'S DONE (shipped, committed, verified)

**Pass 0 — single shared `alerts.db` consolidation: COMPLETE**
- ai_engine `181c14c`, tickets `6f6b6c3`, community_queue `290c2db` — all read/write
  shared DB, verified live. Old per-module `.db` files frozen as fallbacks (until Stage 6).
- Shared DB is WAL + busy_timeout; concurrent-write smoke test passed.

**Pass 0 Stage 4 — partial (the done parts):**
- ✅ Ghost 0-byte DBs deleted (`dashboard.db`, `malware_detection/malware.db`) — confirmed gone.
- ✅ `scan_jobs` → `malware_scan_jobs` rename `9db6e7a` — verified: table exists, `actor`
  column present, core `scan_jobs` intact, scan-status endpoint now 200 (was always 404).
- ✅ Malware DB-accessor fix `5fd3a9c` — verified: uses shared `get_db()`, no `__file__` path.

**Docs / workflow system:**
- Handoff discipline live: worklog → supplement → HANDOFF (CLAUDE.md Rule 9).
- ADR 0004 (scan/task orchestration) recorded; scan/task + malware audits in `docs/audits/`.
- Backups on independent storage, all `integrity_check=ok`.

---

## 2. WORKING vs STUBBED/BROKEN (the real gaps)

**Works:**
- Malware **Layer A** engine — ClamAV + YARA + entropy/PE heuristics → `malware_findings`,
  quarantine, alert hook. *(But only via one manual button — see below.)*
- Remote **hardware monitoring** over the agent — BUILT, end to end (fleet `hw_metrics`,
  per-device anomaly pipeline).
- Core: shared DB, alert pipeline, tickets, community_queue, ai_engine status.

**⚠️ Stubbed / broken / misleading — where the gaps are:**
- **Automation is CLAMAV-ONLY.** Verified: no YARA/heuristics anywhere outside the malware
  module. Every scheduled/fleet/condition/agent scan runs ClamAV alone. Layer A's full stack
  runs **only** on the manual `POST /api/malware/scan`.
- **LATENT BUG — fleet/scheduled scans look full but aren't.** Users believe they're
  full-scanning; they're getting clamav-only. Local + fleet. (`roadmap/latent-bug-fleet-clamav-only.md`)
- **Scheduled scans are DEAD.** Verified: `scan_schedules` is never read; no timer/worker
  drains the queue. The "weekly schedule" UI writes rows nothing acts on.
- **Malware Layer B ABSENT.** No canary / behavioral / Falco / Sysmon code — settings are
  placeholders only. (This is the zero-day/behavioral headline — not built.)
- **Layer C (AI verdict) scaffolding only; Layer D (local ML) absent.**
- **No malware background service** despite manifest flag — on-demand only.
- **3 separate local scanners, 2 engine sets, 2 table families** — no single scan path.
- **Scan dispatch welded into hw_monitor `/hw_data` handler** — tangled with hardware ingest.
- **All 5 `scan_*` tables core/unprefixed** — will need migration under ADR 0001.
- **VPN/DNS connectivity — UNRESOLVED.** Intermittent (worked ~1hr w/ PIA on, then dropped;
  Code lost api.anthropic.com, re-login failed fetching key). NOT a fixed client bug.

---

## 3. NEEDS IMMEDIATE ATTENTION (priority order)

**1. Commercial-readiness / single-user-assumptions audit — TOMORROW'S OPENER.**
   North-star: single version + key-unlock model. Output a change-list → make tree uniformly
   multi-user-ready + key-gate-socketed → work it → finalize.
   *Blocks: scheduler/reporting build (do this first so they're attribution-shaped from creation).*

**2. Scan/task orchestration ADR 0004 — answer the 3 hinge questions.**
   (a) one findings table vs two; (b) how full-stack reaches the fleet; (c) where 5 `scan_*`
   tables migrate. *Depends on #1. Unblocks the scheduler + reporting modules + the clamav-only
   fix.* This is the fix for the latent bug + dead schedules.

**3. Finish Pass 0 Stage 4.**
   - Collapse remaining duplicate CREATEs: `quarantines`, `hw_alerts` (each in two places).
   - Retire hw_monitor's local-clamscan path. *Sequence AFTER ADR 0004 direction is set
     (it owns who scans the local host).*

**4. VPN root-cause — watcher is ARMED.**
   `~/work/vpn-watcher/vpn-watch.sh` (outside repo, not committed) logs every 3s.
   **Next failure → read the log at that timestamp.** Leads: PIA leaves a `blackhole default`
   in table `piavpnOnlyrt` even when disconnected; api.anthropic.com is IPv6 → may be
   v6-routing-specific (watcher splits v4/v6 auth tests). *Independent of #1–3.*
   VPN self-diagnostic feature = AFTER root-cause.

**Dependency chain:** #1 → #2 → (#3 tail + scheduler/reporting build). #4 runs in parallel.
