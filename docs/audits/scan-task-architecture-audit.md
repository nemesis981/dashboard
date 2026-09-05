# Scan & Task Architecture — Audit (ADR Input)

- **Date:** 2026-06-26
- **Mode:** Read-only audit — no code changed, no commits. Maps current reality to
  scope a scan/task orchestration architecture (ADR 0004).
- **Scope:** `alert_manager/hw_monitor.py`, `dashboard.py`,
  `modules/malware_detection/module.py`, `nemesis_agent/`, `windows_agent/`.

> Sanitized for the public repo: no home paths, no real IPs, no secrets. Paths
> repo-relative; decisive claims verified firsthand by grep/read.

> **§A/§B redacted for the public repo, 2026-09-05, per Rule 10** — the exact
> trigger/executor file:line map is a live, unfixed coverage gap, and precision about
> which entry points route through which engine is attacker-relevant detail, not
> architectural direction. Full unredacted tables: private mirror (not named here).

---

## A. Every scan trigger

Multiple trigger paths exist across the dashboard UI, hw_monitor's agent-check-in-driven
condition evaluator (five default conditions), queue dispatch, direct agent commands, and
a schedule-writing endpoint that nothing currently consumes (see §C). **Exact file:line
locations and calling functions for each trigger: kept in the private mirror per Rule 10.**

## B. Every scan executor + the divergence

Four executors exist across the local host (dashboard-triggered and hw_monitor-queued),
and the remote agent. **Exact file:line locations and function names for each executor:
kept in the private mirror per Rule 10.**

**Divergence (core problem, already public via [ADR 0004](../architecture/0004-scan-task-orchestration.md)'s
evidence base facts #2/#3):** the full detection stack (ClamAV + YARA + entropy/PE
heuristics, writing to `malware_findings`) is reachable only via one manual trigger.
Every automated/fleet/condition path runs a reduced engine set and writes to a separate
table family, never `malware_findings`.

## C. Scheduling / queue / condition — scheduled scans do NOT fire

Tables (all `hw_monitor.py`, core/unprefixed): `scan_schedules` (243), `scan_queue`
(265, +index), `scan_conditions` (285, seeded).

- `scan_schedules`: **written** by `/api/scan/schedule` (`dashboard.py:5302`),
  **read by nobody** — verified no `SELECT/UPDATE scan_schedules`, `last_run_at`
  never set. **Write-only / dead config.**
- `scan_queue`: written `_queue_scan` (1375); consumed `_dispatch_pending_scans`
  (1505); read `get_scan_queue` (1613) / cancel (1687).
- `scan_conditions`: conditions API (`dashboard.py:5438–5463`) + evaluated in
  `_check_and_queue_scan_triggers`.

**CONFIRMED:** `_check_and_queue_scan_triggers` (1836) and `_dispatch_pending_scans`
(1840) are called **only** inside the `/hw_data` handler — **purely event-driven on
agent check-in**. The hw_monitor main loop never touches the queue/schedules. So the
"weekly schedule" UI persists rows nothing acts on, and queued scans only dispatch on
the target's next check-in; there is no scheduler/worker draining the queue.

## D. Agent protocol

Transport: agent → server `POST :5001/hw_data` every `poll_interval` (default 300s);
server → agent `POST agent:5002` (no auth, agent-localhost listener). Ingest handler
`hw_monitor.py` `_WaHandler` (body 1815–1863).

Payload (nemesis_agent): `source, device_id, device_name, device_type,
connection_type, timestamp, hardware{sensors}, security{processes,connections,logins,
new_files,usb}, agent_health{…last_scan_*}, suricata_alerts[]`.

| Capability | Status | Evidence |
|---|---|---|
| (a) HW telemetry over agent | **BUILT** | collection → `/hw_data` → `_nemesis_payload_to_metrics` → `insert_sample` → `hw_metrics` (device_id) |
| (b) Scan dispatch to agent | **BUILT** | `/api/scan/trigger` & `_dispatch_pending_scans` POST `action=scan` |
| (c) Scan execution on remote | **BUILT (clamav-only)** | `scanner._run_scan`; results polled via `scan_status` |
| (d) Notifications | **PARTIAL** | server→agent BUILT (`/api/agent/notify`); agent→server rides 5-min payload, no push channel |

## E. Coupling map

**Remote HW monitoring: BUILT** — `_WaHandler` (1834–1838) → metrics + `_update_agent_device`
(`agent_devices`) + `insert_sample` (`hw_metrics.device_id`); per-device retrieval +
anomaly pipeline (14-day same-hour >2σ → `hw_anomaly_snapshots.device_id`).

**The knot — `/hw_data` handler (`hw_monitor.py:1832–1840`)** does 5 things per payload:
metrics → `_check_and_queue_scan_triggers` (scan) → `_update_agent_device` (device mgmt)
→ `insert_sample` (hw) → `_dispatch_pending_scans` (scan). Scan triggering/dispatch are
physically interleaved with hardware ingest + device-state mgmt in one HTTP handler in
the hw_monitor process. Untangling requires: a real timer trigger source (handler has
the live request + prev device state — "before update (needs prev state)" comment at
1836); moving executors `_local_clamscan_thread`/remote-POST out of hw_monitor;
resolving that dispatch reads/writes core unprefixed scan tables (a module may read but
not write them per ADR 0001); and the condition evaluator's tight binding to
`agent_devices.known_users_json/known_usb_json`.

**Scan-table ownership:**

| Table | Created | Prefix | Migrate if dispatch→module |
|---|---|---|---|
| `scan_jobs` | hw_monitor.py:213 | core/unprefixed | yes |
| `scan_threats` | hw_monitor.py:230 | core/unprefixed | yes |
| `scan_schedules` | hw_monitor.py:243 | core/unprefixed | yes (dead, §C) |
| `scan_queue` | hw_monitor.py:265 | core/unprefixed | yes |
| `scan_conditions` | hw_monitor.py:285 | core/unprefixed | yes |
| `malware_scan_jobs` | module.py:156 | `malware_*` (compliant) | none |
| `malware_findings` | module.py:123 | `malware_*` (compliant) | none |

All five `scan_*` tables are core/unprefixed; a scan-module would migrate them under
ADR 0001, touching readers/writers in hw_monitor, dashboard, and the agent-results path.

## F. Agent full-stack feasibility

Agent today is **ClamAV-only** (Windows Defender fallback). Verified: no
`yara|entropy|pefile|heuristic` anywhere in `nemesis_agent/`+`windows_agent/`;
`scanner._build_cmd` returns only `clamscan …`/`MpCmdRun.exe …`. Gap to full-stack on
fleet: ship YARA rules + pefile/entropy engine to endpoints (cross-platform), OR ship
suspect files back to server (no file-transfer channel exists today — agent returns
threat strings only); results would report into `malware_findings` with `device_id`
(column + `scan_file` params already exist, but no agent path calls them). Forces the
"one findings table vs two" decision.

## Cross-cutting facts (ADR hinges)
1. Three local-host scanners, two engine sets, two table families — no single path.
2. YARA + heuristics reachable only via one manual button; all automation clamav-only.
3. Scheduled scans dead (write-only `scan_schedules`); no timer/worker drains the queue.
4. Scan dispatch welded into the hw_monitor `/hw_data` handler.
5. All five `scan_*` tables core/unprefixed; scan-module requires migrating them.
6. Remote HW monitoring BUILT; remote full-stack malware scanning NOT.
