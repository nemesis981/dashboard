# Overnight logging run — audit (2026-07-02)

> Read-only analysis of the two 5-min loggers set up for VM `.83` (working 66d190b agent).
> Raw (sanitized) logs copied alongside: `overnight-run-2026-07-02-server.log`,
> `overnight-run-2026-07-02-vm.log`. No change to the running setup. Rule 8: tailnet IP
> sanitized → `<tailnet-ip>`; device_id + timestamps only.

## ⚠️ Scope correction — this is a ~7-minute run, NOT a full overnight

The loggers were **installed this morning (~05:57, 2026-07-02)**, not last night — so the captured
window is **~7 minutes**, not hours. There are no `2026-07-01` log files (checked); cron only fired
at 06:00 and 06:05. The **device itself heartbeated overnight** (its `agent_last_seen` was advancing
before setup), but the **per-5-min logging only began at 05:57**. So there is no overnight *logging*
window to gap-analyze — the loggers are verified working and will accumulate a real overnight
dataset if left running through a night.

## 1. Counts + span

| Log | Samples | First | Last | Span |
|---|---|---|---|---|
| Server (`…-server.log`) | **3** | 2026-07-02 05:57:56 | 2026-07-02 06:05:01 | ~7m05s |
| VM `.83` (`…-vm.log`) | **2** | 2026-07-02 05:59:10 | 2026-07-02 06:04:01 | ~4m51s |

## 2. Expected vs actual (5-min cadence) — complete for the window, no gaps

- **Server** (cron `*/5`): 05:57:56 (manual seed) + 06:00:01 + 06:05:01 = **3/3**. Cron log confirms
  fires at 06:00:01 and 06:05:01. **No missing slots.**
- **VM** (Scheduled Task every 5 min, SYSTEM): 05:59:10 (seed) + 06:04:01 = **2/2**; next due ~06:09.
  **No missing slots.**
- **No gaps** in the captured window. (No "overnight API turbulence" gaps because there was no
  overnight logging window — see scope correction.)

## 3. cpu%/ram cross-check — CONSISTENT gap (every sample)

| Side | Samples with real cpu%/ram | Samples with EMPTY cpu%/ram |
|---|---|---|
| **VM (local reading)** | **2 / 2** (cpu%=6/2, ram=2.64/2.59 GB) | 0 |
| **Server (`hw_metrics` sample)** | 0 | **3 / 3** (`cpu%=-  ram_gb=-`) |

**The gap is consistent, not intermittent** — in *every* sample the VM reads real CPU/RAM locally,
yet the server-side `hw_metrics` row for the same device has those fields **empty**. So the agent is
enrolled + heartbeating (rows land every 5 min, `last_seen`/`sample_ts` advance) **but the metric
values are not making it into the server sample.** Temps (`cpu_temp`/`gpu_temp`) are also empty —
expected on this 66d190b build (no PawnIO/LHM sensor path), but **cpu%/ram being empty server-side
is the real finding**: a payload→sample mapping gap (`_nemesis_payload_to_metrics` / `insert_sample`),
worth investigating. The two logs together isolate it: **VM has the values, the server sample drops
them.**

## 4. Rule 8

VM log's tailnet IP sanitized to `<tailnet-ip>` before copying; both copied logs re-scanned —
**no IPs / home paths / keys / PII** (device_id + timestamps + placeholders only).

## 5. Status + next

- **Logging infrastructure verified working** — both ends writing timestamped lines; server cron
  active (`*/5`), VM task `NemesisOvernightLog` registered + enabled (every 5 min, run-as SYSTEM,
  unattended). Left running, they'll build a genuine multi-hour dataset.
- **To get a real overnight dataset:** leave both loggers running through a full night, then re-pull.
- **Investigate (separate task):** why approved-agent `hw_metrics` samples land with empty
  cpu%/ram (and temps) server-side while the VM reads them fine — the consistent gap above.

---
*Read-only audit 2026-07-02. Loggers untouched; docs-only.*
