# Roadmap — Connection-Health subsystem (design spec)

- **Status:** DESIGN of record (NOT built). Future build, **staged AFTER the current Tailscale
  join fix** (see `docs/audits/trip-1.0.8-vm3-tsnolaunch-regression-2026-07-01.md`). This doc
  captures the full design so nothing is lost.
- **Date:** 2026-07-02
- **Origin:** the overnight heartbeat-logging run (`docs/audits/overnight-run-2026-07-02.md`) —
  agent heartbeats are already a request/response; this subsystem turns them into per-device
  connection health.
- **Ties into:** the alert engine, the AI engine (tiered explanations), and the latency-defense
  work for remote Tailscale connectivity.
- **Rule 8:** placeholders only — no real IPs/hosts.

## Purpose

Turn agent heartbeats into a per-device **Connection-Health** subsystem: fast onboarding
verification, ongoing health visibility, alerting, on-demand testing, and diagnostics. For the
no-IT-department owner, **connection quality becomes visible, alertable, testable, and
diagnosable per device** — not an invisible black box.

---

## 1. Adaptive heartbeat ramp (agent-side)

- On install / first run, the agent heartbeats at **30-second** intervals.
- After **10 LANDED heartbeats** (§2 defines "landed"), it switches to the **steady-state**
  interval.
- Steady-state interval is a **user setting** (§5), **default 5 minutes**.
- **Why:** the fast ramp delivers install verification + a first connection-health read to the
  server in ~5 minutes of clean beats, instead of ~50 min waiting for 10 steady-state beats.
- The 10 landed readings also **seed an initial baseline/average** for the dashboard health view.

## 2. Reply-based landed/miss detection (agent-side) — CORE MECHANISM

- A heartbeat is a **request/response**: the agent POSTs, the server replies `200` + an ack.
- **LANDED** = agent received a success reply (clean round-trip).
- **MISS** = no reply / timeout / error response.
- **Only LANDED beats count** toward the 10-ramp threshold. Misses do NOT count — so on a rough
  connection the agent **stays in fast-ramp until 10 clean round-trips occur** (it doesn't
  "graduate" a flaky link to slow beats).
- **Gray zone:** "no reply" could be **outbound loss** (beat never arrived) OR **return-path loss**
  (beat arrived, reply lost). The agent alone can't distinguish these — §4 (server comparison)
  resolves it.

## 3. Two-fold evaluation → per-device dashboard health view

- **AGENT side:** tracks its own round-trip success/failure → drives its interval (§1) AND
  triggers traceroute-on-miss (§6).
- **SERVER side:** independently records what it actually **RECEIVES** per device (arrival timing,
  gaps, loss) → drives the dashboard health view + alerts. (Independent of the agent's self-view —
  the two are cross-checked in §4.)
- **DASHBOARD:** a per-device connection-health view the owner/user sees — health status, recent
  miss rate, latency trend, and the seeded baseline (§1).
- **ALERT STATES:** connection health crossing thresholds (excessive misses, high latency) raises
  an alert state, consistent with the existing alert engine. At the alert point, **OFFER AI
  ANALYSIS** of the connection problem (existing AI-engine pattern — likely cause + tiered
  Beginner/Intermediate/Pro explanation).

## 4. Miss disambiguation via server-log comparison (diagnostic)

The server's receipt log is the reference the agent's misses are compared against:

| Agent state at T | Server receipt at T | Classification |
|---|---|---|
| MISS | **no** beat received | **OUTBOUND loss** (agent → server path failed) |
| MISS | beat **was** received | **RETURN-PATH loss** (reply lost coming back) |

- Different failure paths → possibly different causes → diagnostically valuable.
- Runs as part of an **on-demand diagnostic view** (not necessarily per-miss live), surfacing the
  classified comparison. *(Open item: server-job vs dashboard-on-demand — see below.)*

## 5. Settings + on-demand test button

- **Settings page:** the user sets the **steady-state heartbeat interval** (default 5 min) —
  user-friendly, not hardcoded.
- **Near it, a "TEST CONNECTIVITY" button:** resets the agent to the fast **30-second** cadence for
  a **window** (default **30 minutes**, user-settable) for on-demand connectivity testing later —
  e.g. probing a flaky remote device on demand, not just at install.

## 6. Traceroute-on-miss (diagnostic data point)

- On a miss, the agent runs a **tracert** to the server and captures the network path — an extra
  diagnostic data point (helps pinpoint WHERE the connection broke).
- **RATE-LIMIT / BOUND (critical):**
  - **One tracert per miss-EVENT** — a run of consecutive misses = **ONE** tracert, not one per
    missed beat.
  - Plus a **hard daily cap per device** (drop oldest beyond the cap).
  - Prevents a bad-connection storm from generating unbounded traceroute data.

## 7. Data volume + retention (trim in from the start)

- **Receipt log is light:** ~100 bytes/beat → ~200 KB/device/week at 5-min steady state; ~5 MB/week
  at 25 devices. Not a storage concern.
- **RETENTION MODEL:** keep **~1 week of detailed per-beat receipts** (rolling window), THEN
  **roll up to DAILY SUMMARIES** per device (beats expected / landed / missed, avg latency) for
  long-term trend at tiny size. Detail ages out of the window; trend persists cheaply.
- **Traceroutes** are the heavier/spiky part — bounded by §6 (per-event dedup + daily cap). Even a
  flaky device stays under ~1 MB/week.
- **Design the schema with retention/roll-up in mind** — do NOT "log everything forever."

### Proposed schema sketch (retention-aware; prefix `conn_*`, ADR 0001)
- `conn_heartbeats` — per-beat receipts (**1-week rolling window**): `device_id`, `beat_ts`
  (agent-stamped), `received_ts` (server), `latency_ms`, `landed` (bool), `interval_state`
  (ramp|steady|test). Pruned nightly beyond the window.
- `conn_daily_summary` — per-device per-day roll-up (**long-term**): `device_id`, `day`,
  `expected`, `landed`, `missed`, `avg_latency_ms`, `max_latency_ms`. Written by the nightly
  roll-up job before pruning `conn_heartbeats`.
- `conn_traceroutes` — bounded diagnostic captures: `device_id`, `event_ts`, `classification`
  (outbound|return|unknown), `hops_json`. Per-miss-event dedup + daily cap; drop oldest beyond cap.
- All writes route through the Data Manager (ADR 0006) once built; carry the **actor** seam
  (multi-user readiness). Server-received timing is the source of truth for the dashboard/alerts.

---

## Open items (flag for build time — do NOT resolve now)

- Exact **alert thresholds** (miss-rate %, latency ms) — TBD.
- **Where the miss-comparison classification runs** — server job vs dashboard-on-demand.
- **Traceroute daily-cap number** — TBD.
- **Re-ramp-fast on agent restart?** — vs only on first install.

## Sequencing note

This is a **substantial multi-part subsystem** (agent + server + dashboard + alert engine + AI
engine) and a **future build**, staged **after** the current Tailscale join fix. Likely built in
stages (agent ramp + reply-detection → server receipt log + dashboard view → alerts/AI → tracert +
roll-up). This doc is the design of record so nothing is lost.
