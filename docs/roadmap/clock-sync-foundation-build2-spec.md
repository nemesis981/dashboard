# Roadmap — Clock-sync FOUNDATION (build-2 spec)

**Status:** build-2 spec (capture; docs-only — NOT built). Ships in **build 2** alongside the
Tailscale close-detection + latency collection. **Separable/droppable** within build 2.

**Rule 8:** placeholders only — no real IPs/hosts/accounts.

> **What this is:** the minimal, safe FOUNDATION for agent clock offset — a logical-offset
> measurement the agent computes and stores, so its own timestamps can be interpreted against
> server time. It is the v1 anchor that the full precision work refines later.
> **Parent (full vision):** `adaptive-link-aware-agent-clock-sync.md` (adaptive link-aware behavior
> + clock sync; commercial robustness). This spec is that item's **foundation** — the deferred
> precision work lives there and refines *this same measurement stream*.
> **Reconcile:** feeds one-way latency + later tuning accuracy; pairs with
> `connection-health-subsystem.md` (latency collection) but adds **no `conn_*` schema** — offset is
> additive conf data on the agent only.

---

## 🔴 NON-NEGOTIABLE GUARDRAIL — logical offset only, NEVER the OS clock
Store and apply a **LOGICAL OFFSET only.** The agent applies it to **its OWN timestamps**. It
**NEVER touches the operating-system clock** — no `w32tm`, no `SetSystemTime`, no `ntpdate`, no
`timedatectl set-time`, nothing that mutates system time.

**Why this is absolute:** changing the user's system clock needs admin rights and can cascade into
breaking **TLS certificate validation, Kerberos/AD auth, and any other time-sensitive app** on
their machine — catastrophic for a *security* product. This feature is **READ + CALCULATE only**,
the result stored as **DATA**, never an action on the system. **Safe by construction.** Any design
that writes the OS clock is out of scope and forbidden.

---

## Approach — Cristian's algorithm (~15 lines install / ~30 lines runtime)
The agent times a call **it already makes**, reads `server_time` from the response, and computes:

```
t0          = agent monotonic/epoch time just before the request
t1          = agent time when the response returns
rtt         = t1 - t0
server_time = <epoch> read from the response body
offset      = server_time - (t0 + rtt/2)      # midpoint assumption
```

`offset` is the logical correction the agent adds to its own clock readings to express them in
server time. No new request is introduced — it piggybacks on existing calls.

## Hooks (both are calls the agent already makes)
- **Install (sync-on-connect moment):** `_verify_nemesis_reachable()`
  (`nemesis_agent/installer_gui.py:508`) already GETs the auth-exempt `/api/health` (`:516`). Time
  that call, read `server_time`, compute the offset → **log to `install.log` + store in conf.**
  This is the baseline anchor.
- **Runtime (every ~5 min):** `_post_payload()` (`nemesis_agent/agent.py:169`) already POSTs
  `/hw_data`. Time that call, read `server_time` from the response → **recompute, log drift, and
  update the stored offset if `|drift| > threshold`.**

## Server-side change (~2 lines each, auth-exempt, no new endpoint)
Add `"server_time": <epoch>` to the JSON response of:
- `/api/health` (`dashboard.py:1518`, already auth-exempt)
- `/hw_data` response (`alert_manager/hw_monitor.py` receiver)

**No new endpoint. No server-side per-device offset storage** for the foundation — the offset lives
on the agent as data.

## Storage — additive conf keys (agent-side only)
Add to the agent conf (additive; never rewrites existing keys):
- `clock_offset_ms` — the current logical offset
- `clock_rtt_ms` — the RTT of the measurement that produced it
- `clock_synced_at` — when it was last (re)computed

## Other guardrails
- **Best-effort / never-fail:** wrap **every** measurement in try/except; a bad/missing
  `server_time`, a timeout, or a math error is **silently skipped**. It must **never block install
  or a heartbeat**, never raise.
- **Observational / non-gating:** the offset is **only stored + logged.** It does **NOT** reject
  heartbeats, does **NOT** gate enrollment on skew, does **NOT** feed any accept/deny decision in
  the foundation. Purely a recorded measurement.
- **Log RAW INPUTS, not just the derived offset:** persist `t0`, `t1`, `server_time`, `rtt` (not
  only `offset`). The deferred precise version can then re-derive with better math from the logged
  stream — **forward-compatible, no rework.**

## Caveat — install is a COARSE anchor; refine at runtime
The single install-time measurement runs over a **possibly-slow trip link** (jittery RTT weakens
the midpoint assumption). Treat the install offset as a **baseline**, and **refine at runtime** from
the steadier repeated `/hw_data` samples. Do not over-trust the install number.

## Deferred (refines the SAME measurement stream — parent item)
Precision work is deferred to `adaptive-link-aware-agent-clock-sync.md` and refines the same logged
inputs — no re-instrumentation:
- asymmetric-path correction (RTT halves aren't equal on real links),
- smoothed multi-sample offset (median/EWMA over recent samples vs single-shot),
- two-ended corroboration.
This foundation **enables one-way latency** and **feeds tuning accuracy** for that later work.

## Separability (trip-schedule safety)
Keep clock-sync in its **own best-effort methods** within build 2 so it can be **dropped without
touching the trip-critical Tailscale close-detection** if the schedule tightens. It is additive and
isolated by construction.

## Proof-of-pattern
The **install-logging shipped in build 1** already demonstrates this exact discipline —
best-effort / never-fail / additive-conf — so this is a known-safe pattern, not a new risk shape.

## Effort
~15 lines install hook + ~30 lines runtime hook + ~2 lines each on the two server responses.
Additive conf keys only. No new endpoint, no schema.

## Cross-references
`adaptive-link-aware-agent-clock-sync.md` (parent / precision work),
`connection-health-subsystem.md` (latency collection — no shared schema),
`diagnostics-and-access-master-plan.md` (clock-drift was deferred there pending a server timestamp;
this foundation is the server-time-in-response that unblocks it later). Hooks:
`installer_gui.py:508` / `agent.py:169` / `dashboard.py:1518` / `hw_monitor.py` `/hw_data`.
