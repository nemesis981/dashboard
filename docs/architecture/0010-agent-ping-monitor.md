# ADR 0010 — PC Agent Continuous Ping Monitor

- **Status:** Proposed (architecture decided 2026-06-29; design captured, **no code changed**).
  Build deferred until after trip-readiness (pre-enrollment scan + Windows smoke test).
- **Date:** 2026-06-29
- **Depends on:** the agent (`nemesis_agent/`) and its keypair enrollment / device-auth
  ([0005-dns-firewall-device-auth-architecture](0005-dns-firewall-device-auth-architecture.md));
  the agent rebuild / config-pull
  ([agent-rebuild-config-driven.md](../roadmap/agent-rebuild-config-driven.md)) — ping targets
  and intervals become config-driven there
- **Related:** [0009-security-inspection-proxy](0009-security-inspection-proxy.md) (agent dual
  role / inspection path); [0008-impossible-travel-detection](0008-impossible-travel-detection.md)
  (per-device behavioral baseline); [0006-data-manager](0006-data-manager.md) (writes route
  through the Data Manager once built)

> Records an architecture decision; it does not design the implementation. Intervals,
> thresholds, and retention windows below are the captured design intent, to be validated when
> specced. IPs shown are public resolvers (illustrative); local targets are auto-detected at
> runtime, never hardcoded.

## Problem

Network failures are diagnosed **after the fact** and **by hand**: by the time someone notices
"the internet is slow," the routing event that caused it is gone. Today the only connectivity
signal is **host-wide** (`diagnostics_connectivity_samples`, an HTTP-curl latency probe from the
Nemesis box itself) — there is **no per-device view**, so a single device's WiFi problem and a
network-wide ISP outage look identical. The agent that runs on each PC is **stateless** and only
checks in every 300s for telemetry; it carries no continuous connectivity history and drops
samples if the server is unreachable.

We want each enrolled PC to **continuously measure its own path to the internet**, keep the
history locally (surviving offline periods), and feed the dashboard a per-device latency timeline
— so that "device-specific vs network-wide" is answerable at a glance and a failure arrives with
its own evidence trail.

## Decision

**Each agent runs a lightweight, adaptive ICMP ping monitor against a fixed target set, stores
samples in a local SQLite buffer, and syncs batches to the server on a heartbeat (draining any
offline backlog on reconnect).** The server stores per-device samples alongside the existing
agent device record and renders a per-device latency timeline; cross-device correlation
distinguishes a single bad device from an upstream/network-wide event.

The agent stays **thin in policy, local in measurement**: it measures and buffers, the server
correlates and decides. TTL is treated as a **routing-path stability signal**, not just a packet
field.

## Monitored targets (layered, so the failure layer is self-evident)

| # | Target | Source | Layer it proves |
|---|---|---|---|
| 1 | Default gateway | auto-detected (`ip route` / `route print`) | local link / LAN |
| 2 | Nemesis box | server LAN IP from agent config | reachability to home base |
| 3 | ISP DNS | agent's configured resolver | first upstream hop |
| 4 | Google DNS `8.8.8.8` | fixed | public internet (anycast A) |
| 5 | Cloudflare `1.1.1.1` | fixed | public internet (anycast B) |
| 6 | OpenDNS `208.67.222.222` | fixed | public internet (anycast C) |
| 7 | Nearest Tailscale relay | `tailscale netcheck` (if tunnel active) | tunnel path health — **v1.1** |

The layering is deliberate: gateway up but ISP DNS down = ISP problem; everything up but the
relay degraded = tunnel problem; gateway itself unreachable = local WiFi/link problem. **No local
target is ever hardcoded** (Rule 8) — gateway, Nemesis box, and ISP DNS are resolved at runtime.

## Metrics per sample

Each sample (one cycle = a 3-ping burst per target) records:

- **`latency_ms`** — mean RTT across the 3 pings.
- **`ttl`** — TTL of the response (hop-count fingerprint of the path).
- **`packet_loss`** — fraction lost across the 3-ping burst.
- **`reachable`** — bool (any reply received).

## TTL as a route-stability signal

A stable path returns a stable TTL. A **TTL change** for a target between consecutive samples
means **the route changed** — ISP rerouting, a Tailscale relay switch, or a failover. This is the
cheapest possible route-change detector (no traceroute needed for the common case). A **downward
TTL trend** is an early indicator of a developing routing loop. v1 records TTL and flags
discrete changes; trend analysis is v1.1.

## Adaptive interval

The agent self-regulates its ping cadence based on locally-observed health, so early warning
works **even while the server is unreachable**:

| Mode | Trigger | Interval |
|---|---|---|
| **Normal** | healthy | 60s (background, unobtrusive) |
| **Degraded** | current 5-min avg latency > 3× rolling 1-hr baseline | 15s (early warning) |
| **Failure** | target unreachable | 5s (fast recovery detection) |

The 3× spike rule mirrors anomaly-detection Pattern C; the rolling baseline mirrors the hardware
2σ same-hour-of-day baseline. On entering **degraded** mode the agent (a) increases frequency,
(b) flags the batch so the dashboard surfaces it, and (c) **pre-captures diagnostics** (in v1.1,
a traceroute) while the problem is still live.

## Agent-local storage + adaptive retention

The agent gains a **local SQLite buffer** (it is otherwise stateless — only an INI config + RSA
keys today). Storage cost is a few MB. Retention scales with how interesting the data is:

- **7 days** normal,
- **30 days** if the window contained any degraded period,
- **90 days** if it contained any failure.

Pruning is on-write (the diagnostics row-count-cap pattern), keyed on whether a failure/degraded
sample exists in the window — no extra daemon.

## Server sync

- Samples **queue locally** and flush as a **batch on the heartbeat** (default aligned to the
  poll cadence; degraded/failure batches flush sooner).
- If the server is unreachable, samples **accumulate** and **drain on reconnect** (the
  `scan_queue` dispatch pattern at `hw_monitor.py` is the model — today `/hw_data` samples are
  simply dropped on POST failure; this fixes that class of loss for ping data).
- A flushed batch is deleted from the local buffer only after the server acks.

## Transport & auth

- **New endpoint `/ping_batch`**, decoupled from the 300s `/hw_data` telemetry POST (ping cadence
  of 5–60s must not be coupled to telemetry cadence; batching avoids one POST per ping).
- **Device-auth enforced** with the existing `_agent_approved(device_id)` gate (the same gate
  `/hw_data` uses for `nemesis_agent`). Unapproved devices are silently refused, matching the
  existing pattern.
- **Actor seam:** add the `actor` column to `agent_devices` (currently absent) and stamp ping
  samples with `actor = device_id`. This is the actor seam the agent rebuild is already mandated
  to add — fold it in here, do not add it twice. Once the Data Manager (ADR 0006) is built, actor
  is applied automatically and the manual stamp is removed.

## Storage (server side)

Server ingestion and storage live in `hw_monitor` (it owns `agent_devices` / `hw_metrics` and the
auth gate) — **not** a separate dashboard module, which would be too decoupled from the agent
domain. A new `agent_ping_samples` table holds per-device, per-target time series; its DDL lives
in the one canonical `hw_monitor` init (per ADR 0001 — no table without a `CREATE` in the repo).

## Dashboard surface

- **Per-device latency timeline** reusing the existing **Chart.js 4.4.1** infrastructure and the
  per-device-metrics endpoint pattern (`/api/ping/timeline` as a sibling of
  `/api/hw/metrics-for-device`).
- **Device-specific vs network-wide** verdict by cross-device correlation: the **same target**
  degraded on **one** device = device-specific (that device's WiFi/link); the **same target**
  degraded across **all** devices = network-wide (upstream/ISP). This is the question the
  host-only diagnostics card cannot answer today.
- Degraded/failure surfaces to the **header light** via the single alert path
  (`insert_alert(..., action='pending')`), consistent with every other Nemesis alert.

## Failure narrative (v1.1)

When a failure occurs, the agent assembles a **human-readable failure story** with no manual
diagnosis required: the latency timeline leading in + the TTL changes (route shifts) + the failure
layer (which target tier broke) + a traceroute captured at failure time. v1 records the raw
inputs (timeline, TTL, layer); the **automatic traceroute capture and the narrative synthesis are
v1.1**.

## ADR 0009 constraint

The ping monitor **must not bypass the inspection layer**. Probes respect the agent's chosen
connection mode (Mode 1 management-only vs Mode 2 full inspection proxy); the monitor **reads**
the connection type to interpret results, it does **not** route probe traffic outside the agent's
selected path. (See [0009](0009-security-inspection-proxy.md) — "modules must not bypass the
inspection layer.")

## Multi-user readiness

- `actor` on `agent_devices` and on `agent_ping_samples` (= `device_id`), per the agent-rebuild
  mandate — built in once, not retrofitted.
- Per-device state, never a global singleton — the design is per-`device_id` from the start.
- Writes route through a single update path so live-refresh (and later multi-user push) has a
  clean hook; once the Data Manager exists, all writes go through it.

## Phasing

**v1 (core):**
- Targets 1–6 (gateway, Nemesis box, ISP DNS, Google, Cloudflare, OpenDNS).
- Per-sample latency / TTL / packet-loss / reachable.
- Adaptive 60 / 15 / 5s interval with the 3× spike → degraded rule.
- Agent-local SQLite buffer + adaptive 7/30/90-day retention.
- Queued batch sync over `/ping_batch` with reconnect drain.
- `agent_ping_samples` table + `actor` seam.
- Per-device latency timeline + device-vs-network verdict + header-light alert.

**v1.1 (deferred — heaviest, least trip-critical):**
- Target 7: Tailscale nearest-relay via `tailscale netcheck`.
- Automatic traceroute capture on degraded/failure.
- The AI / human-readable failure-narrative synthesis.
- TTL downward-trend (routing-loop early warning).

## Sequencing vs trip-readiness

Build is **deferred until after** the trip-readiness work HANDOFF lists as the resume point
(pre-enrollment scan + Windows smoke test). Rationale: this is heavy **agent** work whose
per-platform ping parsing (`ping -c` vs `-n`; TTL and loss lines differ per OS) can only be
trusted once validated on real Windows hardware — and the Windows agent is not yet smoke-tested.
The platform ping parsing should be validated on the same real-hardware pass that smoke-tests the
agent.

## Connections

- [ADR 0005](0005-dns-firewall-device-auth-architecture.md) — keypair enrollment = the device-auth
  the `/ping_batch` gate reuses.
- [ADR 0006](0006-data-manager.md) — ping-sample writes route through the Data Manager once built;
  actor applied automatically.
- [ADR 0008](0008-impossible-travel-detection.md) — per-device baseline; latency/route history is
  another behavioral dimension.
- [ADR 0009](0009-security-inspection-proxy.md) — agent dual role; probes must not bypass the
  inspection path.
- [agent-rebuild-config-driven.md](../roadmap/agent-rebuild-config-driven.md) — ping targets and
  intervals become config-pull driven; the `actor` seam is shared with the rebuild.
