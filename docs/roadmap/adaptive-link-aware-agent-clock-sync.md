# Roadmap stub — Adaptive link-aware agent behavior + clock sync

**Status:** parked (what + why — do NOT build yet; v1 may be built pre-trip to TEST in
the field). Commercial agent-robustness requirement. Built engine/agent-aware per the
forward mandates in CLAUDE.md / ADR [0005](../architecture/0005-dns-firewall-device-auth-architecture.md)
(§3 device identity & auth, §7 agent rebuild) — this is a property of that same agent.

> **North-star fit:** this is a canonical example of the **deterministic-automation**
> pillar of the [built-in-IT-expertise thesis](product-thesis-built-in-it-expertise.md) —
> the agent self-tunes to a bad link instead of expecting an admin to hand-tune timeouts.
> That makes it CORE (replaces IT-human labor), not secondary.

## Why (motivation)
Remote workers run the agent on **arbitrary / poor last-mile links** — Starlink, hotel
wifi, cellular, congested broadband. A **fast central network (10-gig)** talking to a
**slow remote last-mile** means a **successful** response can arrive **slower than a
LAN-tuned timeout expects**, so the agent **false-times-out a working operation**. This
is a real commercial requirement, not a nicety. Found-by-design via the **Wisconsin trip
scenario** (a known upcoming slow-link environment to validate against).

## What — v1 (smallest, highest value; possibly build pre-trip to test in the field)
- **Self-tuning timeouts off SMOOTHED round-trip latency** measured from the agent's
  OWN real calls home — **not a single ping**. Rolling average + jitter margin, the way
  TCP derives its RTO. Tight timeouts on fast links, automatically generous on slow
  links. **Self-calibrates wherever the agent runs**, instead of hand-tuned constants.

## What — v2 (capture, build later; genuine commercial differentiator)
Uniquely possible because **Nemesis owns BOTH ENDS** of the connection:
- **Two-ended / server-corroborated measurement.** The server reports what IT observes
  (client packet arrival, jitter, gaps, liveness) to inform client tuning **and** give a
  **ground-truth "slow-but-alive vs actually-dead"** signal from the receiving end —
  prevents false-timeout on slow-but-working links.
- **Measure one-way JITTER / TRENDS (clock-skew-robust), NOT absolute one-way delay**
  (which would need synced clocks). RTT drives tuning; two-ended data drives insight +
  liveness.
- **Graceful degradation on poor links** — adapt poll frequency, batch reports, retry
  with backoff. Be a **good citizen** on bad connections, not merely longer timeouts.

## Clock-sync layer (rides on the same client/server differential measurement)
- **Sync on REMOTE CONNECT** — establish a known-good baseline at session start, then
  watch for degradation from that anchor (clean latency math from the connect point).
- **Detect clock DRIFT** (sustained, steady trend in the differential) and push a sync;
  **DISTINGUISH from network jitter** (variable spikes → feed latency adaptation, NOT a
  sync). One measurement stream, **separated by steady-vs-jumpy**, feeds both clock-sync
  and latency adaptation.
- **Benefits beyond latency:**
  - **Fleet-wide timestamp correlation** for security forensics — correlating events
    across agents needs aligned clocks.
  - **Drift as a possible TAMPER signal** — a suddenly-wrong clock may indicate machine
    tampering (ties to ADR 0005 §6 proportional tamper response).

## Key diagnostic principle (high value, applies beyond this feature)
**Failures that surface at LOGIN/CONNECT are often ENVIRONMENTAL, not login-LOGIC bugs.**
Login is the most round-trip-intensive operation, so a slow link **bites there first and
masquerades as a "login bug."** Instrumenting **clock + latency AT CONNECT** lets you
correctly attribute connect-time failures to **LATENCY vs LOGIC**, instead of chasing
phantom auth bugs. (Echoes the 2026-06 DNS saga: the failure surfaced as a login/auth
error but was environmental — see ADR
[0005 §1](../architecture/0005-dns-firewall-device-auth-architecture.md).)

## Reasoning / shape
- **Engine/agent-aware build.** This is a property of the agent being rebuilt (ADR 0005
  §7); fold it in rather than bolting on a separate timeout subsystem later.
- **v1 stands alone** (client-only, self-calibrating) and is field-testable before the
  two-ended machinery exists — hence the option to build it pre-trip.
- **v2 + clock-sync depend on the server side of the agent protocol** (the `/hw_data`
  ingest path and its return channel) being rebuilt auth-aware first.
- Capture the design intent now; defer the build per the forward sequence.
