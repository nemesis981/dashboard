# Roadmap — L2/WinDivert stumble escalation (frequency-threshold, server-side)

**Status:** capture (design note; docs-only — NOT built). Post-L2 work (next-session+). Does **not**
affect tonight's L2 test battery.

**Rule 8:** placeholders only — no real IPs/hosts/accounts.

> Capture only — no code, no build. Covers what happens **after** the L2 local stall-watchdog
> already recovered: server-side awareness + proportional escalation. Relates to
> [ADR 0009 — security inspection proxy](../architecture/0009-security-inspection-proxy.md) /
> [adr-0009-build-scope](adr-0009-build-scope.md) (L2/WinDivert + the **config-pull** push channel),
> the tickets module + [pre-escalation-support-search](pre-escalation-support-search.md)
> (auto-search similar past tickets), and [agent-rebuild-config-driven](agent-rebuild-config-driven.md)
> (server-authoritative config).

---

## Context
L2 WinDivert blocking has a **local stall-watchdog** (default ~5s timeout) that auto-recovers a hung
packet loop on the device. That local recovery already exists. **This note is about what happens
AFTER local recovery** — the server noticing repeated stumbles and escalating proportionally.

## Threshold (starting value — tune against real trip data, NOT final)
**3 watchdog-triggered recoveries within a rolling 30–60 minute window on the same device** →
**disable L2 for that device** + **auto-create a support ticket.**

**Rationale — frequency, not duration.** Each individual stall is already capped at ~5s by the local
watchdog, so duration-per-event is not the signal — **repeated frequency is** (a device stumbling
again and again = a real problem). A single isolated stumble is the watchdog working *as designed* →
**log only, no escalation.**

## Design
- **Client → server report.** On the next reconnect/heartbeat, the client reports each recovered
  stumble as an event: `{device_id, event: "l2_stall_recovered", duration, timestamp}`. (Reported
  after the fact — the device was briefly in a hung/recovering state, so this rides the next
  successful check-in, not real-time.)
- **Server tracks the COUNT per device** over the rolling window (30–60 min).
- **Below threshold → log only.** No action. Proportional by design.
- **Threshold crossed →**
  1. **Mark the device L2-disabled** server-side. The flag is **pushed on the next
     reconnect / config-pull** — the server **cannot** push mid-outage (the device is exactly the
     one that's stumbling), so disablement takes effect on the device's next clean check-in.
  2. **Auto-create a support ticket** (tickets module), tying into the planned
     **auto-search-similar-past-tickets** behavior (`pre-escalation-support-search.md`) so a
     recurring stumble surfaces prior instances/fixes.
- **Explicitly proportional:** an isolated stumble must **NOT** disable protection. Only sustained
  frequency crosses the line. Err toward keeping protection on until the frequency signal is real.

## Targeted disable, NOT whole-agent shutdown
Disabling L2 is a **targeted component stop**, not an agent kill:
- **Uses the clean-stop path already in `nemesis_agent/l2_windivert.py`** — flip `_running` false →
  the `while _running` loop breaks (`:75`, `:143-144`) → `finally` closes the WinDivert handle
  (`:148-151`) → the filter is removed cleanly. The **rest of the agent is UNAFFECTED and keeps
  running normally**: heartbeats, L1 DNS enforcement (if active), sensor reporting, enrollment.
- **The Feature-6 reputation cache is NOT torn down** when L2 blocking is disabled — it is a
  separate, already-safe, **observation-only** component (`nemesis_agent/reputation_cache.py`). It
  can keep syncing and logging *"what would have been blocked"* even with active enforcement off,
  **preserving partial visibility/value rather than falling back to zero.**
- **Principle:** degrade the one misbehaving component, keep everything else — including passive
  visibility — alive. Never a whole-agent shutdown to fix an L2 stumble.

## Testing practice (Rule 2 — one variable at a time)
When diagnosing a suspected L2 issue, **disable L2 and continue testing the REST of the system
independently** to isolate the variable — confirms whether base agent health (heartbeat, hardware,
enrollment) is independent of L2. Don't debug L2 and base-agent behavior tangled together.

## Dependencies (not built — next-session+)
1. **Client-side stumble reporting** — emit the recovered-stall event + buffer it for the next
   check-in.
2. **Server-side per-device event tracking** — rolling-window count store (own the actor seam;
   route writes through the Data Manager path per ADR 0006).
3. **Reconnect-time config-push** — the L2-disabled flag delivered via config-pull (ADR 0009
   Phase 0a); cannot push mid-outage.
4. **Ticket-module integration** — auto-create + auto-search-similar (`pre-escalation-support-search.md`).

## Scope note
Post-L2 escalation layer. **Not part of tonight's L2 test battery** — tonight validates the L2
block + local watchdog; this server-side frequency escalation is later work. Threshold values
(3 / 30–60 min) are **starting points to tune against real trip data**, not final.
