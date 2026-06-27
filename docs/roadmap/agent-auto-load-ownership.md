# Roadmap stub — agent auto-load by device ownership

**Status:** parked (what + why; do NOT build yet). The agent-level expression of the ADR
[0005](../architecture/0005-dns-firewall-device-auth-architecture.md) ownership/consent
boundary. Relates to the [single-user-assumptions audit](single-user-assumptions-audit.md)
and the commercial-tier readiness seams.

## What
Agent load behavior **gated by device ownership classification set at enrollment**:

- **COMPANY-OWNED device** → **forced auto-load on boot.** The company mandates protection on
  its own hardware.
- **EMPLOYEE-OWNED (BYOD)** → **on-demand / opt-in only.** Legal/consent boundary — a company
  cannot mandate always-on monitoring on an employee's personal property.

Ownership classification is **set at enrollment time** and drives load behavior thereafter.

## Why
This is the agent-level form of ADR 0005's rule: **"owned devices may be scanned; unowned
devices may only be observed."** Auto-loading always-on monitoring onto personal property
crosses a consent/legal line; forcing it onto company hardware is expected and defensible. The
distinction must be a first-class, enrollment-time property, not an afterthought — it changes
what the agent is even *allowed* to do.

## Reasoning / shape
- **BYOD mode must clearly disclose what it monitors and when** — a device-side notice, per
  ADR 0005's consent requirements. No silent monitoring on personal devices.
- Ownership is decided once (enrollment) and is the authority for load policy; later changes
  are a re-enrollment / re-consent event.
- Ties to the device-auth hook points already flagged for the agent rebuild — fold the
  ownership field into enrollment rather than retrofitting.
- Capture the policy now; build it with the agent rebuild / commercial tier, not before.
