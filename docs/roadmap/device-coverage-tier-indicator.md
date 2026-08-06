# Roadmap — per-device coverage-tier indicator

**Status:** parked (capture-only — what + why; do NOT build yet). Captured 2026-08-05 per
Rule 7, as a feature candidate raised alongside agent-platform scoping.

## What

A visible per-device indicator on the dashboard's device list distinguishing what kind of
protection a device actually has, instead of implying uniform coverage across every row.
Something like:

- **Fully Protected (Agent)** — the device has the Nemesis agent installed and enrolled.
- **Network-Monitored** — the device is seen and protected at the network level (traffic
  inspection, firewall rules, anomaly detection), but has no agent.

## Why

Nemesis protects every device on the network whether or not it runs an agent — that part
doesn't change. But the *kind* of protection differs (network-level visibility vs. an
agent's host-level view), and today that distinction is invisible: every row in the device
list looks the same regardless of coverage. Making it visible turns a platform limitation
into something legible instead of hidden, which fits this product's general preference for
honest, transparent status over implied parity that doesn't quite exist.

## Design notes

**⚠ Updated 2026-08-05 — "no agent" is not one state, and for phones/Apple devices it is
not a permanent gap.** An earlier version of this doc treated any non-agentable device as
a single "Network-Monitored, permanently" bucket alongside IoT. That's being revisited: a
separate network-architecture decision (isolating non-agent devices onto their own
inspected subnet, with Nemesis handling delivery to the same inspection layers the agent
path already uses) means phones and Apple devices are heading toward a **real, actively
inspected coverage tier**, not just passive network visibility — and specifically not a
permanent limitation the way an un-agentable IoT device's state is. Keep that distinction
sharp in whatever ships here; don't describe Apple/mobile coverage as a permanent gap.

**Consider (at least) four underlying states, even if the UI collapses some for display:**

1. **Agent-enrolled** → "Fully Protected"
2. **Agent-capable platform, not installed** (Windows, Linux, Android) — an *opportunity*,
   not a gap. Copy should invite, not alarm: "you could add stronger protection here."
   This state also functions as an admin-facing discovery list of upgrade candidates.
3. **Non-computer IoT** (a smart plug, a thermostat) — will never run an agent, and
   "Network-Monitored" (or whatever it evolves into once subnet-level inspection ships)
   is this device's permanent, correct, complete state. Nothing is missing here.
4. **Never-agentable but computer-class** (phones, Apple devices pending their own
   platform work) — today this looks like (3) from the outside, but it is expected to
   become its own, stronger state once inspected-subnet delivery ships: not "we can't
   protect this," but "protected a different way." Copy should say so plainly, and should
   name the *temporary, external* reason (e.g. "agent coming for macOS") rather than read
   as a generic no-agent nag for something that doesn't exist yet to install.

The device-type classification needed to tell these apart is the same field this product
already uses elsewhere to distinguish IoT/fixed devices from computer-class ones — no new
classification system needed, just reuse.

## Open questions

- Exact wording/labels — not decided, this is a placeholder framing.
- Where it surfaces: device list row badge, a detail-view field, both?
- Does it need a one-time "what does this mean" explainer for first-time viewers?
- Interaction with device trust/type editing UI — does changing a device's type change its
  displayed tier?

## Connections

- `device-identification.md` — related but distinct: that doc is about *naming* unknown
  devices; this one is about *coverage status* for devices once identified.
- Depends on reliable identity reconciliation between network-observed devices and
  agent-enrolled devices when both exist for the same physical machine — a prerequisite
  this doc does not itself scope.
- Depends on a separate, not-yet-public network-architecture decision (does Nemesis
  become a gateway for isolated device segments, and how many) for state 4 above to
  become real rather than aspirational. Until that ships, state 4 displays the same as
  state 3 — accurate for now, but the label should be written so it doesn't need to change
  meaning later, just gain a stronger backing mechanism.
