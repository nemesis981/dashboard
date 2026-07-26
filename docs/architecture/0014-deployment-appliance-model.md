# ADR 0014 — Deployment Architecture: Appliance Model

- **Status:** **ACCEPTED — CAPTURE ONLY, direction decided, NOT built** (2026-07-26). No code
  changed by this ADR.
- **Date:** 2026-07-26
- **Affects:** primary SMB/venue deployment target, hardware-sizing assumptions, `ROADMAP.md`'s
  Windows Support Status section (updated same-day — see below), `SETUP_WINDOWS.md` /
  `SETUP_LINUX.md` (unchanged; still accurate for the retained home-user VM path).
- **Depends on:** none blocking. **Informs but does NOT resolve** [ADR 0009 addendum Open Item
  3](0009-security-inspection-proxy.md) ("no target hardware baseline exists") — see below.
- **Related:** [hardware-stable-identifiers.md](../roadmap/hardware-stable-identifiers.md) (the
  `is_virtual` detection the VM path still relies on); [nemesis-test-lab.md](../roadmap/nemesis-test-lab.md).
- **Rule 8:** no real IPs/hosts/vendor account info; none used in this doc.

> Capture only — records the decision and reasoning. No code, no hardware purchase, no build.

## Source-material note (read this before trusting the "Problem" section below)

This ADR is written from the operator's same-day (2026-07-26) design-session summary
(`/areas/nemesis-firewall.md`, an external tracking doc **not accessible from this repo/session**
— per instruction, the operator's summary is used as source of truth for what changed). The
summary references "the locked June 22 release sequence (item 2, 'Windows/VM support')" as the
plan this decision reverses. **That document was searched for and not found anywhere in this
repo** (`ROADMAP.md`, `docs/architecture/`, `docs/roadmap/`, `docs/business/`, `docs/specs/`,
and `git log` around 2026-06-20 → 2026-06-24 for docs commits) — it most likely lives only in
the external tracker. The nearest in-repo analog is `ROADMAP.md`'s **"Windows Support Status"**
section, last substantively touched 2026-06-24 (`638407b`, "Mark Windows/VM path as
in-development, recommend Linux native for v1.0") — **that** section is what this ADR updates
in-repo to reflect today's decision. If the external "item 2" language differs materially from
what's captured here, reconcile against the external doc, not this note.

## Problem

The plan on record (per the operator's summary of the external release sequence, and consistent
with `ROADMAP.md`'s prior Windows Support Status framing) treated **a customer's general-purpose
Windows machine, running the full Nemesis stack in a hosted VM,** as a real primary path for
non-Linux-native SMB/venue customers — alongside a dedicated Linux box. This creates two
problems at SMB/venue scale:
- Nemesis has to coexist with **arbitrary proprietary SMB software** (POS/PMS/etc.) on a shared
  general-purpose Windows box — an unbounded compatibility surface.
- Hardware sizing has to target **arbitrary customer hardware** instead of one known platform.

## Decision

A **dedicated Linux appliance** (a mini PC, purpose-run — not a customer's general-purpose
machine) becomes Nemesis's **primary deployment form factor for SMB/venue customers**. This
matches how other serious home/SMB network-security products already ship (Firewalla,
pfSense/OPNsense appliances) — a known, purpose-built box, not "install our stack alongside
whatever else is on this Windows machine."

### Scope narrowing this produces
**Only the agent needs cross-platform compatibility** — already built (the psutil-based unified
Nemesis Agent, Windows/Mac/Linux). **The server/dashboard/detection stack itself does not need
to be cross-platform** — it only needs to run on the appliance's Linux target. This is a real
narrowing of the engineering surface, not just a marketing/packaging change: no more "make the
full stack coexist inside a Windows-hosted VM" as an engineering requirement for the primary
path.

### Home-user path — RETAINED, not replaced
For users who want to run on hardware they already own rather than buy/run a dedicated
appliance, the existing **VM-with-bridged-networking approach** (VirtualBox, wired ethernet,
bridged NIC — as documented today in `SETUP_WINDOWS.md`) **stays exactly as-is.** This was
deliberately re-researched today and **confirmed as the correct mechanism**, not just left alone
by default:
- **WSL2 — rejected.** Cannot do genuine LAN-wide promiscuous packet capture; the NIC is
  virtualized by design.
- **Hyper-V — rejected.** Requires Windows Pro and isn't simpler than VirtualBox — no win to
  justify switching.
- **Dual-boot — rejected.** Gives full native NIC access, but only protects the network while
  the user has specifically booted into Linux instead of Windows — defeats always-on
  protection, which is the whole point.

**Decision: do not reinvent this networking mechanism.** Treat it as solved; package it more
invisibly for the user, not replace it.

**Resource-overhead objection closed, not just deferred:** modern consumer hardware has enough
memory/CPU headroom that the VM's overhead is a non-issue in practice. This is stated explicitly
so a future session doesn't re-open "the VM is too heavy" as a reconsideration — it was
evaluated today and closed.

### Third valid option — repurposed personal machine, Linux full-time
A personal machine repurposed to run Linux full-time (no dual-boot back to Windows) is
**functionally identical to the appliance model** — just customer-sourced hardware instead of a
Nemesis-recommended/sold mini PC. Worth naming explicitly: it gets the appliance model's
engineering simplicity (one known-OS target, no coexistence problem) without requiring a
purchase.

## What this reverses (state plainly, not silently)

**This is a genuine reversal of part of the prior plan**, not an additive refinement:
- **OLD:** Windows/VM support treated as a primary path — implying the full stack running
  inside a VM on a customer's general Windows box was a first-class target alongside dedicated
  Linux hardware.
- **NEW:** Windows/VM support narrows to **(a) agent compatibility** (already shipped, no change
  needed) **+ (b) an optional home-user VM path** (retained, unchanged mechanism, demoted from
  "primary path candidate" to "option for users who'd rather use hardware they own"). The
  **appliance model is the new primary SMB/venue target.**

`ROADMAP.md`'s "Windows Support Status" section is updated same-day to reflect this narrowing —
see that file's diff, not duplicated here.

## Relationship to ADR 0009 addendum Open Item 3 (do not conflate)

The [2026-07-25 ADR 0009 addendum](0009-security-inspection-proxy.md) named **"no target
hardware baseline exists"** as an open item blocking real session estimates for the L3
zero-day/TLS/Tier-3 scoping work. Today's decision **informs but does not resolve** that item:
it establishes **what kind of platform** is being sized for (a dedicated mini-PC-class Linux
appliance, not arbitrary customer hardware) — it does **not** pick an actual SKU, CPU/RAM spec,
or vendor. Real hardware-baseline work (the actual spec Open Item 3 needs) remains open and
unstarted.

## Open items (explicitly not resolved here)

- **Appliance SKU/vendor sourcing** — not decided. Whether Paul sells a specific pre-configured
  mini PC, recommends a spec for self-sourcing, or both — TBD.
- **Pricing/bundling model for the appliance** — TBD; not part of this ADR (business-model
  pricing lives in `product-thesis-built-in-it-expertise.md`, not duplicated here).
- **ADR 0009 Open Item 3 (hardware baseline)** — still open, as above; this decision is a
  prerequisite input to that work, not a substitute for it.

## Status / next

Capture-only, direction decided, **not built**. No code, no purchase, no install-doc rewrite
beyond the `ROADMAP.md` status-section update landing same-day. Next step (not started): a
roadmap stub for actual appliance sourcing/sizing, once real target-hardware work begins.
