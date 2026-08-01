# ADR 0021 — DoS Resilience: Availability and Detection Integrity Under Load

- **Status:** **Captured — preliminary scoping pass only** (2026-08-01). Direction not yet
  decided; no code changed. The real hardening work is deliberately deferred to a later pass
  (post memory-injection work, once most alert features are complete) — this ADR records the
  problem shape and existing state, not a build plan.
- **Date:** 2026-08-01
- **Affects:** the dashboard's network-facing surfaces (HTTP front end, enrollment
  endpoint), SSH, the alert/ticket pipeline, `install.sh` (a host-defense provisioning gap
  identified during this pass)
- **Depends on / Related:**
  [0019-deterministic-enforcement-point](0019-deterministic-enforcement-point.md) — the
  owned-nftables enforcement point is the natural implementation site for any future
  network-layer rate-limiting, and this ADR's findings depend directly on ADR 0019's own
  conclusion that today's perimeter firewall does not meaningfully apply to tailnet-sourced
  traffic;
  [0003-database-resilience-and-recovery](0003-database-resilience-and-recovery.md) — this
  ADR extends that ADR's "protection availability is first-class" design principle from
  database resilience to network/service availability and detection-pipeline correctness
  under load.

> **Full findings kept private per Rule 10 (exact thresholds and test parameters reveal
> where defenses break, which is attacker-relevant precision, not architectural direction).**
> This ADR records the problem framing, the categories of what exists and what's missing,
> and the honest boundary of what a self-hosted box can defend against. Full detail,
> including the existing configuration's exact numbers and the adversarial test that
> informed it: `~/work/nemesis-internal/dos-resilience-scoping-audit-2026-08-01.md`.

---

## Context (safe to state publicly)

Two distinct concerns were raised, and this ADR treats them as separate failure modes
because a fix for one does not cover the other:

1. **Availability under flood** — can Nemesis's own network-facing services and the
   business processes running alongside them (e.g. a POS system on the same box or network)
   stay up and keep functioning during a volumetric attack attempt?
2. **Detection integrity under flood** — does Nemesis's own alerting/enforcement pipeline
   keep working *correctly* under load, or can a flood degrade its ability to notice a real
   intrusion timed underneath it, while the system's own attention is consumed by the flood?

These are treated separately deliberately: a defense that keeps the network up (rate-limiting
requests, for example) says nothing about whether the alert/ticket pipeline can still tell a
genuine incident apart from flood noise, and vice versa.

## Findings (safe to state at a category level)

- **Application-layer request-rate and concurrent-connection limiting already exists** on
  the dashboard's own HTTP front end (login and general dashboard traffic), and a
  repeat-offender response mechanism already exists for SSH. Both were informed by a prior
  internal adversarial test against this reference deployment. Exact rates, burst
  allowances, and the test's own traffic profile are kept private — see the pointer above.
- **This protection exists only on the reference deployment, not in the standard
  installer.** A fresh customer install today does not receive any of it. This is the single
  largest concrete gap this pass identified, and closing it — bringing this protection into
  `install.sh` so every deployment gets it by default — is the natural anchor of the later
  hardening pass.
- **The alert/ticket-creation pipeline currently has no volume-based deduplication or rate
  cap.** A flood of triggering events can create a proportional flood of tickets, with
  nothing to collapse repeats or distinguish "one volumetric event" from "many independent
  real findings." This is a real, architecturally-scoped risk to an operator's ability to
  notice a genuine incident during an attack, independent of whether the network itself
  stays up.
- **Some of Nemesis's own defenses are themselves a potential availability risk**, separate
  from any external attacker — an aggressive repeat-offender response, applied without
  sufficient allowlisting, can lock out a legitimate party (an IT contractor, a vendor's
  remote support session, the operator's own workstation) until an administrator manually
  intervenes. This belongs in the same threat model as external flood risk, not as a
  separate category, because the effect on availability is the same either way.
- No dedicated volumetric-attack detection exists in the network intrusion-detection layer
  today — that layer is scoped to intrusion/malware detection, a reasonable division of
  labor, but not one that should be assumed to also cover this concern.

## The realistic boundary (a commitment, not a hedge)

**True volumetric/bandwidth-exhaustion attacks large enough to saturate a deployment's own
internet uplink are outside what any self-hosted, on-premises box can solve — full stop.**
No firewall rule, no application-layer rate limit, no service configuration running on the
box itself can do anything about traffic that is already saturating the link into the
building. That is squarely the responsibility of upstream network infrastructure — an ISP-
level mitigation, or a cloud-based scrubbing service in front of a public-facing address.

This boundary is stated here deliberately and should be communicated honestly to customers:
Nemesis's positioning (self-hosted, affordable, enterprise-capable security) must never
imply it can absorb an attack class that exists specifically because it requires
infrastructure a single on-premises appliance cannot provide. What this ADR scopes is
Nemesis's own service availability and detection correctness under moderate,
application-reachable load — not a substitute for upstream network resilience.

## Explicitly NOT solved by this ADR

Recorded here so it is not later mistaken for something this pass covered:

- Network-layer rate-limiting for tailnet-sourced traffic is not solved — it depends on
  ADR 0019's enforcement point reaching a cutover increment not yet started; adding rules
  against today's perimeter firewall for that traffic class would very likely be a no-op.
- Bringing the existing application-layer protections into the standard installer is not
  scheduled by this pass — identified as the largest gap, not yet built.
- A real design for distinguishing a volumetric event from a genuine flood of independent
  findings in the alert/ticket pipeline is not designed here — only the gap is named.
- Load-testing of the network intrusion-detection layer's own capacity under sustained
  volume was not performed in this pass (config was read; behavior under real load was not
  measured) and remains open.

## Shape / next

Captured as the scoping record now. The real hardening pass — deciding what to build, in
what order, and against what measured thresholds — is intentionally deferred until after the
memory-injection work resumes and most alert features are complete, per the operator's own
stated sequencing. This ADR should not be read as build-ready; it exists so the two failure
modes, the current honest state, and the infrastructure boundary are on record before that
later pass begins, rather than being rediscovered from scratch.
