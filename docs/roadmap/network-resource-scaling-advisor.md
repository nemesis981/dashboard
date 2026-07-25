# Roadmap stub — Network resource scaling advisor

**Status:** parked (what + why; do NOT build yet). Captured 2026-07-25, same session as the
[ADR 0009 L3 addendum](../architecture/0009-security-inspection-proxy.md) and the
[product-thesis business-model capture](product-thesis-built-in-it-expertise.md).

**Relationship to [nemesis-overhead-meter.md](nemesis-overhead-meter.md) — flagged distinction,
not a merge.** Step 0 of today's session explicitly checked whether this duplicates the
overhead-meter capture. Judgment call: **they're genuinely distinct**, so this is a new file, not
an expansion of that one — flagging the reasoning here so the operator can override if they'd
rather these be one file:
- **nemesis-overhead-meter.md** = **Nemesis's own footprint** (per-service CPU/mem of the
  Nemesis processes themselves) — a self-diagnostic for leak detection and "is Nemesis the
  problem" trust/transparency.
- **This file** = **the CUSTOMER's network/resource usage** (traffic volume, device count,
  inspection load) — a capacity-planning advisor for "does this deployment need more hardware/
  bandwidth as the network grows."
- They likely share measurement plumbing (`psutil`-style sampling, a durable trend table) and
  could reasonably feed a shared dashboard surface — but the *question each answers* is
  different (self-health vs. customer-capacity), so they're captured separately for now.

## What
Deterministic, local measurement of **real network/resource usage** — no AI required for the
measurement itself. Recommends when more hardware, bandwidth, or (for cloud-hosted deployments)
a larger instance size is warranted as a customer's network grows.

## Why
Directly operationalizes the [resource philosophy](product-thesis-built-in-it-expertise.md#resource-philosophy)
captured today: Nemesis targets low server cost relative to network size and low per-device
agent cost, but **accepts that some additional hardware/bandwidth is a fair, expected cost of
scale** — and the product's job is to communicate that transparently, not hide it or promise
infinite free scaling.

## Reasoning / shape
- **Deterministic, local measurement — no AI required.** Real usage metrics (bandwidth,
  connection volume, inspection-queue depth, device count vs. current headroom) are gathered
  and evaluated with fixed thresholds/rules, consistent with the AI-strictly-optional principle
  captured in the same session's product-thesis update.
- **Optional AI narration layer** — translates the raw metrics + recommendation into a
  plain-language explanation ("your network has grown to N devices; current hardware is at X%
  capacity; consider Y"). Same optional-only shape as the post-detection AI explanation
  principle — the underlying recommendation is generated deterministically either way; AI only
  narrates it.
- **Applies to both deployment shapes:**
  - **Physical hardware** — recommend a hardware upgrade/replacement when the current box is
    the bottleneck.
  - **Cloud-hosted deployments** — recommend an elastic resize (larger instance tier) when
    usage warrants it; this is the cloud-native equivalent of the same advisory.
- **Not yet specified (flesh out at spec time):** exact metrics tracked, sampling cadence,
  threshold values that trigger a recommendation, and whether recommendations are purely
  informational or link to an actual upgrade/resize action.

## Open dependency
Like the two ADR 0009 scoping docs from this session, meaningful thresholds here depend on
having **a target hardware baseline** (minimum customer-hardware spec, mini-device SKU) —
without a baseline, "warranted" has no reference point to measure against. Same open item as
[adr-0009-l3-behavioral-trigger-scope.md](adr-0009-l3-behavioral-trigger-scope.md) and
[tls-interception-sterilization-scope.md](tls-interception-sterilization-scope.md) flag.
