# ADR 0015 — Guest Self-Service Enrollment (Venue)

- **Status:** **ACCEPTED — CAPTURE ONLY, direction decided, NOT built** (2026-07-26). No code
  changed by this ADR; needs a dedicated build-spec pass (the way
  [enrollment-modes-build-spec.md](../roadmap/enrollment-modes-build-spec.md) turned ADR 0012
  into a buildable spec) before it's buildable.
- **Date:** 2026-07-26
- **Affects:** the venue-tier enrollment flow, ADR 0012's **VENUE AUTO** mode (this ADR is the
  concrete enrollment mechanism that mode needs), future `enrollment_tokens`/`agent_devices`
  schema, captive-portal UX.
- **Depends on:** [ADR 0011 — enrollment security model](0011-enrollment-security-model.md)
  (the model explicitly **not** reused as-is — see below); [ADR 0012 — enrollment trust
  modes](0012-enrollment-trust-modes.md) (**VENUE AUTO** — the closer relative; this ADR
  specifies its enrollment mechanism); [ADR 0009 — security inspection proxy](0009-security-inspection-proxy.md)
  (guest devices get standard Tier 1/2/3 detection — see Decision).
- **Related:** [venue-guest-network.md](../roadmap/venue-guest-network.md) (existing parked
  roadmap stub — **flagged tension**, see below); [enrollment-modes-build-spec.md](../roadmap/enrollment-modes-build-spec.md).
- **Rule 8:** placeholders only (`<room-number>`, `<last-name>`, `<pms-account>`). No real guest
  data, no real venue names.

> Capture only — design of record for the venue guest enrollment *mechanism*. No code.

## Problem

New market direction (2026-07-26, additive to the existing home/SMB thesis, not a replacement):
a **venue variant** (hotels, boutique properties, event venues). Research motivating it:
hospitality's guest-onboarding vendors (captive portal/QR/marketing capture) and hospitality's
security vendors are **separate markets today** — nobody found combines frictionless guest
onboarding with real deep behavioral/zero-day detection of guest devices. That gap is the
opportunity.

**[ADR 0011](0011-enrollment-security-model.md) cannot be reused as-is.** Its model — TOFU
hardware fingerprinting + a human reviewing a per-device review card — assumes an admin
manually approves each device. That does not scale to walk-in guests arriving at volume with no
admin present.

**Note: ADR 0011 is not actually the closest existing model here — [ADR 0012](0012-enrollment-trust-modes.md)
already is.** ADR 0012's **VENUE AUTO** mode (2026-07-01) already designed "unattended batch
auto-enroll into a guest/monitored tier that is explicitly NOT trusted," bounded by a
campaign (count/window/subnet), with its own audit log and TTL/auto-de-enroll-on-absence
lifecycle. This ADR does not reinvent that — it **specifies the actual self-service enrollment
mechanism** a VENUE AUTO campaign uses in the venue-tier product, and adds two refinements
VENUE AUTO left generic.

## Decision

### The mechanism: QR code / captive portal, matching the hospitality-industry pattern
Self-service enrollment via **QR code scan** or a **captive-portal form** (room number + last
name, or a pure QR scan) — the same UX pattern guests already expect from hotel/venue WiFi
generally. This is a **VENUE AUTO** (ADR 0012) campaign under the hood: bounded, self-expiring,
auditable, admitting into the guest/monitored tier — never the trusted tier.

### Refinement 1 — time-boxed trust, concrete hard-expiry trigger
ADR 0012 specified VENUE guest enrollments as TTL'd with **auto-de-enroll on absence** (aging
out a guest who stops appearing). This ADR adds a concrete, venue-specific **hard expiry: at
minimum, revoke at checkout.** **PMS-integration-triggered revocation** (an automatic pull/push
from the property-management system at actual checkout time) is a valid **future enhancement,
NOT required for v1** — v1 can run on a manually-configured stay-duration TTL (e.g. checkout
date entered at enrollment) if no PMS integration exists yet.

### Refinement 2 — no special posture for frictionless enrollment
Guest devices get the **STANDARD tiered detection** (Tier 1/2/3, per the [ADR 0009
addendum](0009-security-inspection-proxy.md)) — **no special trust, no looser posture** just
because enrollment was frictionless. A newly-enrolled guest device starts **COLD** in the
existing dynamic-trust-cache model (ADR 0009 addendum §4), exactly like any other new device.
Enrollment friction (or the lack of it) has **zero bearing** on detection rigor — this is stated
explicitly because "self-service" could easily be misread as "lighter-touch security," which is
not the decision.

## Why this is a distinct model from ADR 0011, not a replacement of it

ADR 0011's manual-approval flow (a human reviewing a review card per device, informed by
TOFU-locked fingerprint + server-observed source IP) is **correct** for a home/SMB owner
enrolling owned or known hardware, and **stays exactly as-is for non-venue deployments** — this
ADR does not touch it. It is **wrong** for admitting anonymous walk-in guest hardware at volume,
where no admin is realistically available to review each device. This ADR adds a **parallel,
venue-scoped path** (already sketched at the mode level by ADR 0012's VENUE AUTO) rather than
modifying ADR 0011's default.

## Flagged tension — NOT resolved here

[venue-guest-network.md](../roadmap/venue-guest-network.md) is an existing parked roadmap stub
that **pre-dates this ADR** and frames guest enrollment differently: **"the app IS the access
credential — no app = no WiFi,"** implying a Nemesis-branded guest **app install** is mandatory,
with the mobile agent (V2/V3, not started) as a hard dependency.

Today's QR/captive-portal direction does **not** require an app install to serve as the
enrollment credential — a browser-based captive-portal submission may be sufficient, with an
installed app being an optional value-add (persistent protection after the visit, the
"user-acquisition funnel" angle already captured in that stub) rather than the enrollment
mechanism itself.

**This is a real, unresolved tension between the two documents.** It is flagged here, not
silently reconciled: `venue-guest-network.md` should be revisited to either update its framing
to captive-portal-first (app optional), or explain why the app-as-credential model still holds
for the fuller mobile-agent-based vision it describes. Until that happens, treat the two docs as
describing **overlapping but not-yet-reconciled** guest-enrollment visions, not a single agreed
design.

## Open items (explicitly not resolved)

- **PMS-integration-triggered revocation** — future enhancement, no design yet, not v1.
- **Whether a guest app is required at all**, or captive-portal-only enrollment suffices for
  v1 — unresolved; see the flagged tension above.
- **Concrete schema/API design** — new `enrollment_status`/mode values, the captive-portal
  route itself, room-number/last-name lookup (against a PMS or a manually-entered guest list) —
  not designed here. This ADR is direction-only, matching today's other capture-only work; a
  build-spec pass (mirroring `enrollment-modes-build-spec.md`'s treatment of ADR 0012) comes
  later.
- **Mobile-agent dependency scope** — `venue-guest-network.md`'s outbreak-detection/inspection-
  tunnel benefits assume the mobile agent exists (V2/V3, not started). This ADR's *minimum*
  viable guest enrollment (captive-portal auth into the monitored tier) does not strictly
  require the mobile agent; full Tier 1/2/3 coverage of WiFi-origin guest traffic still depends
  on the existing L3/inspection-tunnel machinery (ADR 0009), which itself remains unbuilt.

## Status / next

Capture-only, direction decided, **not built**. Next step (not started): a dedicated build-spec
pass once the app-vs-captive-portal tension above is resolved by the operator — building before
that would risk designing schema/API around the wrong assumption.
