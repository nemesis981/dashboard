# ADR 0016 — Guest Marketing Capture (opt-in export module)

- **Status:** **ACCEPTED — CAPTURE ONLY, direction decided, NOT built** (2026-07-26). No code
  changed. **⚠ REAL LEGAL REVIEW REQUIRED BEFORE ANY BUILD WORK on the PII-collection half of
  this module** — do not treat this as a routine feature decision (see Compliance flag below).
  The PII-transit **monitoring** addendum (§ below) is not gated on that legal review — it can
  be scoped/built independently, once the export API itself exists.
- **Date:** 2026-07-26
- **Affects:** introduces a genuinely new data category (guest PII: name/email) into Nemesis;
  new captive-portal consent step (shared with [ADR 0015](0015-guest-self-service-enrollment.md));
  new export API + scoped per-consumer API keys; new retention/deletion policy requirement.
- **Depends on:** [ADR 0015](0015-guest-self-service-enrollment.md) (the captive portal is the
  capture point); [ADR 0006 — Data Manager](0006-data-manager.md) (local storage + access
  control for the captured PII); [ADR 0009 — security inspection proxy](0009-security-inspection-proxy.md)
  (Tier 1 behavioral engine, reused at a new chokepoint — see PII-transit addendum below).
- **Related:** [venue-guest-network.md](../roadmap/venue-guest-network.md) (business-model note
  added same-day — see that file, not duplicated here); [msp-central-management.md](../roadmap/msp-central-management.md)
  (future multi-site PII-transit case — see addendum §3).
- **Rule 8:** placeholders only (`<venue-api-key>`, `<guest-email>`, `<consumer-id>`). No real
  guest PII, no real venue/vendor names, ever, in this doc or its descendants.

> Capture only — design of record + an explicit non-goal list. No code, and this module must
> not be built before the legal review named above.

## Problem / motivation

Same market research as [ADR 0015](0015-guest-self-service-enrollment.md): hospitality's
guest-onboarding/marketing-capture vendors and hospitality's security vendors are separate
markets. This module lets Nemesis's venue offering also capture the marketing-capture value —
**additive** to the core security thesis, not a pivot into being a marketing platform.

Once this module exists, Nemesis holds a genuinely new kind of data: **guest PII (name/email)**,
distinct from everything else in Nemesis's threat-model-driven data (which is about detecting
attacks, not collecting information about the people using protected networks).

## Decision

### Opt-in, explicit consent
Name/email capture at the captive portal, with **explicit opt-in consent** — **not implied by
connecting to WiFi.** Connecting to guest WiFi and consenting to marketing capture are two
separate acts; the captive-portal flow must not conflate them (e.g. no pre-checked consent box,
no "by connecting you agree").

### Export-only design (explicit non-goal)
Nemesis **captures and hands data off** via a documented, access-controlled export API —
scoped API keys per consumer (per-venue, per-downstream-system credentials, never one shared
key). **Nemesis explicitly does NOT:**
- send emails,
- run marketing campaigns,
- become a marketing/ESP (email service provider) platform itself.

This is a hard non-goal, not a "not yet" — stated so a future session doesn't drift the module
toward becoming an ESP.

### Retention/deletion policy — required, not optional
A retention/deletion policy **ships with the module**, not deferred to a later pass. (Concrete
retention period/deletion trigger — not specified here; this ADR states the requirement, the
build-spec pass sets the actual policy.)

### Compliance flag — this is a new, distinct compliance surface
This is a **new compliance surface for Nemesis** — GDPR/CCPA/CAN-SPAM-adjacent — categorically
different from anything else in Nemesis's threat model. **Needs real legal review before
shipping.** This is stated in the status line above deliberately, not buried in prose, so it
can't be missed on a skim of this ADR.

## Business model note (captured here, full detail lives in the roadmap doc)

Full detail: [venue-guest-network.md](../roadmap/venue-guest-network.md) Business model
section, updated same day — not duplicated here. Summary: custom per-venue integration work
(wiring exported data into a specific venue's other systems) is a **possible paid service** Paul
could offer, but **not required** — the export API should be documented well enough that any
programmer (the venue's own, or one they hire) can build the integration themselves.
**Unconfirmed, needs a lawyer, not a settled fact:** this likely shifts **some** liability for
downstream data handling to the venue/their programmer once data leaves via the documented
export API. This ADR states that reasoning as **flagged and unconfirmed** — it must not be
treated as a guaranteed liability shield in any future doc or decision that cites this one.

## Forward-looking note — future direction only, NOT built now

The export layer could eventually consolidate a venue's broader onsite-software needs (multiple
downstream systems drawing from one governed data layer) rather than being single-purpose
marketing export. **This is documented as future direction only.** **v1 scope is ONE export
surface** (guest marketing data only), designed so a second consumer/scope is a **config
addition later, not a rearchitecture** — do NOT build a generic multi-consumer hub now. Stated
explicitly so a future session doesn't over-engineer v1 in anticipation of a need that isn't
confirmed.

---

## Addendum — PII network-transit monitoring

Since Nemesis will hold PII (guest name/email) once this module exists, this addendum covers
protection at the specific points PII actually crosses a network. It does **not** cover local
(no-network-hop) PII handling — see Scope discipline below.

### 1. Captive portal submission (guest device → Nemesis)
Standard web-security hygiene: input validation, rate limiting. **Not** zero-day/packet-analysis
territory — there is no adversary payload to catch in a first-party form submission; this is a
routine web-app-security concern, not a detection-engine concern.

### 2. Export API (Nemesis → downstream consumer) — where the added protection matters
Reuse the **existing Tier 1 behavioral-anomaly engine** ([ADR 0009 addendum](0009-security-inspection-proxy.md#0-three-tier-structure)
§1–5), scoped to this specific chokepoint:
- **Volume anomalies** — a bulk pull of the whole guest table vs. a normal handful of rows.
- **Destination/consumer anomalies** — an unused credential suddenly used; a new destination.
- **Rate anomalies.**

**Explicitly NOT routed through Tier 2's undetectable-inline machinery.** Tier 2 solves a
different problem — catching malicious **third-party** payloads hiding in traffic. There is no
equivalent "hidden attacker" concern in Nemesis's own structured API traffic to itself; applying
Tier 2 here would be solving a problem that doesn't exist at this chokepoint.

### 3. Future note, not built: multi-site/MSP aggregation
Any multi-site/MSP aggregation (already on the commercial backlog —
[msp-central-management.md](../roadmap/msp-central-management.md)) is where PII would genuinely
transit a **real inter-site network** — flagged as the **strongest future case** for this
protection, not built now.

### Scope discipline — do not over-scope
**Most PII reads/writes are LOCAL** (single-box SQLite via the Data Manager — no network hop at
all). This addendum is **not** "inspect every DB read/write" — most reads/writes have no network
transit to inspect in the first place. The Data Manager's existing access-control-by-prefix and
audit log ([ADR 0006](0006-data-manager.md)) already cover the local case; what's being added
here is specific to the **two real network chokepoints above only.**

## Status / next

Capture-only, direction decided, **not built**. Hard prerequisite before any build work on the
PII-collection half: **legal review** (see status line). The PII-transit monitoring addendum can
be scoped/built independently once the export API itself is built — it has no separate legal
gate of its own, only the underlying PII collection does.
