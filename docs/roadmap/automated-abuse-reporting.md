# Automated abuse reporting — roadmap stub

- **Status:** Idea/roadmap only. Not designed in code detail, not started. Captured
  2026-08-01 (Window 2) from the ADR 0021 (DoS resilience) review.
- **Related:** [0021-dos-resilience-scoping](../architecture/0021-dos-resilience-scoping.md) —
  this is the legitimate outlet for the "make it stop" instinct a DoS/flood naturally
  provokes, positioned explicitly against the hack-back alternative considered and rejected
  below.

## What it is

When a source gets blocked, automatically file a WHOIS-based abuse report to that IP's
hosting provider/ISP abuse contact — the standard, legitimate channel for reporting a source
of attack traffic to whoever is actually positioned to act on it (the network operator
hosting the offending address), rather than anything the target itself does to the traffic.

## What it explicitly is NOT — considered and rejected

**Any form of counter-traffic or "hack back."** Considered during scoping and rejected on
three independent grounds, any one of which would be sufficient on its own:

1. **Illegal.** Unauthorized access/counter-attack against a third-party system is a crime
   under CFAA-equivalent statutes in most jurisdictions, regardless of the counter-attacker's
   intent or the original attack's severity.
2. **High risk of hitting an innocent third party.** The address sending attack traffic is
   very often a compromised machine, not the actual attacker's own infrastructure — a
   counter-action lands on that machine's owner, who is a victim, not the source.
3. **Amplification-shaped by construction.** Any response that sends traffic back toward the
   apparent source scales with the attack itself and can make a volumetric situation worse,
   not better — the opposite of the goal.

WHOIS-based abuse reporting has none of these properties: it's a report to a third party
(the hosting provider/ISP) about their own customer, not any action directed at the source
address itself.

## Design shape — builds on two existing patterns already in the codebase

- **Mirrors the existing AbuseIPDB auto-report feature (already shipped)**, generalized from
  one fixed third-party reporting service to WHOIS-derived abuse contacts — i.e. look up the
  actual network operator responsible for the offending address and report to them directly,
  rather than (or in addition to) a single aggregator.
- **Mirrors the AI Engine's Teaching Mode vs. Automated Mode pattern** — tiered approval gates
  by risk/trust level, not a single on/off switch:
  - **Ships OFF / manual by default.** The operator reviews and files (or doesn't) until
    they've built confidence in the feature.
  - **Settings toggle to enable automatic filing** once trusted.
  - **Rate-limited regardless of mode** — both to avoid flooding an abuse inbox during a
    sustained attack (many blocks in a short window should not become many separate reports),
    and to avoid becoming a nuisance-report generator if the underlying detection has false
    positives.

## Operator visibility — closing the loop (added 2026-08-01)

When a WHOIS-based abuse report is auto-filed, also send the **operator** an email
notification confirming the report was filed: who it went to (the resolved abuse contact),
when, which source IP triggered it, and the current rate-limit status. This is additive to
the design above, not a new toggle or a separate approval gate — the point is that a filed
report shouldn't just disappear into a third party's queue with nobody at Nemesis aware it
happened. The operator gets confirmation that the automated response actually occurred,
mirroring how other automated actions in the product (lockout tiers, quarantine) already
notify rather than acting silently.

## Non-goals / explicitly out of scope for this stub

- Any form of counter-traffic, active response, or action directed at the source address
  itself — see "What it explicitly is NOT" above. This is a hard boundary, not a phased-in
  future capability.
- WHOIS lookup implementation detail, abuse-contact-resolution accuracy/fallback behavior,
  and the exact rate-limit thresholds are all unscoped — this stub records the shape and the
  rejected alternative, not a build plan.
