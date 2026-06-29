# Pre-Escalation Support Search

> Roadmap capture — project-sized idea. Records the concept and design intent; does not
> design the implementation. Runs **before** a [support bundle](support-bundle.md) escalates
> to a human — most common issues already have an answer; find it first.

## Concept

Before generating a support ticket, the AI searches vendor documentation (and Nemesis's own
community knowledge) for an existing fix. Most common issues already have answers — surface
them before involving human support. Escalation becomes the **last** step, not the first.

## Search sources (priority order)

1. **Nemesis community feed** — fastest, already local.
2. **Official vendor KB** — highest trust.
3. **Vendor release notes / known-issues pages.**
4. **Official vendor forums.**
5. **General web search** — last resort.

## Search query — built from the issue profile

```
software name + version + error signature + OS + conflict
```

(The profile fields come from the same already-collected data the
[support bundle](support-bundle.md) assembles — software timeline, certificate, sandbox log,
AI diagnosis.)

## Result tiers

- **Nemesis already knows** → one-click fix, no search needed.
- **Vendor docs have answer** → present with citation; apply or guide.
- **Community workaround** → present with upvote count; try or escalate.
- **No solution found** → generate the support bundle with a "searched" note.

## "Searched, not found" in the support bundle

When nothing is found, the bundle records:

- **What was searched and when** — documents the attempt.
- **Tells the vendor this is genuinely new / unreported** — not a duplicate of a known KB
  article.
- **Helps the vendor improve their KB** — the search terms used are included.

This raises the signal quality of every escalation: a human only ever sees issues that have
**no** existing answer.

## Community knowledge base (self-building)

- User confirms a fix worked → contributed back to the community feed (sanitized, anonymous
  `reporter_id` per [community-reporter-identity.md](community-reporter-identity.md)).
- Over time: common issues are answered locally — no external search needed.
- **Trust signal:** "Nemesis community fix — confirmed by N users" (dedup + `times_seen`
  model per [community-signal-dedup.md](community-signal-dedup.md)).

## Custom vendor search (extensibility)

Community members add vendor support sources via a `CUSTOM_VENDOR_SEARCH.md` pattern — the
same skip-if-absent shape as the existing `CUSTOM_VPN_PROBE.md` vendor guide:

- `vendor_sources.json` registration (KB URL templates, forum endpoints, query format).
- Skip-if-absent: a vendor with no registered source falls through to general web search.
- **Definition-of-done note (when built, not now):** per the Tier-2 vendor-integration rule,
  the `CUSTOM_VENDOR_SEARCH.md` guide must ship **in the same commit** as the search code —
  interface contract, skip-if-absent pattern, a minimal `vendor_sources.json` example, where
  to register it, and any Rule-8 constraints.

## Connects to

- **AI Engine** — search orchestration + result evaluation + plain-language summary (tiered).
- **Support bundle** ([support-bundle.md](support-bundle.md)) — the "search results" /
  "searched, not found" section; this feature is the gate *before* escalation.
- **Community feed** — confirmed fixes contribute back; self-building KB.
- **Web search tool** — the underlying search mechanism (general-web last resort).
- **`CUSTOM_VENDOR_SEARCH.md`** — extensible vendor sources (mirrors `CUSTOM_VPN_PROBE.md`).

## Open questions (not resolved here)

- **Privacy on outbound search:** building the query sends software name + version + error
  signature off-box (steps 2–5). The Rule-8 sanitization gate from
  [support-bundle.md](support-bundle.md) must cover the *query*, not just the bundle — an error
  signature can leak a path/username. Single shared chokepoint.
- **Fix-worked attribution:** how a user confirms "this fix worked" and how that maps to a
  dedup'd community signal (new `community_*` type vs reuse) is undesigned.
- **Vendor-source trust/staleness:** KB URLs and forum endpoints in `vendor_sources.json` rot;
  needs a freshness/validation story.
