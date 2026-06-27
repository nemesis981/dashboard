# Roadmap stub — diagnostics: AI must be TOOL-AWARE (the operating loop)

**Status:** parked (operating model for the diagnostics subsystem — what + why; do NOT
build yet). Ties together ticketing + error codes + watcher/tools + tiered reports into one
loop. Sits with the other diagnostics-thread stubs
([connectivity watcher](diagnostics-connectivity-watcher-tool.md),
[Anthropic status banner](diagnostics-anthropic-status-banner.md),
[scan scope](diagnostic-scan-scope.md)) and is the operating model the
[product thesis](product-thesis-built-in-it-expertise.md) implies.

## What
AI diagnostic calls are given a **structured catalog of available diagnostic tools** — for
each tool: what it checks, which symptoms/error-codes it's relevant to, and what it outputs.
With that catalog the AI runs a **targeted, iterative, hypothesis-driven loop** instead of a
wasteful full-data-dump:

```
symptom/ticket seed
  (watchdog auto-ticket + user's experience description
   + ticket module's prior-similar-issue search)
    → AI (tool-aware) recommends SPECIFIC tools to run
      → tools produce a FOCUSED report + error codes
        → AI narrows hypothesis
          → repeat, BOUNDED (a few iterations)
            → resolution  OR  escalate
```

On **escalation, the iterative trail IS the focused support bundle** for a human/pro — the
narrowed hypothesis + the specific tool outputs that got there, **not a raw dump**.

## Why
Mirrors how a real expert actually works: hypothesis → targeted test → narrow → repeat.
Properties that fall out of it:
- **Efficient** — no full-data dumps; the AI only pulls what the current hypothesis needs.
- **Accurate** — hypothesis-driven, so each step is motivated by the prior result.
- **Cheap** — bounded iterations + focused inputs keep token/compute cost down.
- **Degrades gracefully** — if the loop doesn't resolve, the same trail becomes the support
  bundle, so a dead-end still produces value for the human who picks it up.

## Reasoning / shape
- **The catalog is the enabling artifact** — tools must be described in a machine-consumable
  way (purpose, symptom/error-code mapping, output shape). This is what makes the AI
  "tool-aware" rather than guessing.
- **Bounded loop** — cap iterations so it can't spin; escalate on the cap, not on infinity.
- **Reuses existing pieces** — watchdog auto-tickets, the ticket module's prior-similar-issue
  search, error codes, and the watcher/tools as the catalog's first entries. This stub is the
  loop that wires them together; build it after enough tools exist to be worth cataloguing.
- Capture the operating model now; defer the catalog schema + loop controller until scheduled.
