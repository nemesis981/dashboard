# Roadmap stub — diagnostics: AI reassurance + escalation routing (the "is-it-me-or-them" AI layer)

**Status:** parked (what + why; do NOT build yet). The AI layer on top of the deterministic
[connectivity watcher](diagnostics-connectivity-watcher-tool.md); an instance of the
[tool-aware loop](diagnostics-ai-tool-aware-loop.md) and the
[product thesis](product-thesis-built-in-it-expertise.md)'s AI-interpretation pillar.

## What
The deterministic watcher establishes the **fact** — local stack healthy vs broken. The AI
then **interprets that fact for the user at their tier AND routes the escalation**. E.g.:

> "Your Nemesis system is working normally; the issue appears to be upstream / with the
> provider. If it affects your business and persists, contact [ISP/provider] — it's on their
> side."

Two jobs, both downstream of the measured fact:
- **Reassurance / interpretation** — tell the non-expert what the green/red result *means*,
  at Beginner/Intermediate/Pro tier.
- **Escalation routing** — answer "whose problem is it?" and point the user at the right
  party (ISP, upstream provider, internal) with the evidence to back the call.

## Why
Correctly **routing the escalation** is the high-value move: it saves the non-expert from
calling/paying the **wrong** expert, and lets them make the right call **with the right
evidence** in hand. A measured "your side is fine, it's theirs" turns an anxious guess into a
defensible action.

## Reasoning / shape
- **Strict division of labor** — AI interprets / guides / routes; it does **NOT** guess the
  fact. The fact is **measured** by the deterministic watcher. Same split as the rest of the
  subsystem (deterministic establishes truth; AI explains and routes).
- **Tiered output** — same Beginner/Intermediate/Pro tiering as other AI-interpretation
  surfaces; the routing recommendation is the actionable payload.
- Depends on the watcher producing a clean local-healthy-vs-broken signal first; build the AI
  layer after that signal exists. Capture the intent + the division of labor now.
