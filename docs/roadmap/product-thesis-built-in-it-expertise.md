# North-star principle — Build in the IT department (built-in expertise)

**Status:** principle (record, don't build — this is a **prioritization filter** for all
future work, not a feature). Sits alongside the tiered-UX habit (CLAUDE.md Tier-2 §E /
`ARCHITECTURE.md` 3-tier note) and the diagnostics captures. Sharpens ADR
[0004](../architecture/0004-scan-task-orchestration.md)'s north-star ("enterprise
capability without enterprise pricing").

## The thesis
Enterprise security assumes an **IT DEPARTMENT** absorbs the complexity — connectivity,
tuning, diagnosis, alert interpretation. **Our user has none**: an owner/manager, a
family tech-helper, a tiny SMB. So **the product must BUILD IN the IT department.** Two
complementary pillars:

- **DETERMINISTIC AUTOMATION** for what is mechanizable — auto-tune, self-heal,
  structured self-diagnostics, solid routing. (No human needed; just do it correctly.)
- **AI INTERPRETATION** for what needs human-like judgment/explanation — "what does this
  mean / what do I do" — delivered **at the user's tier** (Beginner/Intermediate/Pro).

## Prioritization filter (use this to rank features)
- **Features that REPLACE IT-human labor are CORE — build deeply.**
- **Features that ASSUME IT-human competence are SECONDARY.**

This built-in expertise **IS the differentiation**: it is exactly what enterprise
products skip (their customers have humans to cover it) and exactly what makes the
product usable by the **non-expert market those products ignore**.

## Why it matters / how to apply
- It is a **lens for every roadmap decision**, not a thing to build once. When two
  features compete, the one that removes a "you need an admin for this" assumption wins.
- It explains *why* several existing captures are CORE rather than nice-to-have:
  - **Adaptive link-aware agent behavior + clock sync**
    ([roadmap](adaptive-link-aware-agent-clock-sync.md)) — the agent **self-tunes** to a
    bad link instead of expecting an admin to hand-tune timeouts: the deterministic-
    automation pillar made concrete.
  - **AI alert/incident interpretation at tier** — the AI-interpretation pillar.
  - **Structured self-diagnostics** (the diagnostics captures) — mechanized triage that
    an IT person would otherwise do by hand.
- **Diagnostic corollary** (recurring this weekend): connect/login failures are often
  **environmental, not logic** — an IT department would know to check the link first; the
  product must encode that instinct (instrument latency/clock at connect, attribute
  LATENCY vs LOGIC) so the non-expert user isn't left chasing phantom bugs.

## Shape / next
Capture as the guiding principle now. It may later **graduate** into `ARCHITECTURE.md`
(durable product-vision section) or a dedicated ADR once it has shaped enough concrete
decisions to be worth pinning durably. Until then it lives here as the prioritization
lens applied to roadmap items.
