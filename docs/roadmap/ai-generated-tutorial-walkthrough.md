# AI-Generated Tutorial Walkthrough

> Roadmap capture — project-sized idea, **ships with v2**. Records the concept and design
> intent; does not design the implementation. The tutorial is **generated, not authored** —
> it regenerates when features change, so it is always current.

## Concept

The AI generates a complete, up-to-date tutorial walkthrough of all features automatically.
Not a static document — it regenerates when features change. Always current.

## Sources (the AI reads these to generate the tutorial)

- All `CUSTOM_*.md` guides (feature extension points).
- All `docs/operation/` files (operational procedures).
- All `docs/modules/` files (module documentation).
- `PUNCHLIST.md` (what's in v1 vs v2 vs deferred).
- The tiered-output principle (generates 3 versions).

> **Current source-corpus reality (2026-06-29):** the inputs exist but are **thin** — only
> `docs/modules/diagnostics/` carries module docs, and the only `CUSTOM_*.md` guide is
> `docs/modules/diagnostics/CUSTOM_VPN_PROBE.md`. Generated today, the tutorial would cover
> diagnostics and not much else. This is *the point* of the completeness bonus below: the
> generator's coverage is a direct measure of how documented the product is.

## Output tiers (same tiered-output principle)

**BEGINNER WALKTHROUGH** — "Getting Started with Nemesis Firewall"
- Plain language, no jargon, screenshots described.
- "Here's what to do first... then this... then this."
- Assumes: can follow instructions, doesn't know security.

**INTERMEDIATE WALKTHROUGH** — "Understanding Your Security Dashboard"
- Explains what things mean, not just what to click.
- "This alert means... this setting controls..."
- Assumes: motivated to learn, some computer confidence.

**PRO WALKTHROUGH** — "Nemesis Firewall — Complete Feature Reference"
- Technical detail, architecture context, CLI commands.
- "The malware-canary service monitors... the Data Manager ensures... the inspection proxy
  routes..."
- Assumes: developer or IT professional.

## Format

- Interactive in-dashboard walkthrough (step-by-step tooltips).
- Downloadable PDF (printable, shareable).
- Video script (for future screencasts).

## Regeneration trigger

- New feature shipped → AI regenerates affected sections.
- Major version bump → full regeneration.
- On-demand → admin can regenerate from Settings.

## AI prompt structure

```
"Read the following feature documentation and generate
 a [Beginner/Intermediate/Pro] tutorial walkthrough.
 Tone: [friendly/informative/technical].
 Assume the user has just installed Nemesis.
 Walk them through every feature in logical order.
 For each feature: what it is, why it matters,
 how to use it, what to expect."
```

## Interactive walkthrough (in-dashboard)

- First login → "Would you like a guided tour?" `[Yes, show me around]` `[I'll explore on my own]`
- Step-by-step tooltips highlighting each feature.
- Progress indicator: "Step 4 of 12."
- Can pause and resume.
- Tier-appropriate language (detected from user preference).

## Connects to

- **Tiered output system** (Beginner/Intermediate/Pro — CLAUDE.md Tier-2 §E / `ARCHITECTURE.md`
  3-tier note).
- **All module documentation** (`docs/modules/`, `CUSTOM_*.md`) — source material.
- **AI Engine** — the generator.
- **Settings → tier preference** — determines which version is shown.
- **Transparency audit** — the tutorial covers every feature, which is itself audit proof.
- **Documentation completeness audit** — if the tutorial can't cover it, the feature isn't
  documented yet.

## Documentation completeness bonus

The AI tutorial-generation process **IS** the documentation completeness audit. If the AI
can't generate a tutorial section for a feature, that feature lacks documentation. Run
tutorial generation as a pre-release check:

> "AI couldn't generate tutorial for X — docs incomplete."

Same check, dual purpose. (This is the generated-coverage counterpart to the manual capture
audits in `docs/audits/` — e.g.
[roadmap-capture-audit-2026-06-29.md](../audits/roadmap-capture-audit-2026-06-29.md).)

## Sequencing

- Build after the v2 feature set is locked.
- Requires: complete module documentation, all `CUSTOM_*.md` guides.
- Run the documentation completeness audit first.
- Generate tutorial → review → ship with v2.
- Regenerate on each subsequent release.

> **Prerequisite, honestly stated:** "complete module documentation" does not exist yet
> (one module documented today). The completeness gap *is* the v2 doc backlog — and the
> generator is the tool that measures it.
