# Interactive AI Clarification Layer (ask-for-more on guidance)

> Roadmap capture — **future item, post-packaging.** Records the concept + design intent; does not
> design the implementation. **Extends the AI Engine module + Teaching Mode.** **Depends on the AI
> Engine module being complete.** NOT a trip task.

**Rule 8:** placeholders only — no real IPs/hosts/accounts/keys.

**Related:** [ai-generated-tutorial-walkthrough](ai-generated-tutorial-walkthrough.md) (Teaching
Mode / generated guidance), the diagnostics-AI items
([reassurance/escalation routing](diagnostics-ai-reassurance-escalation-routing.md),
[tool-aware loop](diagnostics-ai-tool-aware-loop.md)), and the AI Engine module (`modules/ai_engine/`).

---

## The gap

Today the **3-tier system renders guidance AT the user** at their chosen depth (Beginner =
plain-language what-to-do; Pro = raw evidence). It's **one-directional — a broadcast.** There is no
way for the user to **ask a follow-up** when the guidance isn't enough:

- a **Beginner** who still doesn't understand, or
- a **Pro** who wants to go deeper on one specific finding,

has no *"explain that more / why does that matter?"* affordance. The explanation **can't adapt to
the individual's actual confusion.**

---

## Why it fits the thesis

The product serves users with **no IT department to ask.** A static explanation helps, but what a
real IT person adds is **RESPONSIVENESS** — you ask, they clarify. An interactive clarification
affordance is **the closest a self-hosted tool gets to "having someone to ask."** Thesis-aligned,
**not feature-creep.**

Best framed as an **extension of Teaching Mode**: not just *"explain at depth N,"* but *"let me ask
the teacher a follow-up."*

---

## Design tensions (resolve at build time)

1. **Cost / rate-limiting.** Turning each explanation into a potential open-ended conversation is
   **real API spend.** It **MUST live inside the AI Engine module's existing cost tracking, rate
   limiting, and tiered approval gates** — never bypass them. The **BYO-API-key** model applies:
   free-tier users spend **their own key** on their own follow-ups.
2. **Scope discipline — tracks authority, does not decide independently of it.** *(Revised
   2026-08-04, operator decision — supersedes the original explanation-only-always framing below,
   kept for the record.)* **Note on how to read this revision:** this stub scoped a narrower
   concept — "ask a follow-up question about guidance already shown." The contextual chat
   actually built today (item 1 in the AI-interaction scoping work, private mirror) is a broader
   addition that goes beyond what this stub envisioned, not merely a build-out of it. So this
   isn't the product reversing a settled call on the original concept; it's the original stub's
   constraint not fully fitting a feature that grew past what it described, and getting a scope
   definition of its own as a result.

   The feature's scope now tracks the authority level already earned by the action class it's
   anchored to, rather than being fixed at explanation-only forever: it explains only at L0
   (today's behavior), may offer reasoned advice at L1 (*"I'd block this, because X"*) with no
   execution, and may offer to act on confirmation at L2+. **What does not change:** it still
   never acts through its own path — any action it offers dispatches through the same gated
   action layer, same per-action-class authority check, and same audit trail as an autonomous
   action would. That's the part of the original constraint that was actually load-bearing, and
   it's preserved at every level; only the class of things the feature is *allowed to say* expands
   as the graduated-authority model (separate roadmap item) grants an action class more trust.
   Rationale, in the operator's words: *"this chat addition was not originally scoped so we need
   to change the rule to allow a quality experience for the user"* — a fixed explanation-only
   ceiling means the feature tells a user *"I can only explain, not advise"* at the exact moment
   they need help most, which is a real quality-of-experience cost once the feature is bigger than
   the original ask-a-follow-up concept. Full design: the AI graduated-authority scoping doc
   (private mirror, Rule 10).

   *Original framing (for the narrower original concept, kept for context — not itself wrong, just
   scoped to a smaller feature than what got built):* the feature clarifies and explains; it does
   NOT decide, execute, or give network-modification / action advice, mirroring the prop-trader AI
   framing (*"explanation / journaling, not prediction"*) and staying firmly out of the
   action / automation lane.
3. **Context grounding.** A good follow-up needs the specific finding in context — *"explain that
   more"* only works if the AI knows what *"that"* is. So it is **NOT a generic bolted-on
   chatbot**; it's an *"explain THIS alert / THIS reading / THIS recommendation further"*
   affordance **anchored to a specific piece of surfaced data.** That grounding is what makes it
   **useful rather than a hallucination risk.**

---

## Status

- **Future item, post-packaging.**
- **Extends** the AI Engine module + Teaching Mode.
- **Depends on** the AI Engine module being complete.
