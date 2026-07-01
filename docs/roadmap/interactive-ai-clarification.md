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
2. **Scope discipline — explanation lane ONLY.** The feature **clarifies and explains**; it does
   **NOT decide, execute, or give network-modification / action advice.** Mirror the prop-trader AI
   framing (*"explanation / journaling, not prediction"*). Keep it **firmly out of the
   action / automation lane.**
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
