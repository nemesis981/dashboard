# North-star principle — Build in the IT department (built-in expertise)

**Status:** principle (record, don't build — this is a **prioritization filter** for all
future work, not a feature). Sits alongside the tiered-UX habit (CLAUDE.md Tier-2 §E /
`ARCHITECTURE.md` 3-tier note) and the diagnostics captures. Sharpens ADR
[0004](../architecture/0004-scan-task-orchestration.md)'s north-star ("enterprise
capability without enterprise pricing").

**Tracking note (added 2026-08-31, operator decision, roadmap-state-audit-2026-08-31.md):**
this document does **not** participate in the roadmap SHIPPED/PARTIAL/PARKED tally. It is a
reference/principle doc, not a build item, and forcing it into that three-way schema is a
category error — there is no code state to verify it against. Excluded from the file count
in every roadmap audit's tally line going forward; still counted by `ls docs/roadmap/*.md`,
so a future audit's file-set-vs-tally-total check should expect a difference of exactly 1 for
this reason, not read it as drift.

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

## Corollary principle — INFORMATION IS THE CEILING
Both AI and human experts are **only as good as the information available to them**. A
mediocre reasoner over **excellent** evidence beats a brilliant reasoner over **poor**
evidence. Therefore the product's core engineering value is the **information-gathering
layer**, not the reasoner on top of it:
- the connectivity watcher and other continuous diagnostics,
- structured captures (tickets, prior-similar-issue search),
- **error codes**,
- **forced-error-verified diagnostics** (a check is only trustworthy if we've proven it
  actually fires on the failure it claims to detect),
- **two-ended / two-sided measurement** ("is-it-me-or-them" needs both ends).

**The gathering is the moat.** Reasoning sits **downstream** — AI for common cases, a human
pro (via the [tool-aware loop](diagnostics-ai-tool-aware-loop.md)'s focused support bundle)
for the hard ones. Both are gated by evidence quality. So **invest in the information layer**:
its quality is the ceiling on every diagnosis, human or AI. This is *why* the diagnostics
captures ([watcher](diagnostics-connectivity-watcher-tool.md),
[tool-aware loop](diagnostics-ai-tool-aware-loop.md),
[reassurance + routing](diagnostics-ai-reassurance-escalation-routing.md)) are CORE: they
build the moat the reasoning depends on.

## 2FA by default (no setup required)

Every Nemesis device enrollment automatically generates an RSA keypair — the device becomes
the second factor without any user action required.

- **Factor 1 — Something you know:** username + passphrase (Flask-Login session).
- **Factor 2 — Something you have:** device RSA keypair (generated automatically on first
  agent install, never leaves the device).

Two factors. Zero configuration. The right thing happens automatically.

**Contrast with enterprise 2FA:** requires IT to configure an authenticator service, users
to install an app, scan QR codes, save backup codes, and re-enroll when phones change.
Nemesis 2FA requires: install the agent. That's it.

**Mobile hardening:** on Android and iOS, the keypair is stored in hardware security modules
(Android Keystore / iOS Secure Enclave) — cryptographically bound to the physical device,
cannot be extracted even with root access. Stronger than most software-based enterprise 2FA
implementations.

**Connection to impossible travel detection
([ADR 0008](../architecture/0008-impossible-travel-detection.md)):** the keypair also
identifies WHICH device is connecting, not just that someone has the right password. Login
from an unenrolled device (no keypair) is immediately suspicious regardless of correct
password — flagged as a HIGH alert even before geographic analysis. An attacker with a stolen
password has no keypair; they're caught at the device-identity layer before the
impossible-travel layer even fires.

**User-facing explanation (Beginner tier):**
> "Your password proves who you are. Your device proves where you are. Both are required —
> a stolen password alone can't access your network."

**Marketing one-liner:**
> "Two-factor authentication built in — no setup, no apps, no codes. It just works."

## The AI hacking inflection point

AI-assisted attacks are becoming the default attack vector. The barrier to sophisticated
hacking drops to near zero when AI can find vulnerabilities, craft exploits, and execute
attacks automatically. By 2027–2028, mass-scale AI-assisted attacks against home and SMB
networks will be routine.

**The defender's answer: behavioral detection + zero-trust enrollment.**

Signature-based detection fails against AI-generated novel malware (the signature doesn't
exist yet). **Behavioral detection catches it by what it DOES regardless of what it IS:**
- Ransomware modifies files → the **canary** catches it.
- Lateral movement probes other devices →
  [**outbreak detection**](lateral-movement-outbreak-detection.md) catches it.
- Malicious outbound → the **inspection proxy** catches it.
- Novel AI-generated malware → still does one of the above.

**The WiFi device explosion multiplies the attack surface:** every smart device is a
potential entry point, most poorly secured. The
[**venue guest-network**](venue-guest-network.md) solution (agent as credential, inspection
tunnel, outbreak detection) closes the highest-risk attack surface — **public WiFi** — that
AI-assisted attackers will target at scale.

**Market timing: building now, before the wave.** By the time AI attacks are mass-scale,
Nemesis has:
- an established user base + community threat feed,
- behavioral detection that catches novel AI malware,
- venue/employee coverage for the most vulnerable networks.

**Product thesis in one line:**
> "AI makes attacking easy. Nemesis makes defending automatic. No IT department required."

## SMB Software Support (the hidden value)

SMBs are notorious for buying cheap software with issues. The typical experience: something
breaks, support asks for system information the user can't provide, 2 weeks of back-and-forth,
"try reinstalling."

Nemesis changes this dynamic completely:

The [support bundle](support-bundle.md) (generated in 10 seconds from already-collected data)
gives SMB users something they've never had: documented, provable evidence of exactly what
happened.

- The **NMS-INST certificate** proves the install was clean.
- The **registry diff** proves what changed and when.
- The **sandbox log** proves what the software was doing at install.
- The **AI diagnosis** tells them what likely caused the issue.

Vendors can no longer say "works on our end." The conversation shifts from
"describe your problem" to "here's the exact cause, here's the fix."

This is **not a security feature — it's an accountability layer for the software ecosystem.**
But it's only possible because of the security infrastructure underneath it.
(The certificate chain + manifest come from the
[malware-detection-pipeline](malware-detection-pipeline.md) §8; the bundle assembly + routing
from [support-bundle.md](support-bundle.md).)

**Marketing angle for SMB:**
> "Stop wasting weeks on software support. Nemesis documents everything automatically.
> When something breaks, you have the proof."

## Business model & resource philosophy (2026-07-25 capture)

> Capture-only (Window 2, docs/audit — no code, no build). Same session as the
> [ADR 0009 L3 addendum](../architecture/0009-security-inspection-proxy.md) and the TLS/
> behavioral-trigger scoping docs. This section pins the business-model decisions that came up
> repeatedly while scoping today's architecture work — they're product/pricing decisions, not
> engineering ones, but they constrain engineering choices (see the Resource Philosophy /
> TLS-resource-tension cross-link below), so they're captured here rather than lost in
> conversation.

### Tier structure
- **Free tier = home use, FULL uniform detection depth — never stripped down.** A free-tier user
  gets the same detection capability as a paying one; the tier gate is administrative/scale
  features, not security.
- **Commercial tier = FLAT price, NOT device-count or network-size based.**
- **Hardware/bandwidth is customer-owned infrastructure cost**, scales with their network size,
  and is **explicitly OUTSIDE Nemesis's pricing model.** Nemesis prices the software/service;
  the customer's own hardware footprint is theirs to provision, same as any self-hosted product.

### Locked principle — capability is never the upsell
**Detection/security CAPABILITY is uniform at every tier and every scale.** Only
**administrative/organizational** features differ by tier: multi-user, roles, MSP cross-site
management, device-count caps. **Security is never the upsell.** This is a **locked** product
principle, not a current-plan detail subject to routine revision — if a future pricing
discussion proposes gating detection depth by tier, that's a reversal of a stated principle and
should be flagged as such, not treated as a normal roadmap tradeoff.

This directly extends the north-star thesis above ("enterprise capability without enterprise
pricing") — it's the pricing-model expression of the same idea, not a separate decision.

### Resource philosophy
**Explicit engineering targets, not aspirations:**
- Minimize **SERVER** resource cost relative to network size.
- Keep **PER-DEVICE (agent)** resource cost very low.

**Accepted tradeoff, stated explicitly:** as a network grows, some additional hardware/
bandwidth is a **fair, EXPECTED, and TRANSPARENTLY COMMUNICATED** cost of scale — **not**
something to hide or architect around at all costs. This is the philosophy the
[network-resource-scaling-advisor.md](network-resource-scaling-advisor.md) capture
operationalizes: rather than pretending Nemesis can scale for free, tell the customer honestly
when their network has outgrown their current hardware/bandwidth, the same way any honest
capacity-planning tool would. (Distinct from [nemesis-overhead-meter.md](nemesis-overhead-meter.md),
which is Nemesis's own self-overhead/leak-detection diagnostic — see that scoping note for why
these are two files, not one.)

**Direct tension, named not resolved:** this philosophy is in explicit tension with
[tls-interception-sterilization-scope.md](tls-interception-sterilization-scope.md) §c's
resource-tension unknown (full TLS decryption for genuine payload coverage vs. the low-footprint
selective-inspection design). That tension is an open architectural question, not something this
business-model capture resolves — cross-linked here so the two don't drift apart in separate
docs.

### AI principle — strictly optional, never in the detection/decision path
**AI-powered features are STRICTLY OPTIONAL and NEVER part of the detection/scoring/decision
path.** Confirmed uses, and the only confirmed uses:
1. **Opt-in post-detection explanation** — what happened, the risk, a proposed action (after a
   deterministic detection has already fired).
2. **Opt-in narration** for the
   [network-resource-scaling-advisor](network-resource-scaling-advisor.md)'s recommendations —
   translating raw metrics into plain language.

**All core detection, scoring, and resource measurement is deterministic, local, and works with
zero external AI dependency.** This is the same "agent is a dumb sensor, all judgment is
server-side and rule-based" hard principle from today's
[ADR 0009 addendum](../architecture/0009-security-inspection-proxy.md) §3, extended to also mean
"and the server-side judgment itself is deterministic, not AI-dependent, by default."

**This came up repeatedly enough today (L3 design, resource module, this section) that it may
be worth a durable mention in `CLAUDE.md` — flagged for the operator's call, not done here**
(capture-only session; a change to core operating discipline shouldn't be made silently). See
the same flag in the ADR 0009 addendum §3.

### Marketing / product thesis
**"Enterprise-level protection for all user levels."** AI is the enabler that lets a small team
build and price this at a fraction of what an enterprise SOC/security-vendor relationship
costs, **without reducing detection depth for smaller customers.** State this as the product
thesis driving the tier/pricing/resource decisions above — not just a tagline alongside them.

## Shape / next
Capture as the guiding principle now. It may later **graduate** into `ARCHITECTURE.md`
(durable product-vision section) or a dedicated ADR once it has shaped enough concrete
decisions to be worth pinning durably. Until then it lives here as the prioritization
lens applied to roadmap items.
