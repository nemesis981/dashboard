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

## Shape / next
Capture as the guiding principle now. It may later **graduate** into `ARCHITECTURE.md`
(durable product-vision section) or a dedicated ADR once it has shaped enough concrete
decisions to be worth pinning durably. Until then it lives here as the prioritization
lens applied to roadmap items.
