# TLS interception + sterilization layer — Tier 2 (scope, not estimate)

**Status:** scoping doc (read-only analysis; no code changed). Captured 2026-07-25, same
session as the [ADR 0009 addendum](../architecture/0009-security-inspection-proxy.md) and
[adr-0009-l3-behavioral-trigger-scope.md](adr-0009-l3-behavioral-trigger-scope.md). **Extended
same day** with the full undetectable-inline design (Pieces D–I below), consolidated from a
same-day design session, once the three-tier structure named this capability **Tier 2** in the
ADR 0009 addendum §6. **Extended again 2026-07-26** with Piece J (the hybrid inline/mirror
transition) and a correction to the surrounding "Tier 2 catches zero-days" framing — see Piece J.
This decision closes the open question that made "enterprise-competitive zero-day detection"
only partial: without TLS interception, the L3 catch layer (Fork B's tunnel-routed Suricata) can
see metadata and unencrypted traffic, but not the payload of the large majority of real-world
traffic, which is HTTPS.

**Correction (2026-07-26) — this closes the *payload-visibility* gap, not a first-contact-
prevention guarantee.** Seeing the payload is not the same as catching every zero-day on first
contact: a clean-looking first chunk of decrypted data still reaches its destination. See
Piece J for exactly what Tier 2 does and does not guarantee, and why Tier 3 is the real backstop
for payloads that get through undetected.

**Why undetectability is worth attempting (market context):** no NDR market leader and no
commercial inline-interception vendor (Zscaler, Palo Alto, Netskope) attempts per-connection
undetectability today — the industry either stays passive (avoiding the problem entirely) or
accepts detectability as an unaddressed tradeoff. Genuine per-connection indistinguishability
would be real, unclaimed differentiation. It is also an **unsolved problem industry-wide** —
everything in Pieces D–I is an R&D goal with a concrete validation plan, not a guaranteed
shipped property.

> **NO SESSION ESTIMATE IN THIS DOC — DELIBERATELY.** Same treatment as the behavioral-trigger
> scoping doc: mark TBD, needs its own dedicated scoping session. This is genuinely new
> capability (nothing in the existing L2/L3 scope decrypts anything today), and per Open Item 4
> below, there's an unresolved architectural tension (how much traffic actually needs decrypting)
> that should be answered before committing to a session count.

## The decision
**Full TLS interception (decrypt → inspect → re-encrypt)** is the mechanism chosen for genuine
payload-level coverage of HTTPS traffic. This is a real architectural commitment, not a minor
addition — it requires the Nemesis box (or agent, depending on where interception happens) to
sit as a TLS man-in-the-middle for selected traffic, which is a different trust and complexity
class from anything L1/L2/Fork-B do today (all of which operate on metadata: DNS names, IPs,
ports, connection timing — never plaintext payload).

---

## Piece A — Interception mechanism
**What:** the actual decrypt-inspect-reencrypt pipeline. Where this sits (agent-local vs.
tunnel-routed through the server, consistent with the "tunnel carries decisions, not data"
principle in the base ADR 0009) is not decided in this doc — it's a real open design question
depending on where CPU cost and CA-trust are easiest to manage.

- **Relationship to the behavioral trigger (Layer a/b model):** TLS interception is presumably
  invoked under the same catch-layer triggers as Fork-B's Suricata inspection (unknown
  reputation OR behavioral escalation) — i.e., this is a **deeper inspection capability within
  the existing catch layer**, not a third parallel layer. Not yet confirmed; flag for the
  dedicated scoping session.
- **If agent-local: inherits the same redirect-ownership rule.** The ADR 0009 addendum's
  now-RESOLVED Open Item 1 (origin agent owns the redirect when origin is enrolled; destination
  agent owns it when origin is not) would presumably also govern *which* agent performs TLS
  interception for a given flow, if interception happens agent-side rather than server-side —
  same ownership question, not a separate one. Not confirmed; depends on Piece A's
  agent-local-vs-server-side decision above.
- **Agent role, if agent-local:** would need to stay consistent with the hard "agent is sensor/
  enforcement only" principle (ADR 0009 addendum §3) — the agent could perform the mechanical
  decrypt/re-encrypt operation as directed, but must not decide what's inspected or judge the
  content; that judgment still has to be server-side or in a component that reports its
  verdicts server-side.

## Piece B — Sterilization / retention policy
**What:** the policy governing what happens to plaintext once decrypted, and what's stored
afterward. This is a **real policy decision to be specified**, not left implicit — captured here
so it isn't lost, not because it's resolved:

- **Transient inspection, not persistence (for clean/non-triggering traffic):** plaintext is
  inspected **in-memory only**. Nothing about plaintext *content* is persisted. Only
  classification + metadata are retained (this destination was clean/suspicious, at this time,
  matching this rule or none).
- **Bounded evidence retention on an actual detection:** when a rule fires, retain **bounded**
  evidence — rule ID, a hash, possibly a redacted excerpt. **The exact retention threshold
  (what counts as "bounded," what a redacted excerpt looks like, how long evidence is kept) is
  an explicit open policy decision**, not specified by this capture.
- **Why this matters:** this is the mechanism that makes "we decrypt your traffic" defensible
  rather than alarming — the product's entire self-hosted/local-first trust story depends on
  this being airtight and clearly communicated, not just technically true.

## Piece C — Home vs. business toggle
**Explicit product requirement:** the sterilization posture is a toggle, not a fixed policy.
- **Home-network default: strict sterilization** (Piece B's transient-only policy, no
  exceptions).
- **Business/commercial users can opt IN to fuller visibility** over their own equipment/
  network — e.g., for compliance, employee-monitoring, or incident-investigation needs a home
  user wouldn't have. The exact shape of "fuller visibility" (what can be retained, for how
  long, with what consent/disclosure) is not specified here — captured as a requirement to
  design against, not a design.

---

## Piece D — Build order: closed destination first, then generalize (CONFIRMED)
Every obstacle to undetectable interception is specific to impersonating **arbitrary
third-party servers you don't control** — mimicking an unknown client's TLS fingerprint against
a public signature database, guessing which OS/client combination to impersonate, matching
latency profiles that vary per destination. None of that difficulty exists when both ends of a
connection are known and controlled.

**CONFIRMED: validate against a VM as the controlled, fixed test destination first.** This is a
strict subset of the general arbitrary-internet-traffic problem — a solution to the general
case trivially covers the fixed-destination case, but not vice versa, so this is a real
checkpoint, not a shortcut around the real work. Confirm genuine indistinguishability against
the VM before generalizing the same code to handle arbitrary destinations. Build/validation
work begins next session.

**Flagged aside, not a dependency:** this is also exactly the shape of a separate drone
platform's future closed-network case — first mention of that project anywhere in this repo.
The drone project itself is on hold until October 2026 and is **not a build dependency** for
anything here; if the general (arbitrary-destination) version of this work succeeds, the
drone's closed-network case is covered automatically, by extension, with no separate design
needed. Noted here only so it isn't lost; not scoped further.

## Piece E — Side-channel normalization (three layers, all required)
An attacker doesn't need to guess your inspection schedule if any layer of the connection
reveals inspection is happening on THIS specific connection. **All three must be normalized**,
or the weakest one gives the attacker a free, reliable, per-connection test.

- **(a) TLS presentation.** The agent must perform TLS interception (decrypt/re-encrypt)
  **uniformly on EVERY connection**, regardless of whether that connection's payload is
  subsequently forwarded to the server for deep inspection or handled locally against the
  cache. Whether deep inspection happens becomes a decision made *after* decryption, invisible
  to the client. The client-facing cert story must be identical whether or not the connection
  is actually being deep-inspected.
- **(b) Timing.** A round-trip to the server for real inspection adds latency a purely local
  cache-hit decision doesn't have. Locally-cached-clean connections need an **artificial delay**
  inserted to match the typical latency profile of a genuinely tunneled connection. This costs
  local latency, not bandwidth — the resource savings from caching stay intact even with the
  padding.
- **(c) Packet-level artifacts.** TTL, TCP window size, and fragmentation behavior must be
  normalized to be identical regardless of which path (locally cached vs. actually
  tunneled/inspected) the traffic actually took.

**Honest framing, stated explicitly — don't claim more than this:** "no observable difference"
is a target *approached*, not proven. The realistic goal is raising the cost of detecting
inspection high enough that it stops being a cheap, reliable evasion technique for an attacker
— not an absolute, provable guarantee.

## Piece F — Cache design: destination trust, not packet content
**Cache key: destination IP + TLS certificate fingerprint, not hostname alone.** Hostname/SNI
is spoofable (domain fronting, encrypted SNI); cert fingerprint is cryptographically tied to
the actual server. A cert change on a previously-trusted destination is itself a signal, not
just noise — treat it as automatic cache invalidation.

**Bounded validity, never permanent trust.** A cache entry that says "clean forever" is a hole
a patient attacker can exploit — get whitelisted on ordinary traffic, then abuse the same
channel later once it's no longer being watched. Cap what a clean verdict is worth: a time
window, a byte/volume ceiling, or a connection count, after which the destination is
re-inspected regardless of cached status.

**Probabilistic/sampled re-inspection instead of a hard on/off switch.** Rather than "cached
clean = never tunnel again until invalidated," a trusted destination still gets tunneled 1-in-N
times going forward, with N growing as trust accumulates over more clean history. **This is the
strongest single mechanism for the stated goal:** bandwidth stays low for well-established
clean destinations, while there is always a nonzero chance the next connection to that
destination gets caught — genuinely live zero-day detection rather than a hole that, once open,
stays open.

**Data points to explicitly AVOID using as trust signals:** client-side JA3/JA4 TLS handshake
fingerprints must **never** be used to GRANT a cache skip. Real malware families deliberately
mimic common browser fingerprints specifically to blend in and defeat this kind of check — using
it to grant trust hands attackers a known, documented way to get waved through. JA3/JA4 is still
useful as a **trigger** signal (an unusual/rare fingerprint is worth flagging), never as grounds
to trust.

**Governance stays server-side.** The cache itself lives and is governed server-side; the agent
only acts on a verdict token the server actually issued. A cache-skip decision must never be
something the agent determines or self-reports locally — the same sensor-only boundary as
everywhere else in the system (ADR 0009 addendum §3), and it matters here specifically because
a compromised agent could otherwise just lie about a locally-made trust decision.

## Piece G — Dual randomization (two distinct mechanisms, not one)
These address two different failure modes and are named and implemented **separately**:

- **Per-connection sampling probability** (Piece F above) — addresses ongoing abuse of a
  channel that's already been marked clean, on a per-connection basis.
- **Periodic whole-cache re-audit at randomized intervals** — addresses a destination that was
  genuinely clean when cached but changed afterward (domain sold, IP reassigned, a legitimate
  site compromised weeks later). Randomizing WHEN this sweep happens (rather than a fixed
  schedule) defeats an attacker who might otherwise map a predictable audit rhythm and time a
  malicious payload for a known-safe window.

**Both mechanisms are necessary; neither substitutes for the other.**

## Piece H — Evasion-probing and deception (mostly flagged, NOT built now)
- **Evasion-probing as a behavioral trigger signal — safe to build now.** Attempting to
  fingerprint your own security layer (checking whether a connection is being inspected) is
  behavior almost no legitimate client ever does — a strong tell. Feed detected evasion-probing
  into the Tier 1 behavioral trigger engine
  ([adr-0009-l3-behavioral-trigger-scope.md](adr-0009-l3-behavioral-trigger-scope.md)) as a
  strong escalation signal, same as any other anomaly. **This does NOT require deciding where
  the traffic gets routed next** — just that it raises suspicion.
- **Direct honeypot redirect on suspected evasion — REJECTED.** Certificate-pinned legitimate
  apps (banking apps, HSTS/HPKP clients) behave abnormally when they see Nemesis's interception
  cert in exactly the way an evasion-probing attacker would — retry, fail, fall back. A direct
  honeypot that actively impersonates a real service risks routing a legitimate app (and by
  extension a real user's real credentials) into a convincing fake. **Worse than a normal false
  positive**: the failure mode is active harm (a phishing setup pointed at your own customer),
  not a simple connection failure.
- **Sandbox-and-observe with generic, credential-inert decoys — flagged, NOT built now.** A
  better-shaped version of the same idea: route suspected evasion-probing traffic to an isolated
  sandbox with a passive, generic decoy — enough to look like "a server responded" for
  observation purposes, but never soliciting or accepting anything that looks like a real
  credential or real data. If a misrouted legitimate client can extract nothing usable and can't
  be tricked into submitting anything real, this is safe even when the classification is wrong.
  **Real, standalone infrastructure** (isolated network segment, decoy services, containment
  strong enough nothing learned there can pivot back to the real network, someone actually
  reviewing captures) — comparable in scope to the Data Manager or this TLS interception build.
  Treat as a deliberate future capability, not part of this build.
- **TBD — to be decided during build, may be driven by testing results:** how to reliably
  distinguish an attacker probing for interception from a normal cert-pinning app failing for an
  unrelated reason. This is the Section-3.6 disambiguation problem — real, unresolved, and it
  **blocks anything beyond the trigger-signal use** above. Likely solved via the cert-pinned-app
  allowlist work (Piece I / hard unknown (b) below), but not resolved here, and sandbox-and-observe
  can't be scoped further until it is, regardless of which destination-routing model is chosen.

## Piece I — Pinned-app handling (industry-standard approach)
Adopt the standard industry model rather than inventing a new one: a **predefined + user-editable
exclusion/allowlist** for known certificate-pinned applications and destinations, bypassing
inspection entirely for that traffic. This is what every inline-interception vendor (Zscaler,
Palo Alto, Netskope) does; there is no vendor precedent for trying to intercept pinned traffic
invisibly, and pinning is a **declining practice industry-wide**, so the exclusion list's burden
should shrink over time rather than grow. This is the adopted *approach* to hard unknown (b)
below — building and maintaining the allowlist itself remains unscoped work.

## Piece J — Hybrid inline/mirror transition (per-connection gate, added 2026-07-26)

**Replaces the implicit assumption that Tier 2, once engaged for a connection, stays fully
inline (gating delivery) for that connection's entire life.** It does not — only the **first
meaningful chunk of decrypted application data** is inline-gated (held for inspection before
delivery); if it passes, the connection transitions to **mirror** (Piece E's uniform
decrypt/inspect continues, but delivery is no longer gated) for the rest of its life.

**"First meaningful chunk," precisely — not the literal first packet.** The TLS handshake
(ClientHello, ServerHello, certificate exchange, Finished) precedes any application payload;
none of that is application data to inspect. The gate applies to the first chunk of **decrypted
application data** that actually exists to inspect, whatever number of packets that takes.

**Why hybrid, not always-fully-inline:** staying fully inline for a connection's whole life pays
the inline-gating latency cost (a real round-trip per data chunk) for the connection's entire
duration, for marginal detection benefit beyond the first look — most payloads that reveal
themselves in inspectable content do so early. Transitioning to mirror after a clean first chunk
keeps long-lived connections cheap while still gating the highest-value moment.

### Transition-hardening requirements (close a real bypass — not optional hygiene)

Without these, an attacker who controls their own destination can simply **watch round-trip
latency drop** as the observable signal that inline gating has ended for a connection, and time
a malicious payload for right after. Each requirement below closes one version of that
timing-based bypass:

- **(a) Randomize how much of the connection stays inline-gated, rather than a fixed cutoff.**
  "Always exactly one chunk" is itself a learnable, fixed signal. Same unpredictability logic as
  Piece F's per-connection sampling probability — vary the gated portion (more than one chunk,
  sometimes) so there's no single fixed boundary to detect and time around.
- **(b) Continue Layer 2's latency padding (Piece E(b)) through the transition itself.** The
  switch from inline (real round-trip latency) to mirror (no round-trip) must not itself produce
  an observable timing discontinuity — the padding that already normalizes cache-hit vs.
  tunneled-inspection latency (Piece E(b)) has to extend across this transition too, not just
  apply to whichever state a connection is already settled into.
- **(c) Occasionally re-promote an already-downgraded connection back to inline mid-life, as a
  spot-check.** Even after transitioning to mirror, a connection should sometimes be pulled back
  into inline gating later in its life — so an attacker can never be certain the gate has
  *permanently* lifted just because it lifted once. Same family of mechanism as Piece G's
  periodic whole-cache re-audit, applied at connection granularity instead of cache-entry
  granularity.
- **(d) Critical clarification, stated explicitly: downgrading to mirror downgrades the DELIVERY
  GATE only.** Suricata (and Tier 1's behavioral analysis) continues inspecting the connection's
  traffic for its entire life, regardless of gating state. A late-connection anomaly still feeds
  the Tier 1 trigger and can still dirty that destination's reputation — even though that
  specific packet may already have been delivered by the time the anomaly is recognized. **This
  is the same accepted tradeoff as the ADR 0009 addendum §4 dynamic-cache limitation**
  ("invalidate the cache entry going forward, the current connection may complete uninspected")
  — restated here at **connection granularity** instead of **destination granularity**. Not a
  new gap; the same one, at a finer grain.

### Correction to the surrounding Tier 2 framing

Tier 2, including this hybrid gate, does **not** prevent an undetected zero-day payload from
reaching its destination on the very first inline-gated chunk if that chunk itself looks clean.
What Tier 2 provides is fast detection and rapid future-blocking via the dynamic cache, plus
this partial first-contact gate — not a guarantee against a clean-looking first payload.
**Tier 3's local late-triggers are the actual backstop** for a payload that gets through Tiers 1
and 2 undetected and begins executing locally (see
[adr-0009-l3-tier3-local-triggers-scope.md](adr-0009-l3-tier3-local-triggers-scope.md)). This is
intentional defense-in-depth across the three tiers, not a gap unique to Tier 2.

### Relationship to Fork B's now-resolved mirror mechanism

This hybrid gate is the **only** place in the whole L3 design where delivery is ever actually
held pending a verdict. Fork B's own tunnel transport (the redirect/NAT/Suricata-af-packet
mechanism this Tier 2 interception may or may not ride, per Piece A's still-open
agent-local-vs-server-side question) is confirmed **pure mirror** — see
[adr-0009-l3-fork-b-scope.md](adr-0009-l3-fork-b-scope.md) ("Mechanism: MIRROR," resolved
2026-07-26). This hybrid gate exists one layer up, inside Tier 2's own decrypt/inspect/
re-encrypt pipeline, and only applies to connections Tier 2 has actually decrypted.

---

## Named hard unknowns (scoped, not resolved)

### (a) CA trust distribution with no MDM
Enterprise TLS interception relies on MDM to push a trusted root CA to every managed device.
**Nemesis has no MDM and no fleet of centrally-managed devices** — home devices, IoT gadgets,
guests' phones, and any non-agent device on the network have no mechanism to receive and trust
a Nemesis root CA. This is a genuine **onboarding-UX problem, harder here than in a managed
enterprise environment**, not a solved-elsewhere problem being ported in. No mechanism is
proposed in this capture — it's named so it isn't lost.

### (b) Certificate-pinned apps will reject interception
Apps that pin certificates (banking apps being the canonical example) will **refuse to connect**
if their expected certificate doesn't match — interception breaks them outright, not gracefully.
This needs an **explicit bypass/allowlist mechanism**: known-pinned domains/apps skip
interception entirely and pass through uninspected at the TLS layer (they'd still get whatever
metadata-level coverage L1/L2/Fork-B already provide). Building and maintaining that allowlist
(how it's populated, updated, and kept current as apps change their pinning behavior) is
unscoped work in its own right.

### (c) Resource tension — how much traffic genuinely needs decrypting?
**Real, unresolved architectural question, not assumed away by deciding to build TLS
interception:** broad/full TLS decryption needed for genuine payload coverage may conflict with
the **low-footprint, selective-inspection design** already scoped elsewhere (Fork B's whole
premise is "the tunnel carries decisions, not data" and only ~1% of traffic hits deep inspection
after the cache warms). Full-fleet, full-traffic TLS interception is a fundamentally heavier
resource commitment than that model assumes. **How much of a network's traffic genuinely needs
decrypting for effective zero-day coverage is not answered here** — flagged explicitly as the
central tension between "we decided to build TLS interception" and "we also decided to stay
low-footprint and selective." Resolving this shapes Piece A's interception scope (everything
vs. only already-flagged flows) and therefore the eventual session estimate.

---

## Total & confidence
```
TBD — needs its own dedicated scoping session.
```
Same rationale as the behavioral-trigger doc: this is additive, genuinely new capability with
no existing precedent in the codebase, blocked on real unresolved questions (b, c above, plus
Piece H's disambiguation TBD) and on the same missing target-hardware baseline (see Open Item
below) — a session estimate now would not be grounded in anything. The scope grew substantially
with Pieces D–I (the full undetectable-inline design) and again with **Piece J** (added
2026-07-26, the hybrid inline/mirror transition); this makes the missing estimate more
consequential, not less — a bigger unknown, not a smaller one.

## Open item carried from the ADR 0009 addendum
**No target hardware baseline exists yet** (minimum customer-hardware spec, mini-device SKU).
TLS interception is likely the single most resource-intensive piece of today's captured scope
(decrypt/re-encrypt at line rate is CPU-real, unlike metadata-only inspection) — this makes the
missing hardware baseline especially load-bearing for this doc specifically, not just a generic
caveat.

## Cross-references
[ADR 0009 addendum](../architecture/0009-security-inspection-proxy.md) (the L3 direction this
extends — §0 names this capability **Tier 2**; §3 is the sensor-only principle Pieces F/H
depend on; incl. the now-RESOLVED Open Item 1 on agent-to-agent redirect ownership — see Piece A),
[adr-0009-l3-behavioral-trigger-scope.md](adr-0009-l3-behavioral-trigger-scope.md)
(Tier 1's trigger engine; likely shares the catch-layer invocation point with this doc's Piece A,
scopes Open Item 1's new peer-enrollment-lookup dependency as its own Piece 5, and is Piece H's
target for the evasion-probing escalation signal),
[adr-0009-l3-tier3-local-triggers-scope.md](adr-0009-l3-tier3-local-triggers-scope.md) (Tier 3's
local emergency-stop triggers — a separate, always-on tier from this doc's toggleable Tier 2),
[adr-0009-l3-fork-b-scope.md](adr-0009-l3-fork-b-scope.md) (the tunnel transport TLS
interception would presumably ride, if server-side — **now confirmed mirror**, 2026-07-26 — see
its "Mechanism: MIRROR" section; Piece J above is the layer that adds any delivery-gating on top
of that mirror transport), base [ADR 0009](../architecture/0009-security-inspection-proxy.md)
("tunnel carries decisions, not data" — the principle Piece C's resource tension weighs against),
[product-thesis-built-in-it-expertise.md](product-thesis-built-in-it-expertise.md) (the
business-model capture from the same session, including the resource-philosophy principle this
tension relates to).
