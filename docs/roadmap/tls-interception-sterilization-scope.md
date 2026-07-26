# TLS interception + sterilization layer — Tier 2 (scope, not estimate)

**Status:** scoping doc (read-only analysis; no code changed). Captured 2026-07-25, same
session as the [ADR 0009 addendum](../architecture/0009-security-inspection-proxy.md) and
[adr-0009-l3-behavioral-trigger-scope.md](adr-0009-l3-behavioral-trigger-scope.md). **Extended
same day** with the full undetectable-inline design (Pieces D–I below), consolidated from a
same-day design session, once the three-tier structure named this capability **Tier 2** in the
ADR 0009 addendum §6. **Extended again 2026-07-26** with Piece J (the hybrid inline/mirror
transition) and a correction to the surrounding "Tier 2 catches zero-days" framing — see Piece J.

**Repo-structure note (2026-07-26):** Pieces E/F/G/H/J's implementation-level detail (exactly
how each mechanism works, hardening mechanics, the validation harness code that was briefly at
`l3_tls_validation/`) has moved to a private, non-public location — a source-visibility
decision, not a feature-gating one (the capability ships at every tier regardless). This doc
now carries the general shape of each piece plus a pointer, not the full mechanism. See
`l3_tls_validation/README.md` and `PUNCHLIST.md` for the move's rationale and history.

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
Three layers of the connection — TLS presentation, timing, and packet-level artifacts — must
all be normalized so that no layer reveals whether a given connection is being deep-inspected.
**Implementation-level detail (exactly how each layer is normalized) documented internally, not
in the public repo** — this is a source-visibility decision, not a feature-gating one; the
capability ships at every tier regardless. **Honest framing, kept public deliberately:** "no
observable difference" is a target *approached*, not proven — the realistic goal is raising the
cost of detecting inspection, not an absolute guarantee.

## Piece F — Cache design: destination trust, not packet content
Governs how long a destination's "clean" verdict is trusted before re-inspection, keyed on
cryptographic identity rather than a spoofable hostname, with governance staying strictly
server-side (the agent never determines trust locally — same sensor-only boundary as
everywhere else in the system, ADR 0009 addendum §3). **Implementation-level detail (cache key
design, trust-decay mechanics, what signals are deliberately excluded from granting trust)
documented internally, not in the public repo.**

## Piece G — Dual randomization (two distinct mechanisms, not one)
Two separate randomization mechanisms address two different failure modes (ongoing abuse of an
already-trusted channel vs. a destination that changed after being cached clean). **Both are
necessary; neither substitutes for the other. Implementation-level detail documented internally,
not in the public repo.**

## Piece H — Evasion-probing and deception (mostly flagged, NOT built now)
Detecting an attacker probing whether their traffic is being inspected feeds the Tier 1
behavioral trigger engine as a signal — it does not, by itself, determine routing. A
direct-honeypot approach was considered and **explicitly rejected** on user-safety grounds (risk
of misrouting a legitimate cert-pinned app, e.g. a banking app, into a convincing fake — active
harm, not a simple false positive). A safer sandbox-and-observe alternative is flagged as a
future capability, not built now. **Implementation-level detail documented internally, not in
the public repo.**

## Piece I — Pinned-app handling (industry-standard approach)
Adopt the standard industry model rather than inventing a new one: a **predefined + user-editable
exclusion/allowlist** for known certificate-pinned applications and destinations, bypassing
inspection entirely for that traffic. This is what every inline-interception vendor (Zscaler,
Palo Alto, Netskope) does; there is no vendor precedent for trying to intercept pinned traffic
invisibly, and pinning is a **declining practice industry-wide**, so the exclusion list's burden
should shrink over time rather than grow. This is the adopted *approach* to hard unknown (b)
below — building and maintaining the allowlist itself remains unscoped work.

## Piece J — Hybrid inline/mirror transition (per-connection gate, added 2026-07-26)

A per-connection gate: rather than staying fully inline (gating delivery) for a connection's
entire life once Tier 2 engages, only an initial portion of decrypted application data is held
for inspection before delivery; the connection then transitions to a lower-overhead monitoring
mode (mirror — inspected, no longer delivery-gated) for the rest of its life. This closes a real
timing-based bypass an attacker could otherwise use to time a payload for right after gating
ends. **Implementation-level detail (exactly how the gate boundary and the hardening against
that bypass work) documented internally, not in the public repo** — this is a source-visibility
decision, not a feature-gating one; the capability ships at every tier regardless.

**Correction to the surrounding Tier 2 framing, kept public deliberately:** Tier 2, including
this hybrid gate, does **not** prevent an undetected zero-day payload from reaching its
destination on the very first inline-gated chunk if that chunk itself looks clean. What Tier 2
provides is fast detection and rapid future-blocking via the dynamic cache, plus this partial
first-contact gate — not a guarantee against a clean-looking first payload. **Tier 3's local
late-triggers are the actual backstop** for a payload that gets through Tiers 1 and 2 undetected
and begins executing locally (see
[adr-0009-l3-tier3-local-triggers-scope.md](adr-0009-l3-tier3-local-triggers-scope.md)). This is
intentional defense-in-depth across the three tiers, not a gap unique to Tier 2.

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
