# ADR 0009 — Security Inspection Proxy (Self-Hosted SSE)

- **Status:** Proposed (architecture decided 2026-06-28; design captured, **no code changed**).
  **See the 2026-07-25 addendum below**, now organized as a **three-tier structure** (Tier 1
  mirror/passive default, Tier 2 full-inline toggle, Tier 3 client-side local emergency
  triggers) per the same-day consolidated design capture, **further extended 2026-07-26** with
  Fork B's mirror-mechanism resolution and a Tier 2 hybrid inline/mirror transition design.
  Still **not built**.
- **Date:** 2026-06-28 (L3 addendum: 2026-07-25; three-tier consolidation: 2026-07-25; Fork-B
  mirror resolution + Tier 2 hybrid design: 2026-07-26)
- **Extends:** [0005-dns-firewall-device-auth-architecture](0005-dns-firewall-device-auth-architecture.md)
  (device auth), [0007-device-user-model](0007-device-user-model.md) (device-user model)
- **Depends on:** the agent rebuild / config-pull
  ([agent-rebuild-config-driven.md](../roadmap/agent-rebuild-config-driven.md)), a Tailscale
  exit node, and [0006-data-manager](0006-data-manager.md) (Data Manager)
- **Related:** [0008-impossible-travel-detection](0008-impossible-travel-detection.md);
  [0012-enrollment-trust-modes](0012-enrollment-trust-modes.md) (VENUE guest/monitored
  enrollments are the natural consumers of this route-and-inspect verdict path);
  [connection-type-awareness.md](../roadmap/connection-type-awareness.md);
  [venue-guest-network.md](../roadmap/venue-guest-network.md);
  [msp-central-management.md](../roadmap/msp-central-management.md)

> Records an architecture decision; it does not design the implementation. Values below
> (risk weights, percentages) are the captured design intent, to be validated when specced.

## Problem
WiFi devices have **no Suricata coverage** (the promiscuous-mode limitation — WiFi traffic
isn't on the monitored span). A naive exit node (route **all** device traffic through the
Nemesis box) closes the coverage gap but creates a **bandwidth bottleneck** — all device
traffic hits the home connection twice. Unacceptable for SMB, remote workers, and venue guest
networks.

## Decision
**The tunnel carries decisions, not data.** DNS queries, IP-reputation checks, and traffic
metadata flow through the Tailscale tunnel for inspection; **actual data (approved
connections) flows directly** over the device's local internet connection. Nemesis acts as an
**inspection proxy, not a data relay**.

## Three inspection layers

### Layer 1 — DNS inspection (lowest overhead)
Device DNS query → tunnel → Pi-hole → verdict.
- **Blocked:** NXDOMAIN — the connection never happens.
- **Clean:** IP returned, device connects directly.
- **Bandwidth cost:** negligible (DNS packets are tiny).

### Layer 2 — IP reputation (small overhead)
The agent checks the destination IP against the Nemesis AbuseIPDB **verdict cache** before any
new connection.
- **Known bad:** blocked before the connection is established.
- **Clean / cached:** direct connection allowed.
- **Bandwidth cost:** negligible (metadata only; cache hit rate >99%).

### Layer 3 — Traffic inspection (selective)
Suspicious traffic (new destinations, unusual ports, medium risk) → routed through the tunnel
for **Suricata** inspection. Approved/cached traffic → direct connection, no tunnel overhead.
- **Bandwidth cost:** only the suspicious subset (~1% after the cache warms).

## Verdict cache (critical for performance)
Warms over the first 24h. After warm-up, **<1% of traffic hits the tunnel**; repeat
connections go direct. Cache entries have a **TTL by threat type** (DNS indicators decay faster
than file hashes).

## Bandwidth reality
- **First hour:** moderate tunnel traffic (building the cache).
- **After 24h:** <1% through the tunnel (cache warm).
- **Ongoing:** only new/suspicious destinations hit the tunnel.
- **Net:** full security coverage, negligible bandwidth impact.

## WiFi coverage — the key solve
- **Mode 1 (security stack only):** WiFi → internet direct. Suricata blind. Pi-hole manual only.
- **Mode 2 (inspection proxy):** WiFi → tunnel → Nemesis inspection → internet. **Full Suricata
  coverage, Pi-hole automatic** — bypasses the WiFi promiscuous-mode limitation completely.

**Coverage matrix:**

| Connection | Mode 1 | Mode 2 |
|---|---|---|
| **WiFi** | ⚠️ Limited | ✅ Full (tunnel = ethernet-equivalent) |
| **Ethernet** | Partial | ✅ Maximum |

(See [connection-type-awareness.md](../roadmap/connection-type-awareness.md) — Mode 2 is what
turns a WiFi device's coverage from `not_applicable` to full.)

## Device routing modes
- **Mode 1 — management channel only** (default for BYOD / user devices).
- **Mode 2 — full inspection proxy** (default for owned / enrolled devices).

A **dashboard toggle per device** selects the mode. BYOD requires **explicit user consent** —
a **"Request exit node consent"** button rather than a direct toggle.

## ZTNA enforcement
- **No enrolled agent = no internet** (captive portal).
- Captive portal → install agent → **pre-enrollment scan (must be clean)** → owner approves →
  **Mode 2 activated** → internet via the inspection tunnel.
- **The tunnel IS the access credential.** Router firewall: only Tailscale-tunneled devices get
  internet.

## Venue guest network
QR code → install guest app → **TOS disclosure** → **auto-approve after a clean scan** → WiFi
access via the inspection tunnel. (See [venue-guest-network.md](../roadmap/venue-guest-network.md).)

**TOS (mandatory, prominent):** traffic inspected for malware/malicious content while on-site;
no browsing history stored; no data sold; inspection active only while connected to this
network.

The guest app stays useful after the visit → **user-acquisition funnel**. Repeat guests
**restore their historical behavioral baseline on reconnection**, so a compromised returning
device is detected **at reconnection, before network access is granted**.

## Agent dual role
- **Outbound:** sends connection requests to Nemesis for inspection, connects directly if
  approved.
- **Inbound:** receives inspected/approved traffic, delivers to the app.
- The agent is the **enforcement point**. No agent = no Mode 2.

## Enterprise equivalent
Cloudflare Gateway (DNS inspection) + Zscaler (SSE / inspection proxy) + Cisco ISE (NAC / ZTNA)
— **self-hosted, no per-user fees, data stays local**. Industry terms: **SASE / SSE**.

## Addendum (2026-07-30) — multi-site deployments are a distinct case

> Capture-only. **No change to the Decision above for single-site deployments.** This records a
> case the original reasoning was not evaluated against.

The "tunnel carries decisions, not data" decision rests on an explicitly **single-site** bandwidth
argument: *"all device traffic hits the home connection twice. Unacceptable."* That is sound for a
home or single office, where relaying internet-bound traffic through the local box is a pointless
hairpin.

**It does not transfer to multi-site deployments.** Consider a small franchise: a server at one
location, other sites connecting via agents, with POS and back-office tooling at each. The traffic
that matters — site-to-site business data — is **already crossing the public internet**. Routing
it through the tunnel adds no hairpin, because it was inter-site regardless. The bandwidth
objection largely evaporates while the confidentiality benefit is real.

Today, only agent↔server telemetry rides the tunnel. Inter-site application traffic (sales,
inventory, back-office sync) travels with whatever encryption the application itself provides.

**Direction (not yet built):** subnet routing for **inter-site** traffic, direct for
**internet-bound** traffic, decisions over the tunnel for both. This is additive to the Decision
above rather than a reversal of it — that Decision concerns internet-bound data, and inter-site
traffic is a different class.

**Prerequisite, not optional:** subnet routing increases lateral-movement exposure — a compromised
enrolled device gains routed reach into every advertised site network. Per-peer access controls
restricting which peers reach which networks and ports must ship **with** subnet routing, not
after it. Enabling routing without them trades a confidentiality gap for a worse lateral-movement
gap.

**Compliance:** deployments handling payment data need scoping by a qualified assessor before
either subnet routing or Tier 2 inspection is enabled. Detail is held privately with the Tier 2
design.

## AI hacking inflection point
AI-assisted attacks are becoming the default vector. Signature-based detection fails against
AI-generated novel malware. **Behavioral inspection catches malware by what it DOES, not what
it IS.** An enrolled fleet enables high-confidence lateral-movement detection; venue
enforcement closes the highest-risk public-WiFi attack surface.
**Product thesis:** *"AI makes attacking easy. Nemesis makes defending automatic. No IT
department required."*

## Enrollment enriches detection
Every enrolled device has a behavioral baseline (connection graph, typical ports, normal hours,
connection count). Lateral-movement detection uses this baseline for high-confidence verdicts:
a weighted, additive scoring model (new connections between enrolled devices, connections
following a recent finding, unusual ports, sensitive targets, off-hours activity all contribute)
escalating through two tiers (investigate / isolate). **Exact weights and thresholds documented
internally, not in the public repo** (2026-07-26 disclosure audit) — a source-visibility
decision, not a feature-gating one; this scoring runs at every tier regardless. Compounding:
baselines mature over time → fewer false positives (Day 1 sparse → Month 6 near-zero). Feeds, and is fed by,
[0008-impossible-travel-detection](0008-impossible-travel-detection.md).

## Sequencing
- **Layer 1 (DNS):** buildable now (Pi-hole exists; needs tunnel routing).
- **Layer 2 (IP reputation):** next (AbuseIPDB cache exists; agent-side check before connections).
- **Layer 3 (Suricata inspection):** after the agent rebuild (config-pull pushes inspection
  rules to agents).
- **Full ZTNA enforcement:** V2 (needs the mobile agent + captive portal).
- **Venue guest network:** V2 (needs the mobile agent + auto-approve flow).
- **MSP cross-site enforcement:** V3+ (see [msp-central-management.md](../roadmap/msp-central-management.md)).

## Addendum (2026-07-25) — L3 direction finalized: three-tier structure

> Capture-only (Window 2, docs/audit — no code, no build). Full day's design session covering
> the L3 zero-day architecture, TLS interception, and the business/resource model. **Status:
> direction decided, NOT built.** This refines the selection model in
> [adr-0009-l3-fork-b-scope.md](../roadmap/adr-0009-l3-fork-b-scope.md) — that doc's Piece 1–5
> redirect/NAT/return-path/fail-safe mechanics **still apply as the underlying transport**; this
> addendum changes **what triggers the redirect** and adds a behavioral layer on top.
> **Consolidated same-day into a three-tier structure** (§0 below) that supersedes/extends this
> addendum's original two-layer framing without discarding it — sections 1–5 below are now
> specifically **Tier 1's** detail. Companion scoping docs:
> [adr-0009-l3-behavioral-trigger-scope.md](../roadmap/adr-0009-l3-behavioral-trigger-scope.md)
> (Tier 1's trigger engine),
> [tls-interception-sterilization-scope.md](../roadmap/tls-interception-sterilization-scope.md)
> (Tier 2, now including the full undetectable-inline design),
> [adr-0009-l3-tier3-local-triggers-scope.md](../roadmap/adr-0009-l3-tier3-local-triggers-scope.md)
> (Tier 3, new).
>
> **Extended again 2026-07-26:** Open Item 1's Fork-B mirror-vs-inline documentation gap is now
> **RESOLVED** (see §6 and Open Items below) — Fork B is confirmed **mirror**. §6 also gains a
> **hybrid inline/mirror transition** design for Tier 2: a per-connection gate on the first
> meaningful chunk of decrypted application data, plus transition-hardening requirements that
> close a real timing-based bypass. Full detail:
> [tls-interception-sterilization-scope.md](../roadmap/tls-interception-sterilization-scope.md)
> (new Piece J).

### 0. Three-tier structure

Nemesis's zero-day detection is a three-tier system. Each tier is independent and gracefully
degrades to the tier below it if unavailable.

- **Tier 1 — Mirror/passive detection (default, always on).** Out-of-band behavioral and
  metadata analysis on tapped/mirrored traffic — no side channel is possible because the
  inspection point is never in the actual traffic path. The safe, market-proven default every
  Nemesis deployment gets regardless of Tier 2/3 configuration. **This is sections 1–5 below**:
  origin-based routing, the trigger/catch model, the hard sensor-only principle, the dynamic
  cache, and shared fleet intelligence. Escalates to Tier 2 on high-confidence behavioral
  triggers.
- **Tier 2 — Full inline inspection (toggle, off by default).** Active decrypt/inspect/
  re-encrypt on the tunnel (**hybrid, added 2026-07-26**: inline-gated on a connection's first
  meaningful decrypted chunk, then mirror for the rest — see §6) — full payload visibility
  Tier 1 structurally cannot have. When enabled, Nemesis attempts to make the fact of inspection
  itself undetectable to anything observing the connection. **A genuine R&D goal, not a
  guaranteed property** — see
  [tls-interception-sterilization-scope.md](../roadmap/tls-interception-sterilization-scope.md)
  for the full undetectable-inline design and its honest caveats. Summary: §6 below.
- **Tier 3 — Client-side late triggers (always on, narrow scope).** A short, fixed list of
  local, immediate agent actions that fire in milliseconds, without a server round-trip, to
  interrupt ransomware/malware that got past Tiers 1 and 2 before damage becomes irreversible.
  Requires an explicit, narrow exception to §3's sensor-only principle — see the amended §3 and
  [adr-0009-l3-tier3-local-triggers-scope.md](../roadmap/adr-0009-l3-tier3-local-triggers-scope.md).
  Summary: §7 below.

### 1. Origin-based WiFi routing (replaces destination-based reasoning)
**WiFi-origin traffic is ALWAYS a candidate for the tunnel pipeline, regardless of
destination** (internal or external). **Wired-origin traffic is already covered by the
existing LAN tap/promiscuous Suricata capture — no tunnel needed for it, ever.**

This removes the **topology-dependency** that Fork B's original selection model had: Fork B's
Piece 1 (`adr-0009-l3-fork-b-scope.md`) selects flows for redirect purely on the **reputation
verdict** (clean/bad/unknown) with no origin check — meaning, as scoped, it would just as
happily try to redirect a wired device's unknown-reputation flow, which is both unnecessary
(LAN Suricata already sees it) and wasteful (full-flow WinDivert redirect is the single
biggest-unknown piece of Fork B). **The origin check is a gate that sits in front of Fork B's
existing reputation-based selection**: `origin == WiFi` is a prerequisite for a flow to even be
considered for redirect; `origin == wired` flows never enter the redirect path at all,
independent of their reputation verdict.

### 2. Two-layer model — trigger (server) + catch (tunnel)
- **Layer (a) — the TRIGGER.** Continuous, lightweight, **server-side** rule-based
  behavioral/pattern scoring — same shape as the existing lateral-movement risk-weight table
  (ADR 0009 "Enrollment enriches detection" above — exact weights/thresholds documented
  internally). **Open question whether this literally reuses that engine or runs as a parallel
  one** — see Open Items below.
- **Layer (b) — the CATCH.** Tunnel-routed Suricata payload inspection (Fork B's transport),
  invoked on **either** of two triggers:
  1. Unknown reputation verdict (the **original** Fork-B trigger, unchanged), OR
  2. A **behavioral escalation signal** on a previously-cached-clean destination/pattern (the
     **new** trigger this addendum adds).

### 3. Hard principle — the agent is a sensor and enforcement point ONLY
**The agent NEVER performs pattern-matching, scoring, or classification judgment locally. ALL
detection logic/judgment lives server-side.** This is a **hard product requirement** — it
preserves the self-hosted-central-server value proposition — **not** a cost-driven engineering
preference that could reverse under different assumptions. It applies to every layer above:
the agent reports telemetry and enforces verdicts (drop/allow/redirect via WinDivert); it never
decides what's suspicious.

**This is the default and the floor.** With Tier 2 and Tier 3 toggled OFF, the agent remains a
pure telemetry sensor/enforcement point exactly as stated above — no change to that case,
regardless of anything below.

**The narrow Tier 3 exception (added 2026-07-25).** When Tier 3 is toggled ON, the agent may
act unilaterally ONLY on the enumerated trigger list in
[adr-0009-l3-tier3-local-triggers-scope.md](../roadmap/adr-0009-l3-tier3-local-triggers-scope.md)
— nothing else is ever judged locally. This is an **explicit, narrow, auditable carve-out, not
a general loosening** of the sensor-only principle: the agent still never judges *ambiguous*
traffic — that stays server-side, always, in every tier. The exception is scoped to
*executing a fixed, pre-defined emergency stop on an unambiguous signal*, a categorically
different act from investigation or classification.

**Why the exception exists — the reasoning, not just the rule.** Ransomware's most damaging
actions (shadow-copy/backup deletion, mass file encryption) happen in a tight window after a
payload executes. By the time agent telemetry reaches the server and a verdict returns, that
window has usually already closed — **a server round-trip is simply too slow to interrupt it.**
This is the one case in the whole L3 design where "sensor only, judgment is server-side" cannot
hold literally, and it is the *only* case: outside the enumerated Tier 3 trigger list, this
principle is absolute.

**This has become central enough across today's design session (L3, TLS, the behavioral
trigger) that it may be worth a durable mention in `CLAUDE.md`'s Architecture section — flagged
for the operator's call, not done here** (capture-only session; a change to core operating
discipline shouldn't be made silently).

### 4. Dynamic cache (replaces the static TTL-only reputation cache)
A destination/pattern's cached-clean status can now be **invalidated by a behavioral signal**,
not just time expiry.

**Honest limit — accepted, named, not resolved:** an already-established, in-flight connection
likely **cannot** be cleanly converted to tunneled/inspected mid-stream. This is the parallel
problem to Fork B's Piece 5 (fail-open-for-in-flight-flows) **in reverse** — there it's "can't
safely pull an in-flight redirected flow back to direct"; here it's "can't safely push an
in-flight direct flow into inspection." The realistic mechanism:
- Invalidate the cache entry **going forward** — the **next** connection to that
  destination/pattern gets inspected.
- The **current** connection that triggered the signal is flagged/alerted via the existing
  alert pipeline, even though it may complete **uninspected**.

State this as an accepted, named limitation — **not** a promise of real-time interception.

### 5. Shared fleet intelligence
The server aggregates telemetry across **all enrolled devices**, does the classification, and
**pushes resulting verdicts/pattern classifications back down to the whole fleet** — collective
intelligence, detection stays 100% server-side.

**Flagged overlap, not resolved:** this likely overlaps with the parked roadmap items
[community-signal-dedup.md](../roadmap/community-signal-dedup.md) (global cross-install signal
aggregation) and [open-source-threat-feeds.md](../roadmap/open-source-threat-feeds.md) (external
IOC feeds normalized into the same signal schema). Those operate at **community/global** scope
(across all Nemesis installs); this fleet-intelligence layer operates at **single-customer
fleet** scope (across one owner's enrolled devices). Related shapes, different scope — **flag
for later consolidation, do not build three parallel aggregation-and-pushback systems.**

### 6. Tier 2 — full inline inspection (summary; full design in the TLS scoping doc)
Active TLS decrypt/inspect/re-encrypt on the tunnel, toggled OFF by default. When ON, Nemesis
attempts genuine per-connection indistinguishability — nothing about the client-facing
connection (cert presentation, timing, packet-level artifacts) should differ between a locally
cache-cleared connection and one actually deep-inspected. **No NDR market leader or commercial
inline-interception vendor attempts this today** — real, unclaimed differentiation, but also an
unsolved problem industry-wide; treat as an R&D goal with a validation plan, not a guaranteed
shipped property.

**Confirmed build order:** validate against a controlled, fixed VM destination first (a strict
subset of the general arbitrary-internet-traffic problem — solving the general case covers this
one, not vice versa, so it's a real checkpoint), then generalize to arbitrary destinations.
**Implementation-level detail (side-channel normalization, cache design, dual randomization,
evasion-probing handling, pinned-app allowlisting) is documented internally, not in the public
repo** — a source-visibility decision, not a feature-gating one (Tier 2 ships at every tier
regardless). The general shape of each piece stays in
[tls-interception-sterilization-scope.md](../roadmap/tls-interception-sterilization-scope.md).

**Hybrid inline/mirror transition (added 2026-07-26) — replaces the assumption that Tier 2,
once engaged for a connection, stays fully inline (gating delivery) for that connection's whole
life.** It does not: an initial portion of decrypted application data is inline-gated, then the
connection transitions to mirror (inspected, no longer delivery-gated) for the rest of its
life — hardened against a real timing-based bypass. **This is the only place in the whole L3
design where delivery is ever actually gated pending a verdict** — Fork B's own tunnel
transport is confirmed pure mirror (see Open Items below and
[adr-0009-l3-fork-b-scope.md](../roadmap/adr-0009-l3-fork-b-scope.md)). **Implementation-level
detail (the gate boundary and hardening mechanics) documented internally, not in the public
repo** — same source-visibility framing as above; general shape:
[tls-interception-sterilization-scope.md](../roadmap/tls-interception-sterilization-scope.md)
(Piece J).

**Correction — Tier 2 does not guarantee first-contact prevention.** Tier 2, including this
hybrid gate, does **not** prevent an undetected zero-day payload from reaching its destination
on the very first inline-gated chunk if that chunk itself looks clean. What Tier 2 provides is
**fast detection** and **rapid future-blocking** via the dynamic cache (§4), plus this partial
first-contact gate — not a guarantee against a clean-looking first payload. **Tier 3's local
late-triggers (§7) are the actual backstop** for a payload that gets through Tiers 1 and 2
undetected and begins executing locally. This is **intentional defense-in-depth across the
three tiers**, not a gap unique to Tier 2.

### 7. Tier 3 — client-side late triggers (summary; full design in the Tier 3 scoping doc)
A short, fixed, always-on list of local agent actions that fire in milliseconds on an
unambiguous signal, without a server round-trip — the narrow exception to §3 above. On trigger:
block/freeze the responsible process and the specific write immediately, alert, and hand off to
the server for confirmation and forensics **after the fact** — the server's role shifts from
real-time authorizer (every other tier, every other case) to after-the-fact investigator, only
for the enumerated triggers. Full trigger list (deliberately kept as a living list, not a locked
spec — which entries ship/get tuned/get dropped is TBD during build/testing) in
[adr-0009-l3-tier3-local-triggers-scope.md](../roadmap/adr-0009-l3-tier3-local-triggers-scope.md).

### Open items from this session (see also the three companion scoping docs)
**Items 2–4 below are confirmed unchanged by the 2026-07-25 three-tier consolidation** —
intentionally left open; testing during the build may drive the answers rather than a decision
made in advance. (Tier 3's own two new open items — the mass-file-operation trigger's
keep/tune/drop call, and the evasion-probing-vs-cert-pinning disambiguation problem — are
recorded inline at their relevant points in the Tier 3 and TLS scoping docs respectively, not
listed again here.)
1. **Agent-to-agent WiFi traffic** (both ends enrolled): **which end's agent redirects.**
   **RESOLVED (2026-07-25).**
   - **DECISION — one redirect owner per flow:**
     - **Origin (initiating) agent owns the redirect when the origin is ENROLLED.**
     - **Destination agent owns the redirect when the origin is NOT enrolled.**
   - **Rationale:** consistency with the already-locked origin-based selection rule (§1
     above — one rule, not two ends of the same flow independently deciding), and avoiding
     duplicate tunneling of the same flow. **Resource cost is the deciding constraint here,
     not correctness alone** — either end could in principle apply the rule correctly; only
     one should pay the tunneling cost.
   - **New dependency, NOT built, must be scoped:** the destination-owns-it clause requires
     an agent to know whether an arbitrary peer is itself enrolled. Agents do not have that
     state today. Implies fleet-roster distribution or a peer-enrollment lookup on the
     heartbeat. Named as its own piece —
     [adr-0009-l3-behavioral-trigger-scope.md](../roadmap/adr-0009-l3-behavioral-trigger-scope.md)
     Piece 5.
   - **Principle clarification:** peer-enrollment lookup is **enforcement routing** (which
     already-enrolled agent applies an already-server-decided rule), **NOT detection
     judgment**. On a fast read this looks like the agent making a decision — it isn't. The
     agent still never scores or classifies anything; it only resolves which of two
     equally-valid enforcement points applies the redirect. Does **not** violate §3's
     agent-is-a-sensor-only principle.
   - **Server-side backstop:** if the server ever receives the same 5-tuple tunneled from
     two different agents, that is a **bug in the ownership rule's implementation** — log
     it; do **not** enforce on it (no additional blocking/dropping triggered by the
     duplicate itself).
   - **RESOLVED (2026-07-26) — previously an unresolved sub-item.** The ownership decision above
     stands either way, but whether it actually **protects the receiving end** depended on
     whether Fork B's tunnel is INLINE or MIRROR. **Confirmed: MIRROR.** Piece 2's forward is
     unconditional (no verdict gate anywhere in it); Piece 3's Suricata is a passive `af-packet`
     interface (the same passive-capture pattern as the existing LAN tap). Re-reading both
     pieces together: there was never an actual contradiction between them — both were always
     internally consistent with mirror; the doc simply never stated the choice explicitly until
     now. **Consequence, now confirmed rather than merely feared:** an origin-owned redirect
     through Fork B's tunnel does **not** gate traffic reaching the destination — it can only
     alert/escalate after the fact. Full resolution:
     [adr-0009-l3-fork-b-scope.md](../roadmap/adr-0009-l3-fork-b-scope.md) ("Mechanism: MIRROR"
     section). **This does not mean the whole L3 pipeline never gates delivery** — see §6's new
     hybrid inline/mirror transition, which gates delivery one layer up, inside Tier 2, for
     connections it has decrypted.
   - **Flagged edge case — detail documented internally, not in the public repo (2026-07-26
     disclosure audit).** Enrolled-to-enrolled WiFi traffic on the same AP has a real,
     unresolved cost-to-value tension with the origin-based rule (§1). Not resolved here; a
     source-visibility decision, not a feature-gating one.
2. **Does the new behavioral-trigger engine reuse the EXISTING lateral-movement risk-scoring
   engine (this ADR's "Enrollment enriches detection" table) or run as a separate system?** —
   UNRESOLVED.
3. **No target hardware baseline exists yet** (minimum customer-hardware spec, mini-device
   SKU) — needed before ANY of today's new scope gets real session estimates or resource
   validation. This is why Steps 2/3's scoping docs explicitly do not carry a session estimate.
4. **TLS resource-tension** (see `tls-interception-sterilization-scope.md` §c) — how much of a
   network's traffic genuinely needs decrypting for effective zero-day coverage is a real,
   unresolved architectural question, not assumed away by deciding to build TLS interception.

## Connections
- [ADR 0005](0005-dns-firewall-device-auth-architecture.md) — device auth (keypair =
  enrollment credential).
- [ADR 0007](0007-device-user-model.md) — device-user model (ownership → Mode default).
- [ADR 0008](0008-impossible-travel-detection.md) — impossible travel (behavioral baseline
  feeds both).
- [agent-rebuild-config-driven.md](../roadmap/agent-rebuild-config-driven.md) — config-pull
  pushes inspection rules.
- [msp-central-management.md](../roadmap/msp-central-management.md) — cross-site enforcement (V3+).
- [nemesis-test-lab.md](../roadmap/nemesis-test-lab.md) — the VM mirrors the real inspection config.
- `CONTRIBUTING.md` — modules must not bypass the inspection layer.
- [connection-type-awareness.md](../roadmap/connection-type-awareness.md) — Mode 2 solves the
  WiFi gap.
- [adr-0009-l3-fork-b-scope.md](../roadmap/adr-0009-l3-fork-b-scope.md) — the redirect/NAT/
  return-path/fail-safe transport this addendum's trigger model sits on top of; **now confirmed
  mirror** (2026-07-26 — see its "Mechanism: MIRROR" section, and §6/Open Item 1 above).
- [adr-0009-l3-behavioral-trigger-scope.md](../roadmap/adr-0009-l3-behavioral-trigger-scope.md) —
  2026-07-25 engineering-cost scoping for the new behavioral trigger layer (TBD estimate).
- [tls-interception-sterilization-scope.md](../roadmap/tls-interception-sterilization-scope.md) —
  Tier 2: TLS decrypt-inspect-reencrypt + sterilization + the full undetectable-inline design
  (TBD estimate).
- [adr-0009-l3-tier3-local-triggers-scope.md](../roadmap/adr-0009-l3-tier3-local-triggers-scope.md) —
  Tier 3: the local late-trigger list and the §3 sensor-only exception's auditable
  implementation (new, 2026-07-25).
- [community-signal-dedup.md](../roadmap/community-signal-dedup.md),
  [open-source-threat-feeds.md](../roadmap/open-source-threat-feeds.md) — flagged possible
  overlap with the addendum's shared-fleet-intelligence push-back (not resolved; see addendum §5).
- [ADR 0016 — guest marketing capture](0016-guest-marketing-capture.md) — its PII
  network-transit addendum reuses this ADR's Tier 1 behavioral-anomaly engine at a new
  chokepoint (the export API), scoped separately from Tier 2/3 (2026-07-26).
