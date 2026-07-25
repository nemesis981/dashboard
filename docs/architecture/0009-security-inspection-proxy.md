# ADR 0009 — Security Inspection Proxy (Self-Hosted SSE)

- **Status:** Proposed (architecture decided 2026-06-28; design captured, **no code changed**).
  **See the 2026-07-25 addendum below** — the L3 selection model is finalized (origin-based
  routing + two-layer behavioral trigger), refining/superseding parts of
  `adr-0009-l3-fork-b-scope.md`'s original trigger criteria. Still **not built**.
- **Date:** 2026-06-28 (L3 addendum: 2026-07-25)
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
- New connection between enrolled devices: **risk +30**
- Connection after a recent finding on the src device: **risk +40**
- Unusual port for this device: **risk +15**
- Sensitive target (server / NAS): **risk +20**
- Outside normal hours: **risk +15**

**Score ≥70: CRITICAL → isolate. Score ≥40: HIGH → investigate.** Compounding: baselines mature
over time → fewer false positives (Day 1 sparse → Month 6 near-zero). Feeds, and is fed by,
[0008-impossible-travel-detection](0008-impossible-travel-detection.md).

## Sequencing
- **Layer 1 (DNS):** buildable now (Pi-hole exists; needs tunnel routing).
- **Layer 2 (IP reputation):** next (AbuseIPDB cache exists; agent-side check before connections).
- **Layer 3 (Suricata inspection):** after the agent rebuild (config-pull pushes inspection
  rules to agents).
- **Full ZTNA enforcement:** V2 (needs the mobile agent + captive portal).
- **Venue guest network:** V2 (needs the mobile agent + auto-approve flow).
- **MSP cross-site enforcement:** V3+ (see [msp-central-management.md](../roadmap/msp-central-management.md)).

## Addendum (2026-07-25) — L3 direction finalized: origin-based routing + two-layer behavioral model

> Capture-only (Window 2, docs/audit — no code, no build). Full day's design session covering
> the L3 zero-day architecture, TLS interception, and the business/resource model. **Status:
> direction decided, NOT built.** This refines the selection model in
> [adr-0009-l3-fork-b-scope.md](../roadmap/adr-0009-l3-fork-b-scope.md) — that doc's Piece 1–5
> redirect/NAT/return-path/fail-safe mechanics **still apply as the underlying transport**; this
> addendum changes **what triggers the redirect** and adds a behavioral layer on top. Companion
> scoping docs: [adr-0009-l3-behavioral-trigger-scope.md](../roadmap/adr-0009-l3-behavioral-trigger-scope.md),
> [tls-interception-sterilization-scope.md](../roadmap/tls-interception-sterilization-scope.md).

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
  (ADR 0009 "Enrollment enriches detection" above: `risk +30/+40/+15/+20/+15`, thresholds
  `≥70 CRITICAL / ≥40 HIGH`). **Open question whether this literally reuses that engine or runs
  as a parallel one** — see Open Items below.
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

### Open items from this session (see also the two companion scoping docs)
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
   - **Unresolved sub-item — recorded, not resolved:** the ownership decision above stands
     either way, but whether it actually **protects the receiving end** depends on whether
     Fork B's tunnel is **INLINE** (origin → server → destination; server can drop before
     forwarding) or **MIRROR** (traffic goes direct; a copy is sent for inspection only). If
     MIRROR, an origin-owned redirect never gates traffic reaching the destination — it can
     only alert after the fact. **`adr-0009-l3-fork-b-scope.md` does not state which**:
     Piece 2 describes the server forwarding + NAT'ing the flow (sounds inline), but Piece 3
     adds Suricata via a passive `af-packet` capture interface (the same passive-capture
     mechanism as the existing LAN tap) without ever stating whether the forward is gated on
     Suricata's verdict. **Recorded here as a documentation gap in the Fork-B scope doc**,
     not resolved by this addendum.
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
  return-path/fail-safe transport this addendum's trigger model sits on top of.
- [adr-0009-l3-behavioral-trigger-scope.md](../roadmap/adr-0009-l3-behavioral-trigger-scope.md) —
  2026-07-25 engineering-cost scoping for the new behavioral trigger layer (TBD estimate).
- [tls-interception-sterilization-scope.md](../roadmap/tls-interception-sterilization-scope.md) —
  2026-07-25 scoping for the TLS decrypt-inspect-reencrypt + sterilization layer (TBD estimate).
- [community-signal-dedup.md](../roadmap/community-signal-dedup.md),
  [open-source-threat-feeds.md](../roadmap/open-source-threat-feeds.md) — flagged possible
  overlap with the addendum's shared-fleet-intelligence push-back (not resolved; see addendum §5).
