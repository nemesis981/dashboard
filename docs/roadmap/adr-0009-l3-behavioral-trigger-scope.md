# ADR 0009 — L3 behavioral-trigger engineering cost (scope, not estimate)

**Status:** scoping doc (read-only analysis; no code changed). Captured 2026-07-25, same
session as the [ADR 0009 addendum](../architecture/0009-security-inspection-proxy.md) that
finalized the origin-based routing + two-layer trigger/catch model — since consolidated into a
**three-tier structure** (addendum §0); this doc scopes **Tier 1's** trigger engine. Companion
to [adr-0009-l3-fork-b-scope.md](adr-0009-l3-fork-b-scope.md) (the redirect/NAT/return-path
transport this trigger sits on top of),
[tls-interception-sterilization-scope.md](tls-interception-sterilization-scope.md) (**Tier 2**,
same session), and
[adr-0009-l3-tier3-local-triggers-scope.md](adr-0009-l3-tier3-local-triggers-scope.md)
(**Tier 3**, new — where process-lineage anomalies flagged by this engine stay server-side per
its own §3, rather than joining Tier 3's local action list).

> **NO SESSION ESTIMATE IN THIS DOC — DELIBERATELY.** This is **additive scope on top of the
> already-scoped ~13–23 session Fork-B mechanics**, and per the operator's explicit instruction
> this session: estimate final counts here would be premature. **Mark TBD — this needs its own
> dedicated scoping session**, the same treatment the original Fork-B correction got (the
> build-scope doc's "small selective-routing increment" line turned out to need a full 13–23
> session re-scope once broken into pieces; this doc gives the behavioral-trigger layer the same
> piece-by-piece treatment, honest about unknowns, without jumping to a number before a target
> hardware baseline exists — see Open Item 3 below).

## The model (what's being scoped)
The [ADR 0009 addendum](../architecture/0009-security-inspection-proxy.md) adds a **trigger
layer (a)** in front of the existing **catch layer (b)** (Fork B's tunnel-routed Suricata
inspection). Layer (a) is new capability with **no existing scope anywhere** — it isn't a
variant of anything already built or costed. This doc breaks that new capability into pieces,
the same way `adr-0009-l3-fork-b-scope.md` broke Fork B's transport into 5 pieces.

---

## Piece 1 — Continuous flow-telemetry ingestion pipeline (agent → server)
**What:** the agent must continuously stream flow-level telemetry (connections, ports,
destinations, timing/volume shape) to the server for scoring — **new capability, not present in
any existing scope.** The existing heartbeat/hw-metrics channel (300s poll) is a fundamentally
different shape (periodic point-in-time snapshot) from what a behavioral trigger needs
(continuous or near-continuous flow events).

- **Volume/frequency question:** does every flow get reported, or only flows matching some
  cheap local pre-filter? A hard product requirement (§3 of the addendum) is that the agent
  performs **zero judgment** — so any pre-filter must be a **fixed, server-defined rule**
  (e.g. "report all new outbound connections"), not agent-side heuristic scoring. That still
  leaves an open question of whether "all new connections" is a tolerable telemetry volume at
  scale (one home network vs. an MSP's multi-site fleet).
- **Transport:** does this ride the existing `:5001` hw-monitor channel, a new endpoint, or the
  same tunnel Fork B's redirect uses? Undecided — depends on Fork-B's Piece 1/2 transport
  details once built.
- **Complexity:** genuinely new agent capability (not an extension of `l2_windivert.py`'s
  drop/allow/redirect model) — this is an **observability** feed, not an enforcement action.

**Confidence:** low — no existing precedent in this codebase for continuous flow-telemetry
streaming (the closest analog, hw-monitor heartbeat, is periodic snapshot, not flow-level).

---

## Piece 2 — Server-side correlation/scoring engine (runs parallel to the lateral-movement work, one shared data layer)
**What:** the continuous rule-based behavioral/pattern scorer described in the addendum's
Layer (a).

**⛔ RESOLVED 2026-09-03 — Open Item #2 closed: PARALLEL, not reuse.** Full reasoning:
`adr-0009-build-scope.md`'s Phase 5 note and the analysis below; the durable version lives here
since this is the doc Open Item #2 was raised in.

- **Visibility is not the deciding factor, and resolving it doesn't make reuse correct.** Piece
  1's telemetry is agent-reported (the connecting device's own OS stack), so Piece 2 does **not**
  inherit the appliance's flat-L2 unicast blind spot that permanently constrains the shipped
  lateral-movement detectors (`post_detection_egress`, `lan_behavior_monitor` —
  `lateral-movement-outbreak-detection.md`). That gap being irrelevant to Piece 2 was the
  question this item was raised to answer, and the answer is yes — but three independent,
  non-visibility differences still rule out a shared engine:
  1. **Trigger shape.** Piece 2 is *continuous* — it scores every new connection from every
     agent, all the time (Piece 1's "report all new outbound connections"). The shipped
     lateral-movement mechanism is *event-triggered* — it only activates after an existing
     finding lands, over a bounded post-detection window (`CORRELATION_WINDOW_S = 600`,
     `modules/anomaly_detection/post_detection.py`). "Is this new connection suspicious" and
     "did this already-flagged device just start acting differently" are different questions,
     independent of what either can see.
  2. **Consumer and latency budget.** Piece 2's output feeds Fork B's Piece 3 cache
     invalidation — a routing/enforcement decision ("does the *next* connection get redirected
     to Suricata") that must be fast and mechanical. The lateral-movement table's output is a
     human-facing incident on a multi-minute window with no latency requirement. One engine
     serving both means one score semantics satisfying a real-time router and a slow alerting
     path — genuinely non-trivial, not a config change.
  3. **Data shape, not just data source.** The shipped detector was never built against a real
     connection graph — it runs on a narrower proxy (DNS-intent signals `dns_exfiltration`/
     `volume_spike`, plus `lan_probe_scan` discovery events) *because* the appliance couldn't see
     unicast peer traffic. Piece 2, if built, would produce the actual per-connection
     classification ADR 0009's original table envisioned but that was never shipped in any form.
     "Reuse" would not be reusing an existing engine at equal fidelity — there is no engine at
     that fidelity to reuse.
- **The one thing that should genuinely be shared: enrollment-baseline data, not the scorer.**
  "Has device X talked to Y before," typical ports/hours per device (ADR 0009's "Enrollment
  enriches detection" factors) — if Piece 1 ships, both systems want this baseline: Piece 2 for
  live novelty-scoring, lateral-movement detection for post-detection correlation. **One
  baseline store, two independent consumers** — see the forward-looking hook now in
  `lateral-movement-outbreak-detection.md`'s "Enrollment enriches detection" section.
- **Permanent floor, unaffected by this decision either way:** `lan_behavior_monitor` covers
  unmanaged/agentless devices (IoT, guest phones) that can never produce Piece 1 telemetry — no
  agent, no flow report. Piece 2 can never supersede that coverage in any future world, parallel
  or otherwise.
- This is server-side only (hard principle, addendum §3) — the agent contributes telemetry
  (Piece 1), never scores.

**Why this stays closed even if revisited:** if Piece 1/Fork-B never ships, this is moot. If it
does, the trigger-shape, consumer, and latency differences are architectural facts about what
each system is *for*, not artifacts of a visibility limit that better sensors could dissolve —
they don't go away once agent telemetry exists. The permanent-floor point above holds
independently of both.

**Confidence:** low on Piece 2's own build cost (still gated on Piece 1 and the whole Fork-B
program) — no longer blocked on an open design question.

---

## Piece 3 — Dynamic cache invalidation-on-signal + "next connection escalates, current one alerts"
**What:** the addendum's dynamic cache mechanism (§4) — replacing the static TTL-only
reputation cache with one a behavioral signal can invalidate mid-lifetime.

- **Cache invalidation propagation:** when the server's scoring engine (Piece 2) flags a
  previously-cached-clean destination/pattern, that invalidation has to reach every agent
  holding that cache entry — a push, not a pull (agents can't be expected to re-poll fast
  enough for this to be meaningful).
- **The accepted limitation is explicit, not a build task:** an in-flight connection is not
  retroactively inspected — only the *next* connection to that destination/pattern is. The
  current one is flagged/alerted via the existing alert pipeline. This piece's job is to build
  the invalidate-forward + alert-current mechanism cleanly, **not** to solve mid-stream
  interception (which the addendum already names as not cleanly achievable — parallel to Fork
  B's Piece 5 in reverse).
- **Interaction with Fork B:** once a destination/pattern is invalidated, the *next* connection
  to it needs to actually get redirected — i.e., this piece's output must plug into Fork B's
  Piece 1 selection logic (extending it beyond pure reputation-verdict lookup to also check
  "has this been behaviorally invalidated").

**Confidence:** medium for the mechanism itself (cache invalidation + push is a well-understood
pattern); low for the Fork-B integration point, which doesn't exist to integrate with yet.

---

## Piece 4 — Fleet-wide verdict push-back to all agents
**What:** the addendum's shared-fleet-intelligence layer (§5) — server aggregates across all
enrolled devices, classifies, and pushes verdicts back to the whole fleet.

- **Overlaps Piece 3's push mechanism** — likely the same delivery channel (cache
  invalidation-push and fleet-verdict-push are both "server tells agents something changed"),
  worth designing as one push capability rather than two.
- **Flagged overlap with existing roadmap items (not resolved here):** this is conceptually
  close to [community-signal-dedup.md](community-signal-dedup.md) and
  [open-source-threat-feeds.md](open-source-threat-feeds.md), which already do
  aggregate-and-distribute at **community/global** scope. This piece operates at
  **single-customer fleet** scope. Whether these end up as one push mechanism serving both
  scopes, or two deliberately separate ones, is unresolved — see the addendum §5 flag.

**Confidence:** low — depends on both the Piece 3 delivery-channel design and the
consolidation question with the community-signal systems.

---

## Piece 5 — Peer-enrollment lookup / fleet-roster distribution (redirect-ownership dependency)
**What:** the mechanism letting an agent determine whether an arbitrary WiFi peer is itself an
enrolled Nemesis agent. Required by the [ADR 0009 addendum](../architecture/0009-security-inspection-proxy.md)'s
**now-RESOLVED Open Item 1** (agent-to-agent redirect ownership: origin owns the redirect when
the origin is ENROLLED; destination owns it when the origin is NOT enrolled). This is a **new
dependency surfaced by resolving that open item** — not previously scoped anywhere, including in
this doc's original four pieces.

- **Two candidate mechanisms, not decided here:**
  1. **Fleet-roster distribution** — the server periodically pushes the set of enrolled device
     identifiers to every agent. Likely rides the **same delivery channel as Piece 4's**
     fleet-wide verdict push-back rather than a second push mechanism.
  2. **Peer-enrollment lookup on the heartbeat** — an agent asks the server, per new peer
     connection, "is this destination itself enrolled?" — a pull instead of a push.
  Roster-push is likely cheaper at typical fleet sizes (one periodic broadcast vs. a lookup per
  new peer) but goes stale between pushes; lookup-on-heartbeat is always current but adds a
  round-trip on the connection's critical path.
- **Principle note (restated from the addendum):** this lookup is **enforcement routing**
  (which already-enrolled agent applies an already-server-decided rule), **not detection
  judgment** — it requires no local scoring/classification and does not weaken the hard
  agent-is-a-sensor-only principle (addendum §3).
- **Server-side backstop is a safety net, not a substitute:** the addendum's backstop (log a
  same-5-tuple double-tunnel as a bug, don't enforce on it) covers the failure case where this
  piece's mechanism gets it wrong — it doesn't reduce the need for the mechanism to be mostly
  correct.
- **Depends on the same-AP tension (addendum §1, Open Item 1's flagged-not-decided note):**
  enrolled-to-enrolled WiFi traffic on the same AP is the worst cost-to-value case this piece
  has to serve — the roster/lookup mechanism has to exist even for the case where tunneling the
  flow is barely worth it.

**Confidence:** low — genuinely new capability, not an extension of anything already scoped;
shape depends on Piece 4's push-mechanism design (if roster-push is chosen) or adds a new
request/response path (if lookup-on-heartbeat is chosen).

---

## Total & confidence
```
TBD — needs its own dedicated scoping session.
```
This doc deliberately does **not** produce a piece-by-piece or total session estimate, per the
operator's explicit instruction this session. Rationale beyond that instruction: most of the
five pieces above are blocked on unresolved design questions (Open Item #2's reuse-vs-parallel
decision, the push-mechanism consolidation question, Piece 5's roster-vs-lookup choice), and
**no target hardware baseline exists** (Open Item #3) — estimating build sessions before knowing
what hardware this needs to run on and before those decisions are made would be a number without
a foundation, the same mistake the original build-scope doc's "small selective-routing increment"
line made for Fork B.

## Biggest unknowns (explicit)
1. ~~**Reuse-vs-parallel scoring engine (Piece 2 / Open Item #2)**~~ **RESOLVED 2026-09-03 —
   PARALLEL**, with one shared data layer (enrollment-baseline data, not the scorer). See Piece
   2 above for the full reasoning. Piece 2's own build cost is unaffected — still gated on Piece
   1 and the whole Fork-B program.
2. **Continuous telemetry volume at scale (Piece 1)** — no precedent in this codebase for
   flow-level streaming; unknown whether "report all new connections" is tolerable bandwidth/
   load at MSP multi-site scale vs. a single home network.
3. **Agent-to-agent WiFi redirect ownership is RESOLVED (Open Item #1, addendum)**, but resolving
   it surfaced a new unscoped dependency: **peer-enrollment lookup / fleet-roster distribution
   (Piece 5)** — roster-push vs. lookup-on-heartbeat not decided. The mirror-vs-inline question
   this item previously carried is **no longer open**: `adr-0009-l3-fork-b-scope.md` decided
   **MIRROR** on 2026-07-26 (its "Mechanism: MIRROR" section). The consequence for redirect
   ownership is therefore settled rather than feared — an origin-owned redirect does **not** gate
   traffic reaching its destination; it can only alert or escalate after the fact. Note this
   constrains Fork B's own transport only: a connection-level inline gate still exists one layer
   up in **Tier 2** (TLS interception), for connections Tier 2 has decrypted.
4. **No target hardware baseline (Open Item #3)** — blocks turning any of the above into a real
   session estimate or resource-cost validation.

## Cross-references
[ADR 0009 addendum](../architecture/0009-security-inspection-proxy.md) (the direction this
scopes, incl. the now-RESOLVED Open Item 1 that Piece 5 depends on),
[adr-0009-l3-fork-b-scope.md](adr-0009-l3-fork-b-scope.md) (the transport this trigger feeds
into, esp. Piece 1's reputation-verdict selection, and Pieces 2–3's MIRROR mechanism,
decided 2026-07-26), ADR 0009's "Enrollment enriches detection" table (Piece 2 runs **parallel**
to this, RESOLVED 2026-09-03 — see Piece 2 above), [community-signal-dedup.md](community-signal-dedup.md),
[open-source-threat-feeds.md](open-source-threat-feeds.md) (flagged overlap, Piece 4),
[lateral-movement-outbreak-detection.md](lateral-movement-outbreak-detection.md) (shipped,
separate engine from Piece 2 — **not** shared, per the 2026-09-03 resolution; shares only the
enrollment-baseline data layer, once Piece 1 exists),
[tls-interception-sterilization-scope.md](tls-interception-sterilization-scope.md) (Tier 2 —
Piece H there feeds evasion-probing signals into this doc's Piece 2 scoring engine),
[adr-0009-l3-tier3-local-triggers-scope.md](adr-0009-l3-tier3-local-triggers-scope.md) (Tier 3 —
the always-on local-trigger tier this engine's ambiguous/judgment-call signals explicitly do
NOT feed into; see that doc's §3 "Explicitly NOT in scope").
