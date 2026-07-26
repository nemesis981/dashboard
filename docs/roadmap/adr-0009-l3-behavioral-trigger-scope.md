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

## Piece 2 — Server-side correlation/scoring engine (extends or parallels the lateral-movement table)
**What:** the continuous rule-based behavioral/pattern scorer described in the addendum's
Layer (a). **Open Item #2 (unresolved, from the addendum): does this reuse the EXISTING
lateral-movement risk-weight table (ADR 0009 "Enrollment enriches detection" — exact
weights/thresholds documented internally, not in the public repo) or run as a separate,
parallel scoring system?**

- **If reused:** the existing table is scoped for **post-detection correlation between fleet
  devices** (lateral movement) — a different signal shape than "is this destination/pattern
  newly suspicious." Reuse would mean generalizing the table's inputs, which is itself
  non-trivial design work, not just a config change.
- **If parallel:** a second scoring engine means two systems to maintain, tune, and explain to
  the user — worth avoiding if the signal shapes are close enough to unify, but that unification
  question is exactly what's unresolved.
- **Either way:** this is server-side only (hard principle, addendum §3) — the agent contributes
  telemetry (Piece 1), never scores.

**Confidence:** low — blocked on the reuse-vs-parallel decision (Open Item #2), which is itself
unresolved and out of scope for this doc to settle.

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
1. **Reuse-vs-parallel scoring engine (Piece 2 / Open Item #2)** — unresolved; changes the
   shape of the whole server-side half of this work depending on the answer.
2. **Continuous telemetry volume at scale (Piece 1)** — no precedent in this codebase for
   flow-level streaming; unknown whether "report all new connections" is tolerable bandwidth/
   load at MSP multi-site scale vs. a single home network.
3. **Agent-to-agent WiFi redirect ownership is RESOLVED (Open Item #1, addendum)**, but resolving
   it surfaced a new unscoped dependency: **peer-enrollment lookup / fleet-roster distribution
   (Piece 5)** — roster-push vs. lookup-on-heartbeat not decided. Separately, whether the
   ownership decision actually *protects* anything depends on Fork B's tunnel being INLINE vs.
   MIRROR — **`adr-0009-l3-fork-b-scope.md` doesn't state which** (recorded as a documentation
   gap in the addendum, not resolved here).
4. **No target hardware baseline (Open Item #3)** — blocks turning any of the above into a real
   session estimate or resource-cost validation.

## Cross-references
[ADR 0009 addendum](../architecture/0009-security-inspection-proxy.md) (the direction this
scopes, incl. the now-RESOLVED Open Item 1 that Piece 5 depends on),
[adr-0009-l3-fork-b-scope.md](adr-0009-l3-fork-b-scope.md) (the transport this trigger feeds
into, esp. Piece 1's reputation-verdict selection, and Pieces 2–3's unstated INLINE-vs-MIRROR
gap), ADR 0009's "Enrollment enriches detection" table (the existing lateral-movement scoring
this may or may not extend), [community-signal-dedup.md](community-signal-dedup.md),
[open-source-threat-feeds.md](open-source-threat-feeds.md) (flagged overlap, Piece 4),
[lateral-movement-outbreak-detection.md](lateral-movement-outbreak-detection.md) (the
post-detection correlation work this may share an engine with),
[tls-interception-sterilization-scope.md](tls-interception-sterilization-scope.md) (Tier 2 —
Piece H there feeds evasion-probing signals into this doc's Piece 2 scoring engine),
[adr-0009-l3-tier3-local-triggers-scope.md](adr-0009-l3-tier3-local-triggers-scope.md) (Tier 3 —
the always-on local-trigger tier this engine's ambiguous/judgment-call signals explicitly do
NOT feed into; see that doc's §3 "Explicitly NOT in scope").
