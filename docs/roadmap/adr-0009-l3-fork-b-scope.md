# ADR 0009 — L3 Fork B scope & estimate (tunnel-routed central Suricata)

**Status (updated 2026-08-04 — READ THIS BEFORE THE PIECE BREAKDOWN BELOW):**
**Pieces 1 and 4 are RETIRED.** Once mirror was confirmed as Fork B's actual mechanism
(2026-07-26, see the section below), Piece 1's whole reason to exist — per-flow WinDivert
redirect state — had no remaining purpose: a per-flow redirect mechanism only matters if
delivery is gated per-flow, and mirror means it never is. Piece 4 (the return path) existed
solely to serve Piece 1's redirect, so it retires with it. **Piece 2 is NOT retired** — it is
repurposed as the primitive for per-device delivery (exit-node steering), per Window 1's audit
(not independently corroborated by prior docs/commits as of this update — flagged as
Window-1-sourced, not re-derived from this doc's own history). **Piece 3 is NOT retired** —
Pieces 2 and 3 are mutually consistent and both resolve to mirror semantics, the confirmed
mechanism. **Piece 5's status is UNRESOLVED, not carried over unchanged** — its own framing
covers "the redirect/forward/return path" as a unit; with redirect (1) and return (4) gone,
what "fail-safe" means for the surviving Piece 2 alone needs its own re-scope, not an assumption
either way. See the piece-level notes below for detail on each.

**Why this note is at the top, not just on the retired pieces:** the prior version of this doc
already resolved mirror-as-mechanism (2026-07-26) but never carried that resolution's
consequence — Piece 1/4 having no remaining purpose — through to the piece breakdown or the
session-total table below, which kept presenting them as live, estimated work. That gap between
"the doc technically contains the answer" and "the doc's own status line and totals reflect it"
is what led to a misdirected build instruction being issued from a stale read of this doc's
overall state. A piece-level note alone reproduces the same failure mode for the next reader who
only skims the top — hence the status line change here, not just below.

**Status (original):** scoping doc (read-only analysis; no code changed). Companion to
[adr-0009-build-scope.md](adr-0009-build-scope.md) (which scopes L1/L2/L3 overall and Fork A) and
[ADR 0009](../architecture/0009-security-inspection-proxy.md). Estimates are honest ranges, not
commitments. A **session** ≈ one focused 2–4h build block (same unit as the build-scope doc).

> **Why this doc:** the build-scope's L3 section gives **Fork A** a real breakdown (~6–12 sessions)
> but leaves **Fork B** as "the L2(b) driver cost + a small selective-routing increment"
> (`adr-0009-build-scope.md:173-183`). This doc gives Fork B the same numbered treatment — and the
> breakdown shows that "small selective-routing increment" is **optimistic**: the redirect + NAT +
> return-path + fail-safe machinery is substantial beyond the SYN-drop driver shipped tonight. Treat
> this as the corrected Fork B estimate the same way Fork A's "2–3 sessions" was corrected upward.

## The model (and what "selected" means)
Fork B = **route only SELECTED (ambiguous/suspicious) flows through the tunnel** to the server's
**already-working** Suricata (`fast.log` → `alert_manager/alert_watcher.py`, part of the original
stack). Clean flows go direct; clearly-bad flows are already dropped by the shipped L2; **only the
"unknown / needs-a-deeper-look" flows are diverted.** Routing *everything* would violate ADR 0009's
"tunnel carries decisions, not data" — so selectivity is the whole point, and it is driven by the
**reputation verdict the agent already computes** (`nemesis_agent/reputation_cache.py` `lookup(ip)`:
clean / bad / unknown).

---

## Mechanism: MIRROR (resolved 2026-07-26 — not an open question)

**Finding, stated plainly:** the mechanism this doc scopes is **MIRROR**, not inline. Piece 2
forwards every redirected flow to the internet **unconditionally** (IP forwarding + NAT/
masquerade — no verdict gate anywhere in that piece's design). Piece 3 adds Suricata as a
**passive** `af-packet` interface on `tailscale0` — the same passive-capture mechanism as the
existing LAN tap, which by construction inspects a copy of traffic and never sits in its path.
**Neither piece ever describes holding a packet pending a Suricata verdict before forwarding it.**

This was flagged as an open documentation gap in the [2026-07-25 ADR 0009
addendum](../architecture/0009-security-inspection-proxy.md) (Open Item 1's "unresolved
sub-item"). Re-reading both pieces together to resolve it: **there was never an actual
contradiction between Piece 2 and Piece 3.** Both are independently and consistently written as
mirror. The real gap was that this doc never explicitly *decided* mirror was the intent — it
fell out of how the two pieces happened to be written, without anyone stating the choice. That
gap is closed now: **mirror is confirmed as this doc's mechanism, by design, not by accident.**

**Consequence for the redirect-ownership question (ADR 0009 addendum Open Item 1):** since the
tunnel is mirror, an origin-owned redirect (that addendum's §1) does **not** gate traffic
reaching the destination — it can only alert/escalate after the fact, exactly as that addendum's
unresolved sub-item worried it might. That consequence is now confirmed, not merely feared.

**This does NOT mean the whole L3 pipeline never gates delivery.** A separate, connection-level
inline gate exists one layer up, inside **Tier 2** (TLS interception) — not part of Fork B's own
tunnel transport, and only relevant to connections Tier 2 has decrypted. See [ADR 0009 addendum
§6](../architecture/0009-security-inspection-proxy.md) and
[tls-interception-sterilization-scope.md](tls-interception-sterilization-scope.md) (new Piece J)
for that hybrid inline/mirror design. Fork B itself, as scoped in this doc, remains pure mirror
end to end.

---

## Piece 1 — Agent-side selective traffic redirect (WinDivert) — **RETIRED 2026-08-04**

> **Retired, not built.** Mirror was confirmed as Fork B's mechanism 2026-07-26 (see the
> "Mechanism: MIRROR" section below). A per-flow redirect mechanism — this piece's entire
> purpose — only matters if delivery is gated per-flow, and mirror means it never is. Left
> below UNCHANGED as the record of what was scoped and why it seemed necessary at the time; the
> estimate here no longer contributes to Fork B's total (see the corrected table further down).

**What:** extend the shipped L2 WinDivert layer from *drop-or-allow* to *drop / allow / **redirect***.

- **What decides "selected":** the per-connection reputation verdict at SYN time
  (`reputation_cache.lookup(ip)`). Three-way branch instead of L2's two-way:
  `clean → direct`, `bad → drop` (L2's existing behavior), **`unknown/suspicious → redirect the
  flow into the tunnel`** for server-side deep inspection.
- **Interaction with the L2 filter shipped tonight:** it **shares the same interception point but is
  a large superset.** Today L2 (`nemesis_agent/l2_windivert.py`) opens a **narrow SYN-only** filter
  (`FILTER = "outbound and ip and tcp and tcp.Syn"`, `:49`) and only ever **reinjects unmodified or
  drops** — it never touches non-SYN packets. Redirect requires capturing and **rewriting/steering
  the WHOLE flow** (every packet, both directions) toward `tailscale0`, maintaining **per-flow
  redirect state**, and reinjecting — a fundamentally bigger WinDivert task than dropping a SYN.
  The stall-watchdog pattern and pydivert integration are reusable; the full-flow redirect logic is
  greenfield on top.
- **The hard part:** on Windows, cleanly diverting an established flow's packets to a different
  egress (the tunnel) via WinDivert — src/dst handling, reinjection direction, per-flow lifecycle,
  and not corrupting the socket's view — is genuinely hard and under-precedented in this codebase.

**Estimate: ~5–9 sessions.** **Biggest single unknown in Fork B** — could balloon. Low confidence.

---

## Piece 2 — Server-side IP forwarding + NAT (egress + return) — **NOT retired, repurposed**

> **Repurposed 2026-08-04 as the primitive for per-device delivery (exit-node steering), per
> Window 1's audit.** Not independently corroborated against this doc's own prior history as of
> this update — flagged as Window-1-sourced context rather than re-derived here. The
> NAT/forward capability itself, and the open-relay-safety requirement below, remain the same
> engineering task regardless of which use case consumes it.

**What:** the Nemesis box must accept tunnel-sourced flows, **forward them to the internet** (IP
forwarding + source NAT / masquerade), and let responses route back.

- **New capability class for `firewall.py`.** The mandated ufw chokepoint
  (`alert_manager/firewall.py`) is **ufw-only today** — `ufw_insert_top` / deny helpers, **no
  NAT / masquerade / FORWARD helpers exist.** NAT/masquerade isn't cleanly expressible in ufw's
  model; it needs `iptables`/`nft` masquerade + `FORWARD` rules + `net.ipv4.ip_forward=1`. Per
  CLAUDE.md, this must route **through `firewall.py`** (not ad-hoc `nft`) — so a real design task:
  add a NAT/forward capability to the chokepoint, or explicitly extend the ADR-0005 firewall engine.
- **Open-relay safety is mandatory.** Forwarding must be **locked to the tailnet CIDR** and to the
  redirected-flow set only — the box must **not** become an open forwarding proxy. This is a
  security-review gate, not just plumbing.

**Estimate: ~2–4 sessions.** Standard NAT-gateway mechanics are well understood; the cost is doing
it **through `firewall.py`** cleanly + the lock-down/no-open-relay review. Medium confidence.

---

## Piece 3 — Suricata: add `tailscale0` as a second `af-packet` interface
**What:** the server Suricata currently inspects the LAN interface (`enp131s0`, cf.
`alert_manager/hw_monitor.py:27` `NET_IFACE`). Add `tailscale0` as a **second `af-packet`
interface** so tunnel-routed flows are inspected too.

- **Config lives OUTSIDE the repo.** Suricata's interface config is in
  `/etc/suricata/suricata.yaml` (system config; `docs/SETUP_LINUX.md:204-205` already documents
  editing the `af-packet` stanza). So this is a **system-config + service-orchestration** change,
  not a repo code change — note it as an ops step with a `CUSTOM_*`/setup-doc update.
- **Reload/restart:** adding an `af-packet` interface needs a Suricata **restart** (interface
  binding happens at startup) — so this pairs with restart orchestration + a health check that the
  new interface is actually capturing.
- **Rule-set awareness:** `af-packet` interfaces share the loaded rule set by default, so rules
  apply to `tailscale0` automatically — but confirm the alert pipeline (`alert_watcher.py`) doesn't
  need per-interface tagging to distinguish tunnel-inspected alerts from LAN ones.

**Estimate: ~1–2 sessions.** The smallest, best-understood piece (config + reload + validate).
Medium-high confidence.

---

## Piece 4 — The return path (inspected traffic back to the originating client) — **RETIRED 2026-08-04**

> **Retired, not built.** Existed solely to serve Piece 1's per-flow redirect state — the
> "Pieces 1, 2, and 4 must all agree on per-flow state" coupling described below is exactly why
> retiring Piece 1 retires this too, rather than leaving it as standalone scope. Left below
> UNCHANGED as the record of what was scoped; no longer contributes to Fork B's total.

**What:** once the server forwards + Suricata inspects, the **response must return to the exact
originating client** through the tunnel, and the client's socket must see a coherent flow.

- **Server side:** NAT **conntrack** must track each redirected flow so return packets are
  reverse-translated and sent back over `tailscale0` to the right agent (falls out of Piece 2's
  masquerade **if** conntrack + symmetric routing are correct — a real "if").
- **Agent side:** the returning packets arriving via the tunnel must be **reinjected into the local
  stack as if they came direct**, matching Piece 1's per-flow redirect state, or the client's TCP
  stack rejects them. This is the tightest correctness coupling in Fork B — Pieces 1, 2, and 4 must
  all agree on per-flow state.

**Estimate: ~3–5 sessions.** **Second-biggest unknown** — correctness-critical and entangled with
Pieces 1–2; hard to validate without the whole path standing up. Low confidence.

---

## Piece 5 — Fail-open / fail-safe (Fork B's flagged weak spot) — **STATUS UNRESOLVED, not carried over unchanged**

> **Needs its own re-scope decision, not an assumption either way (flagged 2026-08-04).** This
> piece's own framing below covers "the redirect/forward/return path" as a unit. Redirect
> (Piece 1) and return (Piece 4) are now retired; only forward (Piece 2, repurposed for
> per-device delivery) survives. Whether Piece 2 alone still needs the fail-open/fail-safe
> treatment described here — and whether the residual risk named below still applies to it in
> the same shape — has not been evaluated. Left below UNCHANGED pending that evaluation; do not
> read the estimate as still accurate for whatever Piece 2's surviving scope turns out to need.

A fail-safe mode is needed for when the redirect/forward/return path itself breaks. A
health-detect-and-fail-open mechanism is achievable for new flows; **flows already mid-redirect
when the path fails are a residual, not-fully-closeable risk** — an accepted tradeoff, not a
build task. **Full risk narrative documented internally, not in the public repo** (this is the
one piece of Fork B's own analysis that names a concrete exploitable weak point, not just a
build-difficulty estimate) — see `PUNCHLIST.md` for the pointer. Strong argument for keeping
Fork B's redirect set **small** (only genuinely ambiguous flows) and default-OFF until proven.

**Estimate: ~2–3 sessions** to build health-detection + fail-open-for-new-flows + timeouts —
**plus an unresolved residual risk** that no amount of sessions fully removes.

---

## Total & confidence — **SUPERSEDED 2026-08-04, see note above**

The table below is the ORIGINAL estimate, left unchanged as the historical record. It no longer
reflects live scope: Pieces 1 and 4 (8–14 of the 13–23 total) are retired, and Piece 5's
estimate is unevaluated against Piece 2's repurposed, narrower scope (see that piece's note
above) rather than confirmed still accurate. **Do not use this table for current planning.**

| Piece | Sessions | Confidence |
|---|---|---|
| 1. Agent selective full-flow redirect (WinDivert) — RETIRED | **5–9** | low (biggest unknown) |
| 2. Server IP-forward + NAT (via `firewall.py`) — repurposed, live | **2–4** | medium |
| 3. Suricata `tailscale0` af-packet + reload — live | **1–2** | med-high |
| 4. Return path (conntrack + agent reinjection) — RETIRED | **3–5** | low (2nd unknown) |
| 5. Fail-safe (partial; residual risk remains) — needs re-scope | **2–3** | medium build / risk unresolved |
| **Total (original, includes retired pieces)** | **~13–23 sessions** | **low overall** |

**~13–23 sessions, low confidence** — larger than **Fork A's ~6–12** (`adr-0009-build-scope.md`).
This **corrects the build-scope's "small selective-routing increment" framing upward**: Fork B does
reuse the working server Suricata (Piece 3 is cheap), but pays heavily for the **full-flow redirect
(Piece 1), the NAT/forward capability new to `firewall.py` (Piece 2), the return-path correctness
(Piece 4), and an only-partial fail-safe (Piece 5)** — none of which the shipped SYN-drop L2 covers.

**Live scope as of 2026-08-04:** Pieces 2 + 3 only, pending Piece 5's re-scope —
**~3–6 sessions**, medium-to-med-high confidence, not counting whatever Piece 5's re-evaluated
form adds. Substantially smaller than the original ~13–23, since the two biggest, lowest-confidence
unknowns (Pieces 1 and 4) are the ones retired.

## Biggest unknowns (explicit) — **written against the original, RETIRED scope; kept for history**

The two largest unknowns below (#1, #2) belong to the now-retired Pieces 1 and 4. Kept
unchanged as the record of why those pieces were estimated as they were; do not read as current
risk. #3 and #4 remain live-relevant, #3 pending Piece 5's re-scope.

1. **Full-flow WinDivert redirect on Windows (Piece 1, RETIRED)** — no precedent in-tree; the
   shipped L2 only drops SYNs. This is the item most likely to blow the estimate.
2. **End-to-end return-path correctness (Piece 4, RETIRED)** — three-way per-flow state agreement
   (agent redirect ↔ server NAT/conntrack ↔ agent reinject); only testable once the whole path exists.
3. **Fail-safe residual (Piece 5, needs re-scope)** — in-flight redirected flows can black-hole on a
   path break; a structural risk, not a build task. Whether this still applies in the same shape to
   Piece 2's repurposed, narrower scope is the open question, not yet evaluated.
4. **`firewall.py` NAT capability (Piece 2, live)** — adding masquerade/FORWARD to a ufw-only
   chokepoint without ad-hoc `nft` (CLAUDE.md) is a design decision, possibly folding into the
   ADR-0005 engine. Still applies under the repurposed exit-node-steering use case.

## Cross-references
`adr-0009-build-scope.md` (Phase 3 / L3 — Fork A breakdown, the "Fork B = small increment" line this
corrects; and Fork B depends on config-pull Phase 0a + the L2(b)/WinDivert driver), ADR 0009
(architecture — its addendum §6 and Open Item 1 now cross-reference this doc's mirror
resolution above), ADR 0005 (firewall/device-auth engine — natural home for the NAT capability),
`nemesis_agent/l2_windivert.py` (the SYN-drop layer Fork B extends), `nemesis_agent/reputation_cache.py`
(the verdict driving "selected"), `alert_manager/firewall.py` (ufw chokepoint), `alert_manager/hw_monitor.py:27`
(`NET_IFACE = enp131s0`), `docs/SETUP_LINUX.md:204` (the `af-packet` config, outside the repo),
[tls-interception-sterilization-scope.md](tls-interception-sterilization-scope.md) (Piece J —
the hybrid inline/mirror transition this mirror-mechanism resolution motivates and sits beneath).
