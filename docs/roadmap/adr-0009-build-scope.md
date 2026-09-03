# ADR 0009 — Security Inspection Proxy: Build Scope & Estimate

**Status:** scoping doc (read-only analysis; no code changed). Companion to
[ADR 0009](../architecture/0009-security-inspection-proxy.md). Estimates are honest ranges,
not commitments. A **session** here ≈ one focused 2–4h build block.

> Purpose: turn ADR 0009's "tunnel carries decisions, not data" architecture into phased,
> buildable work with dependencies and effort, so we can decide what (if anything) a V1
> "Mode 2 minimum viable" actually costs — and separate it cleanly from the V2 ZTNA program.

---

## What already exists (reduces the build)

Grounding the estimates — these primitives are already in the tree and get reused:

- **Agent command channel** — `nemesis_agent/agent.py:360` command listener on `localhost:5002`,
  dispatch at `_dispatch` (`agent.py:281`) already handles `ping | scan | scan_status | restart |
  notify | update_rules`. `update_rules` already calls `_update_suricata_rules(rules_url)`
  (`agent.py:344`) — a rules-push primitive.
- **Suricata — SERVER-SIDE, real and working (the reusable asset).** Suricata runs on the Nemesis
  box as part of the original security stack (Pi-hole / ClamAV / Suricata); `fast.log` →
  `alert_manager/alert_watcher.py` is the live alert pipeline, present since the initial commit /
  alert_manager core (`3851076`, 2026-06-21). This proven server-side engine is what L3 **Fork B**
  reuses.
- **Agent-side Suricata — SCAFFOLD ONLY, never a working feature (verified).**
  `nemesis_agent/modules/suricata_local.py` is wired (`agent.py:150` drain, `:405` start) but
  **inert**: default-OFF (`config.py:26` + all three installers), **no Suricata binary
  installed/bundled** by any agent installer, a **Linux-hardcoded config path**
  (`/etc/suricata/suricata.yaml`) that breaks on Windows, **no rule files shipped**, and
  **untouched since the single scaffold commit** it arrived in (`d3d7008`, 2026-06-24). It does
  **NOT** reduce the L3 build — it is a placeholder for a *future* agent-side path (Fork A), which
  is greenfield.
- **Connection-type awareness** — `_detect_connection_type` (`agent.py:94`) + `_detect_link_type`
  (`agent.py:112`); schema columns `connection_type` / `interface_name` / `link_type` already on
  `agent_devices`. The roadmap "fold-in" is largely done.
- **Server IP reputation + cache** — `alert_manager/ip_enrichment.py` (225 lines): `ip_enrichment`
  table, 24h TTL cache (`CACHE_TTL_HOURS`), AbuseIPDB + ipinfo fetch, `_classify_threat`,
  `enrich_ip(ip)` with cache-first lookup. **The verdict data + cache + classification exist**
  — as server-side alert enrichment, not yet agent-facing.
- **Firewall chokepoint** — `alert_manager/firewall.py` (`ufw_insert_top`, deny helpers) — the
  single ufw path for enforcement (per CLAUDE.md).
- **Device auth + lifecycle** — enrollment/keypair (ADR 0011), approve/reject endpoints
  (`dashboard.py:1362` / `:1378`), Settings→Devices UI (`_render_agent_devices_html`,
  `dashboard.py:1600`).

**The missing spine is config-pull + a per-device routing mode + connection-level enforcement.**
Everything else is largely assembly.

---

## Phase 0a — Prerequisite: Agent rebuild / config-pull

**Roadmap:** [agent-rebuild-config-driven.md](agent-rebuild-config-driven.md) (parked).

**What's needed**
- **Server:** a device-auth'd, versioned per-device config endpoint (agent pulls full config:
  feature flags, routing mode, poll interval, Suricata rules ref, VPN method). Store a config
  **version** per device; agents report their applied version → dashboard shows current/stale.
- **Agent:** pull-on-start + pull-on-restart, apply, persist, report version. Today config is
  **local-only** (`nemesis_agent/config.py` reads `nemesis_agent.conf`; no server pull exists —
  confirmed: no `/api/agent/*config*` route).
- **Dashboard:** staggered "restart all" orchestration (per-agent restart already exists via the
  `5002` `restart` command; needs the staggered/thundering-herd control + post-restart status).
- **Migration discipline:** the routing-mode column, the readiness `actor` seam, and any new
  `agent_devices` columns must land in **one** migration (don't touch `agent_devices` twice —
  per the roadmap + CLAUDE.md readiness note).

**Depends on:** device auth (exists, ADR 0011). Soft-depends on Data Manager (Phase 0b) for the
new tables' actor seam, but can follow ADR 0001 write-own convention if DM v1 isn't ready.

**Estimate:** **3–5 sessions (~12–20h).** Reuses the `5002` channel; the cost is the config
schema design (server-managed vs local-authoritative fields), versioning, and safe rollout per
`docs/operation/CONFIG_CHANGE_PROCEDURE.md`. **This is the true foundation — nearly every other
phase rides on it.**

---

## Phase 0b — Prerequisite: Data Manager v1 (ADR 0006)

**What's needed:** formalize `alert_manager/data_manager.py`, move the v0 atomic seed into it,
add operation logging + access-control enforcement + loader routing-enforcement. Only the v0
seed (4 atomic race fixes) exists today.

**Estimate:** **3–4 sessions (~10–16h).**

**Honest dependency note:** ADR 0009 *lists* the Data Manager as a dependency, but for an L1+L2
**MVP** it is a **soft** prerequisite. The inspection layers can write to their own prefixed
tables (`*_verdict_cache`, routing-mode column) under the existing ADR 0001 write-own convention.
DM v1 makes the actor seam + access control *clean*, but does not *block* Mode 2 MVP. **Recommend
building DM v1 for its own sake (races, contributor safety), not gating 0009 on it.**

---

## Phase 1 — L1: DNS inspection through the tunnel

ADR 0009 calls this "buildable now (Pi-hole exists; needs tunnel routing)." **It is not as free
as it looks** — see the flag.

**What's needed**
- **Agent (Mode 2):** point the device's resolver at the Nemesis Pi-hole over the tunnel; revert
  on Mode 1. Small agent change, gated on config-pull delivering the mode.
- **Pi-hole / server:** accept tunnel-sourced queries **without becoming an open resolver.**

**⚠️ Hidden prerequisite — the ADR 0005 DNS blocker.**
[ADR 0005 §1](../architecture/0005-dns-firewall-device-auth-architecture.md) proved Pi-hole
currently **REFUSES queries by source address** when traffic arrives from the tunnel IP (1ms
`REFUSED`/EDE-23), and the box currently runs **VPN-off as the workaround** — no interim config
applied, deliberately, to avoid open-resolver risk + tracked debt. **L1 cannot route DNS through
the tunnel until Pi-hole's client-acceptance posture is solved safely.** That design is *not
done*. So L1 really = (a) design + build the Pi-hole tunnel-source acceptance (allow the tunnel
CIDR, keep it closed to the internet) **+** (b) agent-side resolver switch.

**Depends on:** config-pull (0a) for the mode flag; **the unbuilt ADR 0005 DNS-posture fix.**

**Estimate:** DNS-posture design + build **1–2 sessions**; agent resolver switch + Pi-hole
allow-tunnel **2–3 sessions** → **3–5 sessions total.** The posture piece carries the risk.

---

## Phase 2 — L2: IP-reputation pre-connection check

**What's needed**
- **Server (easy):** an agent-auth'd endpoint wrapping the existing `enrich_ip(ip)` +
  `ip_enrichment` cache (`alert_manager/ip_enrichment.py`) → returns a clean/bad verdict. The
  data, cache, and classification already exist. **~1 session.**
- **Agent (the hard part):** *check before connect* enforcement. To block a bad destination IP
  **before** the connection is established, the agent must intercept outbound connections — on
  Windows that means a **filtering driver (WFP callout / WinDivert)** or an equivalent, plus a
  local verdict cache to avoid a round-trip per connection.

**⚠️ Biggest unknown in the whole ADR.** "Check the IP first" reads like a small feature; it is
actually **kernel-adjacent network filtering on Windows.** Realistic paths:
- **(a) DNS-layer enforcement only (recommended MVP):** lean on L1 — Pi-hole already sinkholes
  malicious *domains*, which covers the majority of real-world bad destinations with **zero
  driver work.** Expose the IP verdict for *visibility/scoring*, not inline blocking. Cheap.
- **(b) True inline IP pre-connect block:** WFP/WinDivert filter driver + signing + stability +
  fail-open safety. **5–10+ sessions and genuinely risky** (driver crashes take the box's network
  down; needs careful fail-open).

**Estimate:** MVP path (a): **1–2 sessions** (server endpoint + verdict surfaced; enforcement via
DNS). Full path (b): **+5–10 sessions** and real driver risk.

**Recommendation:** ship (a) for MVP; treat (b) as its own tracked spike, not a line item.

> **Note (shipped L2 spike, 2026-07-02).** The delivered `nemesis_agent/l2_windivert.py` filter
> (`outbound and ip and tcp and tcp.Syn`) is **bidirectional** by design, not outbound-only: `tcp.Syn`
> matches outbound SYN *and* SYN-ACK, so reputation blocking covers both this device connecting OUT to
> a bad IP and this device answering an INBOUND connection from a bad IP. The Phase-2 framing above
> ("intercept outbound connections") describes the outbound use case; the shipped filter intentionally
> covers both directions of handshake initiation. Accepted tradeoff: a new inbound connection is briefly
> blocked during a stall until the watchdog recovers (~5s); established flows are untouched.

---

## Phase 3 — L3: selective Suricata routing

ADR 0009 model: route *suspicious* traffic through the tunnel to Nemesis's Suricata; approved
traffic direct.

**⚠️ Architectural fork (unresolved).** **Correction (verified):** the agent does **NOT** run
Suricata today — `suricata_local.py` is inert scaffold (see "What already exists"). The real,
working Suricata is **server-side**. So Fork A is **greenfield** and Fork B **reuses a proven
engine** — which **reverses** this doc's original recommendation. Two very different builds:
- **Fork A — build agent-side local Suricata (GREENFIELD):** not "just push rules." Real work =
  provision and run Suricata on **each agent OS** (install/bundle the binary — hard on Windows/Mac:
  npcap, service, perf), fix the Linux-hardcoded config path per-platform, wire the agent to fetch
  per-mode rules at start (server endpoint `/api/agent/rules` exists), add an enable path, and
  validate an IDS actually runs + alerts flow on Win/Mac/Linux. The skeleton (start/tail/drain/
  switch) exists; the hard cross-OS provisioning + validation does not. **~6–12 sessions, Windows
  Suricata provisioning the main risk** (up from the wrong "2–3", which assumed a working local
  engine that does not exist).
- **Fork B — ADR's tunnel-routed central Suricata (reuses the WORKING server engine):** selectively
  divert *suspicious* flows through the tunnel to the box's already-working Suricata — **no new IDS
  to build.** Its cost is the **connection-filtering/redirect driver** (WFP/WinDivert) +
  selective-routing policy — the **same driver as L2(b).** If that driver is being built anyway,
  Fork B is largely the **incremental** selective-routing policy on top of it + reuse of the proven
  engine.

**Depends on:** config-pull (0a). Fork B additionally depends on L2(b)'s enforcement driver.

**Estimate (re-scoped):** Fork A **~6–12 sessions** (greenfield cross-OS agent IDS; low confidence;
Windows the risk). Fork B = **the L2(b) driver cost + a small selective-routing increment** (no new
detection engine). **Reversed recommendation:** the earlier "Fork A is ~80% present / the cheap MVP
answer" rested on the false premise that agent Suricata already ran — it does not. **If L3 is in
scope and the L2(b) driver is being built, Fork B is now the cheaper and more coherent path** (reuses
the working server Suricata; it is also ADR 0009's original design). If **no** driver is being built,
neither fork is cheap — Fork A is a greenfield agent IDS, Fork B needs the driver — so **defer L3 out
of the MVP** (as the MVP shape already does).

---

## Phase 4 — Dashboard: per-device routing-mode toggle + BYOD consent

**What's needed**
- `agent_devices` **routing-mode column** (`mode1 | mode2`) — land it in the **Phase 0a
  migration** (don't touch the table twice).
- Toggle endpoint (mirrors `api_agent_approve`/`reject`, `dashboard.py:1362`/`:1378`).
- UI control in `_render_agent_devices_html` (`dashboard.py:1600`).
- BYOD: a **"Request exit-node consent"** button (explicit consent) rather than a direct toggle,
  per ADR 0009.

**Depends on:** config-pull (0a) to actually deliver the mode to the agent; the migration.

**Estimate:** **1–2 sessions (~4–8h).** Watch the #1 recurring bug (JS-in-f-string quoting) in
the rendered UI.

---

## Phase 5 — ZTNA enforcement + lateral-movement scoring (V2 — OUT OF SCOPE for V1)

Explicitly **out of scope** for a V1 Mode-2 build. Recorded here for completeness:
- **ZTNA / captive portal** ("no enrolled agent = no internet") needs a **captive portal + router
  firewall integration + a mobile agent** — none exist. Multi-phase program on its own.
- **Venue guest network** — needs the mobile/guest app + auto-approve flow. V2.
- **Lateral-movement scoring — reconciled 2026-09-03, this line was stale.** The full connection-
  graph risk-weight table this bullet describes still hasn't been built and is **not** a quick
  win — but the reason is more specific than originally written, and a real, reduced-scope
  substitute has since shipped **entirely outside this ADR's program**, using zero Mode-2
  infrastructure:
  - **Shipped, independent of Mode-2:** `post_detection_egress` + `lan_behavior_monitor`
    (`lateral-movement-outbreak-detection.md`, 2026-09-02) — built on Suricata `eve.json`, the
    appliance's own DNS-resolver visibility, and broadcast traffic, all of which this doc's own
    "what already exists" section already lists as pre-existing. No config-pull, no tunnel, no
    driver. Measured limitation: a passive appliance on a flat switched LAN sees ~0.1–0.7% true
    peer-to-peer traffic, confirmed permanent (not fixed by Gateway Mode, which shipped and was
    checked) absent VLAN-capable switch hardware or port mirroring — hardware questions, not a
    Nemesis software gate. So the shipped detectors cover appliance-directed probing, DNS-visible
    egress, broadcast-visible discovery, and self-included broad sweeps — real coverage, but
    structurally never the unicast A→B connection graph ADR 0009's table assumes.
  - **The full connection graph's *only* viable path is the L2(b) driver specifically, not
    "L2/L3" generically.** An agent-side WFP/WinDivert interceptor observes a device's own
    outbound connections from its OS stack, which sidesteps the switched-LAN blind spot the
    passive appliance can't get past. The recommended MVP path — L2(a), DNS-enforced, no driver
    — produces no per-connection metadata at all, so it does not move this forward regardless of
    whether it ships. **Full detail:** `adr-0009-l3-behavioral-trigger-scope.md`'s Piece 2
    (Open Item #2, resolved 2026-09-03: this future engine runs **parallel** to the shipped
    lateral-movement detectors, sharing only an enrollment-baseline data layer, not the scorer).
  - **Estimate, if pursued:** unchanged at server-side ~2–3 sessions for the scoring logic itself
    *if* the connection graph existed — but that graph now has a named, singular prerequisite
    (the L2(b) driver, this doc's single biggest cost/risk item, §"Bigger-unknown-than-they-look
    flags" #1) rather than a vague "until L2/L3 land."
  - Feeds/fed-by [ADR 0008](../architecture/0008-impossible-travel-detection.md).

---

## Honest overall estimates

### "Mode 2 minimum viable" — L1 + L2 + dashboard toggle (no full L3/ZTNA)

**Assuming the recommended MVP shape:** DNS-layer enforcement (no Windows filter driver), **L3
Suricata deferred entirely** (Fork A is greenfield — agent Suricata does not exist today — not a
cheap "basic" add; see the corrected L3 fork), IP verdict surfaced for visibility. *(The MVP total
below already excludes L3, so it is unchanged by the correction.)*

| Piece | Sessions |
|---|---|
| 0a config-pull (foundation) | 3–5 |
| L1 DNS routing **incl. ADR 0005 Pi-hole posture** | 3–5 |
| L2 server verdict endpoint (DNS-enforced) | 1–2 |
| Dashboard toggle + migration | 1–2 |
| **MVP total** | **~8–14 sessions (≈ 2–4 weeks of focused blocks)** |

Data Manager v1 (0b, 3–4 sessions) is recommended in parallel but **not counted as blocking.**

**If MVP is redefined to require true inline IP pre-connect blocking (WFP/WinDivert driver):**
add **5–10+ sessions** and accept driver-stability risk → **~14–24 sessions.** Avoid this for MVP.

### "Full ADR 0009" — all layers + ZTNA + venue + lateral-movement + mobile agent

**A multi-month program, not a feature.** Rough order: MVP (above) + the **L2(b)/L3 Fork B redirect
driver** (large; L3 then reuses the working *server* Suricata for ~incremental cost) **or**, if
agent-local inspection is chosen instead, a greenfield **Fork A agent-side IDS (~6–12 sessions on
its own)** + captive portal + router firewall + **a mobile agent that does not exist** + venue flow
+ lateral-movement graph. Honestly **~35–55+ sessions** (nudged up from the earlier 30–50 now that
L3 is known to be **greenfield whichever fork**, not a cheap extension of existing agent code) and
gated on new surfaces (mobile agent, captive portal) that are their own projects. Low-confidence
until those are scoped.

---

## Bigger-unknown-than-they-look flags

1. **Windows pre-connection enforcement (L2b/L3 Fork B).** "Check/gate the IP before connecting"
   = a WFP/WinDivert **filter driver**: signing, stability, fail-open safety, network-down-on-crash
   risk. This is the single biggest cost/risk in the ADR and the reason the DNS-enforced MVP path
   is recommended. *Estimate confidence: low until a driver spike is done.*
2. **ADR 0005 Pi-hole client-refusal-by-source.** L1's hidden prerequisite; currently mitigated by
   running **VPN-off**. Solving it without opening a public resolver is an unbuilt design problem,
   not a config toggle.
3. **Agent-local vs tunnel-routed Suricata (L3 fork).** Unresolved architectural decision; changes
   L3 cost by an order of magnitude. **Correction:** the tree has agent-local *scaffold* only
   (`suricata_local.py`, inert) — Fork A is **greenfield**, not "already leaning." The real working
   Suricata is **server-side**, so Fork B (tunnel-routed, reusing it) is likely the cheaper path
   **if** the L2(b) driver is built.
4. **Config-pull schema + safe staggered rollout.** The foundation's real cost is design (which
   fields are server-authoritative) + rollout safety, not the transport (the `5002` channel exists).
5. **Data Manager coupling.** Listed as a dependency but is soft for MVP — don't let it become a
   false blocker; don't skip it for the codebase's own health either.

---

## Recommended sequence (if we build)

1. **0a config-pull** (foundation; everything rides on it).
2. **Phase 4 dashboard toggle** (cheap; makes mode a first-class concept; shares 0a's migration).
3. **L1** — resolve ADR 0005 Pi-hole posture, then tunnel DNS. Delivers real WiFi DNS coverage.
4. **L2 (path a)** — server verdict endpoint; enforcement via L1 DNS sinkholing.
5. **L3 — defer, and prefer Fork B if pursued.** Agent-local inspection (Fork A) does **not** exist
   yet (greenfield cross-OS build) — do not treat it as a cheap "push rules" step. If L3 is pursued,
   prefer **Fork B** (tunnel-route suspicious flows to the working *server* Suricata): it reuses a
   proven engine and rides the L2(b) driver rather than building a new agent-side IDS.
6. **STOP and re-evaluate** before any WFP/WinDivert driver (L2b/L3 Fork B) or ZTNA/mobile work —
   those are separate programs, not the tail of this one.

**Bottom line:** a genuinely useful **Mode-2 MVP (WiFi DNS coverage + mode toggle + verdict
visibility)** is ~**8–14 sessions** and needs **no kernel driver** — *if* we accept DNS-layer
enforcement and solve the ADR 0005 Pi-hole posture. "Full ADR 0009" is a multi-month program
gated on surfaces (filter driver, captive portal, mobile agent) that don't exist yet.
