# Build spec — ADR 0009 Self-Hosted SSE Inspection Proxy (3-layer selective)

**Status:** DESIGN CAPTURED — **NOT BUILT.** Well-designed; some bricks partially present, but
the verdict loop and Layer-3 path are unbuilt (see §5 grounding). This turns
[ADR 0009 — security inspection proxy](../architecture/0009-security-inspection-proxy.md) into a
buildable spec. No build order committed here — feasibility gate in §6 must clear first.

**References:** [ADR 0009](../architecture/0009-security-inspection-proxy.md) (the architecture
this specs — "the tunnel carries decisions, not data"); [ADR 0012 — enrollment trust
modes](../architecture/0012-enrollment-trust-modes.md) (the VENUE guest/monitored tier is the
natural consumer of this inspection path — see [enrollment-modes-build-spec](enrollment-modes-build-spec.md));
[ADR 0005](../architecture/0005-dns-firewall-device-auth-architecture.md) (`firewall.py`
chokepoint + device-auth seam); [ADR 0006](../architecture/0006-data-manager.md) (verdict-cache /
atomic ops → Data Manager).

**Separate channel — do NOT conflate:** the **pull-queue command channel** (owner→device commands:
scan / notify / restart / update_rules) is a **different** path — *commands, not verdicts*. It is
designed but **not yet captured as an ADR** (no ADR 0013 exists on disk yet). The verdict loop
below carries per-connection allow/deny decisions; the command queue carries operator intents.
They have opposite direction, volume, and latency profiles and must never be multiplexed onto one
mechanism.

**Rule 8:** placeholders only (`<box-ip>`, `<tailnet-ip>`, `<dest-ip>`, `<asn>`). No real
IPs/hosts/accounts.

> Capture only — design + grounding for the 3-layer selective-inspection model. No code changed.

---

## 1. Framing — what this is

A **self-hosted Security Service Edge (SSE)**: the same category as Cloudflare Gateway, Zscaler,
and Prisma Access — but **self-hosted on the operator's own box** instead of a vendor's global
cloud edge. It is the product's **key differentiator**: real **IDS packet inspection on roaming
devices**, which reputation-only competitors (NextDNS / DNSFilter / Control D) structurally cannot
offer — they see DNS/IP metadata, never packets.

**Core principle (ADR 0009):** the tunnel carries **DECISIONS, not (most) DATA.** Default egress is
**local/direct** off the device's own internet; only the **suspect subset** backhauls through the
box for inspection. This avoids the naive-exit-node bottleneck (all traffic hitting the home link
twice) while still closing the WiFi/roaming inspection gap.

---

## 2. The three layers

Ordered cheapest→heaviest; a destination is resolved at the earliest layer that can decide it.

- **LAYER 1 — DNS inspection.** Device DNS queries tunnel to **Pi-hole on the box** → verdict.
  - **Blocked** → return **NXDOMAIN**; the connection never happens.
  - **Clean** → return the IP; the device connects **DIRECTLY** (local egress).
  - **Bandwidth:** negligible (a DNS query + answer).
- **LAYER 2 — IP reputation.** Before connecting, the agent checks the destination IP against the
  box's **AbuseIPDB / enrichment cache**.
  - **Bad** → block **pre-connection**.
  - **Clean** → allow **direct**.
  - **Bandwidth:** metadata only (one reputation lookup, cache-backed).
- **LAYER 3 — Traffic inspection (the differentiator).** For **SUSPECT traffic only**, route the
  connection **through the box** (Tailscale exit-node style) so **Suricata inspects real packets**
  and a verdict returns. Trusted / cached traffic egresses **direct**.
  - **This is the ONLY layer where traffic actually backhauls** — kept to the suspect subset by the
    §3 heuristic + §4 cache.

---

## 3. `requires_inspection()` heuristic — what triggers Layer-3 backhaul

The gate that keeps Layer-3 to a small subset. **Inspect if any:**
- destination is **new / never-seen** for this device;
- **unusual port** (not 80/443);
- **medium** AbuseIPDB risk (high was already blocked at Layer 2; clean skips);
- **watchlist category** — flagged ASN (`<asn>`) / geo.

**Do NOT inspect (egress direct) if any:**
- **known-good domain** (allowlist);
- **cached verdict within TTL** (see §4);
- **user-configured trusted exception.**

The heuristic is deliberately conservative: false-positive "inspect" costs latency; false-negative
"skip" costs coverage. Tuning thresholds is a build concern, but the *shape* (new/odd-port/medium-
risk/watchlist → inspect) is the locked design.

---

## 4. Verdict cache (performance-critical)

Per-device cache of `{ destination: { verdict, expires } }`. **Most traffic hits the cache → direct
connection → zero tunnel overhead;** only new/suspicious destinations reach the tunnel. Without this
cache the model collapses into a de-facto full exit node — the cache is what makes "decisions not
data" hold at real traffic volumes.

- **Per-verdict TTL — OPEN BUILD VALUE.** Clean verdicts cache **longer**; suspicious/edge verdicts
  cache **short** (re-inspect sooner). Exact TTLs decided at build against measured hit-rate.
- Cache is per-device (a destination trusted for one device isn't automatically trusted for
  another). Data Manager candidate (ADR 0006) for the read/write + expiry sweep.

### Cache warm-up / pre-built seed
**The cold-cache problem:** a freshly-installed agent has an empty verdict cache, so EVERY
destination is "new" and backhauls for inspection. The first few days (before the cache warms) are
the worst-latency, heaviest-backhaul period — and also the user's first impression. Steady-state
performance can look fine while first-run experience quietly drives users off. Cold-cache days and
warm-cache steady-state must be measured SEPARATELY (this is a key trip-test data point — see the
Starlink feasibility unknown in §6).

**Mitigation — pre-built allowlist seed (recommended, SAFE version):** at install, the server
pushes a curated allowlist of known-good high-volume destinations (top few-thousand domains/IPs:
major platforms, CDNs, OS-update servers, AbuseIPDB-clean heavy-hitters). Common traffic then
egresses direct from minute one; the cold-start penalty applies only to genuinely-unusual
destinations — which is exactly the traffic that SHOULD be inspected anyway. The cache still learns
the user's specific pattern over following days.

**Risk boundary — do NOT broadly pre-seed "clean" VERDICTS:** a verdict cache is a trust cache.
Shipping a stale "clean" for a destination compromised after seed-build time tells every fresh
install to skip inspection on a now-bad target. The allowlist version sidesteps most of this
(known-good infrastructure changes slowly). Any broader verdict-seeding requires a conservative TTL
+ versioning/refresh mechanism. Record allowlist-seed as the safe default; broad-verdict-seed as
needing freshness discipline before it's viable.

**Infrastructure synergy:** this reuses the community threat-intelligence feed distribution
machinery (the compressed daily JSON, tiered review) — instead of shipping known-BAD down to
clients, ship known-GOOD as the cache primer over the same download/refresh pipeline. Not a new
system; a second payload on already-designed infrastructure.

---

## 5. Build-state grounding (per the 2026-06-30 ADR 0009 audit — Win 3)

**REUSE — bricks that already exist:**
- **Pi-hole (Layer 1)** — present (`diagnostics/pihole_health.py`, dashboard integration).
- **IP enrichment / AbuseIPDB cache (Layer 2)** — present (`alert_manager/ip_enrichment.py`).
- **Agent signed-request transport** — the enroll keypair primitive
  ([ADR 0011](../architecture/0011-enrollment-security-model.md)) is reusable auth for a verdict
  endpoint.
- **Agent-local Suricata (Layer 3 engine)** — **built** (`nemesis_agent/modules/suricata_local.py`),
  **off by default** (`suricata_enabled=false`).

**NEW / greenfield — ❌ absent today:**
- server-side **verdict endpoint** (the decision API the agent calls);
- agent-side **`requires_inspection()` routing logic**;
- **Layer-3 tunnel / exit-node path** (selective backhaul of suspect flows);
- **verdict cache** (§4);
- **per-device Mode / consent flow** (opt-in to inspection, esp. for guest tiers).

**Overall classification: NOT BUILT.** Well-designed; Layer-1/2 bricks partially present; the
**verdict loop and Layer-3 selective-backhaul are unbuilt.** The reusable pieces reduce the build
but do not constitute a working proxy.

---

## 6. Open design decisions (FLAG, do not resolve here)

- **Single-box latency — FEASIBILITY UNKNOWN (gate before committing).** All inspection happens at
  **ONE operator box**, not a global edge. A roaming device is only as fast/available as its
  backhaul to that box. **Real latency over Starlink + Tailscale from a remote location is
  UNTESTED** and **must be measured before committing to the model** — if Layer-3 backhaul adds
  unacceptable latency from a genuinely remote site, the model needs rethinking (or Layer-3 becomes
  opt-in per link-type). This is the top risk.
- **Fail-open vs fail-closed** when the box is unreachable. Fail-open preserves connectivity but
  drops inspection (roaming device runs unprotected); fail-closed preserves the security guarantee
  but can strand a device off-network. Likely per-tier (guest = fail-closed, trusted-owner =
  fail-open?) — decide at build with the operator.
- **Privacy / legal posture.** Layer-3 inspects **user traffic payloads** — materially heavier than
  reputation-only metadata. Needs explicit informed-consent framing, especially for the **VENUE
  guest tier** ([ADR 0012](../architecture/0012-enrollment-trust-modes.md) — the TOS-at-install
  consent in [venue-guest-network](venue-guest-network.md) is the model). Trusted-owner devices
  inspecting their own traffic is a different consent question than a venue inspecting strangers'.

---

## 7. Related

- [ADR 0009](../architecture/0009-security-inspection-proxy.md) — the architecture this spec builds.
- [ADR 0012](../architecture/0012-enrollment-trust-modes.md) + [enrollment-modes-build-spec](enrollment-modes-build-spec.md)
  — VENUE guest/monitored tier is the natural consumer of this inspection path; VENUE-auto is
  **blocked on this proxy existing.**
- **Pull-queue command channel** (designed; **no ADR on disk yet**) — a **separate** channel
  (commands, not verdicts). Do not conflate or multiplex.
- [venue-guest-network](venue-guest-network.md), [connection-type-awareness](connection-type-awareness.md),
  [agent-rebuild-config-driven](agent-rebuild-config-driven.md) — related roadmap context.
