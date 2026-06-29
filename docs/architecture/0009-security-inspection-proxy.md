# ADR 0009 — Security Inspection Proxy (Self-Hosted SSE)

- **Status:** Proposed (architecture decided 2026-06-28; design captured, **no code changed**)
- **Date:** 2026-06-28
- **Extends:** [0005-dns-firewall-device-auth-architecture](0005-dns-firewall-device-auth-architecture.md)
  (device auth), [0007-device-user-model](0007-device-user-model.md) (device-user model)
- **Depends on:** the agent rebuild / config-pull
  ([agent-rebuild-config-driven.md](../roadmap/agent-rebuild-config-driven.md)), a Tailscale
  exit node, and [0006-data-manager](0006-data-manager.md) (Data Manager)
- **Related:** [0008-impossible-travel-detection](0008-impossible-travel-detection.md);
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
