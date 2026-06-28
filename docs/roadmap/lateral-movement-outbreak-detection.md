# Roadmap stub — lateral-movement / outbreak detection

**Status:** **two tiers, sequenced.** The **core (owned-fleet) version is promoted to a v2
target** — build candidate, still needs a short spec before code. The **venue/epidemic
version stays parked** (separate, later). Lives in the **network / anomaly** subsystem,
**not** the malware module.

## Tier 1 — Core lateral-movement (v2 target, build first)
Detect **an owned/agent-known device making unusual outbound connections to OTHER fleet
devices after a detection event on it** (e.g. canary trip, YARA hit, anomaly flag). The
post-event correlation is the trigger: "device A was just flagged → is A now reaching for
B, C, D?"

**Why this is the simpler, earlier build:**
- **Known fleet topology** — the devices and their normal peer relationships are already
  known (owned, enrolled, agent-reporting), so "unusual peer" is well-defined without
  baselining a hostile/unknown LAN.
- **Owned devices** — no agentless-guest ambiguity; attribution and containment hooks exist.
- **No new sensors** — Suricata `eve.json` + agent data **already carry the raw inputs**.
  This is a **correlation query** (post-detection outbound → other fleet members), not new
  sensor infrastructure. That's why it lands in v2 ahead of the venue work.

Found framing during the diagnostics VM audit 2026-06-28.

## Enrollment enriches detection (applies to both tiers)
Device enrollment (ADR 0005) is what turns this from guessing into knowing:
- **Without enrollment:** IP addresses, no context → high false positives.
- **With enrollment:** a behavioral baseline per device → high-confidence detection.

**Detection factors enabled by enrollment:**
- **Historical connection graph** — has A ever connected to B before?
- **Post-detection timing** — a connection right after a recent finding = critical.
- **Behavioral baseline** — typical ports, hours, connection count.
- **Device role context** — server / NAS / appliance = a sensitive target.
- **Enrollment age** — an older enrollment = a richer baseline = higher confidence.

**Venue compound benefit** ([venue-guest-network.md](venue-guest-network.md)): repeat guests
**restore their historical baseline on reconnection**, so a compromised returning device can
be detected **at reconnection, before network access is granted** — proactive, not reactive.

**Confidence score:** a `risk_score` aggregates multiple signals. A single anomaly = low
confidence → investigate; multiple simultaneous anomalies = high confidence → isolate
immediately. Enrollment data is the difference between guessing and knowing.

**Compounding effect:** detection improves continuously as baselines mature. Day 1 — sparse
baseline, cautious alerts. Month 6 — precise behavioral model, near-zero false positives.
**The longer Nemesis runs, the smarter it gets** — per device, per network, per user pattern.

## Tier 2 — Venue / epidemic spread (later, separate addition)
The broader "outbreak on a shared/public LAN" detection described below — unknown devices,
baseline-from-scratch, agentless-guest protection. Stays parked until Tier 1 ships and the
venue market is scheduled. Everything from here down describes **Tier 2**.

## What
Detect a device on a shared/public LAN exhibiting **spread** behavior — the network
signature of one compromised host trying to infect its neighbors. Signals (Suricata
already sees this traffic):
- **Connection fan-out** — one host suddenly opening connections to many internal peers.
- **Peer port-scan / sweep** — sequential or broad port probing across the subnet.
- **SMB/RDP probing** across the subnet (classic worm/lateral-movement vector).
- **ARP anomalies** — spoofing / unexpected mappings.
- **New-device-immediately-noisy** — a just-joined device that instantly contacts many
  peers (no normal warm-up).

## Why
**Epidemiological framing:** on public/shared wifi (hotels, clinics, retail, venues) a
single infected device is a small epicenter that can spread rapidly to everything else on
the LAN. The high-value detection is not "is this one file bad" but "is something
**spreading**." This protects **agentless devices** — consoles, Alexas/IoT, Firestick,
guest phones — that can never be file-scanned, because you watch their *behavior on the
wire* instead of their disk.

This is a real **differentiator for the multi-site SMB / venue market**: a venue operator
cares most about catching an outbreak before it crosses the whole floor.

## Reasoning / shape
- **Subsystem:** network/anomaly (Suricata `eve.json` is already the feed). Belongs next to
  the existing anomaly_detection work, **not** in malware_detection — the signal is traffic,
  not files.
- **Cross-module hook:** when a flagged spreader **is** agent-controllable, trigger a
  malware scan on it (network detection → file-level confirmation/containment). Leave the
  hook seam; don't wire the malware build to it yet.
- Multi-user/multi-site shaped from the start (per-site/per-segment state, attributed
  events) per CLAUDE.md multi-user-ready rules — the venue market is inherently multi-site.
- Build only after the idea graduates to a real spec/ADR (thresholds, baseline windows,
  false-positive handling on legitimately chatty devices).
