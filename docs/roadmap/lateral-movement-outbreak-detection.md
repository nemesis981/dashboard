# Roadmap stub — lateral-movement / outbreak detection

**Status:** parked (idea captured — do NOT build yet). Lives in the **network / anomaly**
subsystem, **not** the malware module.

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
