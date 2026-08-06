# Roadmap — IPv6 rogue-router / rogue-RA detection

**Status:** parked (capture-only — what + why; do NOT build yet). Captured per Rule 7 after a
live example on this network, 2026-08-05.

## What

Nemesis does not detect or surface a device advertising itself as an **IPv6 router** on the
LAN. There is no check for Router Advertisements (ICMPv6 type 134), no notion of an expected
gateway set, and no alert when a new host starts presenting as a router.

## Why it matters

Rogue RA is a classic IPv6 LAN attack. An attacker (or a misconfigured host) that emits RAs
can make neighbouring hosts install it as their default IPv6 gateway via SLAAC, putting it
on-path for their traffic — the IPv6 analogue of ARP spoofing or a rogue DHCP server. It
needs no credentials and no access to the real gateway; it only needs to be on the segment
and shout. It also causes plain outages: a host that selects a transient device as its
gateway blackholes IPv6 when that device goes away.

This is squarely in scope for a product whose thesis is built-in IT expertise for people
without an IT department. A non-expert will not run `ip -6 neigh` and notice a stranger
flagged `router`.

## The concrete example that surfaced it

A **test VM** — bridged onto the production LAN as a Tailscale exit-node rig — was found
presenting as an IPv6 router (R-bit set in Neighbour Advertisements, `ip_forward=1` in-guest).

What makes it a good motivating case:

- Nemesis's **own device table** had it as `trusted=0`, `device_type=Unknown`, named only by
  its OUI vendor string — i.e. the product was already watching an unidentified, untrusted
  device, and said nothing when that device began presenting as a router.
- The information needed was **already on the box**: `ip -6 neigh` listed it as `router`
  alongside the two legitimate gateways. Nothing correlated that against the device table.
- Investigation showed the *actual* risk here was low — the VM ran no RA daemon, so it emits
  no Router Advertisements and could not become anyone's gateway. **That distinction is the
  interesting part**: a naive check that alarms on the NA R-bit alone would have fired on a
  harmless host. See "Design notes" below.

(Device identifiers deliberately not recorded here — this is a public doc. The specific host
is named in the private VM fleet log.)

## Design notes (the trap to avoid)

**Do not alert on the Neighbour-Advertisement R-bit alone.** Linux sets it automatically
whenever `net.ipv6.conf.all.forwarding=1`. Any host doing NAT, containers, a VPN exit node,
or plain IP forwarding will set it while emitting no RAs and influencing no routing. Alerting
on it produces false positives on exactly the technical users most likely to have such hosts.

The signal that actually matters is a **Router Advertisement from an unexpected source**:

- Observe RAs (ICMPv6 134) and record the advertising source per interface.
- Learn/pin the expected router set (the existing `devices` table already knows which hosts
  are `type=Router` and `trusted=1`).
- Alert when an RA arrives from a source outside that set, or when a previously-unseen source
  starts advertising a default route (`router lifetime > 0`) or a new prefix.
- Severity should distinguish "new router advertising a default route" (high — on-path risk)
  from "known host now forwarding" (informational).

Worth capturing alongside: **RA guard is a switch feature** most home networks lack, which is
part of why host-side detection has value here.

## Open questions

- Passive capture only, or also periodic Router Solicitation to enumerate responders?
- Does this belong in `anomaly_detection`, `malware_detection`, or a new network-integrity
  module? It is a LAN-integrity signal, not a host or traffic-content signal.
- Same question for IPv4: rogue DHCP detection is the sibling problem and probably shares a
  module.
- Interaction with the agent fleet: agents on other subnets could report their own view,
  turning a single-segment check into a fleet-wide one.

## Connections

- `devices` table already carries `device_type` and `trusted`, which is the expected-router
  set this would compare against.
- Private VM fleet log — records the specific host, the measurement, and the standing revisit
  trigger for it.
