# Roadmap — UDP policy: default-deny, Game Mode, hosting, visibility

**Status:** scoping doc (read-only analysis; no code changed). Captured 2026-08-04. Not currently
built. This doc did not exist in the public repo before this entry — the underlying scoping work
happened in the private mirror first; this is the public-facing scope.

---

## The core decision: default-deny is a profile choice, not a universal default

**Do not make UDP default-deny universal.** Ship the QUIC-specific block everywhere — it's
precise and gaming-neutral (see
[tls-interception-sterilization-scope.md](tls-interception-sterilization-scope.md), Piece K).
Offer broader UDP default-deny as the **appliance/commercial profile** default, selected by a
plain-language deployment question at install time. **Never key it to the commercial entitlement
tier** — that would make the free tier deliberately less secure than the paid one, which isn't
the kind of tradeoff this product makes. The choice is about deployment context (a managed
appliance vs. a home network with unmanaged devices and games on it), not about what a customer
has paid for.

## A hard blocker on the current stack

A plain port allowlist cannot express Tailscale's direct peer connectivity — its traffic goes to
arbitrary ephemeral ports by design. Under a strict UDP deny, Tailscale degrades from a direct
path to relay: remote access and enrollment keep working, but route through a third party instead
of directly. An untested mitigation worth a spike: a cgroup-scoped exemption for the Tailscale
daemon specifically, rather than a blanket UDP allowance.

## A production hazard worth stating plainly

**Conntrack grandfathering makes a deny look harmless at apply time; it breaks at the next
re-establishment.** A UDP flow already tracked as established at the moment a deny rule is
applied keeps working until it naturally re-establishes — so the change looks clean immediately
and then breaks something later, disconnected in time from the change that caused it. Worth
naming explicitly so a future "it worked when I tested it" report doesn't get treated as
unrelated to a UDP policy change made earlier.

## What's genuinely solved

- **Auto-close is free and native.** nftables dynamic sets with per-element timeouts, refreshed by
  traffic and expiring on idle — verified. A grant's time-to-live becomes an idle timeout rather
  than a guessed wall-clock duration, so it can't expire out from under an active session.
- **Auto-reopen is agent-only, and that's a real constraint, not an oversight.** The packet that
  would signal "this app relaunched, reopen its port" is exactly the packet the deny rule drops —
  so only a device running the Nemesis agent (which can observe the process launch itself, not
  the network packet) can auto-reopen. Non-agent devices cannot.

## Recommended resolution: learn, then enforce

A learning phase pre-authorizes and logs observed UDP activity; the resulting profile becomes the
allowlist, so only genuinely novel UDP traffic raises a decision afterward. This keeps first
launches of legitimate software working without user intervention, and keeps prompts rare enough
that a user actually reads them when one appears, rather than training a reflexive "allow"
click.

**For non-agent devices, prefer allow-and-notify over block-and-ask.** The person who'd need to
answer a block prompt is at the console of that device, not watching the dashboard — and an
unattended appliance failing overnight has nobody there to see a prompt at all. Notifying after
the fact is more useful than a prompt nobody will answer.

> **A limitation worth naming directly, not softening:** the pre-authorized, activity-gated model
> described above is a **reduced exposure window, not a full security gate**. The first packet of
> a new flow has to be accepted in order to create the tracking element that makes the rest of the
> model work at all — which means, in the narrow window before a flow is classified, the
> protection this model offers is real but bounded, not absolute. Full technical detail and the
> inbound-traffic analysis: held privately for now (Rule 10) — this paragraph states that the
> limitation exists and is understood, which is the part that matters for anyone evaluating this
> feature; it is not a claim that the underlying analysis is being withheld out of caution about
> the product looking bad. Source-visibility only, never a feature gate.

## Game-server hosting (inbound DMZ) — parked behind an architecture decision, not just unbuilt

This is not simply an unbuilt feature; it's blocked on a decision the product hasn't made.
Nemesis today is a bridged LAN peer and ships with forwarding disabled — it never sees inbound
internet traffic at all. Hosting a game server for inbound connections (a DMZ, in the networking
sense) presupposes Nemesis being the network's gateway, which it deliberately isn't today. This
needs its own ADR: **does Nemesis become the gateway?** — and that ADR's core content would be a
forward-gate design, not the hosting feature itself.

**Partial de-risking already exists:** a base chain at `raw` priority gates forwarded traffic
ahead of the chain that already pre-empts `ufw` — demonstrated live. This doesn't answer the
gateway question; it just means the plumbing for a future forward-gate has a natural home once
the architecture decision is made.

Two notes worth carrying into that future ADR, so they aren't rediscovered: the port a game
server needs **is** knowable in practice (the user can read it off the game's own setup
instructions, and an in-path Nemesis could in principle learn it from observed connection
attempts that get dropped) — it isn't an unknowable secret the way a fully generic hosting feature
might assume. And a UDP DMZ opens **every** UDP port on the target device, not just the one the
game needs — the UI for this, whenever it's built, must not present that as equivalent to a
single-port forward, or it will mislead users about their actual exposure.

## Dashboard visibility — ship this part first, and read-only

Of everything in this scope, visibility is the only piece with no blockers, and it's what makes
the rest of this work debuggable once built. It should render from the same state the live
ruleset itself renders from — never a parallel table that can silently drift from what's actually
enforced — and surface intended-vs-installed using the existing out-of-band-change watcher. A
dashboard that shows a rule the kernel doesn't actually have would be exactly the kind of
plausible-but-wrong instrument this codebase's standing verification discipline exists to rule
out.

## Cross-references

[tls-interception-sterilization-scope.md](tls-interception-sterilization-scope.md) (Piece K — the
QUIC-specific block this doc's "ship everywhere" recommendation reuses),
[adr-0009-l3-tier3-local-triggers-scope.md](adr-0009-l3-tier3-local-triggers-scope.md) (the new
activity-gated-UDP-grant-as-C2-channel threat-model entry this doc's design motivates),
`alert_manager/firewall.py` (the single `ufw` chokepoint any UDP enforcement work must route
through, per standing architecture rules — not an exception to invent an ad-hoc path around).
