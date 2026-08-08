# Roadmap — Gateway Mode: full gateway vs. bridged-peer choice

**Status:** scoping doc (read-only analysis; no code changed). Captured 2026-08-08.
This doc formalizes and refines a direction already decided but never written up: `PUNCHLIST.md`
records that the gateway-role decision was taken 2026-08-05 ("Nemesis WILL become the gateway"),
and [udp-default-deny-scoping.md](udp-default-deny-scoping.md) (2026-08-04) independently named
"does Nemesis become the gateway?" as needing its own ADR. Neither source treated it as a
per-deployment *choice* — this doc's core contribution is reframing "Nemesis becomes the gateway"
from a blanket product direction into an opt-in mode, selected per install, changeable later. That
reframing is deliberate, not an oversight of the earlier decision — see "Relationship to the
2026-08-05 decision" below.

**Not yet an ADR. Confirmed 2026-08-08 (Window 2): ADR 0022 is NOT this topic — no collision,
but no reuse either.** 0022 is earmarked for the QUIC/nftables item (the static-policy nftables
block, "Piece K," `deploy-quic-block.sh` — carried as owed on every HANDOFF/briefing since
2026-08-06). That item and the 2026-08-05 gateway-role decision both surfaced in the same
day's PUNCHLIST entries, which is what made them look related — they aren't the same ADR.
When this doc is ready to graduate, it takes the next number free at that time (0023 as of this
writing, but re-check — 0022 stays QUIC/nftables' regardless of write order).

---

## What "Gateway Mode" actually means, scoped

Two axes exist in the current architecture, and they're easy to conflate — this doc treats them
as separate, coupled axes rather than one bundled toggle:

1. **DHCP/DNS ownership** — the existing three-way toggle (`modules/dhcp/module.py`,
   `nemesis` / `pihole` / `provider`). Already built, already has a capability-table data
   structure (`MODE_CAPABILITIES`, `modules/dhcp/module.py:137-193`). DNS handout rides on
   this axis, not on gateway/forwarding role — whichever DHCP server is active is the one that
   tells clients which DNS server to use.
2. **L3 forwarding / gateway role** — new, this doc's actual subject. Whether Nemesis sits
   inline as the network's router (`ip_forward=1`, ADR 0019's `forward`-hook enforcement active,
   NAT) or stays a bridged LAN peer that never sees inbound/routed traffic (`ip_forward=0`, as
   today — confirmed current state, `install.sh:1287-1374`).

**These two axes are coupled, not independent, for exactly one reason: enforced segmentation
needs both.** `nemesis` DHCP mode's own capability entry already claims
`"segmentation": "possible — still requires layer-2 separation (see scope §L2c)"`
(`modules/dhcp/module.py:143`) — but no `§L2c` document exists anywhere in the repo. That's not
a broken cross-reference to fix cosmetically; it's the dangling citation into exactly the ADR
this doc is scoping. The honest resolution: DHCP-mode lease tiering can *assign* a device to a
segment, but nothing *enforces* the boundary between segments without an inline L3 gate filtering
forward traffic between them. So:

- `nemesis` DHCP mode alone (Gateway Mode off) → devices get tiered leases, hostnames captured
  reliably, but segment boundaries are **not enforced** — assignment without isolation.
- Gateway Mode alone (DHCP left on `provider`) → Nemesis can filter/forward traffic, but has no
  DHCP-driven knowledge of which device belongs in which segment — enforcement without a
  meaningful policy to enforce.
- Both together → the actual "full segmentation" capability the task description names.

**Recommendation: Gateway Mode does not require `nemesis` DHCP mode as a hard precondition (a
user could enable inline forwarding without taking over DHCP), but the segmentation/tiering
capability requires both, and the UI must say so explicitly per combination — never silently
no-op when a device gets tiered by DHCP but not actually isolated.** This also gives the `nemesis`
DHCP mode's `MODE_CAPABILITIES` entry a real answer for its `§L2c` placeholder: replace it with a
pointer to whatever this doc's eventual ADR is numbered.

---

## Capability table (per the DHCP toggle's honesty pattern)

Mirroring `MODE_CAPABILITIES`'s shape (`label`, what's gained, `degraded: [...]`, `notes`) —
this is the table the actual toggle UI should render. Flagged explicitly: **the DHCP toggle's own
data structure for this pattern exists in code but is never rendered in the dashboard UI today**
(`get_dashboard_card()` only shows a status dot and one-line label, not the `degraded` list). This
toggle should not repeat that gap — build the rendering, don't just define the data.

### Full Gateway mode

- Inline L3 gate active: ADR 0019's `forward`-hook enforcement live, `ip_forward=1`.
- Segmentation enforced (when paired with `nemesis` DHCP mode + VLAN-capable switch/AP hardware —
  Nemesis cannot manufacture L2 separation the hardware doesn't provide).
- DHCP-based device tiering meaningful (lease behavior actually backed by enforced isolation, not
  just assignment).
- Prerequisite unlocked, not automatically shipped: inbound hosting/DMZ (game-server hosting etc.)
  — that remains its own separately-scoped feature per
  [udp-default-deny-scoping.md](udp-default-deny-scoping.md); Gateway Mode only removes the
  architectural blocker, it doesn't ship the feature.
- **Cost, stated plainly:** requires taking the existing router out of routing/NAT duty (not
  possible on some locked-down ISP hardware — the exact case the task's framing calls out).
  Higher blast radius than any other toggle in the product: a misconfiguration here can take the
  whole network offline, not just degrade one feature. Requires State Snapshots discipline (CLAUDE.md
  Tier 1) before every switch into or out of this mode, not just DB-touching changes.

### Bridged-peer (lighter) mode — today's actual shipped default

- `degraded`: no segmentation (regardless of hardware — same honest phrasing the DHCP module
  already uses for its own non-`nemesis` modes), no enforced DHCP-based tiering, no inline L3
  gate, no inbound hosting/DMZ.
- **What's explicitly NOT degraded — the "security is never the upsell" list:**
  - Suricata IDS: full coverage on visible wired traffic today, identical to Gateway Mode for
    Ethernet devices (ADR 0009's Mode 1, "Maximum" coverage). The WiFi blind spot is closed by
    the inspection-proxy tunnel (ADR 0009), not by becoming the gateway — so choosing bridged-peer
    mode does not reopen or worsen the WiFi gap.
  - Malware scanning: host/endpoint-based (ClamAV on the appliance, agent-side on endpoints) —
    architecturally independent of network role.
  - `nemesis_agent` protection: entirely host-based, POSTs findings to the dashboard regardless
    of how Nemesis sits on the network.
  - `firewall.py`/`nemesis-fwd` host-protection chokepoint (INPUT/OUTPUT blocking): unaffected —
    it protects the box itself either way; only the `forward`-hook half is gateway-role-gated.
- **Notes:** the correct default, and the right choice for locked-down ISP routers or operators
  who don't want Nemesis touching core network plumbing — matches the task's framing directly.

---

## How the choice gets made

**Both install-time and settings-time — mirroring the DHCP module's own design intent
("an operator may want to hand DHCP back temporarily while diagnosing something",
`modules/dhcp/module.py:118-126`), but neither surface for the DHCP toggle is actually wired up
yet** (`install.sh` has no DHCP-mode code; `dashboard.py` has no routes reaching `switch_mode()` —
confirmed by the module's `get_routes()` returning `None`). **This is a known, real gap in the
existing pattern, not a solved template to copy blindly** — Gateway Mode's scoping should plan for
both surfaces explicitly rather than inherit DHCP's current install-time silence.

- **Install-time:** a plain-language deployment question, same shape as
  [udp-default-deny-scoping.md](udp-default-deny-scoping.md)'s recommended profile-selection
  question — not a technical prompt, a "what kind of network is this" framing that a non-expert
  user can answer honestly (e.g., "can you take your router out of DHCP/routing duty, or is it
  locked down / not yours to reconfigure?").
- **Settings-time (changeable without reinstalling):** yes — should follow the DHCP module's
  `switch_mode()` precedent (snapshot prior state → apply → verify with live readback → rollback
  cascade through snapshot tiers on failure), but with the blast radius correctly scaled up: this
  touches system-wide routing (`ip_forward` sysctl), the ADR 0019 enforcement table's active hook
  set, and potentially DHCP ownership — not just one daemon's config file. Should require
  `confirmation_required`/`confirmation_message` (the one manifest field `dashboard.py` already
  consumes today, `dashboard.py:5584-5585,8898-8899`) at minimum; likely also a full State
  Snapshot per Tier 1 discipline given the "config edit that changes live network behavior"
  classification.
- **Do not repeat the DHCP toggle's installer gap.** Its live 2026-08-07 deployment needed a
  polkit rule and group membership wired by hand because `install.sh` never provisioned them
  (`docs/handoff/HANDOFF.md:95-96`, `PUNCHLIST.md:3340-3419`). Gateway Mode's host-level plumbing
  — `ip_forward` persistence, the forward-hook nftables table's install/teardown, any polkit
  needed for privilege-separated switching — must ship in the installer from day one, given this
  mode's larger blast radius makes a "discovered live" gap here considerably more costly than the
  DHCP one was.
- Downgrade (Gateway → bridged-peer) needs the same rollback rigor as upgrade, symmetrically —
  cleanly handing DHCP back (the `provider` mode path already does this) and flushing the
  forward-hook table / resetting `ip_forward` verifiably, not just "should be fine."

---

## Relationship to the 2026-08-05 "Nemesis WILL become the gateway" decision

Worth stating explicitly rather than letting the two read as contradictory: that decision, as
recorded, was a **product-direction** commitment (ship the capability, build toward it) — it was
never framed as "every deployment becomes a gateway unconditionally." This doc's toggle proposal
is consistent with that decision's letter (all the gateway-capable code ships, always available)
while giving it the opt-in shape the task explicitly asks for. Read this doc as **operationalizing**
the 2026-08-05 decision, not reopening or overriding it — but that's a judgment call this scoping
pass is making, not a fact already settled elsewhere, so it should be surfaced to the operator
before being treated as final.

---

## Open questions

- ~~ADR numbering — 0022 collision risk~~ — resolved 2026-08-08: 0022 is QUIC/nftables', not
  this topic; this doc takes the next free number (0023 as of this writing) when it graduates.
- Exact install-time question wording — not decided, placeholder framing only (see above).
- Whether Gateway Mode should be gateable independent of `nemesis` DHCP mode at all, or whether
  the product should just present them as one combined choice in the UI even though they're two
  separate flags underneath — an implementation-simplicity vs. honesty-of-model tradeoff not
  resolved here.
- Whether downgrade (Gateway → bridged-peer) needs its own distinct rollback-cascade design or can
  reuse DHCP module's snapshot-tier mechanism directly — not yet investigated at the code level.
- The stale `ARCHITECTURE.md:37` description of the dhcp module ("Pi-hole DHCP takeover") should
  be corrected independent of this doc — noted here since it was surfaced during this research,
  not itself in scope for this toggle.

## Cross-references

[udp-default-deny-scoping.md](udp-default-deny-scoping.md) (the inbound-hosting/DMZ feature this
toggle unblocks but does not itself ship; also the earlier "does Nemesis become the gateway?"
framing), [device-coverage-tier-indicator.md](device-coverage-tier-indicator.md) (state 4's
"never-agentable but computer-class" tier depends on the same gateway/segmentation decision this
doc scopes), `docs/architecture/0005-dns-firewall-device-auth-architecture.md` and
`docs/architecture/0019-deterministic-enforcement-point.md` (the firewall-engine/enforcement-point
ADRs this toggle's inline-gate half builds on), `modules/dhcp/module.py` (`MODE_CAPABILITIES`,
the honesty-pattern data structure this doc's capability table mirrors), `alert_manager/firewall.py`
(the host-protection chokepoint confirmed unaffected by either mode).
