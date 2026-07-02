# Roadmap — Agent tunnel-environment awareness (2-step)

**Status:** capture (design item; **post-trip**, NOT a trip task). Two-step build; Step 2 gated on
the Tailscale-coupling assessment.

**Rule 8:** placeholders only — no real IPs/hosts/accounts/keys.

> Capture only — no code, no build. This is the runtime **feature** version of tunnel portability:
> the shipped agent detecting and adapting to whatever tunnel/VPN transport it lands in. It is the
> sibling of the **test/eval** item in `PUNCHLIST.md` ("[POST-TRIP EVAL] Tunnel-transport
> portability — Tailscale vs WireGuard / other mesh VPNs"), which just measures how coupled the
> product is to Tailscale today. Assess that coupling **before** committing to Step 2's
> abstraction. Related: [ADR 0011 — enrollment security model](../architecture/0011-enrollment-security-model.md),
> `docs/CUSTOM_TAILSCALE_OAUTH.md`, and the LHM-coupling parallel in
> `docs/audits/architecture-debt-audit-2026-07-02.md`.

---

## Why

Today the agent assumes **Tailscale** as its transport — OAuth key minting, pre-auth-key
enrollment, tailnet join, and "reachable over the tailnet" assumptions are baked into onboarding.
The no-IT-department ethos (and commercial/SMB fit) wants the agent to work across **varied
setups** rather than mandate one vendor's mesh: an SMB with existing WireGuard/mesh infra should be
able to run Nemesis over THEIR tunnel. The end state: the agent **adapts to whatever tunnel it
lands in** instead of assuming Tailscale.

Onboarding fundamentally just needs the agent reachable at a stable address on a private network —
the mesh tech that provides that should be a detail, not a hard dependency.

## Build in two steps

### Step 1 — Foundation: inventory the network + tunnel environment (read-only)
The agent **gathers and inventories** the system's network + tunnel setup. Pure data collection —
**no decisions, no adaptation.** What's installed / running:
- Tailscale present/running? WireGuard present/running? Other mesh/VPN (Headscale, Netbird,
  ZeroTier, PIA/Mullvad/Proton, etc.)?
- Network environment (interfaces, tunnel interfaces, reachable address, subnet context).

**Properties:** low-risk (read-only), and **independently useful** even if Step 2 never ships —
the inventory is diagnostic data that could feed the dashboard and the connection-health subsystem
(`connection-health-subsystem.md`). This is the safe, self-contained first deliverable.

### Step 2 — Detection + decision logic (depends on Step 1)
The agent **reasons about the Step-1 inventory and adapts** the transport branch:
- **Existing Tailscale** → use it (today's path).
- **Raw WireGuard (or other mesh) present** → adapt to it / bring-your-own-tunnel.
- **Nothing** → set up our own (mint + join Tailscale, today's default).

This is the branching/adaptation layer built ON Step 1's data. It is the part that needs the
transport treated as a **swappable abstraction** rather than Tailscale hardcoded through
enrollment / heartbeat / reachability — so it is **gated on the coupling assessment** (the
PUNCHLIST eval item). If that audit finds the coupling thin, Step 2 is small; if it finds
Tailscale baked deep (the LHM shape), Step 2 grows a transport-abstraction seam and likely
graduates to its own build spec / ADR.

## Relationship map (don't conflate the three)
- **PUNCHLIST `[POST-TRIP EVAL]`** = *test/measure* how coupled we are to Tailscale today (audit +
  WireGuard spike). Read-only assessment.
- **This roadmap item, Step 1** = *ship* the inventory/collection (read-only, independently useful).
- **This roadmap item, Step 2** = *ship* the detect-and-adapt logic (gated on the eval's verdict).

## Dependencies / sequencing
1. PUNCHLIST tunnel-portability eval (coupling verdict) — informs Step 2's scope.
2. Step 1 (inventory) — can proceed independently; low-risk; feeds dashboard / connection-health.
3. Step 2 (adaptation) — after Step 1 + the coupling verdict.

**Do NOT build now.** Post-trip. Graduate Step 2 to a full build spec/ADR if the coupling
assessment shows a transport abstraction is warranted.
