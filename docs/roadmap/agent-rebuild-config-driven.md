# Roadmap — Agent rebuild (config-driven, centrally-managed client)

**Status: parked → ACTIVE (2026-08-04) for the observation-layer foundation below.** The
config-driven rebuild described in the rest of this doc remains capture-only/parked as
originally captured. What's now active is a narrower, technique-independent foundation that
several other paused/in-progress efforts depend on — see "Observation-layer foundation" below.
Ties to ADR 0005, the VM Lab, and `docs/operation/CONFIG_CHANGE_PROCEDURE.md`.

A thin, config-driven agent: intelligence lives in the server config; the client reads and
applies it.

---

## Observation-layer foundation (active, 2026-08-04) — build order

Approved by the operator as a standalone foundation, independent of the rest of this doc's
config-driven rebuild. Build order matters — each item below is a real prerequisite for the
ones after it, not an arbitrary sequence:

1. **Agent integrity attestation** — first, because every other item's output is only as
   trustworthy as the agent reporting it. Load-bearing for access control, not just detection
   fidelity, once any firewall grant keys off an agent-reported event (see the UDP policy
   scoping work).
2. **Full process enumeration** — replaces the current top-10-by-CPU sample, which cannot
   support process-launch detection (a quiet process never appears in it) and is insufficient
   for any future memory-injection work, which needs full enumeration as step zero.
3. **UDP-visible connection reporting** — the agent's connection filter currently excludes all
   UDP traffic (it filters on TCP's `ESTABLISHED` state, which UDP sockets never have), making
   UDP-based C2 invisible to it today, independent of anything else in this list.
4. **IPv6 connection-type fix** — local-vs-remote device classification currently only
   considers IPv4 local addresses, so an IPv6-only local device is misclassified as remote. Fails
   toward the more restrictive classification, so this is a misclassification, not an open
   door — but it's the same IPv4-only-assumption class already found and fixed once in the Tier 2
   TLS gate.
5. **Event-triggered early check-in** — the agent polls immediately on a qualifying local event,
   rate-limited by the existing poll-interval floor, rather than waiting up to the default
   interval for anything event-driven to reach the server. **Designed jointly with Tier 3's
   local-trigger path** ([adr-0009-l3-tier3-local-triggers-scope.md](adr-0009-l3-tier3-local-triggers-scope.md))
   rather than built twice — Tier 3's whole premise is deciding locally without a server
   round-trip at all; this is "get to the server faster when a round-trip is fine," a related but
   distinct need that shouldn't duplicate Tier 3's design.

**Why this is technique-independent and can start now, without waiting on any paused
detection-technique decision:** every plausible memory-injection or zero-day detection approach
needs full process visibility, and all of them benefit from UDP- and IPv6-correct connection
reporting. The foundation doesn't block on which module ends up owning the executing-payload
case (see [memory-injection-detection-design.md](memory-injection-detection-design.md)) — only
the detection technique itself does.

**Carried forward from CLAUDE.md, not re-derived:** this rebuild includes the actor seam on
agent-related tables and is built auth-aware at the product's two hook points for it — the
standing instruction is to fold these into this rebuild rather than add them a second time
later.

## Two-phase bootstrap

- **Install package:** server LAN IP + owner install key (only).
- **Phase 1:** agent contacts the server over LAN/direct IP, pulls full config (VPN method,
  auth keys, feature flags, poll intervals).
- **Phase 2:** agent configures the VPN, re-contacts over the tunnel, registers.
- Install key consumed post-enrollment (can't reuse).
- All subsequent config pulls go over the tunnel.

## Config-pull architecture

- Agent is **thin** — intelligence lives in the server config.
- Config changes on the dashboard → restart affected agents → agents pull new config →
  changes applied fleet-wide.
- Config carries a **version number** → agents report their current version → the dashboard
  shows which are current vs stale.
- **VPN method is a configurable field** (Tailscale / Wireguard / Mullvad / ProtonVPN /
  custom) — the agent reads and applies it, never hardcoded.

## Restart control (dashboard)

- Per-agent restart (sends a restart command to the `5002` listener).
- Restart all agents (**staggered** — one at a time, configurable delay — prevents a
  thundering herd, ensures some are always online).
- Post-restart status (came back? what config version?).
- References `docs/operation/CONFIG_CHANGE_PROCEDURE.md` for safe rollout.

## Scripted VM agent creation

- `nemesis-create-test-vm.sh`: `VBoxManage` + cloud-init + auto-enroll.
- Single command, ~5–10 minutes, no manual steps.
- Windows host support (`VBoxManage` is cross-platform).
- Connects to the VM Lab (the UI wrapper around this script).

## Fold in at build time
- **Connection-type awareness** ([connection-type-awareness.md](connection-type-awareness.md)):
  the heartbeat payload + `agent_devices` schema gain `connection_type` / `interface_name` /
  `connection_speed` (`psutil` interface detection). **Fold these columns into the same
  `agent_devices` migration as the readiness actor seam** — don't touch `agent_devices` twice.

## Ties to

ADR 0005, the [VM Lab](nemesis-test-lab.md), `docs/operation/CONFIG_CHANGE_PROCEDURE.md`,
[connection-type-awareness.md](connection-type-awareness.md).
