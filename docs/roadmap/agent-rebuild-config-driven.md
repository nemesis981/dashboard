# Roadmap — Agent rebuild (config-driven, centrally-managed client)

**Status:** parked (capture-only — what + why; do NOT build yet). Ties to ADR 0005, the VM
Lab, and `docs/operation/CONFIG_CHANGE_PROCEDURE.md`.

A thin, config-driven agent: intelligence lives in the server config; the client reads and
applies it.

---

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
