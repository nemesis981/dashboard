# Roadmap stub — Connection-type awareness (ethernet / wifi / unknown)

**Status:** parked (capture-only — what + why; do NOT build yet). **Folds into** the
[agent rebuild](agent-rebuild-config-driven.md), the device-detail-page build, and the
`HEALTH_SERVICES` Suricata check. Related: ADR 0005 (device identity), the header status
lights + diagnostics tiered-display patterns (`PUNCHLIST.md`).

## What
The agent reports its **connection type** on every heartbeat, and the dashboard treats
Suricata coverage as connection-aware instead of assuming every device is span-port-monitorable.

The agent reports three fields to the `agent_devices` table on heartbeat:
- `connection_type` — `ethernet` | `wifi` | `unknown`
- `interface_name` — the active interface (e.g. `eth0`, `wlan0`)
- `connection_speed` — link speed

**Detection (agent):** `psutil.net_if_stats()` + `psutil.net_if_addrs()` to identify the
active interface and classify its type.

The dashboard uses this to:
1. **Gate Suricata coverage expectations per device** — WiFi = `not_applicable`, **not a
   failure**. (WiFi traffic isn't on the monitored span/mirror, so absence of Suricata
   coverage there is expected, not broken.)
2. **Surface coverage gaps transparently** in device detail — tiered display (Beginner: plain
   language → Pro: technical detail). Never pretend coverage is complete when it isn't.
3. **Prevent false alerts** — the header status light does **not** go red for an *expected*
   WiFi coverage gap (only for real failures).
4. **Update automatically** when the connection type changes — laptop unplugs ethernet →
   switches to WiFi → coverage status updates on the next heartbeat.

## Why
Suricata can only see traffic that crosses the monitored link. A WiFi device's traffic
often isn't on that link, so reporting "Suricata not covering this device" as a **failure**
is wrong — it manufactures a red light for a gap that is structural, not broken. That false
red erodes trust (the whole point of the header light is that red means *act now*). Making
coverage **connection-aware** keeps the signal honest: ethernet devices are expected to be
covered (alert if not); WiFi devices are honestly marked `not_applicable` with a plain-language
explanation of the gap. **Transparency over false reassurance** — never pretend coverage is
complete when it isn't.

## Where it folds in (build-time integration)
- **Agent rebuild** ([agent-rebuild-config-driven.md](agent-rebuild-config-driven.md)): the
  heartbeat payload gains `connection_type` / `interface_name` / `connection_speed`; the
  `agent_devices` schema gains those columns. **Fold these into the same `agent_devices`
  migration that carries the readiness actor seam** (per CLAUDE.md, don't add agent_devices
  seams twice — one migration).
- **Suricata health check** (`HEALTH_SERVICES`, `dashboard.py`): make it connection-type
  aware — an **ethernet** device alerts if Suricata isn't running; a **wifi** device shows
  `not_applicable`, not a failure.
- **Device detail page build:** show connection type + Suricata coverage status clearly; for
  WiFi devices, render the coverage-gap explanation at the appropriate tier (Beginner plain
  language / Pro technical). Never pretends coverage is complete when it isn't.

## Reasoning / shape
- Classification lives in the agent (it knows its own interfaces); the server stores and
  interprets. Keep `unknown` as a first-class value (don't force a guess).
- Coverage verdict is **derived from real state** (connection_type + Suricata running),
  recomputed each heartbeat — same "make invisible variables visible / derive from real
  state" discipline as the system-changes badge and header lights.
- Multi-user/actor: the new columns are device telemetry (no attribution needed), but they
  ride the same `agent_devices` migration as the actor seam — coordinate so it's one change.
- Flesh out exact thresholds (what counts as a coverage gap), the tiered copy, and the
  `not_applicable` UI treatment when this graduates from stub to spec/ADR.
