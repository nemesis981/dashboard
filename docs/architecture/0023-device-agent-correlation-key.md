# ADR 0023 — Device↔Agent Correlation Key (reported LAN MAC)

- **Status:** **PROPOSED — draft for review, no code changed.** Records the approach for
  closing the `devices`↔`agent_devices` correlation gap. Approval gates the implementation.
- **Date:** 2026-08-19
- **Affects:** the enrollment payload / `/enroll` + `/hw_data` contract, a new
  `agent_device_macs` table (schema migration), the device categorisation path
  (`nemesis_device_category.classify`'s `has_agent` input).
- **Depends on:** [0011 — enrollment security model](0011-enrollment-security-model.md) (the
  enrollment payload + `/enroll`), [0007 — device/user model](0007-device-user-model.md),
  [0001 — database & module architecture](0001-database-and-module-architecture.md) (write-own /
  read-any, canonical DDL, guarded migrations). Uses `hwid.py`'s physical-link detection but is
  **not** part of the hardware fingerprint (see Decision).

---

## Context

Two tables describe the same real devices from two different vantage points, and nothing
reliably joins them:

- **`devices`** — `mac TEXT PRIMARY KEY, ip, hostname, vendor, …`. The **appliance's own LAN
  view**, populated by the device scanner (ARP) and DHCP. The MAC here is what the appliance
  observes on the wire.
- **`agent_devices`** — `device_id TEXT PRIMARY KEY` (32-char), `ip_address`, `device_name`,
  the hardware fingerprint (`hw_stable_id`, …), enrollment state. Populated at enrollment.
  Its `ip_address` is set to the **address the request arrived from** (`remote_ip`).

The only shared field is IP, and it resolves **2 of 13** enrolled agents in practice (measured
2026-08-06). The root cause is structural, not a bug: agents commonly reach the server over
Tailscale, so `agent_devices.ip_address` is a **tailnet** address while `devices` holds **LAN**
addresses — two different network views of one device. IP is also volatile (DHCP churn) and
identifies the wrong interface.

Two things that look like they should bridge the gap do not:

- **The hardware fingerprint deliberately excludes MAC.** `hwid.py` composes system_uuid /
  machine_id / board_serial / disk_serial precisely because those are hardware-stable; MAC is
  not (NIC swaps, per-network randomisation). So the fingerprint cannot match `devices.mac`,
  and that exclusion is correct **for identity**.
- **The enrollment payload carries no MAC.** It sends `device_name`, OS, `hardware_summary`,
  the fingerprint, and `link_type` (wifi/ethernet) — the agent does not currently collect or
  report a MAC.

This blocks every feature that needs "is this network device an enrolled agent?": accurate
`has_agent` categorisation (today deliberately not computed — see
`nemesis_device_category.classify` and the `dashboard.py` device-list note), BYOD-tier accuracy,
IoT device-count exclusion, and the per-device enrollment check the diagnostics applicability
gate depends on.

## Decision

Add a **reported LAN MAC** as the correlation key. The agent reports the MAC(s) of its
**physical** LAN interface(s) — the ones the appliance's ARP scan already records in
`devices.mac` — and the server stores them in a normalised table used to join the two views.

### Why MAC, and why this is not the fingerprint's mistake repeated

This is a **different use of MAC** than `hwid.py` rejected. MAC-as-identity is wrong: it is not
stable across networks. MAC-as-**LAN-correlation** is right: on the single network the appliance
monitors, the device presents one MAC, and that is exactly the value ARP records. The property
we need is "stable **on this LAN**," which even randomised MACs satisfy (randomisation is
per-network, so a device keeps one MAC on a given network). The two uses do not conflict; the
fingerprint stays MAC-free.

### The key is already within reach on the agent

`nemesis_agent/platforms/linux.py::_route_iface()` already resolves the physical interface used
to reach the server and **skips tunnels** (tailscale/wg/tun/…). From an interface name the MAC
is one read away (`/sys/class/net/<iface>/address` on Linux; platform equivalents for
Windows/macOS under `platforms/`). So collection reuses existing machinery.

### Three parts

1. **Enrollment-contract change.** The agent adds a `lan_macs` field (a list of normalised
   lowercase colon-separated MACs of its physical, non-tunnel interfaces) to the `/enroll`
   payload **and** to the heartbeat (`/hw_data`). Heartbeat re-reporting is required, not
   optional: it is what lets correlation self-heal when a NIC changes or a device re-randomises
   its MAC on network rejoin.

2. **Schema — a normalised `agent_device_macs` table** (approved shape):

   ```
   agent_device_macs(
       device_id  TEXT NOT NULL,   -- FK-in-spirit to agent_devices.device_id
       mac        TEXT NOT NULL,   -- normalised lowercase aa:bb:cc:dd:ee:ff
       last_seen  REAL NOT NULL,   -- epoch; refreshed each heartbeat
       PRIMARY KEY (device_id, mac)
   )
   ```

   One agent → many MACs (dock, WiFi+ethernet, VM host). Upserted at enroll and heartbeat.
   Normalised into its own table rather than a column on `agent_devices` so multi-MAC and
   re-reporting are clean and a stale MAC can age out on its own `last_seen` without rewriting
   the agent row. Canonical DDL lives beside `agent_devices` (the `hw_monitor.py` init), created
   via a guarded `PRAGMA`/`CREATE IF NOT EXISTS`, consistent with ADR 0001. Owned/written by the
   agent-ingest namespace; read-any for the categorisation path.

3. **Correlation becomes a real join.** `devices.mac ∈ agent_device_macs` → `device_id` →
   `agent_devices.enrollment_status`. This replaces the IP heuristic and is what supplies
   `has_agent` (an approved-agent match) to `nemesis_device_category.classify`, closing the
   2/13 gap and unblocking the per-device enrollment check, IoT exclusion, and BYOD accuracy.

### Normalisation and matching rules

- MACs are normalised to lowercase, colon-separated on both sides before comparison (the scanner
  and the agent may format differently). A single canonical form is applied at write time.
- A match against **any** reported MAC for a device counts (multi-NIC). `enrollment_status` from
  the matched `agent_devices` row decides agent-vs-not; only `approved` counts as enrolled.

## What this ADR does not decide

- **The applicability gate and the 3-state VPN check** that consume this correlation are
  separate work (the diagnostics thread). This ADR only makes the correlation reliable; how a
  gate uses "enrolled vs not" — including the honest "enrollment unknown" degrade path when a
  device has no matching MAC yet — is decided there.
- **The fingerprint-mismatch cross-check** (a device behaving inconsistently with its claimed
  type) is out of scope here; it needs a passive traffic-behaviour signal that does not exist
  yet and is its own design.
- **Windows/macOS collection specifics** beyond "platform equivalent under `platforms/`" — the
  exact source per OS is an implementation detail, not an architectural choice.
- **Any change to the hardware fingerprint.** It stays MAC-free.

## Consequences

- **Correlation is LAN-scoped by nature — stated, not hidden.** A device that only ever reaches
  the appliance over routed/tunnel paths never appears in ARP/`devices`, so it cannot be
  correlated — correctly, because it is not a network device the appliance scans. The fix is
  bounded to devices on the monitored L2, which is exactly the set the motivating features care
  about.
- **Backfill is gradual, not instant.** The existing enrolled agents carry no `lan_macs` until
  their next heartbeat, so correlation improves as agents check in. "Still N/13 an hour after
  deploy" is expected convergence, not a failure — worth surfacing in any UI that shows the
  count so it is not misread.
- **MAC randomisation is handled, not defeated.** Randomised MACs are per-network stable, so LAN
  correlation holds; the one failure mode (re-randomise on rejoin) is healed by the heartbeat
  re-report. Ethernet MACs are stable outright.
- **Rule 8 / trust boundary.** The agent reports its own MAC to its own appliance — the same
  trust boundary as the hostname and fingerprint it already sends — and `devices.mac` is already
  stored plaintext locally. Nothing new leaves the box. The reported MACs stay appliance-local.
- **Enrollment-contract compatibility.** `lan_macs` is additive and optional; an older agent
  that omits it simply is not correlated by MAC (it falls back to today's behaviour), so the
  change is backward compatible with the deployed fleet.
- **Multi-user-ready.** The correlation is per-device and attributable; nothing here assumes a
  single global identity.

## Alternatives considered

- **Hostname match** (`device_name` vs `devices.hostname`). Available now, but hostnames collide,
  go unset, get user-renamed, and DHCP option-12 ≠ OS hostname. Usable only as a weak tiebreaker,
  never a key.
- **Appliance-issued beacon** the scanner observes in the device's traffic. Heavier, needs
  traffic correlation infrastructure, and buys nothing over a MAC the agent can simply read.
- **Keep `ip_address` correlation.** Rejected — it is the 2/13 status quo, and the tailnet-vs-LAN
  mismatch is structural.
- **A `mac` column on `agent_devices`** instead of a table. Rejected per the approved decision:
  a single column cannot hold multiple NICs cleanly and forces an agent-row rewrite on every
  re-report; the normalised table ages stale MACs out by `last_seen` independently.
