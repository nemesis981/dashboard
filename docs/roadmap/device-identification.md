# Device Identification (passive + on-demand active)

> Roadmap capture — project-sized idea. Records the concept and design intent; does not
> design the implementation. Turns the "❓ unknown device" problem into named, trusted devices
> **without DNS takeover or router config.** Builds on the existing `devices` table +
> `device_scanner.py` nmap discovery + AI Engine.

## Concept

Identify the unknown (❓) devices on the network — phones, speakers, TVs, printers, smart-home
gear — and suggest friendly names, using **passive** listening (always-on, zero risk) plus
**on-demand active** fingerprinting. No DNS changes, no router reconfiguration.

## Passive (always-on, zero risk)

- **mDNS / Zeroconf listener:** devices announce themselves; the listener just observes.
- Identifies: phones, smart speakers, TVs, printers, most smart-home devices.
- **No DNS changes, no router config, no probing** — purely passive.
- Most ❓ devices identified within ~24h of enabling.

## Active (on-demand, user-triggered)

- **"Run identification scan"** button in the dashboard — per-device or fleet-wide.
- Methods: reverse DNS, mDNS query, NetBIOS, UPnP/SSDP, HTTP banner, port fingerprint.
- AI combines the signals → a friendly-name suggestion.
- User **accepts / edits / skips** each suggestion (state-changing → carries an `actor`).

## New-device trigger

- New device appears on the network → auto-run the passive signals.
- Still unidentified after ~1h → queue for an active scan.
- Notify the user: *"3 new unidentified devices need review."*

## Result

- ❓ devices → identified with a **confidence score**.
- User accepts the suggested name → **Trust = ✅** (`devices.trusted`).
- **No DNS takeover. No router configuration changes.**

## Connects to

- **Device scanner** — existing nmap-based discovery (`alert_manager/device_scanner.py`; scan
  range is `LAN_SUBNET`-driven).
- **AI Engine** — signal combination + name suggestion (tiered output).
- **The `devices` table** — this is the spec's "device_map": core (unprefixed) table in
  `alert_manager/database.py` with `mac, ip, friendly_name, device_type, trusted, notes`.
  Friendly names + trust status already live here.
- **Alerts** — new-unidentified-device notification.

## Data model note (ADR 0001)

`devices` is a **core** table (unprefixed) — core owns it; modules read-any/write-own. New
identification fields (e.g. `identification_confidence`, `identification_signals` JSON,
`last_identified`, `identification_source`) attach to `devices` via a guarded
`PRAGMA table_info` + `ALTER TABLE ADD COLUMN` migration alongside the updated `CREATE`
(no table without a CREATE in the repo). Writes route through the Data Manager once built
(ADR 0006); the accept/edit/skip action carries an `actor` (multi-user seam).

## Open questions (not resolved here)

- **Privacy / Rule 8:** mDNS/NetBIOS announcements often contain **personal** hostnames
  ("Alex's iPhone", "Living Room Echo"). These are fine to store/show locally, but MUST be
  sanitized before any community-feed contribution — same chokepoint as the support bundle.
  A device-name is PII.
- **Passive listener as a long-running service:** the mDNS/Zeroconf listener is a new always-on
  component — decide whether it's a core service or a module (`devices`-owning core leans core),
  and how it registers (module contract: start/stop/status).
- **Active-probe network-access policy:** active fingerprinting (SSDP/NetBIOS/port probes) is
  outbound LAN access — per CLAUDE.md it should not add ad-hoc network calls that the future
  firewall engine (ADR 0005) must reconcile; scope how the probe is gated.
- **Confidence → auto-trust boundary:** define what confidence (if any) may auto-name vs always
  require user accept. Default to user-accept (Teaching mode); never auto-trust silently.
