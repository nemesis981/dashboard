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

## MAC Randomization + IP Change Handling

**Problem:** modern phones (iOS 14+, Android 10+) randomize MAC per network and get new IPs on
reconnect. Naive MAC-based tracking = endless phantom devices on the network.

### Stable signals (survive MAC/IP changes)
- **DHCP hostname** (option 12) — most reliable for phones.
- **mDNS/Bonjour name** — stable per device.
- **Agent keypair** — cryptographic, perfect confidence (1.0).
- **Tailscale node ID** — permanent per device.
- **NetBIOS name** — stable for Windows devices.

### Correlation engine
New MAC/IP appears → check stable signals → match against known devices → same device?
- Confidence: `keypair=1.0`, `dhcp=0.95`, `mdns=0.90`, `timing_correlation=0.70`.
- Threshold ≥ 0.85 → **suggest merge** to user.
- Below threshold → treat as genuinely new device.
- **NEVER auto-merge — always user confirmation.**

### Agent solves phones completely
Agent installed → keypair = permanent cryptographic identity. MAC randomizes, IP changes →
irrelevant. Server recognizes the keypair → same device, confidence 1.0. The enrollment keypair
IS the phone's identity.

### Without agent (unmanaged phones)
DHCP hostname + mDNS name → 85-95% confidence. Timing correlation (departed + reappeared within
60s) → 70%. Suggest merge, never auto-merge. User confirms → identity locked, trust established.

### Phantom-device cleanup
Once the correlation engine is active: scan the historical list for the same stable identifiers
and present merge candidates — *"These 3 entries are probably Alex&#39;s iPhone — merge?"*
`[Yes, merge]` `[No, keep separate]`. Cleans up phantom entries from MAC-rotation history.

### DB additions (guarded migration, ADR 0001 — on the core `devices` table)
```
known_macs TEXT          -- JSON array of historical MACs
known_ips TEXT           -- JSON array of historical IPs
dhcp_hostname TEXT       -- stable DHCP option 12
mdns_name TEXT           -- stable mDNS hostname
stable_id TEXT           -- hardware-derived stable identifier
identity_confidence REAL -- 0.0-1.0
identity_signals TEXT    -- JSON: signals that identified it
```

### ADR 0008 connection (impossible travel)
Impossible-travel detection must distinguish:
- **Same `stable_id`, different MAC** = normal phone behavior (MAC randomization — NOT suspicious).
- **Same `stable_id`, two locations simultaneously** = impossible (strongest travel signal possible).

The correlation engine feeds [ADR 0008](../architecture/0008-impossible-travel-detection.md)
device identity so it doesn't false-positive on MAC changes.

## Hardware Stable Identifiers

**Concept:** hardware-level IDs that survive MAC randomization, IP changes, and OS reinstalls
entirely. **Hash before storing.**

### Per platform
- **Windows:** `MachineGuid` (`HKLM\SOFTWARE\Microsoft\Cryptography\`, generated at OS install);
  Battery DeviceID (`wmic path Win32_Battery get DeviceID`); motherboard serial
  (`wmic baseboard get SerialNumber`); CPU ID (`wmic cpu get ProcessorId`).
- **Linux:** `/etc/machine-id` (128-bit UUID, systemd); battery serial
  (`/sys/class/power_supply/BAT*/serial_number` — world-readable, no root); battery manufacturer;
  dmidecode system UUID (requires root).
- **Mac:** Hardware UUID (`system_profiler SPHardwareDataType`); battery
  (`ioreg -l | grep BatterySerialNumber`); system serial.
- **Android (with agent):** `Settings.Secure.ANDROID_ID`; `Build.SERIAL` (requires permission).
- **iOS:** stable Bonjour service-name component (no direct hardware access without MDM).

### Battery serial — standout identifier
Present on all laptops/phones; survives OS reinstall (hardware-level); rarely replaced (unlike
drives); unique per physical device; available **without root** on Linux
(`/sys/class/power_supply/`), via WMI on Windows (no admin), via `ioreg` on MacBooks (no admin).
The most stable affordable identifier for mobile devices.

### Composite stable ID
Combine all available signals → **sort before combining** (order-independent) →
`SHA256(sorted_signals)[:16]` → `stable_id`. Store `stable_id` + `signals_used` (TYPES only, not
raw values). **Never store raw hardware serial numbers.**

### Privacy model
- Hash → cannot reverse to hardware details.
- `signals_used = ["machine_id", "battery_serial"]` (types only).
- Raw values (e.g. `ABC123XYZ`) never stored anywhere.
- Safe to store locally, safe in support bundles.
- Same hashing principle as [community reporter identity](community-reporter-identity.md).

### Agent enrollment integration
`stable_id` included in the enrollment payload:
```json
{ "stable_id": "a3f7c9d2e1b4f8a0",
  "signals_used": ["machine_id", "battery_serial"],
  "confidence": 0.75 }
```
Server stores it alongside `public_key` in `agent_devices`. Enables: same device recognized
across re-enrollments — *"OS reinstall detected — same hardware, new enrollment"* /
*"Welcome back — your previous enrollment history restored."*

### Forensic value
- **Support bundle:** `stable_id` proves device identity to the vendor.
- **Impossible travel:** same `stable_id` two places = physically impossible.
- **Re-enrollment:** same hardware after OS reinstall recognized.
- **Vendor debugging:** consistent identity across support tickets.

### Connects to
- **Agent enrollment** — `stable_id` in payload (add to the `agent_devices` schema).
- **§MAC Randomization** above — the correlation engine.
- **[ADR 0008](../architecture/0008-impossible-travel-detection.md)** — `stable_id` = strongest signal.
- **[support-bundle.md](support-bundle.md)** — device-identity proof layer.
- **[community-reporter-identity.md](community-reporter-identity.md)** — same hashing principle.
- **[three-snapshot-vendor-package.md](three-snapshot-vendor-package.md)** — `stable_id` in the package.
