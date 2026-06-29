# Hardware Stable Identifiers

> Roadmap capture — project-sized idea. Records the concept and design intent; does not design
> the implementation. Extends [device-identification.md](device-identification.md) (the broader
> ID system) and feeds [ADR 0008](../architecture/0008-impossible-travel-detection.md).

## Concept

Hardware-level IDs that survive MAC randomization, IP changes, and OS reinstalls. **Hash before
storing** (privacy) — store the hash and the *types* of signals used, never raw hardware data.

## Per platform

| Platform | Signals |
|---|---|
| **Windows** | MachineGuid (registry) + battery DeviceID + motherboard serial + CPU ProcessorId |
| **Linux**   | `/etc/machine-id` + `/sys/class/power_supply/BAT*/serial_number` + dmidecode system UUID |
| **Mac**     | Hardware UUID + battery BatterySerialNumber + system serial number (`system_profiler`) |
| **Android** | `ANDROID_ID` + `Build.SERIAL` (with permission) |
| **iOS**     | Stable Bonjour service-name component |

## Battery serial (standout identifier)

- Present on all laptops and phones.
- Survives OS reinstall (hardware-level).
- Rarely replaced (unlike drives).
- Unique per physical device.
- Available **without root** on Linux (`/sys/class/power_supply/`).
- Available via **WMI** on Windows (no admin needed).

## Composite stable ID

- Combine all available signals.
- **Sort before combining** (order-independent).
- `SHA256` hash → 16-char `stable_id`.
- Store: `stable_id` + `signals_used` (types, not raw values).
- **Never store raw hardware data.**

## Privacy

- Hashed → can't reverse to hardware details.
- `signals_used` = types only (`"machine_id, battery_serial"`), **not** raw values (`"ABC123XYZ"`).
- Safe to store locally, safe in support bundles.

## Agent enrollment

- `stable_device_id` included in the enrollment payload.
- Server stores it alongside `public_key`.
- Enables: the same device recognized across re-enrollments
  (OS reinstall → same `stable_id` → "welcome back").

## Phone without agent

- **iOS:** stable Bonjour component + DHCP hostname.
- **Android:** `ANDROID_ID` via agent (requires install).
- **Without agent:** DHCP + mDNS = best available (no hardware access).
- → Agent install strongly recommended for phones.

## Forensic value

- **Support bundle:** `stable_id` proves device identity.
- **Impossible travel:** same `stable_id` in two places at once = impossible.
- **Re-enrollment:** "same hardware, new OS" recognized automatically.
- **Vendor debugging:** consistent device identity across tickets.

## Connects to

- [device-identification.md](device-identification.md) — the broader ID system; also where **MAC
  randomization handling** lives (`stable_id` survives MAC changes).
- Agent enrollment (`enrollment.py` / `_create_enrollment`) — `stable_id` rides in the payload,
  stored alongside `public_key`.
- [ADR 0008 — impossible travel](../architecture/0008-impossible-travel-detection.md) —
  `stable_id` is the **strongest** device signal.
- [support-bundle.md](support-bundle.md) — device-identity proof in the bundle.
- [community-reporter-identity.md](community-reporter-identity.md) — same hash-before-store principle.
