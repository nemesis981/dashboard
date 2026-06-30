# Hardware Stable Identifiers — build-ready design of record

- **Status:** **BUILD-NOW (Windows + Linux, full quality, both tested).** Mac = interface +
  type-vocabulary only (drop-in later, no collector now). Android/iOS = still parked/future.
- **Date promoted:** 2026-06-30 (from parked). Dependency of
  [installer-unified-v1.0.6](installer-unified-v1.0.6.md); powers the TOFU lock + review-card
  "same device?" check in [ADR 0011](../architecture/0011-enrollment-security-model.md), and
  feeds [ADR 0008 impossible-travel](../architecture/0008-impossible-travel-detection.md) post-trip.
- **Build discipline:** this is a dependency, so build it EARLY in the installer sequence — but
  it is small/bounded and **must not crowd out the installer pieces it serves.** The trip
  deliverable is the **Windows install working end-to-end.**
- **Rule 8:** OS-standard paths/registry keys only; no infra values; raw hardware data is
  **never stored** (hash-before-store).

> This doc DESIGNS the implementation (data model, signal sets, interface, schema, payload).
> The actual code lands via a build prompt referencing this doc — but the design below is
> **FINAL and must not need reshaping later.**

## Concept

Hardware-level identity that survives MAC randomization, IP changes, and OS reinstalls.
A **composite of multiple signals** (not one magic ID), **hashed before storage** — store the
composite hash, the per-signal hashes, and the *types* of signals used; **never raw hardware
data**.

## Signal sets (build-now: Windows + Linux)

No single signal is required — **every signal is optional**; the composite degrades
gracefully and reports confidence. This is mandatory because the build-now targets include a
**VM (trip box, no battery)** and a **server (the Nemesis box, no battery, possibly empty
board serial)**. **MAC address, hostname, and volume serial are excluded** (randomized /
mutable / format-volatile).

| Canonical type | Windows source (no admin where possible) | Linux source |
|---|---|---|
| `system_uuid` | `Win32_ComputerSystemProduct.UUID` (SMBIOS) | `/sys/class/dmi/id/product_uuid` (root) |
| `machine_id` | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` | `/etc/machine-id` (→ `/var/lib/dbus/machine-id`) |
| `board_serial` | `Win32_BaseBoard.SerialNumber` | `/sys/class/dmi/id/board_serial` (root) |
| `disk_serial` | system-disk `MSFT_PhysicalDisk.SerialNumber` | `/dev/disk/by-id` of the root disk |
| `cpu_id` | `Win32_Processor.ProcessorId` | `/proc/cpuinfo` (model+features fingerprint) |
| `battery_serial` *(opt)* | `Win32_Battery` (WMI) | `/sys/class/power_supply/BAT*/serial_number` |
| `tpm_ek` *(opt, strong)* | TPM EK public (when present) | TPM EK public (when present) |

Notes the build must honor: SMBIOS `product_uuid`/`board_serial` are **root-gated on Linux**
and may be **empty/garbage on VMs/OEM** (`"To be filled by O.E.M."`, all-zero UUID,
`"Default string"`, `"None"`) — **normalize + reject junk** before use. `machine_id` and
`disk_serial` are the reliable no-privilege anchors on both platforms.

## Composite algorithm (LOCKED)

1. Collect available signals as `(type, raw_value)`.
2. **Normalize** each: trim, upper-case, strip known-junk sentinels (above) → drop if empty/junk.
3. **Per-signal hash:** `signal_hash[type] = SHA256(type + ":" + normalized_value)` (hex).
   (Per-signal hashes enable a **quorum match** without ever storing raw values.)
4. **Composite:** take the valid types, **sort by type**, concatenate `type:normalized_value`
   pairs in sorted order, `SHA256` → **`stable_id`** (full hex; 16-char short form for display).
5. `signals_used` = sorted list of contributing types.
6. **`confidence`**: `high` if ≥2 of {`system_uuid`,`machine_id`,`board_serial`,`disk_serial`}
   present; `medium` if exactly 1 strong; `low` if only `cpu_id`/weak signals.
7. `schema_version = 1`.

## Data model + storage (LOCKED — must not reshape)

Owned by the core/agent table `agent_devices` (write-own; the CLAUDE.md actor seam is added
here, not twice). Schema change uses the ADR-0001 guarded `PRAGMA table_info` +
`ALTER TABLE ADD COLUMN` migration alongside the canonical `CREATE`:

| Column | Type | Meaning |
|---|---|---|
| `hw_stable_id` | TEXT | composite hash (full hex) |
| `hw_signals_used` | TEXT (JSON array) | contributing **types only** |
| `hw_signal_hashes` | TEXT (JSON object) | `{type: signal_hash}` — for quorum match |
| `hw_fp_confidence` | TEXT | `high` / `medium` / `low` |
| `hw_fp_schema_version` | INTEGER | `1` |
| `hw_fp_locked_at` | REAL | TOFU lock timestamp (set on first enrollment) |

**Raw hardware values are never stored** — only hashes + type names.

## Enrollment-payload slot (LOCKED)

Rides the existing `enroll()` payload (`enrollment.py`), stored by `_create_enrollment`
(`hw_monitor.py` ~1853) — the auth-aware `/hw_data` + `firewall.py` seam folds in here, not twice:

```
"hardware_fingerprint": {
  "schema_version": 1,
  "stable_id": "<sha256 hex>",
  "signals_used": ["machine_id", "system_uuid", "disk_serial"],
  "signal_hashes": {"machine_id": "<h>", "system_uuid": "<h>", "disk_serial": "<h>"},
  "confidence": "high"
}
```

## Platform interface (clean — Mac is a drop-in)

- **Only platform-specific code:** `collect_signals() -> dict[type, raw_value]` per platform,
  mapping native sources to the **closed, versioned canonical type vocabulary** above.
- **Everything downstream is shared + platform-agnostic:** normalize → per-signal hash →
  composite → confidence → payload assembly → storage. Identical for all platforms.
- **Mac later** = add `collect_signals_macos()` returning `{type: value}` against the same
  vocabulary (`system_uuid` = Hardware UUID, `board_serial` = system serial, `battery_serial`
  = BatterySerialNumber via `system_profiler`). **No downstream change.** Do **NOT** write the
  Mac collector now (untestable on this box) — the interface + vocabulary make it a pure add.

## TOFU lock + review-card "same device?" (resolves ADR 0011 Q1)

- **First enrollment** for a device: persist `hw_stable_id` + `hw_signal_hashes` +
  `hw_fp_locked_at` = the **locked fingerprint** (trust-on-first-use).
- **Subsequent presentation** (re-enroll / same installer token): compare presented
  `stable_id` to the locked one →
  - exact match → **"same device: YES"**;
  - partial (quorum on `signal_hashes`, e.g. ≥⌈N/2⌉ types match) → **"partial k/n — hardware
    changed or different machine"**;
  - no overlap → **"NO — different machine (stolen/copied-media signature)"** → flag prominently.
- This IS the ADR 0011 review-card "hardware-ID match" row and the binding mechanism for a
  clean remote box (no pre-known fingerprint → lock on first use).

## Privacy / forensic value (unchanged principle)

Hashed → non-reversible; `signals_used` = types only; safe locally and in support bundles.
Forensic uses: re-enrollment "welcome back" (same hardware, new OS), support-bundle device
proof, and (post-trip) impossible-travel — `stable_id` is the strongest device signal (ADR 0008).

## Scope boundary

- **Build-now:** Windows + Linux collectors (full, tested) + the shared core + schema + payload.
- **Deferred (interface only):** Mac collector — vocabulary + interface defined, code later.
- **Still parked:** Android/iOS, agentless-phone identity (see
  [device-identification.md](device-identification.md)).

## Connects to

- [installer-unified-v1.0.6](installer-unified-v1.0.6.md) — the dependent build.
- [ADR 0011 — enrollment security](../architecture/0011-enrollment-security-model.md) — TOFU + review card.
- [ADR 0008 — impossible travel](../architecture/0008-impossible-travel-detection.md) — post-trip consumer.
- [device-identification.md](device-identification.md) — broader ID system + MAC-randomization handling.
- [support-bundle.md](support-bundle.md) / [community-reporter-identity.md](community-reporter-identity.md) — same hash-before-store principle.
