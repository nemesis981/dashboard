# Roadmap — Removable media / USB device control (V2 build target)

**Status:** parked (capture-only — what + why; do NOT build yet). New capture, 2026-08-23 —
nothing existed anywhere in the codebase or roadmap for this before now (verified: no code,
no ADR, no prior roadmap doc). Not yet build-spec'd; capturing intent and scope only.

**Rationale:** removable-storage control (blocking/alerting on unknown USB storage devices)
is a standard enterprise endpoint-suite pillar and a classic SMB attack vector — a malicious
or simply unauthorized USB drive is one of the oldest, still-common ways malware enters a
network or data leaves it. Nothing currently built addresses the *device* itself; the only
existing related mention (`malware-detection-pipeline.md`'s `usb_inserted` scan trigger,
also unbuilt) addresses *file content on the device*, a different and narrower problem — see
Relationship to the existing scan-on-insert trigger, below.

---

## Scope — device-level control, not content scanning

This capability is about the **storage device itself**, independent of what's on it:

1. **Detect** a removable storage device being connected (USB mass storage, and — worth
   scoping explicitly rather than assuming — whatever the platform-native enumeration
   mechanism is: Linux udev, Windows WM_DEVICECHANGE/WMI, per-platform per the agent's
   existing Linux/Windows split).
2. **Alert** — notify the operator that a removable storage device was connected to a
   specific machine, when, and (if determinable) some identifying detail (vendor/product ID,
   serial if available) — not file contents.
3. **Optionally block** — a policy mode where only explicitly-allowed devices (by serial or
   vendor/product ID) may mount at all; everything else is refused or requires approval.
   This is the harder, more invasive tier — likely a v2-later or v3 capability layered on
   top of the simpler detect+alert tier, not required for a first ship.
4. **Policy scope** — almost certainly per-device (not global), consistent with the rest of
   the product's per-device settings model; a home user's own machine probably wants
   detect+alert only, while an SMB fleet machine might want block-by-default.

## What this is not (scope boundary)

- **Not file scanning.** Whether a permitted USB drive's *contents* get scanned is the
  existing `usb_inserted` trigger's job (`malware-detection-pipeline.md`), not this
  capability's. A device could be allowed to mount by this feature and still have its files
  scanned by that one — they compose, they don't overlap.
- **Not a general peripheral-control suite.** Scoped to *storage* devices specifically
  (the actual attack-vector and data-exfiltration surface). Keyboards/mice/printers/etc. are
  explicitly out of scope unless a real reason to extend emerges later.
- **Not (initially) a DLP content-inspection feature.** "What files got copied to the
  device" is a meaningfully bigger, more invasive capability (requires filesystem-level
  interception, not just device enumeration) — worth naming as a possible v3 extension, not
  assumed as part of this scope.

## Relationship to the existing scan-on-insert trigger (`malware-detection-pipeline.md:180`)

Two different, complementary capabilities that happen to both react to "something got
plugged in":

| | This doc (device control) | `usb_inserted` (malware-detection-pipeline.md) |
|---|---|---|
| **Question asked** | Should this *device* be trusted at all? | Is *this file* on the device malicious? |
| **Acts on** | The device (vendor/product ID, serial) | File contents, after mount |
| **When it runs** | Before/at mount (gate) | After mount (scan) |
| **Blocks** | The device from mounting (if policy says so) | The file from being opened, if scanned as bad |

`malware-detection-pipeline.md`'s entry is left as-is — it's the correct, narrower scope for
what it already describes (scan file contents once a device is mounted). This doc does not
change that entry; it captures the separate, upstream "should the device even be allowed to
mount" question the pipeline doc never addressed. If both ship, this capability's gate would
naturally run first (device-level allow/deny), with the existing scan-on-insert trigger
firing on whatever's permitted through.

## Where this likely lives

Agent-side (device enumeration is inherently per-machine and per-platform — same Linux/Windows
split pattern as the rest of the agent, e.g. `keyprotect/`'s `linux_tpm.py`/`windows_cng_tpm.py`
backend-selection shape). Policy/allowlist storage on the appliance side, consistent with
other per-device settings. A new `agent_*`- or `usb_*`-prefixed table per ADR 0001's
module-owns-tables-by-prefix convention, whichever module ends up owning this.

## Sequencing

No hard dependency on other unbuilt roadmap items. Standalone. The detect+alert tier is
almost certainly the right v1 scope (lower effort, immediately useful, no risk of a false
block locking an operator out of their own legitimate USB drive); the allowlist/block tier
is a natural v2-later extension once detect+alert has real usage data to design the
allowlist UX against.

## Cross-references

- `docs/roadmap/malware-detection-pipeline.md` — existing `usb_inserted` scan-content
  trigger (unbuilt); see Relationship section above for exactly how the two differ.
- `docs/roadmap/vulnerability-patch-management.md` — a separate V2 capability captured the
  same day (2026-08-23); no shared scope, listed together only because both were raised in
  the same "what does 'complete enterprise protection' still not cover" review.
