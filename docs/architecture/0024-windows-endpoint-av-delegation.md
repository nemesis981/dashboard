# ADR 0024 — Windows endpoint anti-virus is delegated to Microsoft Defender

**Status:** Accepted (2026-08-22). Resolves the unstated gap flagged by the protection-schema
audit (R5): the appliance runs ClamAV (Linux), Windows endpoints had no on-endpoint AV file-scan
arm, and nothing recorded whether that was a decision or an omission.

## Context
Nemesis endpoints are cross-platform. The Linux arms scan files with ClamAV; Windows endpoints
get the behavioral arm (Sysmon) and, as of 2026-08-22, memory-injection detection — but no
on-endpoint AV file scan. The audit asked: build a Windows file-scan arm, or delegate — and
either way, write it down.

Two build options were weighed:
1. **Ship ClamAV-on-Windows** — bundle a second AV engine, its signature DB, and an update path,
   duplicating a capability every modern Windows install already has, with a much smaller
   signature corpus than the incumbent.
2. **Run our own scanner / re-use the sandbox** — the detonation sandbox (Set 2) analyses
   *submitted* samples; it is not a real-time on-access file scanner and was never meant to be.

## Decision
**Delegate on-endpoint anti-virus file scanning on Windows to Microsoft Defender.** The Nemesis
agent does NOT run a competing on-access scanner on Windows. Instead it OBSERVES and REPORTS
Defender's protection state as a first-class coverage signal:
- is Defender present and its service running;
- is real-time protection enabled (or disabled/tampered);
- recent Defender detections (via the Defender event log / `Get-MpThreatDetection`);
- signature freshness.

This mirrors the design already ratified for the behavioral arm: on Windows, use the native
telemetry/engine (Sysmon for behavior, Defender for AV) rather than reimplementing it, and make
Nemesis's job the honest reporting and correlation layer on top.

## Why this is the right call, not a cop-out
- **Defender is stronger here than what we could ship.** It is present by default, continuously
  updated, and has a vastly larger signature base than a bundled ClamAV. Duplicating it worse is
  the "genuine gaps not chasing" category from the enterprise gap audit.
- **Coverage visibility is the real product value.** An SMB user's actual risk is not "no AV
  engine" — Windows has one — it is "AV silently turned off / out of date / tampered and nobody
  noticed." Reporting Defender's health closes THAT gap, which is the one Nemesis is positioned to
  close.
- **It stays honest under the three-state discipline.** "Defender: real-time protection OFF" or
  "…could not be determined" are honest coverage states, exactly like the memcap/attestation
  tiers. Delegation does not mean blindness.

## Consequences
- Coverage parity is stated, not silent: Linux = ClamAV on-access; Windows = Defender observed.
  Neither endpoint is "AV-blind"; they use different engines and Nemesis reports both.
- A follow-on (not required by this ADR): an on-DEMAND scan trigger via `MpCmdRun.exe -Scan` when
  a behavioral/memory signal warrants a targeted file scan — an enhancement, not a gap.
- The agent needs a Defender-state probe (a small collector, same shape as the Sysmon collector).
  Tracked as build work; this ADR settles the DIRECTION so it is no longer an unstated absence.

## Rule 10 note
This is architecture/direction (public by default). No novel mechanism or unresolved-weakness
disclosure is introduced — it delegates to a documented OS capability and reports its state.
