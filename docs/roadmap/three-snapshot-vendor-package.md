# Three-Snapshot Vendor Package

> Roadmap capture — project-sized idea. Records the concept and design intent; does not
> design the implementation. Builds on already-captured infrastructure: the registry
> backup/diff engine ([sandbox-to-system-migration.md](sandbox-to-system-migration.md)), the
> clone sandbox's continuous capture ([malware-detection-pipeline.md](malware-detection-pipeline.md)
> §6), the [support bundle](support-bundle.md) (delivery) and the
> [Verified Partner Program](verified-partner-program.md) (receiving end).

## Concept

When vendor software causes a problem, hand the vendor **proof**: three system snapshots that
together show the clean baseline, the moment of failure, and exactly what changed between them
— plus everything needed to reproduce it. The vendor can no longer say "works on our end."

## Snapshot 1 — Pre-install (clean baseline)

System state BEFORE the vendor software was installed.

- **Source:** the registry backup taken pre-migration — *already designed*
  ([sandbox-to-system-migration.md](sandbox-to-system-migration.md) §Registry Backup).
- "What the user's system looked like before you."

## Snapshot 2 — Issue state (auto-captured)

System state AT THE MOMENT the issue is detected.

- **Trigger:** canary trip, behavioral flag, crash, user report, unexpected registry
  modification, service failure.
- **Captures:** registry state, running processes, services, network connections, recent file
  changes, memory state, active application, error log, canary file state.
- Captured **automatically** — no user action required.

## Snapshot 3 — Delta (the smoking gun)

DIFF between Snapshot 1 and Snapshot 2.

- Files added / modified / deleted (with attribution).
- Registry keys added / modified / deleted (with attribution).
- Services added / changed.
- Network connections established.
- **AI diagnosis:** "SharedLib.dll modified during install — version conflict is the likely
  cause."

(Reuses the delta engine from
[sandbox-to-system-migration.md](sandbox-to-system-migration.md) §Registry Diff Engine + the
file manifest from [malware-detection-pipeline.md](malware-detection-pipeline.md) §8.)

## Vendor package contents

```
snapshot-1-pre-install.zip    (clean baseline)
snapshot-2-issue-state.zip    (moment of failure)
snapshot-3-delta.zip          (exactly what changed + AI diagnosis)
nemesis-rebuild-linux.sh      (Linux VM rebuild script)
nemesis-rebuild-windows.ps1   (Windows VM rebuild script)
Dockerfile                    (fastest reproduction)
reproduction-steps.txt        (from behavioral log)
```

## Automatic capture

- The sandbox already monitors everything during the install test.
- Snapshots exist because the sandbox captures continuously.
- Export just **packages what was already captured** — no extra user action or setup.

## Update regression detection

- **Snapshot 1:** system with v1.0 (working).
- **Snapshot 2:** system with v2.0 (broken).
- **Delta:** exactly what the UPDATE changed.
- "Your v2.0 modified SharedLib.dll — v1.0 did not."
- Proves a **release regression**, not a user-environment issue. The vendor cannot argue
  "works on our end."

## Sanitization (always)

- All three snapshots sanitized before export.
- Username, hostname, IP, personal data stripped.
- Software config and version info preserved.
- Same Rule-8 pipeline as the [support bundle](support-bundle.md) — the single shared
  sanitization chokepoint, not re-implemented here.

## Connects to

- **Registry backup** — Snapshot 1 source.
- **Clone sandbox** — continuous capture during install.
- **Issue-state capture** — the automatic Snapshot 2 trigger.
- **Support bundle** — the delivery mechanism.
- **Verified Partner Program** — the receiving end.
- **Delta engine** — registry diff + file manifest diff.

## Open questions (not resolved here)

- **Memory-state sanitization is hard.** Snapshot 2 captures "memory state" — a memory/process
  dump can contain credentials, tokens, and personal data that a config-file scrub won't catch.
  Stripping a username from a `.reg` export is easy; sanitizing a memory image is a different,
  much harder problem. Either narrow what "memory state" means (e.g. process list + module
  list, not a full dump) or design a dedicated scrubber **before** any memory artifact is ever
  exported to a commercial recipient. This is the highest-risk Rule-8 surface in the package.
- **Rebuild-script / Dockerfile generation is undesigned.** How `nemesis-rebuild-*.{sh,ps1}`
  and the `Dockerfile` are generated from the snapshots (and how they stay sanitized) needs its
  own design — they encode system profile and installed-software state.
- **Snapshot retention/size.** Three zipped system snapshots per incident is real storage;
  needs a retention policy (likely tied to the SQLite-longevity note in ADR 0006).
