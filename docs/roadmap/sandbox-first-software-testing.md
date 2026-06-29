# Sandbox-First Software Testing

> Roadmap capture — project-sized idea. Records the concept and design intent; does not
> design the implementation. Builds on the VM Lab sandbox infrastructure
> ([nemesis-test-lab.md](nemesis-test-lab.md)).

## Concept

Test any new software in the VM sandbox **before** allowing it to run on the real system. The
sandbox isn't just for malware analysis — it's a safe testing environment for **any** new
installation.

## Trigger

New executable detected in Downloads / Desktop.

**User prompt:** "New software detected. Test safely first?"
`[Test in Sandbox]` `[Run directly]` `[Scan only]`

## Sandbox test flow

1. Take a clean VM snapshot (guaranteed clean state).
2. Install / run the software in the VM.
3. Observe: files created, registry, network, processes, system modifications, privilege
   escalation attempts.
4. AI interprets the behavioral report (tiered output).
5. User sees a plain-language summary + recommendation.
6. User approves → install on the real system.
   User rejects → delete, VM restored to the clean snapshot.

## Trust signal

`sandbox_verified_approved` — the **strongest possible** trust state:
"Ran in isolated environment, AI reviewed, user approved." Hash cached **permanently** →
instant allow on all future runs.

## Trust hierarchy

```
sandbox_verified > run_clean_N > run_clean_1 > scan_clean >
unchecked > run_error > suspicious > confirmed_threat
```

## VM snapshot model

- **Before test:** snapshot taken (clean baseline).
- **After test:**
  - **CLEAN** → restore snapshot, allow on the real system.
  - **THREAT** → restore snapshot, quarantine on the real system.
  - **UNCERTAIN** → show the full report, user decides.
- The VM always returns to a clean state for the next test.

## AI interpretation (tiered)

- **Beginner:** plain language — "this software does X, we recommend Y".
- **Pro:** full behavioral log — files, registry, network, processes.

## Cracked / unknown software

The sandbox reveals exactly what it does **without judgment**. The user sees the behavioral
report and makes an informed decision. `[Reject]` is always available;
`[I understand — install anyway]` for adults.

## Sandbox certificate

`NMS-SAND-{reporter_id}-{date}`
Contains: software hash, behavioral summary, AI verdict, user decision, approval timestamp.
Stored in `scan_cache` as `sandbox_verified`. (`reporter_id` per
[community-reporter-identity.md](community-reporter-identity.md).)

## Connects to

- **VM Lab** ([nemesis-test-lab.md](nemesis-test-lab.md)) — the sandbox infrastructure.
- **AI Engine** — behavioral interpretation (tiered output).
- **Scan cache** — the `sandbox_verified` trust state.
- **Teaching / Automated Mode** — approval gates.
- **Community feed** ([open-source-threat-feeds.md](open-source-threat-feeds.md)) — sandbox
  behavioral logs = threat intelligence.
- **Gaming** — sandbox-verify new games before first play.
