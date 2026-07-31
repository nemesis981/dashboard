# Appliance hardware notes

Running capture file for hardware-baseline observations that do not yet belong in an ADR.
Created 2026-07-31 (Window 1). Companion to `docs/architecture/0014-deployment-appliance-model.md`.

**Status: no proposed hardware spec exists anywhere in the repo.** That remains an open item
against ADR 0014. Nothing here invents one — this file records constraints and dependencies as
they surface, so that when a baseline is written it is written from evidence rather than guessed.

---

## Cross-references

- **RAM baseline ↔ future memory-injection / RAM-scan feature (IDEA ONLY, not scoped).**
  The appliance RAM baseline being established here will also govern a possible future
  memory-injection / RAM-scanning capability: installed RAM size directly dictates that
  feature's scan reliability and timing, so the baseline chosen for ordinary operation
  silently sets the ceiling for what that feature could ever do. Worth deciding the baseline
  with that in mind rather than discovering the constraint afterwards. Captured per Rule 7 —
  not a commitment to build it.
