# Roadmap stub — Nemesis overhead meter (hardware monitor)

**Status:** parked (low priority / cosmetic, but high TRUST value — what + why; do NOT
build yet).

## What
A "Nemesis overhead" section on the hardware monitor that shows, via `psutil`, the
resource footprint of Nemesis itself:
- **Per-process CPU + memory** for each Nemesis service (dashboard, alert-watcher,
  hw-monitor, device-scanner, watchdog, the standalone watchers — canary,
  diagnostics-watcher — etc.).
- **Total** Nemesis CPU/mem (sum across all services).
- **Memory-trend sparkline** per service / total, so a slow climb (leak) is visible at a
  glance rather than only after OOM.

## Why
Two distinct payoffs:
1. **Leak detection (operational).** A per-service memory trend turns a silent leak into
   an observable one — same "make invisible variables visible" discipline as
   [[system-changes-badge]] and [[diagnostics-anthropic-status-banner]].
2. **Transparency / trust (the bigger win).** When the machine slows down, the user can
   immediately confirm **"Nemesis is using X% — it's not us"** instead of Nemesis being a
   black-box suspect. On **shared-machine deployments** (Nemesis running alongside the
   user's real work) this directly answers the "is this thing hogging my computer?"
   question that otherwise erodes trust. Low cosmetic priority, high trust value.

## Reasoning / shape
- Lives in the **hardware monitor** (`hw_monitor.py` / its dashboard card) as a dedicated
  "Nemesis overhead" section; sample with `psutil` (per-pid CPU%, RSS).
- **Service set is derived, not hardcoded** — reuse the existing service registry
  (e.g. the `HEALTH_SERVICES` / install `svc_names` list) so new modules' services appear
  automatically and nothing is missed.
- **Trend persistence:** memory samples need a small rolling history for the sparkline.
  Decide between an in-memory ring buffer (cheap, lost on restart) vs. a prefixed table in
  shared `alerts.db` (durable, survives restart — better for catching slow leaks across
  days). Lean durable + capped-retention, mirroring the diagnostics sampler pattern.
- **Diagnostics-watcher hook (optional escalation):** feed total overhead into the
  is-it-me-or-them verdict in [[modules/diagnostics]] — flag **DEGRADED** when Nemesis's
  own footprint is excessive (i.e. *Nemesis itself* is the local cause). Keep the
  threshold conservative and configurable; this is the "the slowdown really IS us" branch
  of the classifier.
- Multi-user-ready: overhead is a global system property, but if surfaced per-actor later
  the sampler should not assume a single global identity. Cheap to leave the seam.
- Flesh out exact sampling cadence, sparkline window, retention cap, and the DEGRADED
  threshold when this graduates to a spec.
