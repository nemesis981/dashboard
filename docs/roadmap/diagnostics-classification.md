# Roadmap stub — diagnostics: classification framework (two lenses)

**Status:** parked (organizing principle; do NOT build yet). A classification rule for sorting
every existing and future diagnostic tool into "continuous logger outside Flask" vs "fine in
the UI." Drives the [standalone runner](diagnostics-standalone-runner.md) and the
[connectivity watcher](diagnostics-connectivity-watcher-tool.md) decisions.

## What
Two lenses for classifying diagnostic tools:

### Lens A — Condition type
- **Transient / intermittent** — comes and goes; only catchable by **continuous logging**
  (DNS-under-VPN, link quality, intermittent service restarts). → **MUST be continuous.**
- **Persistent / stable** — either broken or not, consistently. → **on-demand is fine.**
- **Threshold / trend** — fine now but trending toward a problem (disk, memory, DB size,
  latency). → **continuous logging needed to see the trend.**

### Lens B — Dashboard dependency
- **Must be dashboard-INDEPENDENT** — detects conditions that could **themselves cause
  dashboard failure** (DB health, service health, memory/disk pressure, DNS/connectivity).
  → must run as **independent processes writing to flat files.**
- **Can be dashboard-DEPENDENT** — stable conditions that can't cause dashboard failure.
  → fine to stay in the UI.

## Classification rule
> **Anything Transient OR Dashboard-independent MUST be a continuous logger running outside
> Flask.** On-demand dashboard tools are unavailable in exactly the failure scenarios that
> matter most.

## Why
The recurring lesson this weekend: the failures you most need to see (intermittent DNS, a
crashing service, a filling disk, the dashboard's own DB going bad) are precisely the ones an
in-Flask, on-demand tool can't catch — either because they're gone by the time you look, or
because the tool itself is down. Classifying up front forces the right home for each tool
(continuous flat-file logger vs UI panel) instead of discovering it the hard way during an
outage.

## Reasoning / shape
- Apply the rule as a **design gate** for new diagnostics and as an **audit** of existing ones
  (e.g. the watcher is Transient + Dashboard-independent → correctly a continuous logger).
- Continuous loggers feed the [standalone runner](diagnostics-standalone-runner.md) and the
  self-diagnostics view; their flat files are readable even when Flask/DB are down.
- Capture the framework now; apply it when each tool is built/migrated.
