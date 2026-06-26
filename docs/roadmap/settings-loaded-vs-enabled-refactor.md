# Roadmap stub — "loaded" vs "enabled" settings refactor

**Status:** parked (post-Pass-0).

## What
Split two concepts that are currently conflated in the module/settings model:
- **`required` / loaded** — the code cannot be unloaded (load-order guaranteed; the module
  is always present for other code to call).
- **features-enabled** — a user-facing toggle for whether the feature *does anything*.

Critically: **"off" must mean off** — no external API calls and **no cost**. For
`ai_engine` specifically, a disabled state must make zero Anthropic API calls.

## Why
Today a "required" module can't be disabled, which entangles "always loaded" with "always
active." That risks silent cost and data egress when a user believes a feature is off.
The two biggest concrete risks (from `docs/audits/settings-ui-reality-audit.md`):
- **#1 AI cost** — `ai_engine` making paid calls when the user thinks AI is off.
- **#3 AbuseIPDB data-egress** — sending data to an external service without a clear,
  honored off switch.

## Reasoning / shape
- Introduce an explicit enabled-state separate from loaded/required.
- Fold in the `settings-ui-reality-audit` findings (make the UI reflect *real* state).
- **Reference pattern:** the incident badge derives its state from real underlying data,
  not a separate manual flag — settings should likewise reflect actual runtime behavior
  ("off" provably means no calls/no cost), not just a stored preference.
