# Roadmap stub — surface new consent/disclosure items in the installer/setup flow

**Status:** PARKED — captured 2026-09-03 (operator-directed), not designed. No urgency today
(zero external installs affected by the motivating case below), but must not be lost before
the agent's next real release, when it starts mattering for real customers.

## What

Every time a new telemetry/collection item is added to the agent's consent gate
(`nemesis_agent/consent.py`, `DISCLOSURE_VERSION`), that disclosure needs to actually reach a
real user as part of the configuration steps they walk through during install/setup — not
just default ON silently for existing installs because bumping the version was deferred, or
because there was no urgent reason to bump it yet.

`consent.py`'s own model (see its module docstring, "Design commitments") already gets half of
this right for **existing** installs: disclosure is versioned, a stale version doesn't disable
collection, it flags that the user should be re-shown the disclosure — and a corrupt/unreadable
record fails closed to OFF, never to ON. What's still open is the **other** half: there is no
current mechanism, in `install.sh` or the agent's own setup/onboarding flow, that actually
walks a NEW user through the current disclosure list at install time, or re-prompts an existing
user when the version bumps. The version-tracking plumbing exists; the UI that uses it to
actually inform someone does not.

## Motivating instance (not the whole scope)

`c332b1a` (2026-09-03) shipped a listening-port exposure collector as a new telemetry item, but
deliberately left it **not wired into the beat** — `security.collect` is consent-gated per item,
and a new item needs a `DISCLOSURE_VERSION` decision the commit explicitly flagged rather than
made. Pushed as-is (operator-confirmed, same session) because zero current external installs
are affected — nothing to silently over-disclose or under-disclose yet. This stub exists so that
when this item (and whatever else accumulates before the next agent release) is finally wired
in, it goes through a real "here's what this collects, here's the toggle" step for the user
installing it — not a version bump nobody sees.

## Why this is a roadmap item, not a PUNCHLIST fix

It's not "add one field to one screen" — it needs a real design pass: where in the
install/setup flow this belongs (first-run only? every version bump? both?), what happens for
an agent that auto-updates past a version bump with nobody watching, and how it interacts with
`installer-unified-v1.0.6.md`'s existing flow stages. Scope grows with however many consent
items accumulate before the next release, not just today's one.

## Connects to

- `nemesis_agent/consent.py` — the gate and version-tracking mechanism this surfaces.
- [installer-unified-v1.0.6.md](installer-unified-v1.0.6.md) — the install/setup flow this
  needs a step inside.
- The listening-port exposure collector (`c332b1a`) — first concrete item waiting on this.

## Open questions (not resolved here)

- First-run-only vs. re-prompt-on-bump vs. both.
- How an already-deployed, auto-updating agent (no human at the console) is supposed to
  surface a version bump at all — this may need its own mechanism distinct from the installer.
- Whether accumulated-but-unwired items (like the port-exposure collector) get batched into one
  disclosure-version bump at release time, or bumped incrementally as each ships.
