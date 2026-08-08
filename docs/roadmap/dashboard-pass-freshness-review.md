# Roadmap stub — dashboard-pass docs, freshness review (QUEUED, read-only)

**Status:** queued. **Read-only check** — run *before* the full dashboard pass actually starts,
*not now*. Flagged 2026-08-08 (operator instruction, from `roadmap-sequence-delta-2026-08-08.md`'s
review): Paul suspects these six docs' assumptions may be stale given how much has shipped since
they were captured. **This doc does not rebuild or re-verify them — it records the suspicion and
what to check it against, so the actual check isn't skipped when the pass starts.**

## The six docs

- `dashboard-l2-toggle.md`
- `dashboard-roles-access-control.md`
- `responsive-dashboard-multiuser-ready.md`
- `single-user-assumptions-audit.md`
- `settings-loaded-vs-enabled-refactor.md`
- `system-changes-badge.md`

All parked/queued as of 2026-08-08, none built. `single-user-assumptions-audit.md` already
sequences itself relative to the other five ("run after Pass-0, before the responsive-dashboard
build") — that internal order stands; this review is an additional check layered on top, not a
replacement for it.

## Why the suspicion — features shipped since these were captured

Named directly by Paul as reasons to doubt the docs' underlying assumptions still hold:

- **Tiered AI explanations** (per-expertise-tier beginner/intermediate/pro variants) — changes
  what the dashboard renders and how much UI surface a given user sees, which
  `dashboard-roles-access-control.md`'s permission model may or may not have accounted for.
- **Device categorization** (five-category device classifier) — new structured data the dashboard
  now carries per device; `system-changes-badge.md` and `responsive-dashboard-multiuser-ready.md`
  may have been written against a flatter device model.
- **Chat popup** (movable, resizable panel, unpinned from a fixed position) — a layout-surface
  change that directly touches whatever `responsive-dashboard-multiuser-ready.md` and
  `dashboard-l2-toggle.md` assumed about fixed screen real estate.
- **DHCP module** (three-way mode toggle, `MODE_CAPABILITIES`, lease tiering) — new settings
  surface and a new "loaded vs. enabled" distinction in practice, directly relevant to
  `settings-loaded-vs-enabled-refactor.md`'s own scope.
- **Connectivity notifications** (connectivity-notifier work, DHCP/Tailscale-related) — another
  new live UI surface that may not have existed when these docs were captured.

None of this has been checked against the six docs' actual content yet — this is the list of
"what to check," not the check itself.

## What "the check" means when it happens

For each of the six docs: re-read its stated assumptions and open questions, and confirm whether
anything in the list above (or anything else shipped since capture) invalidates a premise, adds a
case the doc didn't consider, or is already compatible as written. Produce a short verdict per
doc — still valid / needs a targeted update / needs a re-scope — before any of the six moves from
"parked" to "in progress." This is the standing method already used elsewhere in this repo for
exactly this shape of question (see `docs/audits/roadmap-state-audit-2026-08-07.md`'s
classification method) — applied here to six specific docs' internal assumptions rather than
their build status.

## Cross-references

`docs/audits/roadmap-sequence-delta-2026-08-08.md` (origin of this flag), the six docs listed
above, `docs/roadmap/agent-rebuild-config-driven.md` and `docs/roadmap/track-c-metadata-tier-build-plan.md`
(some of the shipped features above landed under these plans, for anyone tracing exact commits).
