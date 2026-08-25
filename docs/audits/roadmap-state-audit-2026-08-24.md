# Roadmap-vs-state audit — 2026-08-24

> Read-only audit (Rule 1), refreshed as the explicit closeout follow-up owed from the
> 2026-08-24 morning Morning Status pass, which found live shipping drift the 08-22 baseline
> hadn't caught. Classifies every `docs/roadmap/*.md` item against actual project state
> (code, `git log`, ADRs, HANDOFF). Baseline for the next Morning Status roadmap line
> (latest date wins). No PII/infra values (Rule 8): commit hashes + filenames only.
> Supersedes `roadmap-state-audit-2026-08-22.md` (kept as history).

**Tally: 11 SHIPPED · 12 PARTIAL · 60 STUB/PARKED — 83 total.**

## Drift since 2026-08-22 baseline

### File-set: +2, none removed (81 → 83)

`ls docs/roadmap/*.md` count is 83 vs. the 08-22 baseline's 81. Two new files, both
confirmed absent from the 08-22 baseline text and both accounted for by the 08-23 second
session's V2.0 gap-scan (HANDOFF.md item 4, commit `440edf3`):

| File | Status |
|---|---|
| `docs/roadmap/vulnerability-patch-management.md` | STUB/PARKED — capture-only |
| `docs/roadmap/removable-media-device-control.md` | STUB/PARKED — capture-only |

### Shipping: 1 item reclassified — real drift, not header-trusted

- **`dashboard-roles-access-control.md`: PARKED → SHIPPED.** File header still read
  "capture... build NOT started" as of the 08-24 morning audit, but commits `c84dcce`→
  `a0d971c` (2026-08-22, 18:49–18:55 — i.e. *after* the 08-22 baseline audit was committed
  at 08:22:54 that same morning, which is why that baseline missed it) shipped a full RBAC
  foundation: three roles (admin/user/viewonly) enforced at a `before_request` gate across
  all 149 live endpoints, independently re-verified in
  `docs/handoff/supplements/2026-08-23-001.md` (lines 95-108): `test_roles.py` re-run
  directly, `assert_registry_complete()` re-run outside the test harness, all 45 module
  endpoints manually sampled, `dashboard.py` source read to confirm the six known
  GET-that-act routes are genuinely bare GETs. Classified **SHIPPED, not PARTIAL**: the
  core deliverable (roles enforced application-wide) is live and verified, matching the
  bar the 08-22 baseline itself used for `malware-layer-b-behavioral-monitoring.md`'s
  SHIPPED classification despite that item also carrying tracked follow-on work. The six
  GET-that-act routes needing POST conversion are a separate, already-tracked hardening
  item (PUNCHLIST), not a gap in whether RBAC exists. Roadmap file's own status header
  corrected in this pass (2026-08-24 closeout).

**Checked, no drift found:** a keyword sweep of the 101 commits between the 08-22 and
08-24 baselines against every current roadmap filename surfaced no other candidate
crossings. `agent-rebuild-config-driven.md` and `memory-injection-detection-design.md` /
`windows-agent-memory-injection-rework-prereqs.md` (superseded pointer, unchanged) — recent
matching commits (steering-config fix, memory-injection region-features/error-codes work,
the observe-only sweep scheduler landed `029b8e4`) are continuations of already-PARTIAL,
already-permitted "observation-layer proceeds, detection technique stays paused" scope, not
new shipping. Note: `029b8e4` wires the SCHEDULER only (`classifier: 'absent'` without the
private classifier module) — explicitly does not close gap-scan item #9 or change this
roadmap file's PARTIAL classification.

**Not evaluated this pass:** the 17 commits landed 2026-08-24 (Stage 5 first capability,
default-deny dispatch, ADR 0026 D3 admin-approval, meminject sweep, Stage 0 step 1
session-realms/nemesis-fwd op, cert-renew infra, RP identity, local-port watch) do not map
to any existing `docs/roadmap/*.md` filename — consistent with the established pattern of
shipped work landing without a dedicated roadmap file (ADR 0026, ADR 0028 cover this work
instead). No roadmap-file reclassification triggered by today's session.

## SHIPPED (11)
The 10 items from the 08-22 baseline **plus**:
- `dashboard-roles-access-control.md` (new this pass — see Drift section above)

## PARTIAL (12)
Unchanged from the 08-22 baseline.

## STUB/PARKED (60)
The 59 items from the 08-22 baseline, minus the 1 reclassified above, plus the 2 new files:
59 − 1 + 2 = 60.

## Method
Same as prior baselines: `ls docs/roadmap/*.md` file-count/name diff against the prior
baseline, `git log --diff-filter=A`/`-D` provenance for new/removed files, a keyword sweep
of the intervening commit window's subjects against every current roadmap filename to catch
silent shipping. Baseline doc for tomorrow's Morning Status: this file (2026-08-24),
superseding `roadmap-state-audit-2026-08-22.md`.
