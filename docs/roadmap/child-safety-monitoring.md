# Roadmap — Child/teen safety monitoring (ADR 0029)

**Status:** PARKED — designed, awaiting post-V2.0 build phase. Fully designed and
deliberately shelved, not abandoned, not a stub, and not blocked on anything unresolved in
the design.

**Design:** [`docs/architecture/0029-child-safety-monitoring.md`](../architecture/0029-child-safety-monitoring.md)
(public sections; complete design in the private engineering mirror, per that document's
Rule 10 note).

**Shape:** dual — (1) a module/add-on within the existing Nemesis firewall product, as
originally scoped, and (2) a standalone product sharing the same detection core, dashboard
reporting and infrastructure, packaged and positioned independently.

**Blocks:** nothing. Gated on V2.0 completion by operator decision, 2026-08-25.

**Before build starts:** a short kickoff agenda resolving the design's remaining open
decisions (16 of 29 in the private decision register), a legal review — sequenced ahead of
this project's other outstanding legal-review items, given this is a materially larger
exposure than anything else queued — and completing the primary-source lookup for the
starting risky-behavior indicator list (see below).

> **Note on the "Status:" header above:** per CLAUDE.md's morning-audit discipline, roadmap
> `Status:` headers go stale on shipping and should not be trusted without a live check.
> This entry is parked rather than shipping, so it will not drift the same way — but if
> build work ever starts, this header is exactly the thing that will not get updated
> automatically. Re-verify against the ADR and `git log` before treating it as current.

## Two things worth carrying here, not just in the ADR

**The standalone product must be self-hosted — a hard constraint, not a preference.** A
standalone child-monitoring product is exactly the category normally sold as SaaS. If it
went hosted, the operator becomes a custodian of children's communications data, which
collapses the design's no-vendor-escrow decision and invalidates the legal architecture in
ADR 0029 §2.5 simultaneously — that section's reasoning assumes throughout that no
vendor-side copy of anything exists. This is exactly the kind of constraint that gets
revisited the first time someone reasons about recurring revenue, which is why it is
recorded here where a product decision would encounter it.

**The dual shape constrains the module, even though the module ships first.** The detection
core must be built as a self-contained component with a thin integration layer — never woven
into firewall internals. It cannot assume the appliance, the agent, ADR 0026's RBAC, the
shared `alerts.db`, or the existing dashboard. Honoring this from the first commit is nearly
free; retrofitting it after the module is entangled with firewall internals is a rewrite.

## Starting design, resolved rather than to be re-derived when this picks back up

Two decisions are settled in the private build spec and should not be re-litigated from
scratch: metadata-derived signals are permanently capped at a descriptive/check-in framing
(no predictive grooming or radicalization scoring — the constraint is evidentiary, not an
engineering gap that better technique closes later), and a child's own risky-behavior count
replaces contact-threat scoring as the primary detection direction. Both followed from two
completed literature reviews establishing that grooming and radicalization detection from
metadata alone have no evidentiary basis in the published research. The first build task
when this resumes is obtaining the underlying nine-item behavior list from its primary
source — inventing a plausible list would repeat exactly the defect the literature review
disqualified the alternative frameworks for.
