# Roadmap — Email Security Gateway

- **Status:** SHIPPED (bare-provider path) / NOT STARTED (owned-domain MTA-relay path).
  Untracked until this pass (2026-09-02 roadmap audit flagged `modules/email_security/` as
  a real, substantially-shipped module with an ADR but no roadmap file — this file closes
  that gap).
- **Date:** built 2026-08-31 through 2026-09-01 (this window; earlier scoping goes back to
  2026-08-24), roadmap-tracked 2026-09-02.
- **Architecture record:** [ADR 0028 — Email Security Gateway](../architecture/0028-email-security-gateway.md)
  — the full design (12 decisions, D1–D12). This file tracks build/verification status
  against that design; read the ADR for the reasoning behind any of the choices named below.
- **Rule 8:** no real IPs/hosts/accounts in this doc.

---

## What shipped — the bare-provider (Gmail/IMAP-IDLE) path, D2/D3 in ADR 0028

**End-to-end and genuinely scanning mail**, not just plumbing. Confirmed via commit history,
`modules/email_security/`'s files, and the build's own stated test counts (not independently
re-run by this audit pass — pytest wasn't available in this check's environment):

- **Enrollment**: an owner-facing enrollment page walks a household member through
  connecting their own Gmail account via an app password (`enrollment.py`,
  `credential_store.py`), with autodiscovery (`autodiscover.py`, RFC 6186 SRV + Mozilla
  ISPDB) pre-filling provider settings where possible. A 3-provider table with honest
  per-provider notes (including an explicit "Hotmail" caveat) ships in `providers.py`.
- **Credential handling**: a separate, privileged writer path for app passwords
  (`credential_store.py`), atomic slot allocation, owner-side capture — the admin who sets
  up enrollment never sees or handles the credential, matching ADR 0028 D11.5's
  admin-initiated/owner-authorized design.
- **The mailbox supervisor** (`supervisor.py`) is what makes this real rather than
  plumbing-only: one thread per enabled mailbox running an IMAP IDLE connection
  (`imap_idle.py`), each message parsed (`mime_parse.py`), checked (`fast_check.py`,
  `link_classify.py`/`link_extract.py`, `sender_id.py`), and recorded. **Before this shipped,
  the IMAP IDLE client had zero production instantiations — nothing had ever started a
  watcher, so no message had ever flowed through the pipeline end to end.** That gap is
  closed as of `d4d7fdf` (2026-08-31 01:18).
- **Verdict recording is honest about what it doesn't know**: an unparseable message is
  still recorded (a message silently missing from the table is indistinguishable from one
  that never arrived); `verdict` stays `NULL` when `fast_check` has only facts and no
  judgment, rather than manufacturing a false "clean." Per-account failure states
  (`auth_failed` / `config_error` / `crashed`) are kept distinct because the fix for each
  differs, and a credential error is deliberately **not** retried (retrying a dead
  credential burns provider rate limits and turns a config problem into an
  account-recovery one) — it ends that account's watcher loop and surfaces the failure
  rather than silently going quiet.
- **Admin controls**: a route to switch scanning on/off per mailbox (`de3307b`), settings
  resolution across what the build calls "Tiers 1-3" with the guards the strictest tier
  needs (`fc42997`, `settings_resolve.py`) — **the exact meaning of these tiers is not
  independently re-derived in this roadmap pass; read `settings_resolve.py` and
  `views.py` directly before relying on tier semantics for anything user-facing.**
- **Failure-code integration**: wired into the project's `E-EMAIL-*` structured error-code
  system (`a5f426d`).
- **Route-level security findings, found and fixed same window** (`c5afd18`): an
  unauthenticated DoS vector, a case where the mailbox owner was never actually stored, and
  a mailbox-takeover path — all three fixed, per this codebase's standing route-audit
  discipline (CLAUDE.md's "Route-level security audit" section).
- **Registry completeness test added** (`50aaf0f`) — per the standing "every module
  declaring routes needs a registry-completeness test" practice (CLAUDE.md, added
  2026-08-30), so this module's routes can't silently drift out of `ROUTE_MINIMUMS` the way
  `install_windows_start` once did.

**Build's own stated test count at the point mail-scanning went live**: 699 assertions
across `email_security` + `nemesis_fwd` + `roles`, per `d4d7fdf`'s commit message. Further
commits after that point added more coverage (autodiscovery, offline-tolerant provider
checks, the consent-gate review findings). **Not independently re-run by this roadmap pass**
— treat as build-time-verified, not re-confirmed live today.

## What has NOT shipped — the owned-domain MTA-relay path, D1/D4 in ADR 0028

No commits in this window reference an inbound MTA, SMTP relay, or MX-record handling.
**The owned-domain path — the one that gives genuine pre-delivery blocking rather than
near-instant post-delivery detection — has not been started.** ADR 0028 D4 (where the MTA
runs: customer-provided hosting, not a Nemesis-operated relay) is a resolved decision, not
yet built code. This is the harder, hosting-constrained half of the feature; per ADR 0028
§6's own sequencing note, the bare-provider path was always meant to ship first specifically
to prove the detonation/verdict pipeline before the harder path is attempted — which is
exactly what happened.

## What has NOT shipped — link/attachment detonation, D5/D6 in ADR 0028

`attachment_detonate.py` exists in the module's file list, but this roadmap pass did not
verify whether it's wired to a live sandbox call path or is scaffolding — **flagged as
unverified, not guessed at.** ADR 0028 D6's egress-controlled link-detonation mode (a new
sandbox mode, not a reuse of the existing fail-closed one) is architecturally distinct work;
no commit in this window's history clearly claims it shipped. Needs a direct code check
before either direction (shipped / not shipped) is asserted.

## What has NOT shipped — account security monitoring, "pillar 2" in ADR 0028

ADR 0028 §4 names this as "architecturally independent of all of the above" and explicitly
not designed in that ADR — reading a provider's own security/audit API (Workspace Admin SDK,
Microsoft Graph sign-in logs) rather than mail content. No evidence in this window's commit
history that this pillar has started.

## Open items carried from ADR 0028, still genuinely open (see ADR §8 for full detail)

- D5's hold-time budget (measurement-gated, not decided).
- The legal/compliance question for D7's hard-block case.
- D11.7's shared-mailbox ownership model (column vs. join table — blocks schema work if that
  case is hit).
- D12's macOS account-discovery scope (blocked on confirming a shipped macOS agent exists).

## Why this has a roadmap file now but the ADR already existed

ADR 0028 is thorough and current (extended 2026-08-25, still accurate as of this pass). What
was missing was the roadmap-level tracking of *build status against that design* — this file
closes that gap, per the 2026-09-02 roadmap audit's finding that a real, substantially-shipped
module had zero `docs/roadmap/*.md` coverage.
