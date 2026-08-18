# Audit — nginx config drift: deployed front door vs. `install.sh` template

**Date:** 2026-08-16
**Window:** 2 (docs/audit)
**Method:** read-only (Rule 1) — no config or code changed during this pass.
**Full detail (exact live values, IPs, remediation draft):**
`~/work/nemesis-internal/audits/nginx-config-drift-audit-2026-08-16.md` — kept private per
Rule 10, same reasoning as ADR 0021 (exact rate-limit thresholds are attacker-relevant
precision, not architectural direction).

## Summary

The nginx config actually running in front of the dashboard on the reference deployment has
no version-controlled copy in the public repo, and has drifted from what `install.sh`
generates. This is a known gap — ADR 0021 (2026-08-01) already named "bring the deployed
host-defense hardening into `install.sh`" as the largest gap it found, and PUNCHLIST.md
already tracks it (the "Decision B" entry). This pass confirms the gap is still open, and
surfaces one part of it that was **not** previously flagged: `install.sh`'s nginx block is
not idempotent, so re-running it on an already-hardened box would silently regress the
deployed protection.

## Findings

### 1. No version-controlled copy of the live config exists in the public repo
`git status`/`find` against `/opt/nemesis` confirm the two files that actually govern
production nginx behavior — `/etc/nginx/sites-available/nemesis` and
`/etc/nginx/conf.d/nemesis-ratelimit.conf` — are not tracked anywhere in this repo. The only
version-controlled record of them is a dated snapshot in the private mirror from the
2026-07-29 staging pass, whose header still reads "NOT DEPLOYED" even though (per this
audit's diff) its content is now what's actually live — the label is stale, not the content.

### 2. `install.sh`'s nginx heredoc (`install.sh:1633-1662`) is the pre-hardening baseline
Categorical differences from what's deployed (exact values kept in the private copy per
Rule 10):
- No rate-limit or connection-limit directives anywhere in the installer's template, and
  `install.sh` never writes anything under `/etc/nginx/conf.d/` — a fresh install gets zero
  request-rate protection.
- No dedicated, more-tightly-throttled location block for the login endpoint.
- The auth-exempt installer-download/health location in the template carries no limiting at
  all; the deployed equivalent does.

This matches ADR 0021's own conclusion verbatim: "This protection exists only on the
reference deployment, not in the standard installer... the single largest concrete gap this
pass identified."

### 3. A real (non-hardening-related) naming divergence: two different htpasswd filenames
`install.sh:1627-1630,1652` creates and references `/etc/nginx/.nemesis_htpasswd`. The file
that actually exists on disk, and that the live site config actually references, is
`/etc/nginx/.htpasswd` — a different filename, present since before the 2026-07-29 hardening
pass (its mtime predates that work). This is independent of the rate-limiting gap: even
reconciling the rate-limit directives alone would leave the installer creating a file its own
generated config doesn't read.

### 4. New finding — `install.sh`'s nginx block is not idempotent; a re-run would regress production
`install_pihole()` (`install.sh:594-598`) checks `systemctl is-active --quiet pihole-FTL` and
skips if already installed. The nginx block has no equivalent guard: it unconditionally
`cat >`s over `/etc/nginx/sites-available/nemesis` with the bare template on every run
(`install.sh:1633`), and unconditionally recreates the htpasswd file (`install.sh:1627`,
using `-c`, which creates/truncates).

Consequence: if `install.sh` is ever re-run on this box (upgrade, repair, disaster recovery)
it would silently strip the deployed rate-limiting, the login-specific throttling, and the
narrower auth-exempt limiting — with no error. `nginx -t` would still pass, because the bare
template is syntactically valid on its own; nothing in the current install/verify path would
flag that the live protection had been reverted. This risk was not named in ADR 0021 or the
existing PUNCHLIST entry, which frame the gap as "fresh installs don't get it," not "a
re-install of *this* box would remove it."

### 5. Not a bug, but worth naming: the live `server_name` is hardcoded to this box's LAN IP
The template correctly uses `server_name _;` (generic — correct for shipped code, per
CLAUDE.md's "no environment-specific defaults" rule). The deployed file hardcodes this box's
real address instead. That's expected manual customization for a specific reference
deployment, not a template defect — but it means the live file cannot be copied back into
`install.sh` verbatim; whatever reconciliation happens needs to preserve `server_name _;` in
the shipped template.

## The disclosure question this audit does not resolve

Per CLAUDE.md Rule 10, this is a flagged decision, not a default:
- **General architecture** — the fact that request-rate limiting exists, the existence of a
  tighter login bucket, the existence of connection limits — defaults to **public**. Nothing
  above should be read as an argument to hide any of that.
- **The exact tuned values** — the specific req/s rates, burst allowances, and connection
  caps in the deployed config were derived from the adversarial test ADR 0021 references, and
  ADR 0021 already decided those specific numbers stay private for exactly that reason.
  Committing the deployed file verbatim into the public repo, or hardcoding those same
  numbers into `install.sh`'s public template, would publish precisely what ADR 0021 flagged
  as attacker-relevant precision — not something either remediation direction should default
  into silently.

## Recommendation (for review, not yet actioned)

Two different problems are bundled in the user's framing ("bring the deployed config in" vs.
"reconcile the installer") — they don't have to be, and don't cleanly, resolve to the same
fix given the Rule 10 constraint above:

1. **Public — make `install.sh` idempotent and give every fresh install *some* rate-limiting**
   (closing the actual gap ADR 0021 named), using conservative, round, non-precision-revealing
   default values rather than the adversarial-test-derived production numbers, and add the
   `pihole`-style "already configured, don't clobber" guard so a re-run can no longer regress
   the reference deployment's tuning. Also reconcile the htpasswd filename to whichever name
   is kept.
2. **Private — promote the 2026-07-29 staged snapshot from a one-off dated directory into a
   maintained, current record of exactly what's live**, re-synced now (its content already
   matches; only its "NOT DEPLOYED" header is stale) and committed to the private mirror
   (local+USB) as the actual version-controlled front door for this reference deployment.

This is a build-scoped change (touches `install.sh`), so it's Window 1's to implement once a
direction is confirmed. Full remediation draft with exact values: the private copy of this
audit.

## Cross-references
- `docs/architecture/0021-dos-resilience-scoping.md` — original finding, deliberately
  deferred to a later hardening pass.
- `PUNCHLIST.md` (~line 1386, "Decision B") — existing durable tracking of this gap.
- `docs/audits/config-shadowing-audit-2026-08-02.md:94-102` — a prior audit that explicitly
  excluded the nginx template from its scope, describing it as "identical on every install"
  — true as of that audit's own baseline, no longer true once the 2026-08-01 hardening
  deploy landed the day before it ran. Not a contradiction in that audit; a confirmation of
  how the drift happened.
