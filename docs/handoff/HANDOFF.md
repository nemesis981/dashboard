# HANDOFF — current state

> Last updated **2026-08-02 (Window 2)**. Overwritten each closeout (latest state wins).
> Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/accounts/keys
> live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8.
>
> Written to stand on its own — the operator may or may not be back tomorrow. Full detail
> behind every claim below: `docs/handoff/supplements/2026-08-02-001.md` (curated) and
> `docs/handoff/worklog/2026-08-02-001.md` (raw — reconstructed at closeout, not kept live;
> see the discipline note at its top).

---

## 1. Live in production right now — verified, not assumed

- **ADR 0019 Increment 4 (real DROP authority) is live** — Commit B pushed this morning
  after re-confirming its held status was still correctly gated.
- **ADR 0004 is resolved** (all three hinge questions) and its Step 1–3 are built and
  shipped same day: YARA rule auto-update + cross-platform exclusions + operator-facing
  routes/SSRF-guard/rate-limit/UI ("M2"), and the actor-seam + local-ISO-timestamp
  migration on the five `scan_*` tables (Step 2). Agent-heartbeat authentication (Step 3,
  the former FLAG 1 gap) is also shipped. **M3 (full-stack reachability) is unblocked** —
  Window 1's own next item, scoped proposal expected before any code.
- **YARA rule auto-update is live**, SSRF-guarded (https-only, allowlist of
  loopback+IPv4-RFC1918 for the test-only override, no address enumeration), rate-limited,
  with a dashboard card showing rule freshness.
- **Windows installer pre-warn page is live** (`/install/windows/<token>/start`),
  correctly reachable without a dashboard login, forewarning SmartScreen/UAC before
  Windows shows them.
- **`malware_settings` no longer shadows its own code defaults** — verified live,
  pruned to 0 rows after the fix deployed.
- Several smaller fixes also live: lockout-tier email off the request thread,
  `login_events` timestamps local (not UTC), `_SECRET_KEY_PATH`/`_BACKUP_CFG_PATH` follow
  `NEMESIS_DB_PATH` overrides, `/api/malware/canary/check` is POST (was a
  CSRF-triggerable GET), perpetual canary tickets stopped, vpn-dns state path fixed,
  lock-screen findings tile restored + hw tiles added, installer no-conf-path arity crash
  fixed.
- **`origin/main` is at `6f024a5`** as of this writing; today's closeout commit will move
  it further. Nothing else pending push as of this line.

## 2. THE items to pick up first, in priority order

1. **PL-10's actual root cause and fix — still open, reopened today after an incorrect
   closeout.** `_first_screen_text`'s preauth-key gating traces correctly in static
   source (confirmed twice, by two separate passes), but Window 1 directly watched the
   stale manual-Tailscale-install text render on screen from a current build
   (`installer_gui.py:99,105,110`). The discrepancy between "logic is correct in source"
   and "wrong text rendered live" is unresolved — do not assume a one-line copy fix until
   it's understood whether the tested scenario genuinely lacked a preauth key by design,
   or something in the build/packaging path diverges from this source file.
2. **Installer token revocation — FIX-NOW, well-scoped, not built.** `revoked` is
   enforced on read (`_valid_installer_token()`) but no route anywhere writes it —
   confirmed via a full-codebase grep, not just `dashboard.py`. Only reachable in one
   state (issued, never enrolled), which is why it went unnoticed until a real token
   needed withdrawing today. Fix: authenticated `POST /api/agent/installer/revoke`
   alongside the existing generate route, same auth posture, plus a revoke control
   wherever installer links are listed. Full detail: `PUNCHLIST.md`.
3. **Credential rotation — operator's, not code work.** Six credentials were exposed in
   this session's transcript (Anthropic API key, AbuseIPDB key, IPinfo token, watchdog
   email password, Pi-hole password, Tailscale OAuth client ID/secret) via an
   over-broad grep. Redaction was attempted and abandoned as structurally self-defeating
   (every redaction command re-embedded the secrets as new tool-call parameters). A
   pre-rotation snapshot is waiting at
   `/run/media/<user>/storage/nemesis-state-backups/2026-08-02-1329-pre-credential-rotation/`
   (DB integrity-checked). Five of six need the operator's own external-service consoles;
   Pi-hole needs interactive `sudo` unavailable to this session. Not yet done.

## 3. Everything else committed and pushed today (32 commits, full list in git log)

Grouped by theme — full narrative: `docs/handoff/supplements/2026-08-02-001.md`.

- **ADR 0004**: hinge questions (a)/(b)/(c) resolved and authored; Steps 1–3 built same
  day (see §1). M3 unblocked.
- **YARA auto-update**: three successive rounds of SSRF hardening on the same feature,
  each round's independent review catching a real gap the previous round missed —
  culminating in an allowlist-based (not denylist) test-only override, verified by two
  independent test suites before landing.
- **Pre-warn page**: shipped, then two same-day follow-on fixes (`_AUTH_EXEMPT`
  omission, which silently 302'd every visitor to login; and the installer-token
  revocation gap it surfaced during live verification).
- **Config-shadowing audit**: `docs/audits/config-shadowing-audit-2026-08-02.md`,
  enumerating every `/etc/nemesis-*` config plus everything `install.sh` writes.
- **VM fleet**: gauge VM built and pruned (real footprint numbers now in CLAUDE.md),
  W3-TEST rig retired, two new standing rules (`KEEP`-naming protects a clone from any
  cleanup pass; identify VMs by host ARP/in-guest data, never the DHCP leases file — a
  stale lease pointed at the wrong running clone today, read-only that time).
- **Process discipline added to CLAUDE.md**: Window 2 confirmed as backup git-writer for
  private modules; a new distinct hazard (shared-index staging — a `git commit` sweeping
  in an unrelated already-staged change, different from the push-coordination hazard);
  a fifth route-audit shape (`_AUTH_EXEMPT` must be checked explicitly for new public
  routes).
- **Rule-8 hygiene**: two passes caught and placeholdered real LAN identifiers before a
  public commit — one of them a leak that predated today entirely, sitting in
  `PUNCHLIST.md` since an earlier session.

## 4. Mid-flight — needs finishing, with exact next steps

- **PL-10 — see §2.1. Second priority after installer-token-revocation.**
- **Installer token revocation — see §2.2.**
- **`diagnostics_settings` shadowing** (9/10 rows shadowing code defaults, one genuine
  override — `watcher_enabled`) — same prune-on-init fix already shipped for
  `malware_settings` (`cf6d439` is the reference implementation), not yet applied here.
- **`install.sh`'s `write_env_file()`** bakes `SMTP_PORT` and both Anthropic pricing
  constants into every fresh install at values identical to the code defaults — any
  future default change silently never reaches new installs either. Fix: write only
  operator-supplied/non-default keys. Full detail: `docs/audits/config-shadowing-audit-2026-08-02.md`.
- **SSRF guard's DNS-rebinding residual risk** — stated, not solved, in
  `_validate_source_url`'s own docstring. Accepted for now (authenticated-operator-only
  caller); revisit if that value ever becomes settable by a less-privileged path.
- **YARA update rate-limit counter** — non-atomic read-then-write, same shape as the
  `tickets_seq`/AI-rate-limit races already fixed elsewhere (Data Manager v0 seed). Low
  severity given the "abuse-limiting not a security boundary" framing already in its own
  comment; not fixed.

## 5. Blocked on a decision — the operator's calls

1. **Credential rotation** — see §2.3.
2. **PL-10 root cause** — needs the operator or Window 1 to determine which of the two
   explanations (keyless test scenario vs. build/packaging divergence) is actually true
   before a fix can be written with confidence.
3. **`install.sh`'s Rule-10 disclosure gap** — carried forward from 07-31, still unfixed.
4. **`known-limitations/` still has zero version control** — carried forward, recommended
   multiple times, not yet done.
5. **`l3-tier2-tls-interception`'s GitHub remote** — still open from 2026-07-28/29,
   deliberately left for the operator.

## 6. Known issues/gaps, not yet fixed

- PL-10 (§2.1), installer token revocation (§2.2), `diagnostics_settings` shadowing,
  `install.sh`'s frozen env keys, the DNS-rebinding residual, the rate-limit counter race
  — all §4 items above.
- `login_events.timestamp` UTC/local skew — **this one is now RESOLVED** (fixed
  2026-08-01, confirmed still correct today), removing it from future carry-forward.
- Everything else carried forward from prior HANDOFFs, unchanged since 2026-08-01: the
  Rule-8 username finding (`9ffac56`), three unrelated temporary sudoers grants,
  `NEMESIS_AGENT_EXE`'s real home path, `migrate_to_opt.sh` fragility, missing ADR for
  the `/opt` relocation, `backupproc.md` unconfirmed for current layout, ADR 0015 vs.
  venue-guest-network tension, no hardware baseline (though the gauge VM now provides
  real measured data toward one — see VM fleet section of CLAUDE.md), legal review not
  started.

## 7. Cross-references

- `docs/handoff/supplements/2026-08-02-001.md` — curated narrative for today.
- `docs/handoff/worklog/2026-08-02-001.md` — raw log (reconstructed at closeout).
- `docs/architecture/0004-scan-task-orchestration.md` — resolved ADR.
- `docs/audits/config-shadowing-audit-2026-08-02.md` — the shadowing audit.
- `PUNCHLIST.md` — installer token revocation (new FIX-NOW), config-shadowing follow-ons,
  `diagnostics_settings` remediation, PL-10 (reopened).
- `~/work/nemesis-internal/vm-fleet/VM-FLEET-LOG.md` (private mirror) — full VM fleet
  build/cleanup detail, gauge VM footprint comparison.
- Prior day: `docs/handoff/supplements/2026-08-01-001.md`.

## Topology (durable, unchanged from prior handoffs)
- `:80` nginx (Basic-auth; auth-bypass for `/install/windows/` + `/api/health`), LAN-scoped
  SSH/HTTP rate limiting at the ufw layer plus nginx's own `limit_req`.
- `:5000` Flask dashboard (ufw-blocked from LAN, unchanged). `:5001` hw-monitor agent
  endpoint, ThreadingHTTPServer + token-bucket pacing (`MAX_BUCKETS=256` live).
- `:5002` agent command listener — localhost-bound + unauthenticated.
- `nemesis-fwd` — Unix-socket privileged helper, peers: dashboard, alert-watcher,
  `fail2ban` (narrow: `block_ip`/`deny_ip` only, cannot release), `write_env`/
  `restart_dashboard` ops (dashboard peer only).
- `nemesis_enforce` — owned nftables table (ADR 0019), priority-placed ahead of the filter
  hook, derived from `ufw`'s live state. **Real DROP authority live as of today**
  (Increment 4 cutover pushed this morning).
