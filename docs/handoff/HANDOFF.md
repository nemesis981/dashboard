# HANDOFF — current state

> Last updated **2026-07-30 (Window 2)**. Overwritten each closeout (latest state wins).
> Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/accounts/keys
> live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8.
>
> Written to stand on its own — Paul may or may not be back today. Every claim below was
> checked against live system state or Window 1's/Window 3's own session transcripts
> directly, not just their self-reported summaries. Where something couldn't be
> independently verified, that's stated explicitly rather than presented as confirmed.

---

## 1. Live in production right now — verified, not assumed

- **Tailnet-block interim mitigation is active.** `tailscale debug prefs` → `NetfilterMode:
  1` (= nodivert). Confirmed directly, not from a doc.
- **Step 7 ufw hardening is live and done safely.** `ufw status verbose` shows `22/tcp
  LIMIT IN 192.168.4.0/22` and `80/tcp LIMIT IN 192.168.4.0/22`, correctly *replacing* the
  old plain `ALLOW` rules (not appended alongside them — the specific trap that would have
  made the limit meaningless). No rule for port 443 or 5000; both still hit default-deny.
- **fail2ban's `sshd-tailnet` jail split is live.** Confirmed via `/var/log/fail2ban.log`:
  `sshd` (`maxretry=3, bantime=86400`) and `sshd-tailnet` (`maxretry=3, bantime=300`) both
  started today.
- **The fail2ban end-to-end ban test succeeded.** Confirmed via the `audit_log` table
  directly (not trusted from either window's report): three ban/deny cycles against
  `203.0.113.7` (RFC 5737 test address — expendable, non-routable), each attributed to
  actor `fail2ban`, each cleanly expired afterward by `alert-watcher`. `quarantines` table
  is currently empty (0 rows) — the test cleanup worked; **not yet explained is why
  `<test-vm-tailnet-ip>`'s fresh block from today 11:05 (`fw_block_ip` by `alert-watcher`, per
  `audit_log`) also shows no `quarantines` row** — worth a two-minute look before assuming
  the dashboard's quarantine list reflects it correctly.
- **`MAX_BUCKETS` pinned to 256** in `hw-monitor.service` (`Environment=`), the validated
  value — code default remains 4096 as the wider fallback if the env var is absent.
- **`nemesis_enforce` nft table exists, observe-only, zero authority.** Every rule is
  `counter ... log`, no verdict — cannot drop, reject, or alter delivery by construction.
  Not independently re-verified live this session (no sudo grant covers raw `nft list`),
  but this property is provable from `scripts/nemesis-fw-render`'s code, which was read in
  full.
- **All 12 monitored services active**: dashboard, watchdog, alert-watcher, malware-canary,
  diagnostics-watcher, vpn-dns-guard, nemesis-fwd, hw-monitor, device-scanner, suricata,
  fail2ban, nginx.
- **`<test-vm-tailnet-ip>` (test VM) is blocked**, deliberately, per the operator's own dashboard
  unblock-path test. Re-confirmed via `ufw status` (`Anywhere DENY IN <test-vm-tailnet-ip>`).
- **Local `HEAD` is 2 commits ahead of `origin/main`, not yet pushed** (`ac07b22`,
  `19d9b5c` — see §2). Everything else through `e6cbbda` is already public.
- **Deploy-lifetime sudoers grant removed.** `/etc/sudoers.d/nemesis-host-defence-deploy`
  is gone (operator ran the removal directly); the permanent sibling
  `nemesis-fwd-restart` is untouched. Confirmed via `sudo -n -l` no longer listing it — as
  a side effect, several verification commands available to Window 2 yesterday (raw
  `nft`/`iptables` reads, `fail2ban-client status`) are no longer available; today's
  verification used `ufw` (still granted), direct log/DB reads, and file-permission-based
  access instead.

## 2. Staged/tested but not yet deployed

- **`nemesis-fw-apply` and `nemesis-fw-render`** — committed (`19d9b5c`) but **not pushed**,
  per explicit instruction this session. Both reviewed line-by-line: lockout-failsafe
  ordering is correct (revert armed before apply, LKG snapshot verified re-loadable before
  trusted, scoped to `nemesis_enforce` only — never `flush ruleset`), observe-only property
  in `nemesis-fw-render` is structurally guaranteed. `bash -n` clean, Rule-8 clean.
- **ADR 0019 addendum** (`ac07b22`) — also committed, not pushed. Documents the defect and
  interim mitigation at the correct level of abstraction (unlike `install.sh`'s comment,
  see §5).
- **Push decision is Paul's** — nothing above has been pushed this session per the explicit
  "before any push" instruction. When ready: `git push origin main` from `/opt/nemesis`
  publishes both.

## 3. Mid-flight — needs finishing, with exact next steps

- **ADR 0019 Increment 3's counter-agreement comparison — the one thing this increment
  exists to prove, still not done.** Window 1's own words: "I won't call it complete
  without it." Exact next step, per Window 1: one clean `nemesis-fw-apply` run, generate
  real traffic, read both `nemesis_enforce`'s observe counters and ufw's own DROP counters
  in a single command. Estimated ~10 minutes. The window-test run that already happened
  reset the counters, so this needs a fresh cycle, not a re-read of old data.
- **`install.sh`'s Rule-10 disclosure gap — flagged twice now, still unfixed.** The
  `configure_tailnet_enforcement()` comment block has the same level of exploit-relevant
  specificity (exact rule syntax, exact reproduction/measurement method) as the *private*
  Finding 1 writeup, and it's already pushed to the public GitHub repo. The PUNCHLIST entry
  and ADR 0019 addendum covering the same defect are correctly abstracted — only this one
  file's comment is the outlier. Next step: decide whether to trim the comment in a new
  commit (doesn't retract the already-public history) or accept as residual risk (same
  category of decision as the still-open `9ffac56` username finding from 2026-07-28) —
  **this is Paul's call, not a unilateral fix.**
- **`<test-vm-tailnet-ip>` / `quarantines` table discrepancy** (see §1) — needs a two-minute check
  before trusting the dashboard's quarantine list is currently accurate for that IP.

## 4. Blocked on a decision — Paul's calls

1. **`install.sh` disclosure fix** (§3) — trim now vs. accept as residual, and if trimming,
   whether that needs a history rewrite to be meaningful given it's already public.
2. **`nemesis-fw-apply`'s double-apply-overwrites-LKG gap** (found in review, non-blocking
   today since the table has zero authority) — worth a guard (e.g., refuse a new `apply`
   while a revert is pending) before Increment 4+ gives the table real DROP/REJECT
   authority. Not urgent; flag before that increment starts.
3. **`known-limitations/` still has zero version control.** Now holds six findings from
   yesterday (three still unfixed operationally: agent persistence removal, every bound
   service reachable from any tailnet peer, Suricata blind to inbound tailnet traffic) plus
   everything from before — single disk, no history, no backup. Window 1 itself
   recommended `git init` + local/USB remotes yesterday; not yet done.
4. **`l3-tier2-tls-interception`'s GitHub remote** — still the open question from
   2026-07-28/29 (keep vs. drop to local+USB-only like `firewall-enforcement-engine`).
   Unchanged today.
5. **Window 3 pushing directly to `origin/main`, twice now** (yesterday's one-off,
   today's `eb1943c`, unacknowledged as a deviation this time) — worth deciding whether
   this needs a firmer process guard or was legitimately authorized both times and just
   needs clearer instruction-phrasing going forward ("prep for Window 2" vs. "go ahead").

## 5. Known issues/gaps flagged today, not yet fixed

- `install.sh`'s over-specific defect comment (§3/§4) — the main one.
- `nemesis-fw-apply`'s double-apply/LKG gap (§4) — non-blocking today.
- Increment 3's counter-agreement comparison unmeasured (§3).
- `<test-vm-tailnet-ip>`/`quarantines` discrepancy (§1/§3) — small, unexplained, worth a look.
- Everything carried forward from yesterday's HANDOFF that wasn't touched today: the
  Rule-8 username finding (`9ffac56`, still open, still needs an operator decision), the
  three temporary sudoers grants (unrelated to today's removed one), `NEMESIS_AGENT_EXE`'s
  real home path, `migrate_to_opt.sh` fragility, missing ADR for the relocation model,
  `backupproc.md` unconfirmed for current layout, five files still computing raw
  tree-relative `alerts.db` paths, cosmetic items (duplicate `sys.path.insert`, missing
  attestation calls), ADR 0015 vs. venue-guest-network tension, no hardware baseline, legal
  review not started. None of these were in scope today; listed so they aren't lost.

## 6. Repo-staleness issue — nemesis-fw-apply / nemesis-fw-render — RESOLVED today

This was flagged as an open item going into today: `scripts/nemesis-fw-apply` in the repo
needed syncing with fixes made during testing (root guard, accurate dry-run error,
`mktemp` usage), and `nemesis-fw-render` was missing from the repo entirely.

**Status: fixed.** Window 1 confirmed the sync directly ("Repo synced — all three fixes now
present... plus `nemesis-fw-render`... Both syntax-clean, Rule 8 clean") and Window 2
independently re-verified by reading both files in full before committing — the versions
now in git (`19d9b5c`, not yet pushed, see §2) do carry the root guard, the `FAILED
VALIDATION` dry-run error message, `mktemp` for the temp validation file, and the
`reset-failed` fix for the 33s-vs-60s timer bug. No further sync action needed. This item
can be closed once `19d9b5c` is pushed.

## 7. Cross-references — read these directly, not duplicated here

- `~/work/nemesis-internal/scoping-and-estimates/v2.0-roadmap-2026-07-30.md` — the V2.0
  three-phase roadmap. Updated today with sourced figures pulled from Window 1's live
  session (not fabricated): the full 9-row Phase 1–3 sizing table, the fwmark/`ip rule`
  convention's exact sub-allocation, and a resolution of the Piece E(b)
  padding-vs-randomization question (padding stays, corrected from an earlier approved-but-
  reverted shift toward randomization-only).
- `~/work/nemesis-internal/l3-tier2-tls-interception/DESIGN-NOTE-2026-07-30-padding-scope.md`
  — the Piece E(b) self-correction in full.
- `docs/architecture/0019-deterministic-enforcement-point.md` (public stub, now with
  today's addendum) / `~/work/nemesis-internal/firewall-enforcement-engine/ADR-0019-
  deterministic-enforcement-point-FULL.md` (private full writeup).
- `docs/architecture/0020-agent-model-and-tunnel-ownership.md` — new today, agent
  model/transport decisions.
- `docs/roadmap/track-c-metadata-tier-build-plan.md` — new today, approved to build,
  6–9 sessions, consent-gate-first.
- `~/work/nemesis-internal/known-limitations/phase1-verification-findings-2026-07-30.md` —
  Findings 1–6, the private evidence base behind today's ADR 0019 addendum and ADR 0020.
- `docs/handoff/supplements/2026-07-30-001.md` / `docs/handoff/worklog/2026-07-30-001.md`
  — today's curated narrative and raw log respectively.
- Prior day: `docs/handoff/supplements/2026-07-29-001.md`.

## Topology (durable, unchanged from prior handoffs)
- `:80` nginx (Basic-auth; auth-bypass for `/install/windows/` + `/api/health`), now behind
  step-7's LAN-scoped SSH/HTTP rate limiting at the ufw layer in addition to nginx's own
  `limit_req` from yesterday.
- `:5000` Flask dashboard (ufw-blocked from LAN, unchanged). `:5001` hw-monitor agent
  endpoint, ThreadingHTTPServer + token-bucket pacing (`MAX_BUCKETS=256` live).
- `:5002` agent command listener — localhost-bound + unauthenticated.
- `nemesis-fwd` — Unix-socket privileged helper, peers: dashboard, alert-watcher,
  `fail2ban` (narrow: `block_ip`/`deny_ip` only, cannot release).
