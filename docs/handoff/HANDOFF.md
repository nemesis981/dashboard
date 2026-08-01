# HANDOFF — current state

> Last updated **2026-07-31 (Window 2)**. Overwritten each closeout (latest state wins).
> Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/accounts/keys
> live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8.
>
> Written to stand on its own — the operator may or may not be back today. Full detail
> behind every claim below: `docs/handoff/supplements/2026-07-31-001.md` (curated) and
> `docs/handoff/worklog/2026-07-31-001.md` (raw).

---

## 1. Live in production right now — verified, not assumed

- **Cutover A/B complete.** `device-scanner` runs as `nemesis-scan`, `dashboard` as
  `nemesis-dash`. Neither account has sudo. `dashboard.py` has zero `sudo` call sites.
- **Phase 3 hardening applied to production.** `NoNewPrivileges`, `ProtectSystem=strict`,
  `SystemCallFilter`, capability-bounding drop all live on `dashboard.service`.
  `ProtectHome`/`PrivateTmp` deliberately still omitted — a quarantine-file move
  (`_quarantine_file()` runs in-process and can `shutil.move()` a path under `/home`) and a
  `/tmp` log path shared between `hw_monitor.py` and `dashboard.py` both block them. Logged
  as follow-up work, not built.
- **ADR 0019 Increment 3 measured — PASS.** Two independent traffic intervals showed the
  enforcement table's observe-only counters moving 1:1 with ufw's own DROP counter
  (+33/+33, then +22/+22 on a shared start point). Increment 4 (cutover to real enforcement
  authority) remains a separate, later, not-yet-started decision.
- **Never-block guard live and proven on production**, not just the VM: an attempted
  self-block of the host's own address was refused client-side, at the ADR-0005 chokepoint,
  before the privileged helper ever saw the request.
- **`nemesis-fwd` deploys on fresh installs and creates `audit_log` at startup** (Gaps 7/9,
  found by the first end-to-end VM install test — a fresh install previously shipped with no
  firewall helper deployed at all, and any firewall action before the first dashboard action
  wrote into a table that didn't exist yet).
- **All 12 services active**: dashboard, watchdog, alert-watcher, malware-canary,
  diagnostics-watcher, vpn-dns-guard, nemesis-fwd, hw-monitor, device-scanner, suricata,
  fail2ban, nginx.
- **Local `HEAD` is 20 commits ahead of `origin/main`, none pushed.** Window 1 is
  independently verifying the batch; the operator will approve push once that's done. Full
  list: `git log --oneline @{u}..HEAD` from `/opt/nemesis`.

## 2. Staged/committed tonight, NOT pushed — holding for approval

Twenty commits, grouped by theme (full detail: `docs/handoff/supplements/2026-07-31-001.md`
§"Committed tonight"):
- Firewall/audit infra: never-block guard, install.sh Gaps 1-9, Cutover B Phase 0 + unblock
  feature.
- Phase 3 hardening (Steps 1-2) + a Rule-8 redaction of leaked LAN/tailnet IPs that predated
  today.
- ADR 0019 status correction.
- The full authentication system: `login_events` centralization, `password_changed_at`
  (both writers), a root-only guard on `core/manage.py`'s mutating commands, 30-day password
  expiry, the authenticated change-password route, the recovery-code system end to end,
  next-URL preservation + open-redirect guard.
- Supporting docs (worklog + PUNCHLIST appends).

**Two Rule 10 items committed as-authored, unmodified** — source-visibility questions for
the operator, never a feature gate: `core/manage.py`'s `_require_root()` docstring (the
guard is not a boundary against a compromised dashboard) and `recovery_grace_until`'s
column comment (why session state alone was insufficient — stateless-cookie replay).

**Push gate in force.** Nothing above has been pushed. Window 1 verifies independently
first; the operator approves push as an explicit, separate step.

## 3. Two same-night regressions — both caught and recovered same-night

Full evidence-first accounts: `docs/handoff/worklog/2026-07-31-001.md`. Neither reached a
commit or affected production.

1. A span-replace edit briefly clobbered four `_RECOVERY_*` constants (caught by Window 2's
   independent review before any commit; root-caused and restored).
2. `dashboard.py` transiently reverted to byte-identical-with-`HEAD` during a fine-grained
   commit-splitting attempt by Window 2, dropping twelve functions from the working tree
   (never from git — no commit or stash ever held the broken state). Caught within minutes,
   restored from a scratchpad backup, re-verified against all four live checks.

**Adopted process lesson:** after any structural edit, run a whole-file unresolved-name
sweep against a known-good baseline, not a targeted check of only the functions believed
touched. `dashboard.py`'s hunks interleave too heavily across features for fine-grained
commit-splitting to be safe — hand it over as one commit going forward.

## 4. Mid-flight — needs finishing, with exact next steps

- **`core/manage.py`'s whitespace-normalization line** (`pw.strip()` in
  `_choose_password()`) is sitting uncommitted in the working tree — never explicitly
  cleared for tonight's batch, harmless to leave, safe to commit whenever convenient.
- **`login_events.timestamp` is UTC while every other auth-adjacent table is local time.**
  Self-consistent today (nothing currently compares across tables), but a trap for the
  brute-force/impossible-travel detection this table exists to feed. Fix needs care —
  changing the DEFAULT doesn't rewrite existing (genuinely UTC) rows.
- **Out-of-band credential changes write zero `audit_log` rows.** `core/manage.py`'s
  `reset-password`/`create-user`/`unlock` mutate credentials with no queryable record.
  Confirmed live during tonight's own operator lockouts. Small fix — `manage.py` already
  imports `database`; needs an `audit_log` insert per command.
- **`install.sh`'s Rule-10 disclosure gap — flagged multiple times now, still unfixed.**
  Same defect as before: `configure_tailnet_enforcement()`'s comment carries
  exploit-relevant specificity that the equivalent ADR/PUNCHLIST entries correctly abstract
  away. Operator's call: trim vs. accept as residual.

## 5. Blocked on a decision — the operator's calls

1. **Push approval** for tonight's 20 commits — pending Window 1's independent
   verification.
2. **`install.sh` disclosure fix** (§4) — trim now vs. accept as residual.
3. **`known-limitations/` still has zero version control** — recommended twice now, not
   yet done.
4. **`l3-tier2-tls-interception`'s GitHub remote** — still open from 2026-07-28/29.

## 6. Known issues/gaps flagged today, not yet fixed

- `login_events.timestamp` UTC/local skew (§4).
- Out-of-band credential changes have no audit trail (§4).
- Don't run `core/manage.py` as root while `alerts.db`'s WAL sidecars are absent — would
  create them root-owned and lock `nemesis-dash` out of the database. Unforeseen
  interaction with tonight's root-only guard.
- Everything carried forward from prior HANDOFFs that wasn't in scope today: the Rule-8
  username finding (`9ffac56`, still open), three unrelated temporary sudoers grants,
  `NEMESIS_AGENT_EXE`'s real home path, `migrate_to_opt.sh` fragility, missing ADR for the
  `/opt` relocation, `backupproc.md` unconfirmed for current layout, ADR 0015 vs.
  venue-guest-network tension, no hardware baseline, legal review not started.

## 7. Cross-references

- `docs/handoff/supplements/2026-07-31-001.md` — curated narrative for today.
- `docs/handoff/worklog/2026-07-31-001.md` — full raw log, including both regressions'
  complete evidence-first accounts.
- `docs/architecture/0019-deterministic-enforcement-point.md` — corrected status.
- `PUNCHLIST.md` — four new finds from tonight, plus the resolved stale-path entries.
- Prior day: `docs/handoff/supplements/2026-07-30-001.md`, `2026-07-30-002.md`.

## Topology (durable, unchanged from prior handoffs)
- `:80` nginx (Basic-auth; auth-bypass for `/install/windows/` + `/api/health`), LAN-scoped
  SSH/HTTP rate limiting at the ufw layer plus nginx's own `limit_req`.
- `:5000` Flask dashboard (ufw-blocked from LAN, unchanged). `:5001` hw-monitor agent
  endpoint, ThreadingHTTPServer + token-bucket pacing (`MAX_BUCKETS=256` live).
- `:5002` agent command listener — localhost-bound + unauthenticated.
- `nemesis-fwd` — Unix-socket privileged helper, peers: dashboard, alert-watcher,
  `fail2ban` (narrow: `block_ip`/`deny_ip` only, cannot release), plus tonight's new
  `write_env`/`restart_dashboard` ops (dashboard peer only).
