# HANDOFF — current state

> Last updated **2026-08-01 (Window 2)**. Overwritten each closeout (latest state wins).
> Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/accounts/keys
> live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8.
>
> Written to stand on its own — the operator may or may not be back tomorrow. Full detail
> behind every claim below: `docs/handoff/supplements/2026-08-01-001.md` (curated) and
> `docs/handoff/worklog/2026-08-01-001.md` + `-002.md` (raw — Window 2's session and Window
> 1's build session respectively).

---

## 1. Live in production right now — verified, not assumed

- **Idle-lock / walk-away protection is fully live**: server-side enforcement, absolute
  8-hour session cap, in-page overlay with real DOM-interaction heartbeat (not polling), and
  a view-only health summary on the lock screen. Background pollers (dashboard's own plus
  three found unmarked this session) correctly excluded from counting as activity.
- **Three security bugs fixed and live**: `db_action`'s unguarded GET (was CSRF-shaped and
  recorded fake blocks with no real firewall rule), `api_backup_schedule`'s shell-injection
  via unescaped crontab interpolation, `api_vpn_action`'s unguarded GET. Session cookie now
  sets `SameSite=Lax` + `HttpOnly` explicitly.
- **ADR 0019 Increment 3 (counter agreement) is PROVEN** — a correctly-isolated,
  packet-capture-verified measurement passed after four earlier invalid attempts across two
  sessions. The enforcement table now also survives reboot (persistence unit) and is
  integrity-monitored (netlink watcher, VM-verified against a "kill it, tamper while down,
  restart" bypass test). A never-block guard fails closed if it can't classify an address.
- **ADR 0019 Increment 4 (real DROP authority) is built and verified, but the cutover is
  HELD — not live in production, not pushed to git.** See §2, this is the single most
  important item in this document.
- **All 12 services active**: dashboard, watchdog, alert-watcher, malware-canary,
  diagnostics-watcher, vpn-dns-guard, nemesis-fwd, hw-monitor, device-scanner, suricata,
  fail2ban, nginx.
- **`origin/main` is at `bdbb9ac`.** Local `HEAD` is exactly one commit ahead
  (`1ea7e51`) — deliberately held, see §2. Nothing else is pending push.

## 2. THE item to pick up first: Commit B (Increment 4 cutover) is held

`scripts/nemesis-fw-render`'s `NEMESIS_FW_ENFORCE` default flip (0 → 1, giving the
`nemesis_enforce` table real DROP authority) is **committed locally as `1ea7e51`, verified
byte-identical in content after a same-session history reorder, and deliberately NOT
pushed.**

**Why:** a measurement question — does the netlink watcher's unattended re-render path
(`rerender()`) genuinely fail closed when the never-block guard is unavailable? — was
measured tonight with a broken instrument (hashed raw `nft` output including live packet
counters, which move every packet, producing an artifact FAIL). A worklog entry written
during the same session explicitly gated Commit B on a correct re-measurement
("HELD until check 7 has a correctly-measured result... THEN commit Commit B"), but a later
handoff message characterized the same issue as "not blocking" and Commit B got committed on
that basis. Window 2 caught the contradiction before pushing; the operator confirmed the
worklog's gating language was the accurate one.

**Exact next step:** re-measure `rerender()`'s fail-closed behavior with a counter-stripped
hash (the same fix already applied to the *render* path's own hashing — see
`known-limitations/` for the instrument-defect pattern), and make the instrument prove
itself first (two hashes with no real change must match; a known real change must differ).
If it passes, push `1ea7e51` as-is (already verified, already reviewed, nothing else to
redo). If it fails, the fix belongs in `nemesis_fw_watch.py`, not in this held commit.

**Also open, same area:** install `nemesis-fw-watch` on the VM and add the `rerender()`
fail-closed path to the permanent VM test plan — it was never installed there, so this exact
integration path has never actually been tested end-to-end.

## 3. Everything else committed and pushed today (36 commits, full list in git log)

Grouped by theme — full narrative: `docs/handoff/supplements/2026-08-01-001.md`.

- **Idle-lock / walk-away protection**, designed, approved, and built end-to-end in one day:
  server-side enforcement + absolute session cap, background-poller marking (two rounds —
  three pollers were missed the first time), recovery-code-consumption email alert, in-page
  overlay + DOM-interaction heartbeat, lock-screen health summary.
- **ADR 0019**: Increment 3 proof (after retracting a harness-bug false FAIL), the
  persistence unit, the netlink watcher, the never-block guard, Increment 4 gated-off
  verdict emission.
- **Two new standing CLAUDE.md rules**: a route-level security audit that triggers
  automatically on dashboard/routes/template changes, and a verification-code discipline
  rule (self-test against known-different input; never default a failed read to a value that
  looks like data) — the latter came from finding the *same* failure shape nine times in one
  day across shell, Python, and JS.
- **ADR 0021** (DoS resilience scoping — architecture and category-level findings only, real
  hardening deferred to a later pass) and two new roadmap stubs (automated abuse reporting;
  server-side session store).
- **PUNCHLIST**: "Decision B" (host-defense-layer productization — fail2ban and the nginx
  rate-limiting config both live on this reference box but absent from `install.sh`) got a
  durable home after existing only in a worklog since 07-31. Also captured: stale
  pre-relocation sudoers entries, the backup-schedule/`NoNewPrivileges` gap, and the
  dashboard-side `degraded.jsonl` → `audit_log` ingestion follow-up.

## 4. Mid-flight — needs finishing, with exact next steps

- **Commit B — see §2. This is the priority.**
- **`_SECRET_KEY_PATH` testability gap** — resolves against the `DATA_DIR` constant, not the
  `data_dir()` function, so it ignores `NEMESIS_DB_PATH` overrides in test harnesses.
- **Lockout-tier email still blocks the request thread** — `dashboard.py:512` calls the
  blocking `_notify_email()` directly instead of the `_notify_email_async()` wrapper added
  today for the recovery-code alert. Small, mechanical swap.
- **`login_events.timestamp` UTC/local skew** — carried forward from 07-31, still unfixed.
- **`install.sh`'s Rule-10 disclosure gap** — carried forward from 07-31, still unfixed.
  Operator's call: trim vs. accept as residual.

## 5. Blocked on a decision — the operator's calls

1. **Commit B push** — pending the check-7 re-measurement (§2).
2. **`install.sh` disclosure fix** — trim now vs. accept as residual (carried forward).
3. **`known-limitations/` still has zero version control** — recommended multiple times now,
   not yet done.
4. **`l3-tier2-tls-interception`'s GitHub remote** — still open from 2026-07-28/29.
5. **Two live production config files** (nginx rate-limiting, fail2ban) had stale
   "NOT DEPLOYED" headers — corrected directly by the operator outside git (Window 2 has no
   write access to `/etc/`). No outstanding action, noted for completeness.

## 6. Known issues/gaps, not yet fixed

- Commit B's underlying question (§2) — the primary open item.
- `login_events.timestamp` UTC/local skew (§4).
- `install.sh`'s Rule-10 disclosure gap (§4).
- `_SECRET_KEY_PATH` / `NEMESIS_DB_PATH` testability gap (§4).
- Lockout-tier email still synchronous (§4).
- Dashboard-side `degraded.jsonl` → `audit_log` ingestion (PUNCHLIST, tracked today) — the
  netlink watcher's own audit write is a deliberate no-op until this lands (writing as root
  created root-owned WAL sidecars on the VM and locked the dashboard out of its own DB).
- Backup-schedule feature is non-functional on production regardless of the injection fix —
  `nemesis-dash` has no crontab access under `NoNewPrivileges=yes` (PUNCHLIST, tracked today).
- Decision B — host-defense layer (fail2ban, nginx rate-limiting) not shipped via
  `install.sh` (PUNCHLIST, consolidated today).
- Everything carried forward from prior HANDOFFs not touched today: the Rule-8 username
  finding (`9ffac56`), three unrelated temporary sudoers grants, `NEMESIS_AGENT_EXE`'s real
  home path, `migrate_to_opt.sh` fragility, missing ADR for the `/opt` relocation,
  `backupproc.md` unconfirmed for current layout, ADR 0015 vs. venue-guest-network tension,
  no hardware baseline, legal review not started.

## 7. Cross-references

- `docs/handoff/supplements/2026-08-01-001.md` — curated narrative for today.
- `docs/handoff/worklog/2026-08-01-001.md` — Window 2's full raw log.
- `docs/handoff/worklog/2026-08-01-002.md` — Window 1's build session (redacted per Rule 8/10).
- `docs/architecture/0019-deterministic-enforcement-point.md`,
  `docs/architecture/0021-dos-resilience-scoping.md`.
- `docs/audits/roadmap-state-audit-2026-08-01.md` (baseline for tomorrow's Morning Status),
  `docs/audits/adr0019-increment3-counter-agreement-2026-08-01.md`.
- `PUNCHLIST.md` — several new items today, plus Decision B's new durable home.
- Prior day: `docs/handoff/supplements/2026-07-31-001.md`.

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
  hook, derived from `ufw`'s live state. Observe-only in production as of this HANDOFF —
  Increment 4's verdict emission is built but held (§2).
