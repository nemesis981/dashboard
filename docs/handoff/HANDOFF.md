# HANDOFF — current state

> Last updated **2026-07-29 (full-day closeout, Window 2)**. Overwritten each closeout (latest
> state wins). Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/accounts/keys
> live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8 (public repo).
>
> ✅ **core_module layout move is now COMPLETE (6/6).** `alert_watcher` — yesterday's holdout —
> was unblocked and its stale `alert_manager/` copy removed. All six daemons now live
> exclusively in `core_module/<name>/`.
> ✅ **Ransomware canary incident is root-caused and closed**, five bugs deep (see below) — not
> just the two out-of-repo preconditions recorded mid-day, but also dedup/cooldown and the
> underlying `isfile()`-ambiguity fix that landed later in the evening.
> ✅ **Data Manager: all seven `dashboard.py` table-ownership conflicts resolved**, and every
> DB site in `dashboard.py` (read and write) now routes through the guard — zero raw
> `sqlite3.connect(DB_PATH)` sites remain. Namespace stays **WARN mode**, not ENFORCE, by
> deliberate choice pending a quiet-journal period.
> ✅ **Host-defense step 0 landed and appears deployed** (LAN-scan gating, a narrow `fail2ban`
> `nemesis-fwd` peer, `:5001` pacing) — directly answers last night's pen-test finding of zero
> host self-defense. Service restart timestamps confirm both `nemesis-fwd` (18:15) and
> `hw-monitor` (20:07) restarted after the 17:54 commit, but this is deploy confirmation only —
> **not yet functionally verified** (no test traffic run against the new gating/pacing tonight).
> ⚠️ **Rule-8 finding from last night is still open, unchanged** — commit `9ffac56`'s message
> quotes a literal real install username. Still needs an explicit operator decision (rewrite
> vs. accept as residual). See Open Items below.
> 🆕 **Private-module remote policy changed today (operator decision):** new private modules
> default to **local + USB only, no GitHub remote**. `l3-tier2-tls-interception`'s existing
> three-remote setup (incl. GitHub) is flagged as a pre-existing exception, left open.

---

## Today's arc (2026-07-29) — seven threads, a very full day

Full raw log: `docs/handoff/worklog/2026-07-29-001.md`. Curated narrative:
`docs/handoff/supplements/2026-07-29-001.md`. Summary:

1. **core_module layout move finished (6/6)** — `alert_watcher`'s two blockers fixed
   (`test_quarantine.py` import path + a `DB_PATH` bug that was silently testing against an
   empty stray DB instead of the live one), stale copy removed. Same window fixed
   `nemesis_fwd.py`'s per-request fd leak (Open Item #10, now deployed — see below).
   (`e76b964`, `bfd7983`, `a096def`, `eeb5218`)
2. **device-scanner fixes** — macvendors.com error bodies were being stored verbatim as
   device names; `sudo nmap` was dead under `NoNewPrivileges` with no failure signal
   (Open Item #6, now resolved), replaced with an unprivileged scan. (`459585b`, `5849a3b`)
3. **Data Manager rollout** — thirteen commits taking the "dashboard" namespace from
   WARN-mode-with-seven-conflicts to all conflicts resolved and every DB site routed through
   the guard. Caught a dashboard root-logger bug (`log.info()` going nowhere) and a
   `settings_page()` `NameError` silently reverting security settings to default on every page
   load. (`5bd6259`→`5e9e23d`)
4. **Severity/vocabulary consolidation** — one shared severity ladder (fixing a live bug
   where lowercase `"critical"` never crossed a ticket threshold) and canonical-uppercase
   malware vocabulary with case-insensitive reads. (`0b404f4`, `0e571f2`, `ed2c889`)
5. **Process rules** — Window 3 formalized (overflow, never a git-writer); Rule 11 (test data
   in live `alerts.db` must be labeled). (`79f1c06`, `941ec51`)
6. **Ransomware canary incident, closed** — `ProtectHome=yes` had blinded the canary since
   2026-07-25 (~33,500 false CRITICALs, mail rate limit exhausted, zero real detection). Five
   fixes: the masking itself, non-atomic plant+baseline, the missing traverse ACL, dedup/cooldown,
   and the `isfile()`-ambiguity underneath all of it. (`7373b10`, `9cc7746`, `c40f53d`,
   `1705e9c`, `d577e10`)
7. **Fork B / host-defense (evening)** — fixed flask-login missing from install.sh (had
   silently broken ticket-filing for 3 of 4 services), added Fork B source-NAT, removed two
   never-implemented `nemesis-fwd` ops, then shipped host-defense step 0 responding to last
   night's pen-test gap. (`2530977`, `517b1e0`, `8c28525`, `480b1c8`, `1d63734`, `19c783f`,
   `86a4c47`)

Closeout (Window 2): diff-audited and pushed `800b5e2`/`31aee8f` (ADR 0019 stub — full
writeup kept private per Rule 10 in a new `~/work/nemesis-internal/firewall-enforcement-engine/`
repo, local+USB remotes only; Headscale VPN-swap evaluation, capture-only, recommendation: do
not migrate). Found and, on operator confirmation, committed two more files left uncommitted by
a concurrent Window 1/3 session: the private-module remote policy change and an ADR 0019
scope-boundary addition (`e9dab6e`, `2b75b27`).

**Nine bugs fixed today**, all named in commit messages, not trusted from a handoff claim — see
the supplement for the full list with commit hashes.

## core_module layout — COMPLETE

```
alert-watcher        core_module/alert_watcher/alert_watcher.py             LIVE, old copy REMOVED
hw-monitor            core_module/hw_monitor/hw_monitor.py                   LIVE, old copy REMOVED
device-scanner       core_module/device_scanner/device_scanner.py           LIVE, old copy REMOVED
watchdog              core_module/watchdog/watchdog.py                       LIVE, old copy REMOVED
malware-canary       core_module/malware_canary/malware_canary.py           LIVE, old copy REMOVED
diagnostics-watcher  core_module/diagnostics_watcher/diagnostics_watcher.py  LIVE, old copy REMOVED
```

All six daemons now live exclusively in `core_module/<name>/`; `alert_manager/` retains only
`dashboard.py` and `nemesis_fwd.py` (by design) plus non-code artifacts (logs, `.db` files).
`vpn-dns-guard` remains in `core/` by design.

## Ransomware canary — root-caused and closed (2026-07-29)

The Layer-B canary had **two out-of-repo preconditions** missing between 2026-07-25 and
2026-07-29 (~33,500 false CRITICAL findings, zero real tickets, the outbound mail rate limit
exhausted at 14,441 failed sends, no actual detection capability the entire time):

1. **`malware-canary.service` must not run with `ProtectHome=yes`** — masked `/home` in the
   unit's mount namespace, so every bait file read as `deleted / encrypted-in-place`.
   `scripts/gen_units.py` now sets `ProtectHome=read-only` for this unit alone.
2. **`nemesis-canary` must be able to traverse the install user's home** — handled by a
   traverse-only ACL, `install.sh` now applies it and installs the `acl` package explicitly:
   ```
   setfacl -m u:nemesis-canary:--x /home/<install-user>
   ```

Fixing visibility surfaced (and required fixing) three more bugs, all now landed:

3. **Non-atomic plant+baseline** — would have kept false-tripping even after visibility was
   restored, because the baseline dated from a stale re-plant. Fixed atomically; bait filenames
   are now plausible document names (`Account passwords.docx`, …) instead of a shared
   self-identifying label — trade-off: hides the trap from a targeted attacker, but loses the
   old protection against the *user* deleting bait and false-tripping.
4. **No dedup/cooldown** — one stuck condition was capable of flooding alerts/emails.
   Verified: a 4-file deletion now produces exactly 4 rows, then goes silent across subsequent
   polls until the condition changes.
5. **The root ambiguity underneath all of it** — `os.path.isfile()` returning `False` meant
   either "genuinely deleted" or "I can't see this directory," indistinguishable. Now
   disambiguated by parent-directory visibility; the same fix was applied to
   `_module_enabled()`'s DB-read-error-reads-as-disabled bug (101 skipped polls had been
   silently misreported as self-gated-off rather than as a failed check).

**Verifying it is actually working** (all preconditions, one check):
```
grep ' /home ' /proc/$(systemctl show -p MainPID --value malware-canary)/mountinfo
    # a line containing "inaccessible" means precondition 1 is broken
getfacl -p /home/<install-user> | grep nemesis-canary
    # missing means precondition 2 is broken
tail -5 /var/log/nemesis/malware-canary/malware_canary.log
    # healthy looks like: "canary: clean — 4/4 bait ok", no flood of repeated findings
```
Note the daemon logs to that **file**, not the journal — `journalctl -u malware-canary` shows
only systemd's own lines and looks deceptively quiet.

## Data Manager (ADR 0006) — dashboard namespace fully onboarded, still WARN mode

As of tonight, the "dashboard" namespace has **all seven table-ownership conflicts resolved**
(`enrollment_tokens`/`agent_devices` via column grants; `scan_jobs`/`audit_log`/`users` as
genuine shared writers; `scan_threats`/`scan_schedules` DDL relocated to `database.py`,
dropping `hw_monitor`'s now-unneeded grant) and **zero raw `sqlite3.connect(DB_PATH)` sites
remain in `dashboard.py`** — every read and write site routes through `_dm_conn()`.

The namespace is deliberately still registered in **WARN mode, not ENFORCE** — same discipline
used for other namespaces: prove clean via a quiet journal period before flipping the switch.
Not yet scheduled; treat as an open item if it's been quiet a while and nobody's flipped it.

## Host-defense step 0 (2026-07-29 evening) — landed, deploy-confirmed, NOT functionally verified

Directly responds to last night's 4-hour adversarial test finding of **zero host
self-defense** (668 attacks, no damage, but also no detection against a direct port scan /
flood / SSH brute-force on the Nemesis host itself — see
`docs/testing/adversarial-test-2026-07-29.md`, gitignored/local-only). Three pieces:

- LAN-internal severity now derives from Suricata priority when no external reputation data
  exists (using `not is_global`, not `is_private`, so CGNAT/tailnet sources aren't excluded).
- A new narrow **`fail2ban`** `nemesis-fwd` `PEER_POLICY` peer — `block_ip`/`deny_ip` only,
  structurally unable to release quarantines.
- `:5001` moved to `ThreadingHTTPServer` plus new token-bucket pacing (`agent_pacing.py`).

**Deploy status:** `nemesis-fwd` restarted 18:15, `hw-monitor` restarted 20:07 — both after the
17:54 commit, so both processes are running the new code. **This is deploy confirmation only.**
No test traffic has been run against the new gating/pacing tonight; `NEMESIS_NEVER_BLOCK` status
at deploy time not re-checked in this closeout. Verify before relying on it.

## Open items

1. **NEW (found 2026-07-28 closeout, still unresolved): Rule-8 finding** — commit `9ffac56`'s
   own message quotes the literal real install username instead of a placeholder; it's in
   public git history a second time, postdating the 2026-07-26 scoped rewrite so not covered by
   it. Needs an explicit operator decision (rewrite again vs. accept as residual) — not touched
   today either. See `PUNCHLIST.md`.
2. **NEW (2026-07-29): `l3-tier2-tls-interception`'s three-remote asymmetry** — it predates
   today's local+USB-only default for private modules and still has a GitHub remote, holding
   the *more* sensitive Tier 2 design on the *wider* remote set. Resolving means deleting the
   GitHub repo, not just dropping the remote. Operator's call, deliberately left open.
3. **NEW (2026-07-29): PIA compatibility gap blocking Fork B validation** — PIA is installed
   but left disconnected because Nemesis errors while it's active; filed, not investigated.
4. **Data Manager "dashboard" namespace still WARN, not ENFORCE** — all conflicts resolved and
   all sites migrated; flip is a deliberate, not-yet-scheduled follow-up.
5. **Host-defense step 0 deployed but not functionally verified** — see above; run real test
   traffic against the new LAN-scan gating / fail2ban peer / `:5001` pacing before trusting it
   in an incident.
6. **Three temporary sudoers grants still present** (carried forward from 07-27) — the
   de-privileging/relocation-era grants remain live; not urgent, clean up once de-privileging
   is fully closed out.
7. **`/etc/nemesis.env` line 18, `NEMESIS_AGENT_EXE`, still holds a real home path** —
   unchanged since 07-27; deliberately not granted to Window 1 (write access means rewriting
   all 16 secrets).
8. **`migrate_to_opt.sh` should not be run by anyone else as-is** — carried forward from the
   07-27 incident; still doesn't deploy unit files itself and `--verify` still doesn't check
   unit-path correctness.
9. **No ADR written yet for the relocation + de-privileging model** — carried forward; ADR
   0018/0019 landed since but cover backup design and enforcement-point design respectively,
   not this. Still documented only in commit messages.
10. **`docs/operations/backupproc.md` still not re-verified against the `/opt/nemesis`
    layout** — reads path-agnostic so may not need an edit, but the actual revert procedure
    has not been re-run against the current layout. Treat as unconfirmed.
11. **Five files still compute raw tree-relative `alerts.db` paths** (was six — 
    `test_quarantine.py` fixed today by `e76b964`): three `scripts/stage2_migrate_*`,
    `scripts/wal_concurrent_smoketest.py`, `test_anomaly_cleanup.py`.
12. **`device_scanner.py`/`dashboard.py` have no attestation call** (carried forward,
    cosmetic) — their units declare `NEMESIS_EXPECT_USER` and nothing reads it.
13. **`dashboard.py` has a duplicate `sys.path.insert`** (carried forward, cosmetic) — 4
    occurrences (lines 6, 19, 75, 107).
14. **ADR 0015 vs. `venue-guest-network.md` tension** (carried forward) — needs an operator
    decision before either guest-enrollment vision gets built.
15. **No target hardware baseline exists** (carried forward) — blocks turning L3/Tier-1/Tier-2
    scoping docs into real session estimates.
16. **Legal review** (carried forward) — hard prerequisite for ADR 0016's PII-collection half,
    not started.

**Resolved since 07-28:** alert_watcher Commit B / core_module 6/6 (was Open Item #1);
device_scanner's unconditional `sudo nmap` (was Open Item #6); `nemesis_fwd.py` connection leak,
now confirmed deployed via service restart (was Open Item #10).

## Roadmap baseline

`docs/audits/roadmap-state-audit-2026-07-28.md` — **4 SHIPPED / 8 PARTIAL / 52 STUB/PARKED, 64
total.** No drift today (file-set and shipping both re-checked this morning, confirmed same-commit
baseline). A separate, broader audit landed today —
`docs/audits/proposed-features-status-2026-07-29.md` (all 64 roadmap items + 18 ADRs,
operator-requested) — but it uses a different filename pattern and does not reset this baseline
per the Morning Status routine's resolve-at-runtime rule.

## Current state — de-privileging model (unchanged since 07-28; core_module move now fully
## complete, not 5/6)

```
dashboard            <user>            /opt/nemesis/dashboard.py                     (NOT hardened, deliberate)
watchdog              nemesis-watchdog  core_module/watchdog/watchdog.py
hw-monitor            nemesis-hwmon     core_module/hw_monitor/hw_monitor.py
alert-watcher        nemesis-alertw    core_module/alert_watcher/alert_watcher.py
device-scanner       <user>            core_module/device_scanner/device_scanner.py  (retains CAP_NET_RAW)
malware-canary       nemesis-canary    core_module/malware_canary/malware_canary.py
diagnostics-watcher  nemesis-diag      core_module/diagnostics_watcher/diagnostics_watcher.py
vpn-dns-guard         nemesis-vpndns    core/vpn_dns_guard.py
nemesis-fwd           (dedicated user)  alert_manager/nemesis_fwd.py
```

`systemd-analyze` exposure and UID details unchanged since 07-27 (not re-measured tonight — no
hardening directives changed today, only DB-access routing and application logic).
**Dashboard remains deliberately unhardened** — see below, still current.

## THE INCIDENT (2026-07-27, ~25 min degraded production) — historical, still worth reading
before touching `migrate_to_opt.sh`

The operator ran `scripts/migrate_to_opt.sh --run` for real. Code and DB moved cleanly, but the
migration script does not deploy unit files — all 8 units still pointed at the deleted old
path, and `do_migrate`'s end-of-run restart drove all 8 into crash loops. Recovered forward,
one service at a time. Root cause is still an open item (#8 above) — `migrate_to_opt.sh` was
not touched again today; `migrate_core_module.sh` remains deliberately designed around this
exact failure mode and has been proven not to repeat it, six services deep now.

**Dashboard is deliberately not hardened.** `NoNewPrivileges=yes` makes the kernel ignore
setuid, so sudo cannot elevate under it — proven, not assumed. A hardened dashboard would
start, look healthy, and be unable to perform the operations it still shells out for.

**The ADR-0005 ufw chokepoint migration is COMPLETE.** All six firewall operations —
`block_ip`, `deny_ip`, `unblock_ip`, `expire_quarantine`, `list_blocked`, `list_rules` — route
through `fw_client` to `nemesis_fwd`, and `alert_manager/firewall.py` contains no `subprocess`
call and no `sudo` at all.

What still blocks hardening is therefore NOT firewall.py. It is **seven remaining `sudo` call
sites in `dashboard.py`**, none of them ufw:

```
:558          sudo systemctl status clamav-daemon     read-only status
:5454, :5654  sudo systemctl restart dashboard        self-restart ×2
:5464         sudo bash <uninstall_script> --yes      uninstall
:5568-5570    sudo cp/chown/chmod /etc/nemesis.env    the 16-secret env rewrite
```

Do not add hardening directives to `dashboard.service` until all seven are gone. The
self-restart pair likely resolves to a polkit rule scoped to the Nemesis units (precedent:
`10-nemesis-watchdog.rules`); the `/etc/nemesis.env` rewrite is the hard one and needs its own
design. This half stays PARKED — it is independent of the dashboard DB de-privileging work,
which needs no identity change at all.

## LIVE vs DEFAULT-OFF (and why) — unchanged since 2026-07-02, still current

| Capability | State | Why |
|---|---|---|
| **Feature 6** — IP-reputation cache | **ON** (observation-only) | Never enforces; agent pulls the server dataset for local measurement. |
| **Feature 6 server endpoint** `GET /reputation_dataset` | **LIVE** | Serves real rows, no regression. |
| **L1** — DNS enforcement plumbing | **default OFF** | Blocked by the unresolved ADR 0005 "Pi-hole refuses tunnel-sourced queries" problem. |
| **L2** — WinDivert reputation blocking | **default OFF globally** | Validated 2026-07-02; per-device toggle still unbuilt. |
| **L2 on the trip-laptop** | **ON** (that one installer only) | Global default unchanged. |

## Emergency fallback — still flagged unconfirmed for the current layout

`docs/operations/backupproc.md` — Procedure A (local uninstall) and Procedure B (Claude Code
revert prompt). Revert tag `pre-l1l2l3-build-known-good` → `14b066b`, last verified byte-exact
on 2026-07-26 (pre-relocation). The doc itself reads path-agnostic (see Open Items #10) but the
actual procedure has not been re-run against the current layout. Treat as unconfirmed.

## Pointers
- Today's narrative: `docs/handoff/supplements/2026-07-29-001.md`; raw log:
  `docs/handoff/worklog/2026-07-29-001.md`.
- Prior narratives: `docs/handoff/supplements/2026-07-28-001.md`, `2026-07-27-001.md`,
  `2026-07-26-001.md`, `2026-07-25-001.md` (morning audit), `-002.md` (ADR 0006 build),
  `-003.md` (loader-enforcement + L3 consolidation), `2026-07-02-001.md`.
- Private module + audit docs (outside this repo): `~/work/nemesis-internal/`, specifically
  today's new `firewall-enforcement-engine/` (ADR 0019 full writeup, local+USB remotes only)
  and yesterday's `known-limitations/` audits.
- Fallback: `docs/operations/backupproc.md` (unconfirmed for current layout, see above); tag
  `pre-l1l2l3-build-known-good` (`14b066b`).
- Latest audits: `docs/audits/roadmap-state-audit-2026-07-28.md` (baseline),
  `docs/audits/proposed-features-status-2026-07-29.md` (broader, non-baseline).
- Real IPs/hosts/accounts/keys: `~/work/nemesis-private/local-config.md` (outside repo).

## Topology (durable, unchanged)
- `:80` nginx (Basic-auth; auth-bypass for `/install/windows/` + `/api/health`).
- `:5000` Flask dashboard (ufw-blocked from LAN). `:5001` hw-monitor agent endpoint
  (`/enroll`, `/enrollment_status`, `/hw_data`, `/api/agent/uninstall`, `/reputation_dataset` live;
  now ThreadingHTTPServer + token-bucket pacing, see Host-defense step 0 above).
- `:5002` agent command listener — localhost-bound + unauthenticated.
- `nemesis-fwd` — a Unix-socket-based privileged helper for ufw operations, reachable only by
  the dashboard, alert-watcher, and (new today) fail2ban peers, each independently verified via
  kernel-level peer credentials + an admin-account + credential check.
