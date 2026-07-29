# HANDOFF — current state

> Last updated **2026-07-28 (full-day closeout, Window 2)**. Overwritten each closeout (latest
> state wins). Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/accounts/keys
> live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8 (public repo).
>
> 🎯 **Window 1 is running a ~4hr penetration test tonight** against an isolated Linux host and
> a Windows 11 agent (a separate, isolated test lab — NOT production). Production Nemesis
> (`/opt/nemesis`) is uninvolved and, as of this closeout, healthy: all 9 services
> active/running/0 restarts, tree clean, `HEAD` == `origin/main`. Both windows should come up
> fresh tomorrow morning — read this file first.
> ✅ **core_module layout move is 5/6 complete.** Six daemons relocated from `alert_manager/`
> into per-process `core_module/<name>/` directories; five have had their old `alert_manager/`
> copy removed (Commit B). `alert_watcher` is the one holdout — see Open Items #1, it's a real,
> understood block, not neglect.
> ⚠️ **New Rule-8 finding tonight, not yet acted on:** a commit message already in public
> history quotes a literal real username. See Open Items #2 — needs an operator decision, not a
> unilateral fix, especially not right before tonight's test.
> ✅ **The install.sh core_module gap (found during today's Commit-B work) is fixed and
> verified** — fresh installs now correctly resolve migrated-service units.

---

## Today's arc (2026-07-28) — five threads across one long session

Full raw log: `docs/handoff/worklog/2026-07-28-001.md`. Curated narrative:
`docs/handoff/supplements/2026-07-28-001.md`. Summary:

1. **Morning audit** found and fixed a real gap: `dashboard.service`'s deliberate hardening
   exception (see below) wasn't codified in `gen_units.py` — a future regeneration could have
   silently hardened it and broken `sudo -n ufw`. (`bc36219`, `bd23f2b`) Also fixed CLAUDE.md's
   remaining stale `~/dashboard` paths. (`ebd3bf6`)
2. **CSRF fix** — three quarantine/action routes were GET-as-write; now POST-only.
   Window 2 edited `dashboard.py` directly (user-authorized, urgent — Window 1 was blocked on
   it). (`8c8bce9`, amended from `e7360d5` to fix a wrong cross-reference in the message)
3. **`nemesis_fwd.py`** — a new privileged ufw-helper process with three independent
   verification layers (kernel-verified peer identity via `SO_PEERCRED`, a users-table
   admin-account lookup, a bcrypt credential check) plus `PEER_POLICY` per-peer op
   allowlists, deploy tooling, and (later) tiered account lockout matching `dashboard.py`'s own
   scheme. (`3cf0e4d`, `7d4999a`, `401b58d`)
4. **Design capture** — ADR 0018 (attacker-resistant backup medium protection + manifest-based
   recovery) and a roadmap stub for three future Windows-agent requirements tied to the paused
   memory-injection module. (`045cedc`, `2c2d580`, `04a3b88`)
5. **Data Manager v1.1** — explicit table lists, three-state enforcement modes, column-level
   grants. (`c10a9d3`)
6. **core_module layout move** — six daemons relocated from `alert_manager/` into
   `core_module/<name>/`, copy-then-delete across two commits per service. Commit A (additive,
   all six) landed, then Commit B (remove the old copy) landed for five of six. (`9ffac56`,
   `eb5a35b`, `04c9e11`, `85e2baa`, `dd95de1`, `fbce915`) — see the state table below.

Two private audits ran alongside (kept out of the public repo per Rule 10 — read as an attack
roadmap otherwise): dashboard's sensitive-action surfaces vs. the three-layer-verified pattern,
and the core_module identity/DB-access landscape. Both in
`~/work/nemesis-internal/known-limitations/`.

**Review discipline caught five real bugs today, all held and re-verified before landing** (not
trusted from a handoff claim) — see the supplement for full detail on each: a Data Manager
`executescript()` NameError, missing test coverage for the same retrofit, a
`migrate_core_module.sh --verify` silent-abort bug (`set -euo pipefail` + grep-no-match), the
`install.sh` core_module blind spot, and — most recently — two live consumers of the old
`alert_watcher.py` path that contradicted a "confirmed not imported anywhere" claim.

## core_module layout — current state

```
alert-watcher        core_module/alert_watcher/alert_watcher.py             LIVE, old alert_manager/ copy STILL PRESENT
hw-monitor            core_module/hw_monitor/hw_monitor.py                   LIVE, old copy REMOVED (Commit B done)
device-scanner       core_module/device_scanner/device_scanner.py           LIVE, old copy REMOVED (Commit B done)
watchdog              core_module/watchdog/watchdog.py                       LIVE, old copy REMOVED (Commit B done)
malware-canary       core_module/malware_canary/malware_canary.py           LIVE, old copy REMOVED (Commit B done)
diagnostics-watcher  core_module/diagnostics_watcher/diagnostics_watcher.py  LIVE, old copy REMOVED (Commit B done)
```

All six systemd units already point at `core_module/<name>/` in production (independently
confirmed via `systemctl show -p ExecStart`, not just read from a handoff claim) — the
remaining `alert_watcher.py`/`alert-watcher.service` files sitting in `alert_manager/` are
dead weight, not live, but can't be deleted yet (see Open Items #1). `dashboard` and
`nemesis-fwd` remain in `alert_manager/` by design (not part of this move);
`vpn-dns-guard` remains in `core/` by design.

## Open items

1. **`alert_watcher.py` Commit B is blocked on two fixes, held from landing tonight:**
   - `alert_manager/test_quarantine.py:29-30` — `sys.path.insert(0, .../alert_manager)` then
     `import alert_watcher`; needs the path updated to resolve from `core_module/alert_watcher/`
     once the old copy is gone.
   - `scripts/deploy_nemesis_fwd.sh:82`, `check_sources()` — hardcodes
     `alert_manager/alert_watcher.py` in its required-files list; needs updating to
     `core_module/alert_watcher/alert_watcher.py` or every future ufw-helper deploy preflight
     will hard-fail once the old file is gone.
   Both are small, mechanical fixes — Window 1's lane. Once landed, Window 2 re-verifies (test
   still imports cleanly, `check_sources()` still passes) before the final Commit B.
2. **NEW Rule-8 finding (found at tonight's closeout sweep, not yet acted on):** commit
   `9ffac56`'s own message quotes the literal real install username instead of a placeholder —
   it's in public git history a second time, in the commit log itself, in a commit made *after*
   the 2026-07-26 scoped history rewrite (so it postdates the cleaned history and isn't covered
   by it). A rewrite is significant and hard to reverse — **needs an explicit operator decision,
   not a unilateral fix**, and deliberately not actioned tonight, hours before a live test.
   Flagged in `PUNCHLIST.md` for follow-up.
3. **Three temporary sudoers grants still present** (confirmed via direct `ls
   /etc/sudoers.d/` tonight): the de-privileging/relocation-era grants remain live. Carried
   forward unresolved from 07-27 — no action taken today, not urgent, but should be cleaned up
   once the de-privileging effort is fully closed out.
4. **`/etc/nemesis.env` line 18, `NEMESIS_AGENT_EXE`, still holds a real home path** —
   unchanged since 07-27; deliberately not granted to Window 1 (write access to that file means
   rewriting all 16 secrets).
5. **`migrate_to_opt.sh` should not be run by anyone else as-is** — carried forward from the
   07-27 incident; the script still doesn't deploy unit files itself and `--verify` still
   doesn't check unit-path correctness. Unrelated to (and does not overlap with) tonight's
   core_module tooling, which is a separate, newer script (`migrate_core_module.sh`) built with
   this exact failure mode in mind from the start.
6. **`device_scanner.py`'s `scan_network()` still shells out via unconditional `sudo nmap`** —
   carried forward from 07-27, re-confirmed still true during today's core_module identity/DB
   audit. The unit's `CAP_NET_RAW` grant isn't used at the code level yet. Window 1's lane.
7. **No ADR written yet for the relocation + de-privileging model** (carried forward from
   07-27 as "ADR 0017 needed") — still undone; ADR 0018 landed today but covers backup design,
   not this. Architecturally significant and currently documented only in commit messages.
8. **`docs/operations/backupproc.md` still not re-verified against the `/opt/nemesis` layout**
   — read today; it turns out to be written path-agnostically (references "the dashboard
   service" / "the dashboard project", not a literal old path), so it may not need an edit, but
   the actual revert procedure has not been re-run against the current layout. Treat as
   unconfirmed until it is.
9. **Six files still compute raw tree-relative `alerts.db` paths** (carried forward from
   07-27) — `alert_manager/test_quarantine.py`, three `scripts/stage2_migrate_*`,
   `scripts/wal_concurrent_smoketest.py`, `test_anomaly_cleanup.py`. Note:
   `test_quarantine.py` is both this AND item #1's blocker — same file, two separate reasons
   it needs attention.
10. **`nemesis_fwd.py` connection-leak** (found during today's core_module identity/DB audit,
    private): `_db()` returns a plain `sqlite3.Connection` used via `with _db() as conn:` in
    four places — the context manager only handles the transaction, never closes the
    connection, leaking one per call. Documented privately, not fixed tonight.
11. **`device_scanner.py`/`dashboard.py` have no attestation call** (carried forward,
    cosmetic) — their units declare `NEMESIS_EXPECT_USER` and nothing reads it.
12. **`dashboard.py` has a duplicate `sys.path.insert`** (carried forward, cosmetic) — 4
    occurrences (lines 6, 19, 75, 107).
13. **ADR 0015 vs. `venue-guest-network.md` tension** (carried forward) — needs an operator
    decision before either guest-enrollment vision gets built.
14. **No target hardware baseline exists** (carried forward) — blocks turning L3/Tier-1/Tier-2
    scoping docs into real session estimates.
15. **Legal review** (carried forward) — hard prerequisite for ADR 0016's PII-collection half,
    not started.

**Resolved since 07-27:** `.nemesis-premigration-mode` is now gitignored (confirmed present in
`.gitignore`) — the file is still on disk (harmless, root-owned, gitignored) but no longer
makes the tree dirty or threatens `migrate_to_opt.sh`'s preflight. 07-27's item #1 closed.

## Roadmap baseline

`docs/audits/roadmap-state-audit-2026-07-28.md` — **4 SHIPPED / 8 PARTIAL / 52 STUB/PARKED, 64
total.** Drift since the 07-26 baseline: +1 file (`windows-agent-memory-injection-rework-
prereqs.md`, added today, correctly PARKED); no items shipped or moved.

## Current state — de-privileging model (paths updated for the core_module move; users/hardening posture unchanged since 07-27)

```
dashboard            <user>            /opt/nemesis/dashboard.py                     (NOT hardened, deliberate)
watchdog              nemesis-watchdog  core_module/watchdog/watchdog.py
hw-monitor            nemesis-hwmon     core_module/hw_monitor/hw_monitor.py
alert-watcher        nemesis-alertw    core_module/alert_watcher/alert_watcher.py
device-scanner       <user>            core_module/device_scanner/device_scanner.py  (retains CAP_NET_RAW)
malware-canary       nemesis-canary    core_module/malware_canary/malware_canary.py
diagnostics-watcher  nemesis-diag      core_module/diagnostics_watcher/diagnostics_watcher.py
vpn-dns-guard        nemesis-vpndns    core/vpn_dns_guard.py
nemesis-fwd          (dedicated user)  alert_manager/nemesis_fwd.py                  (new today)
```

`systemd-analyze` exposure and UID details unchanged since 07-27 (not re-measured tonight — no
hardening directives changed today, only file locations). **Dashboard remains deliberately
unhardened** — see below for the full reasoning (still current, not revisited today).

## THE INCIDENT (2026-07-27, ~25 min degraded production) — historical, still worth reading
before touching `migrate_to_opt.sh`

The operator ran `scripts/migrate_to_opt.sh --run` for real. Code and DB moved cleanly, but the
migration script does not deploy unit files — all 8 units still pointed at the deleted old
path, and `do_migrate`'s end-of-run restart drove all 8 into crash loops. Recovered forward,
one service at a time. Root cause is still an open item (#5 above) — `migrate_to_opt.sh` was
not touched today; the core_module tooling built today (`migrate_core_module.sh`) was
deliberately designed around this exact failure mode (copy-then-delete, unit redeployed before
restart, preflight that the new `ExecStart` path exists) and has been proven not to repeat it,
five services deep.

**Dashboard is deliberately not hardened.** `NoNewPrivileges=yes` makes the kernel ignore
setuid, so sudo cannot elevate under it — proven, not assumed. A hardened dashboard would
start, look healthy, and be unable to perform the operations it still shells out for.

**The ADR-0005 ufw chokepoint migration is COMPLETE** (corrected 2026-07-29 by the §9
dashboard-identity audit; this section previously said "in progress, not complete"). All six
firewall operations — `block_ip`, `deny_ip`, `unblock_ip`, `expire_quarantine`, `list_blocked`,
`list_rules` — route through `fw_client` to `nemesis_fwd`, and `alert_manager/firewall.py`
now contains no `subprocess` call and no `sudo` at all.

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
on 2026-07-26 (pre-relocation). The doc itself reads path-agnostic (see Open Items #8) but the
actual procedure has not been re-run against the current `/opt/nemesis` + core_module layout.
**If tonight's pen test needs this, treat it as unconfirmed and proceed carefully** — but note
the pen test targets a separate, isolated lab (Linux host + Windows 11 agent), not this
production box, so this fallback should not be needed tonight.

## Pointers
- Today's narrative: `docs/handoff/supplements/2026-07-28-001.md`; raw log:
  `docs/handoff/worklog/2026-07-28-001.md`.
- Prior narratives: `docs/handoff/supplements/2026-07-27-001.md`, `2026-07-26-001.md`,
  `2026-07-25-001.md` (morning audit), `-002.md` (ADR 0006 build), `-003.md` (loader-enforcement
  + L3 consolidation), `2026-07-02-001.md`.
- Private module + audit docs (outside this repo): `~/work/nemesis-internal/`, specifically
  tonight's two new audits under `known-limitations/`
  (`dashboard-sensitive-surfaces-audit-2026-07-28.md`,
  `core-module-identity-and-db-audit-2026-07-28.md`).
- Fallback: `docs/operations/backupproc.md` (unconfirmed for current layout, see above); tag
  `pre-l1l2l3-build-known-good` (`14b066b`).
- Latest audits: `docs/audits/roadmap-state-audit-2026-07-28.md`.
- Real IPs/hosts/accounts/keys: `~/work/nemesis-private/local-config.md` (outside repo).

## Topology (durable, unchanged)
- `:80` nginx (Basic-auth; auth-bypass for `/install/windows/` + `/api/health`).
- `:5000` Flask dashboard (ufw-blocked from LAN). `:5001` hw-monitor agent endpoint
  (`/enroll`, `/enrollment_status`, `/hw_data`, `/api/agent/uninstall`, `/reputation_dataset` live).
- `:5002` agent command listener — localhost-bound + unauthenticated.
- `nemesis-fwd` (new today) — a Unix-socket-based privileged helper for ufw operations,
  reachable only by the dashboard and alert-watcher peers, each independently verified via
  kernel-level peer credentials + an admin-account + credential check.
