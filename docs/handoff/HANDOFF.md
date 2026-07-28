# HANDOFF — current state

> Last updated **2026-07-27 (full-day closeout, Window 2)**. Overwritten each closeout (latest
> state wins). Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/accounts/keys
> live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8 (public repo).
>
> 🚨 **THE INSTALL LOCATION CHANGED TODAY.** `~/dashboard` → **`/opt/nemesis`** (code) and
> **`/var/lib/nemesis`** (database). `/home/<user>/dashboard` no longer exists as a git repo.
> Every doc that says `~/dashboard` or `/home/<user>/dashboard` — including **CLAUDE.md's own
> "Key paths" section and its Morning Status commands** — is now wrong. Not fixed tonight
> (flagged as tomorrow's top priority below); until it is, `find ~/dashboard` and
> `git -C ~/dashboard` in CLAUDE.md will silently return nothing.
> ✅ **Six of eight services no longer run as root** — dedicated per-service system users,
> kernel-verified privilege attestation, `systemd-analyze` exposure 9.6 UNSAFE → 2.0 OK.
> ⚠️ **A real production incident happened today** (~25 min degraded, all 8 services
> crash-looping) and was recovered — see "The incident" below. Root cause: a migration script
> gap, now itself an open item, not yet fully closed.
> ✅ **Dashboard is deliberately still unhardened** (9.2 UNSAFE) — not an oversight, see below.

---

## The relocation + de-privileging effort (today's session arc)

Started on the PUNCHLIST `[FIX-NOW]` fd-leak. Expanded, via operator decisions through the day,
into: fd-leak fix → a Data Manager gatekeeper assessment → a PostgreSQL evaluation (**deferred**
— measured SQLite/WAL at 18,126–25,619 w/s against a 1,000 w/s worst-case projection, ~25x
headroom; the throughput case didn't survive measurement) → a dedicated-writer-process
assessment (**deferred** — measured Unix-socket IPC at 62,666 w/s, viable but superseded) →
service de-privileging → an `/opt` relocation → a production incident and recovery. Both
deferred assessments live only in conversation right now — flagged for a roadmap
stub/ADR decision, not made yet.

Six commits, all pushed, `HEAD` = `7e804a6`:
```
a38a068  fix(anomaly_detection): guarantee DB connection close on exception
84a57d2  feat(privsep): kernel-verified privilege attestation, wired into all six services
597c302  feat(paths): canonical DB path resolver, staged for the /opt relocation
a133892  feat(scripts): /opt relocation migration tool, VM-proven
5e9fcc0  feat(units): /opt layout + per-service de-privileging across all 8 units
7e804a6  fix(paths,privsep): complete the DB-path migration and make services start under /opt
```

Three bugs were caught in review and held before landing (details:
`docs/handoff/supplements/2026-07-27-001.md`): a standalone `--verify` false-fail in
`migrate_to_opt.sh`, four systemd units silently losing real ordering dependencies on
regeneration (fixed with an explicit `after`/`wants` list model plus a new
`gen_units.py --check` drift guard), and a rollback warning pointing at a snapshot path
nothing created (fixed by having `install.sh` actually create it).

## THE INCIDENT (2026-07-27, ~25 min degraded production) — read before touching migrate_to_opt.sh

The operator ran `scripts/migrate_to_opt.sh --run` for real. Code and DB moved cleanly
(integrity confirmed), but the migration script does **not** deploy unit files (`install.sh`
does) — so all 8 deployed units still pointed at the now-deleted `/home/<user>/dashboard`.
`do_migrate` restarts every service at the end of its run; with stale units this drove all 8
into crash loops (`dashboard` hit `StartLimitBurst`/`failed`; the other 7 hit
`INVALIDARGUMENT`/"can't open file", restart counters 23+). Recovered forward, one service at
a time, verifying each.

**Current state independently re-confirmed via `systemctl show` (not relayed):** all 8
services `active`/`running`, `NRestarts=0`, correct `/opt/nemesis` `ExecStart` paths.

**`migrate_to_opt.sh` should not be run by anyone else as-is** (open item below) — it must
either deploy units itself or refuse to restart services when the installed units still
reference the old path. `--verify` also still doesn't check unit-path-correctness at all
(only code location, DB location, old-path-gone) — a different gap from the standalone
`--verify` bug fixed earlier the same day.

## Current state — de-privileging model

```
dashboard            <user>              /opt/nemesis/dashboard.py            (NOT hardened, see below)
watchdog             nemesis-watchdog  /opt/nemesis/alert_manager/watchdog.py
hw-monitor           nemesis-hwmon     /opt/nemesis/alert_manager/hw_monitor.py
alert-watcher        nemesis-alertw    /opt/nemesis/alert_manager/alert_watcher.py
device-scanner       <user>              /opt/nemesis/alert_manager/device_scanner.py
malware-canary       nemesis-canary    /opt/nemesis/alert_manager/malware_canary.py
diagnostics-watcher  nemesis-diag      /opt/nemesis/alert_manager/diagnostics_watcher.py
vpn-dns-guard        nemesis-vpndns    /opt/nemesis/core/vpn_dns_guard.py
```

`systemd-analyze` exposure: 9.6 UNSAFE → 2.0 OK for the six de-privileged services;
device-scanner 2.2 (retains `CAP_NET_RAW`, see Open Items #10 below); dashboard unchanged at
9.2 UNSAFE, deliberately. UIDs for the six confirmed directly (`id`): 985/990/991/992/993/994,
all `gid=972 (nemesis-db)`. Attestation: kernel-verified at runtime (euid, `CapEff`,
`NoNewPrivs` read from `/proc/self/status`), never inferred from the unit file — the pattern
follows a private L3 `SYSTEMD_FAIL_OPEN` finding (a unit that asks for isolation it cannot get
starts anyway, unrestricted). Journal confirmation of the attestation lines and the live
`/etc/sudoers.d/` listing were **not independently verifiable this session** (no passwordless
sudo available) — see Open Items #3.

**Dashboard is deliberately not hardened.** It elevates via `sudo -n` in ~10 places, including
`alert_manager/firewall.py` (the ADR-0005 ufw chokepoint). `NoNewPrivileges=yes` makes the
kernel ignore setuid, so sudo cannot elevate under it — proven, not assumed (`sudo -n ufw
status` succeeds normally, fails under `--no-new-privs`). A hardened dashboard would have
started, looked healthy, and been unable to block or quarantine anything — a silent loss of a
core security function. The unit carries an in-file comment explaining this; do not add
hardening directives to it before the `firewall.py` sudo call sites are rewritten to use a
capability directly (deferred to tomorrow, operator-confirmed, do not scope tonight — the
CAP_NET_RAW/CAP_NET_ADMIN rewrite of `firewall.py` and the other sudo call sites, matching the
device-scanner precedent, is what closes dashboard's 9.2 score).

Data: `/var/lib/nemesis/alerts.db`, `<user>:nemesis-db 0660`, directory 0770 (load-bearing, not
0750 — SQLite WAL mode creates `-wal`/`-shm` siblings in the directory, and 0750 reproduces the
same "attempt to write a readonly database" failure behind the 2026-07-18 fd-exhaustion
incident).

## Open items

1. **`.nemesis-premigration-mode` is untracked and not gitignored** — confirmed at the
   `/opt/nemesis` repo root (content: mode `775`, path `/home/<user>/dashboard`). The only thing
   making the tree dirty; will fail `migrate_to_opt.sh`'s own dirty-tree preflight on any
   future run. Needs a `.gitignore` entry.
2. **`/etc/nemesis.env` line 18, `NEMESIS_AGENT_EXE`, still holds a `/home/<user>` path** —
   confirmed by direct read. Not corrected during the migration; deliberately not granted to
   Window 1, since write access to that file means the ability to rewrite all 16 secrets.
3. **Three temporary sudoers grants need removal at end-of-effort:**
   `nemesis-deprivilege-step1`, `nemesis-relocation`, `nemesis-dashboard-unit`. Only partially
   corroborated this session (via the pre-migration USB snapshot, which predates incident
   recovery and shows 2 of the 3 plus two others not in this list) — confirm the actual live
   `/etc/sudoers.d/` before removing anything.
4. **`migrate_to_opt.sh` should not be run by anyone else as-is** — the defect behind tonight's
   incident (see above).
5. **PUNCHLIST fd-leak entry was stale — corrected this session.** Root cause was never
   `eve.json` handling; it was unclosed SQLite connections in `_set_state`, fixed in `a38a068`.
6. **`docs/reference/operational-notes.md` still carries the same stale eve.json framing** —
   flagged, not fixed tonight (prose, deserves its own pass).
7. **Six files still compute raw tree-relative `alerts.db` paths** — all historical/test
   tooling, no production service: `alert_manager/test_quarantine.py`, three
   `scripts/stage2_migrate_*`, `scripts/wal_concurrent_smoketest.py`, `test_anomaly_cleanup.py`.
8. **`device_scanner.py` and `dashboard.py` have no attestation call** — their units declare
   `NEMESIS_EXPECT_USER` and nothing reads it. Cosmetic.
9. **`dashboard.py` has a duplicate `sys.path.insert`** — 4 occurrences total (lines 6, 19, 75,
   107), not just the 2 originally flagged.
10. **`device_scanner.py`'s `scan_network()` still shells out via `["sudo", "nmap", ...]`
    unconditionally** — no code path uses the unit's new `AmbientCapabilities=CAP_NET_RAW`
    instead. The "CAP_NET_RAW replaces the unrestricted sudo nmap grant" framing from the units
    commit isn't realized at the code level yet: either the old sudoers grant is still live and
    now redundant, or it was revoked and the scanner is silently broken. Needs a code decision
    (Window 1's lane).
11. **ADR 0015 vs. `venue-guest-network.md` tension** (carried forward from 07-26) — needs an
    operator decision before either guest-enrollment vision gets built.
12. **No target hardware baseline exists** (carried forward) — still blocks turning any
    L3/Tier-1/Tier-2 scoping doc into a real session estimate.
13. **Legal review** (carried forward) — hard prerequisite for ADR 0016's PII-collection half,
    not yet started.

## Roadmap baseline

`docs/audits/roadmap-state-audit-2026-07-26.md` — **4 SHIPPED / 8 PARTIAL / 51 PARKED, 63
total.** Unchanged — no `docs/roadmap/*.md` files were touched by any of today's six commits
(all code fixes for the relocation/de-privileging effort), so no re-audit was needed.

## Docs that need the path fixed — TOP PRIORITY for tomorrow

Flagging only, not done tonight (a ~28-reference edit deserves its own pass, not a rushed
tack-on at the end of a long session) — but this is the single highest-priority open item,
since leaving it stale actively breaks the morning routine rather than just reading oddly:
- **CLAUDE.md "Key paths"** — every path is wrong.
- **CLAUDE.md's own Morning Status commands** — `find ~/dashboard` / `git -C ~/dashboard` will
  silently return nothing starting tomorrow.
- **`docs/operations/backupproc.md`** — references the old location and the DB's old in-tree
  position.
- **New ADR needed** (probably 0017) — the relocation + de-privileging model (per-service
  users, `nemesis-db` group, runtime attestation, the dashboard carve-out) is architectural and
  currently undocumented anywhere except commit messages and this handoff.
- **ADR 0003** — its backup design remains unimplemented; the DB has moved, changing what a
  backup targets.
- **Rule 10 decision needed, not made tonight:** the attestation pattern derives from a private
  L3 `SYSTEMD_FAIL_OPEN` finding. The general approach (assert privilege at runtime, never
  trust the unit file) reads as publishable; the L3 harness detail stays private.

## LIVE vs DEFAULT-OFF (and why) — unchanged since 2026-07-02, still current

| Capability | State | Why |
|---|---|---|
| **Feature 6** — IP-reputation cache | **ON** (observation-only) | Never enforces; agent pulls the server dataset for local measurement. |
| **Feature 6 server endpoint** `GET /reputation_dataset` | **LIVE** | Serves real rows, no regression. |
| **L1** — DNS enforcement plumbing | **default OFF** | Blocked by the unresolved ADR 0005 "Pi-hole refuses tunnel-sourced queries" problem. |
| **L2** — WinDivert reputation blocking | **default OFF globally** | Validated 2026-07-02; per-device toggle still unbuilt. |
| **L2 on the trip-laptop** | **ON** (that one installer only) | Global default unchanged. |

## Emergency fallback — NEEDS RE-VERIFICATION, path changed today

`docs/operations/backupproc.md` — Procedure A (local uninstall) and Procedure B (Claude Code
revert prompt). Revert tag `pre-l1l2l3-build-known-good` → `14b066b`, last verified byte-exact
on 2026-07-26 (pre-relocation). **Not re-verified against the new `/opt/nemesis` layout** — the
doc itself still references the old location (see "Docs that need the path fixed" above).
Treat this procedure as unconfirmed for the current install until that doc is updated and
re-tested.

## Pointers
- Today's narrative: `docs/handoff/supplements/2026-07-27-001.md`.
- Prior narratives: `docs/handoff/supplements/2026-07-26-001.md`, `2026-07-25-001.md` (morning
  audit), `-002.md` (ADR 0006 build), `-003.md` (loader-enforcement + L3 consolidation),
  `2026-07-02-001.md`.
- Snapshots (USB, both directions verified restorable):
  `2026-07-27-1846-pre-opt-migration-run` (current rollback target),
  `2026-07-27-1625-pre-opt-relocation` (superseded), `2026-07-27-1537-pre-service-deprivileging`.
- Private module + evaluation docs (outside this repo): `~/work/nemesis-internal/`.
- Fallback: `docs/operations/backupproc.md` (needs re-verification, see above); tag
  `pre-l1l2l3-build-known-good` (`14b066b`).
- Latest audits: `docs/audits/roadmap-state-audit-2026-07-26.md`.
- Real IPs/hosts/accounts/keys: `~/work/nemesis-private/local-config.md` (outside repo).

## Topology (durable, unchanged)
- `:80` nginx (Basic-auth; auth-bypass for `/install/windows/` + `/api/health`).
- `:5000` Flask dashboard (ufw-blocked from LAN). `:5001` hw-monitor agent endpoint
  (`/enroll`, `/enrollment_status`, `/hw_data`, `/api/agent/uninstall`, `/reputation_dataset` live).
- `:5002` agent command listener — localhost-bound + unauthenticated.
