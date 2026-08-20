# HANDOFF — current state

> Last updated **2026-08-19, nightly closeout (Window 2)**. Overwritten each closeout (latest
> state wins). Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/
> accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per
> Rule 8.
>
> Full detail behind every claim below: `docs/handoff/supplements/2026-08-19-001.md` (curated)
> and `docs/handoff/worklog/2026-08-19-001.md` (raw log, written live this time — no
> reconstruction-at-closeout gap tonight). Prior day: `docs/handoff/supplements/2026-08-18-001.md`.

---

## 1. Live in production right now — verified fresh, not carried forward

- **`origin/main` is at `ebfa0bb`.** `HEAD` == `origin/main`, confirmed via fetch. 16 commits
  landed and pushed today, none held back.
- **Services were restarted THIS EVENING, by someone other than this window** (this session
  never ran `systemctl restart` on anything — confirmed by never having issued the command).
  `hw-monitor` at 18:34:58, `watchdog`/`alert-watcher`/`diagnostics-watcher` at 18:49:27–28,
  `dashboard` at 20:25:15. `malware-canary` has NOT restarted (unchanged since 2026-08-18
  19:18:54).
- **This means real behavior changed tonight, not just committed code:**
  - **The production memory-injection ladder loop is genuinely running.** `hw-monitor`'s
    restart (18:34:58) came after `059da4b` (16:24:50, the commit that wires
    `run_ladder_cycle` into the sample loop). Verified directly, not inferred from
    timestamps: `mem_ladder_state.sample_seq` is at 23 and incrementing on the expected
    ~5-minute cadence. THROTTLE can now really fire under sustained pressure against the
    four wired services (gentle, fail-safe, `RUNG_AVAILABILITY`-gated, auto-expiring).
  - **RAM recovery is live.** `dashboard`'s restart (20:25:15) came after `368b828`
    (19:54:25) — the `/api/ram-recovery/*` routes and the "Reclaim…" button are reachable.
  - **Tier 2 attestation stays dormant regardless of any restart** — confirmed live that no
    deployed service adds the private module's path to `sys.path`, so `tier2_available()`
    is `False` everywhere in production.
- **⚠ A real gap surfaced verifying the above, not by design review — see §3 item 1.**
  `mem_ladder_state`/`mem_shadow_records`/`agent_attestation_challenges` were never granted
  to `hw_monitor`'s Data Manager namespace. Currently harmless (DataManager write enforcement
  is still WARN-only) but a real gap, filed in PUNCHLIST with citation.
- **Held in the working tree right now, none of it Window 2's, actively in-flight (Window 1,
  mid-task as of this closeout — do not touch):** `alert_manager/fw_client.py`,
  `alert_manager/nemesis_fwd.py`, `alert_manager/tools/make_orphan_shm.py`, `dashboard.py`,
  `static/fw-credential.js`, `static/ram-recovery.js`. Not reviewed or described further here
  — it's still moving. Also still held, unchanged: the three 08-08 error-code-classification
  batch docs (now 11 days unclaimed) and `nemesis_agent/tools/win_priv_probe.py`.

## 2. What shipped today (16 commits)

Full commit-by-commit detail: `docs/handoff/supplements/2026-08-19-001.md`.

1. `72a7ed0` / `88802c1` — held malware-scan privilege-fix batch (`CAP_DAC_READ_SEARCH`
   engine, `PrivateTmp` fix) + its mountinfo startup guard follow-up.
2. `d9ef10e` / `d18dbd2` — memladder escalation ladder + `RUNG_AVAILABILITY`, then the
   cooperative throttle executor seam wired into 4 services.
3. `f8854ec` — Window 3's error-code wiring batch (13 Tier A sites, `vpn_status.py` Tier B
   convention).
4. `e970d71` — throttle executor (ladder→publish) + `UNTHROTTLED` status model.
5. `d3f1892` — ADR 0023 device↔agent correlation. **A real bug found and fixed** via the
   mandatory route-security audit — see §4.
6. `c44278a` — process-lesson doc: an accidental live-DB write during isolated verification,
   corrected, logged, state-snapshotted. See §4 for the full incident.
7. `dcd4dce` — Tier 2 attestation hooks (additive, guarded, confirmed dormant in production).
8. `fd67bcc` — throttle status surface. **A second real bug found and fixed** — see §4.
9. `6fa5133` — real Windows `get_lan_macs()` (was a stub when `d3f1892` shipped).
10. `2c742e3` — ABORT flipped to `MODE_SHADOW`, per-rung promotion gating.
11. `059da4b` — **production memory-injection ladder loop wired into `hw_monitor`.** Flagged
    in its own commit message as a state-changing deploy, not purely additive. Now genuinely
    live — see §1.
12. `74b2591` — throttle status visual card (Window 3's held presentational work).
13. `368b828` — RAM recovery: orphaned SysV shm reclaim + zombie reaping. The most
    safety-sensitive batch today (can SIGTERM processes / `shmctl` segments via a dashboard
    action) — got the full route-security audit + 73/73 tests + independent live read-only
    re-verification.
14. `ebfa0bb` — roadmap stub capturing RAM recovery's Windows platform gap (SysV shm and
    zombies both lack real Windows equivalents), for whoever scopes that side next.

## 3. Open items to pick up first, in priority order

1. **`mem_ladder_state`/`mem_shadow_records`/`agent_attestation_challenges` are missing from
   `hw_monitor`'s Data Manager namespace grant in `alert_manager/data_manager.py`.** Found
   LIVE tonight via `journalctl` (`WOULD DENY (warn-only)` on every ladder cycle since the
   restart). Currently harmless — WARN-only enforcement, and `run_ladder_cycle`'s own
   try/except degrades gracefully — but MUST be fixed before DataManager enforcement is ever
   flipped to `MODE_ENFORCE`, or the ladder loop and Tier 2 issuance both go silently dark.
   Candidate fix + a direct grant-assertion test (matching the `agent_device_macs` precedent):
   full detail in PUNCHLIST. Not a Window 2 fix — code content, needs Window 1.
2. **`install.sh` still doesn't wire `malware-scan.service`** (open since 2026-08-18) — the
   privilege-fix batch that landed today (`72a7ed0`/`88802c1`) is committed but the service
   itself isn't installed on this box. Two `clamd.conf` phishing-detection settings also still
   missing. Neither blocks further commits; both block deploying that specific feature.
3. **The Windows-side RAM recovery platform gap** (roadmap stub, `ebfa0bb`) needs its own
   scoping pass whenever someone picks up the Windows side — SysV shm's orphan category may
   not exist as a problem there at all; zombies' nearest analogue (handle leaks) is a
   different diagnostic, not a port.
4. **`LICENSE` draft's three open placeholders** (copyright holder, commercial contact,
   governing law) plus real legal review — unchanged, still open.
5. **The 08-08 error-code-classification batches** — now 11 days unclaimed, unchanged.
6. **The undeployed-but-committed pile continues to be worth watching, though tonight
   narrowed it substantially** — most of today's memory-work batches are now genuinely live
   (see §1), which is real progress against the standing "committed vs. running" gap flagged
   the last two closeouts. What's left uncommitted-and-undeployed is smaller than it's been in
   days.

## 4. Verified live today, not just claimed (Rule 3 discipline)

**Two real bugs caught by this window's own pre-commit verification, before either shipped:**

- **`dashboard.py` use-after-close (`d3f1892`).** The mandatory route-security audit — run
  regardless of Window 1's own "doesn't trigger" assessment, per explicit operator instruction
  not to skip it — found `get_network_devices()` closing its DB connection before calling
  `hw_monitor.approved_agent_macs(conn)` on it, silently swallowed by that function's own
  unlogged `except Exception: return set()`. `has_agent` was unconditionally `False` for every
  device, invisibly. Window 1 fixed both the ordering and the root cause (now logs at ERROR on
  read failure). Re-ran the FULL audit on the fixed file, not just the one bug; independently
  re-verified beyond the new unit test by extracting and live-executing the real function
  against a throwaway DB.
- **`mem_appliance.py` missing `import time` (`fd67bcc`).** `throttle_status_report()` called
  `time.time()` with no import anywhere in the file — a guaranteed `NameError` on every real
  call to the new route, reproduced live before reporting it. No test covered the new
  function, which is why it wasn't caught earlier. Window 1 fixed it plus added a regression
  test exercising the exact default-`now=None` path.

**An accidental live-DB write, reported immediately, corrected properly.** While verifying the
Tier 2 schema migration in isolation, `modules.set_shared_db_path()` did not redirect
`hw_monitor.py`'s own independently-resolved `DB_PATH`, which fell back to the real production
path. `init_db()` ran against the live DB, adding three additive/guarded columns before the
commit shipping them had landed. Verified benign immediately (integrity ok, row counts
unchanged); reported in full before any further action; operator directed an after-the-fact
State Snapshot (taken), a PUNCHLIST entry (filed), and a corrected verification approach for
the rest of the session (explicit `NEMESIS_DB_PATH`, confirmed honored before trusting it —
used successfully for every subsequent isolated test tonight).

**RAM recovery (`368b828`) got the heaviest verification of the day**, matching its
safety-sensitivity (can SIGTERM processes, release shared memory): full route-security audit
on both new routes (clean, matches the established `api_vpn_action` CSRF precedent exactly),
73/73 test suite (every dangerous action path tested via injected fakes — SIGTERM, systemctl
restart, `shmctl`, nothing real touched), and independent live READ-ONLY verification beyond
the unit tests that reproduced the exact two real zombies documented in the module's own code
comments, including confirming the ancestor-interlock safety mechanism correctly refused to
act on a process that is genuinely an ancestor of this session.

**Tonight's closeout fact-gathering itself surfaced a real, live finding** — not asserted, not
inferred from timestamps alone: `mem_ladder_state.sample_seq` checked directly to confirm the
ladder loop is really running, which is what surfaced the namespace-grant gap in §3 item 1.

## 5. State snapshots

One taken today, after the fact: `nemesis-state-backups/2026-08-19-1451-after-the-fact-
tier2-schema-migration/` (alerts.db copy, integrity-checked ok; STATE.txt with full incident
narrative, git HEAD/tag, 6-service status). No other snapshot needed — every other action
today was code landing in git, not a direct state-changing action taken by this window (the
service restarts tonight were not this window's doing).

## 6. ⚠ Standing elevated grants — REVIEW FOR REVOCATION

Live-reverified 2026-08-19 (both this morning and again at this closeout), via `sudo -n -l` and
`getent group`.

- **GOOD NEWS: all three previously-flagged broad `(ALL) NOPASSWD:` grants are GONE as of
  tonight.** `(ALL) NOPASSWD: /usr/bin/systemctl restart dashboard`,
  `(ALL) NOPASSWD: /usr/bin/ip, /usr/local/bin/piactl`, and
  `(ALL) NOPASSWD: /usr/bin/systemctl restart hw-monitor` were all present this morning
  (confirmed via this session's own Morning Status check) and are all absent from `sudo -n -l`
  as of this closeout. Not investigated for who/when/why — just confirmed via direct
  before/after comparison, not assumed from the count. These are the same two grants flagged
  as "still unreviewed" across the last several closeouts; they now read as resolved
  (revoked), not merely re-flagged again. Worth a one-line confirmation from Paul that this was
  deliberate, but nothing here reads as accidental or alarming.
- **`paul`'s `pihole` group membership** — confirmed live, unchanged, still for the
  cardinality tool. Same standing note: worth a revoke decision once that tool's current use
  is done, not urgent tonight.
- **Suricata rule-deployment grants** (`tee local.rules`, `reload`/`restart suricata`) —
  confirmed live, unchanged, in active use.
- **`nemesis-fw` group** (`paul`, `nemesis-alertw`, `nemesis-dash`) and **`nemesis-db` group**
  (`paul`) — confirmed live, unchanged, expected service-account shape.
- The large block of narrowly-scoped, command-specific NOPASSWD entries (install/`/opt`-
  migration provisioning, per-service start/stop/restart) is unchanged and not re-flagged
  individually — reviewed previously, still narrowly scoped as designed.

## 7. Known issues/gaps, not yet fixed

Carried forward unchanged from prior closeouts: the Rule-8 username finding,
`NEMESIS_AGENT_EXE`'s real home path, `migrate_to_opt.sh` fragility, missing ADR for the
`/opt` relocation, `backupproc.md` unconfirmed for current layout, ADR 0015 vs.
venue-guest-network tension, no hardware baseline beyond the gauge VM, ruleset-rollback
residual (bounded, fix deferred).

**New tonight:**
- The `hw_monitor` Data Manager namespace gap (§3 item 1) — currently harmless, real, needs a
  fix before DataManager enforcement is ever flipped on.
- `install.sh` still doesn't wire `malware-scan.service` — carried forward from 2026-08-18,
  unchanged, not touched today (today's malware-scan commits were the already-held code
  landing, not new install.sh work).
- The two-DB-path-mechanisms-don't-compose gap (`modules.set_shared_db_path()` vs.
  `nemesis_paths.db_path()`) — filed in PUNCHLIST 2026-08-19, worth a real fix (or at minimum
  a documented convention) rather than relying on every future session remembering to check
  `NEMESIS_DB_PATH` explicitly.
- Live worklog was written AS-YOU-GO tonight, not reconstructed at closeout — first time in
  three sessions this hasn't needed a process-gap note (prior lapses: 2026-08-08, 2026-08-17,
  2026-08-18). Worth naming as the behavior change actually holding, not just hoped for.

## 8. Cross-references

- `docs/handoff/supplements/2026-08-19-001.md` — curated narrative, this closeout.
- `docs/handoff/worklog/2026-08-19-001.md` — live raw log, written as-you-go.
- `docs/architecture/0023-device-agent-correlation-key.md` — new today, landed with its
  implementation.
- `docs/roadmap/ram-recovery-windows-platform-gap.md` — new today.
- `nemesis-state-backups/2026-08-19-1451-after-the-fact-tier2-schema-migration/` — today's
  state snapshot, with the full incident narrative in its `STATE.txt`.
- `PUNCHLIST.md` — three new entries today: the DB-path test-isolation gap, the
  `hw_monitor` namespace-grant gap, and (carried in) the canary-coverage gap from the malware
  batch's own follow-up.
- `~/work/nemesis-internal/scoping-and-estimates/attestation-tier2-challenge-response-scope-2026-08-19.md`
  — Window 3's Tier 2 scope doc, filed today (doc-only; the built module stays owed to
  Window 1).
- Prior day: `docs/handoff/supplements/2026-08-18-001.md`.

## Topology (durable, unchanged from prior handoffs unless noted)

- `:80` nginx (Basic-auth; auth-bypass for `/install/windows/` + `/api/health`), LAN-scoped
  SSH/HTTP rate limiting at the ufw layer plus nginx's own `limit_req`. Deployed config still
  drifted from what `install.sh` generates (nginx audit, committed 08-18, not yet acted on).
- `:5000` Flask dashboard — loopback-only, restarted tonight (20:25:15) to pick up the throttle
  status route/card and RAM recovery. `:5001` hw-monitor agent endpoint — still `0.0.0.0` by
  design, protected by application-layer source admission; restarted tonight (18:34:58) to
  pick up the production ladder loop.
- **NEW tonight: the memory-injection escalation ladder is live**, not just committed. ALERT
  and THROTTLE rungs are `MODE_LIVE` (THROTTLE publishes real cooperative-throttle intent
  against `hw-monitor`/`watchdog`/`alert-watcher`/`diagnostics-watcher`, gentle/fail-safe/
  auto-expiring). ABORT and RESTART are both `MODE_SHADOW` — decided and recorded, never
  executed, each gated on its own accumulated evidence before any future promotion.
- **NEW tonight: manual RAM recovery is live** — `/api/ram-recovery/candidates` (GET,
  auth-gated) and `/api/ram-recovery/clean` (POST, JSON-required, CSRF-hardened) plus a
  dashboard card. Can reclaim orphaned SysV shared memory and reap zombie processes; never
  touches a live application's memory. Heavily safety-interlocked (ancestor interlock,
  container-unit guard, release-time re-verification) — see `alert_manager/ram_recovery.py`
  for the full design.
- **Tier 2 attestation (challenge-response) is committed but confirmed dormant** — no deployed
  service context adds the private module's path to `sys.path`.
- `nemesis-fwd` — Unix-socket privileged helper, peers: dashboard, alert-watcher, `fail2ban`
  (narrow: `block_ip`/`deny_ip` only, cannot release), `write_env`/`restart_dashboard` ops
  (dashboard peer only). Window 1 has in-flight WIP against this file right now (§1) — not
  described further since it's still moving.
- `nemesis_enforce` — owned nftables table (ADR 0019), priority-placed ahead of the filter
  hook, derived from `ufw`'s live state. Real DROP authority live since 2026-08-02.
- The licensing engine's tables and `agent_devices.remote_enabled*` columns exist live on the
  DB, unchanged today.
- `agent_devices` now also carries the ADR 0023 correlation (`agent_device_macs` table, live
  and correctly wired) and the Tier 2 observe-only columns (`tier2_state`/`tier2_detail`/
  `tier2_at`, present but dormant).
