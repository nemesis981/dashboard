# HANDOFF — current state

> Last updated **2026-08-18, nightly closeout (Window 2)**. Overwritten each closeout (latest
> state wins). Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/
> accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per
> Rule 8.
>
> Full detail behind every claim below: `docs/handoff/supplements/2026-08-18-001.md` (curated)
> and `docs/handoff/worklog/2026-08-18-001.md` (raw log, reconstructed at closeout — third
> occurrence of that gap, see its own note). Prior day: `docs/handoff/supplements/2026-08-17-001.md`
> and its same-day correction (`df489d8`) — the lesson from that correction (verify a
> deployment-status claim live, including this window's own prior ones, before repeating it)
> is why this closeout leans as hard as it does on re-verified facts below.

---

## 1. Live in production right now — verified fresh, not carried forward

- **`origin/main` is at `b143c10`.** ⚠ **`HEAD` is one commit ahead, at `f893396`, NOT YET
  PUSHED.** Caught by this closeout's own sync check, not before — see §3 item 1. This is
  exactly the "include a diff to confirm nothing stray" check working as intended.
- **Re-verified fresh (not assumed from yesterday's correction):** `dashboard` and
  `hw-monitor`'s current processes have not restarted since yesterday afternoon
  (`ActiveEnterTimestamp` `2026-08-17 16:56:29` / `16:53:56`, unchanged from yesterday's
  closeout correction). Every file touched by today's commits has an mtime *after* both
  restarts (checked directly: `procmem.py`, `membudget.py`, `mem_appliance.py`, `module.py`,
  `attest.py` are all dated 2026-08-18 afternoon/evening). **Today's work is genuinely not
  live** — unlike yesterday's initial claim, which was wrong. `ss -tlnp` confirms `:5000` is
  still loopback-only and `:5001` still world-bound-by-design, both matching yesterday's
  verified state, not this session's commits.
- **8 commits landed today**, one not yet pushed (see above). Full list and diff stat: §2 and
  the worklog. Cross-checked commit-by-commit against this window's own memory of the
  session before writing this file — no stray or unaccounted-for commit found.
- **Held in the working tree right now, none of it Window 2's, none of it committed:**
  - `core_module/malware_scan/` (new, untracked) + `modules/malware_detection/module.py`
    (modified, large diff) — Window 3's appliance-scan engine switch + trigger + the
    `CAP_DAC_READ_SEARCH` privilege fix. **Blocked from committing**: `malware-scan.service`
    has `PrivateTmp=no` (the deliberate, documented fix) followed later in the same file by
    `PrivateTmp=yes` inside a copy-pasted hardening block — systemd's last-occurrence-wins
    semantics mean the effective value silently undoes the fix. `systemd-analyze verify`
    does not catch this (not a syntax error). Reported to the operator; not committed, not
    edited by Window 2. See §3.
  - `nemesis_agent/memladder.py` + `test_memladder.py` — Window 1's escalation-ladder
    module, offered twice, held both times (readiness offered ≠ requested).
  - `alert_manager/mem_appliance.py` + `test_mem_appliance.py` (further modified, on top of
    the already-committed `b143c10`) — Window 1 continuing the RUNG_AVAILABILITY work,
    answering the THROTTLE-is-a-no-op-for-clamd question flagged to Paul yesterday. Not yet
    asked for.
  - `docs/audits/error-code-classification-batch1/2/3-2026-08-08.md` — Window 3's read-only
    sweep, now 10 days old, still unclaimed across every closeout that's checked it.

## 2. What shipped today (8 commits)

Full commit-by-commit detail: `docs/handoff/supplements/2026-08-18-001.md`.

1. `718e1d0` — nginx config-drift audit, held since 2026-08-16, committed.
2. `6e0b27d` — ADR 0004 amendment (appliance self-scan trigger design) + two derived
   PUNCHLIST entries (Layer B behavioral overclaim, dead `scan_schedules` UI), placing
   Window 3's scoping work per its own recommendation. Rule 10 applied: design/architecture
   public, exact gap-severity measurements kept private.
3. `165be15` — `nemesis_agent/procmem.py` + test + the `AGENT_VERSION` bump it required as
   one logical change, held for and resolved by direct coordination with Window 1 first.
4. `77f12c7` — `AGENT_VERSION` divergence PUNCHLIST entry updated to match the actual bump.
5. `f7dc88f` — Layer B behavioral-overclaim honesty fix (`module.py`, `manifest.json`, new
   roadmap stub), approved by Paul, same Rule 10 disposition as the already-public Layer D
   precedent.
6. `b67ff65` — manifest-built-from-live-tree PUNCHLIST entry, a structural finding from
   Window 1 (uncommitted WIP under `nemesis_agent/` poisons the fleet manifest independent of
   any version mistake), filed at Window 1's request.
7. `b143c10` — RAM budget model (`membudget.py`) + appliance adapter (`mem_appliance.py`) +
   both test suites, independently re-verified with a live demo against this box's real
   processes before landing, not just the test suite.
8. `f893396` — install.sh/clamd.conf open-items flag. **Unpushed — see §1, §3.**

## 3. Open items to pick up first, in priority order

1. **Push `f893396`.** One commit, docs-only, already Rule-8-clean (checked at commit time) —
   just needs the routine push-confirmation step this window otherwise follows every time.
2. **`malware-scan.service`'s `PrivateTmp` bug blocks the entire Linux privilege-fix batch.**
   Not a Window 2 fix — needs Window 3 (or whoever owns that file) to resolve the duplicate
   directive before any of the engine-switch/trigger/capability-grant/canary work can be
   committed. Real, verified via systemd's documented directive-resolution semantics, not
   `systemd-analyze verify` (which doesn't catch this shape).
3. **`nemesis_agent/memladder.py`/`test_memladder.py`** — ready, mutation-tested (21 groups,
   two real bugs found and fixed by Window 1 in its own delivery before handing over), held
   pending Paul's ask. Two real open design questions attached: RESTART ships shadow-only by
   design (needs accumulated evidence of *correct* prior decisions to ever promote, and a
   component dying/being restarted by something else deliberately doesn't count as such
   evidence), and THROTTLE is structurally a no-op for `clamd` (the appliance's biggest
   consumer) since it has no real throttle mechanism and is recovery-exempt — flagged to Paul
   directly, not yet answered.
4. **install.sh wiring + the two `clamd.conf` phishing-detection settings** — tracked
   (`f893396`), not built. Neither blocks the held scan-engine code from being committed once
   the `PrivateTmp` bug is fixed; both block *deploying* it.
5. **Two sudo NOPASSWD grants from yesterday's closeout, still unreviewed**: `(ALL) NOPASSWD:
   /usr/bin/ip, /usr/local/bin/piactl` and `(ALL) NOPASSWD: /usr/bin/systemctl restart
   hw-monitor`. Re-confirmed live today (§6), still no keep/revoke decision.
6. **`LICENSE` draft's three open placeholders** (copyright holder, commercial contact,
   governing law) plus real legal review — unchanged, still open.
7. **The 08-08 error-code-classification batches** — now 10 days unclaimed, unchanged.
8. **A genuinely large undeployed pile continues to grow.** Today added the entire
   memory-injection prerequisite chain built so far (procmem, membudget, mem_appliance) and
   the Layer B fix on top of yesterday's licensing engine and cap enforcement, none of it
   live. This is not urgent by itself (nothing in today's additions is security-regressing —
   the held Linux privilege work is exactly what's blocked from landing), but the gap between
   "committed" and "running" keeps widening and deserves its own deliberate review, not
   another day of accumulation.

## 4. Verified live today, not just claimed (Rule 3 discipline)

Two coordination exchanges with Window 1 surfaced real bugs before they shipped, neither
asked for — Window 1 found both while independently double-checking its own prior claims,
the same discipline this window tries to hold itself to: the `AGENT_VERSION` gap (adding
files without bumping it would have silently disarmed the tampering-detection field for the
next agent to enroll — proven with a real before/after test, not reasoned about) and the
manifest-built-from-the-live-tree finding (measured live: 69 files a manifest would cover
right now vs. 67 an actually-committed agent has). Both were independently re-verified by
this window before being committed or filed, not taken on either party's word: `procmem.py`
+ the version bump re-ran `test_attest.py` (16/16) and `alert_manager/test_attestation.py`
(21/21) fresh; the RAM budget model re-ran both new test suites (15 + 8 functions) fresh plus
a live demo against this box's real processes (63.7 GB total RAM, clamd at 429.5 MB against
its 1600 MB budget, zero breaches).

**This window's own readiness check failed twice today, both caught before committing
anything broken** — not a success story about verification being unnecessary, the opposite:
asked to commit Window 3's held Linux privilege work, direct inspection of
`malware-scan.service` (not the accompanying handoff narrative, not the passing
`systemd-analyze verify` run already recorded against it) found the duplicate `PrivateTmp`
directive described in §1/§3. Held rather than trusted.

## 5. State snapshots

None taken by Window 2 today — every action was code landing in git or documentation, not a
running-system change. No service was restarted by Window 2 today (confirmed: `dashboard`
and `hw-monitor`'s restart timestamps are unchanged from yesterday, checked directly, not
assumed).

## 6. ⚠ Standing elevated grants — REVIEW FOR REVOCATION

Live-reverified 2026-08-18, via `sudo -n -l` and `getent group pihole`. No change from
yesterday's closeout.

- **`<user>`'s `pihole` group membership** — confirmed live, unchanged, still for the
  cardinality tool. Same standing note: worth a revoke decision once that tool's current use
  is done, not urgent tonight.
- **Suricata rule-deployment grants** — confirmed live, unchanged, matches the
  previously-tracked shape.
- **`(ALL) NOPASSWD: /usr/bin/ip, /usr/local/bin/piactl`** and **`(ALL) NOPASSWD:
  /usr/bin/systemctl restart hw-monitor`** — both found live yesterday, not in this file's
  history before that, still unreviewed today. Re-confirmed present, not re-investigated for
  origin. Still owed an explicit keep/revoke decision, now two closeouts running.

## 7. Known issues/gaps, not yet fixed

Carried forward unchanged from prior closeouts: the Rule-8 username finding,
`NEMESIS_AGENT_EXE`'s real home path, `migrate_to_opt.sh` fragility, missing ADR for the
`/opt` relocation, `backupproc.md` unconfirmed for current layout, ADR 0015 vs.
venue-guest-network tension, no hardware baseline beyond the gauge VM, ruleset-rollback
residual (bounded, fix deferred).

**New tonight:**
- The live-worklog habit lapsed a **third** time (prior instances 2026-08-08, 2026-08-17).
  No longer worth treating as an occasional slip — see the worklog's own note. Needs an
  actual behavior change next session, not another flag.
- One commit (`f893396`) sat unpushed into this closeout — caught, not missed, but worth
  noting that "commit, then move immediately to the next task" is how it happened; the
  routine push-confirmation step needs to actually run at the end of every task, not just
  when explicitly prompted.
- The undeployed-but-committed pile (§1, §3 item 8) is now large enough across two days
  running that it's becoming its own standing risk category, not a one-line note.

## 8. Cross-references

- `docs/handoff/supplements/2026-08-18-001.md` — curated narrative, this closeout.
- `docs/handoff/worklog/2026-08-18-001.md` — reconstructed raw log (see its own process-gap
  note, third occurrence).
- `docs/architecture/0004-scan-task-orchestration.md` — today's amendment; the held Linux
  privilege work (§1, §3) builds directly against it.
- `docs/roadmap/malware-layer-b-behavioral-monitoring.md` — new today, captured alongside
  the Layer B honesty fix.
- `~/work/nemesis-internal/appliance-self-scan-scope-2026-08-18.md` — Window 3's full
  scoping detail, placement-resolved note added by Window 2.
- `~/work/nemesis-internal/handoff/2026-08-18-window1-handoff.md` and
  `2026-08-18-window3-handoff.md` — both windows' own context handoffs for today, far more
  build detail than this file carries.
- `PUNCHLIST.md` — three new entries today: the manifest-poisoning finding, the
  `AGENT_VERSION` divergence (updated), and the install.sh/clamd.conf open items.
- Prior day: `docs/handoff/supplements/2026-08-17-001.md` and its same-day correction
  (`df489d8`) — the deployment-status lesson this closeout leans on throughout.

## Topology (durable, unchanged from prior handoffs unless noted)

No changes today — the held Linux privilege work (`CAP_DAC_READ_SEARCH`, `PrivateTmp`,
`clamdscan` engine switch) is not committed and not deployed, so nothing below reflects it
yet. Once it lands, the malware-scan service becomes a new, narrowly-capability-scoped
addition worth its own topology entry.

- `:80` nginx (Basic-auth; auth-bypass for `/install/windows/` + `/api/health`), LAN-scoped
  SSH/HTTP rate limiting at the ufw layer plus nginx's own `limit_req`. Deployed config still
  drifted from what `install.sh` generates (nginx audit, committed today, not yet acted on).
- `:5000` Flask dashboard — loopback-only, confirmed live via `ss -tlnp`, unchanged since
  yesterday. `:5001` hw-monitor agent endpoint — still `0.0.0.0` by design, protected by
  application-layer source admission, unchanged since yesterday.
- `nemesis-fwd` — Unix-socket privileged helper, peers: dashboard, alert-watcher, `fail2ban`
  (narrow: `block_ip`/`deny_ip` only, cannot release), `write_env`/`restart_dashboard` ops
  (dashboard peer only).
- `nemesis_enforce` — owned nftables table (ADR 0019), priority-placed ahead of the filter
  hook, derived from `ufw`'s live state. Real DROP authority live since 2026-08-02.
- The licensing engine's tables (`license_state`, `license_backup_codes`) and
  `agent_devices.remote_enabled*` columns exist live on the DB (confirmed yesterday, one real
  commercial-license activation present), unchanged today. Today's additions on top
  (`procmem`, `membudget`, the Layer B fix) are committed but not yet running — see §1.
