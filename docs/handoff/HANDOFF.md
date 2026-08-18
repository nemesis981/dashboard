# HANDOFF — current state

> Last full closeout: **2026-08-17, nightly (Window 2)**. **Corrected in place 2026-08-18**
> (§1, §3, Topology) — a deployment-status claim from the 2026-08-17 closeout was found stale
> the same day it would next have been read, and fixed immediately per standing instruction
> rather than held for the next nightly closeout. This is a same-day correction, not a new
> full closeout — the rest of the file (§2, §4-§8) still reflects 2026-08-17's session as
> originally written. Overwritten each closeout (latest state wins). Durable history:
> `docs/handoff/supplements/` (append-only). Real IPs/hosts/accounts/keys live ONLY in
> `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8.
>
> Full detail behind every claim below: `docs/handoff/supplements/2026-08-17-001.md` (curated)
> and `docs/handoff/worklog/2026-08-17-001.md` (raw log, reconstructed at closeout — see its
> own process-gap note). Today's (2026-08-18) commits are not yet behind their own supplement
> — due at tonight's closeout.

---

## 1. Live in production right now — verified, not assumed

> **CORRECTED 2026-08-18, same day — the note below this file carried through last night's
> closeout was already stale when written.** That version said the licensing engine and cap
> enforcement were "committed but not yet running." **They are running.** Caught while
> independently verifying an unrelated claim (that three fail-closed fixes were already live)
> — checking service restart timestamps against file mtimes turned up two `dashboard`
> restarts yesterday afternoon (`16:27:54` and `16:56:29`) and one `hw-monitor` restart
> (`16:53:56`), both well after almost all of yesterday's commits landed on disk. Corrected
> the same day it was found, per standing instruction not to let a known-stale deployment
> claim sit in the record. The struck-through text is kept, not deleted, so the correction is
> visible — same convention Window 1 used for the tailnet-deploy-status disagreement two days
> ago.

- **`origin/main` is at `4ff2bc6`** as of this writing (confirmed `HEAD == origin/main` via
  fresh fetch, re-confirmed at this correction). 21 commits landed and pushed since yesterday
  morning across two sessions (15 the first day, 6 today).
- ~~**Nothing landed today has been deployed to this box's running services**, except two
  pieces Window 1 deployed itself... Everything committed AFTER those two restarts... is
  **committed but not yet running** on this box.~~ **WRONG, corrected same-day.** Verified
  directly against the live system, not inferred:
  - `dashboard` (current PID, up since `2026-08-17 16:56:29`) and `hw-monitor` (current PID,
    up since `2026-08-17 16:53:56`) are running whatever was on disk at those moments.
    Checked every `core/*.py` file the licensing/cap-enforcement work touched
    (`cap_guard.py`, `net_reachability.py`, `license_key.py`, `backup_codes.py`,
    `remote_census.py`, `entitlements.py`, `install_id.py`, `database.py`,
    `tailscale_api.py`) plus `dashboard.py` and `hw_monitor.py` themselves — **every one of
    them has an mtime before both restart timestamps.** `journalctl` confirms an earlier
    `dashboard` restart at `16:27:54` too (superseded by `16:56:29`, same PID lineage).
  - **The live database schema has already changed, confirmed by direct read-only query**:
    `license_state` and `license_backup_codes` exist and are populated (`license_state` has
    **1 row**: `tier=commercial, bound_at=2026-08-17T16:36:59, updated_actor=<operator-account>`);
    `agent_devices` has `remote_enabled`/`remote_enabled_at`/`remote_enabled_by` (13 devices,
    0 currently `remote_enabled`); `enrollment_tokens.remote_enabled` exists; 5 backup codes
    are issued. **This is real activation, not test data** — the operator's own account
    activated a real commercial license on this box yesterday, using the real production
    signing key, through the actual dashboard UI, between the two restarts.
  - **What this means practically:** the licensing engine, cap enforcement (both admission
    seams), the fingerprint fix, the 3-category orphan display, and the loopback dashboard
    bind (Gap 3a) are not a pending deploy decision — they are the code currently answering
    every request this box serves. The one exception below.
  - **Not yet live, confirmed by the same method:** `install.sh`'s three commits from today
    (`0925273` h2 deps, `c2149c5` install-id docs, `7d56f78` discoverability card) and the
    three fail-closed fixes from today (`865046a`, `9bbab1a`, `4ff2bc6`) — the discoverability
    card and fail-closed-fix *content* was already on disk before the restarts above (verified
    same way, see the fail-closed-fix commits' own messages), so those ARE live; only
    `install.sh` itself is inert until someone runs it (not a running service). No further
    restart has happened since `16:56:29`/`16:53:56` — confirmed via `systemctl show` at the
    time of this correction, same PIDs.
- **A deliberate deploy decision is still owed, but for a narrower and different reason than
  last night's note implied**: not "is any of this safe to turn on," but "this box has been
  running yesterday's entire licensing/cap-enforcement change set, un-reviewed-post-deploy,
  for the better part of a day without anyone deciding that on purpose." Worth a proper
  after-the-fact verification pass (State Snapshot discipline retroactively — at minimum,
  confirm current behavior matches intent) rather than treating "it's already running and
  nothing's on fire" as equivalent to a reviewed deploy.
- **Directly verified on this box at this correction** (Rule 3): all 8 checked services
  (`dashboard`, `watchdog`, `alert-watcher`, `malware-canary`, `diagnostics-watcher`,
  `vpn-dns-guard`, `hw-monitor`, `nemesis-fwd`) report `active`. `nemesis-fwd`,
  `alert-watcher`, `diagnostics-watcher` last restarted `2026-08-16 17:05:0x` — unchanged
  since before yesterday's session began; today's three fail-closed fixes landed only because
  their file mtimes (2026-08-08 for two of them) already predated even that earlier restart.
- **Active, uncommitted WIP sitting in the tree right now**, none of it Window 2's, none of
  it touched:
  - `docs/audits/error-code-classification-batch1/2/3-2026-08-08.md` — Window 3's read-only
    sweep, unchanged from prior closeouts, still awaiting review.
- **`docs/audits/nginx-config-drift-audit-2026-08-16.md` is still uncommitted**, sitting
  since early yesterday's own audit. Public and Rule-8-clean, just never landed — worth
  committing next session rather than letting it go stale.

## 2. What shipped today (15 commits, one session)

Full commit-by-commit detail: `docs/handoff/supplements/2026-08-17-001.md`. Summary:

1. **Gap 1-3 firewall hardening + tailnet device removal** (`ca00be9`, `9df9b9e`, `21b3541`,
   `8981f52`) — scoped VM-adapter UFW rules replacing a world-open one, tailnet allow rules
   the installer never wrote, the dashboard bound to loopback instead of `0.0.0.0`,
   application-layer source admission on `:5001`, and device revoke now also removes the
   node from the tailnet (not just blocks it in Nemesis) — the last held on request pending
   a real end-to-end test against the live Tailscale API, which found and fixed a genuine bug
   (positional vs. by-name DB row access) before the hold was lifted.
2. **The node-locked licensing engine** (`e25a92c`, `96cfe9b`) — install-identity
   fingerprinting, offline Ed25519 key verification, backup codes, a remote-device census
   reconciled against the live tailnet, and the entitlements rewrite. `FREE_TIER_REMOTE_CAP`
   locked at **5**.
3. **The `remote_enabled` schema + dashboard licensing UI** (`458079f`, `1b52d7c`, schema
   first since the UI depends on the column existing) — four routes, the budget strip, backup
   codes UI.
4. **Cap enforcement** (`c1cd5ff`, `0a359de`) — both admission seams (generate-time and
   download-time), closing a real bypass where a *pasted* Tailscale key skipped the cap check
   entirely, plus connectivity-aware fail-open/fail-closed logic (a vendor API outage still
   grants; this box having no internet at all now refuses, closing a disconnect-to-bypass
   hole) and its own 42-assertion regression suite.
5. **`LICENSE` + `README.md` + ADR 0022** (`326c0e8`) — the repo had no license file at all,
   ever; both new files are explicitly marked DRAFT pending real legal review.
6. **The hw_monitor fingerprint-loader fix** (`2c2ff14`) — two independent defects (a
   hardcoded path-depth count broken by July's directory relocation, plus a sibling-import
   `sys.path` issue) meant the TOFU hardware-match comparison had never once run in
   production.
7. **3-category orphan display** (`49efa1f`) — separates this server's own tailnet node and
   pre-licensing/local-only devices (both benign) from genuinely unknown machines (the only
   category that should warn).
8. **The real production issuer public key** (`8662b14`) — verified independently three ways
   before committing (see §4), on its own commit.
9. **Backup-codes "never issued" vs. "all spent"** (`6597853`) — a fresh install no longer
   reports its recovery codes as exhausted before any have been issued.

## 3. Open items to pick up first, in priority order

> **Updated 2026-08-18** — items 3-5 below (as they read last night) are now committed;
> item 1 is reframed per §1's correction. Kept the historical numbering's intent, not
> renumbering from scratch, so cross-references from last night's supplement still resolve.

1. **Retroactive deploy review owed, reframed from "deploy decision"** — see §1's
   correction. The licensing feature and cap enforcement (including the pasted-key bypass
   fix) are not a pending decision; they are live and have been since yesterday afternoon.
   What's actually owed now is a deliberate **after-the-fact verification pass** — confirm
   the live behavior matches intent, that the real `license_state` activation (§1) is the
   intended one, and only then treat this as a reviewed deploy rather than an accidental one.
2. **`docs/audits/nginx-config-drift-audit-2026-08-16.md`** — still uncommitted, now two
   sessions running. Nothing about it has changed; commit it next session.
3. ~~Three ready-shaped, uncommitted licensing-adjacent pieces~~ **DONE 2026-08-18**: the
   Settings discoverability card (`7d56f78`), the `install_id.py` root-vs-dashboard-user note
   (`c2149c5`), and the install.sh h2 dependency (`0925273`) all committed and pushed.
4. ~~The 08-08 WIP is now over a week old~~ **DONE 2026-08-18**: `nemesis_fwd.py` (`865046a`),
   `redact.py` (`9bbab1a`), and the `hw_monitor.py`/`dashboard.py` clamscan fixes (`4ff2bc6`)
   all committed and pushed — independently verified already running live (mtime-vs-restart
   check) before committing, which is what surfaced §1's correction in the first place.
5. **LICENSE draft's three open placeholders** (copyright holder legal name/entity,
   commercial-licensing contact, governing law/jurisdiction) plus real legal review —
   tracked in `PUNCHLIST.md`'s `[HIGH — legal, not just docs]` entry, still not resolved.
6. **Two sudo NOPASSWD grants found live, not in this file's prior tracked list** — see §6.
   Need a keep/revoke decision, not carried forward silently.
7. **New today**: confirm whether any *other* file this session touched has a similarly
   stale "not deployed" assumption baked into a doc somewhere — this correction was found by
   accident while verifying an unrelated claim, not by a systematic check. Worth a deliberate
   pass rather than assuming this was the only one.

## 4. Verified live today, not just claimed (Rule 3 discipline)

Every commit this session had its factual claims independently checked, not taken from
Window 1's own summary: the licensing engine's Rule 10 read was independently re-scanned
(clean); the cap-enforcement batch's Rule 10 read was **not** taken as clean — a real
bypass-instruction disclosure was found in `cap_guard.py`/`net_reachability.py`'s public
docstrings, sanitized, and the removed text preserved privately before commit. Test suites
were re-run live rather than trusted throughout: `test_licensing.py` 65→71 assertions across
the session as coverage grew, `test_licensing_routes.py`, `test_cap_enforcement.py` (48),
`test_cap_connectivity.py` (42, confirmed independent of the enforcement suite by import and
a standalone run), `test_match_fingerprint.py` (13, run as a real subprocess under the actual
production `PYTHONPATH`, not the caller's own — deliberately, since that's the exact
condition that would hide the bug it exists to catch). The `9ffac56` relocation-commit
citation in the fingerprint-fix PUNCHLIST entry was verified against real git history before
being written down. The production signing key was verified three independent ways (re-derived
from the local private key file, re-derived from its offline USB backup, and a real
already-issued license round-tripped through the product's own verifier) before its commit —
private key material was never printed, logged, or copied at any point.

One backup-codes fix (`6597853`) shipped with only manual, non-persisted verification (a
temp-DB script run at the terminal) rather than a dedicated regression test — flagged in that
commit's own message rather than silently presented as equally rigorous; writing a new test
file was judged to be code-authoring outside this window's role, not something to skip
quietly.

## 5. State snapshots

None taken by Window 2 today — every action this session was code landing in git, not a
running-system change. Window 1's own two mid-session restarts (dashboard, hw-monitor; see
§1) were performed under State Snapshot discipline per its own account; not independently
re-verified against a snapshot artifact by Window 2 tonight.

## 6. ⚠ Standing elevated grants — REVIEW FOR REVOCATION

Live-reverified 2026-08-17 nightly closeout, via `sudo -n -l` and `getent group <name>`.

### `<user>`'s `pihole` group membership — CONFIRMED live
Unchanged from every prior closeout that's checked it. Still for the cardinality tool
(`~/work/nemesis-internal/tools/pihole-cardinality.py`). Same standing note as before: worth
its own revoke decision once that tool's current use is done, not urgent tonight.

### Suricata rule-deployment grants — CONFIRMED live
`tee /etc/suricata/rules/local.rules` plus `systemctl reload/restart suricata`, matching the
previously-tracked `nemesis-suricata-rules` grant in shape. Not required for normal Nemesis
operation; re-check at each closeout.

### ⚠ Two grants found live tonight, NOT in this file's prior tracked list
- `(ALL) NOPASSWD: /usr/bin/ip, /usr/local/bin/piactl` — `piactl` is PIA VPN's control
  binary. Likely a leftover from the PIA VPN evaluation work already noted in
  `PUNCHLIST.md`'s `[FUTURE] PIA VPN deliberately disabled` entry, but that's inference, not
  confirmed — **not verified against a specific prior session tonight**, flagged rather than
  assumed.
- `(ALL) NOPASSWD: /usr/bin/systemctl restart hw-monitor` — plausibly a convenience grant
  from iterative hw-monitor testing (today's Gap 3b work, or earlier), also **not confirmed
  against a specific origin tonight**.

Neither line traces to `install.sh` (`grep`-checked, zero hits for `piactl` or `restart
hw-monitor` in the installer) or to any previously-tracked grant in this file's history.
Both are real, live, passwordless. **Flagged for an explicit keep/revoke decision next
session** — not treated as confirmed-necessary just because they're already live, per the
standing instruction that an unconfirmed claim gets flagged as contradicted, not written
down as fact.

The baseline `(ALL : ALL) ALL` line in the same `sudo -l` output is the standard
password-required Ubuntu admin grant from `paul` being in the `sudo` group — not a NOPASSWD
entry, not new, not part of this tracked list.

## 7. Known issues/gaps, not yet fixed

Carried forward unchanged from prior closeouts unless noted: the Rule-8 username finding,
`NEMESIS_AGENT_EXE`'s real home path, `migrate_to_opt.sh` fragility, missing ADR for the
`/opt` relocation, `backupproc.md` unconfirmed for current layout, ADR 0015 vs.
venue-guest-network tension (unresolved), no hardware baseline beyond the gauge VM, ruleset-
rollback residual (bounded, fix deferred).

**New tonight:**
- The live-worklog habit lapsed again (second time now, prior instance 2026-08-08) —
  reconstructed at closeout rather than written as-you-go. Re-establish it live next session
  rather than let this become the normal pattern.
- The undeployed-but-committed pile (§1, §3 item 1) has grown to include the entire
  licensing/cap-enforcement feature — materially higher-stakes than the usual "code is ahead
  of the running system" note this file has carried for weeks.
- Two unreviewed sudo NOPASSWD grants surfaced live (§6) that weren't in any prior tracked
  list — first time this file has found something in the elevated-grants check that it wasn't
  already watching for.

## 8. Cross-references

- `docs/handoff/supplements/2026-08-17-001.md` — curated narrative, this closeout.
- `docs/handoff/worklog/2026-08-17-001.md` — reconstructed raw log (see its own process-gap
  note).
- `docs/audits/nginx-config-drift-audit-2026-08-16.md` — written this session, still
  uncommitted (§1, §3).
- `docs/architecture/0021-dos-resilience-scoping.md` — the earlier finding the nginx audit
  extends.
- `docs/architecture/0022-source-available-license.md` — new tonight; the LICENSE decision
  record.
- `known-limitations/cap-guard-bypass-disclosure-2026-08-17.md` (private mirror) — the
  Rule-10-withheld bypass detail from the cap-enforcement commit.
- `~/work/nemesis-internal/handoff/2026-08-16-window1-handoff.md` — Window 1's own context
  handoff for today's build work; far more detail on design rationale than this file carries.
- `~/work/nemesis-internal/legal/LICENSE-draft-2026-08-17.md` — reference copy of the LICENSE
  draft, uncommitted in that repo.
- `PUNCHLIST.md` — the `[HIGH — legal, not just docs]` LICENSE entry, and the rewritten
  fingerprint-loader entry.
- Prior day with a closeout: `docs/handoff/supplements/2026-08-08-002.md` (nine days prior —
  no closeout was recorded in the intervening days).

## Topology (durable, unchanged from prior handoffs unless noted)
- `:80` nginx (Basic-auth; auth-bypass for `/install/windows/` + `/api/health`), LAN-scoped
  SSH/HTTP rate limiting at the ufw layer plus nginx's own `limit_req`. **Deployed config has
  drifted from what `install.sh` generates** — see the still-uncommitted nginx audit (§1).
- `:5000` Flask dashboard — **CORRECTED 2026-08-18: live, not pending.** Directly confirmed
  via `ss -tlnp`: `127.0.0.1:5000`, loopback-only, matching `9df9b9e`'s change. ~~binds to
  `127.0.0.1` instead of `0.0.0.0`... live production is still on the old `0.0.0.0` bind
  until this pile is deployed~~ was wrong when written — see §1's correction note. `:5001`
  hw-monitor agent endpoint — still `0.0.0.0` **by design**, not a gap: Gap 3a's fix was
  specifically the dashboard's loopback bind, and `:5001`'s protection is `21b3541`'s
  application-layer source guard (also confirmed live, same restart), not a loopback bind.
  Directly confirmed via `ss -tlnp`.
- `nemesis-fwd` — Unix-socket privileged helper, peers: dashboard, alert-watcher, `fail2ban`
  (narrow: `block_ip`/`deny_ip` only, cannot release), `write_env`/`restart_dashboard` ops
  (dashboard peer only).
- `nemesis_enforce` — owned nftables table (ADR 0019), priority-placed ahead of the filter
  hook, derived from `ufw`'s live state. Real DROP authority live since 2026-08-02.
- ~~**New tonight, committed but not deployed:** the licensing engine's tables... do not
  exist yet on the live DB; `core/cap_guard.py`'s enforcement is not yet active on any
  running process.~~ **WRONG, corrected same-day — see §1.** `license_state` and
  `license_backup_codes` exist live, confirmed by direct read-only query;
  `agent_devices.remote_enabled*` and `enrollment_tokens.remote_enabled` exist live;
  `cap_guard.py`'s enforcement is the code currently serving `/api/agent/installer/generate`
  and the download route on this box.
