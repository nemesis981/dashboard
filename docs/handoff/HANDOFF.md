# HANDOFF — current state

> Last updated **2026-08-17, nightly closeout (Window 2)**. Overwritten each closeout (latest
> state wins). Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/
> accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per
> Rule 8.
>
> Full detail behind every claim below: `docs/handoff/supplements/2026-08-17-001.md` (curated)
> and `docs/handoff/worklog/2026-08-17-001.md` (raw log, reconstructed at closeout — see its
> own process-gap note).

---

## 1. Live in production right now — verified, not assumed

- **`origin/main` is at `6597853`** as of this writing (confirmed `HEAD == origin/main` via
  fresh fetch after every push today, re-confirmed at closeout). 15 commits landed and pushed
  this session.
- **Nothing landed today has been deployed to this box's running services**, except two
  pieces Window 1 deployed itself under State Snapshot discipline mid-session (per its own
  handoff): `dashboard` restarted 11:01:57 (after `8981f52`), and the 11:03 live Tailscale
  E2E revoke ran through that actual production process; `hw-monitor` restarted 2026-08-16
  19:31:39 for Gap 3b. Everything committed AFTER those two restarts — the full licensing
  engine, cap enforcement, the fingerprint fix, the orphan-display fix, the production
  signing key, the backup-codes fix — is **committed but not yet running** on this box.
  `init_licensing_tables()` has never executed against the live DB; the `remote_enabled`
  columns have never been created on the live `agent_devices` table. **This pile needs a
  deliberate deploy decision** — same recurring note as prior closeouts, now covering a much
  larger and more security-relevant set of changes than usual.
- **Directly verified on this box at closeout** (Rule 3): all 8 checked services
  (`dashboard`, `watchdog`, `alert-watcher`, `malware-canary`, `diagnostics-watcher`,
  `vpn-dns-guard`, `hw-monitor`, `nemesis-fwd`) report `active`.
- **Active, uncommitted WIP sitting in the tree right now**, none of it Window 2's, none of
  it touched:
  - `alert_manager/nemesis_fwd.py`, `diagnostics/redact.py` — fail-closed fixes, dated
    2026-08-08 (over a week old now, unclaimed by anyone this session).
  - `core/install_id.py`, `scripts/nemesis-license-issue` — a documented root-vs-dashboard-
    user install-id mismatch finding (docs/comments only, no functional code change).
  - `dashboard.py` (a `_render_license_summary_html()` function + Settings-page card wiring),
    `alert_manager/test_licensing_routes.py` (its tests) — a Settings-page licence
    discoverability card, ready-shaped, not yet committed.
  - `install.sh` — a new, small (+22 line) hunk installing `python3-h2`/`python3-hpack`/
    `python3-hyperframe` for the private L3 Tier 2 delivery gate's HTTP/2 stack. Appeared
    mid-session, unrelated to anything else today, not touched.
  - `docs/audits/error-code-classification-batch1/2/3-2026-08-08.md` — Window 3's read-only
    sweep, unchanged from prior closeouts, still awaiting review.
- **`docs/audits/nginx-config-drift-audit-2026-08-16.md` is still uncommitted**, sitting
  since early this session's own audit. Public and Rule-8-clean, just never landed — worth
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

1. **Deploy decision owed** — see §1. The undeployed pile now includes the entire licensing
   feature and a real security fix (the pasted-key cap bypass); this is materially higher
   stakes than a typical undeployed-code note. Needs a deliberate, State-Snapshot-gated pass,
   not an incidental restart.
2. **`docs/audits/nginx-config-drift-audit-2026-08-16.md`** — write it, then let it sit
   uncommitted for a full session. Commit it next session; nothing about it has changed.
3. **Three ready-shaped, uncommitted licensing-adjacent pieces** (§1): the Settings
   discoverability card, the `install_id.py` root-vs-dashboard-user note (+ its
   `nemesis-license-issue` companion warning). Each was deliberately left out of tonight's
   commits per explicit scope, not because anything is wrong with them — pick up and commit
   when ready.
4. **The 08-08 WIP is now over a week old** (`nemesis_fwd.py`, `redact.py` fail-closed
   fixes) — nobody has claimed it across multiple closeouts. Worth a decision: commit it, or
   explicitly park/discard it, rather than letting it keep aging silently in the tree.
5. **The new install.sh L3 Tier 2 HTTP/2 hunk** — unrelated to tonight's work, appeared
   mid-session, not investigated beyond reading the diff. Flag for whoever owns the private
   L3 Tier 2 module.
6. **LICENSE draft's three open placeholders** (copyright holder legal name/entity,
   commercial-licensing contact, governing law/jurisdiction) plus real legal review —
   tracked in `PUNCHLIST.md`'s `[HIGH — legal, not just docs]` entry, not resolved tonight.
7. **Two sudo NOPASSWD grants found live, not in this file's prior tracked list** — see §6.
   Need a keep/revoke decision, not carried forward silently.

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
- `:5000` Flask dashboard — **as of `9df9b9e` (committed, not yet deployed), binds to
  `127.0.0.1` instead of `0.0.0.0`**; live production is still on the old `0.0.0.0` bind
  until this pile is deployed. `:5001` hw-monitor agent endpoint — **as of `21b3541`
  (committed, not yet deployed on this box's actual process), gains application-layer source
  admission** in addition to the existing token-bucket pacing.
- `nemesis-fwd` — Unix-socket privileged helper, peers: dashboard, alert-watcher, `fail2ban`
  (narrow: `block_ip`/`deny_ip` only, cannot release), `write_env`/`restart_dashboard` ops
  (dashboard peer only).
- `nemesis_enforce` — owned nftables table (ADR 0019), priority-placed ahead of the filter
  hook, derived from `ufw`'s live state. Real DROP authority live since 2026-08-02.
- **New tonight, committed but not deployed:** the licensing engine's tables
  (`license_state`, `license_backup_codes`) and `agent_devices.remote_enabled*` columns do
  not exist yet on the live DB; `core/cap_guard.py`'s enforcement is not yet active on any
  running process.
