# HANDOFF — current state

> Last updated **2026-08-21, nightly closeout (Window 2)**. Overwritten each closeout
> (latest state wins). Durable history: `docs/handoff/supplements/` (append-only). Real
> IPs/hosts/accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` —
> placeholders here per Rule 8.
>
> Full detail behind every claim below: `docs/handoff/supplements/2026-08-21-001.md`
> (curated) and `docs/handoff/worklog/2026-08-21-001.md` (raw log, kept live all session).
> Also see `2026-08-20-002.md` / `2026-08-20-001.md` for the tail end of the prior day.

---

## 1. Push status — all clear, `origin/main` == local HEAD

Nothing pending push in the public repo as of this writing. `git rev-parse HEAD` ==
`git rev-parse origin/main` == `c7ac0cce837ac7daa709aa2bac28743330f9bccc`.

Today's 8 commits (most recent first) — the zero-day M1-M4 cores + operational gaps 1-3,
4 AI-mode fixes, and the AI-surfacing PUNCHLIST entries — see
`docs/handoff/supplements/2026-08-21-001.md` for the full list with descriptions.

## 2. FIRST THING NEXT SESSION — read Window 1's commit-ordering plan before touching anything

`~/work/nemesis-internal/handoff/2026-08-21-window1-handoff.md`, section "HELD FILES for
Window 2", has an explicit, ready-to-execute plan (groups A through H) for the large
held-work batch sitting uncommitted in the working tree right now. It resolves tonight's
specific blocker (see §3) and gives dependency ordering across features from BOTH build
windows. Read that section before staging anything — don't re-derive the grouping from
`git status` alone.

## 3. The blocked batch from tonight — now resolved, not yet executed

Asked tonight to pull: merged `sysmon_collector.py` + tests, `sandbox.py` /
`build_detonation_base_linux.sh` / `behavioral_agent.py`, new Windows detonation artifacts,
`install.sh` + the ISO-dependency doc section. Everything checked out (Rule-8 clean, tests
independently re-verified) **except one real cross-file coupling hazard**:
`build_detonation_base_linux.sh` calls `deploy_behavioral_linux.sh --extra-rules`, but that
flag only exists in the still-uncommitted `deploy_behavioral_linux.sh` — the currently-
committed version (`c091ed5`) hard-exits on any unrecognized argument. Committing
`build_detonation_base_linux.sh` alone would have broken the base-image build script.
Nothing was staged; the operator asked for a nightly closeout instead of resolving it
in-session.

**Resolved while reading Window 1's handoff, not yet acted on**: their own commit-ordering
plan groups `deploy_behavioral_linux.sh` + `build_detonation_base_linux.sh` together as one
unit ("Layer B behavioral fixes") — confirming the flag and its caller are meant to land in
the same commit. Next session should follow that grouping rather than re-litigating it.

## 4. What's live in production vs. what's only committed

**Pushed today, NOT deployed** — no auto-deploy in this repo; everything below needs an
operator-driven install/restart to take effect anywhere real: all 8 of today's commits
(zero-day M1-M4 + 3 operational gaps, 4 AI-mode fixes). Nothing before today changed this
picture.

## 5. Open items, priority order

1. **Execute Window 1's commit-ordering plan (groups A-H)** for the large held batch —
   see §2. Spans steering/L3 forwarder, Windows detonation sandbox, Windows behavioral
   (Sysmon), synthetic sample suite, Layer B behavioral fixes, agent GUI findings tab,
   ai-engine work, and docs/audits. Four files (`agent.py`, `behavioral_agent.py`,
   `config.py`, `agent_errors.py`) are flagged by Window 1 as genuinely mixed across
   multiple features and will need `git add -p` hunk-splitting, not a blanket add — same
   discipline already used tonight for `ai_engine/module.py`.
2. **Two docs remain deliberately deferred** (operator's own call, not forgotten):
   `CUSTOM_SYSMON.md` and the Windows section of `CUSTOM_DETONATION_SANDBOX.md` — come
   later once Window 1's endpoint deploy script work clarifies what needs documenting.
3. **A much larger volume of held work exists beyond the commit-ordering plan** — Window 1's
   memory-injection detection arc (Tier 2 attestation, RAM-budget consumer, Linux
   memory-inspection, Windows authenticated-IPC) and Window 3's AI-automation-mode Phase 1
   (paused at a scoping gate), master-password-authority rebuild, and IP-reversal handlers.
   None of this is in the commit-ordering plan above (it landed after that plan was
   written, or is still mid-build) — read both windows' full 2026-08-21 handoffs before
   assuming §2's plan is exhaustive.
4. **The three 08-08 error-code-classification batches** — many days unclaimed, unchanged.
5. **`docs/audits/roadmap-state-audit-2026-08-19.md`** — still uncommitted, unchanged.
6. **`install.sh` still doesn't wire `malware-scan.service`** — open since 2026-08-18.
7. **`LICENSE` draft's real legal review** — placeholders filled, review unstarted.
8. **Private repo (`nemesis-internal`) has unpushed commits** — Window 1's handoff reports
   4 unpushed (theirs + one Window 3 handoff) as of their closeout. Window 1 is the primary
   git-writer there; Window 2 can push as backup if asked, but wasn't asked tonight — this
   is a heads-up, not an action taken.

## 6. Do NOT touch — the working tree is mid-build for BOTH other windows, snapshot only

`git status` at closeout showed a very large and still-growing set of modified/untracked
files across both windows' work (steering/forwarder, Windows detonation, Sysmon behavioral,
synthetic samples, memory-injection detection, AI automation-mode scoping, master-password
authority, IP reversal). **Do not treat any specific file list in this document as
exhaustive or current — re-run `git status` fresh next session.** The one reliable
reference is Window 1's commit-ordering plan (§2), which names the held set as of their
closeout and should be re-verified against a fresh `git status` before executing, since both
windows may have kept working after writing it.

`modules/malware_detection/synthetic_samples/` specifically: confirmed by Window 1's
handoff as Window 1's own work, with a deliberate operator decision that the AV-triggering
fixtures (EICAR/YARA-signature/PE samples) are **private-mirror only** (gitignored in
public) — only the harness `.py`/`.sh` files are meant for the public repo. Worth
double-checking that `.gitignore` entry is actually in place before staging this directory.

## 7. Verified live today, not just claimed (Rule 3 discipline)

Every commit today carried independent verification by this window: every hunk of every
multi-window-touched file read and categorized personally before deciding how to split it
(not just trusting either build window's description of what changed where); claimed test
pass counts independently re-run and confirmed to match exactly (24/24, 12/12, 19/19,
30/30, 13/13, 16/16→23/23, 28/28, 14/14, 25/25, 22/22, 67/67, plus more); one real
misattribution caught and corrected (`agent_errors.py` was not actually part of the zero-day
batch despite being counted as one of the "4 modified files"); one real cross-file breakage
caught and stopped before it was committed (§3, the `--extra-rules` coupling).

## 8. State snapshots

None taken today by this window — every state-changing action was a code commit, not a
direct production data/config change.

## 9. Elevated grants

**Baseline established 2026-08-22 — diff against this going forward.** No prior itemized
list existed in this file to compare against; the 2026-08-20 worklog only recorded a
shape-level finding ("no broad NOPASSWD"), not an itemized list. This is that itemized list,
captured live via `sudo -n -l` / `getent group` / `id <user>` during the 2026-08-22 Morning
Status pass and folded in as an explicit follow-up.

- **sudo NOPASSWD — scoped, install/service-management shaped, not broad.** The
  `(ALL : ALL) ALL` line is the standard admin-group entry (password required, NOT
  NOPASSWD) — expected for the operator's sudo-group account, not itself a standing grant to
  track.
  Below that, `sudo -n -l` lists narrow, command-specific NOPASSWD entries only, all
  matching the installer's own footprint:
  - `ufw`
  - `systemctl start/stop/restart` for the six core services (`dashboard`,
    `diagnostics-watcher`, `alert-watcher`, `vpn-dns-guard`, `malware-canary`, `watchdog`,
    `device-scanner`) plus `nemesis-fwd` (restart only); `daemon-reload`; `reset-failed
    dashboard`
  - `tee` + `chmod 0644` for each of those services' systemd unit files, and for
    `/etc/polkit-1/rules.d/10-nemesis-watchdog.rules`
  - `groupadd --system nemesis-db`; `useradd --system --no-create-home --shell
    /usr/sbin/nologin --gid nemesis-db` for the six `nemesis-*` service accounts
    (`nemesis-diag`, `nemesis-hwmon`, `nemesis-alertw`, `nemesis-vpndns`, `nemesis-canary`,
    `nemesis-watchdog`)
  - the one-time `/opt` migration set: `mkdir -p /var/lib/nemesis`; `mv` for
    `/home/<user>/dashboard` → `/opt/nemesis` and `alerts.db`(+`-wal`/`-shm`) →
    `/var/lib/nemesis`; matching `chown <user>` / `chgrp nemesis-db` / `chmod 0770`|`0660` on
    those paths; `chmod 0755 /opt/nemesis`
  - `tee` + `reload`/`restart` for `/etc/suricata/rules/local.rules`
  - **Reason still needed:** this is install.sh's own sudoers footprint for provisioning and
    managing the Nemesis services/accounts without a password prompt on every install/update
    step — narrow, command-scoped, no wildcard/shell-out entries observed. No revocation
    action indicated; this stays listed as "still needed" per Rule 7's framing, not flagged
    for revoke.
- **Group memberships** (`id <user>`): `nemesis-db`, `nemesis-fw`, `pihole` — the three
  groups this file's Morning Status section names as meaningful-access groups. `nemesis-fw`
  group membership: the operator account, `nemesis-alertw`, `nemesis-dash`. Also present but
  outside this rule's named set: `adm`, `cdrom`, `sudo`, `dip`, `plugdev`, `users`,
  `lpadmin`, `piavpn`, `nemesis` — standard desktop/admin groups plus VPN-client and a bare
  `nemesis` group, none flagged as needing tracking here. No unexpected group membership
  observed.
- **Polkit rules** (`ls /etc/polkit-1/rules.d/`): **not checked** — `Permission denied` for
  this session's user (needs root to read on this box, per this file's own standing note).
  Carrying forward as explicitly unverified, not silently skipped.

Re-verify each item above at next session start per Rule 7 — this list is the new
comparison baseline, not a permanent record assumed still accurate.

## 10. Cross-references

- `docs/handoff/supplements/2026-08-21-001.md` — curated narrative, today.
- `docs/handoff/worklog/2026-08-21-001.md` — chronological detail, kept live all session.
- `docs/handoff/supplements/2026-08-20-002.md` / `worklog/2026-08-20-002.md` — the tail end
  of yesterday (agent_last_seen fix, GUI/DMZ/sentinel/QUIC split, private-repo pushes).
- `~/work/nemesis-internal/handoff/2026-08-21-window1-handoff.md` — the commit-ordering
  plan (read this first next session), memory-injection detection arc, KEEP VMs, gotchas.
- `~/work/nemesis-internal/handoff/2026-08-21-window3-handoff.md` — AI automation mode
  status, Windows detonation Phase 3, master-password rebuild, IP reversal handlers.
- `PUNCHLIST.md` — 4 new AI-surfacing entries filed today.
- Prior day: `docs/handoff/supplements/2026-08-19-001.md`.

## Topology (durable, unchanged from prior handoffs unless noted)

No topology changes today. See `docs/handoff/supplements/2026-08-19-001.md` for the last
full topology summary.
