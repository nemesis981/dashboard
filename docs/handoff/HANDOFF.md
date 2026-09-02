# HANDOFF — current state

> Last updated **2026-09-02, end-of-session closeout (Window 2)**. Supersedes the earlier
> 09-02 "emergency pre-reboot checkpoint" — that reboot never happened (see §7). Real IPs/
> hosts/accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` — placeholders
> here per Rule 8.
>
> Full detail: `docs/handoff/supplements/2026-09-02-001.md` (curated, appended through the
> day) and `docs/handoff/worklog/2026-09-02-001.md` (raw chronology, appended through the
> day).

---

## 1. Push status — READ THIS FIRST

**Public repo (`/opt/nemesis`): `local` is 16 commits AHEAD of `origin`. NOT PUSHED.**
- `local` HEAD: `ef90806`
- `origin/main`: `1e1cd00`
- Working tree: **clean**.
- Full unpushed range (`git log --oneline origin/main..HEAD`), newest first:
  ```
  ef90806 test(usb-control): pin the real Win11 collector output as a regression sample   [Window 1]
  468cc46 docs(handoff): elevated-grants re-check -- 2026-09-02 Morning Status              [Window 2]
  82b5247 docs(handoff): emergency pre-reboot checkpoint -- 2026-09-02                      [Window 2]
  07ace9e feat(usb-control): structured Windows USB collector (pure core) + dispatch        [Window 1]
  17ce5ab docs(audit): mark the ARP broadcast-MAC gap CLOSED (c372b5b)                      [Window 1]
  c372b5b fix(device_scanner): exclude broadcast MAC from /proc/net/arp parse               [Window 1]
  547234f docs(audit): correct the ARP finding -- one gap, not two (Window 1 caught it)     [Window 1]
  d919936 fix(lan_integrity): bounded first-run lookback + event-ts staleness in eve tailer [Window 1]
  a2aaada docs(audit): scope two consolidations from the duplication sweep -- design only   [Window 1]
  34e7d04 docs(net-identity): record why 3 other net_if_addrs sites are NOT consumers       [Window 1]
  dd6eef0 docs(punchlist): file the lan_integrity eve.json latent-bug finding               [Window 1]
  f3202bd docs(audit): codebase-wide duplicated/drifting-logic sweep                        [Window 1]
  86a3c83 feat(usb-control): read-only /api/usb-events operator view (v1 final piece)       [Window 1]
  0ca9f8e feat(usb-control): removable-media device control v1 -- structured Linux build    [Window 1]
  a89270f docs(audit): repair a self-contradicting sentence left by the correction          [Window 1]
  1119c75 docs(audit): correct my own sweep -- it claimed zero findings on a guess          [Window 1]
  ```
  Attribution confirmed via `Claude-Session` trailer (shared git identity `Nemesis981` makes
  the author field unusable — see standing shared-tree discipline), not inferred from subject
  alone. Window 1's own 2026-09-02 closeout handoff (`~/work/nemesis-internal/handoff/
  2026-09-02-window1-handoff.md`, "PRODUCTION STATE" section, written ~18:43) independently
  lists this exact same 16-commit range and names `468cc46` as the one that's not its own —
  matches what this window found independently. Reads as effectively ready-to-land, but
  **still requires a fresh listing + explicit operator confirmation immediately before the
  push itself**, per standing discipline — not done as part of this closeout.
- Deploy status (separate from push): `05d27c9` (vpn_dns_guard latch fix) and `d0d4fb2`
  (anti-fiction baseline fix) are committed but **NOT deployed** — the running guard has
  neither. Window 1 flagged deploy as state-changing, needing a USB snapshot + operator
  go-ahead first, unrelated to the push question above.

**Private repo (`~/work/nemesis-internal`): FULLY SYNCED across both remotes.**
- `HEAD` = `local/main` = `usb/main` = `fed3b68`. Verified live this session (fetched both,
  compared SHAs directly, not recalled).
- `usb` remote drive confirmed this session: **Seagate One Touch** (`/dev/sda2`, exFAT,
  mounted at `/run/media/paul/storage`) — not the WD Blue, which is VM-archive only
  (`/mnt/nemesis-vmarchive`, unrelated to any git remote).
- Working tree: **not** clean — see below. None of this blocks the sync claim above; sync is
  about commits, and all commits are pushed. The uncommitted material is separate.
  - `migration/magicdns-deploy.sh` — modified, uncommitted, Window 1's, still in-flight per
    Window 1's own handoff (not flagged there as abandoned). Not mine to commit.
  - `handoff/elevated-grants-tracking.md` — modified, uncommitted. **This one is mine** — the
    mirror copy from this session's Morning Status update. Left uncommitted deliberately;
    the source of truth is the committed copy in `/opt/nemesis` (`468cc46`), this is just the
    local mirror per Rule 12 and mirrors are not independently version-controlled.
  - 5 untracked files — other windows' audit/briefing output not yet committed by their
    owners: `audits/proton-permanent-killswitch-RESOLVED-2026-09-02.md`,
    `briefing/2026-09-01.md`, `briefing/2026-09-02.md` (this window's own mirror, untracked
    same reason as above), `handoff/supplements/2026-08-31-001.md`,
    `handoff/worklog/2026-08-31-001.md`.

**My own committed work: fully pushed where I control the remote** (the elevated-grants
tracking-file commit `468cc46` is public-repo-local only pending the origin push above, same
as everything else in that range — I have no separate push channel of my own for the public
repo).

## 2. Live service state (verified this session)

All 8 core services `active`: `dashboard`, `watchdog`, `alert-watcher`, `malware-canary`,
`diagnostics-watcher`, `vpn-dns-guard`, `nemesis-fwd`, `device-scanner`.

## 3. What's actively in-flight (not mine, described for whoever resumes)

**Window 1 — USB device-control thread, now CLOSED per its own handoff:**
Both platforms (Linux + Windows) built and live-validated on real hardware; the earlier VM
accessibility blocker was resolved and closed (`b68c2c1`). Windows backend proven: the
USBSTOR-disk-serial-inside-parent-USB\VID correlation holds on real hardware, and the same
physical stick keys identically through both OS backends. **One hop explicitly NOT
exercised and stated as such by Window 1: agent→server HTTP** — not to be read as fully
end-to-end. `ef90806` pins a real Windows 11 (build 26200) collector output as a regression
fixture, mutation-proven (4 mutants detected, `EXPECTED_CHECKS` 35→45).

**Window 1 — `net_identity.py` six-site follow-up: still open, scope decision pending.**
3 of 6 identified "what are my own local addresses" call sites consolidated
(`firewall.py`, `lan_behavior_monitor`, `post_detection_egress`). The other 3
(`agent_source_guard.py`, `remote_census.py`, `nemesis_agent/agent.py`) independently
verified by both windows to be legitimately different concerns, not missed consumers.
Window 1 said it would surface the full six-site picture to the operator for a scope call;
not confirmed whether that reached the operator.

**Window 1 — 4 items owed to Window 2**, per its own handoff: see
`~/work/nemesis-internal/handoff/2026-09-02-window1-to-window2-latch-fix.md`. Not reviewed
by this window this session — flagged so it isn't dropped.

**Window 3** — posted a "full pre-reboot rewrite -- final true state, not a patch"
(`c2db944` in the private repo, pushed) reacting to the same never-happened reboot this
window's checkpoint was written for. Not read in full this session; check that commit
directly for anything current beyond what's summarized here.

## 4. Today's shipped work — see the supplement for full detail

Very large session (see `docs/handoff/supplements/2026-09-02-001.md`, appended through the
day, for the full account). Headline threads: MagicDNS/killswitch DNS guard (2 real bugs
found/fixed, deployed independently confirmed); `lateral-movement-outbreak-detection.md`
scoped, built, and deployed same day (`lan_behavior_monitor` module, two finding types);
`threat_feeds` module shipped (Window 3); three roadmap-tracked features found shipped with
zero roadmap coverage, closed (3 new roadmap docs + ADR 0030); ADR 0002's stale supersession
banner fixed; `enrollment-modes-build-spec.md` corrected and moved PARKED→PARTIAL, shipped
same day; new CLAUDE.md standing practice added (roadmap dependency claims must be verified
against code at build-pickup time); `CUSTOM_TAILSCALE_UNINSTALL.md` written; two compiled
decision documents written to the private mirror; USB device-control (Linux + Windows)
built and live-validated end-to-end on real hardware (see §3).

## 5. Roadmap-vs-state

Baseline: `docs/audits/roadmap-state-audit-2026-09-02.md` (refreshed twice today via
addenda). **Tally: 16 SHIPPED / 14 PARTIAL / 58 PARKED = 88 total.** File-set check this
session: `docs/roadmap/*.md` → 90 files (2 more than the 88 tracked; not reconciled
item-by-item, flagged as inference not verified drift). Does NOT yet reflect today's newest
work (the `net_identity` six-site follow-up, the completed USB device-control build) —
tomorrow's Morning Status should expect further drift already baked in.

## 6. Elevated grants

Full live re-check this session (production box). See
`docs/handoff/elevated-grants-tracking.md` (updated in place, committed `468cc46`):
- `sudo -n -l`: 70 NOPASSWD entries, all narrowly scoped, unchanged in kind from prior
  sessions. No broad `(ALL) NOPASSWD:` grant.
- `tcpdump` file capabilities unchanged, still active Tier 2 use.
- `pihole` group membership on the operator account — still open, no new decision.
- **New this check:** `nemesis-fw` group gained `nemesis-vpndns` as a member (alongside
  the existing `nemesis-alertw`, `nemesis-dash`). Plausible but **unverified** cause: today's
  shipped MagicDNS/killswitch work needing firewall write access.
- Polkit rules (`/etc/polkit-1/rules.d/`) — still unreadable from this session's privilege
  level, 5th consecutive session.
- Gateway-VM fleet grant — not re-checked (production-box-only scope, open question
  unresolved).

## 7. Why this closeout differs from a routine one

Written at the end of a session that resumed past its own earlier "emergency pre-reboot"
checkpoint (`docs/handoff/supplements/2026-09-02-001.md`'s original text) once it became
clear, live, that the anticipated reboot never happened (`uptime` continuous since 08-28).
Both other windows kept working across that gap — this file reflects the fully current
state as of this closeout, not a patch on top of the stale checkpoint.

**Two items intentionally NOT resolved this session, both requiring the operator:**
1. Whether to push the public repo's 16 unpushed commits to `origin` — see §1's full listing.
   Effectively ready per both windows' independent accounting, but push-coordination
   discipline requires a confirmation cycle immediately before the push, not a decision
   inferred from a closeout note.
2. Whether to deploy the two committed-but-undeployed `vpn_dns_guard` fixes (§1) — state-
   changing, needs a USB snapshot first per the State Snapshots discipline.

## 8. Cross-references
- `docs/handoff/worklog/2026-09-02-001.md` — raw chronology, appended through the day
  (checkpoint + this closeout's continuation).
- `docs/handoff/supplements/2026-09-02-001.md` — curated account, appended through the day
  (includes a correction section for what changed after the original checkpoint text).
- `docs/audits/roadmap-state-audit-2026-09-02.md` — today's roadmap baseline.
- `docs/briefing/2026-09-02.md` — this session's Morning Status briefing (gitignored,
  local-only; mirrored to `~/work/nemesis-internal/briefing/`).
- `docs/handoff/elevated-grants-tracking.md` — elevated-access running record, updated in
  place this session.
- `~/work/nemesis-internal/decisions/2026-09-02-OPEN-business-legal-decisions-COMPILED.md`
  and `...-OPEN-other-decisions-COMPILED.md` — the two compiled decision documents.
- `~/work/nemesis-internal/handoff/2026-09-02-window1-handoff.md` (updated ~18:43, the most
  current Window 1 note) and `2026-09-02-window3-handoff.md` — the two build windows' own
  cold-start notes; read these directly for anything this file compresses away.
