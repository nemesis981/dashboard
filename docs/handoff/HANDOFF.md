# HANDOFF — current state

> Last updated **2026-09-02, emergency pre-reboot checkpoint (Window 2)**. Written ahead of an
> imminent system reboot, not a normal end-of-day closeout — see §7 for exactly what that
> changes. Overwrites the 09-01 nightly closeout (Rule 9). Real IPs/hosts/accounts/keys live
> ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8.
>
> Full detail: `docs/handoff/supplements/2026-09-02-001.md` (curated) and
> `docs/handoff/worklog/2026-09-02-001.md` (raw chronology, reconstructed at this checkpoint —
> today had no live worklog kept, same gap as 09-01).

---

## 1. Push status — READ THIS FIRST

**Public repo (`/opt/nemesis`): `local` is AHEAD of `origin` by 1 commit.**
- `local`: `07ace9e`
- `origin/main`: `1e1cd00`
- The one gap: `07ace9e` (`feat(usb-control): structured Windows USB collector (pure core) +
  dispatch`, Window 1, committed 16:47:52) — **committed locally, NOT pushed, NOT confirmed
  by the operator.** Do not push it on this note alone; get explicit confirmation first, per
  this session's standing push-coordination discipline.
- Working tree: **clean** (`git status --short` empty).

**Private repo (`~/work/nemesis-internal`): `local` remote is 4 commits behind; `usb` remote
is CURRENTLY UNREACHABLE.**
- `local/main..HEAD`: 4 commits, all Window 1's own handoff docs (`6cc5c95`, `cdd8cab`,
  `47ad3ef`, `1e2af28` — oldest to newest, 15:20–16:48 today). Not pushed, not confirmed.
- `usb` remote: `fatal: couldn't find remote ref usb` on fetch — **the USB drive is not
  mounted right now** (`mountpoint -q /run/media/paul/storage` → not mounted). This looks
  like deliberate pre-reboot unmounting, not a fault — noted so nobody chases it as a bug.
  Re-mount and re-fetch before trusting any private-repo push-sync claim.
- Working tree: **uncommitted work present, not mine, flagged rather than touched:**
  - `migration/magicdns-deploy.sh` — modified, uncommitted. Window 1's file, mid-edit as of
    this checkpoint. **Not committed by me — I do not commit another window's in-flight,
    unreviewed file.** If Window 1's session doesn't survive the reboot, this diff is at risk
    per the standing "uncommitted work has zero protection" rule — whoever resumes should
    check this file's state first.
  - Six untracked files, all appear to be other windows' audit/mirror output, not mine:
    `audits/community-reporter-identity-audit-2026-09-02.md`,
    `audits/duplicated-logic-sweep-2026-09-02.md`,
    `audits/proton-permanent-killswitch-RESOLVED-2026-09-02.md`,
    `audits/roadmap-stale-premise-sweep-2026-09-02.md`,
    `audits/tailer-and-arp-parser-consolidation-scope-2026-09-02.md`,
    `briefing/2026-09-01.md`, `handoff/supplements/2026-08-31-001.md`,
    `handoff/worklog/2026-08-31-001.md`. **Untracked files survive a reboot** (they're not at
    the same risk as uncommitted tracked-file diffs), but they're also not backed up anywhere
    until committed — worth a deliberate commit pass by whoever owns each one.

**My own work: fully committed and pushed as of this checkpoint.** Nothing of mine is at risk.

## 2. Live service state (verified this checkpoint, not recalled)

All 8 core services `active`: `dashboard`, `watchdog`, `alert-watcher`, `malware-canary`,
`diagnostics-watcher`, `vpn-dns-guard`, `nemesis-fwd`, `device-scanner`.

**Nothing observed in this session depends on any Claude Code process staying alive.** All
work today (code, docs, deployments) was committed to disk and/or already deployed as
systemd-managed services independent of this conversation. A reboot does not orphan
in-progress work at the process level — the risk is entirely at the **uncommitted-diff**
level described in §1, not at the running-process level.

## 3. What's actively in-flight (not mine, described for whoever resumes)

**Window 1 — two build threads, both mid-flight:**
1. **`net_identity.py` consolidation (shipped, `1e1cd00`, already pushed) → six-site
   inventory follow-up (not yet actioned).** Consolidated 3 of 6 identified call sites for
   "what are my own local addresses" logic (`firewall.py`, `lan_behavior_monitor`,
   `post_detection_egress`). The other 3 (`agent_source_guard.py`, `remote_census.py`,
   `nemesis_agent/agent.py`) were investigated this session and found to be **legitimately
   different concerns**, not missed consumers — see `docs/handoff/supplements/2026-09-02-001.md`
   for the full per-site reasoning. Window 1 said it would surface this to the operator
   directly for a scope decision; unclear if that happened before this checkpoint.
2. **USB device-control (`removable-media-device-control.md`)** — Linux/pyudev backend
   already built per Window 1's own handoff (`cdd8cab`, "USB device-control v1 complete"); a
   Windows backend just landed (`07ace9e`, unpushed — see §1) as "pure core," with **live VM
   validation still pending** per that same commit's handoff (`1e2af28`).
3. **`lan_integrity` option-2 fix + a shared-tree incident recovery** (`47ad3ef`) — title
   only known at this checkpoint; read that commit/handoff directly for what happened, no
   time to expand here before this note needed to ship.

**VM test blocker, still open as of the last update I have:** Window 1 reported the
appliance-master VM clone was inaccessible (GA at RunLevel 1, no `vboxnet0` lease) and that
bridging a DHCP/DNS-serving appliance onto the real LAN isn't safe — relying on an in-process
equivalence proof on the real box instead for the `net_identity` work. Unknown whether this
blocker is resolved for the newer USB-control VM validation Window 1 flagged as pending.

## 4. Today's shipped work, condensed (full detail in commit messages + the supplement)

Very large session. Headline threads, each already pushed to `origin/main` unless noted:
- **MagicDNS/killswitch DNS guard** — 05d27c9, d0d4fb2 (two more real bugs found/fixed:
  the latch bug, the anti-fiction baseline bug), independently confirmed deployed.
- **`lateral-movement-outbreak-detection.md`** naming/module placement finalized with
  Window 1 (two finding types, new `lan_behavior_monitor` module, grounded in
  `lan_integrity`'s own stated scoping principles, not assumed) — then **built and deployed
  same day** (`17b0ec0` → `2f9124f` chain, `post_detection_egress` chain
  `81aed37`→`36c3ddb`), independently verified live via `dashboard`'s restart timestamp.
- **`threat_feeds` module** shipped (Window 3, `c741c85`/`fb22ec9`).
- **Three new roadmap-tracked features** that had shipped with zero roadmap coverage:
  `email-security-gateway.md`, `port-broker-access-control.md` (+ new ADR 0030),
  `vpn-dns-guard-magicdns-killswitch.md`. Roadmap audit refreshed twice same day: **16
  SHIPPED / 14 PARTIAL / 58 PARKED = 88** (was 13/13/59 at 08-31's baseline).
- **ADR 0002's stale supersession banner fixed** (was still claiming a refuted diagnosis).
- **`enrollment-modes-build-spec.md`**: 3 real corrections from a Window 3 audit applied
  (stale `enrollment_status` value count, a non-existent `firewall.py` enforcement mapping
  corrected to a stated dependency, an atomic-decrement claim that doesn't fit existing DM
  ops) — file moved PARKED→PARTIAL (BULK-MANUAL, ADR 0012 step 1, shipped and deployed same
  day, verified live via smoke test with a zero-rows-created control).
- **New CLAUDE.md standing practice** (operator-confirmed directly, not via peer relay):
  roadmap dependency claims must be verified against code at build-pickup time, not just a
  file's build-status header — closes a gap that caused two real incidents this week.
- **`CUSTOM_TAILSCALE_UNINSTALL.md`** written (an owed vendor-integration doc, flagged by
  Window 1).
- **Two compiled decision documents** written to the private mirror at operator request:
  `decisions/2026-09-02-OPEN-business-legal-decisions-COMPILED.md` (8 items — Option B
  venue/commercial legality, community-reporter-identity's tier-vocabulary and
  salt/accountability questions, ADR 0022's still-draft license, two live Rule 10 flags,
  ADR 0028's email-interception and shared-mailbox questions, the TLS-interception module's
  3-remote exposure) and `...-OPEN-other-decisions-COMPILED.md` (4 items — scope/sequencing
  calls). Both pushed to both private remotes.
- **A source-protection scoping pass** (Nuitka/Cython/PyArmor, full/hybrid Go-Rust migration
  feasibility) — reported in-conversation, not written to a file; if that analysis needs to
  survive as a document, it does not currently exist as one and would need transcribing from
  this conversation's history.

## 5. Roadmap-vs-state

Baseline: `docs/audits/roadmap-state-audit-2026-09-02.md` (refreshed twice today via
addenda, not a fresh dated file — see that file's own §3a and the later PARKED→PARTIAL note).
**Tally: 16 SHIPPED / 14 PARTIAL / 58 PARKED = 88 total.** This does NOT yet reflect
today's newest work (the six-site `net_identity` follow-up, the USB device-control build) —
whoever runs tomorrow's Morning Status roadmap check should expect further drift already
baked in, not a clean baseline.

## 6. Elevated grants

Not re-checked at this checkpoint (emergency note, not a full Morning-Status pass). Last live
check: 2026-09-02 morning, see `docs/handoff/elevated-grants-tracking.md` — no changes known
since then, but "known since then" is not the same as "re-verified now."

## 7. Why this checkpoint differs from a normal closeout

This was written on request, ahead of an imminent reboot — not at a natural end-of-session
point. Consequences for whoever reads this next:
- **No closeout health check was run** (Rule 9's usual final step) — this file itself is the
  check.
- **Two other windows' work (Window 1's four private-repo handoffs, its one public commit,
  and Window 3's private-repo audit outputs) are described but not evaluated for
  push-readiness** — that's a decision for whoever resumes with the operator, not assumed
  here.
- **If the reboot is disruptive** (a session doesn't survive it), the uncommitted diff in
  `migration/magicdns-deploy.sh` (§1) is the one piece of real, at-risk work identified this
  checkpoint. Everything else on disk is either committed or untracked-and-therefore-inert
  until someone acts on it.

## 8. Cross-references
- `docs/handoff/worklog/2026-09-02-001.md` — raw chronology (reconstructed at this
  checkpoint).
- `docs/handoff/supplements/2026-09-02-001.md` — curated account, fuller detail than this
  file's condensed §4.
- `docs/audits/roadmap-state-audit-2026-09-02.md` — today's roadmap baseline (refreshed
  twice via addenda).
- `~/work/nemesis-internal/decisions/2026-09-02-OPEN-business-legal-decisions-COMPILED.md`
  and `...-OPEN-other-decisions-COMPILED.md` — the two compiled decision documents.
- `~/work/nemesis-internal/handoff/2026-09-02-window1-handoff.md` and
  `2026-09-02-window3-handoff.md` — the two build windows' own cold-start notes (read these
  for anything this file compresses away).
