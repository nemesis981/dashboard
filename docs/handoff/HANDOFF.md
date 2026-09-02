# HANDOFF — current state

> Last updated **2026-09-01, nightly closeout (Window 2)**. Overwritten each closeout (latest
> state wins). Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/
> accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per
> Rule 8.
>
> Full detail: `docs/handoff/supplements/2026-09-01-001.md` (curated) and
> `docs/handoff/worklog/2026-09-01-001.md` (raw chronology, reconstructed at closeout — see
> that file's own header note). Session ran under an operator-issued tropical-storm/
> power-loss warning from mid-morning; no power event occurred, nothing was lost.

---

## 1. Push status

**Public repo:** `origin/main` == local `HEAD` (`faf7666`), verified. 14 commits landed and
pushed today — the MagicDNS/killswitch DNS guard build (Window 1, 8 commits) plus this
window's docs (elevated grants, the Tailscale-audit sudo grant closure, a user-facing DNS
delay explainer, and a self-corrected PUNCHLIST follow-up).

**Private repo (`~/work/nemesis-internal`, local+usb remotes):** ⚠ **NOT pushed — 82 commits
held.** Fully reviewed tonight (categorized summary in the supplement); the push itself was
blocked by the harness's own permission classifier, most likely due to the scale of the
action (82 commits in one push). `local` and `usb` remain in sync with each other but both
82 commits behind `HEAD`. **Needs explicit operator action to complete** — re-approve the
push or run it directly; nothing in the review found a reason to withhold any of it.

## 2. ⚠ Deploy gap — `dashboard` has NOT restarted since 12:36:56 on 08-31

Still true, over 30 hours later. `vpn-dns-guard` (17:58:13 today) and `nemesis-fwd`
(16:32:33 today) HAVE been restarted with current code — the MagicDNS guard build was
live-tested and is genuinely running current logic. `dashboard` itself is the one process
still on yesterday's build. Check `ExecMainStartTimestamp` against any commit's timestamp
before trusting a dashboard-side live-behavior claim.

## 3. Today's shipped work, condensed (full detail in the supplement)

- **MagicDNS/killswitch DNS guard (ADR 0002 amendment), Window 1.** The Tailscale
  snap→apt migration (identity preserved byte-for-byte) exposed that PIA's killswitch
  blocks the address Tailscale's DNS takeover installs, causing a total DNS outage on VPN
  reconnect. Built, live-tested 6× against PIA + 1× against Proton (generalization test,
  passed — detection is vendor-neutral, evidenced not asserted), found and fixed 5 real
  root causes (a dead call site despite 82 passing tests, a socket-permission gap, an
  oscillation bug, a severed DNS-release path, a Tailscale-side repeated-takeover backup
  loss — closed by a self-repair op). **190 checks passing.** Current live state:
  `accept-dns=True`, MagicDNS working, **safe only because the guard is live and proven** —
  if the guard is ever stopped without also reverting this preference, DNS breaks on the
  next VPN connect with nothing watching.
- **Proton VPN installed on the daily driver** (Window 1, Rule-13-compliant: revert
  written and verified offline-capable before connecting). Used to prove the guard's
  detection generalizes beyond PIA. Cleanup/removal decision not yet made.
- **Tailscale/PIA/snap DNS saga consolidated** into one private-mirror account
  (`~/work/nemesis-internal/known-limitations/tailscale-magicdns-pia-saga-FULL-2026-09-01.md`)
  — corrects a chain of misread symptoms back to 2026-08-01, mistakes kept in
  deliberately. Self-corrected same day when its "not yet built" framing on Option B went
  stale within hours of being written.
- **User-facing doc**: `docs/operation/VPN_CONNECT_DNS_DELAY.md` — explains the existing,
  already-shipped brief-DNS-pause-then-self-heal behavior on VPN connect/disconnect.
  Deliberately scoped away from the MagicDNS-specific case, which didn't self-correct
  without today's new guard.
- **Piece F/G, Tier 2 TLS interception (Window 3, private repo, unpushed there — see §4).**
  Upstream cert-fingerprint capture, gate-side IPC client, wired into the real gate, and a
  randomized re-audit sweep — 169 new checks, Pieces E/F/G now all complete. Real-traffic
  run and daemon deployment remain explicitly on hold (operator decision).
- **Elevated grants**: re-checked live twice; production box clean both times. One closed
  add/revoke cycle recorded (temporary Tailscale-audit sudo grant).
- **Roadmap-vs-state audit**: baseline (08-31, 08:28am snapshot) found to already predate
  ~70 commits of that same day's later shipping — flagged as drift, not corrected in
  place (read-only per Rule 1).

## 4. Open items, queued — not started, not forgotten

- **Private-repo push (82 commits) still not landed** — blocked by the permission
  classifier tonight; the only item genuinely blocking a clean state going into tomorrow.
- **`l3-tier2-tls-interception` (separate private repo) has 16 unpushed commits** —
  Window 3's Piece F/G work. NOT reviewed or pushed tonight (out of scope given the
  `nemesis-internal` review already in progress); deserves its own dedicated review given
  that repo's wider remote set (includes private GitHub) and higher disclosure
  sensitivity.
- **Roadmap audit baseline drift** — flagged this morning, not yet refreshed.
- **Cleanup owed**: orphaned tailnet node `nuKHjHphBz11CNTRL` (non-ephemeral, does not
  self-remove); VM `Nemesis TS-MIGRATION-REHEARSAL 09-01` (powered off, keep only if the
  logged Option-D resolved-stub experiment is still wanted).
- **PUNCHLIST follow-up, correctly not urgent**: verify the MagicDNS guard's design
  against a simulated (non-PIA) killswitch — partially pre-answered by today's real Proton
  test (detection generalizes; the disable/restore path was not exercised under Proton).
- **~100+ untracked files in `~/work/nemesis-internal`** — RESOLVED today (bulk commit
  `43961cb`, 109 files, reviewed as part of tonight's backlog review). No longer open.
- **A1/A2 WebAuthn ceremony, Fork B's `reconcile()` caller gap, WRITE_OPS audit-trail
  gap** — carried forward unchanged from 08-31, not touched today.

## 5. Roadmap-vs-state

Baseline still `docs/audits/roadmap-state-audit-2026-08-31.md` (13 SHIPPED / 13 PARTIAL /
59 PARKED, 85 tracked). Flagged this morning as predating a full day of further shipping;
not refreshed today — today's work (the MagicDNS guard) is itself new roadmap-relevant
material not yet reflected anywhere in `docs/roadmap/`.

## 6. Elevated grants

See `docs/handoff/elevated-grants-tracking.md` (edited in place). Production box confirmed
clean twice today. One grant closed (Tailscale-audit sudo, add+revoke both verified).
`nemesis-vpndns`'s addition to group `nemesis-fw` (for the MagicDNS guard's socket access)
now tracked there.

## 7. Closeout health check

1. **Working tree (public repo): clean** — confirmed via `git status --short` after this
   closeout's own commit.
2. **Closeout commit is HEAD**: confirmed after commit below.
3. **local == origin (0/0)**: confirmed via `git fetch` + SHA comparison after push.
4. **HEAD touched only expected docs**: this closeout commit touches only
   `docs/handoff/HANDOFF.md`, `docs/handoff/worklog/2026-09-01-001.md`,
   `docs/handoff/supplements/2026-09-01-001.md`.
5. **Rule-8 spot-check**: no real IPs/hosts/keys/tokens in this file or its companions —
   placeholders only.
6. **Open items durably captured**: §4 above, plus `PUNCHLIST.md`'s VPN-agnosticism
   follow-up entry (`750c806`).

**Verdict:** clean + synced (public repo) — **private repo NOT synced, 82 commits held,
flagged in §1 and needs operator action.** Not a full "clean + synced" close for tonight.

## 8. Cross-references

- `docs/handoff/worklog/2026-09-01-001.md` — raw chronology.
- `docs/handoff/supplements/2026-09-01-001.md` — curated account, full day.
- `docs/handoff/elevated-grants-tracking.md` — standing elevated-grants record.
- `docs/briefing/2026-09-01.md` — this morning's Morning Status briefing.
- `docs/audits/roadmap-state-audit-2026-08-31.md` — current (stale) roadmap baseline.
- `~/work/nemesis-internal/known-limitations/tailscale-magicdns-pia-saga-FULL-2026-09-01.md`
  — full saga account, private mirror, corrected same day.
- `~/work/nemesis-internal/handoff/2026-09-01-window1-handoff.md` — Window 1's FINAL
  closeout.
- `~/work/nemesis-internal/handoff/2026-09-01-window3-handoff.md` — Window 3's NIGHT
  closeout.
