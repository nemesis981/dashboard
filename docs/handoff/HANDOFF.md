# HANDOFF — current state

> Written at operator-requested closeout, 2026-09-04, end of day. Real IPs/hosts/accounts/keys
> live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8.
>
> Full detail: `docs/handoff/worklog/2026-09-04-001.md` (raw chronology) and
> `docs/handoff/supplements/2026-09-04-001.md` (curated summary of this session, the one that
> resumed after the operator's PC restart mid-afternoon).

---

## 1. Push status — READ THIS FIRST

**Public repo (`/opt/nemesis`): PUSHED AND SYNCED.** Operator confirmed the full list below at
closeout; pushed the exact SHA `7c6f3b5` (not the branch name) to `origin/main`. Verified after:
local `HEAD` == `origin/main` == `7c6f3b5`, 0 commits unpushed. **Nothing pending here — a fresh
session has no push decision to make.**

- `origin/main`: `7c6f3b5` (was `892881c` before this push).
- List of what was pushed, oldest to newest (every one Rule-8-scanned, compiled/tested where
  applicable, kept here for the record rather than because any of it still needs action):

  ```
  3269762 docs(entitlements): warn that MAX_REMOTE_CAP_BONUS is half a cross-repo invariant  [Window 3]
  745c56d feat(layer-d): Phase A -- family-labeller validation harness                        [Window 1]
  5069f57 feat(layer-d): alias table for the family labeller, measured against MOTIF          [Window 1]
  f5d1221 docs(handoff): emergency mid-session checkpoint ahead of logout/login                [Window 2]
  2415cef feat(diagnostics): register the audit-write canary, and make unwiring detectable    [Window 1]
  eb61c9e docs(handoff): flag dashboard restart-verb NOPASSWD asymmetry                        [Window 2]
  6a38f06 docs(claude.md): fix stale core-services path -- all five, not just watchdog         [Window 2]
  8766baa docs(claude.md): extend diagnostics-self-deception table                             [Window 2]
  d06afaa docs(claude.md): Claude-Session trailer is a one-directional attribution signal      [Window 2]
  05f7dc8 fix(diagnostics): four checks were dead in production for want of a temp dir         [Window 1]
  dd6cdef docs(handoff): flag dashboard.service PrivateTmp gap alongside restart-verb asymmetry [Window 2]
  9197976 docs(diagnostics): retract an unmeasured claim in my own scratch_dir comment         [Window 1]
  44f6252 docs(diagnostics): the os.access claim is refuted, not merely unverified             [Window 1]
  f69497b docs(handoff): correct the restart-grant approval rationale before filing            [Window 2]
  1c1115a feat(licensing): refuse an older licence key unless explicitly confirmed             [Window 3]
  14b7320 docs(punchlist): api_usb_events missing ROUTE_MINIMUMS entry                          [Window 2]
  d3a0c55 fix(watchdog): grant polkit restart authority over all 6 supervised units            [Window 1]
  aaeb456 fix(dashboard): mark the throttle-status poll as background -- it defeated idle-lock [Window 1]
  35f3ad7 docs(entitlements): trim cross-repo invariant comment per Rule 10                    [Window 2]
  72f475f docs(handoff): sharpen the watchdog-dashboard polkit question                        [Window 2]
  c550323 docs(handoff): watchdog-dashboard restart authority was never missing                [Window 2]
  7c6f3b5 docs(handoff): closeout refresh for 2026-09-04 (this file's own commit)               [Window 2]
  ```

- Every commit above was individually vetted this session before push (Rule-8 scan,
  compile/test run, and for the two route-touching commits — `1c1115a`, `2415cef` — a real
  route-security/sandbox check, not just a plain-shell test run). Nothing here needs re-review
  by a fresh session.

**Private repo (`~/work/nemesis-internal`): NOT pushed, working tree NOT clean (not Window 2's
files — see below).**

- `local`/`usb` HEAD: unchanged from earlier today. Local HEAD is well ahead — do NOT push it
  by branch or by "latest commit"; it would sweep in many unreviewed commits from Windows 1
  and 3 (their own handoff notes, the licensing-backend-adjacent work, etc.).
- Working tree currently shows (not Window 2's, do not touch): `handoff/2026-09-04-window3-handoff.md`
  staged modified, `known-limitations/issuer-key-permissions-exfat-2026-09-04.md` staged new,
  plus untracked `audits/full-project-audit-2026-09-03.md` and `licensing-backups/` — all
  Window 3's in-flight work.
- Window 2's own private-repo commits today (all local, uncommitted-push not needed to be
  tracked further): the `known-limitations` writeup for the Rule 10 entitlements decision
  (`e1d15c1`) and earlier mirror commits. None pushed, consistent with the sweep-risk above.

## 2. What's actively in-flight (not Window 2's — described for whoever resumes)

**Window 1 — Layer D (malware family-labelling pipeline), mid-task, nothing uncommitted.**
Per their own cold-start note (`~/work/nemesis-internal/handoff/2026-09-04-window1-handoff.md`,
read in full this session): next unblocked step is building the MalwareBazaar fetch layer
(test-first, rate-limited, caching) — zero lines written yet. Three external gates block
further progress, none of them Window 1's to close: an abuse.ch auth-key (needs the operator,
~2 minutes, OAuth + ToS acceptance), a MOTIF licensing reply from Booz Allen (email sent, awaiting
response — all MOTIF-derived *measurement* is on hold, the harness code itself is unaffected),
and a VirusTotal outreach (draft ready, needs the operator to submit a web form). Also flagged:
`port_risk` intentionally not wired pending a consent-surfacing UI that doesn't exist yet
(design decision, not a blocker); ADR numbering gaps at 0013/0017 unexplained.

**Window 3 — key-pack (licensing) build. Step 4 of 5 is COMPLETE** (backend fully built,
mutation-tested, deployed to the VPS and verified live at every step). Per their own cold-start
note (`~/work/nemesis-internal/handoff/2026-09-04-window3-handoff.md`): next step is D5, the
Lemon Squeezy checkout-URL affordance with `install_id` prefilled — not started, and blocked on
the operator for a live variant ID and live-mode webhook secret. **Do not sell the variant**
until D5 lands. Also flagged, unresolved: a real business-exposure question (Stripe/LS
merchant-of-record and tax liability), an intake service still running Flask's dev server
(fine for now, not for launch traffic), and a VPS reboot the operator wants to do deliberately
(kernel/libc updates pending).

**Window 2's own state:** fully caught up, nothing pending review. The only open action across
all three windows tonight is the push confirmation in §1.

## 3. Live service state

All 8 core services active as of this closeout (`dashboard`, `watchdog`, `alert-watcher`,
`malware-canary`, `diagnostics-watcher`, `vpn-dns-guard`, `device-scanner`, `hw-monitor`).
`nemesis-drift-check.service` shows `inactive` — **this is normal**, it's a oneshot triggered by
`nemesis-drift-check.timer` (confirmed active); last run exited `0/SUCCESS` at 17:52:07,
resolving the multi-day failure Window 3 fixed earlier today (see their handoff for detail).

`dashboard.service` was restarted twice this session by Window 1 (canary registration, then the
`PrivateTmp=yes` unit change) — currently `active/running`, `PrivateTmp=yes` live, verified
namespace-accurately (not just "it came up").

**✅ RESOLVED — the license downgrade guard (`1c1115a`) is pushed AND running.** Found as a real
gap by Window 3 (pushed code ≠ running code: the dashboard process at the time predated this
commit by ~21 minutes, so an older signed licence key could still have silently downgraded
capacity), independently confirmed by Window 2, and closed by the operator's own manual
restart:
```
1c1115a committed               : Fri 2026-09-04 17:38:57 -0500
dashboard ActiveEnterTimestamp  : Fri 2026-09-04 18:21:38 CDT  (MainPID 88259)
```
The running process now postdates the fix by ~43 minutes — confirmed live by Window 2
(`systemctl show dashboard`) after the operator reported the restart, not taken on the report
alone. **No further action needed; this is closed, not a carried-forward risk.** Kept in the
record as an example of the general pattern (a push and a restart are different events, and
only the timestamp comparison catches the gap between them) — not because it's still open.

## 4. Today's work — full detail in the worklog and supplement

Extremely high commit-velocity day across three windows. This session (post-restart) alone:
found and fixed a real production bug (4 diagnostics checks silently dead for want of a
writable temp dir under the dashboard's sandbox — root-caused and fixed at both the code and
unit level); settled a multi-round elevated-grants question (a `dashboard` restart-verb grant
was approved on a rationale later proven false — watchdog never needed sudo to restart it, and
the real gap was watchdog's polkit authority missing for 3 of its 6 supervised third-party
daemons, now fixed and deployed); executed a Rule 10 disclosure decision (trimmed a public
comment's honest-limitation language to the private repo); fixed two stale CLAUDE.md entries
(a 5-week-old wrong service-path claim, a diagnostics-self-deception table extension); reviewed
and cleared a licensing security commit (client downgrade guard) with a full route-security
audit; and found + logged a pre-existing, already-public red test suite for a later fix.
Exact commit list: §1 above. Exact chronology: `docs/handoff/worklog/2026-09-04-001.md`.

## 5. Roadmap-vs-state

**Still not refreshed — now three sessions stale.** Baseline remains
`docs/audits/roadmap-state-audit-2026-09-02.md`, already known-stale at this morning's Morning
Status, and yesterday's V2-completion-gate corrections (7 of 13 items found stale) were never
cross-applied to it either. **Next Window 2 session should do a full baseline refresh** rather
than continuing to diff against 09-02 — this is now the single most overdue doc-audit item.

## 6. Elevated grants

Full detail, all verified live this session (not carried forward unchecked):
`docs/handoff/elevated-grants-tracking.md`. Headline: 70+ NOPASSWD entries, narrowly scoped, no
broad grants — one new grant approved today (`dashboard` restart verb, operator-convenience,
not yet added — still an open confirm-or-add pending the operator's actual sudoers edit), one
polkit rule fixed and deployed (watchdog's restart authority over its 3rd-party daemons), one
new discrepancy flagged and NOT chased (`install.sh` specifies `0755` on the polkit rules
directory, live is `0750`), one new least-privilege item flagged (4 services polkit-permitted
but unsupervised by watchdog). Polkit rules directory itself remains unreadable at this
session's privilege level (now the 8th+ consecutive session) — genuinely needs a root session
to resolve, not another re-flag.

## 7. Cross-references

- `docs/handoff/worklog/2026-09-04-001.md` — raw chronology, spans both the pre-restart and
  post-restart sessions today.
- `docs/handoff/supplements/2026-09-04-001.md` — curated summary of this (post-restart) session.
- `docs/briefing/2026-09-04.md` — this morning's Morning Status briefing (pre-restart, now
  several hours stale on service/grant specifics — §3 and §6 above supersede it for tonight).
- `docs/handoff/elevated-grants-tracking.md` — elevated-access running record, updated multiple
  times this session.
- `PUNCHLIST.md` — new entry today: `api_usb_events` missing a `ROUTE_MINIMUMS` entry
  (pre-existing, already public, fails safe, not urgent).
- `~/work/nemesis-internal/handoff/2026-09-04-window1-handoff.md` and
  `2026-09-04-window3-handoff.md` — read in full this session; far more build-specific detail
  than this file compresses to. Read these first if resuming build work directly.
- `~/work/nemesis-internal/known-limitations/entitlements-remote-cap-bonus-cross-repo-invariant-2026-09-04.md`
  — full detail behind tonight's Rule 10 decision.

## 8. Precise next steps for a fresh session reading this cold

**The public repo push is DONE — §1 is a closed record, not a pending action.** No push
decision awaits a fresh session.

1. **Refresh the roadmap-vs-state baseline** (§5) — three sessions overdue, the single most
   overdue doc-audit item.
2. If picking up build work: read the relevant window's private handoff file in full first
   (§7) — they're detailed, current, and written for exactly this.
3. Do NOT re-open: the watchdog/dashboard polkit question (§6, settled — nothing was ever
   missing), the Rule 10 entitlements decision (§4, operator already decided), or the
   `os.access` claim in `diagnostics/canary.py` (already corrected in-place, kept visible
   deliberately, not a live question).
4. The private repo (`~/work/nemesis-internal`) still has a real, unaddressed push decision —
   see §1's private-repo note. That's the one open item this closeout did NOT resolve.
