# HANDOFF — current state

> **⚠ WRITTEN MID-SESSION, 2026-09-04, ahead of an imminent desktop logout/login cycle —
> NOT a routine end-of-day closeout.** Window 2 was mid-task (standing by in support role for
> Window 1) when asked to checkpoint. Real IPs/hosts/accounts/keys live ONLY in
> `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8.
>
> Full detail: `docs/handoff/worklog/2026-09-04-001.md` (raw chronology, written this same
> checkpoint — no curated supplement yet, see §7).

---

## 1. Push status — READ THIS FIRST

**Public repo (`/opt/nemesis`): working tree is CLEAN. 3 commits ahead of `origin`, NOT
pushed, NOT reviewed by Window 2.**
- `origin/main`: `892881c` (confirmed synced as of the last push this session).
- `local` HEAD: `5069f57`.
- The 3 unpushed commits, oldest to newest:
  ```
  3269762 docs(entitlements): warn that MAX_REMOTE_CAP_BONUS is half a cross-repo invariant   [Window 3]
  745c56d feat(layer-d): Phase A -- family-labeller validation harness                         [Window 1]
  5069f57 feat(layer-d): alias table for the family labeller, measured against MOTIF            [Window 1]
  ```
  Attribution by session trailer only (not content-reviewed) — `3269762` carries session
  `01MzQv1oyAGUkTdwfQLrV6F7` (Window 3), the other two carry `01Ltar8DgRuigjPYuaXAJSEG`
  (Window 1). **Whoever resumes as Window 2: do the usual review (content, tests, Rule-8 scan)
  before confirming a push — nothing here has been checked yet.** Standard push-coordination
  discipline applies: re-list fresh immediately before pushing, get explicit operator
  confirmation, push the exact confirmed SHA.
- Nothing else pending in the public repo — everything through `892881c` (14 commits) was
  reviewed, confirmed by the operator, and pushed earlier this session. Full detail in the
  worklog.

**Private repo (`~/work/nemesis-internal`): NOT pushed, working tree partially clean.**
- `local`/`usb` HEAD: `504c308`. Local HEAD: `ea31319` (this session's mirror-file commit, on
  top of ~19 commits from Windows 1/3 that Window 2 has not reviewed).
- **Do NOT push `ea31319` by branch or by naively picking "the latest commit"** — it would
  sweep in all ~19 unreviewed ancestor commits. If a push is wanted, review those commits
  first (they're Window 1's/3's own scoping/handoff/layerd work) or coordinate directly with
  whichever window authored them.
- Working tree still carries: `migration/magicdns-deploy.sh` (modified, Window 1's, in-flight,
  not Window 2's to touch) and `audits/full-project-audit-2026-09-03.md` (untracked, not
  Window 2's — owner should commit it).

## 2. What's actively in-flight (not Window 2's, described for whoever resumes)

**Window 1 — launch-readiness punch list, in progress.** Per the operator: email verdict
pipeline (status note already written this session, ADR 0028, see §4), drift-check fix (DONE,
verified live and closed out this session), ML/sandbox wiring, cross-platform agent
verification. Also actively building **Layer D** (AVClass2 + MOTIF family-labelling pipeline)
— the 2 unpushed commits above are part of that. Per Window 1's own report: the benign corpus
is blocked on *composition* (~30,450 non-OS binaries short of a ~55% target, currently 83.19%
OS), not on raw count; the malicious half has zero samples. Full scoping:
`~/work/nemesis-internal/layerd-model/PATH-TO-TRAINED-MODEL-2026-09-04.md` (`24f9b26`).

**Window 3 — key-pack (licensing) build, multiple steps done today.** Steps 1-4 of the
free-tier "+5 remote-device pack" work landed in the private repo today (see the private
repo's own commit log, `6359ccd` through `47148ec` and beyond) — `d007bf4` (step 1,
`remote_cap_bonus` honoring) is on `origin/main` already, reviewed live by Window 2 before
push (24/24 tests, security shape checked). `3269762` (the unpushed doc note above) is a
cross-repo invariant warning tied to this same work — not yet reviewed.

**Window 2's own open items, unresolved, carried from earlier today:**
- Two already-published Rule-8 leaks (operator's real first name written literally instead of
  the `<user>` placeholder) in `468cc46` (2026-09-02) and `524aa16` (2026-09-03), both already
  on `origin/main`. Flagged to the operator, not fixed — their call whether a history rewrite
  is worth it for a bare first name. **Still open, no decision made.**
- The 3 unpushed/unreviewed public-repo commits (§1).
- The unpushed private-repo mirror commit and the ~19 commits beneath it (§1).

## 3. Live service state

All 8 core services active (last checked at Morning Status). `nemesis-drift-check.service` —
was failing 70 consecutive runs since the Sep-1 Tailscale migration, **fixed and verified live
this session** (`status=0/SUCCESS`, nodivert + anti-spoof both OK). No other live-state changes
made or observed by Window 2 this session beyond what's in the worklog.

## 4. Today's work — full detail in the worklog

Very high commit-velocity day across three windows, most of it a single extended
confirmation/push cycle. Headlines: an ADR-number collision (0022 meant two different things)
found, fixed, and fixed again after a second citation was missed; a full V2-completion-gate
re-audit that found 7 of 13 items stale (all overstating remaining work), applied after
independent re-verification of every fact; one of those corrections was itself wrong (a
Tier-1 "blocker resolved" claim) and had to be retracted the same day — now recorded as a
CLAUDE.md pattern (measurement agreement isn't corroboration when both measurements share a
method); three write-ups from Window 1's audit (drift-check staleness — now fixed, email
verdict pipeline status, two vulnerability-patch-management.md corrections); a second new
CLAUDE.md pattern landed (text-search checks matching their own explanatory comments); and a
14-commit push spanning all three windows, including one commit (Window 3's licensing code)
that got an explicit operator hold-and-review cycle before publishing. Exact commit list and
verification detail: `docs/handoff/worklog/2026-09-04-001.md`.

## 5. Roadmap-vs-state

Baseline was `docs/audits/roadmap-state-audit-2026-09-02.md`, already known-stale at Morning
Status. **Now further out of date** — today's V2-completion-gate correction (5 items closed,
1 blocker resolved, 1 partial) is a DIFFERENT tracking document
(`docs/roadmap/v2-completion-checklist.md`) from the roadmap-state-audit baseline and was not
cross-applied to it. **Next Window 2 session should do a full baseline refresh
(`docs/audits/roadmap-state-audit-2026-09-04.md` or later)** rather than continuing to diff
against 09-02 — two consecutive days of unreconciled drift plus today's gate corrections make
the old baseline more misleading than useful now.

## 6. Elevated grants

Checked live at Morning Status, unchanged from 09-03: 70 NOPASSWD entries, `nemesis-fw`
membership stable, polkit rules unreadable (7th consecutive session — flagged as a standing
gap needing an actual root-access check, not another re-flag). Full detail:
`docs/handoff/elevated-grants-tracking.md`, committed `946c7e5`.

## 7. Why this handoff is incomplete by design

This is a mid-session checkpoint, not a closeout — there is no curated supplement (only the
raw worklog), and Window 2 was in an active support-role loop with Window 1 when asked to
write this. **If the session resumes normally** (no actual logout/crash), ignore this file's
"written ahead of a checkpoint" framing and keep working — update this file properly at actual
end-of-day per the normal Rule 9 cadence. **If a fresh session is reading this cold**, start
here: review and decide on the 3 unpushed public-repo commits (§1), check in with Window 1
(`nemesis-1f`) directly for current status rather than assuming this file is still accurate by
the time it's read, and resolve the two open items in §2 before treating this as fully caught
up.

## 8. Cross-references

- `docs/handoff/worklog/2026-09-04-001.md` — raw chronology for today, written this same
  checkpoint.
- `docs/briefing/2026-09-04.md` — this session's Morning Status briefing.
- `docs/handoff/elevated-grants-tracking.md` — elevated-access running record.
- `docs/roadmap/v2-completion-checklist.md` — today's major correction (7/13 items were
  stale), now the more current gate document; cross-check against the roadmap-state-audit
  baseline next full refresh.
- `docs/architecture/0028-email-security-gateway.md` — new status note on the verdict pipeline.
- `PUNCHLIST.md` — drift-check entry closed today; the never-block-guard and
  `list_listening_ports` items from 09-03 still open.
- `~/work/nemesis-internal/handoff/` — Window 1's and Window 3's own same-day cold-start notes
  (not read in full by Window 2 this checkpoint) will have more current build-specific detail
  than this file compresses to.
