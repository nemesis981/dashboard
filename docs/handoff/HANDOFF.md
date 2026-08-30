# HANDOFF — current state

> Last updated **2026-08-30, morning session (Window 2)**. Overwritten each closeout (latest
> state wins). Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/
> accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here
> per Rule 8.
>
> Full detail: `docs/handoff/supplements/2026-08-30-001.md` (curated) and
> `docs/handoff/worklog/2026-08-30-001.md` (raw chronology).

---

## 1. `ed6af88` orphaned commit — RESOLVED

Previously tracked here as an open incident (companion files wiped, `origin/main` unsafe to
deploy). **Closed this session, on verified evidence, not on the prior entry's word:**

- `ecd6e35` (pushed, landed after the 08-29 closeout was written) restores the full
  companion set: `alert_manager/database.py`, `alert_manager/roles.py`,
  `modules/email_security/{enrollment,views,writes}.py` + 2 new test files.
- `c0e3b57` (also pushed) restores the other file wiped by the same incident —
  `attestation.py`'s `CHALLENGE_TTL_SECONDS` freshness fix.
- **Verified 2026-08-30:** ran `alert_manager/test_roles.py` directly against the live
  working tree (clean, matches `HEAD` for all four files) — **158 passed, 0 failed**,
  including the full registry-completeness and mutation-canary suite. This is the same
  test that previously showed 156/2 against the broken post-incident state.

`origin/main` is safe to deploy fresh as of this check. Full incident account (root cause,
recovery, the shared-checkout hazard it exposed) stays in
`docs/handoff/supplements/2026-08-29-001.md` — not repeated here.

## 2. Push status

`HEAD` (`e302768`) is **2 commits ahead of `origin/main`** (`fc40e31`), confirmed via
`git fetch` + `git rev-parse` this session:
- `30efe9c` — `feat(integrity): fact-file -> ticket path via diagnostics-watcher`
- `e302768` — `feat(email-security): D4 personal sender baseline, salted recurrence tokens`

Both are local commits from Window 1 (per the 2026-08-29 "commit locally, immediately"
rule), independently verified this session via `git show --stat` against the files flagged
in the morning briefing — all 8 accounted for. **Not pushed yet** — no push-confirmation
request has been made of the operator this session. Standard push-coordination discipline
(list unpushed commits, confirm, push the reviewed SHA) applies whenever that happens.

## 3. Working tree — CLEAN

`git status --short` is empty as of this session. The 8 files flagged in this morning's
briefing (`integrity_watch.py` + companions, `email_security/baseline.py` + `sender_id.py`)
are now committed locally — see §2.

## 4. Elevated grants — see `docs/handoff/elevated-grants-tracking.md`

Full detail now lives in that file, **edited in place, not embedded here** — this section
embedded-in-HANDOFF thinned to nothing across four consecutive closeouts (`f79f5ad` full →
`670ab6b` pointer → `f20d696`/this-file's-predecessor gone entirely), because a file that's
overwritten wholesale each closeout only keeps content someone remembers to retype. See the
tracking file's own "Why this file exists" section for the full root-cause writeup, and
CLAUDE.md item 7 for the corrected standing instruction.

**Current-state summary (live-checked 2026-08-30):** production box clean — no broad
`NOPASSWD` grants, no `nmap`, all entries narrowly scoped. `pihole` group membership still
open (unchanged, tracked). Gateway-VM `nmap` grant **not re-verified today** (last confirmed
2026-08-26, carried forward explicitly flagged as such). Polkit rules unchecked (permission
denied, needs root).

## 5. Roadmap-vs-state (2026-08-30 Morning Status)

Baseline: `docs/audits/roadmap-state-audit-2026-08-24.md` (83 total, 11/12/60). File-set
drift: +1 (`child-safety-monitoring.md`, added 2026-08-25, correctly filed PARKED). No
shipping-status drift found after a keyword sweep of 126 intervening commits + direct
spot-checks. **Current tally: 11 SHIPPED / 12 PARTIAL / 61 PARKED — 84 total.** No baseline
doc refreshed yet (owed at next closeout per CLAUDE.md item 6, since drift was found).

## 6. Everything else — unchanged since 2026-08-28's closeout

See `docs/handoff/supplements/2026-08-28-001.md` for that day's full landed-work list (9
commits: tailnet-leak history rewrite, nmap dead-grant fix, sudoers-grant decision,
gap-inventory Tier-1 fixes, worklog/doc cleanup) and
`~/work/nemesis-internal/audits/base-project-gap-inventory-2026-08-28.md` for the
outstanding-work reference document (not refreshed since).

## 7. Closeout health check

Not a full nightly closeout — this is a mid-session refresh responding to specific operator
closeout items (§1 resolution, elevated-grants restructure, push-status check). Full
closeout health check deferred to the actual end-of-day closeout.

## 8. Cross-references

- `docs/handoff/worklog/2026-08-30-001.md` — raw chronology, today.
- `docs/handoff/supplements/2026-08-30-001.md` — curated account of today's findings and
  the elevated-grants structural fix.
- `docs/handoff/elevated-grants-tracking.md` — standing elevated-grants record (new).
- `docs/briefing/2026-08-30.md` — this morning's Morning Status briefing.
- `docs/handoff/supplements/2026-08-29-001.md` — prior day, full `ed6af88` incident account
  (root cause + recovery), now closed per §1 above.

## Topology

No architectural change today. Two structural fixes to project process, not product code:
(1) `docs/handoff/elevated-grants-tracking.md` established as a standing, edited-in-place
file so the elevated-grants record can't silently thin again; (2) `HANDOFF.md`'s own §1
corrected from a stale "open incident" to its actual resolved state, found only by
cross-checking git history against the file's own claims rather than trusting the last
write.
