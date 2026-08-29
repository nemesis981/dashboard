# HANDOFF — current state

> Last updated **2026-08-29, closeout (Window 2)**. Overwritten each closeout (latest state
> wins). Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/accounts/
> keys live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8.
>
> Full detail: `docs/handoff/supplements/2026-08-29-001.md` (curated) and
> `docs/handoff/worklog/2026-08-29-001.md` (raw chronology).

---

## 1. ⚠ OPEN INCIDENT — `ed6af88` orphaned commit, `origin/main` is broken from a fresh clone

**Read this before touching `dashboard.py`, `roles.py`, `writes.py`, `views.py`, or
`database.py`.**

`ed6af88` (Window 1's email-enrollment routes) was committed to `dashboard.py` alone; its
three companion files (`roles.py`, `views.py`, `writes.py`) plus matching `database.py`
edits were wiped by a scoping mistake in a Window-2-run git command immediately after
(`checkout -- .` run with a stray `-C /opt/nemesis`, against the real repo instead of the
scratch dir it was meant for — full account in the supplement). Also wiped in the same
command, unrelated: `attestation.py`'s CHALLENGE_TTL fix, three doc corrections.

**Confirmed still broken, this session, read-only:**
- `HEAD == origin/main == 36c3101` — unchanged. `ed6af88` sits two commits below tip, under
  the (unrelated, legitimate) file-integrity manifest commit.
- Isolated `git worktree` checkout of `HEAD` alone: `test_roles.py` → **156 passed, 2
  failed** (`roles.py` has no entries for the routes `dashboard.py` registers). **A fresh
  clone or deploy from `origin/main` today reproduces this break.**
- The working tree has since been repopulated by other windows (the wiped files are back,
  modified) — but this is NOT a clean restoration to commit as-is. New, unreviewed,
  untracked work has landed in the same files since the incident: `modules/email_security/
  enrollment.py`, `baseline.py`, `sender_id.py`, three new tests, `alert_manager/
  integrity_watch.py` + two new tests. A `test_roles.py` run against this non-isolated
  working tree shows 158/0 — that number reflects the uncommitted tree, not `origin/main`,
  and must not be read as "resolved."

**Not yet actioned.** Given the operator's standing STOP on further destructive git
operations (now satisfied by this accounting) plus the new unreviewed work mixed into the
same files, I have not committed a fix. **This needs an explicit operator call**: have
Window 1/3 hand off the restored companions as their own clean, reviewed batch (closing
`ed6af88` properly, separate from the new enrollment/integrity-watch work), or another
remedy. Until resolved, treat `origin/main` as not safe to deploy fresh.

## 2. Push status

`/opt/nemesis`: `HEAD == origin/main == 36c3101`, verified via `git fetch` +
`git rev-parse` this session. No new commits pushed today — this closeout's own commit
(handoff files) will be the first.

## 3. Working tree — NOT clean, intentionally uncommitted pending §1's resolution

`roles.py`, `database.py`, `attestation.py`, `views.py`, `writes.py`, `docs/OPERATION.md`,
`docs/SETUP_LINUX.md`, `PUNCHLIST.md`, `core_module/diagnostics_watcher/
diagnostics_watcher.py`, `scripts/deploy_integrity_check.sh`, `scripts/
nemesis-integrity-check` — modified, uncommitted. Plus untracked: `alert_manager/
integrity_watch.py`, `alert_manager/test_challenge_freshness.py`, `alert_manager/
test_integrity_watch.py`, `modules/email_security/{enrollment,baseline,sender_id}.py` and
three matching test files. None of this has been handed off to Window 2 for review yet —
do not assume it's ready to land. See §1 before staging any of it.

## 4. Everything else — unchanged since 2026-08-28's closeout

See `docs/handoff/supplements/2026-08-28-001.md` for the prior day's full landed-work list
(9 commits: tailnet-leak history rewrite, nmap dead-grant fix, sudoers-grant decision,
gap-inventory Tier-1 fixes, worklog/doc cleanup) and
`~/work/nemesis-internal/audits/base-project-gap-inventory-2026-08-28.md` for the
outstanding-work reference document (still current — not refreshed today, today's session
was incident accounting, not gap-inventory work).

## 5. Closeout health check

- Working tree: **not clean** — see §3, intentional, blocked on §1's resolution.
- Closeout commit is HEAD: confirmed after this handoff's own commit.
- local == origin: confirmed via `git fetch` + `git rev-parse HEAD origin/main` after push.
- HEAD touches only docs/handoff files: confirmed for this commit.
- Rule 8 spot-check: clean, no real paths/IPs/usernames in this handoff or the worklog.
- Open items durably captured: this file (§1 is the load-bearing one), the worklog, the
  supplement.

## 6. Cross-references

- `docs/handoff/worklog/2026-08-29-001.md` — raw chronology, today, including the full
  incident timeline.
- `docs/handoff/supplements/2026-08-29-001.md` — curated account of the incident and
  end-of-day verification.
- `docs/handoff/supplements/2026-08-28-001.md` + `docs/handoff/worklog/2026-08-28-*.md` —
  prior day, full detail.
- `~/work/nemesis-internal/audits/base-project-gap-inventory-2026-08-28.md` — outstanding-
  work reference, unchanged today.

## Topology

No architectural change today. Today's session was entirely incident accounting for §1 —
no new product surface, no design decisions. The one standing-practice note worth carrying
forward: the supplement flags that `-C <repo> checkout -- .` run from the wrong cwd is a
third shared-tree hazard shape (alongside "don't stage by bare path" and "don't stash"),
not yet named in CLAUDE.md's shared-discipline section — a docs decision for whoever picks
it up next, not actioned unilaterally here.
