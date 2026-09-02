# CLAUDE.md — Nemesis operating rules (auto-read each session)

This file is read automatically at the start of every Claude Code session. It holds
the project's core operating discipline (Tier 1) plus Nemesis-specific rules. Read it
before doing anything. Also read, in this order, before starting work:
`ARCHITECTURE.md` → `docs/architecture/` (ADRs) → `docs/handoff/HANDOFF.md`.

Working-style notes (local-only, gitignored; auto-loaded from disk via @-import):
@docs/COLLABORATION.md

---

## Emergency fallback
If something goes wrong during a live test (lost connectivity, laptop misbehaving): READ
`docs/operations/backupproc.md` immediately. It has the exact recovery steps (laptop-side
uninstall + server-side revert to the `pre-l1l2l3-build-known-good` tag).

---

### Morning Status (run on session start — Window 2)
Run by **Window 2** (the docs/audit window — see Window Roles below) at the start of its
session, before anything else. Run these and report the results in a clean block:

1. **Total code lines:**
   ```
   find /opt/nemesis -type f \( -name "*.py" -o -name "*.js" -o -name "*.html" \
     -o -name "*.css" -o -name "*.sh" \) | grep -v __pycache__ | grep -v .git \
     | xargs wc -l 2>/dev/null | tail -1
   ```
2. **Last 3 commits:** `git -C /opt/nemesis log --oneline -3`
3. **Service status (is-active):**
   ```
   systemctl is-active dashboard watchdog alert-watcher malware-canary \
     diagnostics-watcher vpn-dns-guard 2>/dev/null
   ```
4. **Working tree status:** `git -C /opt/nemesis status --short`
5. **Read `docs/handoff/HANDOFF.md`** and state today's resume point.
6. **Roadmap-vs-state audit (LIVE each session) — baseline diff, not header-trust:**
   report the tally + flag drift vs the maintained baseline
   (`docs/audits/roadmap-state-audit-YYYY-MM-DD.md`, latest date wins). Do NOT classify
   off each file's `Status:` header — headers go stale on shipping (the 3 currently-shipped
   items still say "parked"), so trusting them hides the exact drift this check exists to
   catch. Instead, each morning:
   - **File-set drift:** `ls /opt/nemesis/docs/roadmap/*.md` → compare names/count to the
     baseline's file count. Report any ADDED or REMOVED files.
   - **Shipping drift:** the baseline's non-parked items (SHIPPED + PARTIAL) plus any
     newly-added files get a quick code/`git log` re-check (confirm/upgrade status). For
     baseline-PARKED items, scan recent `git log --oneline` subjects for roadmap keywords
     — a parked item with a fresh feat commit has likely shipped; verify it.
   - This is a READ-ONLY audit (Rule 1) — report only, change nothing. When drift is found,
     refresh the baseline audit doc at closeout (new dated file).
   - **Baseline: RESOLVE AT RUNTIME — never hardcoded in this file.** The current baseline is
     the newest `docs/audits/roadmap-state-audit-*.md` by filename date (ISO names sort
     lexically, and the `roadmap-capture-audit-*` sibling does not match this glob):
     ```
     ls /opt/nemesis/docs/audits/roadmap-state-audit-*.md | sort | tail -1
     ```
     Read that file's `**Tally:**` line for the SHIPPED / PARTIAL / PARKED / total counts and
     diff today's reality against it. If no such file exists, say so and treat the run as a
     first baseline.
   - **Why no number lives here.** A copy of the tally in this file is a SECOND source of truth
     that only updates if someone remembers a separate edit after each closeout refresh — so it
     desyncs by default, and a stale copy then silently produces a FALSE drift finding. Observed
     live 2026-07-27: a pointer left at the 07-25 baseline reported "+4 file-set drift" that the
     07-26 baseline had already absorbed and closed out. The repo was fine; the pointer was
     wrong. Resolving at runtime also REMOVES a closeout obligation — refresh the audit doc and
     you are done, no second edit to remember.
   - **The audit doc's `**Tally:**` line is a machine-read contract.** Every refreshed baseline
     MUST keep the existing shape — `**Tally: N SHIPPED · N PARTIAL · N STUB/PARKED — N total.**`
     (unchanged across every baseline since 2026-06-30). Reformatting it breaks the lookup above.
   - **Name the resolved baseline in the briefing** — state which file was used and the tally
     read from it. A wrong baseline is then visible in the output instead of hiding inside a
     drift number, which is exactly how the 2026-07-27 false positive went unnoticed until it
     was caught by accident.

7. **Elevated access grants — surfaced live every session, not noted once and forgotten.**
   `docs/handoff/elevated-grants-tracking.md` is the running list this rule formalizes as
   recurring Morning Status behavior, same spirit as item 6's "LIVE each session, baseline
   diff" — a grant flagged once in a session that ends and is never re-surfaced is exactly
   how an unneeded grant outlives its reason and nobody notices. Each morning, check what is
   CURRENTLY live — don't just carry forward yesterday's list unchecked:
   - sudo NOPASSWD entries: `sudo -n -l`
   - non-default group memberships that grant meaningful access (e.g. `pihole`, `nemesis-db`,
     `nemesis-fw`) for every account being tracked: `getent group <name>` / `id <user>`
   - polkit rules: `ls /etc/polkit-1/rules.d/` (needs root to read on this box — note
     explicitly if the current session can't check it rather than silently skipping)
   - any other standing elevated grant already named in the tracking file
   Report a short "Elevated grants:" line in the Morning Status output, and **update
   `docs/handoff/elevated-grants-tracking.md` directly, in place** — a grant still needed
   stays listed with its reason; one no longer needed gets flagged for revocation, not
   silently dropped from the list without a revoke actually happening.
   **⛔ This detail lives in its OWN file, edited in place — it does NOT get embedded in
   `HANDOFF.md` (standing rule, added 2026-08-30 after this exact section thinned to
   nothing across four consecutive closeouts — `f79f5ad` full → `670ab6b` pointer-only →
   `f20d696`/`5086b51` gone entirely, traced via `git log -p`).** `HANDOFF.md` is
   OVERWRITTEN wholesale each closeout (Rule 9) — content embedded there survives only if
   every closeout author remembers to manually retype or carry it forward in full, with no
   diff warning and no reflog entry when it's dropped. Same failure shape as the
   uncommitted-tracked-file hazard the "commit locally, immediately" rule (2026-08-29,
   above) exists to close: a structural gap, not a vigilance gap, and vigilance had already
   failed four times running before this fix. `elevated-grants-tracking.md` is edited in
   place (never regenerated from scratch, same discipline as `PUNCHLIST.md`) specifically
   so it cannot lose content nobody touched. `HANDOFF.md` carries only a one-line pointer +
   current-state summary referencing it — cheap enough to keep current every closeout, and
   if that pointer line ever does go stale, the detail behind it hasn't.
   **No hardcoded grant list lives in THIS file (CLAUDE.md)** — same reasoning as item 6's
   baseline: a copy here is a second source of truth that desyncs the moment someone forgets
   to update it after a grant is added or revoked, and a stale "all clear" is worse than no
   check at all. Treat every claimed grant the same way the route-security audit treats an
   unconfirmed finding: verify it against live state (`sudo -n -l`, `getent group`, actual
   file/group membership) before writing it into the tracking file or the briefing as fact —
   a claim that doesn't check out gets flagged as contradicted, not written down anyway.

Format the output as:
```
--- NEMESIS MORNING STATUS ---
Lines of code: XX,XXX
Last commits: [3 lines]
Services: dashboard=active watchdog=active ...
Tree: clean / [N files modified]
Resume: [one sentence from HANDOFF]
Roadmap: N shipped / N partial / N parked (M total) — [drift note or "no change"]
Elevated grants: [short summary — e.g. "2 live (Suricata sudo, gateway-zone DHCP/pihole), see HANDOFF"]
------------------------------
```
8. **Write the briefing to disk (EVERY session, automatically — do not ask).** Save the full
   briefing to `docs/briefing/YYYY-MM-DD.md` — the status block above **plus** the supporting
   detail that doesn't fit in it: the roadmap-vs-state audit findings (baseline file used,
   file-set drift, shipping drift, and the closeout action if drift was found), the elevated-
   grants check (what's live, what changed, what's owed a revoke), the model self-check
   result, any process findings, and the open items carried forward from HANDOFF. Then print
   the status block in chat. Both — the file is not a substitute for reporting.
   - `docs/briefing/` is **gitignored, local-only** — never committed, so this is not a
     git-write and needs no push. Rule 8 still applies to its content (placeholders, not real
     IPs/hosts/accounts) — the file is one copy-paste away from somewhere public.
   - **One file per date; latest run that day overwrites it.** Files accumulate across dates —
     they are the searchable record of what each morning's audit actually found, which the
     chat-only version loses the moment the session ends.
   - Why this is a rule and not a nicety: the audit's whole value is *diffing against what was
     true before*. A finding that lives only in a closed session can't be diffed, and a
     recurring drift pattern is invisible until you can compare three mornings side by side.
   - **Also mirror this file** to `~/work/nemesis-internal/briefing/` — see Rule 12.

Then ask: **"What would you like to work on today?"** This replaces the manual catch-up
prompt — session is oriented in under 30 seconds.

---

## Window Roles (multi-window workflow)

Fixed assignment — **window identity, model, and git-write privilege** are pinned as
follows. The operator identifies a window by number in the FIRST message ("you are
Window 1" / "you are Window 2" / "you are Window 3"). A window has no way to know its
own identity otherwise — the role comes from that load-time assignment, not from open
order or timestamps. If a window is reopened after a crash, the operator re-states its
number.

### Window 1 — BUILD window (role: Opus — currently Opus 5)
- **Expected model: Opus** (currently `claude-opus-5` — bump this string when Anthropic
  ships a newer Opus; the role pin itself doesn't change). Reasoning-heavy build/design
  work. **Launch pinned — `nem1`** (see "Launching a window" below); `/model opus[1m]`
  only as a mid-session correction.
- Owns all CODE changes (dashboard.py, database.py, agent files, installers, etc.).
- Runs Rule-3 verification (real output: py_compile, isolated tests, live checks) on
  every code change.
- **Does NOT push — ever.** `git push` remains exclusively Window 2's. **Local commits ARE
  permitted and expected** — see the "commit completed work locally, immediately" hard rule
  under "Both windows (shared discipline)" below (added 2026-08-29). When a change is ready
  to reach `origin/main`, STOP and report it as ready-to-land; hand off to Window 2, which
  decides what actually lands, in what shape, and performs the push.
- Does NOT author ADRs, roadmap entries, `docs/handoff/` artifacts, or build specs —
  that's Window 2. (Narrow exception: the code-window context handoff below — it is not
  a `docs/handoff/` artifact and lives outside the public repo entirely.)
- Does NOT run the morning briefing or roadmap-vs-state audit — that's Window 2.
- Code work takes priority: never let a read-only audit or doc request preempt
  trip-critical or scheduled code work in this window.
- **Code-window context handoff — own document, separate from Window 2's closeout
  (standing rule, added 2026-08-03, generalized + revised 2026-08-03).** Applies to
  Window 1 always, and to Window 3 whenever it is on a code-writing task. Maintain ONE
  cold-start note per window per day at
  `~/work/nemesis-internal/handoff/YYYY-MM-DD-window<N>-handoff.md` (`<N>` = this
  window's number) — created on first write of the day, then EDITED (not replaced
  wholesale, not blindly appended to) on every later write that same day. A new day
  starts a new file; nothing is lost from a prior day's editing, because
  `~/work/nemesis-internal` is itself a git repo (`local`+`usb` remotes) — every edit
  is a real commit with real history, even though the file on disk always shows only
  the current, useful state.
  **Why this replaces a separate supplement, not just duplicates one (Window 3's
  observation, 2026-08-03):** if this file is genuinely kept current throughout the
  day, a separate end-of-day distillation is redundant work describing the same
  ground twice. One well-maintained file beats one growing file plus one summary of
  it.
  **Written periodically throughout the session — at minimum after each significant
  milestone (a build/fix reaching ready-to-hand-off, a major finding, a verification
  pass completed) — specifically to survive a mid-session context compaction that a
  closeout-only write would not.** A compaction can happen at any point, not only at
  the end of a session, so the defense has to be continuous. The same continuous
  writing is what makes this useful against a lost connection or an unrequested
  reboot too — either one can end a session with no closeout at all, not just a
  compacted one, and a file that is at most one milestone stale is what a cold
  restart actually needs to pick back up, not a document that only ever existed in
  a context that is now gone.
  **At explicit closeout specifically: read the file back and EDIT it down** —
  remove or stub whatever describes now-completed, already-shipped work that a cold
  reader would not need reconstructed in full (a one-line "shipped, see commit X" is
  enough where a paragraph of build narrative used to be needed mid-task). The point
  of the edit pass is that the file stays directly useful as a cold-start document
  going forward, not an ever-growing accumulation of everything that ever happened —
  the git history in the private repo is where the full account still lives if it's
  ever needed.
  This is IN ADDITION TO, not instead of, Window 2's Rule 9 discipline
  (`docs/handoff/HANDOFF.md`/supplements/worklog) — that covers project state for
  anyone; this is the code window's own working-context note for reconstructing
  itself, specifically.
  **May be committed and pushed by the window that owns it, directly** — Window 1 or
  Window 3 may commit+push their own handoff file to `~/work/nemesis-internal`'s
  `local`+`usb` remotes themselves (same privilege already established for other
  private-module work), following the SAME discipline as everywhere else in this
  file: stage the handoff file by its exact path, verify nothing from another
  window's unrelated in-progress work in that same repo got swept in, Rule-8-scan the
  diff, push to both remotes, confirm both report the same HEAD. This is narrower
  than general private-module git-write — it covers only this window's own handoff
  file, not other content in that repo.
  **Write it for a cold start — assume the reader has this document and nothing
  else.** Reference shape (see the most recent file in that directory for a full
  worked example): a role/identity reminder up top; broken-instruments/gotchas found
  this session (the exact wrong-assumption traps that cost time, per the standing
  "verification code must prove its own premise" practice); production state backed
  by real verification evidence, not assertions; committed-vs-held work; prioritized
  open items; any deferred/parked decisions worth flagging explicitly so they aren't
  silently re-litigated; environment/access mechanics that are easy to lose (test
  creds, VM state, tool quirks, workarounds); leftover/cleanup state (test data, temp
  rules, snapshots); items still owed to Window 2; and deliberately tracked risks —
  framed as accepted tradeoffs, not oversights, so they read as decisions on a second
  read, not gaps. Each new write should assume the reader may have ONLY this file (the
  most recent one), not the whole series — recap enough of the still-relevant prior
  state that a cold read of just the latest file is self-sufficient.

### Window 2 — DOCS/AUDIT window (role: Sonnet — currently Sonnet 5) — sole git-writer
- **Expected model: Sonnet** (currently `claude-sonnet-5` — bump this string when
  Anthropic ships a newer Sonnet; the role pin itself doesn't change). Docs, audits,
  commits. **Launch pinned — `nem2`** (see "Launching a window" below); `/model
  claude-sonnet-5` only as a mid-session correction.
- Owns ALL document work: ADRs, roadmap entries, handoff/supplements, build specs, doc
  audits, cross-references.
- Owns the MORNING BRIEFING and the full MORNING ROADMAP-VS-STATE AUDIT.
- **Sole git-writer.** ALL commits and pushes happen ONLY in this window — both for its
  own doc work AND for code Window 1 reports as ready. Pull `--ff-only` before every
  commit. Rule-8 leak-scan every diff before committing.
- Does NOT edit code file CONTENT — code arrives pre-written by Window 1 and is
  committed as reviewed (Rule-8-scanned), not rewritten. (Committing is not the same as
  editing; staging/committing Window 1's finished code is in-scope. If a task would
  require actually writing/changing code, stop and flag it for Window 1.)
- **Save locations (no exceptions):**
  - Morning briefings → `docs/briefing/` (gitignored, local-only, latest run wins).
  - Audits (roadmap-vs-state, install/doc tests, security/PL findings, etc.) →
    `docs/audits/`, dated filename (e.g. `docs/audits/<topic>-audit-<date>.md`).

### Window 3 — OVERFLOW window (role: ad hoc, model follows the TASK not the window) — never a git-writer
- Opened situationally, not a standing window like 1 and 2 — for one-off, ad hoc, and
  parallel work that doesn't need a dedicated build or docs/audit session running (e.g.
  a quick investigation alongside whatever Windows 1 and 2 are already doing).
- **Owns ongoing VM fleet stewardship — a standing responsibility, not just the one-off
  cleanup/audit pass that established it (2026-08-02).** Every time Window 3 touches the
  fleet, three obligations apply regardless of what specific task opened the window: keep
  the living fleet inventory current, fold cleanup into every closeout rather than waiting
  for another full audit, and keep any server/agent-carrying VM current with production.
  Full detail and rationale: "VM test fleet" further down this file.
- **Never pushes — ever.** Same restriction as Window 1: push privilege stays exclusively
  with Window 2, no exceptions for Window 3 either. **Local commits ARE permitted and
  expected** — see the "commit completed work locally, immediately" hard rule under "Both
  windows (shared discipline)" below (added 2026-08-29).
- May pick up occasional audits and doc work as overflow **specifically when Window 2 is
  busy** — hand off findings/drafts to Window 2 for it to review and commit, the same
  handoff shape Window 1 uses for code.
- **Expected model depends on the task just given, not on the window itself:** Opus for
  writing code, Sonnet for docs/audits — mirroring Window 1's and Window 2's model
  choices respectively, without inheriting either window's fixed identity. No launch
  alias (unlike `nem1`/`nem2`) — opened as needed with whatever's already active.
- **Cannot auto-switch models** (same limitation as Windows 1/2 — `/model` is
  operator-typed, not tool-accessible) — but unlike their once-per-session check, Window
  3 re-evaluates on EVERY task it's given, since the expected model can change task to
  task within the same session. Before starting work on a new task, classify it (code-
  writing → Opus expected; docs/audit → Sonnet expected) and compare against the
  currently active model. If they don't match, **flag it in the first response** — e.g.
  "Note: this looks like a code-writing task, expected Opus, currently running on
  Sonnet 5" — then wait for the operator to switch (`/model opus[1m]` / `/model
  claude-sonnet-5`) or explicitly say to proceed anyway, rather than silently doing
  code-writing work on Sonnet or docs work on Opus.
- **Code-window context handoff applies here too, whenever Window 3 is on a
  code-writing task.** Same rule as Window 1's (see that section) — one file per day
  at `~/work/nemesis-internal/handoff/YYYY-MM-DD-window3-handoff.md`, edited
  periodically through the session and pruned down at closeout, not just written once.
  Does not apply during Window 3's docs/audit-mode tasks — that falls under the "hand
  off to Window 2" pattern instead, per the bullet above.

### Both windows (shared discipline)
- **⛔ Commit completed work LOCALLY, immediately — hard rule, not a preference (added
  2026-08-29, operator-directed).** The moment a change to a TRACKED file is complete and
  verified, commit it locally. Not when the batch is finished, not when the handoff is
  written, not when Window 2 is free — as soon as that individual change is stable. Never
  leave finished work sitting as an uncommitted working-tree diff in a shared checkout.

  **This applies to EVERY window, including Windows 1 and 3.** A local commit is **not** a
  publication event and does not touch the sole-git-writer rule: it publishes nothing,
  reaches no remote, and lands on no shared branch. **`git push` remains exclusively
  Window 2's, unchanged.** Window 2 still decides what reaches `origin/main`, in what shape,
  squashed or split, with what review — the only difference is that it now does so from a
  recoverable commit instead of from a working-tree diff that dies the instant anyone
  touches those files. (Window 1's and Window 3's role definitions above are worded
  accordingly: "does not push," not "does not commit.")

  **An uncommitted change to a tracked file has ZERO protection from another window.** Every
  other shared-tree rule in this file protects commits and the index. **Nothing protects an
  unstaged edit.** Any window running `git checkout -- <path>`, `git restore`, or
  `git checkout .` — routine cleanup, done in good faith, usually to tidy the tree before its
  own commit — destroys it instantly, with no conflict, no warning, and **no reflog entry.**
  The loss is therefore invisible to the usual "what happened to HEAD?" check, and is
  normally discovered only when someone later notices the fix is missing from `main`.

  **Untracked files survive `checkout`; tracked-and-modified files do not.** That asymmetry
  is the entire mechanism and it is backwards from intuition: **the more integrated your work
  is, the less protected it is.**

  **A structural guarantee, deliberately, rather than a process one.** The tempting
  alternative — "the committing window should check the handoff's file list against reality
  first" — only works while someone remembers, every time, under pressure, and fails
  silently when they don't. Once a local commit exists, cleanup operations cannot reach the
  work and nobody has to remember anything. **When both are available, take the mechanism
  that does not depend on vigilance.**

  **Verification is not a substitute for a commit.** Both losses below were of work already
  verified and reported ready. **"Ready to hand off" is not a durable state.**

  **Confirmed TWICE on 2026-08-29, both times destroying finished, verified work:**
  1. **Window 1** lost work this way (the `ed6af88` email-enrollment companions) and had to
     rebuild it.
  2. **Window 3**'s five-file batch was reduced to a single survivor. Three tracked files
     were reverted: `attestation.py`'s `CHALLENGE_TTL_SECONDS` freshness enforcement — a
     real security fix, since `expires_at` was written and never read, leaving a stale nonce
     answerable forever — plus two stale-doc corrections and a PUNCHLIST entry. The one
     survivor, `test_challenge_freshness.py`, lived **solely because it was untracked**, and
     then served as the spec for rebuilding the enforcement. **That the rebuild was cheap is
     not evidence this is minor:** it was cheap only because an untracked test happened to
     pin the exact contract. The same accident would have taken the test too, had it been
     tracked.
- Commit-first, then push (performed in Window 2). HOLD the push for operator review on
  anything non-trivial (ADRs, security-default code, schema changes).
- **Push coordination.** Before ANY push, list ALL locally-unpushed commits
  (`git log --oneline @{u}..HEAD`) — a push publishes everything pending, not just what
  was just committed. Show the full list to the operator and get explicit confirmation
  before pushing.

  **⚠ The listing goes STALE between confirmation and push, and in a shared tree that gap is
  where another window commits (confirmed twice, 2026-08-25).** `git push <remote> <branch>`
  publishes the branch ref *as it is at push time*, not as it was when it was read — so a
  correct listing, correctly approved, can still publish commits nobody reviewed. The
  approval window is the vulnerable window, and it is as long as the operator takes to
  answer. This is a DIFFERENT hazard from the shared-index one below: that one is about
  having more pending than realized, which the listing genuinely solves; this is about the
  set *changing after* a correct listing was read and approved, which no amount of care at
  listing time helps.

  **Push the reviewed SHA, not the branch name.** A branch name is a moving target; a commit
  SHA is immutable. Push the exact commit that was confirmed:

  ```
  git push local 2dea5f6:main && git push usb 2dea5f6:main
  ```

  A commit that lands after the confirmation is then simply not published — it stays local
  for its own author to list and confirm. This needs no vigilance and cannot be forgotten
  under time pressure, which is why it is the primary form rather than a check.

  **⚠ IT ONLY PROTECTS AGAINST DESCENDANTS, NOT ANCESTORS — and that half is NOT optional.**
  `git push <remote> <sha>:<branch>` publishes that commit *and its entire reachable
  history*. It excludes commits stacked ABOVE yours; it cannot exclude commits already
  BENEATH yours, which ride along whatever you do. **Confirmed the hard way 2026-08-25**:
  a SHA push of one Window 3 commit also published two unpushed Window 1 commits, because
  they were its ancestors — while using this very rule, which did not catch it and
  structurally cannot.

  **So the listing-and-confirmation step above is NOT superseded by the SHA form. It is the
  only thing that covers ancestors.** Read every entry in
  `git log --format='%h %s' <remote>/<branch>..HEAD` and name any commit that is not yours
  in the confirmation request — the shared-tree attribution rule already requires exactly
  this. The SHA form closes the race at the top of the range; only reading the list closes
  the bottom.

  **If a branch name must be pushed, GATE the push — do not merely re-print the listing.**
  Re-read the unpushed set and *abort* when it differs from what was confirmed:

  ```
  EXPECTED="944c317 dc0e00f 2dea5f6"
  ACTUAL=$(git log --format='%h' local/main..HEAD | sort | tr '\n' ' ')
  [ "$(echo $EXPECTED | tr ' ' '\n' | sort | tr '\n' ' ')" = "$ACTUAL" ] \
    || { echo "ABORT: unpushed set changed since confirmation"; exit 1; }
  git push local main
  ```

  **This is a GATE, not a report — the distinction is the whole point.** Never chain the
  listing to the push (`git log … && git push`): a check whose output arrives alongside the
  action it was meant to guard gates nothing, since the push happens whether or not anyone
  reads the line. The form above is different in kind — it *exits non-zero and does not
  push*. A re-run listing that prints and then pushes anyway is the broken shape wearing
  this rule's clothes, and is worse than no check, because it looks like diligence.
- **Shared-index staging is a DIFFERENT hazard from the above — a distinct failure mode,
  not the same one under another name.** Push coordination is about publishing more commits
  than intended; this is about one `git commit` sweeping in more FILES than intended, because
  `git commit` (with no pathspec) commits the entire index, not just what the current step
  just staged. Confirmed live 2026-08-02: staging a docs-only file by exact path (the
  discipline this file already calls for elsewhere), then running a plain `git commit`,
  still pulled in an unrelated 254-line code change that had been `git add`-ed earlier in the
  same session and left sitting in the index across the intervening steps. "Stage by path,
  not `-A`" does not protect against this — the leftover file was already staged by path; the
  problem was that it stayed staged into a later, unrelated commit. **The actual fix: stage
  and commit as one atomic step (`git add <path> && git commit ...` back to back, nothing
  else staged in between), never leave a file staged across a turn boundary or between
  unrelated commits.**

  **"Exact path" means an exact FILE path — never a directory.** `git add <dir>/` behaves
  like `-A` scoped to that subtree: it stages every eligible file underneath, including
  another window's files that merely happen to live there. Name each file individually,
  even when they share a directory, and even when you created the directory yourself.
  **Confirmed live 2026-08-29:** staging a two-file patch directory (`handoff/patches/`)
  also staged two patch files belonging to another window, authored hours earlier for an
  unrelated split. It produces no output and no warning at staging time — the sweep is
  invisible until a separate deliberate scope check (`git diff --cached --stat`, read
  before every commit per this same discipline) surfaces it. That check is what caught it
  here; nothing was lost and nothing wrong was committed. A window that reads "staged by
  exact path" as satisfied by `git add <dir>/` has a defensible reading of the old wording
  and no reason to run that check — which is why the wording is corrected rather than left
  to imply coverage it didn't have.

  **⚠ AND AN EXACT FILE PATH IS STILL NOT ENOUGH WHEN TWO WINDOWS EDIT THE SAME FILE.**
  This is a THIRD case, distinct from both above, and it is the one the previous two
  wordings actively imply is covered. `git add <file>` stages **the whole file as it stands
  on disk** — every uncommitted change in it, whoever made them. Naming one exact file
  protects against `-A`'s breadth and against a directory's subtree. It does nothing
  whatsoever about a co-edited file, because there is no narrower unit to name: the
  hazard is not *which paths* you staged, it is that one path contains two authors' work.

  **Confirmed live 2026-08-30.** Window 3 staged `dashboard.py` by exact path for the ADR
  0026 A2 build. The file also held 21 uncommitted lines of Window 1's Gateway Mode
  settings-page wiring, edited in the shared checkout at the same time. The commit
  published both under one author and one message.

  **THE SCOPE CHECK DID NOT CATCH IT, AND THAT IS THE PART WORTH INTERNALISING.**
  `git diff --cached --stat` was run before committing, exactly as this section requires.
  It reported `dashboard.py | 151 +++-` — a plausible number for the work in hand, so it
  read as confirmation. **A file-level stat cannot show that a file has two authors in it.**
  The previous case was caught by that check because the sweep added extra FILENAMES, which
  a stat does show. Here the sweep was inside a file that legitimately belonged in the
  commit, and the only visible symptom was a line count nobody could have called wrong.

  **What actually works, in order of preference:**
  - **`git diff --cached <file>` — read the DIFF, not the stat**, for any file another
    window might also be editing. It is the only check that can see a second author.
  - **`git add -p <file>`** to stage hunks deliberately when you already know the file is
    shared.
  - **Check `git status` for co-editors BEFORE starting**, not just before committing: a
    file already showing ` M` that you did not modify is the warning, and it is visible
    hours earlier than the commit.

  **If it happens anyway, and it is caught before a push, the fix is clean** — the same
  `reset --soft` below, then recommit each author's work separately. **Prove the split is
  lossless BEFORE running any git command**, not after: diff the two reconstructed versions
  and confirm one contains only the other author's lines and drops none of yours. In the
  2026-08-30 incident the first reconstruction attempt FAILED that check and aborted
  without touching git; had it been trusted and verified afterwards, the recovery itself
  would have been the second loss.

  If a mis-composed commit like this happens and is caught before
  pushing, `git reset --soft HEAD~1` (recovering the exact prior staged state) followed by
  re-staging only the intended path is the clean fix — confirmed safe in the same incident,
  verified first that the bad commit had not been pushed and that no one else had pushed or
  pulled in the interim.
- **`git stash` operates on the WHOLE SHARED TREE and a SHARED STACK — never use it here
  (confirmed live 2026-08-26).** A pathspec does not make it local to your slice, and the
  stack is shared by every window, so `git stash pop` can apply a DIFFERENT window's stash
  into your working tree. Push-coordination and shared-index staging are about your own work
  escaping; this one pulls someone else's work IN.

  **`stash push` + `stash pop` IS NOT A ROUND TRIP HERE.** `pop` applies the TOP of the
  stack regardless of who pushed it, so in a shared tree the sequence is
  *push-mine, pop-somebody-else's* (Window 1's framing, 2026-08-26 — sharper than the
  original and kept in its words).

  **What happened.** Window 3 ran `git stash push -q alert_manager/roles.py` then
  `git stash pop -q`, to check whether a test failure predated its change. The pop applied
  **Window 1's** stash ("ADR 0019 Phase 1 degraded-journal ingest, pre-deploy") and left
  `dashboard.py` in a conflicted `UU` state with 12 conflict-marker lines, mixing a committed
  fix with another window's unpushed work — in a file the stashing window had not stashed.

  **Nothing was lost, and the reason is luck rather than design:** the fix was already
  committed, and the failed pop happened to KEEP the stash entry. A clean pop would have
  consumed Window 1's stash into Window 3's tree, and a later `git checkout` would then have
  destroyed unpushed, pre-deploy work with no copy anywhere.

  **Recovery, if it happens anyway:** do NOT `git stash drop`, and do not resolve the
  conflict by hand. Confirm the other window's entry still lists (`git stash list`,
  `git stash show --stat`), restore the conflicted file from its committed state
  (`git checkout HEAD -- <file>`), verify zero conflict markers, then TELL THE OWNING WINDOW
  and ask them to verify their own stash rather than accepting your assurance.

  **⚠ AND THE STASH DID NOT EVEN REVERT WHAT IT CLAIMED TO.** The whole point of the
  attempt was to measure a test result WITHOUT the change; because the push did not take,
  the "before" run still contained it. **The change was compared against itself and
  declared innocent.** It was not — it was a real bug (a module that could not load at
  all), and reporting it as pre-existing sent another window chasing a non-existent shared
  defect. A state-moving command that half-fails leaves you with a confident measurement of
  nothing.

  **What to do instead — the question is almost always answerable read-only.** Window 3
  wanted to know whether it had caused a test failure. `git diff --stat -- <testfile>` answers
  that in one command, with no writes: an empty diff means the file was never touched. Reach
  for a read-only comparison before any command that MOVES state. If a stash is genuinely
  unavoidable, use a **worktree** (`git worktree add`) so the experiment has its own checkout,
  or copy the file aside and restore it by hand.
- **Shared working trees — `/opt/nemesis` AND `~/work/nemesis-internal` are SINGLE checkouts
  shared by every window, not per-window clones.** The private repo is the higher-risk of the
  two: it has two git-writers by design (Window 1 authors private-module code, Window 2 is
  backup) plus Window 3's handoff files, so three windows commit from one index. Everything
  above for shared-index staging applies here identically — stage by exact path, `git add
  <paths> && git commit` as one atomic step, never leave a file staged across a turn boundary.
  **A third, distinct failure mode on top of that: an unpushed-commit listing is not a list of
  YOUR commits.** It means "not yet on the remote" — another window's commits can sit below
  yours in the same history, and push-coordination's existing wording invites reading the list
  as solely your own work. Confirmed live 2026-08-25: Window 1's `~/work/nemesis-internal`
  commit `f4fa0ee`'s parent was `5788347`, a Window 3 email-security commit Window 1 had never
  pulled. That day's push happened to publish only Window 1's own commit — but only because
  Window 3 had already pushed minutes earlier, putting its commits below the remote tip rather
  than above it. Had Window 3 committed without pushing, Window 1's "one unpushed commit"
  listing would have been wrong, and confirming it would have published Window 3's unfinished
  work while telling the operator it was Window 1's. Before asking the operator to confirm a
  push in a shared tree:
  - Run `git log --format='%h %s' <remote>/<branch>..HEAD` and read every entry. **Do NOT
    add `%an` to that format and read it as attribution** — every window commits under the
    same shared git identity (`Nemesis981`, confirmed identical `user.name`/`user.email` in
    both repos), so the author field cannot answer "whose commit is this" and a check that
    reads it as if it could is worse than no check — same failure shape as the standing
    "verification code must prove its own premise" practice below, applied to this specific
    field.
  - Read the SUBJECT for this repo's actual naming conventions instead. `~/work/
    nemesis-internal` commits are frequently self-identifying —
    `handoff(window1): ...` / `handoff(window3): ...` name the window directly (confirmed
    live in this repo's own history); a feature-area prefix with no window tag
    (`fix(email-security): ...`, `stage0: ...`) still narrows it by matching against which
    window is known to own that area. This is the primary signal, but it is a naming
    convention, not a structural guarantee — a commit that doesn't name a window is not
    proof it's yours, only a gap the next two checks must close.
  - Cross-reference each SHA against the commits you yourself created THIS session as a
    second, independent signal — you always know your own SHAs regardless of subject
    wording. Any commit in the range that is neither self-identified by subject nor one you
    personally just created is NOT confirmed yours by default — name it explicitly in the
    confirmation request rather than silently including it.
  - `git reflog show <remote>/<branch>` distinguishes "already on the remote, pushed by
    someone else moments ago" from "about to be published by me" — a genuinely useful timing
    signal, unaffected by the shared-identity problem above since it reads ref history rather
    than authorship.
- **⛔ DO NOT CROSS-VERIFY ANOTHER WINDOW'S UNCOMMITTED FILE — commit it first, even locally
  (added 2026-08-29 after it produced a false regression report).** A file that is untracked or
  mid-edit has no stable content: the verifying window reads whatever happened to be on disk at
  that instant, which may be a state the author never intended anyone to run. **The verifier
  cannot tell a snapshot from a regression, because both look like "your code fails".**

  **Confirmed live 2026-08-29.** Window 2 ran Window 3's untracked
  `test_attest_challenge_dispatch.py` while verifying an unrelated fix and reported it "failing
  3 of 12". The file passes 14/0 and always had, from any cwd. The 3-of-12 was a real output —
  of an intermediate save made partway through authoring the file, before two stub fixes landed.
  Real time then went into investigating a regression that did not exist, and the first
  hypothesis (that later work had destabilised it) was wrong.

  **The tell was the COUNT, and it is the generalisable part: 12 is not a number that file
  produces when healthy.** A total that does not match any known-good run means the two sides
  are not looking at the same artifact — check that before debugging the failures themselves.

  **What to do:**
  - **Author:** commit before asking for verification — a local commit is enough, it does not
    need pushing. If you must hand over something in flight, say so explicitly and name the
    SHA-less state as provisional.
  - **Verifier:** check `git status` for the file first. If it is `??` or ` M`, stop and ask —
    do not report results against it. A result from an uncommitted file is not evidence about
    the author's work.
  - **Related but NOT the same as the shared-index hazard above.** That one is about your work
    escaping into someone else's commit. This one is about *reading* someone else's work before
    they have declared it finished. Both come from one checkout; neither implies the other.

- **A test whose ASSERTION COUNT changes under failure cannot be compared between runs
  (same incident).** The file above dropped from 14 checks to 12 because two assertions sat
  inside an `if` that only held on the success path — so a run with *less coverage* reported as
  a smaller suite rather than a failing one, and the missing checks vanished silently instead of
  failing. **Keep the count fixed:** make assertions unconditional (degrade the value, not the
  check), and have the file assert its own expected total so drift reports itself. Same family as
  the standing "a green suite and a suite that never ran the new code are indistinguishable"
  check below — this is that failure applied to the run-to-run comparison rather than to a single
  run.

- **Data Manager (ADR 0006) — loader-enforced, not convention.** All module DB access goes
  through `get_data_manager()` / `data_manager.connect(module)`. This is not a style
  preference: `modules_loader.py` statically refuses to load a module that imports raw
  `sqlite3` or the bare `get_db` accessor, before any of its code runs. See ADR 0006 for the
  full design (access control, audit trail, atomic ops) — not duplicated here.
- Read-only audits and doc-writes never share a window with trip-critical code work.
- One logical change per commit; don't batch unrelated work.

### Private modules — separate version control (Window 1 is git-writer, Window 2 backup)
Carved-out private modules live OUTSIDE the public repo and are version-controlled
separately. The first is `~/work/nemesis-internal/l3-tier2-tls-interception/` (the Tier 2
TLS-interception harness + implementation detail, moved out of the public repo for
source-visibility). This rule covers it and any future similarly-carved-out private modules.
- **Window 1 is the git-writer for these private repos** — it authors the code that lives
  there. It follows the SAME discipline as Window 2's public-repo practice: verify staged
  content before committing, Rule-8 scan the staged diff, and push to every one of a private
  module's configured remotes, then verify they all report the same HEAD — same sync-check
  discipline as anything else in this file.
- **Window 2 is backup git-writer for these private repos when Window 1 is occupied** —
  a standing arrangement, not a one-off override (operator clarification, 2026-08-02, after
  Window 2 flagged a `firewall-enforcement-engine` commit as looking out of scope and asked
  before proceeding — the flag was the right instinct, but the answer is "backup," not
  "barred"). Same discipline applies regardless of which window does it: verify staged
  content, Rule-8 scan the diff, push to every configured remote, confirm all remotes report
  the same HEAD. Worth a quick check the first time in a session that Window 1 is genuinely
  occupied rather than just being routed around out of convenience — once established, proceed
  without re-litigating the role boundary each time.
- **Default remote set for private modules: `local` + `usb` ONLY (operator decision,
  2026-07-29).** `local` is a bare repo on this machine; `usb` is independent physical
  storage. **No GitHub remote by default.** The reason is not secrecy for its own sake — it's
  that some private-module content is a novel solution the operator wants a head start on,
  and off-machine hosting is a deliberate choice to make per module rather than a default to
  inherit. **Confirmed in place for `firewall-enforcement-engine` (2026-07-29)**: both
  remotes verified reporting the same HEAD after push; USB confirmed a genuine separate
  device, not a folder on the same disk.
- **Pre-existing exception — `l3-tier2-tls-interception` has three remotes**, including
  private GitHub, from its 2026-07-26 setup (all three verified same-HEAD then). It predates
  the local+USB default and has **not** been changed. Worth noting the asymmetry: that repo
  holds the *more* sensitive content (the Tier 2 design itself) on the *wider* remote set.
  Resolving it means deleting the GitHub repo, not just dropping the remote — already-pushed
  commits stay until the remote repo is removed. **Operator's call, deliberately left open.**
- **Remote redundancy is specific to private modules — not a general repo requirement.** The
  public dashboard repo intentionally has only `origin` (public GitHub), and that's correct
  as-is, not a partial/unfinished version of this rule: GitHub itself is that repo's durable,
  off-site copy — the entire reason it's hosted there. A private module has no such
  inherently-mirrored host, which is exactly why it carries its own local + USB redundancy.
  **Verified 2026-07-26**, not assumed: the public repo genuinely has a single `origin`
  remote, confirming the asymmetry is intentional rather than a silently unfinished rollout.
- **Window 2 remains sole git-writer for the PUBLIC repo only.** This does NOT change or
  extend that rule. The two repos have two git-writers by design — ownership follows
  authorship: Window 1 authors the private-module code, Window 2 authors the public docs.

### Launching a window (model pinned at launch, not corrected mid-session)

Each window is opened with its role's model already pinned, via shell aliases in `~/.bashrc`:

```
alias nem1="cd /opt/nemesis && claude --model opus[1m]"     # Window 1 — build
alias nem2="cd /opt/nemesis && claude --model claude-sonnet-5"  # Window 2 — docs/audit
```

- **Why a launch flag and not config.** `~/.claude/settings.json` sets `"model": "opus[1m]"`
  at the USER level, so every session everywhere starts on Opus — which is correct for Window 1
  and wrong for Window 2 *every single morning* (this is what the self-check kept catching;
  it was reporting a permanent default, not an occasional slip). A per-window model cannot come
  from config: both windows run in `/opt/nemesis`, so a `model` key in that project's
  `.claude/settings.json` would force BOTH onto one model and break whichever pin it doesn't
  match. **Do not add one.** The launch command is the only layer that distinguishes the two.
- **`opus[1m]` for Window 1, deliberately** — that is what the global default resolves to today;
  plain `claude-opus-5` would silently drop the 1M-token context window.
- **Claude Code cannot switch its own model.** `/model` is an operator-typed CLI command, not a
  tool available to the session — a window can only DETECT and report a mismatch, never fix one.
  That is precisely why the pin belongs at launch: it is the only point where it can be enforced
  rather than merely flagged.
- Bump the model strings here and in the Window Roles above when Anthropic ships a newer Opus
  or Sonnet — the role pins themselves don't change, only the strings.

### Role self-check (first response)
If you have NOT been told your window number this session, do not begin any task. Your
first response must be to ask: **"Which window am I this session — Window 1 (build,
Opus), Window 2 (docs/audit, Sonnet, sole git-writer), or Window 3 (overflow, ad hoc,
never commits)?"** and wait for the operator's answer before proceeding. If the
operator's first message already states it, skip the question and confirm instead
(window number + role + model).

**Model self-check is the first ACTION, every time identity is given** (fresh session
or a mid-session re-statement after a crash) — before any task work. This is a
self-check convention, not a bash/script check (the active model isn't introspectable
from the shell): confirm the currently active model against this window's expected
model above (Window 1 → Opus, Window 2 → Sonnet) via `/status` or by simply noting
which model you are. If there's a mismatch, **flag it clearly and immediately in the
first response** rather than silently proceeding — e.g. "Note: expected Opus for
Window 1, currently running on Sonnet 5" — then switch to the expected model
(`/model claude-opus-5` / `/model claude-sonnet-5`) before starting the day's actual
task.

**Window 3 is the exception to "once per session"** — its expected model is per-task,
not per-window, so it repeats this check before every task rather than once at session
start. See the Window 3 section above for the task-classification detail.

**Window 1 additionally reads its own context handoff as part of this same first
action** — always, every session start or restatement, not just after closeout.
Once identity is confirmed (fresh session or a mid-session re-statement), before
starting any task, check `~/work/nemesis-internal/handoff/` for the most recent
`*-window1-handoff.md` (newest date wins — one file per day, so this is just
"today's, or if none yet, the latest prior day's") and read it — see "Code-window
context handoff" under Window 1 above. If none exists yet, say so and proceed;
that just means it's the first one that will exist, not an error.

**Window 3 does the same, but only when the task just classified is a code-writing
one** (per its per-task model check above) — check for the most recent
`*-window3-handoff.md` before starting that task specifically, same resolution.
Not required before a docs/audit-mode task, since this handoff exists to protect
code-session context, not Window 3's overflow doc work.

---

## State Snapshots (rollback safety)

Before any STATE-CHANGING action, the build window (Window 1) MUST create a complete,
dated backup set on the USB drive. This exists so any change is reversible —
roll back to a known-good state and preserve the broken state to debug later.

### What counts as state-changing (snapshot required)
- Deploying / restarting a service that affects live behavior
- Any database migration or direct DB edit
- Editing live config (/etc/nemesis.env or equivalent)
Pure code commits that do NOT touch the running system do NOT need a DB
snapshot — they are already reversible via git.

### Backup location and mount safety
- Backup root: /run/media/<user>/storage/nemesis-state-backups/
- This is a USB MOUNT POINT. Before writing, verify the drive is actually
  mounted: `mountpoint -q /run/media/<user>/storage` (the directory can exist
  empty when the drive is unplugged — never trust path-exists alone).
- If the drive is NOT mounted: HALT and prompt the operator. NEVER skip the
  snapshot and NEVER write it anywhere else.

### Set structure (complete matched pair)
Create a dated set folder:
  /run/media/<user>/storage/nemesis-state-backups/YYYY-MM-DD-HHMM-<what-it-precedes>/
Each set contains BOTH halves so a rollback is self-contained:
- alerts.db          — snapshot of the live DB (integrity-checked)
- STATE.txt          — the live git commit hash + tag, `systemctl is-active`
                       for the six services, and a one-line description of
                       the change this set precedes
Rolling back the DB without the matching code (or vice versa) is the subtle
failure this pair prevents.

**⛔ Take the DB half with the sqlite3 backup API (or `VACUUM INTO`) — never `cp` (found
2026-08-28).** `alerts.db` runs `journal_mode=wal`; committed transactions can sit in the
`-wal` sidecar rather than the main file. A `cp` of `alerts.db` alone silently omits them.
**The failure is invisible after the fact:** a `cp`-made snapshot still passes `PRAGMA
integrity_check` and still reports the right table count, so there is no way to tell
retroactively how stale any past `cp`-made set actually is. Every set on record before
2026-08-28 was made this way. Verification shape that proved the fix: 93/94 tables
row-count-identical to live, the one difference (`dm_operation_log`, +4 rows) being the audit
log advancing during the backup itself — expected drift, not loss.

### Behavior
Take the snapshot, then PAUSE and report what is about to change + confirm the
set was written. Wait for operator go-ahead before performing the
state-changing action. Dated sets are never overwritten — every state change
gets its own folder, so any prior state remains recoverable.

---

## TIER 1 — Core operating rules

### 1. Audit-first, then act
Before changing existing code or data, run a READ-ONLY audit that reports findings and
**stops for review**. Never "audit and fix" in one pass. Audits are safe to run anytime
(they change nothing) and routinely catch real problems before they bite.

### 2. One variable at a time
Don't bundle a feature change with a migration step, or two unrelated fixes in one commit.
Isolate each change so it's clear what caused what. Separate gates, separate verification.

### 3. Verify with real output — never trust "done"
"Done / verified / clean / smoke-tested" claims get confirmed by ACTUAL output: greps,
row counts, in-browser checks, real terminal results. Treat self-reported success as
"probably, pending my check." Show the change (diff/grep), don't assert it.

### 4. "Continue" is banned as an instruction
Always send a SCOPED prompt stating exactly what to do and where to STOP. Never a bare
"continue" that lets the tool decide scope — it will reliably do more (or less) than meant.

### 5. Commit-first → deploy → verify; respect the chat/Code split
- chat-Claude: design, architecture, review. Read-only externally (fetches public URLs;
  cannot push/write/commit).
- Code: builds, edits, commits, runs on the machine. (See Window Roles above for exactly
  which window performs the commit/push — Window 2 is the sole git-writer.)
- Commit BEFORE deploy; verify after (process IDs/paths, journals, browser).

### 6. Backup-first before touching live data
Before any step that modifies live data: capture a backup that is VERIFIED RESTORABLE
(test-restore into a throwaway location, not just "it opens"), on INDEPENDENT storage
(different disk/machine — same-disk copies die with the original). Take a FRESH snapshot
before risky steps even if an older one exists (live systems drift).

### 7. Capture ideas, don't chase them mid-task — sort by type, scale capture by maturity
When a good idea appears mid-work, WRITE IT DOWN with its reasoning and return to the
active thread. Sort captures:
- **Small fixes** (bounded, known shape: tooltips, wrong defaults, cosmetic cleanup,
  single-file deleaks) → a running `PUNCHLIST.md`. Knocked out in batches between larger work.
- **Project ideas** (design-requiring, possibly architectural) → start as a roadmap STUB
  (what + why, parked); GRADUATE to a full spec or ADR as discussion fleshes them out and
  the reasoning becomes worth preserving durably.
- **Placement is a judgment and it can CHANGE.** A "small fix" that reveals architectural
  implications gets promoted to a project idea/spec; a stub pressure-tested into a real
  design graduates to an ADR. Re-sort as true scope emerges.
- **Never build mid-task.** Capture with reasoning; return to the live thread.

### 8. Public-repo hygiene
Before EVERY commit to a public repo: grep for home paths (`/home/<user>`), real IPs,
usernames, emails, and secrets. Sanitize docs/code with placeholders. Defaults in shipped
code must be correct for ANY user (e.g. `127.0.0.1`, not my box's IP).

**Audit output is not exempt.** BEFORE committing any audit (or other generated report) to
the public repo: leak-scan its output for Rule-8 content and sanitize IN PLACE, then commit
the clean version — `/home/<user>` → `/home/<user>`, real IPs → `<ip>`, real hostnames
(e.g. `<hostname>`) → `<host>`, real emails → placeholder. **Never commit raw audit
output to the public repo.** (An audit that quotes the live box's paths/IPs/hostname reads as
factual but still leaks — sanitize the quotes, keep the meaning.)

**Handoff docs are NOT exempt.** `docs/handoff/` (HANDOFF.md, supplements, worklogs) MUST pass
the Rule-8 leak-scan before EVERY commit. Real LAN/tailnet IPs, hostnames, emails, and account
names → placeholders (`<box-ip>`, `<tailnet-ip>`, `<project-account>`, …); the real values live
ONLY in `~/work/nemesis-private/local-config.md` (outside the repo). (These are operational
notes that read as internal, but the repo is public — they leak just like code.)

### 9. Handoff discipline
- **Nightly:** when I say I'm stopping for the day, write a fresh `docs/handoff/HANDOFF.md`
  capturing current project state (OVERWRITE — latest state wins; this is "where things
  stand now").
- **Per session:** when a new chat/work session starts, create a dated supplemental at
  `docs/handoff/supplements/YYYY-MM-DD-NNN.md` logging that session's actions and decisions
  (APPEND-ONLY, never overwritten — these are the durable log/history).
- **Session start:** read-order is given at the top of this file (`ARCHITECTURE.md` →
  `docs/architecture/` ADRs → `docs/handoff/HANDOFF.md`).
- **Live worklog (append-as-you-go):** during a work session, maintain a raw
  chronological log at `docs/handoff/worklog/YYYY-MM-DD-NNN.md` (mirrors the
  supplement's date/number). Append an entry the moment each discrete step
  COMPLETES — audits + findings, fixes + commit hash, verification results —
  terse and factual, in order. Flight recorder: minimal prose, no curation. Do
  this AUTOMATICALLY without asking. It is the raw material the session
  supplement is distilled from at closeout. Cadence: worklog (live) →
  supplement (closeout, curated) → HANDOFF.md (closeout, current state).
- I provide the WHEN (I say "I'm done" / "fresh session"); the rule provides the WHAT.
- **Also mirror `docs/handoff/`** (HANDOFF.md, supplements, worklog) to
  `~/work/nemesis-internal/handoff/` whenever any of it is written — see Rule 12.
- **Closeout health check (READ-ONLY — runs EVERY closeout, automatically; the LAST thing
  before the day is called done).** AFTER the supplement + HANDOFF refresh are committed AND
  pushed, run a read-only verification and report a one-line verdict. Confirm:
  1. **Working tree clean** — nothing uncommitted/untracked (`git status --short` empty). Call
     out separately anything that's a *concurrent session's* WIP (not mine to commit).
  2. **Closeout commit is HEAD** — the supplement/HANDOFF commit is the tip.
  3. **local == origin (0/0)** — `git rev-parse HEAD` == `git rev-parse origin/main` (after a
     `git fetch`); the closeout was actually PUSHED, not just committed.
  4. **HEAD touched only expected docs** — `git show --stat HEAD` shows only handoff/docs
     files, no stray code.
  5. **Rule-8 spot-check on the committed diff** — `git show HEAD` carries no real
     IPs/hosts/keys/tokens (placeholders only).
  6. **Open / before-next-session fixes are durably captured** in `PUNCHLIST.md` / `HANDOFF.md`
     (not living only in the conversation).
  Verdict: **"clean + synced + leak-free + open items captured"** — or list exactly what's off.

### 10. Disclosure-check before publishing novel mechanisms or honest-limitation language
Before any commit or write operation to the public repo, check whether it introduces:
- a **genuinely novel mechanism** (not standard industry practice elsewhere — same judgment
  bar as the 2026-07-26 disclosure audit), or
- **explicit honest-limitation/caveat language** describing an unresolved weakness (any
  "X doesn't fully solve Y," "the weakest point is Z," or described-but-unresolved edge case).

If either applies, **flag it for a public/private disclosure decision — do not silently commit
either way.** Apply the established policy:
- General architecture, tier/capability structure, and the existence of a capability default
  to **public**.
- Novel mechanism implementation, specific tuning parameters, and honest-limitation/caveat
  language describing unresolved weaknesses default to a **flagged decision**, not automatic
  public commit.
- **Feature availability is never the deciding factor** — this is a source/doc-visibility rule
  only, never a pricing-tier gate. State this distinction explicitly whenever the rule is
  invoked, so it's never misread as feature-gating.

This is a **standing check for all future work**, not a one-time retroactive pass — every
window applies it going forward, the same way Rule 8's leak-scan applies to every commit.
(Precedent/full inventory: the 2026-07-26 novel-mechanism disclosure audit and its resulting
private-module carve-out for Tier 2 and the four follow-on items.)

### 11. Test data written to the live dashboard must be labeled for later cleanup
Any row inserted into the live `alerts.db` for testing/verification purposes (a test
alert, device, ticket, scan job, quarantine, etc. — anything created to exercise a
feature rather than a real detection) must carry both **the literal phrase "test data"**
and **the date** in its description/notes/message field, e.g. `"test data 2026-07-29 —
verifying auto-quarantine threshold"`. This applies regardless of which window creates
the row (Window 1 verifying a build, Window 3 running a one-off check, etc.).

Purpose: a later cleanup pass can find every test row with one grep/SQL search
(`LIKE '%test data%'`) instead of having to guess which rows are real vs. synthetic from
data alone. Do not rely on "I'll remember to delete it" or on it being obviously fake —
label it at creation time, every time, no exceptions.

**DOCUMENTED EXCEPTION — `audit_log`.** This rule assumes the target table has a free-text
description/notes/message field to carry the label. `audit_log` has none: its columns are
`ts`, `rule_id`, `ip`, `action`, `user`, `request_id` — every one of them structured, none
free-text. A test row there therefore CANNOT be labelled in-band, and the `LIKE '%test data%'`
sweep will never find it. For `audit_log` only, the durable marker is: use an RFC 5737 address
(`203.0.113.0/24` — expendable, non-routable, the established convention here) and record the
row `id` + `request_id` in that session's worklog. Confirmed 2026-07-31 while verifying the
`request_id` column; flagged here so it is not re-discovered later as a missed case. Do not
generalise this exception — every other table has a field to label, and must be labelled.

**SECOND DOCUMENTED EXCEPTION — `login_events` (added 2026-08-29, operator-approved).** Same
structural cause as `audit_log`, found the same way. Its columns are `id`, `username`,
`timestamp`, `ip_address`, `device_id`, `tailscale_ip`, `geo_country`, `geo_city`, `success`,
`failure_reason`, `lockout_tier`, `session_id`, `user_agent`, `source`, `action` — **every one
structured, none free-text.** A test row cannot carry the literal phrase in-band, so the
`LIKE '%test data%'` sweep cannot find it.
**Measured, which is why this is written down rather than assumed:** an audit on 2026-08-29
found **at least 9 unlabelled test rows** across four usernames (`harnesstest`, `x`, `nobody`,
`test-network`) — all `curl/8.18.0` from loopback, none with a real account — while the Rule 11
sweep returned only **2 of 11** test rows. The two it did find had been labelled by someone
putting the phrase in the **`username` field** (`test data 2026-08-06 quarantine-suite`):
effective for the sweep, but it pollutes a column the product reads, so it is a workaround, not
the convention.
**The convention for `login_events`, mirroring `audit_log`'s:** use a distinctive,
obviously-synthetic username (the RFC 5737 trick does not apply — the discriminating column here
is the username, not the address) AND record the row `id` in that session's worklog. The worklog
entry is the durable marker, exactly as for `audit_log`.
**⚠ And when sweeping this table, do NOT delete on "looks unfamiliar".** The same audit found
real failed logins under *mistyped* variants of the operator's own username. Those are genuine
authentication history and are exactly what a careless cleanup would destroy — the whole reason
the marker has to be deliberate rather than inferred.
**Still only these two tables.** Every other table has a free-text field and must be labelled
in-band; a third exception needs the same evidence these two have (a schema with no free-text
column), not convenience.
**Caveat (2026-08-03): RFC 5737 is correct for this labelling use only.** It is the wrong
choice for exercising `is_private`-branching code — Python's `ipaddress` classifies all
three TEST-NET blocks (RFC 5737) as `is_private=True`, so code that early-returns or
filters on address privacy silently skips them, and a test built that way can look like it
passed while never reaching the logic under test. That is a separate, code-path concern
from this rule's DB-row-labelling use; see `alert_manager/test_quarantine.py`'s
`TEST_IP_PUBLIC` convention (`192.88.99.x` — IANA-reserved/deprecated, so it goes nowhere,
but reads as public) for the pattern to use instead when a test needs an address Python
will actually treat as public.

### 12. Local mirror for handoff/briefing/audits docs
`docs/handoff/` (`HANDOFF.md`, `supplements/`, `worklog/`), `docs/briefing/`, and
`docs/audits/` live inside `/opt/nemesis` — not convenient to reach from a
`~/work/nemesis-internal` session. **Every time any of the three is written or refreshed**
(HANDOFF.md overwrite, a new supplement/worklog entry, a new dated briefing — see Rule 9 and
Morning Status §8 — or a new/updated audit doc), also copy the current file(s) to the mirror
at `~/work/nemesis-internal/handoff/`, `~/work/nemesis-internal/briefing/`, and
`~/work/nemesis-internal/audits/` (same relative structure: `handoff/HANDOFF.md`,
`handoff/supplements/`, `handoff/worklog/`, `briefing/YYYY-MM-DD.md`,
`audits/<topic>-audit-<date>.md`).
- This is a **copy, not a move** — `/opt/nemesis` stays the source of truth; the mirror is for
  easy local access only, not a second source of truth to keep independently in sync.
- Content is already Rule-8-clean by the time it lands here (handoff docs, briefings, and
  audits are all placeholder-sanitized before being written at all — see Rule 8's "Audit
  output is not exempt" clause) — no extra sanitization step needed for the copy itself.
- The mirror directory follows whatever version-control state `~/work/nemesis-internal`
  already has — copying files here does not by itself commit them there.
- **Why this exists (added 2026-08-01):** direct chat attachments from `/opt/nemesis`
  intermittently arrive as 0-byte files — a known issue, likely browser/snap sandboxing or a
  stale-handle race, worked around by staging copies under `$HOME` first. Files under
  `~/work/nemesis-internal/` are reachable and upload cleanly, which is why the mirror
  pattern exists at all and why it's worth extending to any directory the operator reads from
  day to day — not just handoff/briefing.
- Audits mirroring added 2026-08-01, prompted by that session's roadmap-state-audit refresh;
  brought under the same standing rule as handoff/briefing (permanent, not a one-time copy) so
  future sessions mirror automatically without being asked.

### 13. Host-level network changes need a PROVEN revert, not a claimed one
No change to the operator's own daily-driver machine's network state — exit node, routing,
VPN prefs, iptables/nft rules, DNS — may be handed to Paul with a claimed auto-revert unless
the revert is PROVEN by reading the live state back (e.g. `tailscale debug prefs`, `ip
route`, `nft list ruleset`) before declaring success. This is the same standard Rule 3
already applies everywhere else in a session — a revert mechanism is exactly the kind of
self-reported "it'll handle it" claim Rule 3 exists to distrust by default.

**Prefer not touching the real host's network stack at all.** Route this class of test
through the isolated VM fleet (see "VM test fleet" in TIER 2) instead of the operator's
actual machine — a scoped VM test produces the same observation without ever putting the
operator's real internet/DNS path at risk.

**Why (2026-08-04 → 2026-08-07 incident; full postmortem:
`~/work/nemesis-internal/known-limitations/tailscale-exit-node-persistence-2026-08-07.md`):**
a `trap '...' EXIT INT TERM` was handed to Paul as a self-reverting exit-node test, with the
claim "auto-reverts on exit or Ctrl-C, so it can't leave your machine routed through a test
VM." **The claim was false.** `EXIT` fires when the interactive shell itself exits, not when
a foregrounded `&&`-chained command finishes — on the expected success path (`sleep 300`
elapsing normally), the compound command simply ended and nothing ever reverted; the trap
sat registered and idle. The exit node stayed live for ~2 days 20 hours — invisible because
the test VM kept genuinely forwarding traffic — until an unrelated reboot restored the
persisted Tailscale pref while the VM happened to be offline, breaking the operator's
internet (LAN stayed fine, disguising it as an ISP/router problem). Zero `EditPrefs` journal
events occurred between the change and Paul's own manual fix three days later — hard evidence
the trap never fired once. No production/Nemesis impact, but a real, hours-long workstation
outage caused by an unverified safety claim.

**If a host-level network test is genuinely unavoidable:**
- The revert is a separate, explicit, operator-run command issued as its own step — never
  chained after the change in the same command/trap.
- State is read back and shown before the change is called reverted.
- The change is logged in the live worklog at the moment it's made (per Rule 9), including
  the exact revert command, so a later session can find it without archaeology.
- Treat it as a state-changing action under the State Snapshots discipline above — not an
  exception to it.

---

## TIER 2 — Nemesis-specific rules

### Read-order & roles
Read-order is given at the top of this file. Chat/Code split and commit ownership: see
TIER 1 Rule 5 and Window Roles above (Window 2 is the sole git-writer).

### Architecture
- **Everything new is a MODULE.** A module is `modules/<name>/` with `manifest.json` +
  `module.py` defining a `Module(NemesisModule)` class implementing: `start`, `stop`,
  `status`, `get_dashboard_card`, `get_routes`.
- **Core** = the Flask app + the alert pipeline + email. Core does not reach into module
  internals; modules register via the contract.
- **All new network access-control MUST route through `alert_manager/firewall.py`** (the
  single `ufw` chokepoint). Do NOT add ad-hoc `nft`/`iptables`/`ufw` calls elsewhere — they
  become debt the future firewall engine (ADR 0005) must reconcile. (Readiness audit
  2026-06-27.)

### Data Manager (ADR 0006 — v1 SHIPPED + loader-enforced, 2026-07-25)
- Standing rule and enforcement mechanism: see Window Roles → "Both windows (shared
  discipline)" above. Full design (access control, audit trail, atomic ops, build sequence):
  ADR 0006 — not duplicated here.
- The four atomic SQL fixes (`tickets_seq`, `ai_engine` rate, `community_queue`,
  `anomaly_incidents`) — the **Data Manager v0 seed** — are now formalized as the real
  `next_sequence`/`increment_counter`/`upsert` methods on `DataManager`, not scattered inline
  SQL. Label new atomic operations as calls to those methods, with a pointer to ADR 0006.
- **Actor mechanism has been wired since 2026-08-04** — flagged here because it's easy to miss
  and ADR 0006 doesn't call it out. The Data Manager stamps `current_actor()` on every logged
  write automatically (atomic-helper AND raw passthrough writes alike — proven in
  `test_data_manager.py`). `dashboard.py:_set_dm_actor` (`@app.before_request`, ~line 1291)
  sets `set_actor("user:<username>")` on both `DataManager` instances (`_dm()` and
  `modules.get_data_manager()` — both, deliberately, since the actor is per-instance
  thread-local state) for the duration of each authenticated request, with a matching
  `_clear_dm_actor` teardown. Unauthenticated requests explicitly set `None` rather than
  leaving a stale value. **This entry was itself found stale 2026-08-22** (Window 3's RBAC
  batch handoff caught it, having repeated the same stale claim once before checking) — a
  reminder that even a flag like this one needs periodic re-verification against the code,
  not just against the last time someone wrote it down.

### Vendor-specific integrations
**VENDOR-SPECIFIC INTEGRATIONS: whenever a vendor-specific probe, plugin, or integration is
built (VPN clients, hardware sensors, notification channels, threat feeds, etc.), a
`CUSTOM_*.md` guide must ship alongside it in the same commit.** The guide covers: the
interface contract, the skip-if-absent pattern, a minimal working example, where to register
it, and any Rule-8 constraints. This is part of the definition of done — not optional polish.
A vendor integration without a custom guide is incomplete. Purpose: community members familiar
with a specific product build the custom code they need instead of filing issues.

### Multi-user-ready by default
New features should be built so multi-user/commercial support is an addition, not a rewrite.
Concretely:
- **Attribute state-changing actions** — anywhere an action records "what happened," leave a
  place to record who (an actor field), even if unused now. (Commercial tier requires
  attributed actions; retrofitting later means touching every write.)
- **Don't assume a single global identity/state** — prefer per-user/per-session-shaped state
  over global singletons where it's cheap to do so.
- **Route writes through single update paths and version data domains** — so live-refresh
  (and later multi-user push) has a clean hook.
- **Concurrency-aware writes** — don't assume one writer at a time from the UI (e.g. counter
  increments like `tickets_seq` must be safe under simultaneous actors).
- **The malware Layer-B build and the agent rebuild MUST include the actor seam** on their
  tables (`malware_findings`, `scan_*`/`queue`, `agent_devices`) and be built **auth-aware**
  at the two hook points: the `/hw_data` handler (`hw_monitor.py` ~1812) for device-auth, and
  `firewall.py` for the engine. Do NOT add these seams twice — fold them into the rebuild.
  (Readiness audit 2026-06-27 / ADR 0005.)
- **Do NOT build the multi-user machinery now** (sessions, auth, SSE push, attribution UI) —
  that's commercial-tier. Leave the socket, don't wire the house.

### Database (per ADR 0001)
- **One shared `alerts.db`.** All persistent state lives there.
- **Modules own tables by prefix:** `anomaly_*`, `malware_*`, `tickets_*`, `ai_*`,
  `community_*`. Core owns the unprefixed core tables.
- **Write-own / read-any:** a module may read across any table but only writes/creates its
  own prefixed tables.
- **One DB accessor, passed by the module contract** (`self.get_db()` / the shared
  `modules.get_db()`). **Never compute `__file__`-relative DB paths.** Separate processes
  (e.g. `watchdog`) that call module APIs must register the shared path
  (`modules.set_shared_db_path(...)`) before use.
- **Every table's DDL lives in exactly ONE canonical init** (the `database.py` shared-init
  pattern / the owning module's `_init_db`). **No table without a `CREATE` in the repo** —
  ref the `devices`-table fresh-install crash (it had no `CREATE` anywhere). Schema changes
  use a guarded `PRAGMA table_info` + `ALTER TABLE ADD COLUMN` migration alongside the
  updated `CREATE`. (Readiness audit 2026-06-27.)

### #1 RECURRING BUG — JS strings inside Python f-strings
The dashboard renders HTML/JS from Python f-strings. The most common defect by far:
- Use **single quotes** for JS string literals inside f-strings, or build the value with
  `json.dumps()`.
- English contractions in rendered text (`it's`, `don't`) must be written as `it&#39;s`
  etc. — a raw apostrophe/quote or newline inside the f-string causes a **silent
  `SyntaxError`**.
- **Grep for this in every retro/review pass.** Unescaped quotes and stray newlines are
  the usual culprit when a page mysteriously fails to load.

### Route-level security audit (standing practice, added 2026-08-01)
**After any change that touches `dashboard.py`, its routes, or its templates** — and before,
if the change is large enough that pre-checking makes sense — run a route-level security
audit in the style of the private-mirror audits that previously found three live bugs:
`db_action`'s unguarded GET, `api_backup_schedule`'s shell injection, and
`api_vpn_action`'s unguarded GET (all since fixed). This does not wait to be asked for — it's
a standing trigger on the change shape, the same way Rule 8's leak-scan triggers on "about to
commit," not on request.

**Scope, every time it runs:**
- **Every route that mutates state:** does it require the correct credential where one is
  warranted, and does it use POST rather than GET? (`db_action`'s bug was exactly this: a
  bare GET, no credential check, contradicting its own sibling `set_action()` — GET-as-write
  is CSRF-triggerable via a plain `<img>` tag under default SameSite=Lax cookies.)
- **Any value interpolated into a shell command, SQL string, or crontab line** without
  proper escaping/parameterization. (`api_backup_schedule`'s bug: `dest_exp` interpolated
  raw into a generated crontab line run via `/bin/sh -c` — no `shlex.quote()`.)
- **Any new route that duplicates or diverges from an existing sibling route's security
  posture** — the `db_action`-vs-`set_action()` shape specifically: two routes doing the same
  conceptual job with different gates is itself the defect signature, independent of whether
  either individual route looks wrong in isolation.
- **Cross-check against known-fixed-pattern regressions** so the same bug CLASS doesn't slip
  back in unnoticed even in a different route: the GET-as-write/CSRF shape and unescaped
  shell/SQL/crontab interpolation are the two classes with a confirmed history in this
  codebase (see the private audits above for the full citations) — new code matching either
  shape is a finding even if it's not literally one of the three named bugs.
- **Any new PUBLIC route must be checked against `_AUTH_EXEMPT` explicitly.** A route
  intended to be reachable without a dashboard login is silently swallowed by the auth
  gate if its endpoint name is missing from that set — it returns 302-to-login instead
  of serving, which looks like a working route to every other check. Confirmed live
  2026-08-02: `install_windows_start` passed compile, template render, and a route audit
  that verified its token guard matched its siblings, then failed in production because
  it diverged from those same siblings on the one axis not checked. Verify the endpoint
  name resolves to a real `@app.route` function too — a typo in `_AUTH_EXEMPT` fails
  closed and is indistinguishable from omitting the entry.

**Method (same as the reference audits):**
- Read-only (Rule 1) — **no fixing or editing during the audit itself.** Findings only; a
  fix is a separate, explicit follow-up pass.
- **Direct code citation for every finding** — file:line and the exact snippet, not a
  paraphrase. ("`dest_exp` interpolated raw... `dashboard.py:7136-7143`", not "the backup
  path looks unsafe.")
- **Explicit "not verified / inference" labeling** for anything not directly confirmed
  against live code — never state an unchecked claim as fact.
- **Output goes to the private mirror** (`~/work/nemesis-internal/known-limitations/` or
  `~/work/nemesis-internal/audits/`, dated filename), **not the public repo.** A live,
  unfixed route-level vulnerability inventory is exactly the "described-but-unresolved edge
  case" shape Rule 10 already treats as flagged-not-automatic-public — this is the same
  judgment applied by default to this specific audit type, not a new exception.
- Whichever window lands the `dashboard.py`/routes/template change is responsible for
  triggering this — either running it directly (it's read-only, so it doesn't conflict with
  Window 1's build-window scope) or handing off to Window 2 explicitly if the change was
  trip-critical/time-pressured and audit-first discipline calls for a separate pass rather
  than folding it into the same live session.

### Unauthenticated routes: hand-placed exceptions only, never a module capability (standing practice, added 2026-08-29)
**Unauthenticated routes may only be created as hand-placed, individually-audited exceptions in
`dashboard.py`'s `_AUTH_EXEMPT` list. The module system has no mechanism for declaring a route
public, and none should be added.** A third-party module needing an unauthenticated entry point
must request a hand-placed `dashboard.py` exception from the core team — **the module system
itself never grants this capability to third-party code.**

**Why this is a security boundary and not an inconvenience.** Nemesis's module architecture is
designed to accept third-party/community modules. A module-level "no auth required" declaration
would hand the power to publish an unauthenticated endpoint to authors outside core-team review
— the single most dangerous capability in the product, granted by a manifest key. Keeping the
only path a hand edit in a core file means every public route is seen by someone who can weigh
it.

**The mechanism already enforces this, and the enforcement is worth knowing:**
`modules_loader.py` refuses to register any endpoint absent from `roles.ROUTE_MINIMUMS`
(the route then **404s**), and `ROUTE_MINIMUMS` has no public concept — every entry is a role
tuple. So a module route is authenticated by construction. **Do not "fix" that by adding a
public/None role.**

**⚠ Two registries, two different silent failures.** `install_windows_start` (2026-08-02) is
remembered for the `_AUTH_EXEMPT` **302-to-login** failure. There is a second one: a missing
`ROUTE_MINIMUMS` entry **404s**, which reads as "route doesn't exist" rather than
"misconfigured". Both look like a working route to every check that does not specifically test
an unauthenticated request. **Verified live 2026-08-29:** `roles.py`'s own registry-completeness
test caught a `CAPABILITY_ROUTES`/`ROUTE_MINIMUMS` entry naming an endpoint that did not exist
yet, reporting *"a typo protects nothing while looking like coverage."*

### `_AUTH_EXEMPT` hardening checklist — every entry, every time (standing practice, added 2026-08-29)
Every `_AUTH_EXEMPT` entry MUST satisfy all of the following. **The list is a reviewed artifact,
not a collection of isolated entries** — a new entry is a change to the whole surface.

1. **Its own scoped, single-use token** — hashed at rest, **constant-time compared**, TTL-bound,
   and **atomically consumed** (the consume must be the same operation that checks, or two
   simultaneous uses both succeed).
2. **Identical reject behaviour for invalid vs. expired vs. already-used.** Same status, same
   body, same timing to the caller. A distinguishable response is an oracle: it confirms a token
   *existed*. Log the distinction internally, never expose it.
3. **Rate-limiting keyed on the real `remote_addr`**, with **bounded, evicting storage**. An
   unbounded dict keyed on a client-controlled value is a memory-exhaustion vector reachable
   without credentials.
4. **Full audit logging of BOTH success and failure.** A route with no logged failures is
   indistinguishable from a route nobody attacked.
5. **Fail closed on ambiguous state.** An unparseable expiry, an unreadable row, a missing
   config value → refuse. Never treat "cannot determine" as "permitted".
6. **The standing route-level security audit is MANDATORY, not discretionary, on every
   `_AUTH_EXEMPT` change** — including removals, since removing an entry can silently break a
   flow that depended on it.
7. **Verify the endpoint name resolves to a real `@app.route` function.** A typo fails closed
   and is indistinguishable from omitting the entry entirely.
8. **A test that proves the route is reachable WITHOUT a session** and does not 302. **A test
   asserting the route works while authenticated proves nothing — the broken version passes it
   too.** This is precisely how `install_windows_start` shipped.

**Reviewing the list as a whole:** when adding an entry, re-read every existing one and confirm
each still needs to be there and still satisfies 1–8. The set's risk is its union, not its
newest member.

### Every module declaring routes needs a registry-completeness test (standing practice, added 2026-08-30)
**Any module implementing `get_routes()` MUST carry a test asserting its declared routes match
`roles.ROUTE_MINIMUMS` in BOTH directions** — every route `get_routes()` returns has a
`ROUTE_MINIMUMS` entry, AND no `ROUTE_MINIMUMS` entry names an endpoint the module doesn't
actually declare. Reference implementation:
`modules/lan_integrity/test_lan_integrity_registry.py`'s `test_routes_are_registered()` — copy
its shape for new modules rather than reinventing it.

**Why this just became load-bearing, not merely good practice.** `8a8580f` (2026-08-30) fixed a
live crash-loop: `assert_capabilities_sane`'s startup check used to treat any `ROUTE_MINIMUMS`
entry absent from the LIVE `url_map` as a fatal typo — which was WRONG for a disabled module
(its routes never register, so the "absence" is legitimate, not a mismatch) but had been the
only thing catching a genuine module-route/`ROUTE_MINIMUMS` mismatch loudly, at every boot. The
fix is correct and necessary (a disabled module must not crash-loop the whole dashboard), but it
means the runtime now defers — records as "dormant," does not raise — on any `module_`-prefixed
endpoint present in `ROUTE_MINIMUMS` but absent from the live map. **That is exactly the shape a
real declared-route/registry mismatch would also take** when the module is disabled, or more
generally whenever the live `url_map` can't be trusted to reflect what should be there. The
static per-module registry-completeness test is now the ONLY thing that still catches this
mismatch class loudly and deterministically, independent of whether the module happens to be
enabled at test time. Skipping it on a new module is no longer "one less nice-to-have test" — it
is the one check standing between a real typo and a silent, permanent dormant-capability
misclassification that nothing else in the startup path will ever flag.

### Verification/derivation code must prove its own premise (standing practice, added 2026-08-01)
**Nine instances in one day, all the same shape.** An empty comparison read as "agree." A
failed counter lookup silently defaulting to zero and reported as a real measurement. An
unreadable path reported as merely "absent." A broken cookie decoder. A substring match
standing in for a real check. A `gawk`-only function silently failing under `mawk`. Different
languages, different layers (shell, Python, JS, awk), same defect: **an instrument that can
only produce one answer, reporting that answer as though it measured something.** None of
these failed loudly — each one dressed a non-measurement up as a legitimate result, and the
result was trusted because nothing about its shape looked wrong.

This is not specific to firewall/ADR-0019 code — it showed up across dashboard auth code,
shell harnesses, and JS this same session. Treat it as general to any code in this repo that
compares, derives, or verifies something, not just network/security-adjacent paths.

**Two rules, both required, neither optional:**
1. **Any verification/derivation step must prove its own premise against a known-different
   input before trusting what it reports.** A self-test with a known-good and a known-bad case
   run on every invocation (not just in a test suite, in the production code path itself) is
   what catches "this can only ever say ALLOW" before it ships, not after. See
   `scripts/nemesis-fw-neverblock`'s `CANARIES` self-test for the reference shape: two
   addresses that MUST classify as protected, two that MUST NOT, checked before the tool
   vouches for anything real.
2. **A failed read must surface as an explicit failure state, never as a default value.** A
   default that "means something" (zero, empty, "absent," `False`) is indistinguishable from a
   genuine result to whatever reads it next. Fail closed and loud — raise, exit non-zero,
   return an explicit sentinel the caller cannot mistake for real data — rather than falling
   back to a value that happens to be a legal answer.
- **Grep for this shape in every retro/review pass**, alongside the existing #1-recurring-bug
  check — same category of standing check, different failure class.

### Check the SHAPE of output, not just whether the value looks plausible (standing practice, added 2026-08-23)

**A lookup or control that reads the wrong source can return a value indistinguishable from
the right one.** Assert the shape of the output — count, type, source identity — not only
that the value looks reasonable.

This is the sibling of the rule above and the harder half of it. That one is about an
instrument that can only produce one answer. This one is about an instrument that produced a
*perfectly plausible* answer, from somewhere other than where its label claimed. There is
nothing wrong-looking to notice, which is exactly why reading the result more carefully does
not help.

**Seven instances in one day (2026-08-23), across two windows.** Listed because the pattern
is only visible in aggregate — individually each looked like an ordinary slip:

| # | What happened | What made it invisible |
|---|---|---|
| 1 | A mutation test asserting an unreadable setting could not fall through to a BUNDLE default — it passed against the mutant, because `route()` already fails safe on `None` | The check could not fail. A pass proved nothing |
| 2 | A page-render probe reported every element absent; the response was **302** (unauthenticated), so every assertion would have been False whatever the template contained | "Element missing" and "page never rendered" produce identical output |
| 3 | A control labelled *"from /opt/nemesis"* that actually ran from `/tmp`, because a single `cd` at the top of the block applied to every line | A control that did not run looks identical to one that passed |
| 4 | `find / -name X.service \| head -1` returned a `/sys/fs/cgroup/...` pseudo-directory; `grep` on it printed nothing silently, so the next command's output was read as this one's | The value was a real PYTHONPATH from a real unit — just the wrong unit. **The tell was the line COUNT: two files queried, one line returned** |
| 5 | A `head -12` on a grep silently truncated the result set that a conclusion was drawn from | A short list and a complete short list look the same |
| 6 | A `python3 -c` path test run from the repo root, where the cwd lands on `sys.path` and every variant reports importable | A uniform "all OK" reads as a clean result, not a contaminated one |
| 7 | A cross-shape check that returned the correct state **for the wrong reason** | Right answer, wrong derivation — passes every check on the answer |

**What to actually do:**
- **Assert the count.** Two files queried should produce two lines. Instance 4 was catchable
  and was walked past because only the value was inspected.
- **Assert the source identity**, not just the value — which file, which host, which commit.
  `git show HEAD:<path>` rather than a working-tree read when handing a fact to someone else.
- **Never `head -n` a set you are about to draw a conclusion from** without separately
  reporting whether it was truncated.
- **A control needs its own precondition checked.** Prove the harness was in the state the
  label claims before trusting what it reports.
- **Prefer a neutral cwd** for any path/import test; the repo root silently rescues imports
  that would fail in a service.

**⚠ THIS RULE APPLIES TO YOUR DIAGNOSTICS, NOT ONLY TO PRODUCTION CODE (added 2026-08-26).**
Every example above is production code. On 2026-08-26 three windows hit this shape in one
day, and **all three were in the instruments used to INVESTIGATE**, not in the thing being
investigated:

| the diagnostic | why it looked fine |
|---|---|
| `git stash push` + `pop` to measure a test result "before" a change | the push silently did not take, so the "before" run still contained the change — **it was compared against itself and declared innocent** |
| grepping for symbols, expecting zero, reading hits as damage | the hits were already-committed work; the grep was correct, the **expectation attached to it** was not |
| counting install-directory entries as setup progress | all of them were OS built-ins |

**The first is the most instructive: it LOOKED like a controlled before/after and had no
"before".** It then produced a confident, wrong conclusion that was reported to the operator
and sent another window investigating a defect that did not exist.

**What to do:**
- **Prove the "before" is actually different before trusting a before/after.** A
  state-moving command that half-fails leaves you measuring the same thing twice. This is the
  known-good/known-bad discipline `scripts/nemesis-fw-neverblock` already applies in
  production — turned on your own diagnostic.
- **Separate the query from the expectation.** A grep that returns what you did not expect has
  not necessarily found a problem; check what the hits ARE before naming them.
- **Prefer a read-only comparison to a state-moving one.** "Did I cause this?" is usually
  answerable with `git diff --stat -- <file>` — no writes, and it cannot half-fail.

**Grep for this shape in every retro/review pass**, alongside the checks above and below.
Four standing checks now, one failure class each: a bug that hides in rendering (#1 recurring
bug), an instrument that cannot fail, an instrument that answered from the wrong place (this
one), and a branch nothing ever walked (below).

### A new branch or default needs a test that EXERCISES it, not one that could (standing practice, added 2026-08-24)

**Three consecutive days produced the same bug shape: a new branch or default that nothing
exercises, shipping green because every test that ran happened to take a different path.**
Instances (Window 3's observation, cross-window, 2026-08-24): `capabilities._conn()`,
`role.js`'s missing `sub_admin` entry, the unwired unlock gate, and a near-miss the same day
in `test_capabilities.py`, caught before it shipped. None of these were disproven by a
failing test — none had a test that touched them at all. A green suite and a suite that
never walked the new code are indistinguishable from their own output, which is exactly the
"looks like a real result but isn't" shape the other three checks already name, applied here
to test coverage instead of a verification instrument.

**The check, every review/retro pass: does any new default or branch in this change actually
have a test that exercises it, not just one that could?**
- For every new conditional, default value, or branch: name the specific test (or assertion
  within one) that forces execution down that exact path. If none exists, that IS the
  finding — not "add a general test later."
- "The suite is green" is not evidence a new branch works if nothing in the suite runs it.
  Ask which test would fail if the branch's logic were wrong, and confirm that test actually
  reaches the branch — a coverage tool if one exists; failing that, a deliberate mutation
  (break the branch, confirm the suite goes red, revert).
- A test asserting a new default's VALUE is not the same as a test proving the system behaves
  correctly while that default is in effect.

**Grep for this shape in every retro/review pass**, alongside the other three above. Four
standing checks now — see the tally at the end of the SHAPE section above for the full set.

### A roadmap item picked up for build needs its dependency claims verified against code, not just its build status (standing practice, added 2026-09-02)

**The existing roadmap-audit discipline — classify against code and git log, never against a
file's own `Status:` header — genuinely works, and has already caught drift on its own** (e.g.
`malware-yara-rule-autoupdate.md`). But two incidents this week found a gap the header-check
cannot see by construction: **a file can be correctly classified and still rest on a false
premise stated in its BODY, describing infrastructure it depends on, not its own build state.**
`enrollment-modes-build-spec.md`'s PARKED classification was accurate the whole time — the
audit had nothing wrong to catch — while its §3 stated a `firewall.py` trusted/guest posture
mapping as existing fact when it does not exist, and it (along with ADR 0012) described
FLEET-auto's core mechanism as unbuilt when per-token `auto_approve` had already been doing it
in production. Both stale claims changed what actually got built, and both escaped the
standard audit because the audit checks a file's *classification*, not the *claims inside it*
about the code it assumes is there.

**The check: before building against a roadmap item, verify its dependency/infrastructure
claims against the actual code, not just its build-status bucket.** A claim that another
module, chokepoint, or mechanism "already does X" is itself a testable assertion — grep for
it, read the code it names, confirm the claim rather than inheriting it. This is a build-time
discipline (triggered when a PARKED/PARTIAL item is about to be built, not only during the
daily roadmap-vs-state audit) — the existing audit's incremental/full-re-derivation cadence
does not by itself reach into a file's body claims on every pass, which is exactly why this
gap stayed open across multiple prior audits.

### Conventions
- **Local secrets / test creds (OUTSIDE this repo):** Local secrets and test-server
  credentials live at `~/work/nemesis-private/local-config.md` — **outside this repo, never
  committed.** Read it by absolute path when SMTP config or test creds are needed. **NEVER**
  copy its values into any tracked file, commit message, code, or the public repo —
  reference the location only.
- **No hardcoded environment-specific defaults:** Never hardcode environment-specific values
  (real LAN IPs, home paths, the prod host's IP) as defaults in shipped code — use
  `127.0.0.1` or read from `/etc/nemesis.env`. Defaults must be correct for ANY user, not
  this machine. (This is Rule 8; the `<pihole-ip>` `PIHOLE_IP` default is a known instance
  pending fix.)
- **Model string:** `claude-sonnet-4-6`. **⚠ FLAG — VERIFY BEFORE TRUSTING:** this looks
  potentially stale given the current Anthropic model lineup (Sonnet 5 / Opus 4.8 / Fable 5).
  Confirm what this actually refers to in the live code (likely a hardcoded string in the
  dashboard's own AI-integration, e.g. `ai_engine/module.py` — NOT Claude Code's own model
  selection) before changing it; don't guess-update a value real code depends on.
- **Key paths** (fixed since the 2026-07-27 `/opt` relocation — no longer install-user-home-
  dependent; `scripts/migrate_to_opt.sh` is the one-way move, `alert_manager/nemesis_paths.py`
  is what code actually resolves against, not these paths computed ad hoc):
  - dashboard: `/opt/nemesis/dashboard.py`
  - `/opt/nemesis/alert_manager/` — core services (alert-watcher, hw-monitor,
    device-scanner, watchdog, dashboard)
  - `/opt/nemesis/modules/` — pluggable modules
  - `/var/lib/nemesis/alerts.db` — shared DB (moved out of the tree 2026-07-27; group
    `nemesis-db`, directory mode `0770` — SQLite WAL's `-wal`/`-shm` siblings need directory
    write, not just traverse)
  - `/etc/nemesis.env` — environment/secrets, mode `640 root:nemesis`
  - `docs/CUSTOM_TAILSCALE_OAUTH.md` — Tailscale OAuth auth-key minting setup (the four `TAILSCALE_OAUTH_*`/`TAILSCALE_TAG` env vars + installer self-onboard hybrid fallback)

### VM test fleet (VirtualBox Masters, established 2026-08-02)
Seven baseline "Master" VMs on the build machine, each meant to be **cloned per test rather
than used directly.** Standard test creds apply to all seven — see
`~/work/nemesis-private/local-config.md` (never spelled out here, per the local-secrets
convention above). Bridged NICs use the host's LAN interface (`<bridged-iface>`); isolated NICs use hostonly `vboxnet0`
(`192.168.56.0/24`).

- **⛔ CREDENTIALS NEVER GO ON A COMMAND LINE — `--passwordfile`, always (standing rule,
  added 2026-08-27 after the SECOND occurrence).** Every `VBoxManage guestcontrol` call
  passes `--passwordfile <path>` (note: no hyphen between "password" and "file"), never
  `--password <value>`. Same principle for any other VM/automation tool that offers a file
  or stdin form.

  **Why, concretely.** An argument is visible to every local user via `ps`, and — the way it
  actually bit — **Python's `subprocess.TimeoutExpired` embeds the full argv in its message**,
  so a hung command printed the VM password into a session transcript verbatim. That is the
  second instance of this exact pattern: `local-config.md` already records a unique VM
  password retired on 2026-08-26 for the same reason. Twice is a convention problem, not an
  attention problem, which is why it lives here rather than in a session note.

  **This matters even while the lab credential is low-value.** The current shared lab password
  is trivially guessable, so leaking it disclosed little — but the same call shape is what
  will be used the day a real secret is passed, and the habit is what has to be right by
  then. Write the secret to a `0600` temp file, pass the path, delete it in a `finally`.

- **Fresh-clone discipline (standing rule).** Never test additionally on a Master itself —
  always start testing from a fresh clone of the appropriate Master below. Always delete that
  clone once its testing is done, unless more testing on that exact environment/state is
  likely needed soon — in which case say so explicitly (worklog entry naming the clone and why
  it's being kept) rather than leaving it to linger unlabeled. **Why:** unlabeled clones/
  snapshots accumulating indefinitely is exactly what made the full 2026-08-02 VM fleet cleanup
  necessary in the first place — this rule exists so that cleanup doesn't have to happen again.
  **Scope — does NOT include long-term-testing VMs.** This clone-and-delete rule governs the 7
  Masters above only. It does not apply to any VM explicitly designated for long-term/permanent
  testing — e.g. the permanent hardware/software gauge VM below — which is used directly, by
  design, not cloned-and-discarded, because its entire value comes from persisting state and
  staying current over time (see its maintenance rule below). Those VMs are a deliberate
  exception, not an oversight of this rule.
- **`KEEP`-named VMs are protected — never deleted or destroyed without explicit operator
  confirmation, regardless of appearance.** Any VM whose name contains `KEEP` must be treated
  as protected during any cleanup pass, no matter how stale, unused, or unregistered-looking it
  appears. **The convention:** when a window clones a Master and determines the clone needs to
  survive a cleanup pass (checked out, still needed — the exact case the fresh-clone-discipline
  bullet above already asks to name explicitly), it renames the VM to include `KEEP` in the
  name **before** the clone could otherwise be mistaken for stale sprawl. **Why:** this replaces
  relying on any window remembering not to clean up a needed clone — the decision lives on the
  VM itself, so a later cleanup pass (a different window, or the same window after a context
  reset) doesn't have to rediscover or guess intent from staleness signals alone. Same spirit as
  the living fleet inventory below, but survives even if that log is ever out of date or
  unread — the name is the fail-safe.

**Capability list** — the seven Masters, so picking the right one for a task is a lookup, not
an investigation:

| VM name | OS | Network | Role |
|---|---|---|---|
| `Nemesis Linux Master BRIDGED` | Ubuntu 26.04, bare | bridged | plain Linux client |
| `Nemesis Windows11 Master BRIDGED` | Windows 11, bare | bridged | plain Windows client |
| `Nemesis Appliance Master ISOLATED` | Ubuntu 26.04, Nemesis installed + running | isolated | the firewall appliance itself |
| `Nemesis Linux Master ISOLATED` | Ubuntu 26.04, bare (cloned from the bridged Linux Master) | isolated | plain Linux client |
| `Nemesis Windows11 Master ISOLATED` | Windows 11, bare | isolated | plain Windows client |
| `Nemesis Kali Master ISOLATED` | Kali 2026.1 | isolated | attacker/pentest box |
| `Nemesis Kali Master BRIDGED` | Kali 2026.1 | bridged | attacker/pentest box |

- **Permanent hardware/software gauge VM — `Nemesis Appliance Gateway` (renamed 2026-08-06
  from `Nemesis Appliance HW-GAUGE`, same UUID, snapshot chain intact), built and pruned
  2026-08-02.** Ubuntu 26.04 Server (headless), bridged (`<bridged-iface>`, `<hw-gauge-ip>`),
  production Nemesis (`ce9696a`) with a deliberate OS-package removal pass applied (833 → 738
  packages; all 13 Nemesis-family services verified healthy after every batch). A separate,
  standing asset from `Nemesis Appliance Master ISOLATED` above — **not a Master**, not
  subject to fresh-clone discipline — dedicated to representing an accurate, CURRENT
  hardware/software-requirements baseline, re-tuned over time as real requirements are
  discovered rather than treated as a finalized template. **First real headless measurement**
  against the previously desktop-only/estimated baseline: 1.7GB RAM idle (baseline's own
  extrapolation was ~1.85GB), 3.5G/25G disk (roughly a third of the unpruned desktop
  baseline's 11.4–12G), confirming RAM-bound-not-CPU-bound and ClamAV (`clamd`, ~992MB) as the
  dominant sizing factor, exactly as the existing baseline concluded. Also surfaced a live
  reproduction of `PUNCHLIST.md`'s Pi-hole unattended-install whiptail-hang bug, worked around
  without touching `install.sh`. Full build log, removal-batch reasoning, and the
  footprint-comparison table: private mirror (`vm-fleet/VM-FLEET-LOG.md`).
- **Permanent gauge VM maintenance — standing obligation, not optional.** Whenever production
  Nemesis is updated, the gauge VM MUST be brought up to that same version. Its entire purpose
  is representing what Nemesis currently requires, not what it required when the VM was
  created — a stale gauge VM is worse than no gauge VM at all, because it looks authoritative
  while being wrong. Precedent for exactly this failure mode, found this same cleanup pass:
  the general-purpose `Nemesis Appliance Master ISOLATED` above was discovered four days
  behind HEAD, predating the entire ADR 0019 build — tolerable for a plain test client, but
  the gauge VM must not repeat it, since staying current is the one property its whole purpose
  depends on. **Resolved 2026-08-02**: that VM was brought current to HEAD (`5e5e020`) and
  `nemesis-fw-watch`/`nemesis-fw-enforce` installed, with full verification (table creation,
  correct CAP_NET_ADMIN-only capabilities from `/proc`, a real CONTROL ufw-change test, and
  reboot persistence) — same rigor as the production deploy script, not just "it started."

**Ongoing fleet stewardship — Window 3's standing responsibility, not one-off cleanup/audit
tasks.** Window 3 itself is opened situationally (see its role above), but the three
obligations below apply every time it touches the fleet, not just during a dedicated cleanup
pass. Rationale for all three: today's two concrete lessons — the Appliance Master found four
days stale, predating the entire ADR 0019 build, and the general fleet sprawl (unlabeled
clones/snapshots accumulating for weeks) that made the full 2026-08-02 cleanup necessary in
the first place.

- **Living fleet inventory.** Extend the capability list above from Masters-only into a
  fleet-wide inventory covering every VM that currently exists — Masters, any clone kept past
  its test (per the fresh-clone-discipline exception above), and every entry in "Also present"
  below. Each gets its reason for existing (role/purpose), not just its name — an unlabeled VM
  is exactly the state the 2026-08-02 cleanup had to untangle. Update it as VMs are
  created/retired; it is a living document, not a periodic re-audit.
- **Fleet cleanup runs at EVERY session closeout — a routine, not a request (sharpened
  2026-08-25).** Don't wait for another full audit — at each closeout, identify any stray
  clone/snapshot and either delete it or make (and record) a deliberate keep decision, the
  same per-test choice the fresh-clone-discipline bullet already asks for, now applied as a
  standing closeout check so strays get caught immediately instead of accumulating. Look
  specifically for VMs that are **powered off and clearly abandoned**, **named for a
  since-completed task**, or **otherwise clearly stale**. Then either:
  - **Clean up directly** — non-`KEEP` and obviously disposable. Record what was deleted and
    why in `vm-fleet/VM-FLEET-LOG.md` (private mirror); a deletion with no recorded reason is
    how the next person loses the ability to tell a decision from an accident.
  - **Flag plainly in the handoff** — anything `KEEP`-protected or ambiguous, named
    individually with its size and a recommendation, so the operator makes a *decision*
    rather than a *rediscovery*.

  **Check the name, not just the log, before deleting anything:** a VM with `KEEP` in its
  name is protected regardless of how stale it looks (see the `KEEP`-naming convention
  above) — a closeout sweep may delete non-`KEEP` strays on its own authority, but may
  **never** delete or destroy a `KEEP` VM, however stale it looks, without explicit per-VM
  operator confirmation. The whole point of the name is that a cleanup pass cannot reason its
  way past it.

  **Why a routine and not a reminder.** Confirmed live 2026-08-25: an "overnight" batch from
  08-20 was still running five days later — 8 GB of RAM and 114 GB of disk — and was caught
  only because Window 1 went looking for RAM. Its third member was already powered off and so
  was **invisible to that sweep entirely**: costing nothing, it prompted no look, and it was
  found only because the two running ones led back to it. **Accumulation here is silent by
  construction — an idle VM produces no symptom until the disk is full.** By that point the
  fleet was 923.5 GB, roughly 60% of a disk at 83% capacity. A check that depends on being
  asked is a check that happens after the problem. Reference shape for the flag-it half:
  `vm-fleet/fleet-inventory-2026-08-25.md` (private mirror).
- **`KEEP` now EXPIRES, and the closeout sweep RUNS THE CHECK (added 2026-08-27).** Every `KEEP`
  VM carries a review date in its own VirtualBox extradata (`nemesis/keep-until`, ISO date or the
  literal `permanent`; plus `nemesis/keep-reason` and `nemesis/keep-affirmed`). **Run
  `~/work/nemesis-internal/vm-fleet/tools/nemesis-fleet-review` as part of every closeout sweep**
  — it is read-only, exits **1** if any VM is past its date and **2** if it cannot trust its own
  classifier, so it is a gate rather than a report. Default window is **60 days**; the companion
  `nemesis-fleet-backfill` is a one-time bootstrap (dry-run by default, writes only `nemesis/*`
  extradata, never overwrites an existing value) and has already been applied to all 45 VMs.
  **⛔ THE NAME IS STILL THE FAIL-SAFE AND THIS CHANGES NOTHING ABOUT IT.** `KEEP` in the name
  means protected, unconditionally. The date is advisory metadata layered on top: missing,
  unparseable or unreadable metadata resolves to **protected and listed**, never to "expired" and
  never to "deletable". The mechanism can only ever ADD A FLAG, never remove protection — the same
  invariant shape as ADR 0019's failsafe response. **EXPIRED means a human is asked again; it
  never means delete.** The outcomes are renew, retire (with the explicit per-VM confirmation the
  `KEEP` rule already requires), promote to permanent, or leave it flagged. Nothing may be deleted
  on the strength of the review list alone — the `srv-client` near-miss and the 2026-08-27
  `win11-benign-src.vdi` case (every mechanical test said "orphan, reclaim 40 GB"; the correct
  answer was **do not touch it** — it was another window's completed corpus clone) are exactly why.
  **Why a human-set date and not "N days since last boot":** measured across all 45 VMs,
  `VMStateChangeTime` had a **median age of 1 day**, so an N-day rule flagged **zero VMs at
  N=30/45/60/90** — housekeeping resets it, and a sweep that boots a VM to inspect it resets that
  VM's own aging clock. Full design and verification evidence:
  `vm-fleet/PROPOSAL-keep-expiry-convention-2026-08-27.md` and `vm-fleet/VM-FLEET-LOG.md`
  (private mirror).
- **Keep-current generalizes past the gauge VM.** Any VM in the fleet running a server or
  agent install — not just the permanent gauge VM above — gets updated to match whenever
  production Nemesis updates. Same reasoning as the gauge VM's maintenance rule: a VM meant to
  represent current product behavior is worse than useless if it's silently stale.
- **Identify a VM by ARP or in-guest data — NEVER by the VirtualBox DHCP leases file.** Before
  acting on any VM by IP, resolve IP→VM through host ARP (`ip neigh show dev vboxnet0`) or by
  reading `/sys/class/net/<iface>/address` inside the guest. Do NOT trust
  `~/.config/VirtualBox/HostInterfaceNetworking-vboxnet0-Dhcpd.leases`: it retains stale
  entries and the server reassigns addresses, so a MAC→IP pair read from it can name a VM that
  no longer holds that address. **Confirmed live 2026-08-02**: during the Master-accessibility
  audit a stale lease pointed at one of Window 1's *actively running* clones instead of the
  intended Master, and the misidentification surfaced only because the guest's uptime
  contradicted the reboot cycle just performed on the intended VM. Those commands happened to
  be read-only, so nothing was damaged — but the identical mistake one step later, during the
  fix, would have modified another window's live work. **A wrong-VM write is not recoverable by
  noticing afterwards**, which is why the check belongs before the action, not after.
  Corollary — **uptime is a cheap sanity check**: if a guest's uptime does not match the
  power cycle you just performed on it, you are on the wrong VM; stop and re-resolve.
  This is the same failure class ADR 0019's `VM-TEST-PLAN.md` already names for its own rig
  ("identify by MAC via `VBoxManage`, never by inferring from open ports") — this bullet
  generalises it from that one target to the whole fleet.
- **Fleet archive policy — non-active images move to external storage, not deleted
  (operator-directed, 2026-08-28; archive target corrected same day after measurement).**
  1. Non-active VM images (not currently in use, but not confirmed deletable) live on the
     **WD Blue SA510 4 TB SSD (ext4), mounted at `/mnt/nemesis-vmarchive/vm-archive`** —
     **not** the Seagate USB drive named when this policy was first written hours earlier.
     Move with `VBoxManage movevm --folder "/mnt/nemesis-vmarchive/vm-archive"` (note:
     `--folder` takes the PARENT directory; `movevm` creates the per-VM subdirectory itself),
     never a manual file copy — `movevm` re-registers the VM atomically at its new path and
     preserves the snapshot chain; a manual copy does neither. The Seagate keeps its existing
     job unchanged: `nemesis-state-backups/`, the `usb` git remotes, `nemesis-issuer.priv`,
     the Layer D corpus VDI, and `os-images/` — none of that moves.
  2. Master/template base images may live permanently on the archive drive. When a working
     clone is needed, clone it onto the NVMe on demand. That clone is disposable — delete it
     after use rather than archiving it back; the archived copy stays the source of truth.
  3. **Superseded constraint, kept as history:** the Seagate (spinning, exFAT, USB 2.0) measured
     a flat ~126 IOPS ceiling regardless of concurrency — seek-bound, disqualifying for a VM
     fleet. **This does NOT apply to the WD SSD archive target**, which measured ~90 MB/s
     end-to-end through `movevm` on a 5000 Mbps link and is not seek-bound. Kept here only
     because it still describes the Seagate's own remaining content, not because it constrains
     archiving today.
  4. **Superseded risk, kept as history, plus a live one that replaces it:** exFAT's
     no-journal risk (an unplug mid-write threatens everything on the drive) does not apply to
     the WD's ext4. **A different shared-device risk takes its place:** the WD also holds the
     Timeshift snapshot store, so routine archive/restore traffic shares the physical device
     with those snapshots — Rule 6's independent-storage requirement still holds overall,
     since backups and the `usb` git remote stayed on the Seagate; the two drives now split
     the risk instead of one drive concentrating it. Do not "simplify" this back to the old
     exFAT framing — the mechanism changed, the fact of a shared device did not.
  5. **Tracking requirement.** `nemesis-fleet-review` and the living fleet inventory only see
     VMs currently registered with VirtualBox — an archived VM drops out of both, and without
     a separate record an archived fleet becomes invisible, silently reintroducing the exact
     "clean report is misleading" failure the 2026-08-25/2026-08-27 fleet-review work was
     built to close. **Manifest: `vm-fleet/archive-manifest.md` (private mirror)** — same
     placement as `VM-FLEET-LOG.md` and the fleet-inventory docs it sits beside, per this
     section's established pattern of keeping fleet operational data (real VM names, disk
     paths) out of the public repo. Logs, per archived VM: name, archived date, archived by
     (window), reason, USB path, and the exact restore command. Whichever window archives or
     restores a VM keeps this file current as part of that action, same discipline as the
     living fleet inventory above — not a periodic audit deliverable.

**Also present, outside the 7-Master set — do not fold into it without a deliberate decision:**
- `Nemesis-firewall Utility CLEANBASE 07.31` — deliberately purged-bare Ubuntu base kept
  specifically for install-timing measurement. Not a Master; don't clone it expecting a
  generic Linux box.
**Retired:** `Nemesis-firewall W3-TEST 07.29` + `Nemesis-SW WIN11 W3-TEST 07.29` — the ADR 0019
enforcement-engine test rig, **deleted 2026-08-02** (full 5-snapshot chain included) once that
work was confirmed concluded. The permanent measurement record lives in
`firewall-enforcement-engine/VM-TEST-PLAN.md` (private mirror) — not lost, just no longer a
running VM. Full retirement reasoning: `vm-fleet/VM-FLEET-LOG.md` (private mirror).

`Nemesis Appliance Spare ISOLATED` — the VM itself is gone (not registered); a stale,
`inaccessible` VirtualBox medium registration for its old disk survives (0 MB, file and parent
directory both gone from disk). Zero disk impact. Not yet cleaned up (`VBoxManage closemedium`
on the dangling UUID); logged at `vm-fleet/VM-FLEET-LOG.md` (private mirror).

Known caveats from the 2026-08-02 cleanup pass are tracked in `PUNCHLIST.md`, not duplicated
here.
