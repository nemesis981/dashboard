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

Format the output as:
```
--- NEMESIS MORNING STATUS ---
Lines of code: XX,XXX
Last commits: [3 lines]
Services: dashboard=active watchdog=active ...
Tree: clean / [N files modified]
Resume: [one sentence from HANDOFF]
Roadmap: N shipped / N partial / N parked (M total) — [drift note or "no change"]
------------------------------
```
7. **Write the briefing to disk (EVERY session, automatically — do not ask).** Save the full
   briefing to `docs/briefing/YYYY-MM-DD.md` — the status block above **plus** the supporting
   detail that doesn't fit in it: the roadmap-vs-state audit findings (baseline file used,
   file-set drift, shipping drift, and the closeout action if drift was found), the model
   self-check result, any process findings, and the open items carried forward from HANDOFF.
   Then print the status block in chat. Both — the file is not a substitute for reporting.
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
- **Does NOT commit or push — ever.** When a change is ready, STOP and report it as
  ready-to-commit; hand off to Window 2, which performs the actual git write.
- Does NOT author ADRs, roadmap entries, handoff docs, or build specs — that's Window 2.
- Does NOT run the morning briefing or roadmap-vs-state audit — that's Window 2.
- Code work takes priority: never let a read-only audit or doc request preempt
  trip-critical or scheduled code work in this window.

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
- **Never commits or pushes — ever.** Same restriction as Window 1: git-write privilege
  stays exclusively with Window 2, no exceptions for Window 3 either.
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

### Both windows (shared discipline)
- Commit-first, then push (performed in Window 2). HOLD the push for operator review on
  anything non-trivial (ADRs, security-default code, schema changes).
- **Push coordination.** Before ANY push, list ALL locally-unpushed commits
  (`git log --oneline @{u}..HEAD`) — a push publishes everything pending, not just what
  was just committed. Show the full list to the operator and get explicit confirmation
  before pushing.
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

### 12. Local mirror for handoff/briefing/audits docs
`docs/handoff/` (`HANDOFF.md`, `supplements/`, `worklog/`), `docs/briefing/`, and
`docs/audits/` live inside `/opt/nemesis` — not convenient to reach from a
`~/work/nemesis-internal` session. **Every time any of the three is written or refreshed**
(HANDOFF.md overwrite, a new supplement/worklog entry, a new dated briefing — see Rule 9 and
Morning Status §7 — or a new/updated audit doc), also copy the current file(s) to the mirror
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
- **Actor mechanism is live but currently unwired** — flagged here because it's easy to miss
  and ADR 0006 doesn't call it out. The Data Manager stamps `current_actor()` on every logged
  write automatically (atomic-helper AND raw passthrough writes alike — proven in
  `test_data_manager.py`), so once a caller sets an actor it needs no per-write plumbing. But
  **no caller sets it yet** — nothing in the codebase calls `set_actor()` — so every write's
  logged actor is `NULL` in practice today. Wiring real identity context into `set_actor()` at
  the request/session boundary is separate, unstarted work.

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
convention above). Bridged NICs use `enp131s0`; isolated NICs use hostonly `vboxnet0`
(`192.168.56.0/24`).

- **Fresh-clone discipline (standing rule).** Always start testing from a fresh clone of the
  appropriate Master below, never the Master itself. Always delete that clone once its testing
  is done, unless more testing on that exact environment/state is likely needed soon — in
  which case say so explicitly (worklog entry naming the clone and why it's being kept) rather
  than leaving it to linger unlabeled. **Why:** unlabeled clones/snapshots accumulating
  indefinitely is exactly what made the full 2026-08-02 VM fleet cleanup necessary in the
  first place — this rule exists so that cleanup doesn't have to happen again.

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

- **Permanent hardware/software gauge VM — PLACEHOLDER, not yet built.** A separate VM from
  `Nemesis Appliance Master ISOLATED` above, dedicated to representing an accurate, CURRENT
  hardware/software-requirements baseline rather than a frozen snapshot from whenever it was
  created. Window 3 is still setting this up. **Fill in its name/OS/network/role in the table
  above the moment it exists** — don't leave it as a standalone mention once it does; the
  whole point of the capability list is one lookup table, not two.
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
- **Fleet cleanup at every closeout.** Don't wait for another full audit — at each closeout,
  identify any stray clone/snapshot and either delete it or make (and record) a deliberate
  keep decision, the same per-test choice the fresh-clone-discipline bullet already asks for,
  now applied as a standing closeout check so strays get caught immediately instead of
  accumulating.
- **Keep-current generalizes past the gauge VM.** Any VM in the fleet running a server or
  agent install — not just the permanent gauge VM above — gets updated to match whenever
  production Nemesis updates. Same reasoning as the gauge VM's maintenance rule: a VM meant to
  represent current product behavior is worse than useless if it's silently stale.

**Also present, outside the 7-Master set — do not fold into it without a deliberate decision:**
- `Nemesis Appliance Spare ISOLATED` — a second appliance-installed isolated Ubuntu box
  (former `ISOLATED-TESTBASE`), unslotted spare, fate undecided.
- `Nemesis-firewall Utility CLEANBASE 07.31` — deliberately purged-bare Ubuntu base kept
  specifically for install-timing measurement. Not a Master; don't clone it expecting a
  generic Linux box.
- `Nemesis-firewall W3-TEST 07.29` + `Nemesis-SW WIN11 W3-TEST 07.29` — the live ADR 0019
  enforcement-engine test rig (see `firewall-enforcement-engine/VM-TEST-PLAN.md`, private
  mirror). **Off-limits** until that work is confirmed concluded/archived.

Known caveats from the 2026-08-02 cleanup pass are tracked in `PUNCHLIST.md`, not duplicated
here.
