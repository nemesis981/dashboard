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
   find ~/dashboard -type f \( -name "*.py" -o -name "*.js" -o -name "*.html" \
     -o -name "*.css" -o -name "*.sh" \) | grep -v __pycache__ | grep -v .git \
     | xargs wc -l 2>/dev/null | tail -1
   ```
2. **Last 3 commits:** `git -C ~/dashboard log --oneline -3`
3. **Service status (is-active):**
   ```
   systemctl is-active dashboard watchdog alert-watcher malware-canary \
     diagnostics-watcher vpn-dns-guard 2>/dev/null
   ```
4. **Working tree status:** `git -C ~/dashboard status --short`
5. **Read `docs/handoff/HANDOFF.md`** and state today's resume point.
6. **Roadmap-vs-state audit (LIVE each session) — baseline diff, not header-trust:**
   report the tally + flag drift vs the maintained baseline
   (`docs/audits/roadmap-state-audit-YYYY-MM-DD.md`, latest date wins). Do NOT classify
   off each file's `Status:` header — headers go stale on shipping (the 3 currently-shipped
   items still say "parked"), so trusting them hides the exact drift this check exists to
   catch. Instead, each morning:
   - **File-set drift:** `ls ~/dashboard/docs/roadmap/*.md` → compare names/count to the
     baseline's file count. Report any ADDED or REMOVED files.
   - **Shipping drift:** the baseline's non-parked items (SHIPPED + PARTIAL) plus any
     newly-added files get a quick code/`git log` re-check (confirm/upgrade status). For
     baseline-PARKED items, scan recent `git log --oneline` subjects for roadmap keywords
     — a parked item with a fresh feat commit has likely shipped; verify it.
   - This is a READ-ONLY audit (Rule 1) — report only, change nothing. When drift is found,
     refresh the baseline audit doc at closeout (new dated file).
   - Baseline (2026-07-25): **4 SHIPPED / 8 PARTIAL / 47 PARKED** (59 total) —
     `docs/audits/roadmap-state-audit-2026-07-25.md`. (Superseded the 2026-07-02 baseline —
     the +8 file-count drift flagged against it traced entirely to same-session 07-02 work
     the original baseline doc under-counted; no shipping change.)

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
Then ask: **"What would you like to work on today?"** This replaces the manual catch-up
prompt — session is oriented in under 30 seconds.

---

## Window Roles (multi-window workflow)

Fixed assignment — **window identity, model, and git-write privilege** are pinned as
follows. The operator identifies a window by number in the FIRST message ("you are
Window 1" / "you are Window 2"). A window has no way to know its own identity
otherwise — the role comes from that load-time assignment, not from open order or
timestamps. If a window is reopened after a crash, the operator re-states its number.

### Window 1 — BUILD window (role: Opus — currently Opus 5)
- **Expected model: Opus** (currently `claude-opus-5` — bump this string when Anthropic
  ships a newer Opus; the role pin itself doesn't change). Reasoning-heavy build/design
  work. Set once per session: `/model claude-opus-5`.
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
  commits. Set once per session: `/model claude-sonnet-5`.
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

### Private modules — separate version control (Window 1 is git-writer)
Carved-out private modules live OUTSIDE the public repo and are version-controlled
separately. The first is `~/work/nemesis-internal/l3-tier2-tls-interception/` (the Tier 2
TLS-interception harness + implementation detail, moved out of the public repo for
source-visibility). This rule covers it and any future similarly-carved-out private modules.
- **Window 1 is the git-writer for these private repos** — it authors the code that lives
  there. It follows the SAME discipline as Window 2's public-repo practice: verify staged
  content before committing, Rule-8 scan the staged diff, and push to ALL configured remotes
  (local + USB + private GitHub).
- **Window 2 remains sole git-writer for the PUBLIC repo only.** This does NOT change or
  extend that rule. The two repos have two git-writers by design — ownership follows
  authorship: Window 1 authors the private-module code, Window 2 authors the public docs.

### Role self-check (first response)
If you have NOT been told your window number this session, do not begin any task. Your
first response must be to ask: **"Which window am I this session — Window 1 (build,
Opus) or Window 2 (docs/audit, Sonnet, sole git-writer)?"** and wait for the operator's
answer before proceeding. If the operator's first message already states it, skip the
question and confirm instead (window number + role + model).

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
- **Key paths** (public-repo placeholders — substitute the real install user locally):
  - dashboard: `/home/<user>/dashboard/dashboard.py`
  - `/home/<user>/dashboard/alert_manager/` — core services (alert-watcher, hw-monitor,
    device-scanner, watchdog, dashboard) + shared `alerts.db`
  - `/home/<user>/dashboard/modules/` — pluggable modules
  - `/etc/nemesis.env` — environment/secrets, mode `640 root:nemesis`
  - `docs/CUSTOM_TAILSCALE_OAUTH.md` — Tailscale OAuth auth-key minting setup (the four `TAILSCALE_OAUTH_*`/`TAILSCALE_TAG` env vars + installer self-onboard hybrid fallback)
