# CLAUDE.md — Nemesis operating rules (auto-read each session)

This file is read automatically at the start of every Claude Code session. It holds
the project's core operating discipline (Tier 1) plus Nemesis-specific rules. Read it
before doing anything. Also read, in this order, before starting work:
`ARCHITECTURE.md` → `docs/architecture/` (ADRs) → `docs/handoff/HANDOFF.md`.

Working-style notes (local-only, gitignored; auto-loaded from disk via @-import):
@docs/COLLABORATION.md

---

### Morning Status (run on session start)
At the start of every new session, before anything else, run these and report the results
in a clean block:

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
     baseline's 44. Report any ADDED or REMOVED files.
   - **Shipping drift:** the baseline's 10 non-parked items (4 SHIPPED + 7 PARTIAL) plus any
     newly-added files get a quick code/`git log` re-check (confirm/upgrade status). For the
     33 baseline-PARKED items, scan recent `git log --oneline` subjects for roadmap keywords
     — a parked item with a fresh feat commit has likely shipped; verify it.
   - This is a READ-ONLY audit (Rule 1) — report only, change nothing. When drift is found,
     refresh the baseline audit doc at closeout (new dated file).
   - Baseline (2026-07-01): **4 SHIPPED / 7 PARTIAL / 33 PARKED** (44 total) —
     `docs/audits/roadmap-state-audit-2026-07-01.md`.

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

This project is worked across two role-assigned Claude Code windows. Each window is
told its role in the operator's FIRST message ("you are the build window" / "you are
the docs window"). A window has no way to know its own identity otherwise — the role
comes from that load-time assignment, not from open order or timestamps. If a window
is reopened after a crash, the operator re-states its role.

### BUILD window
- Owns all CODE changes (dashboard.py, database.py, agent files, installers, etc.).
- Runs Rule-3 verification (real output: py_compile, isolated tests, live checks) on
  every code change before commit.
- Owns the MORNING BRIEFING and the full MORNING ROADMAP-VS-STATE AUDIT (read-only).
- Does NOT author ADRs, roadmap entries, handoff docs, or build specs — that is the
  docs window's job.
- Code work takes priority: never let a read-only audit or doc request preempt
  trip-critical or scheduled code work in this window.

### DOCS window
- Owns ALL document work: ADRs, roadmap entries, handoff/supplements, build specs,
  doc audits, cross-references.
- Docs-only + read-only. NEVER touches code files. If a task would require a code
  change, stop and flag it for the build window.

### Both windows (shared discipline)
- pull --ff-only before every commit (concurrent windows are standing practice).
- Rule 8 leak-scan every diff (placeholders only — no PII/IPs/hosts/accounts).
- Commit-first, then push. HOLD the push for operator review on anything non-trivial
  (ADRs, security-default code, schema changes).
- Read-only audits and doc-writes never share a window with trip-critical code work.
- One logical change per commit; don't batch unrelated work.

### Role self-check (first response)
If you have NOT been told your role (build or docs) in this session, do not begin
any task. Your first response must be to ask: "Which window am I this session —
BUILD or DOCS?" and then wait for the operator's answer before proceeding. Once
assigned, operate under that role's contract for the rest of the session. If the
operator's first message already states the role ("you are the build window"),
skip the question and confirm the role instead.

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
- Code: builds, edits, commits, runs on the machine.
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
- **Session start:** read `ARCHITECTURE.md`, `docs/architecture/` (ADRs), and
  `docs/handoff/HANDOFF.md` first to load conventions + current state.
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
- Start every session by reading `ARCHITECTURE.md`, then `docs/architecture/` (ADRs),
  then `docs/handoff/HANDOFF.md`.
- **chat-Claude = design/review, READ-ONLY externally.** It does not build or commit.
- **Code = build/commit.** Commit *before* deploy; then verify live with `ps` /
  `journalctl` / the browser. Never report success without that real output.

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

### Data Manager (ADR 0006 — enforced when built)
- Modules MUST use the Data Manager for ALL DB operations **after it is built**. Direct
  `sqlite3.connect()` or bare `get_db()` calls from module code are **FORBIDDEN**.
- The loader enforces this — a module that bypasses the Data Manager **does not load. No
  exceptions.**
- The four atomic SQL fixes (`tickets_seq`, `ai_engine` rate, `community_queue`,
  `anomaly_incidents`) are the **Data Manager v0 seed**. Label new atomic operations as Data
  Manager functions with a pointer to ADR 0006.
- **Actor is applied automatically** by the Data Manager on every write. Modules do NOT pass
  `actor` manually after the Data Manager is built — they pass identity context and the Data
  Manager handles it.

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
- **Model string:** `claude-sonnet-4-6`.
- **Key paths** (public-repo placeholders — substitute the real install user locally):
  - dashboard: `/home/<user>/dashboard/dashboard.py`
  - `/home/<user>/dashboard/alert_manager/` — core services (alert-watcher, hw-monitor,
    device-scanner, watchdog, dashboard) + shared `alerts.db`
  - `/home/<user>/dashboard/modules/` — pluggable modules
  - `/etc/nemesis.env` — environment/secrets, mode `640 root:nemesis`
