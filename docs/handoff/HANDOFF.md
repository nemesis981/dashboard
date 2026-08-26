# HANDOFF — current state

> Last updated **2026-08-25, pre-reboot closeout (Window 2)**. Overwritten each closeout
> (latest state wins). Durable history: `docs/handoff/supplements/` (append-only). Real
> IPs/hosts/accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` —
> placeholders here per Rule 8.
>
> **Written ahead of an operator-initiated system reboot, at explicit request.** Full detail:
> `docs/handoff/supplements/2026-08-25-001.md` (curated) and
> `docs/handoff/worklog/2026-08-25-001.md` (raw chronology, live-appended). Services are
> untouched by this session's work — the reboot is a host action, not a deploy.

---

## ⚠ ACT ON THIS BEFORE THE REBOOT PROCEEDS

**`Nemesis Appliance Gateway` holds the ONLY copy of the `nemgw` gateway-test-zone config,
and it is not yet backed up off-VM.** Window 1 flagged this to Window 3 as a priority task
at 13:51 today (`~/work/nemesis-internal/handoff/2026-08-25-window1-to-window3-gateway-config-backup.md`)
— explicit instruction: **do NOT shut down or otherwise touch that VM until the config is
exported somewhere durable outside it.** No completion note from Window 3 has been found as
of this write. A host reboot is exactly the kind of event that could shut down or disrupt a
running VM depending on VirtualBox's own shutdown handling — **this is not this session's
call to make, but it needs the operator's eyes before the reboot proceeds**, not discovered
after. The existing `.bak-2026-08-20-w3` file does NOT cover this — it protects against a
bad edit, not against losing the VM, and is stored on the same VM regardless.

---

## 1. Push status — both repos, verified clean, nothing unpushed

**`/opt/nemesis`:** `git rev-parse HEAD` == `git rev-parse origin/main` ==
`e0cddb755ddbb5ebc90f88179ea7ff841af1f0bd`. Re-fetched and re-verified at write time, not
carried forward from an earlier check this session.

**`~/work/nemesis-internal`:** HEAD == `local/main` == `usb/main` ==
`66e7c52feecde29b33556761dfacdca4cd41baf9`. USB drive confirmed mounted at push time.

No commit in either repo is sitting local-only. A reboot right now loses no committed work
in either repo.

## 2. `/opt/nemesis` working tree — not clean, and that is expected (shared tree, not this
   session's files)

`git status --short`:
```
 M PUNCHLIST.md
 M modules/malware_detection/module.py
 M nemesis_agent/agent.py
 M nemesis_agent/agent_errors.py
?? alert_manager/hw_map.json
?? modules/email_security/
```

None of this is mine to commit; ownership, verified against source (not assumed):

- **`PUNCHLIST.md`** (+34, one hunk, lines 3-40) — Window 3's ADR-0028/D9-measurement
  verification batch (four `[LOW]` entries dated 2026-08-24). Unchanged all session; Window
  1's own PUNCHLIST hunk from earlier today already landed separately (`6f3ebe6`).
- **`modules/malware_detection/module.py`** (+28/-7) — Window 1's Layer D docstring-honesty
  fix, correcting the module header's "no model, no classifier, no entry point" claim (two
  of those three have been false since `ac53b0c`/`719d93f`, 2026-08-21). Per Window 1's own
  handoff (`2026-08-25-window1-handoff.md`, "LAYER D — READ-ONLY ANALYSIS" section): **"teed
  up, not done"** — prepared but not yet formally handed off for commit. Do not commit
  without an explicit ready-to-commit signal from Window 1.
- **`nemesis_agent/agent.py`** (+75/-2, 5 hunks) and **`nemesis_agent/agent_errors.py`**
  (+10, 2 hunks) — Window 1's held GUI-findings-buffer work
  (`_recent_findings`/`_findings_lock`/`_GUI_REPORTABLE_CODES`/`_remember_findings`/
  `_findings_response`). Unchanged since 2026-08-24's closeout note. Known consequence still
  live: `test_task_classification` reports a gate mismatch in the shared tree until this
  lands with a `BASE_EXEMPT_ACTIONS` fix in the same commit.
- **`alert_manager/hw_map.json`** (untracked, mtime 2026-08-23) — runtime artifact from
  `hw_discover --auto`. Still undecided: track or gitignore. Unchanged all session.
- **`modules/email_security/`** (untracked directory: `fast_check.py`, `imap_idle.py`,
  `mime_parse.py`, `module.py`, tests, `manifest.json`) — Window 3's email-security Stage
  2.x build, in progress. **Heads-up carried forward from earlier today, not yet
  materialized:** Window 3's Stage 2.6 is expected to touch `alert_manager/database.py`,
  the same file Window 1's CSRF/schema batch modified and this session already committed
  (`3ef5a1d`). Whichever window is ready first should land, then the other must re-check
  the file's live state before editing — not assume a clear shot.

**Model self-check note (Window 2, this session):** running Sonnet 5, matches expected —
no mismatch flagged at any point today.

## 3. This session's landed work — all six items requested, confirmed landed

1. **ADR 0028 D3 revision** (`34a6bd7`, pushed) — bare-provider path narrowed to Gmail-only
   for v1; Outlook.com deferred (OAuth/XOAUTH2 cost), not rejected.
2. **ADR 0028 D10-D12 + ARCHITECTURE.md P1** (`f7d39bb`, pushed) — enrollment architecture
   (no agent code required; attaches to a dashboard user, not a device; admin-initiated/
   owner-authorized enrollment recommended, admin-on-behalf-of-others explicitly rejected)
   plus the project-wide setup-friction principle, placed in `ARCHITECTURE.md` per Window
   3's recommendation (already in the mandated read-order). Six sub-decisions correctly
   left OPEN in §8, not silently picked — see that section for the list (who connects an
   account, shared-mailbox ownership, capability-gating, macOS discovery scope).
3. **ADR 0029 — child/teen safety monitoring** (`8bbdd31`, pushed) —
   `docs/architecture/0029-child-safety-monitoring.md`, **public sections only** (§0
   measurement discipline + positioning, §2 legal grounding + the metadata-only-capture core
   decision), per the operator's explicit Rule 10 resolution. The full design — three
   detection pipelines, severity tiers, retention, consent/attestation, crisis-response path,
   full 29-item decision register — stays in the private mirror, held until built and
   measured. Roadmap tracking entry landed alongside it
   (`docs/roadmap/child-safety-monitoring.md`): PARKED until V2.0 completes, dual
   module/standalone shape, standalone must be self-hosted (hard constraint, not a
   preference — a hosted variant would collapse the published no-vendor-escrow legal
   architecture).
4. **Gap-scan entry #14 struck** (`66e7c52`, private repo, pushed to local+usb) —
   `ARCHITECTURE.md` already documented the L0-L4 ladder and explicitly marked the old
   Teaching Mode/Automated Mode vocabulary as superseded when the entry was written
   (`c7ac0cc`, 2026-08-21, two days before the 2026-08-23 scan). Root cause: grepped for the
   term, found it inside the sentence saying it's gone, concluded the doc still describes
   it — string matched, meaning was the opposite. Independently confirmed by both Window 1
   and Window 3 before being struck. **Second confirmed-stale entry in that document — a
   full re-audit of the remaining entries is still owed, not done as part of this edit.**
5. **Fleet-hygiene CLAUDE.md fold** (`e0cddb7`, pushed) — folded into the existing "Fleet
   cleanup at every closeout" bullet rather than appended as a second one, per Window 3's
   explicit recommendation. Adds: specific staleness signals (powered off + abandoned, named
   for a finished task), the clean-up-directly-vs-flag-plainly split, and the
   `VM-FLEET-LOG.md` recording requirement. Motivating incident: an "overnight" VM batch
   from 08-20 still running five days later (8 GB RAM, 114 GB disk), with a third,
   powered-off member invisible to the same sweep entirely.
6. **CSRF batch** (`e116188` + `3ef5a1d` + `6f3ebe6`, pushed, landed earlier this session) —
   six GET-that-acted routes converted to POST+JSON-only; `enrollment_tokens.auto_approve`
   schema default corrected 1→0 for **new installs only** (SQLite cannot ALTER a column
   default; the live `/var/lib/nemesis/alerts.db` keeps `DEFAULT 1` — production is
   unchanged by this commit and the message says so explicitly, not implied as remediated).
   Independently verified by Window 3 before commit; both suites re-run myself, not taken on
   trust: `test_roles` 158/0, `test_enrollment_token_defaults` 10/0.

Two other CLAUDE.md standing-rule additions also landed and pushed today, ahead of the items
above: the shared-working-tree attribution rule (`2fcf77c` + correction `8ad5cd1`, dropping
`%an` as an attribution signal after it was found to not actually distinguish windows —
every window commits under the identical git identity) and the step-4 firewall self-healing
feature itself (`f78b8f5`..`d8f4e80`, 9 commits, verified against a clean GitHub clone:
281/0 across all six suites).

## 4. Anything else queued, not yet actioned

- **The gateway-config backup risk** — see the top of this file. Not this session's to fix;
  flagged for the operator and for Window 3 to confirm before the reboot.
- **`modules/malware_detection/module.py`** — Window 1's Layer D docstring fix, teed up but
  not formally handed off (see §2). Will need an explicit ready-to-commit signal.
- **`database.py` collision risk** — Window 3's Stage 2.6 vs. this session's already-landed
  schema commit. Sequencing note carried forward (see §2); no actual conflict has occurred
  yet since Stage 2.6 hasn't touched the file as of this write.
- **Six ADR 0028 §8 open decisions** (who connects an account, shared-mailbox ownership,
  `enroll_email_account` as a capability, macOS discovery scope, D5's hold-time budget,
  D7's legal/compliance question) — flagged in the ADR itself, not blocking, not this
  session's to resolve.
- **ADR 0029's own open items** — 16 of 29 decision-register entries remain open in the
  private build spec; not blocking since the whole project is parked until V2.0. Legal
  review for ADR 0029 should be sequenced ahead of the existing PUNCHLIST legal items
  (`PUNCHLIST.md` lines 478, 488, 3581) given it is a materially larger exposure.
- **Gap-scan document itself** — now has two independently-confirmed-stale entries (item 4,
  item 14). A full re-audit of the remaining entries is recommended before anything else is
  scoped off that document; not started.
- **Window 1's Layer D model-funding project** — active, unrelated to anything in this
  repo's working tree. Corpus acquisition VM (`Nemesis Kali KEEP layerd-corpus 08-25`) is
  mid-build as of this write (handoff file still growing, last touched minutes before this
  closeout). Calibration gate locked (N_min 50,000 / N_target 150,000 held-out benign PEs,
  detection floor ≥70%, zero-FP requirement at the malicious threshold). Entirely
  VM/private-repo state — nothing here for `/opt/nemesis` to track, noted only because a
  host reboot could interrupt VM work in progress the same way it could affect the gateway
  VM above. Worth Window 1 confirming their own VM states are safe before a reboot, same
  concern as the gateway backup, lower stakes since this VM isn't the sole copy of anything.
- **`test_analyze_alert_body.py`** (34/35, stale assertion) — captured in PUNCHLIST
  (`6f3ebe6`, landed), not fixed. Own commit when picked up.
- **`_load_secret_key()` PermissionError gap** — captured in PUNCHLIST (`0482d1b`, landed
  earlier today), not fixed.

## 5. Verified live this session, not just claimed (Rule 3 discipline)

Every commit above carried independent verification before landing: CSRF batch re-tested
myself (158/0, 10/0) rather than trusting Window 3's report alone; commit-hash citations in
the Track C roadmap fix checked against `git log` before writing; gap-scan #14's timeline
checked against the actual `ARCHITECTURE.md` content and `c7ac0cc`'s commit date, not taken
from either window's summary; step-4 firewall work re-verified in isolated `git worktree`
checkouts at every intermediate commit, then a genuine fresh `git clone` from GitHub at
final HEAD (281/0). One real correction was caught and fixed before landing: the
shared-tree rule's first draft suggested `%an` as an attribution signal; verified false
(identical git identity across all windows) and rewritten before commit.

## 6. Elevated grants

Not re-checked this specific session (no fresh Morning Status run since the reboot request
came mid-session, after this morning's baseline). Last live check: 2026-08-25 morning
Morning Status, matched HANDOFF's 2026-08-22 baseline exactly. Re-run at next session start.

**New, found 2026-08-26 during Stage 4.2 work, not from a routine check — first entry sourced
from a fleet VM rather than the build host.** `<gateway-vm>` (VM fleet, bridged to the
production LAN): local test account holds full sudo plus a NOPASSWD set (`systemctl`,
`journalctl`, `tail`, `ufw`, `nmap`), confirmed live via `sudo -n -l`. **Still needed** — the
NOPASSWD set is the only working management route today; VirtualBox guest-control's execution
service was found non-functional on this VM, so SSH plus these grants is what makes it
administrable at all. **`nmap` is the outlier worth a second look**: this VM sits bridged on
the production LAN, so passwordless root `nmap` means the shared lab test-account password
grants root-privileged raw-socket scanning of the real LAN from a host already on it —
defensible as a lab credential, but the one to drop first if the set is ever trimmed. Not a
finding against the VM's purpose; the point is that it is now tracked rather than silently
unknown. **Open scope question for the operator**: Morning Status item 7's standing check is
host-oriented; whether it should extend to fleet VMs generally (a bridged VM with a shared lab
credential is a real position on the production LAN) is a docs-scope decision this entry
surfaces but does not resolve.

## 7. Cross-references

- `docs/handoff/supplements/2026-08-25-001.md` — curated narrative, this session.
- `docs/handoff/worklog/2026-08-25-001.md` — raw chronology (live-appended, not
  reconstructed).
- `docs/briefing/2026-08-25.md` — this morning's briefing (roadmap baseline, elevated
  grants, working-tree audit at session start).
- `~/work/nemesis-internal/handoff/2026-08-25-window1-handoff.md` — Window 1's full
  cold-start doc, C0-C6 step-4 build, live VM verification, and the ongoing Layer D
  model-funding project.
- `~/work/nemesis-internal/handoff/2026-08-25-window3-handoff.md`,
  `2026-08-25-window3-to-window2-*.md` (four files) — Window 3's ADR drafts, CSRF
  verification, and the fleet-hygiene draft, all landed this session.
- `~/work/nemesis-internal/handoff/2026-08-25-window1-to-window3-gateway-config-backup.md`
  — the unresolved pre-reboot risk, §top of this file.
- Prior session: `docs/handoff/supplements/2026-08-24-001.md`.

## Topology

**Unchanged from prior handoffs.** No topology-affecting code shipped this session (all
landed work is docs, a CSRF/schema fix, and the already-verified step-4 firewall feature,
which ships inert — `NEMESIS_FW_GUARD` defaults off, not armed anywhere outside the
disposable VM pair). See `docs/handoff/supplements/2026-08-19-001.md` for the last full
topology summary, and the 2026-08-24 supplement for the Stage-0 tailnet-TLS addition.
