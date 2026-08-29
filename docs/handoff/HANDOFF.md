# HANDOFF — current state

> Last updated **2026-08-28, nightly closeout (Window 2)**. Overwritten each closeout
> (latest state wins). Durable history: `docs/handoff/supplements/` (append-only). Real
> IPs/hosts/accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` —
> placeholders here per Rule 8.
>
> Full detail: `docs/handoff/supplements/2026-08-28-001.md` (curated) and
> `docs/handoff/worklog/2026-08-28-001.md` through `-004.md` (raw chronology, live-appended
> through the day across a reboot recovery).

---

## 1. Push status — both repos, fully reconciled

**`/opt/nemesis`:** `HEAD == origin/main`, verified via `git fetch` + `git rev-parse`
immediately before this closeout's final commit.

**`~/work/nemesis-internal`:** `local` and `usb` both confirmed at the same HEAD via
`git ls-remote` (authoritative, not just push output).

## 2. `/opt/nemesis` working tree — one item, intentionally uncommitted

```
 M CLAUDE.md
```

- **`CLAUDE.md`'s `--passwordfile` diff** (added 2026-08-27, standing rule after a second
  same-shape credential leak — a hung `VBoxManage` command's `subprocess.TimeoutExpired`
  embedding the full argv, including the password, in a session transcript). **Still
  unattributed — now SIX sessions running.** Coherent, complete, reads as finished. No
  handoff document describes it and no window has claimed it. Do not sweep it into any
  future commit without its author claiming it first.

Everything else that was uncommitted at any point today (three worklog files, the nmap-grant
batch, the ufw fix, `SETUP_LINUX.md`, the sudoers decision) landed and pushed during the day —
see §3.

## 3. Today's landed work — 9 commits on `/opt/nemesis`, all pushed

**The tailnet-leak history rewrite** (`origin/main` rewritten `9959197`→`1efe285`, all 10 tags
verified unaffected, re-verified from a fresh GitHub clone). One residual: the pre-rewrite SHA
is still fetchable from GitHub's object storage (branch history is clean; the object store
isn't yet) — needs an operator-filed GitHub Support request, draftable on request. Two stray
branches force-pushed by scope-overreach during the rewrite (`backup-closeout-reorder`,
`stage5-2b-meminject`) were reviewed clean and deleted from `origin` per an explicit operator
scope decision.

**CLAUDE.md/PUNCHLIST batch** (`eaff9ff`→`b4c1a24`→`1efe285` pre-rewrite hashes): Fleet Archive
Policy target correction, WAL-fidelity fix for state snapshots, stale VM line removed.

**The nmap dead-grant investigation**, split into two commits after a same-tree race required
mid-flight surgery (`git reset --soft` + hunk-level re-staging) when a single commit turned out
to conflate hygiene and a functional fix:
- **`eaff9ff`** — dead `NOPASSWD /usr/bin/nmap` sudoers grant trimmed from `install.sh`'s
  template; `docs/SETUP_LINUX.md`'s grant-list line corrected to match; `.gitignore` gained
  `hw_map.json` and its two sibling paths (per-install hardware state, not source).
- **`04eb296`** — the actual missing dependency: `install.sh` never installed the `nmap`
  *package* itself. Fixed, verified live on the Gateway fleet VM's 26-day failure log.

**Broader dead-grant sweep** (prompted by the above) found `systemctl`/`journalctl`/`tail`
grants have no confirmed programmatic caller either, but a genuinely different answer: they
serve a real human-admin workflow, unlike nmap. **`d09899e`** — reviewed, kept, no code
change. Full reasoning in the private decision record
(`decisions/2026-08-28-sudoers-admin-grants-RATIFIED.md`); public entry deliberately terse
per Rule 10.

**The gap-inventory Tier-1-PRIORITY fix**, landed as two commits after independent
re-verification of every claim (not taken on trust — reran both new test files directly, the
full diagnostics suite, and the AI-engine regression suite, all exact matches to what was
reported):
- **`2148f60`** — `modules/ai_engine/test_externally_executed.py`, closing a real test-coverage
  gap for the `EXTERNALLY_EXECUTED` branches (24/0, mutation-proven).
- **`db8fe81`** — `diagnostics/ufw_rules.py` no longer reports a permissions denial as a
  firewall fault. Root cause was worse than first diagnosed: `NoNewPrivileges=yes` makes a
  sudoers grant moot regardless of which account runs it. `diagnostics/test_ufw_rules.py`,
  33/0, mutation-proven. Full diagnostics suite: 299/299 across 7 files.

**Worklog + doc cleanup:**
- **`f7bd082`** — committed the day's live worklog (three sessions spanning a reboot), with a
  Rule-8 catch: one entry originally named the actual pre-rewrite leaked tailnet string while
  describing the grep that confirmed its absence — caught and rephrased before commit, since
  publishing it would have reintroduced the exact leak the history rewrite existed to remove.
- **`acd7570`** — `docs/SETUP_LINUX.md`'s `dashboard.service` user line corrected
  (`$SUDO_USER`→`nemesis-dash`, stale since the 2026-07-31 de-privileging effort). Assigned to
  Window 2 in today's operator-approved Tier 1 ownership split.

## 4. The reference document for outstanding work

`~/work/nemesis-internal/audits/base-project-gap-inventory-2026-08-28.md` — a comprehensive,
two-tier accounting of every open item in the codebase, compiled at operator request as "the
baseline complete gets measured against going forward." Read that, not PUNCHLIST alone, for
current state. **Operator-approved ownership split for its Tier 1** (malware-detection and
memory-injection-blocker items led): Window 3 has two small items, Window 1 has the real
build-work items (canary HIGHs, agent integrity attestation, agent enumeration gaps, a new
diagnostics-framework session-context change), Window 2's one item is done (§3 above).

## 5. Verified live this session, not just claimed (Rule 3 discipline)

- Reran `diagnostics/test_ufw_rules.py` (33/0) and `modules/ai_engine/test_externally_executed.py`
  (24/0) directly, plus all 7 diagnostics test files (299/299) and 5 AI-engine regression
  suites (89/0, 14/0, 74/0, all-pass, 24/0) — every count matched Window 3's handoff exactly,
  none taken on trust.
- Re-verified the `backup-closeout-reorder`/`stage5-2b-meminject` content-clean claim
  independently in a post-reboot session before the operator's delete decision, not just
  trusted the earlier claim.
- Re-checked the `hw_map.json` gitignore fix actually took (`git status --ignored`) before
  citing it as resolved here, rather than assuming the commit did what its message said.
- Caught and fixed a Rule-8 leak in the day's own worklog before it reached the public repo
  (see §3).
- Gate-checked every push on both repos: fetched, diffed the unpushed set against exactly
  what had been named/confirmed, pushed the reviewed SHA.

## 6. Anything else queued, not yet actioned

- **`CLAUDE.md`'s uncommitted `--passwordfile` diff** (§2) — sixth session flagging it,
  still unclaimed.
- **GitHub GC request** for the pre-rewrite object — needs the operator to file via GitHub
  Support's web form.
- Everything in the gap inventory's Tier 1/Tier 2 not covered by today's ownership split or
  today's fixes — see §4. In particular: ADR 0028's 6 open decisions (unchanged), ADR 0029's
  16 open decision-register entries (unchanged, zero drift), the fresh roadmap tally (9
  SHIPPED / 10 PARTIAL / 65 PARKED), and today's cross-window findings (Appliance Master 553
  commits behind, the linked-clone archive-policy gap blocking one Layer D corpus VM).
- Two Layer D decision records (D2 RATIFIED, D3 REFRAMED) and two sourcing plans were
  committed on Window 1's behalf to the private repo tonight, content reviewed first — D3
  flags one residual limitation still needing its own future Rule 10 disclosure call, not yet
  made.
- **Not this closeout's to touch:** ~94 lines of long-standing uncommitted backlog in
  `~/work/nemesis-internal` (old briefings/audits/scoping docs from other windows, going back
  to early August) — noted, not acted on, not urgent.

## 7. Closeout health check

- Working tree: **not clean** — see §2, intentional, not this closeout's to commit.
- Closeout commit is HEAD: confirmed after this handoff's own commit.
- local == origin: confirmed via `git fetch` + `git rev-parse HEAD origin/main` after push.
- HEAD touches only docs/handoff files: confirmed (`git show --stat HEAD`) for this specific
  commit — today's earlier commits (§3) each individually scope-checked before landing.
- Rule 8 spot-check: clean on this commit; one real catch earlier in the day (§3, worklog).
- Open items durably captured: this file, §6, plus the gap inventory (§4) and PUNCHLIST.md.

## 8. Cross-references

- `docs/handoff/worklog/2026-08-28-001.md` through `-004.md` — raw chronology, live-appended
  across a reboot.
- `docs/handoff/supplements/2026-08-28-001.md` — curated narrative, today.
- `~/work/nemesis-internal/handoff/2026-08-28-window2-handoff.md` — Window 2's own cold-start
  note, more procedural detail than belongs in the public HANDOFF.
- `~/work/nemesis-internal/handoff/2026-08-28-window3-to-window2-tier1-ufw-and-ownership.md`
  — the ufw fix handoff and ownership-split proposal, operator-approved.
- `~/work/nemesis-internal/audits/base-project-gap-inventory-2026-08-28.md` — the reference
  document, §4 above.
- Prior session: `docs/handoff/supplements/2026-08-27-001.md`.

## Topology

**No architectural change today** — today's work was investigation, cleanup, and one small
diagnostics fix (`ufw_rules.py`), not new product surface. The two structural items from
yesterday's topology (ADR 0019 lockout-failsafe, the L4 `firewall_failsafe_override` action
class) are unchanged. The one thing worth carrying forward as a pattern: today surfaced a
third instance of the same failure class (`sudo` under a `NoNewPrivileges=yes` unit with no
matching grant — first `device_scanner`'s `sudo nmap`, then `alert_watcher`'s old
`load_blocked_ips()`, now `ufw_rules.py`) — worth a grep for any remaining `sudo`-prefixed
calls in service code before assuming this class is closed. See
`docs/handoff/supplements/2026-08-19-001.md` for the last full topology summary.
