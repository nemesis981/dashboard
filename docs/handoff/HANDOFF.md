# HANDOFF — current state

> Written at operator-requested closeout, 2026-09-06. Real IPs/hosts/accounts/keys live ONLY
> in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8.
>
> Full detail: `docs/handoff/worklog/2026-09-06-001.md` (raw chronology, kept live throughout
> the day — this is the fuller account; this file is the current-state summary and resume
> point).

---

## 1. Push status — READ THIS FIRST

**Public repo (`origin/main`): at `c2119810a0034f738209439bcd2d59b36a95eae0`.** A huge amount
landed today across many small, verified pushes — see §2 for the mechanism that made this
necessary.

**✅ Resolved before closeout — no longer an open gap.** Earlier tonight, three commits
describing a real, already-built feature (local engine-health visibility in the agent GUI, its
`engine_problems()` bug-fix, and the entire "If Your Nemesis Server Goes Down" Learning Center
article) were found to have never reached `origin/main` despite being reviewed and fixed
earlier in the session. Pushed as part of tonight's closeout (isolated-worktree method, same as
everything else — see §2), with one merge conflict in each of `nemesis_agent/agent.py` (a
context-anchor conflict against a not-yet-pushed sibling commit's function, correctly resolved
by excluding that unrelated function) and `core/test_learning_routes.py` (the `EXPECTED_CHECKS`
derivation's fixed-count comment, resolved by keeping the higher, more current value). **Verified
live against `origin/main` itself, not just the push output:** `agent_gui_core.py` there now
contains `engine_problems`/`engine_inventory` references; `learning_topics.py` there now has 7
topics including `server_outage_protection`. Full test re-run in the isolated worktree before
pushing: `core/test_learning_routes.py` 114/114, `nemesis_agent/test_agent_gui_core.py` 132/132,
`test_resume_detect.py` 24/24, the mutation gate 6/6, and a live `engine_problems()`
reproduction against real `engine_inventory.inventory()` output. Nothing outstanding from
today's public-repo work as of this writing — re-verify with a fresh `git fetch` regardless,
per §2's own caution about how fast this state can move.

**Private repo (`~/work/nemesis-internal`): `local` and `usb` remotes both at `58c92ff`,
confirmed same HEAD.** Fully current as of tonight's push — no known gap there.

## 2. Why every push tonight went through an isolated worktree, and why that matters going forward

**Both this checkout's local `main` (`/opt/nemesis`) and `~/work/nemesis-internal`'s local
`main` have diverged from their respective `origin`/`local`/`usb` remotes, and the gap grows
with every push.** This is a real, understood, and currently-accepted structural cost, not an
accident:

- The technique used all night: build a scoped, reviewed commit sequence in a **detached
  worktree** based on the remote's actual current tip (`git worktree add --detach <path>
  <remote-tip-sha>`, then `git cherry-pick` the specific reviewed commits onto it), verify the
  resulting diff is byte-identical to the source content, then `git push origin
  <local-sha>:main` — never a branch-name push, never touching this checkout's own `main`.
- **Why:** on any given push, this checkout's `main` branch sits on top of a large pile of
  other windows' in-flight, not-yet-reviewed work (Window 1's uncommitted engine-inventory
  changes were live in the tree for parts of tonight; Window 3's darkweb-sandbox module has
  been mid-build all day). A plain branch push would ship all of it as ancestors. The isolated-
  worktree method publishes only what's actually been reviewed, without disturbing anyone's
  in-progress local state.
- **The cost:** cherry-picking into a fresh commit sequence produces new commit objects with
  new hashes — the content is identical, the SHA is not. This checkout's `main` branch never
  gains these pushed commits back, so it keeps diverging from the remote, and the gap is
  monotonically increasing by construction. Confirmed live tonight, twice (once in each repo):
  a plain `git push` was rejected as non-fast-forward, and the actual fix required cherry-
  picking the full local-only delta onto the remote's real tip in yet another isolated
  worktree.
- **Current measured divergence** (re-check before trusting this number — it moves with every
  push): `/opt/nemesis` local `main` vs. `origin/main` was last measured at **39 ahead / 15+
  behind** and has grown since (more pushes landed after that measurement). `~/work/
  nemesis-internal` was resolved once tonight (`58c92ff` reconciled the full local-only delta
  onto the then-current remote tip) but will start drifting again the moment any window
  commits new local work there.
- **A real hazard this creates, seen live tonight:** a doc that cites a commit hash by number
  (e.g., a roadmap entry saying "see commit `8722521`") can go stale the moment that commit's
  content gets pushed under a different hash via this method. Caught and fixed once already
  (`19d5d658...`'s ancestor `b8e4f34` fixed four dangling hash citations in
  `docs/roadmap/agent-update-scheduling-and-wake.md`) — **check any new doc for this before
  trusting a cited hash**, especially anything written the same day content was isolated-
  pushed.

**⛔ Deliberately deferred to a dedicated closeout session — do not attempt mid-flight, do
not attempt while any window has uncommitted work.** Reconciling the divergence (likely:
identify which of the local-only "ahead" commits already landed upstream under different
hashes and can be dropped, versus which are genuinely still unpushed and need to move onto the
new base) is real, careful work that risks eating another window's in-progress changes if
rushed. Confirm with every active window that nothing is mid-edit before starting it. Both
`/opt/nemesis` and `~/work/nemesis-internal` need this treatment eventually; neither is urgent
tonight now that the private repo has been freshly reconciled and the public repo's known
content gap (§1) is tracked separately.

## 3. What's actively in-flight (not Window 2's, as of closeout)

**Window 1** — was working through the endpoint-split fix (`7586817`/`d1e5dab`, now pushed,
see §1), the agent offline-resilience fixes, and the ratio-class/dual-answer CLAUDE.md write-
ups (both landed tonight, see §5). Confirmed no uncommitted work of theirs at last check, but
re-verify before touching the shared checkout — `git status` first, always.

**Window 3** — darkweb-sandbox module has been mid-build all day (`7baeb08` and further
uncommitted work in `alert_manager/roles.py`/`data_manager.py` were seen at various points
today) — correctly excluded from every push tonight as unreviewed, in-progress work. Also
did the private-repo mutation-gate work (`fe0f8b4`, verified and pushed) and caught/self-
corrected a commit-lane overstep (`8871cc8`→`4fef4c6`, forward-corrected, not rebased — see
worklog for the full reasoning on why reset was no longer safe by the time it was approved).

**Window 2 (this session)'s own state:** fully caught up on everything reviewed tonight except
the §1 gap. No uncommitted changes in either checkout at closeout.

## 4. Live service state

Not independently re-verified at this specific closeout moment — the dashboard was restarted
at **16:24:05** today (confirmed via `systemctl show dashboard -p ActiveEnterTimestamp`) to
deploy the endpoint-split fix (`7586817`, now pushed as `0ba0584`'s ancestor `1c8a14d`).
Re-check `systemctl is-active dashboard watchdog alert-watcher malware-canary
diagnostics-watcher vpn-dns-guard` at next session start per standing Morning Status practice.

## 5. What shipped tonight, briefly (full detail in the worklog)

- **Morning Status, elevated-grants re-check, roadmap-drift audit** — routine, see
  `docs/briefing/2026-09-06.md` (gitignored, local) and `docs/handoff/elevated-grants-tracking.md`.
- **A recurring real-username leak fixed forward** in `elevated-grants-tracking.md` (8 live
  instances, a prior partial fix had not stuck) — history scrub tracked as its own PUNCHLIST
  item, not done tonight (needs coordinated re-cloning across windows).
- **46 commits reviewed and pushed** (Learning Center phases 1/2, Gateway VLAN-mode
  groundwork, email-security attachment signals, `hw_anomaly_snapshots` archival fix, roles.py
  additivity-canary hardening) plus the `api_build` RBAC fix, found and fixed same session.
- **A full agent offline-resilience audit** — what protects a device with no server reachable.
  Private technical audit: `~/work/nemesis-internal/audits/agent-offline-resilience-audit-
  2026-09-06.md`. Found, fixed, and pushed (`c211981`'s ancestry, §1): local engine-health
  visibility, a checkin-staleness escalation policy. Split out and tracked separately (not
  built): autonomous local notification on a finding
  (`docs/roadmap/agent-offline-notification.md`).
- **The Learning Center `server_outage_protection` article** — public-facing, honest
  explanation of the above, three rounds of factual correction with Window 1/3 before landing
  (Suricata/behavioral default OFF, corrected; the ClamAV-never-updates-after-install finding,
  corrected and sharpened). Visibility resolved: `all_users` + entitlement for the current
  user population, verified live against the DB and `learning.visible_topics()`. Pushed and
  confirmed live on `origin/main` (§1).
- **Agent-update scheduling design decision captured**:
  `docs/roadmap/agent-update-scheduling-and-wake.md` — build state-awareness + fairness queue,
  do NOT build Wake-on-LAN, agent-armed RTC timers if wake is ever wanted later. Amended twice
  more the same evening as new measurements landed (the resume-detection capability, the
  `enqueue_task` deadlock fix, then a hash-remapping fix after an isolated push rewrote its own
  citations — see §2).
- **Two new CLAUDE.md standing practices**, both operator-confirmed adoptions of same-day
  findings:
  - "A mutation must target the WIRING, not only the logic."
  - "A ratio between two constants needs its own mutation when the constants sit across a
    review boundary" (two confirmed instances, one withdrawn, one downgraded — the
    downgrade is what proves the criterion excludes as well as includes).
  - "Before trusting any check's result, confirm it can produce BOTH possible answers" — six
    same-day instances cited.
- **Rule 10 decision, resolved by the operator:** the resume-detection timing constants
  (`RESUME_CHECK_SLICE_S`, `POLL_INTERVAL_FLOOR`) stay public, no redaction — the mechanism is
  purely additive (more check-ins only, never fewer) and has no evasion boundary an attacker
  could exploit by knowing the values.
- **A minor commit-lane / audit-trail gap logged**, not fixed: the Learning Center article's
  visibility rows were set via a direct DB path rather than the audit-logged HTTP admin route
  (`PUNCHLIST.md`, low severity, in-band attribution present).

## 6. Precise next steps for a fresh session reading this cold

1. **Do not attempt the divergence reconciliation (§2) without first confirming with every
   active window that nothing is mid-edit.** It's real work, not urgent tonight, and risks real
   loss if rushed. This is the only structurally-owed task left from tonight.
2. **Re-verify current push state before trusting anything in this file** — re-run
   `git fetch origin && git log --oneline origin/main..HEAD` and the private-repo equivalent;
   this file describes state as of closeout (`origin/main` at `c211981`), and other windows may
   have pushed or committed since.
3. **Re-check elevated grants and service status** per standing Morning Status practice — not
   done as part of this closeout write-up specifically, since this was an operator-requested
   mid-session handoff rather than the standing nightly one.
4. Nothing else is currently blocked or waiting on a decision — the Rule 10/visibility questions
   from earlier tonight are resolved (§5), and the public-repo content gap that was open earlier
   in the evening is closed (§1).
