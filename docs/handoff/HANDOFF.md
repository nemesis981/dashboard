# HANDOFF — current state

> Last updated **2026-08-27, nightly closeout (Window 2)**. Overwritten each closeout
> (latest state wins). Durable history: `docs/handoff/supplements/` (append-only). Real
> IPs/hosts/accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` —
> placeholders here per Rule 8.
>
> Full detail: `docs/handoff/supplements/2026-08-27-001.md` (curated) and
> `docs/handoff/worklog/2026-08-27-001.md` (raw chronology — **reconstructed at closeout,
> not live-appended**; flagged as such per the standing convention, since no worklog entry
> was written during the session itself).

---

## 1. Push status — both repos

**`/opt/nemesis`:** verified `git rev-parse HEAD` == `git rev-parse origin/main` after this
closeout's push (see §7, health check, for the re-verified value at write time).

**`~/work/nemesis-internal`:** not this session's to verify — Window 2 did not push there
today; Window 1/Window 3 own its sync state.

## 2. `/opt/nemesis` working tree — not clean, and neither item is this closeout's to commit

`git status --short` (as of this closeout):
```
 M CLAUDE.md
?? alert_manager/hw_map.json
```

- **`CLAUDE.md`** — a new, complete-looking, uncommitted diff appeared during this
  session's closeout prep: a standing rule requiring `--passwordfile` over `--password` on
  every `VBoxManage guestcontrol` call, citing a second same-shape credential leak (a hung
  command's `subprocess.TimeoutExpired` embedding the full argv, including the password, in
  a session transcript). Read in full — it is coherent, complete, and reads as finished, not
  mid-edit. **No handoff document describes it and no window has claimed it.** Not committed
  — whoever authored it should hand it off properly so it can be verified and landed with
  attribution, rather than being swept in unexplained.
- **`alert_manager/hw_map.json`** (untracked, runtime artifact from `hw_discover --auto`) —
  still undecided: track or gitignore. Carried forward unchanged across several sessions
  now; this decision keeps getting deferred rather than made.

## 3. This session's landed work — 14 commits, all pushed

The full ADR 0019 lockout-failsafe mechanism plus DESIGN-L4 §2/§4's authority and
context-store work. (Three additional commits landed and pushed earlier today, before this
batch began, and are not detailed here: `b85d04d` CLAUDE.md fleet-review pointer, `5a1fbe6`
+ `aa0abdd` two small ADR 0019 doc corrections.)

### ADR 0019 — lockout-failsafe (Window 1)
- **`b73a0ad`** — `fw_revert_tokens`: a split-token store (`selector.verifier`; verifier
  hashed at rest) for the revert-link credential.
- **`e6d6841`** — `failsafe_revert` op in `nemesis_fwd.py`/`fw_client.py`. Also the first
  real consumer of `NO_CREDENTIAL_OPS`, declared 2026-07-28 and never read by any dispatch
  path until this commit — a declared-but-inert allowlist, closed rather than left as a
  second trap.
- **`cb71ab5`** — the standalone `/fw/revert` GET/POST endpoint, deliberately unauthenticated
  (the endpoint exists for an admin who cannot log in) with the security boundary living in
  the token, not a session check.
- **`b1b0e52`** — `nemesis-fw-healthcheck` (six-check post-apply probe, UNKNOWN counted as
  failure, self-tests its own probes before reporting) and dual manual/unattended
  revert-window support in `nemesis-fw-apply`.
- **`50cbf2c`** — `firewall_failsafe_override` registered as the first L4 action class, paired
  with its ARCHITECTURE.md documentation in one commit (see §5 for why together, not the
  handoff's original — and disproven — reasoning).
- **`7cd2d35`** — `/api/ai/authority/clear` (the OFF half of the L4 authority toggle) with an
  append-only `ai_authority_events` audit trail, plus a folded-in fix (`EXTERNALLY_EXECUTED`)
  correcting `automation_readiness()`/`authority_raise_warnings()`/`refusal_ticket_text()`,
  which previously reported the failsafe-override class as unable to act when it actually
  does — a false-reassurance direction, not a false alarm.

### DESIGN-L4 (Window 3)
- **`9f7cda4`** — the L4 context store, §4.5 review surface, and engine-side failsafe
  consumer (`failsafe_decision.py`).
- **`23c52a6`** — `l4_ab_harness.py`, the §5 A/B measurement instrument.
- **`c751a77`** — the manual canary-plant route (`POST /api/malware/canary/plant`),
  restoring a manual bait-planting path after auto-plant became opt-in.
- **`29fe5d3`** — landed tonight: a real functional fix to `failsafe_decision.decide()`. It
  read `result["decision"]`, a key the real `analyze()` never populates (confirmed by
  reading every one of `analyze()`'s return statements, `module.py:3438-3597` — only `"ok"`,
  `"text"`, `"reason"` ever appear). Every production call therefore fell through to
  `allow_revert` regardless of input, while 64 unit checks stayed green because each one
  injected a test double supplying `"decision"` directly. The consumer could never actually
  assert an override on any real input until this fix. Also gives `l4_ab_harness.py` real
  A/B measurement support (env loading, genuine per-worker L4 grants) and reframes a failed
  §5 requirement as INCONCLUSIVE rather than FAILED (n=1 against a non-deterministic model
  cannot disprove the mechanism).

### PUNCHLIST entries (both windows, landed as their own commits)
- **`deeca3a`** — `[LOW]` no `nosniff` header anywhere in the app (Window 3, surfaced during
  the L4 route review).
- **`8a53e26`** — `[HIGH]` ×2 canary false-positive root cause (the 2026-08-25 incident) +
  `[MEDIUM]` ×2 plaintext enrollment tokens / `NO_CREDENTIAL_OPS`'s 30-day-inert history
  (Window 1).
- **`ae2ea44`** — `[LOW]` login-page CSRF, flagged for a deliberate operator call, not fixed
  (Window 1).

All report-only per Rule 1 — none of the PUNCHLIST findings were fixed inline.

## 4. Two shared-tree near-misses this session — both caught before push, both fixed

**Co-mingled `roles.py`.** Window 1's own C3 diff for `roles.py` arrived carrying two other
windows' hunks (Window 3's four `ai_engine__route_context_*` entries, a separate
canary-plant entry) that Window 1's handoff hadn't flagged. Caught by reading the full diff
rather than the file list; extracted the genuine hunk via `git apply --cached` (plain
`git apply`/`patch` both failed on a working-tree/index line-number mismatch once the other
hunks were present). Window 3 independently derived the same hunk boundaries in their own
landing-order handoff — cross-confirmed the split was correct.

**An accidental commit swept in in-flight work.** While landing Window 1's authority-toggle
work, three files that turned out to be Window 3's in-flight work
(`failsafe_decision.py`, `l4_ab_harness.py`, `test_failsafe_decision.py`) rode along in the
same working-tree diff and were mistakenly committed together as `8329c8f`. The operator
caught it before push. Fixed with `git reset --soft` (a `rebase --onto` was blocked by the
auto-mode classifier as history-rewriting; the operator supplied the safer reset-based
sequence instead) — dropped the commit, restored the three files to uncommitted status,
verified byte-for-byte that their content was unchanged from what had been in the dropped
commit (two identical, one a pure superset, since Window 3 had continued editing
`l4_ab_harness.py` live during the fix itself). Nothing was lost; nothing had been pushed.

**A provenance claim that didn't check out.** A later message reported those same three
files as sitting in a private-repo commit (`490ef44`) needing a pull, citing Rule 12 as the
reason. Checked directly before acting: that commit touches only a handoff markdown file,
no code, and Rule 12 only governs docs mirroring, not module source. The claim was
mistaken phrasing, confirmed by the operator after checking with Window 3 directly — but it
was caught by reading the actual commit before pulling anything, not by trusting the
citation.

## 5. Verified live this session, not just claimed (Rule 3 discipline)

- Reproduced `test_roles.py` at 158/0 repeatedly against isolated `git worktree` copies
  built from exact staged blobs — never against the shared working tree, which held other
  windows' uncommitted content throughout the entire session.
- Empirically disproved a stale claim in Window 1's handoff ("land ARCHITECTURE.md with C4
  or the suite goes red") by temporarily reverting the change and re-running the suite
  (22/0, not a failure) — then identified the real, different reason to hold them together
  (a doc-accuracy dependency: the new paragraph asserts a fact only true once the code
  change is also present).
- No committed test exercises the new `EXTERNALLY_EXECUTED` branches in
  `automation_readiness`/`authority_raise_warnings`/`refusal_ticket_text`
  (`test_master_authority.py` and `test_package_exports.py` are both green but neither
  touches `firewall_failsafe_override`) — exercised all three directly, against both a
  member class and a control (non-member) class, before landing the fix.
- Read every return statement in the real `analyze()` before landing `29fe5d3`, confirming
  the reported bug against source rather than trusting the report.
- Gate-checked every push: fetched, diffed the unpushed set against exactly what had been
  confirmed, and pushed the reviewed SHA rather than the branch name.

## 6. Anything else queued, not yet actioned

- **`CLAUDE.md`'s uncommitted credential-handling rule** (§2) — needs its author to hand it
  off with attribution before it can be verified and landed.
- **`hw_map.json` track-or-gitignore** (§2) — still undecided, carried forward again.
- **No committed test covers `EXTERNALLY_EXECUTED`** — verified by hand this session (§5),
  but a real test gap remains; worth a PUNCHLIST entry or a follow-up commit.
- **Elevated grants** — not re-checked this session (no fresh Morning Status run; this was
  a continuation, not a new morning start). Last live host-level check: 2026-08-25 morning
  Morning Status. The `<gateway-vm>` grant flagged 2026-08-26 (§6 of that handoff) is
  presumed unchanged, not re-verified.
- Carried forward, unchanged, not touched this session: ADR 0028 §8 (six open decisions),
  ADR 0029 (16/29 decision-register entries open, parked until V2.0), the gap-scan
  re-audit, Stage 4's remaining corpus questions, `test_layer_c.py`,
  `test_analyze_alert_body.py` (34/35), `_load_secret_key()`'s PermissionError gap.

## 7. Closeout health check

- Working tree: **not clean** — see §2 (neither item is this closeout's to commit).
- Closeout commit is HEAD: confirmed after this handoff's own commit.
- local == origin: confirmed via `git fetch` + `git rev-parse HEAD origin/main` after push.
- HEAD touches only docs/handoff files: confirmed (`git show --stat HEAD`).
- Rule 8 spot-check on the committed diff: clean (placeholders only).
- Open items durably captured: this file, §6, plus PUNCHLIST.md (unchanged since §3's
  entries landed).

## 8. Cross-references

- `docs/handoff/worklog/2026-08-27-001.md` — raw chronology (reconstructed at closeout).
- `docs/handoff/supplements/2026-08-27-001.md` — curated narrative, this session.
- `~/work/nemesis-internal/handoff/2026-08-27-window1-to-window2-failsafe-commit-split.md`
  — went through three revisions as Window 1 re-synced it against what had actually landed.
- `~/work/nemesis-internal/handoff/2026-08-27-window3-to-window2-landing-order-l4.md` — the
  independent per-hunk ownership map that cross-confirmed the `roles.py` extraction.
- Prior session: `docs/handoff/supplements/2026-08-26-001.md`.

## Topology

**Two real changes this session, not cosmetic.** The ADR 0019 lockout-failsafe mechanism
is now fully live: a firewall change under test can be reverted by an admin locked out of
the dashboard via a single-use, hashed, 30-minute token, validated entirely inside the
privileged `nemesis_fwd` helper — the dashboard process never sees or checks it. Separately,
the AI engine now has its first live L4 (unattended-governance) action class,
`firewall_failsafe_override`, with a working grant/revoke toggle, an append-only audit
trail independent of the dashboard's own `audit_log`, and (as of tonight's fix) a decision
consumer that can actually assert an override rather than silently always resolving to
`allow_revert`. Otherwise unchanged from prior handoffs. See
`docs/handoff/supplements/2026-08-19-001.md` for the last full topology summary predating
both of these.
