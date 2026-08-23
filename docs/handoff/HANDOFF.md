# HANDOFF — current state

> Last updated **2026-08-23, nightly closeout (Window 2, second session)**. Overwritten each
> closeout (latest state wins). Durable history: `docs/handoff/supplements/` (append-only).
> Real IPs/hosts/accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` —
> placeholders here per Rule 8.
>
> Full detail behind today's second session: `docs/handoff/supplements/2026-08-23-002.md`
> (curated) and `docs/handoff/worklog/2026-08-23-002.md` (raw log). 45 commits — this file
> summarizes by theme; the supplement has the full account, the worklog the chronology.

---

## 1. Push status — all clear, `origin/main` == local HEAD

`git rev-parse HEAD` == `git rev-parse origin/main` == `185e9ba057db56509539f698cbab5138b77d6995`.

## 2. What landed today's second session (45 commits, `c8675b2`..`185e9ba`) — by theme

1. **Unblocked origin/main** (`9eea405`) — last night's overnight batch had committed
   consumers of steering/Sysmon/GUI code without their config defaults/registry entries,
   breaking `test_steering_wiring.py` and `agent_gui.py`. Fixed by hunk-splitting Window 1's
   held diff into a steering-only patch, verified against a materialized isolated copy of
   `origin/main` before committing.
2. **Window 1's 9-commit consolidated plan** (`b35af4e`→`557561f`) — error-code registry
   checker, ADR 0024 (Windows AV delegation), the L0-L4 authority promotion ladder, the
   dashboard R2/R6 settings-honesty + detector-coverage-alarm surface (route-security
   audited, no findings), real TPM backends (Linux tpm2 + Windows CNG), Set 4's
   memory-injection region features, and a classifier-contract fix.
3. **Window 3's batch-5** (`71a651b`→`0373a52`) — lookup-guide reconciliation, digest
   delivery pipe H1-H3 (verified end-to-end via a scratch DB; also confirmed a genuine
   fail-safe live: no SMTP creds → send fails → row correctly stays unsent).
4. **V2.0 gap-scan** — full scoping pass, then a re-audit after one item (malware Layer-C
   verdict rendering) was found already-fixed before the scan ran. Full reports in
   `~/work/nemesis-internal/audits/`. Two Tier-1 items from it (frozen agent attestation,
   Windows behavioral monitoring) were found built-and-tested-but-uncommitted and later
   landed (`68658bb`, `a2d1546`). A dedicated retention/bounded-storage follow-up audit
   found the original scan's premise partly wrong: `dm_operation_log`'s retention mechanism
   is fully built and tested but has ZERO production callers — not a working example, the
   biggest instance of the gap. Two new roadmap stubs captured (vulnerability/patch
   management, USB device control) — `440edf3`.
5. **The digest feature, completed end-to-end** (`f9f27dd`→`dac6ed3`, `c1b84e2`, `7dec49a`)
   — the dispatch helper, all ~9 `send_email()` call sites converted (one, `nemesis_fw_watch`,
   deliberately excepted and documented — converting it would have reintroduced the
   2026-08-01 root-owned-WAL-sidecar incident), and a full digest settings UI section (the
   four settings had zero UI/production callers before this).
6. **Licensing-bypass fix** (`075d551`) — three live revenue-enforcement bypasses closed
   (forgeable license key, forgeable free-tier cap, unmetered-grant-on-broken-census).
   Caught a real gap in the original handoff (a sibling test file missed by a
   `head -12`-truncated grep) before it landed; held, sent back, re-verified, committed.
7. **Batches 6, 8, 9 + AI-engine package exports** (`b83d65d`, `692a517`, `5fb8df6`,
   `fbee98f`, `c1b84e2`, `7dec49a`) — ADR 0026 (RBAC learning gate spec), and a fix for a
   recurring defect class that had silently disabled THREE shipped capabilities via missing
   package re-exports (the L2 reversible-action tier was fully inert; `/api/ai/authority/raise`
   had been 503ing on every call since this morning).
8. **RBAC learning gate, first code** (`6e2d5d9`→`a7ed8a7`, `eecc490`, `48fecb3`, `185e9ba`)
   — `sub_admin` rank (additive, proven via a 2,700-combination recomputation), capability
   declarations (all three still empty — no feature exists yet), unlock schema/quiz
   engine/lifecycle, and the FULL admin-approval backend (payload/verification/limits/
   pairing/atomic state machine — 16-thread concurrency proof for the consumption race).
   Held one exchange on a Rule 10 question (code discloses a still-private protocol spec);
   resolved by the operator — land code, keep spec private until the feature ships
   end-to-end. **Still no live behavior change** — no capability has an endpoint yet.
9. **Process/housekeeping** — a third CLAUDE.md standing-practice section (assert output
   SHAPE, not just plausibility — seven-instance evidence table, `cf9af15`), several stale
   doc corrections (ADR 0026's status line, twice; a PUNCHLIST entry that was already
   resolved before the audit that flagged it ran).

**Not deployed.** No auto-deploy in this repo — every commit above needs an operator-driven
install/restart to take effect anywhere real.

## 3. Open items, priority order (operator's own framing at closeout)

1. **RBAC learning gate — remaining pieces.** A UI (quiz-taking page, unlock display,
   settings route) and wiring an actual capability (`push_and_run` first, per ADR 0026 §6's
   build order) to real endpoints. Until then this is inert scaffolding by design.
2. **V2.0 gap-scan items 9-12** (still unchanged as of the last re-check): Windows
   memory-injection periodic sweep (reactive-only today), malware Layer D's missing trained
   model (`ml_enabled` still off by default), `agent-rebuild-config-driven`'s broader scope
   (foundation shipped, rebuild still parked), Track-C metadata tier (~2 of 6-9 sessions in,
   doc header still says "No code written yet").
3. **The Tier-3 mechanical batch** handed to Window 1 earlier today
   (`~/work/nemesis-internal/handoff/2026-08-23-window2-to-window1-tier3-batch.md`) —
   confirmed entirely unbuilt as of the last re-check: six GET-that-act routes still need
   POST conversion, `mem_appliance.py`'s second stale comment, the uninstall E2E test, two
   named installer bugs, header nav-link dedup, the `anomaly_incidents` merge race.
4. **The retention/bounded-storage build** — its own full audit exists
   (`~/work/nemesis-internal/audits/retention-bounded-storage-audit-2026-08-23.md`), ~20
   tables need work, headlined by wiring `dm_operation_log`'s already-built mechanism to
   something that actually calls it. Sized as a real build spec, not a quick fix — whoever
   picks it up should design ONE shared retention-sweep mechanism rather than repeat the
   pattern that already produced three separately-built-and-never-wired mechanisms.
5. **Email/AI-surfacing security findings** — private audit
   (`~/work/nemesis-internal/audits/ai-surfacing-audit-2026-08-21.md`). One finding (a
   second ungoverned AI path, `hw_discover.py`) was closed this session. Worth a fresh check
   next session on whether the pseudonymization-coverage finding and others from that audit
   are still open, rather than assuming — same discipline that caught item 4 being stale.

## 4. Do NOT touch — still Window 1's held, in-progress work

`nemesis_agent/agent.py`, `nemesis_agent/agent_errors.py`, `nemesis_agent/config.py` still
carry uncommitted hunks: the GUI-findings buffer (`_recent_findings`/`_findings_lock`/
`_GUI_REPORTABLE_CODES`/`_remember_findings`/`_findings_response`/the `report_error` IPC
handler) and Set 4's memory-injection sweep hookup (`_meminject_sweep()` +
`meminject_sweep_interval_s` + `E-AGENT-116`). Both were deliberately excluded from this
session's two surgical hunk-splits (the steering fix and the Sysmon-wiring commit) — neither
was required for either fix, and both remain entangled together in the same file regions.
Confirmed still present and unchanged at closeout. `alert_manager/hw_map.json` is a
runtime-generated hardware-sensor-map artifact sitting untracked in the working tree — not
source, never committed, left alone.

## 5. Verified live this session, not just claimed (Rule 3 discipline)

Every commit landed today carried independent verification — real test suites re-run fresh
against the exact staged content, not trusted from any handoff's own account. This caught
two real defects before they shipped: `core/test_cap_connectivity.py` (untouched by the
licensing-fix handoff, would have broken on commit — held, sent back, fixed, re-verified)
and, earlier in the day, `test_steering_wiring.py`'s root KeyError itself. Several
verification-instrument failures were independently corroborated as real from this session's
own record (see CLAUDE.md's new third standing-practice section, `cf9af15`) — including one
this session caught directly: a `head -12`-truncated completeness grep in Window 1's own
licensing-fix verification.

The RBAC additivity claim (`sub_admin` insertion changes no pre-existing role's answer) was
independently re-confirmed via `test_roles.py` (144/144) after every subsequent commit
touching `roles.py` or `dashboard.py`'s route surface, not just once at N1.

## 6. State snapshots

None taken this session — every state-changing action was a code commit, not a direct
production data/config change.

## 7. Elevated grants

Not re-checked this session (code-batch closeout, not a Morning Status pass — same as last
night). Baseline unchanged since 2026-08-22 as of the last full check (this morning's
Morning Status pass, same day). Re-verify fresh at next Morning Status.

## 8. Cross-references

- `docs/handoff/supplements/2026-08-23-002.md` — curated narrative, this session (45 commits).
- `docs/handoff/worklog/2026-08-23-002.md` — chronological detail.
- `~/work/nemesis-internal/audits/v2-gap-scan-2026-08-23.md` (+ addendum) — the gap-scan.
- `~/work/nemesis-internal/audits/retention-bounded-storage-audit-2026-08-23.md`.
- `~/work/nemesis-internal/handoff/2026-08-23-window2-to-window1-tier3-batch.md` —
  outstanding Tier-3 batch.
- `docs/roadmap/vulnerability-patch-management.md`,
  `docs/roadmap/removable-media-device-control.md` — new stubs.
- `docs/architecture/0026-rbac-learning-gate.md` — RBAC learning gate ADR, now
  partially-implemented status.
- Prior session: `docs/handoff/supplements/2026-08-23-001.md`.

## Topology (durable, unchanged from prior handoffs unless noted)

No topology changes this session. See `docs/handoff/supplements/2026-08-19-001.md` for the
last full topology summary.
