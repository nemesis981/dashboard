# HANDOFF — current state

> Last updated **2026-08-23, nightly closeout (Window 2)**. Overwritten each closeout
> (latest state wins). Durable history: `docs/handoff/supplements/` (append-only). Real
> IPs/hosts/accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` —
> placeholders here per Rule 8.
>
> Full detail behind today's session: `docs/handoff/supplements/2026-08-23-001.md`
> (curated) and `docs/handoff/worklog/2026-08-23-001.md` (raw log). This was an
> exceptionally large session — 51 commits — so this file summarizes by theme rather
> than re-narrating every commit; the supplement has the full list.

---

## 1. Push status — all clear, `origin/main` == local HEAD

`git rev-parse HEAD` == `git rev-parse origin/main` == `a0d971c4101299b34767f183c3451afdabd7804f`.

## 2. What landed today (51 commits, `372b717`..`a0d971c`) — by theme

1. **Roadmap audit refresh + Window 3's detector-coverage-corrections batch** (`5a04d0d`,
   `6448f5b`, then `2618b02`→`7e6cb8b`): bounded settings, malware/diagnostics settings
   validation, IPv6 fix, mem_appliance throttle exclusions, integrity_watch wiring.
2. **Memory-injection Set 1** (`0509b67`→`52d3ab6`): Tier 2 attestation, RAM-budget
   reservations, E-AGENT error codes, Linux memcap (opt-in), Windows privileged channel +
   memory acquisition, `.ps1` encoding/banner fix (including a real regression caught and
   fixed in the same pass).
3. **Diagnostics-tools batch** (`f023bfd`→`062df42`): shared canary harness,
   schema_drift, clock_and_timestamp_sanity, agent_enrollment_integrity,
   dependency_preflight, config_drift, the `anomaly_state` enablement-detection bug fix
   (was unconditionally reporting the module disabled), all five registered.
4. **2026-08-21 AI-automation batch, held two days, landed** (`1225bd0`→`6f93588`):
   master-password authority/spend-metering/undo path, the dashboard authority gate on
   the alert-verdict path (closes a real permission-model incoherence), ARCHITECTURE.md's
   L0-L4 ladder documentation, a malware sandbox guest-dump-error fix, the consent
   five-valued coverage state.
5. **Lookup + TLS investigation tools** (`00c3223`→`93b0e41`, then `542f56a` fixing a
   real load-time defect in `31478f0`): domain/IP lookup (dig/whois), TLS certificate
   inspection, folded into one module wrapper, plus the CUSTOM guide. **`542f56a`
   matters**: `module.py` used a relative import that works when tested directly via
   `spec_from_file_location` but fails under the real `modules_loader` mechanism — fixed
   via an explicit `_sibling()` path-based loader. Verify any future module split via the
   real loader, not a direct import (see §6).
6. **Digest scheduling foundation** (`7a7d703`) + **F1 test-mock fixes**
   (`a809835`, `5478f81`) for the spend-metering rename that broke
   `test_rate_degradation.py` at HEAD.
7. **Pre-filter ladder** (`8cf521d`): cost-control heuristic triage ahead of AI model
   calls — a prerequisite for the AI trial being affordable at all.
8. **Set 2 (malware/zero-day, Groups A-H) — the oldest outstanding debt, now fully
   landed** (`71dda37`→`328e25e`): roaming traffic steering (L3 forwarder/lease/nft),
   Windows detonation base image, **Windows behavioral monitoring (Sysmon)** — Windows
   endpoints are no longer behaviorally blind — synthetic sample suite (harness public,
   AV fixtures correctly gitignored), Layer-B Falco/Sysmon corrections (including a real
   bug: Windows always reported its behavioral engine absent even when healthy), agent
   GUI findings tab, the ISO-builder install.sh dependency, and the 4 outstanding
   error-code-classification/roadmap audit docs.
9. **Netprobe (ping/traceroute)** (`2249930`→`81ca877`): inventory-restricted reachability
   probing — targets must be a known LAN device or enrolled agent, never arbitrary. Port
   scan and packet capture remain deliberately unbuilt (§5).
10. **RBAC foundation** (`c84dcce`→`a0d971c`): three roles (admin/user/viewonly) enforced
    at a `before_request` gate covering all 149 live endpoints including module-registered
    ones a decorator-only design would have missed. `role` existed and was enforced
    nowhere before this. Independently re-verified (not just Window 3's own report): reran
    `test_roles.py` directly, separately replicated the live app+module-loading setup and
    re-ran `assert_registry_complete()` myself, manually sampled all 45 module endpoints
    against the registry, and confirmed the six GET-that-act routes' elevated minimums
    against the actual `dashboard.py` source.

**Not deployed.** No auto-deploy in this repo — every commit above needs an
operator-driven install/restart to take effect anywhere real.

## 3. Two items flagged for Window 3, first thing tomorrow morning

1. **Two overlapping lookup CUSTOM guides need reconciling into one.**
   `docs/modules/lookup/CUSTOM_LOOKUP_BACKEND.md` shipped in today's batch (`93b0e41`).
   Window 3 separately wrote `docs/CUSTOM_LOOKUP_RESOLVER.md` believing lookup had shipped
   with no guide (checked commit `31478f0` in isolation and missed the follow-up two
   commits later in the same batch). The two substantially overlap — contract,
   skip-if-absent, example, Rule 8 — with the newer RESOLVER doc additionally covering TLS
   backends and sinkhole detection. **Held out of tonight's closeout** (operator decision)
   — `docs/CUSTOM_LOOKUP_RESOLVER.md` sits uncommitted in the working tree. Window 3:
   reconcile into ONE accurate guide (likely merging RESOLVER's TLS/sinkhole content into
   the shipped BACKEND doc, or replacing it outright) before either is committed again.
2. **CLAUDE.md's ADR 0006 actor-mechanism note was stale and has been corrected
   tonight** (see the "Actor mechanism" bullet under ADR 0006 in CLAUDE.md). It claimed
   the mechanism was unwired; it's been wired since 2026-08-04
   (`dashboard.py:_set_dm_actor`, verified independently before correcting). Window 3
   flagged this after having repeated the same stale claim once itself before checking —
   worth remembering that a CLAUDE.md flag needs the same periodic re-verification as any
   other claim, not trust-by-inheritance.

## 4. Open items, priority order

1. **Window 1's R1-R7 protection-schema audit work — held, no commit plan yet.**
   Touches `modules/ai_engine/module.py`, `modules/anomaly_detection/manifest.json`,
   `modules/malware_detection/manifest.json`, `modules_loader.py`, a new
   `docs/architecture/0024-windows-endpoint-av-delegation.md`,
   `modules/ai_engine/test_authority_promotion.py`, `scripts/error_code_registry.py` (+
   its test), `test_required_detector_coverage.py`, plus 9 hunks inside `dashboard.py`
   (a detector-coverage monitor/banner labeled "R6" and master-password-authority routes
   labeled "R2" in Window 1's own numbering — coincidentally colliding with tonight's
   RBAC batch's own R2/R3/R5 labels; they are unrelated features). **Do not touch until
   Window 1 hands over a proper commit plan** — explicit operator instruction tonight.
2. **R6's "active pipeline alert"** (the detector-coverage monitor referenced above,
   building on a tested function + a dashboard banner) may or may not be assigned to
   Window 2 — operator was confirming with Window 1 as of tonight. **Do not start
   speculatively.**
3. **Batch 3's digest-delivery remainder (H1-H3) — held tonight, scope was netprobe
   only.** `alert_manager/database.py` carries an uncommitted `init_notify_tables()`
   addition (H1) sitting alongside the R5 comment fix that WAS committed tonight (staged
   by hunk, H1 left in the working tree). `alert_manager/notify.py`/`test_notify.py` and
   `core_module/watchdog/watchdog.py` also carry H2/H3 content. See
   `~/work/nemesis-internal/handoff/2026-08-22-window3-to-window2-batch-3.md` §3 for the
   full spec (bundle/build/send/mark-sent, watchdog tick, 113 checks claimed).
4. **Six GET-routes-that-act should become POST** — tracked in `PUNCHLIST.md` tonight
   (new entry, kept deliberately light on specifics; full detail in the private route
   audit). Role gating (landed tonight) reduces blast radius but doesn't remove the
   underlying shape. Own pass, own commit(s).
5. **Port scan and packet capture are deliberately NOT built.** Per the operator's
   explicit instruction: building a gating layer purely to ship these two would decide
   "full roles system vs. extending master-password" as a side effect. RBAC (tonight) is
   that foundation, now confirmed independently — but building on top of it is still its
   own deliberate pass per Window 3's own batch-4 handoff, not an automatic next step.
6. **Set 4 (memory-injection step 4+)** — Window 1's ongoing work
   (`linmem.py`/`memfeatures.py`/`meminject_scan.py`/the corpus-collection tools +
   tests), plus the mixed files shared with earlier Set 2/Set 1 work (`agent.py`,
   `agent_errors.py`, `config.py`, `privservice.py`, `test_inspect_pid.py`). Not part of
   tonight's scope; still Window 1's in-progress work.
7. `LICENSE` draft's real legal review — placeholders filled, review unstarted (carried
   forward, unchanged for weeks).

## 5. Do NOT touch — the working tree still holds two other windows' in-progress work

Everything under `nemesis_agent/keyprotect/`, `nemesis_agent/linmem.py`,
`nemesis_agent/memfeatures.py`, `nemesis_agent/meminject_scan.py`, the
`nemesis_agent/tools/*corpus*`/`measure_scan_cost.py` tools + their tests,
`scripts/error_code_registry.py` (+test), `test_required_detector_coverage.py`,
`docs/architecture/0024-*.md`, `modules/ai_engine/test_authority_promotion.py`, the
`modules/*/manifest.json` and `modules_loader.py` modifications, and 9 specific hunks
inside `dashboard.py` (identified precisely tonight — see §4.1) are **Window 1's**,
per explicit operator instruction. `alert_manager/database.py` (H1 hunk),
`alert_manager/notify.py`/`test_notify.py`, `core_module/watchdog/watchdog.py` are
**Window 3's held batch-3 digest work** — do not sweep in. `docs/CUSTOM_LOOKUP_RESOLVER.md`
is held pending the reconciliation in §3.1.

## 6. Verified live tonight, not just claimed (Rule 3 discipline)

Every batch tonight carried independent verification, not just Window 3's own report:
every test suite Window 3 claimed a count for was independently re-run and matched
exactly; Rule 8 was independently re-scanned on every new/modified file, not trusted from
the handoff; the `542f56a` lookup-load defect was reproduced myself via the real
`modules_loader` mechanism before trusting the fix, and the fix re-verified the same way;
RBAC's registry-completeness was independently re-run outside `test_roles.py`'s own
harness, plus a manual sample of all 45 module-registered endpoints against the live
`url_map`; the six GET-that-act routes were confirmed as genuinely bare `@app.route()` by
reading `dashboard.py` source directly, not assumed from the handoff's description; every
mixed-file hunk-split (dashboard.py x2 separate diffs today, database.py, agent_errors.py
earlier this week) was done by reading every hunk individually and verifying the
staged-only content compiles/passes in isolation before committing.

**One real dependency surfaced and documented, not silently absorbed:** `roles.py`
(`c84dcce`) references two endpoint names (`api_ai_authority`, `api_ai_authority_raise`)
that only exist in Window 1's held work. This makes `assert_registry_complete()` report 2
phantom entries and `test_roles.py` show 143/144 (not 144/144) until Window 1's routes
land — confirmed to have zero live effect (the check is test/audit-only, never called from
the request path). Documented in commit `91833d9`'s message; will self-resolve once
Window 1's work lands.

## 7. State snapshots

None taken tonight — every state-changing action was a code commit, not a direct
production data/config change.

## 8. Elevated grants

Not re-checked tonight (this was a code-batch closeout, not a Morning Status pass). The
2026-08-22 baseline (scoped sudo NOPASSWD set, `nemesis-db`/`nemesis-fw`/`pihole` group
membership, polkit unreadable this session) stands unchanged — full itemization in this
file's git history (the version immediately prior to this one) and in the mirror at
`~/work/nemesis-internal/handoff/HANDOFF.md`'s own history. Not re-copied into this
revision deliberately, per Rule 7's own reasoning: a duplicated copy is a second source of
truth that desyncs the moment one copy is updated and the other isn't. Re-verify fresh at
next Morning Status.

## 9. Cross-references

- `docs/handoff/supplements/2026-08-23-001.md` — curated narrative, today (51 commits).
- `docs/handoff/worklog/2026-08-23-001.md` — chronological detail.
- `~/work/nemesis-internal/handoff/2026-08-22-window1-to-window2-set2-REDERIVED-commit-plan.md`
  — Set 2's plan, now fully executed.
- `~/work/nemesis-internal/handoff/2026-08-23-window3-to-window2-commit-batch.md`,
  `2026-08-23-window3-to-window2-batch-2.md`, `2026-08-22-window3-to-window2-batch-3.md`,
  `2026-08-22-window3-to-window2-batch-4-rbac.md` — today's four Window-3 handoffs, all
  substantially executed (batch-3's H1-H3 remain outstanding, see §4.3).
- `~/work/nemesis-internal/audits/route-security-audit-netprobe-2026-08-22.md`,
  `route-security-audit-rbac-2026-08-22.md` — private route-level audits.
- `PUNCHLIST.md` — new entry tonight (six GET-that-act routes).
- Prior day: `docs/handoff/supplements/2026-08-21-001.md`.

## Topology (durable, unchanged from prior handoffs unless noted)

No topology changes tonight. See `docs/handoff/supplements/2026-08-19-001.md` for the
last full topology summary.
