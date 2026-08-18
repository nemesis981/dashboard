# ADR 0004 — Scan & Task Orchestration

- **Status:** **BUILD-READY — hinge questions (a)/(b)/(c) resolved** (2026-08-02). Design of
  record for the Scheduler/Execution/Reporting separation and the `scan_*`/`malware_findings`
  migration. **Steps 1–3 of the sequence below shipped 2026-08-02** (Step 1: YARA auto-update +
  cross-platform path exclusions + its routes/SSRF-guard/rate-limit/UI; Step 2: actor seam +
  local-ISO timestamps on the `scan_*` tables, `8a836de`; Step 3: agent heartbeat
  authentication, `f331620`) — **Step 4 (the actual Scheduler/Execution/Reporting build) has
  not started.** See "Status / next" for the full sequence and gating.
- **Date:** 2026-06-26 (opened) · resolved 2026-08-02
- **Affects:** scan triggering/dispatch, the malware module, hw_monitor, reporting,
  the agent fleet, the `scan_*` / `malware_*` tables
- **Depends on:** [0001-database-and-module-architecture](0001-database-and-module-architecture.md)
  (single shared DB + module prefix ownership) — gated on Pass 0. **Dependency SATISFIED:**
  Pass 0 completed 2026-06-26 (worklog `2026-06-26-001`).
- **Related:** [0003-database-resilience-and-recovery](0003-database-resilience-and-recovery.md);
  evidence base = `docs/audits/scan-task-architecture-audit.md`;
  `docs/roadmap/latent-bug-fleet-clamav-only.md` (the user-facing consequence of the gap this
  ADR closes, already public).

> Paths/IPs sanitized for the public repo. This ADR now resolves the direction and the three
> hinge questions opened below; the *build* (module contracts, migration scripts, cutover) is
> still ahead of it. One item is deliberately kept out of this document — see the note at the
> end of "Sequence to build" — per Rule 10 (a live, unfixed gap does not get its specifics
> published while it's still open).

---

## North-star / design driver

The product thesis: **affordable self-hosted zero-day / behavioral detection plus
whole-network security — enterprise capability without enterprise pricing.** The
architecture must enable **automated, fleet-wide, FULL-STACK detection**, because that
IS the product.

**Why this ADR is the strategic case, not internal plumbing** (stated plainly, because it's
already public via `docs/roadmap/latent-bug-fleet-clamav-only.md`): full-stack detection
(ClamAV + YARA + entropy/PE heuristics) today is reachable by exactly **one manual button on
the local host**. Every scheduled, condition-triggered, and fleet path — the dashboard's local
scan, the hw_monitor queued-scan executor, and the agent's remote scanner — is **ClamAV-only**,
writing `scan_jobs`/`scan_threats`, never `malware_findings`. `scan_schedules` is write-only;
nothing drains it. A signature scanner running on a schedule is a commodity capability; it is
not the product. Adding a new detection layer before fixing dispatch would put more capability
behind the same closed door — this ADR is the difference between a product that *has*
zero-day detection and one that *runs* it.

## Context / evidence base

From the scan/task architecture audit (`docs/audits/scan-task-architecture-audit.md`),
six verified cross-cutting facts:

1. **No single scan path** — three local-host scanners, two engine sets, two table
   families.
2. **YARA + heuristics reachable only via one manual button** (`POST /api/malware/scan`).
3. **All automation is clamav-only** — every fleet/condition/scheduled path runs
   ClamAV alone, never YARA/heuristics, never `malware_findings`.
4. **Scheduled scans are DEAD** — `scan_schedules` is write-only; no timer/worker
   drains the queue; dispatch is purely event-driven on agent check-in.
5. **Dispatch is welded into the hw_monitor `/hw_data` handler** — scan triggering +
   dispatch interleaved with hardware ingest + device-state management in one HTTP
   handler in the hw_monitor process.
6. **All five `scan_*` tables are core/unprefixed**; **remote HW monitoring is BUILT
   but remote full-stack scanning is NOT** (agent is clamav-only).

## Decision direction (decided)

A three-role separation, replacing today's hw_monitor-welded dispatch:

- **Scheduler module** — the **authoritative dispatcher** for all scan/task dispatch:
  decides *what* runs, *when*, and against *which target*. Owns the timer/queue that is
  missing today (fact #3/#4). Single place that initiates work.
- **Execution modules** — do the work: **malware = the full-stack engine**
  (ClamAV + YARA + heuristics), hardware, and future engines. They execute; they do
  not schedule.
- **Reporting module** — processes results and delivers **printable reports viewable
  in the dashboard**. Separate from both scheduling and execution. *(Its output-format
  contract is not yet designed — carried forward as an open item, not resolved by this
  update.)*
- **hw_monitor reduced to hardware-only** — scan responsibilities move out of its
  `/hw_data` handler (fact #5), leaving it a pure hardware-telemetry ingester.

---

## Resolved hinge question (a) — one findings table, not two

**Decision: `malware_findings` is canonical. `scan_threats` is retired into it.**
`scan_jobs`/`scan_queue`/`scan_conditions`/`scan_schedules` survive, unchanged in kind, as
orchestration state — a real and distinct concern from findings.

The current two-table split is not a design; it is the fossil of the ClamAV-only divergence
this ADR exists to close. Two findings tables exist because two engines exist on two paths —
once dispatch is unified, keeping both tables would make that defect permanent by enshrining
it in schema.

- **Orchestration state** (what work was requested/queued/running/finished) stays in
  `scan_jobs`, `scan_queue`, `scan_conditions`, `scan_schedules` — owned by the **Scheduler**.
- **Detection findings** (what was actually found) live in `malware_findings` — owned by the
  **execution** module that produced them.

`scan_threats` rows carry real history and must migrate, not drop. Its shape
(`scan_job_id`, `device_id`, `file_path`, `threat_name`, `action_taken`, `detected_at`) maps
onto `malware_findings` with `layer='clamav'` and a null-heavy tail — lossy only in the
direction of gaining columns, which is safe. The migration back-fills `layer='clamav'`,
stating a true fact about that history rather than guessing, the same shape as the
`source TEXT DEFAULT 'login'` backfill.

**Consequence:** once unified, "a scan produced no findings" and "a scan produced no
*full-stack* findings" stop being confusable — the user-facing gap named in
`latent-bug-fleet-clamav-only.md`.

## Resolved hinge question (b) — how full-stack detection reaches the fleet

**Decision: ship the detection engine to endpoints. Do not ship suspect files to the
server.** The rule that makes this coherent rather than an ad-hoc split: **file contents stay
on the endpoint; derived intelligence centralizes.**

| Concern | Where it runs | Why |
|---|---|---|
| Layer A — ClamAV, YARA, entropy/PE | **Endpoint** | Needs the file; the file must not move |
| Layer B — canary, behavioral | **Endpoint** | Endpoint-local by nature |
| Hash / verdict cache | **Central** | Intelligence, not content — dedupes across the fleet |
| Layer C — AI verdict | **Central** | Already specified as metadata only, never file contents |
| Layer D — local ML (deferred) | Open | Deferred with the layer; central avoids model distribution, endpoint keeps files local either way |
| Detonation sandbox (V2) | **Central VM Lab** | The one case where a sample must move — already gated as heavyweight, opt-in, and deliberate |

**Why this direction, stated as the privacy-posture and product-promise argument it is:** the
pipeline design already commits to "your files, your behavioral logs, your manifests = yours."
Routinely shipping user file contents to a central box contradicts that promise, and turns the
security appliance itself into an aggregation point for live malware — a categorically worse
compromise than one endpoint. Detection also scales with the fleet this way rather than
bottlenecking on one box, and roaming endpoints keep scanning without tunneling file contents
home. Central-only scanning does not actually avoid endpoint-side logic either — something
still has to decide which files are worth sending, which is endpoint intelligence by another
name, just dumber and undocumented.

**The honest cost, carried forward rather than hidden:** shipping the engine to endpoints grows
agent footprint materially (YARA + rules + heuristics, per-platform packaging) and makes
version skew a first-class risk — a fleet running uneven rule versions has *silently* uneven
coverage, the same failure shape CLAUDE.md already records for a stale test asset. This is not
optional to mitigate; it is a build requirement (below). There is also a trust asymmetry worth
stating plainly: a sufficiently privileged compromise of the endpoint itself could tamper with
a local engine, its rules, or its results, and report clean. Endpoint findings are therefore
**attested claims, not ground truth** — server-side corroboration (canary state, behavioral
telemetry, hash-cache consistency) is the mitigation, not a reason to move scanning
server-side.

**What this obliges the build to specify:**

1. **Engine + ruleset version reporting per endpoint**, with staleness surfaced in the
   dashboard UI. Without this, uneven fleet coverage is invisible.
2. **A rule distribution channel** — the YARA auto-update mechanism plus its operator-facing
   routes and UI (Step 1 below, both shipped 2026-08-02), **generalized fleet-wide**, with
   compile-check-before-activate so one bad ruleset cannot break the layer across the whole
   fleet. What shipped is this-box-only, dashboard-triggered — fleet-wide distribution to
   endpoints is still future work, tied to hinge question (b)'s build under Step 4.
3. **Endpoint findings treated as attested claims**, with server-side corroboration signals;
   state plainly, in whatever ships, that a fully-compromised endpoint can lie.
4. **Graceful, explicit degradation** where an engine is unavailable on a given platform — it
   must report *reduced capability explicitly*, never silently produce fewer findings. This is
   the standing "prove your premise / never default a failed read to a value that looks like
   real data" discipline, applied to fleet coverage.

## Resolved hinge question (c) — where the five `scan_*` tables live

**Decision: `scan_*` becomes the Scheduler module's prefix-owned namespace.
`scan_threats` does not survive the move (see (a) above).**

| Table | Disposition | Owner |
|---|---|---|
| `scan_jobs` | keep — job lifecycle | Scheduler |
| `scan_queue` | keep — pending work | Scheduler |
| `scan_conditions` | keep — auto-queue rules | Scheduler |
| `scan_schedules` | keep — **and finally drain it** | Scheduler |
| `scan_threats` | retire → `malware_findings` | — |

This satisfies ADR 0001's write-own/read-any prefix model rather than merely coexisting with
it: a Scheduler module owning `scan_*` writes only `scan_*`; the malware module writes only
`malware_*`; Reporting reads across both, writes neither. It also resolves today's anomaly
where `hw_monitor` creates tables it does not own the semantics of — `scan_threats` and
`scan_schedules`'s DDL already moved to `database.py` for this exact reason, which is
precedent for the direction.

**The unavoidable cost, stated honestly:** these are currently core/unprefixed tables created
by `hw_monitor` at startup. Moving ownership means the Data Manager grants change, the loader's
static import-check applies to the new Scheduler module, and every process that currently
self-creates these tables must stop doing so. There is no systemd ordering guarantee between
services, so whichever process becomes the owner must create them, and every reader must
tolerate their absence at first boot.

### Cross-cutting requirements folded into the same migration

Cheap now, while the tables are being rewritten; invasive later. Per CLAUDE.md, these seams do
not get built twice — they belong in this rebuild, not a follow-up.

1. **Actor seam.** `malware_findings` already carries `actor` via an idempotent migration; the
   five `scan_*` tables do not. Add `actor TEXT` to each, same nullable pattern. Note the
   existing standing caveat this inherits: the Data Manager stamps `current_actor()`
   automatically on every write, but nothing calls `set_actor()` yet — so today this is a seam
   for future attribution, not live attribution, and should be described as such wherever it's
   documented.
2. **One time convention, decided: local ISO TEXT, matching the auth tables.** Three formats
   currently coexist in this area: `malware_findings.detected_at` is `REAL` epoch;
   `scan_threats.detected_at`/`scan_queue.queued_at` are UTC `TIMESTAMP DEFAULT
   CURRENT_TIMESTAMP`; the core auth tables are local ISO `T`-separated as of 2026-08-02.
   Local ISO TEXT wins for incident-correlation simplicity — correlating a detection against
   `login_events`/`audit_log` during a live incident becomes a plain join, with no timezone
   reasoning at the exact moment someone is most likely to get it wrong under pressure. (Epoch
   `REAL` is the technically stronger storage form — timezone-free, unambiguous sort order —
   but was not chosen here because it would mean converting the auth tables too, a materially
   larger change, and it pushes timezone handling into every reader instead of removing it.
   Recorded as a deliberate tradeoff, not an oversight.) `malware_findings.detected_at`
   converts from `REAL` as part of this migration. The `CURRENT_TIMESTAMP` UTC defaults on the
   two `scan_*` columns must go regardless of the above — being UTC next to local-time
   neighbors, and being TEXT, they carry the same string-comparison hazard already confirmed
   live elsewhere this same day: a `T`-separated local row sorts differently than a
   space-separated UTC row at the separator character itself, before any time digit is read.
3. **Timestamps supplied by the writer, not the column default.** SQLite cannot alter a column
   default in place, so on an existing install a `DEFAULT` is effectively permanent. Explicit
   writer-side values are what actually fix already-deployed databases — the same fix already
   applied to `login_events` this same day.

## What this update does not resolve

Named here so the eventual build does not inherit them silently:

- **The Reporting module's contract** — output format and the printable-report requirement are
  unexamined by this update.
- **Migration cutover mechanics** — how dispatch moves out of `/hw_data` without a window where
  nothing dispatches.
- **Disposable-VM detonation sandbox design (V2)** — untouched here; gated on the VM Lab and
  scoped separately when V2 is planned.

---

## Sequence to build

| # | Work | Gate |
|---|---|---|
| 0 | This ADR update — resolve (a)/(b)/(c) | done, 2026-08-02 |
| 1 | YARA auto-update **+ the path-exclusion list**, then its routes/SSRF-guard/rate-limit/UI (M2) | independent of (a)/(b)/(c) — **shipped 2026-08-02** |
| 2 | Actor seam + one time convention on the five `scan_*` tables | cheap now, invasive later |
| 3 | Agent heartbeat authentication | before dispatch moves out of the hardware-telemetry handler — see note below |
| 4 | Orchestration build — Scheduler / Execution / Reporting | needs 0 |

**On Step 1:** the path exclusions are a prerequisite for enabling YARA fleet-wide, not a
companion improvement — without them, first-scan false positives on browser-extension
directories, Electron/browser caches, and ad-blocker rulesets (which contain malicious domain
strings *by design*) would be immediate and severe. Both landed together, 2026-08-02, followed
same-day by the operator-facing side: `GET`/`POST` routes, an SSRF guard on the operator-set
update source (https-only, every resolved address checked against public/private/loopback
ranges), a rate limit on the manual trigger, settings-write validation, and a dashboard card
showing rule freshness. This makes Step 1 usable end-to-end **on this box**; it is not yet the
fleet-wide distribution channel requirement (b) obliges (that's still Step 4).

**On Step 3 — deliberately not detailed here.** Moving scan dispatch out of the
hardware-telemetry handler should start from an authenticated agent channel, not carry an
unauthenticated one into its new home, so this step is sequenced ahead of Step 4 rather than
folded into it. Per Rule 10, the specifics of the current gap are **not published here** while
it remains open — full detail is in the private mirror. This line is revisited once the fix
ships, at which point it becomes an ordinary fixed-bug reference like the three route-level
bugs already documented in the public repo.

## Status / next

Direction and all three hinge questions resolved 2026-08-02. Steps 1–3 of the sequence above
have shipped, all the same day: Step 1 in full — the auto-update mechanism, the path-exclusion
list, and its routes/SSRF-guard/rate-limit/UI (M2), usable on this box today; Step 2 — actor
seam + local-ISO time convention on the `scan_*` tables (`8a836de`); Step 3 — agent heartbeat
authentication (`f331620`), live in `observe` mode per its own commit (not yet `enforce`).
**Step 4 is unbuilt** — the actual Scheduler/Execution/Reporting build, the `scan_threats` →
`malware_findings` migration, and generalizing Step 1's distribution channel fleet-wide per
requirement (b).2 above. That is the next and only remaining step in this sequence.

---

## Amendment — appliance self-scan trigger design (2026-08-18)

**Status: scoped, not decided, not built.** Window 3 scoping pass, placed here rather than as
a fresh roadmap stub because it is squarely this ADR's territory and directly extends the
Step 4 sequence above. Whether this ships **now**, as a self-contained scheduler-aware
increment ahead of Step 4, or **waits** for the full Scheduler/Execution/Reporting build, is
an open operator decision (see "Open questions" below) — this amendment records the design
either way needs, not a commitment to build immediately.

### Engine invocation must change before any trigger work

The malware module's local-scan path shells out to the standalone scanner CLI once per file,
which reloads the full signature database on every invocation. On appliance-class hardware
(memory-constrained, no swap), a whole-filesystem pass at that rate cannot complete in a
useful time budget and risks exhausting available memory outright — running a second
full-size signature-database copy alongside the already-resident `clamd` daemon. The daemon
client (`clamdscan`) talks to the already-running `clamd` process instead of reloading the
database per file, and is dramatically cheaper on both dimensions. `install.sh` already
provisions and tunes `clamd` for exactly this reason (a separate, earlier measurement pass);
the daemon path exists and is running today, the module simply doesn't use it.

**Consequence: swapping the engine invocation is a hard prerequisite for a scheduled/automatic
scan, not an optional optimization.** "Add a timer to the existing scan path" is not a viable
plan on its own — per Rule 2 the engine swap is its own change, verified on its own (same
verdicts on a known-clean file and a real positive test sample), before any trigger work
begins. Exact resource measurements and file-count figures for this box are kept in the
private mirror (Rule 10 — see the cross-reference below) rather than published here.

**Related, and worth fixing regardless of scheduling:** the existing local-scan path silently
truncates on a file-count cap and still reports the job as completed — a default that reads as
a real result rather than an incomplete one, the same failure shape CLAUDE.md's standing
verification-discipline note already names. Any scheduled/automatic scan must report coverage
explicitly and fail loud on truncation, never render a capped walk as a finished one.

### Trigger design — a staleness gate, not a fixed-interval timer

The agent fleet already has automatic scan coverage (a full scan is triggered on check-in
when the last scan is older than a configured interval). The appliance has no equivalent
event to hang that logic on — it doesn't reconnect to anything — but the load-bearing part of
the agent's design was never the reconnect event itself; it's the staleness gate. On the
appliance, a periodic timer tick supplies the opportunity instead, with the same gate deciding
whether to act.

**Recommended: one staleness-gated decision, two wake sources** — a periodic tick (default
cadence to match the fleet's interval, both settings-driven) as the primary source, plus a
delayed post-boot check as a catch-up safety net for the case where the box was powered off
across one or more scheduled intervals. Both consult the same gate, so there's exactly one
decision point.

This shape is specifically what avoids double-scanning right after a manual run, avoids a
scan stampede on service restart, and correctly catches up after downtime without queuing
multiple passes — properties a plain fixed-interval timer does not have. Filesystem-event-
driven triggering (inotify or equivalent) was considered and rejected for this increment: that
is a *real-time protection* feature with a materially different cost profile (a watch per
directory across the whole filesystem), a different product than *periodic assurance*, and is
already sequenced separately as future kernel-hook-based work.

A hash-keyed cache (rescan only on content change) is recommended as an explicit design
constraint for this increment even if its implementation is deferred to a second pass — the
scan path already computes a content hash for other purposes, so the key exists; not designing
around its eventual use would make daily full-filesystem re-scans an ongoing cost that grows
with the disk indefinitely.

### Scope boundary — how this stays absorbable by Step 4 rather than competing with it

A naively-built appliance scan timer, built without regard for the Scheduler direction decided
above, would become exactly the kind of ad-hoc dispatch path this ADR exists to eliminate.
Precedent for building *before* the Scheduler exists without creating that debt: the malware
canary service was built self-contained (no dependency on the not-yet-built Scheduler) but
scheduler-*aware* (its cadence is read fresh each loop from a setting, a seam the Scheduler can
take over later by writing the setting rather than by surgery). The same shape applies here:

1. **Do not write to the `scan_*` tables.** They remain Scheduler-owned per hinge (c) above;
   this stays within its own module's prefixed tables for any new state it needs.
2. **Do not drain `scan_schedules`.** Draining it is explicitly the Scheduler's job (hinge (c)
   table above); doing so now would pre-empt that ownership decision rather than simplify the
   eventual migration.
3. **Read cadence fresh each cycle**, the same seam the canary service already uses, so control
   can move to the Scheduler later by changing a setting rather than by code surgery.
4. **No new dispatch path welded into an unrelated request handler.** This gets its own
   service or its own timer — never a bolt-on to a handler already doing something else (the
   exact anti-pattern fact #5 in this ADR's evidence base already names).

### Execution-shape constraints

- Run under the daemon client, not the per-file CLI (above). Must degrade **explicitly** if the
  daemon is unreachable — report reduced/failed capability, never fall back silently to a path
  that cannot finish, and never report a clean result the scan did not actually earn. This is
  hinge (b) requirement #4 (graceful, explicit degradation), applied here.
- Concurrency of one signature-database instance — the binding resource constraint on this
  hardware class, independently measured twice.
- The scan walk must be niced/ioniced: this box also forwards live traffic and runs the
  firewall enforcement path, and a scan must never be able to degrade either.
- Bounded, resumable, and honestly reported — see the truncation note above. An interrupted
  run (restart, shutdown) must be recorded as interrupted, never as completed.
- Systemd unit hardening matching the canary service's existing posture (de-privileged user,
  strict filesystem protection, no new privileges, empty capability set) — with one real
  tension to resolve deliberately, not discover at deploy time: a whole-filesystem *scan* only
  needs read access, but *quarantine* needs to move files anywhere on disk, which that posture
  does not permit. Leaving scheduled-scan findings report-only (matching the canary's existing
  "record and alert, never auto-quarantine" behavior) avoids the conflict; granting broader
  write access is the alternative, and would need its own documented rationale if chosen.
- First-run cost is real on a fresh install (a full pass is long). This should be visible as
  progress in the dashboard, not something silently kicked off during installation.

### Open questions for the operator (not resolved by this amendment)

1. Build this now, as a self-contained scheduler-aware increment ahead of Step 4, or wait for
   the full Scheduler/Execution/Reporting build?
2. Default cadence, and does it ship enabled by default on a fresh install (a multi-hour first
   pass, unprompted) or opt-in (matching the existing pattern where a similarly heavy
   auto-update capability ships disabled until the operator chooses)?
3. Scheduled-scan findings: report-only, or does the quarantine-write-access tension above get
   resolved the other way?
4. Is the hash cache part of the first increment, or deferred to a second pass?

### Cross-reference

Full scoping detail, including the exact resource/timing measurements behind the engine-swap
finding above and the verification plan for whoever builds this, is kept in the private
mirror per Rule 10 (a live, unfixed coverage gap's specifics are attacker-relevant precision,
not architectural direction) — same treatment as this ADR's own Step 3 note above. A related
but independent finding from the same scoping pass — the appliance's UI can create a scan
schedule that will never actually run, distinct from the general architectural fact already
public in this ADR's evidence base (fact #4) — is tracked separately in `PUNCHLIST.md`, not
folded into this amendment.
