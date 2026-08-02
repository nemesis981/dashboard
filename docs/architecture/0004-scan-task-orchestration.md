# ADR 0004 — Scan & Task Orchestration

- **Status:** **BUILD-READY — hinge questions (a)/(b)/(c) resolved** (2026-08-02). Design of
  record for the Scheduler/Execution/Reporting separation and the `scan_*`/`malware_findings`
  migration. Build not started except **Step 1 of the sequence below (YARA auto-update +
  cross-platform path exclusions, then its routes/SSRF-guard/rate-limit/UI), all of which
  landed the same day** this ADR was resolved. See "Status / next" for the full sequence and
  gating.
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

Direction and all three hinge questions resolved 2026-08-02. Step 1 of the sequence above has
shipped in full — the auto-update mechanism, the path-exclusion list, and its routes/SSRF-
guard/rate-limit/UI (M2) — usable on this box today; Steps 2–4 are unbuilt. Next step is
Step 2 (actor seam + time convention on the `scan_*` tables), then Step 3 (agent heartbeat
authentication) before Step 4 begins the actual Scheduler/Execution/Reporting build, the
`scan_threats` → `malware_findings` migration, and generalizing Step 1's distribution channel
fleet-wide per requirement (b).2 above.
