# Roadmap — Data retention: enforcement gap, shared invariant, and Tier A scope

- **Status:** **AUDIT + FIX, 2026-09-05.** The `top_processes` enforcement gap this doc
  was written to record is **CLOSED on this appliance** (§1a, verified evidence). The
  larger gap it uncovered — **no Nemesis install anywhere ships automated retention
  enforcement, for either table** — is **OPEN** and scoped as its own follow-up (§6.1).
  Follow-up to [[data-retention-and-archival-policy]],
  [[hw-anomaly-snapshots-top-processes-archival]] and
  [[storage-monitoring-retention-supplement-2026-08-03]].
- **The audit half was read-only** (Rule 1) and the archiver was not run during it, not
  even in `dry_run`. Every pre-fix figure comes from independent read-only SQL, not from
  invoking a production code path. The fix was a separate, explicitly-authorised pass with
  a state snapshot taken first.

## 1. The enforcement gap (primary finding)

`archive_old_top_processes()` — `core_module/hw_monitor/hw_monitor.py:1492` — **had zero
callers.** The only two references to it anywhere in the tree were its own `def` and a
comment pointing at it. No timer, no systemd unit, no entry in `scripts/`, no call site.

It was invoked once, by hand, on 2026-08-03. It did not run again for 33 days.

Its declared retention window is `TOP_PROC_ARCHIVE_DAYS = 14`. Measured 2026-09-05,
immediately before the fix:

| | |
|---|---|
| Rows past the 14-day window, blob still live | **31,975** |
| Bytes past their own retention window | **64.0 MB** |
| Rows holding a `top_processes` blob at all | 44,339 (88.7 MB) |
| Rows carrying an archive pointer (`top_processes_ref`) | 18,010 — all from the single manual run |
| Oldest blob still live | **2026-07-20 — 47 days, 3.4× the declared window** |
| Accrual | ~850 rows/day, ~1.7 MB/day |

**Why this was invisible.** The August run was real and its numbers were real, so the table
genuinely shrank, and every subsequent check of the *mechanism* — the archive format, the
round-trip verification, the code — passed. Nothing in the codebase distinguished "this
function is correct" from "this function is being called." The roadmap header said SHIPPED
because the build shipped, which was true. What never shipped was the schedule.

### ⛔ 1a. CORRECTION — the gap is far wider than first reported

**The first version of this document contained the very error its §3 warns about, one
section later.** It stated that the sibling `dm_operation_log` coalescer "is scheduled" and
used that as the contrast proving `top_processes` was a one-off oversight. That contrast
was drawn from the RUNNING SYSTEM and stated as a property of the PRODUCT. It is true of
this appliance and false of every other one.

**`install.sh` has no timer-handling logic at all.** Verified: the file contains **zero**
occurrences of `scripts/systemd`. Its unit-deployment loop iterates a hardcoded 9-name
`svc_names` list (`nemesis-fwd`, `dashboard`, `watchdog`, `hw-monitor`, `alert-watcher`,
`device-scanner`, `malware-canary`, `diagnostics-watcher`, `vpn-dns-guard`) and installs
only `${svc}.service`. **The string `.timer` never appears in the deployment path.**

Consequently these units exist in the repo and reach no user:

| Unit | In repo | Installed by `install.sh` |
|---|---|---|
| `nemesis-oplog-coalesce.service` / `.timer` | yes | **no** |
| `nemesis-cert-renew.service` / `.timer` | yes | **no** |
| `nemesis-fw-guard-boot.service` | yes | **no** |
| `nemesis-top-processes-archive.service` / `.timer` | yes (new, §1b) | **no** |
| `nemesis-drift-check` | **script only — no unit file in the repo at all** | **no** |

Every timer on this appliance was installed by hand. The mtimes record it: the repo copy of
`nemesis-oplog-coalesce.timer` was written at 16:36 and the `/etc/systemd/system` copy at
16:39 the same day.

**The honest finding, replacing the one this doc opened with: no Nemesis installation
anywhere has automated retention enforcement for either table.** `dm_operation_log`'s
coalescer is not a working contrast — it is the same failure, one layer further out, and it
is invisible from this box precisely because someone here already worked around it.

Scoped as its own follow-up in §6.1. Deliberately **not** folded into the fix below: it
changes a loop governing nine services plus four orphaned units, and bundling it would have
made a one-table fix into a rewrite of the installer's unit handling.

### 1b. The fix, deployed and verified 2026-09-05

Commit `e54df43`. Ships `scripts/nemesis-top-processes-archive` plus
`nemesis-top-processes-archive.service`/`.timer` (daily, `Persistent=true`, running as
`nemesis-hwmon`), and — more importantly — the **window-liveness check** that would have
caught the gap in the first place (§3).

Verified by re-reading live state, not by trusting the job's own report:

```
16:53:21  before: 31975 rows / 64.0 MB past the 14-day window (oldest 2026-07-20T00:01:40)
          {'status': 'ok', 'archived': 31975, 'bytes': 63950000,
           'file': 'hw_anomaly_top_processes_2026-09-05-165320.jsonl.gz'}
16:53:21  after:  0 rows / 0.0 MB past the 14-day window (oldest None)
16:53:28  before: 0 rows ... archived: 0 ... after: 0 rows      <- idempotent on re-run
```

Independent confirmation by direct SQL (a different query from the archiver's own):

| Check | Result |
|---|---|
| Rows past the 14-day window | **0** |
| Total rows before → after | 62,373 → 62,385 — **zero deleted**, 12 newly collected |
| Rows carrying an archive ref | 18,010 → **49,985** (exactly +31,975) |
| Rows holding BOTH a blob and a ref | **0** — no half-completed archival |
| Archive file | 31,975 rows, 63,950,000 payload bytes, 1.5 MB on disk (43:1) |
| `test_retention_window.py` | **17/17**, having failed only on the live check beforehand |

The row-count line is the one that matters most: **archival moved payload and deleted
nothing**, which is the principle in §2 holding under a real 64 MB run.

## 2. The shared invariant (the standard any future table's treatment must meet)

Both implementations already follow the same ordering, and it is the property that makes
them safe. Stated here so it is a standard rather than a coincidence:

> **Write the archive → re-open it from disk → compare it row-by-row against the live
> values → and only then clear the live column.** Any failure at any step leaves the live
> data exactly as it was.

`hw_monitor.py:1539` calls `verify_archive(...)`; `hw_monitor.py:1541` aborts with live data
untouched if it fails; the clear at `hw_monitor.py:1548` is unreachable except on the
verified path. The `dm_operation_log` side uses the same `write_archive_manifested` /
`verify_archive` pair in `alert_manager/data_manager.py` (manifest plus a sha256 over the
compressed bytes). The archiver also refuses to run at all if its own verifier self-test
fails (`hw_monitor.py:1506`) — "prove your own premise" applied in the production path, not
merely in a test.

**The retention principle this serves, stated explicitly and non-negotiably:**

> **Archived data is never automatically permanently deleted. It is only ever MOVED, with a
> pointer left behind. Permanent deletion stays an explicit user action.**

The schema encodes this: `top_processes_ref` (`hw_monitor.py:269`) holds the archive
filename once the blob has moved, and **the row itself never leaves the table**. A future
reaper that deletes rows rather than relocating payload would violate this principle
regardless of how much space it saved. Measured proof from the 2026-09-05 run: 31,975 rows
had their payload relocated and **not one row was removed**.

## 3. "Scheduled or it doesn't exist" — the generalizable rule

**An archival or retention function without a scheduled invocation is an unshipped policy,
however well-written the function is.** A retention mechanism makes a claim about live state
over time; code that is never called makes no such claim.

Same family as the standing "a new branch needs a test that EXERCISES it, not one that
could", and as the 2026-09-05 rule about open-items lists needing a liveness re-check rather
than a copy-forward. In each case the artifact looks complete and is internally correct,
while the thing that would make it *true of the running system* is absent — and nothing
about its appearance reveals that.

**What to require, for any retention/archival work:**

- **The unit ships in the same commit as the function.** Not "wire it up later" — later is
  where this one went, for 33 days.
- **And confirm the installer actually deploys it.** §1a is what happens when this step is
  skipped: a unit can sit in the repo, correct and reviewed, and reach nobody.
- **A definition of done that names the schedule**, not just the mechanism. "Archives aged
  blobs correctly" is not done; "runs daily and the window holds" is.
- **Verify the WINDOW, not the CODE.** The check that would have caught this is one query:
  *is there data older than the declared retention window?* It needs no knowledge of how the
  archiver works, and it keeps failing if the timer is later disabled or masked — which no
  code-level test would notice. Shipped as
  `hw_monitor.top_processes_retention_status()` + `test_retention_window.py`, and wired into
  the scheduled job itself, which exits **3** if the window is still violated after a
  successful run.
- **The check must NOT inherit the mechanism's own predicate.** `archive_old_top_processes`
  filters on `top_processes_ref IS NULL`; the window check deliberately does not, so a row
  holding both a blob and a ref — meaning archival half-completed — stays visible to the very
  check meant to catch archival going wrong.
- **A doc status of SHIPPED must mean the policy is in effect**, not that the build landed.

## 4. Tier A inventory (measured 2026-09-05, live DB, read-only)

Database total at audit time: **609.6 MB**. Two tables and their indexes were ~94% of it.

| Object | MB | % DB | Rows | Rows/day | Treated? |
|---|---|---|---|---|---|
| `hw_anomaly_snapshots` | 256.0 | 42.0% | 62,355 | 831 | **yes, as of 2026-09-05** (§1b) |
| `dm_operation_log` | 155.0 | 25.4% | 2,207,432 | 53,583 | code yes; **not installed for users** (§1a) |
| `idx_dmlog_mod` | 118.5 | 19.4% | — | — | (index of the above) |
| `idx_dmlog_ts` | 43.1 | 7.1% | — | — | (index of the above) |
| `hw_metrics` | 22.1 | 3.6% | 22,968 | 303 | no — not needed yet |
| `audit_log` (+ index) | 5.3 | 0.9% | 32,710 | 473 | no — Tier A, infinite by design |
| `correlation_events` | 1.4 | 0.2% | — | — | no |
| `tickets` | 0.7 | 0.1% | — | — | no — Tier A |
| `login_events` | <0.1 | ~0% | 213 | 3 | no — Tier A |
| everything else | <1.5 each | — | — | — | no |

**Conclusion: no table beyond the existing two needs archival treatment.** The honest scope
finding is *not* "generalise the pattern to more tables" — the pattern is already where it
needs to be. The gap was enforcement, and §1a shows it is wider than one table.

Thresholds at which this changes, so the next audit inherits a number rather than a
judgment:

- **`hw_metrics`** — 303 rows/day, ~0.29 MB/day, ~106 MB/year. Revisit past **50 MB** or a
  row rate above ~1,000/day. Not urgent.
- **`audit_log`** and **`login_events`** — Tier A, deliberately unbounded; their retention is
  a *feature*. At 473 and 3 rows/day they cost ~5 MB and ~0.02 MB. The work here remains what
  [[data-retention-and-archival-policy]] item 3 already says: **a guard so a future reaper
  cannot accidentally cap them**, not a retention feature.
- **Any new table** crossing **1 MB/day** sustained.

**`dm_operation_log`'s size is an ingest question, not a retention one.** Its 7-day window
holds on this box — 5,717 rows survive past 30 days out of 2,207,432 — but see §1a: that is
true here only because the timer was hand-installed. It is large because it ingests 53,583
rows/day on average, with spikes far above: 921,431 rows on 2026-09-03 and 755,389 on
2026-09-02 against a ~67,000–128,000/day baseline. Those ~10× spikes are **not investigated
here** (§6.4). Its two indexes also cost 161.6 MB — **more than the 155.0 MB table they
index** (§6.5).

## 5. Archival reclaims payload, not file size

Measured before the fix, `hw_anomaly_snapshots` occupied **256.0 MB of pages holding 97.5 MB
of live payload — 38% page utilisation.** The freelist was effectively empty (6 pages), so
pages freed by the August archival were not left unused; they stayed with the table as
intra-page slack and were partially reused by later inserts.

**The 2026-09-05 run confirmed this directly and made it starker.** Clearing 64.0 MB of blob
from 31,975 rows:

| | Before run | After run |
|---|---|---|
| `hw_anomaly_snapshots` pages | 256.0 MB | **256.2 MB** |
| live payload in those pages | 97.5 MB | **35.2 MB** |
| page utilisation | 38% | **14%** |
| database file on disk | 609.6 MB | **610.1 MB** |

**The file did not shrink. It grew slightly.** Roughly **221 MB** of that table is now slack.
The "34.4 MB → 837 KB" figure in [[hw-anomaly-snapshots-top-processes-archival]] is a *column
payload* measurement and correct as such — it should not be read as a reduction in database
file size, and this doc corrects that reading rather than the number.

Returning slack to the filesystem requires `VACUUM` (or `VACUUM INTO`), a **state-changing
operation on live data**, out of scope here and tracked as §6.3. Recorded so the space is
known to be recoverable rather than silently written off, and so nobody expects a future
archival run to shrink the file on its own.

## 6. Open items

1. **⚠ `install.sh` timer support (§1a) — the largest item here, and the one that makes
   this fix real for anyone other than this appliance.** `install.sh` deploys no timers at
   all; `nemesis-oplog-coalesce`, `nemesis-cert-renew`, `nemesis-fw-guard-boot` and the new
   `nemesis-top-processes-archive` all sit in the repo unreachable by any install. Scope
   includes: a `.timer` path in the deployment loop, deciding whether `svc_names` stays a
   hardcoded list, `systemctl enable` for timers, and **adding `nemesis-drift-check`'s unit
   file to the repo at all** — it exists only on this box. Separately scoped deliberately:
   it touches nine services plus four orphaned units.
2. **A window-liveness check for `dm_operation_log`** per §3. Not a copy of the
   `top_processes` one: its retention is coalescing, not clearing, and human-actor rows are
   deliberately retained forever, so the predicate must exempt them. A naive "no rows past
   the window" check would false-positive on exactly the rows the design protects.
3. **`VACUUM` pass** to reclaim the ~221 MB of intra-page slack in §5. Separate; requires a
   snapshot.
4. **`dm_operation_log` ingest spikes** (§4) — uninvestigated. Worth asking whether the
   writer should sample at source rather than relying on downstream coalescing.
5. **`dm_operation_log` index cost** (§4) — 161.6 MB of index against a 155.0 MB table.
6. **Tier A reaper guard** — carried forward unchanged from
   [[data-retention-and-archival-policy]] item 3; still unbuilt, still not urgent.
