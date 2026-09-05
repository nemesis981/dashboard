# Roadmap — Data retention: enforcement gap, shared invariant, and Tier A scope

- **Status:** SCOPE / AUDIT, 2026-09-05. Read-only audit (Rule 1) — nothing was changed,
  and the archiver was not run, not even in `dry_run` mode. Every figure below comes from
  independent read-only SQL against the live `alerts.db`, not from invoking a production
  code path. Follow-up to [[data-retention-and-archival-policy]],
  [[hw-anomaly-snapshots-top-processes-archival]] and
  [[storage-monitoring-retention-supplement-2026-08-03]].
- **Primary finding: a retention policy that shipped as code and was never enforced.**
  Detail in §1. This supersedes
  [[hw-anomaly-snapshots-top-processes-archival]]'s unqualified SHIPPED header.

## 1. The enforcement gap (primary finding)

`archive_old_top_processes()` — `core_module/hw_monitor/hw_monitor.py:1492` — **has zero
callers.** The only two references to it anywhere in the tree are its own `def` and a
comment at `hw_monitor.py:281` pointing at it. There is no timer, no systemd unit, no
entry in `scripts/`, and no call site in any service.

It was invoked once, by hand, on 2026-08-03. It has not run since.

Its own declared retention window is `TOP_PROC_ARCHIVE_DAYS = 14`
(`hw_monitor.py:1468`). Measured against live data on 2026-09-05:

| | |
|---|---|
| Rows past the 14-day window, blob still live | **31,975** |
| Bytes past their own retention window | **64.0 MB** |
| Rows holding a `top_processes` blob at all | 44,339 (88.7 MB) |
| Rows carrying an archive pointer (`top_processes_ref`) | 18,010 — all from the single manual run |
| Oldest blob still live | **2026-07-20 — 47 days, 3.4× the declared window** |
| Accrual | ~850 rows/day, ~1.7 MB/day |

**Why this was invisible.** The August run was real and its numbers were real, so the
table genuinely shrank, and every subsequent check of the *mechanism* — the archive
format, the round-trip verification, the code — passed. Nothing in the codebase or the
docs distinguishes "this function is correct" from "this function is being called." The
roadmap header said SHIPPED because the build shipped, which was true; what did not ship
was the schedule.

**The contrast that proves this is an omission, not a design choice.** The sibling
mechanism for `dm_operation_log` is the same author, the same archive-then-verify-then-
clear discipline, the same "move never delete" rule — and it *is* scheduled:

| | `dm_operation_log` coalescer | `top_processes` archiver |
|---|---|---|
| Window | `OP_LOG_ARCHIVE_DAYS = 7` | `TOP_PROC_ARCHIVE_DAYS = 14` |
| Scheduled | **Yes** — `nemesis-oplog-coalesce.timer`, daily | **No** — no unit exists |
| Last run | 2026-09-05 00:13:30 | 2026-08-03, by hand |
| Window actually held? | **Yes** — 5,717 rows survive past 30 days out of 2,207,432 | **No** — oldest blob is 47 days old |

There is no design difference between the two. There is a missing unit file.

## 2. The shared invariant (the standard any future table's treatment must meet)

Both shipped implementations already follow the same ordering, and it is the property
that makes them safe. Stated here so it is a standard rather than a coincidence:

> **Write the archive → re-open it from disk → compare it row-by-row against the live
> values → and only then clear the live column.** Any failure at any step leaves the live
> data exactly as it was.

`hw_monitor.py:1539` calls `verify_archive(...)` and `hw_monitor.py:1541` aborts with the
live data untouched if it fails; the clear at `hw_monitor.py:1548` is unreachable except
on the verified path. The `dm_operation_log` side uses the same
`write_archive_manifested` / `verify_archive` pair in `alert_manager/data_manager.py`
(manifest plus a sha256 over the compressed bytes). The archiver also refuses to run at
all if its own verifier self-test fails (`hw_monitor.py:1506`) — the
"prove your own premise" discipline applied in the production path, not just in a test.

**The retention principle this serves, stated explicitly and non-negotiably:**

> **Archived data is never automatically permanently deleted. It is only ever MOVED, with
> a pointer left behind. Permanent deletion stays an explicit user action.**

The schema already encodes this: `top_processes_ref` (`hw_monitor.py:269`) holds the
archive filename once the blob has moved, and **the row itself never leaves the table**.
A future reaper that deletes rows rather than relocating payload would violate this
principle regardless of how much space it saved.

## 3. "Scheduled or it doesn't exist" — the generalizable rule

**An archival or retention function without a scheduled invocation is an unshipped
policy, however well-written the function is.** A retention mechanism makes a claim about
live state over time; code that is never called makes no such claim.

This is the same family as the standing "a new branch needs a test that EXERCISES it, not
one that could" practice, and the same family as the 2026-09-05 handoff rule about
open-items lists needing a liveness re-check rather than a copy-forward. In each case the
artifact looks complete and is internally correct, while the thing that would make it
*true of the running system* is absent — and nothing about its appearance reveals that.

**What to require, for any retention/archival work:**

- **The unit ships in the same commit as the function.** Not "wire it up later" — later is
  where this one went.
- **A definition of done that names the schedule**, not just the mechanism. "Archives aged
  blobs correctly" is not done; "runs daily and the window holds" is.
- **Verify the WINDOW, not the CODE.** The check that would have caught this is one query:
  *is there data older than the declared retention window?* It needs no knowledge of how
  the archiver works, and it fails loudly the moment the schedule stops — including if the
  timer is later disabled, which no code-level test would notice.
- **A doc status of SHIPPED must mean the policy is in effect**, not that the build landed.

## 4. Tier A inventory (measured 2026-09-05, live DB, read-only)

Database total: **609.6 MB**. Two tables and their indexes are ~94% of it.

| Object | MB | % DB | Rows | Rows/day | Treated? |
|---|---|---|---|---|---|
| `hw_anomaly_snapshots` | 256.0 | 42.0% | 62,355 | 831 | code yes, **schedule NO** |
| `dm_operation_log` | 155.0 | 25.4% | 2,207,432 | 53,583 | **yes** |
| `idx_dmlog_mod` | 118.5 | 19.4% | — | — | (index of the above) |
| `idx_dmlog_ts` | 43.1 | 7.1% | — | — | (index of the above) |
| `hw_metrics` | 22.1 | 3.6% | 22,968 | 303 | no — not needed yet |
| `audit_log` (+ index) | 5.3 | 0.9% | 32,710 | 473 | no — Tier A, infinite by design |
| `correlation_events` | 1.4 | 0.2% | — | — | no |
| `tickets` | 0.7 | 0.1% | — | — | no — Tier A |
| `login_events` | <0.1 | ~0% | 213 | 3 | no — Tier A |
| everything else | <1.5 each | — | — | — | no |

**Conclusion: no table beyond the existing two currently needs archival treatment.** The
honest scope finding is *not* "generalise the pattern to more tables" — the pattern is
already where it needs to be. The gap is enforcement.

Thresholds at which this changes, so the next audit has a number rather than a judgment:

- **`hw_metrics`** — 303 rows/day, ~0.29 MB/day, ~106 MB/year. Revisit if it passes
  **50 MB** or if its row rate exceeds ~1,000/day. Not urgent.
- **`audit_log`** and **`login_events`** — Tier A, deliberately unbounded. Their retention
  is a *feature*. At 473 and 3 rows/day they cost ~5 MB and ~0.02 MB respectively. The
  work here remains what [[data-retention-and-archival-policy]] item 3 already says it is:
  **a guard so a future reaper cannot accidentally cap them**, not a retention feature.
- **Any new table** crossing **1 MB/day** sustained.

**`dm_operation_log`'s size is an ingest question, not a retention one.** Its 7-day window
is genuinely holding. It is large because it ingests 53,583 rows/day on average, with
spikes far above that — 921,431 rows on 2026-09-03 and 755,389 on 2026-09-02 against a
~67,000–128,000/day baseline. Those ~10× spikes are **not investigated here** and are
flagged as a separate question: what produced them, and should the writer be sampling at
source rather than relying on downstream coalescing. Note also that its two indexes cost
161.6 MB — **more than the 155.0 MB table they index** — which is its own reviewable
question, independent of retention.

## 5. Archival reclaims payload, not file size — a separate, deliberate decision

Measured 2026-09-05: `hw_anomaly_snapshots` occupies **256.0 MB of pages holding 97.5 MB
of live payload — 38% page utilisation.** The database's freelist is effectively empty
(6 pages), so the pages freed by the August archival were not left unused; they were
retained by the table as intra-page slack and partially reused by later inserts.

The practical consequence: **clearing a 2,000-byte column from 18,010 rows shrank what
those rows contain, not what the file occupies.** The "34.4 MB → 837 KB" figure recorded
in [[hw-anomaly-snapshots-top-processes-archival]] is a *column payload* measurement and
is correct as such — it should not be read as a reduction in database file size, and this
doc corrects that reading rather than the number.

Returning that slack to the filesystem requires `VACUUM` (or `VACUUM INTO`), which is a
**state-changing operation on live data** and therefore out of scope for this audit
entirely. It needs its own scoped pass under the State Snapshots discipline. Recorded
here so the space is known to be recoverable and is not silently written off, and so that
a future run of the archiver is not expected to shrink the file on its own.

## 6. Open items this doc creates

1. **Wire a schedule for `archive_old_top_processes()`** — the fix for §1. Scoped
   separately, deliberately not done in this pass (Rule 1). **Priority: genuine, not
   routine** — 64.0 MB of live data is currently past its own declared retention window,
   the oldest by 3.4×, and the backlog grows ~1.7 MB/day for as long as this is open.
2. **A window-liveness check** per §3 — one query per retention-managed table asserting no
   data survives past its declared window. This is what makes §1 impossible to repeat, and
   it is worth more than the fix itself.
3. **`VACUUM` pass** to reclaim the ~158 MB of intra-page slack in §5 — separate, requires
   a snapshot.
4. **`dm_operation_log` ingest spikes** (§4) — uninvestigated, flagged.
5. **`dm_operation_log` index cost** (§4) — 161.6 MB of index against a 155.0 MB table.
6. **Tier A reaper guard** — carried forward unchanged from
   [[data-retention-and-archival-policy]] item 3; still unbuilt, still not urgent.
