# ADR 0003 — Database Resilience & Recovery

- **Status:** Proposed (design decided in planning — no code or data changed)
- **Date:** 2026-06-25
- **Affects:** Core DB layer, write paths, backup, scoring/automation, dashboard surfacing
- **Depends on:** [0001-database-and-module-architecture](0001-database-and-module-architecture.md)
  (single shared DB) — **this design is built AFTER the Pass 0 migration lands.**
- **Related:** [0002-vpn-aware-dns-routing](0002-vpn-aware-dns-routing.md)

> Paths/IPs are sanitized for the public repo. `<INSTALL_DIR>` = the dashboard install
> root (e.g. `/home/<user>/dashboard`); `<DATA_DIR>` = where the shared DB lives;
> `<BACKUP_DIR>` = independent backup storage. No real home paths, usernames, or
> credentials are reproduced.

---

## Context

Nemesis is a **security tool**, so **protection availability is a first-class
requirement**. The architecture already separates two layers:

- **Protection engines** — Suricata (IDS), Pi-hole (DNS filtering), ClamAV (malware
  scanning), and the watchdog's detection loop — run as **separate, DB-independent
  processes**. They keep protecting whether or not the database is reachable.
- **The database** — the **recording + scoring** layer. It stores what the engines
  observed and the scores/decisions derived from it.

The consequence is important and reframes the whole problem: **a DB failure is not a
protection outage.** It is a *recording/scoring-degradation window*. The host keeps
blocking, filtering, and scanning; what is at risk is the **record** of events and the
**scoring/automation** layered on top.

ADR 0001 consolidates all persistent state into **one shared `alerts.db`**. That is the
right design for consistency and backup, but it **concentrates** the recording layer into
a single failure domain — which makes a deliberate resilience design **necessary** rather
than optional. This ADR specifies it.

**Resilience goal:** keep protecting, **lose no recorded data**, recover fast, and
**never fail silently**.

### Alternatives considered and rejected

- **Multi-write / replicated DBs.** Writing every record to two+ DBs adds a **permanent
  consistency tax** on the hot path and a **silent-drift** risk (replicas diverge without
  anyone noticing until restore time). Rejected.
- **Failover-then-merge.** Running a second DB and merging it back after recovery hits the
  **concurrent index-assignment / conflict-resolution** problem — two writers both minting
  "alert #N" and reconciling later is **distributed-consensus territory**, far more
  complexity and failure surface than the problem warrants. Rejected.
- **Keep separate per-module DBs "for isolation."** They do **not** survive the common
  failure modes anyway (same disk, same filesystem, same power event), while costing the
  drift documented in 0001. Rejected.

The design below reaches **zero/near-zero recorded-data loss without any of that**, by
construction: an inert append-only write-ahead log + one tested rebuild path +
corruption-only auto-restore.

---

## Decision

### 1. Failure taxonomy — auto-restore fires ONLY on confirmed corruption

Every DB error is classified into one of three classes; the response differs per class.
Conflating them is the classic way to turn a transient hiccup into a destructive restore.

| Class | Examples | Response |
|---|---|---|
| **Transient / recoverable** | `database is locked`, `database is busy`, timeout | **RETRY with backoff.** Normal under concurrent writers. **Never auto-restore.** WAL mode + `busy_timeout` absorbs most of these. |
| **Confirmed corruption** | `disk image is malformed`, `file is not a database`, failed `PRAGMA integrity_check`/`quick_check` | **The ONLY trigger for auto-restore** (see §4). |
| **Structural / access** | permission denied, **disk full**, file missing | **ALERT LOUDLY, do not auto-restore.** Restore can't write into a full disk or fix permissions — auto-restore would thrash and mask the real cause. |

**Stated rule:** *auto-restore fires only on confirmed corruption.* Transient and
structural failures never trigger it.

### 2. Write-ahead log — the zero-loss mechanism (data, never code)

- **Dual write.** Every write goes to an **append-only flat log file** (`jsonl`/`csv` —
  **inert data**, never an executable script) **and** to the DB.
- **Order: log FIRST, then DB.** Append to the log and confirm it is written **before**
  writing the DB. This guarantees the log is always a **superset** of what reached the DB
  — the safe direction: nothing the DB contains is ever missing from the log, so the log
  can always rebuild the DB.
- **Durability.** **`fsync` the high-value writes** (alerts) so an OS buffer plus a power
  loss cannot lose the last lines; cheaper/high-volume writes (e.g. routine hw_metrics)
  may **batch** their sync. *Tradeoff:* per-record fsync costs IOPS/latency, so sync
  granularity is tuned per write class (see Open Questions).
- **Idempotent replay.** Replay uses **`INSERT … ON CONFLICT IGNORE` / upsert keyed on the
  record's index/id**, so replaying a log that overlaps rows already in the DB is **always
  safe** (no duplicates, no clobber). *This is the real job of the per-record index —
  **idempotent replay, not merge.*** There is no conflict resolution because there is only
  one writer and one log; the index just makes replay re-runnable.
- **Principle: DATA IS DATA, CODE IS CODE.** The log is **inert** and only ever **parsed,
  never executed.** A self-executing "recovery file" is explicitly **rejected**: it would
  (a) couple data corruption to *broken recovery logic* (a corrupt log could no longer be
  trusted to run), and (b) create an **auto-executing payload surface on a security
  product**. Recovery logic lives in versioned service code (§3), never in the data.

### 3. Recovery path — one tested function, centralized logic

- A single, tested **`recover_from_log(logfile) -> rebuilt_db`** is **THE** one recovery
  path. **Auto-restore** calls it; the **manual "Rebuild/Restore DB"** settings action
  calls it; **tests** call it. Recovery logic is **not scattered** across call sites.
- Replay is done in **bulk** — a single transaction with bulk inserts — for speed, rather
  than row-by-row.

### 4. Auto-restore safety rules — when it IS right to fire

When (and only when) §1 confirms corruption:

1. **Preserve the corrupt DB.** Move it aside as `alerts.db.corrupt.<ts>` — **never
   delete.** Keeps forensics and gives a second chance if the backup is also bad.
2. **Verify before swap.** Run `PRAGMA integrity_check` on the **backup/restore target
   BEFORE** swapping it in. Never replace a corrupt DB with an unverified one.
3. **Restore-loop guard.** If auto-restore fires **more than once in a short window**,
   **STOP auto-restoring and escalate to a loud alert.** A repeating restore means the
   cause is systemic (bad disk, bad RAM) and restore cannot fix it — don't thrash.
4. **Quiesce writes during the swap.** Pause DB **writes** for the swap window; the
   **engines keep running** and their writes **queue to the write-ahead log** (§2), so no
   record is lost while the file is replaced. Replay the queued tail after the swap.

### 5. Backup cadence

- **Frequent SQLite-safe snapshots** via the SQLite **backup API** / `VACUUM INTO` /
  WAL-checkpoint — **never a raw `cp`/`tar` of a live WAL DB** (the failure mode flagged in
  0001's current backup path).
- **Integrity-checked at creation.** Run `integrity_check` on each snapshot **when it is
  made** — validate the restore target *before* you ever need it, not during an incident.
- **Keep last N**, on **independent storage** (separate disk or another host), so a
  same-disk failure doesn't take the backups with the primary.
- **Cadence sets the RPO** (max data loss between snapshots); the write-ahead log closes
  the gap to **~zero** between snapshots. **Proposed starting cadence: every 15–30 min,
  tunable.**

### 6. Graceful degradation + loud surfacing (security-grade requirements)

- **Degrade, don't die.** Scoring/automation must fall back to **safe defaults / heuristic
  mode** when the DB is briefly unavailable, never crash the watchdog or ticket path.
  Examples: anomaly scoring → **threshold fallback**; relevance scoring → mark
  **"unscored, will score on recovery"** and continue. The detection/protection path never
  blocks on the DB.
- **Surface loudly.** The dashboard must **prominently** show the failure and the
  recovery: *"Recovered from backup at HH:MM — possible data-loss window HH:MM–HH:MM,"* or
  *"DB error detected, auto-restore OFF, manual action needed."* **No silent recovery** —
  for a security tool a silent gap in the record is nearly as dangerous as the failure
  itself.

### 7. Gate irreversible automated actions while degraded

While running on **fallback/degraded scoring**, **PAUSE/queue any IRREVERSIBLE automated
action** for human confirmation — e.g. **AbuseIPDB auto-report**, **automated IP block**.
Do not fire an **unrecoverable** action on a **degraded** score. This **targeted gating**
is what replaces the need for a replica cluster: instead of guaranteeing perfect scoring
at all times (expensive, complex), we guarantee we **never take an irreversible action on
untrustworthy data**.

### Settings surface

- **Auto-restore toggle** — disclosed to the user, **conservative default** (corruption-
  only triggering per §1).
- **Manual "Restore/Rebuild DB" action** — always available; user picks a snapshot;
  **two-step confirm** (it overwrites live data); show the **snapshot timestamp vs. now**
  so the user sees the potential data-loss window before confirming.

---

## Consequences

**Positive**
- The host **keeps protecting** through any DB failure (engines are DB-independent).
- **Zero / near-zero recorded-data loss**: log-first ordering + idempotent replay + frequent
  integrity-checked snapshots.
- **No replica complexity, no merge, no consensus** — the rejected designs' costs are
  avoided by construction.
- **One tested recovery path** shared by auto-restore, manual restore, and tests.
- **Fails loudly, never silently**; irreversible actions are gated while degraded, so a bad
  score can't cause an unrecoverable mistake.

**Negative / cost**
- A **write-ahead-log write on the hot path** plus **fsync tuning** per write class
  (throughput vs. durability).
- **Degradation handling** must be built into each scoring/automation path (anomaly,
  relevance, auto-report/block), not just the DB layer.
- **Gating logic** adds a queue + human-confirm step for irreversible actions while degraded.
- Snapshot storage + integrity checks consume some IO and **independent storage**.
- **Sequencing:** this is built **after** the 0001 Pass-0 migration lands (it assumes the
  single shared DB and the SQLite-safe backup path).

---

## Open Questions

- **fsync granularity vs. throughput** — exactly which write classes force-sync (alerts
  certainly; what about correlation events, hw_metrics, anomaly baseline updates?).
- **Backup cadence / retention count** — the concrete RPO target and how many snapshots to
  keep (15–30 min is a starting proposal, not final).
- **Independent storage location by default** — separate disk vs. another host, and how the
  installer discovers/configures it without leaking host specifics.
- **Write-ahead log lifecycle** — does the log itself need **rotation/size capping**, and
  how is it **pruned** after a successful, integrity-checked snapshot (so it doesn't grow
  unbounded) while still covering the gap since the last snapshot?
