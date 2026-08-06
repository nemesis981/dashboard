# ADR 0001 — Database & Module Architecture: Restoring the Single Shared DB

- **Status:** **Partially implemented** (verified 2026-07-25 — code + `git log` re-check, header
  was stale). **Stages 0–3 SHIPPED**: all four modules (tickets `6f6b6c3`, community_queue
  `290c2db`, ai_engine `181c14c`, malware_detection pre-existing) cut over to the shared
  `alert_manager/alerts.db` via the shared accessor; old module `.db` files are unreferenced.
  **Stage 4 (dedupe + retire 0-byte ghosts) DONE**: `quarantines`/`hw_alerts`/`scan_jobs` each
  have exactly one `CREATE TABLE` owner; the orphaned 0-byte `dashboard.db` and
  `malware_detection/malware.db` are gone. **Stage 5 (SQLite-safe single-DB backup + discover
  service units) NOT done** — `dashboard.py:36` still hardcodes `HEALTH_SERVICES` rather than
  scanning `*.service` units. **Stage 6 (retire old module DBs) NOT done** — `ai_engine.db`,
  `tickets.db`, `community_queue.db` still on disk, unreferenced but not archived/deleted.
- **Date:** 2026-06-25 (implementation verified 2026-07-25)
- **Affects:** Core DB layer, all modules, backup, install/deploy
- **Related:** [0002-vpn-aware-dns-routing](0002-vpn-aware-dns-routing.md)

> Paths are sanitized for the public repo. `<INSTALL_DIR>` = the dashboard install
> root (e.g. `/home/<user>/dashboard`); `<USER>` = the install user. No real home
> paths, usernames, or credentials are reproduced.

---

## Context

`ARCHITECTURE.md` documents **one shared `alerts.db`** holding alerts, anomaly, hw_*,
devices, agents, malware_*, and scan tables. The code has **drifted** from that into an
inconsistent hybrid: most subsystems use the shared DB, but three modules carry their
own separate SQLite files, two orphaned 0-byte DBs sit on disk, several tables are
created by more than one place, and backup/deploy logic hardcodes lists that should be
discovered.

### 1. Database inventory (filesystem truth, this audit)

**REAL / populated**

| Path | Size | Notable tables (row counts) |
|---|---|---|
| `alert_manager/alerts.db` | 11.5 MB | **shared core** — `alerts`(5), `alert_notes`(4), `anomaly_baseline`(2728), `anomaly_state`(3), `anomaly_ai_cache/usage`, `anomaly_incidents/recurrence/abuseipdb_dedup`, `correlation_events`(534), `devices`(25), `agent_devices`, `hw_metrics`(1109), `hw_anomaly_snapshots`(2353), `hw_alerts/cooldowns/notifications`, `fan_status`(10), `ip_enrichment`(1), `malware_findings`(5), `malware_settings`(10), `modules_enabled`(4), `quarantines`(0), `scan_jobs/threats/queue/schedules/conditions` |
| `modules/ai_engine/ai_engine.db` | 45 KB | `ai_settings`(2 — real config), `ai_cache`(0), `ai_usage`(0), `ai_rate_state`(0) |
| `modules/tickets/tickets.db` | 40 KB | `tickets`(3 — real data), `ticket_seq`(1), `settings`(0) |
| `modules/community_queue/community_queue.db` | 20 KB | `community_queue`(0 — schema only) |

**GHOST / 0-byte (orphans)**

| Path | Size | Status |
|---|---|---|
| `modules/malware_detection/malware.db` | 0 B | No current writer; malware module now writes the shared DB |
| `dashboard.db` (repo root) | 0 B | No code references it at all |

Both ghosts are untracked (gitignored), reference-able by **no current code path**, and
are leftovers of earlier `__file__`/CWD-relative path drift that has since been partly
corrected (e.g. the malware module's `DB_PATH` now points at the shared `alerts.db`). The
empty files were simply never cleaned up. Confirmed: the known set in the task is
accurate and I found **no additional** DBs.

### 2. DB-path computation: no single accessor (root cause)

There is **no central DB_PATH accessor**. At least **ten** files each independently
recompute the shared path as `<their dir>/alerts.db` (or a `../../` walk to it):
`alert_manager/database.py:6`, `hw_monitor.py:24`, `alert_watcher.py:24`,
`device_scanner.py:10`, `ip_enrichment.py:10`, `watchdog.py:26`,
`modules/anomaly_detection/module.py:48`, `modules/malware_detection/module.py:43`,
and `dashboard.py:67` (`DB_PATH = os.path.join(_HERE, "alert_manager", "alerts.db")` —
the de-facto "main" one). Diagnostics/tests go further and **hardcode absolute home-dir
paths** (`diagnostics/alert_summary.py:17`, `anomaly_state.py:17`,
`network_devices.py:16`, `test_anomaly_cleanup.py:9`, `alert_manager/test_quarantine.py:32`),
which both leak the home dir and duplicate the constant.

**Self-computed module DB paths (the drift):**
- `modules/ai_engine/module.py:28` → `_HERE/ai_engine.db`
- `modules/community_queue/module.py:29` → `_HERE/community_queue.db`
- `modules/tickets/module.py:39` → `os.path.dirname(__file__)/tickets.db` (and `:41`
  separately walks `../../alert_manager/alerts.db` as `_ALERTS_DB` for cross-reads)

**Core reaching into a module's private DB (verified current location):**
`dashboard.py:1507–1508` computes `_ai_db_path = os.path.join(_HERE, "modules",
"ai_engine", "ai_engine.db")` and opens it directly to read `ai_settings` — bypassing
both any central accessor *and* the module's own API. (The supplemental's "~1507" is
accurate; the central `DB_PATH` is at `dashboard.py:67`, not `:67`-area only — confirmed.)
Tellingly, the very next block (`dashboard.py:1538`) reads anomaly settings correctly
from the shared `DB_PATH`, so the two patterns sit side by side.

**Why the drift exists (the lever to fix it):** `modules_loader.init(app, DB_PATH,
MODULES_DIR)` *receives* the shared path and stores it (`modules_loader.py:42`,
`_db_path`), but `NemesisModule.__init__(self, manifest)` (`modules/__init__.py`) is
handed **only the manifest — never the DB path**. Modules are given no shared handle, so
each one invents its own. The loader has the single source of truth and simply doesn't
forward it.

### 3. Schema-creation map (every `CREATE TABLE`)

- **Shared `alerts.db` (correct):** `alerts`(database.py:12); all `hw_*`, `fan_status`,
  `correlation_events`, `agent_devices`, `scan_*`(hw_monitor.py); `ip_enrichment`
  (ip_enrichment.py:26); `quarantines`(alert_watcher.py:54); `audit_log`(dashboard.py:420);
  `modules_enabled`(modules_loader.py:107); `anomaly_*`(anomaly_detection/module.py:203–255,
  shared + prefixed ✓); `malware_findings`/`malware_settings`(malware_detection/module.py:123,150,
  shared + prefixed ✓).
- **Separate module DBs (drift):** `ai_*`(ai_engine/module.py:48–71 → ai_engine.db);
  `community_queue`(community_queue/module.py:47 → community_queue.db);
  `tickets`/`settings`/`ticket_seq`(tickets/module.py:65,90,95 → tickets.db).
- **Duplicate CREATE of the same table (multiple sources of truth):**
  - `quarantines` — `dashboard.py:463` **and** `alert_watcher.py:54` (byte-identical).
  - `hw_alerts` — `hw_monitor.py:127` **and** `watchdog.py:162`.
  - `scan_jobs` — `hw_monitor.py:213` **and** `malware_detection/module.py:156`.
- **Naming collision risk on consolidation:** the drift modules use **unprefixed generic
  table names** — tickets' `settings` and `ticket_seq`, and `community_queue` — which
  would collide or confuse if merged as-is into the shared DB. `ai_*` and the
  already-shared `anomaly_*`/`malware_*` conform to the prefix convention.

### 4. Known redundancies / gaps — confirmed

**Quarantine overlap.** Two *distinct* concepts share the word "quarantine":
- `quarantines` **table** (shared DB) — **network/IP** quarantine (firewall holds an IP):
  `ip, rule_id, expires_at, created_at, status`. Created **twice** (dashboard.py:463 +
  alert_watcher.py:54); written by alert_watcher; read by dashboard
  (`get_active_quarantines`).
- `quarantine_path` **column** on `malware_findings` (malware module) — the **filesystem
  path** where a quarantined malware file was moved (`module.py:137,670,841`).

These are **not duplicated data** — they quarantine different resource types (an IP vs a
file). The real redundancy is the **double `CREATE` of the `quarantines` table**.
*Recommendation:* canonical owner of the `quarantines` table = `alert_watcher`
(the firewall/IP-block owner); `dashboard.py` should call that init, not redefine the
schema. Keep `malware_findings.quarantine_path` as the malware module's own
(prefixed) column; consider it the canonical "file quarantine" record. No data merge.

**Backup gap (real, right now).** `_backup_candidates()` (`dashboard.py:4512`) returns a
**hardcoded** list — `alerts.db`, `modules/tickets/tickets.db`, `alert_manager/hw_map.json`,
`/etc/nemesis.env` — then scans **only** `modules/anomaly_detection/` for `.db` files.
Therefore **`ai_engine.db` and `community_queue.db` are NOT backed up** (ai_engine.db
holds real config). Additionally, `api_backup_create()` (`dashboard.py:4787`) uses
`tar.add()` to **raw-copy the live DB**, with no SQLite checkpoint/backup API and without
the `-wal` sibling — an unsafe snapshot if the DB is in WAL mode.

### 5. Open-ended sweep — same "hardcode instead of discover" class

- **`install.sh deploy_services()`** (lines ~810–833) iterates a **hardcoded**
  `svc_names=(dashboard watchdog hw-monitor alert-watcher device-scanner)` and only scans
  `alert_manager/`. So `core/vpn-dns-guard.service` (ADR 0002) **will not be picked up**
  by install — same smell as the DB drift. (It *does* templatize the path via
  `sed s|/home/[^/]*/dashboard|...|`, so the mechanism is fine; the **discovery** is the
  gap.)
- **`HEALTH_SERVICES`** (`dashboard.py:38`) is a hardcoded service list — same pattern;
  new units aren't health-checked unless added by hand.
- **Ten independent `DB_PATH` definitions** (above) — no single source of truth for even
  the *shared* DB's location.
- **Hardcoded absolute home-dir paths** in `diagnostics/*` and tests — leak `<USER>` and
  duplicate the path constant.

All are instances of the same root issue: **a value that should be derived from one
source is instead copied/enumerated by hand**, and drifts.

---

## Decision

Restore the documented design: **one shared `alerts.db`**, with modules owning tables by
**prefix convention**, reached through **one DB accessor that the module contract hands
to every module**. Eliminate the separate module DBs and the ghosts. Make backup and
service-deploy **discover** rather than hardcode.

The single highest-leverage change: **pass the shared DB handle into modules.** Extend
the loader/`NemesisModule` contract so a module receives the DB path/accessor at
construction; remove every `__file__`-relative DB path. This closes the gap that created
the drift in the first place.

---

## Module–DB Contract (target)

1. **One database.** All persistent state lives in the shared `alerts.db`. No module
   opens its own `.db` file.
2. **Table ownership by prefix.** Each module owns tables under its prefix: `anomaly_*`,
   `malware_*`, `tickets_*`, `ai_*`, `community_*`, `diagnostics_*`. Core owns the unprefixed
   core tables (`alerts`, `devices`, `hw_*`, `scan_*`, `quarantines`, `modules_enabled`, …).
   (`diagnostics_*` added 2026-06-28 for the connectivity-watcher module — see
   `docs/specs/diagnostics-connectivity-watcher.md`.)
   **`error_*` is reserved as CORE-owned, not a module namespace** (added 2026-08-06 for the
   error-code system) — it is cross-cutting like `audit_log`, and would otherwise misread as
   claiming module ownership under this same prefix convention.
3. **Write-own / read-any.** A module may `SELECT`/join across any table (cross-module
   reads are allowed and expected), but only `INSERT/UPDATE/DELETE/CREATE` its **own**
   prefixed tables.
4. **One connection path.** Every module gets the DB path/handle from the shared accessor
   passed by the loader (`Module(manifest, db_path)` or a `self.db()` helper on the base
   class). No `__file__`-relative computation anywhere. Core stops reaching into module
   DBs (fix `dashboard.py:1507`): read `ai_*` from the shared DB via the module's API.
5. **One creator per table.** Each table is `CREATE`d in exactly one place (kill the
   duplicate `quarantines` / `hw_alerts` / `scan_jobs` creates).
6. **Module lifecycle:**
   - **ENABLE** — module active; its tables live in the shared DB.
   - **DISABLE** — module off; **data untouched**; instant re-enable.
   - **UNINSTALL (non-destructive)** — archive the module's `<prefix>_*` tables into an
     archive namespace in the **same** DB (e.g. rename to `archive_<prefix>_*` or copy
     into an `archive` schema), and move the module code to an archive dir. Reinstall
     offers restore from the archived tables.
   - **PURGE** — explicit two-step, type-`YES` destructive delete of the archived data.
7. **Backup = one SQLite-safe copy** of the shared DB (via the SQLite **backup API** /
   `VACUUM INTO` / `.backup`, after a WAL checkpoint — never a raw `cp`/`tar` of a live
   WAL DB), plus `hw_map.json` and `/etc/nemesis.env`. Because everything is in one DB,
   backup no longer needs a per-module file list — the gap closes structurally.

---

## Migration Plan (backup-first, staged, verified, reversible — DO NOT RUN here)

**Stage 0 — Capture the unbacked data FIRST (manual, before anything else).**
Hand-copy the two currently-unbacked DBs (`modules/ai_engine/ai_engine.db`,
`modules/community_queue/community_queue.db`) and a full SQLite-safe snapshot of
`alerts.db` and `tickets.db` using `sqlite3 <db> ".backup <dest>"` (consistent snapshot),
not `cp`.
- **Land on INDEPENDENT storage** — a different physical disk or another machine
  (`<BACKUP_DIR>` off the live volume), **never alongside the live DB**. A same-disk copy
  is no backup: disk-full, power loss, and a failing drive take out the primary *and* any
  copy on the same volume together.
- **Verify with a TEST-RESTORE, not just readability.** Restore each Stage-0 snapshot into
  a **throwaway location** and confirm **the app can open and read it** (boot a read path
  against the restored copy). "Opens + row counts match" only proves the file is
  *readable*, not *restorable* — a restore that the app can't actually use is not a backup.
- **No further stage proceeds until a test-restore succeeds** for each captured DB.

**Stage 1 — Introduce the shared accessor (code only, no data move).**
Add `db_path`/`get_db()` to the loader→`NemesisModule` contract. Leave existing module
DBs in place but make the shared accessor available. Verify the app boots unchanged.
Also in this stage, **fix the hardcoded absolute home-dir paths** found in §2
(`diagnostics/alert_summary.py:17`, `anomaly_state.py:17`, `network_devices.py:16`,
`test_anomaly_cleanup.py:9`, `alert_manager/test_quarantine.py:32`): route them through
the shared accessor / a derived path so they neither leak `<USER>` nor duplicate the
constant. (Scheduled here, not left identified-but-unscheduled.)

**Stage 2 — PREREQUISITE: concurrency hardening (hard gate, before any data move).**
Consolidating five modules + multiple services onto one DB **creates write contention
that the current multi-file layout accidentally avoids** (each writer has its own file
today). Before consolidating anything:
- Confirm the shared `alerts.db` is in **WAL mode** (`PRAGMA journal_mode=WAL`) with
  **`busy_timeout` set** (e.g. 5000 ms) on every connection that writes.
- Run a **concurrent-write smoke test**: two services writing the shared DB
  **simultaneously**, and confirm **no `database is locked` errors**.
- **Stage 2 does not begin until this passes.** (This was Open-Question (c); it is now a
  prerequisite because consolidation is what introduces the contention.)

**Stage 2 — Consolidate schema with prefixes (one module at a time).**
For each drift module (ai_engine → `ai_*`, tickets → `tickets_*`, community_queue →
`community_*`): create its prefixed tables in the shared DB; **copy** rows from the
module DB; rename unprefixed names (`settings`→`tickets_settings`,
`ticket_seq`→`tickets_seq`). Verify row counts equal the Stage-0 snapshot before
touching the next module. Keep the old module DB file untouched as a live fallback.

**Stage 2/3 — copy→cutover window safety (services stay running).**
Because services run throughout Stages 1–3, a module DB can be **written between its
Stage-2 row-copy and its Stage-3 cutover**, and those rows would be lost. Chosen
mechanism: **(a) quiesce that module's own writes during its copy→cutover** — i.e.
**DISABLE** the module (lifecycle `stop()`: writes halt, data untouched, instant
re-enable) for the short window in which its rows are copied and its reads/writes are
repointed, then re-ENABLE on the shared tables. Reasoning: the module lifecycle already
supports a clean write-stop, so this **eliminates the race by construction** rather than
detecting-and-catching stragglers after the fact (option (b), index/id reconciliation,
is more code and more failure surface for no gain here). Only that one module pauses
recording briefly; the protection engines and all other modules keep running.

**Stage 3 — Cut over reads/writes.**
Point each module (and `dashboard.py:1507`) at the shared tables via the accessor. Run
the app; verify each feature (tickets list, ai settings, community queue) reads/writes
the shared DB. The old module `.db` files are now unreferenced.

**Stage 4 — De-duplicate creators & retire ghosts.**
Collapse the duplicate `CREATE`s (`quarantines`, `hw_alerts`, `scan_jobs`) to one owner
each. Remove the orphaned 0-byte `dashboard.db` and `malware_detection/malware.db`.

**Stage 5 — Switch backup to SQLite-safe single-DB snapshot** and make deploy/health
**discover** units (replace the hardcoded `svc_names`/`HEALTH_SERVICES` with a scan of
`*.service` across `alert_manager/` **and** `core/`).

**Stage 6 — Retire old module DBs.** Only after N days of verified operation, archive
then delete the now-unreferenced `ai_engine.db` / `tickets.db` / `community_queue.db`.

**Rollback:** each stage leaves the previous source of truth intact (old module DBs
untouched until Stage 6), so reverting a stage = repoint the accessor back and restore
from the Stage-0 snapshot.

---

## Consequences

**Positive** — matches the documented design; one connection path; backup becomes
correct-by-construction (no per-module list to forget); deploy/health auto-discover new
units; eliminates ghost DBs and duplicate schema; modules become trivially
backup/restore/uninstall-able.

**Negative / risk** — touching live data (mitigated by backup-first + staged + per-stage
verify + intact fallbacks); a schema/prefix rename touches module code and any external
query that assumed a separate file; the loop-back app must tolerate both old and new
during Stages 1–3.

**Open questions** — (a) archive namespace mechanism: rename-in-place vs a separate
`archive_*` table set vs attached archive DB; (b) whether cross-module joins should be
mediated by a thin read API rather than raw SQL (to keep "write-own" enforceable);
(d) do diagnostics/tests get the accessor too, or a read-only variant.
*(Former (c) — WAL/`busy_timeout` under concurrent writers — has been promoted from an
open question to a hard **Stage-2 prerequisite** above. (a), (b), (d) unchanged.)*
