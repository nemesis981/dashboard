# ADR 0006 — Data Manager

- **Status:** **v1 SHIPPED — complete** (verified 2026-07-25). `alert_manager/data_manager.py`:
  access control (write-own, fail-closed), operation logging (`dm_operation_log`,
  metadata-only), the atomic ops layer (`next_sequence`/`increment_counter`/`upsert`, the
  formal home of the v0 seed), and actor context stamped on every write (atomic-helper AND
  raw passthrough alike) are all live. **All 6 real DB-using modules migrated** (diagnostics,
  community_queue, tickets, ai_engine, anomaly_detection, malware_detection) — none calls
  `get_db()` directly. **`dhcp` discovered as a 7th module — DB-free, passes the contract
  naturally, no migration needed.** **Loader-level enforcement is now LIVE**:
  `modules_loader.py` statically parses each module's `module.py` before running any of its
  code and refuses to load one that imports raw `sqlite3` or the bare `get_db` accessor, with
  a specific named error (module + violation + line). This closes the gap flagged earlier
  today — v1 now matches its own original definition in full. **v2 (schema gatekeeper)
  explicitly deferred** — not scoped, pending the L3 zero-day work (behavioral-trigger
  telemetry, TLS interception) producing real new schemas to design the gatekeeper against,
  rather than designing it against hypothetical ones now. **v3 (contributor capability
  enforcement) not started.**
- **Date:** 2026-06-28 (v1 shipped + verified: 2026-07-25; loader enforcement completed same day)
- **Affects:** all module/service DB access, `modules_loader.py` (load-time enforcement), the
  four 2026-06-28 race-fix sites (the v0 seed), attribution (`actor`), access control
  (write-own/read-scoped), the schema gatekeeper, third-party module trust
- **Depends on:** [0001-database-and-module-architecture](0001-database-and-module-architecture.md)
  (single shared DB + module prefix ownership — the rule the Data Manager *enforces*)
- **Related:** [0005-dns-firewall-device-auth-architecture](0005-dns-firewall-device-auth-architecture.md)
  (device identity gates sensitive table access); the 2026-06-28 single-user-assumptions audit
  (`docs/audits/single-user-assumptions-audit-2026-06-28.md`); the schema-gatekeeper design
  (2026-06-26 session); `CONTRIBUTING.md`

> Paths sanitized for the public repo. This ADR **records** the decided direction; it does not
> design the implementation. **v1 is complete** (2026-07-25) — all 6 DB-using modules migrated,
> loader enforcement live. **v2/v3 are not built** — v2 is deliberately deferred, not merely
> unstarted (see Status above).

---

## Decision

A **Data Manager** — a single authoritative layer between all modules/services and the
database. **Every significant DB read and write goes through it. Modules never access the
database directly.**

## Problem it solves (five converging design principles)

- **Race conditions.** Four confirmed read-modify-write races were found in the 2026-06-28
  single-user-assumptions audit (`tickets_seq`, `ai_engine` rate, `community_queue`,
  `anomaly_incidents`). More will appear as modules grow. **Direct DB access from modules makes
  races structurally inevitable.**
- **Attribution gaps.** `actor` seams exist in the DB, but modules pass NULL/default because
  attribution is per-call convention, not enforced. **The Data Manager applies `actor`
  automatically on every write.**
- **Access control.** Modules can currently read/write any table; the write-own/read-scoped
  rule (ADR 0001) is convention only. **The Data Manager enforces namespace boundaries** — a
  module can only touch its declared tables.
- **Schema trust.** The schema gatekeeper validates schema declarations before module load.
  The Data Manager is the sole path to DB access, **making gatekeeper bypass impossible.**
- **Contributor safety.** Open-source contributors can accidentally (or deliberately) introduce
  races, attribution gaps, or cross-module table access. **Making direct DB access unavailable
  to modules makes the whole class of bugs structurally impossible.**

## Architecture

```
modules / services
       ↓
  DATA MANAGER (alert_manager/data_manager.py)
  ├── Atomic operations layer                              [v1 — LIVE]
  │   next_sequence(domain) → int          (atomic, no race possible)
  │   increment_counter(key, amount=1)→int (atomic)
  │   upsert(table, data, conflict_keys)   (atomic ON CONFLICT)
  ├── Schema gatekeeper                                     [v2 — DEFERRED, not built]
  │   modules declare schema in manifest → Data Manager validates
  │   before any module code runs → no declaration = no load
  ├── Operation logging (audit trail)                       [v1 — LIVE]
  │   every write logs: module, table, operation, actor, timestamp,
  │   result → feeds the transparency audit + attribution UI
  ├── Access control                                        [v1 — LIVE]
  │   modules can only touch their declared tables (write-own/
  │   read-scoped per ADR 0001) → enforced, not convention
  ├── Loader-level contract enforcement                     [v1 — LIVE]
  │   modules_loader.py statically rejects raw sqlite3 / bare
  │   get_db() at load time, before any module code runs
  └── Failure handling                                      [v1 — LIVE]
      missing table → bounded retry (3x) → structured error →
      graceful module UNLOAD into disabled state with visible reason
       ↓
    alerts.db (SQLite, WAL mode, busy_timeout)
```

## Enforcement (mandatory, loader-enforced — LIVE)

- **The module loader (`_load_module` in `modules_loader.py`) checks every module's
  `module.py` BEFORE running any of its code**, and refuses to load a module that violates the
  Data Manager contract. Implementation: `_check_data_manager_contract()` statically parses
  the module's source with `ast` (no code execution) and walks the tree for:
  - any `import sqlite3` / `from sqlite3 import ...` (including aliased imports), and
  - any bare `get_db` — `from modules import get_db`, or a call to `get_db()` /
    `self.get_db()` / `modules.get_db()`.

  A violation raises `ModuleEnforcementError`, caught by `_load_all_enabled()` and logged as a
  clean, specific refusal — **module name + which check failed + the exact line** — with no
  traceback noise. `get_data_manager()` / `data_manager.connect()` are the sanctioned path and
  are never flagged. A module whose `module.py` fails to parse at all is also rejected (can't
  prove compliance on unparseable source, so it fails closed).
- **This is not a convention anymore. It is a loader-enforced hard requirement**, verified
  2026-07-25 against the AST check both positively (all 7 real modules — the 6 migrated
  DB-users plus DB-free `dhcp` — pass) and negatively (synthetic raw-`sqlite3`, bare-`get_db`-
  import, and bare-`get_db()`-call modules are all correctly refused, each with the specific
  violation named).
- **Access control at the connection level, independently live too:** `GuardedConnection`
  raises `AccessDenied` on any write outside a module's declared namespace, fail-closed on an
  unidentifiable target. So there are now two independent layers — the loader refuses a module
  that doesn't even attempt to route through the Data Manager; the guarded connection refuses a
  write that routes through it but targets the wrong namespace.
- The Data Manager is the **SOLE path to DB access for modules**, now loader-guaranteed, not
  just convention. Core services (watchdog, alert_watcher, etc.) do not pass through this
  loader and keep their higher-trust direct path, per the original design.

## Seed (superseded by v1 — "Data Manager v0")

The four atomic SQL fixes from the 2026-06-28 race audit were the **first concrete functions of
the Data Manager's atomic operations layer**, originally landed as inline SQL labeled with a
pointer to this ADR. **v1 (`alert_manager/data_manager.py`) formalizes them as the real
`next_sequence`/`increment_counter`/`upsert` methods** — the v0 seed's logic now lives there,
not as scattered inline SQL.

## Build sequence

- **v0 (SHIPPED, 2026-06-28):** atomic SQL fixes for the four races (seed functions).
- **v1 (SHIPPED — COMPLETE, 2026-07-25):** formalized as `alert_manager/data_manager.py`;
  atomic operations moved into it (`next_sequence`/`increment_counter`/`upsert`); operation
  logging added (`dm_operation_log`); access-control enforcement added (`GuardedConnection`,
  write-own, fail-closed); actor context applied to every write; **all 6 DB-using modules
  migrated** (`dhcp` discovered DB-free, passes without migration); **module loader updated to
  enforce routing** (`_check_data_manager_contract()`, AST-based, rejects raw `sqlite3`/bare
  `get_db()` at load time with a named error). Every clause of v1's original scope is now
  built — nothing carried forward.
- **v2 (schema gatekeeper) — DEFERRED, not scoped.** Deliberately not designed yet: the
  upcoming L3 zero-day work (behavioral-trigger telemetry storage, TLS interception's
  metadata/evidence retention) will introduce real new schemas. Designing the gatekeeper's
  validation rules now, against only the 6 existing modules' already-stable schemas, risks
  building it around the wrong shape. Wait for L3 to give it real schemas to design against.
- **v3 (open-source contributor scale) — NOT STARTED:** add capability-declaration manifest
  enforcement; consider process isolation.

## SQLite longevity note

The community signal deduplication model (one entry per unique signal, aggregated counts,
bounded timestamp arrays, confidence decay + expiry — see
[community-signal-dedup.md](../roadmap/community-signal-dedup.md)) keeps the backend database
lean indefinitely. The **database grows with the unique threat landscape, not with report
volume or user count**.

- **Estimated scale at 100K installs, 5 years:** ~730MB total — well within SQLite's documented
  capabilities.
- **Submission queue pattern** (reports queue → background dedup worker) prevents write
  contention under high concurrent submission load.
- **Migration path to PostgreSQL exists if needed** (schema portable, application layer unchanged
  via the Data Manager abstraction) but is **not anticipated** given the deduplication model's
  efficiency.

## Connections

- **ADR 0001** — the write-own/read-scoped rule, now **enforced, not convention**.
- **ADR 0005** — device auth: the Data Manager's access-control layer is where device identity
  gates sensitive table access.
- **Schema gatekeeper design** (2026-06-26 session) — this ADR is its implementation home.
- **Module trust model** (third-party modules: the DB gate is necessary-not-sufficient; the
  Data Manager closes the DB surface completely).
- **`CONTRIBUTING.md`** — the contributor contract references this ADR.

## Status / next

**v1 SHIPPED — COMPLETE (2026-07-25).** `alert_manager/data_manager.py` is live: atomic ops
(`next_sequence`/`increment_counter`/`upsert`), operation logging (`dm_operation_log`),
connection-level access control (`GuardedConnection`, write-own, fail-closed), and actor
context on every write (atomic-helper and raw passthrough alike) — all built and verified
(`test_data_manager.py`, 43/43 PASS, incl. a race-free concurrency proof). **All 6 real
DB-using modules migrated** — diagnostics, community_queue, tickets, ai_engine,
anomaly_detection, malware_detection. `dhcp` was discovered as a 7th module: DB-free, passes
the contract with no migration. **Loader-level enforcement is live**: `modules_loader.py`
statically rejects, before any module code runs, a module that imports raw `sqlite3` or the
bare `get_db` accessor — verified against all 7 real modules (pass) and synthetic violation
cases (correctly refused, each with a specific named error). This was the one piece of v1's
original scope left open earlier today; it is now closed. v1 has no remaining gaps.

**Next up: v2 (schema gatekeeper) is explicitly deferred, not scoped yet** — waiting on the L3
zero-day work (behavioral-trigger telemetry, TLS interception) to produce real new schemas to
design the gatekeeper against, rather than designing it against only today's 6 stable schemas.
**v3 (contributor-scale capability enforcement) remains not started.**
