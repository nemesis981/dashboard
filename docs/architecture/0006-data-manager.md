# ADR 0006 — Data Manager

- **Status:** **v1 SHIPPED** (verified 2026-07-25 — code + `alert_manager/test_data_manager.py`
  re-check, header was stale). `alert_manager/data_manager.py` is built: access control
  (write-own, fail-closed), operation logging (`dm_operation_log`, metadata-only), and the
  atomic ops layer (`next_sequence`/`increment_counter`/`upsert`, the formal home of the v0
  seed) are all live. **All 6 modules migrated** (diagnostics, community_queue, tickets,
  ai_engine, anomaly_detection, malware_detection) — none still calls `get_db()` directly.
  **Gap vs. this ADR's own v1 definition:** the module **loader** (`modules_loader.py`) does
  NOT enforce Data Manager routing at load time — a module bypassing the Data Manager would
  still load today; enforcement is currently voluntary (every module happens to comply) not
  loader-guaranteed. See "Enforcement" and "Build sequence" below — that piece is unbuilt.
  v2 (schema gatekeeper) and v3 (contributor capability enforcement) are **not started**.
- **Date:** 2026-06-28 (v1 shipped + verified: 2026-07-25)
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
> design the implementation. **v1 is built and all 6 modules are migrated** (2026-07-25); the
> loader-enforcement piece of v1's own definition, and v2/v3, are not.

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
  ├── Atomic operations layer
  │   next_sequence(domain) → int          (atomic, no race possible)
  │   increment_counter(key, amount=1)→int (atomic)
  │   upsert(table, data, conflict_keys)   (atomic ON CONFLICT)
  ├── Schema gatekeeper (mandatory, unbypassable)
  │   modules declare schema in manifest → Data Manager validates
  │   before any module code runs → no declaration = no load
  ├── Operation logging (audit trail)
  │   every write logs: module, table, operation, actor, timestamp,
  │   result → feeds the transparency audit + attribution UI
  ├── Access control
  │   modules can only touch their declared tables (write-own/
  │   read-scoped per ADR 0001) → enforced, not convention
  └── Failure handling
      missing table → bounded retry (3x) → structured error →
      graceful module UNLOAD into disabled state with visible reason
       ↓
    alerts.db (SQLite, WAL mode, busy_timeout)
```

## Enforcement (mandatory design intent — NOT yet loader-enforced)

- The module loader (`_load_module` in `modules_loader.py`) is **intended** to check that every
  module routes DB access through the Data Manager **before instantiating it**, rejecting at
  load time a module that imports `sqlite3` directly or calls `get_db()` outside the Data
  Manager contract. **This check does not exist yet** — confirmed 2026-07-25, `modules_loader.py`
  has no reference to the Data Manager at all. Today, compliance is voluntary: all 6 modules
  happen to route through it because they were migrated, not because the loader would reject
  one that didn't.
- **Access control that IS live**, at the connection level (not the loader): `GuardedConnection`
  raises `AccessDenied` on any write outside a module's declared namespace, fail-closed on an
  unidentifiable target. This is real enforcement — just scoped to writes made through
  `get_data_manager().connect(module)`, not to whether a module uses that path in the first
  place.
- The Data Manager is the **intended SOLE path to DB access for modules**; core services
  (watchdog, alert_watcher, etc.) use it too but have a higher-trust path for
  performance-critical operations. The loader-rejection gap above means this "sole path" claim
  is enforced by convention today, not by the loader.

## Seed (superseded by v1 — "Data Manager v0")

The four atomic SQL fixes from the 2026-06-28 race audit were the **first concrete functions of
the Data Manager's atomic operations layer**, originally landed as inline SQL labeled with a
pointer to this ADR. **v1 (`alert_manager/data_manager.py`) formalizes them as the real
`next_sequence`/`increment_counter`/`upsert` methods** — the v0 seed's logic now lives there,
not as scattered inline SQL.

## Build sequence

- **v0 (SHIPPED, 2026-06-28):** atomic SQL fixes for the four races (seed functions).
- **v1 (SHIPPED, 2026-07-25 — partial per this section's own original definition):**
  formalized as `alert_manager/data_manager.py`; atomic operations moved into it
  (`next_sequence`/`increment_counter`/`upsert`); operation logging added
  (`dm_operation_log`); access-control enforcement added (`GuardedConnection`, write-own,
  fail-closed); **all 6 modules migrated** to route through it. **NOT done:** "update the
  module loader to enforce routing" — `modules_loader.py` has no Data Manager check; a
  non-compliant module would still load. This is the one piece of v1's original scope left
  for a follow-up, not a v2/v3 item.
- **v2 (with schema-gatekeeper ADR) — NOT STARTED:** add mandatory schema declaration +
  validation at load time.
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

**v1 SHIPPED (2026-07-25).** `alert_manager/data_manager.py` is live: atomic ops
(`next_sequence`/`increment_counter`/`upsert`), operation logging (`dm_operation_log`), and
connection-level access control (`GuardedConnection`, write-own, fail-closed) all built and
verified (`test_data_manager.py`, 43/43 PASS, incl. a race-free concurrency proof). **All 6
modules migrated** — diagnostics, community_queue, tickets, ai_engine, anomaly_detection,
malware_detection — none calls `get_db()` directly anymore.

**Immediate next step (completes v1's original scope):** add the `modules_loader.py` check that
rejects a module at load time if it bypasses the Data Manager. Today that's the only gap between
what's built and what this ADR originally specified for v1 — access control is real but
currently voluntary-by-migration, not loader-guaranteed.

**After that:** fold in the schema gatekeeper (v2), then contributor-scale capability
enforcement (v3) — both **not started**.
