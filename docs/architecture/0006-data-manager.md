# ADR 0006 — Data Manager

- **Status:** Proposed (direction captured; design not yet specified — only the v0 seed exists)
- **Date:** 2026-06-28
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
> design the implementation. Only "Data Manager v0" (the four atomic race fixes) is built.

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

## Enforcement (mandatory, not optional)

- The module loader (`_load_module` in `modules_loader.py`) checks that every module routes DB
  access through the Data Manager **before instantiating it**. A module that imports `sqlite3`
  directly or calls `get_db()` outside the Data Manager contract is **REJECTED at load time**.
- This is not a convention or a guideline. It is a **loader-enforced hard requirement**. No
  Data Manager routing = no module load.
- The Data Manager is the **SOLE path to DB access for modules**. Core services (watchdog,
  alert_watcher, etc.) use it too but have a higher-trust path for performance-critical
  operations.

## Seed (already built — "Data Manager v0")

The four atomic SQL fixes from the 2026-06-28 race audit are the **first concrete functions of
the Data Manager's atomic operations layer**. They are labeled as such in the code with a
pointer to this ADR. Future builds grow the Data Manager from this seed.

## Build sequence

- **v0 (NOW):** atomic SQL fixes for the four races (seed functions).
- **v1 (pre-commercial):** formalize as `alert_manager/data_manager.py`; move atomic operations
  into it; add operation logging; add access-control enforcement; update the module loader to
  enforce routing.
- **v2 (with schema-gatekeeper ADR):** add mandatory schema declaration + validation at load
  time.
- **v3 (open-source contributor scale):** add capability-declaration manifest enforcement;
  consider process isolation.

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

Proposed. Only the v0 seed (the four atomic race fixes) is built. Next steps in sequence:
land the v0 fixes (audit-then-fix, one at a time), then formalize `data_manager.py` (v1) with
operation logging + access-control enforcement + loader routing-enforcement, then fold in the
schema gatekeeper (v2), then contributor-scale capability enforcement (v3).
