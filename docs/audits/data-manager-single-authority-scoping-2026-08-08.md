# Data Manager single-authority — grant gap, hw_monitor DB-path timing, gateway-mode dependency risk

**Status:** scoping doc (read-only analysis + recommended fix shapes; no code changed). Captured
2026-08-08 (Window 3), during the paused error-code classification audit. Two structural gaps
found while investigating that audit's prerequisites, plus one forward-looking check folded in
mid-session. **Framed as one document because they are the same underlying problem stated three
ways: the Data Manager's single-authority guarantee (ADR 0006 — one accessor, one grant map, one
resolved path) is not actually honored everywhere it's assumed to be.** Leaving any of these
unfixed indefinitely invites a future contributor to trust a guarantee that doesn't hold.

---

## Why this matters: the Data Manager is a SECURITY choke point, not just a correctness one

**Standing design principle, recorded 2026-08-08 at Paul's direction. This is the deeper
justification for everything below, and it reframes "single authority" from code hygiene into a
security-architecture requirement.**

The goal is that **all** database activity flows through the Data Manager. Not only because a
single authority is easier to reason about, but because every write that passes through one
chokepoint is a write that **could be inspected, rate-limited, or anomaly-detected as it
happens**. For a security product specifically, that property is the point: a compromised
component behaving oddly — writing to tables it has no business touching, at rates or in
patterns it has never exhibited before — is visible right there at the gate, **if and only if
nothing bypasses it**. Every bypass is a blind spot that a compromised component would occupy
first, and the value of the mechanism degrades non-linearly with the number of bypasses: a gate
that covers most writes provides far less than most of the assurance, because an attacker only
needs the uncovered path.

This is why the gaps in this document are worth real, deliberate fixes rather than an indefinite
PUNCHLIST line. A partially-honored chokepoint invites a future contributor to assume a
guarantee that does not hold — and in a security product, that assumption is itself the
vulnerability.

**Future consideration, explicitly NOT a commitment to build now:** if the Data Manager is the
one place every write passes through, it is also the natural home for **write-pattern monitoring
and anomaly detection on its own chokepoint position** — unexpected table access, unusual write
rates, out-of-profile access patterns per namespace. The `dm_operation_log` audit table and the
existing `WOULD DENY` WARN-mode journal are already most of the raw material such a capability
would need. **Recorded as a design opportunity created by closing these gaps, not as scoped
work.** It should not influence the fix shapes chosen below beyond one thing: prefer fixes that
keep writes flowing *through* the gate over fixes that route around it, because every bypass
permanently forecloses this option for whatever it carries.

### Preliminary chokepoint-completeness finding — the gate is materially incomplete today

Surfaced while investigating Problem 2; **a first-pass inventory, not a completed audit.** A grep
for raw `sqlite3.connect(` outside tests, scripts, and the agent found call sites in core
components that do not route through the Data Manager at all:

- `core_module/alert_watcher/alert_watcher.py` — 5 sites
- `alert_manager/ip_enrichment.py` — 3 sites
- `diagnostics/anomaly_state.py`, `diagnostics/alert_summary.py`, `diagnostics/network_devices.py` — 1 each
- `core_module/device_scanner/device_scanner.py` — 1 site
- `core/manage.py` — 2 sites
- `alert_manager/nemesis_fwd.py` — 1 site

**Legitimately raw, listed so they are not miscounted as violations:**
`alert_manager/data_manager.py:858` (the DM's own connection — it *is* the gate),
`modules_loader.py:121,178,191` (bootstrap, runs before the DM exists),
`alert_manager/database.py` (the canonical DDL owner per ADR 0001),
`modules/__init__.py:54` (the shared `get_db()` accessor).

**Not yet assessed:** whether each non-legitimate site is a genuine bypass needing conversion, or
has a defensible reason (startup ordering, a process outside the namespace model, read-only
access where the gate adds nothing). That assessment is real work and is **not** in scope
tonight — recorded here so the chokepoint's actual coverage is on record as *partial*, which is
the fact that matters for the principle above. **Recommend a dedicated follow-up audit**, scoped
like this one: read-only, per-site classification, with the security framing above as its
explicit standard rather than "does it work."

**Notably NOT on that list: `core_module/hw_monitor/hw_monitor.py` has zero raw
`sqlite3.connect()` calls** — every one of its 52 DB touchpoints already routes through
`_dm().connect("hw_monitor")`. Its `import sqlite3` is used only for `sqlite3.Row`
(`hw_monitor.py:3265`). This is worth stating plainly because Problem 2 below is easy to
misread as "hw_monitor bypasses the Data Manager." **It does not.** Problem 2 is about how
hw_monitor *publishes a path*, an entirely separate concern from whether its writes pass through
the gate — they do.

---

## Problem 1 — `error_codes`/`error_occurrences` have no working grant path for almost any module

### The finding, consolidated
Already on `PUNCHLIST.md:3373`, confirmed for `dhcp` specifically ("every `E-DHCP-*` code the
module has ever tried to record has silently failed to persist" — a silent `WOULD DENY`, not an
exception, invisible to the module's own test suite). I checked the full grant map in
`alert_manager/data_manager.py`'s `NAMESPACES` dict directly: **only `conn_consent` currently
carries the grant** (added tonight by Window 1, empirically verified before adding — see
`alert_manager/conn_consent_errors.py`'s own docstring). `dhcp`, `hw_monitor`, `watchdog`,
`nemesis_fwd`, `dashboard`, `tier2_gate`, `integrity_watch` do not.

**CONFIRMED 2026-08-08 — was an inference, now verified.** The `tickets` module's grant is a bare
prefix tuple, `"tickets": ("tickets",)` (`data_manager.py:72`); `allowed()` matches by
`startswith(prefix)` (`data_manager.py:711`), and neither `error_codes` nor `error_occurrences`
starts with `"tickets"`. Verified by direct call rather than left as reasoning —
`allowed("tickets", "error_codes")` returns **False**, as does `allowed()` for `dhcp`,
`hw_monitor` and `dashboard` on both tables, while `conn_consent` returns True. **So the seeded
reference example — `E-TICKETS-001`, the "textbook shape" `PUNCHLIST.md:3129-3130` points all
future retrofit work at — could not have recorded anything either.**

**⚠ The live-DB check was run and is NOT the evidence, which is worth recording so nobody
re-runs it expecting an answer.** `/var/lib/nemesis/alerts.db` has all four `error_*` tables
present and **0 rows in both `error_codes` and `error_occurrences`** — nothing has ever been
registered or recorded in production. That is consistent with the grant gap, but it is **equally
consistent with "those code paths simply never fired"** — `E-TICKETS-001` only records when a
ticket-count read *fails*, and production may just never have failed. An empty table cannot
distinguish "refused" from "never attempted", which is exactly the
instrument-that-can-only-give-one-answer shape this repo's standing verification practice warns
about. A journal sweep found no error-table denials in 7 days either, with a control proving the
grep works (28 unrelated `WOULD DENY` lines present). **The structural test above is what settles
it; the production evidence is inconclusive by nature and should not be cited as confirmation.**

### The actual root defect: design intent and implementation reality diverged
`nemesis_errors.py`'s own header (lines 20-30) states the design goal explicitly: *"Grants must
not multiply. Writes go through ONE core-namespaced call, so no per-module Data Manager grant is
ever needed. The alternative — listing the error tables in every module's grant — is precisely
the drift that left `scan_tasks` missing from `hw_monitor`'s namespace for five days."* That is a
real, cited prior incident, used as the reason to explicitly reject the per-module-grant shape.

But `make_recorder()`'s docstring (same file, ~line 385) states an equally deliberate, equally
explicit second constraint: *"the connection must come from the CALLER, so the error system
never opens its own DB access and never becomes a way around the ADR 0006 module contract that
`modules_loader` enforces statically."* Every retrofit call site passes its OWN
Data-Manager-gated connection into `record_error_best_effort()` — which means the caller's own
namespace grant governs the write, exactly like any other table. **These two stated design
principles are in tension, and the tension is what actually produced this bug**: the code was
built to honor the second principle (never open a bypass connection), which silently defeated
the first (no per-module grant should ever be needed). Nobody wrote incorrect code — the two
constraints, both individually reasonable, are incompatible as implemented, and the gap sat
undiscovered until `conn_consent` tripped over it tonight.

### Three candidate fixes

**A. Narrow explicit grant per module** (add `error_codes`, `error_occurrences` to every
module's own `NAMESPACES` entry, the same shape `conn_consent` already uses). This is the most
minimal, most consistent-with-current-precedent option — but it is **exactly the anti-pattern
`nemesis_errors.py`'s own header explicitly warns against, citing a real five-day production gap
as the reason not to do this.** Choosing it means re-introducing a known failure mode with a
known cost, in the same file that already documents why not to.

**B. A dedicated `record_module_error()` Data Manager method** (PUNCHLIST's own suggested
alternative) that opens its own privileged/core connection, bypassing per-module grants
entirely. This restores the original "no per-module grant ever needed" intent — but it directly
contradicts `make_recorder()`'s other explicit, documented invariant ("never opens its own DB
access, never becomes a way around the ADR 0006 module contract"). Building this means
deliberately carving an exception into a principle the same file states as load-bearing,
which is a real design decision, not a mechanical fix — worth doing consciously if chosen, not
as an incidental side effect of solving Problem 1.

**C. (Recommended) A small, table-level exemption inside `data_manager.py`'s `allowed()` gate
itself** — the single function every write already passes through
(`alert_manager/data_manager.py:688-711`). Add `error_codes`/`error_occurrences` as universally
insert-permitted regardless of caller namespace, mirroring the **existing precedent already in
this exact function**: `OP_LOG_TABLE` (`dm_operation_log`) is already special-cased
(`if table == OP_LOG_TABLE: return False` — always denied to every module, written only by the
DataManager's own trusted code). This proposal is the same shape, inverted: a small, fixed,
explicitly-named exemption set, checked before the per-namespace lookup, for tables that are
core-owned and meant to be universally writable rather than universally protected.

Why C over A and B: it satisfies the *original* "no per-module grant is ever needed" intent
exactly, without touching `nemesis_errors.py`'s connection-sourcing model at all — the caller's
own `GuardedConnection` is used unmodified, so the "never opens its own DB access, never becomes
an ADR-0006 bypass" invariant stays intact, verbatim. It needs no new method, no new
abstraction — a few lines inside a function that's already the system's one enforcement point,
already audited, already has this exact shape of carve-out for a different table. It also matches
these tables' own documented status: `nemesis_errors.py` already claims `error_codes`/
`error_occurrences` are core-owned, cross-cutting infrastructure, citing `audit_log` as the
existing precedent for "several writers, no single owner" — Option C just makes the write-gate
agree with what the module already claims about itself.

### RESOLVED AND BUILT 2026-08-08 — Option C, approved by Paul, with two refinements found during implementation

**Both open questions this section originally listed are now answered by the build.**

**Refinement 1 — it went in `check_write()`, not `allowed()`.** `allowed(module, table)` takes no
`op`; it answers the pure ownership question, which is exactly why the `OP_LOG_TABLE` rule
correctly lives there (an always-DENY with no op dimension). An op-*restricted* always-ALLOW
needs the operation, so it belongs at `check_write()` (`data_manager.py:501`) — documented in the
code as "THE single decision point for every write", and already home to precisely this shape:
the column-level grant immediately below the new block is "deliberately restricted to UPDATE."

**Refinement 2 — insert-only alone would have silently failed, so `create` is included.** The
first open question above asked whether statement-type granularity was achievable. It is:
`classify()` returns `(op, table)` and `_guard()` passes `op` through. But **insert-only would
have reproduced the exact bug being fixed.** `_Recorder` self-initialises — on first use it calls
`init_error_tables()` on the *module's* guarded connection, issuing `CREATE TABLE IF NOT EXISTS`
on all four tables. `create` is a write op (`_WRITE_OPS`, `:543`) and the default namespace mode
is **ENFORCE** (`namespace_mode()`, `:417-418`), so a denied CREATE raises `AccessDenied`, which
`_Recorder` swallows, increments `_reg_failures`, and after three attempts gives up permanently —
recording nothing, silently. Relying on core to pre-create the tables does not rescue it either:
`init_error_tables()` is called only from `dashboard.py:142`, and hw_monitor is a separate process
that never calls it (`modules/dhcp/module.py:55` already documents this same concern).

**What shipped** (`alert_manager/data_manager.py`, +~60 lines, one file):
- `ERROR_LEDGER_TABLES` (all four) and `ERROR_LEDGER_INSERT_TABLES` (`error_codes`,
  `error_occurrences`) declared next to `OP_LOG_TABLE`. **The two tuples must not be merged** —
  this answers the second original open question: `error_code_snapshots` and
  `error_ledger_causes` get `create` (they are part of `init_error_tables()`) but **not**
  `insert`, because `add_cause()`/`capture_snapshot()` are core-side operations that run on a
  core connection, and no module retrofit call site inserts into them.
- In `check_write()`, after the ownership check: `insert` permitted on the two, `create` on all
  four, everything else falling through to the normal deny path.

**UPDATE / DELETE / DROP remain denied, and that is the security half of the design, not an
oversight.** The error ledger is an append-only audit record. A module able to rewrite or erase
it could erase evidence of its own misbehaviour — the first thing a compromised component would
do. Adding rows is a capability every module needs; altering or removing existing ones is a
capability none of them do. **Widening those tuples later is a security decision, not a
convenience one** — see the chokepoint section at the top of this document.

### Verification performed (real output, controls that must fail)
Isolated temp-DB harness against the `dhcp` namespace in explicit `MODE_ENFORCE`, with a premise
control first (asserting `dhcp` genuinely lacks the grant, so the test cannot pass vacuously):
- **Allowed, as required:** `init_error_tables()` (all four CREATEs), `INSERT error_codes`,
  `INSERT error_occurrences`.
- **8 controls, all correctly DENIED** — `UPDATE`/`DELETE` on `error_occurrences`, `DROP
  error_codes`, `INSERT` into `error_ledger_causes` and `error_code_snapshots` (create-only, not
  insert), `INSERT` into an unrelated unowned table, and `CREATE` of an unrelated table (proving
  `create` is not blanket-allowed).
- **End-to-end:** a real `make_recorder()` recorder for the ungranted `dhcp` namespace returned a
  row id and **persisted exactly 1 row** — a genuine `record_error` path proven working, not just
  a boolean returning True. **11 passed, 0 failed.**
- **Regression suites green:** `test_data_manager.py` ALL PASS, `test_nemesis_errors.py` 73/73,
  `test_conn_consent.py` 23/23 (the last confirms Window 1's `conn_consent` grant still behaves
  identically — the new block is reached only *after* `allowed()` already returns True for it).

---

## Problem 2 — hw_monitor's shared-DB-path publish never happens at startup

### The finding, as Window 1 assessed and handed off tonight
From `~/work/nemesis-internal/handoff/2026-08-08-window1-handoff.md`: *"Looks like a one-line
accessor change; is not. `_dm()`/`_db_connect()` have 54 call sites, and `get_shared_db_path()`
RAISES when unpublished (`modules/__init__.py:33-38`) — while hw_monitor's only publish sits at
line 3496 INSIDE `_create_enrollment()`, a request handler. So the naive fix breaks the ingest
service at startup. That request-handler publish is the real root defect and must be fixed
first."* Window 1 deliberately assessed and did not fix this (operator agreed), and handed the
plan to Window 3 explicitly.

I traced the mechanism directly to confirm the shape, not just the summary:
- `core_module/hw_monitor/hw_monitor.py:28` resolves `DB_PATH` via `nemesis_paths.db_path(...)`
  at import time — correctly resolved (not the `__file__`-relative anti-pattern), but it is
  **hw_monitor's own, independent resolution**, separate from the shared
  `modules.get_shared_db_path()` authority every other core service uses.
- `_db_connect()` (`:78-88`) and `_dm()` (`:1312-1323`) — hw_monitor's own connection helpers,
  48 call sites by my own recount of `_db_connect()` invocations (Window 1's count of 54 likely
  includes additional dependent paths I didn't individually enumerate; worth reconciling exactly
  before the build, doesn't change the shape of the fix) — both source from this local `DB_PATH`
  constant, never from `modules.get_shared_db_path()`.
- The **only** call to `modules.set_shared_db_path(DB_PATH)` anywhere in the file is at
  `:3496`, inside `_create_enrollment()`, immediately before a lazy
  `from modules.tickets.module import open_ticket` (`:3497`) — it publishes the path only because
  *that one line* needs it, and only when an enrollment actually happens. Contrast with the
  correct, established pattern used everywhere else in this codebase —
  `diagnostics_watcher.py:54`, `malware_canary.py:44`, `watchdog.py:422`,
  `nemesis_connectivity_notify.py:206` — which all call `set_shared_db_path()` unconditionally,
  at true process startup, before any handler runs.

### Why the obvious fix is dangerous
If hw_monitor's 48-54 `_dm()`/`_db_connect()` sites were simply switched to source from
`modules.get_shared_db_path()` without also moving the publish to true startup, the **very first**
connection attempt — almost certainly before any enrollment has ever occurred — would raise, and
the ingest service would fail to start. This is exactly the danger Window 1's assessment names,
and exactly why they stopped short of the "one-line accessor change" it superficially looks like.

### Recommended fix — REVISED 2026-08-08 during implementation. Step 2 as originally written was wrong and would have broken the dashboard.

**⚠ CORRECTION, recorded rather than quietly edited away, because the error is instructive.**
This document's first draft proposed a three-part fix whose step 2 was: *"switch `_dm()`'s
construction to source its path from `modules.get_shared_db_path()` instead of the local
`DB_PATH` constant."* **Implementing that would have taken the dashboard down at import time.**
Traced during the build:

- `dashboard.py:108` does `import hw_monitor`, and `dashboard.py:120` calls
  `hw_monitor.init_db()` — which reaches `_db_connect()` → `_dm()`.
- `modules_loader.init(app, DB_PATH, MODULES_DIR)`, the call that publishes the shared path
  (`modules_loader.py:55`), is at **`dashboard.py:2195` — 2,075 lines later.**
- `get_shared_db_path()` RAISES when unpublished (`modules/__init__.py:33-38`).

So `_dm()` sourcing from the shared accessor would raise during dashboard module import, before
Flask ever starts. This is a **more severe** version of the hazard Window 1 identified: they
correctly flagged that the naive fix "breaks the ingest service at startup," but the same change
also kills the primary user-facing service, via a different import path neither of us had traced
at scoping time.

**The deeper error in the original step 2 was a wrong mental model of what the authority IS.**
`nemesis_paths.db_path()` is the real single resolver, and both `hw_monitor.DB_PATH` and
`dashboard.DB_PATH` already go through it — **verified at runtime, both resolve to
`/var/lib/nemesis/alerts.db`** (dashboard's own comments at `dashboard.py:9133,9251` assert the
same equality). `modules.set_shared_db_path()` / `get_shared_db_path()` is a **publication
channel for the modules subsystem**, not the path authority. Treating the publication channel as
the authority inverts the real dependency — which is exactly what made the "fix" look like a
consistency improvement while actually introducing a startup-ordering dependency that did not
previously exist.

**Fix as actually built (two parts, not three):**

1. **Move `modules.set_shared_db_path(DB_PATH)` from inside `_create_enrollment()` to the top of
   `main()`**, before `init_db()` and before `_start_windows_agent_listener()`. The lazy
   `from modules.tickets.module import open_ticket` stays where it is — only the publish moved.
2. **Trace every `_db_connect()`/`_dm()` call site** to confirm none executes before that publish.

**`main()`, NOT module-import level — the distinction is load-bearing and was itself a live
hazard.** The original draft offered "`main()` or module-import time" as if interchangeable. They
are not: `dashboard.py` imports this file, and so do 9 test files, several of which publish their
own temp-DB path (`nemesis_agent/test_observation.py:226` publishes a temp DB and then imports
`hw_monitor` on the very next line). A module-level publish would fire as an import side effect
in every one of those processes and overwrite a path they had deliberately chosen — the failure
mode being tests silently writing to the **production** database. `main()` runs only in the
service process, which is the one that legitimately owns this path.

**Step 2 (single-authority for `_dm()`) is deliberately NOT done, and should not be attempted
without first resolving the dashboard ordering problem.** It is not merely unnecessary — both
values are already provably identical because both resolve through `nemesis_paths` — it is
actively harmful as long as `dashboard.py:120` precedes `dashboard.py:2195`. If genuine
single-authority for `_dm()` is wanted later, the prerequisite is moving the dashboard's own
publish earlier in its import sequence, which is a **dashboard** change, not an hw_monitor one,
and carries its own ordering risk worth scoping separately.

### Verification performed (real output, not assertion)
- `py_compile` clean **and a real import test** — the latter because a prior Window 3 session
  established that `py_compile` passes on modules that cannot actually be imported.
- **Control-backed proof of no import side effect:** `get_shared_db_path()` raises *before*
  importing hw_monitor (control — proves the check can fail) and **still raises after** the
  import, proving the publish does not fire at import time.
- **AST-verified placement and ordering:** zero module-level `set_shared_db_path` calls; the
  single call sits inside `main()` at a line number preceding both `init_db()` and
  `_start_windows_agent_listener()`.
- **Call-site trace: zero import-time calls** to `_db_connect()`/`_dm()`. Count reconciled by
  AST — **52 combined** (47 `_db_connect()` + 5 `_dm()`) across 45 functions, settling the
  earlier 54-vs-48 discrepancy (Window 1's grep-based 54 and my own 48 both counted slightly
  different things; 52 is the parsed figure).
- **No call appears in a default argument** — checked explicitly, since that exact shape
  (`_sleep=time.sleep` evaluated at import) is a documented trap from a prior session.
- Regression suites green: `test_conn_ingest.py` **46/46**, `test_conn_consent.py` **23/23**.

---

## Sequencing between Problem 1 and Problem 2

They share a theme (single-authority isn't honored everywhere) but **not a hard dependency** —
either can be built without the other.

**Explicit coordination risk, already flagged by Window 1 in tonight's handoff:** *"Window 3 is
scoping the broader grant gap + the hw_monitor DB-path fix as one plan. Both touch
`data_manager.py`'s `NAMESPACES` dict. My change is additive (one namespace); do not resolve
that merge blindly."* Having traced both fixes concretely, I can narrow this: **Problem 1's
recommended fix (Option C) does not touch `NAMESPACES` at all — it changes `allowed()`, a
different function in the same file — so it has no structural collision with Window 1's
`conn_consent` addition.** Problem 2's fix lives almost entirely in `hw_monitor.py`; the one
`data_manager.py`-adjacent piece (step 2 above) only changes what value is passed into
`DataManager(...)`, not the grants map. **Net: lower collision risk than it looked like from the
outside, but both still touch `alert_manager/data_manager.py` in the same file even if different
functions — sequence the actual edits, don't land them concurrently in parallel windows without
a rebase check.**

**Recommended order: Problem 2 first, then Problem 1.**
- Problem 2 is narrower (mostly one file), has no open architecture question — the fix shape is
  settled, only the tracing work is real effort — and is a live risk to a running service
  (ingest correctness on a bare restart) rather than a currently-inert gap.
- Problem 1 needs Paul's sign-off on an ADR-0006-adjacent decision (which of A/B/C, and the
  INSERT-only question) before any code lands.
- Both land as separate, single-variable commits (Tier 1 Rule 2) — do not bundle.
- Once Problem 1 lands, the paused error-code classification pass resumes with real, working
  grant status for every module, and the wiring rollout becomes meaningful everywhere, not just
  in `conn_consent`.

---

## Problem 3 — gateway-mode module-disable dependency risk (preliminary, not exhaustive)

Folded in mid-session per your request, checking whether the gateway-mode split scoped in
[gateway-mode-scoping.md](../roadmap/gateway-mode-scoping.md) could silently break a currently-
enabled module's dependents if a future "not gateway" install disables something. **Explicitly
scoped as a first pass, not a resolution** — the risk needs to be on record before gateway-mode
gets built, not discovered after, but full resolution can follow later.

**Finding: nothing breaks today, because no gateway-specific module exists yet.** Confirmed by
grep across `docs/roadmap/` and `docs/architecture/` — the only file referencing a
gateway/segmentation-specific module is `gateway-mode-scoping.md` itself. The entire capability
is unbuilt (consistent with that doc's own research: "zero code or ADR exists yet"). So there is
no live dependency to trace — the check is forward-looking by necessity.

Checked the two axes that scoping doc actually defines against every currently-active module:
- **DHCP/DNS ownership axis** — the `dhcp` module stays enabled regardless of gateway choice; a
  non-`nemesis` sub-mode degrades its own capability (per its own `MODE_CAPABILITIES` honesty
  table) but doesn't disable the module or anything that reads from it. Pi-hole DNS ownership
  rides this same axis and is unaffected by gateway-mode choice specifically (per that doc's own
  clarification).
- **L3 forwarding / gateway role axis** — Track C (agent connection telemetry: `conn_events`,
  `conn_seen_destinations`, `conn_consent`, hw_monitor's ingest path) is confirmed
  endpoint/agent-based end-to-end (ADR 0009), independent of network role. Nothing here is
  gateway-conditional.

**One already-identified, already-well-handled case worth citing as the pattern to reuse:**
[device-coverage-tier-indicator.md](../roadmap/device-coverage-tier-indicator.md)'s "state 4"
(never-agentable but computer-class devices — phones, Apple) explicitly depends on the
gateway/segmentation decision to become a real inspected coverage tier. Until that ships, its own
design note says it **displays identically to state 3** (the permanent IoT tier) rather than
showing wrong or missing data. This is exactly the graceful-degradation shape this problem needs
in general — flagged here as the model, not as a gap needing a fix.

**Principle to record now, for whenever a gateway-conditional module actually gets designed**
(most likely candidate: a segmentation/VLAN-assignment or DHCP-tiering-enforcement module — not
yet designed, no name yet): any table such a module owns that an always-on module needs to read
must be resolved the same way Problem 1 is being resolved here — either (a) the data is
core-owned per ADR 0001, so it's always available regardless of which optional modules are
enabled, or (b) the consuming always-on module has an explicit, tested fallback for "the
producing module is disabled," matching `device-coverage-tier-indicator.md`'s state-3-fallback
shape — never a silent assumption that the table exists and is current.

**Recommendation:** attach this as a standing checklist item to whichever ADR eventually formalizes
gateway mode, rather than treating it as a one-time audit — there's nothing concrete to audit
until that design exists.

---

## Decisions needed from Paul before any building starts

1. Approve Problem 1's fix shape — Option C (the `allowed()` exemption) recommended, or redirect
   to A/B, or a hybrid.
2. Confirm INSERT-only vs. table-wide scope for Problem 1's exemption (open question above).
3. Approve Problem 2's three-part fix and the recommended Problem-2-before-Problem-1 sequencing.
4. Say whether it's worth a quick live-DB query to confirm the `tickets`/`E-TICKETS-001`
   inference empirically before treating it as settled.
5. Acknowledge Problem 3 as recorded-for-now — no action needed until a gateway-conditional
   module is actually designed.

## Cross-references

`PUNCHLIST.md:3373` (original grant-gap finding, `dhcp`-specific), `PUNCHLIST.md:3097-3130`
(the 149-site retrofit item this scoping unblocks), `~/work/nemesis-internal/handoff/2026-08-08-window1-handoff.md`
(hw_monitor assessment, explicit hand-off to Window 3, consent-route grant-fix precedent),
`alert_manager/conn_consent_errors.py` (today's one working example of an Option-A-shaped fix —
left as-is, not required to change even if Option C ships, since it already works),
[gateway-mode-scoping.md](../roadmap/gateway-mode-scoping.md) (Problem 3's origin),
[device-coverage-tier-indicator.md](../roadmap/device-coverage-tier-indicator.md) (the
graceful-degradation model Problem 3 points to), `docs/architecture/0006-data-manager.md` (ADR
0006 itself — both Problem 1 and Problem 2 are effectively addenda to it, not exceptions from it).
