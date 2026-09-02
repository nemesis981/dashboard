# Build spec — ADR 0012 Enrollment Mode System

**Status:** PARTIAL (moved from PARKED 2026-09-02) — **Step 1 (BULK-MANUAL) SHIPPED**
2026-09-02, design remains locked for steps 2–4, which are **not yet built.** See §7 for the
current dependency picture, corrected same day (§3's enforcement-premise finding below).
"Execute-ready post-trip" is satisfied and the conditional is dropped — the Wisconsin trip
referenced was a mid-July 2026 deployment, well past. This
turns [ADR 0012 — enrollment trust modes](../architecture/0012-enrollment-trust-modes.md) into a
buildable spec. Only MANUAL (`auto_approve = 0`) and BULK-MANUAL are live per
[ADR 0011](../architecture/0011-enrollment-security-model.md); steps 2–4 remain future work.

**References:** [ADR 0012](../architecture/0012-enrollment-trust-modes.md) (the four-mode
decision this spec implements); [ADR 0009 — security inspection proxy](../architecture/0009-security-inspection-proxy.md)
(the route-and-inspect verdict loop VENUE-auto consumes — **NOT BUILT**);
[ADR 0005](../architecture/0005-dns-firewall-device-auth-architecture.md) (`firewall.py`
chokepoint — the trusted-vs-guest posture mapping this spec needs is undesigned as of this
writing, see §3 and §7); [ADR 0001](../architecture/0001-database-and-module-architecture.md)
(canonical DDL init); [ADR 0006](../architecture/0006-data-manager.md) (atomic ops → Data Manager).

**Rule 8:** placeholders only (`<account>`, `<subnet>`, `<tailnet-ip>`, `<campaign-id>`,
`<token>`). Tokens are stored/logged **prefix-only** — never the full live value.

> Capture only — schema + build order for the mode system. No code changed by this doc.

---

## 0. Grounding (current state, from code)

- **⚠ Corrected 2026-09-02** — `agent_devices.enrollment_status` has **at least seven** live
  values today, not four. The original four: `approved`, `rejected`, `pending`,
  `pending_with_findings` (column `DEFAULT 'approved'`, grandfathering existing devices). Three
  more exist and must be accounted for when placing the two NEW values this spec adds
  (`guest_monitored`, `guest_expired`) into this space: `pending_unverified`
  (`core_module/hw_monitor/hw_monitor.py:4034` write site; `dashboard.py`'s `PENDING_STATUSES`
  read site), `revoked` (`dashboard.py:4833` write site), and `uninstalled`
  (`diagnostics/agent_enrollment_integrity.py:209` write site) — 13 non-test files reference
  `enrollment_status` in total, not the ~4 the original grounding implied. **Any new status must
  also be registered in `dashboard.py`'s `PENDING_STATUSES` bucketing** — that bucketing exists
  specifically because an unlisted status used to silently disappear from the dashboard (its own
  comment documents the recurring bug); it now renders an unmatched status as `unknown` instead,
  so an unregistered new value fails visibly rather than silently, but registering it is still a
  required build step this spec did not previously name.
- Manual + bulk-manual approvals already write an audit row via the existing
  `_audit(action="agent_approve")` path in `POST /api/agent/<device_id>/approve` — the human
  actor (`enrolled_by`) is the implicit record.
- `agent_devices` already carries `hw_stable_id`, `hw_is_virtual`, `connection_type`,
  `agent_last_seen` — reused below, not re-added.
- All new CREATEs land in the canonical `alert_manager/database.py` init (one DDL per table,
  ADR 0001). Per-admit atomic claims are **Data Manager candidate ops** (ADR 0006).

---

## 1. Schema — auto-enroll audit log (`enrollment_auto_audit`)

Records **FLEET-auto and VENUE-auto events ONLY.** MANUAL / BULK-MANUAL are already recorded via
the existing human-actor approve/audit path — this table exists specifically to reconstruct *what
was admitted while no human was watching, and which campaign let it in.*

```sql
CREATE TABLE IF NOT EXISTS enrollment_auto_audit (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL    NOT NULL,          -- epoch seconds; when the auto-admit fired
    device_id       TEXT    NOT NULL,          -- agent_devices.device_id admitted
    hw_stable_id    TEXT,                      -- TOFU fingerprint stable id
    hw_fingerprint  TEXT,                      -- fingerprint signal hashes / summary (JSON)
    hw_is_virtual   INTEGER DEFAULT 0,         -- virtualized-environment flag
    source_ip       TEXT,                      -- server-observed source (<tailnet-ip>), unforgeable
    source_subnet   TEXT,                      -- campaign subnet bound in force (<subnet>), if any
    token_prefix    TEXT,                      -- granting token PREFIX only (Rule 8 — never full)
    campaign_id     INTEGER NOT NULL,          -- FK -> enrollment_campaigns.id (<campaign-id>)
    mode            TEXT    NOT NULL,          -- 'fleet-auto' | 'venue-auto'
    created_by      TEXT    NOT NULL,          -- campaign-creating account (<account>)
    network_posture TEXT    NOT NULL           -- resulting posture: 'trusted' | 'guest-monitored'
);
CREATE INDEX IF NOT EXISTS idx_enroll_auto_audit_campaign ON enrollment_auto_audit(campaign_id);
CREATE INDEX IF NOT EXISTS idx_enroll_auto_audit_device   ON enrollment_auto_audit(device_id);
```

- `source_ip` is the **server-observed** connection source (ADR 0011: unforgeable "from where"),
  not client-reported.
- `token_prefix` mirrors the existing `_audit(rule_id=token[:8])` convention — Rule 8, prefix only.
- One row **per auto-admit**, written in the same transaction that flips the device state.

---

## 2. Schema — campaign records (`enrollment_campaigns`)

A **scoped, expiring, logged GRANT** — explicitly **NOT a persistent setting.** A campaign is
the *only* way FLEET/VENUE auto ever happens, and it ends itself.

```sql
CREATE TABLE IF NOT EXISTS enrollment_campaigns (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    mode          TEXT    NOT NULL,            -- 'fleet-auto' | 'venue-auto'
    created_by    TEXT    NOT NULL,            -- <account> that set the campaign up
    created_at    REAL    NOT NULL,            -- epoch seconds
    -- ── bounds: AT LEAST ONE must be non-NULL (an unbounded campaign is FORBIDDEN) ──
    expires_at    REAL,                        -- time-window bound (NULL = no time bound)
    max_devices   INTEGER,                     -- device-count bound (NULL = no count bound)
    source_subnet TEXT,                        -- source-subnet bound <subnet> (NULL = no subnet bound)
    remaining     INTEGER,                     -- decrements per admit when max_devices set; 0 => exhausted
    warning_ack   INTEGER NOT NULL DEFAULT 0,  -- typed-"yes" per-mode warning captured at SETUP
    status        TEXT    NOT NULL DEFAULT 'active'  -- 'active' | 'expired' | 'exhausted' | 'stopped'
);
CREATE INDEX IF NOT EXISTS idx_enroll_campaigns_active ON enrollment_campaigns(status, mode);
```

**Invariant (enforce at creation): at least one of `expires_at`, `max_devices`, `source_subnet`
MUST be set.** A campaign with no bound is rejected — that would recreate the `auto_approve = 1`
persistent-toggle hole ADR 0011 closed. Also reject creation unless `warning_ack = 1`.

**Self-termination — an admit is permitted ONLY if all in-force bounds hold:**
```
status = 'active'
AND (expires_at    IS NULL OR expires_at  > now)
AND (remaining     IS NULL OR remaining   > 0)
AND (source_subnet IS NULL OR admit_source_ip ∈ source_subnet)
```
On each admit, atomically decrement `remaining` (when `max_devices` set) — **Data Manager atomic
op** (ADR 0006). **⚠ Corrected 2026-09-02 — this is NOT the same claim pattern as the existing
`enrollment_tokens` `uses` bump, and that difference is real scoping work, not a detail.** The
existing DM ops (`next_sequence`, `increment_counter`, `upsert`) have no `WHERE`-guarded
conditional decrement — `increment_counter` cannot express "refuse the admit if the bound is
already spent," which is the actual security property this self-termination check depends on.
Building this needs either a new Data Manager op (a `WHERE remaining > 0` guarded decrement,
consistent with ADR 0006's existing atomic-op pattern) or a documented raw-connection exception
— estimate it as new work, not reuse. **Both new tables (`enrollment_campaigns`,
`enrollment_auto_audit`) also need Data Manager allowlist registration before either can be
written** — the loader refuses ungranted writes by design, same class of requirement as
`ROUTE_MINIMUMS` for new endpoints. When the last
in-force bound trips (window passed / `remaining` hits 0 / campaign stopped), flip `status` to
`expired` / `exhausted` / `stopped` and **enrollment reverts to MANUAL automatically.** There is no
setting left flipped — the unsafe condition cannot persist by neglect.

---

## 3. Distinct trust outcomes (FLEET ≠ VENUE, never the same flag)

FLEET and VENUE write **different `agent_devices` states — never a shared `approved` boolean:**

| Mode | `agent_devices.enrollment_status` written | Tier / posture |
|---|---|---|
| MANUAL / BULK-MANUAL approve | `approved` (existing) | trusted |
| FLEET-auto | `approved` (existing trusted tier) | trusted |
| VENUE-auto | **`guest_monitored`** (NEW distinct value) | guest / monitored — **NOT trusted** |
| VENUE guest aged out | **`guest_expired`** (NEW) | de-enrolled / dormant |

**Hard rule:** no code path may write `approved` for a VENUE admit. `guest_monitored` is a
first-class distinct state so any read-any consumer (dashboard, `firewall.py`) cannot accidentally
treat a guest as trusted.

**⚠ Corrected 2026-09-02 — the paragraph below describes a DEPENDENCY, not existing
infrastructure.** `firewall.py` today has no `guest_monitored`/trusted-segment mapping of any
kind — it is a `ufw` rule-manipulation library (allow/deny by address and port), and ADR 0005's
own status line already says the firewall-rules engine itself is undesigned. What actually gates
trust today is a heartbeat check
(`core_module/hw_monitor/hw_monitor.py:3689`, `_agent_approved()`): any non-`approved` status —
including a future `guest_monitored` — stops that device's heartbeats, which is a fail-safe
outcome (a guest is never accidentally trusted) but not the contained-and-monitored guest tier
this section's VENUE design assumes. **Building VENUE therefore depends on ADR 0005's posture
mapping existing, not just on ADR 0009's inspection-proxy verdict loop (§7) — the `firewall.py`
chokepoint below is what that dependency would need to provide, once built:**

The `firewall.py` chokepoint (ADR 0005, once its posture-mapping is built) would map
`guest_monitored` → the contained/inspected segment; `approved` → the trusted segment.

**Build decision (recommend option A):**
- **A —** encode tier in `enrollment_status` literals (`guest_monitored` / `guest_expired`).
  Minimal schema churn; the value itself carries the tier. *(Recommended.)*
- **B —** add an explicit `trust_tier TEXT` column (`'trusted' | 'guest'`) alongside status.
  Cleaner querying, one extra migrated column. Choose at build.

---

## 4. Guest-tier lifecycle (VENUE transient; FLEET/trusted permanent)

- **VENUE `guest_monitored` rows carry a TTL — auto-de-enroll on absence.** Reuse the existing
  `agent_devices.agent_last_seen`: a sweeper (piggyback on an existing periodic task) flips a
  `guest_monitored` device to `guest_expired` (or dormant) once it hasn't reported within
  `GUEST_TTL`. Guest state must not accumulate strangers' devices forever.
- **FLEET / trusted devices are permanent** — no absence expiry; they persist like any
  manually-approved device.
- **`GUEST_TTL` — OPEN VALUE, decide at build.** Candidate shape: a short *dormancy* threshold
  (device drops to dormant after N hours of absence, reconnects cleanly on return — matches the
  venue-guest "dormant when the guest leaves" flow) plus a longer *hard de-enroll* after M days.
  Whether dormancy and hard-expiry are one threshold or two is the build decision.

---

## 5. Gate placement (typed-"yes" where the human actually is)

- **FLEET-auto / VENUE-auto → typed-"yes" at CAMPAIGN SETUP.** No human is present at enroll time,
  so the gate is the acknowledgement of the per-mode warning captured when the campaign is created
  (`enrollment_campaigns.warning_ack = 1`). Individual admits during the window are unattended by
  design. **No per-device gate at enroll.**
- **BULK-MANUAL → typed-"yes" at the device-list review page.** The human is present, sees the
  concrete list of PENDING devices, and types the confirmation before the batch approve fires.
- **MANUAL → existing per-device approve button** (implicit single human decision; no typed gate).

---

## 6. Per-mode warnings (each tied to its ACTUAL failure condition)

- **FLEET-auto — physical/ownership control:** *"FLEET auto-approve grants full trusted-network
  access without review. Use ONLY for devices you physically own and control. Any device
  presenting a valid campaign token during the window is trusted automatically."*
- **VENUE-auto — network isolation:** *"VENUE auto-enroll admits UNKNOWN devices you do NOT
  control. These devices are NOT trusted. Ensure guest-network isolation is active before starting
  this campaign — containment, not ownership, is what makes this safe."*
- **MANUAL / BULK-MANUAL — none** (a human reviews before trust is granted).

---

## 7. Dependency callout + build order

**VENUE-auto is blocked on TWO things, not one — corrected 2026-09-02.** VENUE admits devices
into a guest/monitored tier whose safety *is* the route-and-inspect containment:

1. **ADR 0009 (NOT BUILT)** — the route-and-inspect verdict loop,
   [ADR 0009 — security inspection proxy](../architecture/0009-security-inspection-proxy.md).
2. **ADR 0005's posture-enforcement mapping (NOT BUILT — see §3's correction above).** Even with
   ADR 0009's verdict loop in place, nothing today maps a `guest_monitored` device onto an
   actual contained network segment — `firewall.py` has no such mapping, and ADR 0005 itself
   states the firewall-rules engine is undesigned. Today's only enforcement is a heartbeat gate
   that cuts an unapproved device off entirely, which is safe (never accidentally trusted) but
   is not the "contained and monitored" tier the VENUE warning describes.

VENUE-auto therefore **cannot ship until both exist.** Admitting guests without either the
inspection path or the posture mapping would be admitting untrusted strangers with no real
containment — the exact thing the VENUE warning promises against.

**FLEET-auto and BULK-MANUAL have no such dependency** — they operate entirely within the existing
trusted tier + `agent_devices` states and can ship first.

**Suggested build order:**
1. **BULK-MANUAL** — review-page list + typed-"yes" batch approve. Pure UI/endpoint over the
   existing `approved` path; lowest risk, immediate SMB value.
2. **FLEET-auto** — `enrollment_campaigns` + `enrollment_auto_audit` + campaign-setup gate +
   atomic bounded admit into `approved`. No 0009 dependency.
3. **ADR 0009 verdict loop** — the route-and-inspect inspection proxy (its own build).
4. **VENUE-auto** — `guest_monitored` state + guest lifecycle/TTL + venue campaign, **gated on
   step 3.**

Steps 1–2 deliver the SMB batch-provisioning story pre-VENUE; steps 3–4 unlock the venue tier once
the inspection path is real.
