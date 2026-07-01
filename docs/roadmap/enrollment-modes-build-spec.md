# Build spec — ADR 0012 Enrollment Mode System

**Status:** BUILD-READY (design locked; **not yet built**). Execute-ready **post-trip**. This
turns [ADR 0012 — enrollment trust modes](../architecture/0012-enrollment-trust-modes.md) into a
buildable spec. Pre-trip, only MANUAL (`auto_approve = 0`) is live per
[ADR 0011](../architecture/0011-enrollment-security-model.md); everything here is post-trip work.

**References:** [ADR 0012](../architecture/0012-enrollment-trust-modes.md) (the four-mode
decision this spec implements); [ADR 0009 — security inspection proxy](../architecture/0009-security-inspection-proxy.md)
(the route-and-inspect verdict loop VENUE-auto consumes — **NOT BUILT**);
[ADR 0005](../architecture/0005-dns-firewall-device-auth-architecture.md) (`firewall.py`
chokepoint enforcing the trusted-vs-guest posture); [ADR 0001](../architecture/0001-database-and-module-architecture.md)
(canonical DDL init); [ADR 0006](../architecture/0006-data-manager.md) (atomic ops → Data Manager).

**Rule 8:** placeholders only (`<account>`, `<subnet>`, `<tailnet-ip>`, `<campaign-id>`,
`<token>`). Tokens are stored/logged **prefix-only** — never the full live value.

> Capture only — schema + build order for the mode system. No code changed by this doc.

---

## 0. Grounding (current state, from code)

- `agent_devices.enrollment_status` real values today: `approved`, `rejected`, `pending`,
  `pending_with_findings` (column `DEFAULT 'approved'`, grandfathering existing devices).
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
op** (ADR 0006), same claim pattern as the existing `enrollment_tokens` `uses` bump. When the last
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
treat a guest as trusted. The `firewall.py` chokepoint (ADR 0005) maps `guest_monitored` → the
contained/inspected segment; `approved` → the trusted segment.

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

**VENUE-auto is blocked on ADR 0009 (NOT BUILT).** VENUE admits devices into a guest/monitored
tier whose safety *is* the route-and-inspect containment — that verdict loop is
[ADR 0009 — security inspection proxy](../architecture/0009-security-inspection-proxy.md), which
does not exist yet. VENUE-auto therefore **cannot ship until ADR 0009 exists** (also depends on the
guest-network segment). Admitting guests without the inspection path would be admitting untrusted
strangers with no containment — the exact thing the VENUE warning promises against.

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
