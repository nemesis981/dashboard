# Roadmap — Diagnostics & Access-Control master plan

**Status:** master plan (buildable direction; reconciles today's scattered items into one
sequence). **Post-trip build** — EXCEPT the Submit-to-Support redaction leak (§2.1), which is
**pre-wider-release**. Authored by the docs window, 2026-07-02.

**Rule 8:** placeholders only — no real IPs/hosts/accounts (product support address = `support@<product>`).

> **Why this exists:** today (2026-07-02) produced five interconnected diagnostics + access-control
> items. This is the single reference to return to — not five cross-referencing docs. It
> **reconciles** (sequences overlaps, names dependencies), it does not re-audit. Full evidence lives
> in the sources; this is the plan.
>
> **Sources reconciled (all 2026-07-02):**
> - `docs/audits/diagnostics-page-audit-2026-07-02.md` — current-page audit (fixes, additions,
>   redaction/PII finding, cry-wolf reframe, duplicates). *All file:line refs below trace to it.*
> - `docs/roadmap/dashboard-roles-access-control.md` — three-tier role model + learning gate +
>   push-and-run authorization.
> - `docs/roadmap/connection-health-subsystem.md` — the full `conn_*` subsystem (the boundary the
>   interim reporting-health check must not collide with).
> - the push-and-run / server-tasks-consenting-agent design (one-click both-ends logging, agent-side
>   consent config, admin+key-pair authorization) — captured across the roles doc +
>   `diagnostic-scan-scope.md`.

---

## 1. Overview — how the pieces fit

Three layers that only make sense together:

- **Diagnostics visibility** — the owner must be able to SEE the truth about their box + fleet
  (what's healthy, what stopped reporting, is the data even landing). Today's page covers the
  server box but is **blind to the agent fleet** and cries wolf in normal states.
- **Access control** — some diagnostics are *safe to look at*; some *do things to remote machines*
  (push-and-run). The moment a diagnostic can TASK an agent, it needs a real authorization tier —
  hence the three-tier role model + key-pair gate.
- **Agent tasking (push-and-run)** — the sharp end: the server tells an agent to run something. It
  sits at the intersection — a **diagnostic feature** that **requires the access-control
  foundation** and an **agent-side consent gate** to be safe.

So the build direction is: **fix what's there → add fleet visibility (read-only, safe) → build the
access foundation → only then wire push-and-run** (the one thing that needs all of it). Read-only
diagnostics are cheap and safe and come first; anything that tasks a remote machine waits for the
authorization + consent layers.

---

## 2. FIX — existing diagnostics problems

### 2.1 ★ TOP PRIORITY (pre-wider-release) — Submit-to-Support ships device PII to an external address
- **What:** the `/api/diagnostics/submit` flow emails the report to an **external** support address
  (`support@<product>`), but redaction (`diagnostics/redact.py:20-23`) only scrubs **secret env
  values ≥8 chars** + an `sk-ant-`/base64 regex. It does **NOT** redact LAN/tailnet IPs, **MACs**,
  hostnames, emails, or device friendly-names. So `network_devices` (MACs/IPs), `alert_summary`
  (rule/device names), `vpn_status` (routes/ifaces), and `log_tails` (IPs/hostnames) leave the box
  **un-scrubbed** — while the UI tells the user "API keys and passwords are automatically hidden."
- **Where:** `diagnostics/redact.py:20-23`; submit handler `dashboard.py:4328-4370`; the UI promise
  string ~`dashboard.py:4487`.
- **Why it's TOP / not post-trip:** it's an active privacy leak of customer hardware PII to an
  outside inbox, and the UI actively implies it's safe. **This must be fixed before anyone uses
  Submit at any scale** — not a post-trip nicety.
- **Fix direction:** broaden `redact.py` with IP / MAC / hostname / email passes AND/OR scope what
  `/submit` includes (exclude the device inventory + raw log tails, or redact them); update the UI
  copy to state *what* is sent, not just that secrets are hidden. Watch the existing over-redaction
  risk (`_KEY_PATTERN` at `redact.py:22` clobbers any 32+ base64-ish run → can `[REDACTED]` legit
  hashes). **Effort:** ~1–2 hr.

### 2.2 Cry-wolf false-warns — four checks warn in NORMAL healthy states
- **What/where:** **VPN Status** defaults to "warn: No active VPN tunnel" when no tunnel exists
  (`diagnostics/vpn_status.py:80-81`) — but most owners run no outbound VPN; **Network Devices**
  warns on "untrusted" count (every new phone) (`network_devices.py:25`); **Pi-hole** returns warn +
  raw exception when Pi-hole simply isn't installed (`pihole_health.py:77-82`); **Suricata** flips to
  warn on any log "Warn/Error" line (`suricata_health.py:52-71`).
- **Why it matters:** a page that shows orange in the normal case trains a non-expert to ignore it —
  it destroys the signal. Second-highest-value fix after redaction.
- **Fix direction:** reframe each "not-configured / normal" state to **info/neutral**, not warn.
  **Effort:** ~30 min each (VPN, Pi-hole); folds into the trims for Network-Devices (§4).

### 2.3 Raw-output / expert-noise — useful signal buried in monospace blobs
- **What/where:** every check's detailed `output` renders as a raw `<pre>` blob
  (`dashboard.py:4406, 4447`). Worst offenders: **UFW** raw `ufw status verbose` with no
  interpretation (`ufw_rules.py`), **Suricata** raw 20-line log tail (`suricata_health.py:52-71`),
  **Log Entries** pure raw tails (`log_tails.py:29`), **Anomaly State** full KV dump
  (`anomaly_state.py:25`), **Alert Summary** raw column dump + fragile `'total' in dir()`
  (`alert_summary.py:84`).
- **Fix direction:** summarize (UFW → default policy + allow/deny counts; Suricata → keep P1/P2/P3,
  drop/pro-tier the raw tail; Anomaly → "enabled, N incidents this week"); push genuinely raw blobs
  (log tails) behind the **pro tier** and label them "for support." **Effort:** ~20–60 min each.

### 2.4 Service-status unit-list drift
- **What/where:** `diagnostics/service_status.py:16` hardcodes a unit list that **drifts from the
  canonical morning-status set** — omits `malware-canary`, `diagnostics-watcher`, `vpn-dns-guard`.
- **Fix direction:** reconcile to the canonical six+ services. **Effort:** ~15 min.

---

## 3. ADD — new diagnostics (all read-only; server-only unless noted)

**The whole missing category:** every existing check inspects the server box or the LAN `devices`
table — **none inspect the enrolled AGENT FLEET** (`agent_devices` / per-device `hw_metrics`). That
gap is where the value is. All of these are read-only and require **no agent changes** (verified
against live DDL).

| # | Add | Shows | Buildable from (server-only) | Effort |
|---|---|---|---|---|
| **1 ★** | **Agent Reporting-Health (per device)** | last reported, expected-vs-seen cadence, largest gap, **"CPU/RAM landing / NOT landing"** flag | `agent_devices.agent_last_seen` (`hw_monitor.py:190`, indexed `:218`) + `hw_metrics.device_id/timestamp/cpu_percent/ram_used_gb` (`:63-90`). **CONFIRMED server-only, no agent changes.** | small–med |
| 2 | **Enrollment / de-enrollment health** | devices stuck `pending`, plus `rejected`/`uninstalled`, unresolved pre-enroll findings | `agent_devices.enrollment_status/pre_enrollment_scan/enrollment_has_findings/uninstalled_at` (`:195-293`). Server-only. | small |
| 3 | **Scan coverage / stale-scan** | per-device last scan + "overdue" flag; never-scanned count; stuck queue | `agent_devices.last_scan_*`, `scan_jobs`/`scan_schedules`/`scan_queue` (`:222-301`). Server-only. | small–med |
| 4 | **`alerts.db` health** | `PRAGMA integrity_check`, DB+WAL size, per-owner row counts/growth | the DB directly — **no integrity check exists anywhere today.** Server-only, no new schema. | small |
| 5 | **Alert-delivery self-test** | SMTP config resolves + last-send-success (beyond "vars set") | `email_utils.send_email` path + `nemesis.env` SMTP vars. Server-only (config-validate + last-status; no spam-send). | small |

**#1 is the top add** — the fleet is an invisible black box today, and #1 **doubles as the standing
detector for the known empty-cpu/ram bug** (`overnight-run-2026-07-02.md` §3), whose origin is the
`cpu_percent = _val("cpu_pct")` / `ram_mb` payload-mapping mismatch (`hw_monitor.py:1215,1225`). A
check counting `cpu_percent IS NULL` per `device_id` surfaces it the moment it happens.

**Deferred:** clock-drift/receipt-timing is **NOT server-only** (needs a `received_ts` column) →
belongs to the connection-health subsystem, not a one-off column. Do not build now.

### ⚠️ Reconciliation — Reporting-Health (#1) vs the connection-health subsystem
These two must **not collide.** Explicit boundary:
- **#1 Agent Reporting-Health = the lightweight, server-only INTERIM.** It **reads existing rows
  only** (`agent_devices` + `hw_metrics`). No new tables. It answers "did data arrive, and is it
  real?" from what already lands.
- **`connection-health-subsystem.md` = the full, later system.** It builds **new `conn_*` tables**
  and **requires agent changes** (adaptive ramp, reply-based miss detection, tracert-on-miss,
  week+rollup retention). It supersedes the *receipt* side when built.
- **GUARDRAIL:** #1 must **NOT introduce a competing `conn_*`-style schema.** When the full
  subsystem lands, #1's read-only view retires or re-points at `conn_*`. Interim now, full later —
  same question, two lifespans.

---

## 4. TRIM — duplicates (defer to the live endpoints)
Each duplicates a live subsystem and/or misleads; corroborated by `architecture-debt-audit-2026-07-02.md`.

- **`hardware`** (`diagnostics/hardware.py:26`) — one-shot `/proc` + `sensors` snapshot **duplicates
  the live hw_monitor** (`/api/hw/devices`, `/api/hw/metrics-for-device`, `dashboard.py:5715,5761`).
  *(arch-debt Finding 8.)* → trim to "hardware monitor healthy? see live page" or drop.
- **`network_devices`** (`network_devices.py:25`) — **duplicates the live device scanner**
  (`/api/scan/devices` `dashboard.py:5794`) **and is the PII source** in §2.1. → exclude from
  submit; defer the display to the live page.
- **`vpn_status`** (`vpn_status.py:19`) — **duplicates `/api/vpn-status`** (`dashboard.py:1975`) +
  the misleading default-warn (§2.2). *(arch-debt Finding 15.)* → drop or reduce to info-only.

Trimming these also removes two of the four cry-wolf warns (§2.2) and shrinks the PII surface (§2.1)
— so **§2.1 + §2.2 + §4 are one coordinated pass**, not three.

---

## 5. ACCESS-CONTROL foundation (build-on, not from-scratch)
Full design: `dashboard-roles-access-control.md`. Summary + the seam to build on:

- **Build ON the existing seam, not from scratch:** `users.role` already exists
  (`alert_manager/database.py`, `'admin'|'user'`, default `'admin'`, commented "commercial seam");
  Flask-Login is done. But **role is unenforced** — everyone is created admin. The work is
  enforcement + tiering, not a new auth system.
- **Three-tier model:** **USER** (view-only + limited own-settings) / **SUB-ADMIN** (learning-gated —
  earns each powerful capability per tutorial+quiz, per-capability) / **FULL ADMIN** (ungated owner).
- **Push-and-run authorization (defense-in-depth) — ALL required:** (a) admin-tier **role**,
  (b) **learning-gate unlock** for that capability (sub-admins), (c) **key-pair / auth verification**
  (new admin key pair vs. tie into ADR 0011 enrollment keys — TBD), plus (d) the **agent-side
  per-device consent gate** (server-tasks-consenting-agent: server authorizes + agent consents).
- **CRITICAL BOUNDARY:** the learning gate proves **competence, NOT authorization** — it never
  replaces role+key-pair. A quiz stops an untrained delegate, not an attacker.
- **DB:** extend the `role` seam to three tiers + add a per-capability `user_capability_unlocks`
  table (actor seam, routed through the Data Manager / ADR 0006). Guarded `ALTER`, one canonical
  CREATE (ADR 0001).

---

## 6. DEPENDENCY MAP + BUILD ORDER

### Dependencies (what needs what)
- **§2.1 redaction** — independent, blocks nothing, blocks *wider Submit use*. Do first.
- **§2.2 / §2.4 / §2.3 reframes** — independent, cheap, no dependencies.
- **§4 trims** — independent; coordinate with §2.1 (PII) + §2.2 (warns) as one pass.
- **§3 adds #1–#5** — independent of each other; all read-only, server-only; depend on nothing.
  **#1 carries a guardrail** vs the connection-health subsystem (§3 reconciliation) — not a
  dependency, a non-collision rule.
- **§5 access-control** — the role/key-pair foundation. Depends on nothing to *start* (the seam
  exists); the **learning-gate tier depends on the AI-tutorials plan** (`ai-generated-tutorial-walkthrough.md`).
- **Push-and-run (the sharp end)** — depends on **§5 (role + key-pair)** AND the **agent-side
  consent gate**. Do NOT wire push-and-run before both exist.

### Recommended single sequence (across ALL of it)
0. **PRE-WIDER-RELEASE (not post-trip): §2.1 redaction/PII fix.** Before anyone hits Submit at scale.
1. **Cheap safe wins (post-trip, any order):** §2.2 cry-wolf reframe + §2.4 service-list + §4 trims
   (one coordinated pass — they overlap), then §2.3 output summaries.
2. **Fleet visibility (read-only, server-only):** §3 **#1 Agent Reporting-Health** first (highest
   value + bug detector; obey the `conn_*` guardrail), then #4 DB health, #2 enrollment, #3 scan
   coverage, #5 alert-delivery. All safe, no agent changes.
3. **Access-control foundation:** §5 — enforce USER vs ADMIN on the existing seam, then add the
   key-pair gate on sensitive actions. (SUB-ADMIN learning tier waits on the AI-tutorials plan.)
4. **Push-and-run (last, most sensitive):** only after §5's role+key-pair AND the agent-side consent
   gate are in place. This is the item that needed the whole stack.
5. **Later / supersede:** the full **connection-health `conn_*` subsystem** — retires/re-points
   #1's interim receipt view when built.

### Risk/effort flags
- **Cheap + server-only + safe (do freely):** §2.2, §2.3, §2.4, §4, §3 #1–#5. All read-only, no
  agent changes.
- **Must-fix-first (privacy):** §2.1 — small effort, high stakes, gates Submit.
- **Design-heavy + security-sensitive (do carefully, later):** §5 access-control and especially
  **push-and-run** — these task remote machines and gate dangerous capability; they get the
  full role + key-pair + agent-consent + (for delegates) learning-gate stack. Never shortcut.

## Cross-references
`docs/audits/diagnostics-page-audit-2026-07-02.md` (evidence for §2–§4),
`docs/roadmap/dashboard-roles-access-control.md` (§5), `docs/roadmap/connection-health-subsystem.md`
(§3 boundary), `diagnostic-scan-scope.md` (push-and-run scope),
`ai-generated-tutorial-walkthrough.md` (learning gate), `architecture-debt-audit-2026-07-02.md`
(dup corroboration), `overnight-run-2026-07-02.md` (empty-cpu/ram bug #1 detects); ADR 0001 (DB),
0005/0011 (auth/keys), 0006 (Data Manager), 0007 (device-user model).
