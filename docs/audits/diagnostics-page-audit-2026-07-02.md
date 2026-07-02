# Diagnostics-page audit — 2026-07-02

> **READ-ONLY (Rule 1).** Survey + recommend only — **no code changed.** Audits the current
> diagnostics page against the product: is what's there useful to a no-IT-department owner, and
> what's worth adding. Feeds smooth building later. Docs-window (Win 2). Rule 8: repo-relative
> paths, no real IPs/hosts/accounts (the product support address is shown as `support@<product>`).

## Scope & method
Two read-only passes over `dashboard.py` (the page + API), the `diagnostics/` check package, and
`alert_manager/hw_monitor.py` (the fleet data), cross-referenced to the connection-health /
diagnostics / push-and-run roadmap items. Reporting-health data-availability independently verified
against the live DDL. Cited `file:line` throughout. Nothing changed.

## How the page is wired
- Route **`diagnostics_page()` — `dashboard.py:4376`.** Renders one card per check by iterating
  `_diag.CHECKS`, building cards **server-side in Python** (`dashboard.py:4382-4408`) to dodge the
  f-string/JS-quote bug; tiered beginner/intermediate/pro descriptions come from each module's
  `META["descriptions"]`, swapped client-side by `/static/tier.js`.
- **Registry — `diagnostics/__init__.py:25-38`** (`CHECKS`, ordered list of 12 module objects;
  `_CHECK_MAP` at `:40`). `run_check()` (`:43`) runs one module's `run()`, wraps exceptions, and
  pipes every result through `redact_result()` (`:66`).
- **API:** `/api/diagnostics/run/<check_id>` (`dashboard.py:4316`), `/run-all` (`:4322`), `/submit`
  (`:4328`) — the submit flow redacts, builds a plain-text report, and **emails it to an external
  support address** (`support@<product>`) cc the operator via `WATCHDOG_EMAIL` SMTP.
- **The 12 checks, in display order:** `config_check, service_status, disk_space, hardware,
  ufw_rules, suricata_health, pihole_health, network_devices, alert_summary, anomaly_state,
  vpn_status, log_tails`.

---

## PART 1 — Audit of what exists today

### Category A — Useful as-is for a non-technical owner (keep)
| Check | Where | Why it works |
|---|---|---|
| **Configuration Check** | `diagnostics/config_check.py:28` | ✓/✗ of required env keys (presence only, never values) + plain consequence text ("Email alerts…will not work"). Actionable, safe-by-design. |
| **Service Status** | `diagnostics/service_status.py:27` | ✓/✗ per systemd unit + one-line verdict. Clear. *Minor:* hardcoded unit list (`:16`) drifts from the canonical morning-status set — omits `malware-canary`, `diagnostics-watcher`, `vpn-dns-guard`; ~15 min reconcile. |
| **Disk Space** | `diagnostics/disk_space.py:17` | `df -h` with tmpfs/removable skip-lists + warn≥80/error≥90 thresholds + plain verdict. Raw `df` table in `output` but badge+summary carry the meaning. |

### Category B — Useful signal, but raw / expert-facing output or false warns (improve)
| Check | Where | Issue + fix | Effort |
|---|---|---|---|
| **UFW Rules** | `diagnostics/ufw_rules.py:17` | Dumps raw `ufw status verbose`; verdict only "rules retrieved" — opaque table for a non-expert; silent warn if passwordless sudo absent. Summarize (default policy + allow/deny counts). | ~1 hr |
| **Suricata Health** | `diagnostics/suricata_health.py:18` | Good P1/P2/P3 counts, but appends a **raw 20-line log tail** (expert noise; any "Error/Warn" line flips status to warn) and `sudo tail -n 200000` is heavy. Keep counts, drop/pro-tier the raw tail (`:52-71`). | ~45 min |
| **Pi-hole Health** | `diagnostics/pihole_health.py:21` | Useful stats when configured; but returns **"warn" + raw exception** when Pi-hole simply isn't installed/`PIHOLE_PASSWORD` unset (`:77-82`) — a scary orange for a non-problem. Treat "not configured" as info. (`PIHOLE_IP` default `127.0.0.1:8080` is clean here.) | ~30 min |
| **Recent Log Entries** | `diagnostics/log_tails.py:29` | `tail -n 30` of 3 logs — pure raw blobs, zero interpretation. Value is as a *support attachment*, not a user check. Label "for support" / pro-tier only. | ~20 min |
| **Alert DB Summary** | `diagnostics/alert_summary.py:25` | Pending-review count is genuinely useful (flips to warn — actionable). But raw column dump + a fragile `'total' in dir()` idiom (`:84`). Minor polish. | ~20 min |
| **Anomaly State** | `diagnostics/anomaly_state.py:25` | Clean "disabled" short-circuit (`:40-49`), but dumps the full KV store + table row counts — developer internals, not owner-actionable. Surface "enabled, N incidents this week"; hide KV behind pro tier. | ~45 min |

### Category C — Stale / duplicated / misleading (decide: trim, defer, or drop)
- **Hardware Metrics — DUPLICATE of the live hw_monitor.** `diagnostics/hardware.py:26` reads
  `/proc/loadavg`, `/proc/meminfo`, `df`, `sensors` for a one-shot snapshot — **duplicates**
  `alert_manager/hw_monitor.py` (continuous `sensors -u`, `:435-543`) and the live endpoints
  `/api/hw/devices`, `/api/hw/metrics-for-device` (`dashboard.py:5715, 5761`), `/hardware/all`
  (`:6982`). Cruder (raw `sensors` text; "load average 1.4" means nothing to a non-expert) and
  overlaps Disk (#3). *Fix:* trim to "hardware monitor healthy? → see live page" or drop
  (+ remove from `__init__.py`). ~30 min. **(Matches arch-debt audit 2026-07-02 Finding 8.)**
- **Network Devices — DUPLICATE + PII-LEAK RISK.** `diagnostics/network_devices.py:25` dumps the
  `devices` table (IP, **MAC**, friendly_name, trust) — **duplicates** the live device scanner
  (`/api/scan/devices` `dashboard.py:5794`). Two problems: (a) low non-expert value + "untrusted
  count" warns on every new phone; (b) **it flows verbatim into the external support email, and
  `redact.py` does NOT scrub IPs/MACs/hostnames/device-names** (see cross-cutting finding). *Fix:*
  exclude from submit or add IP/MAC redaction. ~1 hr.
- **VPN Status — MISLEADING default-warn + overlap.** `diagnostics/vpn_status.py:19` checks tunnel
  ifaces / `mullvad` / `wg`; **defaults to "warn: No active VPN tunnel detected" whenever no tunnel
  exists** (`:80-81`) — but most owners run no outbound VPN, so the *normal* state shows a scary
  orange warning. Overlaps live `/api/vpn-status` (`dashboard.py:1975`) + emits a raw route dump.
  *Fix:* "no VPN configured" → info, not warn. ~30 min. **(Relates to arch-debt Finding 15,
  VPN-detection ×3.)**

### Page-level assessment
- **Presentation:** good bones — icon + tiered plain-language description + colored badge + summary
  is the right layer for a non-expert. But **every check's detailed `output` is a raw monospace
  `<pre>` blob** (`dashboard.py:4406, 4447`); harmless where ignorable, alarming where it warns.
- **★ TOP CROSS-CUTTING FINDING — redaction scope is narrower than the UI promises.** Redaction is
  applied before display AND submit (`__init__.py:66`, `dashboard.py:4331`), **but only scrubs
  secret env VALUES ≥8 chars + an `sk-ant-`/base64 regex** (`redact.py:20-23`). It does **NOT**
  redact LAN/tailnet IPs, **MACs**, hostnames, emails, or device names. Since submit emails to an
  **external** address, `network_devices` (MACs/IPs), `alert_summary` (rule/device names),
  `vpn_status` (routes/ifaces), and `log_tails` (may carry IPs/hostnames) all leave the box
  **un-scrubbed** — while the UI tells the user "API keys and passwords are automatically hidden"
  (technically true, but a user reasonably assumes more). **Highest-value fix on the page.** Broaden
  `diagnostics/redact.py` (add IP/MAC/hostname passes) and/or scope what `/submit` includes.
  ~1–2 hr. *(Also a minor over-redaction risk: `_KEY_PATTERN` at `redact.py:22` clobbers any 32+
  base64-ish run → can `[REDACTED]` legit hashes/IDs.)*
- **False-alarm UX (second cross-cutting theme):** four checks flip to orange/warn in ordinary
  HEALTHY states — **VPN** (no tunnel = normal), **Network Devices** (new phone = "untrusted"),
  **Pi-hole** (not installed), **Suricata** (any log "Warn" line). For a non-expert, a page that
  cries wolf in the normal case trains them to ignore it. Reframing these four to info/neutral is
  the biggest UX win after redaction.
- **Submit flow:** clear + well-tiered + fails gracefully if email unset (`dashboard.py:4364`). One
  gap: it tells the user secrets are hidden but **not what data is being sent** (device list, logs).

---

## PART 2 — Recommended additions (ranked by value)

**The whole missing category:** every existing check inspects the **server box or the LAN `devices`
table — none inspect the enrolled AGENT FLEET** (`agent_devices` / per-device `hw_metrics`). That
is where the highest-value additions are. All of #1–#5 are **read-only, server-only, no agent
changes.**

### 1. ★ Per-device Agent Reporting-Health — the roadmap item — SERVER-ONLY, NO AGENT CHANGES: **CONFIRMED**
- **Shows:** one row per enrolled device — last reported (min ago), expected-vs-seen sample count
  over last N hours, largest gap, and a plain **"CPU/RAM reading: landing / NOT landing"** flag;
  warns on stale/gappy devices or empty metrics.
- **Why it matters:** the fleet is otherwise an invisible black box — a laptop that quietly stopped
  reporting, or reports with blank metrics, looks identical to a healthy one today. Makes "are my
  devices checking in, and is the data real?" glanceable. **Trip-critical** for an unreachable
  camper box.
- **Buildable from (verified against live DDL):** `agent_devices.agent_last_seen`
  (`hw_monitor.py:190`, indexed `:218`), `enrollment_status`, `ip_address`, `link_type` +
  `hw_metrics.device_id` (`:90`), `timestamp` (`:63`), `cpu_percent` (`:70`), `ram_used_gb` (`:71`).
  Ingest is fully server-side (`/hw_data` → `insert_sample()` `:789-812`). **CONFIRMED server-only.**
- **Bonus — it's the standing detector for the known empty-cpu/ram bug.** `overnight-run-2026-07-02.md`
  §3 reports server-side cpu%/ram landing consistently EMPTY. Origin is visible in the mapping:
  `cpu_percent = _val("cpu_pct")`, `ram` from `_val("ram_mb")` (`hw_monitor.py:1215,1225-1226`) — if
  the agent payload mis-names those, the row inserts with NULL metrics while `agent_last_seen` still
  advances (exactly the symptom). A check counting `cpu_percent IS NULL` per `device_id` surfaces it
  the moment it happens.
- **Effort/home:** small–medium. New `diagnostics/agent_reporting_health.py` (pure read-only SQL,
  same shape as `anomaly_state.py`), added to `CHECKS`. Consider a `device_id` index on `hw_metrics`
  if fleets grow (none today).
- **Roadmap alignment / guardrail:** complements `connection-health-subsystem.md` — does **not**
  overlap. That subsystem builds NEW `conn_*` tables and **requires agent changes** (adaptive ramp,
  reply-based miss detection, tracert-on-miss). This is the lightweight, server-only interim view
  over data that already lands. **Do NOT introduce a competing `conn_*`-style schema here — read
  existing rows only;** the full subsystem later supersedes the receipt side.

### 2. Agent Enrollment & De-enrollment Health
- **Shows:** devices stuck in `enrollment_status='pending'`, plus `rejected`/`uninstalled`, and any
  enrolled with unresolved pre-enrollment findings.
- **Why:** an owner enrolls a device and walks away assuming it's protected; a device stuck
  "pending" is silently **unprotected**. Non-experts won't think to check.
- **Buildable from:** `agent_devices.enrollment_status` (`:195`), `pre_enrollment_scan` (`:206`),
  `enrollment_has_findings` (`:207`), `uninstalled_at` (`:293`). **Server-only, CONFIRMED.**
- **Effort/home:** small — fold in as a second section of #1, or a sibling check. Aligns with
  `enrollment-modes-build-spec.md` / `uninstall-deenroll.md` (reports state; doesn't build flows).

### 3. Agent Malware-Scan Coverage / Stale-Scan Health
- **Shows:** per device last scan time + result + "scan overdue" flag; count never-scanned or
  scanned >N days ago; stuck `scan_queue` entries.
- **Why:** "are my machines actually being scanned?" is a core non-expert worry; a schedule that
  silently stopped is invisible today.
- **Buildable from:** `agent_devices.last_scan_at`/`last_scan_result`, `scan_jobs`
  (`hw_monitor.py:222`), `scan_schedules` (`:252`), `scan_queue` (`:301`). **Server-only, CONFIRMED.**
- **Effort/home:** small–medium. New `diagnostics/agent_scan_coverage.py`. Pairs with
  `diagnostic-scan-scope.md` (that's the pre-run popup; this is the passive health readout).

### 4. Database Health (integrity + size/growth) of `alerts.db`
- **Shows:** `PRAGMA integrity_check`, DB + WAL file size, per-owner table row counts/growth; warns
  on corruption or runaway growth.
- **Why:** `alerts.db` is the single shared store (ADR 0001); silent corruption/bloat takes the
  whole dashboard down — the exact failure a headless trip box can't self-recover. `disk_space.py`
  checks the filesystem, not the DB. **No integrity check exists anywhere today** (grep-confirmed).
- **Buildable from:** the DB directly — no new schema. **Server-only, CONFIRMED.**
- **Effort/home:** small. New `diagnostics/db_health.py`. Serves `diagnostics-classification.md`
  ("DB health" = dashboard-independent, MUST-surface) + `db-resilience-backup-promotion.md`.
  **Guardrail:** thin read-only surfacing only — the deep resilience/recovery engine belongs to the
  standalone-runner thread, not this check.

### 5. Alert-Delivery Self-Test (email actually sends)
- **Shows:** SMTP config resolves + a last-send-success signal — beyond "vars are set."
- **Why:** if alert email is misconfigured, **every alert fails silently** — the owner learns
  nothing is wrong exactly when something is. `config_check` proves presence, not deliverability.
- **Buildable from:** `email_utils.send_email` path + `nemesis.env` SMTP vars. Server-only; a live
  send-test needs care (don't spam) — safe scope is config-validate + last-known-status readout.
- **Effort/home:** small — extend `config_check.py` or a new `alert_delivery.py`. Ties to
  `installer-email-delivery.md`.

### 6. (Lower confidence) Clock-drift / receipt-timing — **NOT server-only as-is**
- Only the **agent-stamped** time is persisted (`agent_last_seen` = payload `timestamp`,
  `hw_monitor.py:1243`); there is **no server `received_ts` column**, so true drift detection needs
  a minor schema add. **Defer** — it overlaps `adaptive-link-aware-agent-clock-sync.md` and the
  `conn_heartbeats.received_ts` field planned in `connection-health-subsystem.md`. Don't add a
  one-off column now.

---

## Bottom line / suggested build order
1. **#1 Agent Reporting-Health** — highest value, server-only (CONFIRMED), and doubles as the
   standing detector for the empty-cpu/ram bug. Build first; obey the guardrail (read existing rows,
   no `conn_*` schema — leave that to the connection-health subsystem).
2. **Redaction fix** (Part-1 top cross-cutting) — broaden `redact.py` to IP/MAC/hostname before the
   next time anyone hits "Submit to Support"; it currently ships device PII to an external address.
3. **False-alarm reframe** — flip VPN / Network-Devices / Pi-hole / Suricata to info-in-normal-state
   so the page stops crying wolf.
4. **#2, #3, #4, #5** — cheap fleet-visibility + server-self checks over columns that already exist.
5. **Trim the duplicates** — `hardware` (defer to hw_monitor), `network_devices` (dup + PII),
   `vpn_status` (dup + misleading).

## Cross-references
Arch-debt audit `docs/audits/architecture-debt-audit-2026-07-02.md` (Findings 8/15 — the hardware &
VPN duplication corroborated here); `overnight-run-2026-07-02.md` (the empty-cpu/ram evidence #1
detects); roadmap `connection-health-subsystem.md`, `diagnostic-scan-scope.md`,
`diagnostics-classification.md`, `diagnostics-standalone-runner.md`, `enrollment-modes-build-spec.md`,
`db-resilience-backup-promotion.md`; ADR 0001 (shared DB).
