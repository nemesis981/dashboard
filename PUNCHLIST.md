# PUNCHLIST — small fixes

Accumulated small fixes (not project-sized — those go to `docs/roadmap/`). Check items off
as done; keep newest context inline.

### [FIX-NOW] — concurrency races (multi-writer, real today)
From `docs/audits/single-user-assumptions-audit-2026-06-28.md` §1. NOT a commercial-tier
concern: Nemesis already runs 6 concurrent writer processes against one shared `alerts.db`,
so these read-modify-write races can bite with a single operator when the agent fleet checks
in concurrently. `get_db()` is autocommit + `busy_timeout` only — no multi-statement atomicity.
Fix each atomically, one at a time, audit-then-fix. The `ai_usage` `INSERT … ON CONFLICT DO
UPDATE` (`modules/ai_engine/module.py`) is the in-repo template.

**✅ All four fixed atomically in `2d200e0` (Data Manager v0 seed, ADR 0006; Rule-6 backup
`alerts-PRE-DATAMGR-V0-20260628`).** Each labeled in code `# DATA MANAGER v0 — atomic
operation`. Anomaly used a *partial* `UNIQUE(offending_target) WHERE status='open'` (a plain
composite UNIQUE would also forbid multiple `closed` rows / break history). One residual
below.

- [x] **[FIX-NOW] `tickets_seq` duplicate ticket numbers.** `_next_ticket_number`
  (`modules/tickets/module.py:113-115`) does `SELECT next_number` then a separate
  `UPDATE … = next_number + 1` → two concurrent `open_ticket()` calls (e.g. auto-ticket-on-
  alert firing from alert-watcher + a module) get the same number. Fix: atomic
  `UPDATE tickets_seq SET next_number = next_number + 1 WHERE id=1 RETURNING next_number`
  (or equivalent single statement). **Highest-likelihood to surface during the trip.**

- [x] **[FIX-NOW] AI rate-limit counter lost increments.** `_increment_rate`
  (`modules/ai_engine/module.py:308-318`) reads `hour_count`/`day_count`, computes `+1`, writes
  back separately → concurrent calls lose increments and under-count the rate limit. Fix:
  atomic upsert like the `_increment_usage` sibling right below it.

- [x] **[FIX-NOW] `community_queue` duplicate rows.** `add_to_queue`
  (`modules/community_queue/module.py:110-135`) is SELECT-then-INSERT/UPDATE with no UNIQUE on
  `(domain_or_ip, submitted)` → concurrent detections create duplicate queue entries. Fix:
  add the UNIQUE constraint + `INSERT … ON CONFLICT DO UPDATE`.

- [x] **[FIX-NOW] `anomaly_incidents` duplicate open incidents.** `_create_or_update_incident`
  (`modules/anomaly_detection/module.py:654-705`) is SELECT-then-INSERT/UPDATE with no UNIQUE
  on `(offending_target, status)` → concurrent detections for one target create duplicate open
  incidents instead of merging. Fix: UNIQUE + atomic upsert (mind the time-window merge logic).

- [ ] **`anomaly_incidents` merge is still read-JSON→merge-Python→write (RACE 4 residual).**
  The `2d200e0` fix removed duplicate open incidents (partial unique index funnels concurrent
  detections into ONE incident), but the device-list merge in `_create_or_update_incident`
  (`modules/anomaly_detection/module.py`, `_merge_into`) still reads `devices_json`, merges in
  Python, and writes back — so *simultaneous* merges on the same target can drop device-list
  entries (lost update). **Low priority:** anomaly detection isn't highly concurrent per target
  in practice, and this is pre-existing (unchanged in kind from before `2d200e0`); it does NOT
  recreate duplicate incidents. Fix (one variable): wrap the read+merge+write in
  `BEGIN IMMEDIATE … COMMIT` (this op owns a fresh `get_db()` connection, so serializing the
  merge is safe), or do the merge SQL-side (JSON1 / `json_*`) as a single atomic UPDATE.
  [ADR 0006 Data Manager — same atomic-operation seam.]

- [ ] **Header de-dup.** Remove the duplicated **Settings** / **Diagnostics** links from the
  upper-right corner — they also exist in the always-visible header. Frees the corner for the
  System Changes badge (`docs/roadmap/system-changes-badge.md`).

- [ ] **Kernel-update check.** Review `/var/log/apt/history.log` and confirm exactly what
  changed — a silent kernel update is the suspected *trigger* of the day-one VPN/DNS
  headaches. (NOT a root cause: the confirmed VPN/DNS root cause is PIA's killswitch +
  source-based policy routing — see ADR 0002. This item asks only *what changed on the box
  that day*; it's an open investigation, separate from that diagnosis.)

- [ ] **Stage-5 backup-purge (do during the backup rework).** When backup is reworked to a
  single SQLite-safe shared-DB snapshot, **remove the per-module-DB references** that back up
  dead fallback files (they won't exist after Stage 6):
  - `dashboard.py` `_backup_candidates()` (~line 4513) — the `modules/tickets/tickets.db` entry.
  - `install.sh` restore (~lines 1084–1089) — the `tickets.db` restore block.
  - backup help/description strings referencing `tickets.db`.

- [ ] **`PIHOLE_IP` hardcoded default (Rule 8 leak).** A personal LAN IP is shipped as a
  default — replace with `127.0.0.1` / read from `/etc/nemesis.env` (defaults must be correct
  for ANY user): `dashboard.py:65`, `diagnostics/pihole_health.py`, `modules/dhcp/module.py`.

- [ ] **`vpn-dns-guard.service` solves the wrong layer (keep/disable deferred to ADR 0005).**
  The unit is installed + running on this box but does **NOT fix** the DNS issue — the real
  cause is Pi-hole client-refusal-by-source, not upstream-blocking (see
  [ADR 0005](docs/architecture/0005-dns-firewall-device-auth-architecture.md), which
  supersedes ADR 0002's root cause). The guard reconciles a layer that was never broken.
  **Keep-or-disable decision is deferred to the ADR 0005 work.** Current workaround on this
  box = **VPN-off**. Also: the guard unit's **Rule-8 hardcoded absolute home path**
  (`core/vpn-dns-guard.service:12` `ExecStart` — a literal `/home/<user>/dashboard/...`)
  still needs parameterizing **before any public commit**.

- [ ] **Full hygiene sweep.** Repo-wide grep of the tracked tree for any other leaked secrets,
  home paths, real IPs, usernames. Known to triage: the `PIHOLE_IP` default above, the
  hardcoded support-destination email in `dashboard.py`, and the example SMTP hostnames in the
  SETUP docs / `install.sh`.

- [ ] **AI Settings: live Anthropic model pricing (replace hardcoded).** Replace the static
  hardcoded Anthropic pricing with LIVE pricing fetched from the Anthropic API (or a cached
  periodic fetch with a known-stale indicator). Static pricing becomes wrong the moment
  Anthropic changes it — and with dynamic/peak pricing likely coming, hardcoded values will
  actively mislead users about actual costs. The AI cost display is only trustworthy if it
  reflects real current pricing. **Fetch live, cache with TTL, show a staleness warning if the
  fetch fails.** Low priority until pricing volatility makes it urgent — but **future-proof the
  architecture now so it's a config change, not a rewrite.** Current hardcoded values live in
  `/etc/nemesis.env` (`ANTHROPIC_INPUT_PRICE_PER_MTOK` / `ANTHROPIC_OUTPUT_PRICE_PER_MTOK`) and
  are surfaced in the AI cost UI (`dashboard.py` ~1661–1663, ~1753–1756).

- [ ] **Pi-hole unattended-install whiptail hang (fresh headless installs).** On a
  headless / no-display server, Pi-hole's installer still exits at a **static-IP whiptail
  notice** even on the non-interactive path — so Pi-hole never installs, and a later
  `uninstall.sh` then reports it "not installed." The `--unattended` call already sets
  `TERM=xterm` (`install.sh:587`), but the static-IP notice needs **pre-answering** (e.g.
  pre-seed `setupVars.conf` / pass the relevant non-interactive flag) so the installer
  doesn't block. Affects fresh installs on servers without a display. Found during the
  diagnostics VM audit 2026-06-28.

- [ ] **PRE-RELEASE: Full system-transparency audit.** Find every place Nemesis affects the
  user's system **without making it visible** — the black-box surfaces that erode trust,
  especially on shared machines. Read-only audit first (Rule 1): inventory + classify, then
  the `[ADD]` items become scoped pre-release work. **Same format as the readiness audit**
  (findings table → classification → fix list). Categories:
  - **Resource transparency** — CPU/memory/disk/network per service (the overhead meter,
    `docs/roadmap/nemesis-overhead-meter.md`).
  - **Action transparency** — every automated action logged and visible (ties to the
    multi-user `actor` seam — attributed, surfaced).
  - **Cost transparency** — live AI pricing, not stale estimates (subsumes the **live
    Anthropic pricing** punchlist item above — fold them together).
  - **Data transparency** — what's stored, where, and the retention policy (per ADR 0001
    shared `alerts.db` + each module's retention caps).
  - **Network transparency** — all outbound connections visible **and user-controlled**
    (relates to the firewall engine, ADR 0005).
  - **State transparency** — what each service is currently doing right now.
  - **Decision transparency** — why the AI said X, why an alert scored Y (surface the
    reasoning, not just the verdict).
  - Classify each finding as **[SAFE already visible]** / **[ADD pre-release]** / **[DEFER]**.
  **Scope:** one focused session (audit → classify → stop for review), to run before
  **v1.1 / commercial release**. The `[ADD]` items graduate to pre-release work.

- [ ] **Hardware monitor — Nemesis overhead meter.** Per-process CPU/memory for each Nemesis
  service (psutil, data already available). A "Nemesis overhead" section: total + per-service
  breakdown + memory-trend sparkline (leak detection). Transparency value: "Nemesis is using
  X% — not us." Could feed a `DEGRADED` verdict to the diagnostics watcher. (Full stub:
  `docs/roadmap/nemesis-overhead-meter.md`.)

- [ ] **Broken-API-endpoint self-healing.** When an AI/external API call fails with a
  connection/endpoint error (NOT auth), attempt to find + verify the correct current endpoint:
  (1) AI-assisted lookup (if the API is partially reachable); (2) web-search fallback (if raw
  egress works); (3) manual-guidance fallback (link to service docs). If found + verified →
  auto-update config → retry. Applies to all configured endpoints.

- [ ] **PRE-RELEASE: Documentation-completeness audit.** Every feature has docs; every vendor
  integration has a `CUSTOM_*.md`. Grep-verifiable.

- [ ] **PRE-RELEASE: Tiered-output audit.** Every client-facing output renders correctly at
  all three tiers. `tierText()` discipline verified end-to-end.

- [ ] **Recurring-user-error audit (ongoing research practice).** Skim help forums for each
  Nemesis component (Pi-hole, Suricata, ClamAV, VirtualBox, Tailscale, Ubuntu, r/selfhosted)
  for recurring error types. Classify: **DOCS / FEATURE / DESIGN.** First pass: alongside the
  pre-release audits. Ongoing: apply the same classification to first-party support tickets
  (`support@nemesis-sw.com`).

### v2/v3 captures — from the enterprise gap audit
Full analysis + priority in `docs/roadmap/enterprise-gap-audit-2026.md`. Listed here as a
working checklist (these are project-sized — they graduate to roadmap specs when scheduled).

- [ ] **MITRE ATT&CK mapping (v2).** Tag existing detections with tactic/technique/sub-technique.
  Canary trip = **T1486** (Data Encrypted for Impact). YARA rules can carry ATT&CK tags. Mostly
  labeling, not new detection. High professional credibility, medium effort.
- [ ] **Vulnerability management — basic (v2).** CVE check on installed packages + open-port
  exposure check + basic misconfiguration detection. Low–medium effort.
- [ ] **Auth/login monitoring via agent (v2).** PAM auth logging, SSH login events, sudo-usage
  tracking. Agent reports auth events to the dashboard. Low effort, high value.
- [ ] **Process-execution monitoring (v2/v3).** Extend psutil to track process spawning +
  parent-child relationships. Catches malware before it touches files (earlier kill chain than
  the canary).
- [ ] **Lateral-movement detection — core (promoted to v2).** Suricata + agent-data
  correlation: "unusual outbound from A to other fleet devices **after a detection on A**" =
  a query, not a new sensor. **Core (owned-fleet) version promoted to a v2 target** — simpler
  than the venue version (known fleet topology, owned devices, inputs already present). The
  **venue/epidemic spread** version remains a separate, later addition. (Stub:
  `docs/roadmap/lateral-movement-outbreak-detection.md`.)
- [ ] **Emergency backup on canary trip (v2).** Trigger the backup module on canary detection.
  Not full rollback, but "emergency backup before more files are encrypted."

- [ ] **Data Manager v0 follow-on — Race 4 residual merge-RMW.** `anomaly_incidents` device-list
  merge is still read-JSON → merge-in-Python → write under concurrent detections on the same
  target (the partial UNIQUE fix prevents duplicate incidents but doesn't atomicize the merge
  itself). Low priority in practice (anomaly detection isn't highly concurrent per target). Fix:
  `BEGIN IMMEDIATE` around the merge, or an SQL-side JSON merge. One variable. Follow-on to
  `2d200e0`.

- [ ] **Dashboard layout memory — server-side, two-level personalization.** Layouts must follow
  the user across devices (laptop → phone → tablet), so localStorage is wrong — store
  **server-side in `alerts.db` from day one**.
  - **Table:** `user_layouts (user_key TEXT, slot_name TEXT, slot_index 1-5, layout_json TEXT,
    updated_at TEXT, UNIQUE(user_key, slot_index))`.
  - **Layout JSON format (two levels):**
    ```json
    {
      "card_order": ["alerts", "hardware", "tickets", "diagnostics"],
      "card_content": {
        "hardware": ["cpu_temp", "fan_speed", "memory", "gpu_temp"],
        "alerts":   ["critical", "high", "medium", "low"],
        "tickets":  ["open", "investigating", "resolved"]
      }
    }
    ```
    - **Level 1 — card order:** which cards appear where on the dashboard.
    - **Level 2 — content order within cards:** which metrics/sections appear first inside each
      card. E.g. a hardware-monitor user may want `cpu_temp` first vs `fan_speed` first vs
      `memory` first — their priority, their order. Applies to: hardware monitor, alerts,
      tickets, diagnostics, malware card.
    - Same Sortable.js, same drag-and-drop, same storage — just applied at **two** levels
      instead of one.
  - **`user_key` evolution** (same table, value changes as identity matures): pre-session-identity
    → `request.remote_addr` (device-specific, functional); session identity (cookie display name)
    → display-name string (follows the user across devices — the trip-ready version); commercial
    auth → real user ID (secure, multi-tenant). Layout upgrades automatically as `user_key` matures.
  - **Layout slots:** 3–5 named slots per user (user-defined names: "Working", "Monitoring",
    "Incident Response", etc.), switchable instantly from a dashboard-header dropdown.
    "Reset to default" → tier-appropriate default layout.
  - **Draggable cards + draggable within-card sections:** Sortable.js (available via cdnjs, no
    new dependency).
  - **2 API routes:** `GET /api/layout` (load slots) + `POST /api/layout` (save slot).
  - **Build-order dependency:** session identity must land **before** layout memory so layouts
    are globally available per-user from day one. Full build order: race fixes ✅ → actor
    attribution → session identity → dashboard layout memory (two-level).
  - **Principle:** *"this feels like my tool"* — what keeps a product in daily use. Layout memory
    at both the card and metric level is complete personalization for the non-expert user who
    builds a specific mental map of where things are.

- [ ] **Dashboard header status lights — global green/amber/red health indicator.** Always
  visible in the header regardless of the current layout — this **solves the layout-memory
  blind-spot**: a user's preferred layout may have the alerts card off-screen, but the header is
  always visible. Three states:
  - **GREEN (●):** all clear — no unacknowledged critical/high alerts, all services healthy,
    canary clean, nothing awaiting action.
  - **AMBER (▲):** attention when convenient — medium alerts, open tickets, degraded (not down)
    services.
  - **RED (■):** action needed now — unacknowledged CRITICAL/HIGH alerts, service down, canary
    trip unresolved, quarantine awaiting confirmation, diagnostics LOCAL_FAIL.
  - **Display:** leftmost header element, color + shape (colorblind-friendly), optional count
    badge (`🔴 3` = 3 things need attention). Clicking jumps to the alerts/tickets view
    regardless of current layout — the "one click to what needs attention" shortcut.
  - **Data sources** (aggregated into one `/api/header/status` verdict): alert severity
    (unacknowledged CRITICAL/HIGH → red); service health (any down → red, degraded → amber);
    diagnostics watcher verdict (LOCAL_FAIL → red, DEGRADED → amber); canary state (unresolved
    trip → red); quarantine state (awaiting confirmation → red).
  - **Polling:** `GET /api/header/status` every 30s (existing `setInterval` pattern), returns
    `{status: 'red'|'amber'|'green', counts: {critical, high, services_down}}`. Count badge shown
    when non-zero.
  - **Tiered tooltip:** same light for all tiers; hover detail is tiered (Beginner: plain language
    "3 alerts need your attention"; Pro: specific counts and states).
  - **Professional value:** makes the product look/feel built by people who thought about how it
    gets *used*, not just how it *works*. Universal signal — no expertise required to understand a
    green vs red light.
  - **Build order:** independent of session identity and layout memory — can be built any time.
    Small: one API route + one 30s polling interval + header HTML/CSS. High visibility, low effort.

- [ ] **Impossible-travel detection — v2 (ADR 0008).** `login_events` table is collecting from
  `21c8931`. Build the detection logic in v2: unknown-location alert, impossible-travel flag,
  time anomaly, and cross-site detection via the central management plane. The **concurrent-
  session seam is already built** (follow-on to `21c8931`). Full design:
  [docs/architecture/0008-impossible-travel-detection.md](docs/architecture/0008-impossible-travel-detection.md).

- [ ] **MSP central management plane — v3+.** See
  [docs/roadmap/msp-central-management.md](docs/roadmap/msp-central-management.md). **Seam to
  leave now:** clean, versioned, authenticated read API endpoints on every Nemesis instance
  (`@login_required` + API key) — free to add correctly, expensive to retrofit. A future central
  plane queries these without major surgery.

- [ ] **Device-user permissions — commercial tier (ADR 0007).** `device_user_permissions` table
  (`device_id`, `username`, `role`, `granted_by`, `granted_at`; many-to-many device↔user).
  Handles shared workstations, shift-based access, the traveling IT person, and visiting support.
  Build **after** Flask-Login + device-auth Level 2. Full design:
  [docs/architecture/0007-device-user-model.md](docs/architecture/0007-device-user-model.md).

- [ ] **Agent ping monitor — v1 (ADR 0010).** Continuous adaptive ICMP monitor on each agent
  (7 targets, latency/TTL/loss/reachable, 60/15/5s adaptive interval, local SQLite buffer,
  queued `/ping_batch` sync, per-device timeline). v1 core; traceroute capture, failure-narrative,
  Tailscale relay netcheck, and TTL-trend deferred to v1.1. **Build deferred** until after
  trip-readiness (pre-enrollment scan + Windows smoke test). Full design:
  [docs/architecture/0010-agent-ping-monitor.md](docs/architecture/0010-agent-ping-monitor.md).

COMMUNITY REPORTER IDENTITY SYSTEM (v1.1):
Free tier key (NMS-FREE-XXXX) auto-generated on install.
Reporter ID derived from license key + network latency +
system entropy (one-time, inputs discarded after derivation).
Server stores derivation entropy for challenge-response
verification (ZKP-adjacent — key never sent over network).
Trust score, rate limiting, abuse detection, upgrade path
with verified identity migration. Three-pass sanitization
pipeline. See docs/roadmap/community-reporter-identity.md.
Build alongside community backend (v2).

COMMUNITY SIGNAL DEDUPLICATION (community backend data model):
One entry per unique signal (SHA256(signal_type:signal_value),
UNIQUE constraint). Duplicate reports bump times_seen / last_seen /
unique_reporters / regions and recompute confidence. Bounded
timestamp aggregates (100 recent / 168h / 90d / 24mo). Local raw
context vs global sanitized aggregates; DB grows with unique
threats not report volume. This is the Phase-2 "Data schema" lock.
See docs/roadmap/community-signal-dedup.md.
Build alongside community backend (v2).

DAILY STATUS REPORT (printable/emailable) — v2:
GET /api/report/daily → HTML + PDF + plain text
Content: system health, services, fleet status, alerts (24h),
open tickets, canary state, Pi-hole stats, connectivity verdict,
AI natural language summary paragraph.
Schedule: auto-generate 7am, email to admin, on-demand from
dashboard. Tiered output (Beginner/Intermediate/Pro).
Connects to: scheduled reports roadmap, transparency audit,
tiered output audit, hw_monitor AI report.

PC AGENT USER INTERFACE + TRAFFIC READOUT (v2):
Localhost:5003 web UI (cross-platform, no native UI needed).
Traffic readout: approved/inspected/blocked counts, current
routing mode, tunnel latency, cache hit rate, recently blocked.
Network type setting (personal/business/venue) = master gate
for all user controls. Admin-gated via device policy.
Tunnel policy (full/split/work_only) is policy output not
user preference — admin sets, agent enforces via config-pull.
BYOD: personal traffic summarized not specific (legal middle
ground). AUP surfaced clearly at connection.
Fail closed (business) vs fail open (personal) per network type.
Time-based switching: tunnel policy can vary by schedule (e.g.
work_only during business hours, personal/split off-hours) —
admin-set via config-pull, not a user preference.
Build alongside agent rebuild (v2).

ZTNA + NAC ENFORCEMENT (v2):
No enrolled agent = no internet (captive portal).
Router firewall: only Tailscale-tunneled devices get internet.
Captive portal: QR code → install agent → TOS → auto-approve
after clean scan → WiFi access via inspection tunnel.
Venue guest network: agent as credential, TOS disclosure,
guest app stays useful after visit (user acquisition funnel).
Outbreak detection on enrolled guest fleet.
Build after mobile agent (v2/v3).

COMMUNITY BACKEND — PRE-BUILD DESIGN REQUIREMENTS:
The following must be fully designed and locked before any
backend code is written (decisions are hard to reverse once
data is flowing):

MUST BE LOCKED (already designed — verify complete):
- Reporter ID derivation algorithm
- Sanitization pipeline (three-pass)
- Three-tier review model
- Trust score algorithm + factors
- Rate limits (free/commercial)
- Upgrade/migration path
- Challenge-response verification
- Data schema
- Consent model + TOS/EULA/Privacy Policy (legal review)

NEEDS DESIGN SESSIONS:
- Feed format (REST/signed JSON/compressed download)
- AI review tier specifics (what does AI check, prompt design)
- Human review interface (your queue, workflow, SLA)
- Open source feed normalization (Abuse.ch/OTX/MISP → schema)
- Abuse detection thresholds (when to flag, when to block)
- Revocation mechanism (key death, data deletion)

LEGAL REVIEW (before Phase 4 — feed goes public):
TOS, EULA, Privacy Policy, consent flows, inspection proxy
disclosure, community feed disclaimer, jurisdiction decision.
Recommended: software/cybersecurity attorney, 2-3 hours.

BUILD SEQUENCE (phases):
Phase 1: Identity layer (reporter registration, verification)
Phase 2: Submission pipeline (sanitization, queue)
Phase 3: Review infrastructure (AI + human review, trust scores)
Phase 4: Feed publication (format, client pull, open source feeds)
Each phase independently deployable. Phase 1 can go live with v1.1.

PRE-ENROLLMENT SCAN — YARA RULES NOT SHIPPED YET:
The agent's pre-enrollment scan (scan-before-trust) runs ClamAV, and runs YARA
only if nemesis_agent/yara_rules/rules.yar is present. No rules file ships yet,
so YARA always reports yara_available=false / not_available. ClamAV coverage is
unaffected. Acceptable for v1, but ship a baseline YARA ruleset (and a way to
update it) before commercial release. See enrollment.py pre_enrollment_scan().

MALWARE DETECTION PIPELINE (see docs/roadmap/malware-detection-pipeline.md):

V1 — Certification scan:
  Deep scan at install, known-good classification, coverage %,
  certificate issued. High-risk paths only for first scan.
  Entropy flagged only with 2+ additional signals (never alone).

V1 — First-run + hash cache:
  SHA256 cache, scan on first run only, rescan on hash change.
  Cache states: sandbox_verified > run_clean_N > scan_clean etc.
  Behavioral monitoring during first run (canary tripwire).
  Gaming: zero overhead after first run, auto Game Mode via psutil.

V1 — Validation pipeline:
  Tier 1: auto-classify (known-good types/paths)
  Tier 2: AI validation (metadata only, not file contents)
  Tier 3: clone sandbox (V2)
  Tier 4: user decision (quarantine/delete/trust/investigate)
  Infected user: 3,294 raw → 7 real threats surfaced cleanly.

V1 — Trigger-based scanning:
  inotify/FSEvents on high-risk directories
  Archive scan to temp before extraction
  USB scan before mount
  V2: kernel-level blocking (fanotify/ESF)

V2 — Clone-based sandbox:
  Clones actual system (OS, hardware profile, software inventory,
  library versions, drivers). NOT personal files/credentials.
  CANARY FILES TRAVEL WITH CLONE → active trap for ransomware.
  VM-aware malware behaves authentically (can't detect clone).
  Performance testing: launch time, RAM, CPU on real hardware profile.
  Compatibility testing: exact dependency tree, real conflict detection.
  Requires VM Lab infrastructure.

V2 — Sandbox-first software testing:
  Any new installer → "test safely first" prompt
  Clone sandbox install → AI behavioral report → user approves
  Available on Windows Home (Defender sandbox is Pro/Enterprise only)
  NMS-INST certificate issued on approval.
  Cracked software: reports what it does without judgment.

V2 — Software lifecycle management:
  software_inventory table: manifest (all files + hashes),
  behavioral baseline, certificate chain, update history.
  Update diff: only changed/added files rescanned (15-30 sec).
  Tamper detection: manifest integrity check catches supply
  chain attacks (trusted binary modified by malware).

V2 — Stale software + monthly health report:
  Categories: truly_forgotten/recently_stale/seasonal/never_run
  Performance impact: RAM/CPU used RIGHT NOW by unused apps
  Hardware longevity + storage projection + dollar value
  Safe uninstall: verify cleanup, remove leftovers, archive cert
  Software health score (0-100), scheduled cleanup option
  Seasonal pattern detection (don't flag tax software in June)

SUPPORT BUNDLE — AUTOMATIC DIAGNOSTIC PACKAGE (see docs/roadmap/support-bundle.md):

Trigger: user clicks "I need help" → ~10s package (data already collected).
Rule 8: sanitized BEFORE any transmission (no real IPs/paths/usernames) —
single shared sanitization chokepoint, not per-destination.

Contents:
  System profile (sanitized), software timeline (30d, with cert IDs),
  registry diff (vs last week + vs pre-last-install), sandbox behavioral logs,
  security state (canary/scan/tickets), connectivity (verdict + ping history),
  AI diagnosis (most-likely cause + fix, plain language), suggested fixes.

Four destinations:
  [Fix automatically] → Nemesis applies suggested fix
  [Contact Nemesis support] → support@nemesis-sw.com (private support module)
  [Contact vendor support] → vendor-ready package (pro format, pre-diagnosed)
  [Post to community] → sanitized bundle for forum/GitHub issue

Vendor-ready package: system info + install timeline + what changed + what
  Nemesis detected + what user tried. 10s vs ~2h manual.

Open prerequisites (not yet captured):
  - Registry backup / registry-diff engine (the diff source — no design doc)
  - Private support intake (route support@nemesis-sw.com into first-party queue,
    distinct from the user-facing tickets module — undesigned)
  - Shared Rule-8 sanitization gate (single chokepoint for all off-box destinations)

NEMESIS VERIFIED PARTNER PROGRAM (see docs/roadmap/verified-partner-program.md):

Future revenue stream — vendors pay for structured access to support bundles +
certificate verification. Post-commercial; possibly a SEPARATE product line.

Vendor value: ticket resolution 3h → 15min, cert verification API (instant
clean-install proof), anonymized install analytics, conflict/failure intelligence.

Certificate verification API:
  GET /verify/{NMS-CERT-id} → {valid, software, date, findings, coverage_pct}
  Vendor verifies clean install in ~30s. Cert IDs from malware-detection-pipeline
  (NMS-CERT §1, NMS-INST §7-8).

Partner tiers: Free (bundle receipt) / Pro (API + analytics) / Enterprise (custom).

Analytics (aggregated, anonymized): install success per OS/hardware, conflict
patterns, time-to-first-issue, "23% of tickets preventable by updating SharedLib".

Privacy: vendors see aggregate only (community-feed model); explicit per-bundle
consent; Rule-8 sanitization gate is a HARD gate (commercial recipient).

Prerequisites (all roadmap-only): support bundle, certificate system,
community backend infrastructure.
Open: separate product line? legal (vendor agreements, consent, disclosure —
same legal bucket as community feed); cert verification-store trust (signing/revocation).

PRE-ESCALATION SUPPORT SEARCH (see docs/roadmap/pre-escalation-support-search.md):

Before generating a support ticket, AI searches for an existing fix — escalation
is the LAST step, not the first. Common issues already have answers.

Search sources (priority): Nemesis community feed (local, fastest) → vendor KB →
release notes/known-issues → vendor forums → general web (last resort).
Query = software + version + error signature + OS + conflict (from issue profile).

Result tiers: Nemesis-knows (one-click) / vendor-docs (cite + apply) /
community-workaround (upvotes, try-or-escalate) / not-found (bundle + "searched" note).

"Searched, not found" in bundle: documents what/when searched, tells vendor it's
genuinely new, includes search terms (helps vendor KB).

Self-building community KB: user confirms fix worked → contributed back
(sanitized, anonymous reporter_id, dedup times_seen) → "confirmed by N users".

Custom vendor search: CUSTOM_VENDOR_SEARCH.md pattern (mirrors CUSTOM_VPN_PROBE.md),
vendor_sources.json registration, skip-if-absent. Vendor guide ships in same commit
as code (Tier-2 vendor rule) when built.

Open: outbound-query privacy (Rule-8 gate must cover the QUERY not just the bundle —
error signature can leak path/username); fix-worked → community-signal mapping
(undesigned); vendor_sources.json freshness/staleness.

AI-GENERATED TUTORIAL WALKTHROUGH (ships v2 — see docs/roadmap/ai-generated-tutorial-walkthrough.md):

AI generates a complete, always-current tutorial from the docs (regenerates when
features change). Not static — sources: CUSTOM_*.md, docs/operation/, docs/modules/,
PUNCHLIST (v1/v2/deferred), tiered-output principle.

Output tiers (Beginner/Intermediate/Pro): "Getting Started" / "Understanding Your
Dashboard" / "Complete Feature Reference". Format: in-dashboard interactive tour
(step tooltips, progress, pause/resume) + downloadable PDF + video script.

Regeneration: new feature → affected sections; major version → full; on-demand from
Settings. First-login guided tour ("Would you like a tour?"), tier-appropriate.

DOC COMPLETENESS BONUS (dual purpose): tutorial generation IS the completeness audit —
if AI can't generate a section, that feature isn't documented. Run as pre-release check.

Sequencing: build after v2 feature set locked; requires complete module docs +
all CUSTOM_*.md guides; run completeness audit first.
Reality (2026-06-29): source corpus is THIN — only docs/modules/diagnostics/ documented,
only CUSTOM_VPN_PROBE.md exists. "Complete module documentation" is itself the v2 backlog.
