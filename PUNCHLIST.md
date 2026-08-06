# PUNCHLIST — small fixes

Accumulated small fixes (not project-sized — those go to `docs/roadmap/`). Check items off
as done; keep newest context inline.

### [DONE] Git-history disclosure decision — scoped rewrite executed 2026-07-26
A git-history exposure question (from the disclosure-audit carve-outs) was evaluated,
decided, rehearsed, and executed. **Full writeup, deliberately NOT in this repo:**
`~/work/nemesis-internal/known-limitations/history-rewrite-evaluation-2026-07-26.md` (per
Rule 10 — the evaluation itself maps where sensitive content sat in history, which is its
own disclosure-sensitive artifact).

**What happened (safe to state publicly):** a scoped rewrite covering the more recent,
non-tagged/non-released portion was rehearsed clean in a throwaway mirror, backed up (full
verified mirror on independent storage), then executed for real and force-pushed. Verified
afterward against a genuinely fresh clone from GitHub: target content fully gone from all
history; everything else — including all published release tags and the emergency-fallback
tag (`pre-l1l2l3-build-known-good`, same commit hash `14b066b...`, unaffected) — confirmed
byte-for-byte untouched. A separate, older portion was explicitly accepted as residual risk
rather than rewritten, on the reasoning that it will age out naturally through normal
parameter rotation, similar to how a leaked credential gets rotated rather than scrubbed from
history.

- [ ] **Minor follow-up, not blocking:** a handful of docs (worklogs/HANDOFF.md) reference the
  pre-rewrite commit hashes by name — those mentions are now stale (describe a commit ID that
  no longer exists on `main`). Cosmetic, not broken; fix opportunistically.

- [ ] **NEW (found 2026-07-28 closeout): a commit made AFTER the 2026-07-26 rewrite reintroduces
  the same class of leak.** Commit `9ffac56`'s own message quotes the literal real install
  username instead of a placeholder, describing the manifest.json bug it fixed — it's now in
  public git history a second time, in the commit log itself, postdating the cleaned history so
  it isn't covered by the prior rewrite. Needs an operator decision (rewrite again vs. accept as
  residual, same reasoning as the older portion above) — not actioned yet, deliberately not
  decided the same night as a live pen-test run. See `docs/handoff/HANDOFF.md` Open Items #2.

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

- [ ] **Systemd unit files + one script ship a literal `/home/<user>/dashboard/...` path (Rule 8
  leak, found 2026-07-26 during a broader re-scan, NOT new today — pre-existing since
  2026-06-21/22/25).** `core/vpn-dns-guard.service` was already flagged above (the one
  instance previously caught); this broader grep (`git grep -InE '/home/[a-z][a-z0-9_-]*'`
  across all tracked `.md`/`.py`/`.sh`/`.service` files) found **six more, previously
  unflagged**, all hardcoding the real install username instead of a placeholder or a
  templated/computed path:
  - `alert_manager/alert-watcher.service:9` (`ExecStart`)
  - `alert_manager/dashboard.service:7,8,11` (`WorkingDirectory`, `Environment=PYTHONPATH`,
    `ExecStart`)
  - `alert_manager/device-scanner.service:7,8` (`WorkingDirectory`, `ExecStart`)
  - `alert_manager/hw-monitor.service:7` (`ExecStart`)
  - `alert_manager/install_pihole_pwd.sh:8` (`UNIT_SRC`)
  - `alert_manager/watchdog.service:10` (`ExecStart`)
  - `scripts/vpn_dns_livetest.sh:22,27` (comment + `GUARD=`)

  **Checked, not assumed:** `install.sh`'s `deploy_services()` (~line 810) DOES rewrite the
  7 core services' paths at install time (`sed -e "s|/home/[^/]*/dashboard|/home/$SUDO_USER/dashboard|g"`)
  — so `alert-watcher`/`dashboard`/`device-scanner`/`hw-monitor`/`watchdog`.service are **not
  a functional bug** for other users, just a repo-hygiene leak of the dev machine's real
  username into a public tracked file. `core/vpn-dns-guard.service` is **not** in
  `deploy_services()`'s `svc_names` array — not templated at all (consistent with its
  existing flag above). `install_pihole_pwd.sh` and `scripts/vpn_dns_livetest.sh` are
  standalone one-shot/dev-diagnostic scripts (not deployed via `install.sh`) with the literal
  path inline — same leak, different flavor (a genuine functional issue if anyone besides the
  original operator ever runs them as-is).
  **Not fixed here** — a real code/config change requiring testing, out of scope for a
  docs-only pass. Flagged per Rule 1 (audit, don't fix silently) for a dedicated pass.

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

- [ ] **[POST-TRIP EVAL] Tunnel-transport portability — Tailscale vs WireGuard / other mesh VPNs.**
  **Evaluation/test item, NOT a committed rebuild** — assess coupling first, then decide if a
  transport abstraction is worth building. The agent tunnel is currently **Tailscale-specific**:
  OAuth key minting, pre-auth-key enrollment, tailnet join, and "reachable over the tailnet"
  assumptions are baked into onboarding (`nemesis_agent/enrollment.py`,
  `alert_manager/tailscale_api.py`, installer Tailscale join steps, the `:5001`/`:5002`
  reachability assumptions, `docs/CUSTOM_TAILSCALE_OAUTH.md`). Post-trip, test/evaluate whether
  the product holds up when the transport is a DIFFERENT mesh/VPN tech — raw **WireGuard**, or
  Tailscale-alternatives (**Headscale, Netbird, ZeroTier**, etc.).
  - **Questions to answer:** (1) How tightly is the agent coupled to Tailscale specifically vs.
    treating the tunnel as a **swappable transport**? (2) Could an SMB with existing WireGuard/mesh
    infra run Nemesis over THEIR tunnel instead of Tailscale? (3) Is the transport a clean
    abstraction, or is Tailscale hardcoded through **enrollment/heartbeat/reachability** — the same
    coupling shape as the LHM issue (heavy vendor path baked in before the boundary was drawn; see
    `docs/audits/architecture-debt-audit-2026-07-02.md`)?
  - **Value:** robustness (not locked to one vendor's mesh) + commercial/SMB fit (businesses often
    have their own VPN infra). Onboarding just needs the agent reachable at a stable address on a
    private network — the mesh tech that provides it should ideally be a detail, not a hard
    dependency.
  - **Method:** read-only coupling audit first (grep the Tailscale touchpoints across enrollment /
    installer / reachability / heartbeat), then a spike over raw WireGuard to see what breaks.
  - **Graduation:** if the audit finds hard coupling worth fixing → graduate to a roadmap
    stub/ADR ("tunnel-transport abstraction") with the eval as its evidence. If coupling is already
    thin → document the "bring-your-own-tunnel" path and close. Project-sized; do NOT build now.
  - **Sibling (runtime FEATURE version):** this is the *test/measure* item. The shipped-agent
    detect-and-adapt feature is tracked separately at
    `docs/roadmap/agent-tunnel-environment-awareness.md` (2-step: inventory → adapt). **This eval's
    coupling verdict gates that item's Step 2.**

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
(NB: this note is AGENT-specific. The server-side malware_detection module
DOES ship YARA — 6 bundled rule files, _yara_scan working.)

YARA FALSE-POSITIVE KNOWN-GOOD PATH EXCLUSIONS (build candidate, live scanner):
The live malware_detection YARA scanner (_yara_scan, scan_directory) has a
max-file-size skip but NO known-good path exclusions, so it will false-positive
on browser extension dirs, browser/Electron caches (VS Code, Chrome), service
worker caches, and ad-blocker rulesets (which contain malicious domains BY
DESIGN). Add a cross-platform, updatable Tier-1 known-good PATH exclusion list.
Design captured in docs/roadmap/malware-detection-pipeline.md ("YARA FALSE-
POSITIVE EXCLUSIONS"). Real FP-prevention on developer machines; needs Rule-6
backup + tests when built (touches the live scanner).

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

AI TUTORIAL — ADDENDUM (first-run + searchable index + connected dashboard):
  First-run baseline (below Beginner tier): no security knowledge, nervous, wants
  reassurance; 5-screen tour (welcome → dashboard → what it watches → what red means →
  all set); [Show me around][Skip][Search]. Default for new installs.
  Searchable tutorial_index table (topic, keywords JSON, section, tier, content_summary,
  last_generated, feature_version) — NL search maps confused-user vocab → feature
  ("virus"→malware scan, "red light"→status lights, "someone hacked me"→incident response).
  ADR 0001: tutorial_index needs an owning prefix (likely ai_*) + canonical CREATE;
  ADR 0006: writes via Data Manager.
  Connected dashboard: index knows each topic's DOM element → "show me" highlights the
  LIVE element (reality, not screenshots — never drifts from UI).

THREE-SNAPSHOT VENDOR PACKAGE (see docs/roadmap/three-snapshot-vendor-package.md):

Hand vendors PROOF: Snapshot 1 (pre-install clean baseline — from registry backup),
Snapshot 2 (issue state, auto-captured on canary/crash/flag — registry, processes,
services, network, file changes, memory, error log, canary state), Snapshot 3 (delta:
files+registry+services+network changed, with attribution + AI diagnosis).

Package: snapshot-1/2/3.zip + nemesis-rebuild-{linux.sh,windows.ps1} + Dockerfile +
reproduction-steps.txt. Auto-captured (sandbox monitors continuously — export just packages).

Update regression: S1=v1.0 working, S2=v2.0 broken, delta = what the UPDATE changed.
"Your v2.0 modified SharedLib.dll — v1.0 did not." Vendor can't say "works on our end".

Sanitization: all 3 snapshots, same Rule-8 chokepoint as support bundle (strip
user/host/IP/personal, preserve software config+version).

Open: MEMORY-state sanitization is hard (dump can hold creds/tokens — narrow to
process+module list or build a dedicated scrubber BEFORE any memory artifact ships to a
commercial recipient — highest-risk Rule-8 surface); rebuild-script/Dockerfile generation
undesigned (encode system profile); snapshot retention/size policy (tie to ADR 0006).

PORT CANONICALIZATION — lives at the NGINX layer (already implemented; no action):
The dashboard entrypoint is nginx :80 (Basic-auth) → Flask :5000 (internal, ufw-blocked
from LAN). Any port redirect/canonicalization belongs in the nginx config, NOT a Flask
before_request: a Flask "host missing :5000 → 301 :5000" would bounce every nginx-proxied
user to a firewall-blocked port = dashboard outage (nginx forwards Host with no port). The
naive Flask redirect is unsafe at any altitude here. Documented in docs/OPERATION.md.
(From the 2026-06-29 smoke-test topology audit.)

DEVICE IDENTIFICATION (passive + on-demand active) — see docs/roadmap/device-identification.md:

Turn ❓ unknown devices into named/trusted ones WITHOUT DNS takeover or router config.
PASSIVE (always-on, zero risk): mDNS/Zeroconf listener — devices announce themselves
(phones, speakers, TVs, printers); most ❓ identified within 24h. No DNS/router changes.
ACTIVE (on-demand button, per-device/fleet): reverse DNS, mDNS query, NetBIOS, UPnP/SSDP,
HTTP banner, port fingerprint → AI combines → name suggestion → user accept/edit/skip.
NEW-DEVICE TRIGGER: passive signals auto-run; unidentified after 1h → queue active scan;
notify "N new unidentified devices need review". Result: confidence score, accept → trusted ✅.

Builds on: existing `devices` core table (mac/ip/friendly_name/device_type/trusted — the spec's
"device_map") + device_scanner.py (nmap, LAN_SUBNET-driven) + AI Engine + alerts.
ADR 0001: new id columns (confidence/signals/last_identified) = guarded migration on `devices`
+ updated CREATE; writes via Data Manager (0006); accept/edit/skip carries actor.
Open: mDNS/NetBIOS names are PII (sanitize before community feed); passive listener = new
always-on core service/module; active probes are LAN access (don't bypass firewall.py / ADR
0005); default user-accept (never silent auto-trust).

MAC RANDOMIZATION + STABLE HARDWARE ID (see docs/roadmap/device-identification.md):
  Correlation engine: new MAC/IP → check stable signals → match known device →
  suggest merge (NEVER auto-merge). Confidence: keypair=1.0, dhcp=0.95, mdns=0.90,
  timing=0.70. Threshold 0.85 → suggest merge to user.
  Stable hardware ID: composite hash of available signals (machine-id, battery serial,
  motherboard serial, CPU ID). Hash before storing — never raw hardware data. Battery
  serial standout: no root needed (Linux /sys, Windows WMI, Mac ioreg), survives reinstall.
  Agent enrollment: stable_id added to enrollment payload.
  DB (guarded migration, ADR 0001, writes via Data Manager): known_macs, known_ips,
  dhcp_hostname, mdns_name, stable_id, identity_confidence, identity_signals.
  ADR 0008: stable_id distinguishes MAC randomization (normal) from true impossible
  travel (suspicious). Build alongside the device-identification feature (same session).

INSTALLER EMAIL DELIVERY (v2 — build AFTER Wisconsin trip; see docs/roadmap/installer-email-delivery.md):
  Admin form (device name, recipient email, support contact, optional message) → Nemesis
  generates enrollment token + sends personalized email with installer /zip download link +
  friendly message. Uses existing SMTP config from nemesis.env. Logs delivery; token tied
  to recipient email (audit trail).
  MOSTLY WIRING — already exists: enrollment_tokens core table, token gen + installer download
  links (dashboard.py ~1458), send_email() helper (email_utils.py, SMTP from env).
  ADDS: admin form, email composition, + guarded migration on enrollment_tokens (ADR 0001):
  recipient_email, support_contact, custom_message, delivered_at (writes via Data Manager).
  Rule 8: recipient email/message are PII (never to community feed); short expires_at +
  max_uses=1 so an intercepted email can't enroll a rogue device; surface send failures.

INSTALLER SIZE OPTIMIZATION (post-trip):
  Current: 272MB (ClamAV bundled = heavy download).
  Better: ~30MB installer + fetch ClamAV on first run.
    Installer copies NemesisAgent.exe + LHM + token only.
    First run: NemesisAgent.exe downloads ClamAV from our mirror/GitHub,
               shows "Downloading security scanner...".
    Result: small installer, same end state; saves ~240MB/user.
  Same model as the Chrome installer (small stub -> downloads the rest).

### [WINDOWS-INSTALL] — v1.0.6 doc-driven install test findings (2026-06-30)
Full detail + verdict: `docs/audits/windows-install-doc-test-2026-06-30.md`. Test HELD at the
install phase (BLOCKED). Items below; the High/architectural ones must GRADUATE to ADR/roadmap
(per Rule 7) — listed here for tracking, not as small fixes.

**Graduate to ADR/roadmap (project-sized — do NOT treat as quick fixes):**
- [ ] **PL-3 (High) — Tailscale onboarding has no working/documented mechanism.** Frozen
  `Setup.exe` hard-gates on Tailscale (`installer_gui.py:194-198,245`); no pre-auth-key/invite
  flow exists; Beginner doc implies sharing the owner's account login (insecure). Blocks every
  real remote user. → design a pre-auth-key / device-invite flow; decide LAN-skip policy. (roadmap/ADR)
- [ ] **[moved to private] PL-6 (High) — enrollment is a bearer-token model; device keypair ≠
  stolen-media protection.** Moved to
  `~/work/nemesis-internal/known-limitations/reauth-gap-and-active-bugs-audit-2026-07-29.md`
  (Rule 10, 2026-07-29 sweep). Still needs to graduate to ADR 0005 (device-auth) per Rule 7.
- [x] **PL-8 (High) — dashboard "Generate Windows Installer" serves the LEGACY system-Python
  `install_windows.ps1`, not a v1.0.6 frozen equivalent.** **RESOLVED (Phase-1 delivery
  foundation):** `/install/windows/<token>/zip` now serves a frozen-exe bundle (generic
  `NemesisAgent-Setup.exe` + per-installer `nemesis_install.conf`); the legacy `.ps1` route is
  retired (410). See the [INSTALLER-DELIVERY Phase 1] follow-ups below for the remaining
  infra/consumption work.
- [ ] **PL-4 (Med) — the two installers disagree on Tailscale** (GUI `Setup.exe` mandatory
  hard-gate vs token `.ps1` optional/skippable). Pick one policy; align both + the doc.

**Small fixes (PUNCHLIST-sized):**
- [ ] **PL-9 — Python detection fooled by the Windows App-Execution-Alias stub.**
  `install_windows.ps1:35` `Get-Command python` matches `...\WindowsApps\python.exe` → passes
  falsely, dies later at `pip`. Fix: require `python --version` success AND source not under
  `WindowsApps`.
- [ ] **PL-1 — Beginner Step 0 Tailscale login has no account/new-tailnet warning.** Caused the
  operator to create a NEW empty tailnet. Add: name the exact account; "if it shows an empty
  network or offers to *create* a tailnet, you used the wrong account."
  (`docs/operation/INSTALL_WINDOWS_BEGINNER.md`)
- [ ] **PL-7 — no owner/admin doc for the invite-generation step.** All 3 tier guides say "the
  installer your admin sent you" but never how to mint/deliver it. Add an owner guide:
  dashboard → Devices → Generate Windows Installer → deliver link.
- [ ] **W-1 — Beginner guide says "you do NOT need any passwords/accounts/settings," but the
  generic released `Setup.exe` prompts for Server address + Install code.** Reconcile (assumes a
  pre-baked installer the doc never explains). `docs/operation/INSTALL_WINDOWS_BEGINNER.md`
- [ ] **PL-5 — dashboard invite doesn't auto-send + links pinned to `<tailnet-ip>`.** Returns
  zip/exe/ps1 links the owner forwards manually (email delivery already parked — see the
  installer-email-delivery note above); `NEMESIS_PUBLIC_URL` pins links to the tailnet so LAN
  devices can't use the handed-out link. Carries no Tailscale info (ties to PL-3).
- [ ] **PL-2 — `[SUPPORT_CONTACT]` placeholder ships raw** in the Beginner guide. Substitute at
  deploy, or explain it's filled by the helper.
- [ ] **W-2 — time estimates** ("~5 min" / install "~2 min") vs a 272MB bundle. Adjust.

- [ ] **PL-10 — Tailscale GUI auto-launches a redundant "Log in" window after the silent
  `--authkey` join (v1.0.7 self-onboard UX wart).** Found in the test VM install audit:
  the installer auto-installs Tailscale (`_install_tailscale` → winget/MSI) and joins headlessly
  via `tailscale up --authkey`, but Tailscale's own GUI app auto-starts on first run and shows a
  "Log in" prompt — confusing the operator into thinking they must connect manually (they did).
  Functional join was the key; the prompt is cosmetic/parallel. Fix direction: suppress/skip the
  Tailscale GUI launch (or `tailscale up --unattended` / config to prevent the login window
  surfacing). Polish, NOT a blocker — the mechanism works. (installer_gui.py `_install_tailscale`.)
  - [x] **Stale first-screen text half — CLOSED AGAIN 2026-08-03. The 2026-08-02 reopening was
    itself a misreading, not a bug.** Full history, so a third reopening doesn't repeat either
    mistake:
    1. Original closeout (2026-08-02, Window 2): marked resolved.
    2. Reopened same day (Window 1): watched the manual "Before you start: install Tailscale…"
       copy render live at `installer_gui.py:99,105,110` and read that as evidence the gating
       was broken.
    3. **Re-verified 2026-08-03, both halves of the question now closed:**
       - **Gating logic** — already established correct in the 08-02 reopening and reconfirmed
         here: `_read_baked_config()`'s `preauth_key` unpacks in the right position, flows
         positionally into `InstallerApp.__init__`, is stored as `self.preauth_key`, and
         `_render_instructions()` branches on `bool(self.preauth_key)` correctly.
       - **The copy itself** — the actual open question from the 08-02 reopening — is also
         correct. `_first_screen_text`'s own docstring states the manual-Tailscale text is
         shown "ONLY on the no-key fallback path," and `_ensure_tailscale()`
         (`installer_gui.py:529-560`) confirms directly: on `state == "not_installed"` it tells
         the user to install Tailscale manually and click Retry — it never calls any
         auto-install path. A no-key build has no self-onboard mechanism to auto-install
         Tailscale with, so telling that user to install it themselves is the ONLY correct
         copy, not stale content.
    4. **Root cause of the reopening itself: option (a) from the 08-02 entry — the tested
       build/scenario genuinely had no preauth key by design.** There was no divergence between
       source and the running build (option (b), the alternative the 08-02 entry left open) —
       watching correct no-key copy render during a no-key install looked like a stale-text bug
       from the outside, but the code was doing exactly what it should for that input.
    - [ ] Follow-on, not part of this closure: the 08-02 entry's copy-precision idea (distinguish
      "install Tailscale yourself" from "sign in yourself" more precisely) is a genuine, small
      wording improvement independent of there being a bug — worth doing opportunistically, not
      blocking.
- [ ] **PL-11 (Doc) — hardware-monitor prompt is PawnIO; install docs must tell users to approve
  it.** Found in the test-2 VM install (screenshot
  `docs/audits/trip-1.0.8-test2-vm-screenshot-2026-07-01.png`): LibreHardwareMonitor 0.9.x pops
  **"PawnIO is not installed, do you want to install it?"** (PawnIO = the kernel I/O driver LHM
  uses for hardware sensor access). This is the "hardware monitor needs a program download
  approved" prompt the operator hit. Not a bug — LHM works, but **temps/fans need PawnIO
  installed** (click OK/approve). Fix: the install guides (INSTALL_WINDOWS_*.md / beginner walk-
  through) must tell users to **expect and approve the PawnIO install** for temperature/fan data;
  without it the agent still runs but skips temps/fans. Docs-only, no code change.
  *(Guide guidance ADDED — Beginner + Intermediate INSTALL_WINDOWS_*.md now tell users to click OK
  on the PawnIO prompt.)*

- [ ] **PL-12 — Tailscale "You're all set" window vs. our close-it guidance (REVIEW FLAG — record,
  do not resolve yet).** From the test-2 screenshot
  (`docs/audits/trip-1.0.8-test2-vm-screenshot-2026-07-01.png`): the auto-launched Tailscale window
  at the **"You're all set"** stage ("Now that you're connected, you can manage your settings…")
  offers **Open local settings** / **Close**. QUESTION to confirm: does the installer's two-part
  Tailscale guidance (open-it-leave-it → now-safe-to-close) correctly account for **this specific
  "You're all set" stage**? Need to verify whether closing **at this stage** is safe or still risks
  the Tailscale **#16086** hang, so the completion-message timing is accurate. Cross-ref **PL-10**
  (redundant auto-launched Tailscale GUI). Do NOT change guidance until the safe-to-close stage is
  confirmed by test.

- [ ] **PL-13 — Uninstall consent-UX enhancement (when we next touch the agent).** Builds on the
  Phase-3 consent checklist already in `uninstaller_gui.py`. Cross-ref: Phase-3 consent UX + the
  PawnIO never-remove decision (**1f495ad**).
  - **Explicit confirmation** before teardown: *"Really uninstall the Nemesis Firewall Agent?"*
  - **List ALL components Nemesis put on the machine** (full transparency), as **CHECKBOXES**
    (independent per-item toggles — **NOT radio buttons**) so the user chooses which to remove vs
    keep. **Never default everything to remove.**
  - **Provenance-driven, conservative defaults** — annotate each component by manifest provenance:
    * **`pre_existing`** (we did NOT install it — it was there before Nemesis): tag *"may be in use
      by [detected consumer if known] — installed before Nemesis."* **Default KEEP** (or don't offer
      removal). **The prior presence IS the evidence** something else owns it — it's theirs, we
      won't remove it.
    * **`installed_by_nemesis` + shared kernel driver** (e.g. **PawnIO**): **conservative default
      KEEP**, tag *"other hardware tools (Fan Control / OpenRGB) may use this."* (kernel-driver
      never-remove backstop, 1f495ad).
    * **`installed_by_nemesis` + clearly ours** (e.g. our agent files): **offer removal, default
      CHECKED.**
  - **Best-effort "needed elsewhere?" detection — NOT a definitive claim:**
    * Manifest provenance is the **primary** signal (`pre_existing` vs `installed_by_nemesis`).
    * At uninstall, **also run a live check** for other likely consumers where feasible — e.g. for
      PawnIO, detect whether **Fan Control / OpenRGB** are installed, or whether the PawnIO service
      is referenced by non-Nemesis processes → surface *"another tool may use this — recommend
      keep."*
    * The **"may be in use by X" tag primarily attaches to `pre_existing` components** — that's the
      honest, evidence-based signal. Kernel-driver never-remove is the **backstop** for the harder
      *"we installed it but something adopted it later"* case.
    * **Present HONESTLY:** state what was detected AND that other software **MAY** still depend on a
      component even if not detected. **Default to KEEP when uncertain** (especially kernel
      drivers). **Never claim a definitive "safe to remove"** for shared components.
    * **Why best-effort:** dependencies formed **AFTER** our install (user installs Fan Control
      later, which reuses our PawnIO) leave **no trace in our manifest**, so detection can never be
      authoritative — hence conservative defaults + honest "may be used elsewhere" language.
  - **Per-item context line so the choice is informed**, e.g.:
    * *"PawnIO — hardware sensor driver; Fan Control / OpenRGB may use it — recommend keep."*
    * *"Tailscale — you had this before Nemesis; it's yours, we won't remove it."* (`pre_existing`)
    * *"Tailscale — installed by Nemesis; safe to remove if not used elsewhere."* (`installed_by_nemesis`)

**Positives (no action — confirmed working):** generate endpoint is auth-gated; LAN download
bakes a LAN-reachable server address + correct token; git acquire + release-asset download +
SSH automation all worked.

### [INSTALLER-DELIVERY Phase 1] — follow-ups from the delivery-foundation build (2026-06-30)
The Phase-1 delivery foundation (frozen-exe bundle serving, baked token + single-use Tailscale
pre-auth key + tailnet target, download-side uses-check, TTL 24h→2h) landed code-side. Remaining:

- [ ] **[moved to private] Install media still served over cleartext `:80`, not tailnet-only.**
  Moved to `~/work/nemesis-internal/known-limitations/reauth-gap-and-active-bugs-audit-2026-07-29.md`
  (Rule 10, 2026-07-29 sweep) — describes exactly what's exposed on that path and the fix.
- [ ] **OPS DEP — stage the generic frozen exe on the box.** `/install/windows/<token>/zip`
  assembles the bundle from a prebuilt generic `NemesisAgent-Setup.exe` at **`NEMESIS_AGENT_EXE`**
  (no per-request PyInstaller — the box is Linux). Build it on Windows/CI (`nemesis_agent/
  build_installer.py`) and place it at that path, else the route hard-fails 503. (Roadmap
  D-dep-2.)
- [ ] **[moved to private] Baked-conf consumption, plaintext-at-rest pre-auth keys, and the
  auto-approve default — three related, unresolved items.** Moved to
  `~/work/nemesis-internal/known-limitations/reauth-gap-and-active-bugs-audit-2026-07-29.md`
  (Rule 10, 2026-07-29 sweep) — describes exact plaintext-secret handling and a current
  permissive default in the live enrollment flow.

### [UNINSTALL / DE-ENROLL] — complete-uninstall follow-ups
Ties to the de-enroll endpoint (`docs/roadmap/clean-uninstall-build-spec.md` §4, `:5001`
`POST /api/agent/uninstall`) and the VM `.83` uninstall remnants (R1/R2 in that spec).

- [ ] **Automate stale tailnet-node removal on uninstall (SERVER-side).** After an agent
  uninstall the client does `tailscale logout` (leaves the tailnet), but the device's **node
  record lingers in the Tailscale admin console** as an offline machine and must be removed
  **manually** (admin console → Machines → offline node → Remove). For no-IT-department users
  that's an orphaned-node rough edge they may not know how to clean. **Automate it server-side:**
  on receiving the signed de-enroll (Finding-1 / `:5001` endpoint), the server — which already
  holds the Tailscale **OAuth creds** used for key minting (`alert_manager/tailscale_api.py`,
  currently `mint_preauth_key` only; no device-delete yet) — should ALSO call the Tailscale API to
  **remove that device's tailnet node** (`DELETE /api/v2/device/{deviceId}`), so uninstall leaves
  no orphaned node.
  - **Why server-side, not the client uninstaller:** node removal needs tailnet-**admin** API
    access; the client must NOT hold admin creds. This belongs on the server that already
    de-enrolls + already has the OAuth token.
  - **Wire into the existing de-enroll flow:** agent de-enrolls → server marks `uninstalled`
    (already built) → **server removes the tailnet node** (new step, same handler).
  - **Guards:** (a) **only remove nodes tagged `tag:nemesis-agent`** — never touch the user's other
    nodes; (b) **idempotent** — handle the node already being gone (manually removed / already
    deleted) without error; (c) map `device_id` → Tailscale `deviceId` (the server needs to know /
    look up the node id for the enrolled device).
  - **Vendor rule:** the node-removal code is Tailscale-specific → extend/ship the
    `CUSTOM_TAILSCALE_*.md` guide (Tier-2 vendor-integration rule).
  - **Value:** closes the "no orphaned node" gap for the complete-uninstall promise; pure server
    add on an existing flow, no client change.

### [DOCS-SYNC] — reflect today's agent changes in install/uninstall docs + agent text (2026-07-02)
**When:** post-install-test (do the edits AFTER the fresh-VM test confirms the new behavior — some
of this — Method B, PawnIO self-install, launch-minimized — is not yet VM-proven, so documenting it
before the test risks writing behavior that still shifts). Capture-only now so the pass isn't
missed. Docs-window work.

- [ ] **1. Method B (in-process sensors) — LHM no longer runs as a separate program.** No
  `LHM.exe` launch, no **port 8085** web server, no `NemesisLHM` scheduled task; sensors read
  in-process via pythonnet. **Update every doc/text that describes LHM as a running component /
  HTTP API:**
  - `docs/SETUP_WINDOWS.md` — heavy: lines ~64, 78, 110, 116, 119–123, 156, 268, 270 all describe
    the old "run LHM as Administrator → Options → Web Server → port 8085 → `/data.json`" model and
    the discovery-script HTTP fetch. Rewrite to the in-process read (no manual LHM web-server setup,
    no 8085, no leaving LHM running).
  - `ARCHITECTURE.md` — line ~104 mermaid node `LibreHardwareMonitor\nlocalhost:8085`; update the
    agent diagram/text to in-process sensor read.
  - Agent user-facing text — any string referencing LHM.exe / port 8085 / the NemesisLHM task.
  - Cross-ref: arch-debt audit `docs/audits/architecture-debt-audit-2026-07-02.md` (LHM cluster,
    Findings 3/4/11) — the docs are the last face of that retirement.
- [ ] **2. PawnIO self-provisioning.** Install now silently installs PawnIO via `_install_pawnio()`
  (LHM no longer auto-installs it). Update install docs + **PawnIO-approval guidance (PL-11):** if a
  **UAC / driver-install prompt** appears during install, docs must tell users to **approve it**
  (needed for temps/fans). Reconcile with PL-11 wherever it's tracked.
- [ ] **3. Tailscale launch-minimized.** Install now briefly shows a **minimized** Tailscale window
  during setup, then **closes it after join**. Update any install-step description of the Tailscale
  behavior (was: suppressed/GUI notes) so testers aren't surprised by the brief window.
- [ ] **4. Finding-1 security fix (changelog / security-notes, NOT user-facing install docs).**
  The legacy `windows_agent` `/hw_data` ingress route was **removed** (closed the ungated-ingress
  hole — arch-debt audit Finding 1, build commit `f9ee9b5`). Add a **changelog / security-notes**
  entry; no install-doc change.
- [ ] **5. Clean-uninstall behavior (user-facing uninstall docs).** The uninstaller **de-enrolls
  (signed)**, removes Nemesis components + **Tailscale (only if we installed it)**, and **KEEPS
  PawnIO** *(⚠️ operator message was truncated here — "KEEPS…"; inferred as the established
  never-remove-shared-kernel-driver rule for PawnIO per HANDOFF/PL-11 — **confirm the intended
  ending**)*. Update uninstall docs to describe this teardown honestly (what's removed vs kept, and
  why PawnIO is kept). Cross-ref `docs/roadmap/clean-uninstall-build-spec.md` + the owed
  `CUSTOM_TAILSCALE_UNINSTALL.md`.

### [RESOLVED — design decision 2026-07-02] L2 WinDivert filter catches SYN-ACK = intentional bidirectional coverage
Found during the live L2 Step-5 battery on test VM (`build2-83`, 2026-07-02). The filter
`nemesis_agent/l2_windivert.py:41` is `"outbound and ip and tcp and tcp.Syn"`. WinDivert
`tcp.Syn` is true for ANY SYN-flagged packet — **including SYN-ACK**. So the outbound SYN-ACK
that a device emits to complete an *inbound* connection's handshake also matches the filter.
Proven live: during `--simulate-hang`, fresh inbound `:22` went UP -> DOWN(~6-9s) -> UP across
the hang window; established sessions were untouched (the control SSH survived).
- **DECISION (operator, 2026-07-02): KEEP AS-IS. This is intentional bidirectional
  handshake-initiation coverage, NOT an accidental broadening.** Rationale: for a security
  product, blocking only outbound connections to bad IPs while accepting inbound connections
  FROM bad-reputation sources would be asymmetric/incomplete protection. Reputation blocking
  covers both directions by design. The earlier "narrow with `and not tcp.Ack`" idea is
  **rejected** — do NOT narrow the filter.
- **Accepted tradeoff (documented, not a bug):** during a stall/hang, NEW inbound connections
  are also briefly blocked (~`l2_stall_timeout_sec`, ~5s, until the watchdog recovers);
  established sessions are unaffected.
- Docs corrected to bidirectional framing (`dashboard-l2-toggle.md`, `l2-windivert-stumble-
  escalation.md`, `adr-0009-build-scope.md`). **OPEN:** the code docstring/comments still say
  "outbound-only" and `l2_windivert.py:39-41` still claims "inbound ... pass untouched (never
  diverted)" which is now inaccurate — pending a build-window follow-up to reword (behavior
  unchanged).

### [NOTE] — kill switch requires BOTH commands for a hung process
Same live test. `sc stop WinDivert` on a *hung* agent (handle still open) parks the service at
**STOP_PENDING** and does NOT restore traffic — the filter stays in effect until the handle is
released. It's the **`taskkill` (process death → OS closes the handle)** that frees it; after
both, driver reaches STOPPED and outbound+inbound restore. The documented pair
(`sc stop WinDivert` + `taskkill /IM NemesisAgent.exe /F`) is correct — just confirm any runbook
lists BOTH and notes the STOP_PENDING-until-handle-freed behavior so an operator doesn't stop at
`sc stop` and think it failed.

### [LOW — moved to private] enrollment token: `auto_approve=0` tokens are never `uses`-consumed
Real, low-severity, unresolved gap in the enrollment-token consumption logic. Moved to
`~/work/nemesis-internal/known-limitations/reauth-gap-and-active-bugs-audit-2026-07-29.md`
(Rule 10, 2026-07-29 sweep) — same category as the enrollment/installer-delivery items below.

### [FUTURE — Option A] dashboard-integrated per-device `l2_enforce_enabled`
Tonight shipped **Option B** (`49061c5`): `installer_gui.py` honors a baked `l2_enforce_enabled` from
its sidecar conf — a per-installer opt-in with no schema/default change. **Option A** is the full
"same pattern as `poll_interval`" integration and is the real future work: a `l2_enforce` column on
`enrollment_tokens` (schema migration) + the generate endpoint storing it + `/zip`/`_render_install_conf`
baking it, so the dashboard UI can mint L2-enabled installers directly. **Security-default + schema
change → audit-first, hold-for-review.** Deferred from tonight deliberately (Option B was the
lower-risk path for one laptop pre-trip).

### [DONE — 2026-07-27] `anomaly_detection` fd leak, root cause corrected (was: dashboard hang, 2026-07-26)
- [x] **Root cause was misdiagnosed when this entry was first written.** The leak was never
  `eve.json` handling — `_detection_cycle`'s reads of `/var/log/suricata/eve.json` were always
  leak-safe. The real leak was bare `conn = _conn() … conn.close()` call sites in
  `modules/anomaly_detection/module.py` (e.g. `_set_state`) where `close()` sat inside the
  `try:` block, so a raised statement (e.g. `sqlite3.OperationalError`) skipped it and leaked
  the connection's fd — eventually exhausting the process's fd table and surfacing as
  `OSError: [Errno 24] Too many open files`, with eve.json's own `open()` as the visible victim,
  not the source. **Fixed in `a38a068`**: a `_db()` contextmanager guarantees `close()` in
  `finally:`, and every call site missing that guarantee was migrated to it. Two remaining bare
  `_conn()` sites were checked and confirmed already safe (already closed in `finally:`).
  `docs/reference/operational-notes.md`'s troubleshooting section still describes the old
  (incorrect) eve.json framing — needs a follow-up pass, not corrected yet.
- [ ] **Future robustness (not urgent, do not build now):** the dashboard should ideally fail
  more gracefully / self-report on resource exhaustion (too-many-open-files) instead of
  silently hanging. Flag for a later error-handling pass — not part of the fd-leak fix itself.

### [LOW] `device_scanner.py` logs via `print()` — convert to `logging` like every other daemon
Filed 2026-07-29. `core_module/device_scanner/device_scanner.py` is the **only** Nemesis daemon
that writes its output with bare `print()`; the other five use `logging`, whose handlers flush
per record:

```
alert_watcher.py  print=0 logging=23     malware_canary.py      print=0 logging=11
watchdog.py       print=0 logging=23     diagnostics_watcher.py print=0 logging=14
hw_monitor.py     print=0 logging=66     device_scanner.py      print=7 logging=0   <-- outlier
```

That outlier status is why one bug class only ever bit this service: systemd hands the process a
pipe, Python block-buffers stdout at 8192 bytes, and the loop sleeps 300s between cycles — so at
~89 bytes of output per cycle the first line reached the journal roughly **7.5 hours** after
start. Measured 2026-07-29: a scan ran, found devices and wrote them to the DB while
`journalctl -u device-scanner` stayed completely empty.

**Already mitigated, so this is not urgent:** `run()` now calls
`sys.stdout.reconfigure(line_buffering=True)` as its first statement, and the six error/warning
paths go through `_loud()` (stderr, `flush=True`). Output is timely today.

**The remaining debt** is consistency: no severity levels, no timestamps of its own, no
`LOGS_DIRECTORY` handling, and a future refactor that drops the one-line buffering call silently
reintroduces the invisibility. Convert the 7 `print()` calls to `logging` and the mitigation stops
being load-bearing. No urgency — do it when the file is open for another reason.

### [LOW] `agent_devices.last_heartbeat_data` not populating (observed 2026-07-03, trip-laptop)
- [ ] **`agent_devices.last_heartbeat_data` is not populating for trip-laptop despite
  hw_metrics/agent_last_seen updating normally** — real telemetry (cpu/ram/temp) is landing
  correctly via the metrics path, but whatever writes the `last_heartbeat_data` blob on the device
  row isn't firing for this device. Low severity, not blocking, but check if any dashboard UI reads
  that column directly.

### [DEFERRED — fold into diagnostics-page design] Step-up re-authentication audit + active-bug triage (2026-07-29)

**Full writeup, deliberately NOT in this repo:**
`~/work/nemesis-internal/known-limitations/reauth-gap-and-active-bugs-audit-2026-07-29.md`
(per Rule 10 — a route-by-route map of every currently-exploitable gap in a live,
publicly-distributed dashboard, including exact locations and payload shapes, reads as an
attack roadmap otherwise).

**Safe to state publicly:** two things were found. (1) The whole app has exactly one auth
gate — a valid session cookie, nothing else, no step-up anywhere. Most sensitive actions
(self-restart, uninstall, secret/env rewrites, module disable, agent enrollment approval,
etc.) should eventually require fresh re-authentication, matching the pattern
`nemesis_fwd.py` already uses for firewall actions. That work **stays deferred** — fold
into the diagnostics-page design when it's picked up, don't build standalone. (2) A
follow-up triage pass found **four items that are independently exploitable bugs today**,
unrelated to whether step-up auth ever gets built (a route bypassing its own sibling's
credential check, a shell-injection bug in a generated cron entry, two GET-that-mutates
CSRF issues, and one machine-to-machine auth gap in `hw_monitor.py`). These four don't
wait on the deferred design — see the private writeup for exact locations and fix
direction, and decide separately whether/when to act on them.

### [DONE — 2026-07-29] `alerts.action` claimed "auto-quarantine" when the block had failed
Found during the nemesis-fwd health/failsafe audit. `alert_watcher.process_new_alert()` wrote the
alert row with `action="auto-quarantine"` **before** attempting `ufw_insert_top()`. If the helper
was down (or any `FirewallError` fired), the block never landed but the alerts table already
asserted it had. The `quarantines` table was correctly left empty — there is an explicit comment
there about not showing "a block that does not exist" — so the two tables disagreed, and the one
the dashboard surfaces most prominently was the one that lied.

- [x] **Fixed**: the ufw call now happens first. On success the alert is recorded as
  `auto-quarantine` and the quarantine row is inserted (unchanged behaviour). On failure the
  alert is recorded as `pending` — the same value every other unacted alert gets — so it lands
  in front of the operator instead of hiding behind a block that never happened. Verified both
  paths against a scratch DB: failure → `action='pending'`, 0 quarantine rows; success →
  `action='auto-quarantine'`, 1 quarantine row.
- [ ] **Not covered**: alerts written before this fix still carry the wrong `action`. No
  migration was attempted — the affected rows cannot be distinguished from genuine
  auto-quarantines after the fact without cross-referencing ufw state at the time. Low impact
  (the quarantines table is authoritative for what is actually blocked), but worth knowing if
  historical alert data is ever audited.

### [LOW] `degraded.jsonl` has no reader — the degraded-state channel terminates in a file
Found during the same audit. `nemesis_fwd.signal_degraded()` writes structured records to
`/var/lib/nemesis/degraded.jsonl` (env `NEMESIS_DEGRADED_LOG`), and **nothing reads it** — grep
finds zero consumers outside `nemesis_fwd.py` itself. Same shape as the helper's `ping` op, which
is exposed in `NO_CREDENTIAL_OPS` and reachable via `fw_client.ping()` but is **polled by nothing**.

So the helper has two working health-signalling mechanisms and neither is wired to anything that
watches. Combined with `Restart=always` + `StartLimitBurst=5` (defaults elsewhere), a crash loop
ends with the helper **down, not restarting, and unannounced** — the ERROR line in alert-watcher's
journal is currently the only signal that enforcement has stopped.

Not urgent in itself, but it is the concrete piece of the larger nemesis-fwd health/failsafe
design (watchdog decision, wiring ping/degraded.jsonl to a watcher, an incident runbook) which is
held as its own scoped follow-up. Filed so the two orphaned mechanisms are not rediscovered a
third time.

### [FUTURE] PIA VPN deliberately disabled — unresolved Nemesis compatibility
Filed 2026-07-29 during L3 Fork B Piece 2 scoping. **Not to be chased now** — recorded so it
is not rediscovered from scratch, and because it is a hard precondition for L3 Fork B work.

**State.** PIA is installed and its policy-routing rules are live (4 `piavpn*` rules in `ip rule`,
a `piavpn.POSTROUTING` chain in nat), but the client is deliberately left **Disconnected** —
confirmed directly via `piactl get connectionstate`, not inferred from iptables counters, which are
cumulative and misleading. The operator turned it off because Nemesis threw errors while it was
active. It
reportedly **works fine sometimes**, so this is intermittent or configuration-dependent, not a hard
incompatibility. The specific original error is not recorded anywhere we could find.

**What is already built for this.** `core/vpn_dns_guard.py` (`vpn-dns-guard.service`, ADR 0002)
exists precisely to solve the known half of it: a VPN killswitch blocks every egress that is not the
tunnel, **including Pi-hole's upstream DNS forwarding**, so Pi-hole keeps answering LAN clients but
stops resolving cache-misses (`FTL: failed to send UDP request (Operation not permitted)`). The
guard watches for tunnel up/down and repoints `dns.upstreams` at a tunnel-reachable resolver,
restoring on tunnel-down.

**The open question.** That guard is **currently active** (`vpn-dns-guard`, NRestarts=0) and yet PIA
is still off because of errors. So one of: the guard does not fully cover the DNS case; there is a
second, non-DNS failure mode; or the guard has a defect. Nobody has re-tested since. **First
diagnostic step for whoever picks this up:** reconnect PIA on a quiet box and capture what actually
breaks, rather than reasoning from the guard's design — the guard may well be doing its job while
something else fails.

**Why it matters beyond convenience — this is the part that is easy to miss.** The killswitch
mechanism that broke Pi-hole's upstream DNS is the *same class of problem* Fork B's Piece 2 will
hit:
Fork B forwards tunnel-sourced flows and masquerades them out the current egress. With a killswitch
active, forwarded-and-masqueraded traffic is exactly the kind of non-tunnel egress a killswitch is
designed to block. Nobody has tested that interaction.

Consequences, concretely:
- Piece 2's masquerade rule is written interface-independently
  (`-s 100.64.0.0/10 ! -o tailscale0 -j MASQUERADE`) so it keeps working when PIA returns — but
  "the rule still applies" is not the same as "the killswitch lets the packet out".
- **L3 Layer 3 measurements taken with PIA off do not transfer to PIA on.** Different egress
  interface, different TTL, and `tun0`'s MTU was 1441 vs 1500 on `<bridged-iface>`. Any Layer 3
  run must record PIA state as a run variable; runs across different states are not comparable.
- So Fork B egress **cannot be validated in the configuration the operator actually intends to
  run** until this is resolved. Step 1's validation is deliberately PIA-off, and that limitation
  should be stated in its results rather than discovered later.

Related: `docs/architecture/0002-vpn-aware-dns-routing.md`, `core/vpn_dns_guard.py`,
`docs/roadmap/adr-0009-l3-fork-b-scope.md` (Piece 2).

### [HIGH — private writeup] Phase 1 verification: two confirmed defects in shipped code (2026-07-30)

End-to-end verification against a real enrolled Windows agent confirmed **two live defects**. Both
writeups are kept private (Rule 10 / disclosure) because each reads as an exploitation roadmap
until fixed:
`~/work/nemesis-internal/known-limitations/phase1-verification-findings-2026-07-30.md`

1. **Network access-control does not apply to one whole traffic class.** Blocks are accepted and
   reported as applied, and have no effect on that path. Cause is chain-traversal ordering, not a
   bug in the block logic — a co-resident daemon terminates evaluation before our rules are
   reached, and re-asserts that position automatically. Measured, not inferred: baseline traffic,
   block applied, identical traffic still passing, plus root-level chain-order output. **This is
   the defect ADR 0019's enforcement table exists to fix**, and it is the reason that work is
   sequenced first.

2. **Agent persistence is removed by the OS's own AV on a default install**, classified severe.
   The agent appears to install correctly, then does not survive reboot. The detection is
   behavioural and **correct** — the persistence mechanism also constitutes a
   privilege-escalation vector on its own terms. Fix is architectural (service install,
   non-user-writable path, code signing), **not** an AV exclusion request.

A positive result worth recording alongside them: the helper's peer-authorization model held
correctly throughout, refusing every out-of-policy operation attempted during the test.

### [FUTURE] Headscale as a self-hosted Tailscale control plane (VPN-swap evaluation, 2026-07-29)

**Why this exists.** While scoping ADR 0019 we asked whether swapping the VPN product would
dissolve the netfilter chain-ownership conflict instead of solving it. It would not — see the
conclusion below — but the evaluation surfaced one option worth keeping, and re-deriving it later
would be tedious. Capture-only; **nothing was built or changed.**

**The conclusion that closed the question.** Swapping Tailscale does **not** avoid needing ADR
0019's enforcement table. The chain-ownership conflict is not unique to the mesh overlay — another
root-privileged VPN client on this box contends for the same positions regardless of which overlay
runs (measured findings in the private writeup referenced from ADR 0019), so a deterministic
enforcement point is required either way. A swap reduces the number of competitors from two to
one; it does not remove the problem. Migration was sized at **16–24 sessions** (OpenVPN) or **10–15** (WireGuard) against
infrastructure that currently works — disproportionate to a conflict a 4–6 session nft table
resolves deterministically. **Recommendation was: do not migrate.**

**The option worth keeping.** The strongest argument against Tailscale is not its netfilter
behaviour — it is that `tailscale.com` is an **external control plane in the enrollment path**.
If it is unreachable or the account lapses, agents cannot enroll. That sits awkwardly against the
product thesis (*"self-hosted, no per-user fees, data stays local"* — ADR 0009) and is the kind of
thing a security-conscious buyer asks about.

**Headscale** is a self-hosted, API-compatible Tailscale control plane. It keeps the Tailscale
client, the tailnet CIDR, `tailscale up --authkey`, exit-node support, and essentially all of
`nemesis_agent/installer_gui.py` (123 Tailscale references) — replacing only the coordination
server with one we run. Estimated **3–5 sessions**. It keeps the Tailscale client and therefore
that client's netfilter-management behaviour, so the chain conflict stays and ADR 0019 is still
required.

**Caveat to check before committing:** Headscale still relies on reachable DERP relays for NAT
traversal. Whether that meaningfully reduces the external dependency depends on whether we run
our own DERP or use the public ones — verify before treating this as "fully self-hosted".

**If a migration ever does happen, the target is plain WireGuard, not OpenVPN.** OpenVPN's
defining cost is that it requires running a CA (key management, revocation, CRL, expiry) and it
returns nothing WireGuard lacks except TCP/443 obfuscation — which only matters if enrolled agents
must traverse restrictive corporate firewalls that block UDP. Tailscale *is* WireGuard underneath,
so plain WireGuard keeps the crypto and performance and drops only the control plane.

**Two findings from the evaluation that stand on their own:**
- **ADR 0011's trust model is not Tailscale-specific.** Its root of trust — *"TRUST signal = the
  SERVER-OBSERVED tailnet source IP ONLY (client cannot forge it)"* — transfers cleanly to any
  tunnel, since a server-assigned pool IP is equally unforgeable post-decrypt. The property is
  portable; only the wording and the key-minting mechanism (`alert_manager/tailscale_api.py`,
  OAuth → single-use pre-auth keys) are Tailscale-bound.
- **Track A's exit-node step is per-device and gated on a SaaS console approval.** That is a
  Tailscale limitation, not an inherent one — OpenVPN and WireGuard both do per-client routing via
  server-side config (`client-config-dir` / `push "redirect-gateway def1"`) with no console and no
  approval. Does not change Track A's plan; explains why that step carries an external dependency.

**Decision-flipping fact, still unknown:** whether this site sits behind CGNAT. If it does, plain
WireGuard and OpenVPN both need infrastructure we do not have, Tailscale's DERP becomes
non-substitutable, and Headscale becomes the only route to dropping the SaaS dependency. Check
before revisiting.

Related: `docs/architecture/0019-deterministic-enforcement-point.md`,
`docs/architecture/0011-enrollment-security-model.md`,
`docs/architecture/0009-security-inspection-proxy.md`, `alert_manager/tailscale_api.py`.

### [SMALL] Two cosmetic finds from the 2026-07-31 change-password build
Captured during step 1b (auth work); neither chased, per Rule 7.

- [x] **DONE 2026-07-31 (step 5). TWO sites, not one.** `templates/login.html` forgot-password hint pointed at the pre-`/opt` path. It tells the
  user to SSH in and run `python3 ~/dashboard/core/manage.py reset-password <username>`. That path
  has been wrong since the 2026-07-27 relocation — the tree is `/opt/nemesis` now. This is the one
  instruction shown to someone who is *already locked out*, so a stale path here costs more than
  its size suggests: it's the recovery path failing at exactly the moment it's needed. Worth
  re-checking when the root-only `nemesis-admin reset-password` CLI lands (queued step 5 of the
  recovery-codes sequence) — that CLI will likely replace this hint's wording entirely, so fixing
  the path now and the wording again later may be one edit, not two.
  **Resolved exactly that way:** fixed during step 5 alongside the root-only guard, so the
  path, the required `sudo`, and the reframing ("No recovery codes either?" — recovery codes
  now being the first resort) landed as a single edit.
  **A SECOND stale site turned up in the same sweep** and is also fixed: `dashboard.py`
  (uninstall panel) told the user "Your ~/dashboard directory and data will NOT be deleted."
  A repo-wide grep across `*.py`/`*.html` now returns zero `~/dashboard` references.

- [ ] **`tickets` row id 26 has an empty `title`.** Pre-existing, unrelated to the auth work —
  spotted only because a tier-1 lockout test wrote ticket 27 next to it. Not investigated. Worth
  one look to confirm it's a benign old row rather than a write path that can leave a ticket
  untitled (an untitled ticket is effectively invisible in the queue UI).

### [SMALL] `login_events.timestamp` is UTC; every other table is local
Found 2026-07-31 while testing the recovery-code login flow. Not fixed that night by
decision — recorded here so it isn't lost.

- [ ] **A 5-hour skew sits between `login_events` and everything else.** `login_events.timestamp`
  is `DEFAULT (datetime('now'))`, which SQLite evaluates as **UTC**. `users.last_login`,
  `users.lockout_until`, `users.password_changed_at` and `audit_log.ts` are all written by
  Python `datetime.now()` — **local**. The same login writes `2026-07-31 22:58:45` to one
  table and `2026-07-31T17:58:45` to the other.

  **Self-consistent today, which is exactly why it's easy to miss.** Nothing is currently
  broken: the concurrent-session query compares `timestamp` against SQLite's own
  `datetime('now','-24 hours')`, so it's UTC-vs-UTC and correct. The trap is that
  `login_events` exists specifically to feed brute-force, impossible-travel, and
  concurrent-session detection — and the first person to correlate it against `users` or
  `audit_log` by time gets a silent 5-hour error, in the direction that makes attacker
  activity look like it happened in the future.

  Also note the two formats differ (`YYYY-MM-DD HH:MM:SS` with a space vs. ISO `T`), so a
  naive string comparison between the columns misorders as well as misaligns.

  Fix carefully — changing the DEFAULT does not rewrite existing rows, so any migration has
  to decide what to do about history (rows written before the change are genuinely UTC).
  Converting in place is possible but must be one-shot and guarded; the safer route may be
  a new explicitly-named column alongside, with readers migrated over.

### [SMALL] Out-of-band credential changes leave no audit trail
Found 2026-07-31 during a live operator lockout, while closing out the recovery-code work.

- [x] **DONE 2026-08-01 (Window 1; uncommitted, held for operator review as of this entry).**
  `core/manage.py` added `_actor()`/`_audit()` helpers and wired them into `reset_password`,
  `create_user`, and `unlock` — each now inserts an `audit_log` row (`cli_reset_password` /
  `cli_create_user` / `cli_unlock`) attributed via `SUDO_USER` (prefixed `cli:` so it can never
  be mistaken for a dashboard username in the same column), best-effort/non-blocking so a
  failed audit write can never cost the operator the credential recovery itself. Originally
  reported below (verbatim, kept for context): `core/manage.py` wrote ZERO `audit_log` rows
  (`grep -cE "audit_log|_audit\(|login_events"` returned 0). `reset-password`, `create-user`
  and `unlock` all mutated credentials or lockout state and recorded nothing anywhere. The same
  was true of a direct SQL edit.

  **Why it matters more than it looks.** Everything the dashboard does is now attributed:
  `password_change`, `login_recovery_code_used`, `recovery_codes_generated`, plus
  `login_events` carrying `source`/`action` so even nemesis-fwd's credential checks are
  recorded. The one path that is *entirely unrecorded* is the most privileged one — root
  resetting the admin password. "Who reset this password, and when?" is answerable for every
  route except the route most likely to be asked about after an incident.

  Confirmed live: two lockout clears performed during the 2026-07-31 incident produced no
  audit rows at all. Their only trace is the session worklog, which is not a security record.

- [ ] **Don't run `manage.py` as root while the WAL sidecars are absent.** `alerts.db` is
  currently checkpointed with no `-wal`/`-shm` present. A root process opening the database
  would create them **root-owned**, after which `nemesis-dash` could no longer write and the
  dashboard would fail. Recoverable with a `chown` to `<user>:nemesis-db`, but avoidable:
  prefer the recovery-code path, or chown the sidecars afterwards. This is an unintended
  consequence of the root-only guard added the same evening — the guard is right, the
  interaction was not foreseen.

### [SMALL] Two follow-ups flagged by Window 1 during the recovery-code-email build (2026-08-01)

- [ ] **Migrate the existing lockout-tier email onto `_notify_email_async`.** `dashboard.py`
  gained `_notify_email_async()` (a daemon-thread wrapper around the existing, blocking
  `_notify_email()`) as part of the recovery-code-consumption alert (commit `66715af`). The
  existing lockout-tier notification at `dashboard.py:512` (inside `_register_credential_failure`)
  still calls the blocking `_notify_email()` directly, so it can still stall a login/change-
  password/idle-unlock response for up to 30s on an SMTP hang. Deliberately NOT folded into the
  recovery-code-email commit — a behavior change to a working path belongs in its own commit,
  per Window 1's note in `_notify_email_async`'s docstring. Small, mechanical: swap the one call
  site, verify the lockout email still sends (real SMTP test or timing check, not assumed).

- [ ] **Testability gap: `_SECRET_KEY_PATH` resolves against `nemesis_paths.DATA_DIR` (the
  constant), not `data_dir()` (the function).** Flagged by Window 1 while working the
  idle-lock/recovery-email auth code. Because it reads the module-level constant rather than
  calling the function, it ignores a `NEMESIS_DB_PATH` override — meaning a test harness or
  throwaway-DB verification run that sets `NEMESIS_DB_PATH` to redirect the database still has
  the Flask secret key resolve against the real `DATA_DIR`, not the overridden one. Worth
  checking whether other `_HERE`/`nemesis_paths`-adjacent constants in `dashboard.py` have the
  same constant-vs-function mismatch — this may not be the only site.

### [SMALL] Backup-schedule feature is non-functional on production, independent of the injection fix

Found 2026-08-01 by Window 1 while verifying the `api_backup_schedule` shell-injection fix
(crontab-interpolation commit). Separate from that fix — the injection was real and is now
closed, but the feature it belongs to doesn't currently work at all on the live box, for an
unrelated reason.

- [ ] **`nemesis-dash` cannot write a crontab.** The service runs under
  `NoNewPrivileges=yes` (Phase 3 hardening, 2026-07-31), and `crontab` invocation from that
  context has no crontab access — so every scheduled-backup save silently fails to actually
  install anything on the running system, regardless of whether the cron-line content itself
  is now safe. The UI presumably still reports success (not independently confirmed here — no
  claim either way about the response path, just that the crontab write itself doesn't take).
  Needs its own investigation: whether to route the crontab write through `nemesis-fwd` (the
  existing privileged-helper pattern used elsewhere for exactly this kind of
  needs-a-privilege-the-hardened-service-doesn't-have problem), or a different mechanism
  entirely (systemd timer owned by a different unit, etc.).

### [SMALL] Stale NOPASSWD sudoers rules reference the pre-relocation dashboard path

Reported by Window 1, 2026-08-01. Not independently re-checked in this session — Window 2
does not have read access to `/etc/sudoers.d/` (root-only, mode 0440) to confirm directly, so
this is recorded as reported rather than verified against the live files.

- [ ] **One or more `/etc/sudoers.d/` entries still grant `NOPASSWD` against the
  pre-`/opt`-relocation `/home/<user>/dashboard/...` path**, not the current
  `/opt/nemesis/...` path. Same category as the "three unrelated temporary sudoers grants"
  already open in `docs/handoff/HANDOFF.md` §6, and the same shape as PUNCHLIST's existing
  literal-`/home/<user>/dashboard/...`-path findings (systemd units + `vpn-dns-guard.service`,
  above). Inert rather than actively dangerous — a rule referencing a path that no longer
  exists cannot be exercised — but it's leftover attack surface from the 2026-07-27 `/opt`
  relocation that should be cleaned up in the same pass as those other stale-path items rather
  than tracked separately. Not urgent.

### [PROJECT] Decision B — host-defense layer productization (durable tracking, first flagged 2026-07-31)

"Decision B" has existed as a scoping decision since the 2026-07-31 install-test session
(`docs/handoff/worklog/2026-07-31-001.md`, Gap 8) but has never had a home in PUNCHLIST or
`docs/roadmap/` until now — only mentioned inline in that worklog. This entry consolidates
what's known so it isn't rediscovered piecemeal.

- [ ] **`install.sh` does not ship the host-defense hardening layer to real customer
  installs — confirmed twice now, two different components, same root cause.**
  - **fail2ban** (Gap 8, 2026-07-31): the package is never installed by `install.sh`;
    `deploy_nemesis_fwd.sh`'s `F2B_USER` check warns and never dies, so a fresh install
    silently runs without the repeat-offender jail at all.
  - **The 2026-07-29 hardened nginx rate-limiting + fail2ban configuration** (confirmed
    2026-08-01, during the DoS-resilience scoping pass — see
    `docs/architecture/0021-dos-resilience-scoping.md`): this reference deployment now has
    it live, but it exists only as manually-staged config on this one box, not as anything
    `install.sh` provisions. A fresh customer install today gets none of this protection.
  - Same shape as the previously-found Gap 6 (a capability that exists on the reference
    deployment but was never wired into the standard installer) — this is that pattern
    recurring against a different capability, not a new category of defect.
  - Scope note from the DoS-resilience ADR: bringing this into `install.sh` is identified as
    "the natural anchor of the later hardening pass," not scheduled standalone — recorded
    here as the durable PUNCHLIST home for Decision B, not as a commitment to build now.

### [SMALL] Dashboard-side ingestion of `degraded.jsonl` into `audit_log`

Flagged by Window 1, 2026-08-01, as a distinct next item during the ADR 0019 netlink-watcher
build (`nemesis_fw_watch.py`'s `_audit_row()` is a deliberate no-op — see that function's
docstring for the full account). Designed and approved; deliberately not built as part of
that commit.

- [ ] **The netlink watcher (and any other privileged, non-dashboard process) must never open
  `alerts.db` directly.** Measured on the VM 2026-08-01: a privileged process writing
  `audit_log` as root created root-owned WAL sidecars (`-wal`/`-shm`) and **locked
  `nemesis-dash` out of writing its own database** ("nemesis-dash CANNOT write: attempt to
  write a readonly database"). Same hazard already recorded in HANDOFF §6 for
  `core/manage.py`. The fix pattern already exists in the codebase — `nemesis_fwd.py`'s
  `signal_degraded()` deliberately writes to a **file** (`degraded.jsonl`), not a DB table,
  for exactly this reason.
  - **What's needed:** the dashboard (running as `nemesis-dash`, which owns the DB) reads
    `degraded.jsonl` and writes the corresponding `audit_log` row itself, as the owning user.
    This keeps the audit trail intact while keeping every privileged process out of the
    shared database entirely.
  - Until this lands, watcher-raised events (tamper, enforcement-loss) are still fully
    alerted via the other two channels (journal, email) — this is a durability/completeness
    gap in the audit trail, not a detection gap.

### [SMALL] Absolute session cap not evaluated on the unlock page itself

Flagged by Window 3, 2026-08-01, during the lock-screen health-summary build.
Pre-existing — not introduced by that commit, just made more visible by it.

- [ ] **`/account/unlock` (`account_unlock`) is in `_IDLE_LOCK_ALLOWED`, so requests to it
  skip `_enforce_setup_and_auth()`'s walk-away-protection branch entirely** — including the
  `_session_lock_state()` check that decides between "locked" (confine) and "expired"
  (`SESSION_MAX_HOURS`, full logout). A session that reaches the unlock page while idle-
  locked and later crosses the absolute cap while that page sits open (or auto-refreshing,
  as of the health-summary commit) never gets transitioned to "expired" by visiting or
  refreshing that page — only navigating to a DIFFERENT route re-triggers the check. Low
  urgency: the cap still enforces correctly everywhere else, and the practical exposure is
  bounded to whatever's already on-screen on the one page that was deliberately exempted
  from the idle-lock gate. Candidate for the standing route-level security audit
  (CLAUDE.md) rather than a standalone fix — worth checking whether `_session_lock_state()`
  should be split so the absolute-cap half runs even inside `_IDLE_LOCK_ALLOWED` routes
  while the idle-lock half stays skipped there.

### [SMALL] Intermittent reboot hang on `boot-efi.mount` — OS/desktop-level, not Nemesis

Flagged by Window 3, 2026-08-02, investigating a reboot hang reported that morning
(screenshot evidence: `boot-efi.mount/stop` running 1m43s → 6+ min, kernel hung-task
warnings). Read-only investigation, no fix applied — see that session's findings for full
detail. **Confirmed NOT caused by last night's (2026-08-01) ADR 0019 Increment 4 work**: the
identical hang signature reproduced on the *prior* morning's reboot (boot -4,
2026-07-31 08:06:57 → 08:11:25), hours before `nemesis-fw-watch`/`nemesis-fw-enforce` existed
as installed units. `nemesis-fw-watch`, `nemesis-fw-enforce`, and `nemesis-fwd` all stop
cleanly and near-instantly (`Deactivated successfully`, same second as the reboot request)
in both occurrences — well outside the blocking chain. Other reboots in between unmount
`boot-efi.mount` in under 2 seconds with no hang, so this is intermittent, not universal.

**Root cause chain (established, not yet fixed):** a long-running Firefox (snap) session's
apparmor confinement **denies** it the `PrepareForShutdown`/`PrepareForShutdownWithMetadata`
dbus signals from `logind`, so it never gets a clean-shutdown notice → the GNOME session
scope's 90s stop-timeout expires and SIGKILLs it → the hard kill triggers an apport coredump
write for a process that's been running ~24h → that coredump write contends for I/O with
systemd's own internal `(sd-sync)` helper (confirmed genuine systemd-internal component,
found in `libsystemd-shared-259.so`; same naming convention as the well-known `(sd-pam)`
helper) which does a blocking sync/writeback flush before unmounting `/boot/efi` — and
`/boot/efi` and `/` share the same physical NVMe device, so the backlog stalls the EFI
partition's unmount specifically. System eventually force-unmounts and completes the reboot
on its own; no data loss observed, just several extra minutes on shutdown.

**VirtualBox VM teardown checked and ruled out for THIS occurrence** (VM teardown during
sync is an independently known trigger for this class of stall in general, so it was worth
excluding explicitly rather than assumed away). Evidence, all from the same boot's journal +
on-disk VM logs: (1) `virtualbox.service` (the vboxdrv/VBoxNetFlt kernel-module unload)
completed in under 1 second with no error — would not happen cleanly/instantly if any VM
process still held `/dev/vboxdrv` open; (2) zero `VBoxHeadless`/`VirtualBoxVM`/`VBoxSVC`
process references anywhere in the boot's journal at shutdown time; (3) the two
most-recently-active VM logs (`Nemesis-firewall Master Ubunty 26.04`, `Nemesis-firewall
W3-TEST 07.29`) both show clean, deliberate `PoweredOff`/`VBoxHeadless: exiting` sequences
timestamped **hours before** the reboot (~16:37 and ~21:14 on 08-01, vs. the 09:12 08-02
reboot); (4) the last VM-start kernel event (`vboxdrv: ... VMMR0.r0` / `VBoxNetFlt: attached`)
in the entire boot was 16:35:37 on 08-01, ~17h before shutdown, with nothing after; (5) no VM
log file anywhere shows write activity in the 09:00–09:20 08-02 window. This directly
contradicts a "two VMs running at shutdown" premise floated during the investigation — worth
noting since it means that recollection doesn't match the journal for *this* reboot. I/O
contention traces to the Firefox coredump write alone, not VM teardown, not both overlapping.

- [ ] **Low priority, not urgent — host OS/desktop config, not application code.** Candidate
  fixes (not yet evaluated for tradeoffs):
  - Adjust the `snap.firefox.firefox` apparmor profile to allow receiving `login1`'s
    `PrepareForShutdown`/`PrepareForShutdownWithMetadata` dbus signals, so Firefox gets a
    chance to exit cleanly instead of being hard-killed.
  - Lower `session-*.scope`'s stop timeout (or otherwise avoid the SIGKILL-into-coredump
    path) for graphical sessions at shutdown.
  - Exclude large/long-running browser processes from coredump generation on shutdown
    specifically (e.g. scoped `core_pattern`/apport handling), since the dump is never
    useful post-reboot anyway in this scenario.

### [SMALL] VM test fleet — three minor items from the 2026-08-02 cleanup pass

Flagged by Window 3 while consolidating the VirtualBox inventory down to the 7-Master fleet
(see `CLAUDE.md` → "VM test fleet"). All low priority, none blocking.

- [ ] **`Nemesis Linux Master ISOLATED` — SSH unreachable on the isolated subnet.** Port 22
  times out (reproducible, not transient); ICMP works fine, so the box itself is up and
  networked correctly. Most likely a `ufw` rule scoped to this VM's original bridged-LAN
  subnet (`<bridged-lan-subnet>`) that doesn't match the new hostonly subnet
  (`192.168.56.0/24`) after the NIC was switched to isolated — not confirmed in-guest
  (no Guest Additions installed on this VM to inspect safely; SSH itself being the thing
  that's broken makes it hard to check from inside without a riskier method). Not urgent —
  revisit only if a future test specifically needs inbound SSH to this box.
- [ ] **`Nemesis Windows11 Master BRIDGED` and `...ISOLATED` share the identical NetBIOS
  hostname `NEMESIS-SW-CLEA`.** `...ISOLATED` is a clone of `...BRIDGED`'s lineage and never
  got a unique hostname. Matches an old NetBIOS name-collision event found in `...BRIDGED`'s
  event log history (dated 2026-07-02, from before this cleanup). Not a live conflict today
  since the two sit on separate network segments (bridged vs. isolated), but would collide
  if both were ever active on the same segment at once. Fix: rename one guest's hostname.
- [ ] **`Nemesis Windows11 Master BRIDGED` and `...ISOLATED` — password auth not
  independently verified.** Login was confirmed via SSH key auth (passwordless, already
  configured) and `test-user` was confirmed in the local Administrators group on both, but
  the actual password *value* wasn't re-checked against local-config.md's standard test
  creds — `sshpass` wasn't available on the host at verification time and installing new
  tooling mid-task felt out of scope. Low risk (key auth already proves the account is
  usable) but worth a real check before relying on password-based login to either box.

### [SMALL] Guard-unavailable degradation is journal-only — the enforcement table goes silently stale

Found 2026-08-02 by Window 1 while re-measuring check 7 (`rerender()` fail-closed) on the VM.
Not a fail-closed defect — the refusal behaviour is correct and now proven. This is the
*observability* half.

- [ ] **When the never-block guard is unavailable, nothing outside the systemd journal records
  it.** `rerender()` (`alert_manager/nemesis_fw_watch.py:220-222`) checks the render exit code,
  calls `log.error("fwwatch: render failed: ...")` and `return`s. It does **not** call `alert()`,
  so there is no `degraded.jsonl` record, no email, and no `audit_log` row. Confirmed on the VM,
  not inferred: during the check-7 run `degraded.jsonl` captured the tamper alerts
  (`NEM-FWW-0001`) and **nothing** for the render failure.

  **Consequence.** While the guard is broken the derived table keeps enforcing the last good
  ruleset but stops tracking ufw — it goes **stale**, silently. Enforcement is still safe (that is
  the deliberate tradeoff: stale-but-guarded beats fresh-but-unguarded), but an operator has no
  signal that their firewall changes have stopped propagating to the enforcement table. Fail-closed
  and silent is still silent.

  **Distinct from the two existing `degraded.jsonl` items above** — those are downstream (nothing
  *reads* the file; ingesting it into `audit_log`). This one is upstream: the record is never
  *written*. Building a reader and wiring the ingestion would still leave this event invisible,
  because nothing emits it. Worth fixing in the same pass as the ingestion item so the channel is
  end-to-end rather than half-wired.

  Deliberately out of scope for the Increment 4 cutover; captured rather than folded in.
  Reference: `~/work/nemesis-internal/firewall-enforcement-engine/VM-TEST-PLAN.md` check 2.

### [LOW] Unlabeled test row in live `login_events` (id 83, `harnesstest`)

Found 2026-08-02 by Window 1 while verifying the `login_events` UTC→local migration.

- [ ] **Row id 83, username `harnesstest`** (now `2026-08-01T18:11:03` after the migration) is a
  leftover from the 2026-08-01 session. It carries no Rule 11 label — no literal `test data`
  string, no date — so the standard `LIKE '%test data%'` sweep will never find it.

  `login_events` is **not** the documented `audit_log` exception to Rule 11: it has free-text
  fields (`username`, `failure_reason`) that could have carried the label, so this is a genuine
  miss rather than an unlabelable table.

  Verified the same day that this is the only such stray in live `login_events` (57 rows total).
  The `tzwritercheck` row from that session's writer-arity check was deliberately written to a
  throwaway copy and never entered the live database.

  Not urgent. Delete or relabel at the next cleanup pass.

### [SMALL] Never ship a starter config that duplicates the in-code defaults

Root cause of the 2026-08-02 YARA-exclusion shadowing incident. Not urgent; prevents a repeat.

- [ ] **`/etc/nemesis-yara-exclusions.conf` was created on 2026-06-29 as a "starter config"
  containing a verbatim copy of the shipped defaults** (AST-compared 2026-08-02: 14 patterns,
  same order, **zero** operator customisation). Because `_load_exclusions()` correctly prefers
  the conf file whenever it exists and is non-empty, that starter permanently and silently
  shadowed the in-code defaults on this box.

  **The consequence, six weeks later:** the 2026-08-02 commit removing `/tmp` and `/var/tmp`
  from the exclusion list — a deliberate coverage fix, since those are the design's own
  high-risk dropper-landing paths — was **correct in code and completely inert in production**.
  Caught by Window 2 during commit review; resolved by removing the conf (snapshot
  `2026-08-02-1251-pre-yara-exclusions-conf-removal`) and restarting.

  **The override mechanism is not the bug — seeding it with a copy of the defaults is.** It
  guarantees that every future defaults change is shadowed on every box carrying the starter,
  and it looks perfectly healthy while doing it.

  - [ ] **Rule to adopt:** never install a config file whose content duplicates shipped
    defaults. If discoverability is the goal, ship `<name>.conf.example` — a filename the
    loader does not read — so it documents the mechanism without overriding it.
  - [ ] Audit whether any other `/etc/nemesis-*` config on this box (or written by `install.sh`)
    has the same shape: present, unmodified, and shadowing code defaults. (Tracked as its own
    audit — see the "Config-shadows-code-defaults audit" work below.)

### [SMALL] `_load_exclusions()` should log when it is SHADOWING, not just count + source

Companion to the item above — the detection half of the same failure.

- [ ] **The existing log line is true and useless.** `_load_exclusions()` logs
  `"%d known-good path exclusions loaded from %s"`. During the entire six weeks the stale conf
  was shadowing corrected defaults, that line read `14 ... loaded from
  /etc/nemesis-yara-exclusions.conf` — accurate, and giving no hint that the code's own defaults
  were being ignored or that they had since changed.

  - [ ] When loading from a conf file, additionally report whether the conf **differs from the
    in-code defaults**, and how (count delta, or an explicit "identical to defaults — this
    override is a no-op" note). An override that matches the defaults exactly is almost always
    an accident, and saying so at load time is what would have surfaced this in June rather
    than August.
  - [ ] Same class as the standing "verification/derivation code must prove its own premise"
    rule: a status line that cannot distinguish a deliberate override from an accidental
    shadow is reporting a value, not a measurement.

### [PRIORITY — right after M2] Test-seam for the YARA fetch-and-activate path

The 2026-08-02 SSRF guard on `yara_update_source` (`_validate_source_url`,
`modules/malware_detection/module.py`) is correct and stays as-is — but as a direct
consequence, `update_yara_rules()`'s full fetch→validate→stage→compile→activate path now has
**no runnable live-service test**. The guard rejects `https://` to loopback, private, and
link-local ranges (correctly — that's its entire job), which means the obvious test approach
— spin up a local test HTTPS server, point the updater at it — is rejected by the very guard
being exercised. This is a testability gap, not a production defect: nothing here is a
security hole, but "we can't test it, so it ships untested" should not sit open for long.

**What's still testable today without this fix, so it's not blocking:** `_validate_source_url`
itself is a pure function and needs no live server — it's already directly unit-testable
against known public/private/loopback addresses (this is exactly how it was verified during
M2's review). The gap is specifically the *integration* path downstream of validation: does a
fetched ruleset actually stage atomically, compile-check against the combined bundled+
candidate set, activate via `os.replace`, and reload — end to end, against something that
behaves like a real server.

**Two approaches, not equivalent:**

- **Injectable opener/fetcher (recommended).** Give `_fetch_ruleset` (or the thing it calls)
  a swappable dependency for the actual network I/O — defaulting to the real
  `urllib.request`-based fetch, overridable by a test harness with an in-process fake server
  or a canned response. `_validate_source_url` is untouched and still runs for real inputs;
  a test exercising the *activation* logic supplies its own opener and never goes near the
  guard at all, because the two concerns (is this URL safe to fetch / does fetched content
  activate correctly) are orthogonal and should be tested that way. Cost: a small, real
  refactor of `_fetch_ruleset`'s signature to accept the dependency.
- **Off-by-default, API-unsettable override (rejected as primary, worth naming why).** An
  env-var or similar flag checked inside `_validate_source_url` itself to skip the
  public/private check in test contexts. Simpler to write, but it puts a bypass branch
  directly inside the production security function being validated — exactly the kind of
  seam that can survive an unrelated future refactor and become reachable when it shouldn't
  be. Rejected for that reason: the injectable-opener approach gets the same test coverage
  without ever adding a conditional bypass to the guard's own code path.

**Closes:** a live-service round-trip test for activate / reject / rules-landing-in-the-
writable-dir, without weakening `_validate_source_url` for real operator-supplied values.
Propose the actual refactor as its own reviewed change, not bundled into a fix commit —
this entry is the proposal, not the implementation.

### [FIX-NOW] Installer tokens cannot be revoked through the product

- [ ] **Installer tokens cannot be revoked through the product — `revoked` is enforced on read
  but nothing ever writes it.** Found 2026-08-02 while withdrawing a token that had been pasted
  into a chat transcript during live verification of the pre-warn download page.
    - [ ] `_valid_installer_token()` (`dashboard.py`) correctly refuses a row with `revoked=1`,
      so the enforcement half is already right and needs no change.
    - [ ] But **no route anywhere writes that column.** Grep confirms `revoked` appears only in
      the SELECT's WHERE clause. Issuance exists (`POST /api/agent/installer/generate`);
      withdrawal does not.
    - [ ] The gap is only reachable in one specific state, which is why it went unnoticed: a token
      that was **issued but never used to enrol**. It has no device and therefore never appears in
      the device-approval flow, which is the only place anything revocation-shaped lives. A
      mis-sent or exposed link can currently only be waited out until `expires_at`.
    - [ ] Fix is small and well-scoped: an authenticated `POST /api/agent/installer/revoke`
      alongside the existing generate route, plus a revoke control wherever installer links are
      listed. Same auth posture as generate — this is a state-changing action, so POST with the
      correct credential, never a GET (standing route-audit shape 1).
    - [ ] Interim workaround used this time, for the record: direct `UPDATE enrollment_tokens SET
      revoked=1`, preceded by a USB state snapshot, and verified end-to-end (`/start` and `/zip`
      both returned 410 afterwards) rather than trusting the flag alone.

- [ ] **Installer target address is inherited, not chosen — transport security decided by whichever
  URL fetched the installer.** `_nemesis_tailnet_host()` (`dashboard.py`) prefers
  `NEMESIS_TAILNET_ADDR`, then `NEMESIS_SERVER_IP`, then falls back to the host of whatever request
  fetched the installer. With neither env var set, two installers generated minutes apart can bake
  different server addresses — and therefore different transport security — with nothing anywhere
  recording which a device got.
    - [ ] Why it matters: Nemesis terminates TLS nowhere (the single enabled nginx site is
      `listen 80`, no `ssl_certificate`; no `ssl_context`/`wrap_socket` in any Python). A
      non-tailnet target therefore means the installer download — which carries a one-time
      enrollment token and a live Tailscale pre-auth key — and every later heartbeat cross the
      network in clear. A tailnet target rides WireGuard and none of that is exposed.
    - [ ] **Currently latent, not active** (verified 2026-08-03): `NEMESIS_PUBLIC_URL` is set on
      this box and resolves inside `100.64.0.0/10`, so links and agents already ride the tailnet.
      Unset it, or point it at a LAN address, and everything silently drops to cleartext.
    - [ ] **Warned-on, not prevented** (2026-08-03): cleartext and unclassifiable targets now raise
      an operator-facing warning when a link is generated, plus a server-side log line. The
      fallback was deliberately kept rather than made fatal — a LAN-only deployment with no tailnet
      is a supported configuration, so refusing outright would break legitimate installs.
    - [ ] Fix: set `NEMESIS_TAILNET_ADDR` on every deployment that has a tailnet (makes the target
      deterministic and independent of request context), then decide whether a cleartext target
      should be refused rather than warned. Worth doing regardless of the separate TLS decision,
      which is sequenced after ADR 0004 Stage 1.

- [ ] **` ` (narrow no-break space) before KB/MB units in `dashboard.py` silently breaks exact-
  match edits.** Confirmed live 2026-08-03 while building the storage/retention work: the line
  `mb < 1 ? Math.round(mb * 1024) + ' KB' : mb.toFixed(1) + ' MB';` in `openBackupModal()` does not
  contain ASCII spaces before `KB`/`MB` — it contains U+202F. Two separate Edit calls failed with
  "string not found" against text that was visually identical to the file, and the cause was only
  found by dumping `repr()` of the raw line.
    - [ ] Why it matters as an EDITING TRAP, not a display bug: it renders correctly and reads
      correctly in every normal tool (`grep`, `sed`, `cat`, the Read tool). Nothing about the
      failure points at the real cause, so the natural next move is to assume the line moved or
      the file changed underneath you and start re-reading — which finds nothing, because the text
      really is there. Cost this session was several wasted edit attempts.
    - [ ] How to recognise it: an exact-match edit failing on a line you can see verbatim in the
      file. Confirm with `python3 -c "print(repr(open('dashboard.py').readlines()[N]))"` and look
      for ` ` (or any `\uXXXX`) where a space appears.
    - [ ] How to work around it: anchor the edit on a neighbouring ASCII-only line, or insert by
      line number after asserting on a substring that avoids the Unicode.
    - [ ] Decide separately whether the character should simply be normalised to ASCII across
      `dashboard.py`. It appears to be deliberate typography (narrow space before a unit), so this
      is a judgement call, not an obvious cleanup — normalising changes rendered output.

- [ ] **Backup modal still lists a file the backup no longer contains.** The modal's contents list
  (`dashboard.py`, backup modal HTML) names "Tickets & notes (modules/tickets/tickets.db)", but
  `_backup_candidates()` retired that entry at ADR 0001 Stage 6 — tickets now live in the shared
  `alerts.db` and are captured by its entry. The list is stale copy, not a missing backup: the data
  IS backed up, just not from where the modal claims.
    - [ ] Why it matters: an operator reading the list to confirm coverage sees a path that no
      longer exists, which is the kind of detail that erodes trust in the rest of the list.
    - [ ] Fix is one line of copy in the modal HTML. Do it alongside the next backup-UI change
      rather than as its own commit.

- [ ] **The frozen agent's log is written into the PyInstaller temp dir and vanishes when it
  exits.** `agent.py` sets `_HERE = os.path.dirname(os.path.abspath(__file__))` and logs to
  `_HERE/nemesis_agent.log`. Under a PyInstaller one-file build `__file__` resolves inside the
  `_MEIPASS` extraction directory, so the log lands there and is removed with it on exit.
    - [ ] **Confirmed live 2026-08-03** on a frozen `NemesisAgent.exe` (CI run for `74d68b6`):
      the log was found at `%TEMP%\_MEI<nnnnn>\nemesis_agent.log`, containing the expected
      `Nemesis Agent starting (platform=Windows)` line — in a directory that only exists while
      the process is alive.
    - [ ] Why it matters: an agent that fails on a remote or trip machine leaves no diagnostic
      behind, which is exactly the case the log exists for. A crash is the scenario where the
      evidence is most needed and least likely to survive.
    - [ ] Pre-existing — not introduced by the tier-3 key-protection work; that work just made
      it visible, because the startup gate and migration prompt are the first things anyone
      would want to read the log to debug.
    - [ ] Fix is small: resolve the log path the way `config.py` already resolves its own state
      (`%APPDATA%\Nemesis` when frozen, alongside the source otherwise) rather than from
      `__file__`. `installer_gui.py` already does the right thing and writes its install log to
      `%APPDATA%\Nemesis`, so there is a working pattern in-tree to copy.

- [ ] **Archive/verify/self-test helpers are duplicated between `hw_monitor.py` and
  `data_manager.py`.** The storage/retention build (2026-08-03) shipped the same
  archive-verify-then-modify machinery twice: `_read_archive`/`_verify_archive`/
  `_selftest_verifier` in `core_module/hw_monitor/hw_monitor.py` (piece 4,
  `top_processes`) and `_read_oplog_archive`/`_verify_oplog_archive`/
  `_selftest_oplog_verifier` in `alert_manager/data_manager.py` (piece 5,
  `dm_operation_log`). Same ordering, same canary discipline, two copies.
    - [ ] Why it was left duplicated, deliberately: piece 4 was already committed,
      deployed, and run against live data by the time piece 5 was written. Refactoring
      working, verified archival code mid-build to share helpers is real regression risk
      for no functional gain. The duplication was the safer trade at the time.
    - [ ] Why it should still be fixed: duplicated VERIFICATION logic is exactly the kind
      that drifts. If one copy gains a check the other does not, the weaker one keeps
      approving moves it should refuse, and nothing about that failure is visible — it
      looks like a successful archival. That is the same class of defect the standing
      "verification code must prove its own premise" practice exists to catch.
    - [ ] **The fix must respect the core_module / Data Manager architecture — it is NOT a
      casual two-file merge (operator direction, 2026-08-03).** A full day was spent
      untangling processes into `core_module/` and forcing DB access through the Data
      Manager specifically so shared logic like this has ONE authoritative home. A "quick
      dedup" that picks whichever file is more convenient, or that introduces a third
      free-floating helper module alongside the two existing copies, recreates exactly the
      problem it claims to solve — now with three implementations instead of two. Whatever
      the consolidation does, it routes through the established structure rather than
      around it.
    - [ ] Shape of the fix (subject to the constraint above): the archival helpers are DB
      lifecycle operations on tables the Data Manager already mediates, so the Data Manager
      is the architecturally correct owner — `hw_monitor` already imports `data_manager`, so
      no new dependency edge is created. The two copies differ only in payload shape
      (`{id: text}` vs `{id: row_dict}`), which one implementation handles by comparing
      whatever it is given. Confirm this against ADR 0006 before building, rather than
      treating this bullet as the decision.
    - [ ] Sequencing: do this AFTER the storage/retention pieces are fully done, not
      squeezed in mid-build (operator direction, 2026-08-03). Piece 4 was already deployed
      and run against live data before piece 5 existed; refactoring verified archival code
      while more of it was still being written is the wrong order.
    - [ ] **SCOPE BOUND — a small contained fix, NOT a cleanup pass (operator direction,
      2026-08-03).** This is one duplication, in two named files, with one shared
      implementation as the outcome. It is explicitly NOT a broader audit of shared logic,
      NOT a survey of other possible duplications, and NOT a repeat of the multi-day
      core_module untangling. "Route it through core_module/Data Manager properly" is a
      constraint on WHERE the single implementation lands — it is not licence to expand the
      work into a structural review. If the fix starts growing beyond these two files and
      their verification suites, stop and re-scope with the operator rather than continuing.
    - [ ] Do NOT do this without re-running both pieces' verification suites afterwards,
      including the three injected-failure abort tests for each. The whole point of the
      helpers is that they fail correctly; a refactor that is only proved to succeed
      correctly has not been tested.

- [ ] **`alert_manager/test_quarantine.py` calls `alert_watcher.handle_line()` with the wrong
  arity — the test drifted, the watcher did not.** Running the script raises
  `TypeError: handle_line() takes 1 positional argument but 2 were given` at
  `test_quarantine.py:163`, which passes `(fake_line(rule_id), blocked_cache)`.
    - [ ] **Surfaced 2026-08-03 as an apparent outage.** Ubuntu's Apport captured the unhandled
      exception and the desktop crash-notifier fired, which read as "quarantine.py stopped".
      It is not a service — there is no `quarantine.py` in the repo, no systemd unit by that
      name, and it is not in the watchdog's monitored list. All Nemesis services were healthy
      throughout. Cost roughly half an hour to establish that nothing was actually down.
    - [ ] **Second instance of the same defect class as the 2026-08-02 installer arity crash**
      (`_read_baked_config()` returning 7 values while `main()` unpacked 8). A caller and a
      callee drift apart, nothing type-checks the boundary, and it stays invisible until
      something actually runs the path. Worth treating as a pattern rather than two unlucky
      one-offs — the tests that would catch it are exactly the ones nobody runs by default.
    - [ ] **Scoped 2026-08-03 — it is THREE stale sites, not one.** The traceback only reaches
      the first, so fixing that line alone just moves the same `TypeError` down the file:
      - `:163` `alert_watcher.handle_line(fake_line(rule_id), blocked_cache)` → `handle_line(line)`
      - `:296` `alert_watcher.expiry_sweep(blocked_cache)` → `expiry_sweep()`
      - `:303` `check("blocked_cache pruned", TEST_IP not in blocked_cache)` → asserts behaviour
        that **no longer exists anywhere**; nothing in `alert_watcher.py` prunes any cache.
    - [ ] The first two are mechanical. **The third is a judgment call and must not be silently
      deleted** — dropping the line removes real coverage and leaves the suite quietly weaker.
      Replace it with an assertion about the behaviour that actually superseded it (blocked-IP
      state is now internal to the watcher via `load_blocked_ips`/`ufw_insert_top`), or state
      explicitly in the diff why that coverage is no longer meaningful.
    - [ ] **The dedupe assumption did NOT drift** — checked. `fake_line` yields a Priority-1 alert
      with a fresh `rule_id`, so `handle_line` still routes to `process_new_alert()`, which is
      where `insert_quarantine_row()` now lives. The test's expectation ("watcher created a
      quarantine") remains correct; only the caller-supplied cache argument is obsolete.
    - [ ] **Safe to run meanwhile.** Dry-run by default (enrichment, ufw and email are
      monkeypatched); `--live` additionally requires root. It writes to the real `alerts.db`
      using `TEST_IP = 203.0.113.99` (RFC 5737) and cleans up after itself. Nobody has been
      touching the firewall by running it.
    - [ ] **Origin: `9ffac56`**, the core_module six-daemon relocation — so this rot predates all
      current work and is not a regression from anything landed on 2026-08-03.
    - [ ] Related nuisance, not a defect: unhandled exceptions in ANY repo test script trigger
      an Apport popup, because they run from `/opt/nemesis` as a normal user. Expect these
      during test work; they are cosmetic.

- [ ] **Watchdog alert emails are being sent but not arriving.** On 2026-07-31 the watchdog
  correctly detected the dashboard crash-loop within 86s and escalated by email four times
  (10:55:08, 10:57:15, 10:59:21, 11:05:28 — `[INFO] Sent alert email for dashboard` each time
  in `/var/log/nemesis/watchdog/watchdog.log`). None of them reached the operator. (A fifth
  restart attempt at 11:07:28 succeeded — `[INFO] Service 'dashboard' restarted successfully`
  — so correctly sent no email; verified directly against the log before filing this, not
  copied from the original count of five.)
    - [ ] **Detection and escalation are NOT the problem** — both worked exactly as designed.
      The failure is somewhere between the send call and the inbox.
    - [ ] **Just as likely an email-host or Proton-side issue as a Nemesis one.** Do not assume
      the fault is ours: the send path may be fine and the mail silently dropped, filtered, or
      rejected downstream. Establish which end before changing any code.
    - [ ] **`Sent alert email` is a weak instrument and should be treated as one.** It proves the
      send call returned without raising — not that SMTP accepted the message, and certainly not
      that it was delivered. A log line that cannot distinguish "queued" from "delivered" will
      report success through a total delivery outage, which is exactly what happened here. Worth
      capturing the SMTP response code / message-id at minimum.
    - [ ] **Consequence while unfixed:** every email-only alert path is effectively silent. The
      watchdog's service-down escalation is the one that matters most, because nothing else
      notices a dead service — it writes no `alerts` row, so the dashboard shows nothing either.
    - [ ] **Do this during the email system pass**, not standalone — it belongs with the "full
      email system review + real email antivirus protection" work already scoped for V2.0
      Phase B, where the SMTP path is being examined anyway.

- [ ] **Concurrent runs of the same archival job double-process — no single-run guard exists at
  any level.** Found by Window 3 while auditing the archive/coalesce consolidation (the
  `alert_manager/data_manager.py` + `core_module/hw_monitor/hw_monitor.py` merge). Pre-existing
  in both copies before the merge; the merge did not introduce it and does not fix it — it just
  means there is now one place to fix it instead of two.
    - [ ] **Same-second filename collision.** Both jobs derive their archive filename from a
      `%Y-%m-%d-%H%M%S` timestamp. Two concurrent runs of the *same* job compute the identical
      name, both pass the `os.path.exists()` guard (neither sees the other yet), and both write
      to the same `<name>.tmp` — one run's write silently clobbers the other's.
    - [ ] **The success report can be wrong, not just the file.** Measured directly in an
      isolated two-thread test against the same `.tmp` path: thread A reported success while
      thread B's content was what actually landed on disk. A caller can be told its archival
      run succeeded when its own data was the one discarded.
    - [ ] **SELECT and DELETE are not in one transaction.** Both concurrent runs of the same job
      select the same candidate rows, both archive them, both insert summary rows — producing
      duplicate summary buckets. Measured: 3 duplicate summary buckets from one deliberate
      concurrent double-invocation.
    - [ ] **No data is lost in any of the three failure modes** — rows are archived before any
      live-table modification, and SQLite keeps the database itself internally consistent
      throughout. The damage is duplicate summary rows and a misleading success return, not
      destroyed data.
    - [ ] **Exposure today is low, not zero: both jobs are currently manual-invoke-only**, so
      triggering this requires deliberately invoking the same job twice within the same second.
      **It becomes a real, live hazard the moment either job is scheduled** (cron/timer-driven),
      which is exactly the decision currently parked for both. Fix this before scheduling
      either, not after.
    - [ ] **Recommended fix:** a single-run guard — an `O_EXCL` lockfile or a `PRAGMA`-level
      advisory lock — so a second concurrent run of the same job fails fast instead of
      double-processing.
    - [ ] **Scope the fix at the Data Manager level, not per-job.** Now that the archive/verify
      primitives have exactly one home (the consolidation above), the guard belongs there too —
      a lock keyed per archival job (e.g. by the target table/filename prefix), not a bespoke
      lockfile reinvented separately in each of the two current callers. Matches the broader
      audit Window 3 is now running across the Data Manager, rather than a fix scoped to just
      the two jobs it happened to be found in.

- [ ] **PIA's policy-routing and IPv6 handling cause at least four unrelated-looking failures,
  and its rules survive disconnection.** Everything below shares one root cause. They were
  investigated separately and at length before the connection was made, so they are recorded
  together deliberately.
    - [ ] **1. Agent enrollment over the tailnet is blocked while PIA is up** — the original
      finding, detailed in the sub-entry below.
    - [ ] **2. IPv6 egress is blocked while PIA is CONNECTED — corrected 2026-08-03, this entry
      previously overstated it as blocked while disconnected too.** Directly measured against
      `diagnostics_connectivity_samples`: `DEGRADED / ipv6 keytest failed` continuously through
      2026-08-03 15:05:23, then a clean, complete flip to `ALL_OK` at 15:06:29 with **zero**
      renewed IPv6 failures across the following 10+ minutes of samples (checked minute-by-minute
      to confirm, not just spot-checked) — the same transition entry #4 below documents in full.
      There is no supporting data anywhere in that table for a sustained post-disconnect outage.
      **What IS independently confirmed to survive disconnection: the policy rules themselves,
      not their effect.** Re-checked live 2026-08-03: `ip rule show` still lists the
      `piavpnOnlyrt`/`piavpnrt`/`piavpnFwdrt` fwmark rules, and `ip route show table
      piavpnOnlyrt` still shows `blackhole default`, with no PIA tunnel interface present. So
      the June 6/26 lead (`docs/audits/project-status-2026-06-26.md`, itself hedged as "may be
      v6-routing-specific," never a confirmed finding) was right that the blackhole route
      persists — but persisting in the table is not the same as intercepting live traffic, and
      the one directly measured transition shows it did not. Do not restate the disconnected
      claim as settled without a fresh measurement showing an actual post-disconnect failure.
    - [ ] **3. A browser session against the dashboard fails transiently during teardown** —
      reported as "cannot reach server" in the Flask UI's idle-lock. NOT a dashboard fault:
      `dashboard.service` had not restarted (`ActiveEnterTimestamp` unchanged at 11:54:49), so
      a page reload was the only fix needed.
    - [ ] **4. The connectivity watcher reports a false `DEGRADED`** for as long as an
      IPv6-blocking VPN is connected — see
      `docs/audits/diagnostics-ipv6-keytest-false-degraded-2026-08-03.md`. That audit shows
      1,264 consecutive `DEGRADED / ipv6 keytest failed` samples flipping to `ALL_OK` at
      **15:06 on 2026-08-03, the minute PIA was stopped** — independent confirmation that PIA
      was the blocker, and a useful timestamped marker for the whole family.
    - [ ] **"Just turn the VPN off" is NOT a workaround.** Stopping PIA is not a clean no-op:
      the teardown itself caused #2 and #3. So the choice is not "VPN or enrollment" — both
      states break something, which is what makes the split-tunnel / allowed-CIDR fix the only
      real answer rather than a documented instruction to disable the VPN.
    - [ ] **Cross-reference:** the diagnostics false positive is filed separately (audit above)
      because it is a diagnostics defect rather than a connectivity one. Keep them linked —
      investigating either alone will rediscover the same PIA behaviour from scratch.

- [ ] **A VPN on the Nemesis host silently breaks agent enrollment over the tailnet.** Confirmed
  live 2026-08-03 with PIA (OpenVPN protocol, `allowlan=true`) running on the server: every
  agent install failed at the reachability check with "Cannot reach your security server.
  Tailscale is connected but the server is not responding." Stopping PIA fixed it immediately
  and completely — same VM, same tailnet, same ACL, nothing else changed.
    - [ ] **Mechanism.** The agent's SYN *does* arrive (`SYN-RECV` observed in the server's socket
      table), but the SYN-ACK never returns, so the handshake half-opens and the client times
      out. `ip route get <agent-tailnet-ip>` resolves correctly to `dev tailscale0 table 52`, so
      this is NOT a routing-table problem — it is PIA's policy rules / killswitch. PIA's
      `allowlan` covers only the LAN (`<lan-subnet>`); the tailnet is `100.64.0.0/10` and is
      therefore treated as non-local.
    - [ ] **Why it is hard to diagnose — three separate instruments lie about it:**
      - `tailscale ping` SUCCEEDS (1ms pong). It is a control-plane/disco probe and does not
        traverse the data path, so it proves nothing about whether real traffic flows.
      - The nginx access log shows NOTHING, because nginx logs *completed* requests; a half-open
        handshake never reaches the log. Absence there is not absence of traffic.
      - `ufw` logs no BLOCK, and the tailnet peer shows healthy/online on both sides.
      The only honest signals are `SYN-RECV` in `ss -tan` and a plain TCP port test.
    - [ ] **Cost when undiagnosed:** this consumed most of an afternoon and sent the operator to
      the Tailscale admin console twice to add an ACL grant that was never the problem. The
      symptom points squarely at tailnet ACLs and nothing on the server logs a thing.
    - [ ] **Product impact — this is not a lab quirk.** The appliance is expected to run behind a
      VPN *and* accept agent enrolments over the tailnet. With a VPN active those are currently
      mutually exclusive, it fails silently with no server-side log, and the user-facing message
      blames the server or the tailnet. Any customer running a VPN on their Nemesis box hits it.
    - [ ] **Likely fix (untested):** add the tailnet range to the VPN's allowed/split-tunnel
      networks rather than disabling the VPN. Needs verifying per-provider — PIA's `allowlan` is
      LAN-only and there may be no supported way to add an arbitrary CIDR, in which case the
      answer may be a documented deployment constraint plus a startup check that detects the
      condition and says so plainly instead of failing silently.
    - [ ] **Detection is the cheap win even before the fix:** the server can notice that a VPN
      tunnel is up and that inbound tailnet traffic is half-opening, and surface it. Silent
      failure is what made this expensive, not the incompatibility itself.

- [x] **Retrying a failed install could make Nemesis disown software it actually
  installed — FIXED same day (`edc6133`).** `_probe_preinstall_state()` ran at the top of
  `_run()`, but the Retry button re-enters `_run()` from the start. If the first attempt got
  far enough to install Tailscale (the pre-auth self-onboard path does) and then failed later
  — e.g. at the server reachability check — the second probe saw Tailscale already present
  and recorded it as pre-existing.
    - [x] **Confirmed live 2026-08-03.** After one retry, `install-manifest.json` contained
      `{"pre_existing": true, "installed_by_nemesis": false, "removal": "never"}` for Tailscale
      on a VM that had no Tailscale before the install started.
    - [x] **Consequence (pre-fix):** the uninstaller would have honoured the manifest and never
      offered to remove it, so uninstalling Nemesis would leave Tailscale installed AND a live
      node in the operator's tailnet, silently and permanently. The provenance logic is
      deliberately conservative ("never touch the user's own software") — which is right, but
      it meant a wrong reading failed in the direction of leaving things behind.
    - [x] **Fix, landed same day:** the probe is now idempotent across retries — a
      `_provenance_probed` flag on `InstallerApp` captures provenance ONCE per installer
      process (first entry to `_run()`) and reuses it on any re-entry, rather than
      re-probing on each attempt. Regression-covered:
      `nemesis_agent/test_provenance_retry.py` extracts `_probe_preinstall_state` verbatim
      via AST and exercises the exact retry-after-partial-install scenario. Reviewed and
      re-verified against live code 2026-08-04 (Window 2) before this entry was committed —
      the fix is real, not just claimed.
    - [x] **Residual gap this fix does NOT close — tracked separately, see the
      "Provenance should be recorded when a component is INSTALLED" entry below.** The cache
      is per-process by design, so a crash or manual close after installing Tailscale,
      followed by a relaunch, still re-probes fresh and hits the same wrong answer via a
      different trigger.

- [ ] **Uninstall leaves the agent running and some state behind.** After a successful uninstall
  on 2026-08-03, verified on the VM: `NemesisAgent.exe` was still running (and still polling the
  server from a now-deleted install path), and `%APPDATA%\Nemesis` still contained
  `nemesis_agent.conf` and `reputation.db` alongside `NemesisUninstall.exe`.
    - [ ] The uninstaller cannot delete itself while running, so its own presence is expected.
      The surviving `nemesis_agent.conf` (which carries device_id and enrollment state) and
      `reputation.db` are not.
    - [ ] **The running process is the more serious half.** It keeps sending heartbeats after the
      user believes the software is gone. Combined with the de-enroll behaviour below, a user who
      uninstalls can be left with an agent still reporting to a fleet they think they left.
    - [ ] Check against the clean-uninstall spec (Phase 3) — this may be a regression against a
      documented requirement rather than a new gap.
    - [ ] **Reviewed against live code 2026-08-04 (Window 2):** `_remove_components()`
      (`nemesis_agent/uninstaller_gui.py`) already calls `taskkill /F /IM NemesisAgent.exe` and
      schedules `rmdir /s /q` on the install dir (which would take `nemesis_agent.conf` and
      `reputation.db` with it — both live in the same `%APPDATA%\Nemesis` directory as
      `CONF`/`CACHE_PATH`). This logic has been in place since Phase 3 shipped
      (`14ce142`), unchanged since — so the 2026-08-03 live finding is a real behavioral gap
      (taskkill/rmdir not succeeding as intended), not a missing code path. Root cause (silent
      `taskkill` failure — wrong session/access, or a scheduled-task relaunch race between
      `taskkill` and the later `schtasks /Delete`) not yet diagnosed; entry left open as found.

- [ ] **A revoked device has no idea it was revoked, and neither does anyone reading its logs.**
  `hw_monitor` refuses an unapproved device by returning **HTTP 200** with
  `{"ok":false,"status":"not_approved"}`. The agent's `_post_payload()` only checks
  `r.status_code == 200`, so it logs `Posted payload to ...` and carries on indefinitely.
    - [ ] **Verified live 2026-08-03:** after a revoke at 15:48:02, the agent POSTed on schedule
      at 15:52:30 and logged success; the server correctly did not advance `agent_last_seen`.
      Enforcement worked perfectly — the *reporting* is what misleads.
    - [ ] **Server side is silent too:** the not-approved branch writes no log line at all, so
      nothing on the server records that a revoked device is still trying. During this
      investigation that produced a false negative — grepping hw-monitor's journal for
      rejections returns zero whether or not any occurred.
    - [ ] **Why it matters:** an operator revoking a suspected-stolen device gets no confirmation
      the device actually stopped, and the device's own logs claim it is still protected. Both
      halves read as "fine" while the truth is "cut off".
    - [ ] **Fix:** log the refusal server-side (rate-limited — a revoked agent will retry
      forever), and have the agent inspect the response body rather than only the status code,
      so it can report an explicit "revoked / not approved" state instead of a false success.
    - [ ] **Reviewed against live code 2026-08-04 (Window 2), confirmed exactly as described:**
      `core_module/hw_monitor/hw_monitor.py` sends `send_response(200)` with the
      `not_approved` body on the unapproved-device branch, no log line either side of it; the
      code's own inline comment even documents relying on this ("nemesis_agent checks
      `r.status_code == 200` and nothing else"); `nemesis_agent/agent.py:598`
      (`_post_payload`) checks only `r.status_code == 200`. Real, still-open gap, not stale.

- [ ] **Provenance should be recorded when a component is INSTALLED, not inferred at the end
  from a probe taken at the start.** The proper fix behind the retry bug (now FIXED, see the
  "Retrying a failed install" entry above) — mitigated there by caching the first probe per
  installer process, 2026-08-03.
    - [ ] **What the caching fix does not cover.** It is per-process by design — "was this here
      before THIS run?" is the honest scope, and persisting it to disk would create the mirror
      bug, refusing to remove software Nemesis installed because the user installed their own
      copy in between. So one hole remains: if the installer **crashes or is closed** after
      installing Tailscale and the user relaunches, the new process probes fresh, sees it, and
      records it as the user's. Same wrong answer, different trigger.
    - [ ] **The design change.** Write `install-manifest.json` incrementally: at the moment
      Tailscale (or PawnIO, or any future shared component) is actually installed, record
      `installed_by_nemesis: true` for it. Provenance then becomes an observation of what the
      installer DID, rather than an inference from what it SAW beforehand — which is the
      property that makes it survive retries, crashes and relaunches alike.
    - [ ] **Why it generalises.** Every shared component Nemesis installs inherits the same
      hazard, and each one currently needs its own `_x_pre_existing` flag threaded through
      `_run()`. An append-as-you-go manifest removes the whole class rather than patching
      per-component. PawnIO already has the identical bug for the identical reason.
    - [ ] **Cost:** the manifest is currently composed near the end of a successful install, so
      this means restructuring it to be written progressively and tolerate partial state — the
      uninstaller must already handle a manifest from an install that never finished.
    - [ ] **Reviewed 2026-08-04 (Window 2):** design item, no live-code claim to verify against
      — accurately describes the residual gap left by `edc6133`'s per-process cache. Still
      valid, still unbuilt.

- [ ] **A signed ruleset update can be rolled BACK to an older-but-genuine ruleset.**
  Content authenticity is now bound into the signed task envelope (`sha256` + `size` in
  `params`, verified by the agent before install — ADR 0004 Stage 1). That closes
  substitution: nobody can make an agent install bytes the server did not attest to.
  It does NOT close replay of a *previously valid* attestation.
    - [ ] **The gap.** Every enqueued `update_rules` task is a signed statement that
      "ruleset with digest D is current". Capture one, and within its TTL it can be
      re-presented to roll a device back to that older D — genuine bytes, genuine
      signature, stale content. The practical impact is losing recent detection rules,
      which is the same silent-blinding outcome the digest work exists to prevent, just
      reached by a different route.
    - [ ] **What already bounds it (so this is narrow, not open):** the envelope's
      `expires_at` limits the window, and the agent's atomic claim store (`task_claims/`)
      refuses a task_id it has already executed. A replay therefore needs a *different*
      unexecuted task within its TTL — not an arbitrary rewind to any past ruleset.
    - [ ] **The fix, deliberately deferred as separate scope:** a monotonic ruleset
      version carried in the signed params, with the agent refusing any version lower
      than the one it currently holds. Needs a version counter that survives ruleset
      regeneration (the digest alone cannot order two rulesets), which is why it is its
      own design item rather than a follow-on line in the digest commit.
    - [ ] **Not a regression** — pre-digest, this attack was strictly easier and did not
      need a captured task at all. Filed as a tracked residual, per the standing practice
      of naming a bounded weakness rather than letting it read as fully solved.

- [ ] **Archive files are written with inconsistent ownership.** `/var/lib/nemesis/archives/`
  currently holds one file owned by `root:nemesis-db` and one by `<user>:nemesis-db` — whichever
  account happened to run the archival job, since both are manual-invoke only today.
    - [ ] **Nothing is broken right now.** Both files are mode `0640` with group `nemesis-db`,
      and the directory is `2770` setgid, so the group is inherited correctly and every
      service account that needs to read them can. This is a consistency/latent issue, not a
      live access failure — filed so it is fixed before it becomes one.
    - [ ] **Why it matters later:** once these jobs are scheduled rather than hand-run, the
      owning account becomes whatever the timer/unit uses. A file written by an account whose
      primary group is not `nemesis-db` would land group-owned by that account instead, and
      the setgid bit on the directory is what is quietly saving this today. Archives can hold
      the ONLY surviving copy of data removed from a live table, so a read failure here is
      not recoverable by re-running anything.
    - [ ] **Fix direction:** decide the owning account as part of the archival-job scheduling
      decision (currently deferred alongside archive-integrity scheduling), and have
      `ensure_archive_dir()`'s sibling write path assert the expected owner/mode rather than
      relying on directory setgid inheritance to paper over it.

- [ ] **The connectivity watcher reports DEGRADED for as long as an IPv6-blocking VPN is
  connected.** Moved in from `docs/audits/diagnostics-ipv6-keytest-false-degraded-2026-08-03.md`
  now that this file is free (that doc was filed there only because PUNCHLIST.md was
  contended at the time — kept in place as the evidence record; this entry points at it
  rather than duplicating the analysis). `_probe()` in `modules/diagnostics/watcher.py` runs
  three curls against `api_host` — unforced, `-4`, and `-6` — and `classify()` returns
  `ALL_OK` only when all three succeed. A consumer VPN that blocks IPv6 as leak protection
  (correct, deliberate behaviour) therefore pins the verdict at `DEGRADED` with note
  `ipv6 keytest failed` for the entire time it is connected.
    - [ ] **Observed at least 60 hours continuous** (1,264 samples, 2026-08-01 03:12 →
      08-03 15:05); true duration unknown because the table is capped at 2,880 rows and the
      start had already aged out. Throughout, `routing_ok`/`dns_ok`/`egress_ok`/`api_ok`
      recorded zero failures — real connectivity was never affected.
    - [ ] **This is the expensive part:** a permanent DEGRADED badge is indistinguishable from
      a real one, so it hid a genuine 23-hour DNS outage (2026-08-01 10:19 → 08-02 09:22,
      root cause still unknown — see the separate audit). A warning state that is always on
      is not a warning state.
    - [ ] **Fix:** treat IPv6 as N/A rather than failed when no usable IPv6 path exists —
      check for a global IPv6 address and default route before counting `curl -6` as a
      keytest, and report `ipv6 unavailable` distinctly from `ipv6 keytest failed`. Cheap.
    - [ ] Full evidence, mechanism confirmation, and the honestly-labelled inference about
      VPN attribution: `docs/audits/diagnostics-ipv6-keytest-false-degraded-2026-08-03.md`.

- [ ] **`_dispatch_pending_scans` marks a `scan_queue` row `executing` before enqueuing the
  task, so a failed enqueue strands the row there permanently.**
  `core_module/hw_monitor/hw_monitor.py:2156` sets `status='executing'`; the `enqueue_task()`
  call that's supposed to actually deliver the scan happens afterward, at line 2184. If that
  call raises, the exception is caught and logged (`:2191-2197`) but the row is never rolled
  back — it sits at `executing` forever, with no scan actually running.
    - [ ] **Flagged by Window 1 during Step 5 (ADR 0004 Stage 1, loopback-push retirement,
      `67326d0`), not fixed there — deliberately out of scope for that commit.** Pre-Step-5,
      this was a live bug on every remote-device dispatch attempt, since the old direct POST
      to `http://{agent_ip}:5002` failed for every non-loopback device (the listener only
      ever binds `127.0.0.1`) — see the loopback-retirement work above. Step 5 replaced that
      unconditionally-failing push with `enqueue_task()`, which mostly succeeds, so the
      window in which this can strand a row narrowed from "every remote attempt" to
      "requires a DB write to fail." Narrowed, not closed.
    - [ ] **Fix:** reorder — call `enqueue_task()` first, and only mark the `scan_queue` row
      `executing` once the task is confirmed queued. Deliberately not bundled into the Step 5
      commit, which was scoped to retiring the transport, not to this pre-existing
      ordering bug.

- [x] **Correcting the record: the "468/468" test-suite baseline quoted in 2026-08-03's
  handoff docs was wrong.** `docs/handoff/supplements/2026-08-03-001.md` and
  `docs/handoff/worklog/2026-08-03-001.md` both record Window 1 reporting "16 suites/468
  checks" during the Step 4 recovery that day. That number was a miscounted baseline, not a
  later-outdated one — Window 1 has since proven the real structural maximum for that
  pre-Step-5 tree was **465/465**, which matches Window 2's own independent 5-suite
  spot-check from the same session exactly (213 checks: `test_task_results.py` 55/55,
  `test_rules_integrity.py` 49/49, `test_key_rotation.py` 58/58, `test_task_dispatch.py`
  24/24, `test_task_envelope.py` 27/27).
    - [x] **Historical worklog/supplement text left unedited, per standing practice** (same
      as the PL-10 stale-text correction above) — Rule 9's worklog is a flight recorder, not
      rewritten after the fact. This entry is the correction pointer instead, so 468 stops
      propagating into future references.
    - [x] **Current baseline, post Step 5+6 (`67326d0`, 2026-08-04):** 498/498 checks across
      18 suites — 465 plus the two new suites added by the loopback-retirement work
      (`test_loopback_retirement.py`, 17/17) and the poll-hint work
      (`test_next_poll_hint.py`, 16/16). 465 + 17 + 16 = 498.
    - [x] **Going forward:** cite 465/465 (16 suites) for anything describing the tree as it
      stood before Step 5, and 498/498 (18 suites) for current state. Neither is 468.

- [x] **`community_queue`'s batch AI analysis has no in-flight dedup — the same defect class
  **RESOLVED 2026-08-04 (`d7851df`).** Both halves shipped: `job_id=f"cq:{domain_or_ip}"`
  engages `ai_engine`'s in-flight dedup, AND `_analyse_one()` returns `ran: False` on any
  not-ok result which `_api_analyse` honours by skipping the write and leaving
  `ai_reviewed=0`, so the row is retried instead of being marked reviewed with no
  analysis behind it. Code-verified 2026-08-05 (caller checked, not just the docstring's
  claim). **Follow-on fixed 2026-08-05:** the backend returned a `skipped` count that the
  UI dropped, so a deduped second click reported "0 item(s) reviewed" and said nothing
  about the rows it had skipped — the dedup worked but looked like nothing happened.
  the concurrency emergency fixed on `analyze_alert`, still live.** `_analyse_one()`
  (`modules/community_queue/module.py:190-195`) calls `ai_analyze()` with `cache_key` and
  `cache_hours` but **no `job_id`**, so `ai_engine`'s in-flight dedup never engages. The
  sibling path does pass one — `dashboard.py:3979`, `job_id=f"alert_{rule_id}"` — added
  precisely because two concurrent requests for the same uncached item each made, and were
  each **billed for**, a separate Claude call. Found during the 2026-08-04 AI interaction
  audit (`docs/audits/ai-interaction-audit-2026-08-04.md` §2).
    - [ ] **Worse here than on the alert path, because this one is a batch.** "Analyse Queue"
      (`_api_analyse`, `module.py:573`) loops every unreviewed row and calls `_analyse_one()`
      per row. Two concurrent clicks bill a full duplicate batch, not a single duplicate
      call — the cost multiplies by the queue length. The button is disabled client-side
      during the request (`module.py:511-525`), but that is a UI courtesy, not a guard: two
      browser tabs, a page reload mid-request, or any direct POST bypasses it entirely.
    - [ ] **NOT a one-line fix — adding `job_id` alone would trade double-billing for
      silently-lost work.** `_analyse_one()` collapses *every* not-ok result to
      `{"confidence": "uncertain", "assessment": "AI analysis unavailable — review
      manually."}` (`module.py:196-198`), and the caller writes that straight through with
      **`ai_reviewed=1`** (`module.py:598-602`). A dedup rejection is a not-ok result, so the
      second concurrent batch would mark rows reviewed with no analysis behind them — and
      because the row selector is `WHERE submitted=0 AND ai_reviewed=0` (`module.py:585`),
      those rows are then **never picked up again**. That converts a visible double-charge
      into an invisible gap in the queue, which is the worse failure.
    - [ ] **So the fix is two parts:** (1) pass a per-row `job_id` (e.g. keyed on
      `domain_or_ip`, mirroring the alert path's per-`rule_id` granularity), and (2) have the
      caller skip the `UPDATE` when the analysis did not actually run, rather than persisting
      the fallback text as a completed review. Part 2 is the load-bearing half — it needs
      `_analyse_one()` to distinguish "AI ran and was unsure" from "AI never ran", which it
      currently cannot, since both return the same dict.
    - [ ] **Same shape as the standing "a failed read must surface as an explicit failure
      state, never as a default value" rule** — the `uncertain`/"unavailable" pair is a
      default that reads as a real verdict to everything downstream, including the sort order
      in `_api_rows()` that ranks by `ai_confidence`.
    - [ ] Worth doing **before** any work that increases AI call volume (see the four items
      scoped in `docs/roadmap/ai-interaction-scoping-2026-08-04.md`); the contextual-chat item
      in particular adds uncached, user-triggered calls.

- [ ] **[FIX-NOW] `scan_conditions` seed only backfills on an EMPTY table, so later condition
  types never reach existing installs.** `init_db()` seeds the five default scan conditions
  **only** when the table is empty (`if c.execute("SELECT COUNT(*) FROM scan_conditions")
  .fetchone()[0] == 0`). Correct for a fresh install, silently wrong for every existing one: a
  condition type added to the `defaults` list after a database already has rows is never
  inserted, so the trigger it represents simply never fires there.
    - [ ] **Live, not hypothetical — confirmed against this box's own DB (2026-08-04):** the
      table holds three of the five (`first_connect`, `return_from_remote`,
      `extended_absence`). `new_login` and `usb_inserted` are absent, so those two scan
      triggers have never fired on this machine. Nothing looks broken: no error, no warning,
      the feature appears present in the code.
    - [ ] **Backfill missing condition types instead of all-or-nothing seeding.** Insert any
      default whose `condition_type` is absent, rather than skipping the whole seed when the
      table is non-empty. Same shape as the guarded `PRAGMA table_info` + `ALTER TABLE`
      column migrations already used elsewhere in `init_db()` — per-item presence check, not
      a single table-level one.
    - [ ] **Do not resurrect deliberately disabled rows.** A condition an operator switched
      off has `enabled=0` and still exists; only genuinely ABSENT types should be inserted, or
      the backfill will undo an operator decision every restart.
    - [ ] **Check for the same shape elsewhere.** Any other "seed if empty" block has the same
      defect by construction. Worth a grep for `COUNT(*)` + seed patterns while in here.
    - [ ] Found by Window 1, 2026-08-04, while investigating mandatory-scan triggers for the
      trust-boundary work. Verified against live code and live DB state by Window 2 before
      this entry was committed.

- [ ] **[SECURITY — READ BEFORE STARTING the malware/zero-day + memory-injection work] Agent-side
  integrity attestation: two evasion paths nothing currently detects.** The trust-boundary work
  (2026-08-04) closed the revoke→reinstate scan gap and now forces a scan whenever a device is
  readmitted from `revoked`, `uninstalled`, or `rejected`. **Two adjacent evasion paths are NOT
  closed by that work, and cannot be closed by any staleness or enrollment mechanism**, because
  neither crosses a trust boundary or ages anything. Both confirmed by reading the code, not
  inferred.
    - [ ] **(a) The stopped-agent path.** Stop the agent process, act on the machine, restart
      it. No uninstall, no re-enrollment: `ensure_enrolled()`
      (`nemesis_agent/enrollment.py:484`) returns immediately when the stored `device_id` is
      already `approved`, so `pre_enrollment_scan()` — which only runs inside `enroll()` — never
      executes. The server-side `first_connect` trigger tests `prev is None`
      (`hw_monitor.py:1739`) and the `agent_devices` row still exists, so it does not fire
      either. The only remaining trigger is `extended_absence`, whose live threshold is 24h
      (`hw_monitor.py:475`). **Stopping the agent for under 24 hours therefore evades every
      scan trigger that exists.** Strictly easier than uninstalling.
    - [ ] **(b) The selective file-replacement path — worse, and the ranking is
      counter-intuitive.** Keep `nemesis_agent.conf` and `keys/`, replace the agent's own code.
      Identity and signing keys are intact, so heartbeats authenticate normally and the server
      sees a healthy approved device. Nothing triggers. An attacker who neuters
      `scanner.trigger_scan` gets an agent that reports `ok: true` with no findings for every
      scan task it is given — turning the already-documented "task results are attested claims,
      not ground truth" limitation into an active bypass rather than a stated caveat.
    - [ ] **There is no agent self-integrity check of any kind.** Every sha256/integrity
      mechanism in the agent covers the server trust anchor, the heartbeat body, rules content,
      or key rotation — confirmed by grepping specifically for code validating the agent's own
      files. Nothing does.
    - [ ] **The uncomfortable consequence:** a full uninstall-and-reinstall is the ONE tampering
      path that reliably triggers a fresh scan (new `device_id` → new row → `first_connect` + a
      real pre-enrollment scan). Every more surgical, more sophisticated tampering preserves
      identity and triggers nothing. The protection is currently strongest against the least
      careful attacker.
    - [ ] **Decide the mechanism.** Agent-side integrity attestation is a new capability, not a
      patch: signed manifest of agent files verified at start and periodically, reported in the
      heartbeat, with the server treating a missing or failed attestation as an explicit state
      rather than as "healthy". A self-report from a compromised agent is worth exactly what a
      compromised agent says it is worth — the design has to state plainly what it does and does
      not establish, rather than implying more.
    - [ ] **Sequence it against the memory-injection work deliberately.** That work shares the
      same threat model and the same trust assumption about the agent's own code, and will
      inherit this gap wholesale if it is built first. **This entry exists specifically so that
      does not happen by omission.**
    - [ ] **Related, cheaper, and worth doing regardless:** the TOFU fingerprint match at
      enrollment is computed and then only logged (`hw_monitor.py:2985`, "informational; the
      match NEVER blocks enrollment — degrade-visibly principle, ADR 0011"). That is currently
      what makes reinstall-as-new-device safe. It is safe by accident, not by design — if anyone
      later "improves" enrollment to recognise returning devices via that match, the reinstall
      path silently becomes an evasion too. Worth a test pinning the current behaviour so the
      change cannot be made unknowingly.
    - [ ] Found by Window 1, 2026-08-04, during the trust-boundary investigation. Verified
      against live code by Window 2 before this entry was committed
      (`ensure_enrolled`/`enroll`/`pre_enrollment_scan` in `nemesis_agent/enrollment.py`;
      `first_connect`/`extended_absence`/TOFU-fingerprint in `hw_monitor.py`).

- [x] **[FIX-NOW] `parse_alert` stores the wrong field as `rule_name` — FIXED 2026-08-04
  (`53bf7ed`). Historical rows NOT backfilled — see the open decision below.** `parse_alert()`
  (`alert_manager/firewall.py`) split a Suricata `fast.log` line on `[**]` and took
  **`parts[2]`** as the rule name. In that format the rule name is in **`parts[1]`**; `parts[2]`
  is the Classification/Priority block. The result was that `alerts.rule_name` held
  classification text going forward, and the actual rule name was discarded entirely.
    - [x] **Confirmed against a real Suricata line, not a synthetic one:**
      ```
      input : ... [**] [1:2001219:20] ET SCAN Potential SSH Scan [**] [Classification: Attempted
              Information Leak] [Priority: 2] {TCP} ...
      stored: rule_name = '[Classification: Attempted Information Leak] [Priority: 2] {'
      lost  : 'ET SCAN Potential SSH Scan'
      ```
    - [x] **Why it stayed invisible:** the stored value was plausible-looking text of about
      the right length, truncated to 50 chars by `insert_alert`'s `rule_name[:50]`
      (`core_module/alert_watcher/alert_watcher.py:138`, called from `process_new_alert`).
      Nothing errored, nothing was empty, and `classification` was populated correctly in its own
      column — so a reader saw a populated field and no reason to doubt it. This was the
      "instrument reporting a wrong answer confidently" shape rather than a visible failure.
    - [x] **Blast radius was wider than the column.** `alert_watcher.py` renders `Rule:
      {rule_name}` into the alert email (`core_module/alert_watcher/alert_watcher.py:203`), so
      that string went out to operators. Any UI, export, or triage view reading `rule_name`
      showed the same. It was also duplicative — the classification was already captured
      correctly elsewhere, so the field cost storage while carrying no unique information.
    - [x] **Fix landed (`53bf7ed`):** reads `parts[1]`, strips the leading `[gid:sid:rev]`
      bracket via a single split (a rule message may legitimately contain further brackets,
      which now correctly stay part of the name). 18/18 checks in the new
      `alert_manager/test_parse_alert.py`, confirmed against the real captured line above, not
      just a hand-built one.
    - [ ] **OPEN DECISION FOR PAUL — NOT MADE, NOT ACTED ON.** Existing `alerts` rows written
      before `53bf7ed` still hold classification text in `rule_name` from the pre-fix code —
      this is historical data, deliberately untouched by the fix commit. A migration could strip
      the prefix on old rows, or they could be left as-is with the fix applied forward-only only
      — but the choice belongs to Paul, since a mixed column silently means two different things
      depending on row age, and no backfill has been performed or scheduled without his explicit
      direction. Do not act on this without that direction.
    - [x] **Other extracted fields checked against the same line shape while fixing this.**
      `rule_id`, `classification`, `protocol`, and the src/dst parse all come from the same
      string-splitting block; `test_other_fields_unaffected` in the new test suite independently
      confirms all of them were already correct and remain so — the bug was isolated to
      `rule_name`, not a wider parsing defect.
    - [x] **Rule 11 label interaction confirmed, not just predicted.** `test_quarantine.py`'s
      label (`69ade29`), placed in BOTH the rule-name segment and the Classification specifically
      to survive this fix, is unbroken by it — the fix changes which of the two placements is
      doing the work, exactly as anticipated when that label was written.
    - [x] Found by Window 1, 2026-08-04, while verifying the Rule 11 cleanup label actually
      reached the database — the label did not land where expected, and tracing why surfaced
      this. Verified against live code by Window 2 before this entry was committed (the
      `parts[2]`/`parts[1]` split reproduced directly against `firewall.py`'s `parse_alert`;
      the email-rendering and truncation citations confirmed by grep).

- [ ] **Rename `_hour_of_week()` to `_hour_of_day()` — the name has been wrong since
  2026-06-20 and has now cost real time.** `modules/anomaly_detection/module.py:1268` returns
  `dt.hour` (24 buckets, 0-23). It genuinely was hour-of-week (`dt.weekday() * 24 + dt.hour`,
  168 buckets) until `e0c4c9a`, which narrowed it deliberately and said so: 168 slots needed
  five weeks to reach `MIN_BASELINE_OBS=5`, making the 7-day baseline useless. That commit
  explicitly kept the old name "for the call sites".
    - [ ] **Not a behaviour change — the behaviour is correct and evidence-backed.** `e0c4c9a`
      recorded the measured payoff: 118 of 680 network domains correctly classified as known
      after baseline, versus effectively zero at 168 slots. Confirmed still true 2026-08-04:
      24/24 buckets covered, `obs_count` avg 6.8 across 9,667 rows / 1,234 metric keys.
    - [ ] **Scope: function name + docstring only.** The `anomaly_baseline.hour_of_week` COLUMN
      keeps its name — renaming it is a migration on a 9,667-row table for zero functional gain,
      and the column is referenced in several queries. A comment on the column DDL pointing at
      the function is enough.
    - [ ] **Why it is worth doing at all:** the name misled the 2026-08-04 AI-autonomy scoping
      into designing item 4's readiness gate around "168 buckets covered", a criterion that can
      never be met. That went into a design document before measurement caught it. A name that
      only the docstring contradicts will mislead the next reader the same way.

- [ ] **Revisit weekday/weekend separation in the anomaly baseline — the question `e0c4c9a`
  explicitly deferred.** That commit ended "Weekly periodicity can be revisited once the
  baseline design is stable." It is now stable: 9,667 rows, 1,234 metric keys, ~6.8 observations
  per bucket.
    - [ ] **What the current design cannot see.** With 24 hour-of-day buckets, Sunday 03:00 and
      Wednesday 03:00 are the same bucket. A domain queried only during weekday working hours
      looks equally normal at 3am on a Sunday, because weekday and weekend traffic are averaged
      together. On a home or small-business network that distinction is real signal.
    - [ ] **A hybrid is the obvious middle.** 24 hour-of-day slots plus a weekday/weekend flag =
      48 buckets: most of the discrimination at 2x the data cost rather than 7x. That keeps the
      saturation property `e0c4c9a` was protecting (a weekday bucket still gets ~5 observations
      per week) while restoring the weekend/weeknight distinction.
    - [ ] **Not urgent, and explicitly not a bug** — the current behaviour was chosen on measured
      evidence and works as intended. This is a deferred design question with the data now
      available to answer it, filed so it stops living only in a commit message.

- [ ] **Malware file quarantine has no restore/undo function.** `_quarantine_file()` in
  `modules/malware_detection/module.py` moves a file to `quarantine_dir` and `chmod 000`s it;
  no `restore_from_quarantine()` or equivalent exists anywhere in the module. Reversing a
  quarantine today means a human manually moving the file back and re-chmod'ing it outside the
  product — not a supported action.
    - [ ] **Not a live incident** — quarantine is currently human-triggered only
      (`_api_finding_quarantine`), so a wrong quarantine is at least a deliberate human call, not
      an autonomous one.
    - [ ] **Why it matters now:** it's a named prerequisite in the AI graduated-authority scoping
      (`known-limitations/ai-interaction-scoping-2026-08-04.md`, Part IV §17, private mirror) —
      that design caps any action class without a real undo at L1 (Recommend-only) permanently,
      and malware quarantine is the one class in the product that currently fails this, hard-
      blocking it from ever reaching L2 regardless of track record. Confirmed directly in the now-
      shipped `effective_ceiling()` (`modules/ai_engine/module.py`): `malware_file_quarantine` is
      pinned at `L1_RECOMMEND` in `ACTION_CLASS_CEILINGS` for exactly this reason, and the code
      comment there states it cannot be raised by any amount of track record until a restore
      function exists.
    - [ ] **Fix:** a `restore_from_quarantine(finding_id)` that reverses both steps (`shutil.move`
      back to the original path, restore original mode, flip `status` back) and is exercised by a
      test — same shape as `ufw_delete` being the ufw side's proven inverse of `ufw_deny_append`.
    - [ ] Found by Window 3, 2026-08-04, during the graduated-authority-model scoping pass, while
      grepping `malware_detection/module.py` for a restore function to ground the action-class
      table in real code. Verified against live code by Window 2 before this entry was committed
      (`_quarantine_file`'s `shutil.move`/`chmod 0o000`, absence of any restore function, the
      `_api_finding_quarantine` route, and the `ACTION_CLASS_CEILINGS` pin all confirmed directly).

- [ ] **`_network_connections()` reports no UDP at all.** `nemesis_agent/modules/security.py:54`
  skips any socket whose status is not `ESTABLISHED`. UDP sockets never have an `ESTABLISHED`
  state, so this filter excludes every UDP connection from the agent's connection reporting,
  unconditionally.
    - [ ] **Impact beyond the UDP/gaming policy work: UDP-based C2 is invisible to the agent's
      connection reporting today.** This is a malware-detection gap independent of anything else
      in the UDP-policy scoping — it exists regardless of whether default-deny or Game Mode ever
      ship.
    - [ ] **Also capped at 50 entries** — worth revisiting at the same time as the UDP fix rather
      than as a separate pass.
    - [ ] **Fix shape:** report UDP sockets explicitly rather than filtering on a TCP-only state.
      Verify with a control that a known UDP flow actually appears in the report — an empty
      result must not be mistaken for "no UDP traffic," the same "instrument that can only
      produce one answer" trap this codebase keeps finding.
    - [ ] Part of the technique-independent observation-layer foundation
      (`docs/roadmap/agent-rebuild-config-driven.md`). Found and verified by Window 1, 2026-08-04,
      confirmed directly against `security.py:54` (`if c.status != "ESTABLISHED": continue`)
      before this entry was committed.

- [ ] **`_top_processes()` is a top-10-by-CPU sample, not process enumeration.**
  `nemesis_agent/modules/security.py:34-47` sorts running processes by CPU usage and slices
  `[:10]` — it never looks at the rest.
    - [ ] **Impact:** it cannot support process-launch detection (a quiet process simply never
      appears in a CPU-sorted top-10), and it is insufficient for the planned memory-injection
      work, which needs full enumeration as step zero. A low-CPU malicious process — exactly the
      kind an attacker who cares about staying unnoticed would run — is the case this sampling
      approach never surfaces.
    - [ ] **Fix shape:** full enumeration, with the top-N view retained as a *presentation*
      concern (what the dashboard shows by default) rather than a *collection* one (what the
      agent actually observes).
    - [ ] Part of the technique-independent observation-layer foundation
      (`docs/roadmap/agent-rebuild-config-driven.md`) and a named blocker for
      `memory-injection-detection-design.md`. Found and verified by Window 1, 2026-08-04,
      confirmed directly against `security.py:34-47` (the `sorted(...)[:10]` slice) before this
      entry was committed.

- [x] **`_detect_connection_type()` is IPv4-only — FIXED 2026-08-05 (`41ba66f`).** `nemesis_agent/agent.py:211-212` collected
  local addresses filtering on `addr.family == socket.AF_INET`, so IPv6 addresses were never
  considered when deciding whether a device is local or remote.
    - [x] **Impact (resolved):** a device with only IPv6 on the local link was classified as remote.
      The function failed toward the more restrictive classification (`vpn_remote`), so this was a
      **misclassification, not an open door** — but it was the same IPv4-only-assumption class
      already found and fixed once in the Tier 2 TLS gate. `41ba66f` widens the sweep to
      `AF_INET`/`AF_INET6` both.
    - [x] **Secondary observation, fixed alongside the IPv6 gap:** the function's `except`
      path still returns the shared `vpn_remote` fallback (`agent.py`) rather than an explicit
      failure state — kept deliberately (Paul's call; sentinel work is a separate, unopened
      future item, see below). What changed: the failure path now logs at **WARNING**, not
      DEBUG, and the docstring documents the shared-fallback tradeoff explicitly instead of
      leaving it undocumented.
    - [x] **Two more defects found during the fix, not in this entry originally:** the
      per-address parse sat inside a loop-wide `try/except`, so one unparseable address (e.g. a
      scope-suffixed IPv6 link-local like `fe80::1%eth0`) silently aborted the whole sweep — the
      guard moved inside the loop. A dead `hostname = socket.gethostname()` assignment was also
      removed.
    - [x] Part of the technique-independent observation-layer foundation
      (`docs/roadmap/agent-rebuild-config-driven.md`) — **step 4 of 5** in the operator-approved
      observation-layer foundation order. Found and verified by Window 1, 2026-08-04,
      confirmed directly against `agent.py:203-218` (both the `AF_INET`-only filter and the
      shared except/fallback path) before this entry was committed. **Fixed and verified by
      Window 1, 2026-08-05:** `nemesis_agent/test_connection_type.py` (new, 14/14 checks,
      mutation control reimplementing the pre-fix v4-only sweep to confirm it fails the v6 and
      bad-address-first cases); full agent suite reconciles to 621 (607 baseline + 14, no
      regressions); `alert_manager/test_attestation_e2e.py` still 22/22. `AGENT_VERSION` bumped
      `1.0.0` → `1.0.1` (`attest.py`) to reflect the changed digest set (55 → 58 files).
      Committed and pushed by Window 2, 2026-08-05 (`41ba66f`). **Sentinel/explicit-failure-state
      work for the three callers of `_detect_connection_type()` remains open, scoped out of this
      fix as a separate future change — not closed by this entry.**

- [ ] **`alert_manager/test_quarantine.py` has been RED for 8 days.** The quarantine confirm/lift
  routes were hardened to `methods=["POST"]` on 2026-07-28 (`8c8bce9`, "require POST for
  state-changing quarantine/action endpoints"), but the test still issues GETs against them —
  405s on confirm/lift, cascading to six dependent checks.
    - [ ] **Confirmed unrelated to the 2026-08-05 `data_manager`/`scan_tasks` namespace work:**
      zero references to `data_manager`, `scan_tasks`, or `namespace` anywhere in the test file.
      Its last touch (2026-08-04, `69ade29`) was a Rule 11 test-data-labelling pass, not a method
      fix — the file has been silently broken since the security hardening landed, not since
      anything done this week.
    - [ ] **The real gap this exposes:** an e2e suite went red the moment a security fix shipped
      and stayed red over a week without anyone noticing, because nothing runs `alert_manager`'s
      suites as a whole by default — only per-suite, which is why this surfaced only when Window 1
      swept the full directory today rather than running a targeted suite.
    - [ ] **Fix shape:** update the test's confirm/lift calls to POST, matching `8c8bce9`'s
      route change; re-verify the six cascaded checks pass once the method mismatch is corrected.
    - [ ] Found by Window 1, 2026-08-05, during the `data_manager`/`scan_tasks` namespace audit
      (unrelated investigation — the red suite was collateral discovery, not the target).

- [x] **Shared chat widget: duplicate `id="nemChatSection"` collides on the main dashboard page.**
  **RESOLVED 2026-08-05 (`dd32ccb`, deployed).** Render-once/relocate-everywhere: markup moved
  to a private `_chat_widget_markup()`, injected once by `get_chat_js()`, every surface
  relocates it via `nemChatAttach()`. NOTE: fixing this did NOT restore chat — a separate
  pre-existing `SyntaxError` (see the newline entry) was the actual cause of the reported
  symptom. Both had to land.
  `modules/ai_engine/module.py:1883` hardcodes `id="nemChatSection"`, and three surfaces each
  embed their own copy of that markup onto the SAME page (`/`): `dashboard.py:10693` (inside
  `#alertModal`), `modules/anomaly_detection/module.py:1458` via `_ai_modal_html()` (inside the
  `display:none` `#_adAIOverlay`), and `modules/malware_detection/module.py:3173`.
    - [ ] **Impact — the alert chat box is dead.** `document.getElementById()` returns the FIRST
      match, and module load order (`modules_loader.py:164`, alphabetical among non-required
      modules) puts anomaly_detection's copy first. So `viewAlert()`'s `nemChatInit("alert", ...)`
      (`dashboard.py:11103`) sets `display:block` on a node nested inside `#_adAIOverlay`, whose
      own `display:none` the alert flow never touches — the widget "opens" behind a hidden
      ancestor. The alert modal itself is unaffected (unique ID); only the chat affordance is a
      no-op. This is the surface a user tries first.
    - [ ] **Anomaly-incident chat works only by coincidence** of that same load order, and
      **malware-finding chat breaks it destructively**: `nemChatAttach()` RELOCATES the node it
      finds into its own container, so using malware chat once moves anomaly_detection's widget
      out of its overlay for the rest of the page session. community_queue is unaffected — it
      renders on its own page (`/community-queue`), never sharing the DOM.
    - [ ] **Fix shape:** render the widget exactly ONCE per page and relocate it into place at
      every surface — i.e. `nemChatAttach()`'s existing approach applied consistently, rather
      than at one of four surfaces. Injecting the markup from `get_chat_js()` (already guarded by
      `window._nemChatJsLoaded`) makes single-instancing structural rather than a convention each
      surface has to remember.
    - [ ] Found by Window 3, 2026-08-05, investigating an operator report that chat was "not
      appearing to work." Confirmed by executing the render path directly (not by reading):
      `_ai_modal_html()` returns 3036 chars containing exactly one `id="nemChatSection"` at
      offset 595, nested inside the `#_adAIOverlay` opened at offset 6. Ruled out the obvious
      suspects first — no `/api/ai/chat` request ever reached the backend, no journal errors, and
      anchor registration did NOT fail.

- [x] **Chat runs adaptive thinking at `high` effort on every question.**
  **RESOLVED 2026-08-05 (`dd32ccb`, deployed).** `effort` threaded through `analyze()` and set
  to `medium` for the chat path only, against an allowlist (`effort` is a hard 400 on Sonnet 4.5
  / Haiku 4.5). Non-chat callers still send no `output_config` at all. Adaptive thinking left ON
  deliberately. Latency improvement is UNMEASURED — no chat call completed before the fix, so
  there is no baseline to compare against.
  `modules/ai_engine/module.py:2268` builds the API kwargs as
  `dict(model, max_tokens, messages)` (+ optional `system`) and sets neither `thinking` nor
  `output_config`.
    - [ ] **Impact:** on `claude-sonnet-5`, omitting `thinking` runs adaptive thinking and
      omitting `output_config` defaults effort to `high`. Every short chat follow-up therefore
      pays deep-reasoning latency and tokens. This is the same model-drift root cause as
      `d151dc3`: the code was written when `_ACTIVE_MODEL` was `claude-sonnet-4-6`, and `110239f`
      bumped it to `claude-sonnet-5` — that bump broke the response parse loudly and the latency
      quietly.
    - [ ] **Fix shape:** thread an explicit `effort` through `analyze()` → `_analyze_inner()` and
      set it for the chat path only; leave adaptive thinking ON (disabling it on the 5-series has
      two documented failure modes — tool calls emitted as plain text, and `<thinking>` tags
      leaking into output). **`effort` is model-gated** — it errors on Sonnet 4.5 / Haiku 4.5 —
      so it must be sent against an allowlist, not unconditionally.
    - [ ] Identified by Window 1, 2026-08-04 (evening handoff); model-gating constraint confirmed
      by Window 3, 2026-08-05 against the current API contract before the fix was written.

- [ ] **BACKLOG IDEA (not scoped, do not build): one-shot AI analysis panel on `/firewall-db`.**
  The full alert view now carries the contextual **chat** affordance (`dd32ccb`), but not the
  one-shot AI analysis panel the main dashboard's alert modal has via `/api/analyze/<rule_id>`.
    - [ ] **Why it's plausible:** `/firewall-db` lists ALL alerts including historical ones
      (20 rows today vs the main dashboard's active subset), so it is the natural surface for
      "explain this old alert to me." The route is already auth-gated and already keys on the
      same TEXT `rule_id` the analyze endpoint takes.
    - [ ] **Why it is NOT being built now:** operator explicitly descoped it (2026-08-05) —
      "hold the /firewall-db one-shot AI analysis panel — not scoped for this pass." To be
      folded into the work-order doc separately if it gets prioritised. Captured here per
      Rule 7 so it is not silently re-discovered or silently built.
    - [ ] **Cost caveat to settle first if it IS prioritised:** `/api/analyze/` is a billed
      call with a 24h cache, and putting it on a page that lists every historical alert makes
      it far easier to trigger many analyses in a row than the current active-only surface
      does. Decide the spend-gating story before wiring, not after.

- [x] **[DONE 2026-08-06] "Unpin" the chat widget into a movable, resizable panel.** Feature
  request, not a bug — the fixed-size embedded chat area (`#nemChatSection`) works well for
  some users but feels cramped for others. Shipped `1f75ae6`.
    - [x] **Shape actually built differs from the original proposal, deliberately.** This entry
      originally proposed a real `window.open()` popup. Built instead: the SAME DOM node floated
      via `position:fixed` in the same document (drag handle, `resize:both` + `ResizeObserver`,
      viewport-clamped, geometry persisted in `localStorage`). A real popup was evaluated and
      rejected at build time — `appendChild` cannot move a node between documents, and every
      control here is an inline `onclick` resolving against this document's globals, so a popup
      would turn each button into a silent no-op and `ensureWidget()`'s backstop would mint a
      second widget in the opener, recreating the duplicate-instance bug the single-instance
      design (`5330220`) exists to prevent. The float approach delivers the same user-facing
      value (bigger, user-positioned, user-resized) without crossing a document boundary.
    - [x] Requested by the operator, 2026-08-05. Built by Window 3, 2026-08-06.

- [ ] **`analyze_alert()`'s early-return gate reads `priority`, so the AI is never called
  for any alert.** `dashboard.py` — `SELECT * FROM alerts` column order is
  `0 id · 1 rule_id · 2 rule_name · 3 classification · 4 priority · 5 explanation ·
  6 risk_level · …`, but the gate is `if existing and existing[4]:` and the code treats
  index 4 as `explanation`. An off-by-one on two indices only; 2/7/8/10/11 are correct,
  which is why it went unnoticed.
    - [ ] **Impact (measured 2026-08-05):** `priority` is truthy on **20/20** rows, so the
      early return ALWAYS fires. `/api/analyze/<rule_id>` therefore never reaches the AI,
      `ai_cache` is never written for an alert (confirmed: 0 `alert_*` rows for any real
      alert), and the chat anchor's "Analysis already shown to the user" enrichment in
      `_anchor_load_alert` is consequently **dead** — it looks like a grounding source and
      contributes nothing. Only 1 of 20 rows has an `explanation` at all.
    - [ ] **DISPLAY HALF FIXED 2026-08-05** (same commit as this entry): the two display
      reads were the same off-by-one and are corrected — `"explanation": existing[5]` and
      `"risk_level": existing[6]`. That removes the literal **"Explanation: 2"** in the
      alert modal (it was rendering `priority`) and the **"Risk Level: UNKNOWN"** on an
      alert stored as `HIGH` (it was rendering the empty `explanation`).
    - [ ] **GATE DELIBERATELY LEFT WRONG — needs a COST decision, not a code decision.**
      Correcting `existing[4]` → `existing[5]` would start making **real billed AI calls**
      for every alert that currently returns instantly. Operator explicitly held this on
      2026-08-05 pending a separate spend decision. The reason is documented inline above
      the gate so it is not "tidied" by accident. Do not change it without that decision.
    - [ ] Found by Window 3, 2026-08-05, while answering whether the "Analyse this alert"
      pre-step matters for chat grounding. It does — but via `_HISTORY_TURNS=3`
      conversation replay, NOT via the cached-analysis path, which this bug had disabled.

- [ ] **`_anchor_load_incident()` reported every anomaly incident's device list as
  "unreadable".** `modules/anomaly_detection/module.py` — `devices_json` holds a list of
  **dicts** (`{ip, name, first_seen_ts, query_count}`), but the loader did
  `", ".join(json.loads(...))`, which raises `TypeError: expected str instance, dict found`.
  A bare `except` converted that into the literal string `"unreadable"`.
    - [ ] **Impact (measured 2026-08-05): 153 of 153 incidents — it had never once
      succeeded.** The anomaly chat was told `Devices involved (1): unreadable` while the
      same row contained `<device-name> (<lan-ip>)`. Operator had to identify the
      device by hand mid-conversation; the loader already had it and discarded it.
    - [ ] **FIXED 2026-08-05** (same commit as this entry): format the dicts as
      `name (ip)`, tolerate the plain-string shape the old code assumed, and `log.exception`
      on failure so the next shape change is visible instead of silently absorbed.
      Verified across all 153 incidents (153/153 now format; was 0/153), with a control
      confirming the old expression still raises on the same real data.
    - [ ] **The durable lesson:** `"unreadable"` reads like a DATA problem, so nobody
      suspected the reader. Third instance today of the same shape — a bare `except`
      turning a type error into a plausible-looking string that a caller cannot
      distinguish from a real answer. See also the two entries above.

- [x] **Chat input required clicking "Ask"; Enter did not submit.**
  `modules/ai_engine/module.py` — the shared chat widget's input is a `<textarea>`, so
  Enter inserted a newline and the only way to send a question was the button. Standard
  chat-input expectation is Enter-to-send.
    - [ ] **FIXED 2026-08-05** (same commit as this entry): `keydown` handler on the input —
      **Enter submits, Shift+Enter still inserts a newline.** Bound inside the one branch of
      `ensureWidget()` that creates the node, so it attaches exactly once however many times
      `ensureWidget()` runs (verified: a second call does not double-bind).
    - [ ] **Gated on the Ask button's own `disabled` flag** rather than re-deriving the
      conditions. That flag already means both "out of turns" (`meta()` sets it from
      `turns_left`) and "a request is in flight" (`nemChatAsk` disables it on entry), so
      Enter can never spend a turn the button itself would have refused, and cannot
      double-submit. Re-deriving those conditions would have been a second copy of a
      spend-gating rule — the thing the shared widget exists to avoid.
    - [ ] `isComposing` is checked so an Enter that commits an IME candidate (CJK input)
      does not fire a half-typed question.
    - [ ] Verified behaviourally against the *emitted* JS in node with a DOM stub: 11
      checks including Shift+Enter passthrough, the disabled-button no-op, a control
      proving re-enabling makes Enter work again (i.e. the guard is the live button state,
      not a one-way latch), and single-binding on repeat calls.
    - [ ] **Not done, deliberately:** no "(Enter to send)" hint added to the placeholder.
      The existing placeholder is already a full example sentence and the operator asked
      only for the behaviour. Worth considering separately if discoverability matters.

- [ ] **PUNCHLIST entries are being trusted at face value instead of code-verified, and four
  were stale in one day.** On 2026-08-05, four AI-related entries marked `[ ]` open were found
  already fixed: the duplicate-`id` collision and the `high`-effort chat bug (both shipped in
  `dd32ccb`), Enter-to-submit, and `community_queue`'s batch dedup (shipped in `d7851df` the
  previous day).
    - [ ] **The concrete cost:** during an AI-item survey the `community_queue` dedup was ranked
      *"the highest-value bug in the batch"* purely on the strength of its entry text, and was
      queued as the next piece of work. It had been fixed for a day. Reading the code first is
      what caught it; a fix would otherwise have been written for a bug that no longer existed,
      and the duplicate work would have looked like progress.
    - [ ] **Habit change:** before picking up ANY punchlist item as work, verify it against the
      current code — the entry describes the bug as it was when written, not as it is now. This
      mirrors the rule the morning roadmap audit already applies (`CLAUDE.md`: do not classify
      off each file's `Status:` header, because headers go stale on shipping). PUNCHLIST has the
      same failure mode and no equivalent guard.
    - [ ] **Why entries go stale:** a fix commit closes the code but nothing forces the entry to
      be updated, so the list drifts one-way toward over-reporting open work. Marking `[x]` at
      fix time is the cheap prevention; a periodic verify-and-close sweep is the cure.
    - [ ] Found by Window 3, 2026-08-05, while working the AI-related items as a batch.

- [ ] **`/api/analyze/<rule_id>` is a GET route that spends money.** `dashboard.py:4221`
  — `@app.route("/api/analyze/<rule_id>")` carries no `methods=`, so it defaults to GET.
  Pre-existing shape, not introduced by today's changes, and auth-gated (absent from
  `_AUTH_EXEMPT`) — but now more consequential than when it was written.
    - [ ] **Why it matters more today:** until `analyze_alert()`'s gate fix (`9521346`,
      2026-08-05) this route's early-return always fired, so hitting it never actually
      called the AI. The gate now works as designed, so every un-cached hit is a real
      billed call. A GET that spends money is CSRF-triggerable via a plain `<img>` tag
      under default SameSite=Lax cookies — the same pattern CLAUDE.md's route-level
      audit already names as a known-fixed-pattern regression class to watch for
      (`db_action`'s GET-as-write bug, fixed prior).
    - [ ] **Not urgent:** auth-gating limits this to an authenticated session, and the
      per-alert 24h cache bounds repeat-spend even under abuse. Worth a look eventually
      (methods=["POST"], matching the convention every other state-changing/spending
      route in this file already follows), not a fire drill.
    - [ ] Flagged by Window 1, 2026-08-05, while adding the `/firewall-db` Analyze link
      (`6358b5d`) — noticed in passing, not the target of that change.

- [x] **RESOLVED 2026-08-05 (Window 3) — `/api/analyze/<rule_id>` sends real
  source/destination IPs to an external AI model with no redaction.** Built as
  `alert_manager/nemesis_pseudonymize.py` (new module, not an extension of `redact.py`,
  per the scope boundary below) plus three `dashboard.py` integration points:
  pseudonymize after the empty-body 422 guard, resolve immediately on the reply before
  anything stores it, and the `/diagnostics` disclosure string updated to match.
  Tests: `alert_manager/test_pseudonymize.py`, 51/51; the pre-existing
  `test_analyze_alert_body.py` re-run for regression, 29/29.
    - [x] **Resolve-immediately, ephemeral per-call mapping, no persisted table**
      (operator decision). The reply fans out to four places — `alerts.explanation`,
      ai_engine's 24h `ai_cache`, the browser JSON, and `_anchor_load_alert()` feeding
      chat — so resolving once at the source means none of the four need to know tokens
      existed. Storing tokenized would have needed a persisted map plus every display
      path updated, for a benefit (cross-call token stability) only multi-turn chat needs.
    - [x] **Tokenize every address, no public/private branch** (operator decision). A LAN
      address identifies a device on this network and is exactly what is being protected.
      Also avoids a live test trap: Python classifies all three RFC 5737 TEST-NET blocks —
      this repo's own test-address convention — as `is_private`, so private-branching
      logic would have been silently skipped by its own fixtures and passed without ever
      executing. No branch, no trap.
    - [x] **Operates on the assembled body, not the `src_ip`/`dst_ip` columns.** The `raw`
      fallback path is a whole Suricata fast.log line with addresses inline rather than in
      fields, and `rule_name`/`classification` are free text that can carry one — column-level
      tokenizing would have left the caller-controlled path fully unprotected.
    - [x] **Both substring hazards handled by single-pass boundary-anchored regex, both
      tested:** outbound, `192.0.2.1` inside `192.0.2.10`; inbound, `host-A` inside
      `host-AA` (tested with 27 addresses to force the rollover). A replace-loop corrupts
      in both directions; one `re.sub` pass cannot.
    - [x] **Accepted tradeoff, documented not hidden:** a bare dotted quad that is really a
      version number is tokenized (fail-closed — over-tokenizing costs prompt fidelity,
      under-tokenizing leaks). The `v1.2.3.4` form is spared by the lookbehind, which is a
      partial mitigation and is labelled as one in both the code and the tests.
    - [ ] **CARRIED FORWARD, not fixed here — cache-hit token skew.** On an `ai_cache` hit
      the cached reply carries tokens from the original call, resolved against a map
      recomputed from today's row. The map is deterministic from the body, so an unchanged
      row resolves identically — but if `src_ip`/`dst_ip` changed since the reply was
      cached, `host-A` could resolve to a different address than it meant when written.
      Narrow (the gate early-returns once `explanation` is set, so this needs a cached
      reply with no stored explanation) but real, and silently wrong rather than visibly
      broken if it fires. Deliberately not solved inside an unrelated change.

- [ ] **Superseded detail from the original entry, kept for provenance.** Confirmed live: the prompt for
  rule 1000002 carried `{TCP} <internal-ip>:53779 -> <internal-ip>:53` verbatim, and the
  stored reply quoted both back. `diagnostics/redact.py` does NOT cover this and would not
  if wired in — it is a secrets scrubber (`_SECRET_KEYS` + values ≥8 chars from
  `nemesis.env`), confirmed to have zero IP/MAC/hostname handling. Window 1's own
  empty-prompt fix (`8f227a4`) widened this exposure on the deep-link path without
  checking it at the time.
    - [ ] **DECISION (operator, 2026-08-05): pseudonymize to stable `host-A`/`host-B`
      tokens.** Mapping stays local; the UI resolves tokens client-side so real addresses
      still display to the user. Preserves the relational reasoning that makes an analysis
      useful (rule 1000002's answer was good *because* it could say which host scanned
      which) while sending no real addresses externally.
    - [ ] **Scope boundary, explicit:** its own PII pass with its own tests — do NOT
      overload `redact.py`. A secrets scrubber and a PII pseudonymizer have different
      correctness conditions (one matches known key names/lengths, the other must
      recognize IPs/hosts it has never seen before); conflating them risks both jobs
      being done poorly.
    - [x] **Build was queued behind UDP work — since built, see the resolved entry above.**
    - [x] **Interim mitigation shipped separately:** `/diagnostics`'s redaction banner
      previously implied broader coverage than it has. Now carries an explicit "what this
      does not cover" disclosure at all three tier levels — rewritten 2026-08-05 to state
      that AI analysis IS now pseudonymized, and to disclose the separate AbuseIPDB/ipinfo
      exposure that pseudonymization does not touch (see the entry below).
    - [ ] Found by Window 1, 2026-08-05, while auditing malware-detection completeness;
      not the target of that investigation.

- [ ] **The alert-analysis path is NOT leak-free even with pseudonymization shipped —
  `enrich_ip()` sends the real source IP to two external services, and this is
  unfixable by pseudonymization.** `alert_manager/ip_enrichment.py:141-147` transmits the
  real `src_ip` to `api.abuseipdb.com` and `ipinfo.io` — on the *same* `/api/analyze/<rule_id>`
  route, *before* the AI call (`dashboard.py`, the `enrich_ip(src_ip)` calls near the top of
  `analyze_alert`). Tokenizing cannot help here: for a reputation lookup the address **is**
  the query, so a token would return a lookup of nothing.
    - [ ] **Why this entry exists separately from the resolved one above:** so nobody reads
      "AI prompt pseudonymization shipped" as "the alert path no longer sends real addresses
      off-box." It still does, by a different route, for a different reason. Two exposures,
      one fixed, one not.
    - [ ] **Must be a DISCLOSED exposure, not just an internal known-limitation**
      (operator, 2026-08-05). Partially done: the `/diagnostics` disclosure string now names
      AbuseIPDB and ipinfo.io explicitly at all three tier levels, and states the real source
      address is sent because those APIs require it to function. **Still open:** confirm
      `/diagnostics` is the right or only surface — anywhere the product describes its
      data-handling posture should say the same thing, and today only one place does.
    - [ ] **Make the transmission user-initiated, not automatic** (operator, 2026-08-05).
      Add a confirmation dialog with an explicit **"Report with real address"** button,
      shown wherever an external API genuinely requires a real address — abuse reporting
      and IP-reputation enrichment being the known cases. The user then chooses, per
      action, to send it, instead of it happening silently as a side effect of opening an
      alert. Design note: this needs a stated default for the un-chosen case (skip the
      lookup and show the alert without enrichment, rather than block the alert), and
      should not become a dialog the user learns to click through reflexively — worth
      pairing with a remembered per-service preference rather than prompting every time.
    - [ ] Found by Window 3, 2026-08-05, while auditing the analyze_alert prompt path for
      the pseudonymization build — not the target of that work, and specifically NOT fixed
      by it.

- [ ] **Layer D (local ML classifier) is declared in three places with zero
  implementation — an honesty gap, not a build gap.** `modules/malware_detection/module.py`
  — the module header comment (`D — local ML classifier (EMBER/PE, no API key)`, line 8),
  the `LAYERS` enumeration (`"ml"`, line 50), and a UI legend colour (`"ml": "#00d4ff"`,
  line 2956). Confirmed: zero EMBER references anywhere else in the module, no classifier
  code, no entry point.
    - [ ] **Why this is distinct from "Layer D is on the roadmap":** a roadmapped-but-absent
      feature is normal and fine. A feature that appears in the product's own layer
      enumeration and UI legend — the exact places a reader checks to learn what the
      product does — reads as present. That is actively misleading independent of whether
      Layer D is ever built, and does not require Layer D to exist to fix: the fix is
      dropping it from the enumeration and legend until it does.
    - [ ] **Fix shape (small, one-line-ish):** remove `"ml"` from `LAYERS` and its entry
      from the UI colour legend. Re-add both together when Layer D actually ships — not
      before.
    - [ ] **Distinct from the two related findings that do NOT need a fix, only accurate
      status:** Layer C (AI verdict) is deliberately evidence-only by design — the only
      `SELECT` of `ai_verdict` anywhere is its own test, and that is correct, not a bug.
      Quarantine has no restore path (`restore_from_quarantine()` does not exist anywhere
      in the repo) — a real gap, but pinned as a documented ceiling (L1, per
      `ai_engine/module.py:189-192`'s own comment: "missing-capability ceiling, not a
      threshold choice"), not something this entry asks to change.
    - [ ] Found by Window 1, 2026-08-05, verifying against code rather than memory whether
      malware detection could be called done. It cannot: Layer A+B is shippable and
      useful, but the four-layer description the product gives of itself is not accurate
      today.

- [ ] **ADR needed: does Nemesis get a static-policy nft table?** Piece K (the QUIC-specific
  block) has no home. The validated rule is nftables, but neither existing surface can take
  it: `ufw` would mean re-deriving byte-offset matching as an iptables `u32` expression and
  discarding the measurement, and ADR 0019's `nemesis_enforce` table forbids it outright —
  that table is DERIVED from ufw's live state and its single-authority constraint exists
  precisely to stop independent population. So a third surface is proposed, and per
  `CLAUDE.md`'s prohibition on ad-hoc `nft` outside the chokepoint, that needs deciding
  deliberately rather than by a commit.
    - [ ] **Operator decision already taken (2026-08-05):** separate static-policy table,
      distinct from both. **Rule 10 checked — public by default**: the architecture and the
      standards-track RFC 9001 detail are not new disclosure, and the public roadmap already
      describes the detection approach.
    - [ ] **Technical input for whoever authors it, so it is not re-derived:**
        - Keep the validated rule VERBATIM, do not re-derive:
          `udp dport 443 @th,64,8 & 0xc0 == 0xc0 @th,72,32 { 0x00000001, 0x6b3343cf }`
          (long-header form + fixed bit, then the version field). Measured **0/24 false
          positives** against real protocol shapes plus an adversarial near-miss crafted to
          defeat header-form matching alone.
        - **`reject with icmpx type port-unreachable`** — never `drop`, never `reject with
          icmp`. In an `inet` table nft silently adds `meta nfproto ipv4` to the latter, the
          rule then misses all IPv6 QUIC, and the counter sits at 0 while handshakes pass —
          which reads as "the mechanism does not work". `icmpx` is the only form covering
          both families.
        - `nemesis_enforce` occupies priority **-300** (input/forward) and **-175** (output).
          A new table must not collide.
        - The table will not survive a reboot — nft state is kernel-only. It needs a boot
          unit, the lesson `nemesis-fw-enforce.service` already paid for.
    - [ ] **Hook choice is the ADR's central decision.** The `forward` hook is the real
      feature; `output` only protects the appliance itself. **The gateway decision was taken
      2026-08-05 (Nemesis WILL become the gateway)**, so `forward` is now the correct target
      — but it matches nothing until that role is actually deployed (`ip_forward=0` and
      FORWARD chains at 0 packets on the current bridged-peer topology). An enforcement rule
      that has never matched a packet in production is indistinguishable from a broken one,
      so whatever ships must state plainly what it is and is not doing yet.
    - [ ] **Two caveats to carry into the ADR, both operator-confirmed:** QUIC v2
      (`0x6b3343cf`) is in the match set but was **never observed on the wire** — v1 is
      proven, v2 is not. And **Safari fallback is unverified** — the fleet has 14 VMs and
      zero macOS, and provisioning macOS virtualisation was judged not worth it for this
      alone. Firefox must be measured, not assumed.
    - [ ] Raised by Window 1, 2026-08-05. **ADRs are Window 2's to author** — this entry is
      the technical input, not the ADR. Next free number is 0022.

- [ ] **Agent check-in scheduling has NO jitter, so the fleet synchronises — and the cost is
  measured, not theoretical.** `nemesis_agent/agent.py` contains zero randomisation anywhere in
  its beat scheduling: no `random`, `jitter`, `uniform`, `randint` or `splay`. The interval chain
  (`_ramp_interval` → `_clamp_poll_hint` → `_effective_interval`) is fully deterministic, so
  given the same beat index and poll interval every agent computes the identical sleep and they
  never drift apart.
    - [ ] **Measured 2026-08-05 on the gauge VM** (Phase 4, DB write-path contention, 100
      simulated devices): 100 devices writing SIMULTANEOUSLY gave **p95 3140ms / max 3541ms**.
      The same 100 devices writing **1000x more often** but staggered gave **p95 105ms**. Thirty
      times better latency at a thousand times the load — because SQLite serialises writes, so
      simultaneous arrivals queue behind one another while spread-out arrivals find the lock free.
      **The worst case for this system is synchronised load, not sustained load.**
    - [ ] **The trigger is ordinary, not exotic:** a power cut, a switch reboot, or a mass agent
      restart starts every agent's clock at the same instant. With a deterministic interval they
      stay locked together indefinitely rather than drifting apart, so the herd persists.
    - [ ] **Fix is cheap and purely agent-side:** add a small random splay (a few percent of the
      interval) to the computed sleep. No protocol change, no server change, no coordination —
      each agent desynchronises itself. Worth doing independently of any hardware sizing.
    - [ ] **Scope of the measurement, stated so it is not overread:** Phase 4 drove the DATABASE
      WRITE PATH, not HTTP, enrollment or signature verification. It bounds DB contention; the
      full check-in cost per agent is higher and unmeasured.
    - [ ] Found by Window 1, 2026-08-05, while load-testing the gauge appliance VM. Verified
      against `agent.py` by direct search before filing — the absence of jitter is confirmed,
      not inferred from the measurement.

- [ ] **Dashboard alert list can read as empty on a noisy network while the severity cards
  report real counts — same root cause already fixed once, in only one of two consumers.**
  `get_active_alerts()` (`dashboard.py:2406-2428`) sources from `get_suricata_alerts()`
  (`dashboard.py:2207-2222`), which runs `tail -n 100 /var/log/suricata/fast.log`.
  `get_active_alerts()` then filters to today + Priority 1/2 only, drops `ignore`d rules,
  and caps the result at 10 (`active[:10]`, line 2425). On a busy network a burst of
  Priority-3 noise pushes every P1/P2 line out of that 100-line window before the P1/P2
  filter ever runs, so the list renders empty even though real high-priority alerts exist.
    - [ ] **The severity-card counters do NOT share this bug — it was already fixed there.**
      `get_alert_counts()` (`dashboard.py:2236-`), which feeds `alert_counts["p2"]` etc.,
      carries its own docstring recording this exact failure mode as already found and
      fixed: *"The previous version only sampled the last 100 lines, so a burst of P3 noise
      would push P1/P2 entries off the window and report counts as 0."* It now runs
      `tail -n 200000`. So the list and the counters read the same log through two
      different windows — one deep, one shallow — and can legitimately disagree: a real
      "534 High P2" card sitting directly above a list rendering nothing.
    - [ ] **Fix is a known pattern here already, not a new design.** Apply the same
      deep-tail approach `get_alert_counts()` already uses to `get_suricata_alerts()` (or
      have `get_active_alerts()` source from the same wide read `get_alert_counts()`
      performs, deduped against the existing 10-row display cap). The display cap of 10 is
      not the bug and should stay — the bug is the read window feeding it.
    - [ ] Found by Window 3, 2026-08-05, while testing alert chat against a visually-empty
      list sitting next to a populated severity card. Re-verified against live code
      2026-08-06 immediately before filing — line numbers and the already-fixed sibling
      function were confirmed today, not carried over from the prior session's memory.

- [ ] **`audit_log.ts` mixes ISO-`T` and space-separated timestamps, so string ordering
      does not match chronological ordering. This is ACTIVE, not theoretical — measured
      2026-08-06 against the live table.**
    - [ ] **Measured:** 175 rows — 140 ISO-`T` (`2026-08-05T09:15:52.075279`), 35
          space-separated (`2026-08-05 11:04:15`). Five distinct dates contain both.
    - [ ] **The defect made concrete:** on 2026-08-05, `SELECT ... ORDER BY ts` reports the
          day beginning at `11:04:15` with a firewall block. The day actually began at
          `09:15:52`. Space (0x20) sorts before `T` (0x54), so every space-separated row of
          a given day sorts ahead of every ISO-`T` row of that same day regardless of time.
    - [ ] **Worse, the two formats are not separate event streams — they are two halves of
          the same operator actions.** On 2026-07-31, `fw_deny_ip` (nemesis_fwd) at
          `11:19:48` and `block` (dashboard `_audit`) at `11:19:48.150060` are one action
          recorded by two writers 150ms apart. String ordering scatters the pair.
    - [ ] **Writers:** 3 of 4 use `datetime.now().isoformat()` — `dashboard.py:2534`
          (`_audit`), `core/manage.py:118`, and `alert_manager/degraded_ingest.py:291`
          (preserves the journal's own ISO-`T`). The single outlier is
          `alert_manager/nemesis_fwd.py:640`, `time.strftime("%Y-%m-%d %H:%M:%S")`.
          **ISO-`T` is the house norm and predates the outlier by a month** (earliest ISO-`T`
          row 2026-06-28; earliest space row 2026-07-28).
    - [ ] **Nothing currently orders `audit_log` by `ts`** — verified by grep; the only
          `ORDER BY ts` sites are on `diagnostics_connectivity_samples`. So this is a latent
          *consumer* bug on live-wrong *data*: the first person to write the obvious
          `ORDER BY ts DESC` for an audit-trail view gets a silently mis-ordered answer.
    - [ ] **Migration hazard to respect:** `degraded_ingest._is_duplicate()`
          (`degraded_ingest.py:190`) dedupes on exact `ts` string equality against the
          journal's value. Rewriting historical `ts` values would break that match, so a
          backfill and the ingest offset have to be considered together, not separately.
    - [ ] Full recommendation (normalize forward via a shared helper; fold in the
          timezone-awareness decision rather than touching the audit trail twice) delivered
          to the operator 2026-08-06 — decision is his, not filed as a chosen fix here.

- [x] **[DONE] `test_quarantine.py` was red for five weeks, and three of its checks were
      false passes.** Fixed 2026-08-06 (see the fix commit); entry is for the *lesson*, and
      to correct the record.
    - [x] **The reported cause was incomplete.** It was recorded as red for 8 days because
          the confirm/lift routes were hardened to `methods=["POST"]` on 2026-07-28
          (`8c8bce9`) while the test still issued GET. True, but only 8 of 14 failures. The
          other 6 date from the **auth gate landing 2026-06-28** (`21c8931`) — five weeks,
          not eight days. Every route the suite calls is absent from `_AUTH_EXEMPT`.
    - [x] **Fixing the method alone would have turned zero checks green** — an
          unauthenticated POST is still 302'd to `/login`, so `success=true` and both DB
          transitions stay red. Measured, not reasoned: both GET and POST return 302.
    - [x] **The false-pass, which is the durable part.** `http_get()` used
          `urllib.request.urlopen`, which **follows redirects by default**. The 302 to
          `/login` was chased, the login page came back 200, and
          `check("/api/quarantines status=200", status == 200)` PASSED on it — in all three
          scenarios. A green check whose only possible answer was green.
    - [x] **Six further checks were invisible rather than failing** — `dashboard ip=test_ip`
          and `minutes_remaining ~60` sat behind `if ours:`, so when the quarantine was not
          found they never ran at all: not passed, not failed, absent from the tally.
    - [ ] **Standing-practice hit, still open:** this is the "instrument that can only return
          one answer" class the repo already tracks, in a *test suite* — the thing that is
          supposed to catch it. Worth a grep pass for other uses of bare `urlopen` in test
          code, since redirect-following silently converts any auth failure into a 200.
    - [x] Found and fixed by Window 1, 2026-08-06.

- [ ] **Host-defence rules `sid:1000001`/`1000002` say "SYN sweep" but measure SYN RATE, with
      no port-diversity test — so a legitimate high-rate client of a service this box hosts
      trips them.** Investigated 2026-08-06; the standing "TCP SYN sweep" security finding
      against a LAN host turned out to be a false positive, and this rule shape is the cause.
    - [ ] **Measured:** every one of the 7,040 connections from the reporting host to this box
          went to **port 53 and no other port**. Port diversity — the defining property of a
          sweep — is entirely absent. The source is a known, `trusted=1` device in `devices`,
          and :53 is this box's own advertised service (`pihole-FTL` active, listening on
          `0.0.0.0:53`), which every LAN client is supposed to use. Correlating traffic is
          ~6,200 Discord DNS lookups across three ET INFO rules — ordinary chat-app behaviour.
    - [ ] **The rule logic:** `alert tcp any any -> $HOME_NET any; flow:to_server; flags:S,12;
          threshold: type both, track by_src, count 100, seconds 60`. A pure rate counter. The
          `msg` claims a behaviour the rule never tests for, so the alert text misdescribes
          what fired — which is what made this read as reconnaissance for a week.
    - [ ] **⚠ The real risk is the auto-quarantine adjacency.** The rule is `priority:1`, and
          the gate at `core_module/alert_watcher/alert_watcher.py:237` is
          `priority == 1 and threat == "CRITICAL"`. This scored MEDIUM so it did not fire
          (verified: zero quarantine rows for that IP). **The product's highest-volume false
          positive therefore sits one severity rung away from auto-firewalling a trusted
          household device off the LAN's DNS server** — which would present to a family member
          as "the internet is broken", with the cause buried in a firewall rule. Volume is
          rising: 10 → 60 → 91 hits/day over 08-03 → 08-05.
    - [ ] **Fix direction (not built — captured per Rule 7):** exclude this box's own listening
          service ports from the host-defence rules, and/or add a real port-diversity condition
          so "sweep" means what it says. Either is a rule-design change, not a threshold tweak.
    - [ ] Investigated by Window 1, 2026-08-06, read-only: rule text, `fast.log` port
          distribution (direction-checked), `devices`, `quarantines`, and the live listener set.

- [ ] **`install.sh` detects the network interface via the DEFAULT ROUTE, so on any box
      with a VPN default route it configures Suricata to monitor the VPN interface
      instead of the LAN.** Found 2026-08-06 while wiring host-defence rule deployment.
    - [ ] `install.sh:122` sets `DETECTED_IFACE` from `ip route get 8.8.8.8 | grep -oP
          'dev \K\S+'`, and `:129` sets `DETECTED_IP` from the `src` of the same route.
          `install_suricata()` then writes that interface into `suricata.yaml`'s
          `af-packet` section.
    - [ ] **Measured on the dev box:** internet routes leave via the tailnet interface
          (its own routing table), so that derivation returns the TAILNET interface and
          address — while Suricata is in fact monitoring the LAN interface, because that
          was corrected by hand at some point. A fresh install would not get that
          correction.
    - [ ] **Why it matters and why it is quiet:** Suricata bound to a VPN interface sees
          none of the LAN traffic the host-defence rules exist to detect. The install
          succeeds, the service runs, the dashboard looks healthy — and the box is blind
          to exactly the scans the rules were added for. Nothing reports an error.
    - [ ] **Fix direction (not built):** choose the interface by which one carries the
          LAN/`HOME_NET`-facing address, not by the default route; or prompt when the two
          disagree. `scripts/deploy-suricata-rules.sh` already contains the safer
          derivation (enumerate every non-loopback address, then cross-check against the
          interface Suricata is actually configured to monitor) — reuse that shape.
    - [ ] Deliberately NOT fixed alongside the rule work: one variable at a time, and this
          changes install-time behaviour for every user rather than a detection rule.

- [ ] **The host-defence rule NAMES claim a narrower scope than the rules actually watch.**
      Design-honesty item, filed 2026-08-06; not a defect in behaviour.
    - [ ] Every rule is titled "... against Nemesis host", but their destination is
          `$HOME_NET` — the whole LAN — so they fire on scans against ANY LAN device, not
          just this host. That mismatch is what made the self-scan false positive read as
          an attack for a week: alerts said "against Nemesis host" while describing this
          box scanning other devices.
    - [ ] **This is deliberate and was KEPT.** Narrowing the destination to the host itself
          was considered as the fix for the self-scan noise and rejected: it would silently
          drop lateral-movement coverage (one LAN device scanning another), which is real
          value the rules provide today by accident of their scope.
    - [ ] **What is owed is a naming/description decision, not a rule change** — either
          rename to reflect LAN-wide scope, or split into two rule families (host-targeted
          vs. LAN-wide) with distinct messages so an operator can tell which they are
          looking at from the alert text alone.
    - [ ] Related: the source-exclusion fix (2026-08-06) means these rules no longer fire
          on this host's own scanning, so the remaining alerts are genuinely third-party.

- [ ] **BACKLOG IDEA (documented, deliberately NOT built): "same device as X" manual merge,
      for when a device's randomised MAC makes it reappear as new.** Investigated
      2026-08-06; the automatic version was assessed and REJECTED on feasibility.
    - [ ] **Why automatic re-identification is not buildable reliably, measured not assumed:**
          reverse DNS resolves **1 of 41** LAN devices on the dev network, so the hostname
          signal that any such scheme would lean on is effectively absent. The Pi-hole lease
          API needs a token (401 unauthenticated) and the lease files are not readable, so
          even the authenticated path is unverified.
    - [ ] **The asymmetry that kills it:** devices which randomise MACs (phones, laptops) are
          the ones that do NOT advertise a stable hostname; devices with stable, meaningful
          names (printers, TVs, speakers, smart-home gear) generally do NOT randomise. The
          available signal and the actual problem barely overlap.
    - [ ] DHCP fingerprinting (Option 55/60) identifies a device CLASS or OS, never an
          individual device — useful for the category, useless for re-attaching a name.
          mDNS could catch some Apple devices but needs a listener this codebase does not
          have, and Apple has been reducing passive discoverability. Traffic/TLS
          fingerprinting is fragile and adversarial for a home product.
    - [ ] **And the point of principle:** MAC randomisation exists specifically to defeat
          this correlation. Anything that worked reliably would be a tracking mechanism.
    - [ ] Mitigating fact: iOS/Android randomised MACs are **stable per-SSID** by default,
          not per-connection. A device usually only reappears as "new" after forgetting/
          rejoining the network, a reset, or a privacy-setting toggle — rarer than it feels.
    - [ ] **If ever built, build the MANUAL version only:** an operator-driven "this is the
          same device as X" merge, requiring confirmation. A wrong auto-merge silently
          corrupts the inventory (a name lands on the wrong device, or two devices collapse
          into one) and is INVISIBLE; a wrong suggestion is visible and free to dismiss.
    - [ ] Operator decision 2026-08-06: do not build MAC-rotation persistence. The related
          real bug — the OUI vendor being stored in `friendly_name` and destroyed on rename —
          IS being fixed, via a persisted `vendor` column in the categorisation work.

- [x] **[CLOSED — NOT A BUG] AI chat popup reopening at its last size/position.** Reported
      2026-08-06, **retested by the operator the same day: the resize DID persist correctly.**
      The original report was against a stale/pre-deploy page. The existing implementation
      works as built; no work is owed. Kept rather than deleted because the source-read below
      documents how the persistence actually works, which is worth having written down.
    - [x] **Geometry persistence is fully implemented** in `modules/ai_engine/module.py`
          (the unpin/floating-panel work):
        - `FKEY="nemChatFloat"` in `localStorage`; `fstate()`/`fsave()` read/write it, both
          guarded so a corrupt value falls back to defaults instead of throwing.
        - **position** saved on drag — `st.left`/`st.top`.
        - **size** saved via a guarded **`ResizeObserver`** — the only way to notice a corner
          drag, since CSS `resize:both` fires no standard event.
        - **floating state** saved as `st.on` and read back on load:
          `if(fstate().on&&window.nemChatUnpin)window.nemChatUnpin();`
        - `fapply()` restores all four with defaults (`st.w||420`, `st.h||460`, etc.), then
          `fclamp()` keeps an off-screen panel reachable.
    - [ ] **WORTH KEEPING — `localStorage` is PER-ORIGIN, and this dashboard has several.**
          It is reachable via nginx on `:80` at the box's LAN address, the Flask port
          directly, and a tailnet address. Each is a separate localStorage bucket, so a panel
          sized at one origin legitimately reopens at defaults when the dashboard is opened
          at another — indistinguishable from broken persistence. Not the cause this time,
          but it WILL be the cause eventually, and it applies to every localStorage-backed
          preference the dashboard grows, not just this panel.
    - [x] **Process note worth more than the item:** the first report was tested against a
          stale page. Re-testing after the deploy is what resolved it. A UI bug report taken
          before the fix is live reads exactly like a real defect — confirm what build the
          page was actually serving before scoping any UI investigation.

- [ ] **Silent exception-swallow sites — retrofit to the error-code system, incrementally.**
      Filed 2026-08-06 (Window 1) alongside the `nemesis_errors` build. These are the
      `except ...: pass` sites where a failure produces no record anywhere — the exact shape
      the error-code system exists to replace, and a concrete instance of CLAUDE.md's
      standing "a failed read must surface as an explicit failure state, never as a default
      value" practice.
    - [ ] **Measured count: 149 sites across 40 files** (re-counted 2026-08-06 — an earlier
          in-session figure of "158" was wrong; this is the verified number). Detector: a
          line matching `except <anything>:` whose body is exactly `pass`, either same-line
          or on the following line.
    - [ ] **Zero are the same-line `except: pass` form, and zero use a truly bare `except:`.**
          Worth stating because it changes the remediation: this is not a codebase full of
          careless catch-alls. The breakdown is **96 broad `except Exception:`** and **53
          genuinely specific** (`OSError` 13, `ValueError` 8, `(TypeError, …)` 8,
          `FileNotFoundError` 7, `sqlite3.Error` 2, and a tail of others).
    - [ ] Concentration: `dashboard.py` 39, `nemesis_agent/installer_gui.py` 14,
          `core_module/hw_monitor/hw_monitor.py` 10, `nemesis_agent/uninstaller_gui.py` 9,
          `modules/malware_detection/module.py` 8, `alert_manager/nemesis_fwd.py` 6.
    - [ ] **NOT a mechanical sweep — do not script this.** A large share of the 53 specific
          handlers are legitimately-empty by design (optional-file reads, best-effort UI
          cleanup, `queue.Empty` polling, `KeyboardInterrupt` on shutdown). Converting those
          to recorded errors would generate noise and devalue the ledger. Each site needs a
          judgment call: is this failure something an operator would ever want to know
          happened? Only then does it get a code.
    - [ ] **Prioritise the 96 broad `except Exception:` sites**, and within those the ones on
          a data path (a read that returns a default, a count that falls back to 0) over ones
          on a presentation path. Those are the ones that produce a plausible-looking wrong
          answer rather than a visibly missing one.
    - [ ] **Use `record_error_best_effort()`, not `record_error()`, at these sites.** They are
          already in a failure handler; a raising error-recorder would replace the original
          exception with a second one and lose the actual fault. That is why the best-effort
          variant exists.
    - [ ] Seeded already (2026-08-06): `modules/tickets/module.py` `get_open_ticket_count()`
          records `E-TICKETS-001` and still returns 0 — the reference shape for the rest.

- [ ] **Vestigial tables in the live DB — audit WHY before removing anything.**
      Found 2026-08-06 (Window 1) during the schema-drift sweep prompted by Window 3's
      `devices` CREATE finding. Three tables exist in `/var/lib/nemesis/alerts.db` with
      effectively no live code behind them. **No removal decision yet — Window 2 audits
      tomorrow.**
    - [ ] **SCOPE OF TOMORROW'S AUDIT — narrowed by operator, 2026-08-06: confirm removal
          is SAFE, not whether the data is worth keeping.** None of the contents matter
          (see the `alert_notes` note below), so there is no data-loss question to weigh.
          The audit's one job is dependency confirmation: does anything still read these,
          including under another name, via a constant, an f-string, a dynamically-built
          query, or a doc/diagnostic that would break? **That last part is the real work** —
          this same day's schema sweep proved a plain grep is not sufficient evidence, since
          dynamically-constructed SQL (`ALTER TABLE %s`, `f"...{OP_LOG_TABLE}"`) is
          invisible to it and produced a string of false conclusions until each was checked
          by hand.
    - [ ] **STARTING HYPOTHESIS (Paul's, 2026-08-06) — not a conclusion.** These are
          likely leftovers from past reworks: a table got replaced by a redesign and the
          old one was never cleaned up. The git history below is consistent with that and
          is offered as a lead for the audit, not as the answer.
    - [ ] **`alert_notes`** — 4 rows, all `author='admin'`, all created 2026-06-21 within
          four minutes. **These are Paul's own test data from that day's testing, NOT
          operator history** (confirmed by the operator, 2026-08-06). No export, no special
          handling, nothing to preserve.
        - [ ] **Process note, and the actually useful lesson here: these rows are exactly
              what Rule 11 exists to prevent.** They are unlabelled test data — no "test
              data" phrase, no date marker in the note body — so from the DB alone they
              were indistinguishable from genuine operator content. That is not a
              hypothetical cost: this entry originally reported them as "a working feature
              with real use, not test scaffolding" and specified an export requirement, on
              the strength of `author='admin'` and 0 orphaned `rule_id`s. Both signals were
              real and both pointed the wrong way. Rule 11 predates this and would have
              answered it in one grep.
        - [ ] Correction to the first report: it is NOT zero-reference. It has no *code*
              reference, but IS named in `docs/architecture/0001-database-and-module-architecture.md`.
              A doc that still lists it makes it look current.
        - [ ] Lead: introduced by `679eea7` ("Add admin notes system..."), and the last
              commit touching it in Python is `cd47fe2` — **"Add tickets module (replaces
              notes system)"**. The commit message states the replacement outright.
        - [ ] Checked: `alerts` has no note/comment/annotation column, so nothing was
              folded back into the parent row when the tickets module superseded this.
              Recorded as a schema fact for the dependency check, NOT as a data-loss
              concern — there is nothing here worth migrating.
    - [ ] **`anomaly_ai_cache`** — 0 rows. Schema is a per-target AI report cache
          (`offending_target` PK, `ai_report_json`, `generated_at`).
        - [ ] **The module contradicts itself in the same file**, which is its own small
              finding: `modules/anomaly_detection/module.py:16` documents it in the module
              docstring as live ("per-target AI reports (24h dedup / 30-day reuse)"), while
              line 2023 says "not from anomaly_ai_cache which is removed". Also still
              listed in `diagnostics/anomaly_state.py:70`.
        - [ ] Lead: last touched by `0980d1f` ("Refactor: centralize all AI functionality
              into ai_engine module").
    - [ ] **`anomaly_ai_usage`** — 0 rows, and the only one of the three with **genuinely
          zero references in any tracked file**. Schema is an hourly AI call counter
          (`date`, `hour`, `call_count`, `UNIQUE(date,hour)`).
        - [ ] Lead: same `0980d1f` AI-centralisation refactor. Worth checking against
              ADR 0006 — the `ai_engine` rate counter was formalised into
              `DataManager.increment_counter()`, which would supersede this table exactly.
    - [ ] **Not a fresh-install hazard** (unlike the `devices` CREATE gap that started this
          sweep): nothing reads them, so a fresh install simply never creates them and
          nothing breaks. That is why this is a cleanup item and not a bug.
    - [ ] If removal IS agreed: a normal Rule 6 backup before the DROP is sufficient. No
          export step is owed for any of the three — the two `anomaly_ai_*` tables are
          empty and `alert_notes` holds only test data. The backup is there to make the
          DROP reversible if the dependency check missed something, which is the only
          risk left in this item.

- [ ] **⚠ URGENT — dhcp module's Data Manager grant is a PREFIX match, not the exact-match
      it claims to be. Fix before landing; flagged before commit specifically because
      tonight is an unattended overnight run.** Found by Window 2, 2026-08-06, reviewing
      Window 1's dhcp-module thread-wiring delivery (held, not committed).
    - [ ] **The claim, verbatim from the code comment:** `alert_manager/data_manager.py`'s
          new `"dhcp": ("dhcp_leases",)` entry is commented "EXPLICIT table, not a `dhcp_`
          prefix grant... so it can't silently acquire writable tables as it grows."
    - [ ] **The actual behaviour, demonstrated, not inferred:** `allowed()` treats a plain
          tuple value as a PREFIX list (`table.startswith(p) for p in spec`) — exact-match
          semantics only exist for the dict form (`{"tables": (...)}`), already used for
          exactly this precision by `integrity_watch`. Live test:
          ```
          dm.allowed('dhcp', 'dhcp_leases')          -> True   (correct)
          dm.allowed('dhcp', 'dhcp_leases_archive')  -> True   (WRONG — no such table
                                                                 exists yet, but it is
                                                                 silently pre-authorized)
          dm.allowed('dhcp', 'devices')              -> False  (correct)
          ```
    - [ ] **Fix:** change the entry to `"dhcp": {"tables": ("dhcp_leases",)}`, matching the
          `integrity_watch` precedent exactly.
    - [ ] **The new test doesn't catch this, and that is the more important finding.**
          `test_dhcp_module.py`'s "the grant is an EXPLICIT table, not a `dhcp_` prefix"
          check greps the source for the literal substring `("dhcp_leases",)` — it never
          calls `allowed()` to test actual semantics. This is the SAME "matches my own
          text, not my own behaviour" trap the same delivery's handoff describes fixing
          (instances 4 and 5, moving those checks to AST) — this would be a 6th, hiding
          inside the one check meant to guard this exact property. Replace the grep with
          a real assertion: `dm.allowed('dhcp', 'dhcp_leases_archive') is False`.
    - [ ] **Not exploitable today** — no second `dhcp_`-prefixed table exists anywhere in
          the codebase, so nothing is currently over-privileged. This is a latent gap in a
          security-boundary claim, not an active hole. Filed as urgent anyway because the
          whole point of this grant is to be the thing that makes ADR 0001's boundary
          enforced rather than merely documented, and it should not ship — especially into
          an unattended overnight run — with a precision claim the code does not back up.
    - [ ] **Held, not committed:** `alert_manager/data_manager.py`, `modules/dhcp/module.py`,
          `modules/dhcp/manifest.json`, `alert_manager/test_dhcp_module.py`. All four are
          otherwise reviewed clean — 78/78 passing, `py_compile` clean, Rule-8 clean — and
          ready to land the moment this one entry is corrected.
