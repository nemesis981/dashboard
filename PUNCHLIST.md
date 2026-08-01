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
  Functional join was the key; the prompt is cosmetic/parallel. ALSO: the installer's first-screen
  instructional text still says "install Tailscale (tailscale.com/download), log in…" — now STALE
  (the installer does this itself). Fix direction: suppress/skip the Tailscale GUI launch (or
  `tailscale up --unattended` / config to prevent the login window surfacing), and update the
  installer_gui.py first-screen text to reflect auto-onboard. Polish, NOT a blocker — the
  mechanism works. (installer_gui.py `_install_tailscale` / `steps_text`.)
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
  interface, different TTL, and `tun0`'s MTU was 1441 vs 1500 on `enp131s0`. Any Layer 3 run must
  record PIA state as a run variable; runs across different states are not comparable.
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
