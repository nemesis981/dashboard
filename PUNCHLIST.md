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

- [ ] **[FIX-NOW] `tickets_seq` duplicate ticket numbers.** `_next_ticket_number`
  (`modules/tickets/module.py:113-115`) does `SELECT next_number` then a separate
  `UPDATE … = next_number + 1` → two concurrent `open_ticket()` calls (e.g. auto-ticket-on-
  alert firing from alert-watcher + a module) get the same number. Fix: atomic
  `UPDATE tickets_seq SET next_number = next_number + 1 WHERE id=1 RETURNING next_number`
  (or equivalent single statement). **Highest-likelihood to surface during the trip.**

- [ ] **[FIX-NOW] AI rate-limit counter lost increments.** `_increment_rate`
  (`modules/ai_engine/module.py:308-318`) reads `hour_count`/`day_count`, computes `+1`, writes
  back separately → concurrent calls lose increments and under-count the rate limit. Fix:
  atomic upsert like the `_increment_usage` sibling right below it.

- [ ] **[FIX-NOW] `community_queue` duplicate rows.** `add_to_queue`
  (`modules/community_queue/module.py:110-135`) is SELECT-then-INSERT/UPDATE with no UNIQUE on
  `(domain_or_ip, submitted)` → concurrent detections create duplicate queue entries. Fix:
  add the UNIQUE constraint + `INSERT … ON CONFLICT DO UPDATE`.

- [ ] **[FIX-NOW] `anomaly_incidents` duplicate open incidents.** `_create_or_update_incident`
  (`modules/anomaly_detection/module.py:654-705`) is SELECT-then-INSERT/UPDATE with no UNIQUE
  on `(offending_target, status)` → concurrent detections for one target create duplicate open
  incidents instead of merging. Fix: UNIQUE + atomic upsert (mind the time-window merge logic).

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
