# SPEC — Diagnostics: Connectivity Watcher (productization)

- **Status:** DRAFT for review (spec-first; no code changed). Graduates roadmap stub
  `docs/roadmap/diagnostics-connectivity-watcher-tool.md`.
- **Date:** 2026-06-28
- **Owner module (new):** `modules/diagnostics/`
- **Depends on:** ADR 0001 (DB + module prefix ownership), ADR 0003 (resilience),
  classification framework (`docs/roadmap/diagnostics-classification.md`)
- **Feeds:** standalone runner (`docs/roadmap/diagnostics-standalone-runner.md`) — the
  watcher's "is-it-me-or-them" fact is the gate that doc relies on.
- **Engine-aware (ADR 0005):** OBSERVE-ONLY. The watcher makes **no** routing/firewall/DNS
  changes. Any future remediation routes through the firewall engine — never from here.

> Paths/IPs sanitized for the public repo (`/home/<user>`, `<host>`, `<ip>`). This spec
> decides the design; it does not contain code.

---

## 1. Problem & goal

The throwaway watcher `~/work/vpn-watcher/vpn-watch.sh` (OUTSIDE the repo because it logs
real IPs — Rule 8) proved its value twice on 2026-06-27: with PIA off and the watcher
all-green, it showed a backend hiccup was **NOT** local DNS. That "is-it-me-or-them" signal
turns an ambiguous failure into an attributable one.

**Goal:** graduate it into a first-class, toggleable Nemesis diagnostic — the first concrete
piece of the diagnostics subsystem — **without** leaking real IPs into the repo or the DB, and
**without** the 137 MB/day log growth the 3 s shell loop produced.

**Non-goal:** the AI interpretation tier, the `nemesis-diag` CLI runner, and safe-mode are
separate stubs. This spec builds the **continuous connectivity logger + its dashboard surface**
only — the deterministic fact source those later pieces consume.

## 2. Classification (why this shape is forced, not chosen)

Per `diagnostics-classification.md`:
- **Lens A — Transient/intermittent** (DNS-under-VPN, link quality come and go).
- **Lens B — Dashboard-INDEPENDENT** (connectivity failure can itself take the dashboard down).

Rule: *anything Transient OR Dashboard-independent MUST be a continuous logger running
outside Flask, writing flat files readable when Flask/DB are down.* → The detection loop is a
**standalone systemd service**, not in-process Flask. The Flask module owns only
settings/card/routes and reads **sanitized** summaries the service writes.

## 3. Architecture — module + standalone service (mirror the canary)

Two cooperating parts, exactly the proven `malware_detection` + `malware_canary.py` split:

| Part | File | Role |
|------|------|------|
| Flask module | `modules/diagnostics/module.py` + `manifest.json` | contract (`start/stop/status/get_dashboard_card/get_routes`), settings, DB schema, **reads** sanitized samples for the card. Does NOT run the probe loop. |
| Probe library | `modules/diagnostics/watcher.py` | the probes + classifier + flat-file writer + sanitized DB sampler. Pure functions callable by the service AND (later) the `nemesis-diag` runner. |
| Standalone service | `alert_manager/diagnostics_watcher.py` | process host: registers shared DB path, self-gates, reads cadence fresh each loop, calls the probe library. Mirror of `malware_canary.py`. |
| Unit file | `alert_manager/diagnostics-watcher.service` | `Type=simple`, `User=root`, `EnvironmentFile=/etc/nemesis.env`, `Restart=always`, `ExecStart=/usr/bin/python3 /home/<user>/dashboard/alert_manager/diagnostics_watcher.py`. Mirror of `malware-canary.service`. |

**Self-gating (no `systemctl`-from-toggle):** the toggle flips a settings flag; the always-on
service decides whether to act. Two gates each loop, like the canary: **module enabled AND
`watcher_enabled=1`**. When off, the loop logs one "self-gated off" line and sleeps. This
avoids privilege escalation from the dashboard process.

## 4. The Rule-8 split — flat file (raw) vs DB (sanitized)

This is the central hygiene decision. **Raw probe output contains real LAN/tunnel/public IPs;
it must never reach the repo or the DB.**

- **Flat file = raw, runtime-only, OUTSIDE the repo.** Default dir `/var/log/nemesis/diagnostics/`
  (root-writable, FHS-correct, survives repo moves), overridable via setting `watcher_log_dir`.
  Holds the full probe blocks (routing tables, resolved IPs, curl timings). Never committed;
  `.gitignore` guards the path; the install creates the dir.
- **DB = sanitized verdicts only, for the dashboard.** Tables under the new `diagnostics_*`
  prefix store **classification results, not addresses**: per-cycle boolean/enum verdicts
  (`routing_ok`, `dns_ok`, `egress_ok`, `api_ok`), the `is-it-me-or-them` verdict (§6), latency
  buckets, and timestamps. **No raw IPs, no hostnames beyond the configured probe target name.**
  A leak-scan grep over the DB writers is part of the Pass-0 review gate.

Rationale: the dashboard card and trend view need queryable status; the forensic detail lives
in the flat file (readable over SSH when the DB/Flask are down — the whole point of Lens B).

## 5. Probes (generalized from `vpn-watch.sh`, observe-only)

Port the existing probe set to Python, **decoupled from PIA** (the box may be on Starlink with
no VPN on the trip). Each probe is independent and never kills the loop (the shell loop's
`set +e` discipline → per-probe try/except):

1. **VPN state (optional plugin)** — if `piactl` present, record connection state/vpnip/pubip;
   else skip cleanly. Not assumed.
2. **Tunnel interface** — presence + assigned IP of `tun*/wg*`.
3. **Routing** — default route, `ip rule`, full table, `ip route get <egress>`,
   `ip route get <api-ip>` (source-IP selection — the ADR 0005 client-refusal-by-source signal).
4. **DNS** — resolver from `/etc/resolv.conf` + resolve the API host (+ optional `-b loopback`
   refusal probe, the ADR 0005 decisive test).
5. **Raw egress by IP** — `curl https://<egress-ip>` (no DNS in path). Target configurable
   (`watcher_egress_ip`, default `1.1.1.1`).
6. **KEYTEST — the real upstream dependency** — `curl https://<api-host>` default/`-4`/`-6`
   (api.anthropic.com resolves v6; isolates v6-routing failures). Host configurable
   (`watcher_api_host`, default `api.anthropic.com`).

All read-only. No probe changes system state.

## 6. The "is-it-me-or-them" classifier (the core value)

Each cycle derives one verdict from the probe results:

- **LOCAL_OK / UPSTREAM_FAIL** — routing+DNS+raw-egress green but KEYTEST fails → *it's them*
  (e.g. the 2026-06-27 backend hiccup).
- **LOCAL_FAIL** — routing/DNS/egress red → *it's us* (e.g. source-refusal under VPN).
- **ALL_OK** — everything green.
- **DEGRADED** — partial (e.g. v6 fails, v4 ok).

This enum is what lands in the DB and drives the card. It is the fact the standalone runner
gates its AI tier on (`diagnostics-standalone-runner.md`).

## 7. Cadence & log management (must not repeat the 137 MB/day)

Two modes, one service:
- **Continuous (boot default) — quiet.** Cadence `watcher_interval_seconds` default **60 s**.
  Writes **one summary line per cycle** to the flat file + **one sanitized DB sample**. This is
  what runs unattended on the trip.
- **Verbose (opt-in, time-boxed) — debug.** Flag `watcher_verbose=1` (optionally with
  `watcher_verbose_until` timestamp) drops to ~3 s and writes full probe blocks. **Never the
  boot default**; auto-reverts to quiet when the time-box expires so it can't silently fill the
  disk again.
- **Rotation/retention** — size cap (`watcher_log_max_mb`, default 50) + age prune
  (`watcher_log_retain_days`, default 14), enforced by the service itself (no dependency on
  external logrotate). Rotate-on-size, prune-on-age each cycle boundary.

## 8. Settings (DB-backed, `_get_setting`/`_set_setting`, like malware)

| Key | Default | Meaning |
|-----|---------|---------|
| `watcher_enabled` | `0` | master self-gate (off until user enables) |
| `watcher_interval_seconds` | `60` | continuous cadence |
| `watcher_verbose` | `0` | verbose debug mode |
| `watcher_verbose_until` | `` | ISO ts; auto-revert to quiet after |
| `watcher_log_dir` | `/var/log/nemesis/diagnostics` | flat-file dir (outside repo) |
| `watcher_log_max_mb` | `50` | rotate threshold |
| `watcher_log_retain_days` | `14` | prune age |
| `watcher_egress_ip` | `1.1.1.1` | raw-egress probe target |
| `watcher_api_host` | `api.anthropic.com` | KEYTEST upstream |

`enabled_by_default: false` in the manifest (matches malware). No env-specific defaults
(Rule 8 / CLAUDE.md): `1.1.1.1` and `api.anthropic.com` are correct for any user.

## 9. Database (ADR 0001 — NEW prefix `diagnostics_*`)

New module → **new owned prefix `diagnostics_*`**, an addition to ADR 0001's prefix list
(`anomaly_/malware_/tickets_/ai_/community_` → add `diagnostics_`). Update ADR 0001 in the
same change. Tables (every DDL in exactly one canonical `_init_db`, per CLAUDE.md "no table
without a CREATE"):

- `diagnostics_connectivity_samples` — rolling, capped per-cycle sanitized verdicts:
  `id, ts, routing_ok, dns_ok, egress_ok, api_ok, verdict, latency_ms, actor, note`.
  Capped (delete oldest beyond N) so it can't grow unbounded.
- `diagnostics_status` — single latest-status row for the card (cheap read).

**Multi-user seams (CLAUDE.md):** `actor` column from the start (always `watcher-service` now);
writes concurrency-safe (single-writer service today, but use the shared accessor + guarded
writes). Read-any/write-own honored.

**DB accessor:** the service registers `modules.set_shared_db_path(...)` before importing the
module — exactly as `malware_canary.py` does (it never runs `modules_loader.init()`). Never
compute `__file__`-relative DB paths.

## 10. Dashboard surface

- `get_dashboard_card()` — current `verdict` (color-coded ALL_OK/UPSTREAM_FAIL/LOCAL_FAIL/
  DEGRADED), last-sample age, enabled/disabled, link to the detail view. **JS strings via
  single quotes / `json.dumps`, contractions HTML-escaped** (CLAUDE.md #1 recurring bug).
- `get_routes()` — a read-only status/trend route over `diagnostics_connectivity_samples`
  (sparkline of verdicts over time → Lens-A trend visibility). No raw IPs rendered.
- A settings panel for the §8 toggles.

## 11. Install / uninstall integration (apply the canary VM-audit lessons)

- **install.sh:** add `diagnostics-watcher` to `svc_names` (line ~814), the restart list
  (~965, ~1019, ~1123). Create `/var/log/nemesis/diagnostics/` (root-owned). Template-substitute
  `/home/<user>` like the other units.
- **uninstall.sh:** add `diagnostics-watcher` to `SERVICES` (line ~122). **Remove the flat-file
  log dir on uninstall** (mirror the canary bait+baseline cleanup lesson — don't leave runtime
  artifacts behind). Service-count wording is already count-agnostic (`c78cbfc`).
- Boot-enable verified end-to-end before closeout.

## 12. Build phases (one variable at a time — STOP between, verify with real output)

- **Pass 0 — module skeleton.** `modules/diagnostics/` (manifest + module + `_init_db` with the
  two `diagnostics_*` tables) + ADR 0001 prefix update. No service, no probes. Verify: fresh
  `_init_db` creates tables; leak-scan DB writers. STOP.
- **Pass 1 — probe library.** `watcher.py`: probes (§5) + classifier (§6) + flat-file writer
  with rotation (§7) + sanitized DB sampler (§4/§9). Hand-runnable. Verify: run once VPN-off and
  VPN-on, confirm verdicts + **grep the DB for any IP-shaped string = none**. STOP.
- **Pass 2 — dashboard.** Card + routes + settings panel (§10). Verify in-browser. STOP.
- **Pass 3 — service + lifecycle.** `diagnostics_watcher.py` + `.service`, self-gating, install/
  uninstall integration (§11), boot-enable. Verify: toggle on → samples appear; toggle off →
  "self-gated off"; reboot persists; verbose time-box auto-reverts; rotation caps size. STOP.

## 13. Open questions — RESOLVED 2026-06-28 (recommendations accepted)

a. **Flat-file dir default** → `/var/log/nemesis/diagnostics/` (FHS, root-writable, survives
   repo moves). Overridable via `watcher_log_dir`.
b. **PIA probe** → keep as an **optional plugin** (skip cleanly if no `piactl`). Framing is
   generic connectivity; PIA is one input.
c. **Samples retention** → **both** — row-count cap on `diagnostics_connectivity_samples`, age
   prune on the flat file.
d. **ADR?** → **no new ADR.** ADR 0001 prefix-list edit + this spec suffice (follows established
   patterns; no new decision).
