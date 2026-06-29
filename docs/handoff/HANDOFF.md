# HANDOFF — current state

> Current project state, last updated 2026-06-29 (closeout). Overwritten at each closeout
> (latest state wins). Durable history: `docs/handoff/supplements/` (append-only); raw step
> log: `docs/handoff/worklog/`.
> Real IPs/hosts/accounts/names live in `~/work/nemesis-private/local-config.md` (outside the
> repo) — placeholders here per Rule 8 (public repo).

## Current state
- **Windows self-installer BUILT and working** (concurrent session), now **v1.0.6**: two-exe
  model (frozen NemesisAgent.exe + Setup.exe, no system Python), UAC elevation, Defender
  exclusion, bundled ClamAV + LibreHardwareMonitor, token auto-approve enrollment, tkinter
  guided GUI, 3-tier install guides, GitHub Actions exe+zip build.
- **First real NON-DEVELOPER enrollment ✅** — a family member's laptop enrolled via the token
  installer, proving the non-technical-user install flow end-to-end (not just a developer box).
- **Token installer verified end-to-end** (generate token → download → install → auto-approve
  enroll → heartbeat).
- **`/api/health` live — 200 confirmed** through nginx (auth-bypass applied + verified).
- **`link_type` detection shipped (`b3146fe`):** WiFi vs ethernet on all platforms (Linux
  live-verified, Windows/Mac syntax-verified). Dashboard shows "WiFi · VPN remote" + the
  Suricata Mode 2 note.
- **`NEMESIS_AGENT_VERSION=1.0.6`** (updating now).
- **Agent enrollment flow verified 8/8** (smoke test, Linux VM over LAN): scan-before-trust →
  enroll → owner-approve → authenticated heartbeat. Two deployment gaps found & fixed
  (firewall 5001 `c37a177`; stale `hw-monitor` restarted → endpoints live + migration applied).
- **My installer additions:** Windows uninstall script (`1b3aba3`), Tailscale 5-state handling
  + retry loop (`c58b7f7`), `/api/health` + nginx bypass + installer reachability check
  (`b3b3a5e`).
- **Rule-8 public-repo scrub COMPLETE** (`d63cb81`/`6c24fe9`/`d0be3d5`/`10902ed`): PII (real
  device names), handoff docs (box/tailnet IP, project account), hardcoded box IP/subnet in
  shipped code → env-driven, + explicit CLAUDE.md handoff scan rule. HEAD clean of real infra.
- **Big doc-capture arc landed** (morning + afternoon): malware pipeline, sandbox→system
  migration, support bundle, vendor package, tutorial walkthrough, partner program,
  pre-escalation search, device identification + MAC randomization/stable hardware IDs,
  installer email delivery. All in `docs/roadmap/` + PUNCHLIST; capture audit at
  `docs/audits/roadmap-capture-audit-2026-06-29.md`.
- **Concurrent sessions active on `main`** — pull-before-commit is standing practice.
- **Header light: green.** All 6 services active.
- **Wisconsin trip: READY** (Friday, 2 weeks). Enrollment flow works; Starlink + project
  tailnet confirmed.

## Next-session resume
1. **Clean Windows VM test of v1.0.6** — all 9 installer phases on a fresh Windows box
   (UAC, bundle extraction, Tailscale states, enroll/approve, heartbeat, uninstall).
2. **Master VM audit** — verify/reset the throwaway test VM baseline.
3. **(post-trip) Installer size optimization** — 272MB → ~30MB (fetch ClamAV on first run).

## Open items
- **Installer size: 272MB → ~30MB** (post-trip; small stub + fetch ClamAV on first run).
- **`/api/agent/uninstall` endpoint doesn't exist yet** — the uninstall script POSTs to it
  best-effort (local removal always completes); build the endpoint when convenient.
- **`link_type` detection** (Window 1, landing soon).
- **Clean Windows VM test** (v1.0.6, all 9 phases).
- **Owner's laptop agent install** (trip device).
- Son's laptop Tailscale re-enrollment (project account).
- Ethernet cable for Wisconsin (before Friday).
- KDE Connect broken (not pursuing).
- VPN-off workaround still in place (ADR 0005 real fix deferred).
- Live 5001 ufw rule is `/24` while others are `/22` (cosmetic); `install.sh` windows_vm 5001
  `from any` rule now redundant + broad (tighten someday).
- Rule-6 smoke-cleanup backup parked in scratchpad (`alerts-PRE-SMOKE-CLEANUP-20260629.db`).

## Resolved today (was open / pending)
- **All 3 deploy gates done:**
  - `PIHOLE_IP` + `LAN_SUBNET` set in `/etc/nemesis.env` ✅
  - nginx `/api/health` + `/install/windows/` auth-bypass applied + verified 200 ✅
  - UFW tailnet rules already existed ✅
- **Port redirect** → resolved: port canonicalization is an **nginx-layer** concern (documented
  in OPERATION.md + PUNCHLIST); the naive Flask redirect would have blacked out the dashboard.
- **Rule-8 handoff/repo leak** → scrubbed (4 commits); HEAD clean. History retains old values
  by decision (no rewrite).
- **`PIHOLE_IP` hardcoded** → env-driven (and now set in `/etc/nemesis.env`).

## Pointers
- **ADRs:** 0006 (Data Manager), 0007 (device-user model), 0008 (impossible travel),
  0009 (security inspection proxy), 0010 (agent ping monitor).
- `docs/roadmap/` — full capture set. `docs/audits/roadmap-capture-audit-2026-06-29.md`.
- `docs/operation/OPERATION.md` (nginx = official entrypoint), `CONFIG_CHANGE_PROCEDURE.md`,
  `WINDOWS_AGENT_SETUP.md` + the 3-tier Windows install guides.
- `core/manage.py` (SSH recovery CLI).
- `~/work/nemesis-private/local-config.md` — real IPs/hosts/accounts/names (outside repo).

## Topology note (durable)
- **:80** = nginx (Basic-auth "Nemesis Firewall"), LAN-allowed, proxies to :5000; auth-bypass
  for `/install/windows/` + `/api/health` applied (verified 200).
- **:5000** = Flask dashboard, ufw-blocked from LAN — internal only.
- **:5001** = hw-monitor agent endpoint (`/enroll`, `/enrollment_status`, `/hw_data`),
  LAN-subnet-allowed (+ tailnet reachable).
