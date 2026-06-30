# HANDOFF — current state

> Current project state, last updated 2026-06-30 (closeout). Overwritten at each closeout
> (latest state wins). Durable history: `docs/handoff/supplements/` (append-only); raw step
> log: `docs/handoff/worklog/`.
> Real IPs/hosts/accounts/names live in `~/work/nemesis-private/local-config.md` (outside the
> repo) — placeholders here per Rule 8 (public repo).

## Current state
- **v1.0.7 installer SELF-ONBOARDS end-to-end** — PROVEN on a real clone (`<clone-ip>`) over
  live Tailscale tonight: download credentialed `/zip` → install Tailscale on a bare box → join
  the tailnet via the **baked single-use pre-auth key** → **consume + delete** the sidecar conf →
  enroll. Only manual step is approval. This replaces the morning's two dead ends (Tailscale
  hard-gate + legacy-Python `.ps1`).
- **PL-3 RESOLVED (functionally):** conf read/consumed/deleted; clone joined the **PROJECT
  tailnet under the project account** via the key (an operator login can't reach it — the key did
  it). Frozen exe confirmed built from `a21b782` (CI headSha match). **Single-use verified:**
  enrollment token `uses=1/1` spent; Tailscale pre-auth key consumed + gone from the registry.
- **Fingerprint shipped + live (`daf273f`):** hardware-stable-identifiers (Windows+Linux), TOFU
  match, `agent_devices` migration, enrollment-payload wiring. Tested both platforms; live `/enroll`
  probe confirmed storage (`is_virtual` flows through). Mac = interface-only (deferred).
- **Design locked:** ADR 0011 **BUILD-READY** (enrollment security); `hardware-stable-identifiers`
  built+tested; unified-installer **design of record** (`docs/roadmap/installer-unified-v1.0.6.md`).
- **Concurrent sessions active on `main`** — pull-before-commit is standing practice.
- **Header light: green.** All 6 services active.
- **Wisconsin trip: Friday, 2 weeks.** Installer self-onboards, but **two before-trip fixes remain**
  (below) → not yet trip-shippable.

## ⚠️ NOT fully trip-ready — two before-trip fixes (found by tonight's verify pass)
1. **SECURITY — auto-approve default contradicts ADR 0011.** `api_agent_installer_generate` mints
   tokens with `auto_approve=1`; the "approved" device appeared via the **token's own flag**, not a
   manual approval. Must default `auto_approve=0`; auto-approve = explicit opt-in.
2. **DOUBLE-ENROLL — one device, two rows.** Installer `_enroll` doesn't persist `device_id`, so the
   agent re-enrolls ~11s later. Fix: persist `device_id`/status into `nemesis_agent.conf`.

## Next-session resume (IN ORDER)
1. **Fix (1) auto-approve default → `auto_approve=0` + explicit opt-in** [BEFORE-TRIP, security].
2. **Fix (2) double-enroll → persist `device_id` into the conf** [before-trip].
3. **Regenerate a fresh installer + a FRESH single-use Tailscale pre-auth key.**
4. **Laptop test over Starlink** — real physical device, remote/tailnet (the real trip topology;
   `is_virtual=False` expected).
5. **Cleanup pass → assess where things stand.**

## Open items (carry)
- **Phase 2 integration (NOT built):** TOFU lock wiring into the live approval path,
  scan-in-enrollment, owner **review card**, the manual-approval flip (= fix #1), enroll-time
  used-token behavior.
- **Infra: nginx `:80` → tailnet-only** for media + `/enroll` (ADR 0011 IMMEDIATE; removes the
  cleartext interception path).
- **PL-10 (post-trip UX):** Tailscale GUI auto-launches a redundant login window after the silent
  `--authkey` join; installer first-screen text stale. Suppress GUI / `--unattended` + fix text.
- **Installer size: 272MB → ~30MB** (post-trip; small stub + fetch ClamAV on first run).
- **`/api/agent/uninstall` endpoint** doesn't exist yet (uninstall script POSTs best-effort).
- VPN-off workaround still in place (ADR 0005 real fix deferred).
- Rule-6 backups parked in scratchpad (`alerts-PRE-HWID-MIGRATION-20260630.db`,
  `alerts-PRE-DASH-RESTART-20260630.db`).

## Resolved today
- **Installer self-onboard (PL-3)** — built (`a21b782`/v1.0.7), proven on the clone.
- **Hardware-stable-identifiers** — built + tested + live (`daf273f`).
- **`/zip` 503** — `NEMESIS_AGENT_EXE` was unset; staged the frozen exe + restarted dashboard → 200.
- **Master VM** — frozen as the reusable bare baseline (no agent/Python/Git/Tailscale; SSH preserved).
- **Roadmap-vs-state baseline** refreshed (`docs/audits/roadmap-state-audit-2026-06-30.md`).

## Pointers
- **ADRs:** 0006 (Data Manager), 0007 (device-user model), 0008 (impossible travel),
  0009 (security inspection proxy), 0010 (agent ping monitor), **0011 (enrollment security — BUILD-READY)**.
- **Installer design of record:** `docs/roadmap/installer-unified-v1.0.6.md` + ADR 0011.
- **Today's audit + verify:** `docs/audits/windows-install-doc-test-2026-06-30.md`;
  supplement `docs/handoff/supplements/2026-06-30-001.md`.
- `docs/roadmap/` — full capture set. Roadmap-vs-state baseline `docs/audits/roadmap-state-audit-2026-06-30.md`.
- `docs/operation/OPERATION.md` (nginx = official entrypoint), `WINDOWS_AGENT_SETUP.md` + 3-tier guides.
- `~/work/nemesis-private/local-config.md` — real IPs/hosts/accounts/names (outside repo).

## Topology note (durable)
- **:80** = nginx (Basic-auth), LAN-allowed, proxies to :5000; auth-bypass for `/install/windows/`
  + `/api/health`. **ADR 0011 wants media + `/enroll` moved to tailnet-only (carry).**
- **:5000** = Flask dashboard, ufw-blocked from LAN — internal only.
- **:5001** = hw-monitor agent endpoint (`/enroll`, `/enrollment_status`, `/hw_data`),
  LAN-subnet-allowed (+ tailnet reachable).
- **`NEMESIS_AGENT_EXE`** = staged frozen `NemesisAgent-Setup.exe` (outside repo) that `/zip` re-zips
  with a per-installer conf; set in `/etc/nemesis.env`.
