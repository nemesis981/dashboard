# HANDOFF — current state

> Current project state, last updated 2026-06-29 (smoke-test session). Overwritten at each
> closeout (latest state wins). Durable history: `docs/handoff/supplements/` (append-only);
> raw step log: `docs/handoff/worklog/`.
> Real IPs/hosts/accounts live in `~/work/nemesis-private/local-config.md` (outside the repo) —
> placeholders used here per Rule 8 (public repo).

## Current state
- **Agent enrollment smoke test: COMPLETE ✅ (8/8).** Full scan-before-trust → enroll →
  owner-approve → authenticated heartbeat path verified end-to-end over the LAN
  (test VM → prod box). See worklog `2026-06-29-001`.
- **Two deployment gaps found & fixed during the smoke test:**
  - **Firewall:** port 5001 was only opened under `INSTALL_MODE=windows_vm`; standard installs
    never opened it. Fixed in `install.sh` (always-on, subnet-scoped) — commit `c37a177` — and
    applied on the live box.
  - **Stale service:** live `hw-monitor` was running pre-enrollment code (started Jun 27).
    Restarted (owner-run `sudo systemctl restart hw-monitor`) → enrollment endpoints live +
    `agent_devices` migration applied. `/enrollment_status` now returns 200 (was 501).
- **Wisconsin trip: READY.** The agent enrollment flow works; Starlink + project tailnet
  confirmed. Trip uses the project tailnet (see local-config for account/IP).
- **Header light: green.** All 6 services active (dashboard, watchdog, alert-watcher,
  malware-canary, diagnostics-watcher, vpn-dns-guard).
- **Big doc capture arc landed today** (malware pipeline, sandbox→system migration, support
  bundle, vendor package, tutorial, partner program, pre-escalation search) — all in
  `docs/roadmap/` + PUNCHLIST, audit `docs/audits/roadmap-capture-audit-2026-06-29.md`.

## Next-session resume
1. **Port redirect — NEEDS REDESIGN (do NOT ship the naive Flask version).** Audit during the
   smoke test found the box runs **nginx :80 (LAN-reachable, Basic-auth, `Host $host` → no port)
   → Flask :5000 (ufw-BLOCKED from LAN)**. A Flask `before_request` "host missing :5000 → 301
   :5000" would fire on *every* proxied request and bounce all users to a firewall-blocked port
   = dashboard outage. Any port-canonicalization belongs at the **nginx layer** and must respect
   that :5000 is internal. (Detail in worklog `2026-06-29-001`.)
2. **Master VM audit** (the throwaway test VM — verify state / reset baseline).
3. **Session closeout** (write supplement, finalize).
4. **Rule-8 cleanup of handoff docs (NEW — see below).** Existing committed handoff docs leak
   real IPs + the project Gmail on the public repo; decide remediation.

## Open items
- **Rule-8: public repo leaks real infra in committed handoff docs.** HANDOFF/supplements/
  worklogs already expose real LAN IPs, the tailnet IP, and the project Gmail on public GitHub.
  Needs a decision: scrub going forward + optionally rewrite history, or make the repo private.
- Son's laptop Tailscale re-enrollment (project Gmail account).
- Ethernet cable for Wisconsin (find before Friday).
- KDE Connect broken (not pursuing).
- `PIHOLE_IP` hardcoded at `dashboard.py:71` (known Rule-8 PUNCHLIST item).
- VPN-off workaround still in place (ADR 0005 real fix deferred).
- Live 5001 ufw rule is `/24` while other rules are `/22` (cosmetic; both cover the LAN).
- `install.sh:883` windows_vm 5001 rule (`from any`) now redundant with the base rule + broader
  than ideal — someday tightening.
- Rule-6 smoke-cleanup backup parked in scratchpad (`alerts-PRE-SMOKE-CLEANUP-20260629.db`).

## Pointers
- **ADRs:** 0006 (Data Manager), 0007 (device-user model), 0008 (impossible travel),
  0009 (security inspection proxy), 0010 (agent ping monitor).
- `docs/roadmap/` — full capture set (see today's arc above).
- `docs/audits/roadmap-capture-audit-2026-06-29.md` (39-item capture audit).
- `docs/operation/CONFIG_CHANGE_PROCEDURE.md`, `docs/operation/WINDOWS_AGENT_SETUP.md`
- `core/manage.py` (SSH recovery CLI)
- `~/work/nemesis-private/local-config.md` — real IPs/hosts/accounts (outside repo).

## Topology note (from smoke-test audit, durable)
- **:80** = nginx 1.28.x (Basic-auth realm "Nemesis Firewall"), LAN-allowed, proxies to :5000.
- **:5000** = Flask dashboard (`app.run port=5000`), ufw-blocked from LAN — internal only.
- **:5001** = hw-monitor agent endpoint (`/enroll`, `/enrollment_status`, `/hw_data`), now
  LAN-allowed (subnet-scoped).
