# HANDOFF — current state

> Current project state, last updated 2026-06-28 (end-of-day closeout). Overwritten at each
> closeout (latest state wins). Durable history: `docs/handoff/supplements/` (append-only);
> raw step log: `docs/handoff/worklog/`.

## Current state
- **Auth live** — Flask-Login, `<owner>` account, tiered lockout, `login_events` collecting,
  concurrent-session seam.
- **Header light: green.**
- **Services:** dashboard + watchdog + alert-watcher + malware-canary + diagnostics-watcher
  all running.
- **Tailscale:** `100.87.130.25` (`nemesis.tailscale@gmail.com`).
- **Windows agent:** built, enrollment flow complete, agent launchable (platform shadow bug
  fixed). **NOT YET SMOKE TESTED on a real Windows box.**
- **Trip:** Friday. Wisconsin, 2 weeks. **Starlink confirmed working.**

## Next-session resume
1. **Pre-enrollment scan** (scan before trust — add to `enrollment.py` and the hw_monitor
   `/enroll` endpoint).
2. **Windows smoke test** (`install.ps1` on a real Windows box — full 12-step sequence; see the
   Wisconsin test plan below).
3. Fix any gaps.
4. Session closeout + trip ready.

## Open items
- Son's laptop Tailscale re-enrollment (`nemesis.tailscale@gmail.com`).
- Ethernet cable for Wisconsin (find before Friday).
- KDE Connect broken (not pursuing).
- `PIHOLE_IP` hardcoded at `dashboard.py:71` (known Rule-8 PUNCHLIST item).
- VPN-off workaround still in place (ADR 0005 real fix deferred).
- Race 4 residual merge-RMW (low-priority PUNCHLIST item).

## Pointers
- **ADRs:** 0006 (Data Manager), 0007 (device-user model), 0008 (impossible travel),
  0009 (security inspection proxy / self-hosted SSE — `docs/architecture/0009-security-inspection-proxy.md`).
- `docs/roadmap/nemesis-test-lab.md` (VM Lab + sandbox)
- `docs/roadmap/agent-rebuild-config-driven.md`
- `docs/roadmap/msp-central-management.md`
- `docs/roadmap/open-source-threat-feeds.md`
- `docs/roadmap/enterprise-gap-audit-2026.md`
- `docs/roadmap/post-update-module-repair.md`
- `docs/roadmap/product-thesis-built-in-it-expertise.md`
- `docs/operation/CONFIG_CHANGE_PROCEDURE.md`
- `docs/operation/WINDOWS_AGENT_SETUP.md`
- `core/manage.py` (SSH recovery CLI)

## Wisconsin test plan
1. Enroll daughter's PC via `install.ps1`.
2. Verify enrollment appears in the dashboard.
3. Approve the device.
4. Verify hardware metrics (LHM temps + fans).
5. Verify connection type (WiFi gap, or Mode 2 tunnel).
6. Push restart from the dashboard.
7. Test concurrent-session detection (login from two devices).
8. Test layout memory (set layout on laptop, verify on daughter's PC).
9. Test header light (create alert → verify red → acknowledge → green).
10. Starlink bandwidth test under load.
