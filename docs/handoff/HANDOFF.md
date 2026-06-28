# HANDOFF — current state

> Current project state, last updated 2026-06-28 (session closeout). Overwritten at each
> closeout (latest state wins). Durable history lives in `docs/handoff/supplements/`
> (append-only); raw step log in `docs/handoff/worklog/`.

## Resume point → NEXT OPENER

Order driven by the trip deadline (**leaving Friday**, 2-week Wisconsin camper deployment):

1. **Starlink SSH test FIRST (~5 min)** — Tailscale proven over the project tailnet; Starlink
   is **arriving soon**. SSH-over-Starlink completes the connectivity gate and **gates the
   trip**. Run it the moment Starlink lands.
2. **NEXT BUILD — multi-user trip-testing surface.** Read-only audit already staged (see
   chat). Three focused items, goal = make attribution **TESTABLE in Wisconsin without full
   auth machinery**:
   - **Basic session identity** — cookie-based "who am I" (NO real auth yet).
   - **Actor surfacing in the UI** — Tier-B `actor` data already in the DB, just needs display.
   - **Entitlements stub** (optional).
3. **After multi-user — Windows agent readiness.** Minimum bar: **installs + phones home**,
   testable on a Windows PC at the trip site.

## Where things stand

**Diagnostics connectivity-watcher — ✅ COMPLETE + deployed.** Passes 0-3 (`2e4f3e3 ->
086a659`). `diagnostics-watcher.service` is **live, boot-enabled**, self-gating; live verdict
`ALL_OK` at 60s cadence. **Rule-8 split proven** (raw detail to flat log outside repo;
sanitized booleans-only to the DB). **5 VPN providers** (PIA/Mullvad/ProtonVPN/WireGuard/
Tailscale, skip-if-absent) + `CUSTOM_VPN_PROBE.md`. **VM audit = ZERO gaps** (install/
uninstall lifecycle clean; `diagnostics_*` tables preserved on uninstall). Detail:
`supplements/2026-06-28-003.md`. Old throwaway `vpn-watch.sh` retired (logs saved).

**Layer B (ransomware canary) — ✅ v1 COMPLETE.** Live + **boot-enabled** via
`malware-canary.service`, verified end-to-end (trip → finding → ticket → alert), VM-audited.
**Both `malware-canary` and `diagnostics-watcher` are live and boot-enabled.** Detail:
`supplements/2026-06-27-001.md` §3; audit `docs/audits/malware-layer-b-canary-audit.md`.

**Project identity — ✅ demo-ready, no PII in the public repo.** Domain `nemesis-sw.com`;
support `support@nemesis-sw.com` (subject-tag `[Nemesis Firewall]`). **Tailscale migrated to
project account `nemesis.tailscale@gmail.com`**, box tailnet IP **`100.87.130.25`**. Son's
laptop still on the old personal account → **re-enroll under the project account when
convenient** (not blocking). (`5b9f9d6`.)

**Connectivity — ⏳ Tailscale proven, Starlink pending.** SSH proven over Tailscale; Starlink
arriving soon → SSH-over-Starlink test completes the gate (resume #1).

**DNS root cause — ✅ CORRECTED (ADR 0002 superseded by ADR 0005).** Proven
**client-refusal-by-source** (`-b 127.0.0.1`). The shelved DNS guard solved the wrong layer.
**Workaround still in place on this box: run VPN-off** for Claude Code connectivity — the real
fix is the firewall engine (ADR 0005), **deferred**. Detail: `supplements/2026-06-27-001.md` §1.

**Pass 0 readiness — ✅ Tier A + Tier B COMPLETE.** Fresh-install crash fixed (`fb52a83`);
attribution (`actor`) seams + CLAUDE.md build-discipline mandates (`31337e1`). The **vendor-
integration mandate** (a vendor probe ships its `CUSTOM_*.md` in the same commit) was added
this session.

## Trip context (drives priorities)
**Leaving Friday — 2-week camper deployment in Wisconsin, Starlink ordered.** Live field test
of the **remote-worker scenario that is the product's core market**. Pre-trip build targets:
**multi-user trip-testing surface** (attribution testable), then **Windows agent readiness**.

## Architecture / roadmap captured (PARKED — ADR/roadmap-bound)
- **ADR 0005** — firewall engine as the **foundational primitive** (DNS control, device auth,
  hardware binding, tamper response). Supersedes ADR 0002's DNS framing.
- **VM Test Lab + sandbox integration (major).** Five-layer architecture; same VM engine drives
  `--mode test` and `--mode sandbox`. **Sandbox stub (was deferred — Firejail insufficient) NOW
  ENABLED** by the VM Lab. Post-commercial milestone. (`docs/roadmap/nemesis-test-lab.md`,
  `malware-local-isolated-sandbox.md`.)
- **Agent rebuild — config-driven** two-phase bootstrap, VPN as a configurable field, staggered
  restart, scripted VM creation. (`docs/roadmap/agent-rebuild-config-driven.md`.)
- **Open-source threat feeds → V2** (Abuse.ch/OTX/MISP/Spamhaus), in the community backend build,
  not deferred — closes the record-count gap at zero cost. (`docs/roadmap/open-source-threat-feeds.md`.)
- **Enterprise gap audit** — network layer stronger than most pure-EDR; v2 adds MITRE ATT&CK
  mapping, vuln mgmt, auth/login monitoring, lateral-movement core.
  (`docs/roadmap/enterprise-gap-audit-2026.md`.)
- **Lateral movement — core promoted to v2** (owned fleet, correlation query, no new sensors);
  venue/epidemic version stays parked. (`docs/roadmap/lateral-movement-outbreak-detection.md`.)
- **Product thesis** — built-in IT expertise; enterprise capability without enterprise pricing.
  (`docs/roadmap/product-thesis-built-in-it-expertise.md`.)

## Carried from prior sessions (still live)
- **Scan/task orchestration — DIRECTION DECIDED (ADR 0004, Proposed):** scheduler = dispatcher;
  execution modules do the work; reporting delivers reports; 3 open hinge questions in the ADR.
- **Licensing principle:** SINGLE version; a key unlocks commercial features (multi-user,
  attribution, device limits) IN PLACE — the key "wires the house" the multi-user-ready seams
  leave socketed. (Flagged for CLAUDE.md promotion.)
- **Schema gatekeeper / registry**, **third-party module trust & isolation**, **ownership/
  consent boundary** — `supplements/2026-06-26-002.md` §10.

**Secrets:** externalized OUT of the repo to `~/work/nemesis-private/local-config.md` —
referenced by location only, never committed.

## Stage 5 / 6 + parked quick wins (later)
- **Stage 5** — single SQLite-safe shared-DB snapshot backup; deploy/health DISCOVER services;
  purge per-module-DB refs (`PUNCHLIST.md`). **Stage 6** — retire old module `.db` fallbacks.
- **PUNCHLIST quick wins** — `PIHOLE_IP` hardcoded-default fix (Rule 8), header de-dup,
  kernel-update check, live Anthropic pricing capture, **Pi-hole unattended-install quirk**.
- **PRE-RELEASE audits (PUNCHLIST)** — full system-transparency audit, documentation-
  completeness, tiered-output, recurring-user-error.

## Pointers
- Methodology & rules: `CLAUDE.md`
- Architecture: `ARCHITECTURE.md`, `docs/architecture/` (ADR 0001 DB, 0002 DNS **[superseded by
  0005]**, 0003 resilience, 0004 scan/task orchestration, **0005 DNS/firewall/device-auth — the
  foundational architecture**)
- Operations: `docs/operation/CONFIG_CHANGE_PROCEDURE.md`
- Roadmap: `docs/roadmap/` — incl. `product-thesis-built-in-it-expertise.md`,
  `nemesis-test-lab.md`, `agent-rebuild-config-driven.md`, `enterprise-gap-audit-2026.md`,
  `open-source-threat-feeds.md`, `lateral-movement-outbreak-detection.md`, `diagnostics-*`
- Audits: `docs/audits/` (incl. `malware-layer-b-canary-audit.md`)
- Small fixes: `PUNCHLIST.md`
- Session logs: `docs/handoff/supplements/` (latest `2026-06-28-003.md`); worklog
  `docs/handoff/worklog/2026-06-28-001.md`
