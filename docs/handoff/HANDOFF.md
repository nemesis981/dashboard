# HANDOFF — current state

> Current project state, last updated 2026-06-27 (major-session closeout). Overwritten at
> each nightly closeout (latest state wins). Durable history lives in
> `docs/handoff/supplements/` (append-only); raw step log in `docs/handoff/worklog/`.

## Resume point → NEXT OPENER

In order (trip deadline = **this Friday** drives the sequence):
1. **Starlink SSH test FIRST (~5 min)** — Tailscale is enrolled on the Nemesis box
   (tailnet IP `100.87.130.25`) + laptop, and SSH is **proven over Tailscale**.
   Starlink arrives tomorrow → test SSH over Starlink to **complete the connectivity gate**.
2. **Multi-user upgrades for trip testing.**
3. **Diagnostics audit** (watcher productization FIRST — connectivity self-diagnostic for
   the Starlink link; see `docs/roadmap/diagnostics-*`).

Reasoning in `supplements/2026-06-27-001.md` §7.

## Where things stand

**Layer B (ransomware canary) — ✅ v1 COMPLETE.** Canary is **live on the dev box**,
**boot-enabled** via `malware-canary.service`, and **verified end-to-end**: 4 bait files,
30s poll, a forced trip propagated **trip → finding → ticket → alert** through the full
pipeline. Pushed at `60c19ff`. Detail: `supplements/2026-06-27-001.md` §3; audit:
`docs/audits/malware-layer-b-canary-audit.md`.

**VM audit — ✅ COMPLETE.** Uninstall → fresh install → forced trip → recovery on the test
VM. 3 gaps found and fixed: auto-plant (`plant_canaries()` had no caller → wired into
`Module.start()`, `163ea31`); uninstall canary cleanup (`ef5ad6f`, wording `c78cbfc`);
ghost-row mass-trip bug (remove bait + baselines together, else reinstall trips on missing
files — folded into `ef5ad6f`). **Layer B v1 is FULLY complete including VM audit fixes.**

**Connectivity — ⏳ Tailscale proven, Starlink pending.** Tailscale enrolled on the Nemesis
box (`100.87.130.25`) + laptop; SSH proven over Tailscale. Starlink arrives tomorrow →
SSH-over-Starlink test completes the gate (resume item #1).

**Pass 0 readiness — ✅ Tier A + Tier B COMPLETE.**
- ✅ **Tier A (`fb52a83`)** — fresh-install crash fixed (`devices` table had **no CREATE
  anywhere** → added canonical CREATE); `anomaly_detection` on shared `get_db()`;
  cross-process reads guarded.
- ✅ **Tier B (`31337e1`)** — attribution (`actor`) seams on the module tables the Layer-B
  + agent rebuilds write through; config-change audit; **CLAUDE.md build-discipline
  mandates** added (firewall single-chokepoint, multi-user-ready-by-default, DB
  canonical-init / "no table without a CREATE").

**DNS root cause — ✅ CORRECTED (ADR 0002 superseded by ADR 0005).** Proven
**client-refusal-by-source** via the `-b 127.0.0.1` test — the failure is which *source
address* the client may query from, NOT policy routing / killswitch. The previously-
considered DNS **guard solves the wrong layer** and is shelved. **Workaround on this box
until the firewall engine exists: run VPN-off** for Claude Code connectivity. Detail:
`supplements/2026-06-27-001.md` §1.

**VPN watcher — corroborating evidence captured.** Running since this morning; stayed
**all-green through 7 failed Claude-Code attempts**, confirming the failure was **not
local DNS** (backend hiccup + source-based refusal). Stays armed for the trip's Starlink
link. (`~/work/vpn-watcher/`, OUTSIDE repo, not committed.)

## Trip context (drives priorities)
**Leaving Friday — 2-week camper deployment in Wisconsin, Starlink ordered.** This is a
live field test of the **remote-worker scenario that is the product's core market**.
Canary + agent = **road security without carrying extra hardware**. Pre-trip build
targets: **Tailscale/remote-access** + a **Windows agent**.

## Architecture captured this session (PARKED — ADR/roadmap-bound)
- **ADR 0005** — firewall engine as a **foundational primitive** (base for DNS control,
  device auth Level 2, hardware binding, proportional tamper response, forward build
  sequence). Supersedes ADR 0002's DNS framing.
- **Product thesis** — built-in IT expertise; enterprise capability without enterprise
  pricing. (`docs/roadmap/product-thesis-built-in-it-expertise.md`.)
- **Market position** — the remote / infrastructure-light / expertise-light edge;
  Starlink/remote-worker is **core market**, not a niche.
- **Adaptive link-aware agent + clock sync** — agent robust over bad links, ordered
  findings across devices. (`docs/roadmap/adaptive-link-aware-agent-clock-sync.md`.)
- **Watcher productization** (toggleable connectivity self-diagnostic),
  **tiered diagnostic reports**, **AI tool-aware diagnostic loop**, **reassurance/
  escalation routing**. (`docs/roadmap/diagnostics-*.md`, `diagnostic-scan-scope.md`.)
- **DB resilience via backup-promotion**; **agent auto-load-by-ownership**.

## Carried from prior sessions (still live)
- **Scan/task orchestration — DIRECTION DECIDED (ADR 0004, Proposed):** scheduler =
  authoritative dispatcher; execution modules (malware = full-stack, hardware) do the
  work; reporting module delivers printable reports; `hw_monitor` → hardware-only. 3 open
  hinge questions in the ADR.
- **Licensing principle:** SINGLE version; a key/license unlocks commercial features
  (multi-user, attribution, device limits) IN PLACE — the key "wires the house" the
  multi-user-ready seams leave socketed. (Flagged for CLAUDE.md promotion.)
- **Schema gatekeeper / registry** + **third-party module trust & isolation model** +
  **ownership/consent boundary** — see `supplements/2026-06-26-002.md` §10.

**Secrets:** externalized OUT of the repo to `~/work/nemesis-private/local-config.md`
— referenced by location only, never committed.

## Stage 5 / 6 (later)
- **Stage 5** — single SQLite-safe shared-DB snapshot backup; make deploy/health DISCOVER
  services (now also `malware-canary.service`); purge per-module-DB refs in
  `_backup_candidates()` / `install.sh` (`PUNCHLIST.md`).
- **Stage 6** — retire old module `.db` fallbacks after N verified days.
- **Parked quick wins** — `PIHOLE_IP` hardcoded-default fix (Rule 8), settings status-fix,
  header de-dup, kernel-update check, live Anthropic pricing capture (all `PUNCHLIST.md`).

## Pointers
- Methodology & rules: `CLAUDE.md`
- Architecture: `ARCHITECTURE.md`, `docs/architecture/` (ADR 0001 DB, 0002 DNS
  **[superseded by 0005]**, 0003 resilience, 0004 scan/task orchestration,
  **0005 DNS/firewall/device-auth — the new foundational architecture**)
- Audits: `docs/audits/` — incl. **`malware-layer-b-canary-audit.md`**
- Parked ideas: `docs/roadmap/` (incl. `product-thesis-built-in-it-expertise.md`,
  `adaptive-link-aware-agent-clock-sync.md`, `diagnostics-*`)
- Small fixes: `PUNCHLIST.md`
- Session logs: `docs/handoff/supplements/` (latest `2026-06-27-001.md`);
  worklog `docs/handoff/worklog/2026-06-27-001.md`
- VPN watcher (outside repo, not committed): `~/work/vpn-watcher/vpn-watch.sh`
